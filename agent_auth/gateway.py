"""Certificate sessions and per-call authorization."""
from __future__ import annotations

import datetime as dt
import secrets
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlparse

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID

from agent_auth.policy import (
    AuthorizationError, PolicyStore, canonicalize_resource,
    matches_permissions, validate_permissions, validate_policy,
)
from agent_auth.pki import AGENT_AUTHZ_OID, TRUST_DOMAIN, ResearchCA, decode_agent_extension


@dataclass(frozen=True)
class Session:
    serial_number: int
    agent_id: str
    cert: x509.Certificate
    mode: str
    embedded_policy: dict[str, Any] | None = None
    policy_id: str | None = None
    max_permissions: list[dict[str, Any]] | None = None


class AuthorizationGateway:
    def __init__(self, ca: ResearchCA, policy_store: PolicyStore, *,
                 clock: Callable[[], dt.datetime] | None = None):
        self.ca = ca
        self._clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))
        self.policy_store = policy_store
        self.kill_registry: set[int] = set()
        self.audit_log: list[dict[str, Any]] = []

    def _verify_certificate(self, cert: x509.Certificate) -> None:
        """Validate the lab certificate profile and trust relationship.

        This deliberately handles the single-root, direct-leaf research profile.
        A production implementation should use a full PKIX path validator.
        """
        now = self._clock()
        if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            raise AuthorizationError("certificate expired or not yet valid")
        if cert.issuer != self.ca.cert.subject:
            raise AuthorizationError("wrong issuer")
        try:
            self.ca.cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise AuthorizationError("invalid certificate signature") from exc

        supported_critical = {
            ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.KEY_USAGE,
            ExtensionOID.EXTENDED_KEY_USAGE, ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
            ExtensionOID.SUBJECT_KEY_IDENTIFIER, ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
            AGENT_AUTHZ_OID,
        }
        for extension in cert.extensions:
            if extension.critical and extension.oid not in supported_critical:
                raise AuthorizationError("unsupported critical certificate extension")

        try:
            bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
            ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
            eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        except x509.ExtensionNotFound as exc:
            raise AuthorizationError("required certificate extension missing") from exc

        if bc.ca:
            raise AuthorizationError("CA certificate cannot be used as an agent certificate")
        if not ku.digital_signature or ku.key_cert_sign or ku.crl_sign:
            raise AuthorizationError("invalid agent key usage")
        if ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
            raise AuthorizationError("clientAuth EKU required")

    @staticmethod
    def _extract_agent_id(cert: x509.Certificate) -> str:
        try:
            san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        except x509.ExtensionNotFound as exc:
            raise AuthorizationError("subjectAltName missing") from exc
        uris = san.get_values_for_type(x509.UniformResourceIdentifier)
        if len(uris) != 1:
            raise AuthorizationError("expected exactly one URI SAN")
        agent_id = uris[0]
        parsed = urlparse(agent_id)
        if parsed.scheme != "spiffe" or parsed.netloc != TRUST_DOMAIN or not parsed.path.startswith("/agent/"):
            raise AuthorizationError("agent identity outside trusted SPIFFE domain")
        return agent_id

    @staticmethod
    def _decode_mode(cert: x509.Certificate) -> tuple[str, dict[str, Any] | None]:
        try:
            ext = cert.extensions.get_extension_for_oid(AGENT_AUTHZ_OID).value
            payload = decode_agent_extension(ext.value)
            if type(payload.get("version")) is not int or payload["version"] != 1:
                raise AuthorizationError("unsupported authorization extension version")
            mode = payload["mode"]
            if mode not in {"certificate", "hybrid", "hybrid_ceiling"}:
                raise AuthorizationError("unknown authorization mode")
            if mode == "certificate":
                validate_permissions(payload.get("permissions"))
            else:
                if not isinstance(payload.get("policy_id"), str) or not payload["policy_id"]:
                    raise AuthorizationError("hybrid certificate requires policy_id")
                if mode == "hybrid_ceiling":
                    validate_permissions(payload.get("max_permissions"))
            return mode, payload
        except x509.ExtensionNotFound:
            return "external", None
        except (ValueError, KeyError, TypeError) as exc:
            raise AuthorizationError("malformed authorization extension") from exc

    def _build_session(self, cert: x509.Certificate) -> Session:
        self._verify_certificate(cert)
        agent_id = self._extract_agent_id(cert)
        mode, payload = self._decode_mode(cert)
        return Session(
            serial_number=cert.serial_number,
            agent_id=agent_id,
            cert=cert,
            mode=mode,
            embedded_policy=payload if mode == "certificate" else None,
            policy_id=(payload or {}).get("policy_id"),
            max_permissions=(payload or {}).get("max_permissions"),
        )

    def open_session(self, cert: x509.Certificate, private_key) -> Session:
        """Open a session using an explicit proof-of-possession challenge.

        This remains useful for unit testing. The networked mTLS demo uses
        open_mtls_session(), because the TLS handshake itself proves key possession.
        """
        session = self._build_session(cert)
        challenge = secrets.token_bytes(32)
        signature = private_key.sign(challenge, ec.ECDSA(hashes.SHA256()))
        try:
            cert.public_key().verify(signature, challenge, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as exc:
            raise AuthorizationError("private-key proof failed") from exc
        return session

    def open_mtls_session(self, cert: x509.Certificate) -> Session:
        """Open an application session after a successful mTLS handshake."""
        return self._build_session(cert)

    def kill(self, session: Session) -> None:
        self.kill_registry.add(session.serial_number)

    # Retain the public resource helper for existing callers.
    canonicalize_resource = staticmethod(canonicalize_resource)

    def _policy_for_session(self, session: Session) -> dict[str, Any]:
        if session.mode == "certificate":
            # Reconstruct authority from immutable signed bytes, not cached lists.
            _, payload = self._decode_mode(session.cert)
            return payload
        if session.mode == "external":
            return self.policy_store.get_agent_policy(session.agent_id)
        if session.mode in {"hybrid", "hybrid_ceiling"}:
            if not session.policy_id:
                raise AuthorizationError("hybrid certificate missing policy_id")
            return self.policy_store.get_named_policy(session.policy_id)
        raise AuthorizationError("unknown authorization mode")

    def authorize(self, session: Session, request: dict[str, str]) -> tuple[bool, str]:
        if not isinstance(request, dict) or set(request) != {"tool", "action", "resource"} or any(
            not isinstance(value, str) or not value for value in request.values()
        ):
            decision = (False, "invalid_request")
            self._audit(session, request, *decision)
            return decision
        if session.serial_number in self.kill_registry:
            decision = (False, "session_revoked")
            self._audit(session, request, *decision)
            return decision

        now = self._clock()
        if not (session.cert.not_valid_before_utc <= now <= session.cert.not_valid_after_utc):
            decision = (False, "certificate_expired")
            self._audit(session, request, *decision)
            return decision

        try:
            policy = validate_policy(self._policy_for_session(session))
            live_match = matches_permissions(policy.get("permissions", []), request)
            if session.mode == "hybrid_ceiling":
                _, signed_payload = self._decode_mode(session.cert)
                ceiling_match = matches_permissions(signed_payload["max_permissions"], request)
                allowed = live_match and ceiling_match
                reason = "matched_live_policy_and_ceiling" if allowed else (
                    "outside_signed_ceiling" if live_match and not ceiling_match else "outside_scope"
                )
            else:
                allowed = live_match
                reason = "matched_permission" if allowed else "outside_scope"
        except (AuthorizationError, KeyError, TypeError):
            decision = (False, "policy_error")
            self._audit(session, request, *decision)
            return decision

        decision = (allowed, reason)
        self._audit(session, request, *decision)
        return decision

    def _audit(self, session: Session, request: dict[str, str], allowed: bool, reason: str) -> None:
        request = request if isinstance(request, dict) else {}
        self.audit_log.append({
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
            "certificate_serial": str(session.serial_number),
            "agent_id": session.agent_id,
            "mode": session.mode,
            "tool": request.get("tool"),
            "action": request.get("action"),
            "resource": request.get("resource"),
            "decision": "ALLOW" if allowed else "DENY",
            "reason": reason,
        })
