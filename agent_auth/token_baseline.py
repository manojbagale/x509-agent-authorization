"""Basic opaque bearer-token + live server-policy comparison baseline.

The token is a random reference, not a JWT or RFC 8705 certificate-bound token.
Keep the registry and issuer in the trusted gateway/control plane. Send tokens
only over server-authenticated TLS in a deployment; the benchmark is in-process.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import secrets
from dataclasses import dataclass

from agent_auth.gateway import AuthorizationError, AuthorizationGateway, PolicyStore, validate_policy


@dataclass(frozen=True)
class TokenSession:
    token_digest: str
    agent_id: str
    mode: str = "token"


@dataclass(frozen=True)
class TokenRecord:
    agent_id: str
    issued_at: dt.datetime
    expires_at: dt.datetime


class TokenAuthority:
    def __init__(self, *, clock=None):
        self._clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))
        self._records: dict[str, TokenRecord] = {}
        self._revoked: set[str] = set()

    @staticmethod
    def digest(token: str) -> str:
        if not isinstance(token, str) or len(token) != 64 or any(c not in "0123456789abcdef" for c in token):
            raise AuthorizationError("invalid bearer token")
        return hashlib.sha256(token.encode("ascii")).hexdigest()

    def issue(self, *, agent_id: str, lifetime_minutes: int = 15, expires_at=None) -> str:
        """Trusted low-level fixture; demonstrations use ApprovedIssuer."""
        now = self._clock()
        expiry = expires_at or now + dt.timedelta(minutes=lifetime_minutes)
        if not isinstance(agent_id, str) or not agent_id or not now < expiry <= now + dt.timedelta(minutes=15):
            raise AuthorizationError("invalid token identity or lifetime")
        token = secrets.token_hex(32)
        self._records[self.digest(token)] = TokenRecord(agent_id, now, expiry)
        return token

    def lookup(self, digest: str) -> TokenRecord:
        if digest in self._revoked:
            raise AuthorizationError("session_revoked")
        record = self._records.get(digest)
        if record is None:
            raise AuthorizationError("invalid_token")
        now = self._clock()
        if not record.issued_at <= now < record.expires_at:
            raise AuthorizationError("token_expired")
        return record

    def revoke(self, digest: str):
        self._revoked.add(digest)


class TokenGateway:
    def __init__(self, authority: TokenAuthority, policy_store: PolicyStore):
        self.authority, self.policy_store = authority, policy_store
        self.audit_log: list[dict] = []

    def _verify_token(self, token: str):
        return self.authority.lookup(self.authority.digest(token))

    def open_token_session(self, token: str) -> TokenSession:
        record = self._verify_token(token)
        return TokenSession(self.authority.digest(token), record.agent_id)

    def kill(self, session: TokenSession):
        self.authority.revoke(session.token_digest)

    def authorize(self, session: TokenSession, request: dict) -> tuple[bool, str]:
        try:
            if not isinstance(request, dict) or set(request) != {"tool", "action", "resource"} or any(
                not isinstance(value, str) or not value for value in request.values()
            ):
                raise AuthorizationError("invalid_request")
            record = self.authority.lookup(session.token_digest)
            if record.agent_id != session.agent_id:
                raise AuthorizationError("invalid_token")
            policy = self.policy_store.get_agent_policy(record.agent_id)
            validate_policy(policy)
            allowed = AuthorizationGateway._matches(policy["permissions"], request)
            decision = (allowed, "matched_permission" if allowed else "outside_scope")
        except AuthorizationError as exc:
            reason = str(exc)
            decision = (False, reason if reason in {"session_revoked", "token_expired", "invalid_token", "invalid_request"}
                        else "policy_error")
        except (ValueError, KeyError, TypeError, AttributeError):
            decision = (False, "policy_error")
        safe_request = request if isinstance(request, dict) else {}
        self.audit_log.append({
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(), "agent_id": session.agent_id,
            "mode": "token", "tool": safe_request.get("tool"), "action": safe_request.get("action"),
            "resource": safe_request.get("resource"),
            "decision": "ALLOW" if decision[0] else "DENY", "reason": decision[1],
        })
        return decision
