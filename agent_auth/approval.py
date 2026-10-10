"""Trusted owner approval and lab credential issuance, outside the agent API.

The lab resource owner manually configures an allowlist and holds an Ed25519
approval key. Agents submit permission requests; they never receive that key or
the CA key. This is not a deployed human-consent UI or OAuth consent server.
"""
from __future__ import annotations

import datetime as dt
import json
import uuid
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from agent_auth.policy import (
    AuthorizationError, PolicyStore, canonicalize_resource,
    resource_matches, validate_permissions,
)
from agent_auth.pki import AGENT_URI, ResearchCA, canonical_json


@dataclass(frozen=True)
class ApprovedGrant:
    payload: str
    signature: bytes

    def public_record(self) -> dict[str, Any]:
        return json.loads(self.payload)


class PermissionAuthority:
    def __init__(self, owner_id: str, allowed_permissions: list[dict], allowed_agents: set[str]):
        if not owner_id or not allowed_agents:
            raise ValueError("owner and permitted agent identities are required")
        validate_permissions(allowed_permissions)
        self.owner_id = owner_id
        self._envelope = canonical_json(allowed_permissions)
        self._allowed_agents = frozenset(allowed_agents)
        self._key = ed25519.Ed25519PrivateKey.generate()

    @classmethod
    def create(cls, *, owner_id: str = "resource-owner:seminar-admin",
               allowed_permissions: list[dict], allowed_agents: set[str] | None = None):
        return cls(owner_id, allowed_permissions,
                   allowed_agents if allowed_agents is not None else {AGENT_URI})

    @property
    def public_key(self):
        return self._key.public_key()

    def approve(self, *, agent_id: str, requested_permissions: list[dict],
                policy_id: str = "research-policy-v1", lifetime_minutes: int = 15) -> ApprovedGrant:
        """Called by the trusted owner, after checking an agent's request."""
        validate_permissions(requested_permissions)
        if agent_id not in self._allowed_agents:
            raise AuthorizationError("owner has not approved this agent identity")
        if (not isinstance(policy_id, str) or not policy_id
                or type(lifetime_minutes) is not int or not 1 <= lifetime_minutes <= 15):
            raise AuthorizationError("invalid approval policy or lifetime")
        envelope = json.loads(self._envelope)
        for permission in requested_permissions:
            requested_path = canonicalize_resource(permission["resource_prefix"])
            if not any(
                p["tool"] == permission["tool"] and p["action"] == permission["action"]
                and resource_matches(p["resource_prefix"], requested_path)
                for p in envelope
            ):
                raise AuthorizationError("requested permission exceeds resource-owner allowlist")
        now = dt.datetime.now(dt.timezone.utc)
        payload = canonical_json({
            "version": 1, "approval_id": str(uuid.uuid4()), "approved_by": self.owner_id,
            "agent_id": agent_id, "policy_id": policy_id,
            "permissions": requested_permissions, "issued_at": now.isoformat(),
            "expires_at": (now + dt.timedelta(minutes=lifetime_minutes)).isoformat(),
        })
        return ApprovedGrant(payload, self._key.sign(payload.encode("utf-8")))


class ApprovedIssuer:
    """CA control-plane adapter that trusts exactly one configured owner key."""
    def __init__(self, ca: ResearchCA, owner_public_key, owner_id: str):
        self.ca, self.owner_public_key, self.owner_id = ca, owner_public_key, owner_id
        self.issuance_log: list[dict] = []

    def verify_grant(self, grant: ApprovedGrant) -> dict:
        try:
            self.owner_public_key.verify(grant.signature, grant.payload.encode("utf-8"))
            payload = json.loads(grant.payload)
            if (not isinstance(payload, dict) or type(payload["version"]) is not int
                    or payload["version"] != 1):
                raise ValueError("invalid grant")
            if payload["approved_by"] != self.owner_id:
                raise ValueError("untrusted approver")
            validate_permissions(payload["permissions"])
            start = dt.datetime.fromisoformat(payload["issued_at"])
            end = dt.datetime.fromisoformat(payload["expires_at"])
            now = dt.datetime.now(dt.timezone.utc)
            if not start <= now < end or end - start > dt.timedelta(minutes=15):
                raise ValueError("expired or invalid approval window")
            if not payload["agent_id"] or not payload["policy_id"]:
                raise ValueError("missing approval binding")
            return payload
        except (InvalidSignature, ValueError, KeyError, TypeError, AttributeError) as exc:
            raise AuthorizationError("owner approval invalid") from exc

    @staticmethod
    def _install_policy(payload: dict, policy_store: PolicyStore) -> None:
        """Initialize shared live policy from approval; later admin edits are allowed.

        This lab uses one agent and one named policy. Reusing identifiers in a
        multi-agent service would require separate ownership and versioning.
        """
        policy = {"permissions": validate_permissions(payload["permissions"])}
        policy_store.replace_agent_policy(payload["agent_id"], policy)
        policy_store.replace_named_policy(payload["policy_id"], policy)

    def issue_agent(self, grant: ApprovedGrant, *, mode: str,
                    policy_store: PolicyStore | None = None):
        if mode not in {"certificate", "external", "hybrid", "hybrid_ceiling"}:
            raise AuthorizationError("unsupported issuance mode")
        if mode != "certificate" and policy_store is None:
            raise AuthorizationError("approved live-policy issuance requires a policy store")
        payload = self.verify_grant(grant)
        remaining = (dt.datetime.fromisoformat(payload["expires_at"])
                     - dt.datetime.now(dt.timezone.utc)).total_seconds()
        minutes = int(remaining // 60)
        if minutes < 1:
            raise AuthorizationError("approval too close to expiry for certificate issuance")
        issued = self.ca.issue_agent(
            mode=mode, agent_uri=payload["agent_id"], policy_id=payload["policy_id"],
            permissions=payload["permissions"], max_permissions=payload["permissions"],
            lifetime_minutes=minutes,
        )
        if policy_store is not None:
            self._install_policy(payload, policy_store)
        self.issuance_log.append({**payload, "certificate_serial": str(issued.cert.serial_number),
                                  "mode": mode})
        return issued

    def issue_token(self, grant: ApprovedGrant, token_authority, *, policy_store: PolicyStore):
        payload = self.verify_grant(grant)
        token = token_authority.issue(agent_id=payload["agent_id"],
                                     expires_at=dt.datetime.fromisoformat(payload["expires_at"]))
        self._install_policy(payload, policy_store)
        self.issuance_log.append({**payload, "mode": "token"})
        return token
