"""Policy storage, validation and matching shared by both credential types."""
from __future__ import annotations

import posixpath
from copy import deepcopy
from typing import Any


class AuthorizationError(Exception):
    pass


def canonicalize_resource(resource: str) -> str:
    """Canonicalize a POSIX logical resource; percent characters are literal.

    A dispatcher must use these same semantics. This is not a filesystem
    symlink or URI-percent-decoding security boundary.
    """
    if not isinstance(resource, str) or not resource.startswith("/"):
        raise AuthorizationError("resource must be an absolute POSIX path")
    if "\\" in resource or "\x00" in resource:
        raise AuthorizationError("resource contains unsupported path characters")
    return "/" + posixpath.normpath(resource).lstrip("/")


def validate_permissions(permissions: Any) -> list[dict[str, str]]:
    if not isinstance(permissions, list):
        raise AuthorizationError("permissions must be a list")
    validated = []
    for permission in permissions:
        if not isinstance(permission, dict) or set(permission) != {"tool", "action", "resource_prefix"}:
            raise AuthorizationError("permission requires tool, action and resource_prefix")
        if any(not isinstance(value, str) or not value for value in permission.values()):
            raise AuthorizationError("permission fields must be nonempty strings")
        validated.append({**permission, "resource_prefix": canonicalize_resource(permission["resource_prefix"])})
    return validated


def validate_policy(policy: Any) -> dict[str, Any]:
    if not isinstance(policy, dict) or "permissions" not in policy:
        raise AuthorizationError("policy requires permissions")
    return {**deepcopy(policy), "permissions": validate_permissions(policy["permissions"])}


class PolicyStore:
    """Trusted control-plane configuration, never exposed as an agent tool.

    Copies prevent callers from silently changing a policy outside replacement.
    Replacements are validated when evaluated so unavailable/malformed runtime
    configuration denies requests rather than granting wider authority.
    """
    def __init__(self, policies: dict[str, Any]):
        self.policies = deepcopy(policies)

    def get_agent_policy(self, agent_id: str) -> dict[str, Any]:
        return deepcopy(self.policies["agents"][agent_id])

    def get_named_policy(self, policy_id: str) -> dict[str, Any]:
        return deepcopy(self.policies["named_policies"][policy_id])

    def replace_named_policy(self, policy_id: str, policy: dict[str, Any]) -> None:
        self.policies["named_policies"][policy_id] = deepcopy(policy)

    def replace_agent_policy(self, agent_id: str, policy: dict[str, Any]) -> None:
        self.policies["agents"][agent_id] = deepcopy(policy)


def resource_matches(allowed_prefix: str, resource: str) -> bool:
    prefix = posixpath.normpath(allowed_prefix)
    if resource == prefix:
        return True
    return resource.startswith(prefix.rstrip("/") + "/")


def matches_permissions(permissions: list[dict[str, Any]], request: dict[str, str]) -> bool:
    resource = canonicalize_resource(request["resource"])
    for permission in validate_permissions(permissions):
        if permission["tool"] != request["tool"] or permission["action"] != request["action"]:
            continue
        if resource_matches(permission["resource_prefix"], resource):
            return True
    return False
