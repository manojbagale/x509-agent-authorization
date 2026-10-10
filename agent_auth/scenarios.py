"""Shared policies, request cases and low-level issuance fixtures for experiments."""
from copy import deepcopy

from agent_auth.pki import AGENT_URI, ResearchCA
from agent_auth.policy import PolicyStore

BASE_POLICY = {
    "permissions": [
        {"tool": "file", "action": "read", "resource_prefix": "/research"},
        {"tool": "dns", "action": "lookup", "resource_prefix": "/fisk.edu"},
    ]
}

REQUESTS = [
    ("allowed_file", {"tool": "file", "action": "read", "resource": "/research/paper.pdf"}, True),
    ("allowed_nested_file", {"tool": "file", "action": "read", "resource": "/research/papers/x509/paper.pdf"}, True),
    ("outside_path", {"tool": "file", "action": "read", "resource": "/home/user/.ssh/id_rsa"}, False),
    ("path_traversal", {"tool": "file", "action": "read", "resource": "/research/../.ssh/id_rsa"}, False),
    ("prefix_confusion", {"tool": "file", "action": "read", "resource": "/research-old/secret.txt"}, False),
    ("relative_path", {"tool": "file", "action": "read", "resource": "research/paper.pdf"}, False),
    ("wrong_action", {"tool": "file", "action": "write", "resource": "/research/paper.pdf"}, False),
    ("wrong_tool", {"tool": "shell", "action": "execute", "resource": "/bin/sh"}, False),
    ("allowed_dns", {"tool": "dns", "action": "lookup", "resource": "/fisk.edu/www"}, True),
    ("outside_dns", {"tool": "dns", "action": "lookup", "resource": "/example.com"}, False),
]

MODES = ("certificate", "external", "hybrid", "hybrid_ceiling")


def make_store():
    return PolicyStore({
        "agents": {AGENT_URI: deepcopy(BASE_POLICY)},
        "named_policies": {"research-policy-v1": deepcopy(BASE_POLICY)},
    })


def issue_for_mode(ca: ResearchCA, mode: str):
    if mode == "certificate":
        return ca.issue_agent(mode=mode, permissions=deepcopy(BASE_POLICY["permissions"]))
    if mode == "hybrid":
        return ca.issue_agent(mode=mode, policy_id="research-policy-v1")
    if mode == "hybrid_ceiling":
        return ca.issue_agent(
            mode=mode,
            policy_id="research-policy-v1",
            max_permissions=deepcopy(BASE_POLICY["permissions"]),
        )
    return ca.issue_agent(mode=mode)
