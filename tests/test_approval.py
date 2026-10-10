import datetime as dt
import json
from dataclasses import replace

import pytest

from agent_auth.approval import ApprovedGrant, ApprovedIssuer, PermissionAuthority
from agent_auth.scenarios import BASE_POLICY, make_store
from agent_auth.gateway import AuthorizationError, AuthorizationGateway
from agent_auth.pki import AGENT_URI, ResearchCA
from agent_auth.token_baseline import TokenAuthority, TokenGateway


@pytest.mark.parametrize("mode", ["certificate", "external", "hybrid", "hybrid_ceiling", "token"])
def test_initial_policy_uses_narrow_approval_instead_of_existing_broad_policy(mode):
    owner, ca, store = authority(), ResearchCA.create(), make_store()
    grant = owner.approve(agent_id=AGENT_URI, requested_permissions=[
        {"tool": "file", "action": "read", "resource_prefix": "/research/papers"}
    ])
    issuer = ApprovedIssuer(ca, owner.public_key, owner.owner_id)
    if mode == "token":
        tokens = TokenAuthority()
        token = issuer.issue_token(grant, tokens, policy_store=store)
        gateway = TokenGateway(tokens, store)
        session = gateway.open_token_session(token)
    else:
        issued = issuer.issue_agent(grant, mode=mode, policy_store=store)
        gateway = AuthorizationGateway(ca, store)
        session = gateway.open_session(issued.cert, issued.key)
    assert gateway.authorize(session, {"tool": "file", "action": "read", "resource": "/research/papers/a.txt"})[0]
    assert not gateway.authorize(session, {"tool": "file", "action": "read", "resource": "/research/private.txt"})[0]


def test_invalid_issuance_does_not_change_existing_live_policy():
    owner, store = authority(), make_store()
    grant = owner.approve(agent_id=AGENT_URI, requested_permissions=[])
    issuer = ApprovedIssuer(ResearchCA.create(), owner.public_key, owner.owner_id)
    with pytest.raises(AuthorizationError):
        issuer.issue_agent(grant, mode="unknown", policy_store=store)
    assert store.get_agent_policy(AGENT_URI) == BASE_POLICY
    with pytest.raises(AuthorizationError):
        issuer.issue_agent(grant, mode="external")


def test_explicitly_empty_agent_allowlist_is_not_replaced_with_default():
    with pytest.raises(ValueError):
        PermissionAuthority.create(allowed_permissions=[], allowed_agents=set())


def authority():
    return PermissionAuthority.create(allowed_permissions=BASE_POLICY["permissions"])


def test_owner_signed_approval_is_required_before_issuance():
    owner = authority()
    ca = ResearchCA.create()
    grant = owner.approve(agent_id=AGENT_URI, requested_permissions=[
        {"tool": "file", "action": "read", "resource_prefix": "/research/papers"}
    ])
    issuer = ApprovedIssuer(ca, owner.public_key, owner.owner_id)
    store = make_store()
    issued = issuer.issue_agent(grant, mode="hybrid_ceiling", policy_store=store)
    gateway = AuthorizationGateway(ca, store)
    session = gateway.open_session(issued.cert, issued.key)
    assert gateway.authorize(session, {"tool": "file", "action": "read", "resource": "/research/papers/a.txt"})[0]
    assert not gateway.authorize(session, {"tool": "file", "action": "read", "resource": "/research/private.txt"})[0]
    assert issuer.issuance_log[0]["approved_by"] == owner.owner_id
    assert issued.cert.not_valid_after_utc <= dt.datetime.fromisoformat(grant.public_record()["expires_at"])


@pytest.mark.parametrize("permission", [
    {"tool": "shell", "action": "execute", "resource_prefix": "/bin"},
    {"tool": "file", "action": "write", "resource_prefix": "/research"},
    {"tool": "file", "action": "read", "resource_prefix": "/"},
    {"tool": "file", "action": "read", "resource_prefix": "/research-old"},
])
def test_owner_rejects_request_beyond_configured_authority(permission):
    with pytest.raises(AuthorizationError):
        authority().approve(agent_id=AGENT_URI, requested_permissions=[permission])


def test_unapproved_agent_is_rejected():
    with pytest.raises(AuthorizationError):
        authority().approve(agent_id="spiffe://seminar.fisk.edu/agent/other", requested_permissions=[])


def test_agent_cannot_edit_owner_signed_permissions_or_use_own_approver_key():
    owner = authority()
    grant = owner.approve(agent_id=AGENT_URI, requested_permissions=BASE_POLICY["permissions"])
    issuer = ApprovedIssuer(ResearchCA.create(), owner.public_key, owner.owner_id)
    altered = json.loads(grant.payload)
    altered["permissions"].append({"tool": "shell", "action": "execute", "resource_prefix": "/bin"})
    with pytest.raises(AuthorizationError):
        issuer.issue_agent(replace(grant, payload=json.dumps(altered)), mode="certificate")
    rogue = authority()
    rogue_grant = rogue.approve(agent_id=AGENT_URI, requested_permissions=BASE_POLICY["permissions"])
    with pytest.raises(AuthorizationError):
        issuer.issue_agent(rogue_grant, mode="certificate")


def test_expired_owner_grant_denies_issuance_even_with_valid_signature():
    owner = authority()
    grant = owner.approve(agent_id=AGENT_URI, requested_permissions=[])
    payload = grant.public_record()
    payload["issued_at"] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=20)).isoformat()
    payload["expires_at"] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)).isoformat()
    text = json.dumps(payload)
    expired = ApprovedGrant(text, owner._key.sign(text.encode()))
    with pytest.raises(AuthorizationError):
        ApprovedIssuer(ResearchCA.create(), owner.public_key, owner.owner_id).issue_agent(expired, mode="external", policy_store=make_store())
