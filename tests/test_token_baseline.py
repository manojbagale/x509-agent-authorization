import datetime as dt

import pytest

from agent_auth.approval import ApprovedIssuer, PermissionAuthority
from agent_auth.scenarios import BASE_POLICY, REQUESTS, make_store
from agent_auth.gateway import AuthorizationError
from agent_auth.pki import AGENT_URI, ResearchCA
from agent_auth.token_baseline import TokenAuthority, TokenGateway


def fixture():
    authority = TokenAuthority()
    store = make_store()
    gateway = TokenGateway(authority, store)
    token = authority.issue(agent_id=AGENT_URI)
    return authority, store, gateway, token, gateway.open_token_session(token)


def test_equivalent_token_server_policy_request_matrix_and_live_narrowing():
    authority, store, gateway, token, session = fixture()
    for _, request, expected in REQUESTS:
        assert gateway.authorize(session, request)[0] is expected
    store.replace_agent_policy(AGENT_URI, {"permissions": []})
    assert not gateway.authorize(session, REQUESTS[0][1])[0]


def test_revocation_blocks_existing_token_session_and_reopening():
    authority, store, gateway, token, session = fixture()
    assert gateway.authorize(session, REQUESTS[0][1])[0]
    gateway.kill(session)
    assert gateway.authorize(session, REQUESTS[0][1]) == (False, "session_revoked")
    with pytest.raises(AuthorizationError):
        gateway.open_token_session(token)


def test_expiry_checked_after_session_open_with_injected_clock():
    now = [dt.datetime.now(dt.timezone.utc)]
    authority = TokenAuthority(clock=lambda: now[0])
    gateway = TokenGateway(authority, make_store())
    token = authority.issue(agent_id=AGENT_URI, lifetime_minutes=1)
    session = gateway.open_token_session(token)
    assert gateway.authorize(session, REQUESTS[0][1])[0]
    now[0] += dt.timedelta(minutes=1)
    assert gateway.authorize(session, REQUESTS[0][1]) == (False, "token_expired")


@pytest.mark.parametrize("bad", [None, "0"*64, "\u00e9"*64, "a", "g"*64])
def test_unknown_or_malformed_token_denied(bad):
    with pytest.raises(AuthorizationError):
        TokenGateway(TokenAuthority(), make_store()).open_token_session(bad)


@pytest.mark.parametrize("tool_request", [None, {"tool":"file","action":"read","resource":None},
    {"tool":"file","action":"read","resource":"/research/a", "admin":True}])
def test_malformed_request_denies_and_audits(tool_request):
    _, _, gateway, _, session = fixture()
    assert gateway.authorize(session, tool_request) == (False, "invalid_request")
    assert gateway.audit_log[-1]["decision"] == "DENY"


def test_same_bearer_token_can_be_replayed_until_revoked():
    _, _, gateway, token, first = fixture()
    second = gateway.open_token_session(token)
    assert gateway.authorize(first, REQUESTS[0][1])[0]
    assert gateway.authorize(second, REQUESTS[0][1])[0]
    # Baseline deliberately has bearer semantics: no private-key proof.
    gateway.kill(first)
    assert not gateway.authorize(second, REQUESTS[0][1])[0]


def test_owner_approved_token_issuance_has_same_subject_binding():
    owner = PermissionAuthority.create(allowed_permissions=BASE_POLICY["permissions"])
    grant = owner.approve(agent_id=AGENT_URI, requested_permissions=BASE_POLICY["permissions"])
    authority = TokenAuthority()
    store = make_store()
    token = ApprovedIssuer(ResearchCA.create(), owner.public_key, owner.owner_id).issue_token(
        grant, authority, policy_store=store)
    session = TokenGateway(authority, store).open_token_session(token)
    assert session.agent_id == grant.public_record()["agent_id"]
