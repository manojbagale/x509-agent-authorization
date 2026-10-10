from copy import deepcopy

import pytest

from agent_auth.pki import AGENT_URI, ResearchCA
from agent_auth.gateway import AuthorizationGateway, AuthorizationError, PolicyStore
from agent_auth.scenarios import BASE_POLICY, REQUESTS, issue_for_mode


def make_gateway():
    ca = ResearchCA.create()
    store = PolicyStore({
        "agents": {AGENT_URI: deepcopy(BASE_POLICY)},
        "named_policies": {"research-policy-v1": deepcopy(BASE_POLICY)},
    })
    return ca, store, AuthorizationGateway(ca, store)


@pytest.mark.parametrize("mode", ["certificate", "external", "hybrid", "hybrid_ceiling"])
def test_request_matrix(mode):
    ca, store, gw = make_gateway()
    issued = issue_for_mode(ca, mode)
    session = gw.open_session(issued.cert, issued.key)
    for _, request, expected in REQUESTS:
        actual, _ = gw.authorize(session, request)
        assert actual is expected


def test_wrong_private_key_is_rejected():
    ca, store, gw = make_gateway()
    issued = ca.issue_agent(mode="external")
    wrong_key = ca.issue_agent(mode="external").key
    with pytest.raises(AuthorizationError):
        gw.open_session(issued.cert, wrong_key)


def test_expired_certificate_is_rejected():
    ca, store, gw = make_gateway()
    issued = ca.issue_agent(mode="external", lifetime_minutes=-1, backdate_minutes=5)
    with pytest.raises(AuthorizationError):
        gw.open_session(issued.cert, issued.key)


def test_wrong_issuer_is_rejected():
    ca, store, gw = make_gateway()
    other = ResearchCA.create().issue_agent(mode="external")
    with pytest.raises(AuthorizationError):
        gw.open_session(other.cert, other.key)


def test_ca_certificate_is_rejected_as_agent():
    ca, store, gw = make_gateway()
    with pytest.raises(AuthorizationError):
        gw.open_session(ca.cert, ca.key)


def test_wrong_trust_domain_is_rejected():
    ca, store, gw = make_gateway()
    issued = ca.issue_agent(mode="external", agent_uri="spiffe://evil.example/agent/test")
    with pytest.raises(AuthorizationError):
        gw.open_session(issued.cert, issued.key)


def test_multiple_uri_sans_are_rejected():
    ca, store, gw = make_gateway()
    issued = ca.issue_agent(
        mode="external",
        extra_uri_sans=["spiffe://seminar.fisk.edu/agent/second"],
    )
    with pytest.raises(AuthorizationError):
        gw.open_session(issued.cert, issued.key)


def test_external_policy_narrowing_applies_without_reissue():
    ca, store, gw = make_gateway()
    issued = ca.issue_agent(mode="external")
    session = gw.open_session(issued.cert, issued.key)
    request = REQUESTS[0][1]
    assert gw.authorize(session, request)[0] is True
    store.replace_agent_policy(AGENT_URI, {"permissions": []})
    assert gw.authorize(session, request)[0] is False


def test_certificate_policy_is_static_during_cert_lifetime():
    ca, store, gw = make_gateway()
    issued = ca.issue_agent(mode="certificate", permissions=deepcopy(BASE_POLICY["permissions"]))
    session = gw.open_session(issued.cert, issued.key)
    request = REQUESTS[0][1]
    assert gw.authorize(session, request)[0] is True
    store.replace_agent_policy(AGENT_URI, {"permissions": []})
    assert gw.authorize(session, request)[0] is True


def test_hybrid_ceiling_allows_dynamic_narrowing():
    ca, store, gw = make_gateway()
    issued = ca.issue_agent(
        mode="hybrid_ceiling",
        policy_id="research-policy-v1",
        max_permissions=deepcopy(BASE_POLICY["permissions"]),
    )
    session = gw.open_session(issued.cert, issued.key)
    request = REQUESTS[0][1]
    assert gw.authorize(session, request)[0] is True
    store.replace_named_policy("research-policy-v1", {"permissions": []})
    assert gw.authorize(session, request)[0] is False


def test_hybrid_ceiling_blocks_dynamic_privilege_expansion():
    ca, store, gw = make_gateway()
    issued = ca.issue_agent(
        mode="hybrid_ceiling",
        policy_id="research-policy-v1",
        max_permissions=deepcopy(BASE_POLICY["permissions"]),
    )
    session = gw.open_session(issued.cert, issued.key)
    store.replace_named_policy("research-policy-v1", {"permissions": [
        {"tool": "shell", "action": "execute", "resource_prefix": "/bin"}
    ]})
    allowed, reason = gw.authorize(session, {"tool": "shell", "action": "execute", "resource": "/bin/sh"})
    assert allowed is False
    assert reason == "outside_signed_ceiling"


def test_plain_hybrid_accepts_live_policy_expansion():
    ca, store, gw = make_gateway()
    issued = ca.issue_agent(mode="hybrid", policy_id="research-policy-v1")
    session = gw.open_session(issued.cert, issued.key)
    store.replace_named_policy("research-policy-v1", {"permissions": [
        {"tool": "shell", "action": "execute", "resource_prefix": "/bin"}
    ]})
    assert gw.authorize(session, {"tool": "shell", "action": "execute", "resource": "/bin/sh"})[0] is True


def test_kill_registry_denies_next_request():
    ca, store, gw = make_gateway()
    issued = ca.issue_agent(mode="external")
    session = gw.open_session(issued.cert, issued.key)
    assert gw.authorize(session, REQUESTS[0][1])[0] is True
    gw.kill(session)
    allowed, reason = gw.authorize(session, REQUESTS[0][1])
    assert allowed is False
    assert reason == "session_revoked"


def test_audit_event_is_recorded():
    ca, store, gw = make_gateway()
    issued = ca.issue_agent(mode="external")
    session = gw.open_session(issued.cert, issued.key)
    gw.authorize(session, REQUESTS[0][1])
    assert len(gw.audit_log) == 1
    event = gw.audit_log[0]
    assert event["decision"] == "ALLOW"
    assert event["agent_id"] == AGENT_URI
