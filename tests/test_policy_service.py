"""Real process and HTTP regressions for the optional remote decision path."""
import datetime as dt
import http.client
import os
from dataclasses import replace

import pytest

from agent_auth.gateway import AuthorizationGateway
from agent_auth.mtls_demo import run_mtls_demo
from agent_auth.pki import AGENT_URI, ResearchCA
from agent_auth.policy import PolicyServiceError
from agent_auth.policy_service import MAX_BODY, PolicyService, RemotePolicyClient, strict_json
from agent_auth.scenarios import BASE_POLICY, REQUESTS, issue_for_mode, make_store


@pytest.fixture
def service():
    with PolicyService(AGENT_URI, "research-policy-v1", BASE_POLICY) as server:
        yield server


def gateway(service, mode="hybrid_ceiling", **kwargs):
    ca = ResearchCA.create()
    g = AuthorizationGateway(ca, make_store(), policy_decider=service.client, **kwargs)
    issued = issue_for_mode(ca, mode)
    return g, g.open_session(issued.cert, issued.key)


@pytest.mark.parametrize("mode", ["external", "hybrid", "hybrid_ceiling"])
def test_same_request_matrix_over_http(service, mode):
    g, session = gateway(service, mode)
    assert service.process.pid != os.getpid()
    for _, request, expected in REQUESTS:
        assert g.authorize(session, request)[0] is expected
    assert len(g.audit_log) == 10
    assert service.client.calls == 10


def test_live_policy_change_has_no_allow_cache(service):
    g, session = gateway(service)
    assert g.authorize(session, REQUESTS[0][1])[0]
    service.replace_policy({"permissions": []})
    assert g.authorize(session, REQUESTS[0][1]) == (False, "outside_scope")
    service.replace_policy(BASE_POLICY)
    assert g.authorize(session, REQUESTS[0][1])[0]
    assert service.client.calls == 3


@pytest.mark.parametrize("mode,expected", [("external", True), ("hybrid", True), ("hybrid_ceiling", False)])
def test_remote_expansion_does_not_override_signed_ceiling(service, mode, expected):
    g, session = gateway(service, mode)
    service.replace_policy({"permissions": [{"tool": "shell", "action": "execute", "resource_prefix": "/bin"}]})
    request = {"tool": "shell", "action": "execute", "resource": "/bin/sh"}
    assert service.client.evaluate(session, request) is True
    allowed, reason = g.authorize(session, request)
    assert allowed is expected
    if not expected:
        assert reason == "outside_signed_ceiling"


@pytest.mark.parametrize("fault", ["http_error", "timeout", "malformed", "duplicate", "oversized"])
def test_fault_denies_and_recovers_without_cached_allow(service, fault):
    g, session = gateway(service)
    assert g.authorize(session, REQUESTS[0][1])[0]
    service.set_fault(fault)
    assert g.authorize(session, REQUESTS[0][1]) == (False, "policy_unavailable")
    assert g.audit_log[-1]["decision"] == "DENY"
    service.set_fault(None)
    assert g.authorize(session, REQUESTS[0][1])[0]


def test_stopped_service_denies_existing_session(service):
    g, session = gateway(service)
    assert g.authorize(session, REQUESTS[0][1])[0]
    service.stop()
    assert g.authorize(session, REQUESTS[0][1]) == (False, "policy_unavailable")


def test_kill_and_expiry_are_checked_before_remote_call(service):
    now = [dt.datetime.now(dt.timezone.utc)]
    g, session = gateway(service, clock=lambda: now[0])
    g.kill(session)
    assert g.authorize(session, REQUESTS[0][1]) == (False, "session_revoked")
    assert service.client.calls == 0
    g.kill_registry.clear()
    now[0] = session.cert.not_valid_after_utc + dt.timedelta(seconds=1)
    assert g.authorize(session, REQUESTS[0][1]) == (False, "certificate_expired")
    assert service.client.calls == 0


def test_certificate_native_mode_remains_independent_of_service(service):
    g, session = gateway(service, "certificate")
    service.stop()
    assert g.authorize(session, REQUESTS[0][1])[0]
    assert service.client.calls == 0


@pytest.mark.parametrize("change", [{"agent_id": "spiffe://other/agent/unapproved"}, {"policy_id": "unapproved-policy"}])
def test_service_binds_subject_and_policy_reference(service, change):
    _, session = gateway(service)
    assert service.client.evaluate(replace(session, **change), REQUESTS[0][1]) is False


def test_wrong_service_token_fails_closed(service):
    g, session = gateway(service)
    g.policy_decider = RemotePolicyClient(f"http://127.0.0.1:{service.client.port}", "wrong-token")
    assert g.authorize(session, REQUESTS[0][1]) == (False, "policy_unavailable")


@pytest.mark.parametrize("body", [b'{}', b'[]', b'{"subject":null}', b'x' * (MAX_BODY + 1)])
def test_service_rejects_invalid_request_without_crashing(service, body):
    c = http.client.HTTPConnection("127.0.0.1", service.client.port, timeout=1)
    c.request("POST", "/access/v1/evaluation", body, {"Authorization": "Bearer " + service.client.token, "Content-Type": "application/json"})
    assert c.getresponse().status == 400
    c.close()
    g, session = gateway(service)
    assert g.authorize(session, REQUESTS[0][1])[0]


@pytest.mark.parametrize("endpoint", ["http://example.com:80", "http://localhost:80", "http://127.0.0.1:80/path", "http://user:pass@127.0.0.1:80"])
def test_unprotected_transport_is_restricted_to_explicit_loopback(endpoint):
    with pytest.raises(ValueError):
        RemotePolicyClient(endpoint, "token")


def test_duplicate_decisions_are_rejected():
    with pytest.raises(ValueError):
        strict_json(b'{"decision":false,"decision":true}')


def test_remote_demo_keeps_one_tls_session_and_never_dispatches_denials(service):
    result = run_mtls_demo(policy_service=service)
    s = result["server"]
    assert s["connection_count"] == s["handshake_count"] == 1
    assert len(result["policy_service_pids"]) == 2
    assert [r["allowed"] for r in s["calls"]] == [True, False, False, False, True, False, False, False, False, False, True, False, False]
    assert s["dispatch_count"] == 3
    for call in s["calls"]:
        if not call["allowed"]:
            assert call["dispatch_count_before"] == call["dispatch_count_after"]
    assert s["calls"][5]["reason"] == "outside_signed_ceiling"
    assert [c["reason"] for c in s["calls"][6:10]] == ["policy_unavailable"] * 4
    assert s["calls"][11]["reason"] == s["calls"][12]["reason"] == "session_revoked"
    assert len(s["audit_log"]) == 13


@pytest.mark.parametrize("event", ["kill", "expire"])
def test_lifecycle_change_during_remote_decision_is_rechecked(service, monkeypatch, event):
    now = [dt.datetime.now(dt.timezone.utc)]
    g, session = gateway(service, clock=lambda: now[0])
    def delayed_decision(*args):
        if event == "kill":
            g.kill(session)
        else:
            now[0] = session.cert.not_valid_after_utc + dt.timedelta(seconds=1)
        return True
    monkeypatch.setattr(service.client, "evaluate", delayed_decision)
    assert g.authorize(session, REQUESTS[0][1]) == (
        False, "session_revoked" if event == "kill" else "certificate_expired")
