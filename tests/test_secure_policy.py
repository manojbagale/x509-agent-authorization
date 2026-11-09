"""TLS trust, restart state and concurrent version regressions."""
import concurrent.futures as futures
import sqlite3
import threading
from dataclasses import replace

import pytest

from agent_auth.gateway import AuthorizationGateway
from agent_auth.pki import AGENT_URI, ResearchCA
from agent_auth.policy import PolicyServiceError
from agent_auth.policy_service import PolicyService, RemotePolicyClient
from agent_auth.policy_state import PolicyState, PolicyStateError, PolicyConflict
from agent_auth.scenarios import BASE_POLICY, REQUESTS, issue_for_mode, make_store
from agent_auth.service_tls import ServiceTLS
from agent_auth.mtls_demo import run_mtls_demo


def session_and_gateway(service, mode="hybrid_ceiling"):
    ca = ResearchCA.create()
    gateway = AuthorizationGateway(ca, make_store(), policy_decider=service.client)
    issued = issue_for_mode(ca, mode)
    return gateway, gateway.open_session(issued.cert, issued.key)


@pytest.fixture
def secure(tmp_path):
    config = ServiceTLS.create(tmp_path/"tls")
    with PolicyService(AGENT_URI, "research-policy-v1", BASE_POLICY,
                       tls=config, state_path=tmp_path/"policy.db") as service:
        yield service


@pytest.mark.parametrize("mode", ["external", "hybrid", "hybrid_ceiling"])
def test_same_matrix_over_mutual_tls(secure, mode):
    gateway, session = session_and_gateway(secure, mode)
    for _, request, expected in REQUESTS:
        assert gateway.authorize(session, request)[0] is expected
    reply = secure.client.evaluate_details(session, REQUESTS[0][1])
    assert reply == {"decision": True, "policy_version": 1, "tls_version": "TLSv1.3"}


@pytest.mark.parametrize("case", ["missing_client", "untrusted_client", "untrusted_server", "wrong_token"])
def test_tls_and_service_identity_reject_bad_peer(secure, tmp_path, case):
    gateway, session = session_and_gateway(secure)
    other = ServiceTLS.create(tmp_path/"other")
    context = secure.tls.client_context(include_certificate=case != "missing_client")
    if case == "untrusted_client":
        context.load_cert_chain(other.client_cert, other.client_key)
    if case == "untrusted_server":
        context = other.client_context()
        context.load_cert_chain(secure.tls.client_cert, secure.tls.client_key)
    gateway.policy_decider = RemotePolicyClient(
        f"https://localhost:{secure.client.port}",
        "wrong" if case == "wrong_token" else secure.client.token, ssl_context=context)
    assert gateway.authorize(session, REQUESTS[0][1]) == (False, "policy_unavailable")
    assert gateway.audit_log[-1]["decision"] == "DENY"


@pytest.mark.parametrize("case", ["hostname", "pin"])
def test_hostname_and_exact_gateway_certificate_are_checked(tmp_path, case):
    config = ServiceTLS.create(tmp_path/"tls", server_name="wrong.example" if case == "hostname" else "localhost")
    if case == "pin":
        config = replace(config, client_fingerprint="0"*64)
    with PolicyService(AGENT_URI, "research-policy-v1", BASE_POLICY, tls=config) as service:
        gateway, session = session_and_gateway(service)
        assert gateway.authorize(session, REQUESTS[0][1]) == (False, "policy_unavailable")


def test_restricted_policy_survives_abrupt_process_death(secure):
    gateway, session = session_and_gateway(secure)
    assert gateway.authorize(session, REQUESTS[0][1])[0]
    assert secure.replace_policy({"permissions": []}, expected_version=1) == 2
    previous_pid = secure.process.pid
    secure.process.terminate(); secure.process.join(2); secure.pipe.close()
    secure.__enter__()
    gateway.policy_decider = secure.client
    assert secure.process.pid != previous_pid
    assert secure.version == 2
    assert gateway.authorize(session, REQUESTS[0][1]) == (False, "outside_scope")
    with pytest.raises(PolicyConflict):
        secure.replace_policy(BASE_POLICY, expected_version=1)
    assert secure.replace_policy(BASE_POLICY, expected_version=2) == 3
    assert gateway.authorize(session, REQUESTS[0][1])[0]


def test_persistent_update_requires_an_explicit_version(secure):
    with pytest.raises(PolicyStateError):
        secure.replace_policy(BASE_POLICY)
    assert secure.version == 1


def test_failed_sql_update_does_not_acknowledge_or_change_policy(secure):
    with sqlite3.connect(secure.state_path) as db:
        db.execute("CREATE TRIGGER refuse_update BEFORE UPDATE ON policy BEGIN SELECT RAISE(ABORT, 'blocked'); END")
    with pytest.raises(PolicyStateError):
        secure.replace_policy({"permissions": []}, expected_version=1)
    assert secure.version == 1
    _, session = session_and_gateway(secure)
    assert secure.client.evaluate(session, REQUESTS[0][1])


def test_missing_runtime_record_denies_instead_of_using_initial_grant(secure):
    gateway, session = session_and_gateway(secure)
    with sqlite3.connect(secure.state_path) as db:
        db.execute("DELETE FROM policy")
    assert gateway.authorize(session, REQUESTS[0][1]) == (False, "policy_unavailable")


@pytest.mark.parametrize("bad", ["binding", "json", "database", "missing", "permissions"])
def test_invalid_persistent_state_fails_startup(tmp_path, bad):
    path = tmp_path/"policy.db"
    PolicyState(path, AGENT_URI, "research-policy-v1", BASE_POLICY)
    if bad == "database":
        path.write_bytes(b"not a SQLite database")
    else:
        with sqlite3.connect(path) as db:
            if bad == "binding":
                db.execute("UPDATE policy SET agent_id='other'")
            elif bad == "missing":
                db.execute("DELETE FROM policy")
            elif bad == "permissions":
                db.execute("UPDATE policy SET permissions='{}'")
            else:
                db.execute("UPDATE policy SET permissions='not json'")
    with pytest.raises(RuntimeError, match="startup failed"):
        with PolicyService(AGENT_URI, "research-policy-v1", BASE_POLICY, state_path=path):
            pass


def test_two_writers_with_same_expected_version_have_one_winner(tmp_path):
    path = tmp_path/"policy.db"
    stores = [PolicyState(path, AGENT_URI, "research-policy-v1", BASE_POLICY) for _ in range(2)]
    barrier = threading.Barrier(2)
    def update(store):
        barrier.wait(timeout=3)
        try:
            return store.replace({"permissions": []}, expected_version=1)
        except PolicyConflict:
            return "conflict"
    with futures.ThreadPoolExecutor(2) as pool:
        outcomes = list(pool.map(update, stores))
    assert outcomes.count(2) == outcomes.count("conflict") == 1
    assert stores[0].snapshot() == {"version": 2, "permissions": []}


def test_concurrent_decisions_observe_committed_version(secure):
    _, session = session_and_gateway(secure)
    def call(_):
        return secure.client.evaluate_details(session, REQUESTS[0][1])
    with futures.ThreadPoolExecutor(8) as pool:
        before = list(pool.map(call, range(80)))
        secure.replace_policy({"permissions": []}, expected_version=1)
        after = list(pool.map(call, range(80)))
    assert all(r["decision"] and r["policy_version"] == 1 for r in before)
    assert all(not r["decision"] and r["policy_version"] == 2 for r in after)
    assert secure.client.calls == 160


@pytest.mark.parametrize("fault", ["http_error", "timeout", "malformed", "duplicate", "oversized"])
def test_secure_path_retains_failure_denial_and_recovers(secure, fault):
    gateway, session = session_and_gateway(secure)
    assert gateway.authorize(session, REQUESTS[0][1])[0]
    secure.set_fault(fault)
    assert gateway.authorize(session, REQUESTS[0][1]) == (False, "policy_unavailable")
    secure.set_fault(None)
    assert gateway.authorize(session, REQUESTS[0][1])[0]


def test_plain_http_does_not_work_against_tls_listener(secure):
    gateway, session = session_and_gateway(secure)
    gateway.policy_decider = RemotePolicyClient(f"http://127.0.0.1:{secure.client.port}", secure.client.token)
    assert gateway.authorize(session, REQUESTS[0][1]) == (False, "policy_unavailable")


def test_secure_policy_demo_preserves_real_tool_dispatch(tmp_path):
    config = ServiceTLS.create(tmp_path/"tls")
    with PolicyService(AGENT_URI, "research-policy-v1", BASE_POLICY, tls=config) as service:
        result = run_mtls_demo(policy_service=service)
    server = result["server"]
    assert server["dispatch_count"] == 3
    assert server["connection_count"] == server["handshake_count"] == 1
    assert len(server["calls"]) == 13
    assert sum(c["allowed"] for c in server["calls"]) == 3
    assert all(c["dispatch_count_before"] == c["dispatch_count_after"] for c in server["calls"] if not c["allowed"])
