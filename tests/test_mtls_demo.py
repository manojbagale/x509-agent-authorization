import io
import ssl

import pytest

from agent_auth.mtls_demo import MAX_FRAME_BYTES, _read_frame, _valid_request, run_mtls_demo
from agent_auth import mtls_demo


def test_real_mtls_persistent_tool_dispatch_policy_changes_and_revocation():
    result = run_mtls_demo()
    server = result["server"]
    assert result["mTLS_client_certificate_required"] is True
    assert server["agent_id"].startswith("spiffe://seminar.fisk.edu/agent/")
    assert server["tls_version"] == result["client_tls_version"] == "TLSv1.3"
    assert server["connection_count"] == server["handshake_count"] == 1
    responses = result["client_responses"]
    assert responses == server["responses"]
    assert [r["allowed"] for r in responses] == [True, False, False, False, True, False, False]
    assert responses[0]["output"]["content"].startswith("Server-private research note:")
    assert responses[4]["output"] == responses[0]["output"]
    assert [r["dispatch_count"] for r in responses] == [1, 1, 1, 1, 2, 2, 2]
    assert responses[5]["reason"] == responses[6]["reason"] == "session_revoked"
    assert server["revocation_precondition_allowed"] is True
    assert server["dispatch_count"] == 2
    for call in server["calls"]:
        if not call["allowed"]:
            assert call["dispatch_count_after"] == call["dispatch_count_before"]
    assert len(server["audit_log"]) == 7
    assert [r["decision"] for r in server["audit_log"]] == ["ALLOW", "DENY", "DENY", "DENY", "ALLOW", "DENY", "DENY"]
    timing = result["revocation_timing"]
    assert 0 <= timing["next_call_decision_ms"] <= timing["kill_to_next_decision_ms"]
    assert timing["kill_to_next_decision_ms"] <= timing["kill_to_client_receive_ms"]
    assert timing["kill_to_next_decision_ms"] <= timing["kill_to_reply_sent_ms"]
    # Client receive and post-flush server timestamps can race, so no ordering
    # assertion between those two observations is valid.


@pytest.mark.parametrize("frame", [b"", b"{}", b"[]\n", b"bad-json\n", b"x" * (MAX_FRAME_BYTES + 1) + b"\n"])
def test_protocol_rejects_eof_partial_nonobject_malformed_and_oversized(frame):
    with pytest.raises(ValueError):
        _read_frame(io.BytesIO(frame))


def test_request_schema_has_no_client_administration_commands():
    assert not _valid_request({"admin": "kill"})
    assert not _valid_request({"tool": "file", "action": "read", "resource": 42})
    assert not _valid_request({"tool": "file", "action": "read", "resource": "/research/paper.txt", "admin": "restore"})


def test_network_rejects_client_without_certificate_and_propagates_server_error(monkeypatch):
    original = ssl.create_default_context

    def omit_client_certificate(*args, **kwargs):
        context = original(*args, **kwargs)
        context.load_cert_chain = lambda *args, **kwargs: None
        return context

    monkeypatch.setattr(mtls_demo.ssl, "create_default_context", omit_client_certificate)
    with pytest.raises(RuntimeError, match="TLS server failed") as failure:
        run_mtls_demo()
    assert isinstance(failure.value.__cause__, ssl.SSLError)
    assert "PEER_DID_NOT_RETURN_A_CERTIFICATE" in str(failure.value.__cause__)
