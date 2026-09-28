from agent_auth.mtls_demo import run_mtls_demo


def test_real_mtls_handshake_and_gateway_authorization():
    result = run_mtls_demo()
    assert result["mTLS_client_certificate_required"] is True
    assert result["server"]["agent_id"].startswith("spiffe://seminar.fisk.edu/agent/")
    assert result["client_responses"][0]["allowed"] is True
    assert result["client_responses"][1]["allowed"] is False
