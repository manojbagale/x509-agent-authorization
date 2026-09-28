from __future__ import annotations

import json
import socket
import ssl
import tempfile
import threading
from copy import deepcopy
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from agent_auth.pki import AGENT_URI, ResearchCA
from agent_auth.gateway import AuthorizationGateway, PolicyStore
from agent_auth.experiment import BASE_POLICY


def _write(path: Path, data: bytes) -> str:
    path.write_bytes(data)
    return str(path)


def run_mtls_demo() -> dict:
    """Run a real localhost mTLS handshake and two application authorization checks."""
    ca = ResearchCA.create()
    store = PolicyStore({
        "agents": {AGENT_URI: deepcopy(BASE_POLICY)},
        "named_policies": {"research-policy-v1": deepcopy(BASE_POLICY)},
    })
    gateway = AuthorizationGateway(ca, store)

    client = ca.issue_agent(
        mode="hybrid_ceiling",
        policy_id="research-policy-v1",
        max_permissions=deepcopy(BASE_POLICY["permissions"]),
    )
    server = ca.issue_server(dns_name="localhost")

    allowed_request = {"tool": "file", "action": "read", "resource": "/research/paper.pdf"}
    denied_request = {"tool": "shell", "action": "execute", "resource": "/bin/sh"}
    server_result: dict = {}
    ready = threading.Event()

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        ca_file = _write(td / "ca.pem", ca.cert.public_bytes(serialization.Encoding.PEM))
        server_cert = _write(td / "server.pem", server.pem)
        server_key = _write(td / "server-key.pem", server.key_pem)
        client_cert = _write(td / "client.pem", client.pem)
        client_key = _write(td / "client-key.pem", client.key_pem)

        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_sock.bind(("127.0.0.1", 0))
        listen_sock.listen(1)
        port = listen_sock.getsockname()[1]

        def server_thread():
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(server_cert, server_key)
            context.load_verify_locations(cafile=ca_file)
            context.verify_mode = ssl.CERT_REQUIRED
            ready.set()
            raw, _ = listen_sock.accept()
            try:
                with context.wrap_socket(raw, server_side=True) as tls:
                    peer_der = tls.getpeercert(binary_form=True)
                    peer_cert = x509.load_der_x509_certificate(peer_der)
                    session = gateway.open_mtls_session(peer_cert)
                    fp = tls.makefile("rwb")
                    responses = []
                    for _ in range(2):
                        req = json.loads(fp.readline().decode("utf-8"))
                        allowed, reason = gateway.authorize(session, req)
                        response = {"allowed": allowed, "reason": reason}
                        fp.write((json.dumps(response) + "\n").encode("utf-8"))
                        fp.flush()
                        responses.append(response)
                    server_result.update({
                        "tls_version": tls.version(),
                        "cipher": tls.cipher()[0],
                        "agent_id": session.agent_id,
                        "responses": responses,
                    })
            finally:
                listen_sock.close()

        t = threading.Thread(target=server_thread, daemon=True)
        t.start()
        ready.wait(timeout=2)

        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(client_cert, client_key)
        with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname="localhost") as tls:
                fp = tls.makefile("rwb")
                client_responses = []
                for req in (allowed_request, denied_request):
                    fp.write((json.dumps(req) + "\n").encode("utf-8"))
                    fp.flush()
                    client_responses.append(json.loads(fp.readline().decode("utf-8")))
        t.join(timeout=3)

    return {
        "server": server_result,
        "client_responses": client_responses,
        "mTLS_client_certificate_required": True,
    }


if __name__ == "__main__":
    print(json.dumps(run_mtls_demo(), indent=2))
