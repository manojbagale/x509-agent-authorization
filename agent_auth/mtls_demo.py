from __future__ import annotations

import json
import queue
import socket
import ssl
import tempfile
import threading
import time
from copy import deepcopy
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from agent_auth.pki import AGENT_URI, ResearchCA
from agent_auth.approval import ApprovedIssuer, PermissionAuthority
from agent_auth.gateway import AuthorizationGateway, PolicyStore
from agent_auth.experiment import BASE_POLICY
from agent_auth.tool_dispatch import FileToolDispatcher, ToolDispatchError

MAX_FRAME_BYTES = 16384
IO_TIMEOUT_SECONDS = 5


def _write(path: Path, data: bytes) -> str:
    path.write_bytes(data)
    return str(path)


def _read_frame(stream) -> dict:
    """Bounded newline-delimited JSON; malformed requests never reach a tool."""
    frame = stream.readline(MAX_FRAME_BYTES + 1)
    if not frame or len(frame) > MAX_FRAME_BYTES or not frame.endswith(b"\n"):
        raise ValueError("missing, unterminated, or oversized JSON frame")
    value = json.loads(frame)
    if not isinstance(value, dict):
        raise ValueError("JSON frame must be an object")
    return value


def _write_frame(stream, value: dict) -> None:
    frame = (json.dumps(value, separators=(",", ":")) + "\n").encode("utf-8")
    if len(frame) > MAX_FRAME_BYTES:
        raise ValueError("response frame too large")
    stream.write(frame)
    stream.flush()


def _valid_request(request: dict) -> bool:
    return set(request) == {"tool", "action", "resource"} and all(
        isinstance(value, str) and 0 < len(value) <= 2048 for value in request.values()
    )


def run_mtls_demo() -> dict:
    """Exercise seven tool calls on one authenticated TLS 1.3 connection.

    Trusted harness events change policy/kill state outside the client protocol.
    This is a local custom JSON file-tool demo, not a complete MCP/LLM integration,
    a distributed revocation service, or an OS/network sandbox for agent code.
    """
    ca = ResearchCA.create()
    store = PolicyStore({
        "agents": {AGENT_URI: deepcopy(BASE_POLICY)},
        "named_policies": {"research-policy-v1": deepcopy(BASE_POLICY)},
    })
    gateway = AuthorizationGateway(ca, store)
    authority = PermissionAuthority.create(allowed_permissions=BASE_POLICY["permissions"])
    grant = authority.approve(agent_id=AGENT_URI, requested_permissions=BASE_POLICY["permissions"])
    issuer = ApprovedIssuer(ca, authority.public_key, authority.owner_id)
    client = issuer.issue_agent(grant, mode="hybrid_ceiling", policy_store=store)
    server = ca.issue_server(dns_name="localhost")
    read = {"tool": "file", "action": "read", "resource": "/research/paper.txt"}
    requests = [
        ("approved_read", read),
        ("unauthorized_shell", {"tool": "shell", "action": "execute", "resource": "/bin/sh"}),
        ("unauthorized_path", {"tool": "file", "action": "read", "resource": "/research/../secret.txt"}),
        ("policy_narrowed", read),
        ("policy_restored", read),
        ("revoked_next_call", read),
        ("revoked_repeated_call", read),
    ]
    # Only the trusted test harness holds these events. No request field or
    # endpoint can change permissions or revoke a session.
    control_requested = {name: threading.Event() for name in ("narrow", "restore", "kill")}
    control_committed = {name: threading.Event() for name in control_requested}
    controls_after_request = {2: "narrow", 3: "restore", 4: "kill"}
    ready = threading.Event()
    errors: queue.Queue = queue.Queue()
    server_result: dict = {}
    client_responses = []
    client_receive_ns = []

    with tempfile.TemporaryDirectory() as temp_dir:
        td = Path(temp_dir)
        tool_root = td / "server-private"
        tool_root.mkdir()
        (tool_root / "paper.txt").write_text("Server-private research note: certificate identity is not permission.\n")
        (td / "secret.txt").write_text("OUTSIDE TOOL ROOT: must never be returned")
        ca_file = _write(td / "ca.pem", ca.cert.public_bytes(serialization.Encoding.PEM))
        server_cert = _write(td / "server.pem", server.pem)
        server_key = _write(td / "server-key.pem", server.key_pem)
        client_cert = _write(td / "client.pem", client.pem)
        client_key = _write(td / "client-key.pem", client.key_pem)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.settimeout(IO_TIMEOUT_SECONDS)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def server_thread():
            dispatcher = None
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
                context.load_cert_chain(server_cert, server_key)
                context.load_verify_locations(cafile=ca_file)
                context.verify_mode = ssl.CERT_REQUIRED
                dispatcher = FileToolDispatcher(tool_root)
                ready.set()
                raw, _ = listener.accept()
                with raw:
                    raw.settimeout(IO_TIMEOUT_SECONDS)
                    with context.wrap_socket(raw, server_side=True) as tls:
                        peer = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
                        session = gateway.open_mtls_session(peer)
                        server_result.update({
                            "tls_version": tls.version(), "cipher": tls.cipher()[0],
                            "agent_id": session.agent_id, "connection_count": 1,
                            "handshake_count": 1, "responses": [], "calls": [],
                        })
                        with tls.makefile("rwb") as stream:
                            for index, (label, _) in enumerate(requests):
                                request = _read_frame(stream)
                                before = dispatcher.dispatch_count
                                decision_started_ns = time.monotonic_ns()
                                if _valid_request(request):
                                    authorized, reason = gateway.authorize(session, request)
                                else:
                                    authorized, reason = False, "malformed_request"
                                decision_ns = time.monotonic_ns()
                                response = {"allowed": authorized, "reason": reason}
                                if authorized:
                                    try:
                                        response["output"] = dispatcher.execute(request)
                                    except ToolDispatchError as exc:
                                        response = {"allowed": False, "reason": str(exc), "authorization_allowed": True}
                                response["dispatch_count"] = dispatcher.dispatch_count
                                _write_frame(stream, response)
                                reply_sent_ns = time.monotonic_ns()
                                server_result["responses"].append(response)
                                server_result["calls"].append({
                                    "case": label, "request": request, "allowed": response["allowed"],
                                    "reason": response["reason"], "dispatch_count_before": before,
                                    "dispatch_count_after": dispatcher.dispatch_count,
                                    "decision_started_ns": decision_started_ns,
                                    "decision_ns": decision_ns, "reply_sent_ns": reply_sent_ns,
                                })
                                if index in controls_after_request:
                                    control = controls_after_request[index]
                                    if not control_requested[control].wait(IO_TIMEOUT_SECONDS):
                                        raise TimeoutError("trusted harness control did not arrive")
                                    if control == "narrow":
                                        store.replace_named_policy("research-policy-v1", {"permissions": []})
                                    elif control == "restore":
                                        store.replace_named_policy("research-policy-v1", deepcopy(BASE_POLICY))
                                    else:
                                        # The immediately preceding read must have executed.
                                        if not response["allowed"] or dispatcher.dispatch_count != 2:
                                            raise AssertionError("revocation timing requires an allowed precondition")
                                        gateway.kill(session)
                                        server_result["kill_committed_ns"] = time.monotonic_ns()
                                        server_result["revocation_precondition_allowed"] = True
                                    control_committed[control].set()
                        server_result["dispatch_count"] = dispatcher.dispatch_count
                        server_result["audit_log"] = deepcopy(gateway.audit_log)
            except BaseException as exc:
                errors.put(exc)
                ready.set()
                for event in control_committed.values():
                    event.set()
            finally:
                if dispatcher is not None:
                    dispatcher.close()
                listener.close()

        thread = threading.Thread(target=server_thread, daemon=True)
        thread.start()
        client_error = None
        try:
            if not ready.wait(IO_TIMEOUT_SECONDS):
                raise TimeoutError("TLS server did not start")
            if not errors.empty():
                raise RuntimeError("TLS server failed") from errors.get()
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
            context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.load_cert_chain(client_cert, client_key)
            with socket.create_connection(("127.0.0.1", port), timeout=IO_TIMEOUT_SECONDS) as raw:
                with context.wrap_socket(raw, server_hostname="localhost") as tls:
                    client_tls_version = tls.version()
                    with tls.makefile("rwb") as stream:
                        for index, (_, request) in enumerate(requests):
                            _write_frame(stream, request)
                            client_responses.append(_read_frame(stream))
                            client_receive_ns.append(time.monotonic_ns())
                            if index in controls_after_request:
                                control = controls_after_request[index]
                                control_requested[control].set()
                                if not control_committed[control].wait(IO_TIMEOUT_SECONDS):
                                    raise TimeoutError("trusted mutation did not commit")
                                if not errors.empty():
                                    raise RuntimeError("TLS server failed") from errors.get()
        except BaseException as exc:
            client_error = exc
        finally:
            for event in control_requested.values():
                event.set()
            thread.join(IO_TIMEOUT_SECONDS + 1)
            listener.close()
        if thread.is_alive():
            raise TimeoutError("TLS server did not terminate")
        if not errors.empty():
            raise RuntimeError("TLS server failed") from errors.get()
        if client_error is not None:
            raise client_error

    revoked = server_result["calls"][5]
    committed = server_result["kill_committed_ns"]
    return {
        "server": server_result, "client_responses": client_responses,
        "client_tls_version": client_tls_version,
        "approval": grant.public_record(),
        "issuance": issuer.issuance_log[0],
        "mTLS_client_certificate_required": True,
        "revocation_timing": {
            "clock": "time.monotonic_ns on one host",
            "kill_to_next_decision_ms": (revoked["decision_ns"] - committed) / 1_000_000,
            "kill_to_reply_sent_ms": (revoked["reply_sent_ns"] - committed) / 1_000_000,
            "kill_to_client_receive_ms": (client_receive_ns[5] - committed) / 1_000_000,
            "next_call_decision_ms": (revoked["decision_ns"] - revoked["decision_started_ns"]) / 1_000_000,
            "interpretation": "One local sample includes harness scheduling and next-call transport; it is not a distributed revocation bound.",
        },
        "limitations": [
            "Single host, trusted harness, one gateway, custom JSON protocol; no MCP or LLM runtime.",
            "The client must not have direct access to the server private root in a deployment; this demo does not provide OS/network isolation.",
            "Revocation blocks subsequent admitted calls, not an operation already executing.",
        ],
    }


if __name__ == "__main__":
    print(json.dumps(run_mtls_demo(), indent=2))
