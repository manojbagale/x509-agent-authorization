"""Loopback policy decision service with HTTP and mutual-TLS lab profiles.

The JSON envelope follows AuthZEN's subject/action/resource vocabulary. This
lab uses a private context schema, not full AuthZEN conformance or a production
server. Administrative changes use an inherited IPC pipe.
"""
from __future__ import annotations

import http.client
import json
import multiprocessing as mp
import secrets
import hashlib
import sqlite3
import ssl
import threading
import time
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from agent_auth.policy import AuthorizationError, PolicyServiceError, matches_permissions, validate_permissions
from agent_auth.policy_state import PolicyState, PolicyStateError, PolicyConflict

MAX_BODY = 16384


def strict_json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON key")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique)


class RemotePolicyClient:
    """One authenticated HTTP request per decision; no retries or allow cache."""
    def __init__(self, endpoint: str, token: str, *, timeout: float = 0.15, ssl_context=None):
        url = urlsplit(endpoint)
        valid_transport = ((url.scheme == "http" and url.hostname == "127.0.0.1" and ssl_context is None)
                           or (url.scheme == "https" and url.hostname == "localhost" and ssl_context is not None
                               and ssl_context.check_hostname and ssl_context.verify_mode == ssl.CERT_REQUIRED))
        if (not valid_transport or not url.port
                or url.path or url.query or url.fragment or url.username or url.password):
            raise ValueError("loopback HTTP or verified https://localhost:port required")
        if not token or timeout <= 0:
            raise ValueError("token and positive socket timeout required")
        self.host, self.port, self.token, self.timeout = url.hostname, url.port, token, timeout
        self.ssl_context = ssl_context
        self.calls = 0
        self._calls_lock = threading.Lock()

    def evaluate(self, session, request: dict) -> bool:
        return self.evaluate_details(session, request)["decision"]

    def evaluate_details(self, session, request: dict) -> dict:
        payload = {
            "subject": {"type": "agent", "id": session.agent_id},
            "action": {"name": request["action"], "properties": {"tool": request["tool"]}},
            "resource": {"type": "path", "id": request["resource"]},
            "context": {"mode": session.mode, "policy_id": session.policy_id},
        }
        body = json.dumps(payload).encode()
        if len(body) > MAX_BODY:
            raise PolicyServiceError("request too large")
        connection = (http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=self.ssl_context)
                      if self.ssl_context else http.client.HTTPConnection(self.host, self.port, timeout=self.timeout))
        with self._calls_lock:
            self.calls += 1
        try:
            connection.request("POST", "/access/v1/evaluation", body=body, headers={
                "Authorization": "Bearer " + self.token, "Content-Type": "application/json",
            })
            tls_version = connection.sock.version() if self.ssl_context else None
            response = connection.getresponse()
            if response.status != 200 or response.getheader("Content-Type", "").split(";")[0] != "application/json":
                raise PolicyServiceError("invalid policy service response")
            raw = response.read(MAX_BODY + 1)
            if len(raw) > MAX_BODY:
                raise PolicyServiceError("response too large")
            result = strict_json(raw)
            if not isinstance(result, dict) or set(result) != {"decision"} or type(result["decision"]) is not bool:
                raise PolicyServiceError("decision must be a JSON boolean")
            policy_version = response.getheader("X-Policy-Version")
            if policy_version is not None and (not policy_version.isdecimal() or int(policy_version) < 1):
                raise PolicyServiceError("invalid policy version")
            return {"decision": result["decision"], "policy_version": int(policy_version) if policy_version else None,
                    "tls_version": tls_version}
        except (OSError, http.client.HTTPException, ValueError, UnicodeError) as exc:
            raise PolicyServiceError("policy service unavailable or invalid") from exc
        finally:
            connection.close()


def _serve(pipe, token, agent_id, policy_id, policy, tls=None, state_path=None):
    lock = threading.Lock()
    state = {"policy": deepcopy(policy), "fault": None, "version": 1}
    try:
        persistent = PolicyState(state_path, agent_id, policy_id, policy) if state_path else None
        tls_context = tls.server_context() if tls else None
    except Exception as exc:
        pipe.send({"error": type(exc).__name__})
        pipe.close()
        return

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def setup(self):
            super().setup()
            self.connection.settimeout(1.0)

        def reply(self, status, body, version=None):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            if version is not None:
                self.send_header("X-Policy-Version", str(version))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass  # Expected after the client's timeout test.

        def do_POST(self):
            if tls and not secrets.compare_digest(
                    hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest(), tls.client_fingerprint):
                self.reply(403, b'{}'); return
            if self.path != "/access/v1/evaluation":
                self.reply(404, b'{}'); return
            if not secrets.compare_digest(self.headers.get("Authorization", ""), "Bearer " + token):
                self.reply(401, b'{}'); return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= MAX_BODY or self.headers.get("Transfer-Encoding"):
                    raise ValueError("invalid body size")
                if self.headers.get("Content-Type") != "application/json":
                    raise ValueError("JSON required")
                data = strict_json(self.rfile.read(length))
                if not isinstance(data, dict) or set(data) != {"subject", "action", "resource", "context"}:
                    raise ValueError("invalid envelope")
                subject, action, resource, context = (data[k] for k in ("subject", "action", "resource", "context"))
                if (set(subject) != {"type", "id"} or subject["type"] != "agent"
                        or set(action) != {"name", "properties"} or set(action["properties"]) != {"tool"}
                        or set(resource) != {"type", "id"} or resource["type"] != "path"
                        or set(context) != {"mode", "policy_id"}):
                    raise ValueError("invalid envelope fields")
                request = {"tool": action["properties"]["tool"], "action": action["name"], "resource": resource["id"]}
                if any(not isinstance(v, str) or not v for v in (*request.values(), subject["id"])):
                    raise ValueError("nonempty strings required")
                mode = context["mode"]
                if mode not in ("external", "hybrid", "hybrid_ceiling"):
                    raise ValueError("unsupported mode")
                bound = subject["id"] == agent_id and (
                    context["policy_id"] is None if mode == "external" else context["policy_id"] == policy_id)
                with lock:
                    snapshot = persistent.snapshot() if persistent else {**deepcopy(state["policy"]), "version": state["version"]}
                    current, fault = snapshot, state["fault"]
                if fault == "timeout":
                    time.sleep(0.4)
                if fault == "http_error":
                    self.reply(503, b'{}'); return
                if fault == "malformed":
                    self.reply(200, b'{"decision":"true"}'); return
                if fault == "duplicate":
                    self.reply(200, b'{"decision":false,"decision":true}'); return
                if fault == "oversized":
                    self.reply(200, b' ' * (MAX_BODY + 1)); return
                decision = bound and matches_permissions(current["permissions"], request)
                self.reply(200, json.dumps({"decision": decision}).encode(), current["version"])
            except (sqlite3.Error, PolicyStateError):
                self.reply(503, b'{}')
            except (ValueError, KeyError, TypeError, AuthorizationError, OSError):
                self.reply(400, b'{}')

    class Server(ThreadingHTTPServer):
        request_queue_size = 64

        def process_request_thread(self, request, client_address):
            if tls_context:
                try:
                    request.settimeout(1.0)
                    request = tls_context.wrap_socket(request, server_side=True)
                except OSError:
                    request.close()
                    return
            super().process_request_thread(request, client_address)

    server = Server(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    pipe.send({"port": server.server_port})
    try:
        while True:
            command, value = pipe.recv()
            if command == "stop":
                break
            try:
                with lock:
                    if command == "policy":
                        policy, expected = value
                        if persistent:
                            version = persistent.replace(policy, expected_version=expected)
                        else:
                            if expected is not None and expected != state["version"]:
                                raise PolicyConflict("stale policy version")
                            state["policy"] = {"permissions": validate_permissions(policy["permissions"])}
                            state["version"] += 1
                            version = state["version"]
                    elif command == "snapshot":
                        version = (persistent.snapshot() if persistent else state)["version"]
                    elif command == "fault":
                        state["fault"] = value
                        version = None
                    else:
                        raise ValueError("unknown control operation")
                pipe.send({"ok": True, "version": version})
            except (ValueError, AuthorizationError, sqlite3.Error) as exc:
                pipe.send({"ok": False, "conflict": isinstance(exc, PolicyConflict), "error": str(exc)})
    finally:
        server.shutdown()
        server.server_close()
        pipe.close()


class PolicyService:
    """Trusted lab harness; controls are never exposed through HTTP."""
    def __init__(self, agent_id: str, policy_id: str, policy: dict, *, tls=None, state_path=None):
        self.policy = {"permissions": validate_permissions(policy["permissions"])}
        self.agent_id, self.policy_id = agent_id, policy_id
        self.process = None
        self.tls, self.state_path = tls, str(state_path) if state_path else None
        self._control_lock = threading.Lock()

    def __enter__(self):
        if self.process is not None and self.process.is_alive():
            raise RuntimeError("policy service is already running")
        ctx = mp.get_context("spawn")
        self.pipe, child = ctx.Pipe()
        token = secrets.token_urlsafe(32)
        self.process = ctx.Process(target=_serve, args=(child, token, self.agent_id, self.policy_id, self.policy,
                                                       self.tls, self.state_path))
        self.process.start()
        child.close()
        if not self.pipe.poll(5):
            self.stop()
            raise RuntimeError("policy service did not start")
        ready = self.pipe.recv()
        if "error" in ready:
            self.process.join(2)
            self.pipe.close()
            raise RuntimeError("policy service startup failed: " + ready["error"])
        port = ready["port"]
        self.client = (RemotePolicyClient(f"https://localhost:{port}", token, ssl_context=self.tls.client_context())
                       if self.tls else RemotePolicyClient(f"http://127.0.0.1:{port}", token))
        return self

    def _control(self, command, value):
        with self._control_lock:
            self.pipe.send((command, value))
            if not self.pipe.poll(3):
                raise RuntimeError("policy control was not acknowledged")
            result = self.pipe.recv()
        if not result["ok"]:
            if result.get("conflict"):
                raise PolicyConflict(result["error"])
            raise PolicyStateError(result["error"])
        return result["version"]

    def replace_policy(self, policy, *, expected_version=None):
        if self.state_path and expected_version is None:
            raise PolicyStateError("persistent updates require expected_version")
        return self._control("policy", ({"permissions": validate_permissions(policy["permissions"])}, expected_version))

    @property
    def version(self):
        return self._control("snapshot", None)

    def set_fault(self, fault):
        if fault not in (None, "timeout", "http_error", "malformed", "duplicate", "oversized"):
            raise ValueError("unknown lab fault")
        self._control("fault", fault)

    def stop(self):
        if self.process is not None:
            if self.process.is_alive():
                self.pipe.send(("stop", None))
                self.process.join(2)
                if self.process.is_alive():
                    self.process.terminate()
                    self.process.join(2)
            self.pipe.close()

    def __exit__(self, *args):
        self.stop()
