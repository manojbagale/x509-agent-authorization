"""Loopback policy decision service for process-boundary experiments.

The JSON envelope follows AuthZEN's subject/action/resource vocabulary. This
lab uses a private context schema and HTTP on loopback, not AuthZEN conformance
or a production transport. Administrative changes use an inherited IPC pipe.
"""
from __future__ import annotations

import http.client
import json
import multiprocessing as mp
import secrets
import threading
import time
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from agent_auth.policy import AuthorizationError, PolicyServiceError, matches_permissions, validate_permissions

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
    def __init__(self, endpoint: str, token: str, *, timeout: float = 0.15):
        url = urlsplit(endpoint)
        if (url.scheme != "http" or url.hostname != "127.0.0.1" or not url.port
                or url.path or url.query or url.fragment or url.username or url.password):
            raise ValueError("the lab PDP must use http://127.0.0.1:port")
        if not token or timeout <= 0:
            raise ValueError("token and positive socket timeout required")
        self.host, self.port, self.token, self.timeout = url.hostname, url.port, token, timeout
        self.calls = 0

    def evaluate(self, session, request: dict) -> bool:
        payload = {
            "subject": {"type": "agent", "id": session.agent_id},
            "action": {"name": request["action"], "properties": {"tool": request["tool"]}},
            "resource": {"type": "path", "id": request["resource"]},
            "context": {"mode": session.mode, "policy_id": session.policy_id},
        }
        body = json.dumps(payload).encode()
        if len(body) > MAX_BODY:
            raise PolicyServiceError("request too large")
        connection = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        self.calls += 1
        try:
            connection.request("POST", "/access/v1/evaluation", body=body, headers={
                "Authorization": "Bearer " + self.token, "Content-Type": "application/json",
            })
            response = connection.getresponse()
            if response.status != 200 or response.getheader("Content-Type", "").split(";")[0] != "application/json":
                raise PolicyServiceError("invalid policy service response")
            raw = response.read(MAX_BODY + 1)
            if len(raw) > MAX_BODY:
                raise PolicyServiceError("response too large")
            result = strict_json(raw)
            if not isinstance(result, dict) or set(result) != {"decision"} or type(result["decision"]) is not bool:
                raise PolicyServiceError("decision must be a JSON boolean")
            return result["decision"]
        except (OSError, http.client.HTTPException, ValueError, UnicodeError) as exc:
            raise PolicyServiceError("policy service unavailable or invalid") from exc
        finally:
            connection.close()


def _serve(pipe, token, agent_id, policy_id, policy):
    lock = threading.Lock()
    state = {"policy": deepcopy(policy), "fault": None}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def setup(self):
            super().setup()
            self.connection.settimeout(1.0)

        def reply(self, status, body):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass  # Expected after the client's timeout test.

        def do_POST(self):
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
                    current, fault = deepcopy(state["policy"]), state["fault"]
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
                self.reply(200, json.dumps({"decision": decision}).encode())
            except (ValueError, KeyError, TypeError, AuthorizationError, OSError):
                self.reply(400, b'{}')

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    pipe.send(server.server_port)
    try:
        while True:
            command, value = pipe.recv()
            if command == "stop":
                break
            with lock:
                if command == "policy":
                    state["policy"] = {"permissions": validate_permissions(value["permissions"])}
                elif command == "fault":
                    state["fault"] = value
                else:
                    raise ValueError("unknown control operation")
            pipe.send(True)  # Ack only after replacement is committed.
    finally:
        server.shutdown()
        server.server_close()
        pipe.close()


class PolicyService:
    """Trusted lab harness; controls are never exposed through HTTP."""
    def __init__(self, agent_id: str, policy_id: str, policy: dict):
        self.policy = {"permissions": validate_permissions(policy["permissions"])}
        self.agent_id, self.policy_id = agent_id, policy_id
        self.process = None

    def __enter__(self):
        ctx = mp.get_context("spawn")
        self.pipe, child = ctx.Pipe()
        token = secrets.token_urlsafe(32)
        self.process = ctx.Process(target=_serve, args=(child, token, self.agent_id, self.policy_id, self.policy))
        self.process.start()
        child.close()
        if not self.pipe.poll(5):
            self.stop()
            raise RuntimeError("policy service did not start")
        port = self.pipe.recv()
        self.client = RemotePolicyClient(f"http://127.0.0.1:{port}", token)
        return self

    def _control(self, command, value):
        self.pipe.send((command, value))
        if not self.pipe.poll(2) or self.pipe.recv() is not True:
            raise RuntimeError("policy control was not acknowledged")

    def replace_policy(self, policy):
        self._control("policy", {"permissions": validate_permissions(policy["permissions"])})

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
