"""Evaluate mutual TLS, committed policy versions and concurrent decisions."""
from __future__ import annotations

import argparse
import concurrent.futures as futures
import datetime as dt
import hashlib
import json
import platform
import sqlite3
import ssl
import statistics
import subprocess
import tempfile
import threading
import time
from contextlib import ExitStack
from dataclasses import replace
from importlib.metadata import version
from pathlib import Path

from agent_auth.evaluation import distribution
from agent_auth.gateway import AuthorizationGateway
from agent_auth.pki import AGENT_URI, ResearchCA
from agent_auth.policy_service import PolicyService, RemotePolicyClient
from agent_auth.policy_state import PolicyConflict
from agent_auth.scenarios import BASE_POLICY, REQUESTS, issue_for_mode, make_store
from agent_auth.service_tls import ServiceTLS

POLICY_ID = "research-policy-v1"
READ = REQUESTS[0][1]


def make_gateway(client=None):
    ca = ResearchCA.create()
    gateway = AuthorizationGateway(ca, make_store(), policy_decider=client)
    issued = issue_for_mode(ca, "hybrid_ceiling")
    return gateway, gateway.open_session(issued.cert, issued.key)


def run(runs=5, iterations=100):
    if runs < 1 or iterations < 1:
        raise ValueError("positive runs and iterations required")
    root = Path(__file__).resolve().parents[1]
    records, rejections, restarts, concurrent, overlaps = [], [], [], [], []
    with tempfile.TemporaryDirectory() as temp:
        td = Path(temp)
        tls = ServiceTLS.create(td/"tls")
        with ExitStack() as stack:
            http = stack.enter_context(PolicyService(AGENT_URI, POLICY_ID, BASE_POLICY))
            mtls = stack.enter_context(PolicyService(AGENT_URI, POLICY_ID, BASE_POLICY, tls=tls))
            stored = stack.enter_context(PolicyService(AGENT_URI, POLICY_ID, BASE_POLICY, tls=tls, state_path=td/"timing.db"))
            # One issued certificate and session for every path in each paired run.
            for run_index in range(runs):
                gateway, session = make_gateway()
                paths = [("local", None), ("http_memory", http.client),
                         ("mtls_memory", mtls.client), ("mtls_sqlite", stored.client)]
                paths = paths[run_index % 4:] + paths[:run_index % 4]
                for name, client in paths:
                    gateway.policy_decider = client
                    matrix = []
                    for label, request, expected in REQUESTS:
                        allowed, reason = gateway.authorize(session, request)
                        assert allowed is expected
                        matrix.append({"case": label, "allowed": allowed, "reason": reason})
                    for _ in range(10):
                        assert gateway.authorize(session, READ)[0]
                    samples = []
                    for _ in range(iterations):
                        start = time.perf_counter_ns()
                        allowed, _ = gateway.authorize(session, READ)
                        samples.append((time.perf_counter_ns()-start)/1e6)
                        assert allowed
                    records.append({"run": run_index, "path": name, "matrix": matrix,
                                    "samples_ms": samples, "latency": distribution(samples)})

            other = ServiceTLS.create(td/"other")
            wrong_host = ServiceTLS.create(td/"wrong-host", server_name="wrong.example")
            hostname_service = stack.enter_context(PolicyService(AGENT_URI, POLICY_ID, BASE_POLICY, tls=wrong_host))
            pin_service = stack.enter_context(PolicyService(AGENT_URI, POLICY_ID, BASE_POLICY,
                                                          tls=replace(tls, client_fingerprint="0"*64)))
            missing = tls.client_context(include_certificate=False)
            untrusted_client = tls.client_context(include_certificate=False)
            untrusted_client.load_cert_chain(other.client_cert, other.client_key)
            untrusted_server = other.client_context(include_certificate=False)
            untrusted_server.load_cert_chain(tls.client_cert, tls.client_key)
            cases = [
                ("missing_client_certificate", mtls, missing, False),
                ("untrusted_client_certificate", mtls, untrusted_client, False),
                ("untrusted_server_ca", mtls, untrusted_server, False),
                ("wrong_server_hostname", hostname_service, wrong_host.client_context(), False),
                ("gateway_leaf_pin_mismatch", pin_service, tls.client_context(), False),
                ("wrong_service_token", mtls, tls.client_context(), True),
                ("plaintext_to_tls_listener", mtls, None, False),
            ]
            for label, server, context, wrong_token in cases:
                assert mtls.client.evaluate(make_gateway()[1], READ)  # Valid precondition.
                endpoint = f"https://localhost:{server.client.port}" if context else f"http://127.0.0.1:{server.client.port}"
                bad = RemotePolicyClient(endpoint, "wrong" if wrong_token else server.client.token, ssl_context=context)
                gateway, session = make_gateway(bad)
                for trial in range(10):
                    allowed, reason = gateway.authorize(session, READ)
                    assert (allowed, reason) == (False, "policy_unavailable")
                    rejections.append({"case": label, "trial": trial, "allowed": allowed, "reason": reason})

        with PolicyService(AGENT_URI, POLICY_ID, BASE_POLICY, tls=tls, state_path=td/"restart.db") as service:
            gateway, session = make_gateway(service.client)
            for trial in range(10):
                before = service.version
                assert gateway.authorize(session, READ)[0]
                narrowed = service.replace_policy({"permissions": []}, expected_version=before)
                old_pid = service.process.pid
                service.process.terminate(); service.process.join(2); service.pipe.close()
                service.__enter__()
                gateway.policy_decider = service.client
                reply = service.client.evaluate_details(session, READ)
                assert reply["decision"] is False and reply["policy_version"] == narrowed
                assert service.process.pid != old_pid
                try:
                    service.replace_policy(BASE_POLICY, expected_version=before)
                    raise AssertionError("stale update accepted")
                except PolicyConflict:
                    pass
                restored = service.replace_policy(BASE_POLICY, expected_version=narrowed)
                assert gateway.authorize(session, READ)[0]
                restarts.append({"trial": trial, "before": before, "narrowed": narrowed,
                                 "after_restart": reply["policy_version"], "decision_after_restart": reply["decision"],
                                 "stale_update_rejected": True, "restored": restored})

        for workers in (1, 4, 8):
            with PolicyService(AGENT_URI, POLICY_ID, BASE_POLICY, tls=tls, state_path=td/f"concurrent-{workers}.db") as service:
                _, session = make_gateway(service.client)
                for phase in ("before", "after"):
                    if phase == "after":
                        service.replace_policy({"permissions": []}, expected_version=1)
                    def call(i):
                        start = time.perf_counter_ns()
                        reply = service.client.evaluate_details(session, READ)
                        return {"index": i, **reply, "latency_ms": (time.perf_counter_ns()-start)/1e6}
                    started = time.perf_counter_ns()
                    with futures.ThreadPoolExecutor(workers) as pool:
                        rows = list(pool.map(call, range(200)))
                    elapsed = (time.perf_counter_ns()-started)/1e9
                    expected_version = 1 if phase == "before" else 2
                    assert all(r["policy_version"] == expected_version and r["decision"] is (phase == "before") for r in rows)
                    concurrent.append({"workers": workers, "phase": phase, "requests": rows,
                                       "elapsed_seconds": elapsed, "requests_per_second": len(rows)/elapsed,
                                       "latency": distribution([r["latency_ms"] for r in rows])})

        # Continuous client work while an acknowledged policy update occurs.
        with PolicyService(AGENT_URI, POLICY_ID, BASE_POLICY, tls=tls, state_path=td/"overlap.db") as service:
            _, session = make_gateway(service.client)
            enough = threading.Event()
            lock = threading.Lock()
            completed = [0]
            def overlapping(i):
                start = time.perf_counter_ns()
                reply = service.client.evaluate_details(session, READ)
                end = time.perf_counter_ns()
                with lock:
                    completed[0] += 1
                    if completed[0] >= 20:
                        enough.set()
                return {"index": i, "start_ns": start, "end_ns": end, **reply}
            with futures.ThreadPoolExecutor(8) as pool:
                pending = [pool.submit(overlapping, i) for i in range(320)]
                assert enough.wait(10)
                service.replace_policy({"permissions": []}, expected_version=1)
                acknowledged = time.perf_counter_ns()
                overlaps = [future.result() for future in pending]
            assert {r["policy_version"] for r in overlaps} == {1, 2}
            assert all(r["decision"] is (r["policy_version"] == 1) for r in overlaps)
            assert all(r["policy_version"] == 2 for r in overlaps if r["start_ns"] > acknowledged)
            overlap_summary = {"update_acknowledged_ns": acknowledged,
                               "version_1": sum(r["policy_version"] == 1 for r in overlaps),
                               "version_2": sum(r["policy_version"] == 2 for r in overlaps),
                               "old_snapshot_completed_after_ack": sum(r["policy_version"] == 1 and r["end_ns"] > acknowledged for r in overlaps)}

    def git(*args):
        return subprocess.check_output(["git", *args], cwd=root, text=True).strip()
    sources = sorted(p for folder in ("agent_auth", "scripts", "tests") for p in (root/folder).glob("*.py"))
    summary=[]
    for path in ("local", "http_memory", "mtls_memory", "mtls_sqlite"):
        rows = [r for r in records if r["path"] == path]
        summary.append({"path": path, "median_run_median_ms": statistics.median(r["latency"]["median_ms"] for r in rows),
                        "median_run_p95_ms": statistics.median(r["latency"]["p95_ms"] for r in rows)})
    return {"metadata": {"generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                         "source_commit": git("rev-parse", "HEAD"), "source_dirty": bool(git("status", "--porcelain")),
                         "source_sha256": {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
                         "python": platform.python_version(), "openssl": ssl.OPENSSL_VERSION,
                         "sqlite": sqlite3.sqlite_version, "cryptography": version("cryptography"), "platform": platform.platform(),
                         "runs": runs, "iterations": iterations, "warmup": 10,
                         "timing_scope": "authorize() including audit, one signed-ceiling allowed read request, fresh policy connection; excludes issuance, agent TLS and file execution",
                         "concurrency_scope": "direct policy decision API including TLS and SQLite; excludes gateway audit and file tool",
                         "restart_scope": "abrupt child-process termination after acknowledged transaction, same host and DB; not power-loss testing"},
            "summary": summary, "runs": records, "trust_rejections": rejections,
            "restart_trials": restarts, "concurrency": concurrent,
            "overlap_summary": overlap_summary, "overlapping_requests": overlaps}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path(".local-runs/secure-policy"))
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--iterations", type=int, default=100)
    args = parser.parse_args()
    result = run(args.runs, args.iterations)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir/"evaluation.json").write_text(json.dumps(result, indent=2)+"\n")
    print("Signed-ceiling authorization: median of run medians / median of run p95 values (ms)")
    for row in result["summary"]:
        print(f"{row['path']:16} {row['median_run_median_ms']:.4f} / {row['median_run_p95_ms']:.4f}")
    print(f"Trust rejection trials denied: {len(result['trust_rejections'])}/70")
    print(f"Abrupt restarts preserved narrowed policy: {len(result['restart_trials'])}/10")
    print("Stale updates rejected after restart: 10/10")
    for row in result["concurrency"]:
        print(f"{row['workers']} workers, {row['phase']:6}: 200/200 correct, p95 {row['latency']['p95_ms']:.3f} ms, {row['requests_per_second']:.1f} req/s")
    overlap = result["overlap_summary"]
    print(f"Overlapping update: 320/320 matched snapshot; v1={overlap['version_1']}, v2={overlap['version_2']}")
    print(f"Old-version replies completing after update acknowledgement: {overlap['old_snapshot_completed_after_ack']}")
    print(f"Saved: {args.output_dir/'evaluation.json'}")


if __name__ == "__main__":
    main()
