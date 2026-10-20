"""Compare local and remote policy decisions on the same certificate sessions."""
import argparse
import datetime as dt
import hashlib
import json
import platform
import statistics
import subprocess
import time
from importlib.metadata import version
from pathlib import Path

from agent_auth.evaluation import distribution
from agent_auth.gateway import AuthorizationGateway
from agent_auth.pki import AGENT_URI, ResearchCA
from agent_auth.policy_service import PolicyService
from agent_auth.scenarios import BASE_POLICY, REQUESTS, issue_for_mode, make_store


def evaluate(runs=5, iterations=100, warmup=10):
    if runs < 1 or iterations < 1 or warmup < 0:
        raise ValueError("positive runs/iterations and nonnegative warmup required")
    root = Path(__file__).resolve().parents[1]
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=root, text=True).strip()
    records, faults = [], []
    with PolicyService(AGENT_URI, "research-policy-v1", BASE_POLICY) as service:
        for run in range(runs):
            ca = ResearchCA.create()
            for mode in ("external", "hybrid", "hybrid_ceiling"):
                issued = issue_for_mode(ca, mode)
                for transport in (("local", "http") if run % 2 == 0 else ("http", "local")):
                    g = AuthorizationGateway(ca, make_store(), policy_decider=service.client if transport == "http" else None)
                    session = g.open_session(issued.cert, issued.key)
                    cases = []
                    for name, request, expected in REQUESTS:
                        allowed, reason = g.authorize(session, request)
                        assert allowed is expected, (mode, transport, name, reason)
                        cases.append({"case": name, "expected": expected, "actual": allowed})
                    for index in range(warmup):
                        g.authorize(session, REQUESTS[index % len(REQUESTS)][1])
                    samples = []
                    for index in range(iterations):
                        _, request, expected = REQUESTS[index % len(REQUESTS)]
                        start = time.perf_counter_ns()
                        actual, _ = g.authorize(session, request)
                        samples.append((time.perf_counter_ns() - start) / 1e6)
                        assert actual is expected
                    records.append({"run": run + 1, "mode": mode, "transport": transport,
                                    "cases": cases, "authorization_ms": distribution(samples), "raw_ms": samples})
        g = AuthorizationGateway(ca, make_store(), policy_decider=service.client)
        session = g.open_session(issued.cert, issued.key)
        for fault in ("http_error", "timeout", "malformed", "duplicate", "oversized", "stopped"):
            service.set_fault(None)
            assert g.authorize(session, REQUESTS[0][1])[0]
            if fault == "stopped":
                service.stop()
            else:
                service.set_fault(fault)
            for trial in range(10):
                start = time.perf_counter_ns()
                actual, reason = g.authorize(session, REQUESTS[0][1])
                elapsed = (time.perf_counter_ns() - start) / 1e6
                assert not actual and reason == "policy_unavailable"
                faults.append({"fault": fault, "trial": trial+1, "allowed": actual, "reason": reason, "elapsed_ms": elapsed})
    summary = []
    for mode in ("external", "hybrid", "hybrid_ceiling"):
        for transport in ("local", "http"):
            rows = [r for r in records if r["mode"] == mode and r["transport"] == transport]
            summary.append({"mode": mode, "transport": transport,
                            "median_run_median_ms": statistics.median(r["authorization_ms"]["median_ms"] for r in rows),
                            "median_run_p95_ms": statistics.median(r["authorization_ms"]["p95_ms"] for r in rows)})
    sources = [p for folder in ("agent_auth", "scripts", "tests") for p in (root/folder).glob("*.py")]
    return {"metadata": {"generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                          "source_commit": git("rev-parse", "HEAD"), "source_dirty": bool(git("status", "--porcelain")),
                          "source_sha256": {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(sources)},
                          "python": platform.python_version(), "platform": platform.platform(), "cryptography": version("cryptography"),
                          "runs": runs, "iterations": iterations, "warmup": warmup,
                          "scope": "authorize() including audit; HTTP includes a new loopback TCP connection and JSON; excludes TLS client transport and file dispatch",
                          "timeout_seconds": 0.15, "fault_trials_per_kind": 10},
            "summary": summary, "runs": records, "fault_trials": faults}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path(".local-runs/remote-policy"))
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=10)
    args = parser.parse_args()
    result = evaluate(args.runs, args.iterations, args.warmup)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "evaluation.json").write_text(json.dumps(result, indent=2)+"\n")
    print(f"{args.runs} runs; {args.iterations} samples per mode/transport/run; {args.warmup} warmups")
    print("mode              transport  median ms   p95 ms (median of run p95)")
    for row in result["summary"]:
        print(f"{row['mode']:18} {row['transport']:9} {row['median_run_median_ms']:9.4f} {row['median_run_p95_ms']:9.4f}")
    print(f"Fault trials denied: {sum(not r['allowed'] for r in result['fault_trials'])}/{len(result['fault_trials'])}")
    print(f"Saved: {args.output_dir / 'evaluation.json'}")


if __name__ == "__main__":
    main()
