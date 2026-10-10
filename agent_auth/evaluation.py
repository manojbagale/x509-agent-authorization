"""Reproducible local evaluation; never substitutes for a network benchmark.

Run ``python -m agent_auth.evaluation --output-dir .local-runs``.
Each result names the operation inside its timer. Historical results are untouched.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import platform
import ssl
import statistics
import subprocess
import sys
import time
from copy import deepcopy
from importlib.metadata import version
from pathlib import Path
from typing import Callable

from cryptography import x509

from agent_auth.scenarios import BASE_POLICY, MODES, REQUESTS, issue_for_mode, make_store
from agent_auth.gateway import AuthorizationGateway
from agent_auth.pki import AGENT_URI, ResearchCA

EVALUATION_MODES = (*MODES, "token")


def timed_ms(operation: Callable) -> float:
    start = time.perf_counter_ns()
    operation()
    return (time.perf_counter_ns() - start) / 1_000_000


def pct(values, p):
    values = sorted(values)
    if not values:
        return 0.0
    idx = min(len(values) - 1, int(round((p / 100) * (len(values) - 1))))
    return values[idx]


def distribution(values: list[float]) -> dict:
    return {
        "samples": len(values), "median_ms": statistics.median(values),
        "p95_ms": pct(values, 95), "min_ms": min(values), "max_ms": max(values),
    }


def evaluate_mode(mode: str, *, ca: ResearchCA, iterations: int, warmup: int) -> dict:
    store = make_store()
    processing_samples = min(iterations, 100)
    if mode == "token":
        from agent_auth.token_baseline import TokenAuthority, TokenGateway
        authority = TokenAuthority()
        gateway = TokenGateway(authority, store)
        issuance = [timed_ms(lambda: authority.issue(agent_id=AGENT_URI, lifetime_minutes=15)) for _ in range(processing_samples)]
        def create_session():
            token = authority.issue(agent_id=AGENT_URI, lifetime_minutes=15)
            return gateway.open_token_session(token)
        token = authority.issue(agent_id=AGENT_URI, lifetime_minutes=15)
        open_times = [timed_ms(lambda: gateway.open_token_session(token)) for _ in range(processing_samples)]
        session = gateway.open_token_session(token)
        credential_bytes = len(token.encode("utf-8"))
        parse, validation = [], []
    else:
        gateway = AuthorizationGateway(ca, store)
        issuance = [timed_ms(lambda: issue_for_mode(ca, mode)) for _ in range(processing_samples)]
        issued = issue_for_mode(ca, mode)
        def create_session():
            credential = issue_for_mode(ca, mode)
            return gateway.open_session(credential.cert, credential.key)
        cert_der = issued.der
        credential_bytes = len(cert_der)
        parse = [timed_ms(lambda: x509.load_der_x509_certificate(cert_der)) for _ in range(processing_samples)]
        validation = [timed_ms(lambda: gateway._verify_certificate(issued.cert)) for _ in range(processing_samples)]
        open_times = [timed_ms(lambda: gateway.open_session(issued.cert, issued.key)) for _ in range(processing_samples)]
        session = gateway.open_session(issued.cert, issued.key)

    cases = []
    for name, request, expected in REQUESTS:
        allowed, reason = gateway.authorize(session, request)
        cases.append({"case": name, "expected": expected, "actual": allowed, "reason": reason})
    positive = sum(case["expected"] for case in cases)
    negative = len(cases) - positive
    false_allow = sum(case["actual"] and not case["expected"] for case in cases)
    false_deny = sum(not case["actual"] and case["expected"] for case in cases)
    if false_allow or false_deny:
        mismatches = [case for case in cases if case["actual"] != case["expected"]]
        raise AssertionError(f"{mode}: correctness matrix failed: {mismatches}")

    # Both allowed and denied requests are timed; all models share this order.
    for index in range(warmup):
        gateway.authorize(session, REQUESTS[index % len(REQUESTS)][1])
    decision_samples = []
    by_outcome = {"allow": [], "deny": []}
    for index in range(iterations):
        _, request, expected = REQUESTS[index % len(REQUESTS)]
        elapsed = timed_ms(lambda: gateway.authorize(session, request))
        decision_samples.append(elapsed)
        by_outcome["allow" if expected else "deny"].append(elapsed)

    def replace_live_policy(policy):
        if mode in {"external", "token"}:
            store.replace_agent_policy(AGENT_URI, policy)
        elif mode in {"hybrid", "hybrid_ceiling"}:
            store.replace_named_policy("research-policy-v1", policy)
        else:
            store.replace_agent_policy(AGENT_URI, policy)

    pre_narrow, _ = gateway.authorize(session, REQUESTS[0][1])
    replace_live_policy({"permissions": []})
    post_narrow, narrow_reason = gateway.authorize(session, REQUESTS[0][1])
    shell = {"tool": "shell", "action": "execute", "resource": "/bin/sh"}
    replace_live_policy({"permissions": [{"tool": "shell", "action": "execute", "resource_prefix": "/bin"}]})
    post_expand, expand_reason = gateway.authorize(session, shell)
    expected_narrow = mode != "certificate"
    expected_expand = mode in {"external", "hybrid", "token"}
    if not pre_narrow or (not post_narrow) != expected_narrow or post_expand != expected_expand:
        raise AssertionError("dynamic policy outcome differs from model definition")
    replace_live_policy(deepcopy(BASE_POLICY))
    revocations = []
    for _ in range(min(iterations, 30)):
        # kill is credential-serial scoped. A fresh credential makes each trial independent.
        trial_session = create_session()
        request = REQUESTS[0][1]
        before, _ = gateway.authorize(trial_session, request)
        if not before:
            raise AssertionError("revocation measurement requires a previously allowed request")
        mutation_start = time.perf_counter_ns()
        gateway.kill(trial_session)
        committed = time.perf_counter_ns()
        after, reason = gateway.authorize(trial_session, request)
        observed = time.perf_counter_ns()
        if after or reason != "session_revoked":
            raise AssertionError("revocation did not deny the next call")
        revocations.append({
            "precondition_allowed": before, "after_allowed": after, "reason": reason,
            "mutation_ms": (committed - mutation_start) / 1_000_000,
            "commit_to_first_denial_ms": (observed - committed) / 1_000_000,
            "mutation_start_to_first_denial_ms": (observed - mutation_start) / 1_000_000,
        })

    return {
        "mode": mode,
        "correctness": {
            "total": len(cases), "expected_allows": positive, "expected_denies": negative,
            "false_allows": false_allow, "false_denies": false_deny,
            "false_allow_rate": false_allow / negative,
            "false_deny_rate": false_deny / positive,
            "cases": cases,
        },
        "credential_bytes": credential_bytes,
        "credential_encoding": "opaque token UTF-8" if mode == "token" else "X.509 DER",
        "certificate_der_parse": distribution(parse) if parse else None,
        "certificate_leaf_issuance": distribution(issuance) if mode != "token" else None,
        "token_registry_issuance": distribution(issuance) if mode == "token" else None,
        "certificate_trust_profile_validate": distribution(validation) if validation else None,
        "synthetic_session_open": distribution(open_times) if mode != "token" else None,
        "token_registry_session_open": distribution(open_times) if mode == "token" else None,
        "dynamic_policy": {
            "pre_narrow_allowed": pre_narrow, "narrowing_denied_without_reissue": not post_narrow,
            "narrowing_reason": narrow_reason, "expansion_allowed_without_reissue": post_expand,
            "expansion_reason": expand_reason,
        },
        "authorization_audit_included": distribution(decision_samples),
        "authorization_by_expected_outcome": {
            outcome: distribution(samples) for outcome, samples in by_outcome.items() if samples
        },
        "local_revocation": distribution([r["commit_to_first_denial_ms"] for r in revocations]),
        "raw_samples_ms": {
            "certificate_leaf_issuance": issuance if mode != "token" else [],
            "token_registry_issuance": issuance if mode == "token" else [],
            "certificate_der_parse": parse, "certificate_trust_profile_validate": validation,
            "synthetic_session_open": open_times if mode != "token" else [],
            "token_registry_session_open": open_times if mode == "token" else [],
            "authorization_audit_included": decision_samples,
        },
        "revocation_trials": revocations,
    }


def evaluate(*, runs: int = 10, iterations: int = 2000, warmup: int = 100) -> dict:
    if runs < 1 or iterations < 1 or warmup < 0:
        raise ValueError("runs and iterations must be positive; warmup must be nonnegative")
    repo = Path(__file__).resolve().parents[1]
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True)
    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=repo, capture_output=True, text=True)
    source_files = sorted(path for folder in ("agent_auth", "scripts", "tests") for path in (repo / folder).rglob("*.py"))
    source_files.extend([repo / "pyproject.toml", repo / ".github/workflows/ci.yml"])
    source_hashes = {str(path.relative_to(repo)): hashlib.sha256(path.read_bytes()).hexdigest() for path in source_files if path.exists()}
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    records = []
    for run in range(runs):
        ca = ResearchCA.create()
        offset = run % len(EVALUATION_MODES)
        order = EVALUATION_MODES[offset:] + EVALUATION_MODES[:offset]
        for position, mode in enumerate(order):
            row = evaluate_mode(mode, ca=ca, iterations=iterations, warmup=warmup)
            row.update({"run": run + 1, "position": position + 1})
            records.append(row)
    summary = []
    for mode in EVALUATION_MODES:
        rows = [row for row in records if row["mode"] == mode]
        summary.append({
            "mode": mode, "runs": runs,
            "matrix_expected_allows_per_run": rows[0]["correctness"]["expected_allows"],
            "matrix_expected_denies_per_run": rows[0]["correctness"]["expected_denies"],
            "false_allows_total": sum(row["correctness"]["false_allows"] for row in rows),
            "false_denies_total": sum(row["correctness"]["false_denies"] for row in rows),
            "median_run_authorization_p95_ms": statistics.median(row["authorization_audit_included"]["p95_ms"] for row in rows),
            "median_run_der_parse_ms": statistics.median(row["certificate_der_parse"]["median_ms"] for row in rows) if mode != "token" else None,
            "median_run_certificate_leaf_issuance_ms": statistics.median(row["certificate_leaf_issuance"]["median_ms"] for row in rows) if mode != "token" else None,
            "median_run_token_registry_issuance_ms": statistics.median(row["token_registry_issuance"]["median_ms"] for row in rows) if mode == "token" else None,
            "median_run_trust_profile_validate_ms": statistics.median(row["certificate_trust_profile_validate"]["median_ms"] for row in rows) if mode != "token" else None,
            "median_run_synthetic_session_open_ms": statistics.median(row["synthetic_session_open"]["median_ms"] for row in rows) if mode != "token" else None,
            "median_run_token_registry_session_open_ms": statistics.median(row["token_registry_session_open"]["median_ms"] for row in rows) if mode == "token" else None,
            "median_run_local_commit_to_first_denial_ms": statistics.median(row["local_revocation"]["median_ms"] for row in rows),
            "narrowing_denied_without_reissue": rows[0]["dynamic_policy"]["narrowing_denied_without_reissue"],
            "expansion_allowed_without_reissue": rows[0]["dynamic_policy"]["expansion_allowed_without_reissue"],
        })
    return {
        "metadata": {
            "started_utc": started, "finished_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "starting_git_sha": revision.stdout.strip() if revision.returncode == 0 else None,
            "starting_worktree_dirty": bool(dirty.stdout),
            "starting_git_status": dirty.stdout.splitlines(),
            "source_sha256": source_hashes,
            "python": sys.version, "platform": platform.platform(), "machine": platform.machine(),
            "processor": platform.processor(), "openssl": ssl.OPENSSL_VERSION,
            "cryptography": version("cryptography"),
            "timer": "time.perf_counter_ns", "timer_resolution_s": time.get_clock_info("perf_counter").resolution,
            "runs": runs, "iterations_per_run_mode": iterations, "warmup_per_run_mode": warmup,
            "order": "cyclic rotation of models across runs; shared request order",
            "processing_samples_per_run_mode": min(iterations, 100),
            "revocation_trials_per_run_mode": min(iterations, 30),
            "scope": {
                "certificate_leaf_issuance": "fresh P-256 leaf private-key generation, certificate/profile/authorization payload construction and CA signing; excludes CA creation and approval workflow",
                "token_registry_issuance": "random bearer credential generation, SHA-256 registry key, record construction and insertion into local trusted registry; excludes approval workflow",
                "certificate_der_parse": "DER bytes to cryptography Certificate object only",
                "certificate_trust_profile_validate": "single direct issuer signature, validity, profile checks; excludes DER parse, authorization extension decode and TLS",
                "synthetic_session_open": "profile validation, identity/authorization decode, random challenge, private-key signing and verification; not TLS",
                "token_registry_session_open": "opaque bearer token hash and trusted registry lookup/expiry checks; no TLS, no OAuth server, no certificate-bound token claim",
                "authorization_audit_included": "in-process complete authorize call including local policy lookup and audit append; mixed static request matrix",
                "local_revocation": "local kill commit to return of the first subsequent denial; no propagation, network, polling or in-flight cancellation measured",
            },
            "interpretation": "Repeated deterministic correctness cases are not independent security trials. Timing is local descriptive evidence, not production performance or superiority. Certificate and token session-opening operations provide different authentication guarantees and are not interchangeable speed comparisons.",
            "equivalence_controls": "Same identity, initial permissions, request matcher, request matrix and 15-minute credential lifetime; every authorization call includes current local revoke/expiry checks and audit. All stores are in-process. Live policy mutation applies to token/external/hybrid models; certificate permissions are static by design.",
            "size_scope": "Presented credential bytes only, with encoding named per model; excludes chains, TLS framing, server policy and token registry state.",
            "approval_scope": "Trusted low-level issuance fixtures use identical pre-approved BASE_POLICY; human approval/issuance workflow is tested separately and not included in these timers.",
        },
        "summary": summary, "runs": records,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path(".local-runs"))
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--warmup", type=int, default=100)
    args = parser.parse_args()
    result = evaluate(runs=args.runs, iterations=args.iterations, warmup=args.warmup)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "evaluation.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    with (args.output_dir / "evaluation_summary.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(result["summary"][0]))
        writer.writeheader()
        writer.writerows(result["summary"])
    print(json.dumps({"metadata": result["metadata"], "summary": result["summary"]}, indent=2))


if __name__ == "__main__":
    main()
