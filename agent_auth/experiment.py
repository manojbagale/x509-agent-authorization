"""Original four-certificate experiment and certificate-size study."""
from __future__ import annotations

import csv
import json
import statistics
import time
from copy import deepcopy
from pathlib import Path

from agent_auth.pki import AGENT_URI, ResearchCA
from agent_auth.gateway import AuthorizationGateway, AuthorizationError
from agent_auth.scenarios import BASE_POLICY, MODES, REQUESTS, issue_for_mode, make_store
from agent_auth.evaluation import pct


def run_mode(mode: str, iterations: int = 10000):
    ca = ResearchCA.create()
    store = make_store()
    gw = AuthorizationGateway(ca, store)
    issued = issue_for_mode(ca, mode)

    t0 = time.perf_counter_ns()
    session = gw.open_session(issued.cert, issued.key)
    session_open_ms = (time.perf_counter_ns() - t0) / 1e6

    false_allow = 0
    false_deny = 0
    correctness = []
    for name, req, expected in REQUESTS:
        actual, reason = gw.authorize(session, req)
        correctness.append({"mode": mode, "case": name, "expected": expected, "actual": actual, "reason": reason})
        if actual and not expected:
            false_allow += 1
        if not actual and expected:
            false_deny += 1

    latencies_ms = []
    req = REQUESTS[0][1]
    for _ in range(iterations):
        start = time.perf_counter_ns()
        gw.authorize(session, req)
        latencies_ms.append((time.perf_counter_ns() - start) / 1e6)

    if mode == "external":
        store.replace_agent_policy(AGENT_URI, {"permissions": []})
    elif mode in {"hybrid", "hybrid_ceiling"}:
        store.replace_named_policy("research-policy-v1", {"permissions": []})
    post_narrow_allowed, post_narrow_reason = gw.authorize(session, REQUESTS[0][1])

    if mode == "external":
        store.replace_agent_policy(AGENT_URI, deepcopy(BASE_POLICY))
        store.replace_agent_policy(AGENT_URI, {"permissions": [
            {"tool": "shell", "action": "execute", "resource_prefix": "/bin"}
        ]})
    elif mode in {"hybrid", "hybrid_ceiling"}:
        store.replace_named_policy("research-policy-v1", {"permissions": [
            {"tool": "shell", "action": "execute", "resource_prefix": "/bin"}
        ]})
    shell_request = {"tool": "shell", "action": "execute", "resource": "/bin/sh"}
    post_expand_allowed, post_expand_reason = gw.authorize(session, shell_request)

    # Revocation must turn a previously allowed operation into a denial.
    # Restore live permissions after the independent policy-expansion trial.
    if mode == "external":
        store.replace_agent_policy(AGENT_URI, deepcopy(BASE_POLICY))
    elif mode in {"hybrid", "hybrid_ceiling"}:
        store.replace_named_policy("research-policy-v1", deepcopy(BASE_POLICY))
    assert gw.authorize(session, REQUESTS[0][1])[0], "revocation trial needs an allowed precondition"
    start = time.perf_counter_ns()
    gw.kill(session)
    kill_allowed, kill_reason = gw.authorize(session, REQUESTS[0][1])
    kill_to_deny_ms = (time.perf_counter_ns() - start) / 1e6

    return {
        "mode": mode,
        "certificate_der_bytes": len(issued.der),
        "session_open_ms": session_open_ms,
        "decision_p50_ms": pct(latencies_ms, 50),
        "decision_p95_ms": pct(latencies_ms, 95),
        "decision_p99_ms": pct(latencies_ms, 99),
        "false_allow": false_allow,
        "false_deny": false_deny,
        "policy_narrow_effective_without_reissue": not post_narrow_allowed,
        "post_narrow_reason": post_narrow_reason,
        "policy_expand_shell_allowed_without_reissue": post_expand_allowed,
        "post_expand_reason": post_expand_reason,
        "kill_to_deny_ms_local": kill_to_deny_ms,
        "kill_result": kill_reason,
        "correctness": correctness,
        "audit_events": len(gw.audit_log),
    }


def negative_identity_tests():
    ca = ResearchCA.create()
    store = make_store()
    gw = AuthorizationGateway(ca, store)
    issued = ca.issue_agent(mode="external")
    wrong_key = ca.issue_agent(mode="external").key

    checks = {}

    try:
        gw.open_session(issued.cert, wrong_key)
        checks["wrong_private_key_rejected"] = False
    except AuthorizationError:
        checks["wrong_private_key_rejected"] = True

    expired = ca.issue_agent(mode="external", lifetime_minutes=-1, backdate_minutes=5)
    try:
        gw.open_session(expired.cert, expired.key)
        checks["expired_certificate_rejected"] = False
    except AuthorizationError:
        checks["expired_certificate_rejected"] = True

    other_ca = ResearchCA.create()
    wrong_issuer = other_ca.issue_agent(mode="external")
    try:
        gw.open_session(wrong_issuer.cert, wrong_issuer.key)
        checks["wrong_issuer_rejected"] = False
    except AuthorizationError:
        checks["wrong_issuer_rejected"] = True

    try:
        gw.open_session(ca.cert, ca.key)
        checks["ca_certificate_rejected"] = False
    except AuthorizationError:
        checks["ca_certificate_rejected"] = True

    wrong_domain = ca.issue_agent(mode="external", agent_uri="spiffe://evil.example/agent/test")
    try:
        gw.open_session(wrong_domain.cert, wrong_domain.key)
        checks["wrong_trust_domain_rejected"] = False
    except AuthorizationError:
        checks["wrong_trust_domain_rejected"] = True

    multiple_uri = ca.issue_agent(
        mode="external",
        extra_uri_sans=["spiffe://seminar.fisk.edu/agent/second-identity"],
    )
    try:
        gw.open_session(multiple_uri.cert, multiple_uri.key)
        checks["multiple_uri_sans_rejected"] = False
    except AuthorizationError:
        checks["multiple_uri_sans_rejected"] = True

    return checks


def permission_set(n: int):
    return [
        {"tool": "file", "action": "read", "resource_prefix": f"/research/project-{i:03d}"}
        for i in range(n)
    ]


def certificate_size_scaling(samples: int = 15):
    rows = []
    for count in (0, 1, 10, 100):
        cert_sizes = []
        external_sizes = []
        hybrid_sizes = []
        ceiling_sizes = []
        for _ in range(samples):
            ca = ResearchCA.create()
            perms = permission_set(count)
            cert_sizes.append(len(ca.issue_agent(mode="certificate", permissions=perms).der))
            external_sizes.append(len(ca.issue_agent(mode="external").der))
            hybrid_sizes.append(len(ca.issue_agent(mode="hybrid", policy_id="research-policy-v1").der))
            ceiling_sizes.append(len(ca.issue_agent(
                mode="hybrid_ceiling", policy_id="research-policy-v1", max_permissions=perms
            ).der))
        for mode, values in (
            ("certificate", cert_sizes),
            ("external", external_sizes),
            ("hybrid", hybrid_sizes),
            ("hybrid_ceiling", ceiling_sizes),
        ):
            rows.append({
                "mode": mode,
                "permission_count": count,
                "median_der_bytes": int(statistics.median(values)),
                "min_der_bytes": min(values),
                "max_der_bytes": max(values),
            })
    return rows


def main():
    results = [run_mode(m) for m in MODES]
    negatives = negative_identity_tests()
    sizes = certificate_size_scaling()

    out_dir = Path(__file__).resolve().parents[1] / ".local-runs" / "certificate-study"
    out_dir.mkdir(parents=True, exist_ok=True)

    with (out_dir / "summary_v2.json").open("w", encoding="utf-8") as f:
        json.dump({"results": results, "negative_identity_tests": negatives, "certificate_size_scaling": sizes}, f, indent=2)

    with (out_dir / "summary_v2.csv").open("w", newline="", encoding="utf-8") as f:
        fields = [
            "mode", "certificate_der_bytes", "session_open_ms", "decision_p50_ms",
            "decision_p95_ms", "decision_p99_ms", "false_allow", "false_deny",
            "policy_narrow_effective_without_reissue", "policy_expand_shell_allowed_without_reissue",
            "kill_to_deny_ms_local", "audit_events"
        ]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in results:
            w.writerow({k: r[k] for k in fields})

    with (out_dir / "certificate_size_scaling.csv").open("w", newline="", encoding="utf-8") as f:
        fields = ["mode", "permission_count", "median_der_bytes", "min_der_bytes", "max_der_bytes"]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(sizes)

    print(json.dumps({
        "results": [{k: v for k, v in r.items() if k not in {"correctness"}} for r in results],
        "negative_identity_tests": negatives,
        "certificate_size_scaling": sizes,
    }, indent=2))


if __name__ == "__main__":
    main()
