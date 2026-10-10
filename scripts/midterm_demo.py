"""Run and explain the actual persistent mTLS demonstration for a recording."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from agent_auth.mtls_demo import run_mtls_demo


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Save the complete evidence JSON from this execution.")
    args = parser.parse_args()
    result = run_mtls_demo()
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    server = result["server"]
    print("Actual localhost file-tool demonstration")
    print(f"Permissions approved by: {result['approval']['approved_by']}")
    print(f"Agent: {server['agent_id']}")
    print(f"Transport: {server['tls_version']}; client certificate required: {result['mTLS_client_certificate_required']}")
    print(f"Connections: {server['connection_count']}; handshakes: {server['handshake_count']}")
    print("Policy changes and revocation below come from the trusted server harness.")
    print()
    for index, (call, response) in enumerate(zip(server["calls"], result["client_responses"]), start=1):
        decision = "ALLOW" if call["allowed"] else "DENY"
        print(f"{index}. {call['case'].replace('_', ' ')}: {decision} ({call['reason']})")
        print(f"   Completed file reads: {call['dispatch_count_before']} -> {call['dispatch_count_after']}")
        if index == 1:
            print(f"   Actual file content: {response['output']['content'].strip()}")
    print()
    timing = result["revocation_timing"]
    print("Revocation timing: one local sample on the same TLS connection")
    print(f"Allowed read immediately before kill: {server['revocation_precondition_allowed']}")
    print(f"Kill commit -> next denied decision: {timing['kill_to_next_decision_ms']:.6f} ms")
    print(f"Kill commit -> client receives denial: {timing['kill_to_client_receive_ms']:.6f} ms")
    print(f"Audit entries: {len(server['audit_log'])}; completed file reads: {server['dispatch_count']}")
    print("Scope: local custom JSON protocol; no MCP/LLM integration or OS sandbox.")
    print("Subsequent calls are blocked; an already-running operation is not canceled.")
    if args.output is not None:
        print(f"Complete evidence saved: {args.output}")


if __name__ == "__main__":
    main()
