"""Display measured evaluation evidence without rerunning or inventing results."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def yes_no(value: bool) -> str:
    return "yes" if value else "no"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", type=Path, default=Path("results/midterm/evaluation.json"))
    args = parser.parse_args()
    if not args.input.is_file():
        parser.error(f"Evidence file missing: {args.input}. Run python -m agent_auth.evaluation --output-dir results/midterm first.")
    result = json.loads(args.input.read_text(encoding="utf-8"))
    metadata = result["metadata"]
    print(f"Measured evaluation evidence: {args.input}")
    print(f"Generated UTC: {metadata['finished_utc']}")
    print(f"Runs: {metadata['runs']}; authorization samples per run/model: {metadata['iterations_per_run_mode']}")
    print("Shared request matrix and permissions; in-process stores; audit included.")
    print()
    for row in result["summary"]:
        allows = row["matrix_expected_allows_per_run"]
        denies = row["matrix_expected_denies_per_run"]
        print(f"{row['mode']}")
        print(f"  Static matrix per run: {allows + denies} cases ({allows} expected allows, {denies} expected denies)")
        print(f"  Across runs: {row['false_allows_total']} false allows, {row['false_denies_total']} false denies")
        print(f"  Narrowing denies without reissue: {yes_no(row['narrowing_denied_without_reissue'])}")
        print(f"  Expansion allowed without reissue: {yes_no(row['expansion_allowed_without_reissue'])}")
        runs = [run for run in result["runs"] if run["mode"] == row["mode"]]
        trials = [trial for run in runs for trial in run["revocation_trials"]]
        denied = sum(trial["precondition_allowed"] and not trial["after_allowed"] and trial["reason"] == "session_revoked" for trial in trials)
        print(f"  Local kill trials: {denied}/{len(trials)} denied next previously allowed call")
        print(f"  Median of per-run authorization p95: {row['median_run_authorization_p95_ms']:.6f} ms")
        print(f"  Median of per-run local commit-to-denial medians: {row['median_run_local_commit_to_first_denial_ms']:.6f} ms")
        if row["median_run_der_parse_ms"] is not None:
            print(f"  Median of per-run DER parse medians: {row['median_run_der_parse_ms']:.6f} ms")
        print()
    print("Repeated matrix cases are deterministic checks, not independent security trials.")
    print("Times describe this local run; certificate and token authentication have different guarantees.")
    print("Network revocation on a persistent TLS socket is shown separately by midterm_demo.py.")


if __name__ == "__main__":
    main()
