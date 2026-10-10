from __future__ import annotations

import csv
import json
import statistics
from pathlib import Path

from agent_auth.experiment import MODES, run_mode


def main(runs: int = 10):
    raw = {m: [] for m in MODES}
    for _ in range(runs):
        for mode in MODES:
            raw[mode].append(run_mode(mode, iterations=5000))

    summary = []
    for mode, rows in raw.items():
        p95 = [r["decision_p95_ms"] for r in rows]
        open_ms = [r["session_open_ms"] for r in rows]
        kill_ms = [r["kill_to_deny_ms_local"] for r in rows]
        summary.append({
            "mode": mode,
            "runs": runs,
            "median_decision_p95_ms": statistics.median(p95),
            "min_decision_p95_ms": min(p95),
            "max_decision_p95_ms": max(p95),
            "median_session_open_ms": statistics.median(open_ms),
            "median_kill_to_deny_ms_local": statistics.median(kill_ms),
        })

    out = Path(__file__).resolve().parents[1] / ".local-runs" / "certificate-study"
    out.mkdir(parents=True, exist_ok=True)
    (out / "benchmark_repeated.json").write_text(json.dumps({"summary": summary}, indent=2))
    with (out / "benchmark_repeated.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(summary[0].keys()))
        w.writeheader(); w.writerows(summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
