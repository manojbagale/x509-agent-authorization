# Recorded results

Saved experiment output is grouped by date. New runs write to `.local-runs/` by default, leaving these snapshots unchanged.

| Snapshot | Contents |
|---|---|
| [2026-09-28](2026-09-28/) | Original four-certificate comparison, size scaling, repeated benchmark, mTLS output, and OpenSSL checks |
| [2026-10-05](2026-10-05/) | Five-model evaluation, raw samples and source hashes, persistent mTLS recording, local test output, and verification summary |

## October 5 comparison

The saved evaluation used 10 rotated runs, 2,000 authorization samples/model/run, 100 warmups, 100 processing samples/model/run, and 30 fresh-credential kill trials/model/run. The local suite passed 104 tests. All 50 model/case decisions matched expectations, and all 1,500 kill trials denied the next previously allowed call.

| Model | Median of run authorization p95, ms | Median of run local kill-to-denial medians, ms |
|---|---:|---:|
| Certificate-native | 0.022169 | 0.003443 |
| External | 0.016925 | 0.003102 |
| Hybrid reference | 0.017040 | 0.003240 |
| Signed ceiling | 0.028833 | 0.003365 |
| Basic token | 0.015834 | 0.002431 |

These timings include local authorization and audit; they exclude tool execution and transport. Authentication differs between certificates and bearer tokens, so these values do not establish overall superiority. Repeated deterministic cases do not expand the distinct request matrix.

- [Raw evaluation and metadata](2026-10-05/evaluation.json) · [Summary CSV](2026-10-05/evaluation_summary.csv)
- [Network recording](2026-10-05/mtls_recording.json) · [Readable demo output](2026-10-05/demo_output.txt)
- [Local test output](2026-10-05/pytest.txt) · [Verification summary](2026-10-05/verification.json)
- [Authorization timing figure](2026-10-05/authorization_p95.png)

The network recording contains seven calls on one TLS 1.3 connection and two completed file reads. Denied calls did not invoke the dispatcher. Local kill stops subsequent calls; it does not measure distributed propagation or cancellation of work already running.

Snapshot files retain their original bytes, source revision identifiers, and source hashes. Those identifiers describe the code at measurement time, before later history and layout cleanup; they do not describe the current checkout. The September and October measurements should be interpreted separately. See the [experiment design](../docs/experiment-design.md) for timing definitions.
