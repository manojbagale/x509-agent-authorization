# X.509 Authorization for AI Agents

A Senior Seminar research prototype comparing where tool permissions should live: in a signed X.509 credential, in server-side policy, or in both.

The research question is: **how much of an agent's authority should be bound to its credential, and which decisions should remain changeable at runtime?** Authentication establishes an identity or credential holder; a separate authorization check decides whether a particular tool/action/resource is permitted.

## Scope and comparison

This is a controlled, single-agent, single-host Python experiment. Its network demonstration uses a custom JSON protocol over localhost TLS 1.3 and a real read-only file tool. It is not an MCP SDK integration, an LLM benchmark, a deployed Step CA, an OAuth authorization server, or an agent sandbox.

| Model / code mode | Presented credential | Permission source | Live narrowing | Live administrative expansion without reissue |
|---|---|---|---|---|
| Certificate-native / `certificate` | X.509 identity + permissions | Signed extension | No; full credential kill is separate | No |
| External / `external` | Identity-only X.509 | Agent policy in server store | Yes | Yes |
| Hybrid reference / `hybrid` | X.509 identity + policy ID | Named server policy | Yes | Yes |
| Hybrid signed ceiling / `hybrid_ceiling` | X.509 identity + policy ID + maximum permissions | Intersection of live policy and signed maximum | Yes | Only within signed maximum |
| Basic token / `token` | Random opaque bearer reference | Agent policy in server store | Yes | Yes |

The external model supplies the equivalent server-side policy comparison. The token model supplies a basic token-based comparison using the same request matcher and initial permissions. It uses a trusted in-memory registry and a 32-byte random secret presented as 64 hexadecimal characters. It is neither a JWT nor an RFC 8705 certificate-bound access token. Bearer possession and mTLS private-key possession provide different authentication guarantees; their session-opening timings are not interchangeable speed comparisons.

## Who approves permissions

The trusted resource owner (`resource-owner:seminar-admin` in the lab) configures an allowlist and approved agent identities. `PermissionAuthority` rejects requests exceeding that allowlist, then signs the approved identity, permission set, policy ID, approver, approval ID, and expiry with an Ed25519 key. `ApprovedIssuer` verifies the configured owner key before issuing a short-lived credential. This is a programmatic control-plane demonstration, not a human-consent UI.

The owner key, CA key, registry, policy mutation, and kill operations belong to the trusted harness/control plane; none is exposed as a client tool-call endpoint. The issuer adapter installs the approved initial live policy for external, reference, ceiling, and token modes. After issuance, the live policy administrator is deliberately authoritative for external/reference/token models and may broaden those policies. The signed-ceiling model also requires a match against the immutable issuer maximum. Initial approval does not make an external policy an immutable ceiling.

## What is implemented

- Local P-256 research CA, short-lived client credentials, SPIFFE-style URI SAN identity, and client profile checks.
- Versioned experimental authorization extension with strict payload validation; identity stays in SAN and key purpose stays in EKU.
- Five controlled authorization models; identical initial policy, request matrix, matching, expiry/revocation checks, and audit behavior.
- Per-call validity and local kill checks, live policy reevaluation, and issuer-ceiling intersection where selected.
- Signed owner-approval workflow, negative approval controls, and immutable session authority checks.
- Persistent TLS 1.3 mTLS connection with seven requests: allowed read, forbidden shell, forbidden path, live narrowing, restoration, kill denial, repeated kill denial.
- Actual file dispatch after authorization; denied calls do not invoke the dispatcher. POSIX directory-descriptor traversal rejects symlinks and nonregular files, with a fixed 4,096-byte tool limit.
- Negative profile/parser/policy/lifecycle tests and OpenSSL critical-extension experiment.
- Reproducible measurement entry point with raw samples, environment, source hashes, and precise timing scopes.

The network demo proves this dispatch path on one connection. The client and trusted server run on one host, and the harness holds both sides' objects. It does not prove OS/network isolation against a compromised local process. DNS cases are logical authorization requests, not a DNS resolver implementation; no shell tool executes.

## Run and inspect

Use Ubuntu, Linux, or Ubuntu under WSL, Python 3.11+, and OpenSSL. The file dispatcher relies on POSIX `dir_fd`, `O_DIRECTORY`, and `O_NOFOLLOW`; the full demo is not supported in native Windows Python. The CI configuration targets Ubuntu with Python 3.11–3.13.

```bash
git clone https://github.com/manojbagale/x509-agent-authorization.git
cd x509-agent-authorization
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest
python -m agent_auth.evaluation --runs 10 --iterations 2000 --warmup 100 --output-dir results/midterm
python -m agent_auth.mtls_demo > results/midterm/mtls_output.json
python -m json.tool results/midterm/mtls_output.json
```

The evaluation creates its output directory. To run the demo alone, create the directory first with `mkdir -p results/midterm`. Inspect `server.calls`, dispatch counts, `approval`, `issuance`, and `revocation_timing` in the demo JSON. A single handshake remains open while live policy changes and local revocation affect later requests.

For recording-friendly output, use `python scripts/midterm_demo.py --output results/midterm/recording_take.json` and `python scripts/show_midterm_results.py`. The first executes the program; the second reads the saved evaluation.

Legacy entry points `python scripts/run_experiments.py` and `python scripts/benchmark.py` cover the earlier four-model experiment. They are not the five-model midterm evaluation.

## Evidence and interpretation

Existing files directly under `results/` and `evidence/` are historical Weeks 5–6 outputs, associated with the earlier implementation. New evaluation output belongs under `results/midterm/` and must be accompanied by its run metadata. Earlier 20-test/four-model results should not be presented as current test counts or mixed with new timings. The verified October 5 results below preserve their own source revision and measurement scope.

The evaluator separates certificate issuance, DER parsing, profile validation, synthetic private-key challenge session opening, token registry operations, authorization including audit, and local kill-to-first-denial. It rotates model order and retains raw samples. Repeated deterministic cases establish bounded correctness, not independent security trials or a guarantee against prompt injection.

The local kill mechanism is distinct from CA revocation. It denies the next admitted call after a serial/token digest is killed; it does not cancel an operation already executing. Single-process measurement and one localhost network sample do not establish a distributed propagation bound. Smallstep's passive revocation stops renewal but leaves an existing certificate usable until expiry.

The hybrid ceiling demonstrates a narrow invariant: for requests mediated by this gateway, live policy alone cannot authorize outside the signed permission maximum. It does not solve malicious behavior within approved scope, issuer compromise, distributed consistency, or general agent security.

## Verified midterm evidence

The October 5 evaluation began from clean source revision `64410aa66ac40048b2ca24e18c37db9da5064ab8` on Linux x86_64, Python 3.12.14, cryptography 46.0.7 and OpenSSL 3.5.8. The local suite passed **104 tests**.

- [Raw evaluation, distributions, metadata and source hashes](results/midterm/evaluation.json) and [summary CSV](results/midterm/evaluation_summary.csv): 10 rotated runs, 2,000 authorization samples/model/run, 100 warmups, 100 processing samples/model/run, 30 fresh-credential kill trials/model/run.
- All 50 distinct model/case decisions matched expectations: zero false allows and zero false denies. Repeated runs do not expand that deterministic test matrix.
- All 1,500 local kill trials denied the next previously allowed call. This measures local subsequent-call denial, not distributed propagation or in-flight cancellation.
- [Actual network recording](results/midterm/mtls_recording.json) and [readable captured output](evidence/midterm/demo_output.txt): seven calls, one TLS 1.3 connection/handshake, two completed file reads, no dispatch for denied calls.
- [Local test output](evidence/midterm/pytest.txt), [verification summary](evidence/midterm/verification.json), and [measured authorization figure](evidence/midterm/authorization_p95.png).

| Model | Median of run authorization p95, ms | Median of run local kill-to-denial medians, ms |
|---|---:|---:|
| Certificate-native | 0.022169 | 0.003443 |
| External | 0.016925 | 0.003102 |
| Hybrid reference | 0.017040 | 0.003240 |
| Signed ceiling | 0.028833 | 0.003365 |
| Basic token | 0.015834 | 0.002431 |

These are descriptive in-process values with audit included, excluding tool execution and network transport. The source hashes identify the exact code used; regenerated timings will vary. Certificate and token authentication differ, so these values do not establish production performance or overall superiority.

## CI status

Packaging was repaired by explicitly limiting package discovery to `agent_auth`, and installation/tests have been checked locally. The observed hosted Actions failure was blocked before runner execution; it was not an executed pytest failure. Account-specific diagnostics are omitted from public evidence. The workflow is configured, but no hosted green result is claimed until a run actually executes. See [Actions](https://github.com/manojbagale/x509-agent-authorization/actions/workflows/ci.yml).

## Documents and remaining work

- [Experiment design and measurement definitions](docs/experiment-design.md)
- [Research history and proposal comparison](docs/research-notes.md)
- [Verified primary references](docs/references.md)
- [Security boundary and limitations](SECURITY.md)

Remaining work includes a real MCP tool path, distributed policy/kill state, deployment isolation, stronger PKIX validation and issuing hierarchy, richer resource/argument semantics, and concurrency/failure measurements. These are separate milestones rather than claims about the current lab.
