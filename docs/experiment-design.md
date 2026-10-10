# Experiment design

## Research question and scope

Compare credential-carried authority with mutable server policy for per-call tool authorization. The experiment uses one logical agent, one local research CA, one gateway, local stores, and an identical deterministic request matrix. The network demonstration is a custom JSON protocol over persistent localhost mTLS with real file dispatch; it is not MCP or an LLM trial.

## Models and equivalence controls

| Code mode | Credential/authority | Runtime policy |
|---|---|---|
| `certificate` | X.509 with signed permissions | Embedded permissions stay fixed |
| `external` | Identity-only X.509 | Agent policy from server store |
| `hybrid` | X.509 identity + policy ID | Named policy from server store |
| `hybrid_ceiling` | X.509 identity + policy ID + maximum | Live named policy intersected with signed maximum |
| `token` | Random opaque bearer reference + trusted registry | Agent policy from server store |

All start with the same identity, permissions, 15-minute fixture lifetime, request matcher, request order, local revocation checks, and audit append. The approval demonstration uses a signed trusted-owner grant and a credential expiry bounded by that grant. Microbenchmarks use trusted low-level issuance fixtures and exclude approval cost.

The token is 32 random bytes represented as 64 hexadecimal characters; only its SHA-256 digest keys the trusted registry. It provides a basic bearer/server-policy baseline. It is not OAuth, JWT, or an RFC 8705 certificate-bound token. Certificate proof-of-possession and bearer registry lookup have different guarantees; lower lookup time cannot establish overall superiority.

## Approval and enforcement

The lab resource owner configures approved identities and a permission envelope. Requested tool/action/resource prefixes must fit that envelope. The owner signs an approval containing identity, policy ID, permissions, approval ID, approver, issuance time, and expiry. The issuer verifies the configured owner key and installs initial live policy for models using it. Agent protocol requests cannot access this control plane.

Live mutation is performed by a trusted administrator/harness. External, reference, and token models intentionally treat current server policy as authoritative, including expansion. Signed-ceiling authorization requires both live and issuer-maximum matches. Certificate-native permissions remain static; all models permit separate full credential kill.

On every admitted call, the gateway checks current local credential kill/expiry state, validates the selected policy, and matches tool/action/canonical resource before dispatch. Initial session establishment checks the certificate profile/signature and proves private-key possession through either a synthetic challenge fixture or the real mTLS handshake. These two session paths are labeled separately.

## Correctness and mutation measurements

The shared ten-case matrix contains three expected allows and seven expected denies: approved/nested file reads, an approved logical DNS lookup, outside paths/namespaces, traversal, prefix confusion, relative path, wrong action, and wrong tool. DNS rows are policy decisions only. No shell or DNS operation executes in this experiment.

- False-allow count: denied-by-specification cases that the implementation permits. Rate denominator: seven expected denies per matrix.
- False-deny count: allowed-by-specification cases that the implementation rejects. Rate denominator: three expected allows per matrix.
- Dynamic narrowing: allow a read, replace live policy with empty permissions, retry without reissuing.
- Dynamic expansion: replace live policy with a shell permission, ask for that permission without reissuing. This is a policy-decision experiment; no shell dispatch exists.

Repeated runs reuse a deterministic matrix. They are not new independent attack samples or evidence of a statistical prompt-injection rate. Tests separately exercise credential, parser, policy, approval, and dispatch failure conditions; test count should come from the actual run.

## Timing definitions

All evaluation timings use `time.perf_counter_ns`; output records timer resolution, environment, versions, starting Git state, source hashes, raw samples, and scopes.

| Measurement | Included | Excluded / interpretation |
|---|---|---|
| Leaf issuance | Fresh P-256 leaf key, certificate/profile/authorization payload construction, CA signing | CA creation, approval workflow, CA network protocol |
| DER parsing | DER bytes to `cryptography.Certificate` | Trust/profile validation and TLS |
| Trust/profile validation | Direct issuer signature, validity and lab profile | DER parse, authorization-extension decode, general PKIX path building, TLS |
| Synthetic session opening | Validation, identity/authorization decode, random challenge, private-key signing and verification | Real TLS establishment |
| Token issuance | Secret generation, digest key, registry record insertion | Approval/OAuth/network |
| Token session opening | Token hash, trusted registry lookup and expiry check | TLS and private-key proof |
| Authorization including audit | Complete local authorize call, policy lookup, matching and audit append | Tool execution and networked PDP |
| Local kill commit to first denial | Return of first subsequent authorize call after local kill commit | Network/polling/propagation/in-flight cancellation |

Default protocol: 10 runs; cyclic rotation of five model orders; 100 authorization warmup calls/model/run; 2,000 timed mixed allow/deny calls/model/run; 100 processing samples/model/run; 30 fresh-credential kill trials/model/run. Processing and kill sample counts are capped by the requested iteration count. Outputs retain per-run sample count, median, p95, minimum, maximum, and raw samples; a median of run p95 values is not a pooled p95. No timing result is a production latency bound.

Credential size reports presented credential bytes with encoding (DER or opaque-token UTF-8). It excludes the CA chain, TLS framing, server policy, and registry storage. Earlier size-scaling experiments concern the four certificate models and their verbose lab encoding; token-reference length is not the system's total authorization-storage cost.

## Persistent-connection demonstration

The trusted harness approves the agent and issues a ceiling certificate. One TLS 1.3 handshake opens one connection. Seven calls demonstrate allowed file dispatch, forbidden shell/path denial, live narrowing, policy restoration with successful dispatch, local kill, and repeated post-kill denial. Trusted control events occur outside the client request protocol. JSON records before/after dispatch counts and per-call reasons; denied calls do not execute the file operation.

The demo records one-host monotonic timestamps for kill commit, next decision, reply sent, and client receipt. These elapsed intervals include harness scheduling and transport as labeled. They are one local sample, not p95 values, distributed propagation guarantees, or cancellation of already-running calls.

## Reproduction and evidence handling

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m agent_auth.evaluation --runs 10 --iterations 2000 --warmup 100 --output-dir results/midterm
python -m agent_auth.mtls_demo > results/midterm/mtls_output.json
python -m json.tool results/midterm/mtls_output.json
```

Run on Ubuntu/Linux or WSL; the dispatcher requires POSIX directory-descriptor operations. Inspect metadata, summary, per-run distributions, raw samples, and demo audit/dispatch records. Historic Weeks 5–6 evidence remains separate from current generated output. A hosted Actions status must be taken from a run that actually executed, not inferred from local tests.

## Remaining experiments

Real MCP integration; distributed policy and kill state; outage/caching/concurrency/clock behavior; fuller PKIX and issuing hierarchy; deployed agent isolation; richer argument semantics and delegation; certificate-bound tokens or attribute certificates as additional baselines. These are beyond the current comparison.
