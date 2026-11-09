# Remote policy decisions

The optional remote path moves live policy evaluation into a separate Python process. The certificate gateway remains the enforcement point. It reads the authenticated agent identity and signed policy reference from the session, asks the decision service about the requested tool/action/resource, then applies the signed ceiling locally.

`policy_service.py` contains the loopback HTTP client, service and process harness. `gateway.py` accepts an optional `policy_decider`; the original in-process path remains the default. Certificate-native authorization does not contact the service. The remote extension currently covers external, hybrid and hybrid-ceiling certificate modes; the opaque-token baseline remains local.

## Request and trust boundary

The gateway sends `POST /access/v1/evaluation` with subject, action, resource and context objects. The endpoint and vocabulary follow [OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html), particularly sections 5, 6 and 10. The application context carries mode and policy ID. The service binds the subject and policy reference to its configured grant.

This is a restricted lab profile, not full AuthZEN conformance. The original comparison uses HTTP restricted to explicit `127.0.0.1`, with a random gateway service token. The secure profile below adds mutual TLS. That token authenticates the gateway's requests; it is not an agent credential or OAuth token. It is kept out of outputs. Deployment still needs isolation from untrusted local processes. Python's [http.server](https://docs.python.org/3.12/library/http.server.html) is intended here only for a small controlled experiment.

Policy replacement and fault injection use an inherited multiprocessing pipe held by the trusted harness. There is no HTTP administration route. Replacement is acknowledged after the service updates its state. In-memory mode reconstructs the initial configuration at restart. The optional SQLite mode below retains committed updates.

## Enforcement and failures

The gateway checks request shape, local kill state and certificate validity before evaluation. Each remote decision uses a fresh HTTP connection with a 150 ms socket timeout, no retry and no decision cache. Requests and replies are bounded at 16 KiB. JSON duplicate fields, missing decisions, non-boolean decisions, non-200 status, oversized replies and transport failures are rejected. The socket timeout is not a guaranteed end-to-end deadline against a peer that continuously streams partial data.

| Observation | Gateway result |
|---|---|
| Service permits and certificate permits | Allow |
| Live policy denies | `outside_scope` |
| Service permits beyond signed maximum | `outside_signed_ceiling` |
| Unavailable, slow or invalid service response | `policy_unavailable` |
| Local credential kill | `session_revoked` |
| Expired credential | `certificate_expired` |

Lifecycle state is checked again before returning an allow because it may change while a remote decision is pending. The existing dispatcher is called only after the gateway allows the request. This does not cancel an in-flight operation or make the decision and dispatch an atomic distributed transaction.

## Reproduce

```bash
python -m pip install -e ".[dev]"
python -m pytest
python scripts/demo.py --remote-policy --output .local-runs/remote-demo.json
python scripts/evaluate_remote_policy.py --output-dir .local-runs/remote-policy
```

The demo makes 13 requests over one mTLS connection, including live narrowing, ceiling rejection, HTTP 503, a delayed response, an invalid decision, process shutdown, recovery and local revocation. Its three allowed requests perform real file reads; denied requests leave dispatch counts unchanged. The two recorded policy process IDs identify the initial process and its replacement after recovery.

The evaluator compares three certificate modes across local and HTTP policy paths. Defaults: five runs, 100 timed calls per mode/path/run, ten warmups. Local/HTTP order alternates by run, and both use the same certificate and deterministic ten-request matrix. Timing covers authorization and audit; HTTP additionally includes a new loopback TCP connection, serialization, service execution and response parsing. Client mTLS, certificate issuance and tool execution are outside the timer.

Six failure conditions each receive ten trials: HTTP error, timeout, non-boolean decision, duplicate decision, oversized reply and stopped process. A successful request precedes each failure group. Repetition checks consistency, not independent attack coverage. JSON output retains raw timings, environment, source revision and SHA-256 hashes.

## Secure transport and persistent policy

`python scripts/demo.py --secure-policy` exercises the same 13-call file demo with TLS 1.3 on the gateway-to-policy link as well as the existing agent connection. `service_tls.py` creates a separate ephemeral service CA, a `localhost` server certificate and a gateway client certificate. The client checks the server chain and hostname. The service requires a trusted client certificate and compares its SHA-256 leaf fingerprint with the configured gateway fingerprint before accepting the bearer service token. The fingerprint is an explicit local allowlist; it is not automated rotation or general workload attestation. Private files use mode 0600 in a temporary directory. The demo retains in-memory policy to preserve its original recovery scenario.

`PolicyService(..., tls=config, state_path=path)` opts into persistent policy. `policy_state.py` stores one agent/policy binding, permissions and positive version in SQLite. A new database starts at version 1; an existing invalid, empty or differently bound record fails startup. Each decision reads a validated committed snapshot. Updates use `BEGIN IMMEDIATE`, compare `expected_version`, increment it and acknowledge only after commit. Stale writers raise `PolicyConflict`. WAL and `synchronous=FULL` are configured. There is no HTTP administration API: the trusted inherited pipe remains the control path.

Persistent updates require `replace_policy(policy, expected_version=service.version)`. A reply reports its snapshot version through `X-Policy-Version`; the JSON decision body remains a boolean envelope. Snapshot selection occurs before evaluation, so an already pending old-version reply can finish after an update acknowledgement. The version is evidence of the evaluated snapshot, not a promise that every in-flight request is canceled or re-evaluated. Local certificate expiry and kill are still rechecked in the gateway before returning allow.

`python scripts/evaluate_secure_policy.py` compares local, HTTP/memory, mTLS/memory and mTLS/SQLite authorization in the signed-ceiling mode. Five rotated runs use the same issued session across paths within each run, ten warmups and 100 timed allowed calls per path. It records seven trust-failure groups (ten trials each), ten abrupt process restarts after acknowledged narrowing, stale-update rejection, 1/4/8-client decision batches and an update during 320 concurrent requests. The output distinguishes gateway authorization/audit timing from direct policy API concurrency timing. Raw samples, environment and source hashes are preserved.

SQLite persistence is tested against child-process termination, not power loss. Its directory and files remain trusted: replacing the entire database with an older copy, deleting it before startup, disk loss or a malicious local administrator are outside the guarantee. Audits and kill state still live in gateway memory.

## Remaining work

Distributed kill propagation, sustained overload and partial-response deadline tests, certificate rotation, MCP integration and deployment isolation remain open. The standard-library HTTP server remains a controlled lab harness even when wrapped in TLS. A remote decision introduces another availability dependency; denying on failure blocks legitimate work during outages.
