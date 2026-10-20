# Remote policy decisions

The optional remote path moves live policy evaluation into a separate Python process. The certificate gateway remains the enforcement point. It reads the authenticated agent identity and signed policy reference from the session, asks the decision service about the requested tool/action/resource, then applies the signed ceiling locally.

`policy_service.py` contains the loopback HTTP client, service and process harness. `gateway.py` accepts an optional `policy_decider`; the original in-process path remains the default. Certificate-native authorization does not contact the service. The remote extension currently covers external, hybrid and hybrid-ceiling certificate modes; the opaque-token baseline remains local.

## Request and trust boundary

The gateway sends `POST /access/v1/evaluation` with subject, action, resource and context objects. The endpoint and vocabulary follow [OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html), particularly sections 5, 6 and 10. The application context carries mode and policy ID. The service binds the subject and policy reference to its configured grant.

This is a restricted lab profile, not full AuthZEN conformance. Unlike the specification's HTTPS binding, this service uses HTTP restricted to explicit `127.0.0.1`, with a random gateway service token. That token authenticates the gateway's requests; it is not an agent credential or OAuth token. It is kept out of outputs. Deployment needs authenticated encrypted transport and isolation from untrusted local processes. Python's [http.server](https://docs.python.org/3.12/library/http.server.html) is intended here only for a small controlled experiment.

Policy replacement and fault injection use an inherited multiprocessing pipe held by the trusted harness. There is no HTTP administration route. Replacement is acknowledged after the service updates its state. Restart currently reconstructs the initial configuration; it does not persist policy updates.

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

## Remaining work

Authenticated service TLS, persistent versioned policy, distributed kill propagation, concurrent clients, load and partial-response deadline tests, MCP integration and deployment isolation remain open. A remote decision introduces another availability dependency; denying on failure preserves the access boundary at the cost of blocking legitimate work during outages.
