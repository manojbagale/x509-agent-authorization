# Experiment design

## Research question

How much of an AI agent's authority should be carried in an X.509 credential, and which authorization decisions should remain in a live policy system?

## Compared models

| Model | Certificate carries | Runtime policy | Intended property |
|---|---|---|---|
| Certificate-native | identity + permissions | no | self-contained signed authority |
| External | identity only | yes | maximum runtime flexibility |
| Hybrid reference | identity + policy ID | yes | certificate-to-policy binding |
| Hybrid signed ceiling | identity + policy ID + maximum permissions | yes | runtime narrowing without runtime expansion beyond signed authority |

## Security boundary

The authorization gateway is outside the agent's trust boundary. A protected tool should not be directly reachable by the agent. Every tool request is evaluated against certificate validity, session state, and the selected authorization model.

## Correctness matrix

The current request set covers:

- allowed file reads;
- nested allowed paths;
- resource access outside scope;
- path traversal attempts;
- prefix-confusion paths such as `/research-old`;
- relative paths;
- wrong actions;
- wrong tools;
- allowed DNS access; and
- DNS access outside the allowed namespace.

## Negative identity/profile tests

The prototype rejects:

- wrong private-key possession;
- expired certificates;
- certificates from the wrong issuer;
- CA certificates presented as agent credentials;
- identities outside the configured SPIFFE trust domain; and
- more than one URI SAN.

## Runtime mutation experiment

After a session is opened, the live policy is first narrowed and then expanded.

- Certificate-native authority does not change without reissuance.
- External and hybrid-reference policies can both narrow and expand at runtime.
- Hybrid signed ceiling can narrow at runtime but cannot expand beyond the maximum authority signed into the certificate.

This distinction is central to the project because it separates **runtime policy agility** from **issuer-bounded authority**.

## Measurements

The prototype records:

- false-allow and false-deny counts;
- certificate DER size;
- session-opening validation/proof latency;
- p50/p95/p99 authorization-decision latency;
- local runtime kill-to-deny latency; and
- certificate-size scaling at 0, 1, 10, and 100 permissions.

The latency data is an in-process localhost microbenchmark. It is not a production throughput or network-latency claim.
