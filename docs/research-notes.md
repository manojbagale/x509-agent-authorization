# Research history and interpretation

## Proposal and first design phase

The Aug 27 proposal asked whether X.509 extensions could express tool permissions for MCP-based agents. The Sept 8 revision proposed Step CA, a Python MCP SDK agent, certificates lasting at most 15 minutes, per-call enforcement, ACME revocation, and normal/scope/lifecycle/adversarial scenarios. Neither proposal assigned week-by-week deadlines. Progress should be compared with those deliverables, not an invented original weekly schedule.

Progress Report 1 (Sept 14) documented research and design only. It separated authentication from authorization, reviewed SAN/EKU/custom-extension semantics, proposed a separate gateway, introduced an external-policy comparison, and identified resource matching and runtime session kill. Its diagrams and pseudocode were design evidence; implementation metrics were not claimed.

## Weeks 5–6 historical prototype

Progress Report 2 (Sept 28, explicitly Weeks 5–6) documented a Python `cryptography` research CA, short-lived client/server credentials, loopback mTLS, a local policy store/gateway, four authorization models, kill registry, audit, tests, dynamic policy experiments, OpenSSL interoperability, size scaling, and local decision microbenchmarks. Existing top-level `results/` and `evidence/` preserve that phase. Historic test counts and timings must not be substituted for the current implementation's results.

A direct-root local CA replaced Step CA in that prototype to isolate authorization semantics. The custom JSON TLS path is not MCP. Application-level kill replaced the assumption that passive certificate revocation instantly stops a session. These are substantive scope changes to explain, not completed versions of Step CA/ACME/MCP milestones.

## Midterm corrections

The current revision adds a fifth comparison: opaque bearer token plus equivalent server policy. The certificate-external model and token model share the initial agent policy and request matcher; certificate-native and reference/ceiling variants expose different placement and mutation semantics.

A trusted resource-owner allowlist and signed approval establish who approves identity and requested permissions. An issuer adapter verifies approval and installs the initial corresponding live policy. The client protocol has no issuance or administrative endpoint. Live administrators remain authoritative in external/reference/token modes; only the ceiling constrains later administrative expansion to the issuer maximum.

A persistent mTLS/file demonstration now exercises live policy changes and local kill across later calls on the same connection, with actual dispatch counts. A new evaluator separates issuance, DER parsing, trust/profile validation, synthetic session opening, authorization/audit, and local kill-to-denial. Fresh evidence must be generated and dated after code repairs; it must not be backdated into Weeks 5–6.

Package discovery was constrained to the intended Python package. Local installation/test verification and hosted Actions execution are separate claims. The observed hosted account-billing block prevented runner startup; it cannot be described as a passing hosted test run.

## Literature and bounded contribution

Established prior art already binds identity and authorization. RFC 5755 distinguishes public-key certificates from attribute certificates and explains their different lifetimes and issuers (§1). RFC 8705 standardizes mTLS client authentication and certificate-bound access tokens; RFC 9396 defines structured authorization requests. These are comparison context, not protocols implemented by this lab.

RFC 5280 defines SAN, EKU and critical-extension rules. SPIFFE constrains URI SAN to one workload identity. Those sources motivate identity in SAN and a private lab extension for experimental authority. Smallstep documents passive revocation as blocking renewal while an issued certificate remains valid until expiry, motivating a separately checked local kill registry.

The MCP authorization page pinned at 2025-11-25 describes OAuth access-token-based HTTP authorization. The experiment does not implement that stack or claim to replace it. WIMSE workload-creds-02 (July 2, 2026) and AIMS-00 (Sept 15, 2026) discuss workload identity and agent authentication/authorization using existing mechanisms. They remain works in progress, not RFC standards. AIMS postdates the original Aug 27/Sept 8 proposals and Sept 14 Report 1; it belongs in the later literature review. See [references](references.md) for exact versions and links.

The directly overlapping Sharif agent-identity profile draft-04 (Oct 2, 2026) proposes capability fields, delegation constraints, owner attribution, and kill/revocation endpoints. It is an individual Internet-Draft with no IETF endorsement or formal standards standing. It further limits any novelty claim: this lab compares specific enforcement semantics and costs rather than inventing agent capability certificates, and it does not claim to implement or validate the draft schema. This revision postdates Report 2 and belongs to the midterm literature update.

The project's contribution is a bounded, reproducible comparison of authority placement, local mutation, per-call termination, parsing/interoperability, and cost in one controlled tool gateway. It does not establish that agent authorization is otherwise unsolved or that no prior published system has evaluated similar mechanisms.

## Interpretation and remaining gaps

A policy reference binds an identity to a named policy but does not cap what that policy administrator can grant. A signed maximum combined with current policy gives the gateway an explicit intersection rule: live policy may narrow but cannot authorize outside the issuer maximum. This requires all relevant requests to cross the trusted gateway and requires issuer reissuance to expand the maximum.

This invariant says little about malicious actions inside approved scope, compromised issuers/gateways, deployment isolation, distributed propagation, or general prompt-injection resistance. Local matrix correctness and single-host timings are descriptive evidence. Real MCP/LLM integration, networked policy services, issuing hierarchy, broader argument controls and distributed/concurrent failure experiments remain incomplete milestones.
