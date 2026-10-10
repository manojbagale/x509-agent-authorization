# Research history and interpretation

## Initial design

The initial August–September design explored X.509 extensions for MCP agent tool permissions. It proposed Step CA, a Python MCP SDK agent, short-lived certificates, per-call enforcement, and lifecycle/adversarial scenarios. Early research separated authentication from authorization, placed identity in SAN, and identified the need for a separate gateway and runtime session kill.

## September prototype

The September 28 implementation used a Python `cryptography` CA to isolate authorization semantics. It implemented client/server credentials, loopback mTLS, a local policy store, four authorization models, kill checks, audit, dynamic-policy experiments, OpenSSL interoperability checks, and certificate-size and timing measurements. Its recorded output is preserved in [`results/2026-09-28/`](../results/2026-09-28/).

A direct-root local CA replaced the planned Step CA deployment. The custom JSON TLS path does not implement MCP. Application-level kill addresses subsequent-call denial separately from certificate revocation, which does not by itself guarantee immediate termination of an established session.

## October extension

The October comparison adds an opaque bearer token with equivalent server policy. Both credential types use the same initial permissions and request matcher; the certificate models explore different placement and mutation rules.

Signed resource-owner approval establishes who approves the identity and requested permissions. An issuer adapter verifies that approval and installs initial live policy where applicable. Administration is outside the client request protocol. External, reference, and token policies can expand under a trusted administrator; the ceiling model also enforces the issuer's signed maximum.

The persistent mTLS demo exercises live policy changes and local kill with actual file dispatch. The evaluator separates issuance, DER parsing, profile validation, synthetic session opening, authorization/audit, and local kill-to-denial. The October 5 snapshot is preserved in [`results/2026-10-05/`](../results/2026-10-05/), with its own source hashes and environment. Local verification does not imply a successful hosted Actions run.

## Literature and bounded contribution

Established prior art already binds identity and authorization. RFC 5755 distinguishes public-key certificates from attribute certificates and explains their different lifetimes and issuers (§1). RFC 8705 standardizes mTLS client authentication and certificate-bound access tokens; RFC 9396 defines structured authorization requests. These are comparison context, not protocols implemented by this lab.

RFC 5280 defines SAN, EKU and critical-extension rules. SPIFFE constrains URI SAN to one workload identity. Those sources motivate identity in SAN and a private lab extension for experimental authority. Smallstep documents passive revocation as blocking renewal while an issued certificate remains valid until expiry, motivating a separately checked local kill registry.

The MCP authorization page pinned at 2025-11-25 describes OAuth access-token-based HTTP authorization. The experiment does not implement that stack or claim to replace it. WIMSE workload-creds-02 (July 2, 2026) and AIMS-00 (Sept 15, 2026) discuss workload identity and agent authentication/authorization using existing mechanisms. They remain works in progress, not RFC standards. See [references](references.md) for exact versions and links.

The directly overlapping Sharif agent-identity profile draft-04 (Oct 2, 2026) proposes capability fields, delegation constraints, owner attribution, and kill/revocation endpoints. It is an individual Internet-Draft with no IETF endorsement or formal standards standing. It further limits any novelty claim: this lab compares specific enforcement semantics and costs rather than inventing agent capability certificates, and it does not claim to implement or validate the draft schema. This revision was included in the October literature review.

The project's contribution is a bounded, reproducible comparison of authority placement, local mutation, per-call termination, parsing/interoperability, and cost in one controlled tool gateway. It does not establish that agent authorization is otherwise unsolved or that no prior published system has evaluated similar mechanisms.

## Interpretation and remaining gaps

A policy reference binds an identity to a named policy but does not cap what that policy administrator can grant. A signed maximum combined with current policy gives the gateway an explicit intersection rule: live policy may narrow but cannot authorize outside the issuer maximum. This requires all relevant requests to cross the trusted gateway and requires issuer reissuance to expand the maximum.

This invariant says little about malicious actions inside approved scope, compromised issuers/gateways, deployment isolation, distributed propagation, or general prompt-injection resistance. Local matrix correctness and single-host timings are descriptive evidence. Real MCP/LLM integration, networked policy services, issuing hierarchy, broader argument controls and distributed/concurrent failure experiments remain incomplete milestones.
