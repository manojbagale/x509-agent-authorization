# Research security boundary

This is a controlled local research prototype. The trusted components are the resource-owner approval key, lab CA, issuer adapter, policy/credential stores, authorization gateway, kill registry, and file dispatcher. The client may request actions but must not control those components in a deployment.

## Properties tested

The client profile validates a direct research issuer signature, validity, required key usages, URI identity/trust domain, and supported critical extensions. This narrow validator is not a general PKIX path builder or an independent assertion of full SPIFFE conformance. The network path obtains the client certificate from TLS, rather than trusting a supplied certificate object as proof of identity.

Each well-formed tool call checks credential validity and current local kill state before matching tool, action, and canonical logical resource. External/reference/token modes consult the current server policy. The signed-ceiling mode also matches the immutable signed maximum. Malformed or missing policy denies. Invalid requests are denied before dispatch. No client API exists for approval, live policy mutation, kill, or CA issuance.

Owner approval checks a configured permission envelope and signs the initial grant. The trusted issuer verifies that grant and installs the corresponding initial live policy. Live administrative changes are an explicit separate authority: external/reference/token policy may expand; the ceiling model requires issuer reissue to expand its maximum. Agent requests do not grant themselves authority.

In the network demo, an authorized read reaches a server-owned file dispatcher. Directory-descriptor operations avoid symlink traversal and require regular files. Reads have a fixed 4,096-byte limit. This is a narrow POSIX tool adapter, not general filesystem isolation or a user-defined argument policy engine.

## Limits

- Client and trusted harness share a host and process infrastructure. The demo does not isolate the agent with containers, OS permissions, or network namespaces; a compromised local process is outside its tested boundary.
- Direct-root lab CA, lab-only OID, JSON-in-DER encoding, local memory state, and in-memory audit logs are unsuitable as a production PKI design without further work.
- Application kill denies later admitted calls. It does not revoke at the CA, distribute CRLs/OCSP, cancel an in-flight operation, or prove propagation across gateways.
- No deployed Step CA/ACME workflow, complete MCP/LLM integration, OAuth consent server, or networked policy decision point is implemented.
- The token baseline is a basic bearer reference. A holder of a copied valid token can act as that credential's subject until expiry/revocation; it is not bound to a private key or mTLS certificate.
- Agent private-key theft, malicious approved operations, approval/issuer/gateway compromise, policy-plane compromise within the ceiling, distributed outages, replay across audiences, and general delegation are not eliminated by the tested mechanism.
- Deterministic malicious-call tests do not measure prompt-injection success rates. Zero mismatches in a finite matrix is bounded correctness evidence, not a security proof.
- Native Windows is not supported by the POSIX file dispatcher. Use Ubuntu/Linux or WSL.

Generate keys only for the local lab. Never commit private keys or use lab credentials outside this trust domain. Do not include live tokens, secrets, or private keys in issue reports. Public approval/issuance and decision logs may describe identity and scope, but should not contain bearer secrets.
