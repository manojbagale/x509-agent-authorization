# Research Notes — Weeks 5–6

## Main question

How much of an AI agent's authority should be carried in an X.509 credential, and which authorization decisions should remain in a live policy system?

## Standards findings

1. **RFC 5280** permits private X.509v3 extensions. Unknown critical extensions must cause rejection; unknown non-critical extensions may be ignored. That creates a concrete interoperability-versus-fail-closed trade-off for certificate-carried authorization.
2. **SPIFFE X.509-SVID** uses one URI SAN as workload identity. This supports treating SAN as identity rather than as a list of tool permissions.
3. **RFC 5755** is important prior art because it explicitly separates authorization attributes from ordinary public-key certificates when authorization has different issuers or lifetimes.
4. **RFC 8705** is strong precedent for a hybrid design: mTLS/X.509 proves client identity and key possession while a separate access token carries authorization.
5. **WIMSE Workload Credentials** treats X.509 primarily as a workload identity credential.
6. **AIMS (draft-ietf-wimse-aims-00)** separates credential, authentication, authorization, observability, and remediation concerns. It is a working-group Internet-Draft, not an RFC.
7. **Smallstep** distinguishes passive from active revocation. Passive revocation can leave an already-issued certificate valid until expiry, which motivates testing an application-level kill path separately.
8. Emerging agent-certificate drafts experiment with capability information in X.509, but they remain Internet-Drafts rather than standards.

## Prototype implemented

The prototype compares four models using the same agent identity and request set:

- **Certificate-native:** permissions are embedded in a private X.509 extension.
- **External:** X.509 carries identity only; permissions live in a policy store.
- **Hybrid reference:** X.509 carries identity plus a policy identifier; detailed permissions remain external.
- **Hybrid signed ceiling:** X.509 additionally carries a maximum permission set; live policy may narrow authority but may not expand beyond the signed ceiling.

Implemented components include:

- local ECDSA research CA and short-lived leaf credentials;
- URI SAN workload identity;
- Basic Constraints, Key Usage, and `clientAuth` EKU checks;
- proof-of-possession challenge for unit tests;
- a real localhost TLS 1.3 mutual-authentication demo;
- per-request authorization gateway;
- path canonicalization and deny-by-default matching;
- runtime kill registry and structured audit events;
- negative certificate/profile tests;
- OpenSSL critical-extension interoperability checks;
- certificate-size scaling measurements; and
- repeated local latency measurements.

## Verified prototype results

- **20 automated tests pass** in the current prototype.
- Across the 10-request correctness matrix for each of the four models, there were **0 false allows and 0 false denies**.
- Wrong private key, expired credential, wrong issuer, CA-as-leaf, wrong SPIFFE trust domain, and multiple URI SAN identities are rejected.
- External and hybrid-reference policy can narrow or broaden authority during a session without certificate reissuance.
- Certificate-native permissions remain fixed for the certificate lifetime unless a new certificate is issued.
- The **hybrid signed-ceiling** model allows live policy to narrow authority but blocks expansion beyond the maximum permission set signed by the issuer.
- Median DER certificate size grows from **557 B to 7,964 B** for certificate-native authorization when moving from 0 to 100 permissions; the external identity-only certificate remains about **488 B**.
- Across 10 repeated in-process runs, median p95 policy-decision latency was approximately **0.0067 ms** for certificate-native, **0.0067 ms** for external, **0.0068 ms** for hybrid reference, and **0.0078 ms** for hybrid signed ceiling. These are local microbenchmarks, not production network-performance claims.
- A real localhost **TLS 1.3 mTLS** handshake completed successfully, the gateway extracted the peer certificate, allowed an in-scope file read, and denied an unauthorized shell request.
- Generic OpenSSL validation accepts the experimental authorization extension when it is non-critical and rejects the same unknown extension when marked critical with `unhandled critical extension`.

## Current interpretation

The evidence does not support the claim that X.509 should become the complete authorization database for an AI agent.

A narrower working interpretation is better supported:

- X.509 is a strong fit for cryptographic workload identity and proof of private-key possession.
- Certificate-carried authority is viable when the assertion is stable, issuer-bounded, and short-lived.
- Dynamic resource- and argument-level permissions, rapid remediation, and runtime policy changes fit more naturally in a live authorization plane.
- A policy reference alone does not create a cryptographic authority ceiling.
- A hybrid signed-ceiling model is worth further study because it combines a CA-signed maximum authority with runtime narrowing.

The next phase should move these experiments from the local prototype toward a real MCP tool path, stronger PKIX validation, richer argument-level policy, and concurrent networked measurements.
