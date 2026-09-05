# ADR 0002: AWS Nitro Enclaves, TLS-in-Enclave, us-east-1

- Status: Accepted
- Date: 2026-08-09

## Context

Maskura's core value proposition is operator-resistant confidentiality: plaintext and secrets must be hidden from Maskura operators and cloud host administrators. The trusted execution environment must:

- Not expose plaintext to the parent EC2 instance.
- Terminate TLS inside the enclave (parent is an opaque byte relay).
- Support remote attestation for customer verification.
- Be available in a region with reasonable latency for US customers.

## Decision

Use AWS Nitro Enclaves with TLS termination inside the enclave (ACM for Nitro Enclaves with NGINX/PKCS#11). Deploy in `us-east-1` initially. Parent EC2 runs a minimal TCP/vsock relay that never sees plaintext. KMS enforces PCR-based attestation conditions before releasing gateway secrets.

## Consequences

- No Cloudflare proxying for data-plane traffic (would expose plaintext outside the enclave).
- ARM Graviton instances (`m7g.xlarge`) preferred for cost/performance; validate arm64 Wasmtime before provisioning.
- Local development uses a virtualized parent/enclave pair with clearly marked dev attestation roots.
- Documentation must record PCRs and release manifests for customer verification via `maskura`.
