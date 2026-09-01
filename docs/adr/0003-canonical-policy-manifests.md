# ADR 0003: Canonical CBOR and Ed25519 Policy Manifests

Date: 2026-08-09
Status: Accepted

## Context

Tenant-defined pipeline configuration (destinations, routes, filters, limits) must be verifiably authentic. Maskura operators must not silently change policy. The signed manifest is the customer's attestable statement of intent.

Options considered:
- **JSON with detached signature**: Non-deterministic whitespace and key ordering make verification fragile.
- **Protobuf/FlatBuffers**: Binary formats with deterministic encoding, but separate schema tooling adds complexity.
- **Canonical CBOR with Ed25519**: Deterministic map ordering, compact binary encoding, and well-supported Rust libraries.

## Decision

Use canonical CBOR encoding with lexicographically sorted map keys and Ed25519 signatures. The manifest body is encoded deterministically, then signed. The resulting `SignedManifest` carries the canonical body bytes, signer ID, and signature. Verification validates the signature against trust roots and checks expiry/version monotonicity.

## Consequences

- Trust roots are tenant-managed Ed25519 public keys provisioned during onboarding.
- Policy updates require a new signature; the dashboard can draft but `maskura` signs and activates.
- Manifests have short expiry; monotonic version warnings on stale manifests discourage rollback.
- Implementation uses `ciborium` crate with BTreeMap-based canonical serialization.
