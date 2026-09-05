# ADR 0006: Dev Attestation Never Production-Valid

- Status: Accepted
- Date: 2026-08-09

## Context

The local development environment simulates the Nitro Enclave topology using Docker containers. It must be impossible to accidentally trust a dev attestation as production-valid.

## Decision

The dev attestation provider uses a private CA, clearly marked root certificate, and `UNTRUSTED DEVELOPMENT ATTESTATION` labels in all tools and outputs. The production attestation chain (AWS Nitro root, KMS PCR conditions) is never present in dev images.

The transport protocol, secret-provider trait, and attestation-provider trait are identical between dev and production, but their implementations are swapped. `maskura` and the dashboard prominently label dev attestations and refuse to treat dev PCRs as production-approved.

## Consequences

- Docker Compose local stack uses the same gateway binary but different provider implementations.
- No production signing keys, TLS certificates, or KMS configurations exist in the repository.
- CI gates prevent dev attestation data from entering production configuration.
