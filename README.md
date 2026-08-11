# S4 — PII-cleaning S3 proxy

S4 is an S3-compatible gateway that filters personally identifiable information (PII)
from data in transit. Point your existing S3 SDK at S4; S4 detects PII (emails, credit
cards, SSNs), redacts or encrypts it per field, and forwards the cleaned object to any
S3-compatible storage backend — or to a multi-cloud set of backends with dual-write and
fail-over.

- **Zero-trust by default**: PII never reaches your storage; S4 keeps no decryption keys.
- **Pluggable Wasm pipeline**: `noop`, `pii-default`, `email/ssn/card-detect`,
  `envelope-encrypt`, `stable-encrypt` — sandboxed with wasmtime, pure byte-in/byte-out.
- **Envelope encryption**: per-field AES-256-GCM with a per-field DEK wrapped by RSA-OAEP
  using your public key. S4 sees ciphertext only; only you can decrypt.
- **Provider-agnostic storage**: AWS S3, Google Cloud Storage, Backblaze B2, Cloudflare R2,
  Vultr Object Storage, MinIO, or any S3-compatible endpoint — single or multi-cloud
  (consistent-hash ring, dual-write, read fail-over).
- **Runs anywhere**: a single binary — locally, or serverless (Cloud Run, AWS Lambda),
  or on a plain VPS.
- **Typed SDKs**: generated Python and TypeScript clients with a high-level API
  (`put_object` / `get_object` / `generate_keypair` / `decrypt_payload`).

## Quickstart (local-only)

The fastest path needs no cloud account — S4 stores cleaned data in memory or a local
MinIO:

```bash
cargo install s4ctl          # or: cargo run -p s4ctl
s4ctl local init             # starts the gateway in local mode (AUTH_DISABLED)

# Write PII through S4 — it never reaches storage as plaintext
s4ctl key create --label dev
s4ctl put ./data.csv ingest/data.csv --bucket dev

# Read it back
s4ctl get ingest/data.csv --bucket dev
```

`local init` boots the gateway with auth disabled, keys in a local store, and an
in-memory object store. Point `S3_ENDPOINT` at MinIO (see `local/docker-compose.yml`)
for durable local storage.

## How it works

```
S3 SDK/CLI ──▶ S4 gateway (Wasm pipeline: detect → redact/encrypt) ──▶ storage
                     │                                                     │
                     └── PII stays out of the object;                     └── AWS S3, GCS, B2,
                         only envelopes/redactions                        R2, MinIO, multi-cloud
```

- **Pipeline**: plugins run in order; output of N feeds N+1. A plugin emits, drops, or
  rejects. Sandbox: 64 MiB memory, fuel-limited (`S4_WASM_FUEL`).
- **Envelope format** (per encrypted field): `{alg: "RSA-OAEP/AES-256-GCM", iv,
  enc_dek, ct, tag}`.
- **Stable encryption** (opt-in): deterministic AES-SIV-style ciphertext for JOIN keys.

## Deploy

- **Local / dev**: `just e2e` spins up MinIO and validates the full data plane.
- **Cloud Run** (scale-to-zero), **AWS Lambda** (Web Adapter), **Vultr** (Docker
  Compose + Object Storage), **Fly.io** — see `docs/` for per-provider guides.

## Documentation

- `docs/adr/` — architecture decision records (WIT interface, storage model, …).
- `AGENTS.md` — development conventions for AI agents and humans.

## Development

```bash
just check        # fmt + clippy + build filters + tests
just e2e          # end-to-end against MinIO (Docker)
just build-sdks   # regenerate Python/TypeScript SDKs from the OpenAPI spec
```

See `CONTRIBUTING.md`.

## License

Apache-2.0. See `LICENSE`.
