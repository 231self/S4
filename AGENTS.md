# Maskura development conventions

## Version Control

This is a **jj** repository. Do not use `git` directly for mutations.

```bash
jj st                # show working copy status
jj log               # show commit history
jj commit -m "msg"   # commit working copy changes
jj git push          # push to origin
jj git fetch         # fetch from origin
```

All commits require a description (-m). Avoid interactive flags.
Verify with `jj st` and `jj log` after each mutation.

## Build

- `just check` — format, lint, test
- `just check-fmt` — `cargo fmt --check`
- `just check-lint` — `cargo clippy --all-targets -- -D warnings`
- `just test` — `cargo test --workspace`
- `just build-filters` — build the Wasm filter component
- `just build-sdks` — generate Python + TypeScript client SDKs from OpenAPI spec
- `just deny` — run cargo-deny
- `just audit` — run cargo-audit

## Code Conventions

- Rust 2024 edition.
- No warnings allowed in production code (RUSTFLAGS = -D warnings).
- Crate boundaries at security/protocol seams, not one crate per noun.
- If a crate has one caller and no independent tests, merge it.
- No functionality is added without extensive unit tests.
- Prefer specialized libraries over raw regex for PII detection (email, card validation).

## Database

- Relational modeling with normalized Postgres relations.
- JSONB only for opaque provider payloads, signed manifests, and audit details.
- Store money as integer minor units, byte usage as BIGINT.
- Use **SeaORM** for all database access: entities in `src/entity/` (derive
  `DeriveEntityModel`) + the SeaORM query builder. Never raw `sqlx::query(...)`
  strings in application code.
- All queries go through `Entity::find`/`insert`/`update`/`delete`/`update_many` etc.
- Database migrations are `.sql` files (schema only), managed by `sqlx::migrate!` —
  never applied manually via `psql` or `docker exec`.
- Migration files live in `migrations/` at the crate or workspace root, versioned sequentially.
- Run `sqlx migrate run` to apply; test migrations with `sqlx migrate info` before commit.

## API Design

- Frontend-to-backend APIs must be typed end-to-end.
- Define shared types in a dedicated crate or generate from OpenAPI/Smithy schemas.
- Use `serde` derive for all request/response types.
- API errors use a single typed envelope: `{ code, message, details? }`.
- Never pass raw upstream errors or stack traces to clients.
- S3 data-plane responses use proper S3 XML error documents.

## Architecture Decisions

Document every infrastructure, auth, storage, and deployment choice so automations stay in line.

### Auth

- **Supabase Auth (GoTrue)** for user signup, login, magic-link emails, and session management.
- Supabase JS client in the dashboard browser app; `jsonwebtoken` crate in the gateway validates JWTs.
- API keys (S3 access key + secret) are separate from user sessions. Generated on key creation, hashed with SHA-256, stored in Postgres.
- Gateway verifies API keys on S3 routes via `x-maskura-access-key` / `x-maskura-secret-key` headers (with permanent `x-s4-*` aliases) or `Authorization: Bearer <access_key>:<secret>`.

### Database

- **Supabase Postgres** (local: supabase CLI Docker containers; cloud: Supabase Pro).
- ORM: `sea-orm` (built on `sqlx`). Queries use entities (`crates/gateway/src/entity/`) and the SeaORM query builder — no raw SQL strings in code. `sqlx::migrate!` runs the `.sql` schema migrations.
- Migration files in workspace-root `migrations/`, versioned sequentially (`YYYYMMDDHHMMSS_description.sql`). The gateway runs `sqlx::migrate!()` at startup.
- `sqlx migrate run` applies; `sqlx migrate info` checks status. Never use `psql` or `docker exec` directly.
- **API keys are persisted in Postgres** when `DATABASE_URL` is set (`PostgresKeyStore`); otherwise the in-memory `KeyStore` is used (local dev). Both implement the async `KeyRepository` trait. `PostgresKeyStore` survives restarts / scale-to-zero.

### Storage (Object Data)

- **Storage resolution order**: explicit `x-maskura-storage-mode: managed`, per-object
  presigned URL (`x-maskura-backend-url`), per-workspace configuration, then configured
  Maskura service storage. Only explicit single-tenant mode may continue to global
  `S3_ENDPOINT` and then in-memory storage.

- **Presigned URL proxy**: User generates a presigned PUT/GET URL for their bucket with their own SDK. Sends it as `x-maskura-backend-url`. Maskura validates the API key, filters PII, and forwards to the presigned URL. No backend credentials are stored. Platform-agnostic (S3, R2, B2, MinIO).

- **Per-workspace backend**: `WorkspaceStorageRepository` maps authenticated users
  to canonical, unchanged `WorkspaceId` values and returns either `managed` or
  `s3_compatible` configuration with static credentials. `aws_role` is not
  implemented and is rejected; there is no per-user `BackendRegistry` contract.

- **Tenant storage boundary**: Multi-tenant startup requires non-empty
  `S4_SERVICE_BUCKETS` and rejects `S3_ENDPOINT`. Missing workspace configuration
  defaults to managed storage; repository or required-managed failures fail closed.
  Persisted workspace endpoints require an operator-trusted provider allowlist;
  the SDK resolves DNS again, so tenants must not control allowed provider DNS.
  Per-workspace and presigned clients disable proxies. Presigned HTTP is opt-in
  only for source `GET`; presigned `PUT`/`DELETE` stay HTTPS-only. AWS SDK clients
  make one attempt; transaction layers own their bounded retries.

- **Maskura service storage**: "Just works" mode. Users write PII-cleansed data without configuring any backend. Maskura manages dedicated buckets across multiple cloud providers. Objects are distributed via consistent hashing (150 virtual nodes per backend), dual-written to primary + replica, and read from the replica on primary miss. The operator-only `S4_SERVICE_BUCKETS` setting remains unchanged. Implementation: `crates/gateway/src/service_storage.rs`.

- **Multi-cloud write strategies — progress** (how concurrent multi-cloud writes work today, and the variants we track):

  | Strategy | Status | Behavior in Maskura today |
  |----------|--------|----------------------|
  | Dispersed writes across providers | ✅ implemented | Consistent-hash ring (150 vnodes/backend) assigns each key a primary + one replica, so keys spread across all configured backends; a provider is just an S3-compatible endpoint label (`S4_SERVICE_BUCKETS`) |
  | Active-active writes | ✅ implemented | `put` dual-writes primary + replica concurrently (`tokio::join!`); a replica write failure is logged and does not fail the request |
  | Active-read / passive-read (fail-over) | ✅ implemented | `get` reads the primary; on miss/error it falls back to the replica (`"primary miss for {key}, trying replica"`) |
  | Provider-agnostic R/W | ✅ implemented | No cloud-specific code — every backend is a plain S3-compatible endpoint (AWS, R2, B2, MinIO, …); consistent hashing, dual-write, and fail-over all operate on endpoints only |
  | Active-active reads (read both, compare / use fastest) | 🔲 planned | Would issue reads to primary + replica in parallel and return the first success (or verify equality) — a latency/consistency trade-off, not yet needed |
  | Quorum / consistency checking | 🔲 planned | e.g. write to N-of-M, verify digest across replicas on read; useful once object integrity is a requirement |
  | Regional fail-over / cross-region promotion | 🔲 planned | Promote replica to primary on sustained primary outage (today fail-over is per-request, not a topology change) |
  | Erasure / sharded dispersal | 🔲 not planned | Sharding a single object across providers (e.g. Reed-Solomon) — heavy, low value for PII-cleansed data |

  Anything not in the "✅ implemented" rows is a future consideration, not currently built.

- Objects are NOT persisted in Postgres — only metadata (keys, usage receipts) goes there.

### CLI (`maskura`)

- Binary crate at `crates/s4ctl/`. Full-featured CLI for Maskura operations; `s4ctl` remains an alias.
- Subcommands: `login`, `logout`, `whoami`, `key {create,list,revoke}`, `backend {get,set-aws,set-r2,set-b2,set-minio,presign}`, `put`, `get`, `list`, `health`, `local {init,down}`, `test upload`. The legacy `set-aws` command submits unsupported `aws_role` configuration and is rejected by the gateway.
- Auth from the preserved `~/.config/s4/config.json`, `MASKURA_ACCESS_KEY`/`MASKURA_SECRET_KEY` (with permanent `S4_*` aliases), or demo mode.
- Key expiry support: `--expiry never|30d|90d|1y` (or raw seconds).
- Backend presign: generates presigned URLs via local AWS CLI for use with the Maskura proxy.

### OpenAPI & SDK Generation

- OpenAPI 3.1 spec auto-generated from Rust types via `utoipa` + `utoipa-swagger-ui`.
- Served at `/openapi.json` (raw spec) and `/docs` (Swagger UI).
- `utoipa::ToSchema` on all API types (`ApiKeyResponse`, `ListKeyResponse`, `CreateKeyRequest`, `DeleteKeyRequest`, `ObjectResponse`, `BackendConfig`).
- `#[utoipa::path(...)]` annotations on all dashboard API handlers.
- `just build-sdks` extracts spec, runs `openapi-generator` (Docker) to produce Python and TypeScript SDKs in `sdks/python/` and `sdks/typescript/`.
- Schema is the single source of truth — SDKs always in sync with server changes.
- `scripts/generate-sdks.sh` re-applies the hand-written high-level client from `sdks/overlay/<lang>/` after each generation, so it survives regeneration:
  - `s4_client/highlevel.py` / `highlevel.ts` — `MaskuraClient` with `S4Client` compatibility, `put_object`/`get_object` (S3 data plane, `x-maskura-*` auth), `generate_keypair` (RSA-2048 SPKI), `attach_public_key`, and `decrypt_payload` (RSA-OAEP unwrap + AES-256-GCM). Python extras: `requests`, `cryptography`. TypeScript uses Web Crypto + global fetch (Node 18+ or browser).
  - Client flow: `generate_keypair()` → `attach_public_key(public_pem)` once → `put_object(...)` (gateway encrypts PII server-side) → `get_object(...)` + `decrypt_payload(bytes, private_pem)`.

### Web Dashboard

- Single-page HTML/JS served inline from the gateway binary at `/`.
- Uses Supabase JS client from CDN for auth. No React/Vite build step needed for the gateway crate.
- Dashboard JS calls `/dashboard/api/*` on the gateway for key management and object listing.

### Deployment

- Single internal Rust binary (`s4-gateway`). No separate frontend server in dev.
- **Local**: `restart-dev.sh` builds filters + gateway, kills stale port, nohup-launches.
- **Cloud candidates**: any container platform (fly.io, render, run.dev). Domain: `s4.the-no-corp.com`.
- **Emails**: loops.so for transactional (welcome, key created). Supabase Auth handles magic-link emails.
- **Control plane**: Cloudflare Workers + Pages (per plan Phase 3), deferred until alpha has paying users.

### Secrets & Config

- All secrets via environment variables, never in source or committed config.
- `LISTEN_ADDR`, `S3_ENDPOINT`, `DATABASE_URL`, `SUPABASE_JWT_SECRET`, `SUPABASE_URL`, `SUPABASE_ANON_KEY`, and the explicit customer/operator settings documented in `docs/security.md`.
- Local dev uses Supabase CLI default credentials; cloud uses Supabase dashboard values.

### Key Formats

- API key IDs: `s4_<32-hex>` (UUID without dashes).
- API key secrets: `s4s_<32-hex>`. Revealed once on creation, hashed with SHA-256 for storage.
- S3 requests authenticate with the plaintext secret (like AWS SigV4 secret key).

### Wasm Filter Plugins

- **Plugin pipeline**: Enabled plugins run in order. Output of plugin N becomes input of plugin N+1.
- **Plugin registry** (`crates/gateway/src/plugin_registry.rs`): Stores metadata (id, name, version, enabled) and component bytes. Supports import, enable/disable, remove, reorder.
- **Runtime import**: `POST /dashboard/api/plugins` with `.wasm` body + `x-maskura-plugin-name` header.
- **Runtime toggle**: `PUT /dashboard/api/plugins/{id}` with `{"enabled": true/false}`.
- **Auto-load**: `MASKURA_PLUGINS_DIR` loads all `.wasm` files from a directory at startup.
- **WIT interface** (`wit/s4-filter/world.wit`): `begin(Context)`, `transform(Vec<u8>) → Decision`, `finish()`. Context carries `format`, `content-type`, `policy-version`. Decision variants: `Emit`, `Drop`, `Reject`.
- **Sandbox**: 64 MiB memory, 10K table entries, 512 KiB stack. No host imports; pure byte-in/byte-out. `MASKURA_WASM_FUEL` (default 1B) sets the per-session instruction budget. The baseline `FilterEngine::new` default is 10M; crypto filters require the larger pipeline budget.
- **Default plugin**: `filters/pii-default/` — detects emails (via `@`), credit cards (Luhn check, 13-19 digits), SSNs (9 digits, SSA range validation). Redacts to `[REDACTED_EMAIL]`, `[REDACTED_CARD]`, `[REDACTED_SSN]`.

### Envelope Encryption per Field (design doc)

**Goal**: Encrypt PII fields so they are recoverable by authorized clients, without
storing plaintext or requiring Maskura to hold decryption keys. Falls back to redaction
when no public key is configured.

```
┌─────────────────────────────────────────────────────────────────────┐
│                      ENCRYPTION ARCHITECTURE                        │
├───────────────┬───────────────────────┬─────────────────────────────┤
│  Client SDK   │   Maskura Gateway     │       Storage               │
├───────────────┼───────────────────────┼─────────────────────────────┤
│               │                       │                             │
│ 1. Generate   │                       │                             │
│    keypair    │                       │                             │
│    (priv+pub) │                       │                             │
│               │                       │                             │
│ 2. POST /keys │                       │                             │
│    with X.509 │                       │                             │
│    cert ─────→│ 3. Store cert with    │                             │
│               │    API key in KeyStore│                             │
│               │                       │                             │
│ 4. PUT data   │                       │                             │
│    + API key ─→                       │                             │
│               │ 5. Authenticate       │                             │
│               │ 6. Plugin pipeline:   │                             │
│               │    a. Detect PII      │                             │
│               │    b. For each field: │                             │
│               │       • Gen DEK (AES) │                             │
│               │       • Encrypt DEK   │                             │
│               │         with cert     │                             │
│               │       • Encrypt field │                             │
│               │         with DEK      │                             │
│               │       • Package:      │                             │
│               │         {alg, iv,     │                             │
│               │          enc_dek, ct} │                             │
│               │ 7. Replace field ─────→ 8. Store                    │
│               │                       │                             │
│ 9. GET data  ←─ 10. Return encrypted  │                             │
│    + API key    │     fields as-is    │                             │
│               │                       │                             │
│ 11. Decrypt:  │                       │                             │
│     • Use priv│                       │                             │
│       key to  │                       │                             │
│       decrypt │                       │                             │
│       enc_dek │                       │                             │
│     • Use DEK │                       │                             │
│       to      │                       │                             │
│       decrypt │                       │                             │
│       field   │                       │                             │
└───────────────┴───────────────────────┴─────────────────────────────┘
```

**Envelope format** (each encrypted field):

```json
{
  "alg": "RSA-OAEP/AES-256-GCM",
  "iv": "<base64 12-byte IV>",
  "enc_dek": "<base64 RSA-OAEP-encrypted DEK>",
  "ct": "<base64 AES-256-GCM ciphertext>",
  "tag": "<base64 16-byte auth tag>"
}
```

**WIT interface extension** (to pass public key to plugin):

```wit
record context {
  format: string,
  content-type: string,
  policy-version: u64,
  public-key-pem: option<string>,    // NEW: X.509 cert for encryption
}
```

**Plugin composition (pipeline)**:

```
PUT /bucket/data.jsonl + Maskura API key (with X.509 cert)
  │
  ▼
[noop]          ← pass-through, baseline benchmark
  │
  ▼
[pii-detect]    ← identifies PII fields (email, SSN, card)
  │              ← returns Decision::Emit with metadata annotations
  ▼
[encrypt]       ← for each annotated PII field:
  │              ←   if public_key_pem is set in context:
  │              ←     envelope-encrypt (DEK + cert)
  │              ←   else:
  │              ←     redact to [REDACTED_*]
  ▼
Storage
```

**Stable (deterministic) encryption for JOIN keys**:

Certain fields (e.g., `user_id`, `email`) need deterministic encryption —
same input always produces same ciphertext. This enables JOINs and dedup
across datasets. Implemented as a separate plugin that uses AES-SIV
(deterministic AEAD) with a key derived from the API key secret.

```
field_value → HMAC(api_key_secret, field_value) → deterministic_ciphertext
```

NOT enabled by default — the user explicitly tags fields as "stable" in
the API key configuration or request headers.

**Client SDK flow**:

```bash
# 1. Initialize: generate keypair and send the certificate to Maskura
maskura key create --label prod-encryption --generate-encryption-key

# 2. Upload: Maskura encrypts PII fields with the certificate
maskura put ./data.jsonl ingest/data.jsonl --bucket my-ingest

# 3. Download — client decrypts fields with private key
maskura get ingest/data.jsonl --bucket my-ingest --decrypt
```

**Security properties**:

- Maskura never has access to the client's private key
- Maskura never sees plaintext PII after encryption (only during the transform in the Wasm sandbox, which is ephemeral per-session)
- Each field gets a unique DEK (even within the same record)
- DEK is encrypted with RSA-OAEP (2048-bit minimum) — only the private key holder can recover it
- AES-256-GCM provides authenticated encryption (confidentiality + integrity)
- Compromise of one field's DEK doesn't compromise other fields
- Public key rotation: generate a new API key with a new cert, re-upload data
