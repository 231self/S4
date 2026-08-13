# S4 Security

This document describes the security model of the S4 gateway: who authenticates,
how API keys are handled at rest and in use, what the trust boundaries are, and
what a production deployment must configure. It is written to be accurate for the
current code and explicitly flags anything that is planned.

---

## 1. Overview & trust boundaries

```
                       ┌────────────────────────────────────────────────────┐
  Dashboard (browser)  │                 S4 gateway                         │
   Supabase Auth/JWT ──▶  /dashboard/*  (JWT-validated, admin/keys/backends)│
                       │                                                    │
  S4 SDK / CLI ────────▶  S3 data plane  ── Wasm plugin pipeline ──▶ storage │
  native S3 tools ─────▶  (API key auth)  (filter/redact/encrypt)   (S3/R2/  │
                       └────────────────────────────────────────────────────┘  B2/MinIO)
```

Trust boundaries:

1. **Identity** — the data plane is authenticated by S4 API keys, not by user
   sessions. The dashboard is authenticated by Supabase Auth (JWT).
2. **Data in transit** — every request is HTTPS in production; the S3 API is
   SigV4-signed end-to-end between the client and the gateway.
3. **Data at rest** — objects are stored on the configured backend **after** the
   plugin pipeline; S4 never stores plaintext PII longer than the in-memory
   transform. API key secrets are never stored in plaintext (see §3).
4. **The gateway is a router** — it holds credentials only to re-sign requests
   to the configured backend (per-user backend config, service storage, or
   `S3_ENDPOINT`). The zero-trust presigned-URL path forwards without storing any
   backend credential at all.

## 2. Authentication

### Dashboard

- Supabase Auth (GoTrue); the gateway validates the access token JWT
  (`SUPABASE_JWT_SECRET`) for `/dashboard/*` routes.
- Local/demo mode (`AUTH_DISABLED=true`) bypasses auth entirely — do not use
  that flag outside local development.

### S3 data plane — API keys, two modes

An S4 API key is a pair `s4_<32-hex>` (access key ID) + `s4s_<32-hex>` (secret),
revealed once at creation. It authenticates two ways:

1. **S4 SDK path** — the client sends the plaintext secret in
   `x-s4-access-key` / `x-s4-secret-key` headers or
   `Authorization: Bearer <access_key>:<secret>`. The gateway compares
   `sha256(secret)` against the stored `secret_hash` (constant-time-ish compare).
2. **Native S3 tools** — the client puts the key in `~/.aws/credentials` and
   points any S3 SDK/CLI at the gateway with `--endpoint-url`. The client signs
   each request with AWS SigV4 using that key; the gateway **recomputes the
   signature** (same S3 signing rules the AWS SDK uses: single percent-encoding,
   no URI path normalization, `x-amz-content-sha256` payload hash) and rejects
   requests whose signature does not match the stored secret. SigV4 verification
   is skipped only in `AUTH_DISABLED` local mode.

`AWS4-…` Authorization headers are never trusted by themselves — they must
produce a valid signature for a registered key, otherwise the request is denied.

## 3. API key handling at rest

### Never plaintext

Each key stores two artifacts:

- `secret_hash` — `sha256(secret)`. Used for the SDK header path. Not reversible.
- `secret_encrypted` — an **envelope**: `v1:{base64(wrapped_dek)}:{base64(nonce)}:{base64(ciphertext+tag)}`
  where the secret is AES-256-GCM encrypted under a fresh, per-key 256-bit data
  key (DEK), and the DEK itself is encrypted ("wrapped") by a `KeyWrapping`
  implementation (`crates/gateway/src/key_cipher.rs`).

The plaintext secret exists only in the create-key HTTP response and, transiently,
in memory when a SigV4 signature is verified. It is never logged or persisted.

### Key-wrapping providers

| Provider | Status | Master key location | When to use |
|----------|--------|---------------------|-------------|
| `LocalKeyWrapping` (`S4_SECRET_KEK`) | ✅ implemented | Operator-provided 32-byte KEK (env var), held in gateway memory | Local dev only |
| Ephemeral (no KEK configured) | ✅ implemented | Random in-memory KEK, lost on restart | Local dev only |
| HashiCorp Vault transit (`S4_VAULT_ADDR`) | ✅ via injected `KeyWrapping` | Vault server (self-host or HCP free tier) | **Production** |
| AWS KMS (`S4_KMS_KEY_ID`) | ✅ via injected `KeyWrapping` | AWS KMS key (free tier ≈ 20k req/mo) | **Production** |

`build_state` accepts an injected `Arc<dyn KeyWrapping>` (alongside the
`Arc<dyn ControlPlane>`). The OSS self-host binary resolves `S4_SECRET_KEK` /
ephemeral via `key_cipher::default_wrapping()`; a KMS/Vault-backed wrapper can be
supplied by an embedding deployment (e.g. the hosted SaaS control plane) without
changing the engine.

> **⚠ Non-local deployments must use a KMS/Vault-backed key wrapping.**
> Running with auth enabled (`AUTH_DISABLED=false`) while the active wrapping is
> the local KEK or an ephemeral key is **not secure** for shared/non-local use:
> the master key is either operator-managed plaintext or disappears on restart
> (SigV4 verification silently stops working). The gateway logs a prominent
> warning at startup in this configuration.

Why KMS/Vault: the master key never exists on S4 infrastructure. A compromised
database yields only ciphertext and wrapped DEKs that cannot be decrypted without
the KMS/Vault key, and the key can be rotated/revoked centrally.

### Legacy keys

Keys created before `secret_encrypted` existed (or by keystores without a cipher)
have no envelope and continue to authenticate via the SDK path. They **cannot**
verify SigV4 signatures (a hash cannot be un-hashed) — regenerate them if you
need native S3 tools.

## 4. The plugin pipeline (data transformation)

- Plugins are Wasm components (`wasmtime`), 64 MiB memory, fuel-limited
  (`S4_WASM_FUEL`, default 1B), no host imports — byte-in/byte-out.
- The pipeline is deterministic and runs **before** data reaches storage:
  redaction replaces PII, encryption (per-field RSA-OAEP/AES-256-GCM) keeps the
  decryption key solely with the client.
- Per-field encryption never requires S4 to hold a decryption key; `stable-encrypt`
  (AES-SIV) is opt-in for JOIN keys and is derived from the API key secret.

### Read-time processing (`x-s4-process: read`) — agent-safe reads

In addition to the write path (pipeline runs *before* storage), S4 can run the
pipeline on **read**: a GET with `x-s4-process: read` (or `true`) fetches the raw
object and scrubs it before returning it to the caller.

- **Raw at rest, safe on the way out** — the object in storage is unchanged; the
  caller (e.g. an AI agent) receives only the redacted/encrypted projection. No
  duplicate cleaned dataset to keep in sync.
- **Trust boundary** — the header is honored for any authenticated caller with
  read permission; it is not a separate authorization scope. If an object's raw
  bytes must never leave storage, restrict read access itself (per-user backend /
  IAM policy) — read-time processing reduces *exposure to the caller*, it does
  not prevent a caller from issuing a plain GET.
- **Format-aware** — the response format is detected from the object's
  Content-Type (JSON/JSONL/CSV/TSV/text); binary formats fall back to passthrough.
- **Resilient** — a pipeline error falls back to raw bytes (logged) so reads never
  break.

## 5. Storage backends

- **Presigned URL proxy (`x-s4-backend-url`)** — the user generates a presigned
  URL with their own cloud SDK; S4 filters and forwards. **No backend credential
  is stored.**
- **Per-user backend config** — IAM role (trusted by a unique External ID) or
  endpoint+token for non-AWS (R2/B2/MinIO). Credentials are kept in the in-memory
  `BackendRegistry`, never persisted.
- **Service storage** — S4-managed multi-cloud buckets (`S4_SERVICE_BUCKETS`).
- **Global `S3_ENDPOINT`** — shared backend; credentials come from
  `S3_ACCESS_KEY_ID`/`S3_SECRET_ACCESS_KEY`/`S3_REGION` (never hardcoded).

Multipart uploads are buffered in gateway memory and assembled before the filter
pipeline runs — plan memory sizing accordingly for very large parts.

## 6. Secrets & configuration

All secrets come from environment variables — never source, logs, or committed
config:

| Variable | Purpose |
|----------|---------|
| `AUTH_DISABLED` | `true` = local/demo mode (auth bypassed). **Never set in production.** |
| `DATABASE_URL` | Postgres keystore (persistent keys) |
| `S4_KEYS_FILE` | JSON keystore file (local mode default) |
| `S4_SECRET_KEK` | Local KEK (base64, 32 bytes) — **dev only** |
| `S4_VAULT_ADDR` / `S4_VAULT_TOKEN` / `S4_VAULT_TRANSIT_KEY` | Vault transit wrapping (injected) |
| `S4_KMS_KEY_ID` | AWS KMS wrapping (injected) |
| `S3_ENDPOINT`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_REGION` | Global S3 backend |
| `S4_SERVICE_BUCKETS` | Managed multi-cloud backends (`provider|endpoint|region|bucket|access_key|secret_key;…`) |
| `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_JWT_SECRET` | Dashboard auth |

## 7. Production deployment checklist

- [ ] `AUTH_DISABLED` unset/false.
- [ ] KMS/Vault-backed `KeyWrapping` configured (`S4_VAULT_ADDR` or `S4_KMS_KEY_ID`) —
      confirm the startup log shows the KMS/Vault wrapping, not local.
- [ ] Keys persisted in Postgres (`DATABASE_URL`), not in-memory.
- [ ] TLS termination (terminating proxy / container platform) — SigV4 is
      over-the-wire signed, but HTTPS is required for the secret-bearing headers.
- [ ] No `S4_SECRET_KEK` in the environment (dev-only).
- [ ] `S4_KEYS_FILE`/`keys.json` not shipped in the image.
- [ ] S3 data-plane body limit sized for your objects (default 5 GiB for PUTs).
- [ ] Backend credentials via per-user IAM roles / presigned URLs where possible
      (zero-trust), not shared `S3_ENDPOINT` creds.
- [ ] Container runs as non-root; network egress limited to the backends + KMS/Vault.

## 8. Known limitations

- SigV4 verification requires the key's plaintext secret to be recoverable —
  only keys created with an envelope support it.
- The SDK header path sends the secret in headers; do not use it without TLS.
- Multipart parts are buffered in memory.
- Legacy hash-only keys cannot be migrated to SigV4 automatically.
