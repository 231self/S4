# S4 Security

This document describes the security model of the S4 gateway as it exists in
the current streaming architecture (Phases 0–12): who authenticates, how API
keys are handled at rest and in use, how objects are transformed and staged,
what the trust boundaries are, what a production deployment must configure, and
what S4 explicitly does **not** guarantee. Anything not described here is not a
guarantee.

For the vulnerability reporting process, see [SECURITY.md](../SECURITY.md).

---

## 1. Overview & trust boundaries

```
                        ┌─────────────────────────────────────────────────────┐
  Dashboard (browser)   │                 S4 gateway                          │
   Supabase Auth/JWT ───▶  /dashboard/*  (JWT-validated)                      │
                        │                                                     │
  S4 SDK / CLI ─────────▶  S3 data plane  ── Wasm pipeline ──▶ storage        │
  native S3 tools ──────▶  (SigV4 / API key)  (streaming, fail-closed)        │
                        │  (durable journal + staging for transactional paths)│
                        └─────────────────────────────────────────────────────┘
                                                                   (S3/R2/B2/MinIO)
```

Trust boundaries:

1. **Identity** — the data plane is authenticated by S4 API keys. Requests are
   accepted only when the SigV4 signature or the SDK header secret verifies
   against a registered key; the dashboard is authenticated by Supabase Auth
   (JWT). `AUTH_DISABLED=true` bypasses auth and is a local-development-only
   mode.
2. **Data in transit** — HTTPS is required in production. SigV4 signatures are
   computed over-the-wire but the secret-bearing headers must not traverse
   plaintext HTTP.
3. **Data at rest** — objects are stored on the configured backend **after**
   the plugin pipeline has run. Staged object bytes are encrypted before they
   touch the staging artifact store or disk. API key secrets are never stored
   in plaintext (see §4).
4. **The gateway is a router** — it holds backend credentials only to re-sign
   requests to the configured backend. The zero-trust presigned-URL path
   forwards without storing any backend credential at all.

## 2. Authentication

### Dashboard

- Supabase Auth (GoTrue); the gateway validates the access token JWT
  (`SUPABASE_JWT_SECRET`, with audience validation) for `/dashboard/*` routes.
- Local/demo mode (`AUTH_DISABLED=true`) bypasses auth entirely — do not use
  that flag outside local development.

### S3 data plane — API keys

An S4 API key is a pair `s4_<32-hex>` (access key ID) + `s4s_<32-hex>`
(secret), revealed once at creation. Two authentication paths:

1. **S4 SDK header path** — the client sends the plaintext secret in
   `x-s4-access-key` / `x-s4-secret-key` headers or
   `Authorization: Bearer <access_key>:<secret>`. The gateway compares
   `sha256(secret)` against the stored `secret_hash`. Requires TLS.
2. **Native S3 tools (SigV4)** — the client signs each request with AWS SigV4
   using its S4 key. The gateway recomputes the signature and rejects requests
   whose signature does not match the stored secret.

### SigV4 verification

Verification is **header-first and pre-body**: parsing, credential-scope
checks, signed-header validation, timestamp checks, and canonical seed
signature verification all complete before a request body is polled.

- **Header auth** — `Authorization: AWS4-HMAC-SHA256 Credential=…` with
  `x-amz-date` and `x-amz-content-sha256` (mandatory for header auth).
- **Query auth (presigned)** — `X-Amz-*` query parameters; presigned requests
  without an explicit `x-amz-content-sha256` header default to
  `UNSIGNED-PAYLOAD`, which is only accepted over trusted TLS.
- **Signed-header integrity** — `host` is always signed, and header auth also
  requires signed `x-amz-date` and `x-amz-content-sha256`. In every SigV4 mode,
  every present `x-amz-*` header except `x-amz-user-agent` and
  `x-amz-checksum-mode`, plus each present request-semantic header
  (`x-s4-storage-mode`, `x-s4-backend-url`, `x-s4-process`,
  `x-s4-stable-fields`, `content-type`, `content-encoding`, and `content-md5`),
  must appear in `SignedHeaders`, occur exactly once, contain valid UTF-8, and
  already equal AWS SigV4 TrimAll form: no leading or trailing SP/HTAB and every
  internal SP/HTAB run collapsed to one ASCII space. The gateway rejects rather
  than rewrites noncanonical values, including comma-equivalent duplicates, so
  metadata and tagging consumers observe the same sole canonical value that was
  signed. The two exact exceptions are also exempt from duplicate and canonical
  value enforcement because the pinned `aws-sigv4` presigner excludes them.
  `x-amz-checksum-mode` is read-only response-integrity negotiation, not a
  storage-selection or processing semantic. Optional headers may be absent, so
  a normal host-only presigned GET remains valid; violations receive the generic
  signature-mismatch response before the request body is read.
- **Scope validation** — region (`S4_SIGV4_REGION`, default `us-east-1`),
  service (`s3`), and terminator (`aws4_request`) are enforced; the request
  timestamp must fall within the clock-skew window (15 minutes) and presigned
  URLs cannot exceed 7 days.
- **Payload integrity** — the request body is verified against the declared
  payload hash and, for aws-chunked streaming, each chunk signature and the
  `x-amz-trailer`-declared checksum trailer are verified incrementally with
  constant-time comparisons. Supported modes:
  `UNSIGNED-PAYLOAD`, `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`,
  `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`,
  `STREAMING-UNSIGNED-PAYLOAD-TRAILER`, and a raw SHA-256 payload hash.
- **Checksums** — `x-amz-checksum-*` (CRC32, CRC32C, CRC64NVME, SHA-1,
  SHA-256) declared in headers or trailers are verified against the decoded
  body. Conflicting declarations, missing trailer declarations, duplicate
  trailers, trailing data after the final frame, and mismatched checksums are
  rejected. Decoded length must match `x-amz-decoded-content-length`.
- **Signing-key cache** — a bounded, TTL-based cache stores only derived
  signing keys and secret fingerprints; the plaintext secret exists in memory
  only transiently during verification and is never logged or persisted.
- SigV4 verification is skipped only in `AUTH_DISABLED` local mode.

## 3. API key handling at rest

Each key stores two artifacts:

- `secret_hash` — `sha256(secret)` for the SDK header path. Not reversible.
- `secret_encrypted` — an envelope: `v2:{base64(wrapped_dek)}:{base64(nonce)}:{base64(ciphertext+tag)}`
  where the secret is AES-256-GCM encrypted under a fresh, per-key 256-bit data
  key (DEK), and the DEK is wrapped by a `KeyWrapping` implementation
  (`crates/gateway/src/key_cipher.rs`). v2 envelopes bind the API key identity
  as AES-GCM additional authenticated data (AAD), preventing an encrypted
  secret from being moved to another key. v1 envelopes are accepted for legacy
  keys.

The plaintext secret exists only in the create-key HTTP response and,
transiently, in memory during SigV4 verification. It is never logged or
persisted.

Credential mutations are bounded before persistence. API-key and MCP labels are
trimmed, non-empty, free of control characters, and at most 128 UTF-8 bytes.
Non-zero API-key and MCP lifetimes are at most one year (`0` means no expiry).
Encryption public keys are at most 16 KiB and must be an SPKI public-key PEM or
X.509 certificate carrying an RSA key between 2048 and 4096 bits, matching the
formats consumed by the envelope-encryption filter. Credential JSON endpoints
also have route-specific body limits; oversized requests receive `413`.

Credential creation returns plaintext only after the repository has committed
the new credential. File-backed mutations remain hidden from concurrent readers
until snapshot persistence succeeds, and failed mutations restore the prior
state before readers resume. Repository failures are reported as service
unavailable; they are never treated as a missing credential, an empty list, or
an authentication denial.

The file-backed repository writes and synchronizes a permission-restricted
temporary snapshot, then atomically renames it as the mutation commit boundary.
It attempts to synchronize the parent directory after rename; failure is warned
but cannot make the already-published snapshot uncommitted. This provides
committed atomic visibility, not an absolute power-loss durability guarantee.
Missing snapshots start empty; unreadable or invalid snapshots stop startup
instead of being replaced. This repository is a single gateway-instance
abstraction and does not provide multi-process locking.

### Key-wrapping providers

| Provider | Durability | When to use |
|----------|-----------|-------------|
| `LocalKeyWrapping` (`S4_SECRET_KEK`) | Durable (operator-provided 32-byte KEK) | Local dev and self-host with a managed KEK |
| Ephemeral (no KEK configured) | Not durable (random in-memory KEK, lost on restart) | Local dev only |
| KMS/Vault-backed wrapping (injected) | Durable | **Production** |

`build_state` accepts an injected `Arc<dyn KeyWrapping>`. The OSS self-host
binary resolves `S4_SECRET_KEK` / ephemeral via `key_cipher::default_wrapping()`;
a KMS/Vault-backed wrapper can be supplied by an embedding deployment without
changing the engine. `is_durable()` is the load-bearing flag: **durable staging
fails closed when the active wrapping is not durable** (see §7), because a lost
DEK would permanently strand staged tenant data.

`SecretCipher::decrypt` retains its public compatibility behavior and collapses
invalid data or wrapping failures to `None`. Credential repositories use
`decrypt_result` instead, allowing operational KMS/Vault failures to become a
generic service-unavailable response rather than an authentication denial.

> **Non-local deployments must use a durable KMS/Vault-backed wrapping.**
> Running with auth enabled while the active wrapping is the local KEK or an
> ephemeral key is **not secure** for shared/non-local use. The gateway logs a
> prominent warning at startup in this configuration.

Legacy hash-only keys (created before envelopes existed) cannot verify SigV4
signatures — regenerate them if you need native S3 tools.

## 4. The plugin pipeline (data transformation)

- Plugins are Wasm components (`wasmtime`, Component Model + WIT
  `s4:filter@0.1.0`), 64 MiB aggregate guest memory per object, 10K table
  entries, 4 memories, 512 KiB max stack. No host imports beyond WASI
  stdout/stderr; the boundary is byte-in/byte-out.
- A **fresh `Store` and component instance per object** (ADR 0007): no runtime
  state is shared across objects or tenants. Compiled components may be cached
  by hash; guest state (linear memory, globals, resources) is strictly
  per-invocation and dropped when the object completes.
- **Fuel and deadlines** — per-call and cumulative fuel budgets
  (`S4_WASM_FUEL`), a per-call wall-clock deadline (epoch interruption, default
  30s) and an object deadline (default 5 minutes), plus cancellation tokens
  that interrupt active guest calls.
- **Admission control** — streaming sessions run on a bounded worker pool with
  a capped queue and a guest-memory budget (`MemoryAdmission`); admission
  failure surfaces as `SlowDown` rather than unbounded parallelism.
- The pipeline is deterministic and runs **before** data reaches storage on
  the write path: redaction replaces PII, encryption (per-field RSA-OAEP /
  AES-256-GCM) keeps the decryption key solely with the client. `stable-encrypt`
  (AES-SIV) is opt-in for JOIN keys and derives from the API key secret, never
  the raw secret.
- Every authenticated request resolves its user through the
  `WorkspaceStorageRepository` to a canonical `WorkspaceId`. Workspace IDs are
  opaque, used unchanged, and limited to 1–128 ASCII characters from
  `[A-Za-z0-9._-]`; a repository may map multiple users to one workspace.
  Resolution failure fails closed.
- The canonical workspace ID, not the user ID, scopes backend configuration,
  managed placement, multipart identities and quotas, and usage metering.
  Object sessions remain isolated per invocation.

## 5. Transformed reads — fail-closed disclosure rules

Read-time processing (`x-s4-process: read`) runs the pipeline on the way out:
the object in storage is unchanged, and the caller receives only the
transformed projection. This is the agent-safe-read path. The guarantees are
deliberately strict:

- **Preflight from stored metadata.** A transformed read performs a metadata
  preflight against the stored object *before* any source body is consumed.
  The preflight validates `Content-Type` against a known format
  (JSON/JSONL/CSV/TSV/text), rejects `Range`, `partNumber`, non-identity
  `Content-Encoding`, and unknown mandatory formats, and requires stored
  metadata. Presigned-HTTP backends are rejected for transformed reads because
  they cannot provide a safe metadata preflight.
- **Version/ETag binding.** The source GET must match the preflight: either an
  immutable version ID equality or a strong ETag equality (weak ETags are not
  accepted). If the source metadata changed between preflight and GET, the
  request is rejected — never silently served.
- **No raw fallback.** A pipeline error, decoder error, or staging failure
  fails the request closed. There is **no** fallback to raw bytes under any
  condition.
- **Prefix-safe direct streaming only.** When *every* component in the
  pipeline snapshot is marked prefix-safe for read (operator-declared via
  `S4_PREFIX_SAFE_COMPONENT_HASHES` at process start — imported components are
  unsafe by default and the capability is immutable per component hash), the
  transformed output is streamed directly.
- **Encrypted read spool otherwise.** Any snapshot containing an unsafe
  component is rejected unless `S4_TRANSFORMED_READ_SPOOL=encrypted` is set.
  The transformed output is then written to a disk spool in independently
  authenticated AES-256-GCM chunks under a key that lives **only in the request
  task** (a stale spool file is unreadable after a restart). The spool quota is
  reserved before source disclosure, file permissions are 0600, the response
  body is streamed from the spool only after the full representation is
  written, and a truncated or corrupted spool terminates the response body.
  Dropping the response body cancels the replay and releases the reservation.
- **No `HEAD` on transformed reads** — `HEAD` is rejected until transformed
  metadata is available.
- Transformed reads require stored, version-bound metadata and work with S3,
  managed storage, and in-memory backends (in local mode). Presigned backend
  URLs remain raw-only.
- `S4_STREAMING_READ_MODE` gates the path: `off` (default) rejects transformed
  reads entirely; `passthrough` enables only raw streaming; `transformed`
  enables this path.

## 6. Storage backends

- **Presigned URL proxy (`x-s4-backend-url`)** — the user generates a presigned
  URL with their own cloud SDK; S4 filters and forwards. **No backend
  credential is stored.** The gateway applies SSRF controls before any request
  is made (see §10).
- **Per-workspace backend config** — `managed`, or `s3_compatible` with an
  endpoint, region, and static access credentials. `aws_role` remains
  unsupported and is rejected. Runtime S3-compatible endpoints are governed by
  `WorkspaceEndpointPolicy` (see §10), and dashboard reads return only a
  redacted configuration.
- **Service storage** — S4-managed multi-cloud buckets (`S4_SERVICE_BUCKETS`),
  tenant-namespaced by workspace and optionally backed by authoritative
  placement metadata (see §9).
- **Resolution contract** — an explicit `x-s4-storage-mode: managed` request is
  resolved first, followed by a presigned URL, a per-workspace configuration,
  and configured service storage as the default. Only explicit single-tenant
  mode (`AUTH_DISABLED=true` or `S4_SINGLE_TENANT=true`) may continue to the
  global `S3_ENDPOINT` and then in-memory storage.
- **Multi-tenant fail-closed boundary** — startup rejects `S3_ENDPOINT` and
  requires non-empty `S4_SERVICE_BUCKETS`. An unconfigured workspace therefore
  uses managed storage; workspace repository failures and unavailable explicit
  or workspace-managed selections never fall through to a process-global
  backend.

Multipart uploads are **not** buffered in gateway memory: parts are staged
durably and encrypted before any downstream processing (see §7).

## 7. Multipart staging — durable, encrypted, fenced

`S4_MULTIPART_MODE=staged` (default `reject`) enables client multipart uploads
through a durable staging subsystem:

- **Durable encrypted staging.** Each part is written to a local artifact file
  (`S4_MULTIPART_STAGING_DIR`) framed as `S4MP10` magic + JSON header
  (containing the wrapped DEK, tenant/upload/part identity, and a digest of the
  multipart snapshot) followed by AES-256-GCM chunks whose AAD binds the header
  and chunk number. The artifact is then copied to a dedicated S4-controlled
  object store (`S4_MULTIPART_STAGING_BUCKET`/`ENDPOINT`/credentials). The
  encryption key never exists in the gateway beyond the request lifetime, and
  the DEK is wrapped by the configured `KeyWrapping`.
- **`is_durable` requirement.** Staged multipart requires a durable wrapping
  (KMS/Vault or a configured `S4_SECRET_KEK`); an ephemeral wrapping causes
  staging to fail closed. It also requires `DATABASE_URL` (durable repository)
  and the complete staging backend configuration.
- **Durable quota reservations.** Per-tenant and global staging quotas
  (`S4_MULTIPART_STAGING_TENANT_QUOTA_BYTES` / `_GLOBAL_QUOTA_BYTES`) are
  reserved in Postgres with row locks *before* any body frame is consumed,
  temp file opened, or artifact created. Crash-consistency is handled by a
  pending-outbox (begin/commit/discard) state machine that reconciliation
  replays.
- **Snapshot binding.** The multipart snapshot (metadata, tags, checksum mode,
  destination, plugin snapshot, limits) is recorded at initiation; completion
  replays each artifact through a reader that authenticates the envelope
  identity, snapshot digest, and AEAD tags before any frame is exposed, and
  verifies the replayed part against the committed ETag/checksum/size.
- **Completion fencing.** `CompleteMultipartUpload` is serialized by a durable
  completion lease with a fencing token and a request fingerprint. Idempotent
  retries replay the stored result; a stale worker that loses its lease is
  fenced (its renewals and any abort are rejected) — a fenced completion
  returns `ServiceUnavailable` instead of corrupting state. Takeover is
  explicit: a new worker acquires the lease with its own token, and the old
  worker cannot abort.
- **Expiry and reconciliation.** Expired uploads are reaped by a background
  worker (aborting the destination and cleaning staged parts); orphaned
  artifact files are removed by startup and periodic cleanup; pending outbox
  entries are reconciled against the artifact store.

## 8. Transactional writes — journal, atomic commit, reconciliation

Streaming writes (`S4_STREAMING_WRITE_MODE=single` or `all`) run through a
durable transaction layer:

- **Operation journal.** A Postgres-backed `OperationJournal`
  (`DATABASE_URL`) records each operation's state machine:
  `INTENT → OPEN → COMPLETING → COMMITTED`, with `COMMIT_UNKNOWN` and
  `PROVEN_ABORTED` for crash recovery. Streaming writes in a non-development
  deployment require a durable journal; there is no in-memory fallback.
- **Atomic commit.** The transformed output is fully verified (decoded length,
  SHA-256 of the emitted bytes, per-part ETags/checksums) against the expected
  object *before* the destination commit is issued. On any failure the sink is
  aborted and the destination multipart upload is cleaned up.
- **`COMMIT_UNKNOWN` reconciliation.** When a completion outcome is ambiguous
  (the request failed after `complete` was issued), the operation transitions
  to `COMMIT_UNKNOWN` and a reconciler probes the destination with
  head-with-operation-identity; it either records the committed object or,
  if proven absent, aborts discovered incomplete uploads and marks the
  operation `PROVEN_ABORTED`. A lease on the operation row prevents two
  reconcilers from acting on the same operation, and the backend capability
  gate (see §12) guarantees the recovery primitives exist.
- **Direct vs. spooled sinks.** For direct S3 destinations the output is
  streamed as a multipart upload; for presigned-HTTP destinations the output
  is spooled to a bounded, quota-accounted local spool (`S4_SPOOL_DIR`,
  `S4_SPOOL_MAX_OBJECT_BYTES`, `S4_SPOOL_QUOTA_BYTES`) and then uploaded.

## 9. Managed replication — authority and repair fencing

`S4_MANAGED_STREAMING_MODE` (default `off`; `observe`/`enforce` require
`S4_MANAGED_STREAMING_TRANSACTIONAL=true` and a durable repository) adds
authoritative metadata over the consistent-hash placement:

- **Placement.** Deterministic rendezvous hashing (versioned,
  `S4_MANAGED_PLACEMENT_VERSION`) selects a primary and one replica backend per
  logical object, independent of backend input order.
- **Authority.** An `ObjectAuthority` row records generation, digest, size,
  metadata, and primary/replica copy status with compare-and-swap semantics
  (`cas_version`); concurrent writers cannot silently overwrite authority.
- **Repair fencing.** Replication repairs are durable records claimed with a
  lease owner and token; renewal, completion (compare-and-swap), and failure
  are all token-checked, so a stale worker cannot apply or duplicate a repair
  after its lease is taken over. `validate_mode` refuses to turn managed mode
  off after authority rows exist, and refuses `observe`/`enforce` without
  `DATABASE_URL`.

## 10. Outbound requests — SSRF, DNS, redirect, expiry, address pinning

Presigned-URL handling (`PresignedHttpPolicy`) applies the following before a
single byte is fetched or sent:

- **Host allowlist** — the URL host must be in `S4_PRESIGNED_HTTP_ALLOWLIST`
  (supports `*.suffix` wildcards).
- **Scheme** — HTTPS is required. `S4_PRESIGNED_HTTP_ALLOW_HTTP=true` permits
  HTTP only for an explicit presigned source `GET`; presigned `PUT` and
  `DELETE` destinations remain HTTPS-only.
- **No userinfo or fragments**, and the scheme must be supported.
- **Expiry validation** — the URL must carry an explicit expiry
  (`X-Amz-Date`+`X-Amz-Expires` or `Expires`) with at least
  `S4_PRESIGNED_HTTP_MIN_VALIDITY_SECS` (default 30s) remaining.
- **DNS + address pinning** — the host is resolved at request time; any
  non-public address range rejects the request unless the host is in
  `S4_PRESIGNED_HTTP_PRIVATE_ALLOWLIST`. The resolved address is pinned on the
  client (no re-resolution) and proxying is disabled.
- **No redirects** — redirects are disabled at the client and redirect
  responses are rejected outright on reads.

Persisted S3-compatible workspace endpoints use a separate
`WorkspaceEndpointPolicy`; presigned URL policy and expiry rules are not reused:

- In multi-tenant mode HTTPS is mandatory, URLs cannot contain userinfo, query,
  or fragment components, and the host must exactly match or be a strict
  dot-boundary `*.suffix` entry in `S4_WORKSPACE_ENDPOINT_ALLOWLIST`.
- DNS is revalidated before every per-workspace AWS SDK client is constructed.
  Empty answers, private/reserved addresses, mixed public/private answers,
  IP-literal allowlist bypasses, and IPv4-mapped private IPv6 are rejected.
- The per-workspace AWS SDK connector explicitly disables proxies and does not
  use browser-style redirect following. It performs its own DNS lookup after
  validation rather than using the validated addresses, so the multi-tenant
  allowlist is a trusted-provider boundary: operators must allow only provider
  domains whose DNS tenants cannot control or rebind.
- Every gateway AWS SDK S3 client is configured for one SDK attempt. Journaled
  and spooled write transactions retain their own explicit bounded retry budget
  (currently three attempts), so retries remain visible to transaction evidence,
  fencing, and reconciliation rather than occurring inside the SDK.
- HTTP or private addresses are accepted only in explicit single-tenant mode.
  Private destinations additionally require an exact operator entry in
  `S4_WORKSPACE_ENDPOINT_PRIVATE_ALLOWLIST`; wildcard private exceptions are
  invalid.
- Public builds provide no common-provider allowlist defaults. Deployments must
  choose the provider domains they trust.

## 11. Cancellation and cleanup

- **Cancellation.** Every streaming operation carries a cancellation token that
  propagates through the Wasm pipeline, the source body, the sink, and spool
  replays. Dropping a response body cancels the source and pipeline; a
  cancelled guest call is interrupted via the epoch engine and surfaced as
  `WASM_CANCELLED`. Request aborts never issue destination aborts from a stale
  worker (fencing checks first).
- **Cleanup/reconciliation workers.** Startup and periodic jobs remove stale
  compatibility spool files, orphaned encrypted multipart spool files,
  reconcile pending staging outboxes against the artifact store, reap expired
  multipart uploads, and reconcile `COMMIT_UNKNOWN` operations and managed
  repairs.

## 12. Bounded parsing and memory

- The legacy 16 MiB whole-object buffering path was **removed** (Phase 12):
  there is no whole-object memory buffer on the data plane. The gateway runs
  fixed-RSS streaming: source frames are bounded by `S4_SOURCE_MAX_FRAME_BYTES`
  and decoded object bytes by `S4_MAX_OBJECT_BYTES`; per-record decoder limits
  apply; and `S4_LEGACY_MAX_OBJECT_BYTES` is no longer load-bearing.
- `CompleteMultipartUpload` XML is capped at 1 MiB and parsed by a strict
  grammar parser (no general XML resolver): DTDs and entities are rejected
  before tokenization, parts must be sorted and unique, and part ETags/checksums
  are validated against staged parts.
- aws-chunked framing is decoded with fixed-size state and explicit limits;
  oversized frames, duplicate trailers, and trailing data are rejected.
- Wasm guest memory is capped per object (64 MiB aggregate) with a bounded
  worker pool and memory budget (see §4).

## 13. Logging prohibitions

The gateway must never log:

- **Object bytes or transformed payloads** (neither plaintext nor ciphertext
  object content),
- **Staging keys or DEKs** (wrapped or unwrapped),
- **Credentials** — API key secrets, backend access keys, KEKs, or tokens,
- **Backend endpoint URLs containing query data** (these are rejected before
  persistence or client construction),
- **Signed URLs** (presigned URLs are bearer credentials),
- **Staging artifact ciphertext or key material**.

Operational logs may reference keys, buckets, user IDs, and error messages
that do not embed the above.

## 14. Deployment responsibilities

These are **operator responsibilities**; S4 will not and cannot enforce them
from inside a container:

- **TLS termination** — place the gateway behind a TLS-terminating proxy
  (platform load balancer, ingress, or reverse proxy). SigV4 is signed
  over-the-wire, but the SDK header path sends secrets in headers, so HTTPS is
  required for the secret-bearing headers. Set `S4_SIGV4_TRUSTED_TLS=true` if
  your proxy terminates TLS and the gateway sees HTTP.
- **Trusted proxy** — restrict access to the gateway to the trusted proxy
  (or bind the listener accordingly); do not expose it directly on the
  internet without TLS.
- **KMS/Vault readiness** — configure a durable `KeyWrapping` (KMS or Vault)
  for any non-local deployment. `S4_SECRET_KEK` is durable but operator-managed
  plaintext; the ephemeral wrapper loses all wrapped secrets on restart.
  Durable multipart staging fails closed without a durable wrapping.
- **Durable journal / staging + Postgres** — set `DATABASE_URL`. Streaming
  writes require the durable operation journal; staged multipart requires
  Postgres plus the complete `S4_MULTIPART_STAGING_*` configuration; managed
  observe/enforce requires Postgres and transactional capabilities.
- **Backend lifecycle permissions** — the backend credentials S4 uses for
  direct/managed streaming must be able to create, abort, and discover
  multipart uploads, complete uploads, and (for reconciliation) perform
  conditional reads/HEAD. The capability gate refuses streaming eligibility
  without incomplete-upload discovery, abort, completion reconciliation, and a
  cleanup SLA within five minutes.
- **Feature-gate defaults** — all streaming features are **off/reject by
  default** and must be explicitly enabled:
  `S4_STREAMING_READ_MODE=off`, `S4_STREAMING_WRITE_MODE=off`,
  `S4_MULTIPART_MODE=reject`, `S4_MANAGED_STREAMING_MODE=off`. Enabling them
  without the corresponding durable dependencies causes startup to refuse
  configuration rather than silently degrade.
- **Self-host hardening** — run the container as non-root; limit egress to the
  configured backends, KMS/Vault, and Supabase; do not ship `S4_KEYS_FILE` or
  `keys.json` in the image; do not set `AUTH_DISABLED` in production; put the
  spool and staging directories on private, capacity-reserved volumes sized
  for `S4_SPOOL_MAX_OBJECT_BYTES`/`S4_SPOOL_QUOTA_BYTES` (including encrypted
  framing overhead).
- **Dependency/update policy** — track releases and apply security fixes
  promptly; run `just deny` (cargo-deny) and `just audit` (cargo-audit) in
  your pipeline and keep the pinned toolchain (Rust 1.97.0) and Wasmtime
  version current. Only the latest stable minor is supported (see SECURITY.md).

## 15. Non-guarantees — the data-plane vs. provider distinction

S4 is a **data-plane processing gateway**, not a storage provider. S4 does not
secure the third-party storage it is pointed at:

- S4 does not control bucket policies, server-side encryption, access logs,
  retention, replication, or deletes on the destination. Configure those on
  the destination itself.
- S4 forwards to the destination exactly the transformed representation and
  relies on the destination's credentials/permissions for access control.
  Misconfigured destination credentials, world-readable buckets, or missing
  destination-side encryption are outside S4's control and are not S4
  vulnerabilities.
- S4 does not secure the identity provider (Supabase) or the email/analytics
  services used by the dashboard.
- Client-side decryption keys (for per-field encryption) and stable-encrypt
  keys are held by the client; S4 never holds them.
