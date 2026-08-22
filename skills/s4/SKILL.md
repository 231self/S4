---
name: s4
description: S4 — pluggable processing gateway for S3-compatible object storage. Use when working in the S4 codebase: building/testing, the Wasm plugin pipeline, the S3 data plane, envelope encryption, SDKs, or the CI/release pipeline.
---

# S4 — pluggable processing gateway for object storage

S4 is an S3-compatible gateway that runs WebAssembly plugins over every object in
transit. Point any S3 SDK/tool at S4; each object passes through an ordered plugin
pipeline (filter, redact, encrypt, convert, validate, route) and the result is
forwarded to any S3-compatible backend (MinIO, AWS, GCS, B2, R2, …).

## Core concepts

- **Plugin pipeline** — enabled plugins run in order; output of plugin N feeds
  plugin N+1. Each plugin is a Wasm component (`wit/s4-filter/world.wit`):
  `begin(Context)`, `transform(Vec<u8>) -> Decision`, `finish()`.
  Decision variants: `Emit`, `Drop`, `Reject`.
- **Sandbox** — wasmtime, 64 MiB memory, 10K table entries, 512 KiB stack, no host
  imports. Fuel: `S4_WASM_FUEL` (default 1B; crypto filters need the pipeline
  budget, ~25M per RSA-OAEP wrap).
- **Plugins are BYO** — write in any Wasm-capable language, `wasm-tools component
  new`, then runtime import via `s4ctl plugin upload` (no gateway rebuild/restart).
  `S4_PLUGINS_DIR` auto-loads a directory at startup. Default filter:
  `filters/pii-default/` (redact emails / Luhn-valid cards / validated SSNs).
- **Envelope encryption** — `filters/envelope-encrypt/` replaces each PII field
  with `{"alg":"RSA-OAEP/AES-256-GCM","iv","enc_dek","ct","tag"}` using the API
  key's bound X.509 public key. S4 never holds the private key; clients decrypt
  (`s4_client.decrypt_payload`). Falls back to redaction without a key.
  `filters/stable-encrypt/` is AES-SIV deterministic encryption for JOIN keys
  (opt-in via stable-key/stable-fields context).
- **Auth** — API keys (`x-s4-access-key`/`x-s4-secret-key` headers or
  `Authorization: Bearer <ak>:<sk>`). Key stores: in-memory `KeyStore`,
  `FileKeyStore` (`S4_KEYS_FILE`, default in local mode), `PostgresKeyStore`
  (`DATABASE_URL`). Secrets stored SHA-256-hashed. `AUTH_DISABLED=true` = demo
  bypass.
- **Storage** — tiered: presigned-URL proxy (`x-s4-backend-url`), per-user
  backend config (`BackendRegistry`), service storage (`S4_SERVICE_BUCKETS`,
  consistent-hash ring + dual-write + read fail-over), global `S3_ENDPOINT`,
  in-memory `MemoryStore` (local default).

## Commands

```bash
just check            # fmt + clippy (-D warnings) + build filters + workspace tests
just e2e              # MinIO data-plane e2e (Docker) — gateway server + s4ctl test upload
just build-sdks       # regenerate Python/TypeScript SDKs (docker openapi-generator)
just ci-local         # run the real ci.yml locally via act (colima)
just image-local      # dagger: build the deploy image (cargo-cached)
just publish-local TAG=x  # dagger: push ghcr.io/231self/s4/s4:<tag>
s4ctl local init      # run the published gateway image standalone (Docker, in-memory)
s4ctl put/get         # S3 data plane through the pipeline
bash examples/b2-encrypt-demo.sh   # B2 encryption round-trip (needs B2_* env vars)
```

## Layout

- `crates/gateway/` — the server: S3 data plane + dashboard API (axum, utoipa).
- `crates/s4ctl/` — the CLI.
- `crates/wasm-runtime/` — wasmtime sandbox (`FilterEngine`).
- `crates/policy/`, `crates/error/` — shared policy/error types.
- `filters/*/` — 7 Wasm filter crates (wasm32, wit-bindgen).
- `wit/s4-filter/world.wit` — the plugin interface.
- `sdks/{python,typescript}/` — generated clients + `overlay/` hand-written
  high-level client (`S4Client`).
- `migrations/` — sqlx migrations (run by the gateway at startup via `migrate!`).
- `scripts/` — build-filters.sh, e2e-local.sh, generate-sdks.sh, check.sh.
- `docs/plugins.md`, `docs/adr/` — plugin guide and architecture decisions.

## Gotchas

- **CI/release**: `ci.yml` splits fmt/lint/test/sdk/e2e into parallel jobs plus an
  aggregate `check` (branch protection requires `check`). `release.yml` builds a
  multi-arch image (`linux/amd64,linux/arm64`); the arm64 leg cross-compiles with
  `gcc-aarch64-linux-gnu`. Cargo registry/target ride BuildKit cache mounts, and
  binaries/components are copied OUT of the cache mount in the same RUN — never
  `COPY --from=build .../target/...` without the mount.
- **`.dockerignore` excludes `target/`** — without it, the host runner's binaries
  leak into the image.
- **act/colima**: act can't bind-mount the colima docker socket
  (`.actrc` sets `--container-daemon-socket=-`); docker-dependent steps are guarded
  with `if: ${{ !env.ACT }}`; `CARGO_BUILD_JOBS=2` keeps shared-VM memory bounded.
- **Local mode keys**: with `AUTH_DISABLED=true` and no `DATABASE_URL`, keys persist
  to `~/.config/s4/keys.json` (`FileKeyStore`).
- **Toolchain**: Rust 1.97.0 with `wasm32-wasip1`; wasm-tools 1.255.0. Pins live
  in `rust-toolchain.toml`, Dockerfiles, Dagger, and GitHub Actions.
- **jj repo**: never use git for mutations (`jj commit -m`, `jj git push -b <bk>`).
