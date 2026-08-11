# S4 — pluggable processing gateway for object storage

S4 is an S3-compatible gateway that runs your WebAssembly plugins over every object
in transit. Point any S3 SDK, CLI, or tool at S4; each object passes through your
plugin pipeline — filter, redact, encrypt, convert, validate, route — and the result
is forwarded to any S3-compatible storage backend.

**Bring your own plugin.** The gateway is a router: plugins are Wasm components
compiled once and uploaded at runtime. No gateway rebuild, no restart, no lock-in.

- **Pluggable pipeline** — plugins run in order; each can emit, drop, or reject. A tiny
  WIT interface (`begin` / `transform` / `finish`), pure byte-in/byte-out.
- **Sandboxed** — wasmtime, 64 MiB memory, fuel-limited, no host imports.
- **BYO plugins** — write in Rust (or any Wasm-capable language), wrap with
  `wasm-tools component`, `s4ctl plugin upload`. See [docs/plugins.md](docs/plugins.md).
- **Any S3-compatible storage** — MinIO, AWS S3, Google Cloud Storage, Backblaze B2,
  Cloudflare R2, Vultr Object Storage — single or multi-cloud (consistent-hash ring,
  dual-write, read fail-over).
- **Optional auth** — run with auth disabled locally, or enable API keys (in-memory,
  a JSON file, or Postgres).
- **Typed SDKs** — generated Python and TypeScript clients, published with every release.

Filters shipped in-tree (as examples to learn from): `noop`, `pii-default` (redact
emails / SSNs / credit cards), `email-detect`, `ssn-detect`, `card-detect`,
`envelope-encrypt` (per-field RSA-OAEP / AES-256-GCM), `stable-encrypt`
(deterministic encryption).

## Quickstart (local-only)

No cloud account, no database, no repo clone — everything runs on your machine:

```bash
cargo install s4ctl --git https://github.com/231self/S4
s4ctl local init                  # runs the published gateway image (Docker)
s4ctl plugin list                 # the pii-default plugin is preloaded

# Write data through the pipeline; it is transformed before it reaches storage
s4ctl put ./data.csv ingest/data.csv --bucket s4-local

# Read it back
s4ctl get ingest/data.csv --bucket s4-local
```

`s4ctl local init` pulls `ghcr.io/231self/s4/s4` and runs the gateway in local mode
(`AUTH_DISABLED=true`, keys persisted on a volume, in-memory storage). `s4ctl local
down` stops it. For durable local storage (MinIO), clone the repo and use
`just dev-up`.

## Run your own plugin

```bash
# 1. Write a filter (Rust + wit-bindgen against wit/s4-filter/world.wit)
# 2. Build it:
cargo build --release --target wasm32-unknown-unknown
wasm-tools component new target/wasm32-unknown-unknown/release/my_filter.wasm \
  -o my-filter.component.wasm
# 3. Upload and enable it:
s4ctl plugin upload my-filter.component.wasm
s4ctl plugin enable <id>
# 4. Reorder the pipeline — output of one feeds the next:
s4ctl plugin reorder pii-default my-filter
```

Full guide: [docs/plugins.md](docs/plugins.md).

## How it works

```
S3 SDK / CLI / tool ──▶ S4 gateway (Wasm plugin pipeline) ──▶ storage
                            │
                            ├─ filter  → redact, strip fields, validate
                            ├─ encrypt → per-field envelope encryption
                            ├─ convert → CSV ⇄ JSONL ⇄ text
                            └─ ...     → your plugins, in order
```

## Development

```bash
just check        # fmt + clippy + build filters + tests
just e2e          # end-to-end against MinIO (Docker)
just build-sdks   # regenerate Python/TypeScript SDKs from the OpenAPI spec
```

### Run CI/release locally (no GitHub minutes)

Two local pipeline runners, both with persistent caches:

- **`just ci-local`** — runs the real `.github/workflows/ci.yml` via
  [act](https://github.com/nektos/act) (local Docker; `actions/cache` backed by act's
  cache server, so cargo deps are reused across runs).
- **`just build-local` / `just image-local` / `just publish-local TAG=x`** — dagger
  pipeline (`dagger/main.py`) with cargo registry + target dirs on persistent cache
  volumes; `publish-local` pushes to `ghcr.io/231self/s4/s4` (needs `docker login ghcr.io`
  once).

See `CONTRIBUTING.md`.

## Documentation

- `docs/plugins.md` — create and consume your own plugins.
- `docs/adr/` — architecture decision records.
- `AGENTS.md` — development conventions.

## License

Apache-2.0. See `LICENSE`.
