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
  dual-write, read fail-over). MinIO is covered by the CI end-to-end suite;
  Backblaze B2 is validated by the credentialed provider harness against a real
  bucket (redaction and envelope-encryption round-trips).
- **Agent-safe reads** — read data through S4 with `x-s4-process: read`: the pipeline
  runs on the way *out*, so AI agents get redacted/encrypted output while the object
  at rest stays raw. No second cleaned copy to keep in sync.
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

# A sample file to push through the pipeline:
echo "jane.doe@example.com 4111111111111111" > data.csv

# Write data through the pipeline; it is transformed before it reaches storage
s4ctl put ./data.csv ingest/data.csv --bucket s4-local

# Read it back
s4ctl get ingest/data.csv --bucket s4-local
```

`s4ctl local init` pulls the gateway image tagged with the CLI version
(`ghcr.io/231self/s4/s4:v0.3.3` for s4ctl 0.3.3 — CLI and gateway always match,
never `:latest`) and runs it in local mode (`AUTH_DISABLED=true`, keys persisted on a
volume, in-memory storage); it picks a free port (8080+) and binds the loopback
interface only. `s4ctl local down` stops it. For durable local storage (MinIO),
clone the repo and use `just dev-up`.

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

Typed binary codecs use a separate schema-aware reductor contract, not the
byte-oriented plugin pipeline. See [docs/binary-adapters.md](docs/binary-adapters.md)
when adding a custom logical-type adapter.

Opt-in Avro OCF processing (`S4_ENABLE_AVRO=true`) and its supported subset are
documented in [docs/avro.md](docs/avro.md). A runnable PUT/read example is in
[examples/avro-demo.py](examples/avro-demo.py).

## Usage examples

Everything below is copy-paste runnable.

**Redaction — PII filtered on write**

```bash
# Local gateway (published image, Docker, in-memory storage):
s4ctl local init
s4ctl put ./data.csv ingest/data.csv --bucket s4-local
s4ctl get ingest/data.csv --bucket s4-local     # emails/SSNs/cards redacted

# Durable local storage (MinIO) from a repo clone:
just dev-up
s4ctl put ./data.csv ingest/data.csv --bucket s4-local

# End-to-end validation:
just e2e
```

**Agent-safe reads — raw at rest, scrubbed on the way out**

```bash
# Data at rest stays raw (your app owns the originals).
s4ctl put ./customers.json customers/c1.json --bucket s4-local

# Transformed reads are deliberately opt-in. Unsafe component snapshots are
# staged encrypted before any response bytes are disclosed.
export S4_STREAMING_READ_MODE=transformed
export S4_TRANSFORMED_READ_SPOOL=encrypted
# Set this to the SHA-256 component digests reviewed for prefix-safe disclosure.
# Imported components are unsafe unless listed here.
export S4_PREFIX_SAFE_COMPONENT_HASHES=<comma-separated-component-sha256-digests>

# An AI agent reads THROUGH S4: PII is redacted before the agent sees it.
curl -H "x-s4-process: read" http://localhost:8080/customers/c1.json
# → {"email":"[REDACTED_EMAIL]","card":"[REDACTED_CARD]","note":"hi"}

# Same object, no header: the raw bytes your app owns.
curl http://localhost:8080/customers/c1.json
# → {"email":"alice@example.com","card":"4111111111111111","note":"hi"}
```

One source of truth, two projections: the app gets full fidelity, the agent
gets only what you allow. Transformed reads require stored, version-bound
metadata and work with S3, managed storage, and in-memory backends. Presigned
backend URLs remain raw-only because they cannot provide a safe metadata
preflight.

Transformed reads reject `Range`, `partNumber`, non-identity source encodings,
unknown mandatory formats, and `HEAD`. They never fall back to raw bytes.
`S4_STREAMING_READ_MODE=off` (the default) rejects transformed reads;
`passthrough` enables only raw streaming. `transformed` enables this path.
Without `S4_TRANSFORMED_READ_SPOOL=encrypted`, a snapshot containing any
component not listed in `S4_PREFIX_SAFE_COMPONENT_HASHES` is rejected before
its source body is consumed. Set `S4_SPOOL_DIR`, `S4_SPOOL_MAX_OBJECT_BYTES`,
and `S4_SPOOL_QUOTA_BYTES` to a private, capacity-reserved volume; the quota
must cover encrypted framing overhead as well as plaintext output.

**Encryption — per-field envelope encryption, decryptable only by you**

```bash
# Round-trip against any S3-compatible bucket: pre-encrypt fixture →
# encrypted bytes fetched straight from the bucket → decrypted through S4:
export B2_S3_ENDPOINT=https://s3.us-east-005.backblazeb2.com
export B2_REGION=us-east-005
export B2_BUCKET=your-bucket
export B2_ACCESS_KEY_ID=your-key-id
export B2_SECRET_ACCESS_KEY=your-application-key
bash examples/b2-encrypt-demo.sh
```

**Plugins — bring your own transform**

```bash
s4ctl plugin list                              # pipeline order
s4ctl plugin upload my-filter.component.wasm   # runtime import, no rebuild
s4ctl plugin enable <id>
s4ctl plugin reorder pii-default my-filter     # output of one feeds the next
```

**SDKs — Python**

```python
from s4_client import S4Client
client = S4Client(gateway="http://localhost:8080")
pub, priv = client.generate_keypair()                  # RSA-2048
client.attach_public_key(pub)                          # bind to your API key
client.put_object("bucket", "key", b"jane@example.com 4111111111111111")
blob = client.get_object("bucket", "key")
assert "jane@example.com" not in blob.decode()          # stored encrypted
print(client.decrypt_payload(blob, priv))              # you hold the key
```

Full details: [examples/README.md](examples/README.md) and
[docs/plugins.md](docs/plugins.md).

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

## Security

S4 transforms sensitive data before it reaches storage and applies strict,
fail-closed guarantees on the streaming data plane (see
[docs/security.md](docs/security.md) for the full model, including deployment
responsibilities and non-guarantees).

Found a vulnerability? Report it **privately** — via GitHub private
vulnerability reporting or security@231self.com — and never through a public
issue. See [SECURITY.md](SECURITY.md) for the supported-version policy,
response timeline, and what to include in a report.

## Documentation

- `examples/` — runnable end-to-end demos (B2 encryption round-trip).
- `docs/plugins.md` — create and consume your own plugins.
- `docs/security.md` — the security model of the gateway.
- `docs/adr/` — architecture decision records.
- `AGENTS.md` — development conventions.

## LLM agents

Coding agents (Claude Code, Kilo, Cursor, …) read `AGENTS.md` from the repo root
automatically. For reusable, domain-specific S4 context, install the bundled skill:

```bash
# Claude Code (user-global):
mkdir -p ~/.claude/skills && ln -s "$(pwd)/skills/s4" ~/.claude/skills/s4
# Kilo (user-global):
mkdir -p ~/.kilo/skills && ln -s "$(pwd)/skills/s4" ~/.kilo/skills/s4
```

The skill teaches agents what S4 is, the plugin pipeline, build/test/run commands,
crate layout, and the CI/release gotchas (BuildKit cache mounts, act/colima,
multi-arch builds).

## License

Apache-2.0. See `LICENSE`.
