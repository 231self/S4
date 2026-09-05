# Maskura: pluggable processing gateway for object storage

Maskura is an S3-compatible gateway that runs your WebAssembly plugins over every object
in transit. Point any S3 SDK, CLI, or tool at Maskura; each object passes through your
plugin pipeline — filter, redact, encrypt, convert, validate, route — and the result
is forwarded to any S3-compatible storage backend.

The name combines the English word "mask" with the Japanese "kura", meaning storage.

**Bring your own plugin.** The gateway is a router: plugins are Wasm components
compiled once and uploaded at runtime. No gateway rebuild, no restart, no lock-in.

- **Pluggable pipeline** — plugins run in order; each can emit, drop, or reject. A tiny
  WIT interface (`begin` / `transform` / `finish`), pure byte-in/byte-out.
- **Sandboxed** — wasmtime, 64 MiB memory, fuel-limited, no host imports.
- **BYO plugins** — write in Rust (or any Wasm-capable language), wrap with
  `wasm-tools component`, `maskura plugin upload`. See [docs/plugins.md](docs/plugins.md).
- **Any S3-compatible storage** — MinIO, AWS S3, Google Cloud Storage, Backblaze B2,
  Cloudflare R2, Vultr Object Storage — single or multi-cloud (consistent-hash ring,
  dual-write, read fail-over). MinIO is covered by the CI end-to-end suite;
  Backblaze B2 is validated by the credentialed provider harness against a real
  bucket (redaction and envelope-encryption round-trips).
- **Agent-safe reads** — read data through Maskura with `x-maskura-process: read`: the pipeline
  runs on the way *out*, so AI agents get redacted/encrypted output while the object
  at rest stays raw. No second cleaned copy to keep in sync.
- **Optional auth** — run with auth disabled locally, or enable API keys (in-memory,
  a JSON file, or Postgres).
- **Typed SDKs** — generated Python and TypeScript clients, published with every release.

Filters shipped in-tree (as examples to learn from): `noop`, `pii-default` (redact
emails / SSNs / credit cards), `email-detect`, `ssn-detect`, `card-detect`,
`envelope-encrypt` (per-field RSA-OAEP / AES-256-GCM), `stable-encrypt`
(deterministic encryption).

## Contents

- [Try it in 60 seconds](#try-it-in-60-seconds)
- [Install the CLI (optional)](#install-the-cli-optional)
- [Compatibility](#compatibility)
- [Run your own plugin](#run-your-own-plugin)
- [Usage examples](#usage-examples)
- [How it works](#how-it-works)
- [Development](#development)
- [Security](#security)
- [Documentation](#documentation)
- [LLM agents](#llm-agents)
- [License](#license)

## Try it in 60 seconds

No cloud account, no database, no repo clone — run the published image and open
the demo dashboard:

```bash
docker run --rm -p 127.0.0.1:8791:8080 -e AUTH_DISABLED=true \
  ghcr.io/231self/maskura/maskura:latest
# open http://localhost:8791 → demo dashboard (no sign-up)

# Grab an API key from the dashboard's "API Keys" tab, then either follow its
# "Quick Start" (the snippets auto-fill your port) or run:
echo "jane.doe@example.com 4111111111111111" > data.jsonl
curl -X PUT http://localhost:8791/ingest/data.jsonl \
  -H "x-maskura-access-key: YOUR_KEY_ID" \
  -H "x-maskura-secret-key: YOUR_SECRET" \
  --data-binary @data.jsonl
curl http://localhost:8791/ingest/data.jsonl \
  -H "x-maskura-access-key: YOUR_KEY_ID" \
  -H "x-maskura-secret-key: YOUR_SECRET"
```

The container listens on `8080`; `8791` is just the uncommon host port this
example maps it to, so nothing already on `8080` collides. Dashboard snippets
rewrite themselves to whatever `host:port` you open, so copy-paste works for any
mapping.

## Install the CLI (optional)

Prefer the CLI? Install it with `cargo install`, or grab the prebuilt Linux
(amd64/arm64) binaries attached to each
[GitHub Release](https://github.com/231self/maskura/releases):

```bash
cargo install --git https://github.com/231self/maskura --bin maskura s4ctl
maskura local init                  # runs the published gateway image (Docker)
maskura plugin list                 # the pii-default plugin is preloaded

# A sample file to push through the pipeline:
echo "jane.doe@example.com 4111111111111111" > data.csv

# Write data through the pipeline; it is transformed before it reaches storage
maskura put ./data.csv ingest/data.csv --bucket s4-local

# Read it back
maskura get ingest/data.csv --bucket s4-local
```

`maskura local init` pulls the gateway image tagged with the CLI version
(`ghcr.io/231self/maskura/maskura:v0.3.3` for `maskura` 0.3.3; CLI and gateway always
match, never `:latest`) and runs it in local mode (`AUTH_DISABLED=true`, keys
persisted on a volume, in-memory storage); it picks a free port (8080+) and binds
the loopback interface only. `maskura local down` stops it. For durable local
storage (MinIO), clone the repo and use `just dev-up`.

## Compatibility

New integrations should use `MASKURA_*` environment variables and
`x-maskura-*` headers. Every shipped customer `S4_*` setting and `x-s4-*`
header remains a permanent alias. Equal dual values are accepted; differing
values fail closed, and an empty value is treated as a real value for conflict
checks. The `s4ctl` and `s4-mcp` binaries, `s4_*` MCP tools, `s4_client` Python
module, and `S4Client` SDK exports remain available.

Persistent and security-sensitive identifiers do not change: credentials still
use `s4_`/`s4s_`/`s4m_`, local CLI state remains under `~/.config/s4`, existing
container/volume names remain shared, WIT namespaces remain `s4:*`, stored
metadata remains `s4-*`, and legacy images remain pullable from
`ghcr.io/231self/s4/s4`.

## Run your own plugin

```bash
# 1. Write a filter (Rust + wit-bindgen against wit/s4-filter/world.wit)
# 2. Build it:
cargo build --release --target wasm32-unknown-unknown
wasm-tools component new target/wasm32-unknown-unknown/release/my_filter.wasm \
  -o my-filter.component.wasm
# 3. Upload and enable it:
maskura plugin upload my-filter.component.wasm
maskura plugin enable <id>
# 4. Reorder the pipeline — output of one feeds the next:
maskura plugin reorder pii-default my-filter
```

Full guide: [docs/plugins.md](docs/plugins.md).

Typed binary codecs use a separate schema-aware reductor contract, not the
byte-oriented plugin pipeline. See [docs/binary-adapters.md](docs/binary-adapters.md)
when adding a custom logical-type adapter.

Opt-in Avro OCF processing (`MASKURA_ENABLE_AVRO=true`) and its supported subset are
documented in [docs/avro.md](docs/avro.md). A runnable PUT/read example is in
[examples/avro-demo.py](examples/avro-demo.py).

The local stdio MCP server exposes put, get, list, and delete tools to agent
clients while preserving the gateway's normal auth, pipeline, and metering path.
See [docs/mcp.md](docs/mcp.md).

## Usage examples

Everything below is copy-paste runnable.

**Redaction — PII filtered on write**

```bash
# Local gateway (published image, Docker, in-memory storage):
maskura local init
maskura put ./data.csv ingest/data.csv --bucket s4-local
maskura get ingest/data.csv --bucket s4-local     # emails/SSNs/cards redacted

# Durable local storage (MinIO) from a repo clone:
just dev-up
maskura put ./data.csv ingest/data.csv --bucket s4-local

# End-to-end validation:
just e2e                # see docs/e2e.md for the feature-by-feature breakdown
```

**Agent-safe reads — raw at rest, scrubbed on the way out**

```bash
# Data at rest stays raw (your app owns the originals).
maskura put ./customers.json customers/c1.json --bucket s4-local

# Transformed reads are deliberately opt-in. Unsafe component snapshots are
# staged encrypted before any response bytes are disclosed.
export MASKURA_STREAMING_READ_MODE=transformed
export MASKURA_TRANSFORMED_READ_SPOOL=encrypted
# Set this to the SHA-256 component digests reviewed for prefix-safe disclosure.
# Imported components are unsafe unless listed here.
export MASKURA_PREFIX_SAFE_COMPONENT_HASHES=<comma-separated-component-sha256-digests>

# An AI agent reads through Maskura: PII is redacted before the agent sees it.
curl -H "x-maskura-process: read" http://localhost:8080/customers/c1.json
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
`MASKURA_STREAMING_READ_MODE=off` (the default) rejects transformed reads;
`passthrough` enables only raw streaming. `transformed` enables this path.
Without `MASKURA_TRANSFORMED_READ_SPOOL=encrypted`, a snapshot containing any
component not listed in `MASKURA_PREFIX_SAFE_COMPONENT_HASHES` is rejected before
its source body is consumed. Set `MASKURA_SPOOL_DIR`, `MASKURA_SPOOL_MAX_OBJECT_BYTES`,
and `MASKURA_SPOOL_QUOTA_BYTES` to a private, capacity-reserved volume; the quota
must cover encrypted framing overhead as well as plaintext output.

**Encryption — per-field envelope encryption, decryptable only by you**

```bash
# Round-trip against any S3-compatible bucket: pre-encrypt fixture →
# encrypted bytes fetched straight from the bucket → decrypted through Maskura:
export B2_S3_ENDPOINT=https://s3.us-east-005.backblazeb2.com
export B2_REGION=us-east-005
export B2_BUCKET=your-bucket
export B2_ACCESS_KEY_ID=your-key-id
export B2_SECRET_ACCESS_KEY=your-application-key
bash examples/b2-encrypt-demo.sh
```

**Plugins — bring your own transform**

```bash
maskura plugin list                              # pipeline order
maskura plugin upload my-filter.component.wasm   # runtime import, no rebuild
maskura plugin enable <id>
maskura plugin reorder pii-default my-filter     # output of one feeds the next
```

**SDKs — Python**

```python
from maskura_client import MaskuraClient
client = MaskuraClient("http://localhost:8080", "s4_access_key", "s4s_secret_key")
priv, pub = client.generate_keypair()                  # RSA-2048
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
S3 SDK / CLI / tool ──▶ Maskura Gateway (Wasm plugin pipeline) ──▶ storage
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
  volumes; `publish-local` pushes identical canonical and legacy tags to
  `ghcr.io/231self/maskura/maskura` and `ghcr.io/231self/s4/s4` (needs `docker login ghcr.io`
  once).

See `CONTRIBUTING.md`.

## Security

Maskura transforms sensitive data before it reaches storage and applies strict,
fail-closed guarantees on the streaming data plane (see
[docs/security.md](docs/security.md) for the full model, including deployment
responsibilities and non-guarantees).

Found a vulnerability? Report it **privately** — via
[Maskura private vulnerability reporting](https://github.com/231self/maskura/security/advisories/new)
or security@231self.com — and never through a
[public issue](https://github.com/231self/maskura/issues/new/choose). See
[SECURITY.md](SECURITY.md) for the supported-version policy,
response timeline, and what to include in a report.

## Documentation

- **Docs site** — the same docs, rendered:
  <https://231self.github.io/maskura/>.
- `examples/` — runnable end-to-end demos (B2 encryption round-trip).
- `docs/plugins.md` — create and consume your own plugins.
- `docs/security.md` — the security model of the gateway.
- `docs/adr/` — architecture decision records.
- `AGENTS.md` — development conventions.

## LLM agents

Coding agents (Claude Code, Kilo, Cursor, …) read `AGENTS.md` from the repo root
automatically. For reusable, domain-specific Maskura context, install the bundled skill:

```bash
# Claude Code (user-global):
mkdir -p ~/.claude/skills && ln -s "$(pwd)/skills/maskura" ~/.claude/skills/maskura
# Kilo (user-global):
mkdir -p ~/.kilo/skills && ln -s "$(pwd)/skills/maskura" ~/.kilo/skills/maskura
```

The skill teaches agents what Maskura is, the plugin pipeline, build/test/run commands,
crate layout, and the CI/release gotchas (BuildKit cache mounts, act/colima,
multi-arch builds).

## License

Apache-2.0. See `LICENSE`.
