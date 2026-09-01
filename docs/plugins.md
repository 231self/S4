# Maskura plugins: create and consume your own

Plugins are how Maskura transforms text data. A plugin is a WebAssembly component that receives
each object's payload, optionally transforms it, and returns a decision. Plugins run in
a pipeline — the output of one is the input of the next — so you compose transforms:
filter, then encrypt, then convert.

## The interface

Plugins implement one world, `s4:filter`
([wit/s4-filter/world.wit](../wit/s4-filter/world.wit)):

| Function | Called | Purpose |
|---|---|---|
| `begin(context)` | once per object | Per-object setup; context carries `format`, `content-type`, `policy-version`, and optional `public-key-pem`, `stable-key`, `stable-fields` |
| `transform(payload)` | once per record | Transform the bytes; return `emit(bytes)`, `drop`, or `reject(reason)` |
| `finish()` | once at the end | Flush buffered output; return trailing bytes |

Sandbox limits: wasmtime, 64 MiB memory, 10K table entries, 512 KiB stack, no host
imports, and a fuel budget (`MASKURA_WASM_FUEL`, default 1B; enough for crypto filters).

## Write one (Rust)

`Cargo.toml`:

```toml
[package]
name = "my-filter"
edition = "2021"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
wit-bindgen = "0.60"
```

`src/lib.rs`:

```rust
wit_bindgen::generate!({
    world: "filter",
    path: "path/to/wit/s4-filter/world.wit",
});

struct MyFilter;

impl Guest for MyFilter {
    fn begin(_context: Context) -> Result<(), String> {
        Ok(())
    }

    fn transform(payload: Vec<u8>) -> Result<Decision, String> {
        // ... transform the bytes ...
        Ok(Decision::Emit(payload))
    }

    fn finish() -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }
}

export!(MyFilter);
```

Build and wrap as a component:

```bash
cargo build --release --target wasm32-unknown-unknown
wasm-tools component new target/wasm32-unknown-unknown/release/my_filter.wasm \
  -o my-filter.component.wasm
```

`filters/noop/` is a minimal example; `filters/pii-default/` shows detection + redaction
with `addr-spec` / `card-validate` style libraries and a pure-Wasm crypto fallback.

## Load it

At runtime — no gateway rebuild, no restart:

```bash
maskura plugin upload my-filter.component.wasm     # prints the plugin id
maskura plugin list                                # shows pipeline order
maskura plugin reorder my-filter pii-default       # output of one feeds the next
maskura plugin disable <id>                        # remove from the pipeline
maskura plugin delete <id>                         # drop the plugin
```

Or auto-load a directory of plugins at gateway startup:

```bash
MASKURA_PLUGINS_DIR=./components ./target/debug/s4-gateway
```

The default local setup preloads `pii-default` via `MASKURA_FILTER_COMPONENT`.

## Decision semantics

- `emit(bytes)` — pass the transformed bytes to the next plugin.
- `drop` — discard this record entirely.
- `reject(reason)` — fail the request with the reason.

## Notes

- Plugins are pure byte-in/byte-out. The gateway handles transport (S3 API), auth, and
  storage.
- Plugins do not declare an output schema, so they cannot be used directly for Avro,
  Parquet, or another typed binary format. Binary codecs use schema-aware transforms and
  optional `s4:binary-reductor` components instead; see
  [Binary adapters](binary-adapters.md).
- Filters shipped in-tree: `noop` (pass-through baseline), `pii-default`,
  `email-detect`, `ssn-detect`, `card-detect`, `envelope-encrypt`, `stable-encrypt`.
- The original WIT design is recorded in `docs/adr/0001-component-model-wit.md`.

## Hosted workspaces (`s4ctl hosted`)

Self-hosted/local gateways load plugins with the `s4ctl plugin` commands above and a
directory (`S4_PLUGINS_DIR`) at startup. Hosted S4 workspaces instead manage plugins as
first-class relational configuration owned by the workspace owner — the `s4ctl plugin`
commands and directory auto-enable **do not** apply there and are not available on hosted
S4. Hosted management authenticates with a **Supabase access token**
(`S4_ACCESS_TOKEN` or `--token`) and a workspace ID (`S4_WORKSPACE_ID` or
`--workspace`); an S4 data-plane API key is never accepted for hosted mutations.

```bash
export S4_ACCESS_TOKEN=<supabase-jwt>
export S4_WORKSPACE_ID=<workspace-uuid>
s4ctl hosted catalog                  # catalog + versions + capability grants
s4ctl hosted upload ./my-filter.component.wasm \
  --slug my-filter --display-name "My Filter" --version 1.0.0 \
  --world s4-filter@0.2.0 --wit-version 0.2.0 --capability stable_fields
s4ctl hosted validation <version-id>  # poll the secret-free validation run
s4ctl hosted grant --installation-id <id> --capability stable_fields --version-id <version-id>
s4ctl hosted pipelines create --direction write --name "redact"
s4ctl hosted pipelines draft --pipeline-id <id> --step <install-id>:<version-id>:config.json
s4ctl hosted pipelines publish --pipeline-id <id>
s4ctl hosted assign-default write --pipeline-id <id>
s4ctl hosted assign-bucket write ingest --pipeline-id <id>
s4ctl hosted audit
```

- **Worlds.** Components implement `s4-filter@0.1.0` (no config) or `s4-filter@0.2.0`
  (`operation` + optional `config-json`). Config is only valid for v0.2 components.
- **Ordering.** Draft steps run in the order given (`installation_id:version_id[:config]`);
  the fingerprint covers ordered versions, enabled flags, configs, and grants.
- **Capability grants.** A component only receives sensitive context (for example
  `stable_fields`) after the owner explicitly grants it per installation/version.
- **Pass-through.** An empty chain is only publishable when `--passthrough` is set; a
  missing bucket assignment inherits the workspace default, and an exact bucket
  assignment replaces the chain entirely.
- **Read spooling.** Custom read filters are spooled to encrypted storage and never
  disclosed as a raw fallback on failure.
- **Ownership.** Only workspace owners mutate plugins, grants, pipelines, or assignments;
  members may inspect the effective configuration and audit trail.
