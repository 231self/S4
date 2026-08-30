# S4 Plugins — create and consume your own

Plugins are how S4 transforms text data. A plugin is a WebAssembly component that receives
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
imports, and a fuel budget (`S4_WASM_FUEL`, default 1B — enough for crypto filters).

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
s4ctl plugin upload my-filter.component.wasm     # prints the plugin id
s4ctl plugin list                                # shows pipeline order
s4ctl plugin reorder my-filter pii-default       # output of one feeds the next
s4ctl plugin disable <id>                        # remove from the pipeline
s4ctl plugin delete <id>                         # drop the plugin
```

Or auto-load a directory of plugins at gateway startup:

```bash
S4_PLUGINS_DIR=./components ./target/debug/s4-gateway
```

The default local setup preloads `pii-default` via `S4_FILTER_COMPONENT`.

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
