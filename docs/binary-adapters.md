# Binary adapters

Typed binary formats such as Avro and Parquet do not pass through the
byte-oriented `s4:filter` plugin pipeline. A binary encoder needs its complete
output schema before it writes the first record. Use a binary reductor when a
format-specific logical type must be converted to an S4-supported type before a
typed transform, then reconstructed for output.

The contract is `s4:binary-reductor@0.1.0` in
[`wit/s4-binary-reductor/world.wit`](../wit/s4-binary-reductor/world.wit).

## Lifecycle

For one object, the host calls the component in this order:

1. `plan(source-schema-ir)` returns a reduced schema, owned claims, and an opaque
   reduction plan.
2. `reduce(plan, source-value-ir)` runs once per source value.
3. The host applies schema-aware binary transforms to reduced values.
4. `plan-restore(source-schema-ir, transformed-reduced-schema-ir, plan)` returns
   the final output schema and an opaque restoration plan.
5. `restore(restore-plan, transformed-value-ir)` runs once per retained value.

The component only owns paths it claims. The gateway verifies that claims point
to a custom logical value or declared record, and rejects a schema mutation
outside a claim. Plans are bound to the SHA-256 digest of the exact component;
do not reuse plans across component versions.

## Canonical IR

Schema and value inputs are canonical JSON representations of the bounded S4
IR. The definitive Rust types and validators are in
[`crates/gateway/src/binary_ir.rs`](../crates/gateway/src/binary_ir.rs).

- A nullable Avro-like field is represented by `"nullable": true`, not an
  arbitrary union.
- Custom logical values use `{"type":"custom","type_id":"...","value":...}`.
- Map keys are UTF-8 strings and map entries are canonicalized by key.
- The gateway validates every returned schema and value before it reaches an
  encoder. Invalid or unsupported data must return `reductor-error`, never a
  best-effort result.

The test fixture in
[`filters/test-binary-reductor/src/lib.rs`](../filters/test-binary-reductor/src/lib.rs)
is the smallest complete example. It reduces `vendor.money` from a custom value
to a string and restores it after the typed transform.

## Write an adapter

Create a `cdylib` crate that uses the workspace-compatible `wit-bindgen` release:

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
wit-bindgen = "0.60"
```

Generate bindings and implement the exported `Guest` trait:

```rust
wit_bindgen::generate!({
    world: "binary-reductor",
    path: "path/to/S4/wit/s4-binary-reductor/world.wit",
});

struct MyReductor;

impl Guest for MyReductor {
    // Implement plan, reduce, plan_restore, and restore.
}

export!(MyReductor);
```

Build a bare component. Binary reductors receive no WASI and no other host
imports, so do not use the WASI adapter used by text plugins:

```bash
cargo build --release --target wasm32-unknown-unknown
wasm-tools component new target/wasm32-unknown-unknown/release/my_reductor.wasm \
  -o my-reductor.component.wasm
```

## Required behavior

- Keep every returned IR, plan, claim, identifier, and diagnostic within the
  host limits. The host rejects oversized output.
- Claim each custom logical subtree that the component changes. Claims may not
  overlap or prefix one another.
- Treat `plan` and `plan-restore` output as immutable. Preserve all state needed
  later in opaque plan bytes.
- Return stable error codes and bounded diagnostics. Never include plaintext,
  keys, or full source records in diagnostics.
- Do not depend on filesystem, network, clocks, environment variables, or host
  imports. The binary-reductor sandbox intentionally provides none.

## Test locally

From an S4 checkout:

```bash
bash scripts/build-filters.sh
cargo test -p s4-wasm-runtime binary_reductor
cargo test -p s4-gateway binary_reductor::tests
```

Add conformance vectors beside the fixture for each new logical type. Cover
round trips, invalid claims, invalid plan bytes, malformed IR, fuel exhaustion,
deadlines, cancellation, and component-digest changes before connecting an
adapter to a codec.

## Current integration boundary

The Wasm runtime and gateway adapter are available to codec code. Runtime
component selection for binary formats is intentionally separate from dashboard
text-plugin upload: a byte filter cannot safely become a binary adapter merely
by changing its file extension. A codec integration must explicitly select and
pin its binary-reductor component.
