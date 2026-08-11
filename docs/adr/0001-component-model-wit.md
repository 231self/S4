# ADR 0001: WebAssembly Component Model and WIT Contract

Date: 2026-08-09
Status: Accepted

## Context

S4 needs a contract between the gateway host and tenant-supplied filter plugins. The options considered:

1. **Core Wasm C ABI** (pointer + length): Host and guest exchange raw linear memory pointers. Fragile, no type safety, manual memory management on the guest side.
2. **WASI command model** (wasm32-wasip1): Treats each invocation as a separate process with stdin/stdout. Can't maintain state across records within a single object stream.
3. **WebAssembly Component Model with WIT**: Typed interface definitions, stateful sessions, automatic memory management via `list<u8>`.

## Decision

Use the Component Model and a versioned WIT world (`package s4:filter@0.1.0`). The guest exports `begin`, `transform`, and `finish` functions with typed parameters. Stateful per-object sessions allow filters to accumulate context across records.

## Consequences

- Host side uses wasmtime's component model bindgen for typed function calls.
- Guest side uses wit-bindgen for idiomatic Rust trait implementations.
- Shared WIT file is the single source of truth for the data-plane contract.
- Fresh `Store` per object provides strong isolation between requests.
