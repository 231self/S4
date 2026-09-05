# ADR 0007: Fresh Wasmtime Store Per Object

- Status: Accepted
- Date: 2026-08-09

## Context

Wasm modules from different tenants share the same gateway process. A cross-tenant state leak would break the confidentiality guarantee. Wasmtime's `Store` holds instance state, including linear memory and mutable globals.

## Decision

Create a fresh `Store` and component instance for each S3 object. Never reuse a Store or instance across objects. Compiled components may be cached by hash (immutable static code), but runtime state (Store, linear memory, globals, resources) is strictly per-invocation.

## Consequences

- Sandbox limits are set per-object: fuel, epoch deadline, memory, stack, hostcall transfer limits.
- Multiple concurrent objects each get their own Store, instance, and sandbox state.
- After each object completes, the Store is dropped, releasing all instance memory.
- No mutable guest state is shared across objects or tenants. Cross-tenant pooling is deferred until zeroization can be demonstrated.
- Wasmtime's `Store` lifetime documentation confirms resources are not released until the Store is dropped, matching the per-object model.
