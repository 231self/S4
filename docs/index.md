# Maskura docs

Maskura is an S3-compatible gateway that runs your WebAssembly plugins over every
object in transit. Point any S3 SDK, CLI, or tool at Maskura; each object passes
through your plugin pipeline — filter, redact, encrypt, convert, validate, route —
and the result is forwarded to any S3-compatible storage backend.

The quickest way to see it working is the README's
[60-second Docker demo](https://github.com/231self/maskura#try-it-in-60-seconds):
run the published image with `AUTH_DISABLED=true`, open the demo dashboard, and
push a file through the pipeline. This site is the deeper documentation:

- **[Plugins](plugins.md)** — write, load, and compose your own Wasm filters.
- **[Avro gate](avro.md)** — the typed Avro OCF processing path.
- **[Binary adapters](binary-adapters.md)** — schema-aware binary reductors for
  typed formats.
- **[MCP](mcp.md)** — the local stdio MCP server for agent clients.
- **[End-to-end suite](e2e.md)** — the no-secrets local e2e harness.
- **[Security](security.md)** — the security model, trust boundaries, and
  deployment responsibilities.
- **[Architecture Decision Records](adr/0001-component-model-wit.md)** — the
  decisions behind the design.
