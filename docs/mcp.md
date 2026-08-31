# MCP server

`s4-mcp` is a local stdio Model Context Protocol server. It exposes four text
object tools to Claude, Codex, Cursor, and other MCP clients:

- `s4_put_object`
- `s4_get_object`
- `s4_list_objects`
- `s4_delete_object`

The server does not implement a second storage or processing path. Every tool
calls the S4 gateway's S3-compatible HTTP surface, so gateway authentication,
the configured plugin pipeline, backend selection, limits, and metering still
apply.

## Install

Build and install from the public source:

```bash
cargo install --git https://github.com/231self/S4 s4-mcp
```

Linux x86_64 and arm64 binaries are also attached to each
[GitHub release](https://github.com/231self/S4/releases) as
`s4-mcp-linux-amd64` and `s4-mcp-linux-arm64`.

There is currently no npm package or hosted MCP transport.

## Configure

Create an MCP token in the S4 dashboard, then configure the local server:

```json
{
  "mcpServers": {
    "s4": {
      "command": "s4-mcp",
      "env": {
        "S4_GATEWAY_URL": "https://api.s4.231self.com",
        "S4_MCP_TOKEN": "s4m_your_token"
      }
    }
  }
}
```

An S4 API key pair can be used instead:

```json
{
  "S4_GATEWAY_URL": "https://api.s4.231self.com",
  "S4_ACCESS_KEY": "s4_your_access_key",
  "S4_SECRET_KEY": "s4s_your_secret_key"
}
```

`S4_MCP_TOKEN` takes precedence when both credential forms are present. Secret
values are validated at startup and are omitted from debug output.

## Tool behavior

`s4_put_object` accepts a UTF-8 body and a `content_type` (default
`text/plain; charset=utf-8`). S4 uses that Content-Type to select the processing
format before writing to the configured backend.

`s4_get_object` returns the stored representation by default. Set `process` to
`true` to send `x-s4-process: read` and run the configured read pipeline before
the MCP client receives the object.

`s4_list_objects` performs S3 ListObjectsV2 with an optional prefix and returns
decoded object keys. `s4_delete_object` deletes one bucket/key pair.

MCP text responses are limited to 8 MiB. Binary request/response bodies,
presigning, hosted Streamable HTTP transport, and agent payment protocols are
not part of this stdio release.
