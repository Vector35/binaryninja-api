# MCP Server

Binary Ninja can expose analysis data to MCP clients through the Model Context Protocol (MCP). This allows an AI assistant or other MCP client to inspect open files, open binaries, run analysis updates, and query read-only BinaryView information such as functions, symbols, strings, sections, disassembly, IL, and decompiled text.

Binary Ninja provides two MCP server variants:

| Variant | Binary | Transport | Availability |
| --- | --- | --- | --- |
| GUI MCP server | `binaryninja` | HTTP only | Runs inside the Binary Ninja GUI; not included with Binary Ninja Free or Personal |
| Headless MCP server | `binaryninja_mcp` | stdio only | Runs as a standalone command-line server; not included with Binary Ninja Free or Personal |

## Tool Overview

The exact tool list may change as the MCP server develops, but both server variants expose tools in the following broad categories:

- **File and view management**: list open files and databases, open a file or database, close or save an open item, list BinaryViews, and select the active BinaryView.
- **Analysis control**: inspect analysis status, start an analysis update, run analysis and wait for completion, or abort active analysis work.
- **Binary overview**: request a compact triage summary of the active BinaryView, including entry point, segment, section, symbol, function, string, and data variable counts.
- **Program structure**: list entry points, segments, sections, symbols, imports, exports, relocations, data variables, and strings.
- **Memory inspection**: read bytes from the active BinaryView and receive the result as hex and base64.
- **Function inspection**: list and search functions, request function metadata, render disassembly, render decompiled Pseudo C, render IL, inspect basic blocks, callers, callees, cross-references, stack layout, and complexity metrics.

Use your MCP client's tool listing UI or command to see the complete set of tools available in your installed Binary Ninja version.

## Tool Calling Conventions

The MCP server exposes Binary Ninja state through a small set of identifiers and conventions. These are worth understanding because they differ from many REST APIs.

### Handles

Open files, projects, databases, and BinaryViews are identified by opaque handles returned from MCP tools:

- `openItem` handles identify files, databases, or projects. Tools such as `bn_open_item_save` and `bn_open_item_close` use these handles.
- `binaryView` handles identify BinaryViews for an open item. Use `bn_binary_view_list` to discover them and `bn_binary_view_set_active` to select one.

Do not construct handles yourself. Treat them as session-scoped values returned by the server.

Some BinaryViews may be listed as available but not yet created. Selecting one with `bn_binary_view_set_active` may create that view. When multiple BinaryViews are available for a file, use the `recommended` field from `bn_binary_view_list` or choose the view type you need before running read-only analysis tools.

### Active BinaryView

Most read-only tools operate on the active BinaryView rather than taking a `binaryView` parameter every time. If a tool returns `no_active_binary_view`, first call `bn_binary_view_list`, choose a view, and call `bn_binary_view_set_active`.

In the GUI server, the active BinaryView follows the Binary Ninja UI unless an MCP client explicitly changes it. In the headless server, the active BinaryView is managed entirely through MCP tools.

### Address Expressions

Address parameters are strings, not JSON numbers. They are parsed as Binary Ninja expressions in the active BinaryView, so clients can use plain addresses, symbols, and expressions supported by Binary Ninja.

Examples:

```json
{"address": "0x401000", "length": 64}
```

```json
{"function": "main"}
```

```json
{"start": ".text", "length": "0x100"}
```

Use address expressions for fields named `address`, `start`, `end`, and `function`. Use integers or decimal/hex strings for byte counts such as `length`.

Function tools identify a function by its start address expression:

```json
{"function": "0x401000"}
```

If more than one function has the same start address, pass `arch` with the architecture name returned by function-listing tools:

```json
{"function": "0x401000", "arch": "x86_64"}
```

### Ranges, Queries, and Pagination

List tools commonly accept range filters:

- `address`: exact address match
- `start` plus `length`: byte range
- `start` plus `end`: byte range with exclusive end address

Use either `address` or `start`, not both. Use either `length` or `end`, not both.

`query` fields are case-insensitive substring filters, not regular expressions.

Large lists are paginated with `offset` and `limit`. Responses include `count`, `total`, `nextOffset`, and `truncated`; if `truncated` is true, call the same tool again with `offset` set to `nextOffset`.

Addresses in tool output are formatted as hexadecimal strings so clients do not lose precision when handling 64-bit addresses.

## GUI Server

The GUI MCP server is hosted inside the Binary Ninja application. It uses HTTP only and must be both enabled and started before a client can connect. Some MCP clients refer to this as an HTTP or streamable HTTP server.

### Enable and Start

1. Open Settings with `[CMD/CTRL] ,`.
2. Enable `ui.mcp.enabled`. This setting requires a restart.
3. Optionally configure the HTTP settings:
    - `ui.mcp.host`: Local interface to bind. Default: `127.0.0.1`
    - `ui.mcp.port`: HTTP port. Default: `24642`; use `0` for an OS-assigned port
    - `ui.mcp.endpoint`: HTTP endpoint path. Default: `/mcp`
    - `ui.mcp.token`: Optional bearer token. Leave blank to disable HTTP authorization
4. Restart Binary Ninja.
5. Start the server with `Plugins > MCP > Start Server`.
6. Use `Plugins > MCP > Copy Connection Info` to copy the exact URL and authorization header for your current session.

Use `Plugins > MCP > Stop Server` to stop the server.

### GUI Commands

The GUI server adds these commands under `Plugins > MCP`. They are also registered as UI commands, so they can be found by name from command search or key binding configuration:

- `MCP\Start Server`: Start the GUI MCP HTTP server. This command is available when the server is not already running.
- `MCP\Stop Server`: Stop the GUI MCP HTTP server. This command is available while the server is running.
- `MCP\Copy Connection Info`: Copy the current connection details to the clipboard and write them to the log. When the server is running, the copied text includes the URL and, if configured, the `Authorization` header. When the server is not running, the copied text reports that the server is not running.

With default settings, the GUI MCP server listens at:

```text
http://127.0.0.1:24642/mcp
```

If `ui.mcp.token` is set, configure your MCP client to send:

```text
Authorization: Bearer <token>
```

If `ui.mcp.port` is `0`, the operating system chooses a port when the server starts. Use `Plugins > MCP > Copy Connection Info` instead of guessing the URL.

## Headless Server

The standalone `binaryninja_mcp` server is for headless operation and uses stdio only. Configure your MCP client to launch `binaryninja_mcp` as a local command-line MCP server.

The headless server opens and analyzes files without the GUI and exposes the same file manager and read-only BinaryView inspection tools as the GUI server. The `binaryninja_mcp` binary is not included with Binary Ninja Free or Personal.

Use the full path to `binaryninja_mcp` in client configuration unless it is already on your `PATH`.

## Client Configuration Examples

MCP client configuration formats change over time. Use these examples as starting points, and check each client's own documentation for the latest supported fields.

### Claude Desktop

Claude Desktop can launch the headless stdio server from its MCP server configuration. See the [MCP local server guide](https://modelcontextprotocol.io/docs/develop/connect-local-servers) for current Claude Desktop setup details.

```json
{
  "mcpServers": {
    "binaryninja": {
      "command": "/path/to/binaryninja_mcp"
    }
  }
}
```

### Cursor

Cursor supports both stdio and HTTP MCP servers in `mcp.json`. See the [Cursor MCP documentation](https://cursor.com/docs/mcp.md) for current configuration locations and fields.

Headless stdio:

```json
{
  "mcpServers": {
    "binaryninja-headless": {
      "type": "stdio",
      "command": "/path/to/binaryninja_mcp"
    }
  }
}
```

GUI streamable HTTP:

```json
{
  "mcpServers": {
    "binaryninja-gui": {
      "url": "http://127.0.0.1:24642/mcp",
      "headers": {
        "Authorization": "Bearer <token>"
      }
    }
  }
}
```

Omit `headers` if HTTP authorization is disabled.

### VS Code

VS Code supports MCP servers in workspace `.vscode/mcp.json` files and user profile configuration. See the [VS Code MCP server documentation](https://code.visualstudio.com/docs/agent-customization/mcp-servers) for current setup details.

Headless stdio:

```json
{
  "servers": {
    "binaryninja-headless": {
      "command": "/path/to/binaryninja_mcp"
    }
  }
}
```

GUI HTTP:

```json
{
  "servers": {
    "binaryninja-gui": {
      "type": "http",
      "url": "http://127.0.0.1:24642/mcp",
      "headers": {
        "Authorization": "Bearer <token>"
      }
    }
  }
}
```

Omit `headers` if HTTP authorization is disabled.

### Codex

Codex stores MCP configuration in `~/.codex/config.toml` or project-scoped `.codex/config.toml` files. See the [Codex MCP documentation](https://developers.openai.com/codex/mcp) for current CLI and config-file options.

Headless stdio:

```toml
[mcp_servers.binaryninja_headless]
command = "/path/to/binaryninja_mcp"
```

GUI HTTP:

```toml
[mcp_servers.binaryninja_gui]
url = "http://127.0.0.1:24642/mcp"
bearer_token_env_var = "BN_MCP_TOKEN"
```

Set `BN_MCP_TOKEN` to the value of `ui.mcp.token`. Omit `bearer_token_env_var` if HTTP authorization is disabled.

## Troubleshooting

If an MCP client cannot connect to the GUI server:

- Confirm `ui.mcp.enabled` is enabled.
- Confirm the server has been started with `Plugins > MCP > Start Server`.
- Use `Plugins > MCP > Copy Connection Info` and copy the exact URL and token header into the client configuration.
- If you changed `ui.mcp.host`, `ui.mcp.port`, or `ui.mcp.endpoint`, restart the GUI MCP server.
- Check the Binary Ninja log for MCP startup errors.

If a headless client cannot start `binaryninja_mcp`:

- Use an absolute path to `binaryninja_mcp`.
- Confirm the installed product includes the headless MCP server.
- Run the same command manually in a terminal to check for startup errors.
