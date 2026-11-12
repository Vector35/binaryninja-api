# MCP Server

Binary Ninja can expose analysis data to MCP clients through the Model Context Protocol (MCP). This allows an AI assistant or other MCP client to open binaries, run analysis updates, inspect functions, symbols, strings, sections, disassembly, IL, and decompiled text, and edit analysis data such as comments, names, and types.

Binary Ninja provides two MCP server variants:

| Variant | Binary | Transport | Availability |
| --- | --- | --- | --- |
| GUI MCP server | `binaryninja` | HTTP only | Runs inside the Binary Ninja GUI. Included with every GUI edition and supported on native Windows. |
| Headless MCP server | `binaryninja_mcp` | stdio only | Runs as a standalone command-line server. Included with Binary Ninja Commercial or Ultimate on macOS and Linux. Native Windows packages do not yet include `binaryninja_mcp.exe`. |

## Tool Overview

The exact tool list may change as the MCP server develops, but both server variants expose tools in the following broad categories:

- **Binary and project management**: list, open, save, and close binaries and databases, list and open projects, and open files within projects.
- **Analysis control**: inspect analysis status, start an analysis update, run analysis and wait for completion, or abort active analysis work.
- **Binary overview**: request a compact triage summary of a BinaryView, including entry point, segment, section, symbol, function, string, and data variable counts.
- **Program structure**: list entry points, segments, sections, symbols, imports, exports, relocations, data variables, and strings.
- **Memory inspection**: read bytes from a BinaryView and receive the result as hex and base64.
- **Function inspection**: list and search functions, request function metadata, render disassembly, render decompiled Pseudo C, render IL, inspect basic blocks, callers, callees, cross-references, stack layout, and complexity metrics.
- **Analysis editing**: manage comments, symbols, variables, function prototypes, types, data variables, and sections.

Use your MCP client's tool listing UI or command to see the complete set of tools available in your installed Binary Ninja version.

Plugins can add their own tools, which both server variants offer alongside the built-in ones. See [Writing MCP Tools](../dev/mcp-tools.md).

Tool groups are controlled by boolean settings under `mcp.groups`. Built-in groups are enabled by default. Disabling a group hides its tools and rejects calls to them. Reconnect your MCP client after changing these settings so it loads the updated tool list.

## Tool Calling Conventions

The MCP server exposes Binary Ninja state through a small set of identifiers and conventions. These are worth understanding because they differ from many REST APIs.

### Handles

Open files, projects, databases, and BinaryViews are identified by opaque handles returned from MCP tools:

- `binary` handles identify BinaryViews for open files and databases. Get them from `bn_binary_open` or `bn_binary_list`.
- `project` handles identify open projects. Get them from `bn_project_open` or `bn_project_list`.

Do not construct handles yourself. They remain valid while the corresponding binary or project is open in the server process.

The `viewTypes` metadata lists available view types for a file. Pass `viewType` to `bn_binary_open` to request a particular view type.

### Target BinaryView

Every BinaryView-scoped tool requires a `binary` handle on each call. If a tool returns `binary_not_found`, call `bn_binary_list` and supply a valid handle.

Both server variants use this per-call target. In the GUI, the target can be any open binary, regardless of which tab has focus.

### Address Expressions

Address parameters are strings, not JSON numbers. They are parsed as Binary Ninja expressions in the selected BinaryView, so clients can use plain addresses, symbols, and expressions supported by Binary Ninja.

Binary-view-domain numeric parameters, such as byte counts for memory reads and ranges, accept either JSON integers or strings when the tool input schema advertises them. JSON integers are consumed directly. String values are parsed as Binary Ninja expressions in the selected BinaryView. Binary Ninja expression syntax applies to string values; use `0n` for decimal strings when needed, for example `0n64`.

Examples:

```json
{"binary": "<binary handle>", "address": "0x401000", "length": 64}
```

```json
{"binary": "<binary handle>", "function": "main"}
```

```json
{"binary": "<binary handle>", "start": ".text", "length": "0n256"}
```

Use address expressions for fields named `address`, `start`, `end`, `function`, `symbol`, `comment`, and `datavar`. Use JSON integers or expression strings for byte-span input parameters such as `length` when the tool input schema advertises them. A `length` output column is returned metadata and does not imply that the tool accepts a `length` input. Metadata parameters such as pagination `offset` and `limit`, symbol `ordinal`, and collection caps such as `maxItems` are JSON integers only.

Function tools identify a function by its start address expression:

```json
{"binary": "<binary handle>", "function": "0x401000"}
```

If more than one function has the same start address, pass `arch` with the architecture name returned by function-listing tools:

```json
{"binary": "<binary handle>", "function": "0x401000", "arch": "x86_64"}
```

### Ranges, Queries, and Pagination

List tools accept range filters only when their input schema advertises these fields:

- `address`: exact address match
- `start` plus `length`: byte range
- `start` plus `end`: byte range with exclusive end address

Use either `address` or `start`, not both. Use either `length` or `end`, not both.

`query` fields are case-insensitive substring filters, not regular expressions.

Entry point, segment, and section list tools are pagination-only; use their returned address, start, end, and length columns as output metadata.

Large lists are paginated with `offset` and `limit`. Responses include `count`, `total`, `nextOffset`, and `truncated`; if `truncated` is true, call the same tool again with `offset` set to `nextOffset`.

Addresses in tool output are formatted as hexadecimal strings so clients do not lose precision when handling 64-bit addresses.

## GUI Server

The GUI MCP server is hosted inside the Binary Ninja application. It uses HTTP only and must be started before a client can connect. Some MCP clients refer to this as an HTTP or streamable HTTP server.

On Windows, use this built-in HTTP server for native MCP clients. Binary Ninja does not yet ship a standalone `binaryninja_mcp.exe` in Windows packages.

### Start the Server

1. Open Settings with `[CMD/CTRL] ,`.
2. Optionally configure the HTTP settings:
    - `ui.mcp.port`: HTTP port. Default: `24642`; use `0` for an OS-assigned port
    - `ui.mcp.endpoint`: HTTP endpoint path. Default: `/mcp`
    - `ui.mcp.token`: Optional bearer token. Leave blank to disable HTTP authorization
3. Start the server with `Plugins > MCP > Start Server`.
4. Use `Plugins > MCP > Copy Connection Info` to copy the exact URL and authorization header for your current session.

Enable `ui.mcp.enabled` to start the server automatically the next time Binary Ninja launches.

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

The headless server opens and analyzes files without the GUI and exposes the same built-in tools as the GUI server.

Native Windows packages do not yet include `binaryninja_mcp.exe`. On Windows, connect to the built-in GUI MCP HTTP server instead. If you require the headless stdio server, install and run the Linux build of Binary Ninja under WSL and use the Linux `binaryninja_mcp` executable from that environment.

Use the full path to `binaryninja_mcp` in client configuration unless it is already on your `PATH`.

By default, `binaryninja_mcp` loads plugins the same way as the main Binary Ninja executable. Launch it with `-p`, or set `BN_DISABLE_USER_PLUGINS`, to disable user and Extension Manager plugins for that server process.

!!! warning "Headless Server Availability"
    The `binaryninja_mcp` headless server is not available in Binary Ninja Free or Personal and is not yet available in native Windows packages. The headless stdio examples below require an edition and platform that include the headless server, or a Linux installation running under WSL.

## Client Configuration Examples

MCP client configuration formats change over time. Use these examples as starting points, and check each client's own documentation for the latest supported fields.

On native Windows, use the GUI HTTP examples below. The headless stdio examples apply to macOS, Linux, or a Linux Binary Ninja installation running under WSL.

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

- Confirm the server has been started with `Plugins > MCP > Start Server`.
- Use `Plugins > MCP > Copy Connection Info` and copy the exact URL and token header into the client configuration.
- If you changed `ui.mcp.port` or `ui.mcp.endpoint`, restart the GUI MCP server.
- Check the Binary Ninja log for MCP startup errors.

If a headless client cannot start `binaryninja_mcp`:

- On native Windows, use the GUI HTTP server or run the Linux headless server under WSL; `binaryninja_mcp.exe` is not yet shipped.
- Use an absolute path to `binaryninja_mcp`.
- Confirm the installed product includes the headless MCP server.
- Run the same command manually in a terminal to check for startup errors.
