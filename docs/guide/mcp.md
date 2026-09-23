# MCP Server

Binary Ninja can expose analysis data to MCP clients through the Model Context Protocol (MCP). This allows an AI assistant or other MCP client to inspect open files, open binaries, run analysis updates, and query read-only BinaryView information such as functions, symbols, strings, sections, disassembly, IL, and decompiled text.

Binary Ninja provides two MCP server variants:

| Variant | Binary | Transport | Availability |
| --- | --- | --- | --- |
| GUI MCP server | `binaryninja` | HTTP only | Runs inside the Binary Ninja GUI. Included with every GUI edition and supported on native Windows. |
| Headless MCP server | `binaryninja_mcp` | stdio only | Runs as a standalone command-line server. Included with Binary Ninja Commercial or Ultimate on macOS and Linux. Native Windows packages do not yet include `binaryninja_mcp.exe`. |

## Tool Overview

The exact tool list may change as the MCP server develops, but both server variants expose tools in the following broad categories:

- **File and view management**: list open files and databases, open a file or database, close or save an open item, list BinaryViews, and select the active BinaryView.
- **Analysis control**: inspect analysis status, start an analysis update, run analysis and wait for completion, or abort active analysis work.
- **Binary overview**: request a compact triage summary of the active BinaryView, including entry point, segment, section, symbol, function, string, and data variable counts.
- **Program structure**: list entry points, segments, sections, symbols, imports, exports, relocations, data variables, and strings.
- **Memory inspection**: read bytes from the active BinaryView and receive the result as hex and base64.
- **Function inspection**: list and search functions, request function metadata, render disassembly, render decompiled Pseudo C, render IL, inspect basic blocks, callers, callees, cross-references, stack layout, and complexity metrics.
- **Debugger**: launch, attach to, or connect to a debug target; step, run to, pause, restart, detach, or quit it; inspect and set breakpoints (including hardware watchpoints), registers, memory, threads, and backtraces; list loaded modules and the memory map; read or write standard input and backend-specific properties. See [Debugger Tools](#debugger-tools).
- **Binary Similarity (Ultimate, GUI server)**: create a comparison from two MCP BinaryView handles, inspect its matches, render provider-annotated diffs, and explicitly apply a match to port function metadata.

Use your MCP client's tool listing UI or command to see the complete set of tools available in your installed Binary Ninja version.

Plugins can add their own tools, which both server variants offer alongside the built-in ones. See [Writing MCP Tools](../dev/mcp-tools.md). The Debugger plugin's `debugger_*` tools (see [Debugger Tools](#debugger-tools) below) are an example.

To run Binary Similarity entirely through MCP, open both binaries with `bn_open_item_open`, choose their analyzed BinaryView handles, and pass those handles to `bn_similarity_session_compare`. The tool creates an MCP-owned review session, enables every available similarity provider, and can wait for the comparison to finish. Use `bn_similarity_session_info`, `bn_similarity_result_list`, and `bn_similarity_result_diff` to inspect it. The same inspection tools also work with the current Binary Similarity tab or sidebar session when no MCP-owned session exists.

Both binaries remain loaded in an MCP-created session so results can be rendered or applied. `bn_similarity_result_apply` ports available function names, types, variable information, and comments into the compared binary's analysis. Applying a result mutates the destination analysis; save its database afterward to persist the changes.

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

Binary-view-domain numeric parameters, such as byte counts for memory reads and ranges, accept either JSON integers or strings when the tool input schema advertises them. JSON integers are consumed directly. String values are parsed as Binary Ninja expressions in the active BinaryView. Binary Ninja expression syntax applies to string values; use `0n` for decimal strings when needed, for example `0n64`.

Examples:

```json
{"address": "0x401000", "length": 64}
```

```json
{"function": "main"}
```

```json
{"start": ".text", "length": "0n256"}
```

Use address expressions for fields named `address`, `start`, `end`, `function`, `symbol`, `comment`, and `datavar`. Use JSON integers or expression strings for byte-span input parameters such as `length` when the tool input schema advertises them. A `length` output column is returned metadata and does not imply that the tool accepts a `length` input. Metadata parameters such as pagination `offset` and `limit`, symbol `ordinal`, and collection caps such as `maxItems` are JSON integers only.

Function tools identify a function by its start address expression:

```json
{"function": "0x401000"}
```

If more than one function has the same start address, pass `arch` with the architecture name returned by function-listing tools:

```json
{"function": "0x401000", "arch": "x86_64"}
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

The GUI MCP server is hosted inside the Binary Ninja application. It uses HTTP only and must be both enabled and started before a client can connect. Some MCP clients refer to this as an HTTP or streamable HTTP server.

On Windows, use this built-in HTTP server for native MCP clients. Binary Ninja does not yet ship a standalone `binaryninja_mcp.exe` in Windows packages.

### Enable and Start

1. Open Settings with `[CMD/CTRL] ,`.
2. Enable `ui.mcp.enabled`. This setting requires a restart.
3. Optionally configure the HTTP settings:
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

## Debugger Tools

`debugger_*` tools drive Binary Ninja's debugger, from either server variant, when the [Debugger](https://github.com/Vector35/debugger) plugin is installed. The plugin registers them in-process through the MCP plugin API (see [Writing MCP Tools](../dev/mcp-tools.md)) the same way any other plugin would, when it loads — there is no separate server, port, or authentication token to manage, and nothing to enable. If the plugin is not installed, these tools are simply absent from `tools/list`; every other MCP tool is unaffected.

### Sessions

Debugger tools act on the debug session of the active BinaryView (see [Active BinaryView](#active-binaryview) above). A view only has a session once a lifecycle tool (`debugger_launch`, `debugger_attach`, or `debugger_connect`) has been called for it; an inspection tool called before that returns the `no_controller` error rather than silently creating one.

### Tools

| Tool | Purpose |
| --- | --- |
| `debugger_status` | Whether the view has a session, and its connected/running/stopped state. |
| `debugger_launch` / `debugger_attach` / `debugger_connect` | Start a session by launching, attaching to, or connecting to a target. |
| `debugger_detach` / `debugger_quit` / `debugger_restart` | End or restart the session. |
| `debugger_go` / `debugger_step_into` / `debugger_step_over` / `debugger_step_return` / `debugger_run_to` / `debugger_pause` | Resume or single-step execution. |
| `debugger_breakpoint_set` / `debugger_breakpoint_delete` / `debugger_breakpoint_set_enabled` / `debugger_breakpoint_condition_set` / `debugger_breakpoints_list` | Manage breakpoints, including hardware watchpoints. |
| `debugger_registers_get` / `debugger_register_set` | Read or write the active thread's registers. |
| `debugger_read_memory` / `debugger_write_memory` | Read or write the live process's memory (not the static BinaryView). |
| `debugger_backtrace` | A thread's stack trace. |
| `debugger_threads_list` / `debugger_thread_select` | List threads, or make one active. |
| `debugger_modules_list` / `debugger_memory_map` | Loaded modules, or the process memory map. |
| `debugger_processes_list` | Processes the debug adapter can see, to choose a pid for `debugger_attach`. |
| `debugger_write_stdin` / `debugger_execute_backend_command` | Write to the target's standard input, or run a raw backend command (for example an LLDB command). |
| `debugger_property_get` / `debugger_property_set` | Read or write a debug adapter (backend-specific) property. |

Address parameters on debugger tools follow the same [Address Expressions](#address-expressions) rules as the rest of the MCP server, resolved against the active BinaryView. Registers, hardware watchpoint sizes, and similar debugger-specific values are plain JSON integers or the debugger's own hex strings, not Binary Ninja address expressions.

See the Debugger plugin's own MCP Tools documentation for the full argument and error-code reference.

## Headless Server

The standalone `binaryninja_mcp` server is for headless operation and uses stdio only. Configure your MCP client to launch `binaryninja_mcp` as a local command-line MCP server.

The headless server opens and analyzes files without the GUI and exposes the same file manager, BinaryView inspection and editing, and debugger tools as the GUI server (see [Debugger Tools](#debugger-tools) for how debugger sessions work without a GUI to track them).

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

- Confirm `ui.mcp.enabled` is enabled.
- Confirm the server has been started with `Plugins > MCP > Start Server`.
- Use `Plugins > MCP > Copy Connection Info` and copy the exact URL and token header into the client configuration.
- If you changed `ui.mcp.port` or `ui.mcp.endpoint`, restart the GUI MCP server.
- Check the Binary Ninja log for MCP startup errors.

If a headless client cannot start `binaryninja_mcp`:

- On native Windows, use the GUI HTTP server or run the Linux headless server under WSL; `binaryninja_mcp.exe` is not yet shipped.
- Use an absolute path to `binaryninja_mcp`.
- Confirm the installed product includes the headless MCP server.
- Run the same command manually in a terminal to check for startup errors.

If `bn_debugger_*` tools return `debugger_endpoint_unavailable`:

- In the GUI server, confirm `ui.mcp.debugger.enabled` is enabled and the MCP server has been (re)started since.
- In the headless server, confirm `BN_MCP_DISABLE_DEBUGGER` is not set.
- Check the Binary Ninja log for why the endpoint failed to start. `ModuleNotFoundError` for `binaryninja.debugger.rpc_server` means this debugger build does not include the endpoint yet; set `ui.mcp.debugger.endpointScript` (`BN_MCP_DEBUGGER_ENDPOINT_SCRIPT` headlessly) to its `rpc_server.py` instead.

If `bn_debugger_*` tools return `unknown_session` in the headless server specifically, check the Binary Ninja log for a "could not register this view with the debugger endpoint" warning, which names the underlying problem.

If a tool from `ui.mcp.debugger.customCommandsFile` (`BN_MCP_DEBUGGER_CUSTOM_COMMANDS` headlessly) does not appear in `tools/list`:

- Check the Binary Ninja log for `MCP: custom debugger command entry N: ...`, which names the file entry and the problem.
- Confirm the file is a JSON array, and that the command's `name` starts with `bn_debugger_` and does not repeat another tool's name.
- Restart the MCP server; the file is only read when it starts.
