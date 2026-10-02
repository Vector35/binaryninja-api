# Writing MCP Tools

Plugins can add tools to Binary Ninja's [MCP server](../guide/mcp.md). Both the GUI's MCP server and the headless `binaryninja_mcp` server offer the tools you register alongside the built-in `bn_*` tools. Tools can be written in Python, C++ or Rust.

## Concepts

A tool has a name, a description, a JSON Schema describing its input, and a handler that receives the arguments and returns a result.

- **Names** must be 1 to 64 letters, digits, `_` or `-`, and unique in the process. Prefix yours with your plugin's name, such as `myplugin_find_crypto`. The `bn_` prefix is used by Binary Ninja's built-in tools.
- **Scope.** A BinaryView-scoped tool, the default, runs against the MCP session's active BinaryView. The server resolves that view before the handler runs and reports `no_active_binary_view` itself when there is none, so the handler can rely on having one. A global tool runs without a view, and can still ask for one if the session has it.
- **Annotations** mark a tool as read-only, destructive, idempotent or open-world. Clients use them to decide how to present a tool and whether to ask the user before running it. Every hint is sent, so a tool without a flag is advertised as one that may modify its environment, is not destructive, is not idempotent, and does not reach outside Binary Ninja.
- **Results** are text, structured content (a JSON object), or both. When a tool returns structured content and no text, clients that ignore structured content see the JSON as text. An error result carries a machine-readable `errorCode` and an `errorMessage` as structured content. A tool with an output schema returns them as text instead, since the error does not match the schema.
- **Return one representation.** Some MCP clients show the model only the structured content, and others only the text. A tool that returns both must put everything the model needs in each, so prefer returning one or the other.
- **Warnings** are advisory notes about a result, such as analysis that has not finished, each with a `code` and a `message`. Binary Ninja adds them to structured content as a `warnings` array and lists them as plain text after any text. The `warnings` property is reserved, so an output schema must not declare it. Registration adds it to every output schema. Facts about the result, such as how many bytes were read, belong in the result itself.
- **Argument checking.** The typed interfaces in each language build the input schema from your declarations and check every argument before the handler runs, except one whose schema you supply yourself. A missing, mistyped or undeclared argument produces an `invalid_params` error without calling the handler. A null argument for an optional parameter is treated as absent.
- **Address expressions.** Parameters declared as addresses accept Binary Ninja expression strings such as `0x401000`, `main` or `.text + 0x10`, and your handler receives the evaluated address. Parameters declared as integer expressions accept either a JSON integer or an expression string. See [Address Expressions](../guide/mcp.md#address-expressions).
- **Threading.** Handlers run on the MCP server's thread, not the UI's main thread. Use `execute_on_main_thread_and_wait` (Python), `ExecuteOnMainThreadAndWait` (C++) or `main_thread::execute_on_main_thread_and_wait` (Rust) for anything that touches the UI.
- **Cancellation and progress.** Binary Ninja's MCP servers don't yet pass cancellation requests or progress between clients and tools. Until they do, a call never reports that it has been cancelled while the handler runs, and progress a tool reports is discarded. A long-running tool should still check for cancellation and report its progress, so that both work once the servers support them. Once the handler returns, the call is detached. It then has no binary view and reports itself cancelled, so a background thread that keeps the call stops with it.

Clients cache the tool list, so register tools when your plugin loads. A client that connected before your plugin registered its tools sees them after it reconnects.

## Python

The `binaryninja.mcp` module's `tool` decorator builds the tool from the function. The first parameter receives the `ToolCall`. Every other parameter becomes a tool parameter, and needs a type annotation and a `:param name:` line in the docstring. The docstring's leading paragraph becomes the tool's description.

```python
from typing import List, Literal, Optional
from binaryninja import mcp

@mcp.tool(read_only=True)
def myplugin_find_strings(
	call: mcp.ToolCall,
	min_length: int = 4,
	section: Optional[str] = None,
) -> dict:
	"""Find strings in the active binary view.

	:param min_length: Minimum string length in bytes.
	:param section: Only search this section.
	"""
	bv = call.binary_view
	strings = [s for s in bv.strings if s.length >= min_length]
	if section is not None:
		target = bv.get_section_by_name(section)
		if target is None:
			raise mcp.ToolError("section_not_found", f"No section named {section}")
		strings = [s for s in strings if target.start <= s.start < target.end]
	return {"strings": [{"address": hex(s.start), "value": s.value} for s in strings]}
```

The decorator supports these annotations:

| Annotation | Schema | The function receives |
| --- | --- | --- |
| `str`, `int`, `float`, `bool` | `string`, `integer`, `number`, `boolean` | the value |
| `Annotated[int, mcp.Minimum(0), mcp.Maximum(100)]` | `integer` with those bounds | the value, after rejecting values outside the bounds |
| `Annotated[int, mcp.ClampTo(0, 1000)]` | `integer` with those bounds | the value, moved to the nearest bound when outside them |
| `Annotated[str, mcp.NonEmpty()]` | `string` with `minLength` 1 | the value, after rejecting an empty string |
| `mcp.Address` | `string` | the evaluated address, as an `int` |
| `mcp.IntegerExpression` | `integer` or `string` | the integer or evaluated expression, as an `int` |
| `Annotated[mcp.IntegerExpression, mcp.RelativeTo("address")]` | `integer` or `string` | the same, with `$here` set to an earlier integer parameter's value, or its default when it is absent, or 0 when it has none |
| a Binary Ninja enum, such as `SectionSemantics` | `string` with the member names | the enum member |
| `Literal["a", "b"]` | `string` with those choices | the string |
| `List[T]` | `array` of `T` | a list |
| `Annotated[T, mcp.Schema({...})]` | the schema you supply | the decoded JSON, unchecked |

`Optional[T]`, `T | None` or a default value makes a parameter optional. A default value also appears in the schema.

Return a `str` for text, a `dict` for structured content, `None` for an empty result, or an `mcp.ToolResult` to combine text and structured content, and call its `add_warning(code, message)` for a warning. Raise `mcp.ToolError(code, message, details)` to return an error result. Any other exception, or a result that cannot be serialized as JSON, produces an `internal_error` result, and its traceback goes to the log.

The decorator also accepts `name` (defaults to the function's name), `title`, `scope` (`McpToolScope.GlobalScope` for a global tool), `read_only`, `destructive`, `idempotent`, `open_world` and `output_schema`.

To supply a schema yourself, use `mcp.register_tool(name, description, input_schema, handler)`, where `handler(call, arguments)` receives the decoded arguments object.

`mcp.Tool` lists every registered tool, and `mcp.Tool.by_name(name).invoke(arguments, view)` runs one as an MCP server would, which is useful in tests.

## C++

Include `mcp.h` and describe each parameter with the builder. Each parameter's declaration produces both its schema and its conversion, and the handler's signature is checked against the parameters at compile time.

```cpp
#include "mcp.h"

using namespace BinaryNinja;
using namespace BinaryNinja::MCP;

extern "C" BINARYNINJAPLUGIN bool CorePluginInit()
{
	MakeTool({"myplugin_set_comment", "Set Comment", "Set the comment at an address in the active binary view.",
				 Scope::BinaryView, IdempotentHint})
		.Param(Address("address", "Address expression of the comment."))
		.Param(String("text", "Comment text."))
		.Param(Bool("replace", "Replace an existing comment.").Default(true))
		.Register([](ToolCall& call, uint64_t address, const std::string& text, bool replace) {
			Ref<BinaryView> view = call.GetBinaryView();
			if (!replace && !view->GetCommentForAddress(address).empty())
				return ToolResult::Error("comment_exists", "The address already has a comment");
			view->SetCommentForAddress(address, text);
			return ToolResult::Text("Comment set");
		});
	return true;
}
```

| Parameter | Schema | The handler receives |
| --- | --- | --- |
| `String` | `string` | `std::string`. `.NonEmpty()` rejects an empty string. |
| `Bool` | `boolean` | `bool` |
| `UInt` | `integer` | `uint64_t`. `.Maximum(n)` rejects larger values and `.ClampTo(n)` caps them. |
| `Address` | `string` | `uint64_t`, the evaluated address |
| `IntegerExpression` | `integer` or `string` | `uint64_t`, the integer or evaluated expression. `.RelativeTo("address")` sets `$here` to an earlier integer parameter's value, or its default when it is absent, such as for a length measured from an address. |
| `Int` | `integer` | `int64_t`. `.Minimum(n)` and `.Maximum(n)` reject values outside them, and `.ClampTo(min, max)` moves them to the nearest bound. |
| `Number` | `number` | `double` |
| `List<Item>` | `array` of `Item` | `std::vector<Item::Value>`, such as `std::vector<std::string>` for `List<String>`. Pass an item, such as `Choice("levels", "", {...})`, for a kind that needs settings. |
| `Choice` | `string` with fixed choices | `std::string` |
| `Enum<T>` | `string` with the listed core enum values | `T` |
| `JsonValue` | the schema fragment you supply | `const rapidjson::Value*` |

`.Optional()` makes the handler receive `std::optional<T>`, empty when the argument is absent or null. `.Default(value)` makes it receive `value` when the argument is absent or null, and advertises the default in the schema. `JsonValue` has no default, and its `.Optional()` keeps the handler's `const rapidjson::Value*`, which is null when the argument is absent or null.

Return `ToolResult::Text`, `ToolResult::Structured(rapidjson::Value)` or `ToolResult::Error(code, message, details)`, and use `AddText` to combine text with structured content. A handler that throws produces an `internal_error` result.

`Register` returns null when the tool is rejected, such as for two parameters with the same name or a `RelativeTo` that does not name an earlier integer parameter.

To supply a schema yourself, call `RegisterTool(definition, inputSchema, handler)` with a handler taking `(ToolCall&, const rapidjson::Value& arguments)`.

## Rust

Implement `McpTool` and pass it to `register_mcp_tool`:

```rust
use binaryninja::mcp::tool::*;
use serde_json::{json, Value};

struct FunctionCount;

impl McpTool for FunctionCount {
    fn definition(&self) -> McpToolDefinition {
        McpToolInfo::new("myplugin_function_count", "Count the functions in the active binary view.")
            .with_annotations(McpToolAnnotations::READ_ONLY)
            .with_input_schema(empty_input_schema())
    }

    fn invoke(&self, call: &McpToolCall, _arguments: Value) -> Result<McpToolResult, McpToolError> {
        let view = call.require_binary_view()?;
        Ok(McpToolResult::structured(json!({ "count": view.functions().len() })))
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    register_mcp_tool(FunctionCount).is_some()
}
```

With the crate's `schemars` feature enabled, implement `TypedMcpTool` instead and pass it to `register_typed_mcp_tool`. The input schema and argument parsing then come from the arguments type, which derives `serde::Deserialize` and `schemars::JsonSchema`, so your plugin depends on `serde` with its `derive` feature and on `schemars` 1. That type is a struct with named fields, or with none for a tool that takes no arguments, since the input schema must be an object. Doc comments become parameter descriptions. `Option` fields and `#[serde(default)]` make parameters optional, and undeclared arguments are rejected. `McpAddress` and `McpIntegerExpression` hold address and integer expressions until you `resolve` them against the call. `McpNonEmptyString` rejects an empty string.

```rust
#[derive(serde::Deserialize, schemars::JsonSchema)]
struct CommentArgs {
    /// Address expression of the comment.
    address: McpAddress,
    /// Comment text.
    text: String,
}

struct SetComment;

impl TypedMcpTool for SetComment {
    type Args = CommentArgs;

    fn info(&self) -> McpToolInfo {
        McpToolInfo::new("myplugin_set_comment", "Set the comment at an address in the active binary view.")
    }

    fn invoke(&self, call: &McpToolCall, args: CommentArgs) -> Result<McpToolResult, McpToolError> {
        let address = args.address.resolve(call)?;
        call.require_binary_view()?.set_comment_at(address, &args.text);
        Ok(McpToolResult::text("Comment set"))
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    register_typed_mcp_tool(SetComment).is_some()
}
```

A tool that panics produces an `internal_error` result when the plugin is built with `panic = "unwind"`. Under `panic = "abort"`, which the Rust plugins bundled with Binary Ninja use, a panic ends the process.
