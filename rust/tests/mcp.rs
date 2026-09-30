use binaryninja::binary_view::BinaryView;
use binaryninja::file_metadata::FileMetadata;
use binaryninja::headless::Session;
use binaryninja::mcp::server::{create_mcp_tool, invoke_mcp_tool, McpToolCallHost};
use binaryninja::mcp::tool::{
    empty_input_schema, register_mcp_tool, CoreMcpTool, McpIntegerExpression, McpTool,
    McpToolAnnotations, McpToolCall, McpToolDefinition, McpToolError, McpToolInfo, McpToolResult,
    McpToolScope,
};
use binaryninja::rc::Ref;
use serde_json::{json, Value};
use std::sync::Mutex;

// The registry is process-global and has no unregistration, so every test registers its tools under
// its own names.

/// Reports whether it was given a binary view.
struct ViewTool {
    name: &'static str,
    scope: McpToolScope,
}

impl McpTool for ViewTool {
    fn definition(&self) -> McpToolDefinition {
        McpToolInfo::new(self.name, "Report whether the call has a binary view.")
            .with_scope(self.scope)
            .with_annotations(McpToolAnnotations::READ_ONLY | McpToolAnnotations::IDEMPOTENT)
            .with_input_schema(empty_input_schema())
    }

    fn invoke(&self, call: &McpToolCall, _arguments: Value) -> Result<McpToolResult, McpToolError> {
        Ok(McpToolResult::structured(
            json!({ "hasView": call.binary_view().is_some() }),
        ))
    }
}

/// Evaluates its `size` argument, which may be an integer or an expression.
struct SizeTool;

impl McpTool for SizeTool {
    fn definition(&self) -> McpToolDefinition {
        McpToolInfo::new("rust_mcp_size", "Evaluate a size.").with_input_schema(json!({
            "type": "object",
            "properties": { "size": { "type": ["integer", "string"] } },
            "required": ["size"],
        }))
    }

    fn invoke(&self, call: &McpToolCall, arguments: Value) -> Result<McpToolResult, McpToolError> {
        let size: McpIntegerExpression = serde_json::from_value(arguments["size"].clone())?;
        Ok(McpToolResult::structured(
            json!({ "size": size.resolve(call)? }),
        ))
    }
}

struct FailingTool;

impl McpTool for FailingTool {
    fn definition(&self) -> McpToolDefinition {
        McpToolInfo::new("rust_mcp_failing", "Always fail.")
            .with_scope(McpToolScope::GlobalScope)
            .with_input_schema(empty_input_schema())
    }

    fn invoke(
        &self,
        _call: &McpToolCall,
        _arguments: Value,
    ) -> Result<McpToolResult, McpToolError> {
        Err(McpToolError::new("requested_failure", "Failed on request")
            .with_details(json!({ "why": "asked" })))
    }
}

struct PanickingTool;

impl McpTool for PanickingTool {
    fn definition(&self) -> McpToolDefinition {
        McpToolInfo::new("rust_mcp_panicking", "Always panic.")
            .with_scope(McpToolScope::GlobalScope)
            .with_input_schema(empty_input_schema())
    }

    fn invoke(
        &self,
        _call: &McpToolCall,
        _arguments: Value,
    ) -> Result<McpToolResult, McpToolError> {
        panic!("requested panic")
    }
}

/// Reports progress, then whether the call was cancelled.
struct ProgressTool;

impl McpTool for ProgressTool {
    fn definition(&self) -> McpToolDefinition {
        McpToolInfo::new("rust_mcp_progress", "Report progress and cancellation.")
            .with_scope(McpToolScope::GlobalScope)
            .with_input_schema(empty_input_schema())
    }

    fn invoke(&self, call: &McpToolCall, _arguments: Value) -> Result<McpToolResult, McpToolError> {
        call.report_progress(1.0, 2.0, "halfway");
        Ok(McpToolResult::structured(
            json!({ "cancelled": call.is_cancelled() }),
        ))
    }
}

struct ViewHost(Option<Ref<BinaryView>>);

impl McpToolCallHost for ViewHost {
    fn binary_view(&self) -> Option<Ref<BinaryView>> {
        self.0.clone()
    }
}

struct RecordingHost {
    cancelled: bool,
    progress: Mutex<Vec<(f64, f64, String)>>,
}

impl McpToolCallHost for RecordingHost {
    fn binary_view(&self) -> Option<Ref<BinaryView>> {
        None
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    fn report_progress(&self, progress: f64, total: f64, message: &str) {
        self.progress
            .lock()
            .unwrap()
            .push((progress, total, message.to_string()));
    }
}

fn raw_view() -> Ref<BinaryView> {
    BinaryView::from_data(&FileMetadata::new(), &[0u8; 0x100])
}

fn invoke(tool: &CoreMcpTool, arguments: &Value, view: Option<&BinaryView>) -> Value {
    invoke_mcp_tool(tool, &ViewHost(view.map(|view| view.to_owned())), arguments)
}

fn error_code(result: &Value) -> &str {
    assert_eq!(result["isError"], true, "{result}");
    result["structuredContent"]["errorCode"]
        .as_str()
        .unwrap_or_default()
}

#[test]
fn registers_lists_and_describes_tools() {
    let _session = Session::new().expect("Failed to initialize session");
    let tool = register_mcp_tool(ViewTool {
        name: "rust_mcp_describe",
        scope: McpToolScope::GlobalScope,
    })
    .expect("registration failed");

    assert_eq!(tool.name(), "rust_mcp_describe");
    assert_eq!(
        tool.description(),
        "Report whether the call has a binary view."
    );
    assert_eq!(tool.scope(), McpToolScope::GlobalScope);
    assert_eq!(
        tool.annotations(),
        McpToolAnnotations::READ_ONLY | McpToolAnnotations::IDEMPOTENT
    );
    assert_eq!(tool.input_schema(), empty_input_schema());
    assert_eq!(tool.output_schema(), None);
    assert_eq!(CoreMcpTool::from_name("rust_mcp_describe"), Some(tool));

    let names: Vec<String> = CoreMcpTool::list().iter().map(|tool| tool.name()).collect();
    assert!(names.iter().any(|name| name == "rust_mcp_describe"));
    assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
}

#[test]
fn hosts_supply_cancellation_and_receive_progress() {
    let _session = Session::new().expect("Failed to initialize session");
    let tool = create_mcp_tool(ProgressTool).expect("creation failed");

    for cancelled in [false, true] {
        let host = RecordingHost {
            cancelled,
            progress: Mutex::new(Vec::new()),
        };
        let result = invoke_mcp_tool(&tool, &host, &json!({}));
        assert_eq!(result["structuredContent"]["cancelled"], cancelled);
        assert_eq!(
            *host.progress.lock().unwrap(),
            vec![(1.0, 2.0, "halfway".to_string())]
        );
    }
}

#[test]
fn created_tools_are_not_registered() {
    let _session = Session::new().expect("Failed to initialize session");
    let tool = create_mcp_tool(ViewTool {
        name: "rust_mcp_created",
        scope: McpToolScope::GlobalScope,
    })
    .expect("creation failed");

    assert_eq!(tool.name(), "rust_mcp_created");
    assert_eq!(CoreMcpTool::from_name("rust_mcp_created"), None);
    assert!(CoreMcpTool::list()
        .iter()
        .all(|tool| tool.name() != "rust_mcp_created"));
    assert_eq!(
        invoke(&tool, &json!({}), None)["structuredContent"]["hasView"],
        false
    );
}

#[test]
fn rejects_duplicate_and_invalid_names() {
    let _session = Session::new().expect("Failed to initialize session");
    let scope = McpToolScope::GlobalScope;
    assert!(register_mcp_tool(ViewTool {
        name: "rust_mcp_duplicate",
        scope
    })
    .is_some());
    assert!(register_mcp_tool(ViewTool {
        name: "rust_mcp_duplicate",
        scope
    })
    .is_none());
    assert!(register_mcp_tool(ViewTool {
        name: "rust mcp",
        scope
    })
    .is_none());
}

#[test]
fn errors_and_panics_become_error_results() {
    let _session = Session::new().expect("Failed to initialize session");
    let failing = register_mcp_tool(FailingTool).expect("registration failed");
    let panicking = register_mcp_tool(PanickingTool).expect("registration failed");

    let result = invoke(&failing, &json!({}), None);
    assert_eq!(error_code(&result), "requested_failure");
    assert_eq!(result["structuredContent"]["details"]["why"], "asked");

    let result = invoke(&panicking, &json!({}), None);
    assert_eq!(error_code(&result), "internal_error");
    assert_eq!(
        result["structuredContent"]["errorMessage"],
        "The tool panicked: requested panic"
    );
}

#[test]
fn binary_view_scope_requires_a_view() {
    let _session = Session::new().expect("Failed to initialize session");
    let tool = register_mcp_tool(ViewTool {
        name: "rust_mcp_view",
        scope: McpToolScope::BinaryViewScope,
    })
    .expect("registration failed");

    assert_eq!(
        error_code(&invoke(&tool, &json!({}), None)),
        "no_active_binary_view"
    );

    let view = raw_view();
    let result = invoke(&tool, &json!({}), Some(&view));
    assert_eq!(result["structuredContent"]["hasView"], true);
}

#[test]
fn integer_arguments_accept_integers_and_expressions() {
    let _session = Session::new().expect("Failed to initialize session");
    let tool = register_mcp_tool(SizeTool).expect("registration failed");
    let view = raw_view();

    assert_eq!(
        invoke(&tool, &json!({ "size": 4 }), Some(&view))["structuredContent"]["size"],
        4
    );
    assert_eq!(
        invoke(&tool, &json!({ "size": "0x10 + 2" }), Some(&view))["structuredContent"]["size"],
        0x12
    );
    assert_eq!(
        error_code(&invoke(&tool, &json!({ "size": true }), Some(&view))),
        "invalid_params"
    );
}

#[cfg(feature = "schemars")]
mod typed {
    use super::*;
    use binaryninja::mcp::server::create_typed_mcp_tool;
    use binaryninja::mcp::tool::{
        register_typed_mcp_tool, McpAddress, McpNonEmptyString, TypedMcpTool,
    };
    use schemars::JsonSchema;
    use serde_derive::Deserialize;

    #[derive(Deserialize, JsonSchema)]
    #[serde(rename_all = "lowercase")]
    enum CommentKind {
        Regular,
        Repeatable,
    }

    #[derive(Deserialize, JsonSchema)]
    #[serde(deny_unknown_fields)]
    struct CommentArgs {
        /// Address expression of the comment.
        address: McpAddress,
        /// Comment text.
        text: String,
        /// Kind of comment.
        kind: CommentKind,
        /// Bytes the comment covers.
        length: Option<McpIntegerExpression>,
        /// Optional repeat count.
        #[serde(default)]
        count: Option<u32>,
    }

    struct CommentTool;

    impl TypedMcpTool for CommentTool {
        type Args = CommentArgs;

        fn info(&self) -> McpToolInfo {
            McpToolInfo::new("rust_mcp_typed", "Resolve a comment address.")
        }

        fn invoke(
            &self,
            call: &McpToolCall,
            args: CommentArgs,
        ) -> Result<McpToolResult, McpToolError> {
            let address = args.address.resolve(call)?;
            let length = args.length.map(|length| length.resolve(call)).transpose()?;
            let repeatable = matches!(args.kind, CommentKind::Repeatable);
            Ok(McpToolResult::structured(json!({
                "address": address,
                "text": args.text,
                "repeatable": repeatable,
                "length": length,
                "count": args.count,
            })))
        }
    }

    #[test]
    fn typed_tools_generate_schemas_and_parse_arguments() {
        let _session = Session::new().expect("Failed to initialize session");
        let tool = register_typed_mcp_tool(CommentTool).expect("registration failed");
        let created = create_typed_mcp_tool(CommentTool).expect("creation failed");
        assert_eq!(created.input_schema(), tool.input_schema());

        assert_eq!(
            tool.input_schema(),
            json!({
                "type": "object",
                "properties": {
                    "address": { "type": "string", "description": "Address expression of the comment." },
                    "text": { "type": "string", "description": "Comment text." },
                    "kind": { "type": "string", "enum": ["regular", "repeatable"], "description": "Kind of comment." },
                    "length": {
                        "type": ["integer", "string", "null"],
                        "minimum": 0,
                        "description": "Bytes the comment covers.",
                    },
                    "count": {
                        "type": ["integer", "null"],
                        "format": "uint32",
                        "minimum": 0,
                        "default": null,
                        "description": "Optional repeat count.",
                    },
                },
                "required": ["address", "text", "kind"],
                "additionalProperties": false,
            })
        );

        let view = raw_view();
        let result = invoke(
            &tool,
            &json!({ "address": "0x20", "text": "hi", "kind": "repeatable", "length": "0x10 + 2", "count": 3 }),
            Some(&view),
        );
        assert_eq!(
            result["structuredContent"],
            json!({ "address": 0x20, "text": "hi", "repeatable": true, "length": 0x12, "count": 3 })
        );

        let result = invoke(
            &tool,
            &json!({ "address": "0x20", "text": "hi", "kind": "regular" }),
            Some(&view),
        );
        assert_eq!(result["structuredContent"]["length"], Value::Null);
        assert_eq!(result["structuredContent"]["count"], Value::Null);

        for arguments in [
            json!({ "address": "0x20", "text": "hi", "kind": "regular", "other": 1 }),
            json!({ "address": "0x20", "text": "hi" }),
            json!({ "address": "0x20", "text": "hi", "kind": "block" }),
            json!({ "address": "0x20", "text": 5, "kind": "regular" }),
        ] {
            let result = invoke(&tool, &arguments, Some(&view));
            assert_eq!(error_code(&result), "invalid_params", "{arguments}");
        }

        let result = invoke(
            &tool,
            &json!({ "address": "not_a_symbol", "text": "hi", "kind": "regular" }),
            Some(&view),
        );
        assert_eq!(error_code(&result), "invalid_params");
    }

    #[derive(Deserialize, JsonSchema)]
    struct LenientArgs {
        /// Optional value.
        value: Option<u32>,
    }

    struct LenientTool;

    impl TypedMcpTool for LenientTool {
        type Args = LenientArgs;

        fn info(&self) -> McpToolInfo {
            McpToolInfo::new("rust_mcp_typed_lenient", "Echo a value.")
                .with_scope(McpToolScope::GlobalScope)
        }

        fn invoke(
            &self,
            _call: &McpToolCall,
            args: LenientArgs,
        ) -> Result<McpToolResult, McpToolError> {
            Ok(McpToolResult::structured(json!({ "value": args.value })))
        }
    }

    #[test]
    fn typed_tools_reject_undeclared_arguments() {
        let _session = Session::new().expect("Failed to initialize session");
        let tool = register_typed_mcp_tool(LenientTool).expect("registration failed");
        assert_eq!(tool.input_schema()["additionalProperties"], false);

        assert_eq!(
            invoke(&tool, &json!({ "value": 3 }), None)["structuredContent"]["value"],
            3
        );
        let result = invoke(&tool, &json!({ "value": 3, "other": 1 }), None);
        assert_eq!(error_code(&result), "invalid_params");
        assert_eq!(
            result["structuredContent"]["errorMessage"],
            "Unexpected parameter 'other'"
        );
    }

    #[test]
    fn typed_tools_name_the_invalid_parameter() {
        let _session = Session::new().expect("Failed to initialize session");
        let tool = create_typed_mcp_tool(CommentTool).expect("creation failed");
        let view = raw_view();

        for (arguments, message) in [
            (
                json!({ "address": "0x20", "text": 5, "kind": "regular" }),
                "Invalid parameter 'text': invalid type: integer `5`, expected a string",
            ),
            (
                json!({ "address": "0x20", "text": "hi", "kind": "regular", "length": -1 }),
                "Invalid parameter 'length': invalid value: integer `-1`, expected an unsigned integer or an integer expression string",
            ),
            (
                json!({ "address": "0x20", "text": "hi", "kind": "regular", "length": 1.5 }),
                "Invalid parameter 'length': invalid type: floating point `1.5`, expected an unsigned integer or an integer expression string",
            ),
            (json!({ "address": "0x20", "text": "hi" }), "missing field `kind`"),
        ] {
            let result = invoke(&tool, &arguments, Some(&view));
            assert_eq!(error_code(&result), "invalid_params", "{arguments}");
            assert_eq!(result["structuredContent"]["errorMessage"], message, "{arguments}");
        }
    }

    #[derive(Deserialize, JsonSchema)]
    struct LabelArgs {
        /// Some text.
        text: McpNonEmptyString,
        /// A label.
        label: Option<McpNonEmptyString>,
    }

    struct LabelTool;

    impl TypedMcpTool for LabelTool {
        type Args = LabelArgs;

        fn info(&self) -> McpToolInfo {
            McpToolInfo::new("rust_mcp_typed_non_empty", "Echo non-empty strings.")
                .with_scope(McpToolScope::GlobalScope)
        }

        fn invoke(
            &self,
            _call: &McpToolCall,
            args: LabelArgs,
        ) -> Result<McpToolResult, McpToolError> {
            Ok(McpToolResult::structured(
                json!({ "text": args.text.0, "label": args.label.map(|label| label.0) }),
            ))
        }
    }

    #[test]
    fn typed_tools_reject_empty_non_empty_strings() {
        let _session = Session::new().expect("Failed to initialize session");
        let tool = create_typed_mcp_tool(LabelTool).expect("creation failed");
        let schema = tool.input_schema();
        assert_eq!(
            schema["properties"]["text"],
            json!({ "type": "string", "minLength": 1, "description": "Some text." })
        );
        assert_eq!(schema["properties"]["label"]["minLength"], 1);

        assert_eq!(
            invoke(&tool, &json!({ "text": "a", "label": "b" }), None)["structuredContent"],
            json!({ "text": "a", "label": "b" })
        );

        for (arguments, message) in [
            (
                json!({ "text": "" }),
                "Invalid parameter 'text': invalid value: string \"\", expected a non-empty string",
            ),
            (
                json!({ "text": "a", "label": "" }),
                "Invalid parameter 'label': invalid value: string \"\", expected a non-empty string",
            ),
            (json!({}), "missing field `text`"),
        ] {
            let result = invoke(&tool, &arguments, None);
            assert_eq!(error_code(&result), "invalid_params", "{arguments}");
            assert_eq!(result["structuredContent"]["errorMessage"], message, "{arguments}");
        }
    }

    #[derive(Deserialize, JsonSchema)]
    struct NoArgs {}

    struct NoArgsTool;

    impl TypedMcpTool for NoArgsTool {
        type Args = NoArgs;

        fn info(&self) -> McpToolInfo {
            McpToolInfo::new("rust_mcp_typed_no_args", "Take no arguments.")
                .with_scope(McpToolScope::GlobalScope)
        }

        fn invoke(
            &self,
            _call: &McpToolCall,
            _args: NoArgs,
        ) -> Result<McpToolResult, McpToolError> {
            Ok(McpToolResult::text("ok"))
        }
    }

    #[test]
    fn typed_tools_without_arguments_reject_every_argument() {
        let _session = Session::new().expect("Failed to initialize session");
        let tool = create_typed_mcp_tool(NoArgsTool).expect("creation failed");
        assert_eq!(tool.input_schema()["type"], "object");
        assert_eq!(tool.input_schema()["additionalProperties"], false);

        assert_eq!(invoke(&tool, &json!({}), None)["content"][0]["text"], "ok");
        let result = invoke(&tool, &json!({ "other": 1 }), None);
        assert_eq!(error_code(&result), "invalid_params");
        assert_eq!(
            result["structuredContent"]["errorMessage"],
            "Unexpected parameter 'other'"
        );
    }
}
