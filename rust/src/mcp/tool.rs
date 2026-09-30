// Copyright 2022-2026 Vector 35 Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Writing and registering MCP tools.
//!
//! A tool registered here is offered by every MCP server in the process, alongside the built-in
//! `bn_*` tools. Implement [`McpTool`] and pass it to [`register_mcp_tool`]. With the `schemars`
//! feature, implement `TypedMcpTool` instead and pass it to `register_typed_mcp_tool`. The input
//! schema and argument parsing then come from the arguments type.

use binaryninjacore_sys::*;
use serde_json::{json, Value};
use std::ffi::{c_char, c_void, CStr, CString};
use std::fmt;
use std::panic::{self, AssertUnwindSafe};
use std::ptr;

use crate::binary_view::BinaryView;
use crate::rc::*;
use crate::string::{BnString, IntoCStr};

pub use binaryninjacore_sys::BNMcpToolScope as McpToolScope;

bitflags::bitflags! {
    /// Hints a client uses to decide how to present a tool and whether to ask before running it.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub struct McpToolAnnotations: u32 {
        const READ_ONLY = BNMcpToolAnnotation::ReadOnlyHint.0;
        const DESTRUCTIVE = BNMcpToolAnnotation::DestructiveHint.0;
        const IDEMPOTENT = BNMcpToolAnnotation::IdempotentHint.0;
        const OPEN_WORLD = BNMcpToolAnnotation::OpenWorldHint.0;
    }
}

/// Everything about a tool except its input schema.
#[derive(Clone, Debug)]
pub struct McpToolInfo {
    pub name: String,
    pub title: String,
    pub description: String,
    pub scope: McpToolScope,
    pub annotations: McpToolAnnotations,
    pub output_schema: Option<Value>,
}

impl McpToolInfo {
    /// A BinaryView-scoped tool with no title, annotations or output schema.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            title: String::new(),
            description: description.into(),
            scope: McpToolScope::BinaryViewScope,
            annotations: McpToolAnnotations::empty(),
            output_schema: None,
        }
    }

    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    pub fn with_scope(mut self, scope: McpToolScope) -> Self {
        self.scope = scope;
        self
    }

    pub fn with_annotations(mut self, annotations: McpToolAnnotations) -> Self {
        self.annotations = annotations;
        self
    }

    pub fn with_output_schema(mut self, schema: Value) -> Self {
        self.output_schema = Some(schema);
        self
    }

    /// Completes the definition with a JSON Schema object for the tool's input.
    pub fn with_input_schema(self, input_schema: Value) -> McpToolDefinition {
        McpToolDefinition {
            info: self,
            input_schema,
        }
    }
}

#[derive(Clone, Debug)]
pub struct McpToolDefinition {
    pub info: McpToolInfo,
    /// A JSON Schema object with `"type": "object"`.
    pub input_schema: Value,
}

/// An error result with a machine-readable code.
#[derive(Clone, Debug, PartialEq)]
pub struct McpToolError {
    pub code: String,
    pub message: String,
    pub details: Option<Value>,
}

impl McpToolError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            details: None,
        }
    }

    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new("invalid_params", message)
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }
}

impl fmt::Display for McpToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for McpToolError {}

/// Arguments that do not match the type they are parsed into are invalid parameters.
impl From<serde_json::Error> for McpToolError {
    fn from(error: serde_json::Error) -> Self {
        Self::invalid_params(error.to_string())
    }
}

/// Tool output is arbitrary text, and a NUL would otherwise panic in `CString::new`.
fn c_text(text: &str) -> CString {
    CString::new(text.replace('\0', "\u{FFFD}")).unwrap_or_default()
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct McpToolResult {
    text: Vec<String>,
    structured_content: Option<Value>,
    error: Option<McpToolError>,
    warnings: Vec<(String, String)>,
}

impl McpToolResult {
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: vec![text.into()],
            ..Self::default()
        }
    }

    /// `content` must be a JSON object. When no text is added, clients that ignore structured
    /// content see it serialized as text.
    pub fn structured(content: Value) -> Self {
        Self {
            structured_content: Some(content),
            ..Self::default()
        }
    }

    pub fn error(error: McpToolError) -> Self {
        Self {
            error: Some(error),
            ..Self::default()
        }
    }

    pub fn with_text(mut self, text: impl Into<String>) -> Self {
        self.text.push(text.into());
        self
    }

    /// An advisory warning about the result, such as analysis that has not finished. Clients see
    /// it in the structured content's reserved `warnings` member, and after any text.
    pub fn with_warning(mut self, code: impl Into<String>, message: impl Into<String>) -> Self {
        self.warnings.push((code.into(), message.into()));
        self
    }

    fn apply(&self, result: *mut BNMcpToolResult) {
        unsafe {
            if let Some(error) = &self.error {
                let code = c_text(&error.code);
                let message = c_text(&error.message);
                let details = error
                    .details
                    .as_ref()
                    .map(|details| details.to_string().to_cstr());
                BNSetMcpToolResultError(
                    result,
                    code.as_ptr(),
                    message.as_ptr(),
                    details
                        .as_ref()
                        .map_or(ptr::null(), |details| details.as_ptr()),
                );
            } else if let Some(content) = &self.structured_content {
                let json = content.to_string().to_cstr();
                if !BNSetMcpToolResultStructuredContent(result, json.as_ptr()) {
                    let code = "internal_error".to_cstr();
                    let message =
                        "The tool produced structured content that is not a JSON object".to_cstr();
                    BNSetMcpToolResultError(result, code.as_ptr(), message.as_ptr(), ptr::null());
                    return;
                }
            }
            for text in &self.text {
                let text = c_text(text);
                BNAddMcpToolResultText(result, text.as_ptr());
            }
            for (code, message) in &self.warnings {
                let code = c_text(code);
                let message = c_text(message);
                BNAddMcpToolResultWarning(result, code.as_ptr(), message.as_ptr());
            }
        }
    }
}

impl From<McpToolError> for McpToolResult {
    fn from(error: McpToolError) -> Self {
        Self::error(error)
    }
}

/// One invocation of a tool. The binary view and cancellation state are only available while the
/// tool is running.
pub struct McpToolCall {
    handle: *mut BNMcpToolCall,
}

impl McpToolCall {
    pub(crate) unsafe fn ref_from_raw(handle: *mut BNMcpToolCall) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Ref::new(Self { handle })
    }

    /// The binary view the MCP session targets. Never `None` while a BinaryView-scoped tool runs.
    pub fn binary_view(&self) -> Option<Ref<BinaryView>> {
        let view = unsafe { BNGetMcpToolCallBinaryView(self.handle) };
        (!view.is_null()).then(|| unsafe { BinaryView::ref_from_raw(view) })
    }

    /// The binary view, or the `no_active_binary_view` error to return with `?` when there is none.
    pub fn require_binary_view(&self) -> Result<Ref<BinaryView>, McpToolError> {
        self.binary_view().ok_or_else(|| {
            McpToolError::new(
                "no_active_binary_view",
                "No active Binary Ninja binary view is selected",
            )
        })
    }

    pub fn is_cancelled(&self) -> bool {
        unsafe { BNIsMcpToolCallCancelled(self.handle) }
    }

    pub fn report_progress(&self, progress: f64, total: f64, message: &str) {
        let message = c_text(message);
        unsafe { BNReportMcpToolCallProgress(self.handle, progress, total, message.as_ptr()) }
    }

    /// Evaluates an address expression string against the call's binary view, with `here` as the
    /// value of `$here`.
    pub fn parse_address(&self, value: &Value, here: u64) -> Result<u64, String> {
        self.parse(BNParseMcpToolCallAddress, value, here)
    }

    /// Evaluates an unsigned integer, or an expression string against the call's binary view with
    /// `here` as the value of `$here`.
    pub fn parse_integer(&self, value: &Value, here: u64) -> Result<u64, String> {
        self.parse(BNParseMcpToolCallInteger, value, here)
    }

    fn parse(
        &self,
        parse: unsafe extern "C" fn(
            *mut BNMcpToolCall,
            *const c_char,
            *mut u64,
            u64,
            *mut *mut c_char,
        ) -> bool,
        value: &Value,
        here: u64,
    ) -> Result<u64, String> {
        let json = value.to_string().to_cstr();
        let mut result = 0;
        let mut error: *mut c_char = ptr::null_mut();
        if unsafe { parse(self.handle, json.as_ptr(), &mut result, here, &mut error) } {
            Ok(result)
        } else if error.is_null() {
            Err(String::new())
        } else {
            Err(unsafe { BnString::into_string(error) })
        }
    }
}

unsafe impl Send for McpToolCall {}
unsafe impl Sync for McpToolCall {}

impl ToOwned for McpToolCall {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for McpToolCall {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewMcpToolCallReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeMcpToolCall(handle.handle);
    }
}

/// A tool with a hand-written input schema that receives its arguments as JSON.
pub trait McpTool: 'static + Send + Sync {
    fn definition(&self) -> McpToolDefinition;

    /// Called on an arbitrary thread. An error produces an error result. Under `panic = "unwind"`
    /// a panic produces an `internal_error` result, and under `panic = "abort"` it ends the process.
    fn invoke(&self, call: &McpToolCall, arguments: Value) -> Result<McpToolResult, McpToolError>;
}

/// Registers a tool for the life of the process. Returns `None` when the definition is invalid or
/// its name is already registered, or when a string in it contains a NUL.
pub fn register_mcp_tool<T: McpTool>(tool: T) -> Option<Ref<CoreMcpTool>> {
    create_with(tool, BNRegisterMcpTool)
}

pub(super) fn create_with<T: McpTool>(
    tool: T,
    create: unsafe extern "C" fn(
        *const BNMcpToolDefinition,
        *const BNMcpToolCallbacks,
    ) -> *mut BNMcpTool,
) -> Option<Ref<CoreMcpTool>> {
    struct ToolContext<T> {
        name: String,
        tool: T,
    }

    extern "C" fn cb_invoke<T: McpTool>(
        ctxt: *mut c_void,
        call: *mut BNMcpToolCall,
        arguments: *const c_char,
        result: *mut BNMcpToolResult,
    ) {
        let context = unsafe { &*(ctxt as *const ToolContext<T>) };
        let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
            let call = unsafe { McpToolCall::ref_from_raw(BNNewMcpToolCallReference(call)) };
            let arguments = unsafe { CStr::from_ptr(arguments) }.to_string_lossy();
            serde_json::from_str::<Value>(&arguments)
                .map_err(|error| {
                    McpToolError::invalid_params(format!("Arguments are not valid JSON: {error}"))
                })
                .and_then(|arguments| context.tool.invoke(&call, arguments))
                .unwrap_or_else(McpToolResult::error)
        }));
        let tool_result = outcome.unwrap_or_else(|payload| {
            let message = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                .unwrap_or("unknown panic");
            tracing::error!("MCP tool '{}' panicked: {message}", context.name);
            McpToolError::new("internal_error", format!("The tool panicked: {message}")).into()
        });
        tool_result.apply(result);
    }

    let definition = tool.definition();
    let name = CString::new(definition.info.name.as_str()).ok()?;
    let title = CString::new(definition.info.title.as_str()).ok()?;
    let description = CString::new(definition.info.description.as_str()).ok()?;
    let input_schema = definition.input_schema.to_string().to_cstr();
    let output_schema = definition
        .info
        .output_schema
        .as_ref()
        .map(|schema| schema.to_string().to_cstr());
    let api_definition = BNMcpToolDefinition {
        name: name.as_ptr(),
        title: title.as_ptr(),
        description: description.as_ptr(),
        inputSchema: input_schema.as_ptr(),
        outputSchema: output_schema
            .as_ref()
            .map_or(ptr::null(), |schema| schema.as_ptr()),
        scope: definition.info.scope,
        annotations: definition.info.annotations.bits(),
    };

    extern "C" fn cb_free_object<T: McpTool>(ctxt: *mut c_void) {
        unsafe { drop(Box::from_raw(ctxt as *mut ToolContext<T>)) };
    }

    let ctxt = Box::into_raw(Box::new(ToolContext {
        name: definition.info.name.clone(),
        tool,
    }));
    let callbacks = BNMcpToolCallbacks {
        context: ctxt as *mut c_void,
        invoke: Some(cb_invoke::<T>),
        freeObject: Some(cb_free_object::<T>),
    };
    let handle = unsafe { create(&api_definition, &callbacks) };
    if handle.is_null() {
        unsafe { drop(Box::from_raw(ctxt)) };
        return None;
    }
    Some(unsafe { CoreMcpTool::ref_from_raw(handle) })
}

/// A tool in the tool registry.
#[derive(PartialEq, Eq, Hash)]
pub struct CoreMcpTool {
    pub(super) handle: *mut BNMcpTool,
}

impl CoreMcpTool {
    pub(crate) unsafe fn from_raw(handle: *mut BNMcpTool) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: *mut BNMcpTool) -> Ref<Self> {
        Ref::new(Self::from_raw(handle))
    }

    /// Every registered tool, sorted by name.
    pub fn list() -> Array<CoreMcpTool> {
        let mut count = 0;
        let tools = unsafe { BNGetMcpToolList(&mut count) };
        unsafe { Array::new(tools, count, ()) }
    }

    pub fn from_name(name: &str) -> Option<Ref<Self>> {
        let name = name.to_cstr();
        let handle = unsafe { BNGetMcpToolByName(name.as_ptr()) };
        (!handle.is_null()).then(|| unsafe { Self::ref_from_raw(handle) })
    }

    pub fn name(&self) -> String {
        unsafe { BnString::into_string(BNGetMcpToolName(self.handle)) }
    }

    pub fn title(&self) -> String {
        unsafe { BnString::into_string(BNGetMcpToolTitle(self.handle)) }
    }

    pub fn description(&self) -> String {
        unsafe { BnString::into_string(BNGetMcpToolDescription(self.handle)) }
    }

    pub fn input_schema(&self) -> Value {
        let schema = unsafe { BnString::into_string(BNGetMcpToolInputSchema(self.handle)) };
        serde_json::from_str(&schema).unwrap_or(Value::Null)
    }

    pub fn output_schema(&self) -> Option<Value> {
        let schema = unsafe { BnString::into_string(BNGetMcpToolOutputSchema(self.handle)) };
        serde_json::from_str(&schema).ok()
    }

    pub fn scope(&self) -> McpToolScope {
        unsafe { BNGetMcpToolScope(self.handle) }
    }

    pub fn annotations(&self) -> McpToolAnnotations {
        McpToolAnnotations::from_bits_retain(unsafe { BNGetMcpToolAnnotations(self.handle) })
    }
}

impl fmt::Debug for CoreMcpTool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoreMcpTool")
            .field("name", &self.name())
            .finish()
    }
}

unsafe impl Send for CoreMcpTool {}
unsafe impl Sync for CoreMcpTool {}

impl ToOwned for CoreMcpTool {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for CoreMcpTool {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Self::ref_from_raw(BNNewMcpToolReference(handle.handle))
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeMcpTool(handle.handle);
    }
}

impl CoreArrayProvider for CoreMcpTool {
    type Raw = *mut BNMcpTool;
    type Context = ();
    type Wrapped<'a> = Guard<'a, CoreMcpTool>;
}

unsafe impl CoreArrayProviderInner for CoreMcpTool {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeMcpToolList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(CoreMcpTool::from_raw(*raw), context)
    }
}

/// An address expression string, evaluated against the call's binary view with
/// [`McpAddress::resolve`].
#[derive(Clone, Debug, PartialEq, Eq, serde_derive::Deserialize)]
#[serde(transparent)]
pub struct McpAddress(pub String);

impl McpAddress {
    /// An invalid expression is an `invalid_params` error.
    pub fn resolve(&self, call: &McpToolCall) -> Result<u64, McpToolError> {
        call.parse_address(&Value::String(self.0.clone()), 0)
            .map_err(McpToolError::invalid_params)
    }
}

/// A string argument that rejects an empty string.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct McpNonEmptyString(pub String);

impl<'de> serde::Deserialize<'de> for McpNonEmptyString {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = <String as serde::Deserialize>::deserialize(deserializer)?;
        if value.is_empty() {
            return Err(serde::de::Error::invalid_value(
                serde::de::Unexpected::Str(&value),
                &"a non-empty string",
            ));
        }
        Ok(McpNonEmptyString(value))
    }
}

/// An unsigned integer, or an expression string evaluated against the call's binary view with
/// [`McpIntegerExpression::resolve`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum McpIntegerExpression {
    Integer(u64),
    Expression(String),
}

impl<'de> serde::Deserialize<'de> for McpIntegerExpression {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = McpIntegerExpression;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an unsigned integer or an integer expression string")
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(McpIntegerExpression::Integer(value))
            }

            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                u64::try_from(value)
                    .map(McpIntegerExpression::Integer)
                    .map_err(|_| E::invalid_value(serde::de::Unexpected::Signed(value), &self))
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(McpIntegerExpression::Expression(value.to_owned()))
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

impl McpIntegerExpression {
    /// An invalid expression is an `invalid_params` error.
    pub fn resolve(&self, call: &McpToolCall) -> Result<u64, McpToolError> {
        self.resolve_relative_to(call, 0)
    }

    /// Resolves an expression with `here` as the value of `$here`, such as a length measured from
    /// an address argument.
    pub fn resolve_relative_to(&self, call: &McpToolCall, here: u64) -> Result<u64, McpToolError> {
        match self {
            McpIntegerExpression::Integer(value) => Ok(*value),
            McpIntegerExpression::Expression(expression) => call
                .parse_integer(&Value::String(expression.clone()), here)
                .map_err(McpToolError::invalid_params),
        }
    }
}

#[cfg(feature = "schemars")]
pub(super) mod typed {
    use super::*;
    use schemars::{json_schema, JsonSchema, Schema, SchemaGenerator};
    use serde::Deserialize;
    use std::borrow::Cow;
    use std::sync::OnceLock;

    impl JsonSchema for McpAddress {
        fn schema_name() -> Cow<'static, str> {
            "McpAddress".into()
        }

        fn inline_schema() -> bool {
            true
        }

        fn json_schema(_: &mut SchemaGenerator) -> Schema {
            json_schema!({ "type": "string" })
        }
    }

    impl JsonSchema for McpNonEmptyString {
        fn schema_name() -> Cow<'static, str> {
            "McpNonEmptyString".into()
        }

        fn inline_schema() -> bool {
            true
        }

        fn json_schema(_: &mut SchemaGenerator) -> Schema {
            json_schema!({ "type": "string", "minLength": 1 })
        }
    }

    impl JsonSchema for McpIntegerExpression {
        fn schema_name() -> Cow<'static, str> {
            "McpIntegerExpression".into()
        }

        fn inline_schema() -> bool {
            true
        }

        fn json_schema(_: &mut SchemaGenerator) -> Schema {
            json_schema!({ "type": ["integer", "string"], "minimum": 0 })
        }
    }

    /// A tool whose input schema and argument parsing come from its arguments type. Doc comments on
    /// the arguments type's fields become parameter descriptions, and `Option` fields and
    /// `#[serde(default)]` make parameters optional, with a null argument treated as absent.
    /// Undeclared arguments produce an `invalid_params` result, unless the arguments type accepts
    /// additional properties.
    ///
    /// The input schema must be an object, so `Args` is a struct with named fields, or with none for
    /// a tool that takes no arguments. A unit struct or `()` describes `null` and is rejected.
    pub trait TypedMcpTool: 'static + Send + Sync {
        type Args: serde::de::DeserializeOwned + JsonSchema;

        fn info(&self) -> McpToolInfo;

        /// Called on an arbitrary thread with arguments that already match `Args`. A panic is
        /// handled as it is for [`McpTool::invoke`].
        fn invoke(
            &self,
            call: &McpToolCall,
            args: Self::Args,
        ) -> Result<McpToolResult, McpToolError>;
    }

    struct Parameters {
        // The only argument names `invoke` accepts, or `None` when it accepts any name.
        accepted: Option<Vec<String>>,
        // The parameters whose null arguments are treated as absent.
        optional: Vec<String>,
    }

    pub(in crate::mcp) struct TypedAdapter<T> {
        tool: T,
        parameters: OnceLock<Parameters>,
    }

    impl<T: TypedMcpTool> TypedAdapter<T> {
        pub(in crate::mcp) fn new(tool: T) -> Self {
            Self {
                tool,
                parameters: OnceLock::new(),
            }
        }

        fn input_schema() -> Value {
            let settings = schemars::generate::SchemaSettings::draft2020_12().with(|settings| {
                settings.inline_subschemas = true;
            });
            let mut schema = settings
                .into_generator()
                .into_root_schema_for::<T::Args>()
                .to_value();
            if let Some(object) = schema.as_object_mut() {
                object.remove("$schema");
                object.remove("title");
                if object.get("type") == Some(&Value::String("object".into()))
                    && !object.contains_key("additionalProperties")
                {
                    object.insert("additionalProperties".into(), Value::Bool(false));
                }
            }
            schema
        }

        fn parameters(schema: &Value) -> Parameters {
            let no_properties = serde_json::Map::new();
            let properties = schema
                .get("properties")
                .and_then(Value::as_object)
                .unwrap_or(&no_properties);
            let required = schema.get("required").and_then(Value::as_array);
            let is_required = |name: &String| {
                required.is_some_and(|required| required.iter().any(|entry| entry == name))
            };
            let accepted = (schema.get("additionalProperties") == Some(&Value::Bool(false)))
                .then(|| properties.keys().cloned().collect());
            let optional = properties
                .keys()
                .filter(|name| !is_required(name))
                .cloned()
                .collect();
            Parameters { accepted, optional }
        }
    }

    /// Deserializes the arguments object as `Args`, naming the parameter in each error.
    struct Arguments<'de>(&'de serde_json::Map<String, Value>);

    impl<'de> serde::Deserializer<'de> for Arguments<'de> {
        type Error = serde_json::Error;

        fn deserialize_any<V: serde::de::Visitor<'de>>(
            self,
            visitor: V,
        ) -> Result<V::Value, Self::Error> {
            visitor.visit_map(ArgumentsMap {
                entries: self.0.iter(),
                value: None,
            })
        }

        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf
            option unit unit_struct newtype_struct seq tuple tuple_struct map struct enum identifier
            ignored_any
        }
    }

    struct ArgumentsMap<'de> {
        entries: serde_json::map::Iter<'de>,
        value: Option<(&'de String, &'de Value)>,
    }

    impl<'de> serde::de::MapAccess<'de> for ArgumentsMap<'de> {
        type Error = serde_json::Error;

        fn next_key_seed<K: serde::de::DeserializeSeed<'de>>(
            &mut self,
            seed: K,
        ) -> Result<Option<K::Value>, Self::Error> {
            use serde::de::IntoDeserializer;

            let Some((name, value)) = self.entries.next() else {
                return Ok(None);
            };
            self.value = Some((name, value));
            seed.deserialize(name.as_str().into_deserializer())
                .map(Some)
        }

        fn next_value_seed<S: serde::de::DeserializeSeed<'de>>(
            &mut self,
            seed: S,
        ) -> Result<S::Value, Self::Error> {
            let (name, value) = self
                .value
                .take()
                .expect("next_value_seed called before next_key_seed");
            seed.deserialize(value).map_err(|error| {
                serde::de::Error::custom(format!("Invalid parameter '{name}': {error}"))
            })
        }
    }

    impl<T: TypedMcpTool> McpTool for TypedAdapter<T> {
        fn definition(&self) -> McpToolDefinition {
            self.tool.info().with_input_schema(Self::input_schema())
        }

        fn invoke(
            &self,
            call: &McpToolCall,
            mut arguments: Value,
        ) -> Result<McpToolResult, McpToolError> {
            let parameters = self
                .parameters
                .get_or_init(|| Self::parameters(&Self::input_schema()));
            let Some(arguments) = arguments.as_object_mut() else {
                return Err(McpToolError::invalid_params("Expected object arguments"));
            };
            if let Some(accepted) = &parameters.accepted {
                if let Some(name) = arguments.keys().find(|name| !accepted.contains(name)) {
                    return Err(McpToolError::invalid_params(format!(
                        "Unexpected parameter '{name}'"
                    )));
                }
            }
            arguments.retain(|name, value| !value.is_null() || !parameters.optional.contains(name));
            let args = T::Args::deserialize(Arguments(arguments))?;
            self.tool.invoke(call, args)
        }
    }

    /// Registers a [`TypedMcpTool`] for the life of the process. See [`register_mcp_tool`].
    pub fn register_typed_mcp_tool<T: TypedMcpTool>(tool: T) -> Option<Ref<CoreMcpTool>> {
        register_mcp_tool(TypedAdapter::new(tool))
    }
}

#[cfg(feature = "schemars")]
pub use typed::{register_typed_mcp_tool, TypedMcpTool};

/// A JSON Schema object for a tool that takes no arguments.
pub fn empty_input_schema() -> Value {
    json!({ "type": "object", "additionalProperties": false })
}
