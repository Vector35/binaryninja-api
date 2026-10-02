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

//! Offering MCP tools from an MCP server.

use binaryninjacore_sys::*;
use serde_json::Value;
use std::borrow::Cow;
use std::ffi::{c_char, c_void, CStr};
use std::panic::{self, AssertUnwindSafe};
use std::ptr;

use super::tool::{create_with, CoreMcpTool, McpTool};
use crate::binary_view::BinaryView;
use crate::rc::*;
use crate::string::{BnString, IntoCStr};

/// Creates a tool without registering it. This can be used to expose a tool that is specific to one
/// MCP server, such as one that manages that server's active binary view. Otherwise the same as
/// [`register_mcp_tool`](super::tool::register_mcp_tool).
pub fn create_mcp_tool<T: McpTool>(tool: T) -> Option<Ref<CoreMcpTool>> {
    create_with(tool, BNCreateMcpTool)
}

/// Creates a [`TypedMcpTool`](super::tool::TypedMcpTool) without registering it. See
/// [`create_mcp_tool`].
#[cfg(feature = "schemars")]
pub fn create_typed_mcp_tool<T: super::tool::TypedMcpTool>(tool: T) -> Option<Ref<CoreMcpTool>> {
    create_mcp_tool(super::tool::typed::TypedAdapter::new(tool))
}

/// The request state an MCP server supplies for one invocation of a tool.
pub trait McpToolCallHost: Sync {
    fn binary_view(&self) -> Option<Ref<BinaryView>>;

    fn is_cancelled(&self) -> bool {
        false
    }

    fn report_progress(&self, _progress: f64, _total: f64, _message: &str) {}
}

/// Runs the tool for an MCP server and returns the MCP `CallToolResult`.
pub fn invoke_mcp_tool<H: McpToolCallHost>(
    tool: &CoreMcpTool,
    host: &H,
    arguments: &Value,
) -> Value {
    extern "C" fn cb_get_binary_view<H: McpToolCallHost>(ctxt: *mut c_void) -> *mut BNBinaryView {
        let host = unsafe { &*(ctxt as *const H) };
        match panic::catch_unwind(AssertUnwindSafe(|| host.binary_view())) {
            Ok(Some(view)) => unsafe { BNNewViewReference(view.handle) },
            Ok(None) => ptr::null_mut(),
            Err(_) => {
                tracing::error!("MCP host panicked supplying a binary view");
                ptr::null_mut()
            }
        }
    }

    extern "C" fn cb_is_cancelled<H: McpToolCallHost>(ctxt: *mut c_void) -> bool {
        let host = unsafe { &*(ctxt as *const H) };
        panic::catch_unwind(AssertUnwindSafe(|| host.is_cancelled())).unwrap_or_else(|_| {
            tracing::error!("MCP host panicked reporting cancellation");
            false
        })
    }

    extern "C" fn cb_report_progress<H: McpToolCallHost>(
        ctxt: *mut c_void,
        progress: f64,
        total: f64,
        message: *const c_char,
    ) {
        let host = unsafe { &*(ctxt as *const H) };
        let message = if message.is_null() {
            Cow::Borrowed("")
        } else {
            unsafe { CStr::from_ptr(message) }.to_string_lossy()
        };
        if panic::catch_unwind(AssertUnwindSafe(|| {
            host.report_progress(progress, total, &message)
        }))
        .is_err()
        {
            tracing::error!("MCP host panicked receiving progress");
        }
    }

    let callbacks = BNMcpToolCallCallbacks {
        context: host as *const H as *mut c_void,
        getBinaryView: Some(cb_get_binary_view::<H>),
        isCancelled: Some(cb_is_cancelled::<H>),
        reportProgress: Some(cb_report_progress::<H>),
    };
    let arguments = arguments.to_string().to_cstr();
    unsafe {
        let call = BNCreateMcpToolCall(&callbacks);
        let result = BNCreateMcpToolResult();
        BNInvokeMcpTool(tool.handle, call, arguments.as_ptr(), result);
        let json = BnString::into_string(BNGetMcpToolResultJson(result));
        BNFreeMcpToolResult(result);
        BNFreeMcpToolCall(call);
        serde_json::from_str(&json).unwrap_or(Value::Null)
    }
}
