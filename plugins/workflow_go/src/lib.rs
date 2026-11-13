#![warn(clippy::all)]
#![warn(missing_docs)]

//! Binary Ninja workflow plugin for analyzing Go binaries.
//!
//! Given golang binaries use some wild calling conventions, and have some interesting
//! data structures (pcIntTab) we may parse, we can add details to the default analysis of
//! binja to improve precision, and readability.
//!
//! # Workflows
//!
//! A module workflow detects whether the binary is Go, and records the result
//! (Go-ness, pclntab presence, version) as view metadata that the per-function
//! activities gate on.
//!
//! Then, two function workflows then run only on Go binaries:
//! - *Calling convention*: applies the Go ABI to each function -- the register-based
//!   `go-abiinternal`, or the stack-based `go-stack` for `.abi0` functions.
//! - *String narrowing*: where a call passes a (const pointer, length) pair, the
//!   pointed-to data is redefined as `char[len]` so literals have the correct length.

/// Export the analyses
pub mod activities;
/// Export the internals of golang
pub mod go;
/// Export the module that registers the workflows
pub mod workflow;

use crate::workflow::register_activities;
use binaryninja::add_optional_plugin_dependency;
use go::cc::GoCallingConventions;

/// Entrypoint of our plugin
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "C" fn CorePluginInit() -> bool {
    binaryninja::tracing_init!("Plugin.Golang");

    if GoCallingConventions::for_x86().is_none() {
        tracing::warn!("go: x86_64 calling conventions not registered");
        return false;
    }

    if GoCallingConventions::for_arm64().is_none() {
        tracing::warn!("go: aarch64 calling conventions not registered");
        return false;
    }

    if register_activities().is_err() {
        tracing::warn!("go: workflow registration failed");
        return false;
    }

    true
}

/// We mark the main architectures that have a calling convention defined as dependencies
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginDependencies() {
    add_optional_plugin_dependency("arch_x86");
    add_optional_plugin_dependency("arch_armv7");
    add_optional_plugin_dependency("arch_arm64");
}
