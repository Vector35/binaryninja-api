//! Interface for registering new websocket providers
//!
//! WARNING: Do _not_ use this for anything other than provider registration. If you need to open a
//! websocket connection use a real websocket library.

mod client;
mod provider;

pub use client::*;
pub use provider::*;
