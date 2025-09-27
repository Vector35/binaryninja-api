//! Interface for registering new download providers
//!
//! WARNING: Do _not_ use this for anything other than provider registration. If you need to perform
//! http requests, use a real requests library.

mod instance;
mod provider;

pub use instance::*;
pub use provider::*;
