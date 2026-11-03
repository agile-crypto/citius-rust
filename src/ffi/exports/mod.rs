//! The `extern "C"` functions, one module per header. Only the exported
//! functions are public here: build.rs checks `crate::ffi::exports::NAME`
//! against the header, so nothing else may be reachable under that path.

mod core;
mod crypto;
mod key;
mod key_migrate;
mod metadata;
mod policy;
mod sign;
mod stubs;
mod types;

pub use self::core::*;
pub use self::crypto::*;
pub use self::key::*;
pub use self::key_migrate::*;
pub use self::metadata::*;
pub use self::policy::*;
pub use self::sign::*;
pub use self::stubs::*;
pub use self::types::*;

#[cfg(test)]
mod tests;
