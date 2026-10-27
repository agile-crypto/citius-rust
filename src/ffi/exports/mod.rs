//! The `extern "C"` functions, one module per header. Only the exported
//! functions are public here: build.rs checks `crate::ffi::exports::NAME`
//! against the header, so nothing else may be reachable under that path.

mod core;
mod key;
mod key_migrate;
mod policy;
mod types;

pub use self::core::*;
pub use self::key::*;
pub use self::key_migrate::*;
pub use self::policy::*;
pub use self::types::*;

#[cfg(test)]
mod tests;
