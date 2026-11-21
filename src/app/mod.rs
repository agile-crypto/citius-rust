//! Application layer: services that coordinate several domains to carry out
//! one use case. Depends on domain interfaces only; never on `bindings` or
//! `ffi`.

mod crypto_orchestrator;
mod crypto_signing;
mod discovery;
mod key_metadata;
mod key_migration;
mod key_orchestrator;
mod policy_admin;
mod startup;

pub use crypto_orchestrator::*;
pub use crypto_signing::*;
pub use discovery::*;
pub use key_metadata::*;
pub use key_migration::*;
pub use key_orchestrator::*;
pub use policy_admin::*;
pub use startup::*;

// The domain types the application services take and return beyond the
// shared kernel (`domain::core`): ffi names them through here, never the
// domains themselves (tests/architecture.rs).
pub use crate::domain::policy::Policy;
pub use crate::domain::provider::{EncryptParams, Encoding, SignContext};
