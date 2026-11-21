//! The domains of citius-core, one module each. A domain imports `core` and
//! nothing else: not another domain, not `bindings`, `ffi`, `app` or
//! `adapters` (enforced by tests/architecture.rs). Where two domains must
//! meet, the application layer (`crate::app`) coordinates them.

pub mod core;
pub mod key;
pub mod policy;
pub mod provider;
pub mod template;
