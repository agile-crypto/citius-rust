//! Application layer: orchestrators that coordinate several domains to carry
//! out one use case. Depends on domain interfaces only; never on `bindings`
//! or `ffi`.

mod key_orchestrator;

pub use key_orchestrator::*;
