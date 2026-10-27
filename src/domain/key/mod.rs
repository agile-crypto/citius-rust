//! Key lifecycle: the Key aggregate and the repository it is persisted through.

// key::key mirrors citius-core's package layout; the types are re-exported below.
#[allow(clippy::module_inception)]
mod key;
mod repository;

pub use key::*;
pub use repository::*;
#[cfg(test)]
pub(crate) use key::testing;
