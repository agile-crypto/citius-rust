//! Shared vocabulary. Every domain imports this module; it imports no domain.

mod error;
mod id;
mod scope;
mod spec;

pub use error::*;
pub use id::*;
pub use scope::*;
pub use spec::*;
