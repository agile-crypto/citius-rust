//! Shared vocabulary. Every domain imports this module; it imports no domain.

mod error;
mod id;
mod operation;
mod provider_requirements;
mod scope;
mod spec;

pub use error::*;
pub use id::*;
pub use operation::*;
pub use provider_requirements::*;
pub use scope::*;
pub use spec::*;
