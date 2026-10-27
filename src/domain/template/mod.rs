//! Algorithm catalogue: templates and the registry that selects one by intent.

mod catalog;
mod material;
mod registry;
// template::template mirrors citius-core's package layout.
#[allow(clippy::module_inception)]
mod template;

pub use catalog::*;
pub use material::*;
pub use registry::*;
pub use template::*;
#[cfg(test)]
pub(crate) use template::testing;
