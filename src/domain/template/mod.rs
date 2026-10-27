//! Algorithm catalogue: templates and the registry that selects one by intent.

mod catalog;
mod registry;
// template::template mirrors citius-core's package layout.
#[allow(clippy::module_inception)]
mod template;

pub use catalog::*;
pub use registry::*;
pub use template::*;
#[cfg(test)]
pub(crate) use template::testing;
