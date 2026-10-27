//! Algorithm catalogue: templates and the registry that selects one by intent.

mod registry;
// template::template mirrors citius-core's package layout.
#[allow(clippy::module_inception)]
mod template;

pub use registry::*;
pub use template::*;
