pub mod registry;
// template::template mirrors citius-core's package layout; see registry.rs for its use.
#[allow(clippy::module_inception)]
pub mod template;
pub use registry::*;
