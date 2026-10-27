//! Who does the cryptography: the provider contract, key material as
//! providers produce it, and the registry that matches a provider to a key.

mod backend;
mod material;
mod registry;
#[cfg(test)]
pub(crate) mod testing;

pub use backend::*;
pub use material::*;
pub use registry::*;
