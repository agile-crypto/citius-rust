//! What a provider keeps with a key version: state it derived from the
//! version (a decoded key, say) and wants for the version's life. Opaque to
//! the domain: the provider that serves the version owns it, decides what it
//! holds and how much, and interprets it; the domain only keeps it with the
//! version and drops it with the last clone.
//!
//! Keeping it with the version, rather than in a map inside the provider,
//! is what makes it free per call: an operation already holds its version,
//! and a provider-side map would be shared state every call looks up.

use std::any::Any;
use std::sync::OnceLock;

use super::{Code, Error};

#[derive(Default)]
pub struct ProviderState(OnceLock<Box<dyn Any + Send + Sync>>);

impl ProviderState {
    /// The provider's state, made with `T::default()` on first use. A
    /// version is served by one provider, so it holds one type; another one
    /// here is a bug, reported as `Internal`.
    pub fn get_or_default<T: Any + Send + Sync + Default>(&self) -> Result<&T, Error> {
        self.0
            .get_or_init(|| Box::new(T::default()))
            .downcast_ref()
            .ok_or_else(|| Error::new(Code::Internal, "ProviderState", "the version holds another provider's state"))
    }

    /// Whether the provider has attached state.
    pub fn is_attached(&self) -> bool {
        self.0.get().is_some()
    }
}

impl std::fmt::Debug for ProviderState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderState").field("attached", &self.is_attached()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_is_made_once_and_typed() {
        let s = ProviderState::default();
        assert!(!s.is_attached());
        *s.get_or_default::<std::sync::Mutex<u32>>().unwrap().lock().unwrap() = 7;
        assert_eq!(*s.get_or_default::<std::sync::Mutex<u32>>().unwrap().lock().unwrap(), 7);
        assert_eq!(s.get_or_default::<String>().unwrap_err().code(), Code::Internal);
    }
}
