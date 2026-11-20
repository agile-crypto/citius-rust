//! What a provider derives once from a key version and keeps for its life:
//! a decoded public key, for example. Deriving it per call is what made
//! signing cost a scalar multiplication more than the signature itself
//! (docs/performance.md F1).
//!
//! It holds public values only. A secret derived from the material (an
//! expanded signing key) would sit in ordinary memory for the life of the
//! version, outside the locked pages the material lives in; such a cache
//! needs its own design (docs/improvement-plan.md, phase 7).
//!
//! The cache belongs to the version, never to the material: a transform
//! that retains the material reuses its bytes under another template, and
//! that version starts with an empty cache. It is shared by every clone of
//! the version (and so of the key) and dropped with the last one.

use std::any::Any;
use std::sync::OnceLock;

use super::{Code, Error};

#[derive(Default)]
pub struct PublicCache(OnceLock<Box<dyn Any + Send + Sync>>);

impl PublicCache {
    /// The cached value, made by `make` on first use. Two threads may both
    /// make it the first time; one result is kept, and both are the same
    /// value, since `make` derives it from the version alone.
    pub fn get_or_try_init<T: Any + Send + Sync>(&self, make: impl FnOnce() -> Result<T, Error>) -> Result<&T, Error> {
        if self.0.get().is_none() {
            let _ = self.0.set(Box::new(make()?));
        }
        // A version is served by one provider and one template, so it only
        // ever caches one type; another type here is a bug.
        self.0
            .get()
            .and_then(|v| v.downcast_ref())
            .ok_or_else(|| Error::new(Code::Internal, "PublicCache", "the version's cached value has another type"))
    }
}

impl std::fmt::Debug for PublicCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicCache").field("filled", &self.0.get().is_some()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_is_made_once() {
        let cache = PublicCache::default();
        let mut made = 0;
        for _ in 0..3 {
            let v: &u32 = cache
                .get_or_try_init(|| {
                    made += 1;
                    Ok(7)
                })
                .unwrap();
            assert_eq!(*v, 7);
        }
        assert_eq!(made, 1);
    }

    #[test]
    fn a_failure_caches_nothing() {
        let cache = PublicCache::default();
        let err = cache.get_or_try_init::<u32>(|| Err(Error::new(Code::InvalidKeyMaterial, "t", "bad"))).unwrap_err();
        assert_eq!(err.code(), Code::InvalidKeyMaterial);
        assert_eq!(*cache.get_or_try_init(|| Ok(8u32)).unwrap(), 8);
    }

    #[test]
    fn another_type_is_an_internal_error() {
        let cache = PublicCache::default();
        cache.get_or_try_init(|| Ok(1u32)).unwrap();
        assert_eq!(cache.get_or_try_init(|| Ok(1u64)).unwrap_err().code(), Code::Internal);
    }
}
