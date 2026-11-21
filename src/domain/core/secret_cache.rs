//! A secret a provider derives once from a key version and keeps for its
//! life: an expanded ML-DSA signing key, whose expansion from the stored seed
//! is most of a signature's work (docs/performance.md F1).
//!
//! The value lives in sealed pages (`secret::Sealed`): locked in RAM, out of
//! core dumps and forked children, wiped when the version is dropped. It is
//! never kept in swappable memory: a value that cannot be sealed (the sealed
//! budget is used up, the pages cannot be locked) is made per call, as
//! without a cache. That is decided once per version, at its first use, so
//! a version that cannot be cached costs no failing system calls later.
//!
//! Like `PublicCache`, it belongs to the version, never to the material, and
//! is shared by the version's clones.

use std::any::Any;
use std::sync::OnceLock;

use super::{Cached, Code, Error};
use crate::secret::Sealed;

#[derive(Default)]
pub struct SecretCache(OnceLock<Option<Box<dyn Any + Send + Sync>>>);

impl SecretCache {
    /// The cached value, made by `make` and sealed on first use; made per
    /// call when the version's value could not be sealed. `make` may run
    /// again in the call that lost a race to fill the cache.
    ///
    /// # Safety
    /// `T` keeps all its state inline (`Sealed::new`).
    pub unsafe fn get_or_try_init<T: Send + Sync + 'static>(
        &self,
        make: impl Fn() -> Result<T, Error>,
    ) -> Result<Cached<'_, T>, Error> {
        let slot = match self.0.get() {
            Some(slot) => slot,
            None => {
                let value = make()?;
                // SAFETY: forwarded from this function's contract.
                match unsafe { Sealed::new(value) } {
                    // Lost a race: the other result is kept, this one is wiped.
                    Ok(sealed) => drop(self.0.set(Some(Box::new(sealed)))),
                    Err(value) => {
                        let _ = self.0.set(None);
                        return Ok(Cached::Fresh(value));
                    }
                }
                self.0.get().expect("set above")
            }
        };
        match slot {
            Some(sealed) => sealed.downcast_ref::<Sealed<T>>().map(|s| Cached::Shared(&**s)).ok_or_else(|| {
                Error::new(Code::Internal, "SecretCache", "the version's cached value has another type")
            }),
            None => make().map(Cached::Fresh),
        }
    }

    /// Whether a sealed value is cached.
    pub fn is_filled(&self) -> bool {
        matches!(self.0.get(), Some(Some(_)))
    }
}

impl std::fmt::Debug for SecretCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret.
        f.debug_struct("SecretCache").field("sealed", &self.is_filled()).finish()
    }
}

/// What a key version keeps of what its provider derived from it.
#[derive(Default, Debug)]
pub struct VersionCache {
    pub public: super::PublicCache,
    pub secret: SecretCache,
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Inline([u8; 16]);

    #[test]
    fn a_secret_is_made_once_and_sealed() {
        let cache = SecretCache::default();
        let made = std::cell::Cell::new(0);
        for _ in 0..3 {
            // SAFETY: Inline is a plain array.
            let v = unsafe {
                cache.get_or_try_init(|| {
                    made.set(made.get() + 1);
                    Ok(Inline([9; 16]))
                })
            }
            .unwrap();
            assert!(matches!(v, Cached::Shared(Inline([9, ..]))));
        }
        assert_eq!(made.get(), 1);
        assert_eq!(format!("{cache:?}"), "SecretCache { sealed: true }");
    }

    #[test]
    fn a_failure_caches_nothing() {
        let cache = SecretCache::default();
        // SAFETY: Inline is a plain array.
        let r = unsafe { cache.get_or_try_init::<Inline>(|| Err(Error::new(Code::InvalidKeyMaterial, "t", "bad"))) };
        assert_eq!(r.err().unwrap().code(), Code::InvalidKeyMaterial);
        assert!(!cache.is_filled());
        // SAFETY: as above.
        assert!(unsafe { cache.get_or_try_init(|| Ok(Inline([1; 16]))) }.is_ok());
        assert!(cache.is_filled());
    }
}
