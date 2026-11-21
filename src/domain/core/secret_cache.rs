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

use super::{Code, Error};
use crate::secret::Sealed;

#[derive(Default)]
pub struct SecretCache(OnceLock<Option<Box<dyn Any + Send + Sync>>>);

/// A secret from a version's cache, or, where it could not be sealed, the
/// owner it was made in for this call (`part` reads it from there).
pub enum Secret<'a, S, T> {
    Sealed(&'a T),
    Owned { owner: S, part: fn(&S) -> &T },
}

impl<S, T> std::ops::Deref for Secret<'_, S, T> {
    type Target = T;
    fn deref(&self) -> &T {
        match self {
            Secret::Sealed(t) => t,
            Secret::Owned { owner, part } => part(owner),
        }
    }
}

impl SecretCache {
    /// The cached secret, sealed on first use by copying `part` of what
    /// `make` builds (so a large secret is never copied onto the stack);
    /// built per call when the version's secret could not be sealed. `make`
    /// may run twice in the call that loses a race to fill the cache.
    ///
    /// Whether a version's secret is sealed is decided once, at its first
    /// use: a version that could not be sealed then (no budget, a failed
    /// lock, even a passing one) is built per call for the rest of its life.
    ///
    /// # Safety
    /// `T` keeps all its state inline (`Sealed::copy_of`).
    pub unsafe fn get_or_try_init<S, T: Send + Sync + 'static>(
        &self,
        make: impl Fn() -> Result<S, Error>,
        part: fn(&S) -> &T,
    ) -> Result<Secret<'_, S, T>, Error> {
        let slot = match self.0.get() {
            Some(slot) => slot,
            None => {
                let owner = make()?;
                // SAFETY: forwarded from this function's contract.
                match unsafe { Sealed::copy_of(part(&owner)) } {
                    // Lost a race: the other result is kept, this one is wiped.
                    Some(sealed) => drop(self.0.set(Some(Box::new(sealed)))),
                    None => {
                        let _ = self.0.set(None);
                        return Ok(Secret::Owned { owner, part });
                    }
                }
                self.0.get().expect("set above")
            }
        };
        match slot {
            Some(sealed) => sealed.downcast_ref::<Sealed<T>>().map(|s| Secret::Sealed(&**s)).ok_or_else(|| {
                Error::new(Code::Internal, "SecretCache", "the version's cached value has another type")
            }),
            None => Ok(Secret::Owned { owner: make()?, part }),
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
                cache.get_or_try_init(
                    || {
                        made.set(made.get() + 1);
                        Ok(Box::new(Inline([9; 16])))
                    },
                    |b| &**b,
                )
            }
            .unwrap();
            assert!(matches!(v, Secret::Sealed(Inline([9, ..]))));
        }
        assert_eq!(made.get(), 1);
        assert_eq!(format!("{cache:?}"), "SecretCache { sealed: true }");
    }

    #[test]
    fn a_failure_caches_nothing() {
        let cache = SecretCache::default();
        let fail = || Err::<Box<Inline>, _>(Error::new(Code::InvalidKeyMaterial, "t", "bad"));
        // SAFETY: Inline is a plain array.
        let r = unsafe { cache.get_or_try_init(fail, |b| &**b) };
        assert_eq!(r.err().unwrap().code(), Code::InvalidKeyMaterial);
        assert!(!cache.is_filled());
        // SAFETY: as above.
        assert!(unsafe { cache.get_or_try_init(|| Ok(Box::new(Inline([1; 16]))), |b| &**b) }.is_ok());
        assert!(cache.is_filled());
    }
}
