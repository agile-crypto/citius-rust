//! What a provider derives once from a key version and keeps for its life:
//! a decoded public key, for example. Deriving it per call is what made
//! signing cost a scalar multiplication more than the signature itself, and
//! ML-DSA verification re-expand its public matrix (docs/performance.md F1).
//!
//! It holds public values only. A secret derived from the material (an
//! expanded signing key) would sit in ordinary memory for the life of the
//! version, outside the locked pages the material lives in; such a cache
//! needs its own design (docs/improvement-plan.md, phase 7).
//!
//! The cache lives in the version's `ProviderState` (derived.rs), never with
//! the material: a transform that retains the material reuses its bytes
//! under another template, and that version starts with an empty cache. It
//! is shared by every clone of the version (and so of the key) and dropped
//! with the last one.
//!
//! All caches together hold at most `BUDGET` bytes, so memory stays bounded
//! however many keys a process uses. There is no eviction (it would put
//! bookkeeping and re-decode jitter on the hot path): past the budget, a
//! value is made per call, as without a cache.

use std::any::Any;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::domain::core::{Code, Error};

/// The bytes all public caches may hold, process-wide: about 900 ML-DSA-87
/// verifying keys, or every Ed25519 and ECDSA key a process will have.
pub const BUDGET: usize = 64 << 20;

/// A byte budget shared by caches.
pub struct Budget {
    cap: usize,
    used: AtomicUsize,
}

impl Budget {
    pub const fn new(cap: usize) -> Self {
        Budget { cap, used: AtomicUsize::new(0) }
    }

    /// The bytes cached values hold now.
    #[cfg_attr(not(test), allow(dead_code, reason = "for tests and diagnostics"))]
    pub fn used(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }

    fn reserve(&'static self, bytes: usize) -> Option<Reservation> {
        self.used
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |u| {
                u.checked_add(bytes).filter(|&total| total <= self.cap)
            })
            .ok()
            .map(|_| Reservation { budget: self, bytes })
    }
}

static PROCESS: Budget = Budget::new(BUDGET);

/// Bytes taken from a budget, given back when dropped.
struct Reservation {
    budget: &'static Budget,
    bytes: usize,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

struct Entry {
    value: Box<dyn Any + Send + Sync>,
    _bytes: Reservation,
}

#[derive(Default)]
pub(super) struct PublicCache(OnceLock<Entry>);

/// A value from a version's cache, or made for this call alone.
pub enum Cached<'a, T> {
    Shared(&'a T),
    Fresh(T),
}

impl<T> std::ops::Deref for Cached<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        match self {
            Cached::Shared(v) => v,
            Cached::Fresh(v) => v,
        }
    }
}

impl PublicCache {
    /// The cached value, made by `make` on first use and kept if its `bytes`
    /// fit the process budget; otherwise made for this call. Two threads may
    /// both make it the first time; one result is kept, and both are the
    /// same value, since `make` derives it from the version alone.
    pub fn get_or_try_init<T: Any + Send + Sync>(
        &self,
        bytes: usize,
        make: impl FnOnce() -> Result<T, Error>,
    ) -> Result<Cached<'_, T>, Error> {
        self.get_or_try_init_within(&PROCESS, bytes, make)
    }

    fn get_or_try_init_within<T: Any + Send + Sync>(
        &self,
        budget: &'static Budget,
        bytes: usize,
        make: impl FnOnce() -> Result<T, Error>,
    ) -> Result<Cached<'_, T>, Error> {
        if self.0.get().is_none() {
            let value = make()?;
            let Some(reservation) = budget.reserve(bytes) else {
                return Ok(Cached::Fresh(value));
            };
            // Lost a race: the other entry is kept, this one gives its bytes back.
            let _ = self.0.set(Entry { value: Box::new(value), _bytes: reservation });
        }
        // A version is served by one provider and one template, so it only
        // ever caches one type; another type here is a bug.
        let entry = self.0.get().expect("set above");
        entry
            .value
            .downcast_ref()
            .map(Cached::Shared)
            .ok_or_else(|| Error::new(Code::Internal, "PublicCache", "the version's cached value has another type"))
    }

    /// Whether a value is cached.
    pub fn is_filled(&self) -> bool {
        self.0.get().is_some()
    }
}

impl std::fmt::Debug for PublicCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicCache").field("filled", &self.is_filled()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared<T>(c: Cached<'_, T>) -> bool {
        matches!(c, Cached::Shared(_))
    }

    #[test]
    fn a_value_is_made_once() {
        static B: Budget = Budget::new(100);
        let cache = PublicCache::default();
        let mut made = 0;
        for _ in 0..3 {
            let v = cache
                .get_or_try_init_within(&B, 8, || {
                    made += 1;
                    Ok(7u32)
                })
                .unwrap();
            assert!(shared(v));
        }
        assert_eq!((made, B.used()), (1, 8));
        drop(cache);
        assert_eq!(B.used(), 0, "dropping the version gives the bytes back");
    }

    #[test]
    fn past_the_budget_values_are_made_per_call() {
        static B: Budget = Budget::new(10);
        let (a, b) = (PublicCache::default(), PublicCache::default());
        assert!(shared(a.get_or_try_init_within(&B, 8, || Ok(1u32)).unwrap()));
        let v = b.get_or_try_init_within(&B, 8, || Ok(2u32)).unwrap();
        assert!(matches!(v, Cached::Fresh(2)) && !b.is_filled());
        assert_eq!(B.used(), 8);
        drop(a);
        assert!(shared(b.get_or_try_init_within(&B, 8, || Ok(2u32)).unwrap()), "room again");
    }

    #[test]
    fn a_failure_caches_nothing() {
        static B: Budget = Budget::new(100);
        let cache = PublicCache::default();
        let err = cache
            .get_or_try_init_within::<u32>(&B, 8, || Err(Error::new(Code::InvalidKeyMaterial, "t", "bad")))
            .err()
            .unwrap();
        assert_eq!((err.code(), B.used(), cache.is_filled()), (Code::InvalidKeyMaterial, 0, false));
        assert_eq!(*cache.get_or_try_init_within(&B, 8, || Ok(8u32)).unwrap(), 8);
    }

    #[test]
    fn another_type_is_an_internal_error() {
        static B: Budget = Budget::new(100);
        let cache = PublicCache::default();
        cache.get_or_try_init_within(&B, 1, || Ok(1u32)).unwrap();
        let err = cache.get_or_try_init_within(&B, 1, || Ok(1u64)).err().unwrap();
        assert_eq!(err.code(), Code::Internal);
    }

    #[test]
    fn racing_threads_keep_one_value_and_account_for_it_once() {
        static B: Budget = Budget::new(1000);
        let cache = PublicCache::default();
        std::thread::scope(|s| {
            for i in 0..8u32 {
                let cache = &cache;
                s.spawn(move || cache.get_or_try_init_within(&B, 10, || Ok(i)).map(|_| ()).unwrap());
            }
        });
        assert_eq!(B.used(), 10);
    }
}
