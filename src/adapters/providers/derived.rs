//! What the rustcrypto provider keeps with a key version, in the version's
//! `ProviderState`: public values it derived (a decoded public key) and an
//! expanded signing key in sealed pages. Deriving them per call was most of
//! a signature's or verification's cost (docs/performance.md F1). Keys read
//! outside an operation (and in provider tests) come without a state, and
//! every call derives afresh.

use std::any::Any;

use super::public_cache::{Cached, PublicCache};
use super::secret_cache::{Secret, SecretCache};
use crate::domain::core::Error;
use crate::domain::provider::StoredKey;

#[derive(Default, Debug)]
pub(super) struct Derived {
    public: PublicCache,
    secret: SecretCache,
}

impl Derived {
    fn of<'a>(key: StoredKey<'a>) -> Result<Option<&'a Derived>, Error> {
        key.provider_state().map(|s| s.get_or_default::<Derived>()).transpose()
    }
}

/// A public value derived from `key`, made once per version if its `bytes`
/// fit the cache budget (`PublicCache`), else per call. `make` must derive it
/// from this key alone, and it must be public: the cache is ordinary memory.
pub(super) fn public_value<'a, T: Any + Send + Sync>(
    key: StoredKey<'a>,
    bytes: usize,
    make: impl FnOnce() -> Result<T, Error>,
) -> Result<Cached<'a, T>, Error> {
    match Derived::of(key)? {
        Some(d) => d.public.get_or_try_init(bytes, make),
        None => make().map(Cached::Fresh),
    }
}

/// A secret derived from `key`: `part` of what `make` builds, sealed once
/// per version if sealed pages can be had (`SecretCache`), else built per
/// call. `make` must derive it from this key alone.
///
/// # Safety
/// `T` keeps all its state inline (`secret::Sealed::copy_of`).
pub(super) unsafe fn secret_value<'a, S, T: Send + Sync + 'static>(
    key: StoredKey<'a>,
    make: impl Fn() -> Result<S, Error>,
    part: fn(&S) -> &T,
) -> Result<Secret<'a, S, T>, Error> {
    match Derived::of(key)? {
        // SAFETY: forwarded from this function's contract.
        Some(d) => unsafe { d.secret.get_or_try_init(make, part) },
        None => Ok(Secret::Owned { owner: make()?, part }),
    }
}

/// Whether `key`'s version holds its sealed secret. Once it does, it holds it
/// for the version's life, and an operation needs none of the stack the
/// derivation takes (`stack_budget`, docs/performance.md F12).
pub(super) fn secret_sealed(key: StoredKey<'_>) -> bool {
    matches!(Derived::of(key), Ok(Some(d)) if d.secret.is_filled())
}

/// Whether a version's public value and sealed secret are cached (tests).
#[cfg(test)]
pub(super) fn filled(state: &crate::domain::core::ProviderState) -> (bool, bool) {
    let d = state.get_or_default::<Derived>().unwrap();
    (d.public.is_filled(), d.secret.is_filled())
}
