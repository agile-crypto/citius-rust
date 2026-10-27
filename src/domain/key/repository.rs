use crate::domain::core::Error;
use crate::domain::key::{Key, KeyId};

/// Persists the Key aggregate, versions included. Implementations are
/// shared by every thread of a context: they take `&self` and synchronise
/// internally. Lookups return owned keys (a reference could not outlive the
/// lock); a miss is `Ok(None)`, `Err` means the store itself failed.
///
/// Writes are optimistic: `update` stores a key only if it is still at the
/// revision it was read at, so two concurrent changes cannot silently
/// overwrite each other (Go's per-request locks did not prevent that).
pub trait KeyRepository: Send + Sync {
    /// Stores a new key at revision 1. `AlreadyExists` if the id or the name
    /// is taken, and then nothing is stored.
    fn create(&self, k: Key) -> Result<Key, Error>;
    /// Stores `k` if the stored key is still at `k.revision()`, returning it
    /// at its new revision. `ConcurrentAccess` if it changed meanwhile,
    /// `KeyNotFound` if it is gone.
    fn update(&self, k: Key) -> Result<Key, Error>;
    fn get_by_id(&self, id: &KeyId) -> Result<Option<Key>, Error>;
    fn get_by_name(&self, name: &str) -> Result<Option<Key>, Error>;
    /// `KeyNotFound` for an unknown id.
    fn delete(&self, id: &KeyId) -> Result<(), Error>;
    /// Every key, ordered by name.
    fn list(&self) -> Result<Vec<Key>, Error>;
}
