use crate::domain::core::Error;
use crate::domain::key::{Key, KeyId};

/// Persists the Key aggregate. Implementations are shared by every thread
/// that uses a context, so they take `&self` and synchronise internally.
///
/// Lookups return owned keys: a reference could not outlive the lock that
/// protects it. A miss is `Ok(None)`; `Err` means the store itself failed.
pub trait KeyRepository: Send + Sync {
    /// Fails with `AlreadyExists` if the id or the name is taken, and then
    /// stores nothing.
    fn create(&self, k: Key) -> Result<(), Error>;
    fn get_by_id(&self, id: &KeyId) -> Result<Option<Key>, Error>;
    fn get_by_name(&self, name: &str) -> Result<Option<Key>, Error>;
    /// Fails with `KeyNotFound` for an unknown id.
    fn delete(&self, id: &KeyId) -> Result<(), Error>;
    /// Every key, ordered by name.
    fn list(&self) -> Result<Vec<Key>, Error>;
}
