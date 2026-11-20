//! The index both key stores keep in memory: keys by id, ids by name.
//!
//! One lock guards both maps, so the name index can never disagree with the
//! keys, and every check-then-write is atomic. Keys are held behind `Arc`:
//! a lookup shares the stored key (one reference count) instead of copying
//! it with every version, which is what made a lookup on the hot path cost
//! a dozen allocations (docs/performance.md F3).
//!
//! A store adds persistence by passing a closure to the writes: it runs
//! under the lock, after the checks and before the index changes, so a key
//! that cannot be persisted is not recorded either.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::domain::core::{Code, Error, poisoned};
use crate::domain::key::{Key, KeyId};

#[derive(Default)]
pub(super) struct KeyIndex {
    state: RwLock<State>,
}

#[derive(Default)]
struct State {
    keys: HashMap<KeyId, Arc<Key>>,
    names: HashMap<String, KeyId>,
}

impl KeyIndex {
    /// Adds a key read back from storage, before the index is shared.
    /// False (and nothing added) if its id or name is already taken.
    pub(super) fn load(&mut self, k: Key) -> bool {
        let s = self.state.get_mut().unwrap_or_else(std::sync::PoisonError::into_inner);
        if s.keys.contains_key(k.id()) || s.names.contains_key(k.name()) {
            return false;
        }
        s.names.insert(k.name().to_owned(), k.id().clone());
        s.keys.insert(k.id().clone(), Arc::new(k));
        true
    }

    /// Records a new key at revision 1 (`KeyRepository::create`).
    pub(super) fn create(
        &self,
        op: &'static str,
        mut k: Key,
        persist: impl FnOnce(&Key) -> Result<(), Error>,
    ) -> Result<Key, Error> {
        let mut s = self.state.write().map_err(|_| poisoned(op))?;
        if s.keys.contains_key(k.id()) {
            return Err(Error::new(Code::AlreadyExists, op, format!("key id {} exists", k.id().as_str())));
        }
        if s.names.contains_key(k.name()) {
            return Err(Error::new(Code::AlreadyExists, op, format!("key name {} exists", k.name())));
        }
        k.set_revision(1);
        persist(&k)?;
        s.names.insert(k.name().to_owned(), k.id().clone());
        s.keys.insert(k.id().clone(), Arc::new(k.clone()));
        Ok(k)
    }

    /// Replaces a key still at the revision it was read at
    /// (`KeyRepository::update`).
    pub(super) fn update(
        &self,
        op: &'static str,
        mut k: Key,
        persist: impl FnOnce(&Key) -> Result<(), Error>,
    ) -> Result<Key, Error> {
        let mut s = self.state.write().map_err(|_| poisoned(op))?;
        let stored = s
            .keys
            .get(k.id())
            .ok_or_else(|| Error::new(Code::KeyNotFound, op, format!("no key with id {}", k.id().as_str())))?;
        if stored.revision() != k.revision() {
            let msg = format!("key {} changed since it was read; retry", k.name());
            return Err(Error::new(Code::ConcurrentAccess, op, msg));
        }
        k.set_revision(k.revision() + 1);
        persist(&k)?;
        s.keys.insert(k.id().clone(), Arc::new(k.clone()));
        Ok(k)
    }

    /// Removes a key (`KeyRepository::delete`).
    pub(super) fn delete(
        &self,
        op: &'static str,
        id: &KeyId,
        persist: impl FnOnce(&Key) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut s = self.state.write().map_err(|_| poisoned(op))?;
        let k = s
            .keys
            .get(id)
            .ok_or_else(|| Error::new(Code::KeyNotFound, op, format!("no key with id {}", id.as_str())))?;
        persist(k)?;
        let name = k.name().to_owned();
        s.keys.remove(id);
        // Keep the name index consistent with `keys`.
        s.names.remove(&name);
        Ok(())
    }

    pub(super) fn get_by_name(&self, op: &'static str, name: &str) -> Result<Option<Arc<Key>>, Error> {
        let s = self.state.read().map_err(|_| poisoned(op))?;
        Ok(s.names.get(name).and_then(|id| s.keys.get(id)).cloned())
    }

    pub(super) fn get_by_id(&self, op: &'static str, id: &KeyId) -> Result<Option<Arc<Key>>, Error> {
        let s = self.state.read().map_err(|_| poisoned(op))?;
        Ok(s.keys.get(id).cloned())
    }

    /// Every key, ordered by name.
    pub(super) fn list(&self, op: &'static str) -> Result<Vec<Arc<Key>>, Error> {
        let s = self.state.read().map_err(|_| poisoned(op))?;
        let mut keys: Vec<Arc<Key>> = s.keys.values().cloned().collect();
        keys.sort_by(|a, b| a.name().cmp(b.name()));
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::key::testing::key;

    fn none(_: &Key) -> Result<(), Error> {
        Ok(())
    }

    #[test]
    fn a_poisoned_lock_fails_closed() {
        let index = KeyIndex::default();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = index.state.write().unwrap();
            panic!("simulated bug while holding the lock");
        }));
        assert_eq!(index.get_by_name("get", "x").unwrap_err().code(), Code::Internal);
        assert_eq!(index.create("create", key("key-1", "x"), none).unwrap_err().code(), Code::Internal);
    }

    #[test]
    fn a_lookup_shares_the_stored_key() {
        let index = KeyIndex::default();
        index.create("create", key("key-1", "x"), none).unwrap();
        let a = index.get_by_name("get", "x").unwrap().unwrap();
        let b = index.get_by_name("get", "x").unwrap().unwrap();
        assert!(Arc::ptr_eq(&a, &b), "no copy per lookup");
    }

    #[test]
    fn a_failed_persist_records_nothing() {
        let index = KeyIndex::default();
        let fail = |_: &Key| Err(Error::new(Code::Internal, "persist", "disk full"));
        assert!(index.create("create", key("key-1", "x"), fail).is_err());
        assert!(index.get_by_name("get", "x").unwrap().is_none());
    }
}
