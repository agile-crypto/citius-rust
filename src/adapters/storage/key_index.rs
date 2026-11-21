//! The index both key stores keep in memory: keys by id, ids by name.
//!
//! The index is one immutable snapshot that writers replace whole
//! (`ArcSwap`), so the name index can never disagree with the keys, and a
//! lookup writes nothing shared: no lock word, no reference count. A shared
//! `RwLock` read writes its reader count, and on 8 threads that cache line
//! alone capped all lookups at ~5 M/s (docs/performance.md F7). Keys are
//! held behind `Arc`, so a new snapshot copies the maps, not the keys.
//!
//! Writers take a mutex, copy the snapshot, change the copy and publish it:
//! every check-then-write is atomic, and a write costs time linear in the
//! number of keys (key administration is rare; operations are not). A store
//! adds persistence by passing a closure to the writes: it runs after the
//! checks and before the new snapshot is published, so a key that cannot be
//! persisted is not recorded either.
//!
//! A panic during a write leaves the published snapshot as it was: lookups
//! keep working on consistent data, and later writes fail closed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use arc_swap::ArcSwap;

use crate::domain::core::{Code, Error, poisoned};
use crate::domain::key::{Key, KeyId};

#[derive(Default)]
pub(super) struct KeyIndex {
    state: ArcSwap<State>,
    writer: Mutex<()>,
}

#[derive(Default, Clone)]
struct State {
    keys: HashMap<KeyId, Arc<Key>>,
    names: HashMap<String, KeyId>,
}

impl KeyIndex {
    /// Adds a key read back from storage, before the index is shared.
    /// False (and nothing added) if its id or name is already taken.
    pub(super) fn load(&mut self, k: Key) -> bool {
        // Not shared yet: the snapshot has one owner and is changed in place.
        let arc = std::mem::take(&mut self.state).into_inner();
        let mut s = Arc::try_unwrap(arc).unwrap_or_else(|shared| (*shared).clone());
        let added = !s.keys.contains_key(k.id()) && !s.names.contains_key(k.name());
        if added {
            s.names.insert(k.name().to_owned(), k.id().clone());
            s.keys.insert(k.id().clone(), Arc::new(k));
        }
        self.state = ArcSwap::from_pointee(s);
        added
    }

    fn write(&self, op: &'static str) -> Result<(MutexGuard<'_, ()>, State), Error> {
        let guard = self.writer.lock().map_err(|_| poisoned(op))?;
        Ok((guard, State::clone(&self.state.load())))
    }

    /// Records a new key at revision 1 (`KeyRepository::create`).
    pub(super) fn create(
        &self,
        op: &'static str,
        mut k: Key,
        persist: impl FnOnce(&Key) -> Result<(), Error>,
    ) -> Result<Key, Error> {
        let (_writing, mut s) = self.write(op)?;
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
        self.state.store(Arc::new(s));
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
        let (_writing, mut s) = self.write(op)?;
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
        self.state.store(Arc::new(s));
        Ok(k)
    }

    /// Removes a key (`KeyRepository::delete`).
    pub(super) fn delete(
        &self,
        op: &'static str,
        id: &KeyId,
        persist: impl FnOnce(&Key) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let (_writing, mut s) = self.write(op)?;
        let k = s
            .keys
            .remove(id)
            .ok_or_else(|| Error::new(Code::KeyNotFound, op, format!("no key with id {}", id.as_str())))?;
        persist(&k)?;
        // Keep the name index consistent with `keys`.
        s.names.remove(k.name());
        self.state.store(Arc::new(s));
        Ok(())
    }

    /// Calls `f` with the stored key, in place in the current snapshot, if
    /// there is one by that name (`KeyRepository::inspect_by_name`).
    pub(super) fn inspect_by_name(&self, name: &str, f: &mut dyn FnMut(&Key)) {
        let s = self.state.load();
        if let Some(k) = s.names.get(name).and_then(|id| s.keys.get(id)) {
            f(k);
        }
    }

    pub(super) fn get_by_name(&self, name: &str) -> Option<Arc<Key>> {
        let s = self.state.load();
        s.names.get(name).and_then(|id| s.keys.get(id)).cloned()
    }

    pub(super) fn get_by_id(&self, id: &KeyId) -> Option<Arc<Key>> {
        self.state.load().keys.get(id).cloned()
    }

    /// Every key, ordered by name.
    pub(super) fn list(&self) -> Vec<Arc<Key>> {
        let mut keys: Vec<Arc<Key>> = self.state.load().keys.values().cloned().collect();
        keys.sort_by(|a, b| a.name().cmp(b.name()));
        keys
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
    fn a_panic_while_writing_leaves_lookups_working_and_writes_closed() {
        let index = KeyIndex::default();
        index.create("create", key("key-1", "x"), none).unwrap();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = index.create("create", key("key-2", "y"), |_| panic!("simulated bug while persisting"));
        }));
        assert!(index.get_by_name("x").is_some(), "the published snapshot is intact");
        assert!(index.get_by_name("y").is_none(), "the half-done write was never published");
        assert_eq!(index.create("create", key("key-3", "z"), none).unwrap_err().code(), Code::Internal);
    }

    #[test]
    fn a_lookup_shares_the_stored_key() {
        let index = KeyIndex::default();
        index.create("create", key("key-1", "x"), none).unwrap();
        let a = index.get_by_name("x").unwrap();
        let b = index.get_by_name("x").unwrap();
        assert!(Arc::ptr_eq(&a, &b), "no copy per lookup");
        let mut seen = None;
        index.inspect_by_name("x", &mut |k| seen = Some(k as *const Key));
        assert_eq!(seen, Some(Arc::as_ptr(&a)), "inspected in place");
    }

    #[test]
    fn a_failed_persist_records_nothing() {
        let index = KeyIndex::default();
        let fail = |_: &Key| Err(Error::new(Code::Internal, "persist", "disk full"));
        assert!(index.create("create", key("key-1", "x"), fail).is_err());
        assert!(index.get_by_name("x").is_none());
    }

    #[test]
    fn a_snapshot_held_by_a_reader_survives_a_write() {
        let index = KeyIndex::default();
        index.create("create", key("key-1", "x"), none).unwrap();
        index.inspect_by_name("x", &mut |k| {
            // A write while this reader holds the snapshot: it publishes a
            // new one and leaves the reader's untouched.
            index.delete("delete", k.id(), none).unwrap();
            assert_eq!(k.name(), "x");
        });
        assert!(index.get_by_name("x").is_none());
    }
}
