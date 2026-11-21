//! The index both key stores keep in memory: keys by id, ids by name.
//!
//! The index is one immutable snapshot that writers replace whole
//! (`ArcSwap`), so the name index can never disagree with the keys, and a
//! lookup writes nothing shared: no lock word, no reference count. A shared
//! `RwLock` read writes its reader count, and on 8 threads that cache line
//! alone capped all lookups at ~5 M/s (docs/performance.md F7). Keys are
//! held behind `Arc`, so a new snapshot copies the maps, not the keys.
//!
//! Writers take a mutex, copy the snapshot, change the copy and publish it,
//! so every check-then-write is atomic. The snapshot is split into shards by
//! hash, each behind its own `Arc`: a write copies only the shards it
//! changes (`Arc::make_mut`), about 1/64 of the keys, instead of all of
//! them, which made creating 10k keys take seconds. A store adds persistence
//! by passing a closure to the writes: it runs after the checks and before
//! the new snapshot is published, so a key that cannot be persisted is not
//! recorded either.
//!
//! A panic during a write fails the index closed, as a poisoned lock did:
//! the store may already have persisted what the index never published, so
//! neither lookups nor writes trust it any more. Lookups learn that from
//! the writer mutex's poison flag, a read of a line nobody writes.

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::sync::{Arc, Mutex, MutexGuard};

use arc_swap::ArcSwap;

use crate::domain::core::{Code, Error, poisoned};
use crate::domain::key::{Key, KeyId};

const SHARDS: usize = 64;

pub(super) struct KeyIndex {
    state: ArcSwap<State>,
    writer: Mutex<()>,
    hasher: RandomState,
}

/// Keys by id and ids by name, each split into `SHARDS` maps by hash.
#[derive(Clone)]
struct State {
    keys: Vec<Arc<HashMap<KeyId, Arc<Key>>>>,
    names: Vec<Arc<HashMap<String, KeyId>>>,
}

impl Default for State {
    fn default() -> Self {
        State { keys: vec![Arc::default(); SHARDS], names: vec![Arc::default(); SHARDS] }
    }
}

/// An index being filled from storage, before anything shares it.
#[derive(Default)]
pub(super) struct Loading {
    state: State,
    hasher: RandomState,
}

impl Loading {
    /// Adds a key read back from storage. False (and nothing added) if its
    /// id or name is already taken.
    pub(super) fn load(&mut self, k: Key) -> bool {
        let (i, n) = (shard(&self.hasher, k.id().as_str()), shard(&self.hasher, k.name()));
        let s = &mut self.state;
        if s.keys[i].contains_key(k.id()) || s.names[n].contains_key(k.name()) {
            return false;
        }
        Arc::make_mut(&mut s.names[n]).insert(k.name().to_owned(), k.id().clone());
        Arc::make_mut(&mut s.keys[i]).insert(k.id().clone(), Arc::new(k));
        true
    }

    pub(super) fn finish(self) -> KeyIndex {
        KeyIndex { state: ArcSwap::from_pointee(self.state), writer: Mutex::new(()), hasher: self.hasher }
    }
}

impl Default for KeyIndex {
    fn default() -> Self {
        Loading::default().finish()
    }
}

fn shard(hasher: &RandomState, s: &str) -> usize {
    (hasher.hash_one(s) % SHARDS as u64) as usize
}

impl KeyIndex {
    fn id_shard(&self, id: &KeyId) -> usize {
        shard(&self.hasher, id.as_str())
    }

    fn name_shard(&self, name: &str) -> usize {
        shard(&self.hasher, name)
    }

    /// The writer's lock and a copy of the snapshot (its shard pointers) to
    /// change.
    fn write(&self, op: &'static str) -> Result<(MutexGuard<'_, ()>, State), Error> {
        let guard = self.writer.lock().map_err(|_| poisoned(op))?;
        Ok((guard, State::clone(&self.state.load())))
    }

    /// The current snapshot, unless a write panicked (fail closed).
    fn read(&self, op: &'static str) -> Result<arc_swap::Guard<Arc<State>>, Error> {
        if self.writer.is_poisoned() {
            return Err(poisoned(op));
        }
        Ok(self.state.load())
    }

    /// Records a new key at revision 1 (`KeyRepository::create`).
    pub(super) fn create(
        &self,
        op: &'static str,
        mut k: Key,
        persist: impl FnOnce(&Key) -> Result<(), Error>,
    ) -> Result<Key, Error> {
        let (_writing, mut s) = self.write(op)?;
        let (i, n) = (self.id_shard(k.id()), self.name_shard(k.name()));
        if s.keys[i].contains_key(k.id()) {
            return Err(Error::new(Code::AlreadyExists, op, format!("key id {} exists", k.id().as_str())));
        }
        if s.names[n].contains_key(k.name()) {
            return Err(Error::new(Code::AlreadyExists, op, format!("key name {} exists", k.name())));
        }
        k.set_revision(1);
        persist(&k)?;
        Arc::make_mut(&mut s.names[n]).insert(k.name().to_owned(), k.id().clone());
        Arc::make_mut(&mut s.keys[i]).insert(k.id().clone(), Arc::new(k.clone()));
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
        let i = self.id_shard(k.id());
        let stored = s.keys[i]
            .get(k.id())
            .ok_or_else(|| Error::new(Code::KeyNotFound, op, format!("no key with id {}", k.id().as_str())))?;
        if stored.revision() != k.revision() {
            let msg = format!("key {} changed since it was read; retry", k.name());
            return Err(Error::new(Code::ConcurrentAccess, op, msg));
        }
        k.set_revision(k.revision() + 1);
        persist(&k)?;
        Arc::make_mut(&mut s.keys[i]).insert(k.id().clone(), Arc::new(k.clone()));
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
        let i = self.id_shard(id);
        let k = s.keys[i]
            .get(id)
            .cloned()
            .ok_or_else(|| Error::new(Code::KeyNotFound, op, format!("no key with id {}", id.as_str())))?;
        persist(&k)?;
        Arc::make_mut(&mut s.keys[i]).remove(id);
        // Keep the name index consistent with `keys`.
        Arc::make_mut(&mut s.names[self.name_shard(k.name())]).remove(k.name());
        self.state.store(Arc::new(s));
        Ok(())
    }

    /// Calls `f` with the stored key, in place in the current snapshot, if
    /// there is one by that name (`KeyRepository::inspect_by_name`).
    pub(super) fn inspect_by_name(&self, op: &'static str, name: &str, f: &mut dyn FnMut(&Key)) -> Result<(), Error> {
        let s = self.read(op)?;
        if let Some(k) = self.find(&s, name) {
            f(k);
        }
        Ok(())
    }

    fn find<'s>(&self, s: &'s State, name: &str) -> Option<&'s Arc<Key>> {
        let id = s.names[self.name_shard(name)].get(name)?;
        s.keys[self.id_shard(id)].get(id)
    }

    pub(super) fn get_by_name(&self, op: &'static str, name: &str) -> Result<Option<Arc<Key>>, Error> {
        let s = self.read(op)?;
        Ok(self.find(&s, name).cloned())
    }

    pub(super) fn get_by_id(&self, op: &'static str, id: &KeyId) -> Result<Option<Arc<Key>>, Error> {
        Ok(self.read(op)?.keys[self.id_shard(id)].get(id).cloned())
    }

    /// Every key, ordered by name.
    pub(super) fn list(&self, op: &'static str) -> Result<Vec<Arc<Key>>, Error> {
        let s = self.read(op)?;
        let mut keys: Vec<Arc<Key>> = s.keys.iter().flat_map(|m| m.values().cloned()).collect();
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
    fn a_panic_while_writing_fails_the_index_closed() {
        let index = KeyIndex::default();
        index.create("create", key("key-1", "x"), none).unwrap();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = index.create("create", key("key-2", "y"), |_| panic!("simulated bug while persisting"));
        }));
        // The store may have persisted what the index never published.
        assert_eq!(index.get_by_name("get", "x").unwrap_err().code(), Code::Internal);
        assert_eq!(index.inspect_by_name("get", "x", &mut |_| ()).unwrap_err().code(), Code::Internal);
        assert_eq!(index.create("create", key("key-3", "z"), none).unwrap_err().code(), Code::Internal);
    }

    #[test]
    fn many_keys_across_shards_stay_consistent() {
        let index = KeyIndex::default();
        for i in 0..500 {
            index.create("create", key(&format!("key-{i}"), &format!("name-{i}")), none).unwrap();
        }
        assert_eq!(index.list("list").unwrap().len(), 500);
        for i in (0..500).step_by(7) {
            let k = index.get_by_name("get", &format!("name-{i}")).unwrap().unwrap();
            assert_eq!(k.id().as_str(), format!("key-{i}"));
            index.delete("delete", k.id(), none).unwrap();
            assert!(index.get_by_name("get", &format!("name-{i}")).unwrap().is_none());
            assert!(index.get_by_id("get", k.id()).unwrap().is_none());
        }
        assert_eq!(index.list("list").unwrap().len(), 500 - (0..500).step_by(7).count());
    }

    #[test]
    fn loading_rejects_a_taken_id_or_name() {
        let mut l = Loading::default();
        assert!(l.load(key("key-1", "x")));
        assert!(!l.load(key("key-1", "y")), "id taken");
        assert!(!l.load(key("key-2", "x")), "name taken");
        let index = l.finish();
        assert_eq!(index.get_by_name("get", "x").unwrap().unwrap().id().as_str(), "key-1");
        assert!(index.get_by_name("get", "y").unwrap().is_none());
    }

    #[test]
    fn a_lookup_shares_the_stored_key() {
        let index = KeyIndex::default();
        index.create("create", key("key-1", "x"), none).unwrap();
        let a = index.get_by_name("get", "x").unwrap().unwrap();
        let b = index.get_by_name("get", "x").unwrap().unwrap();
        assert!(Arc::ptr_eq(&a, &b), "no copy per lookup");
        let mut seen = None;
        index.inspect_by_name("get", "x", &mut |k| seen = Some(k as *const Key)).unwrap();
        assert_eq!(seen, Some(Arc::as_ptr(&a)), "inspected in place");
    }

    #[test]
    fn a_failed_persist_records_nothing() {
        let index = KeyIndex::default();
        let fail = |_: &Key| Err(Error::new(Code::Internal, "persist", "disk full"));
        assert!(index.create("create", key("key-1", "x"), fail).is_err());
        assert!(index.get_by_name("get", "x").unwrap().is_none());
    }

    #[test]
    fn a_snapshot_held_by_a_reader_survives_a_write() {
        let index = KeyIndex::default();
        index.create("create", key("key-1", "x"), none).unwrap();
        index
            .inspect_by_name("get", "x", &mut |k| {
                // A write while this reader holds the snapshot: it publishes a
                // new one and leaves the reader's untouched.
                index.delete("delete", k.id(), none).unwrap();
                assert_eq!(k.name(), "x");
            })
            .unwrap();
        assert!(index.get_by_name("get", "x").unwrap().is_none());
    }
}
