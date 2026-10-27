use crate::domain::core::{Code, Error, poisoned};
use crate::domain::key::*;
use std::collections::HashMap;
use std::sync::RwLock;

/// Keys held in process memory: lost when the context is closed.
///
/// One lock guards both maps, so the name index can never disagree with the
/// keys, and every check-then-write is atomic.
pub struct InMemoryKeyRepository {
    state: RwLock<State>,
}

#[derive(Default)]
struct State {
    keys: HashMap<KeyId, Key>,
    names: HashMap<String, KeyId>,
}

impl InMemoryKeyRepository {
    pub fn new() -> Self {
        InMemoryKeyRepository { state: RwLock::new(State::default()) }
    }
}

impl KeyRepository for InMemoryKeyRepository {
    fn create(&self, mut k: Key) -> Result<Key, Error> {
        const OP: &str = "InMemoryKeyRepository.create";
        let mut s = self.state.write().map_err(|_| poisoned(OP))?;
        if s.keys.contains_key(k.id()) {
            return Err(Error::new(Code::AlreadyExists, OP, format!("key id {} exists", k.id().as_str())));
        }
        if s.names.contains_key(k.name()) {
            return Err(Error::new(Code::AlreadyExists, OP, format!("key name {} exists", k.name())));
        }
        k.set_revision(1);
        s.names.insert(k.name().into(), k.id().clone());
        s.keys.insert(k.id().clone(), k.clone());
        Ok(k)
    }

    fn update(&self, mut k: Key) -> Result<Key, Error> {
        const OP: &str = "InMemoryKeyRepository.update";
        let mut s = self.state.write().map_err(|_| poisoned(OP))?;
        let stored = s
            .keys
            .get_mut(k.id())
            .ok_or_else(|| Error::new(Code::KeyNotFound, OP, format!("no key with id {}", k.id().as_str())))?;
        if stored.revision() != k.revision() {
            return Err(Error::new(
                Code::ConcurrentAccess,
                OP,
                format!("key {} changed since it was read; retry", k.name()),
            ));
        }
        k.set_revision(k.revision() + 1);
        *stored = k.clone();
        Ok(k)
    }

    fn get_by_name(&self, name: &str) -> Result<Option<Key>, Error> {
        let s = self.state.read().map_err(|_| poisoned("InMemoryKeyRepository.get_by_name"))?;
        Ok(s.names.get(name).and_then(|id| s.keys.get(id)).cloned())
    }

    fn get_by_id(&self, id: &KeyId) -> Result<Option<Key>, Error> {
        let s = self.state.read().map_err(|_| poisoned("InMemoryKeyRepository.get_by_id"))?;
        Ok(s.keys.get(id).cloned())
    }

    fn delete(&self, id: &KeyId) -> Result<(), Error> {
        const OP: &str = "InMemoryKeyRepository.delete";
        let mut s = self.state.write().map_err(|_| poisoned(OP))?;
        let Some(k) = s.keys.remove(id) else {
            return Err(Error::new(Code::KeyNotFound, OP, format!("no key with id {}", id.as_str())));
        };
        // Keep the name index consistent with `keys`.
        s.names.remove(k.name());
        Ok(())
    }

    fn list(&self) -> Result<Vec<Key>, Error> {
        let s = self.state.read().map_err(|_| poisoned("InMemoryKeyRepository.list"))?;
        let mut keys: Vec<Key> = s.keys.values().cloned().collect();
        keys.sort_by(|a, b| a.name().cmp(b.name()));
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::key::testing::{key, version};

    fn code<T: std::fmt::Debug>(r: Result<T, Error>) -> Code {
        r.unwrap_err().code()
    }

    #[test]
    fn create_then_get_by_name_and_id() {
        let r = InMemoryKeyRepository::new();
        let stored = r.create(key("key-1", "my-key")).unwrap();
        assert_eq!(stored.revision(), 1);
        assert_eq!(r.get_by_name("my-key").unwrap().unwrap().id().as_str(), "key-1");
        assert_eq!(r.get_by_id(&KeyId::new("key-1")).unwrap().unwrap().name(), "my-key");
        assert!(r.get_by_name("unknown").unwrap().is_none());
        assert!(r.get_by_id(&KeyId::new("key-2")).unwrap().is_none());
    }

    #[test]
    fn same_name_or_id_twice_is_rejected_and_nothing_changes() {
        let r = InMemoryKeyRepository::new();
        r.create(key("key-1", "first")).unwrap();
        assert_eq!(code(r.create(key("key-2", "first"))), Code::AlreadyExists);
        assert_eq!(code(r.create(key("key-1", "second"))), Code::AlreadyExists);
        assert_eq!(r.get_by_id(&KeyId::new("key-1")).unwrap().unwrap().name(), "first");
        assert!(r.get_by_name("second").unwrap().is_none());
    }

    #[test]
    fn update_is_optimistic() {
        let r = InMemoryKeyRepository::new();
        let mut a = r.create(key("key-1", "k")).unwrap();
        let mut b = a.clone(); // read by someone else at the same revision

        a.add_version(version(2)).unwrap();
        let a = r.update(a).unwrap();
        assert_eq!((a.revision(), r.get_by_name("k").unwrap().unwrap().current().number()), (2, 2));

        // b is stale: its change would silently drop a's version 2.
        b.add_version(version(2)).unwrap();
        assert_eq!(code(r.update(b)), Code::ConcurrentAccess);

        r.delete(a.id()).unwrap();
        assert_eq!(code(r.update(a)), Code::KeyNotFound);
    }

    #[test]
    fn concurrent_updates_of_one_key_admit_exactly_one() {
        let r = InMemoryKeyRepository::new();
        let k = r.create(key("key-1", "k")).unwrap();
        let ok = std::thread::scope(|s| {
            let hs: Vec<_> = (0..8)
                .map(|_| {
                    let mut mine = k.clone();
                    let r = &r;
                    s.spawn(move || {
                        mine.add_version(version(2)).unwrap();
                        r.update(mine).is_ok()
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).filter(|&ok| ok).count()
        });
        assert_eq!(ok, 1);
    }

    #[test]
    fn delete_removes_key_and_frees_its_name() {
        let r = InMemoryKeyRepository::new();
        r.create(key("key-1", "my-key")).unwrap();
        r.delete(&KeyId::new("key-1")).unwrap();
        assert!(r.get_by_name("my-key").unwrap().is_none());
        r.create(key("key-2", "my-key")).unwrap();
        assert_eq!(code(r.delete(&KeyId::new("key-1"))), Code::KeyNotFound);
    }

    #[test]
    fn list_is_ordered_by_name() {
        let r = InMemoryKeyRepository::new();
        for (id, name) in [("1", "c"), ("2", "a"), ("3", "b")] {
            r.create(key(id, name)).unwrap();
        }
        let names: Vec<_> = r.list().unwrap().iter().map(|k| k.name().to_owned()).collect();
        assert_eq!(names, ["a", "b", "c"]);
    }

    #[test]
    fn a_poisoned_lock_fails_closed() {
        let r = InMemoryKeyRepository::new();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = r.state.write().unwrap();
            panic!("simulated bug while holding the lock");
        }));
        assert_eq!(code(r.get_by_name("x")), Code::Internal);
        assert_eq!(code(r.create(key("key-1", "x"))), Code::Internal);
    }
}
