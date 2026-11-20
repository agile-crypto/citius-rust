use std::sync::Arc;

use super::key_index::KeyIndex;
use crate::domain::core::Error;
use crate::domain::key::*;

/// Keys held in process memory: lost when the context is closed.
pub struct InMemoryKeyRepository {
    index: KeyIndex,
}

impl InMemoryKeyRepository {
    pub fn new() -> Self {
        InMemoryKeyRepository { index: KeyIndex::default() }
    }
}

/// Nothing to persist.
fn in_memory(_: &Key) -> Result<(), Error> {
    Ok(())
}

impl KeyRepository for InMemoryKeyRepository {
    fn create(&self, k: Key) -> Result<Key, Error> {
        self.index.create("InMemoryKeyRepository.create", k, in_memory)
    }

    fn update(&self, k: Key) -> Result<Key, Error> {
        self.index.update("InMemoryKeyRepository.update", k, in_memory)
    }

    fn get_by_name(&self, name: &str) -> Result<Option<Arc<Key>>, Error> {
        self.index.get_by_name("InMemoryKeyRepository.get_by_name", name)
    }

    fn get_by_id(&self, id: &KeyId) -> Result<Option<Arc<Key>>, Error> {
        self.index.get_by_id("InMemoryKeyRepository.get_by_id", id)
    }

    fn delete(&self, id: &KeyId) -> Result<(), Error> {
        self.index.delete("InMemoryKeyRepository.delete", id, in_memory)
    }

    fn list(&self) -> Result<Vec<Arc<Key>>, Error> {
        self.index.list("InMemoryKeyRepository.list")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::core::Code;
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
}
