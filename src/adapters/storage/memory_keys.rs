use crate::domain::core::{Code, Error, poisoned};
use crate::domain::key::*;
use std::collections::HashMap;
use std::sync::RwLock;

/// Keys held in process memory: lost when the context is closed.
///
/// One lock guards both maps, so the name index can never disagree with the
/// keys, and the check-then-insert in `create` is atomic.
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
        InMemoryKeyRepository {
            state: RwLock::new(State::default()),
        }
    }
}

impl KeyRepository for InMemoryKeyRepository {
    fn create(&self, k: Key) -> Result<(), Error> {
        const OP: &str = "InMemoryKeyRepository.create";
        let mut s = self.state.write().map_err(|_| poisoned(OP))?;
        if s.keys.contains_key(k.get_id()) {
            return Err(Error::new(Code::AlreadyExists, OP, format!("key id {} exists", k.get_id().as_str())));
        }
        if s.names.contains_key(k.get_name()) {
            return Err(Error::new(Code::AlreadyExists, OP, format!("key name {} exists", k.get_name())));
        }
        s.names.insert(k.get_name().into(), k.get_id().clone());
        s.keys.insert(k.get_id().clone(), k);
        Ok(())
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
        s.names.remove(k.get_name());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::core::ScopeKind;

    fn key(id: &str, name: &str) -> Key {
        Key::new(
            KeyId::new(id),
            String::from(name),
            1,
            String::from("aes-256-gcm"),
            String::from("stub"),
            String::from("default"),
            vec![0; 32],
            ScopeKind::Aead,
        )
    }

    fn code<T: std::fmt::Debug>(r: Result<T, Error>) -> Code {
        r.unwrap_err().code()
    }

    #[test]
    fn create_then_get_by_name() {
        let r = InMemoryKeyRepository::new();
        r.create(key("key-1", "my-key")).unwrap();
        let found = r.get_by_name("my-key").unwrap().expect("key should be found by its name");
        assert_eq!(found.get_id().as_str(), "key-1");
        assert_eq!(found.get_name(), "my-key");
    }

    #[test]
    fn get_by_name_misses_unknown() {
        let r = InMemoryKeyRepository::new();
        r.create(key("key-1", "my-key")).unwrap();
        assert!(r.get_by_name("unknown").unwrap().is_none());
    }

    #[test]
    fn same_name_twice_is_rejected() {
        let r = InMemoryKeyRepository::new();
        r.create(key("key-1", "my-key")).unwrap();
        assert_eq!(code(r.create(key("key-2", "my-key"))), Code::AlreadyExists);
        // The first key is kept, not overwritten.
        assert_eq!(r.get_by_name("my-key").unwrap().unwrap().get_id().as_str(), "key-1");
    }

    #[test]
    fn different_names_are_both_kept() {
        let r = InMemoryKeyRepository::new();
        r.create(key("key-1", "a")).unwrap();
        r.create(key("key-2", "b")).unwrap();
        assert!(r.get_by_name("a").unwrap().is_some());
        assert!(r.get_by_name("b").unwrap().is_some());
    }

    #[test]
    fn create_then_get_by_id() {
        let r = InMemoryKeyRepository::new();
        r.create(key("key-1", "my-key")).unwrap();

        let found = r.get_by_id(&KeyId::new("key-1")).unwrap().expect("key should be found by its id");
        assert_eq!(found.get_name(), "my-key");

        assert!(r.get_by_id(&KeyId::new("key-2")).unwrap().is_none());
    }

    #[test]
    fn same_id_twice_is_rejected() {
        let r = InMemoryKeyRepository::new();
        r.create(key("key-1", "first")).unwrap();

        assert_eq!(code(r.create(key("key-1", "second"))), Code::AlreadyExists);

        // Nothing changed: the original key is still there, and "second" was not indexed.
        assert_eq!(r.get_by_id(&KeyId::new("key-1")).unwrap().unwrap().get_name(), "first");
        assert!(r.get_by_name("second").unwrap().is_none());
    }

    #[test]
    fn delete_removes_key_and_frees_its_name() {
        let r = InMemoryKeyRepository::new();
        r.create(key("key-1", "my-key")).unwrap();

        r.delete(&KeyId::new("key-1")).unwrap();

        assert!(r.get_by_id(&KeyId::new("key-1")).unwrap().is_none());
        assert!(r.get_by_name("my-key").unwrap().is_none());
        // The name index was cleaned up too, so the name can be used again.
        r.create(key("key-2", "my-key")).unwrap();
    }

    #[test]
    fn delete_unknown_id_is_not_found() {
        let r = InMemoryKeyRepository::new();
        assert_eq!(code(r.delete(&KeyId::new("key-1"))), Code::KeyNotFound);
    }

    #[test]
    fn concurrent_creates_of_one_name_admit_exactly_one() {
        let r = InMemoryKeyRepository::new();
        let ok = std::thread::scope(|s| {
            let handles: Vec<_> = (0..16)
                .map(|i| {
                    let r = &r;
                    s.spawn(move || r.create(key(&format!("key-{i}"), "contended")).is_ok())
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).filter(|&ok| ok).count()
        });
        assert_eq!(ok, 1);
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
