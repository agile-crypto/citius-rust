use crate::exports::error::Error::{self, AlreadyExists, KeyNotFound};
use crate::exports::key::*;
use std::collections::HashMap;

pub trait Repository {
    fn create(&mut self, k: Key) -> Result<(), Error>;
    fn get_by_id(&self, id: &KeyId) -> Option<&Key>;
    fn get_by_name(&self, name: &str) -> Option<&Key>;
    fn delete(&mut self, id: &KeyId) -> Result<(), Error>;
}

pub struct InMemoryRepository {
    keys: HashMap<KeyId, Key>,
    names: HashMap<String,KeyId>,
    next_id: u32,
}

impl InMemoryRepository {
    pub fn new() -> Self {
        InMemoryRepository {
            keys: HashMap::new(),
            names: HashMap::new(),
            next_id: 0,
        }
    }
    pub fn next_free_key_id(&mut self) -> KeyId{
        let id = self.next_id;
        self.next_id += 1;
        KeyId::new(format!("key-{}", id))
    }
}

impl Repository for InMemoryRepository {
    fn create(&mut self, k: Key) -> Result<(), Error> {
        if self.keys.contains_key(k.get_id()) {
            return Err(AlreadyExists);
        }
        if self.names.contains_key(k.get_name()) {
            return Err(AlreadyExists);
        }
        self.names.insert(k.get_name().into(), k.get_id().clone());
        self.keys.insert(k.get_id().clone(), k);
        Ok(())
    }

    

    fn get_by_name(&self, name: &str) -> Option<&Key> {
        self.names.get(name).and_then(|x| self.keys.get(x))
    }

    fn get_by_id(&self, id: &KeyId) -> Option<&Key> {
       self.keys.get(id) 
    }

    fn delete(&mut self, id: &KeyId) -> Result<(), Error> {
        let Some(k) = self.keys.remove(id) else {
            return Err(KeyNotFound);
        };
        // Keep the name index consistent with `keys`.
        self.names.remove(k.get_name());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::bindings::agc_scope_kind_AGC_SCOPE_KIND_AEAD;

use super::*;

    fn key(id: KeyId, name: &str) -> Key {
        Key::new(
            id,
            String::from(name),
            1,
            String::from("aes-256-gcm"),
            String::from("stub"),
            String::from("default"),
            vec![0; 32],
            agc_scope_kind_AGC_SCOPE_KIND_AEAD
        )
    }

    #[test]
    fn create_then_get_by_name() {
        let mut r = InMemoryRepository::new();
        r.create(key(KeyId::new("key-1"), "my-key")).unwrap();
        let found = r.get_by_name("my-key").expect("key should be found by its name");
        assert_eq!(found.get_id().as_str(), "key-1");
        assert_eq!(found.get_name(), "my-key");
    }

    #[test]
    fn get_by_name_misses_unknown() {
        let mut r = InMemoryRepository::new();
        r.create(key(KeyId::new("key-1"), "my-key")).unwrap();
        assert!(r.get_by_name("unknown").is_none());
    }

    #[test]
    fn same_name_twice_is_rejected() {
        let mut r = InMemoryRepository::new();
        r.create(key(KeyId::new("key-1"), "my-key")).unwrap();
        let second = r.create(key(KeyId::new("key-2"), "my-key"));
        assert!(matches!(second, Err(AlreadyExists)));
        // The first key is kept, not overwritten.
        assert_eq!(r.get_by_name("my-key").unwrap().get_id().as_str(), "key-1");
    }

    #[test]
    fn different_names_are_both_kept() {
        let mut r = InMemoryRepository::new();
        r.create(key(KeyId::new("key-1"), "a")).unwrap();
        r.create(key(KeyId::new("key-2"), "b")).unwrap();
        assert!(r.get_by_name("a").is_some());
        assert!(r.get_by_name("b").is_some());
    }

    #[test]
    fn key_ids_are_unique() {
        let mut r = InMemoryRepository::new();
        let first = r.next_free_key_id();
        let second = r.next_free_key_id();
        assert!(first.as_str().starts_with("key-"));
        assert_ne!(first, second);
    }

    #[test]
    fn create_then_get_by_id() {
        let mut r = InMemoryRepository::new();
        r.create(key(KeyId::new("key-1"), "my-key")).unwrap();

        let found = r.get_by_id(&KeyId::new("key-1")).expect("key should be found by its id");
        assert_eq!(found.get_name(), "my-key");

        assert!(r.get_by_id(&KeyId::new("key-2")).is_none());
    }

    #[test]
    fn same_id_twice_is_rejected() {
        let mut r = InMemoryRepository::new();
        r.create(key(KeyId::new("key-1"), "first")).unwrap();

        let second = r.create(key(KeyId::new("key-1"), "second"));
        assert!(matches!(second, Err(AlreadyExists)));

        // Nothing changed: the original key is still there, and "second" was not indexed.
        assert_eq!(r.get_by_id(&KeyId::new("key-1")).unwrap().get_name(), "first");
        assert!(r.get_by_name("second").is_none());
    }

    #[test]
    fn delete_removes_key_and_frees_its_name() {
        let mut r = InMemoryRepository::new();
        r.create(key(KeyId::new("key-1"), "my-key")).unwrap();

        r.delete(&KeyId::new("key-1")).unwrap();

        assert!(r.get_by_id(&KeyId::new("key-1")).is_none());
        assert!(r.get_by_name("my-key").is_none());
        // The name index was cleaned up too, so the name can be used again.
        r.create(key(KeyId::new("key-2"), "my-key")).unwrap();
    }

    #[test]
    fn delete_unknown_id_is_not_found() {
        let mut r = InMemoryRepository::new();
        let res = r.delete(&KeyId::new("key-1"));
        assert!(matches!(res, Err(KeyNotFound)));
    }
}
