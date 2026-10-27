use std::sync::Arc;

use crate::domain::core::{Code, Error};
use crate::domain::key::KeyRepository;
use crate::domain::policy::{Manager, Policy};

/// Policy administration (the CryptoPolicyService use cases). An application
/// service rather than the policy engine itself because deleting a policy
/// must look at keys: a policy still bound to keys cannot be deleted
/// (agc_policy.h, referential integrity).
pub struct PolicyAdmin {
    policies: Arc<dyn Manager>,
    keys: Arc<dyn KeyRepository>,
}

impl PolicyAdmin {
    pub fn new(policies: Arc<dyn Manager>, keys: Arc<dyn KeyRepository>) -> Self {
        PolicyAdmin { policies, keys }
    }

    pub fn create(&self, name: &str, document: &str) -> Result<Policy, Error> {
        self.policies.create_policy(name, document)
    }

    pub fn get(&self, name: &str) -> Result<Policy, Error> {
        self.policies.get_policy(name)
    }

    pub fn update(&self, name: &str, document: &str) -> Result<Policy, Error> {
        self.policies.update_policy(name, document)
    }

    pub fn list(&self) -> Result<Vec<Policy>, Error> {
        self.policies.list_policies()
    }

    /// Known gap: a key created between the check and the delete is bound to
    /// a policy that no longer exists. Its operations then fail with
    /// `PolicyNotFound` (fail closed). A transactional store closes the gap.
    pub fn delete(&self, name: &str) -> Result<(), Error> {
        let bound = self.keys.list()?.iter().filter(|k| k.get_policy() == name).count();
        if bound > 0 {
            return Err(Error::new(
                Code::PolicyViolation,
                "PolicyAdmin::delete",
                format!("policy {name} is still bound to {bound} key(s)"),
            ));
        }
        self.policies.delete_policy(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::storage::{InMemoryKeyRepository, InMemoryPolicyRepository};
    use crate::domain::core::ScopeKind;
    use crate::domain::key::{Key, KeyId};
    use crate::domain::policy::Enforcer;

    #[test]
    fn a_policy_bound_to_keys_cannot_be_deleted() {
        let keys = Arc::new(InMemoryKeyRepository::new());
        let admin = PolicyAdmin::new(Arc::new(Enforcer::new(Arc::new(InMemoryPolicyRepository::new()))), keys.clone());
        admin.create("p", "{}").unwrap();
        admin.create("unused", "{}").unwrap();
        keys.create(Key::new(KeyId::new("k1"), "k".into(), 1, "t".into(), "pr".into(), "p".into(), vec![], ScopeKind::Aead))
            .unwrap();

        let err = admin.delete("p").unwrap_err();
        assert_eq!(err.code(), Code::PolicyViolation);
        assert!(err.message().contains("1 key"), "{}", err.message());
        admin.delete("unused").unwrap();

        keys.delete(&KeyId::new("k1")).unwrap();
        admin.delete("p").unwrap();
    }
}
