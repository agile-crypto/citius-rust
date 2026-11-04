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

    /// `format` "" or "json": the one rules language this library parses
    /// (Go: checkFormat).
    pub fn create(&self, name: &str, document: &str, format: &str) -> Result<Policy, Error> {
        check_format(format, "PolicyAdmin::create")?;
        self.policies.create_policy(name, document)
    }

    pub fn get(&self, name: &str) -> Result<Policy, Error> {
        self.policies.get_policy(name)
    }

    pub fn update(&self, name: &str, document: &str, format: &str, expected_version: i64) -> Result<Policy, Error> {
        check_format(format, "PolicyAdmin::update")?;
        self.policies.update_policy(name, document, expected_version)
    }

    pub fn list(&self) -> Result<Vec<Policy>, Error> {
        self.policies.list_policies()
    }

    /// Known gap: a key created between the check and the delete is bound to
    /// a policy that no longer exists. Its operations then fail with
    /// `PolicyNotFound` (fail closed). A transactional store closes the gap.
    pub fn delete(&self, name: &str) -> Result<(), Error> {
        let bound = self.keys.list()?.iter().filter(|k| k.policy() == name).count();
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

/// The format every stored policy has: the JSON rules language.
pub const POLICY_FORMAT: &str = "json";

fn check_format(format: &str, op: &'static str) -> Result<(), Error> {
    if format.is_empty() || format == POLICY_FORMAT {
        return Ok(());
    }
    Err(Error::new(
        Code::InvalidArgument,
        op,
        format!("unsupported policy format {format:?}: only {POLICY_FORMAT:?} is supported"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::storage::{InMemoryKeyRepository, InMemoryPolicyRepository};
    use crate::domain::key::testing::key;
    use crate::domain::policy::Enforcer;

    #[test]
    fn a_policy_bound_to_keys_cannot_be_deleted() {
        let keys = Arc::new(InMemoryKeyRepository::new());
        let admin = PolicyAdmin::new(Arc::new(Enforcer::new(Arc::new(InMemoryPolicyRepository::new()))), keys.clone());
        admin.create("p", "{}", "").unwrap();
        admin.create("unused", "{}", "").unwrap();
        let k = keys.create(key("k1", "k")).unwrap(); // bound to policy "p"

        let err = admin.delete("p").unwrap_err();
        assert_eq!(err.code(), Code::PolicyViolation);
        assert!(err.message().contains("1 key"), "{}", err.message());
        admin.delete("unused").unwrap();

        keys.delete(k.id()).unwrap();
        admin.delete("p").unwrap();
    }
}
