use std::collections::BTreeMap;
use std::sync::RwLock;

use crate::domain::core::{Code, Error, poisoned};
use crate::domain::policy::{Policy, PolicyRepository};

/// Policies held in process memory, ordered by name.
pub struct InMemoryPolicyRepository {
    policies: RwLock<BTreeMap<String, Policy>>,
}

impl InMemoryPolicyRepository {
    pub fn new() -> Self {
        InMemoryPolicyRepository { policies: RwLock::new(BTreeMap::new()) }
    }
}

impl PolicyRepository for InMemoryPolicyRepository {
    fn create(&self, p: Policy) -> Result<(), Error> {
        const OP: &str = "InMemoryPolicyRepository.create";
        let mut m = self.policies.write().map_err(|_| poisoned(OP))?;
        if m.contains_key(p.name()) {
            return Err(Error::new(Code::AlreadyExists, OP, format!("policy {} exists", p.name())));
        }
        m.insert(p.name().to_owned(), p);
        Ok(())
    }

    fn update(&self, p: Policy, expected_version: i64) -> Result<(), Error> {
        const OP: &str = "InMemoryPolicyRepository.update";
        let mut m = self.policies.write().map_err(|_| poisoned(OP))?;
        let slot = m.get_mut(p.name()).ok_or_else(|| not_found(OP, p.name()))?;
        // One check under the lock, so two updates from the same version
        // cannot both succeed (Go's repository has no compare-and-put).
        let stale = slot.version() != p.version() - 1;
        if stale || (expected_version > 0 && slot.version() != expected_version) {
            let want = if expected_version > 0 { expected_version } else { p.version() - 1 };
            return Err(Error::new(
                Code::PolicyVersionConflict,
                OP,
                format!("policy {} is at version {}, expected {want}", p.name(), slot.version()),
            ));
        }
        *slot = p;
        Ok(())
    }

    fn get(&self, name: &str) -> Result<Option<Policy>, Error> {
        let m = self.policies.read().map_err(|_| poisoned("InMemoryPolicyRepository.get"))?;
        Ok(m.get(name).cloned())
    }

    fn inspect(&self, name: &str, f: &mut dyn FnMut(&Policy)) -> Result<(), Error> {
        let m = self.policies.read().map_err(|_| poisoned("InMemoryPolicyRepository.inspect"))?;
        if let Some(p) = m.get(name) {
            f(p);
        }
        Ok(())
    }

    fn delete(&self, name: &str) -> Result<(), Error> {
        const OP: &str = "InMemoryPolicyRepository.delete";
        let mut m = self.policies.write().map_err(|_| poisoned(OP))?;
        m.remove(name).map(|_| ()).ok_or_else(|| not_found(OP, name))
    }

    fn list(&self) -> Result<Vec<Policy>, Error> {
        let m = self.policies.read().map_err(|_| poisoned("InMemoryPolicyRepository.list"))?;
        Ok(m.values().cloned().collect())
    }
}

fn not_found(op: &'static str, name: &str) -> Error {
    Error::new(Code::PolicyNotFound, op, format!("no policy named {name}"))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::SystemTime;

    use super::*;
    use crate::domain::core::{Operation, ProviderRequirements};
    use crate::domain::policy::{Enforcer, Evaluator, Manager, TemplateSecurityInfo};
    use crate::proto::api::TemplateStatus;

    const DOC: &str = r#"{"version": "1",
        "allowed_templates": ["b", "a"],
        "allowed_operations": {"key_operations": ["create_key"]},
        "security_requirements": {"quantum_safe": true},
        "provider_requirements": {"memory_safe": true}}"#;

    fn engine() -> Enforcer {
        Enforcer::new(Arc::new(InMemoryPolicyRepository::new()))
    }

    fn code<T: std::fmt::Debug>(r: Result<T, Error>) -> Code {
        r.unwrap_err().code()
    }

    #[test]
    fn crud() {
        let e = engine();
        e.create_policy("p", DOC).unwrap();
        assert_eq!(code(e.create_policy("p", "{}")), Code::AlreadyExists);
        assert_eq!(e.get_policy("p").unwrap().document(), DOC);

        let before = e.get_policy("p").unwrap();
        e.update_policy("p", "{}", 0).unwrap();
        let after = e.get_policy("p").unwrap();
        assert_eq!(after.document(), "{}");
        assert_eq!(after.created_at(), before.created_at());
        assert_eq!(code(e.update_policy("q", "{}", 0)), Code::PolicyNotFound);
        assert_eq!(code(e.update_policy("p", "{", 0)), Code::InvalidArgument);

        e.create_policy("a", "{}").unwrap();
        let names: Vec<_> = e.list_policies().unwrap().iter().map(|p| p.name().to_owned()).collect();
        assert_eq!(names, ["a", "p"]);

        e.delete_policy("p").unwrap();
        assert_eq!(code(e.get_policy("p")), Code::PolicyNotFound);
        assert_eq!(code(e.delete_policy("p")), Code::PolicyNotFound);
    }

    #[test]
    fn evaluation() {
        let e = engine();
        e.create_policy("p", DOC).unwrap();
        assert!(e.validate_operation("p", Operation::CreateKey, Some("a")).is_ok());
        assert_eq!(code(e.validate_operation("p", Operation::CreateKey, Some("c"))), Code::PolicyViolation);
        assert_eq!(code(e.validate_operation("p", Operation::Sign, None)), Code::PolicyViolation);
        assert_eq!(e.allowed_templates("p").unwrap(), ["b", "a"]);
        assert_eq!(
            e.provider_requirements("p").unwrap(),
            ProviderRequirements { memory_safe: true, ..Default::default() }
        );
        let classical = TemplateSecurityInfo {
            template_id: "a".into(),
            status: TemplateStatus::Active,
            fips_approved: false,
            quantum_safe: false,
            strength_bits: 128,
        };
        assert_eq!(code(e.check_template_security("p", &classical)), Code::PolicyViolation);
    }

    #[test]
    fn unknown_or_missing_policy_never_bypasses() {
        let e = engine();
        assert_eq!(code(e.validate_operation("nope", Operation::CreateKey, None)), Code::PolicyNotFound);
        assert_eq!(code(e.validate_operation("", Operation::CreateKey, None)), Code::InvalidArgument);
        assert_eq!(code(e.allowed_templates("nope")), Code::PolicyNotFound);
    }

    #[test]
    fn concurrent_creates_of_one_name_admit_exactly_one() {
        let e = engine();
        let ok = std::thread::scope(|s| {
            let hs: Vec<_> = (0..16).map(|_| s.spawn(|| e.create_policy("p", "{}").is_ok())).collect();
            hs.into_iter().map(|h| h.join().unwrap()).filter(|&b| b).count()
        });
        assert_eq!(ok, 1);
    }

    #[test]
    fn listing_is_ordered_by_name() {
        let r = InMemoryPolicyRepository::new();
        for n in ["c", "a", "b"] {
            r.create(Policy::new(n, "{}", SystemTime::now()).unwrap()).unwrap();
        }
        let names: Vec<_> = r.list().unwrap().iter().map(|p| p.name().to_owned()).collect();
        assert_eq!(names, ["a", "b", "c"]);
    }
}
