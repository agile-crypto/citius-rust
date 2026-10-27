use std::sync::Arc;

use crate::domain::core::{Code, Error, KeyCreationSpec, Operation};
use crate::domain::key::*;
use crate::domain::policy::{Evaluator, TemplateSecurityInfo};
use crate::domain::provider::{ProviderRegistry, Requirements};
use crate::domain::template::*;

/// Runs the key lifecycle use cases. Holds no state of its own: everything
/// it touches is behind a shared domain interface, so one orchestrator serves
/// every thread of a context.
pub struct KeyOrchestrator {
    keys: Arc<dyn KeyRepository>,
    templates: Arc<dyn TemplateRegistry>,
    providers: Arc<ProviderRegistry>,
    policy: Arc<dyn Evaluator>,
}

impl KeyOrchestrator {
    pub fn new(
        keys: Arc<dyn KeyRepository>,
        templates: Arc<dyn TemplateRegistry>,
        providers: Arc<ProviderRegistry>,
        policy: Arc<dyn Evaluator>,
    ) -> Self {
        Self { keys, templates, providers, policy }
    }

    /// Go's CreateKey sequence: work out what the key needs from its
    /// provider (custody), pick a template the policy allows for the intent
    /// that a qualifying provider serves, check the policy allows creating a
    /// key with it, have the provider generate the material, store the key.
    pub fn create_key(&self, spec: KeyCreationSpec) -> Result<Key, Error> {
        const OP: &str = "KeyOrchestrator::create_key";
        if spec.name.is_empty() || spec.policy.is_empty() {
            return Err(Error::new(Code::InvalidArgument, OP, "key name and policy are required"));
        }
        // A request may add provider requirements but never relax the policy's.
        let implementation = self.policy.provider_requirements(&spec.policy)?.merge(&spec.provider_requirements);
        let custody = |template_id: &str| Requirements {
            template_id: template_id.to_owned(),
            pinned: spec.provider_id.clone(),
            implementation,
        };

        let template = match &spec.template_id {
            // Checked against the policy below, so that a disallowed template
            // is a policy violation rather than "no match".
            Some(id) => self.templates.select(&spec.scope_spec, &only_templates(vec![id.clone()]))?,
            // Only the policy's templates, in its order, and of those only
            // ones a qualifying provider serves.
            None => {
                let allowed = self.policy.allowed_templates(&spec.policy)?;
                let servable: Vec<String> =
                    allowed.iter().filter(|id| self.providers.select(&custody(id)).is_ok()).cloned().collect();
                match self.templates.select(&spec.scope_spec, &only_templates(servable)) {
                    Ok(t) => t,
                    // Say which half failed: no template for the intent, or
                    // templates but no provider that qualifies for any.
                    Err(e) if e.code() == Code::NoMatchingTemplate => {
                        let t = self.templates.select(&spec.scope_spec, &only_templates(allowed))?;
                        return Err(self.providers.select(&custody(t.id())).err().unwrap_or(e));
                    }
                    Err(e) => return Err(e),
                }
            }
        };

        self.policy.validate_operation(&spec.policy, Operation::CreateKey, Some(template.id()))?;
        self.policy.check_template_security(&spec.policy, &security_info(template, &spec))?;

        let provider = self.providers.select(&custody(template.id()))?;
        let algorithm = template.info().algorithm.as_ref().expect("templates always have an algorithm");
        let material = provider.generate_key(algorithm)?.to_bytes();

        let k = Key::new(
            KeyId::generate(),
            spec.name,
            1,
            template.id().into(),
            provider.name().into(),
            spec.policy,
            material,
            spec.scope_spec.scope.kind(),
        );
        // Known gap (as in Go): if storing fails after generation, nothing
        // undoes it. Harmless for stateless providers like rustcrypto; a
        // provider that keeps keys inside itself would need compensation.
        self.keys.create(k.clone())?;
        Ok(k)
    }
}

/// What the policy needs to know about the template, for this intent.
fn security_info(template: &Template, spec: &KeyCreationSpec) -> TemplateSecurityInfo {
    let sec = template.security_for(&spec.scope_spec).unwrap_or_default();
    TemplateSecurityInfo {
        template_id: template.id().to_owned(),
        status: template.status(),
        fips_approved: sec.fips_approved == Some(true),
        quantum_safe: sec.quantum_safe == Some(true),
        strength_bits: sec.strength_bits,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::providers::RustCrypto;
    use crate::adapters::storage::{InMemoryKeyRepository, InMemoryPolicyRepository, InMemoryTemplateRegistry};
    use crate::domain::core::{ProviderRequirements, Scope, ScopeSpecification};
    use crate::domain::policy::{Enforcer, Manager};
    use crate::domain::provider::{Backend, GeneratedKey, testing::FakeProvider};
    use crate::proto::api::{AeadScope, HashScope, SignatureScope};

    const AEAD: Scope = Scope::Aead(AeadScope::Standard);

    /// An orchestrator with the standard catalog, one policy "p", and the
    /// given providers.
    fn with_providers(policy_document: &str, providers: Vec<Arc<dyn Backend>>) -> KeyOrchestrator {
        let enforcer = Arc::new(Enforcer::new(Arc::new(InMemoryPolicyRepository::new())));
        enforcer.create_policy("p", policy_document).unwrap();
        let mut registry = ProviderRegistry::new();
        for p in providers {
            registry.register(p).unwrap();
        }
        KeyOrchestrator::new(
            Arc::new(InMemoryKeyRepository::new()),
            Arc::new(InMemoryTemplateRegistry::standard()),
            Arc::new(registry),
            enforcer,
        )
    }

    /// With the real rustcrypto provider.
    fn orchestrator(policy_document: &str) -> KeyOrchestrator {
        with_providers(policy_document, vec![Arc::new(RustCrypto)])
    }

    fn allowing(templates: &[&str], ops: &[&str]) -> String {
        format!(
            r#"{{"version": "1", "allowed_templates": {templates:?}, "allowed_operations": {{"key_operations": {ops:?}}}}}"#
        )
    }

    fn spec(name: &str, scope: Scope, template_id: Option<&str>) -> KeyCreationSpec {
        KeyCreationSpec {
            name: String::from(name),
            policy: String::from("p"),
            template_id: template_id.map(String::from),
            scope_spec: ScopeSpecification::any_of(scope),
            provider_id: None,
            provider_requirements: ProviderRequirements::default(),
        }
    }

    fn code(r: Result<Key, Error>) -> Code {
        r.unwrap_err().code()
    }

    #[test]
    fn the_policys_first_matching_template_is_chosen() {
        let ko = orchestrator(&allowing(&["chacha20-poly1305", "aes-256-gcm-128-96"], &["create_key"]));
        let k = ko.create_key(spec("my-key", AEAD, None)).unwrap();
        assert_eq!((k.get_name(), k.get_template_id(), k.get_policy()), ("my-key", "chacha20-poly1305", "p"));
        assert_eq!((k.get_version(), k.get_provider()), (1, "rustcrypto"));
        // The provider's material, stored as its opaque bytes.
        let material = GeneratedKey::from_bytes(k.get_material()).unwrap();
        assert_eq!(material.private.len(), 32);
    }

    #[test]
    fn same_name_twice_is_rejected() {
        let ko = orchestrator(&allowing(&["chacha20-poly1305"], &["create_key"]));
        ko.create_key(spec("my-key", AEAD, None)).unwrap();
        assert_eq!(code(ko.create_key(spec("my-key", AEAD, None))), Code::AlreadyExists);
    }

    #[test]
    fn nothing_allowed_for_the_intent_is_no_match() {
        let ko = orchestrator(&allowing(&["chacha20-poly1305"], &["create_key"]));
        let sig = Scope::Signature(SignatureScope::Standard);
        assert_eq!(code(ko.create_key(spec("k", sig, None))), Code::NoMatchingTemplate);
        assert_eq!(code(ko.create_key(spec("k", Scope::Hash(HashScope::Standard), None))), Code::NoMatchingTemplate);
    }

    #[test]
    fn an_explicit_template_the_policy_does_not_allow_is_a_violation() {
        let ko = orchestrator(&allowing(&["chacha20-poly1305"], &["create_key"]));
        assert_eq!(code(ko.create_key(spec("k", AEAD, Some("aes-256-gcm-128-96")))), Code::PolicyViolation);
        // An explicit template that does not serve the intent is still "no match".
        assert_eq!(code(ko.create_key(spec("k", AEAD, Some("hmac-sha256-256")))), Code::NoMatchingTemplate);
    }

    #[test]
    fn creating_keys_must_be_an_allowed_operation() {
        let ko = orchestrator(&allowing(&["chacha20-poly1305"], &["sign"]));
        assert_eq!(code(ko.create_key(spec("k", AEAD, None))), Code::PolicyViolation);
    }

    #[test]
    fn the_security_floor_applies() {
        let ko = orchestrator(
            r#"{"version": "1", "allowed_templates": ["chacha20-poly1305"],
                "allowed_operations": {"key_operations": ["create_key"]},
                "security_requirements": {"fips_approved": true}}"#,
        );
        assert_eq!(code(ko.create_key(spec("k", AEAD, None))), Code::PolicyViolation);
    }

    #[test]
    fn an_unknown_or_missing_policy_fails() {
        let ko = orchestrator("{}");
        let mut s = spec("k", AEAD, None);
        s.policy = "nope".into();
        assert_eq!(code(ko.create_key(s.clone())), Code::PolicyNotFound);
        s.policy = String::new();
        assert_eq!(code(ko.create_key(s)), Code::InvalidArgument);
    }

    // --- Providers ---

    const TWO_AEADS: &str = r#"{"version": "1", "allowed_templates": ["chacha20-poly1305", "aes-256-gcm-128-96"],
        "allowed_operations": {"key_operations": ["create_key"]}}"#;

    #[test]
    fn templates_no_qualifying_provider_serves_are_skipped() {
        // Only the second template has a provider.
        let ko = with_providers(TWO_AEADS, vec![Arc::new(FakeProvider::new("f", &["aes-256-gcm-128-96"]))]);
        let k = ko.create_key(spec("k", AEAD, None)).unwrap();
        assert_eq!((k.get_template_id(), k.get_provider()), ("aes-256-gcm-128-96", "f"));
    }

    #[test]
    fn requirements_merge_and_choose_the_provider() {
        let ko = with_providers(
            TWO_AEADS,
            vec![
                Arc::new(FakeProvider::new("plain", &["chacha20-poly1305"])),
                Arc::new(FakeProvider::new("ct", &["chacha20-poly1305"]).with(|i| i.constant_time = Some(true))),
            ],
        );
        assert_eq!(ko.create_key(spec("a", AEAD, None)).unwrap().get_provider(), "plain");
        let mut s = spec("b", AEAD, None);
        s.provider_requirements.constant_time = true;
        assert_eq!(ko.create_key(s).unwrap().get_provider(), "ct");
    }

    #[test]
    fn templates_without_a_qualifying_provider_say_so() {
        let ko = orchestrator(TWO_AEADS);
        let mut s = spec("k", AEAD, None);
        s.provider_requirements.min_fips_140_level = 3; // rustcrypto is not FIPS validated
        assert_eq!(code(ko.create_key(s)), Code::NoMatchingProvider);
    }

    #[test]
    fn a_pinned_provider_is_honoured_or_the_call_fails() {
        let ko = with_providers(
            TWO_AEADS,
            vec![Arc::new(RustCrypto), Arc::new(FakeProvider::new("other", &["chacha20-poly1305"]))],
        );
        let mut s = spec("a", AEAD, None);
        s.provider_id = Some("other".into());
        assert_eq!(ko.create_key(s.clone()).unwrap().get_provider(), "other");
        s.name = "b".into();
        s.provider_id = Some("nope".into());
        assert_eq!(code(ko.create_key(s.clone())), Code::ProviderNotFound);
        s.provider_id = Some("other".into());
        s.template_id = Some("aes-256-gcm-128-96".into());
        assert_eq!(code(ko.create_key(s)), Code::ProviderIncompatible);
    }

    #[test]
    fn orchestrator_is_shareable_across_threads() {
        fn assert_sync<T: Send + Sync>() {}
        assert_sync::<KeyOrchestrator>();
    }
}
