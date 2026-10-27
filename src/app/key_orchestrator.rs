use std::sync::Arc;
use std::time::SystemTime;

use super::KeyMetadata;
use crate::domain::core::{Code, Error, KeyCreationSpec, Operation, ScopeSpecification};
use crate::domain::key::*;
use crate::domain::policy::{Evaluator, TemplateSecurityInfo};
use crate::domain::provider::{GeneratedKey, ProviderRegistry, Requirements, transfer_of};
use crate::domain::template::*;

/// Runs the key lifecycle use cases. Holds no state of its own: everything
/// it touches is behind a shared domain interface, so one orchestrator serves
/// every thread of a context.
pub struct KeyOrchestrator {
    pub(super) keys: Arc<dyn KeyRepository>,
    pub(super) templates: Arc<dyn TemplateRegistry>,
    pub(super) providers: Arc<ProviderRegistry>,
    pub(super) policy: Arc<dyn Evaluator>,
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
    pub fn create_key(&self, spec: KeyCreationSpec) -> Result<KeyMetadata, Error> {
        self.create_key_admitting(spec, |_| Ok::<(), Error>(()))
    }

    /// `create_key` with a last check on the finished key before it is
    /// stored: if `admit` fails, nothing is stored and its error is returned.
    /// The C layer uses it to refuse a response region too small for the
    /// key's record before the key exists (agc_key_types.h, STORAGE
    /// CONTRACT for create operations).
    pub fn create_key_admitting<E: From<Error>>(
        &self,
        spec: KeyCreationSpec,
        admit: impl FnOnce(&KeyMetadata) -> Result<(), E>,
    ) -> Result<KeyMetadata, E> {
        const OP: &str = "KeyOrchestrator::create_key";
        if spec.name.is_empty() || spec.policy.is_empty() {
            return Err(Error::new(Code::InvalidArgument, OP, "key name and policy are required").into());
        }
        // A request may add provider requirements but never relax the policy's.
        let implementation = self.policy.provider_requirements(&spec.policy)?.merge(&spec.provider_requirements);
        let custody = |template_id: &str| Requirements {
            template_id: template_id.to_owned(),
            pinned: spec.provider_id.clone(),
            implementation,
        };

        let template = self.choose_template(&spec.policy, spec.template_id.as_deref(), &spec.scope_spec, &custody)?;

        self.policy.validate_operation(&spec.policy, Operation::CreateKey, Some(template.id()))?;
        self.policy.check_template_security(&spec.policy, &security_info(template, &spec.scope_spec))?;

        let provider = self.providers.select(&custody(template.id()))?;
        let algorithm = template.info().algorithm.as_ref().expect("templates always have an algorithm");
        let material = provider.generate_key(algorithm)?.to_bytes();
        let provenance = Provenance {
            extractable: transfer_of(provider.as_ref(), algorithm).releases_material(),
            approved_lineage: approved(provider.as_ref()),
            origin: Origin::Generated,
        };
        let first = Version::new(
            1,
            template.id().into(),
            provider.name().into(),
            spec.scope_spec,
            material,
            provenance,
            SystemTime::now(),
        );
        let k = Key::new(KeyId::generate(), &spec.name, &spec.policy, first)?;
        let metadata = KeyMetadata::of(&k, k.current(), &self.providers);
        admit(&metadata)?;
        // Known gap (as in Go): if storing fails after generation, nothing
        // undoes it. Harmless for stateless providers like rustcrypto; a
        // provider that keeps keys inside itself would need compensation.
        self.keys.create(k)?;
        Ok(metadata)
    }

    /// A new version of a key under another template for the same intent, on
    /// the same provider: algorithm agility (Go: TransformKey). Moving a key
    /// to another provider is `migrate_key`.
    ///
    /// The material is regenerated, or with `retain` kept, if the target
    /// template uses the same kind of key material. `admit` is checked
    /// before anything is stored, as for `create_key_admitting`.
    pub fn transform_key_admitting<E: From<Error>>(
        &self,
        spec: TransformSpec,
        admit: impl FnOnce(&KeyMetadata) -> Result<(), E>,
    ) -> Result<KeyMetadata, E> {
        let plan = self.plan_transform(spec)?;
        let TransformPlan { mut key, template_id, provider, scope_spec, retained } = plan;
        let template = self.templates.get(&template_id).expect("planned with this template");
        let algorithm = template.info().algorithm.as_ref().expect("templates always have an algorithm");
        let current = key.current().clone();
        let (material, provenance) = match retained {
            Some(provenance) => (zeroize::Zeroizing::new(current.material().to_vec()), provenance),
            None => (
                provider.generate_key(algorithm)?.to_bytes(),
                Provenance {
                    extractable: transfer_of(provider.as_ref(), algorithm).releases_material(),
                    approved_lineage: approved(provider.as_ref()),
                    origin: Origin::Generated,
                },
            ),
        };
        let next = Version::new(
            current.number() + 1,
            template_id,
            provider.name().into(),
            scope_spec,
            material,
            provenance,
            SystemTime::now(),
        );
        key.add_version(next)?;
        let metadata = KeyMetadata::of(&key, key.current(), &self.providers);
        admit(&metadata)?;
        // Fails with CONCURRENT_ACCESS if the key changed since it was read.
        self.keys.update(key)?;
        Ok(metadata)
    }

    /// Everything a transform checks, with no side effect: what
    /// `transform_key` would do, or why it cannot. Generates no material.
    pub fn plan_transform(&self, spec: TransformSpec) -> Result<TransformPlan, Error> {
        const OP: &str = "KeyOrchestrator::transform_key";
        let k = self.keys.get_by_name(&spec.key_name)?.ok_or_else(|| not_found(OP, &spec.key_name))?;
        k.can_originate()?;
        let current = k.current().clone();

        // A transform keeps the key's scope; without a specification, the one
        // the current version was created for applies.
        let scope_spec = match spec.scope_spec {
            None => current.scope_spec().clone(),
            Some(mut s) => {
                if s.scope.kind() == current.scope_spec().scope.kind() && s.scope.is_any() {
                    s.scope = current.scope_spec().scope;
                }
                if s.scope != current.scope_spec().scope {
                    return Err(Error::new(
                        Code::IncompatibleParameters,
                        OP,
                        format!("a transform keeps the key's scope ({:?})", current.scope_spec().scope),
                    ));
                }
                s
            }
        };
        if spec.retain && spec.template_id.is_none() {
            return Err(Error::new(Code::InvalidArgument, OP, "retaining the material needs an explicit template"));
        }

        // Custody: the current provider, under the policy's requirements.
        let implementation = self.policy.provider_requirements(k.policy())?;
        let custody = |template_id: &str| Requirements {
            template_id: template_id.to_owned(),
            pinned: Some(current.provider().to_owned()),
            implementation,
        };
        let template = self.choose_template(k.policy(), spec.template_id.as_deref(), &scope_spec, &custody)?;
        self.policy.validate_operation(k.policy(), Operation::CreateKey, Some(template.id()))?;
        self.policy.check_template_security(k.policy(), &security_info(template, &scope_spec))?;
        let provider = self.providers.select(&custody(template.id()))?;
        let algorithm = template.info().algorithm.as_ref().expect("templates always have an algorithm");

        let retained = if spec.retain {
            let source = self.templates.get(current.template_id()).ok_or_else(|| {
                Error::new(Code::TemplateNotFound, OP, format!("the key's template {} is gone", current.template_id()))
            })?;
            let source_algorithm = source.info().algorithm.as_ref().expect("templates always have an algorithm");
            if material_profile(source_algorithm)? != material_profile(algorithm)? {
                return Err(Error::new(
                    Code::IncompatibleParameters,
                    OP,
                    format!("{} cannot use the key material of {}", template.id(), source.id()),
                ));
            }
            // The provider must take the stored material for the new template
            // (Go: retainFeasibility).
            let encoding = GeneratedKey::from_bytes(current.material())?.private_encoding;
            if !transfer_of(provider.as_ref(), algorithm).accept.stored_payload.contains(&encoding) {
                return Err(Error::new(
                    Code::IncompatibleParameters,
                    OP,
                    format!("provider {} does not take {encoding:?} material for {}", provider.name(), template.id()),
                ));
            }
            // Kept material carries its history: it never regains
            // extractability or an approved lineage it lost.
            let was = current.provenance();
            if implementation.approved_generation && !was.approved_lineage {
                return Err(Error::new(
                    Code::PolicyViolation,
                    OP,
                    "the policy requires material of approved lineage; this key's material is not",
                ));
            }
            Some(Provenance {
                extractable: was.extractable && transfer_of(provider.as_ref(), algorithm).releases_material(),
                approved_lineage: was.approved_lineage && approved(provider.as_ref()),
                origin: Origin::Retained { source_version: current.number() },
            })
        } else {
            None
        };
        Ok(TransformPlan { template_id: template.id().to_owned(), provider, scope_spec, retained, key: k })
    }

    pub fn transform_key(&self, spec: TransformSpec) -> Result<KeyMetadata, Error> {
        self.transform_key_admitting(spec, |_| Ok::<(), Error>(()))
    }

    /// The template for a new version: an explicit one (checked against the
    /// policy by the caller, so that a disallowed template is a violation
    /// rather than "no match"), or the first of the policy's templates, in
    /// its order, that serves the intent and that a provider meeting
    /// `custody` serves. When templates serve the intent but no provider
    /// qualifies for any, the error says so.
    fn choose_template(
        &self,
        policy: &str,
        template_id: Option<&str>,
        scope_spec: &ScopeSpecification,
        custody: &dyn Fn(&str) -> Requirements,
    ) -> Result<&Template, Error> {
        if let Some(id) = template_id {
            return self.templates.select(scope_spec, &only_templates(vec![id.to_owned()]));
        }
        let allowed = self.policy.allowed_templates(policy)?;
        let servable: Vec<String> =
            allowed.iter().filter(|id| self.providers.select(&custody(id)).is_ok()).cloned().collect();
        match self.templates.select(scope_spec, &only_templates(servable)) {
            Err(e) if e.code() == Code::NoMatchingTemplate => {
                let t = self.templates.select(scope_spec, &only_templates(allowed))?;
                Err(self.providers.select(&custody(t.id())).err().unwrap_or(e))
            }
            other => other,
        }
    }

    /// One version of a key; `None` is the current one (Go: ReadKey). Reading
    /// metadata involves no key material, so, as in Go, it is not a policy
    /// decision.
    pub fn read_key(&self, name: &str, version: Option<u32>) -> Result<KeyMetadata, Error> {
        const OP: &str = "KeyOrchestrator::read_key";
        let k = self.keys.get_by_name(name)?.ok_or_else(|| not_found(OP, name))?;
        let v = match version {
            None => k.current(),
            Some(n) => k
                .version(n)
                .ok_or_else(|| Error::new(Code::KeyNotFound, OP, format!("key {name} has no version {n}")))?,
        };
        Ok(KeyMetadata::of(&k, v, &self.providers))
    }

    /// The current version of every key that passes `filter`, ordered by
    /// name (Go: ListKeys, with the C API's filters).
    pub fn list_keys(&self, filter: &KeyFilter) -> Result<Vec<KeyMetadata>, Error> {
        Ok(self
            .keys
            .list()?
            .iter()
            .filter(|k| filter.admits(k))
            .map(|k| KeyMetadata::of(k, k.current(), &self.providers))
            .collect())
    }
}

/// Which keys a listing returns; every field narrows, `None` admits all.
#[derive(Debug, Clone, Default)]
pub struct KeyFilter {
    /// The current version must serve this intent.
    pub scope_spec: Option<ScopeSpecification>,
    pub provider: Option<String>,
    pub policy: Option<String>,
    pub state: Option<crate::proto::api::KeyLifecycleState>,
}

impl KeyFilter {
    fn admits(&self, k: &Key) -> bool {
        let v = k.current();
        self.scope_spec.as_ref().is_none_or(|want| v.scope_spec().satisfies(want))
            && self.provider.as_deref().is_none_or(|p| v.provider() == p)
            && self.policy.as_deref().is_none_or(|p| k.policy() == p)
            && self.state.is_none_or(|s| k.state() == s)
    }
}

pub(super) fn not_found(op: &'static str, name: &str) -> Error {
    Error::new(Code::KeyNotFound, op, format!("no key named {name}"))
}

/// A checked transform, ready to run: the key as read, the target, and for
/// retained material its provenance.
pub struct TransformPlan {
    key: Key,
    template_id: String,
    provider: Arc<dyn crate::domain::provider::Backend>,
    scope_spec: ScopeSpecification,
    retained: Option<Provenance>,
}

/// What a transform asks for (Go: TransformKeySpec).
#[derive(Debug, Clone)]
pub struct TransformSpec {
    pub key_name: String,
    /// Keep the current material instead of generating new material.
    pub retain: bool,
    /// The intent; `None` keeps the current version's.
    pub scope_spec: Option<ScopeSpecification>,
    pub template_id: Option<String>,
}

/// Whether a provider is an approved (FIPS-validated) module, so that the
/// material it generates or holds keeps an approved lineage.
pub(super) fn approved(provider: &dyn crate::domain::provider::Backend) -> bool {
    let approved_generation =
        crate::domain::core::ProviderRequirements { approved_generation: true, ..Default::default() };
    crate::domain::provider::unmet(&provider.implementation(), &approved_generation).is_empty()
}

/// What the policy needs to know about the template, for this intent.
pub(super) fn security_info(template: &Template, scope_spec: &ScopeSpecification) -> TemplateSecurityInfo {
    let sec = template.security_for(scope_spec).unwrap_or_default();
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

    fn code(r: Result<KeyMetadata, Error>) -> Code {
        r.unwrap_err().code()
    }

    #[test]
    fn the_policys_first_matching_template_is_chosen() {
        let ko = orchestrator(&allowing(&["chacha20-poly1305", "aes-256-gcm-128-96"], &["create_key"]));
        let k = ko.create_key(spec("my-key", AEAD, None)).unwrap();
        assert_eq!((k.name.as_str(), k.template_id.as_str(), k.policy.as_str()), ("my-key", "chacha20-poly1305", "p"));
        assert_eq!((k.version, k.provider.as_str()), (1, "rustcrypto"));
        assert!(k.extractable && k.public_key.is_none());
        // The provider's material, stored as its opaque bytes.
        let stored = ko.keys.get_by_name("my-key").unwrap().unwrap();
        let material = GeneratedKey::from_bytes(stored.current().material()).unwrap();
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
        assert_eq!((k.template_id.as_str(), k.provider.as_str()), ("aes-256-gcm-128-96", "f"));
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
        assert_eq!(ko.create_key(spec("a", AEAD, None)).unwrap().provider, "plain");
        let mut s = spec("b", AEAD, None);
        s.provider_requirements.constant_time = true;
        assert_eq!(ko.create_key(s).unwrap().provider, "ct");
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
        assert_eq!(ko.create_key(s.clone()).unwrap().provider, "other");
        s.name = "b".into();
        s.provider_id = Some("nope".into());
        assert_eq!(code(ko.create_key(s.clone())), Code::ProviderNotFound);
        s.provider_id = Some("other".into());
        s.template_id = Some("aes-256-gcm-128-96".into());
        assert_eq!(code(ko.create_key(s)), Code::ProviderIncompatible);
    }

    // --- Reading and listing ---

    const SIGS_AND_AEAD: &str = r#"{"version": "1",
        "allowed_templates": ["chacha20-poly1305", "ed25519", "ml-dsa-65"],
        "allowed_operations": {"key_operations": ["create_key"]}}"#;

    #[test]
    fn an_admit_failure_stores_nothing() {
        let ko = orchestrator(SIGS_AND_AEAD);
        let refused = ko.create_key_admitting(spec("k", AEAD, None), |_| Err(Error::new(Code::Internal, "test", "no")));
        assert_eq!(code(refused), Code::Internal);
        assert_eq!(code(ko.read_key("k", None)), Code::KeyNotFound);
        ko.create_key(spec("k", AEAD, None)).unwrap(); // the name is still free
    }

    #[test]
    fn reading_returns_the_public_key_and_implementation() {
        let ko = orchestrator(SIGS_AND_AEAD);
        ko.create_key(spec("sig", Scope::Signature(SignatureScope::Standard), None)).unwrap();
        let k = ko.read_key("sig", None).unwrap();
        assert_eq!((k.template_id.as_str(), k.version), ("ed25519", 1));
        let (public, enc) = k.public_key.unwrap();
        assert_eq!((public.len(), enc), (44, crate::domain::provider::Encoding::SpkiDer)); // SPKI of Ed25519
        assert_eq!(k.implementation.memory_safe_language, Some(true));
        assert_eq!(ko.read_key("sig", Some(1)).unwrap().version, 1);
        assert_eq!(code(ko.read_key("sig", Some(2))), Code::KeyNotFound);
        assert_eq!(code(ko.read_key("nope", None)), Code::KeyNotFound);
    }

    #[test]
    fn listing_filters_and_orders_by_name() {
        let ko = orchestrator(SIGS_AND_AEAD);
        ko.create_key(spec("b-sig", Scope::Signature(SignatureScope::Standard), None)).unwrap();
        ko.create_key(spec("a-aead", AEAD, None)).unwrap();
        let names = |f: &KeyFilter| ko.list_keys(f).unwrap().into_iter().map(|k| k.name).collect::<Vec<_>>();

        assert_eq!(names(&KeyFilter::default()), ["a-aead", "b-sig"]);
        let sigs = KeyFilter {
            scope_spec: Some(ScopeSpecification::any_of(Scope::Signature(SignatureScope::Unspecified))),
            ..Default::default()
        };
        assert_eq!(names(&sigs), ["b-sig"]);
        assert!(names(&KeyFilter { policy: Some("other".into()), ..Default::default() }).is_empty());
        assert_eq!(names(&KeyFilter { provider: Some("rustcrypto".into()), ..Default::default() }).len(), 2);
    }

    // --- Transform ---

    const AGILE: &str = r#"{"version": "1",
        "allowed_templates": ["chacha20-poly1305", "xchacha20-poly1305", "aes-128-gcm-128-96",
                              "aes-256-gcm-128-96", "ecdsa-p256-sha256-der", "ed25519"],
        "allowed_operations": {"key_operations": ["create_key"]}}"#;

    fn transform(name: &str, template: Option<&str>, retain: bool) -> TransformSpec {
        TransformSpec { key_name: name.into(), retain, scope_spec: None, template_id: template.map(String::from) }
    }

    #[test]
    fn transform_adds_a_version_under_another_template() {
        let ko = orchestrator(AGILE);
        ko.create_key(spec("sig", Scope::Signature(SignatureScope::Standard), None)).unwrap();
        let t = ko.transform_key(transform("sig", Some("ed25519"), false)).unwrap();
        assert_eq!((t.version, t.template_id.as_str(), t.provider.as_str()), (2, "ed25519", "rustcrypto"));

        // Both versions stay readable: old signatures name version 1.
        assert_eq!(ko.read_key("sig", Some(1)).unwrap().template_id, "ecdsa-p256-sha256-der");
        assert_eq!(ko.read_key("sig", None).unwrap().version, 2);
        let stored = ko.keys.get_by_name("sig").unwrap().unwrap();
        assert_eq!(stored.current().provenance().origin, Origin::Generated);
        assert_ne!(stored.version(1).unwrap().material(), stored.current().material());
    }

    #[test]
    fn without_a_template_the_policys_first_choice_is_taken() {
        let ko = orchestrator(AGILE);
        ko.create_key(spec("k", AEAD, Some("aes-256-gcm-128-96"))).unwrap();
        assert_eq!(ko.transform_key(transform("k", None, false)).unwrap().template_id, "chacha20-poly1305");
    }

    #[test]
    fn compatible_material_can_be_retained() {
        let ko = orchestrator(AGILE);
        ko.create_key(spec("k", AEAD, Some("chacha20-poly1305"))).unwrap();
        let t = ko.transform_key(transform("k", Some("xchacha20-poly1305"), true)).unwrap();
        assert_eq!(t.template_id, "xchacha20-poly1305");
        let stored = ko.keys.get_by_name("k").unwrap().unwrap();
        assert_eq!(stored.version(1).unwrap().material(), stored.current().material());
        assert_eq!(stored.current().provenance().origin, Origin::Retained { source_version: 1 });
        assert!(stored.current().provenance().extractable);
    }

    #[test]
    fn incompatible_retention_and_missing_template_are_refused() {
        let ko = orchestrator(AGILE);
        ko.create_key(spec("k", AEAD, Some("aes-128-gcm-128-96"))).unwrap();
        assert_eq!(code(ko.transform_key(transform("k", Some("aes-256-gcm-128-96"), true))), Code::IncompatibleParameters);
        assert_eq!(code(ko.transform_key(transform("k", None, true))), Code::InvalidArgument);
        assert_eq!(ko.read_key("k", None).unwrap().version, 1, "nothing was added");
    }

    #[test]
    fn a_transform_keeps_the_scope() {
        let ko = orchestrator(AGILE);
        ko.create_key(spec("k", AEAD, None)).unwrap();
        let mut t = transform("k", Some("ed25519"), false);
        t.scope_spec = Some(ScopeSpecification::any_of(Scope::Signature(SignatureScope::Standard)));
        assert_eq!(code(ko.transform_key(t)), Code::IncompatibleParameters);
        // "Any AEAD scope" means the key's own scope.
        let mut t = transform("k", None, false);
        t.scope_spec = Some(ScopeSpecification::any_of(Scope::Aead(AeadScope::Unspecified)));
        assert_eq!(ko.transform_key(t).unwrap().version, 2);
    }

    #[test]
    fn the_policy_governs_transforms_too() {
        let ko = orchestrator(AGILE);
        ko.create_key(spec("k", AEAD, None)).unwrap();
        assert_eq!(code(ko.transform_key(transform("k", Some("aes-192-gcm-128-96"), false))), Code::PolicyViolation);
        assert_eq!(code(ko.transform_key(transform("nope", None, false))), Code::KeyNotFound);
    }

    #[test]
    fn only_an_active_key_is_transformed() {
        let ko = orchestrator(AGILE);
        ko.create_key(spec("k", AEAD, None)).unwrap();
        let mut stored = ko.keys.get_by_name("k").unwrap().unwrap();
        stored.transition(crate::proto::api::KeyLifecycleState::Suspended, SystemTime::now()).unwrap();
        ko.keys.update(stored).unwrap();
        assert_eq!(code(ko.transform_key(transform("k", None, false))), Code::KeyOperationNotAllowed);
    }

    #[test]
    fn an_admit_failure_adds_no_version() {
        let ko = orchestrator(AGILE);
        ko.create_key(spec("k", AEAD, None)).unwrap();
        let refused =
            ko.transform_key_admitting(transform("k", None, false), |_| Err(Error::new(Code::Internal, "test", "no")));
        assert_eq!(code(refused), Code::Internal);
        assert_eq!(ko.read_key("k", None).unwrap().version, 1);
    }

    #[test]
    fn orchestrator_is_shareable_across_threads() {
        fn assert_sync<T: Send + Sync>() {}
        assert_sync::<KeyOrchestrator>();
    }
}
