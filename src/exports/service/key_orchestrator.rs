// use crate::bindings::*;

use crate::bindings::*;
use crate::exports::error::Error::{self};
use crate::exports::key::*;
use crate::exports::template::*;

// TODO: Toy definitions. Replace them by correct ones later
pub struct ProviderRegistry {}
pub struct PolicyEngine {}

pub struct KeyOrchestrator {
    repo: InMemoryRepository,
    templates: InMemoryRegistry,
    providers: ProviderRegistry,
    policy: PolicyEngine,
}

// TODO: Where is this orchestrator ever constructed?
impl KeyOrchestrator {
    pub fn new(providers: ProviderRegistry, policy: PolicyEngine) -> Self {
        Self {
            repo: InMemoryRepository::new(),
            templates: InMemoryRegistry::with_defaults(),
            providers,
            policy,
        }
    }

    pub fn create_key(&mut self, spec: KeyCreationSpec) -> Result<&Key, Error> {
        let template = match spec.template_id {
            Some(tid) => self
                .templates
                .select(spec.scope_kind, &only_templates(vec![tid]))?,
            None => self.templates.select(spec.scope_kind, &all_templates())?,
        };
        let material = vec![0u8; 32]; // TODO replace by real creation.
        let id = self.repo.next_free_key_id();
        let k = Key::new(
            id.clone(),
            spec.name,
            1,
            template.get_id().into(),
            "stub".into(),
            spec.policy,
            material,
            spec.scope_kind
        );
        self.repo.create(k)?;
        Ok(self.repo.get_by_id(&id).expect("Key was just inserted"))
    }
}

pub struct KeyCreationSpec {
    pub name: String,
    pub policy: String,
    pub template_id: Option<String>,
    pub scope_kind: agc_scope_kind,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exports::error::Error::{AlreadyExists, NoMatchingTemplate};

    fn orchestrator() -> KeyOrchestrator {
        KeyOrchestrator::new(ProviderRegistry {}, PolicyEngine {})
    }

    fn spec(name: &str, kind: agc_scope_kind, template_id: Option<&str>) -> KeyCreationSpec {
        KeyCreationSpec {
            name: String::from(name),
            policy: String::from("default"),
            template_id: template_id.map(String::from),
            scope_kind: kind,
        }
    }

    #[test]
    fn aead_without_template_id_uses_default() {
        let mut ko = orchestrator();
        let k = ko
            .create_key(spec("my-key", agc_scope_kind_AGC_SCOPE_KIND_AEAD, None))
            .expect("AEAD key should be created");
        assert_eq!(k.get_name(), "my-key");
        assert_eq!(k.get_template_id(), "aes-256-gcm");
        assert_eq!(k.get_version(), 1);
        assert_eq!(k.get_policy(), "default");
    }

    #[test]
    fn same_name_twice_is_rejected() {
        let mut ko = orchestrator();
        // `.unwrap();` drops the returned &Key, so `ko` is no longer borrowed afterwards.
        ko.create_key(spec("my-key", agc_scope_kind_AGC_SCOPE_KIND_AEAD, None))
            .unwrap();
        let second = ko.create_key(spec("my-key", agc_scope_kind_AGC_SCOPE_KIND_AEAD, None));
        assert!(matches!(second, Err(AlreadyExists)));
    }

    #[test]
    fn explicit_template_of_wrong_kind_does_not_match() {
        let mut ko = orchestrator();
        let r = ko.create_key(spec(
            "my-key",
            agc_scope_kind_AGC_SCOPE_KIND_AEAD,
            Some("hmac-sha256"),
        ));
        assert!(matches!(r, Err(NoMatchingTemplate)));
    }

    #[test]
    fn kind_without_default_template_does_not_match() {
        let mut ko = orchestrator();
        let r = ko.create_key(spec("my-key", agc_scope_kind_AGC_SCOPE_KIND_KEM, None));
        assert!(matches!(r, Err(NoMatchingTemplate)));
    }
}
