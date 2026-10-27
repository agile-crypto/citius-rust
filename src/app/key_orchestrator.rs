use std::sync::Arc;

use crate::domain::core::{Error, KeyCreationSpec};
use crate::domain::key::*;
use crate::domain::template::*;

/// Runs the key lifecycle use cases. Holds no state of its own: everything
/// it touches is behind a shared domain interface, so one orchestrator serves
/// every thread of a context.
pub struct KeyOrchestrator {
    keys: Arc<dyn KeyRepository>,
    templates: Arc<dyn TemplateRegistry>,
}

impl KeyOrchestrator {
    pub fn new(keys: Arc<dyn KeyRepository>, templates: Arc<dyn TemplateRegistry>) -> Self {
        Self { keys, templates }
    }

    pub fn create_key(&self, spec: KeyCreationSpec) -> Result<Key, Error> {
        let candidates = match spec.template_id {
            Some(tid) => only_templates(vec![tid]),
            None => all_templates(),
        };
        let template = self.templates.select(&spec.scope_spec, &candidates)?;
        let material = vec![0u8; 32]; // TODO replace by real creation.
        let k = Key::new(
            KeyId::generate(),
            spec.name,
            1,
            template.id().into(),
            "stub".into(),
            spec.policy,
            material,
            spec.scope_spec.scope.kind(),
        );
        self.keys.create(k.clone())?;
        Ok(k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::storage::{InMemoryKeyRepository, InMemoryTemplateRegistry};
    use crate::domain::core::{Code, Scope, ScopeSpecification};
    use crate::proto::api::{AeadScope, HashScope};

    fn orchestrator() -> KeyOrchestrator {
        KeyOrchestrator::new(
            Arc::new(InMemoryKeyRepository::new()),
            Arc::new(InMemoryTemplateRegistry::standard()),
        )
    }

    const AEAD: Scope = Scope::Aead(AeadScope::Standard);

    fn spec(name: &str, scope: Scope, template_id: Option<&str>) -> KeyCreationSpec {
        KeyCreationSpec {
            name: String::from(name),
            policy: String::from("default"),
            template_id: template_id.map(String::from),
            scope_spec: ScopeSpecification::any_of(scope),
        }
    }

    #[test]
    fn aead_without_template_id_uses_default() {
        let ko = orchestrator();
        let k = ko
            .create_key(spec("my-key", AEAD, None))
            .expect("AEAD key should be created");
        assert_eq!(k.get_name(), "my-key");
        assert_eq!(k.get_template_id(), "aes-128-gcm-128-96");
        assert_eq!(k.get_version(), 1);
        assert_eq!(k.get_policy(), "default");
    }

    #[test]
    fn same_name_twice_is_rejected() {
        let ko = orchestrator();
        ko.create_key(spec("my-key", AEAD, None)).unwrap();
        let second = ko.create_key(spec("my-key", AEAD, None));
        assert_eq!(second.unwrap_err().code(), Code::AlreadyExists);
    }

    #[test]
    fn explicit_template_of_wrong_kind_does_not_match() {
        let ko = orchestrator();
        let r = ko.create_key(spec("my-key", AEAD, Some("hmac-sha256-256")));
        assert_eq!(r.unwrap_err().code(), Code::NoMatchingTemplate);
    }

    #[test]
    fn kind_without_default_template_does_not_match() {
        let ko = orchestrator();
        let r = ko.create_key(spec("my-key", Scope::Hash(HashScope::Standard), None));
        assert_eq!(r.unwrap_err().code(), Code::NoMatchingTemplate);
    }

    #[test]
    fn orchestrator_is_shareable_across_threads() {
        fn assert_sync<T: Send + Sync>() {}
        assert_sync::<KeyOrchestrator>();
    }
}
