use crate::domain::core::{Code, Error};
use crate::domain::template::*;

/// The catalog compiled into the library (catalog/PROVENANCE.md).
const STANDARD_CATALOG: &str = include_str!("../../../catalog/standard_algorithms.json");

/// The template catalog held in process memory, in registration order.
pub struct InMemoryTemplateRegistry {
    templates: Vec<Template>,
}

impl InMemoryTemplateRegistry {
    pub fn new() -> Self {
        InMemoryTemplateRegistry { templates: Vec::new() }
    }

    /// The registry filled from a catalog in JSON.
    pub fn from_catalog(json: &str) -> Result<Self, Error> {
        let mut r = Self::new();
        for t in parse_catalog(json)? {
            r.register(t)?;
        }
        Ok(r)
    }

    /// The registry filled from the compiled-in standard catalog.
    pub fn standard() -> Self {
        Self::from_catalog(STANDARD_CATALOG).expect("the compiled-in catalog is valid (tested)")
    }
}

impl TemplateRegistry for InMemoryTemplateRegistry {
    fn register(&mut self, t: Template) -> Result<(), Error> {
        if self.get(t.id()).is_some() {
            return Err(Error::new(
                Code::AlreadyExists,
                "InMemoryTemplateRegistry.register",
                format!("template {} exists", t.id()),
            ));
        }
        self.templates.push(t);
        Ok(())
    }

    fn get(&self, id: &str) -> Option<&Template> {
        self.templates.iter().find(|t| t.id() == id)
    }

    fn list(&self) -> Vec<&Template> {
        self.templates.iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::core::{Scope, ScopeSpecification};
    use crate::domain::template::testing::template;
    use crate::proto::api::{AeadScope, KemScope, SignatureScope, TemplateStatus};

    const AEAD: Scope = Scope::Aead(AeadScope::Standard);

    fn want(scope: Scope) -> ScopeSpecification {
        ScopeSpecification::any_of(scope)
    }

    fn registry(templates: &[(&str, Scope, TemplateStatus)]) -> InMemoryTemplateRegistry {
        let mut r = InMemoryTemplateRegistry::new();
        for &(id, scope, status) in templates {
            r.register(template(id, scope, status)).unwrap();
        }
        r
    }

    fn code(r: Result<&Template, Error>) -> Code {
        r.unwrap_err().code()
    }

    #[test]
    fn selects_restricted_and_unrestricted() {
        let r = registry(&[("aead", AEAD, TemplateStatus::Active)]);
        assert_eq!(r.select(&want(AEAD), &only_templates(vec!["aead".into()])).unwrap().id(), "aead");
        assert_eq!(r.select(&want(AEAD), &all_templates()).unwrap().id(), "aead");
    }

    #[test]
    fn empty_restriction_selects_nothing() {
        let r = registry(&[("aead", AEAD, TemplateStatus::Active)]);
        assert_eq!(code(r.select(&want(AEAD), &only_templates(vec![]))), Code::NoMatchingTemplate);
    }

    #[test]
    fn restricted_set_excludes_other_ids() {
        let r = registry(&[("aead", AEAD, TemplateStatus::Active)]);
        assert_eq!(code(r.select(&want(AEAD), &only_templates(vec!["other".into()]))), Code::TemplateNotFound);
        assert_eq!(
            code(r.select(&want(AEAD), &only_templates(vec!["x".into(), "y".into()]))),
            Code::NoMatchingTemplate
        );
    }

    #[test]
    fn restricted_order_is_the_preference_order() {
        let r = registry(&[("a", AEAD, TemplateStatus::Active), ("b", AEAD, TemplateStatus::Active)]);
        let picked = r.select(&want(AEAD), &only_templates(vec!["b".into(), "a".into()])).unwrap();
        assert_eq!(picked.id(), "b");
        assert_eq!(r.select(&want(AEAD), &all_templates()).unwrap().id(), "a");
    }

    #[test]
    fn wrong_kind_does_not_match() {
        let r = registry(&[("aead", AEAD, TemplateStatus::Active)]);
        assert_eq!(code(r.select(&want(Scope::Kem(KemScope::Standard)), &all_templates())), Code::NoMatchingTemplate);
    }

    #[test]
    fn unselectable_templates_are_skipped() {
        let r = registry(&[("old", AEAD, TemplateStatus::Deprecated), ("new", AEAD, TemplateStatus::Active)]);
        assert_eq!(r.select(&want(AEAD), &all_templates()).unwrap().id(), "new");
    }

    #[test]
    fn naming_a_deprecated_or_forbidden_template_says_so() {
        let r = registry(&[("old", AEAD, TemplateStatus::Deprecated), ("bad", AEAD, TemplateStatus::Forbidden)]);
        assert_eq!(code(r.select(&want(AEAD), &only_templates(vec!["old".into()]))), Code::TemplateDeprecated);
        assert_eq!(code(r.select(&want(AEAD), &only_templates(vec!["bad".into()]))), Code::TemplateForbidden);
        // ...but only if it would have served the intent at all.
        let sig = want(Scope::Signature(SignatureScope::Standard));
        assert_eq!(code(r.select(&sig, &only_templates(vec!["old".into()]))), Code::NoMatchingTemplate);
    }

    #[test]
    fn duplicate_register_is_rejected_and_first_kept() {
        let mut r = registry(&[("t", AEAD, TemplateStatus::Active)]);
        let second = r.register(template("t", Scope::Signature(SignatureScope::Standard), TemplateStatus::Active));
        assert_eq!(second.unwrap_err().code(), Code::AlreadyExists);
        assert!(r.get("t").unwrap().matches(&want(AEAD)));
    }

    #[test]
    fn empty_registry_does_not_match() {
        let r = InMemoryTemplateRegistry::new();
        assert_eq!(code(r.select(&want(AEAD), &all_templates())), Code::NoMatchingTemplate);
    }

    // Against the compiled-in catalog.

    #[test]
    fn standard_catalog_loads_every_template() {
        assert_eq!(InMemoryTemplateRegistry::standard().list().len(), 72);
    }

    #[test]
    fn standard_catalog_serves_the_documented_intents() {
        let r = InMemoryTemplateRegistry::standard();
        let pick = |scope| r.select(&want(scope), &all_templates()).map(|t| t.id().to_owned());
        assert_eq!(pick(AEAD).unwrap(), "aes-128-gcm-128-96");
        assert_eq!(pick(Scope::Kem(KemScope::Standard)).unwrap(), "ml-kem-1024");
        assert!(pick(Scope::Signature(SignatureScope::Prehashed)).unwrap().contains("prehashed"));
        // The catalog has no hash templates.
        let hash = Scope::Hash(crate::proto::api::HashScope::Standard);
        assert_eq!(pick(hash).unwrap_err().code(), Code::NoMatchingTemplate);
    }

    #[test]
    fn security_requirements_narrow_the_choice() {
        use crate::domain::core::SecurityProperties;
        let r = InMemoryTemplateRegistry::standard();
        let mut quantum_safe = want(Scope::Signature(SignatureScope::Standard));
        quantum_safe.security = Some(SecurityProperties { quantum_safe: Some(true), ..Default::default() });
        let t = r.select(&quantum_safe, &all_templates()).unwrap();
        let offers_it = t.capabilities().iter().any(|c| c.spec.security.and_then(|s| s.quantum_safe) == Some(true));
        assert!(offers_it, "{} is not quantum safe", t.id());
        // Without the requirement, the first signature template is a classical one.
        let any = r.select(&want(Scope::Signature(SignatureScope::Standard)), &all_templates()).unwrap();
        assert_eq!(any.id(), "ecdsa-p256-sha256-der");
    }
}
