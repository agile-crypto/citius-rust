use crate::domain::core::{Code, Error, ScopeKind};
use crate::domain::template::*;

/// The template catalog held in process memory.
pub struct InMemoryTemplateRegistry {
    templates: Vec<Template>,
}
impl InMemoryTemplateRegistry {
    fn new() -> Self {
        InMemoryTemplateRegistry {
            templates: Vec::new(),
        }
    }
    pub fn with_defaults() -> Self {
        let mut r = InMemoryTemplateRegistry::new();
        for (id, kind, algo) in [
            (
                "aes-256-gcm",
                ScopeKind::Aead,
                "AES-256-GCM",
            ),
            (
                "hmac-sha256",
                ScopeKind::Mac,
                "HMAC-SHA256",
            ),
            (
                "ed25519",
                ScopeKind::Signature,
                "Ed25519",
            ),
        ] {
            r.register(Template::new(id.into(), kind, algo.into(), true))
                .expect("Wrong default value");
        }
        r
    }
}
impl TemplateRegistry for InMemoryTemplateRegistry {
    fn register(&mut self, t: Template) -> Result<(), Error> {
        // check duplicates
        if self.get(t.get_id()).is_some() {
            return Err(Error::new(Code::AlreadyExists, "InMemoryTemplateRegistry.register", format!("template {} exists", t.get_id())));
        }
        self.templates.push(t);
        Ok(())
    }

    fn get(&self, id: &str) -> Option<&Template> {
        self.templates.iter().find(|x| x.get_id() == id)
    }

    fn select(&self, kind: ScopeKind, candidates: &CandidateSet) -> Result<&Template, Error> {
        self.templates
            .iter()
            .find(|x| candidates.allows(x.get_id()) && x.get_scope_kind() == kind && x.is_active())
            .ok_or_else(|| Error::new(Code::NoMatchingTemplate, "InMemoryTemplateRegistry.select", format!("no active template for {kind:?}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selects_aead() {
        let id = "aead_temp";
        let t = Template::new(
            String::from(id),
            ScopeKind::Aead,
            String::from("AES_GCM_SOMETHING"),
            true,
        );
        let mut r = InMemoryTemplateRegistry {
            templates: Vec::new(),
        };
        r.register(t).unwrap();
        let cs = &only_templates(vec![String::from("aead_temp")]);
        let found_t = r.select(ScopeKind::Aead, cs);
        assert_eq!(id, found_t.expect("should find AEAD template").get_id());
    }

    #[test]
    fn selects_aead_unrestricted() {
        let id = "aead_temp";
        let t = Template::new(
            String::from(id),
            ScopeKind::Aead,
            String::from("AES_GCM_SOMETHING"),
            true,
        );
        let mut r = InMemoryTemplateRegistry {
            templates: Vec::new(),
        };
        r.register(t).unwrap();
        let cs = &all_templates();
        let found_t = r.select(ScopeKind::Aead, cs);
        assert_eq!(id, found_t.expect("should find AEAD template").get_id());
    }

    #[test]
    fn no_matching_test() {
        let id = "aead_temp";
        let t = Template::new(
            String::from(id),
            ScopeKind::Aead,
            String::from("AES_GCM_SOMETHING"),
            true,
        );
        let mut r = InMemoryTemplateRegistry {
            templates: Vec::new(),
        };
        r.register(t).unwrap();
        let cs = &&only_templates(vec![]);
        let found_t = r.select(ScopeKind::Aead, cs);
        assert_eq!(found_t.unwrap_err().code(), Code::NoMatchingTemplate);
    }

    fn template(id: &str, kind: ScopeKind, active: bool) -> Template {
        Template::new(String::from(id), kind, String::from("SOME_ALGO"), active)
    }

    #[test]
    fn restricted_set_excludes_other_ids() {
        let mut r = InMemoryTemplateRegistry::new();
        r.register(template(
            "aead_temp",
            ScopeKind::Aead,
            true,
        ))
        .unwrap();
        let cs = only_templates(vec![String::from("other_temp")]);
        let found_t = r.select(ScopeKind::Aead, &cs);
        assert_eq!(found_t.unwrap_err().code(), Code::NoMatchingTemplate);
    }

    #[test]
    fn restricted_set_picks_allowed_among_several() {
        let mut r = InMemoryTemplateRegistry::new();
        r.register(template("aead_a", ScopeKind::Aead, true))
            .unwrap();
        r.register(template("aead_b", ScopeKind::Aead, true))
            .unwrap();
        let cs = only_templates(vec![String::from("aead_b")]);
        let found_t = r
            .select(ScopeKind::Aead, &cs)
            .expect("should find aead_b");
        assert_eq!(found_t.get_id(), "aead_b");
    }

    #[test]
    fn wrong_kind_does_not_match() {
        let mut r = InMemoryTemplateRegistry::new();
        r.register(template(
            "aead_temp",
            ScopeKind::Aead,
            true,
        ))
        .unwrap();
        let found_t = r.select(ScopeKind::Kem, &all_templates());
        assert_eq!(found_t.unwrap_err().code(), Code::NoMatchingTemplate);
    }

    #[test]
    fn inactive_template_is_skipped() {
        let mut r = InMemoryTemplateRegistry::new();
        r.register(template(
            "old_aead",
            ScopeKind::Aead,
            false,
        ))
        .unwrap();
        r.register(template(
            "new_aead",
            ScopeKind::Aead,
            true,
        ))
        .unwrap();
        let found_t = r
            .select(ScopeKind::Aead, &all_templates())
            .expect("should skip the inactive template");
        assert_eq!(found_t.get_id(), "new_aead");
    }

    #[test]
    fn only_inactive_template_does_not_match() {
        let mut r = InMemoryTemplateRegistry::new();
        r.register(template(
            "old_aead",
            ScopeKind::Aead,
            false,
        ))
        .unwrap();
        let found_t = r.select(ScopeKind::Aead, &all_templates());
        assert_eq!(found_t.unwrap_err().code(), Code::NoMatchingTemplate);
    }

    #[test]
    fn empty_registry_does_not_match() {
        let r = InMemoryTemplateRegistry::new();
        let found_t = r.select(ScopeKind::Aead, &all_templates());
        assert_eq!(found_t.unwrap_err().code(), Code::NoMatchingTemplate);
    }

    #[test]
    fn duplicate_register_is_rejected() {
        let mut r = InMemoryTemplateRegistry::new();
        r.register(template(
            "aead_temp",
            ScopeKind::Aead,
            true,
        ))
        .unwrap();
        let second = r.register(template(
            "aead_temp",
            ScopeKind::Mac,
            true,
        ));
        assert_eq!(second.unwrap_err().code(), Code::AlreadyExists);
        // The first registration is kept, not overwritten.
        assert_eq!(
            r.get("aead_temp").unwrap().get_scope_kind(),
            ScopeKind::Aead
        );
    }

    #[test]
    fn get_finds_registered_and_misses_unknown() {
        let mut r = InMemoryTemplateRegistry::new();
        r.register(template(
            "aead_temp",
            ScopeKind::Aead,
            true,
        ))
        .unwrap();
        assert_eq!(r.get("aead_temp").map(Template::get_id), Some("aead_temp"));
        assert!(r.get("unknown").is_none());
    }
    #[test]
    fn with_defaults_selects_aead() {
        let r = InMemoryTemplateRegistry::with_defaults();
        let t = r
            .select(ScopeKind::Aead, &all_templates())
            .unwrap();
        assert_eq!(t.get_id(), "aes-256-gcm");
    }
}
