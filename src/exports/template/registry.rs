use super::template::Template;
use crate::{
    bindings::*,
    exports::error::Error::{self, AlreadyExists, NoMatchingTemplate},
};

pub struct CandidateSet {
    ids: Vec<String>,
    restricted: bool,
}

pub fn all_templates() -> CandidateSet {
    CandidateSet {
        ids: Vec::new(),
        restricted: false,
    }
}

pub fn only_templates(ids: Vec<String>) -> CandidateSet {
    CandidateSet {
        ids,
        restricted: true,
    }
}

impl CandidateSet {
    pub fn is_restricted(&self) -> bool {
        self.restricted
    }

    pub fn get_ids(&self) -> &Vec<String> {
        &self.ids
    }

    pub fn allows(&self, id: &str) -> bool {
        !self.restricted || self.ids.iter().any(|x| x == id)
    }
}

pub trait Registry {
    fn register(&mut self, t: Template) -> Result<(), Error>;

    fn get(&self, id: &str) -> Option<&Template>;

    fn select(&self, kind: agc_scope_kind, candidates: &CandidateSet) -> Result<&Template, Error>;
}

pub struct InMemoryRegistry {
    templates: Vec<Template>,
}
impl InMemoryRegistry {
    fn new() -> Self {
        InMemoryRegistry {
            templates: Vec::new(),
        }
    }
    pub fn with_defaults() -> Self {
        let mut r = InMemoryRegistry::new();
        for (id, kind, algo) in [
            (
                "aes-256-gcm",
                agc_scope_kind_AGC_SCOPE_KIND_AEAD,
                "AES-256-GCM",
            ),
            (
                "hmac-sha256",
                agc_scope_kind_AGC_SCOPE_KIND_MAC,
                "HMAC-SHA256",
            ),
            (
                "ed25519",
                agc_scope_kind_AGC_SCOPE_KIND_SIGNATURE,
                "Ed25519",
            ),
        ] {
            r.register(Template::new(id.into(), kind, algo.into(), true))
                .expect("Wrong default value");
        }
        r
    }
}
impl Registry for InMemoryRegistry {
    fn register(&mut self, t: Template) -> Result<(), Error> {
        // check duplicates
        if self.get(t.get_id()).is_some() {
            return Err(AlreadyExists);
        }
        self.templates.push(t);
        Ok(())
    }

    fn get(&self, id: &str) -> Option<&Template> {
        self.templates.iter().find(|x| x.get_id() == id)
    }

    fn select(&self, kind: agc_scope_kind, candidates: &CandidateSet) -> Result<&Template, Error> {
        self.templates
            .iter()
            .find(|x| candidates.allows(x.get_id()) && x.get_scope_kind() == kind && x.is_active())
            .ok_or(NoMatchingTemplate)
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
            agc_scope_kind_AGC_SCOPE_KIND_AEAD,
            String::from("AES_GCM_SOMETHING"),
            true,
        );
        let mut r = InMemoryRegistry {
            templates: Vec::new(),
        };
        r.register(t).unwrap();
        let cs = &only_templates(vec![String::from("aead_temp")]);
        let found_t = r.select(agc_scope_kind_AGC_SCOPE_KIND_AEAD, cs);
        assert_eq!(id, found_t.expect("should find AEAD template").get_id());
    }

    #[test]
    fn selects_aead_unrestricted() {
        let id = "aead_temp";
        let t = Template::new(
            String::from(id),
            agc_scope_kind_AGC_SCOPE_KIND_AEAD,
            String::from("AES_GCM_SOMETHING"),
            true,
        );
        let mut r = InMemoryRegistry {
            templates: Vec::new(),
        };
        r.register(t).unwrap();
        let cs = &all_templates();
        let found_t = r.select(agc_scope_kind_AGC_SCOPE_KIND_AEAD, cs);
        assert_eq!(id, found_t.expect("should find AEAD template").get_id());
    }

    #[test]
    fn no_matching_test() {
        let id = "aead_temp";
        let t = Template::new(
            String::from(id),
            agc_scope_kind_AGC_SCOPE_KIND_AEAD,
            String::from("AES_GCM_SOMETHING"),
            true,
        );
        let mut r = InMemoryRegistry {
            templates: Vec::new(),
        };
        r.register(t).unwrap();
        let cs = &&only_templates(vec![]);
        let found_t = r.select(agc_scope_kind_AGC_SCOPE_KIND_AEAD, cs);
        assert!(matches!(found_t, Err(NoMatchingTemplate)));
    }

    fn template(id: &str, kind: agc_scope_kind, active: bool) -> Template {
        Template::new(String::from(id), kind, String::from("SOME_ALGO"), active)
    }

    #[test]
    fn restricted_set_excludes_other_ids() {
        let mut r = InMemoryRegistry::new();
        r.register(template(
            "aead_temp",
            agc_scope_kind_AGC_SCOPE_KIND_AEAD,
            true,
        ))
        .unwrap();
        let cs = only_templates(vec![String::from("other_temp")]);
        let found_t = r.select(agc_scope_kind_AGC_SCOPE_KIND_AEAD, &cs);
        assert!(matches!(found_t, Err(NoMatchingTemplate)));
    }

    #[test]
    fn restricted_set_picks_allowed_among_several() {
        let mut r = InMemoryRegistry::new();
        r.register(template("aead_a", agc_scope_kind_AGC_SCOPE_KIND_AEAD, true))
            .unwrap();
        r.register(template("aead_b", agc_scope_kind_AGC_SCOPE_KIND_AEAD, true))
            .unwrap();
        let cs = only_templates(vec![String::from("aead_b")]);
        let found_t = r
            .select(agc_scope_kind_AGC_SCOPE_KIND_AEAD, &cs)
            .expect("should find aead_b");
        assert_eq!(found_t.get_id(), "aead_b");
    }

    #[test]
    fn wrong_kind_does_not_match() {
        let mut r = InMemoryRegistry::new();
        r.register(template(
            "aead_temp",
            agc_scope_kind_AGC_SCOPE_KIND_AEAD,
            true,
        ))
        .unwrap();
        let found_t = r.select(agc_scope_kind_AGC_SCOPE_KIND_KEM, &all_templates());
        assert!(matches!(found_t, Err(NoMatchingTemplate)));
    }

    #[test]
    fn inactive_template_is_skipped() {
        let mut r = InMemoryRegistry::new();
        r.register(template(
            "old_aead",
            agc_scope_kind_AGC_SCOPE_KIND_AEAD,
            false,
        ))
        .unwrap();
        r.register(template(
            "new_aead",
            agc_scope_kind_AGC_SCOPE_KIND_AEAD,
            true,
        ))
        .unwrap();
        let found_t = r
            .select(agc_scope_kind_AGC_SCOPE_KIND_AEAD, &all_templates())
            .expect("should skip the inactive template");
        assert_eq!(found_t.get_id(), "new_aead");
    }

    #[test]
    fn only_inactive_template_does_not_match() {
        let mut r = InMemoryRegistry::new();
        r.register(template(
            "old_aead",
            agc_scope_kind_AGC_SCOPE_KIND_AEAD,
            false,
        ))
        .unwrap();
        let found_t = r.select(agc_scope_kind_AGC_SCOPE_KIND_AEAD, &all_templates());
        assert!(matches!(found_t, Err(NoMatchingTemplate)));
    }

    #[test]
    fn empty_registry_does_not_match() {
        let r = InMemoryRegistry::new();
        let found_t = r.select(agc_scope_kind_AGC_SCOPE_KIND_AEAD, &all_templates());
        assert!(matches!(found_t, Err(NoMatchingTemplate)));
    }

    #[test]
    fn duplicate_register_is_rejected() {
        let mut r = InMemoryRegistry::new();
        r.register(template(
            "aead_temp",
            agc_scope_kind_AGC_SCOPE_KIND_AEAD,
            true,
        ))
        .unwrap();
        let second = r.register(template(
            "aead_temp",
            agc_scope_kind_AGC_SCOPE_KIND_MAC,
            true,
        ));
        assert!(matches!(second, Err(AlreadyExists)));
        // The first registration is kept, not overwritten.
        assert_eq!(
            r.get("aead_temp").unwrap().get_scope_kind(),
            agc_scope_kind_AGC_SCOPE_KIND_AEAD
        );
    }

    #[test]
    fn get_finds_registered_and_misses_unknown() {
        let mut r = InMemoryRegistry::new();
        r.register(template(
            "aead_temp",
            agc_scope_kind_AGC_SCOPE_KIND_AEAD,
            true,
        ))
        .unwrap();
        assert_eq!(r.get("aead_temp").map(Template::get_id), Some("aead_temp"));
        assert!(r.get("unknown").is_none());
    }
    #[test]
    fn with_defaults_selects_aead() {
        let r = InMemoryRegistry::with_defaults();
        let t = r
            .select(agc_scope_kind_AGC_SCOPE_KIND_AEAD, &all_templates())
            .unwrap();
        assert_eq!(t.get_id(), "aes-256-gcm");
    }
}
