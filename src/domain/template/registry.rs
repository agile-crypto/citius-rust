use super::template::Template;
use crate::domain::core::{Error, ScopeKind};

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

/// Holds the algorithm templates and selects one for an intent. Templates are
/// immutable reference data: the registry is filled before it is shared, so
/// lookups can hand out plain references without a lock.
pub trait TemplateRegistry: Send + Sync {
    /// Fails with `AlreadyExists` for a duplicate id and keeps the first.
    fn register(&mut self, t: Template) -> Result<(), Error>;

    fn get(&self, id: &str) -> Option<&Template>;

    /// The first active template of `kind` that `candidates` allows, else
    /// `NoMatchingTemplate`.
    fn select(&self, kind: ScopeKind, candidates: &CandidateSet) -> Result<&Template, Error>;
}
