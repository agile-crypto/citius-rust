use super::template::Template;
use crate::domain::core::{Code, Error, ScopeSpecification, TemplateStatus};

/// Which templates are eligible for a selection. There is deliberately no
/// default: callers choose `all_templates()` or `only_templates(ids)`, and an
/// empty `only_templates` means nothing is eligible, never everything.
#[derive(Debug, Clone)]
pub struct CandidateSet {
    ids: Vec<String>,
    restricted: bool,
}

#[cfg(test)]
pub fn all_templates() -> CandidateSet {
    CandidateSet { ids: Vec::new(), restricted: false }
}

pub fn only_templates(ids: Vec<String>) -> CandidateSet {
    CandidateSet { ids, restricted: true }
}

impl CandidateSet {
    pub fn is_restricted(&self) -> bool {
        self.restricted
    }

    pub fn ids(&self) -> &[String] {
        &self.ids
    }
}

/// Holds the algorithm templates and selects one for an intent. Templates are
/// immutable reference data: the registry is filled before it is shared, so
/// lookups hand out plain references without a lock.
pub trait TemplateRegistry: Send + Sync {
    /// Fails with `AlreadyExists` for a duplicate id and keeps the first.
    fn register(&mut self, t: Template) -> Result<(), Error>;

    fn get(&self, id: &str) -> Option<&Template>;

    /// Every template, in registration order.
    fn list(&self) -> Vec<&Template>;

    /// The first selectable template among `candidates` that serves `want`:
    /// in the candidates' order when they are restricted (a policy's order of
    /// preference), else in registration order.
    ///
    /// Errors: `NoMatchingTemplate` if none qualifies. When exactly one
    /// template was named, the reason is specific: `TemplateNotFound`,
    /// `TemplateDeprecated` or `TemplateForbidden`.
    fn select(&self, want: &ScopeSpecification, candidates: &CandidateSet) -> Result<&Template, Error> {
        const OP: &str = "TemplateRegistry::select";
        let ordered: Vec<&Template> = if candidates.is_restricted() {
            candidates.ids().iter().filter_map(|id| self.get(id)).collect()
        } else {
            self.list()
        };
        if let Some(t) = ordered.iter().find(|t| t.is_selectable() && t.matches(want)) {
            return Ok(t);
        }
        if let [id] = candidates.ids() {
            match self.get(id) {
                None => return Err(Error::new(Code::TemplateNotFound, OP, format!("no template {id}"))),
                Some(t) if t.matches(want) && t.status() == TemplateStatus::Deprecated => {
                    return Err(Error::new(Code::TemplateDeprecated, OP, format!("template {id} is deprecated")));
                }
                Some(t) if t.matches(want) && t.status() == TemplateStatus::Forbidden => {
                    return Err(Error::new(Code::TemplateForbidden, OP, format!("template {id} is forbidden")));
                }
                Some(_) => {}
            }
        }
        Err(Error::new(Code::NoMatchingTemplate, OP, format!("no selectable template serves {:?}", want.scope)))
    }
}
