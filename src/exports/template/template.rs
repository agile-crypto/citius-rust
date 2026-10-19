use crate::bindings::agc_scope_kind;

#[derive(Debug)]
pub struct Template {
    id: String,
    scope_kind: agc_scope_kind,
    algorithm: String,
    active: bool,
}

impl Template {
    pub fn new(id: String, scope_kind: agc_scope_kind, algorithm: String, active: bool) -> Template {
        Template {
            id,
            scope_kind,
            algorithm,
            active,
        }
    }

    pub fn get_id(&self) -> &str {
        &self.id
    }

    pub fn get_scope_kind(&self) -> agc_scope_kind {
        self.scope_kind
    }

    pub fn is_active(&self) -> bool {
        self.active
    }
}
