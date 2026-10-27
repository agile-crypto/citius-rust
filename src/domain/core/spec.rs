use super::ScopeKind;

/// What the caller asks for when creating a key. Lives in the shared
/// vocabulary, like `core.KeyCreationSpec` in Go, because the key, policy and
/// template domains all read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyCreationSpec {
    pub name: String,
    pub policy: String,
    pub template_id: Option<String>,
    pub scope_kind: ScopeKind,
}
