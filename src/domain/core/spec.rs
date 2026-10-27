use super::{ProviderRequirements, ScopeSpecification};

/// What the caller asks for when creating a key. Lives in the shared
/// vocabulary, like `core.KeyCreationSpec` in Go, because the key, policy and
/// template domains all read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyCreationSpec {
    pub name: String,
    pub policy: String,
    pub template_id: Option<String>,
    pub scope_spec: ScopeSpecification,
    /// A provider the caller pins: used, or the call fails.
    pub provider_id: Option<String>,
    /// Added to the policy's provider requirements, never relaxing them.
    pub provider_requirements: ProviderRequirements,
}
