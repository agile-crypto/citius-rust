use zeroize::Zeroizing;

use crate::domain::core::{ScopeKind, new_id};
use std::fmt::Debug;

#[derive(Clone)]
pub struct Key {
    id: KeyId,
    name: String,
    version: u32, // C api has uint32_t version
    template_id: String,
    provider: String,
    policy: String,
    /// Opaque: only the provider that made it can interpret it.
    material: Zeroizing<Vec<u8>>,
    scope_kind: ScopeKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyId(String);

impl KeyId {
    pub fn new(id: impl Into<String>) -> Self {
        KeyId(id.into())
    }

    /// A fresh, globally unique id.
    pub fn generate() -> Self {
        KeyId(new_id("key_"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Key {
    // One argument per field, like the Go struct literal. A parameter struct or
    // builder would be the fix once Key grows further.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: KeyId,
        name: String,
        version: u32,
        template_id: String,
        provider: String,
        policy: String,
        material: Zeroizing<Vec<u8>>,
        scope_kind: ScopeKind,
    ) -> Self {
        Key {
            id,
            name,
            version,
            template_id,
            provider,
            policy,
            material,
            scope_kind,
        }
    }
    pub fn get_id(&self) -> &KeyId {
        &self.id
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_version(&self) -> u32 {
        self.version
    }

    pub fn get_template_id(&self) -> &str {
        &self.template_id
    }

    pub fn get_provider(&self) -> &str {
        &self.provider
    }

    pub fn get_policy(&self) -> &str {
        &self.policy
    }

    pub fn get_material(&self) -> &[u8] {
        &self.material
    }

    pub fn get_scope_kind(&self) -> ScopeKind {
        self.scope_kind
    }
}

impl Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("version", &self.version)
            .field("template_id", &self.template_id)
            .field("provider", &self.provider)
            .field("policy", &self.policy)
            .finish()
    }
}
