use std::time::SystemTime;

use crate::domain::core::ScopeSpecification;
use crate::domain::key::{Key, KeyId, Version};
use crate::domain::provider::{Encoding, GeneratedKey, ProviderRegistry};
use crate::proto::api;

/// What a caller may know about one version of a key (Go: the
/// `service.KeyMetadata` read model): assembled from the Key aggregate, the
/// version, and the provider. It never carries private material, so
/// listings and iterators hold no secrets.
#[derive(Debug, Clone)]
pub struct KeyMetadata {
    pub id: KeyId,
    pub name: String,
    pub policy: String,
    pub state: api::KeyLifecycleState,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
    pub version: u32,
    pub template_id: String,
    pub provider: String,
    pub scope_spec: ScopeSpecification,
    pub extractable: bool,
    pub public_key: Option<(Vec<u8>, Encoding)>,
    pub implementation: api::ImplementationProperties,
}

impl KeyMetadata {
    pub fn of(key: &Key, v: &Version, providers: &ProviderRegistry) -> KeyMetadata {
        // The stored material is the provider's GeneratedKey; its public half
        // is meant to be read. Material of another format has none to show.
        let public_key = GeneratedKey::from_bytes(v.material()).ok().and_then(|g| g.public);
        KeyMetadata {
            id: key.id().clone(),
            name: key.name().to_owned(),
            policy: key.policy().to_owned(),
            state: key.state(),
            created_at: key.created_at(),
            updated_at: key.updated_at(),
            version: v.number(),
            template_id: v.template_id().to_owned(),
            provider: v.provider().to_owned(),
            scope_spec: v.scope_spec().clone(),
            extractable: v.provenance().extractable,
            public_key,
            implementation: providers.get(v.provider()).map(|p| p.implementation()).unwrap_or_default(),
        }
    }
}
