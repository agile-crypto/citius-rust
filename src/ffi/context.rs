use std::sync::Arc;

use crate::adapters::providers::RustCrypto;
use crate::adapters::storage::{InMemoryKeyRepository, InMemoryPolicyRepository, InMemoryTemplateRegistry};
use crate::app::{CryptoOrchestrator, KeyOrchestrator, PolicyAdmin, validate_providers};
use crate::domain::policy::Enforcer;
use crate::domain::provider::ProviderRegistry;
use crate::bindings::*;
use crate::ffi::error::FfiError;
use crate::ffi::translation::optional_str;

/// What an `agc_ctx*` really points to (see `agc_ctx_open`).
///
/// agc_core.h promises that any number of threads may use one context at
/// once, so a context is only ever reached through `&Context`, never
/// `&mut Context`, and everything it holds is `Send + Sync`.
pub struct Context {
    pub keys: KeyOrchestrator,
    pub crypto: CryptoOrchestrator,
    pub policies: PolicyAdmin,
    /// `agc_ctx_config.default_policy`: used when a call names no policy.
    pub default_policy: Option<String>,
}

impl Context {
    /// Builds a context from the caller's configuration: the composition
    /// root, like `WireFactorySet` in the Go server, run once per context.
    ///
    /// # Safety
    /// The string fields of `cfg` are NULL or valid C strings.
    pub unsafe fn open(cfg: &agc_ctx_config) -> Result<Context, FfiError> {
        if cfg.mode != agc_mode_AGC_MODE_EMBEDDED {
            return Err(FfiError::NotImplemented("AGC_MODE_LOCAL/AGC_MODE_REMOTE"));
        }
        // Key material is not held in locked memory yet; accepting the flag
        // would promise a protection the library does not give.
        if cfg.require_locked_memory != 0 {
            return Err(FfiError::NotImplemented("require_locked_memory"));
        }
        // SAFETY: default_policy is NULL or a C string (agc_core.h contract;
        // the configuration is copied, so it need not outlive this call).
        let default_policy = unsafe { optional_str(cfg.default_policy, "cfg.default_policy") }?.map(str::to_owned);

        let templates = Arc::new(InMemoryTemplateRegistry::standard());
        let mut providers = ProviderRegistry::new();
        providers.register(Arc::new(RustCrypto))?;
        validate_providers(&providers, templates.as_ref())?;

        let keys = Arc::new(InMemoryKeyRepository::new());
        let policy = Arc::new(Enforcer::new(Arc::new(InMemoryPolicyRepository::new())));
        let providers = Arc::new(providers);
        Ok(Context {
            keys: KeyOrchestrator::new(keys.clone(), templates.clone(), providers.clone(), policy.clone()),
            crypto: CryptoOrchestrator::new(keys.clone(), templates, providers, policy.clone()),
            policies: PolicyAdmin::new(policy, keys),
            default_policy,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_is_shareable_across_threads() {
        fn assert_sync<T: Send + Sync>() {}
        assert_sync::<Context>();
    }
}
