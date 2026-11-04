use std::sync::Arc;

use crate::adapters::providers::RustCrypto;
use crate::adapters::storage::{InMemoryKeyRepository, InMemoryPolicyRepository, InMemoryTemplateRegistry};
use crate::app::{CryptoOrchestrator, Discovery, KeyOrchestrator, PolicyAdmin, validate_providers};
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
    /// The process that opened the context. In a forked child it differs
    /// from the current one, and the context is poisoned (agc_core.h FORK).
    pub pid: u32,
    /// What it was opened with, for agc_ctx_reinit_after_fork.
    pub config: Config,
    pub keys: KeyOrchestrator,
    pub crypto: CryptoOrchestrator,
    pub policies: PolicyAdmin,
    pub discovery: Discovery,
    /// `agc_ctx_config.default_policy`: used when a call names no policy.
    pub default_policy: Option<String>,
}

/// The owned part of `agc_ctx_config` that a context depends on (the C
/// strings are copied: agc_core.h says the caller need not keep them alive).
#[derive(Clone)]
pub struct Config {
    pub mode: agc_mode,
    pub default_policy: Option<String>,
}

impl Config {
    /// Reads and validates the caller's configuration. Settings the library
    /// cannot honour yet are refused, never silently ignored (DEVIATIONS C4).
    ///
    /// # Safety
    /// The string fields of `cfg` are NULL or valid C strings.
    pub unsafe fn from_c(cfg: &agc_ctx_config) -> Result<Config, FfiError> {
        if cfg.mode != agc_mode_AGC_MODE_EMBEDDED {
            return Err(FfiError::NotImplemented("AGC_MODE_LOCAL/AGC_MODE_REMOTE"));
        }
        // Key material is not held in locked memory yet; accepting the flag
        // would promise a protection the library does not give.
        if cfg.require_locked_memory != 0 {
            return Err(FfiError::NotImplemented("require_locked_memory"));
        }
        if cfg.fips_mode != 0 {
            return Err(FfiError::NotImplemented("fips_mode (no FIPS-validated provider is available)"));
        }
        if !cfg.catalog_path.is_null() {
            return Err(FfiError::NotImplemented("catalog_path (the catalog is compiled in)"));
        }
        if !cfg.provider_config_path.is_null() {
            return Err(FfiError::NotImplemented("provider_config_path"));
        }
        // NULL (also what an older, shorter config reads as) keeps keys in
        // memory. A persistent store waits for its at-rest protection to be
        // agreed: plaintext key material on disk is not offered.
        if !cfg.key_store_uri.is_null() {
            return Err(FfiError::NotImplemented("key_store_uri (keys are held in memory only)"));
        }
        // SAFETY: default_policy is NULL or a C string (this function's contract).
        let default_policy = unsafe { optional_str(cfg.default_policy, "cfg.default_policy") }?.map(str::to_owned);
        Ok(Config { mode: cfg.mode, default_policy })
    }
}

/// The current process id.
pub fn pid() -> u32 {
    std::process::id()
}

impl Context {
    /// Builds a context from a configuration: the composition root, like
    /// `WireFactorySet` in the Go server, run once per context.
    pub fn open(config: Config) -> Result<Context, FfiError> {

        let templates = Arc::new(InMemoryTemplateRegistry::standard());
        let mut providers = ProviderRegistry::new();
        providers.register(Arc::new(RustCrypto))?;
        validate_providers(&providers, templates.as_ref())?;

        let keys = Arc::new(InMemoryKeyRepository::new());
        let policy = Arc::new(Enforcer::new(Arc::new(InMemoryPolicyRepository::new())));
        let providers = Arc::new(providers);
        Ok(Context {
            pid: pid(),
            default_policy: config.default_policy.clone(),
            config,
            keys: KeyOrchestrator::new(keys.clone(), templates.clone(), providers.clone(), policy.clone()),
            crypto: CryptoOrchestrator::new(keys.clone(), templates.clone(), providers.clone(), policy.clone()),
            discovery: Discovery::new(templates, providers),
            policies: PolicyAdmin::new(policy, keys),
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
