use std::path::PathBuf;
use std::sync::Arc;

use crate::adapters::providers::RustCrypto;
use crate::adapters::storage::{
    FileKeyRepository, InMemoryKeyRepository, InMemoryPolicyRepository, InMemoryTemplateRegistry, WrappingKey,
};
use crate::domain::key::KeyRepository;
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
    /// The file key store, if any, for agc_ctx_reinit_after_fork to release
    /// the directory lock this context holds.
    file_store: Option<Arc<FileKeyRepository>>,
}

/// The owned part of `agc_ctx_config` that a context depends on (the C
/// strings are copied: agc_core.h says the caller need not keep them alive).
#[derive(Clone)]
pub struct Config {
    pub default_policy: Option<String>,
    /// Where keys live: in memory, or a sealed file store.
    pub key_store: KeyStore,
}

/// `agc_ctx_config.key_store_uri` and its wrapping key.
#[derive(Clone)]
pub enum KeyStore {
    Memory,
    File { dir: PathBuf, wrapping_key_path: PathBuf },
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
        // SAFETY: the strings are NULL or C strings (this function's contract).
        let key_store = unsafe { key_store(cfg) }?;
        // SAFETY: default_policy is NULL or a C string (this function's contract).
        let default_policy = unsafe { optional_str(cfg.default_policy, "cfg.default_policy") }?.map(str::to_owned);
        Ok(Config { default_policy, key_store })
    }
}

/// The key store `cfg` names. NULL (also what an older, shorter config
/// reads as: the fields are zero) keeps keys in memory.
///
/// # Safety
/// The string fields of `cfg` are NULL or valid C strings.
unsafe fn key_store(cfg: &agc_ctx_config) -> Result<KeyStore, FfiError> {
    // SAFETY: forwarded from this function's contract.
    let Some(uri) = (unsafe { optional_str(cfg.key_store_uri, "cfg.key_store_uri") })? else {
        return Ok(KeyStore::Memory);
    };
    let Some(dir) = uri.strip_prefix("file:").filter(|d| !d.is_empty()) else {
        return Err(FfiError::NotImplemented("key_store_uri schemes other than file:<directory>"));
    };
    // SAFETY: forwarded from this function's contract.
    let wrapping_key_path = unsafe { optional_str(cfg.key_store_wrapping_key_path, "cfg.key_store_wrapping_key_path") }?
        .ok_or_else(|| FfiError::invalid("a file: key store requires key_store_wrapping_key_path"))?;
    Ok(KeyStore::File { dir: PathBuf::from(dir), wrapping_key_path: PathBuf::from(wrapping_key_path) })
}

/// The current process id.
pub fn pid() -> u32 {
    std::process::id()
}

impl Context {
    /// In a forked child: lets go of what this (poisoned) context shares
    /// with the parent and would keep a fresh context from opening: the key
    /// store's directory lock.
    pub fn release_inherited(&self) {
        if let Some(store) = &self.file_store {
            store.release_inherited_lock();
        }
    }

    /// Builds a context from a configuration: the composition root, like
    /// `WireFactorySet` in the Go server, run once per context.
    pub fn open(config: Config) -> Result<Context, FfiError> {

        let templates = Arc::new(InMemoryTemplateRegistry::standard());
        let mut providers = ProviderRegistry::new();
        providers.register(Arc::new(RustCrypto))?;
        validate_providers(&providers, templates.as_ref())?;

        let file_store = match &config.key_store {
            KeyStore::Memory => None,
            KeyStore::File { dir, wrapping_key_path } => {
                Some(Arc::new(FileKeyRepository::open(dir, WrappingKey::from_file(wrapping_key_path)?)?))
            }
        };
        let keys: Arc<dyn KeyRepository> = match &file_store {
            None => Arc::new(InMemoryKeyRepository::new()),
            Some(store) => store.clone(),
        };
        let policy = Arc::new(Enforcer::new(Arc::new(InMemoryPolicyRepository::new())));
        let providers = Arc::new(providers);
        Ok(Context {
            pid: pid(),
            default_policy: config.default_policy.clone(),
            config,
            file_store,
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
