use std::sync::Arc;

use crate::adapters::storage::{InMemoryKeyRepository, InMemoryTemplateRegistry};
use crate::app::KeyOrchestrator;
use crate::bindings::*;
use crate::ffi::error::FfiError;

/// What an `agc_ctx*` really points to (see `agc_ctx_open`).
///
/// agc_core.h promises that any number of threads may use one context at
/// once, so a context is only ever reached through `&Context`, never
/// `&mut Context`, and everything it holds is `Send + Sync`.
pub struct Context {
    pub keys: KeyOrchestrator,
}

impl Context {
    /// Builds a context from the caller's configuration: the composition
    /// root, like `WireFactorySet` in the Go server, run once per context.
    pub fn open(cfg: &agc_ctx_config) -> Result<Context, FfiError> {
        if cfg.mode != agc_mode_AGC_MODE_EMBEDDED {
            return Err(FfiError::NotImplemented("AGC_MODE_LOCAL/AGC_MODE_REMOTE"));
        }
        // Key material is not held in locked memory yet; accepting the flag
        // would promise a protection the library does not give.
        if cfg.require_locked_memory != 0 {
            return Err(FfiError::NotImplemented("require_locked_memory"));
        }
        Ok(Context {
            keys: KeyOrchestrator::new(
                Arc::new(InMemoryKeyRepository::new()),
                Arc::new(InMemoryTemplateRegistry::standard()),
            ),
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
