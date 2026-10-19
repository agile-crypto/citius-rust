use crate::bindings::{agc_create_key_params, agc_key_info_response};
use crate::exports::error::Error;
use crate::exports::ffi_translation::{fill_key_info_response, spec_from_params};
use crate::exports::service::*;

/// What an `agc_ctx*` really points to (see `agc_ctx_open` in exports.rs).
pub struct Context {
    pub key_orch: KeyOrchestrator,
}

impl Context {
    /// Body of `agc_create_key` once the pointers are checked. Returns a `Result`,
    /// so every step can use `?`; the extern "C" shim turns it into an `agc_rc` once.
    ///
    /// # Safety
    /// The string pointers inside `params` must each be NULL or a valid
    /// NUL-terminated string for the duration of the call (agc_key.h contract).
    pub unsafe fn create_key(
        &mut self,
        params: &agc_create_key_params,
        resp: &mut agc_key_info_response,
    ) -> Result<(), Error> {
        // SAFETY: forwarded from this function's contract.
        let spec = unsafe { spec_from_params(params) }?;
        // Known gap: the key is stored before we know whether `resp.storage` is big
        // enough. On BUFFER_TOO_SMALL the key exists anyway, unlike what the STORAGE
        // CONTRACT asks for create operations (agc_key_types.h).
        let key = self.key_orch.create_key(spec)?;
        fill_key_info_response(resp, key)
    }
}
