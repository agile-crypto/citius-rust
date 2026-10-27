//! agc_key.h — KeyManagementService.

use crate::bindings::*;
use crate::ffi::context::Context;
use crate::ffi::guard::guard;
use crate::ffi::translation::{fill_key_info_response, spec_from_params};
use crate::ffi::{exports::core::context, versioned};

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_create_key(
    ctx: *mut agc_ctx,
    params: *const agc_create_key_params,
    resp: *mut agc_key_info_response,
) -> agc_rc {
    guard(|| {
        // SAFETY: ctx is NULL or a live context from agc_ctx_open (agc_core.h contract).
        let ctx: &Context = unsafe { context(ctx) }?;
        // SAFETY: params is NULL or the caller's struct with struct_size readable bytes.
        let params = unsafe { versioned::read(params, "params") }?;
        // SAFETY: resp is NULL or the caller's struct with struct_size accessible bytes.
        let mut out = unsafe { versioned::read(resp, "resp") }?;

        // SAFETY: the string pointers inside params are NULL or valid C strings (agc_key.h contract).
        let spec = unsafe { spec_from_params(&params, ctx.default_policy.as_deref()) }?;
        // Known gap: the key is stored before we know whether `resp.storage` is big
        // enough. On BUFFER_TOO_SMALL the key exists anyway, unlike what the STORAGE
        // CONTRACT asks for create operations (agc_key_types.h).
        let key = ctx.keys.create_key(spec)?;
        let result = fill_key_info_response(&mut out, &key);
        // SAFETY: resp passed versioned::read above, so its struct_size is valid.
        unsafe { versioned::write_back(resp, &out) };
        result
    })
}
