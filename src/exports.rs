use crate::{
    bindings::*,
    exports::{
        context::Context,
        service::{KeyOrchestrator, PolicyEngine, ProviderRegistry},
    },
};

// The error module defines error types for the domain
mod error;
// The service package contains application-layer orchestrator interfaces. The orchestrators access multiple domains
mod service;
// The domains of citius-core are reflected in the following modules
mod core;
mod crypto;
mod key;
mod policy;
mod provider;
mod template;

mod context;
mod ffi_translation;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_create_key(
    ctx: *mut agc_ctx,
    params: *const agc_create_key_params,
    resp: *mut agc_key_info_response,
) -> agc_rc {
    // Validate pointers and then call rust function

    // SAFETY: ctx is NULL (handled below) or was returned by agc_ctx_open and not closed yet,
    // so it points to a valid Context. The caller must not use it from a different thread.
    let Some(ctx) = (unsafe { ctx.cast::<Context>().as_mut() }) else {
        // "ctx must not be null
        return AGC_ERR_INVALID_ARGUMENT;
    };

    // SAFETY: params must be aligned and is either NULL or points to a caller-owned initialized agc_create_key_params that stays valid and unmodified throughout the call. The pointer is only read.
    // Callers built against an older, smaller struct are not supported yet: struct_size is only checked afterwards.
    let Some(params) = (unsafe { params.as_ref() }) else {
        // params must not be null
        return AGC_ERR_INVALID_ARGUMENT;
    };

    // SAFETY: resp is NULL (handled below) or aligned, owned by the caller and writable during the call of this function
    let Some(resp) = (unsafe { resp.as_mut() }) else {
        // resp must not be null
        return AGC_ERR_INVALID_ARGUMENT;
    };
    // SAFETY: the string pointers inside params are NULL or valid C strings (agc_key.h contract).
    match unsafe { ctx.create_key(params, resp) } {
        Ok(()) => AGC_OK as agc_rc,
        Err(e) => e.rc(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_ctx_open(
    cfg: *const agc_ctx_config,
    out_ctx: *mut *mut agc_ctx,
) -> agc_rc {
    // SAFETY: out_ctx is NULL (handled below) or points to the caller's agc_ctx* variable, which is writable for the duration of this call
    let Some(cmut) = (unsafe { out_ctx.as_mut() }) else {
        return AGC_ERR_INVALID_ARGUMENT;
    };
    let ctx = Box::new(Context {
        key_orch: KeyOrchestrator::new(ProviderRegistry {}, PolicyEngine {}),
    });
    *cmut = Box::into_raw(ctx).cast::<agc_ctx>();
    AGC_OK as agc_rc
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_ctx_close(ctx: *mut agc_ctx) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: ctx is non-null (checked above) and, per the agc_ctx.h contract, came from Box::into_raw in agc_ctx_open and has not been closed before.
    drop(unsafe { Box::from_raw(ctx.cast::<Context>()) });
}
