use crate::bindings::*;

use std::ffi::CStr;
mod service;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_create_key(
    ctx: *mut agc_ctx,
    params: *const agc_create_key_params,
    resp: *mut agc_key_info_response,
) -> agc_rc {
    // Validate pointers and then call rust function
    let Some(ctx) = (unsafe { ctx.as_mut() }) else {
        panic!("ctx must not be null")
    };

    let Some(params) = (unsafe { params.as_ref() }) else {
        panic!("params must not be null");
    };

    let Some(resp) = (unsafe { resp.as_mut() }) else {
        panic!("resp must not be null")
    };
    let ko = service::KeyOrchestrator::new(service::KeyRepository{},service::TemplateRegistry{},service::ProviderRegistry{},service::PolicyEngine{});
    return ko.agc_create_key(ctx, params, resp);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_ctx_open(
    cfg: *const agc_ctx_config,
    out_ctx: *mut *mut agc_ctx,
) -> agc_rc {
    return AGC_OK as agc_rc;
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_ctx_close(ctx: *mut agc_ctx) {
    return;
}
