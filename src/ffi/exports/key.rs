//! agc_key.h — KeyManagementService.

use std::ffi::c_char;

use crate::app::{KeyFilter, KeyMetadata, TransformSpec};
use crate::bindings::*;
use crate::ffi::context::Context;
use crate::ffi::error::FfiError;
use crate::ffi::guard::{guard, guard_value};
use crate::ffi::translation::{fill_key_info_response, key_info_size, optional_str, required_str, scope_spec, spec_from_params};
use crate::ffi::{exports::core::context, versioned};
use crate::proto::api;

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

        // SAFETY: the pointers inside params are NULL or valid (agc_key.h contract).
        let spec = unsafe { spec_from_params(&params, ctx.default_policy.as_deref()) }?;
        let result = admitted(&mut out, |admit| ctx.keys.create_key_admitting(spec, admit));
        // SAFETY: resp passed versioned::read above, so its struct_size is valid.
        unsafe { versioned::write_back(resp, &out) };
        result
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_transform_key(
    ctx: *mut agc_ctx,
    params: *const agc_transform_key_params,
    resp: *mut agc_key_info_response,
) -> agc_rc {
    guard(|| {
        // SAFETY: ctx is NULL or a live context (agc_core.h contract).
        let ctx = unsafe { context(ctx) }?;
        // SAFETY: params is NULL or the caller's struct with struct_size readable bytes.
        let p = unsafe { versioned::read(params, "params") }?;
        // SAFETY: resp is NULL or the caller's struct with struct_size accessible bytes.
        let mut out = unsafe { versioned::read(resp, "resp") }?;
        let spec = TransformSpec {
            // SAFETY: the strings in params are NULL or valid C strings (agc_key.h contract).
            key_name: unsafe { required_str(p.key_name, "key_name") }?.to_owned(),
            retain: p.retain_key_bytes != 0,
            // SAFETY: scope_spec is NULL or a valid agc_scope_spec (agc_key.h contract).
            scope_spec: match unsafe { p.scope_spec.as_ref() } {
                None => None,
                // SAFETY: as above, including its additional_properties.
                Some(s) => Some(unsafe { scope_spec(s) }?),
            },
            // SAFETY: as for key_name.
            template_id: unsafe { optional_str(p.template_id, "template_id") }?.map(str::to_owned),
        };
        let result = admitted(&mut out, |admit| ctx.keys.transform_key_admitting(spec, admit));
        // SAFETY: resp passed versioned::read above.
        unsafe { versioned::write_back(resp, &out) };
        result
    })
}

/// Runs a mutating key operation under the STORAGE CONTRACT for mutations:
/// a region too small for the resulting record fails before anything is
/// stored, with the exact size needed (the record is complete, generated but
/// not stored, when it is checked). Then fills `out`.
fn admitted(
    out: &mut agc_key_info_response,
    run: impl FnOnce(&mut dyn FnMut(&KeyMetadata) -> Result<(), FfiError>) -> Result<KeyMetadata, FfiError>,
) -> Result<(), FfiError> {
    let storage = out.storage;
    let mut needed = None;
    let mut admit = |k: &KeyMetadata| {
        let n = key_info_size(k);
        if storage.data.is_null() || storage.cap < n {
            needed = Some(n);
            return Err(FfiError::BufferTooSmall { needed: n });
        }
        Ok(())
    };
    match run(&mut admit) {
        Ok(key) => fill_key_info_response(out, &key),
        Err(e) => {
            if let Some(n) = needed {
                out.storage_used = n;
            }
            Err(e)
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_read_key(
    ctx: *mut agc_ctx,
    key_name: *const c_char,
    version: u32,
    resp: *mut agc_key_info_response,
) -> agc_rc {
    guard(|| {
        // SAFETY: ctx is NULL or a live context (agc_core.h contract).
        let ctx = unsafe { context(ctx) }?;
        // SAFETY: key_name is NULL or a valid C string (agc_key.h contract).
        let name = unsafe { required_str(key_name, "key_name") }?;
        // SAFETY: resp is NULL or the caller's struct with struct_size accessible bytes.
        let mut out = unsafe { versioned::read(resp, "resp") }?;
        // Versions start at 1, so 0 is "the current one" (agc_key.h).
        let key = ctx.keys.read_key(name, (version != 0).then_some(version))?;
        let result = fill_key_info_response(&mut out, &key);
        // SAFETY: resp passed versioned::read above.
        unsafe { versioned::write_back(resp, &out) };
        result
    })
}

/// What an `agc_key_iter*` points to: a snapshot of the matching keys'
/// metadata (never their material) and a cursor. Like the policy iterator it
/// does not refer to the context; `page_size` has nothing to page in process.
struct KeyIter {
    keys: Vec<KeyMetadata>,
    next: usize,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_list_keys(
    ctx: *mut agc_ctx,
    params: *const agc_list_keys_params,
    out_iter: *mut *mut agc_key_iter,
) -> agc_rc {
    guard(|| {
        // SAFETY: ctx is NULL or a live context (agc_core.h contract).
        let ctx = unsafe { context(ctx) }?;
        // SAFETY: params is NULL or the caller's struct with struct_size readable bytes.
        let p = unsafe { versioned::read(params, "params") }?;
        if out_iter.is_null() {
            return Err(FfiError::invalid("out_iter must not be NULL"));
        }
        // SAFETY: scope_spec is NULL or a valid agc_scope_spec (agc_key.h contract).
        let scope = match unsafe { p.scope_spec.as_ref() } {
            None => None,
            // SAFETY: as above, including its additional_properties.
            Some(s) => Some(unsafe { scope_spec(s) }?),
        };
        let state = match p.lifecycle_state {
            0 => None,
            v => Some(
                i32::try_from(v)
                    .ok()
                    .and_then(|v| api::KeyLifecycleState::try_from(v).ok())
                    .ok_or_else(|| FfiError::invalid(format!("lifecycle_state {v} is not a known state")))?,
            ),
        };
        let filter = KeyFilter {
            scope_spec: scope,
            // SAFETY: provider_id and policy are NULL or valid C strings (agc_key.h contract).
            provider: unsafe { optional_str(p.provider_id, "provider_id") }?.map(str::to_owned),
            // SAFETY: as above.
            policy: unsafe { optional_str(p.policy, "policy") }?.map(str::to_owned),
            state,
        };
        let it = Box::new(KeyIter { keys: ctx.keys.list_keys(&filter)?, next: 0 });
        // SAFETY: out_iter is non-null (checked) and points to the caller's variable.
        unsafe { out_iter.write(Box::into_raw(it).cast()) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_key_iter_next(it: *mut agc_key_iter, out: *mut agc_key_info_response) -> agc_rc {
    guard(|| {
        // SAFETY: it is NULL or from agc_list_keys and not freed; an iterator
        // is used by one thread at a time (like a session).
        let it = unsafe { it.cast::<KeyIter>().as_mut() }.ok_or_else(|| FfiError::invalid("it must not be NULL"))?;
        // SAFETY: out is NULL or the caller's struct with struct_size accessible bytes.
        let mut resp = unsafe { versioned::read(out, "out") }?;
        let Some(key) = it.keys.get(it.next) else {
            return Err(FfiError::IteratorExhausted);
        };
        let result = fill_key_info_response(&mut resp, key);
        // SAFETY: out passed versioned::read above.
        unsafe { versioned::write_back(out, &resp) };
        // On BUFFER_TOO_SMALL the cursor stays, so the caller can retry.
        if result.is_ok() {
            it.next += 1;
        }
        result
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_key_iter_free(it: *mut agc_key_iter) {
    if it.is_null() {
        return;
    }
    // SAFETY: it came from Box::into_raw in agc_list_keys and is freed once.
    guard_value((), || drop(unsafe { Box::from_raw(it.cast::<KeyIter>()) }))
}
