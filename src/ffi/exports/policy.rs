//! agc_policy.h — CryptoPolicyService (CRUD and listing; evaluation follows).

use crate::bindings::*;
use crate::domain::policy::Policy;
use crate::ffi::error::FfiError;
use crate::ffi::exports::core::context;
use crate::ffi::guard::{guard, guard_value};
use crate::ffi::translation::{
    fill_policy_summary_response, fill_read_policy_response, null_check_c_string, optional_str, required_str,
};
use crate::ffi::versioned;

/// Writes the policy's version to the caller's optional output.
///
/// # Safety
/// `out` is NULL or valid for writing an `i64`.
unsafe fn put_version(out: *mut i64, version: i64) {
    if !out.is_null() {
        // SAFETY: non-null and writable (this function's contract).
        unsafe { out.write(version) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_create_policy(
    ctx: *mut agc_ctx,
    req: *const agc_create_policy_request,
    out_version: *mut i64,
) -> agc_rc {
    guard(|| {
        // SAFETY: ctx is NULL or a live context (agc_core.h contract).
        let ctx = unsafe { context(ctx) }?;
        // SAFETY: req is NULL or the caller's struct with struct_size readable bytes.
        let req = unsafe { versioned::read(req, "req") }?;
        // SAFETY: the strings in req are NULL or valid C strings (agc_policy.h contract).
        let name = unsafe { required_str(req.name, "name") }?;
        // SAFETY: as above.
        let document = unsafe { document(req.policy_document) }?;
        // SAFETY: as above.
        let format = unsafe { optional_str(req.format, "format") }?.unwrap_or_default();
        let p = ctx.policies.create(name, document, format)?;
        // SAFETY: out_version is NULL or the caller's variable (agc_policy.h contract).
        unsafe { put_version(out_version, p.version()) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_update_policy(
    ctx: *mut agc_ctx,
    req: *const agc_update_policy_request,
    out_version: *mut i64,
) -> agc_rc {
    guard(|| {
        // SAFETY: ctx is NULL or a live context (agc_core.h contract).
        let ctx = unsafe { context(ctx) }?;
        // SAFETY: req is NULL or the caller's struct with struct_size readable bytes.
        let req = unsafe { versioned::read(req, "req") }?;
        // SAFETY: the strings in req are NULL or valid C strings (agc_policy.h contract).
        let name = unsafe { required_str(req.name, "name") }?;
        // SAFETY: as above.
        let document = unsafe { document(req.policy_document) }?;
        // SAFETY: as above.
        let format = unsafe { optional_str(req.format, "format") }?.unwrap_or_default();
        let p = ctx.policies.update(name, document, format, req.expected_version)?;
        // SAFETY: out_version is NULL or the caller's variable (agc_policy.h contract).
        unsafe { put_version(out_version, p.version()) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_read_policy(
    ctx: *mut agc_ctx,
    name: *const std::ffi::c_char,
    resp: *mut agc_read_policy_response,
) -> agc_rc {
    guard(|| {
        // SAFETY: ctx is NULL or a live context (agc_core.h contract).
        let ctx = unsafe { context(ctx) }?;
        // SAFETY: name is NULL or a valid C string (agc_policy.h contract).
        let name = unsafe { required_str(name, "name") }?;
        // SAFETY: resp is NULL or the caller's struct with struct_size accessible bytes.
        let mut out = unsafe { versioned::read(resp, "resp") }?;
        let policy = ctx.policies.get(name)?;
        let result = fill_read_policy_response(&mut out, &policy);
        // SAFETY: resp passed versioned::read above.
        unsafe { versioned::write_back(resp, &out) };
        result
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_delete_policy(ctx: *mut agc_ctx, name: *const std::ffi::c_char) -> agc_rc {
    guard(|| {
        // SAFETY: ctx is NULL or a live context (agc_core.h contract).
        let ctx = unsafe { context(ctx) }?;
        // SAFETY: name is NULL or a valid C string (agc_policy.h contract).
        let name = unsafe { required_str(name, "name") }?;
        ctx.policies.delete(name)?;
        Ok(())
    })
}

/// What an `agc_policy_iter*` points to: a snapshot taken when the listing
/// started, and a cursor. It does not refer to the context, so it stays
/// memory-safe even if the caller closes the context first, and concurrent
/// changes to policies do not affect a listing in progress. Everything is in
/// process, so `page_size` has nothing to page and is ignored.
struct PolicyIter {
    policies: Vec<Policy>,
    next: usize,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_list_policies(
    ctx: *mut agc_ctx,
    req: *const agc_list_policies_request,
    out_iter: *mut *mut agc_policy_iter,
) -> agc_rc {
    guard(|| {
        // SAFETY: ctx is NULL or a live context (agc_core.h contract).
        let ctx = unsafe { context(ctx) }?;
        // SAFETY: req is NULL or the caller's struct with struct_size readable bytes.
        let req = unsafe { versioned::read(req, "req") }?;
        if out_iter.is_null() {
            return Err(FfiError::invalid("out_iter must not be NULL"));
        }
        // SAFETY: name_prefix is NULL or a valid C string (agc_policy.h contract).
        let prefix = unsafe { optional_str(req.name_prefix, "name_prefix") }?.unwrap_or("");
        let policies = ctx.policies.list()?.into_iter().filter(|p| p.name().starts_with(prefix)).collect();
        let it = Box::new(PolicyIter { policies, next: 0 });
        // SAFETY: out_iter is non-null (checked) and points to the caller's variable.
        unsafe { out_iter.write(Box::into_raw(it).cast()) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_policy_iter_next(it: *mut agc_policy_iter, out: *mut agc_policy_summary_response) -> agc_rc {
    guard(|| {
        // SAFETY: it is NULL or from agc_list_policies and not freed; an
        // iterator is used by one thread at a time (like a session).
        let it = unsafe { it.cast::<PolicyIter>().as_mut() }.ok_or_else(|| FfiError::invalid("it must not be NULL"))?;
        // SAFETY: out is NULL or the caller's struct with struct_size accessible bytes.
        let mut resp = unsafe { versioned::read(out, "out") }?;
        let Some(policy) = it.policies.get(it.next) else {
            return Err(FfiError::IteratorExhausted);
        };
        let result = fill_policy_summary_response(&mut resp, policy);
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
pub unsafe extern "C" fn agc_policy_iter_free(it: *mut agc_policy_iter) {
    if it.is_null() {
        return;
    }
    // SAFETY: it came from Box::into_raw in agc_list_policies and is freed once.
    guard_value((), || drop(unsafe { Box::from_raw(it.cast::<PolicyIter>()) }))
}

/// A policy document: required (NULL is invalid), but may be empty, which
/// is a policy that allows nothing.
///
/// # Safety
/// `p` is NULL or a valid C string.
unsafe fn document<'a>(p: *const std::ffi::c_char) -> Result<&'a str, FfiError> {
    // SAFETY: forwarded from this function's contract.
    unsafe { null_check_c_string(p) }
        .ok_or_else(|| FfiError::invalid("policy_document must not be NULL"))?
        .to_str()
        .map_err(|_| FfiError::invalid("policy_document must be UTF-8"))
}
