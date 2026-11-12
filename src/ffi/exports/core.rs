//! agc_core.h — version, context, errors, memory hygiene. agc_types.h — rc helpers.

use std::ffi::{CString, c_char, c_int, c_void};
use std::ptr;
use std::sync::LazyLock;

use crate::bindings::*;
use crate::ffi::context::{Config, Context};
use crate::ffi::error::{FfiError, rc_message, rc_name};
use crate::ffi::guard::{guard, guard_value};
use crate::ffi::{last_error, versioned};
use crate::secret as secure_memory;

// --- Version ---------------------------------------------------------------

/// The API version this library implements, from agc_abi.h.
static VERSION: LazyLock<CString> = LazyLock::new(|| {
    CString::new(format!("{AGC_API_VERSION_MAJOR}.{AGC_API_VERSION_MINOR}.{AGC_API_VERSION_PATCH}")).unwrap()
});

static BUILD_INFO: LazyLock<CString> = LazyLock::new(|| {
    CString::new(format!(
        "agilecrypto (Rust) {}; api {}; providers: none; fips=0",
        env!("CARGO_PKG_VERSION"),
        VERSION.to_str().unwrap(),
    ))
    .unwrap()
});

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_version(major: *mut c_int, minor: *mut c_int, patch: *mut c_int) {
    // A version number is tiny; the casts cannot truncate.
    for (out, v) in [(major, AGC_API_VERSION_MAJOR), (minor, AGC_API_VERSION_MINOR), (patch, AGC_API_VERSION_PATCH)] {
        if !out.is_null() {
            // SAFETY: each pointer is NULL (skipped) or the caller's writable int.
            unsafe { out.write(v as c_int) };
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_version_string() -> *const c_char {
    guard_value(ptr::null(), || VERSION.as_ptr())
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_build_info() -> *const c_char {
    guard_value(ptr::null(), || BUILD_INFO.as_ptr())
}

// --- Context ---------------------------------------------------------------

/// The context behind a caller's `agc_ctx*`. Shared, never `&mut`: other
/// threads may be using the same context (agc_core.h, THREADING).
///
/// # Safety
/// `ctx` is NULL or was returned by `agc_ctx_open` and not closed yet.
pub(in crate::ffi) unsafe fn context<'a>(ctx: *mut agc_ctx) -> Result<&'a Context, FfiError> {
    // SAFETY: by this function's contract, a non-NULL ctx came from Box::into_raw
    // in agc_ctx_open and is still alive; only shared references are made from it.
    let ctx = unsafe { ctx.cast::<Context>().as_ref() }.ok_or_else(|| FfiError::invalid("ctx must not be NULL"))?;
    if ctx.pid != crate::ffi::context::pid() {
        return Err(FfiError::InvalidHandle(
            "the context was inherited across fork(); call agc_ctx_reinit_after_fork",
        ));
    }
    Ok(ctx)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_ctx_open(cfg: *const agc_ctx_config, out_ctx: *mut *mut agc_ctx) -> agc_rc {
    guard(|| {
        if out_ctx.is_null() {
            return Err(FfiError::invalid("out_ctx must not be NULL"));
        }
        // SAFETY: cfg is NULL or the caller's config with struct_size accessible bytes.
        let cfg = unsafe { versioned::read(cfg, "cfg") }?;
        // SAFETY: cfg's strings are NULL or valid C strings (agc_core.h contract).
        let ctx = Box::new(Context::open(unsafe { Config::from_c(&cfg) }?)?);
        // SAFETY: out_ctx is non-null (checked above) and points to the caller's agc_ctx* variable.
        unsafe { out_ctx.write(Box::into_raw(ctx).cast::<agc_ctx>()) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_ctx_close(ctx: *mut agc_ctx) {
    if ctx.is_null() {
        return;
    }
    // Dropping runs only our own destructors; a panic there must not unwind into C.
    let _ = guard(|| {
        // SAFETY: ctx is non-null and, per the agc_core.h contract, came from
        // Box::into_raw in agc_ctx_open, has not been closed before, and no
        // other thread uses it any more.
        drop(unsafe { Box::from_raw(ctx.cast::<Context>()) });
        Ok(())
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_ctx_reinit_after_fork(poisoned: *mut agc_ctx, out_ctx: *mut *mut agc_ctx) -> agc_rc {
    guard(|| {
        if out_ctx.is_null() {
            return Err(FfiError::invalid("out_ctx must not be NULL"));
        }
        // SAFETY: poisoned is NULL or a context opened by agc_ctx_open, in
        // this process or the parent this one was forked from; only shared
        // references are made, as for any context.
        let old = unsafe { poisoned.cast::<Context>().as_ref() }.ok_or_else(|| FfiError::invalid("poisoned must not be NULL"))?;
        if old.pid == crate::ffi::context::pid() {
            return Err(FfiError::invalid("the context is not poisoned: it was opened in this process"));
        }
        // The inherited context still holds the child's copy of the key
        // store's lock descriptor; with it open, the fresh context could
        // never lock the store, even after the parent has closed it.
        // Releasing it first leaves the poisoned context unusable but still
        // valid to close, should opening fail.
        old.release_inherited();
        let fresh = Box::new(Context::open(old.config.clone())?);
        // agc_core.h: "The inherited context is closed". The child owns its
        // copy of the parent's memory, so freeing it touches nothing of the
        // parent's. (A context holds no threads; its only descriptor, the
        // store lock, was closed above.)
        // SAFETY: poisoned came from Box::into_raw in agc_ctx_open; the
        // child's caller hands it over and does not use it again.
        drop(unsafe { Box::from_raw(poisoned.cast::<Context>()) });
        // SAFETY: out_ctx is non-null (checked above) and points to the caller's agc_ctx* variable.
        unsafe { out_ctx.write(Box::into_raw(fresh).cast::<agc_ctx>()) };
        Ok(())
    })
}

/// The mode the context was opened in. EMBEDDED for a NULL or poisoned
/// context too: it is the only mode a context can have here, so the answer
/// is right without dereferencing anything.
#[unsafe(no_mangle)]
pub extern "C" fn agc_ctx_mode(_ctx: *const agc_ctx) -> agc_mode {
    agc_mode_AGC_MODE_EMBEDDED
}

// --- Errors ----------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_last_error(out: *mut agc_error_detail) -> agc_rc {
    // Not through `guard`: reading the error must not record a new one.
    // SAFETY: out is NULL or the caller's struct with struct_size accessible bytes.
    match unsafe { versioned::read(out, "out") } {
        Ok(_) => {
            // SAFETY: out passed versioned::read, so its struct_size is valid.
            unsafe { versioned::write_back(out, &last_error::detail()) };
            AGC_OK as agc_rc
        }
        Err(e) => e.rc(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_clear_error() {
    last_error::clear();
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_rc_name(rc: agc_rc) -> *const c_char {
    rc_name(rc).unwrap_or(c"(unknown agc_rc)").as_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_rc_message(rc: agc_rc) -> *const c_char {
    rc_message(rc).unwrap_or(c"unknown result code").as_ptr()
}

// --- Memory hygiene --------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_secure_zero(p: *mut c_void, n: usize) {
    // SAFETY: p is NULL or valid for n bytes (agc_core.h contract).
    guard_value((), || unsafe { secure_memory::zero(p.cast(), n) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_ct_equal(a: *const c_void, b: *const c_void, n: usize) -> c_int {
    // SAFETY: a and b are NULL or valid for n bytes (agc_core.h contract).
    guard_value(0, || c_int::from(unsafe { secure_memory::ct_equal(a.cast(), b.cast(), n) }))
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_secure_alloc(n: usize) -> *mut c_void {
    guard_value(ptr::null_mut(), || secure_memory::alloc(n).cast())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_secure_free(p: *mut c_void, n: usize) {
    // SAFETY: p is NULL or from agc_secure_alloc and not freed (agc_core.h contract).
    guard_value((), || unsafe { secure_memory::free(p.cast(), n) })
}
