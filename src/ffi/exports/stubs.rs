//! The operations the Go server does not implement (DEVIATIONS G30): its
//! handlers return gRPC Unimplemented, so these return
//! AGC_ERR_NOT_IMPLEMENTED with a last_error message. They exist so that C
//! programs link and can detect the gap at run time, and so the build checks
//! their signatures against the headers like any other export.
//!
//! A stub writes nothing, with two exceptions that keep the header's
//! fail-safe rules: a verify-shaped response gets `valid = 0` (D9), and an
//! output handle pointer gets NULL. A NULL context is rejected first, as by
//! every export; a session argument is never dereferenced (no session can
//! exist while streaming is a stub).

use std::ffi::{c_char, c_int};

use crate::bindings::*;
use crate::ffi::error::FfiError;
use crate::ffi::exports::core::context;
use crate::ffi::guard::guard;

/// The stub body: check the context, then refuse.
///
/// # Safety
/// `ctx` is NULL or a context from agc_ctx_open.
unsafe fn not_implemented(ctx: *mut agc_ctx, what: &'static str) -> agc_rc {
    guard(|| {
        // SAFETY: forwarded from this function's contract.
        unsafe { context(ctx) }?;
        Err(FfiError::NotImplemented(what))
    })
}

/// The stub body for calls on a session, which cannot exist: refuse
/// without touching the handle.
fn session_not_implemented(what: &'static str) -> agc_rc {
    guard(|| Err(FfiError::NotImplemented(what)))
}

/// Clears `valid` in a caller's verify response before refusing, as every
/// verify-shaped call must (agc_verify_response, D9). Only `valid` is
/// written, and only when the struct is big enough to have it.
///
/// # Safety
/// `resp` is NULL or the caller's struct with struct_size accessible bytes.
unsafe fn clear_valid(resp: *mut agc_verify_response) {
    if resp.is_null() {
        return;
    }
    // SAFETY: resp is non-null; struct_size is its first field (agc_abi.h).
    let size = unsafe { resp.cast::<usize>().read_unaligned() };
    if size >= std::mem::offset_of!(agc_verify_response, valid) + size_of::<std::ffi::c_int>() {
        // SAFETY: the caller's struct has the field (size checked above).
        unsafe { std::ptr::addr_of_mut!((*resp).valid).write_unaligned(0) };
    }
}

/// Sets an output handle to NULL, so a caller that ignores the rc does not
/// use an uninitialised pointer.
///
/// # Safety
/// `out` is NULL or valid for writing one pointer.
unsafe fn clear<T>(out: *mut *mut T) {
    if !out.is_null() {
        // SAFETY: non-null and writable (this function's contract).
        unsafe { out.write(std::ptr::null_mut()) };
    }
}

// --- agc_key.h: KeyManagementService ---------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_delete_key(ctx: *mut agc_ctx, _key_name: *const c_char, _remove_metadata: c_int) -> agc_rc {
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "DeleteKey (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_rotate_key(
    ctx: *mut agc_ctx,
    _key_name: *const c_char,
    _reason: *const c_char,
    _resp: *mut agc_key_info_response,
) -> agc_rc {
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "RotateKey (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_update_key_state(
    ctx: *mut agc_ctx,
    _key_name: *const c_char,
    _target_state: agc_key_lifecycle_state,
    _reason: *const c_char,
    _resp: *mut agc_key_info_response,
) -> agc_rc {
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "UpdateKeyState (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_update_key_policy(
    ctx: *mut agc_ctx,
    _key_name: *const c_char,
    _new_policy_name: *const c_char,
    _resp: *mut agc_key_info_response,
) -> agc_rc {
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "UpdateKeyPolicy (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_export_key(
    ctx: *mut agc_ctx,
    _params: *const agc_export_key_params,
    _resp: *mut agc_export_key_response,
) -> agc_rc {
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "ExportKey (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_import_key(
    ctx: *mut agc_ctx,
    _params: *const agc_import_key_params,
    _resp: *mut agc_key_info_response,
) -> agc_rc {
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "ImportKey (the Go server does not implement it)") }
}

// --- agc_crypto.h: CryptoService -------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_generate_mac(
    ctx: *mut agc_ctx,
    _req: *const agc_mac_request,
    _resp: *mut agc_mac_response,
) -> agc_rc {
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "GenerateMAC (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_verify_mac(
    ctx: *mut agc_ctx,
    _req: *const agc_verify_mac_request,
    resp: *mut agc_verify_response,
) -> agc_rc {
    // SAFETY: resp is NULL or the caller's struct (header contract).
    unsafe { clear_valid(resp) };
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "VerifyMAC (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_digest(
    ctx: *mut agc_ctx,
    _req: *const agc_digest_request,
    _resp: *mut agc_digest_response,
) -> agc_rc {
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "Digest (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_xof(
    ctx: *mut agc_ctx,
    _req: *const agc_xof_request,
    _resp: *mut agc_digest_response,
) -> agc_rc {
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "Xof (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_generate_random(
    ctx: *mut agc_ctx,
    _req: *const agc_random_request,
    _resp: *mut agc_random_response,
) -> agc_rc {
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "GenerateRandom (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_random_bytes(ctx: *mut agc_ctx, _out: *mut u8, _len: usize) -> agc_rc {
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "GenerateRandom (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_seed_random(
    ctx: *mut agc_ctx,
    _req: *const agc_seed_random_request,
    _resp: *mut agc_seed_random_response,
) -> agc_rc {
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "SeedRandom (the Go server does not implement it)") }
}

// --- agc_stream.h: StreamingCryptoService ----------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_encrypt_init(
    ctx: *mut agc_ctx,
    _req: *const agc_encrypt_init_request,
    out_session: *mut *mut agc_session,
) -> agc_rc {
    // SAFETY: out_session is NULL or the caller's pointer variable (header contract).
    unsafe { clear(out_session) };
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "EncryptInit (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_encrypt_update(
    _s: *mut agc_session,
    _plaintext_chunk: agc_slice,
    _resp: *mut agc_stream_chunk_response,
) -> agc_rc {
    session_not_implemented("EncryptUpdate (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_encrypt_final(_s: *mut agc_session, _resp: *mut agc_stream_final_response) -> agc_rc {
    session_not_implemented("EncryptFinal (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_decrypt_init(
    ctx: *mut agc_ctx,
    _req: *const agc_decrypt_init_request,
    out_session: *mut *mut agc_session,
) -> agc_rc {
    // SAFETY: out_session is NULL or the caller's pointer variable (header contract).
    unsafe { clear(out_session) };
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "DecryptInit (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_decrypt_update(
    _s: *mut agc_session,
    _ciphertext_chunk: agc_slice,
    _resp: *mut agc_stream_chunk_response,
) -> agc_rc {
    session_not_implemented("DecryptUpdate (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_decrypt_final(_s: *mut agc_session, _resp: *mut agc_stream_final_response) -> agc_rc {
    session_not_implemented("DecryptFinal (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_encrypt_message_init(
    ctx: *mut agc_ctx,
    _req: *const agc_encrypt_init_request,
    out_session: *mut *mut agc_session,
) -> agc_rc {
    // SAFETY: out_session is NULL or the caller's pointer variable (header contract).
    unsafe { clear(out_session) };
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "EncryptMessageInit (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_encrypt_message(
    ctx: *mut agc_ctx,
    _req: *const agc_encrypt_message_request,
    _resp: *mut agc_encrypt_response,
) -> agc_rc {
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "EncryptMessage (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_encrypt_message_begin(
    _s: *mut agc_session,
    _associated_data: agc_slice,
    _resp: *mut agc_stream_metadata_response,
) -> agc_rc {
    session_not_implemented("EncryptMessageBegin (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_encrypt_message_next(
    _s: *mut agc_session,
    _plaintext_chunk: agc_slice,
    _end_of_message: c_int,
    _resp: *mut agc_stream_chunk_response,
) -> agc_rc {
    session_not_implemented("EncryptMessageNext (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_encrypt_message_final(_s: *mut agc_session) -> agc_rc {
    session_not_implemented("EncryptMessageFinal (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_decrypt_message_init(
    ctx: *mut agc_ctx,
    _req: *const agc_decrypt_message_init_request,
    out_session: *mut *mut agc_session,
) -> agc_rc {
    // SAFETY: out_session is NULL or the caller's pointer variable (header contract).
    unsafe { clear(out_session) };
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "DecryptMessageInit (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_decrypt_message(
    ctx: *mut agc_ctx,
    _req: *const agc_decrypt_message_request,
    _resp: *mut agc_decrypt_response,
) -> agc_rc {
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "DecryptMessage (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_decrypt_message_begin(
    _s: *mut agc_session,
    _associated_data: agc_slice,
    _partial_metadata: agc_slice,
) -> agc_rc {
    session_not_implemented("DecryptMessageBegin (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_decrypt_message_next(
    _s: *mut agc_session,
    _ciphertext_chunk: agc_slice,
    _end_of_message: c_int,
    _resp: *mut agc_stream_chunk_response,
) -> agc_rc {
    session_not_implemented("DecryptMessageNext (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_decrypt_message_final(_s: *mut agc_session) -> agc_rc {
    session_not_implemented("DecryptMessageFinal (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_sign_init(
    ctx: *mut agc_ctx,
    _req: *const agc_sign_init_request,
    out_session: *mut *mut agc_session,
) -> agc_rc {
    // SAFETY: out_session is NULL or the caller's pointer variable (header contract).
    unsafe { clear(out_session) };
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "SignInit (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_sign_update(_s: *mut agc_session, _data_chunk: agc_slice) -> agc_rc {
    session_not_implemented("SignUpdate (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_sign_final(_s: *mut agc_session, _resp: *mut agc_sign_response) -> agc_rc {
    session_not_implemented("SignFinal (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_verify_init(
    ctx: *mut agc_ctx,
    _req: *const agc_verify_init_request,
    out_session: *mut *mut agc_session,
) -> agc_rc {
    // SAFETY: out_session is NULL or the caller's pointer variable (header contract).
    unsafe { clear(out_session) };
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "VerifyInit (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_verify_update(_s: *mut agc_session, _data_chunk: agc_slice) -> agc_rc {
    session_not_implemented("VerifyUpdate (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_verify_final(
    _s: *mut agc_session,
    _signature: agc_slice,
    resp: *mut agc_verify_response,
) -> agc_rc {
    // SAFETY: resp is NULL or the caller's struct (header contract).
    unsafe { clear_valid(resp) };
    session_not_implemented("VerifyFinal (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_sign_message_init(
    ctx: *mut agc_ctx,
    _req: *const agc_sign_init_request,
    out_session: *mut *mut agc_session,
) -> agc_rc {
    // SAFETY: out_session is NULL or the caller's pointer variable (header contract).
    unsafe { clear(out_session) };
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "SignMessageInit (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_sign_message(
    ctx: *mut agc_ctx,
    _req: *const agc_sign_message_request,
    _resp: *mut agc_sign_response,
) -> agc_rc {
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "SignMessage (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_sign_message_begin(_s: *mut agc_session) -> agc_rc {
    session_not_implemented("SignMessageBegin (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_sign_message_next(
    _s: *mut agc_session,
    _message_chunk: agc_slice,
    _end_of_message: c_int,
    _resp: *mut agc_sign_response,
) -> agc_rc {
    session_not_implemented("SignMessageNext (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_sign_message_final(_s: *mut agc_session) -> agc_rc {
    session_not_implemented("SignMessageFinal (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_verify_message_init(
    ctx: *mut agc_ctx,
    _req: *const agc_verify_init_request,
    out_session: *mut *mut agc_session,
) -> agc_rc {
    // SAFETY: out_session is NULL or the caller's pointer variable (header contract).
    unsafe { clear(out_session) };
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "VerifyMessageInit (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_verify_message(
    ctx: *mut agc_ctx,
    _req: *const agc_verify_message_request,
    resp: *mut agc_verify_response,
) -> agc_rc {
    // SAFETY: resp is NULL or the caller's struct (header contract).
    unsafe { clear_valid(resp) };
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "VerifyMessage (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_verify_message_begin(_s: *mut agc_session) -> agc_rc {
    session_not_implemented("VerifyMessageBegin (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_verify_message_next(
    _s: *mut agc_session,
    _message_chunk: agc_slice,
    _end_of_message: c_int,
    _signature: agc_slice,
    resp: *mut agc_verify_response,
) -> agc_rc {
    // SAFETY: resp is NULL or the caller's struct (header contract).
    unsafe { clear_valid(resp) };
    session_not_implemented("VerifyMessageNext (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_verify_message_final(_s: *mut agc_session) -> agc_rc {
    session_not_implemented("VerifyMessageFinal (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_digest_init(
    ctx: *mut agc_ctx,
    _req: *const agc_digest_init_request,
    out_session: *mut *mut agc_session,
) -> agc_rc {
    // SAFETY: out_session is NULL or the caller's pointer variable (header contract).
    unsafe { clear(out_session) };
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "DigestInit (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_digest_update(_s: *mut agc_session, _data_chunk: agc_slice) -> agc_rc {
    session_not_implemented("DigestUpdate (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_digest_key(_s: *mut agc_session, _key_name: *const c_char) -> agc_rc {
    session_not_implemented("DigestKey (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_digest_final(_s: *mut agc_session, _resp: *mut agc_digest_response) -> agc_rc {
    session_not_implemented("DigestFinal (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_xof_init(
    ctx: *mut agc_ctx,
    _req: *const agc_xof_init_request,
    out_session: *mut *mut agc_session,
) -> agc_rc {
    // SAFETY: out_session is NULL or the caller's pointer variable (header contract).
    unsafe { clear(out_session) };
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "XofInit (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_xof_update(_s: *mut agc_session, _data_chunk: agc_slice) -> agc_rc {
    session_not_implemented("XofUpdate (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_xof_final(_s: *mut agc_session, _resp: *mut agc_digest_response) -> agc_rc {
    session_not_implemented("XofFinal (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_digest_encrypt_update(
    _digest_session: *mut agc_session,
    _encrypt_session: *mut agc_session,
    _plaintext_chunk: agc_slice,
    _resp: *mut agc_stream_chunk_response,
) -> agc_rc {
    session_not_implemented("DigestEncryptUpdate (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_decrypt_digest_update(
    _decrypt_session: *mut agc_session,
    _digest_session: *mut agc_session,
    _ciphertext_chunk: agc_slice,
    _resp: *mut agc_stream_chunk_response,
) -> agc_rc {
    session_not_implemented("DecryptDigestUpdate (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_sign_encrypt_update(
    _sign_session: *mut agc_session,
    _encrypt_session: *mut agc_session,
    _plaintext_chunk: agc_slice,
    _resp: *mut agc_stream_chunk_response,
) -> agc_rc {
    session_not_implemented("SignEncryptUpdate (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_decrypt_verify_update(
    _decrypt_session: *mut agc_session,
    _verify_session: *mut agc_session,
    _ciphertext_chunk: agc_slice,
    _resp: *mut agc_stream_chunk_response,
) -> agc_rc {
    session_not_implemented("DecryptVerifyUpdate (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_generate_mac_init(
    ctx: *mut agc_ctx,
    _req: *const agc_generate_mac_init_request,
    out_session: *mut *mut agc_session,
) -> agc_rc {
    // SAFETY: out_session is NULL or the caller's pointer variable (header contract).
    unsafe { clear(out_session) };
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "GenerateMACInit (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_generate_mac_update(_s: *mut agc_session, _data_chunk: agc_slice) -> agc_rc {
    session_not_implemented("GenerateMACUpdate (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_generate_mac_final(_s: *mut agc_session, _resp: *mut agc_mac_response) -> agc_rc {
    session_not_implemented("GenerateMACFinal (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_verify_mac_init(
    ctx: *mut agc_ctx,
    _req: *const agc_verify_mac_init_request,
    out_session: *mut *mut agc_session,
) -> agc_rc {
    // SAFETY: out_session is NULL or the caller's pointer variable (header contract).
    unsafe { clear(out_session) };
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "VerifyMACInit (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_verify_mac_update(_s: *mut agc_session, _data_chunk: agc_slice) -> agc_rc {
    session_not_implemented("VerifyMACUpdate (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_verify_mac_final(
    _s: *mut agc_session,
    _mac: agc_slice,
    resp: *mut agc_verify_response,
) -> agc_rc {
    // SAFETY: resp is NULL or the caller's struct (header contract).
    unsafe { clear_valid(resp) };
    session_not_implemented("VerifyMACFinal (the Go server does not implement it)")
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_cancel_operation(
    ctx: *mut agc_ctx,
    _operation_id: *const c_char,
    _reason: *const c_char,
) -> agc_rc {
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "CancelOperation (the Go server does not implement it)") }
}

// --- agc_establish.h: KeyEstablishmentService ------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_wrap_key(
    ctx: *mut agc_ctx,
    _req: *const agc_wrap_key_request,
    _resp: *mut agc_wrap_key_response,
) -> agc_rc {
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "WrapKey (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_unwrap_key(
    ctx: *mut agc_ctx,
    _req: *const agc_unwrap_key_request,
    _resp: *mut agc_establish_key_response,
) -> agc_rc {
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "UnwrapKey (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_derive_key(
    ctx: *mut agc_ctx,
    _req: *const agc_derive_key_request,
    _resp: *mut agc_establish_key_response,
) -> agc_rc {
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "DeriveKey (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_key_agreement(
    ctx: *mut agc_ctx,
    _req: *const agc_key_agreement_request,
    _resp: *mut agc_establish_key_response,
) -> agc_rc {
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "KeyAgreement (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_encapsulate_key(
    ctx: *mut agc_ctx,
    _req: *const agc_encapsulate_key_request,
    _resp: *mut agc_encapsulate_key_response,
) -> agc_rc {
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "EncapsulateKey (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_decapsulate_key(
    ctx: *mut agc_ctx,
    _req: *const agc_decapsulate_key_request,
    _resp: *mut agc_establish_key_response,
) -> agc_rc {
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "DecapsulateKey (the Go server does not implement it)") }
}

// --- agc_policy.h: CryptoPolicyService -------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_evaluate_policy(
    ctx: *mut agc_ctx,
    _req: *const agc_evaluate_policy_request,
    _resp: *mut agc_evaluate_policy_response,
) -> agc_rc {
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "EvaluatePolicy (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_batch_evaluate_policy(
    ctx: *mut agc_ctx,
    _req: *const agc_batch_evaluate_policy_request,
    _resp: *mut agc_batch_evaluate_policy_response,
) -> agc_rc {
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "BatchEvaluatePolicy (the Go server does not implement it)") }
}

// --- agc_provider.h: ProviderService ---------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_register_provider_instance(
    ctx: *mut agc_ctx,
    _instance: *const agc_provider_instance,
    _resp: *mut agc_provider_instance_response,
) -> agc_rc {
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "RegisterProviderInstance (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_update_provider_instance(
    ctx: *mut agc_ctx,
    _instance: *const agc_provider_instance,
    _resp: *mut agc_provider_instance_response,
) -> agc_rc {
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "UpdateProviderInstance (the Go server does not implement it)") }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_delete_provider_instance(ctx: *mut agc_ctx, _instance_id: *const c_char) -> agc_rc {
    // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
    unsafe { not_implemented(ctx, "DeleteProviderInstance (the Go server does not implement it)") }
}

// --- agc_core.h: sessions ---------------------------------------------------
//
// Every function that creates a session is a stub, so no `agc_session*` this
// library could have issued exists. The accessors report "none" and the
// cleanup calls do nothing: both are what the header asks of an unknown
// session, and neither dereferences the handle.

#[unsafe(no_mangle)]
pub extern "C" fn agc_session_id(_s: *const agc_session) -> *const c_char {
    std::ptr::null()
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_session_operation(_s: *const agc_session) -> agc_crypto_operation {
    agc_crypto_operation_AGC_CRYPTO_OPERATION_UNSPECIFIED
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_session_selected_template_id(_s: *const agc_session) -> *const c_char {
    std::ptr::null()
}

/// agc_core.h: "cancelling an unknown or already-closed session succeeds".
#[unsafe(no_mangle)]
pub extern "C" fn agc_session_cancel(_s: *mut agc_session, _reason: *const c_char) -> agc_rc {
    AGC_OK as agc_rc
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_session_free(_s: *mut agc_session) {}

/// agc_core.h: "Fails with AGC_ERR_CRYPTO_OPERATION_EXPIRED if unknown" --
/// and every operation_id is unknown.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_session_attach(
    ctx: *mut agc_ctx,
    _operation_id: *const c_char,
    out_session: *mut *mut agc_session,
) -> agc_rc {
    // SAFETY: out_session is NULL or the caller's pointer variable (agc_core.h).
    unsafe { clear(out_session) };
    guard(|| {
        // SAFETY: ctx is NULL or a context from agc_ctx_open (agc_core.h).
        unsafe { context(ctx) }?;
        Err(FfiError::Domain(crate::domain::core::Error::new(
            crate::domain::core::Code::OperationExpired,
            "agc_session_attach",
            "no session has this operation_id (streaming is not implemented)",
        )))
    })
}
