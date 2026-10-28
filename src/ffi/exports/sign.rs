//! agc_crypto.h — Sign / Verify, DigestSign / DigestVerify, and the sizing
//! helpers agc_hash_algorithm_output_len and agc_metadata_max_encoded_len.

use std::ffi::c_char;

use super::crypto::{put, short};
use crate::app::{CryptoOrchestrator, SignInput, SignRequest, VerifyRequest};
use crate::bindings::*;
use crate::domain::core::hash_output_len;
use crate::domain::crypto::metadata::{self, MetadataEncoding};
use crate::domain::provider::SignContext;
use crate::ffi::error::FfiError;
use crate::ffi::exports::core::context;
use crate::ffi::guard::{guard, guard_value};
use crate::ffi::translation::{encoding, kv_list, required_str, slice};
use crate::ffi::versioned;
use crate::proto::api::HashAlgorithm;

/// The caller's signature parameters. The oneof is required.
///
/// # Safety
/// `p` is NULL or a versioned struct readable for its struct_size.
unsafe fn sign_params(p: *const agc_sign_params) -> Result<SignContext, FfiError> {
    // SAFETY: forwarded from this function's contract.
    let p = unsafe { versioned::read(p, "params") }?;
    match p.kind {
        agc_sign_params_kind_AGC_SIGN_PARAMS_NO_CONTEXT => Ok(SignContext::None),
        agc_sign_params_kind_AGC_SIGN_PARAMS_DOMAIN_CONTEXT => {
            // SAFETY: kind selects the domain_context member, a byte array
            // and a byte; every bit pattern is valid.
            let d = unsafe { p.u.domain_context };
            // context_len is a u8, so the 255-byte bound is structural.
            Ok(SignContext::Domain(d.context[..usize::from(d.context_len)].to_vec()))
        }
        agc_sign_params_kind_AGC_SIGN_PARAMS_VENDOR => Err(FfiError::NotImplemented("vendor signature parameters")),
        agc_sign_params_kind_AGC_SIGN_PARAMS_NONE => {
            Err(FfiError::invalid("params.kind is required (NONE is not a choice)"))
        }
        other => Err(FfiError::invalid(format!("params.kind {other} is not a signature parameter kind"))),
    }
}

/// The hash a digest request declares. UNSPECIFIED passes through for the
/// core to refuse with the other request-shape rules; OTHER is refused there
/// too (no fixed length), so its OID is not consulted.
fn hash(h: agc_hash_algorithm) -> Result<HashAlgorithm, FfiError> {
    i32::try_from(h)
        .ok()
        .and_then(|v| HashAlgorithm::try_from(v).ok())
        .ok_or_else(|| FfiError::invalid(format!("hash_algorithm {h} is not a hash algorithm")))
}

/// The common half of agc_sign and agc_digest_sign: size, then sign.
fn sign_into(
    crypto: &CryptoOrchestrator,
    request: SignRequest,
    enc: MetadataEncoding,
    out: &mut agc_sign_response,
) -> Result<(), FfiError> {
    // SIZE QUERIES: every length is set, and a NULL or short region stops
    // the call before the key is touched or randomness drawn. The signature
    // length is a bound (DER-encoded ECDSA varies); the metadata's is exact.
    let (sig_len, md_len) = crypto.sign_sizes(&request, enc)?;
    out.signature_len = sig_len;
    out.metadata_len = md_len;
    if short(out.signature, sig_len) || short(out.metadata, md_len) {
        return Err(FfiError::BufferTooSmall { needed: sig_len.max(md_len) });
    }
    let s = crypto.sign(request)?;
    let md = metadata::encode(&s.metadata, enc)?;
    debug_assert_eq!(md.len(), md_len, "metadata sizes are exact");
    put(out.signature, &s.signature);
    put(out.metadata, &md);
    out.signature_len = s.signature.len();
    out.metadata_len = md.len();
    out.key_version = s.metadata.key_version;
    Ok(())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_sign(
    ctx: *mut agc_ctx,
    req: *const agc_sign_request,
    resp: *mut agc_sign_response,
) -> agc_rc {
    guard(|| {
        // SAFETY: ctx is NULL or a live context (agc_core.h contract).
        let ctx = unsafe { context(ctx) }?;
        // SAFETY: req is NULL or the caller's struct with struct_size readable bytes.
        let r = unsafe { versioned::read(req, "req") }?;
        // SAFETY: resp is NULL or the caller's struct with struct_size accessible bytes.
        let mut out = unsafe { versioned::read(resp, "resp") }?;
        let enc = encoding(r.metadata_encoding, "metadata_encoding")?;
        let request = SignRequest {
            // SAFETY: the pointers and slices in req
            // are NULL or valid for the call (agc_crypto.h contract).
            key_name: unsafe { required_str(r.key_name, "key_name") }?,
            // SAFETY: as above.
            input: SignInput::Message(unsafe { slice(r.input, "input") }?),
            // SAFETY: as above.
            context: unsafe { sign_params(r.params) }?,
            // SAFETY: as above.
            user_context: unsafe { kv_list(&r.user_context, "user_context") }?,
        };
        let result = sign_into(&ctx.crypto, request, enc, &mut out);
        // SAFETY: resp passed versioned::read above.
        unsafe { versioned::write_back(resp, &out) };
        result
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_digest_sign(
    ctx: *mut agc_ctx,
    req: *const agc_digest_sign_request,
    resp: *mut agc_sign_response,
) -> agc_rc {
    guard(|| {
        // SAFETY: ctx is NULL or a live context (agc_core.h contract).
        let ctx = unsafe { context(ctx) }?;
        // SAFETY: req is NULL or the caller's struct with struct_size readable bytes.
        let r = unsafe { versioned::read(req, "req") }?;
        // SAFETY: resp is NULL or the caller's struct with struct_size accessible bytes.
        let mut out = unsafe { versioned::read(resp, "resp") }?;
        let enc = encoding(r.metadata_encoding, "metadata_encoding")?;
        let request = SignRequest {
            // SAFETY: as in agc_sign, the pointers in req are NULL or valid.
            key_name: unsafe { required_str(r.key_name, "key_name") }?,
            input: SignInput::Digest {
                // SAFETY: as above.
                digest: unsafe { slice(r.digest, "digest") }?,
                hash: hash(r.hash_algorithm)?,
            },
            // SAFETY: as above.
            context: unsafe { sign_params(r.params) }?,
            // SAFETY: as above.
            user_context: unsafe { kv_list(&r.user_context, "user_context") }?,
        };
        let result = sign_into(&ctx.crypto, request, enc, &mut out);
        // SAFETY: resp passed versioned::read above.
        unsafe { versioned::write_back(resp, &out) };
        result
    })
}

/// The signing metadata a verify request carries: its encoding (the
/// response's, too) and the version it names. `{NULL, 0}` means the latest
/// version, and the response is in WIRE_V1 (agc_verify_response).
///
/// # Safety
/// `md` is valid for the call (agc_crypto.h contract).
unsafe fn verify_metadata(md: agc_slice) -> Result<(MetadataEncoding, Option<u32>), FfiError> {
    // SAFETY: forwarded from this function's contract.
    let bytes = unsafe { slice(md, "metadata") }?;
    let Some(&first) = bytes.first() else {
        return Ok((MetadataEncoding::WireV1, None));
    };
    let enc = MetadataEncoding::from_byte(first)
        .ok_or_else(|| FfiError::invalid("metadata must begin with its encoding byte"))?;
    let version = metadata::decode(enc, bytes)?.key_version;
    if version == 0 {
        return Err(FfiError::invalid("the metadata names no key version"));
    }
    Ok((enc, Some(version)))
}

/// The common half of agc_verify and agc_digest_verify, on a response whose
/// `valid` is already 0.
fn verify_into(
    crypto: &CryptoOrchestrator,
    request: VerifyRequest,
    enc: MetadataEncoding,
    out: &mut agc_verify_response,
) -> Result<(), FfiError> {
    // The metadata output is optional: {NULL, 0} opts out; it is not a size
    // query. A short region stops the call before the key is touched.
    let wants_md = !(out.metadata.data.is_null() && out.metadata.cap == 0);
    if wants_md {
        let md_len = crypto.verify_sizes(&request, enc)?;
        out.metadata_len = md_len;
        if short(out.metadata, md_len) {
            return Err(FfiError::BufferTooSmall { needed: md_len });
        }
    }
    let v = crypto.verify(request)?;
    out.key_version = v.metadata.key_version;
    if !v.valid {
        out.metadata_len = 0;
        return Err(FfiError::SignatureInvalid);
    }
    if wants_md {
        let md = metadata::encode(&v.metadata, enc)?;
        put(out.metadata, &md);
        out.metadata_len = md.len();
    }
    out.valid = 1;
    Ok(())
}

/// Reads `resp` and records `valid = 0` in it before anything else can
/// fail (the D9 contract), then runs `body` and writes the response back.
///
/// # Safety
/// `resp` is NULL or the caller's struct with struct_size accessible bytes.
unsafe fn fail_closed(
    resp: *mut agc_verify_response,
    body: impl FnOnce(&mut agc_verify_response) -> Result<(), FfiError>,
) -> Result<(), FfiError> {
    // SAFETY: forwarded from this function's contract.
    let mut out = unsafe { versioned::read(resp, "resp") }?;
    out.valid = 0;
    out.metadata_len = 0;
    out.key_version = 0;
    // SAFETY: resp passed versioned::read above.
    unsafe { versioned::write_back(resp, &out) };
    let result = body(&mut out);
    debug_assert!(result.is_ok() == (out.valid == 1), "valid is 1 exactly on success");
    // SAFETY: as above.
    unsafe { versioned::write_back(resp, &out) };
    result
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_verify(
    ctx: *mut agc_ctx,
    req: *const agc_verify_request,
    resp: *mut agc_verify_response,
) -> agc_rc {
    guard(|| {
        let body = |out: &mut agc_verify_response| {
            // SAFETY: ctx is NULL or a live context (agc_core.h contract).
            let ctx = unsafe { context(ctx) }?;
            // SAFETY: req is NULL or the caller's struct with struct_size readable bytes.
            let r = unsafe { versioned::read(req, "req") }?;
            // SAFETY: the pointers and slices in req are NULL or valid for the call.
            let (enc, key_version) = unsafe { verify_metadata(r.metadata) }?;
            let request = VerifyRequest {
                // SAFETY: as above.
                key_name: unsafe { required_str(r.key_name, "key_name") }?,
                // SAFETY: as above.
                input: SignInput::Message(unsafe { slice(r.input, "input") }?),
                // SAFETY: as above.
                signature: unsafe { slice(r.signature, "signature") }?,
                key_version,
                // SAFETY: as above.
                context: unsafe { sign_params(r.params) }?,
                // SAFETY: as above.
                user_context: unsafe { kv_list(&r.user_context, "user_context") }?,
            };
            verify_into(&ctx.crypto, request, enc, out)
        };
        // SAFETY: resp is NULL or the caller's struct (agc_crypto.h contract).
        unsafe { fail_closed(resp, body) }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_digest_verify(
    ctx: *mut agc_ctx,
    req: *const agc_digest_verify_request,
    resp: *mut agc_verify_response,
) -> agc_rc {
    guard(|| {
        let body = |out: &mut agc_verify_response| {
            // SAFETY: ctx is NULL or a live context (agc_core.h contract).
            let ctx = unsafe { context(ctx) }?;
            // SAFETY: req is NULL or the caller's struct with struct_size readable bytes.
            let r = unsafe { versioned::read(req, "req") }?;
            // SAFETY: the pointers and slices in req are NULL or valid for the call.
            let (enc, key_version) = unsafe { verify_metadata(r.metadata) }?;
            let request = VerifyRequest {
                // SAFETY: as above.
                key_name: unsafe { required_str(r.key_name, "key_name") }?,
                input: SignInput::Digest {
                    // SAFETY: as above.
                    digest: unsafe { slice(r.digest, "digest") }?,
                    hash: hash(r.hash_algorithm)?,
                },
                // SAFETY: as above.
                signature: unsafe { slice(r.signature, "signature") }?,
                key_version,
                // SAFETY: as above.
                context: unsafe { sign_params(r.params) }?,
                // SAFETY: as above.
                user_context: unsafe { kv_list(&r.user_context, "user_context") }?,
            };
            verify_into(&ctx.crypto, request, enc, out)
        };
        // SAFETY: resp is NULL or the caller's struct (agc_crypto.h contract).
        unsafe { fail_closed(resp, body) }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn agc_hash_algorithm_output_len(h: agc_hash_algorithm) -> usize {
    guard_value(0, || hash(h).ok().and_then(hash_output_len).unwrap_or(0))
}

/// 0 when the key is unknown or the arguments are unusable; the reason is
/// in agc_last_error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_metadata_max_encoded_len(
    ctx: *mut agc_ctx,
    key_name: *const c_char,
    enc: agc_encoding,
    user_context: agc_kv_list,
) -> usize {
    // Set only on success, so every failure returns 0.
    let mut len = 0;
    guard(|| {
        // SAFETY: ctx is NULL or a live context (agc_core.h contract).
        let ctx = unsafe { context(ctx) }?;
        // SAFETY: key_name is NULL or a NUL-terminated string (agc_metadata.h contract).
        let key_name = unsafe { required_str(key_name, "key_name") }?;
        let enc = encoding(enc, "enc")?;
        // SAFETY: user_context follows the kv_list contract.
        let user_context = unsafe { kv_list(&user_context, "user_context") }?;
        len = ctx.crypto.metadata_max_len(key_name, enc, &user_context)?;
        Ok(())
    });
    len
}
