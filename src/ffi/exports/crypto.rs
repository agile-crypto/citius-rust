//! agc_crypto.h — CryptoService (one-shot operations).

use crate::app::{DecryptRequest, EncryptRequest};
use crate::bindings::*;
use crate::domain::crypto::metadata::{self, MetadataEncoding};
use crate::domain::provider::EncryptParams;
use crate::ffi::error::FfiError;
use crate::ffi::exports::core::context;
use crate::ffi::guard::guard;
use crate::ffi::translation::{encoding, kv_list, required_str, slice};
use crate::ffi::versioned;

/// The caller's encryption parameters. The oneof is required; the arms no
/// provider implements yet are not offered.
///
/// # Safety
/// `p` is NULL or a versioned struct whose slices are valid for the call.
unsafe fn encrypt_params(p: *const agc_encrypt_params) -> Result<EncryptParams, FfiError> {
    // SAFETY: forwarded from this function's contract.
    let p = unsafe { versioned::read(p, "params") }?;
    match p.kind {
        agc_encrypt_params_kind_AGC_ENCRYPT_PARAMS_NO_PARAMS => Ok(EncryptParams::None),
        agc_encrypt_params_kind_AGC_ENCRYPT_PARAMS_AEAD => {
            // SAFETY: kind selects the aead member; its aad slice is valid (contract).
            let aad = unsafe { slice(p.u.aead.aad, "params.u.aead.aad") }?;
            Ok(EncryptParams::Aead { aad: aad.to_vec() })
        }
        agc_encrypt_params_kind_AGC_ENCRYPT_PARAMS_XTS => Err(FfiError::NotImplemented("XTS encryption")),
        agc_encrypt_params_kind_AGC_ENCRYPT_PARAMS_ASYMMETRIC => Err(FfiError::NotImplemented("asymmetric encryption")),
        agc_encrypt_params_kind_AGC_ENCRYPT_PARAMS_VENDOR => Err(FfiError::NotImplemented("vendor encryption parameters")),
        other => Err(FfiError::invalid(format!("params.kind {other} is not an encryption parameter kind"))),
    }
}

/// An output region too small for `len` bytes (a NULL region always is).
fn short(region: agc_buf, len: usize) -> bool {
    region.data.is_null() || region.cap < len
}

/// Copies `bytes` into a region `short` has accepted.
fn put(region: agc_buf, bytes: &[u8]) {
    // SAFETY: the region is non-null with at least bytes.len() writable bytes
    // (checked by `short` before any work), distinct from `bytes`.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), region.data, bytes.len()) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_encrypt(ctx: *mut agc_ctx, req: *const agc_encrypt_request, resp: *mut agc_encrypt_response) -> agc_rc {
    guard(|| {
        // SAFETY: ctx is NULL or a live context (agc_core.h contract).
        let ctx = unsafe { context(ctx) }?;
        // SAFETY: req is NULL or the caller's struct with struct_size readable bytes.
        let r = unsafe { versioned::read(req, "req") }?;
        // SAFETY: resp is NULL or the caller's struct with struct_size accessible bytes.
        let mut out = unsafe { versioned::read(resp, "resp") }?;
        let enc = encoding(r.metadata_encoding, "metadata_encoding")?;
        let request = EncryptRequest {
            // SAFETY: the pointers and slices in req
            // are NULL or valid for the call (agc_crypto.h contract).
            key_name: unsafe { required_str(r.key_name, "key_name") }?,
            // SAFETY: as above.
            plaintext: unsafe { slice(r.plaintext, "plaintext") }?,
            // SAFETY: as above.
            params: unsafe { encrypt_params(r.params) }?,
            // SAFETY: as above.
            user_context: unsafe { kv_list(&r.user_context, "user_context") }?,
        };

        // SIZE QUERIES: every length is set, and a NULL or short region stops
        // the call before any provider work or randomness.
        let (ct_len, md_len) = ctx.crypto.encrypt_sizes(&request, enc)?;
        out.ciphertext_len = ct_len;
        out.metadata_len = md_len;
        let result = if short(out.ciphertext, ct_len) || short(out.metadata, md_len) {
            Err(FfiError::BufferTooSmall { needed: ct_len.max(md_len) })
        } else {
            ctx.crypto.encrypt(request).map_err(FfiError::from).and_then(|e| {
                let md = metadata::encode(&e.metadata, enc)?;
                debug_assert_eq!((e.ciphertext.len(), md.len()), (ct_len, md_len), "sizes were exact");
                put(out.ciphertext, &e.ciphertext);
                put(out.metadata, &md);
                out.ciphertext_len = e.ciphertext.len();
                out.metadata_len = md.len();
                out.key_version = e.metadata.key_version;
                Ok(())
            })
        };
        // SAFETY: resp passed versioned::read above.
        unsafe { versioned::write_back(resp, &out) };
        result
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_decrypt(ctx: *mut agc_ctx, req: *const agc_decrypt_request, resp: *mut agc_decrypt_response) -> agc_rc {
    guard(|| {
        // SAFETY: ctx is NULL or a live context (agc_core.h contract).
        let ctx = unsafe { context(ctx) }?;
        // SAFETY: req is NULL or the caller's struct with struct_size readable bytes.
        let r = unsafe { versioned::read(req, "req") }?;
        // SAFETY: resp is NULL or the caller's struct with struct_size accessible bytes.
        let mut out = unsafe { versioned::read(resp, "resp") }?;
        // SAFETY: the metadata slice is valid for the call (agc_crypto.h contract).
        let md_in = unsafe { slice(r.metadata, "metadata") }?;
        let enc = md_in
            .first()
            .and_then(|&b| MetadataEncoding::from_byte(b))
            .ok_or_else(|| FfiError::invalid("metadata must begin with its encoding byte"))?;
        let request = DecryptRequest {
            // SAFETY: as in agc_encrypt, the pointers in req are NULL or valid.
            key_name: unsafe { required_str(r.key_name, "key_name") }?,
            // SAFETY: as above.
            ciphertext: unsafe { slice(r.ciphertext, "ciphertext") }?,
            metadata: metadata::decode(enc, md_in)?,
            // SAFETY: as above.
            params: unsafe { encrypt_params(r.params) }?,
            // SAFETY: as above.
            user_context: unsafe { kv_list(&r.user_context, "user_context") }?,
        };

        // The metadata output is optional here: {NULL, 0} opts out (the
        // caller already holds the input metadata); it is not a size query.
        let wants_md = !(out.metadata.data.is_null() && out.metadata.cap == 0);
        let (pt_len, md_len) = ctx.crypto.decrypt_sizes(&request, enc)?;
        out.plaintext_len = pt_len;
        out.metadata_len = if wants_md { md_len } else { 0 };
        let result = if short(out.plaintext, pt_len) || (wants_md && short(out.metadata, md_len)) {
            Err(FfiError::BufferTooSmall { needed: pt_len.max(md_len) })
        } else {
            match ctx.crypto.decrypt(request) {
                // Authentication failed: nothing is written (agc_crypto.h).
                Err(e) => {
                    out.plaintext_len = 0;
                    out.metadata_len = 0;
                    Err(e.into())
                }
                Ok(d) => {
                    put(out.plaintext, &d.plaintext);
                    out.plaintext_len = d.plaintext.len();
                    if wants_md {
                        let md = metadata::encode(&d.metadata, enc)?;
                        put(out.metadata, &md);
                        out.metadata_len = md.len();
                    }
                    out.key_version = d.metadata.key_version;
                    Ok(())
                }
            }
        };
        // SAFETY: resp passed versioned::read above.
        unsafe { versioned::write_back(resp, &out) };
        result
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use crate::app::API_VERSION;
    use crate::bindings::AGC_API_VERSION_STRING;

    #[test]
    fn the_metadata_api_version_is_the_headers() {
        let header = CStr::from_bytes_with_nul(AGC_API_VERSION_STRING).unwrap().to_str().unwrap();
        assert_eq!(API_VERSION, header);
    }
}
