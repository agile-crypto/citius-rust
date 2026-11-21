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
use crate::secret::SecretVec;

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
pub(super) fn short(region: agc_buf, len: usize) -> bool {
    region.data.is_null() || region.cap < len
}

/// Copies `bytes` into a caller region. The region was sized before the
/// work; should the work have produced more than that (a provider breaking
/// its bound), nothing is written and the caller learns the real need.
/// Never trusts an earlier size check alone: that check is the only thing
/// between the result and the caller's memory.
pub(super) fn put(region: agc_buf, bytes: &[u8]) -> Result<(), FfiError> {
    if short(region, bytes.len()) {
        return Err(FfiError::BufferTooSmall { needed: bytes.len() });
    }
    // SAFETY: the region is non-null with at least bytes.len() writable bytes
    // (checked just above), distinct from `bytes`.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), region.data, bytes.len()) };
    Ok(())
}

/// Whether `input` shares a byte with the caller's output region.
fn overlaps(input: &[u8], region: agc_buf) -> bool {
    let (a, b) = (input.as_ptr() as usize, region.data as usize);
    !input.is_empty() && !region.data.is_null() && a < b.saturating_add(region.cap) && b < a.saturating_add(input.len())
}

/// An input the operation reads while it writes `region`: borrowed, or
/// copied first when the caller passed overlapping buffers (in-place use),
/// so that the output slice never aliases a live input slice.
fn apart_from<'a>(input: &'a [u8], region: agc_buf, copy: &'a mut Option<SecretVec>) -> &'a [u8] {
    if overlaps(input, region) { copy.insert(SecretVec::from(input.to_vec())) } else { input }
}

/// `apart_from` for the key name, which the request borrows too.
fn apart_name<'a>(name: &'a str, region: agc_buf, copy: &'a mut Option<String>) -> &'a str {
    if overlaps(name.as_bytes(), region) { copy.insert(name.to_owned()) } else { name }
}

/// The first `len` bytes of the caller's region, for the operation to write.
///
/// # Safety
/// `short(region, len)` is false; the region is the caller's writable
/// memory for the call; no input slice the operation reads overlaps it
/// (`apart_from`).
unsafe fn region_mut<'b>(region: agc_buf, len: usize) -> &'b mut [u8] {
    // SAFETY: non-null with at least `len` writable bytes (not `short`),
    // and unaliased while the operation runs (this function's contract).
    unsafe { std::slice::from_raw_parts_mut(region.data, len) }
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
        // SAFETY: the pointers and slices in req are NULL or valid for the
        // call (agc_crypto.h contract).
        let plaintext = unsafe { slice(r.plaintext, "plaintext") }?;
        let (mut copy, mut name) = (None, None);
        let request = EncryptRequest {
            // SAFETY: as above.
            key_name: apart_name(unsafe { required_str(r.key_name, "key_name") }?, out.ciphertext, &mut name),
            plaintext: apart_from(plaintext, out.ciphertext, &mut copy),
            // SAFETY: as above.
            params: unsafe { encrypt_params(r.params) }?,
            // SAFETY: as above.
            user_context: unsafe { kv_list(&r.user_context, "user_context") }?,
        };

        // SIZE QUERIES: every length is set, and a NULL or short region stops
        // the call before any provider work or randomness. The sizes and the
        // ciphertext come from one lookup of the key; the provider encrypts
        // straight into the caller's region.
        let result = ctx
            .crypto
            .encrypt_admitting(request, enc, |sizes| {
                out.ciphertext_len = sizes.artifact;
                out.metadata_len = sizes.metadata;
                if short(out.ciphertext, sizes.artifact) || short(out.metadata, sizes.metadata) {
                    return Err(FfiError::BufferTooSmall { needed: sizes.artifact.max(sizes.metadata) });
                }
                // SAFETY: not short (just checked). The request's borrowed
                // inputs, plaintext and key name, are apart from it
                // (apart_from, apart_name); AAD and user context are copies.
                Ok(unsafe { region_mut(out.ciphertext, sizes.artifact) })
            })
            .and_then(|w| {
                let md = metadata::encode(&w.metadata, enc)?;
                out.ciphertext_len = w.len;
                out.metadata_len = md.len();
                put(out.metadata, &md)?;
                out.key_version = w.metadata.key_version;
                Ok(())
            });
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
        // SAFETY: as in agc_encrypt, the pointers in req are NULL or valid.
        let ciphertext = unsafe { slice(r.ciphertext, "ciphertext") }?;
        let (mut copy, mut name) = (None, None);
        let request = DecryptRequest {
            // SAFETY: as above.
            key_name: apart_name(unsafe { required_str(r.key_name, "key_name") }?, out.plaintext, &mut name),
            ciphertext: apart_from(ciphertext, out.plaintext, &mut copy),
            metadata: metadata::decode(enc, md_in)?,
            // SAFETY: as above.
            params: unsafe { encrypt_params(r.params) }?,
            // SAFETY: as above.
            user_context: unsafe { kv_list(&r.user_context, "user_context") }?,
        };

        // The metadata output is optional here: {NULL, 0} opts out (the
        // caller already holds the input metadata); it is not a size query.
        let wants_md = !(out.metadata.data.is_null() && out.metadata.cap == 0);
        let mut md_out = None;
        let result = ctx
            .crypto
            .decrypt_admitting(request, wants_md.then_some(enc), |sizes, md| {
                out.plaintext_len = sizes.artifact;
                out.metadata_len = sizes.metadata;
                if short(out.plaintext, sizes.artifact) || (wants_md && short(out.metadata, sizes.metadata)) {
                    return Err(FfiError::BufferTooSmall { needed: sizes.artifact.max(sizes.metadata) });
                }
                md_out = md;
                // SAFETY: not short (just checked). The request's borrowed
                // inputs, ciphertext and key name, are apart from it
                // (apart_from, apart_name); AAD, metadata and user context
                // are copies.
                Ok(unsafe { region_mut(out.plaintext, sizes.artifact) })
            })
            .and_then(|w| {
                // The provider wrote the plaintext only once it had decided
                // every failure. The metadata was encoded before, and its
                // region checked against exactly these bytes: this copy
                // cannot fail, so a written plaintext always stands.
                if let Some(md) = &md_out {
                    out.metadata_len = md.len();
                    put(out.metadata, md)?;
                }
                out.plaintext_len = w.len;
                out.key_version = w.metadata.key_version;
                Ok(())
            });
        // Authentication failed (or any failure after sizing): nothing is
        // written (agc_crypto.h), and no length promises output.
        if matches!(&result, Err(e) if !matches!(e, FfiError::BufferTooSmall { .. })) {
            out.plaintext_len = 0;
            out.metadata_len = 0;
        }
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
    fn put_never_writes_past_the_region() {
        let mut buf = [0xA5u8; 8];
        let region = super::agc_buf { data: buf.as_mut_ptr(), cap: 4 };
        let err = super::put(region, &[1; 5]).unwrap_err();
        assert!(matches!(err, super::FfiError::BufferTooSmall { needed: 5 }));
        assert_eq!(buf, [0xA5; 8], "nothing written");
        super::put(region, &[1; 4]).unwrap();
        assert_eq!(buf, [1, 1, 1, 1, 0xA5, 0xA5, 0xA5, 0xA5]);
        let null = super::agc_buf { data: std::ptr::null_mut(), cap: 0 };
        assert!(super::put(null, &[]).is_err(), "a NULL region is never written");
    }

    #[test]
    fn overlap_is_any_shared_byte() {
        // Only addresses are compared: nothing is written through `region`.
        let buf = [0u8; 32];
        let base = buf.as_ptr().cast_mut();
        let region = |at: usize, cap: usize| super::agc_buf { data: base.wrapping_add(at), cap };
        let input = &buf[8..16];
        assert!(super::overlaps(input, region(0, 9)), "last byte of the region");
        assert!(super::overlaps(input, region(15, 4)), "first byte of the region");
        assert!(super::overlaps(input, region(10, 2)), "inside");
        assert!(!super::overlaps(input, region(0, 8)), "just before");
        assert!(!super::overlaps(input, region(16, 8)), "just after");
        assert!(!super::overlaps(input, super::agc_buf { data: std::ptr::null_mut(), cap: 64 }));
        assert!(!super::overlaps(&[], region(0, 32)));
    }

    #[test]
    fn the_metadata_api_version_is_the_headers() {
        let header = CStr::from_bytes_with_nul(AGC_API_VERSION_STRING).unwrap().to_str().unwrap();
        assert_eq!(API_VERSION, header);
    }
}
