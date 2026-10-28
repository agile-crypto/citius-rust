//! agc_metadata.h — OperationMetadata codec and envelopes.

use crate::bindings::*;
use crate::domain::crypto::metadata;
use crate::ffi::error::FfiError;
use crate::ffi::guard::guard;
use crate::ffi::translation::{Packer, check_representable, encoding, md_from_c, md_to_c, pack_exact, slice};
use crate::ffi::versioned;
use crate::proto::api;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_metadata_encode(
    md: *const agc_metadata,
    enc: agc_encoding,
    out: agc_buf,
    out_len: *mut usize,
) -> agc_rc {
    guard(|| {
        // SAFETY: md is NULL or the caller's struct with struct_size readable bytes.
        let md = unsafe { versioned::read(md, "md") }?;
        let enc = encoding(enc, "enc")?;
        if out_len.is_null() {
            return Err(FfiError::invalid("out_len must not be NULL"));
        }
        // SAFETY: md's pointers are NULL or valid (agc_metadata.h contract).
        let bytes = metadata::encode(&unsafe { md_from_c(&md) }?, enc)?;
        // SAFETY: out_len is non-null (checked) and writable.
        unsafe { out_len.write(bytes.len()) };
        write_out(out, &bytes)
    })
}

/// The two-call rule for a byte output: NULL or too small is
/// BUFFER_TOO_SMALL (the length is already reported), else the bytes.
fn write_out(out: agc_buf, bytes: &[u8]) -> Result<(), FfiError> {
    if out.data.is_null() || out.cap < bytes.len() {
        return Err(FfiError::BufferTooSmall { needed: bytes.len() });
    }
    // SAFETY: out.data is non-null with cap >= len writable bytes (caller's
    // region, checked), distinct from `bytes`.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out.data, bytes.len()) };
    Ok(())
}

/// Decodes into the caller's result: validation first, then the exact
/// storage check, then the writes (agc_metadata.h, CONTRACT 2-4).
///
/// # Safety
/// `out` is NULL or the caller's struct with struct_size accessible bytes.
unsafe fn decode_into(
    md: Result<api::OperationMetadata, FfiError>,
    out: *mut agc_decode_metadata_result,
) -> Result<(), FfiError> {
    // SAFETY: forwarded from this function's contract.
    let mut r = unsafe { versioned::read(out, "out") }?;
    let md = md?;
    check_representable(&md)?;
    let result = pack_exact(r.storage, &mut r.storage_used, |p| md_to_c(&md, p)).map(|c| r.metadata = c);
    // SAFETY: out passed versioned::read above.
    unsafe { versioned::write_back(out, &r) };
    result
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_metadata_decode(
    enc: agc_encoding,
    encoded: agc_slice,
    out: *mut agc_decode_metadata_result,
) -> agc_rc {
    guard(|| {
        let decoded = (|| {
            let enc = encoding(enc, "enc")?;
            // SAFETY: encoded is the caller's slice, valid for the call (agc_abi.h).
            Ok(metadata::decode(enc, unsafe { slice(encoded, "encoded") }?)?)
        })();
        // SAFETY: out is NULL or the caller's result struct.
        unsafe { decode_into(decoded, out) }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_metadata_decode_body(
    enc: agc_encoding,
    body: agc_slice,
    out: *mut agc_decode_metadata_result,
) -> agc_rc {
    guard(|| {
        let decoded = (|| {
            let enc = encoding(enc, "enc")?;
            // SAFETY: body is the caller's slice, valid for the call.
            Ok(metadata::decode_body(enc, unsafe { slice(body, "body") }?)?)
        })();
        // SAFETY: out is NULL or the caller's result struct.
        unsafe { decode_into(decoded, out) }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_metadata_storage_len(enc: agc_encoding, encoded: agc_slice, out_len: *mut usize) -> agc_rc {
    guard(|| {
        let enc = encoding(enc, "enc")?;
        // SAFETY: encoded is the caller's slice, valid for the call.
        let md = metadata::decode(enc, unsafe { slice(encoded, "encoded") }?)?;
        check_representable(&md)?;
        if out_len.is_null() {
            return Err(FfiError::invalid("out_len must not be NULL"));
        }
        // Exact for a suitably aligned region, as agc_metadata_decode measures
        // a NULL region.
        let mut m = Packer::measuring_at(std::ptr::null());
        md_to_c(&md, &mut m);
        // SAFETY: out_len is non-null (checked) and writable.
        unsafe { out_len.write(m.used()) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_metadata_peek_key_version(enc: agc_encoding, encoded: agc_slice, out: *mut u32) -> agc_rc {
    guard(|| {
        let enc = encoding(enc, "enc")?;
        // SAFETY: encoded is the caller's slice, valid for the call.
        let v = metadata::peek_key_version(enc, unsafe { slice(encoded, "encoded") }?)?;
        if out.is_null() {
            return Err(FfiError::invalid("out must not be NULL"));
        }
        // SAFETY: out is non-null (checked) and writable.
        unsafe { out.write(v) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agc_envelope_split(
    envelope: agc_slice,
    out_encoding: *mut agc_encoding,
    out_metadata_body: *mut agc_slice,
    out_ciphertext: *mut agc_slice,
) -> agc_rc {
    guard(|| {
        if out_encoding.is_null() || out_metadata_body.is_null() || out_ciphertext.is_null() {
            return Err(FfiError::invalid("every output must be non-NULL"));
        }
        // SAFETY: envelope is the caller's slice, valid for the call.
        let bytes = unsafe { slice(envelope, "envelope") }?;
        let (enc, body, ct) = metadata::split_envelope(bytes)?;
        let as_slice = |b: &[u8]| agc_slice { data: b.as_ptr(), len: b.len() };
        // SAFETY: all three are non-null (checked) and writable; the slices
        // point into the caller's envelope, as the header promises.
        unsafe {
            out_encoding.write(enc as u8 as agc_encoding);
            out_metadata_body.write(as_slice(body));
            out_ciphertext.write(as_slice(ct));
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;
    use std::ptr;

    use super::*;
    use crate::domain::crypto::metadata::MetadataEncoding;
    use crate::bindings::{
        AGC_ERR_BUFFER_TOO_SMALL, AGC_ERR_CRYPTO_PROVIDER_NOT_FOUND, AGC_ERR_INVALID_ARGUMENT, AGC_OK,
    };

    const PB: agc_encoding = MetadataEncoding::Protobuf as agc_encoding;
    const WIRE: agc_encoding = MetadataEncoding::WireV1 as agc_encoding;

    /// The multi_user_context golden vector (citius-c-api tests/golden),
    /// encoding byte first: key_version 42, encoding "der", NO_OUTPUT, api
    /// "1.0", user context {request_id: abc-123, tenant: acme}.
    fn golden() -> Vec<u8> {
        let hex = "082a12070a0364657252001a03312e3022150a0a726571756573745f696412076162632d313233220e0a0674656e616e74120461636d65";
        let mut v = vec![1u8];
        v.extend((0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()));
        v
    }

    fn as_slice(b: &[u8]) -> agc_slice {
        agc_slice { data: b.as_ptr(), len: b.len() }
    }

    fn result(storage: &mut [u8]) -> agc_decode_metadata_result {
        // SAFETY: all-zero is AGC_INIT's state.
        let mut r: agc_decode_metadata_result = unsafe { std::mem::zeroed() };
        r.struct_size = size_of::<agc_decode_metadata_result>();
        r.storage = agc_buf { data: storage.as_mut_ptr(), cap: storage.len() };
        r
    }

    fn s(p: *const std::ffi::c_char) -> &'static str {
        // SAFETY: points into a live test buffer, NUL-terminated by the packer.
        unsafe { CStr::from_ptr(p) }.to_str().unwrap()
    }

    #[test]
    fn decode_lays_values_out_in_storage_and_the_size_is_exact() {
        let g = golden();
        let mut needed = 0usize;
        // SAFETY: g and needed are live.
        assert_eq!(unsafe { agc_metadata_storage_len(PB, as_slice(&g), &mut needed) }, AGC_OK as agc_rc);
        assert_eq!(needed, 2 * size_of::<agc_kv>() + "request_id\0abc-123\0tenant\0acme\0".len());

        // An aligned region of exactly that size.
        let mut words = vec![0u64; needed.div_ceil(8)];
        // SAFETY: viewing the u64 buffer as bytes; it outlives the test.
        let storage = unsafe { std::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), needed) };
        let mut r = result(storage);
        // SAFETY: g and r are live.
        assert_eq!(unsafe { agc_metadata_decode(PB, as_slice(&g), &mut r) }, AGC_OK as agc_rc);
        assert_eq!(r.storage_used, needed);
        let md = &r.metadata;
        assert_eq!(md.key_version, 42);
        assert_eq!(s(md.api_version.as_ptr()), "1.0");
        assert_eq!(s(md.provider_output.encoding.as_ptr()), "der");
        assert_eq!(md.provider_output.kind, agc_algorithm_output_kind_AGC_ALGORITHM_OUTPUT_NO_OUTPUT);
        // SAFETY: items points at 2 entries in storage.
        let kv = unsafe { std::slice::from_raw_parts(md.user_context.items, md.user_context.count) };
        assert_eq!((s(kv[0].key), s(kv[0].value), s(kv[1].key)), ("request_id", "abc-123", "tenant"));
        assert_eq!(md.user_context.items.cast::<u8>(), storage.as_ptr(), "the item array comes first");

        // ...and encodes back to the same bytes.
        let mut out = [0u8; 128];
        let mut len = 0usize;
        let buf = agc_buf { data: out.as_mut_ptr(), cap: out.len() };
        // SAFETY: r.metadata points into storage, which is alive.
        assert_eq!(unsafe { agc_metadata_encode(&r.metadata, PB, buf, &mut len) }, AGC_OK as agc_rc);
        assert_eq!(&out[..len], &g[..]);
    }

    #[test]
    fn a_too_small_region_writes_only_the_size() {
        let g = golden();
        let mut storage = [0xAAu8; 8];
        let mut r = result(&mut storage);
        // SAFETY: as above.
        assert_eq!(unsafe { agc_metadata_decode(PB, as_slice(&g), &mut r) }, AGC_ERR_BUFFER_TOO_SMALL);
        assert!(r.storage_used > 8);
        assert_eq!(r.metadata.key_version, 0, "nothing else written");
        assert!(storage.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn encode_is_two_call_and_converts_between_encodings() {
        let g = golden();
        let mut storage = [0u64; 32];
        // SAFETY: viewing the u64 buffer as bytes.
        let bytes = unsafe { std::slice::from_raw_parts_mut(storage.as_mut_ptr().cast::<u8>(), 256) };
        let mut r = result(bytes);
        // SAFETY: as above.
        assert_eq!(unsafe { agc_metadata_decode(PB, as_slice(&g), &mut r) }, AGC_OK as agc_rc);

        let mut len = 0usize;
        let none = agc_buf { data: ptr::null_mut(), cap: 0 };
        // SAFETY: r.metadata points into live storage.
        assert_eq!(unsafe { agc_metadata_encode(&r.metadata, WIRE, none, &mut len) }, AGC_ERR_BUFFER_TOO_SMALL);
        let mut wire = vec![0u8; len];
        let buf = agc_buf { data: wire.as_mut_ptr(), cap: wire.len() };
        // SAFETY: as above.
        assert_eq!(unsafe { agc_metadata_encode(&r.metadata, WIRE, buf, &mut len) }, AGC_OK as agc_rc);
        assert_eq!(wire[0], 2);

        let mut v = 0u32;
        // SAFETY: wire and v are live.
        assert_eq!(unsafe { agc_metadata_peek_key_version(WIRE, as_slice(&wire), &mut v) }, AGC_OK as agc_rc);
        assert_eq!(v, 42);
        // SAFETY: as above.
        assert_eq!(unsafe { agc_metadata_peek_key_version(PB, as_slice(&wire), &mut v) }, AGC_ERR_INVALID_ARGUMENT);
    }

    #[test]
    fn vendor_output_and_bad_input_are_refused() {
        let vendor_hex = "12248201210a130a0b6174746573746174696f6e1204deadbeef0a0a0a04736c6f7412020001";
        let mut vendor = vec![1u8];
        vendor.extend((0..vendor_hex.len()).step_by(2).map(|i| u8::from_str_radix(&vendor_hex[i..i + 2], 16).unwrap()));
        let mut storage = [0u8; 256];
        let mut r = result(&mut storage);
        // SAFETY: vendor and r are live.
        unsafe {
            assert_eq!(agc_metadata_decode(PB, as_slice(&vendor), &mut r), AGC_ERR_CRYPTO_PROVIDER_NOT_FOUND);
            assert_eq!(agc_metadata_decode(0, as_slice(&golden()), &mut r), AGC_ERR_INVALID_ARGUMENT);
            assert_eq!(agc_metadata_decode(PB, agc_slice { data: ptr::null(), len: 3 }, &mut r), AGC_ERR_INVALID_ARGUMENT);
            assert_eq!(agc_metadata_decode(PB, as_slice(&golden()), ptr::null_mut()), AGC_ERR_INVALID_ARGUMENT);
        }
    }

    #[test]
    fn envelope_split_points_into_the_envelope() {
        let env = [2u8, 0, 2, 7, 7, b'c', b't'];
        let (mut enc, mut body, mut ct) = (0, agc_slice { data: ptr::null(), len: 0 }, agc_slice { data: ptr::null(), len: 0 });
        // SAFETY: env and the outputs are live.
        assert_eq!(unsafe { agc_envelope_split(as_slice(&env), &mut enc, &mut body, &mut ct) }, AGC_OK as agc_rc);
        assert_eq!((enc, body.len, ct.len), (WIRE, 2, 2));
        assert_eq!(body.data, env[3..].as_ptr());
        assert_eq!(ct.data, env[5..].as_ptr());
    }
}
