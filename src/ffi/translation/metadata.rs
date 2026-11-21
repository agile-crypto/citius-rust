//! `agc_metadata` (the decoded C form) to and from `OperationMetadata`.

use std::collections::BTreeMap;
use std::ffi::c_char;

use super::Packer;
use crate::bindings::*;
use crate::wire::metadata::{MetadataEncoding, kind};
use crate::ffi::error::FfiError;
use crate::proto::api::{self, provider_output::AlgorithmOutput};

/// Bytes the caller lends for the call; `{NULL, 0}` is empty.
///
/// # Safety
/// `s.data` is NULL or valid for reading `s.len` bytes for `'a`.
pub unsafe fn slice<'a>(s: agc_slice, what: &str) -> Result<&'a [u8], FfiError> {
    if s.len == 0 {
        return Ok(&[]);
    }
    if s.data.is_null() {
        return Err(FfiError::invalid(format!("{what}.data is NULL but len is {}", s.len)));
    }
    // SAFETY: non-null and valid for len bytes (this function's contract).
    Ok(unsafe { std::slice::from_raw_parts(s.data, s.len) })
}

/// The encoding a request names. UNSPECIFIED and unknown values are invalid.
pub fn encoding(e: agc_encoding, what: &str) -> Result<MetadataEncoding, FfiError> {
    u8::try_from(e)
        .ok()
        .and_then(MetadataEncoding::from_byte)
        .ok_or_else(|| FfiError::invalid(format!("{what} {e} is not PROTOBUF or WIRE_V1")))
}

/// A NUL-terminated string in a fixed array.
fn fixed_str(chars: &[c_char], what: &str) -> Result<String, FfiError> {
    let bytes: Vec<u8> = chars.iter().map(|&c| c as u8).collect();
    let end = bytes.iter().position(|&b| b == 0).ok_or_else(|| FfiError::invalid(format!("{what} is not NUL-terminated")))?;
    String::from_utf8(bytes[..end].to_vec()).map_err(|_| FfiError::invalid(format!("{what} is not UTF-8")))
}

fn put_fixed(dst: &mut [c_char], s: &str) {
    for (d, b) in dst.iter_mut().zip(s.bytes()) {
        *d = b as c_char;
    }
    dst[s.len()] = 0;
}

/// Whether `md` fits the C struct: its fixed-size strings must fit their
/// arrays with the NUL.
pub fn check_representable(md: &api::OperationMetadata) -> Result<(), FfiError> {
    let encoding = md.provider_output.as_ref().map_or("", |p| p.encoding.as_str());
    if md.api_version.len() >= AGC_API_VERSION_MAX_LEN as usize {
        return Err(FfiError::invalid(format!("api_version {:?} does not fit agc_metadata", md.api_version)));
    }
    if encoding.len() >= AGC_OUTPUT_ENCODING_MAX_LEN as usize {
        return Err(FfiError::invalid(format!("output encoding {encoding:?} does not fit agc_metadata")));
    }
    Ok(())
}

/// The caller's metadata as the API message. Reads its slices and
/// user-context strings through their pointers.
///
/// # Safety
/// Every pointer in `md` is NULL or valid for its length, per agc_metadata.h.
pub unsafe fn md_from_c(md: &agc_metadata) -> Result<api::OperationMetadata, FfiError> {
    let po = &md.provider_output;
    let s = |v: agc_slice, what| {
        // SAFETY: the slices of md are NULL or valid (this function's contract).
        unsafe { slice(v, what) }.map(<[u8]>::to_vec)
    };
    // Each union read below reads the arm `kind` selects; every arm is made
    // of slices and integers.
    let output = match po.kind {
        agc_algorithm_output_kind_AGC_ALGORITHM_OUTPUT_NO_OUTPUT => AlgorithmOutput::NoOutput(api::NoAlgorithmOutput {}),
        agc_algorithm_output_kind_AGC_ALGORITHM_OUTPUT_AEAD => {
            // SAFETY: see above.
            let a = unsafe { po.u.aead };
            AlgorithmOutput::AeadOutput(api::AeadOutput { nonce: s(a.nonce, "aead.nonce")?, tag_length_bytes: a.tag_len })
        }
        agc_algorithm_output_kind_AGC_ALGORITHM_OUTPUT_BLOCK_CIPHER => {
            // SAFETY: see above.
            let a = unsafe { po.u.block_cipher };
            AlgorithmOutput::BlockCipherOutput(api::BlockCipherOutput { iv: s(a.iv, "block_cipher.iv")? })
        }
        agc_algorithm_output_kind_AGC_ALGORITHM_OUTPUT_COUNTER_MODE => {
            // SAFETY: see above.
            let a = unsafe { po.u.counter_mode };
            AlgorithmOutput::CounterModeOutput(api::CounterModeOutput {
                counter_block: s(a.counter_block, "counter_mode.counter_block")?,
                counter_bits: a.counter_bits,
            })
        }
        agc_algorithm_output_kind_AGC_ALGORITHM_OUTPUT_STREAM_CIPHER => {
            // SAFETY: see above.
            let a = unsafe { po.u.stream_cipher };
            AlgorithmOutput::StreamCipherOutput(api::StreamCipherOutput {
                nonce: s(a.nonce, "stream_cipher.nonce")?,
                block_counter: s(a.block_counter, "stream_cipher.block_counter")?,
            })
        }
        agc_algorithm_output_kind_AGC_ALGORITHM_OUTPUT_KDF => {
            // SAFETY: see above.
            let a = unsafe { po.u.kdf };
            AlgorithmOutput::KdfOutput(api::KdfOutput { salt: s(a.salt, "kdf.salt")?, iv: s(a.iv, "kdf.iv")? })
        }
        agc_algorithm_output_kind_AGC_ALGORITHM_OUTPUT_VENDOR => {
            return Err(FfiError::Domain(crate::domain::core::Error::new(
                crate::domain::core::Code::ProviderNotFound,
                "agc_metadata_encode",
                "vendor output needs its provider, and none is registered",
            )));
        }
        other => return Err(FfiError::invalid(format!("provider_output.kind {other} is not an output kind"))),
    };
    // SAFETY: user_context follows the kv_list contract (agc_metadata.h).
    let user_context: BTreeMap<String, String> = unsafe { super::kv_list(&md.user_context, "user_context") }?;
    Ok(api::OperationMetadata {
        key_version: md.key_version,
        provider_output: Some(api::ProviderOutput {
            encoding: fixed_str(&po.encoding, "provider_output.encoding")?,
            algorithm_output: Some(output),
        }),
        api_version: fixed_str(&md.api_version, "api_version")?,
        user_context,
        digest_hash: md.digest_hash as i32,
    })
}

/// The decoded C form of `md` (which `check_representable` accepted), its
/// variable-length values in storage in the order agc_metadata.h fixes: the
/// user-context item array (aligned), then the strings, then the bytes.
pub fn md_to_c(md: &api::OperationMetadata, p: &mut Packer) -> agc_metadata {
    // SAFETY: all-zero is AGC_INIT's state (integers, arrays, pointers).
    let mut c: agc_metadata = unsafe { std::mem::zeroed() };
    c.struct_size = size_of::<agc_metadata>();
    c.key_version = md.key_version;
    c.digest_hash = md.digest_hash as u32;
    put_fixed(&mut c.api_version, &md.api_version);

    let slot = p.reserve_array::<agc_kv>(md.user_context.len());
    let entries: Vec<agc_kv> = md.user_context.iter().map(|(k, v)| agc_kv { key: p.str(k), value: p.str(v) }).collect();
    p.fill_array(slot, &entries);
    c.user_context = agc_kv_list { items: slot.cast_const(), count: entries.len() };

    let po = md.provider_output.as_ref().expect("decoded metadata has an output");
    put_fixed(&mut c.provider_output.encoding, &po.encoding);
    let a = po.algorithm_output.as_ref().expect("decoded metadata has an output kind");
    c.provider_output.kind = u32::from(kind(a));
    // Writing a union member is safe; `kind` names the one written.
    match a {
        AlgorithmOutput::NoOutput(_) | AlgorithmOutput::VendorOutput(_) => {}
        AlgorithmOutput::AeadOutput(o) => {
            c.provider_output.u.aead.nonce = p.bytes(&o.nonce);
            c.provider_output.u.aead.tag_len = o.tag_length_bytes;
        }
        AlgorithmOutput::BlockCipherOutput(o) => c.provider_output.u.block_cipher.iv = p.bytes(&o.iv),
        AlgorithmOutput::CounterModeOutput(o) => {
            c.provider_output.u.counter_mode.counter_block = p.bytes(&o.counter_block);
            c.provider_output.u.counter_mode.counter_bits = o.counter_bits;
        }
        AlgorithmOutput::StreamCipherOutput(o) => {
            c.provider_output.u.stream_cipher.nonce = p.bytes(&o.nonce);
            c.provider_output.u.stream_cipher.block_counter = p.bytes(&o.block_counter);
        }
        AlgorithmOutput::KdfOutput(o) => {
            c.provider_output.u.kdf.salt = p.bytes(&o.salt);
            c.provider_output.u.kdf.iv = p.bytes(&o.iv);
        }
    }
    c
}
