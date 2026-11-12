//! `OperationMetadata` as bytes: the two encodings of the C API
//! (citius-c-api docs/representing_metadata.md, include/agc/agc_metadata.h).
//!
//! Every encoded metadata starts with its encoding byte:
//! - `0x01` PROTOBUF: the `OperationMetadata` message, for anything the Go
//!   service must read. Decoding is strict canonical: ascending fields, no
//!   duplicates, minimal varints, in-range values, no unknown fields. Go's
//!   decoder is lenient (last wins); every blob a real encoder produces is
//!   canonical, and on hand-crafted ones the two would disagree about which
//!   key version a ciphertext belongs to.
//! - `0x02` WIRE_V1: a fixed layout with exactly one byte string per value,
//!   O(1) to parse.
//!
//! No metadata is authenticated: `key_version` and the output kind are
//! routing hints, as in the Go service.

use prost::Message;

use crate::domain::core::{Code, Error};
use crate::proto::api::{self, provider_output::AlgorithmOutput};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MetadataEncoding {
    Protobuf = 1,
    WireV1 = 2,
}

impl MetadataEncoding {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(MetadataEncoding::Protobuf),
            2 => Some(MetadataEncoding::WireV1),
            _ => None,
        }
    }
}

const OP: &str = "metadata";

fn invalid(msg: impl Into<String>) -> Error {
    Error::new(Code::InvalidArgument, OP, msg)
}

fn vendor_unsupported() -> Error {
    Error::new(Code::ProviderNotFound, OP, "vendor output needs its provider, and none is registered")
}

/// The metadata in `enc`, encoding byte first.
pub fn encode(md: &api::OperationMetadata, enc: MetadataEncoding) -> Result<Vec<u8>, Error> {
    let mut out = vec![enc as u8];
    match enc {
        MetadataEncoding::Protobuf => {
            match arm(md)? {
                AlgorithmOutput::VendorOutput(_) => return Err(vendor_unsupported()),
                _ => md.encode(&mut out).expect("a Vec grows as needed"),
            }
        }
        MetadataEncoding::WireV1 => wire::encode(md, &mut out)?,
    }
    Ok(out)
}

/// Decodes `encoded`, encoding byte first; `enc` must match that byte (the
/// byte is authoritative, the argument catches a caller that lost track).
pub fn decode(enc: MetadataEncoding, encoded: &[u8]) -> Result<api::OperationMetadata, Error> {
    let (&first, body) = encoded.split_first().ok_or_else(|| invalid("empty metadata"))?;
    if first != enc as u8 {
        return Err(invalid(format!("metadata is encoded as {first}, not {}", enc as u8)));
    }
    decode_body(enc, body)
}

/// Decodes a body without its encoding byte, as an envelope holds it.
pub fn decode_body(enc: MetadataEncoding, body: &[u8]) -> Result<api::OperationMetadata, Error> {
    let md = match enc {
        MetadataEncoding::Protobuf => {
            canonical::check(body, canonical::OPERATION_METADATA)?;
            api::OperationMetadata::decode(body).map_err(|e| invalid(format!("metadata does not decode: {e}")))?
        }
        MetadataEncoding::WireV1 => wire::decode(body)?,
    };
    match arm(&md)? {
        AlgorithmOutput::VendorOutput(_) => Err(vendor_unsupported()),
        _ => Ok(md),
    }
}

/// `key_version` without a full decode: one load for WIRE_V1, the strict
/// scan for protobuf (no cheaper read agrees with the decoder on every input).
pub fn peek_key_version(enc: MetadataEncoding, encoded: &[u8]) -> Result<u32, Error> {
    match enc {
        MetadataEncoding::WireV1 => {
            let (&first, body) = encoded.split_first().ok_or_else(|| invalid("empty metadata"))?;
            if first != enc as u8 {
                return Err(invalid(format!("metadata is encoded as {first}, not {}", enc as u8)));
            }
            // Same validation as decode: a peek must not accept what decode rejects.
            wire::decode(body)?;
            Ok(u32::from_be_bytes(body[2..6].try_into().expect("checked by decode")))
        }
        MetadataEncoding::Protobuf => Ok(decode(enc, encoded)?.key_version),
    }
}

/// An envelope: `encoding byte ‖ metadata_len u16 BE ‖ metadata body ‖
/// ciphertext`. Returns the encoding, the body (without encoding byte) and
/// the ciphertext, all borrowed; no parse of the body.
pub fn split_envelope(envelope: &[u8]) -> Result<(MetadataEncoding, &[u8], &[u8]), Error> {
    let [first, hi, lo, rest @ ..] = envelope else {
        return Err(invalid("envelope shorter than its header"));
    };
    let enc = MetadataEncoding::from_byte(*first).ok_or_else(|| invalid(format!("unknown encoding byte {first}")))?;
    let len = u16::from_be_bytes([*hi, *lo]) as usize;
    if rest.len() < len {
        return Err(invalid("envelope shorter than its metadata length"));
    }
    let (body, ciphertext) = rest.split_at(len);
    Ok((enc, body, ciphertext))
}

/// The output arm; metadata without one is invalid (an unset oneof is a
/// provider bug, and no consumer could interpret it).
pub fn arm(md: &api::OperationMetadata) -> Result<&AlgorithmOutput, Error> {
    md.provider_output
        .as_ref()
        .and_then(|p| p.algorithm_output.as_ref())
        .ok_or_else(|| invalid("metadata has no provider output kind"))
}

/// The proto field number of an output arm (= `agc_algorithm_output_kind`).
pub fn kind(a: &AlgorithmOutput) -> u8 {
    match a {
        AlgorithmOutput::NoOutput(_) => 10,
        AlgorithmOutput::AeadOutput(_) => 11,
        AlgorithmOutput::BlockCipherOutput(_) => 12,
        AlgorithmOutput::CounterModeOutput(_) => 13,
        AlgorithmOutput::StreamCipherOutput(_) => 14,
        AlgorithmOutput::KdfOutput(_) => 15,
        AlgorithmOutput::VendorOutput(_) => 16,
    }
}

/// The strict canonical protobuf check (docs/representing_metadata.md §4.1),
/// against an explicit schema of `OperationMetadata`.
mod canonical {
    use super::{invalid, vendor_unsupported};
    use crate::domain::core::Error;

    #[derive(Clone, Copy)]
    pub enum Kind {
        /// The vendor arm: its layout belongs to its provider, so the scan
        /// refuses it (PROVIDER_NOT_FOUND) without interpreting it.
        Vendor,
        Uint32,
        /// An `int32` enum: a varint whose value is an `int32`, a negative
        /// one in its canonical 64-bit sign extension.
        Enum,
        Bytes,
        Str,
        Message(&'static [Field]),
        /// A `map<string, string>` entry; keys must be unique across entries.
        MapEntry,
    }

    #[derive(Clone, Copy)]
    pub struct Field {
        num: u64,
        kind: Kind,
        repeated: bool,
    }

    const fn f(num: u64, kind: Kind) -> Field {
        Field { num, kind, repeated: false }
    }

    const EMPTY: &[Field] = &[];
    const AEAD: &[Field] = &[f(1, Kind::Bytes), f(2, Kind::Uint32)];
    const BLOCK: &[Field] = &[f(1, Kind::Bytes)];
    const COUNTER: &[Field] = &[f(1, Kind::Bytes), f(2, Kind::Uint32)];
    const STREAM: &[Field] = &[f(1, Kind::Bytes), f(2, Kind::Bytes)];
    const KDF: &[Field] = &[f(1, Kind::Bytes), f(2, Kind::Bytes)];
    /// Fields 10-16 are the `algorithm_output` oneof: at most one is set.
    const PROVIDER_OUTPUT: &[Field] = &[
        f(1, Kind::Str),
        f(10, Kind::Message(EMPTY)),
        f(11, Kind::Message(AEAD)),
        f(12, Kind::Message(BLOCK)),
        f(13, Kind::Message(COUNTER)),
        f(14, Kind::Message(STREAM)),
        f(15, Kind::Message(KDF)),
        f(16, Kind::Vendor),
    ];
    pub const OPERATION_METADATA: &[Field] = &[
        f(1, Kind::Uint32),
        f(2, Kind::Message(PROVIDER_OUTPUT)),
        f(3, Kind::Str),
        Field { num: 4, kind: Kind::MapEntry, repeated: true },
        f(5, Kind::Enum),
    ];
    const MAP_ENTRY: &[Field] = &[f(1, Kind::Str), f(2, Kind::Str)];

    /// A minimal varint at the start of `b`: its value and length.
    fn varint(b: &[u8]) -> Result<(u64, usize), Error> {
        let mut v: u64 = 0;
        for (i, &byte) in b.iter().enumerate().take(10) {
            v |= u64::from(byte & 0x7f) << (7 * i);
            if byte & 0x80 == 0 {
                // Minimal: no trailing zero group (except the value 0 itself),
                // and the 10th byte may only carry the top bit of a u64.
                if (i > 0 && byte == 0) || (i == 9 && byte > 1) {
                    return Err(invalid("metadata has a non-minimal varint"));
                }
                return Ok((v, i + 1));
            }
        }
        Err(invalid("metadata has a truncated or overlong varint"))
    }

    pub fn check(mut b: &[u8], schema: &[Field]) -> Result<(), Error> {
        let mut last: Option<u64> = None;
        let mut oneof_set = false;
        let mut map_keys: Vec<Vec<u8>> = Vec::new();
        while !b.is_empty() {
            let (tag, n) = varint(b)?;
            b = &b[n..];
            let (num, wire) = (tag >> 3, tag & 7);
            let field = schema
                .iter()
                .find(|f| f.num == num)
                .ok_or_else(|| invalid(format!("metadata has an unknown field {num}")))?;
            match last {
                Some(l) if num < l || (num == l && !field.repeated) => {
                    return Err(invalid("metadata fields are out of order or duplicated"));
                }
                _ => {}
            }
            last = Some(num);
            if schema.len() == 8 && (10..=16).contains(&num) {
                // PROVIDER_OUTPUT's oneof.
                if oneof_set {
                    return Err(invalid("metadata has more than one output kind"));
                }
                oneof_set = true;
            }
            match (field.kind, wire) {
                (Kind::Vendor, _) => return Err(vendor_unsupported()),
                (Kind::Uint32, 0) => {
                    let (v, n) = varint(b)?;
                    if v > u64::from(u32::MAX) {
                        return Err(invalid("metadata has a uint32 out of range"));
                    }
                    b = &b[n..];
                }
                (Kind::Enum, 0) => {
                    let (v, n) = varint(b)?;
                    if i32::try_from(v as i64).is_err() {
                        return Err(invalid("metadata has an enum value out of range"));
                    }
                    b = &b[n..];
                }
                (Kind::Bytes | Kind::Str | Kind::Message(_) | Kind::MapEntry, 2) => {
                    let (len, n) = varint(b)?;
                    let len = usize::try_from(len).map_err(|_| invalid("metadata length out of range"))?;
                    let rest = &b[n..];
                    if rest.len() < len {
                        return Err(invalid("metadata length runs past its end"));
                    }
                    let (value, after) = rest.split_at(len);
                    match field.kind {
                        Kind::Str if std::str::from_utf8(value).is_err() => {
                            return Err(invalid("metadata has a string that is not UTF-8"));
                        }
                        Kind::Message(inner) => check(value, inner)?,
                        Kind::MapEntry => {
                            check(value, MAP_ENTRY)?;
                            let key = map_key(value)?;
                            if map_keys.contains(&key) {
                                return Err(invalid("metadata has a duplicate map key"));
                            }
                            map_keys.push(key);
                        }
                        _ => {}
                    }
                    b = after;
                }
                _ => return Err(invalid(format!("metadata field {num} has the wrong wire type"))),
            }
        }
        Ok(())
    }

    /// The key of a validated map entry ("" if absent).
    fn map_key(entry: &[u8]) -> Result<Vec<u8>, Error> {
        let mut b = entry;
        while !b.is_empty() {
            let (tag, n) = varint(b)?;
            let (len, m) = varint(&b[n..])?;
            let value = &b[n + m..n + m + len as usize];
            if tag >> 3 == 1 {
                return Ok(value.to_vec());
            }
            b = &b[n + m + len as usize..];
        }
        Ok(Vec::new())
    }
}

/// WIRE_V1 (docs/representing_metadata.md §6): big-endian, fixed header,
/// exactly one valid byte string per value.
mod wire {
    use std::collections::BTreeMap;

    use super::{AlgorithmOutput, arm, invalid, kind, vendor_unsupported};
    use crate::domain::core::Error;
    use crate::proto::api;

    const ENCODINGS: [&str; 5] = ["", "raw", "der", "jws", "cbor"];

    fn api_version(s: &str) -> Result<(u8, u8), Error> {
        let bad = || invalid(format!("api_version {s:?} is not \"major.minor\" with parts 0-255"));
        let (a, b) = s.split_once('.').ok_or_else(bad)?;
        let part = |p: &str| {
            // Canonical decimal only, so the string round-trips exactly.
            if p.is_empty() || (p.len() > 1 && p.starts_with('0')) || !p.bytes().all(|c| c.is_ascii_digit()) {
                return Err(bad());
            }
            p.parse::<u8>().map_err(|_| bad())
        };
        Ok((part(a)?, part(b)?))
    }

    fn u8_len(b: &[u8], what: &str) -> Result<u8, Error> {
        u8::try_from(b.len()).map_err(|_| invalid(format!("{what} is longer than 255 bytes")))
    }

    fn u8_val(v: u32, what: &str) -> Result<u8, Error> {
        u8::try_from(v).map_err(|_| invalid(format!("{what} {v} does not fit WIRE_V1")))
    }

    fn put_bytes(out: &mut Vec<u8>, b: &[u8], what: &str) -> Result<(), Error> {
        out.push(u8_len(b, what)?);
        out.extend_from_slice(b);
        Ok(())
    }

    pub fn encode(md: &api::OperationMetadata, out: &mut Vec<u8>) -> Result<(), Error> {
        // v1 has no slot for it (docs/representing_metadata.md §6.7, DV-15).
        if md.digest_hash != api::HashAlgorithm::Unspecified as i32 {
            return Err(invalid("WIRE_V1 cannot express digest_hash: use PROTOBUF for digest signing"));
        }
        let (major, minor) = api_version(&md.api_version)?;
        let po = md.provider_output.as_ref().expect("arm() checked it");
        let encoding_id = ENCODINGS
            .iter()
            .position(|e| *e == po.encoding)
            .ok_or_else(|| invalid(format!("output encoding {:?} cannot be expressed in WIRE_V1", po.encoding)))?;
        let a = arm(md)?;
        let mut output = Vec::new();
        match a {
            AlgorithmOutput::NoOutput(_) => {}
            AlgorithmOutput::AeadOutput(o) => {
                put_bytes(&mut output, &o.nonce, "nonce")?;
                output.push(u8_val(o.tag_length_bytes, "tag length")?);
            }
            AlgorithmOutput::BlockCipherOutput(o) => put_bytes(&mut output, &o.iv, "IV")?,
            AlgorithmOutput::CounterModeOutput(o) => {
                put_bytes(&mut output, &o.counter_block, "counter block")?;
                output.push(u8_val(o.counter_bits, "counter bits")?);
            }
            AlgorithmOutput::StreamCipherOutput(o) => {
                put_bytes(&mut output, &o.nonce, "nonce")?;
                put_bytes(&mut output, &o.block_counter, "block counter")?;
            }
            AlgorithmOutput::KdfOutput(o) => {
                put_bytes(&mut output, &o.salt, "salt")?;
                put_bytes(&mut output, &o.iv, "IV")?;
            }
            AlgorithmOutput::VendorOutput(_) => return Err(vendor_unsupported()),
        }
        let uc_count = u8::try_from(md.user_context.len())
            .map_err(|_| invalid("WIRE_V1 holds at most 255 user-context entries"))?;
        out.extend_from_slice(&[major, minor]);
        out.extend_from_slice(&md.key_version.to_be_bytes());
        out.extend_from_slice(&[encoding_id as u8, kind(a)]);
        out.extend_from_slice(&(output.len() as u16).to_be_bytes()); // at most 2 + 2 * 255
        out.extend_from_slice(&output);
        out.push(uc_count);
        // A BTreeMap iterates in bytewise key order, as the format requires.
        for (k, v) in &md.user_context {
            for s in [k, v] {
                let len = u16::try_from(s.len()).map_err(|_| invalid("a user-context string exceeds 65535 bytes"))?;
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(s.as_bytes());
            }
        }
        Ok(())
    }

    /// A cursor that fails on every overrun.
    struct R<'a>(&'a [u8]);

    impl<'a> R<'a> {
        fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
            if self.0.len() < n {
                return Err(invalid("WIRE_V1 metadata is truncated"));
            }
            let (a, b) = self.0.split_at(n);
            self.0 = b;
            Ok(a)
        }

        fn u8(&mut self) -> Result<u8, Error> {
            Ok(self.take(1)?[0])
        }

        fn u16(&mut self) -> Result<usize, Error> {
            let b = self.take(2)?;
            Ok(u16::from_be_bytes([b[0], b[1]]) as usize)
        }

        fn bytes8(&mut self) -> Result<Vec<u8>, Error> {
            let n = self.u8()? as usize;
            Ok(self.take(n)?.to_vec())
        }

        fn string16(&mut self) -> Result<String, Error> {
            let n = self.u16()?;
            String::from_utf8(self.take(n)?.to_vec()).map_err(|_| invalid("WIRE_V1 string is not UTF-8"))
        }
    }

    pub fn decode(body: &[u8]) -> Result<api::OperationMetadata, Error> {
        let mut r = R(body);
        let (major, minor) = (r.u8()?, r.u8()?);
        let key_version = u32::from_be_bytes(r.take(4)?.try_into().expect("4 bytes"));
        let encoding = *ENCODINGS
            .get(r.u8()? as usize)
            .ok_or_else(|| invalid("WIRE_V1 metadata has an unknown output encoding"))?;
        let kind = r.u8()?;
        let output_len = r.u16()?;
        let mut o = R(r.take(output_len)?);
        let output = match kind {
            10 => AlgorithmOutput::NoOutput(api::NoAlgorithmOutput {}),
            11 => AlgorithmOutput::AeadOutput(api::AeadOutput { nonce: o.bytes8()?, tag_length_bytes: o.u8()?.into() }),
            12 => AlgorithmOutput::BlockCipherOutput(api::BlockCipherOutput { iv: o.bytes8()? }),
            13 => AlgorithmOutput::CounterModeOutput(api::CounterModeOutput {
                counter_block: o.bytes8()?,
                counter_bits: o.u8()?.into(),
            }),
            14 => AlgorithmOutput::StreamCipherOutput(api::StreamCipherOutput {
                nonce: o.bytes8()?,
                block_counter: o.bytes8()?,
            }),
            15 => AlgorithmOutput::KdfOutput(api::KdfOutput { salt: o.bytes8()?, iv: o.bytes8()? }),
            16 => return Err(vendor_unsupported()),
            other => return Err(invalid(format!("WIRE_V1 metadata has an unknown output kind {other}"))),
        };
        if !o.0.is_empty() {
            return Err(invalid("WIRE_V1 output section has trailing bytes"));
        }
        let mut user_context = BTreeMap::new();
        let mut previous: Option<String> = None;
        for _ in 0..r.u8()? {
            let (k, v) = (r.string16()?, r.string16()?);
            if previous.as_ref().is_some_and(|p| *p >= k) {
                return Err(invalid("WIRE_V1 user-context keys are not strictly ascending"));
            }
            previous = Some(k.clone());
            user_context.insert(k, v);
        }
        if !r.0.is_empty() {
            return Err(invalid("WIRE_V1 metadata has trailing bytes"));
        }
        Ok(api::OperationMetadata {
            key_version,
            provider_output: Some(api::ProviderOutput { encoding: encoding.to_owned(), algorithm_output: Some(output) }),
            api_version: format!("{major}.{minor}"),
            user_context,
            digest_hash: api::HashAlgorithm::Unspecified as i32,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    /// The real protobuf library's encodings, against the same pinned
    /// descriptor (citius-c-api conformance/golden).
    const GOLDEN: &str = include_str!("../../../../citius-c-api/conformance/golden/operation_metadata_vectors.json");

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn golden() -> Vec<(String, Vec<u8>, serde_json::Value)> {
        let v: serde_json::Value = serde_json::from_str(GOLDEN).unwrap();
        v.as_object()
            .unwrap()
            .iter()
            .map(|(name, case)| (name.clone(), hex(case["bytes"].as_str().unwrap()), case.clone()))
            .collect()
    }

    fn with_byte(enc: MetadataEncoding, body: &[u8]) -> Vec<u8> {
        let mut v = vec![enc as u8];
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn golden_protobuf_vectors_decode_and_re_encode_byte_for_byte() {
        for (name, body, case) in golden() {
            let encoded = with_byte(MetadataEncoding::Protobuf, &body);
            let r = decode(MetadataEncoding::Protobuf, &encoded);
            if name == "vendor" {
                assert_eq!(r.unwrap_err().code(), Code::ProviderNotFound);
                continue;
            }
            let md = r.unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(md.key_version as u64, case["key_version"].as_u64().unwrap(), "{name}");
            assert_eq!(md.api_version, case["api_version"].as_str().unwrap(), "{name}");
            assert_eq!(encode(&md, MetadataEncoding::Protobuf).unwrap(), encoded, "{name}: re-encoding differs");
            assert_eq!(peek_key_version(MetadataEncoding::Protobuf, &encoded).unwrap(), md.key_version);
        }
    }

    #[test]
    fn the_reference_case_in_wire_v1_is_26_bytes() {
        // docs/representing_metadata.md §6.3.
        let md = api::OperationMetadata {
            key_version: 3,
            provider_output: Some(api::ProviderOutput {
                encoding: "raw".into(),
                algorithm_output: Some(AlgorithmOutput::AeadOutput(api::AeadOutput {
                    nonce: (1..=12).collect(),
                    tag_length_bytes: 16,
                })),
            }),
            api_version: "1.0".into(),
            user_context: BTreeMap::new(),
            ..Default::default()
        };
        let w = encode(&md, MetadataEncoding::WireV1).unwrap();
        let mut want = vec![0x02, 0x01, 0x00, 0, 0, 0, 3, 0x01, 0x0B, 0x00, 0x0E, 0x0C];
        want.extend(1..=12u8);
        want.extend([0x10, 0x00]);
        assert_eq!(w, want);
        assert_eq!(decode(MetadataEncoding::WireV1, &w).unwrap(), md);
        assert_eq!(peek_key_version(MetadataEncoding::WireV1, &w).unwrap(), 3);
    }

    #[test]
    fn every_golden_value_round_trips_through_wire_v1() {
        for (name, body, _) in golden() {
            if name == "vendor" {
                continue;
            }
            let mut md = decode_body(MetadataEncoding::Protobuf, &body).unwrap();
            if md.api_version.is_empty() {
                md.api_version = "1.0".into(); // WIRE_V1 cannot express an empty version
            }
            let w = encode(&md, MetadataEncoding::WireV1).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(decode(MetadataEncoding::WireV1, &w).unwrap(), md, "{name}");
        }
    }

    /// Rejected as invalid, for the reason named by `because` (a substring
    /// of the message), so that a vector cannot pass by failing elsewhere.
    fn reject(enc: MetadataEncoding, body: &[u8], because: &str) {
        let e = decode(enc, &with_byte(enc, body)).map(|_| ()).unwrap_err();
        assert_eq!(e.code(), Code::InvalidArgument, "{because}: {e}");
        assert!(e.message().contains(because), "expected {because:?}, got {:?}", e.message());
    }

    #[test]
    fn non_canonical_protobuf_is_rejected() {
        let pb = MetadataEncoding::Protobuf;
        // The no_output golden vector is 08 01 | 12 02 52 00 | 1a 03 "1.0".
        reject(pb, &hex("120252000801"), "out of order");
        reject(pb, &hex("0801080112025200"), "out of order or duplicated");
        reject(pb, &hex("08810012025200"), "non-minimal varint");
        reject(pb, &hex("0880"), "truncated");
        // Field 5 is digest_hash since v0.3.0; 6 is still unknown.
        reject(pb, &hex("0801120252003001"), "unknown field 6");
        reject(pb, &hex("0801120452006200"), "more than one output kind");
        reject(pb, &hex("08011200"), "no provider output kind");
        reject(pb, &hex("088080808010120252 00".replace(' ', "").as_str()), "uint32 out of range");
        reject(pb, &hex("0a0112025200"), "wrong wire type");
        reject(pb, &hex("0801120252001a02c328"), "not UTF-8");
        reject(pb, &hex("0801120352"), "runs past its end");
        // Two user-context entries {"k": ""} with the same key.
        reject(pb, &hex("08011202520022030a016b22030a016b"), "duplicate map key");
    }

    #[test]
    fn malformed_wire_v1_is_rejected() {
        let w = MetadataEncoding::WireV1;
        let ok = encode(
            &api::OperationMetadata {
                key_version: 1,
                provider_output: Some(api::ProviderOutput {
                    encoding: "".into(),
                    algorithm_output: Some(AlgorithmOutput::NoOutput(api::NoAlgorithmOutput {})),
                }),
                api_version: "1.0".into(),
                user_context: BTreeMap::from([("a".into(), "1".into()), ("b".into(), "2".into())]),
                ..Default::default()
            },
            w,
        )
        .unwrap();
        let body = &ok[1..];
        assert!(decode_body(w, body).is_ok());
        let mutate = |f: &dyn Fn(&mut Vec<u8>)| {
            let mut b = body.to_vec();
            f(&mut b);
            b
        };
        reject(w, &mutate(&|b| b.push(0)), "trailing bytes");
        reject(w, &body[..body.len() - 1], "truncated");
        reject(w, &mutate(&|b| b[7] = 9), "unknown output kind");
        reject(w, &mutate(&|b| b[6] = 5), "unknown output encoding");
        // Swap the two keys' first bytes: "b" then "a" is not ascending.
        reject(w, &mutate(&|b| {
            let i = b.iter().position(|&x| x == b'a').unwrap();
            let j = b.iter().position(|&x| x == b'b').unwrap();
            b.swap(i, j);
        }), "not strictly ascending");
        let e = decode(MetadataEncoding::Protobuf, &ok).unwrap_err();
        assert!(e.message().contains("is encoded as 2"), "byte mismatch: {e}");
    }

    #[test]
    fn wire_v1_refuses_what_it_cannot_express() {
        let mut md = api::OperationMetadata {
            key_version: 1,
            provider_output: Some(api::ProviderOutput {
                encoding: "p1363".into(),
                algorithm_output: Some(AlgorithmOutput::NoOutput(api::NoAlgorithmOutput {})),
            }),
            api_version: "1.0".into(),
            user_context: BTreeMap::new(),
            ..Default::default()
        };
        assert_eq!(encode(&md, MetadataEncoding::WireV1).unwrap_err().code(), Code::InvalidArgument);
        md.provider_output.as_mut().unwrap().encoding = "der".into();
        for v in ["", "1", "1.0.0", "256.0", "01.0", "a.b"] {
            md.api_version = v.into();
            assert!(encode(&md, MetadataEncoding::WireV1).is_err(), "{v:?}");
        }
        // Protobuf expresses all of them.
        md.api_version = "anything".into();
        assert!(encode(&md, MetadataEncoding::Protobuf).is_ok());
    }

    /// digest_hash (v0.3.0) has no slot in WIRE_V1 (DV-15); protobuf carries
    /// it as field 5, and the strict decoder accepts it there.
    #[test]
    fn digest_hash_is_protobuf_only() {
        let mut md = api::OperationMetadata {
            key_version: 2,
            provider_output: Some(api::ProviderOutput {
                encoding: "der".into(),
                algorithm_output: Some(AlgorithmOutput::NoOutput(api::NoAlgorithmOutput {})),
            }),
            api_version: "1.0".into(),
            ..Default::default()
        };
        assert!(encode(&md, MetadataEncoding::WireV1).is_ok(), "UNSPECIFIED is expressible");
        md.digest_hash = api::HashAlgorithm::Sha384 as i32;
        assert_eq!(encode(&md, MetadataEncoding::WireV1).unwrap_err().code(), Code::InvalidArgument);
        let pb = encode(&md, MetadataEncoding::Protobuf).unwrap();
        assert_eq!(decode(MetadataEncoding::Protobuf, &pb).unwrap(), md);
        // Field 5 holding a value outside int32 is not canonical.
        let mut bad = pb.clone();
        bad.extend([0x28, 0x80, 0x80, 0x80, 0x80, 0x10]); // 5: 2^32
        assert!(decode(MetadataEncoding::Protobuf, &bad).is_err());
    }

    #[test]
    fn envelopes_split_without_parsing() {
        let mut env = vec![2, 0, 3, 9, 9, 9];
        env.extend_from_slice(b"ciphertext");
        let (enc, body, ct) = split_envelope(&env).unwrap();
        assert_eq!((enc, body, ct), (MetadataEncoding::WireV1, &[9u8, 9, 9][..], &b"ciphertext"[..]));
        assert!(split_envelope(&[2, 0, 4, 9, 9, 9]).is_err(), "body runs past the end");
        assert!(split_envelope(&[7, 0, 0]).is_err(), "unknown encoding");
        assert!(split_envelope(&[2, 0]).is_err(), "short header");
    }
}
