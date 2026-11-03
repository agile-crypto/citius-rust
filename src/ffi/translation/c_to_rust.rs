use std::collections::BTreeMap;
use std::ffi::{CStr, c_char};

use crate::bindings::*;
use crate::domain::core::{
    KeyCreationSpec, PrimitiveProperties, ProviderRequirements, Scope, ScopeKind, ScopeSpecification,
    SecurityProperties,
};
use crate::ffi::error::FfiError;

/// Turns a C string pointer into a `&CStr`; NULL becomes `None`.
///
/// # Safety
/// `p` must be NULL or point to a NUL-terminated string that stays valid and
/// unmodified for the lifetime `'a`.
pub unsafe fn null_check_c_string<'a>(p: *const c_char) -> Option<&'a CStr> {
    if p.is_null() {
        None
    } else {
        // SAFETY: p is non-null (checked above); NUL-termination and lifetime are this function's contract.
        Some(unsafe { CStr::from_ptr(p) })
    }
}

/// A required, non-empty UTF-8 string argument.
///
/// # Safety
/// As `null_check_c_string`.
pub unsafe fn required_str<'a>(p: *const c_char, what: &str) -> Result<&'a str, FfiError> {
    // SAFETY: forwarded from this function's contract.
    let s = unsafe { null_check_c_string(p) }.ok_or_else(|| FfiError::invalid(format!("{what} must not be NULL")))?;
    let s = s.to_str().map_err(|_| FfiError::invalid(format!("{what} must be UTF-8")))?;
    if s.is_empty() {
        return Err(FfiError::invalid(format!("{what} must not be empty")));
    }
    Ok(s)
}

/// An optional UTF-8 string argument: NULL and "" both mean "not given".
///
/// # Safety
/// As `null_check_c_string`.
pub unsafe fn optional_str<'a>(p: *const c_char, what: &str) -> Result<Option<&'a str>, FfiError> {
    // SAFETY: forwarded from this function's contract.
    match unsafe { null_check_c_string(p) } {
        None => Ok(None),
        Some(s) => {
            let s = s.to_str().map_err(|_| FfiError::invalid(format!("{what} must be UTF-8")))?;
            Ok((!s.is_empty()).then_some(s))
        }
    }
}

/// The C scope kind as a domain value. `NONE` and values this header does
/// not name are rejected: a C enum can hold any integer.
pub fn scope_kind(kind: agc_scope_kind) -> Result<ScopeKind, FfiError> {
    Ok(match kind {
        agc_scope_kind_AGC_SCOPE_KIND_SIGNATURE => ScopeKind::Signature,
        agc_scope_kind_AGC_SCOPE_KIND_AEAD => ScopeKind::Aead,
        agc_scope_kind_AGC_SCOPE_KIND_MAC => ScopeKind::Mac,
        agc_scope_kind_AGC_SCOPE_KIND_KEM => ScopeKind::Kem,
        agc_scope_kind_AGC_SCOPE_KIND_KEY_AGREEMENT => ScopeKind::KeyAgreement,
        agc_scope_kind_AGC_SCOPE_KIND_KDF => ScopeKind::Kdf,
        agc_scope_kind_AGC_SCOPE_KIND_HASH => ScopeKind::Hash,
        agc_scope_kind_AGC_SCOPE_KIND_KEY_WRAPPING => ScopeKind::KeyWrapping,
        agc_scope_kind_AGC_SCOPE_KIND_SYMMETRIC_CIPHER => ScopeKind::SymmetricCipher,
        agc_scope_kind_AGC_SCOPE_KIND_GENERIC_SECRET => ScopeKind::GenericSecret,
        agc_scope_kind_AGC_SCOPE_KIND_DISK_ENCRYPTION => ScopeKind::DiskEncryption,
        // Go's core.Scope has no asymmetric-encryption scope (DEVIATIONS G31).
        agc_scope_kind_AGC_SCOPE_KIND_ASYMMETRIC_ENCRYPTION => {
            return Err(FfiError::invalid("unrecognized scope: asymmetric encryption"));
        }
        agc_scope_kind_AGC_SCOPE_KIND_NONE => return Err(FfiError::invalid("scope_spec.kind must be set")),
        other => return Err(FfiError::invalid(format!("scope_spec.kind {other} is not a known scope kind"))),
    })
}

/// A proto enum from the C value of the same enum. agc_types.h is generated
/// from the proto, so the numbers are the same; values the proto does not
/// name are rejected.
fn proto_enum<E: TryFrom<i32>>(v: u32, what: &str) -> Result<E, FfiError> {
    i32::try_from(v)
        .ok()
        .and_then(|v| E::try_from(v).ok())
        .ok_or_else(|| FfiError::invalid(format!("{what} {v} is not a known value")))
}

pub fn tribool(v: agc_tribool, what: &str) -> Result<Option<bool>, FfiError> {
    match v {
        agc_tribool_AGC_UNSET => Ok(None),
        agc_tribool_AGC_FALSE => Ok(Some(false)),
        agc_tribool_AGC_TRUE => Ok(Some(true)),
        other => Err(FfiError::invalid(format!("{what} {other} is not an agc_tribool"))),
    }
}

/// All-zero means "no requirements" and becomes `None`: Go's matching treats a
/// present security filter as "the template must declare security
/// properties", which a caller who set nothing did not ask for.
fn security(s: &agc_security_properties) -> Result<Option<SecurityProperties>, FfiError> {
    let p = SecurityProperties {
        strength_bits: s.security_strength_bits,
        nist_level: proto_enum(s.nist_security_level, "security.nist_security_level")?,
        quantum_safe: tribool(s.quantum_safe, "security.quantum_safe")?,
        nist_status: proto_enum(s.nist_status, "security.nist_status")?,
        fips_approved: tribool(s.fips_approved, "security.fips_approved")?,
    };
    Ok((p != SecurityProperties::default()).then_some(p))
}

/// A proto `map<string, string>`: NULL items with a non-zero count, NULL or
/// non-UTF-8 strings and duplicate keys are rejected (agc_abi.h).
///
/// # Safety
/// `list.items` is NULL or points to `list.count` entries whose strings are
/// NULL or valid C strings, for the duration of the call.
pub unsafe fn kv_list(list: &agc_kv_list, what: &str) -> Result<BTreeMap<String, String>, FfiError> {
    if list.count == 0 {
        return Ok(BTreeMap::new());
    }
    if list.items.is_null() {
        return Err(FfiError::invalid(format!("{what}.items is NULL but count is {}", list.count)));
    }
    // SAFETY: items is non-null and has count entries (this function's contract).
    let items = unsafe { std::slice::from_raw_parts(list.items, list.count) };
    let mut map = BTreeMap::new();
    for kv in items {
        // SAFETY: key and value are NULL or valid C strings (this function's contract).
        let key = unsafe { null_check_c_string(kv.key) }.ok_or_else(|| FfiError::invalid(format!("{what}: NULL key")))?;
        // SAFETY: as above.
        let value =
            unsafe { null_check_c_string(kv.value) }.ok_or_else(|| FfiError::invalid(format!("{what}: NULL value")))?;
        let (key, value) = match (key.to_str(), value.to_str()) {
            (Ok(k), Ok(v)) => (k.to_owned(), v.to_owned()),
            _ => return Err(FfiError::invalid(format!("{what}: strings must be UTF-8"))),
        };
        if map.insert(key.clone(), value).is_some() {
            return Err(FfiError::invalid(format!("{what}: duplicate key {key:?}")));
        }
    }
    Ok(map)
}

/// The C scope specification as a domain value. The family's scope value 0
/// (UNSPECIFIED) means "any scope of this kind".
///
/// # Safety
/// The `additional_properties` list of the member `s.kind` selects follows
/// the `kv_list` contract.
pub unsafe fn scope_spec(s: &agc_scope_spec) -> Result<ScopeSpecification, FfiError> {
    // Each arm reads the union member that `kind` selects. Every member is
    // made of integers and raw pointers, so the read itself is always defined;
    // reading the selected one is what makes the values meaningful.
    macro_rules! member {
        ($field:ident, $variant:ident, $what:literal) => {{
            // SAFETY: see above.
            let m = unsafe { &s.u.$field };
            (Scope::$variant(proto_enum(m.scope, concat!("scope_spec.u.", $what, ".scope"))?), &m.security, &m.additional_properties)
        }};
    }
    let mut props = PrimitiveProperties::default();
    let (scope, sec, additional) = match scope_kind(s.kind)? {
        ScopeKind::Signature => {
            // SAFETY: kind selects the signature member (see above).
            let m = unsafe { &s.u.signature };
            props.non_malleable = tribool(m.non_malleable, "scope_spec.u.signature.non_malleable")?;
            props.deterministic = tribool(m.deterministic, "scope_spec.u.signature.deterministic")?;
            member!(signature, Signature, "signature")
        }
        ScopeKind::Aead => {
            // SAFETY: kind selects the aead member.
            let m = unsafe { &s.u.aead };
            props.nonce_misuse_resistant = tribool(m.nonce_misuse_resistant, "scope_spec.u.aead.nonce_misuse_resistant")?;
            member!(aead, Aead, "aead")
        }
        ScopeKind::KeyAgreement => {
            // SAFETY: kind selects the key_agreement member.
            let m = unsafe { &s.u.key_agreement };
            props.forward_secrecy = tribool(m.forward_secrecy, "scope_spec.u.key_agreement.forward_secrecy")?;
            member!(key_agreement, KeyAgreement, "key_agreement")
        }
        ScopeKind::Kdf => {
            // SAFETY: kind selects the kdf member.
            let m = unsafe { &s.u.kdf };
            props.memory_hard = tribool(m.memory_hard, "scope_spec.u.kdf.memory_hard")?;
            member!(kdf, Kdf, "kdf")
        }
        ScopeKind::Mac => member!(mac, Mac, "mac"),
        ScopeKind::Kem => member!(kem, Kem, "kem"),
        ScopeKind::Hash => member!(hash, Hash, "hash"),
        ScopeKind::KeyWrapping => member!(key_wrapping, KeyWrapping, "key_wrapping"),
        ScopeKind::SymmetricCipher => member!(symmetric_cipher, SymmetricCipher, "symmetric_cipher"),
        ScopeKind::GenericSecret => member!(generic_secret, GenericSecret, "generic_secret"),
        ScopeKind::DiskEncryption => member!(disk_encryption, DiskEncryption, "disk_encryption"),
    };
    Ok(ScopeSpecification {
        scope,
        security: security(sec)?,
        properties: props,
        // SAFETY: forwarded from this function's contract.
        additional: unsafe { kv_list(additional, "scope_spec additional_properties") }?,
    })
}

/// The caller's provider requirements; NULL requires nothing. A `false`
/// tribool requires nothing either: these are minimums, never "must not".
/// `additional` requirements cannot be checked by this library and are
/// rejected rather than ignored.
///
/// # Safety
/// `p` is NULL or a versioned struct with `struct_size` readable bytes.
pub unsafe fn provider_requirements(p: *const agc_provider_requirements) -> Result<ProviderRequirements, FfiError> {
    if p.is_null() {
        return Ok(ProviderRequirements::default());
    }
    // SAFETY: forwarded from this function's contract.
    let r = unsafe { crate::ffi::versioned::read(p, "provider_requirements") }?;
    if r.additional.count != 0 {
        return Err(FfiError::NotImplemented("provider_requirements.additional"));
    }
    let yes = |v, what| Ok::<_, FfiError>(tribool(v, what)? == Some(true));
    Ok(ProviderRequirements {
        fips_140_certified: yes(r.fips_140_certified, "provider_requirements.fips_140_certified")?,
        min_fips_140_level: match r.min_fips_level {
            level @ 0..=4 => level,
            other => return Err(FfiError::invalid(format!("provider_requirements.min_fips_level {other} is not 0-4"))),
        },
        common_criteria_certified: yes(r.common_criteria_certified, "provider_requirements.common_criteria_certified")?,
        formally_verified: yes(r.formally_verified, "provider_requirements.formally_verified")?,
        memory_safe: yes(r.memory_safe, "provider_requirements.memory_safe")?,
        constant_time: yes(r.constant_time, "provider_requirements.constant_time")?,
        side_channel_hardened: yes(r.side_channel_hardened, "provider_requirements.side_channel_hardened")?,
        no_known_cve: yes(r.no_known_cve, "provider_requirements.no_known_cve")?,
        approved_generation: false,
        prefer_hardware_accelerated: yes(r.prefer_hardware_accelerated, "provider_requirements.prefer_hardware_accelerated")?,
    })
}

/// Converts the C request into a `KeyCreationSpec` and validates it. A
/// request that names no policy gets `default_policy`
/// (`agc_ctx_config.default_policy`); with neither, it is invalid.
///
/// # Safety
/// The string fields of `p` must each be NULL or a valid NUL-terminated
/// string, `scope_spec` must follow the `scope_spec` contract, and
/// `provider_requirements` must be NULL or a valid struct, for the duration
/// of the call.
pub unsafe fn spec_from_params(
    p: &agc_create_key_params,
    default_policy: Option<&str>,
) -> Result<KeyCreationSpec, FfiError> {
    // SAFETY: forwarded from this function's contract.
    let scope_spec = unsafe { scope_spec(&p.scope_spec) }?;
    // SAFETY: key_name is NULL or a valid C string (this function's contract).
    let name = unsafe { required_str(p.key_name, "key_name") }?;
    // SAFETY: policy_name is NULL or a valid C string (this function's contract).
    let policy = unsafe { optional_str(p.policy_name, "policy_name") }?
        .or(default_policy)
        .ok_or_else(|| FfiError::invalid("policy_name is required (no agc_ctx_config.default_policy is set)"))?;
    // SAFETY: template_id is NULL or a valid C string (this function's contract).
    let template_id = unsafe { optional_str(p.template_id, "template_id") }?;
    // SAFETY: provider_id is NULL or a valid C string (this function's contract).
    let provider_id = unsafe { optional_str(p.provider_id, "provider_id") }?;
    // Provider configuration is not consumed by any provider yet; rejected
    // rather than silently dropped (as the Go handler does).
    if p.provider_configuration.count != 0 {
        return Err(FfiError::NotImplemented("provider_configuration"));
    }
    // SAFETY: provider_requirements is NULL or a valid struct (agc_key.h contract).
    let provider_requirements = unsafe { provider_requirements(p.provider_requirements) }?;

    Ok(KeyCreationSpec {
        name: name.to_owned(),
        policy: policy.to_owned(),
        template_id: template_id.map(str::to_owned),
        scope_spec,
        provider_id: provider_id.map(str::to_owned),
        provider_requirements,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::api;

    fn convert(p: &agc_create_key_params) -> Result<KeyCreationSpec, FfiError> {
        // SAFETY: test params hold only NULL or 'static C string literals.
        unsafe { spec_from_params(p, None) }
    }

    fn params() -> agc_create_key_params {
        // SAFETY: integers and raw pointers only; all zeros is AGC_INIT's state.
        let mut p: agc_create_key_params = unsafe { std::mem::zeroed() };
        p.struct_size = size_of::<agc_create_key_params>();
        p.key_name = c"k".as_ptr();
        p.policy_name = c"default".as_ptr();
        // scope_spec is a const member in C; bindgen gives a plain field.
        p.scope_spec.kind = agc_scope_kind_AGC_SCOPE_KIND_AEAD;
        p
    }

    #[test]
    fn valid_params_convert() {
        let spec = convert(&params()).unwrap();
        assert_eq!(spec.name, "k");
        assert_eq!(spec.policy, "default");
        assert_eq!(spec.template_id, None);
        // Only the kind is set: any AEAD scope, no further requirements.
        assert_eq!(spec.scope_spec, ScopeSpecification::any_of(Scope::Aead(api::AeadScope::Unspecified)));
    }

    #[test]
    fn empty_template_id_means_none() {
        let mut p = params();
        p.template_id = c"".as_ptr();
        assert_eq!(convert(&p).unwrap().template_id, None);
        p.template_id = c"aes-128-gcm-128-96".as_ptr();
        assert_eq!(convert(&p).unwrap().template_id.as_deref(), Some("aes-128-gcm-128-96"));
    }

    #[test]
    fn missing_or_empty_name_is_rejected() {
        let mut p = params();
        p.key_name = std::ptr::null();
        assert!(matches!(convert(&p), Err(FfiError::InvalidArgument(_))));
        p.key_name = c"".as_ptr();
        assert!(matches!(convert(&p), Err(FfiError::InvalidArgument(_))));
    }

    #[test]
    fn the_default_policy_applies_only_when_none_is_named() {
        let mut p = params();
        // SAFETY: as in `convert`.
        let with_default = |p: &agc_create_key_params| unsafe { spec_from_params(p, Some("fallback")) };
        assert_eq!(with_default(&p).unwrap().policy, "default");
        p.policy_name = std::ptr::null();
        assert_eq!(with_default(&p).unwrap().policy, "fallback");
        p.policy_name = c"".as_ptr();
        assert_eq!(with_default(&p).unwrap().policy, "fallback");
        assert!(matches!(convert(&p), Err(FfiError::InvalidArgument(_))));
    }

    #[test]
    fn non_utf8_name_is_rejected() {
        let mut p = params();
        p.key_name = c"\xff".as_ptr();
        assert!(matches!(convert(&p), Err(FfiError::InvalidArgument(_))));
    }

    #[test]
    fn scope_and_requirements_are_converted() {
        let kvs = [agc_kv { key: c"vendor".as_ptr(), value: c"x".as_ptr() }];
        let mut p = params();
        // Writing a union member is safe; kind selects the aead member.
        p.scope_spec.u.aead.scope = agc_aead_scope_AGC_AEAD_SCOPE_DETERMINISTIC;
        p.scope_spec.u.aead.nonce_misuse_resistant = agc_tribool_AGC_TRUE;
        p.scope_spec.u.aead.security.security_strength_bits = 256;
        p.scope_spec.u.aead.security.quantum_safe = agc_tribool_AGC_FALSE;
        p.scope_spec.u.aead.additional_properties = agc_kv_list { items: kvs.as_ptr(), count: 1 };
        let spec = convert(&p).unwrap().scope_spec;
        assert_eq!(spec.scope, Scope::Aead(api::AeadScope::Deterministic));
        assert_eq!(spec.properties.nonce_misuse_resistant, Some(true));
        let sec = spec.security.unwrap();
        assert_eq!((sec.strength_bits, sec.quantum_safe), (256, Some(false)));
        assert_eq!(spec.additional.get("vendor").map(String::as_str), Some("x"));
    }

    #[test]
    fn bad_scope_values_are_rejected() {
        let dup = [
            agc_kv { key: c"k".as_ptr(), value: c"1".as_ptr() },
            agc_kv { key: c"k".as_ptr(), value: c"2".as_ptr() },
        ];
        let cases: [fn(&mut agc_create_key_params, *const agc_kv); 5] = [
            |p, _| p.scope_spec.u.aead.scope = 77,
            |p, _| p.scope_spec.u.aead.nonce_misuse_resistant = 3,
            |p, _| p.scope_spec.u.aead.security.nist_status = 42,
            |p, _| p.scope_spec.u.aead.additional_properties = agc_kv_list { items: std::ptr::null(), count: 1 },
            |p, items| p.scope_spec.u.aead.additional_properties = agc_kv_list { items, count: 2 },
        ];
        for (i, set) in cases.iter().enumerate() {
            let mut p = params();
            set(&mut p, dup.as_ptr());
            assert!(matches!(convert(&p), Err(FfiError::InvalidArgument(_))), "case {i}");
        }
    }

    #[test]
    fn unset_or_unknown_scope_kind_is_rejected() {
        let mut p = params();
        p.scope_spec.kind = agc_scope_kind_AGC_SCOPE_KIND_NONE;
        assert!(matches!(convert(&p), Err(FfiError::InvalidArgument(_))));
        p.scope_spec.kind = 999;
        assert!(matches!(convert(&p), Err(FfiError::InvalidArgument(_))));
    }
}
