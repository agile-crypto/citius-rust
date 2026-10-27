use std::ffi::{CStr, c_char};

use crate::bindings::*;
use crate::domain::core::{KeyCreationSpec, ScopeKind};
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
#[allow(non_upper_case_globals)] // bindgen's constant names
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
        agc_scope_kind_AGC_SCOPE_KIND_ASYMMETRIC_ENCRYPTION => ScopeKind::AsymmetricEncryption,
        agc_scope_kind_AGC_SCOPE_KIND_NONE => return Err(FfiError::invalid("scope_spec.kind must be set")),
        other => return Err(FfiError::invalid(format!("scope_spec.kind {other} is not a known scope kind"))),
    })
}

/// Converts the C request into a `KeyCreationSpec` and validates it.
///
/// # Safety
/// `key_name`, `policy_name` and `template_id` in `p` must each be NULL or a valid
/// NUL-terminated string for the duration of the call.
pub unsafe fn spec_from_params(p: &agc_create_key_params) -> Result<KeyCreationSpec, FfiError> {
    let scope_kind = scope_kind(p.scope_spec.kind)?;
    // SAFETY: key_name is NULL or a valid C string (this function's contract).
    let name = unsafe { required_str(p.key_name, "key_name") }?;
    // SAFETY: policy_name is NULL or a valid C string (this function's contract).
    let policy = unsafe { required_str(p.policy_name, "policy_name") }?;
    // SAFETY: template_id is NULL or a valid C string (this function's contract).
    let template_id = unsafe { optional_str(p.template_id, "template_id") }?;

    Ok(KeyCreationSpec {
        name: name.to_owned(),
        policy: policy.to_owned(),
        template_id: template_id.map(str::to_owned),
        scope_kind,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn convert(p: &agc_create_key_params) -> Result<KeyCreationSpec, FfiError> {
        // SAFETY: test params hold only NULL or 'static C string literals.
        unsafe { spec_from_params(p) }
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
        assert_eq!(spec.scope_kind, ScopeKind::Aead);
    }

    #[test]
    fn empty_template_id_means_none() {
        let mut p = params();
        p.template_id = c"".as_ptr();
        assert_eq!(convert(&p).unwrap().template_id, None);
        p.template_id = c"aes-256-gcm".as_ptr();
        assert_eq!(convert(&p).unwrap().template_id.as_deref(), Some("aes-256-gcm"));
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
    fn non_utf8_name_is_rejected() {
        let mut p = params();
        p.key_name = c"\xff".as_ptr();
        assert!(matches!(convert(&p), Err(FfiError::InvalidArgument(_))));
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
