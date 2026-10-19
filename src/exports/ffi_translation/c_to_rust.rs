use std::ffi::{CStr, c_char};

use crate::{bindings::*, exports::{error::Error::{self, AbiMismatch, InvalidArgument}, service::KeyCreationSpec}};

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

/// Converts the C request into a `KeyCreationSpec` and validates it.
///
/// # Safety
/// `key_name`, `policy_name` and `template_id` in `p` must each be NULL or a valid
/// NUL-terminated string for the duration of the call.
pub unsafe fn spec_from_params(p: &agc_create_key_params) -> Result<KeyCreationSpec, Error> {
    if p.struct_size < size_of::<agc_create_key_params>() {
        return Err(AbiMismatch);
    }

    if p.scope_spec.kind == agc_scope_kind_AGC_SCOPE_KIND_NONE {
        return Err(InvalidArgument("Scope kind must be specified."));
    }
    
    // SAFETY: key_name is NULL or a valid C string (this function's contract).
    let Some(key_name) = (unsafe { null_check_c_string(p.key_name) }) else {
        return Err(InvalidArgument("key name must not be null"));
    };
    let Ok(name) = CStr::to_str(key_name) else {
        return Err(InvalidArgument("key name must be a utf-8 string."));
    };
    if name.is_empty() {
        return Err(InvalidArgument("key name must not be empty"));
    }


    // SAFETY: policy_name is NULL or a valid C string (this function's contract).
    let Some(policy_name) = (unsafe { null_check_c_string(p.policy_name) }) else {
        return Err(InvalidArgument("Policy name must not be null"));
    };
    let Ok(policy) = CStr::to_str(policy_name) else {
        return Err(InvalidArgument("Policy name must be utf-8 string."));
    };
    if policy.is_empty() {
        return Err(InvalidArgument("Policy name must not be empty"));
    }

    // SAFETY: template_id is NULL or a valid C string (this function's contract).
    let template_id = match unsafe { null_check_c_string(p.template_id) } {
        None => None,
        Some(cstr) => {
            let st = cstr
                .to_str()
                .map_err(|_| InvalidArgument("template id must be valid utf-8 string."))?;
            if st.is_empty() {
                None
            } else {
                Some(st.to_owned())
            }
        }
    };

    Ok(KeyCreationSpec {
        name: String::from(name),
        policy: String::from(policy),
        template_id,
        scope_kind: p.scope_spec.kind,
    })
}
