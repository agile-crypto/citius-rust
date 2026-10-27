//! The thread-local record behind `agc_last_error` (agc_core.h): the detail of
//! the last failing call on this thread. Its strings stay valid until the next
//! failing call on the same thread, or `agc_clear_error`.

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::ptr;

use crate::bindings::*;
use crate::ffi::error::{is_crypto_rc, rc_name};

const CRYPTO_DOMAIN: &CStr = c"caas.crypto.v1";

struct Record {
    rc: agc_rc,
    message: CString,
    reason: Option<CString>,
}

thread_local! {
    static LAST: RefCell<Option<Record>> = const { RefCell::new(None) };
}

/// Records a failure. Crypto codes also get the wire error's domain and
/// reason ("CRYPTO_ERROR_KEY_NOT_FOUND"), as the proto's ErrorInfo would.
pub fn set(rc: agc_rc, message: &str) {
    // A C string ends at the first NUL; keep the rest of the message readable.
    let message = CString::new(message.replace('\0', "\u{FFFD}")).expect("NULs were replaced");
    let reason = is_crypto_rc(rc)
        .then(|| rc_name(rc))
        .flatten()
        .and_then(|n| n.to_str().ok()?.strip_prefix("AGC_ERR_CRYPTO_").map(|s| format!("CRYPTO_ERROR_{s}")))
        .map(|r| CString::new(r).expect("rc names contain no NUL"));
    LAST.with_borrow_mut(|last| *last = Some(Record { rc, message, reason }));
}

pub fn clear() {
    LAST.with_borrow_mut(|last| *last = None);
}

/// The detail to hand to the caller, pointing into this thread's record.
/// With nothing recorded: `AGC_OK` and every string NULL.
pub fn detail() -> agc_error_detail {
    LAST.with_borrow(|last| {
        let mut d = agc_error_detail {
            struct_size: size_of::<agc_error_detail>(),
            rc: AGC_OK as agc_rc,
            message: ptr::null(),
            domain: ptr::null(),
            reason: ptr::null(),
            provider_id: ptr::null(),
            provider_code: 0,
            failed_check: ptr::null(),
        };
        if let Some(r) = last {
            d.rc = r.rc;
            d.message = r.message.as_ptr();
            if is_crypto_rc(r.rc) {
                d.domain = CRYPTO_DOMAIN.as_ptr();
            }
            d.reason = r.reason.as_ref().map_or(ptr::null(), |s| s.as_ptr());
        }
        d
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(p: *const std::ffi::c_char) -> Option<&'static str> {
        // SAFETY: the pointers come from `detail()` on this thread, and the
        // record is not replaced until the next `set`/`clear`.
        (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_str().unwrap())
    }

    #[test]
    fn empty_record_is_ok_and_null() {
        clear();
        let d = detail();
        assert_eq!(d.rc, AGC_OK as agc_rc);
        assert!(d.message.is_null() && d.domain.is_null() && d.reason.is_null());
    }

    #[test]
    fn local_code_has_message_but_no_domain() {
        set(AGC_ERR_INVALID_ARGUMENT, "key name must not be null");
        let d = detail();
        assert_eq!(d.rc, AGC_ERR_INVALID_ARGUMENT);
        assert_eq!(s(d.message), Some("key name must not be null"));
        assert_eq!(s(d.domain), None);
        assert_eq!(s(d.reason), None);
    }

    #[test]
    fn crypto_code_has_wire_domain_and_reason() {
        set(AGC_ERR_CRYPTO_KEY_NOT_FOUND, "no key named k");
        let d = detail();
        assert_eq!(s(d.domain), Some("caas.crypto.v1"));
        assert_eq!(s(d.reason), Some("CRYPTO_ERROR_KEY_NOT_FOUND"));
    }

    #[test]
    fn interior_nul_does_not_truncate_silently() {
        set(AGC_ERR_INTERNAL, "a\0b");
        assert_eq!(s(detail().message), Some("a\u{FFFD}b"));
    }

    #[test]
    fn records_are_per_thread() {
        set(AGC_ERR_INTERNAL, "main thread");
        std::thread::spawn(|| assert_eq!(detail().rc, AGC_OK as agc_rc)).join().unwrap();
        assert_eq!(detail().rc, AGC_ERR_INTERNAL);
    }
}
