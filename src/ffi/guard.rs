use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::bindings::*;
use crate::ffi::error::FfiError;
use crate::ffi::last_error;

/// Runs the body of an export: turns its result into an `agc_rc`, records
/// failures for `agc_last_error`, and stops a panic at the C boundary.
///
/// A panic is a bug in this library. It becomes `AGC_ERR_INTERNAL` instead of
/// unwinding into C (undefined behaviour) or aborting the host process. State
/// a panic may have left half updated sits behind locks that are now
/// poisoned, and every later use of them fails closed (`domain::core::poisoned`),
/// which is why `AssertUnwindSafe` is sound here.
pub fn guard(body: impl FnOnce() -> Result<(), FfiError>) -> agc_rc {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(())) => AGC_OK as agc_rc,
        Ok(Err(e)) => {
            let rc = e.rc();
            last_error::set(rc, &e.message());
            rc
        }
        Err(payload) => {
            record_panic(payload.as_ref());
            AGC_ERR_INTERNAL
        }
    }
}

/// `guard` for exports that return a value instead of an `agc_rc` (or
/// nothing): on a panic they return `on_panic`, with the panic recorded for
/// `agc_last_error`.
pub fn guard_value<T>(on_panic: T, body: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or_else(|payload| {
        record_panic(payload.as_ref());
        on_panic
    })
}

fn record_panic(payload: &(dyn std::any::Any + Send)) {
    let what = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("unknown cause");
    last_error::set(AGC_ERR_INTERNAL, &format!("internal error (panic: {what})"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_is_agc_ok() {
        assert_eq!(guard(|| Ok(())), AGC_OK as agc_rc);
    }

    #[test]
    fn error_is_recorded() {
        let rc = guard(|| Err(FfiError::invalid("bad")));
        assert_eq!(rc, AGC_ERR_INVALID_ARGUMENT);
        assert_eq!(last_error::detail().rc, AGC_ERR_INVALID_ARGUMENT);
    }

    #[test]
    fn guard_value_returns_the_fallback_on_panic() {
        assert_eq!(guard_value(0, || 7), 7);
        assert_eq!(guard_value(0, || -> i32 { panic!("boom") }), 0);
        assert_eq!(last_error::detail().rc, AGC_ERR_INTERNAL);
    }

    #[test]
    fn panic_becomes_internal_error() {
        let rc = guard(|| panic!("boom"));
        assert_eq!(rc, AGC_ERR_INTERNAL);
        let d = last_error::detail();
        assert_eq!(d.rc, AGC_ERR_INTERNAL);
        // SAFETY: points into this thread's record, which was just set.
        let msg = unsafe { std::ffi::CStr::from_ptr(d.message) }.to_str().unwrap();
        assert!(msg.contains("boom"), "{msg}");
    }
}
