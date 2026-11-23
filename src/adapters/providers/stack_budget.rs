//! How much stack the RustCrypto operations need, and running them where
//! they get it (`crate::stack`, docs/performance.md F12).
//!
//! Measured on a pattern-filled thread stack (`cargo xtask bench --only
//! stack`), release build, KiB, the larger of macOS arm64 and Linux arm64
//! (glibc) where they differ (docs/performance.md F12 and §7):
//!
//! | ML-DSA   | keygen | sign | sign, sealed key | verify |
//! |----------|--------|------|------------------|--------|
//! | 44       | 277    | 227  | 73               | 86     |
//! | 65       | 356    | 311  | 99               | 131    |
//! | 87       | 650    | 520  | 130              | 204    |
//!
//! Expanding the key from its seed is the deepest part of a signature. A
//! version whose expanded key is sealed (`derived::secret_sealed`) signs
//! without it, so it fits a 512 KiB thread (the macOS default) inline even
//! for ML-DSA-87; the version's first signature, and every signature of a
//! version that could not be sealed, still expand.
//!
//! A debug build needs up to 2× that, and the first use of an ECDSA curve
//! up to 4× (35 / 68 / 128 KiB release for P-256 / P-384 / P-521, when
//! RustCrypto lazily builds the curve's basepoint table on the stack). Later
//! ECDSA operations need ≤ 25 KiB, Ed25519 and the ciphers ≤ 12 KiB; they run
//! inline without a check.
//!
//! The budgets below are those numbers ×1.5 (release) or ×4 (debug). They are
//! compared with what is left on the caller's stack; only an operation that
//! would not fit moves to a helper thread.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::domain::core::{Code, Error};

/// An ML-DSA operation, for its budget.
#[derive(Clone, Copy)]
pub(super) enum MlDsaOp {
    Keygen,
    /// A signature that expands the key from its seed first: the version's
    /// first, or every one where the expanded key could not be sealed.
    Sign,
    /// A signature with the version's sealed expanded key.
    SignSealed,
    Verify,
}

/// The release-build stack in KiB an ML-DSA operation was measured to need.
pub(super) const fn ml_dsa_kib(level: u16, op: MlDsaOp) -> usize {
    match (level, op) {
        (44, MlDsaOp::Keygen) => 277,
        (44, MlDsaOp::Sign) => 227,
        (44, MlDsaOp::SignSealed) => 73,
        (44, MlDsaOp::Verify) => 86,
        (65, MlDsaOp::Keygen) => 356,
        (65, MlDsaOp::Sign) => 311,
        (65, MlDsaOp::SignSealed) => 99,
        (65, MlDsaOp::Verify) => 131,
        (87, MlDsaOp::Sign) => 520,
        (87, MlDsaOp::SignSealed) => 130,
        (87, MlDsaOp::Verify) => 204,
        _ => 650, // ML-DSA-87 key generation, the largest
    }
}

/// The bytes of stack to ask for, for an operation measured at `release_kib`.
const fn need(release_kib: usize, debug: bool) -> usize {
    if debug { release_kib * 1024 * 4 } else { release_kib * 1024 * 3 / 2 }
}

/// Runs `f` with the stack an operation measured at `release_kib` needs.
pub(super) fn run<T: Send>(release_kib: usize, f: impl FnOnce() -> Result<T, Error> + Send) -> Result<T, Error> {
    let need = need(release_kib, cfg!(debug_assertions));
    // Starting a thread fails for want of resources (EAGAIN: thread limit,
    // ENOMEM), not because of a library bug.
    crate::stack::with_stack(need, f).map_err(|e| {
        Error::new(
            Code::ResourceExhausted,
            "rustcrypto",
            format!("cannot start a thread with enough stack for this operation: {}", e.0),
        )
    })?
}

/// An ECDSA curve, for its first-use budget.
#[derive(Clone, Copy)]
pub(super) enum EcCurve {
    P256 = 0,
    P384 = 1,
    P521 = 2,
}

/// Whether a curve's basepoint table has been built in this process.
static WARM: [AtomicBool; 3] = [AtomicBool::new(false), AtomicBool::new(false), AtomicBool::new(false)];

const FIRST_USE_KIB: [usize; 3] = [35, 68, 128];

/// Runs an ECDSA operation. The first one on a curve builds the curve's
/// basepoint table on a big enough stack first; later ones run inline.
pub(super) fn ecdsa<T: Send>(curve: EcCurve, f: impl FnOnce() -> Result<T, Error> + Send) -> Result<T, Error> {
    let i = curve as usize;
    if WARM[i].load(Ordering::Acquire) {
        return f();
    }
    run(FIRST_USE_KIB[i], || {
        build_table(curve);
        // The table exists now, whatever f returns.
        WARM[i].store(true, Ordering::Release);
        f()
    })
}

/// Forces the curve's lazily built basepoint table into existence: any
/// multiplication by the generator does.
fn build_table(curve: EcCurve) {
    use elliptic_curve::Group;
    match curve {
        EcCurve::P256 => drop(std::hint::black_box(p256::ProjectivePoint::mul_by_generator(&p256::Scalar::ONE))),
        EcCurve::P384 => drop(std::hint::black_box(p384::ProjectivePoint::mul_by_generator(&p384::Scalar::ONE))),
        EcCurve::P521 => drop(std::hint::black_box(p521::ProjectivePoint::mul_by_generator(&p521::Scalar::ONE))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stack::MARGIN;

    /// The point of the sealed budget: a version's later ML-DSA signatures
    /// run inline on a 512 KiB thread (the macOS default), where expanding
    /// the key each time would not fit for ML-DSA-87.
    #[test]
    fn a_sealed_ml_dsa_signature_fits_a_512_kib_thread() {
        let thread = 512 * 1024;
        for level in [44, 65, 87] {
            assert!(need(ml_dsa_kib(level, MlDsaOp::SignSealed), false) + MARGIN <= thread, "ML-DSA-{level}");
        }
        assert!(need(ml_dsa_kib(87, MlDsaOp::Sign), false) + MARGIN > thread);
    }
}
