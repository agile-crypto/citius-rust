//! How much stack the RustCrypto operations need, and running them where
//! they get it (`crate::stack`, docs/performance.md F12).
//!
//! Measured on a pattern-filled thread stack (benches/stack.rs and
//! `cargo xtask bench --only stack` on the perf-study branch), release
//! build, KiB:
//!
//! | ML-DSA   | keygen | sign | verify |
//! |----------|--------|------|--------|
//! | 44       | 268    | 221  | 86     |
//! | 65       | 328    | 287  | 128    |
//! | 87       | 631    | 507  | 200    |
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
    Sign,
    Verify,
}

/// The release-build stack in KiB an ML-DSA operation was measured to need.
pub(super) const fn ml_dsa_kib(level: u16, op: MlDsaOp) -> usize {
    match (level, op) {
        (44, MlDsaOp::Keygen) => 268,
        (44, MlDsaOp::Sign) => 221,
        (44, MlDsaOp::Verify) => 86,
        (65, MlDsaOp::Keygen) => 328,
        (65, MlDsaOp::Sign) => 287,
        (65, MlDsaOp::Verify) => 128,
        (87, MlDsaOp::Sign) => 507,
        (87, MlDsaOp::Verify) => 200,
        _ => 631, // ML-DSA-87 key generation, the largest
    }
}

/// Runs `f` with the stack an operation measured at `release_kib` needs.
pub(super) fn run<T: Send>(release_kib: usize, f: impl FnOnce() -> Result<T, Error> + Send) -> Result<T, Error> {
    let need = if cfg!(debug_assertions) { release_kib * 1024 * 4 } else { release_kib * 1024 * 3 / 2 };
    crate::stack::with_stack(need, f).map_err(|e| {
        Error::new(
            Code::Internal,
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
