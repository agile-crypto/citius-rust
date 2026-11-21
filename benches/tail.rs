//! Per-call latency distributions for ML-DSA signing (docs/performance.md
//! F10): is the tail the C harness shows ours, or RustCrypto's?
//!
//! Each call is timed on its own, like benches/c/bench.c. Rows:
//! - L0 hedged: RustCrypto, key parsed once, `sign_randomized` (what our
//!   templates use)
//! - L0 deterministic, fixed message: the rejection loop runs the same number
//!   of times on every call, so the spread is only noise
//! - L0 deterministic, a new message per call: the iteration count varies
//!   with the message, as with hedged signing
//! - L0p: the key parsed per call; L1: our provider; L2ffi: as `agc_sign`
//! - Ed25519 L0: a control with no loop
//!
//! `cargo bench --features bench --bench tail [-- SECONDS]`

use agilecrypto::bench_support::{Encoding, SignBench};
use ml_dsa::pkcs8::DecodePrivateKey;
use std::hint::black_box;
use std::time::{Duration, Instant};

fn report(name: &str, mut v: Vec<u64>) {
    v.sort_unstable();
    let p = |q: f64| v[((q * v.len() as f64) as usize).min(v.len() - 1)] as f64 / 1000.0;
    let mean = v.iter().sum::<u64>() as f64 / v.len() as f64 / 1000.0;
    println!(
        "{name:<44} {:>7} {:>8.1} {:>8.1} {:>8.1} {:>8.1} {:>8.1} {:>8.1} {:>8.1}  {:>5.2}",
        v.len(),
        p(0.0),
        p(0.5),
        p(0.9),
        p(0.99),
        p(0.999),
        p(1.0),
        mean,
        p(0.99) / p(0.5)
    );
}

/// Times `op(i)` per call for `secs` after a short warm-up.
fn sample(secs: f64, mut op: impl FnMut(u64)) -> Vec<u64> {
    let warm = Instant::now();
    let mut i = 0;
    while warm.elapsed() < Duration::from_secs_f64(secs / 10.0) {
        op(i);
        i += 1;
    }
    let mut v = Vec::with_capacity(1 << 16);
    let start = Instant::now();
    while v.len() < 100 || start.elapsed() < Duration::from_secs_f64(secs) {
        let t = Instant::now();
        op(i);
        v.push(t.elapsed().as_nanos() as u64);
        i += 1;
    }
    v
}

macro_rules! level {
    ($secs:expr, $p:ty, $template:expr) => {{
        let f = SignBench::new($template);
        let der = f.private_der().to_vec();
        let sk = ml_dsa::SigningKey::<$p>::from_pkcs8_der(&der).unwrap();
        let fixed = [0x5au8; 1024];
        let mut msg = [0u8; 1024];
        let t = $template;
        report(
            &format!("{t}/L0 hedged"),
            sample($secs, |_| {
                black_box(sk.expanded_key().sign_randomized(&fixed, b"", &mut getrandom::SysRng).unwrap());
            }),
        );
        report(
            &format!("{t}/L0 deterministic, fixed message"),
            sample($secs, |_| {
                black_box(sk.expanded_key().sign_deterministic(&fixed, b"").unwrap());
            }),
        );
        report(
            &format!("{t}/L0 deterministic, new message per call"),
            sample($secs, |i| {
                msg[..8].copy_from_slice(&i.to_le_bytes());
                black_box(sk.expanded_key().sign_deterministic(&msg, b"").unwrap());
            }),
        );
        report(
            &format!("{t}/L0p hedged (parse per call)"),
            sample($secs, |_| {
                let sk = ml_dsa::SigningKey::<$p>::from_pkcs8_der(&der).unwrap();
                black_box(sk.expanded_key().sign_randomized(&fixed, b"", &mut getrandom::SysRng).unwrap());
            }),
        );
        report(&format!("{t}/L1"), sample($secs, |_| drop(black_box(f.provider_sign(&fixed)))));
        report(
            &format!("{t}/L2ffi"),
            sample($secs, |_| drop(black_box(f.orchestrator_sign_as_ffi(&fixed, Encoding::WireV1)))),
        );
    }};
}

fn main() {
    // `cargo bench` passes `--bench`; a number is the seconds per row.
    let secs = std::env::args().skip(1).find_map(|a| a.parse::<f64>().ok()).unwrap_or(2.0);
    println!(
        "{:<44} {:>7} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}  {:>5}",
        "µs per call", "n", "min", "p50", "p90", "p99", "p99.9", "max", "mean", "p99/p50"
    );
    level!(secs, ml_dsa::MlDsa44, "ml-dsa-44");
    level!(secs, ml_dsa::MlDsa65, "ml-dsa-65");
    level!(secs, ml_dsa::MlDsa87, "ml-dsa-87");

    use ed25519_dalek::Signer;
    let f = SignBench::new("ed25519");
    let sk = <ed25519_dalek::SigningKey as DecodePrivateKey>::from_pkcs8_der(f.private_der()).unwrap();
    let m = [0x5au8; 1024];
    report(
        "ed25519/L0 (control: no loop)",
        sample(secs, |_| {
            black_box(sk.sign(&m));
        }),
    );
}
