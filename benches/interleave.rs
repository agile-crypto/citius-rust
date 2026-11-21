//! Re-measures docs/performance.md F4 (P-256 L1 → L2 gap) without order
//! effects: the variants run interleaved in short rounds (A B C D, A B C D,
//! …), so CPU frequency, thermal state and core migration hit every variant
//! alike. Prints per variant the median over all calls, and the spread of
//! the per-round medians, which shows how stable a block measurement is.
//!
//! `cargo bench --features bench --bench interleave [-- ROUNDS [MS_PER_SLICE]]`

mod common;

use agilecrypto::bench_support::{Encoding, SignBench};
use common::{Variant, interleave, keep};
use std::hint::black_box;
use std::time::Duration;

macro_rules! ecdsa {
    ($curve:ident, $hash:ty, $t:expr, $rounds:expr, $slice:expr) => {{
        use sha2::Digest;
        use $curve::ecdsa::signature::hazmat::RandomizedPrehashSigner;
        fn parse(der: &[u8]) -> $curve::ecdsa::SigningKey {
            $curve::ecdsa::SigningKey::from(&$curve::SecretKey::from_sec1_der(der).unwrap())
        }
        fn sign(k: &$curve::ecdsa::SigningKey, m: &[u8]) -> $curve::ecdsa::DerSignature {
            k.sign_prehash_with_rng(&mut getrandom::SysRng, &<$hash>::digest(m)).unwrap()
        }
        let f = SignBench::new($t);
        let der = f.private_der().to_vec();
        let k = parse(&der);
        let m = [0x5au8; 1024];
        interleave(
            $t,
            $rounds,
            $slice,
            vec![
                ("L0 (key parsed once)", Box::new(|| keep(sign(&k, &m)))),
                ("L0p (parse per call)", Box::new(|| keep(sign(&parse(&der), &m)))),
                ("L1 provider", Box::new(|| keep(f.provider_sign(&m)))),
                ("L2 orchestrator", Box::new(|| keep(f.orchestrator_sign(&m)))),
                ("L2ffi (as agc_sign)", Box::new(|| keep(f.orchestrator_sign_as_ffi(&m, Encoding::WireV1)))),
            ],
        );
    }};
}

/// Is a stable per-variant difference due to the key, or to where its bytes
/// sit in memory? L0p (parse per call + sign) for several fresh keys, and for
/// one key copied to different offsets.
macro_rules! key_or_placement {
    ($curve:ident, $hash:ty, $t:expr, $rounds:expr, $slice:expr) => {{
        use sha2::Digest;
        use $curve::ecdsa::signature::hazmat::RandomizedPrehashSigner;
        fn l0p(der: &[u8], m: &[u8]) -> $curve::ecdsa::DerSignature {
            let k = $curve::ecdsa::SigningKey::from(&$curve::SecretKey::from_sec1_der(der).unwrap());
            k.sign_prehash_with_rng(&mut getrandom::SysRng, &<$hash>::digest(m)).unwrap()
        }
        let keys: Vec<Vec<u8>> = (0..4).map(|_| SignBench::new($t).private_der().to_vec()).collect();
        // Key 0 again, at offsets 1, 8 and 64 inside fresh buffers.
        let placed: Vec<(usize, Vec<u8>)> = [1usize, 8, 64]
            .iter()
            .map(|&o| {
                let mut b = vec![0u8; o + keys[0].len()];
                b[o..].copy_from_slice(&keys[0]);
                (o, b)
            })
            .collect();
        let m = [0x5au8; 1024];
        let names: Vec<String> = (0..4)
            .map(|i| format!("key {i}"))
            .chain(placed.iter().map(|(o, _)| format!("key 0 at offset {o}")))
            .collect();
        let mut vs: Vec<Variant> = Vec::new();
        for (i, k) in keys.iter().enumerate() {
            vs.push((names[i].as_str(), Box::new(move || keep(l0p(k, &m)))));
        }
        // A pure integer loop (~100 µs): if it jumps with the rounds too, the
        // CPU's clock changed, not our code.
        vs.push((
            "calibration (integer loop)",
            Box::new(|| {
                let mut x = black_box(1u64);
                for i in 0..300_000u64 {
                    x = x.wrapping_mul(6364136223846793005).wrapping_add(i);
                }
                black_box(x);
            }),
        ));
        for (j, (o, b)) in placed.iter().enumerate() {
            vs.push((names[4 + j].as_str(), Box::new(move || keep(l0p(&b[*o..], &m)))));
        }
        interleave(&format!("{} L0p: key or placement?", $t), $rounds, $slice, vs);
    }};
}

fn main() {
    let nums: Vec<f64> = std::env::args().skip(1).filter_map(|a| a.parse().ok()).collect();
    let rounds = nums.first().map(|&r| r as usize).unwrap_or(20);
    let slice = Duration::from_millis(nums.get(1).map(|&s| s as u64).unwrap_or(100));
    ecdsa!(p256, sha2::Sha256, "ecdsa-p256-sha256-der", rounds, slice);
    ecdsa!(p384, sha2::Sha384, "ecdsa-p384-sha384-der", rounds, slice);
    ecdsa!(p521, sha2::Sha512, "ecdsa-p521-sha512-der", rounds, slice);
    key_or_placement!(p256, sha2::Sha256, "ecdsa-p256-sha256-der", rounds, slice);
    key_or_placement!(p521, sha2::Sha512, "ecdsa-p521-sha512-der", rounds, slice);
}
