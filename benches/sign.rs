//! Message signing per layer (docs/performance.md):
//! L0 RustCrypto with the key parsed once, L0p parsing it per call,
//! L1 the provider adapter, L2 the orchestrator, L2ffi as `agc_sign` drives it.

use agilecrypto::bench_support::{Encoding, SignBench};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use sha2::Digest;
use std::hint::black_box;

const SIZES: &[usize] = &[32, 1024, 16 * 1024];

/// L0: what a native client does, one closure with a pre-parsed key and one
/// that parses per call.
#[allow(clippy::type_complexity)]
struct Baseline {
    parsed: Box<dyn Fn(&[u8]) -> Vec<u8>>,
    per_call: Box<dyn Fn(&[u8]) -> Vec<u8>>,
}

macro_rules! ecdsa {
    ($curve:ident, $hash:ty, $der:expr) => {{
        use $curve::ecdsa::signature::SignatureEncoding;
        use $curve::ecdsa::signature::hazmat::RandomizedPrehashSigner;
        fn sign(k: &$curve::ecdsa::SigningKey, m: &[u8]) -> Vec<u8> {
            let sig: $curve::ecdsa::DerSignature =
                k.sign_prehash_with_rng(&mut getrandom::SysRng, &<$hash>::digest(m)).unwrap();
            sig.to_vec()
        }
        fn parse(der: &[u8]) -> $curve::ecdsa::SigningKey {
            $curve::ecdsa::SigningKey::from(&$curve::SecretKey::from_sec1_der(der).unwrap())
        }
        let der = $der.to_vec();
        let k = parse(&der);
        Baseline { parsed: Box::new(move |m| sign(&k, m)), per_call: Box::new(move |m| sign(&parse(&der), m)) }
    }};
}

macro_rules! ml_dsa {
    ($p:ty, $der:expr) => {{
        use ml_dsa::pkcs8::DecodePrivateKey;
        fn sign(k: &ml_dsa::SigningKey<$p>, m: &[u8]) -> Vec<u8> {
            k.expanded_key().sign_randomized(m, b"", &mut getrandom::SysRng).unwrap().encode().to_vec()
        }
        let der = $der.to_vec();
        let k = ml_dsa::SigningKey::<$p>::from_pkcs8_der(&der).unwrap();
        Baseline {
            parsed: Box::new(move |m| sign(&k, m)),
            per_call: Box::new(move |m| sign(&ml_dsa::SigningKey::<$p>::from_pkcs8_der(&der).unwrap(), m)),
        }
    }};
}

fn ed25519(der: &[u8]) -> Baseline {
    use ed25519_dalek::Signer;
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    let der = der.to_vec();
    let k = ed25519_dalek::SigningKey::from_pkcs8_der(&der).unwrap();
    Baseline {
        parsed: Box::new(move |m| k.sign(m).to_bytes().to_vec()),
        per_call: Box::new(move |m| {
            ed25519_dalek::SigningKey::from_pkcs8_der(&der).unwrap().sign(m).to_bytes().to_vec()
        }),
    }
}

pub const TEMPLATES: &[&str] = &[
    "ed25519",
    "ecdsa-p256-sha256-der",
    "ecdsa-p384-sha384-der",
    "ecdsa-p521-sha512-der",
    "ml-dsa-44",
    "ml-dsa-65",
    "ml-dsa-87",
];

fn baseline(template: &str, der: &[u8]) -> Baseline {
    match template {
        "ed25519" => ed25519(der),
        "ecdsa-p256-sha256-der" => ecdsa!(p256, sha2::Sha256, der),
        "ecdsa-p384-sha384-der" => ecdsa!(p384, sha2::Sha384, der),
        "ecdsa-p521-sha512-der" => ecdsa!(p521, sha2::Sha512, der),
        "ml-dsa-44" => ml_dsa!(ml_dsa::MlDsa44, der),
        "ml-dsa-65" => ml_dsa!(ml_dsa::MlDsa65, der),
        "ml-dsa-87" => ml_dsa!(ml_dsa::MlDsa87, der),
        t => panic!("no baseline for {t}"),
    }
}

fn bench(c: &mut Criterion) {
    for &template in TEMPLATES {
        let f = SignBench::new(template);
        let l0 = baseline(template, f.private_der());
        let mut g = c.benchmark_group(format!("sign/{template}"));
        for &n in SIZES {
            let msg = vec![0x5a; n];
            g.throughput(Throughput::Bytes(n as u64));
            g.bench_with_input(BenchmarkId::new("L0", n), &msg, |b, m| b.iter(|| (l0.parsed)(black_box(m))));
            g.bench_with_input(BenchmarkId::new("L0p", n), &msg, |b, m| b.iter(|| (l0.per_call)(black_box(m))));
            g.bench_with_input(BenchmarkId::new("L1", n), &msg, |b, m| b.iter(|| f.provider_sign(black_box(m))));
            g.bench_with_input(BenchmarkId::new("L2", n), &msg, |b, m| b.iter(|| f.orchestrator_sign(black_box(m))));
            g.bench_with_input(BenchmarkId::new("L2ffi-wire", n), &msg, |b, m| {
                b.iter(|| f.orchestrator_sign_as_ffi(black_box(m), Encoding::WireV1))
            });
            g.bench_with_input(BenchmarkId::new("L2ffi-proto", n), &msg, |b, m| {
                b.iter(|| f.orchestrator_sign_as_ffi(black_box(m), Encoding::Protobuf))
            });
        }
        g.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
