//! Encryption and decryption per layer (docs/performance.md). L0 exists for
//! the AEADs (key schedule done once, a fresh random nonce per call, as the
//! adapter does); CBC and CTR are measured at L1 and L2 only so far.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use agilecrypto::bench_support::{CipherBench, Encoding};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

const SIZES: &[usize] = &[32, 1024, 16 * 1024, 1024 * 1024];

/// (template, aead, nonce length)
const TEMPLATES: &[(&str, bool, usize)] = &[
    ("aes-128-gcm-128-96", true, 12),
    ("aes-256-gcm-128-96", true, 12),
    ("chacha20-poly1305", true, 12),
    ("aes-256-cbc-pkcs7-128", false, 0),
    ("aes-256-ctr", false, 0),
];

/// L0 seal and open for one AEAD: a fresh nonce per seal, the key schedule
/// done once. `parsed: false` redoes the key schedule per call (L0p).
#[allow(clippy::type_complexity)]
fn l0<C: KeyInit + Aead + 'static>(
    key: &[u8],
) -> (impl Fn(&[u8]) -> (Vec<u8>, [u8; 12]), impl Fn(&[u8], &[u8; 12]) -> usize, impl Fn(&[u8]) -> Vec<u8>) {
    let c = C::new_from_slice(key).unwrap();
    let c2 = C::new_from_slice(key).unwrap();
    let key = key.to_vec();
    let seal = move |pt: &[u8]| {
        let mut n = [0u8; 12];
        getrandom::fill(&mut n).unwrap();
        (c.encrypt((&n[..]).try_into().unwrap(), Payload { msg: pt, aad: b"ad" }).unwrap(), n)
    };
    let open = move |ct: &[u8], n: &[u8; 12]| {
        c2.decrypt((&n[..]).try_into().unwrap(), Payload { msg: ct, aad: b"ad" }).unwrap().len()
    };
    let seal_per_call = move |pt: &[u8]| {
        let c = C::new_from_slice(&key).unwrap();
        let mut n = [0u8; 12];
        getrandom::fill(&mut n).unwrap();
        c.encrypt((&n[..]).try_into().unwrap(), Payload { msg: pt, aad: b"ad" }).unwrap()
    };
    (seal, open, seal_per_call)
}

macro_rules! l0_group {
    ($c:ty, $f:expr, $g:expr, $n:expr, $pt:expr) => {{
        let (seal, open, seal_per_call) = l0::<$c>($f.raw_key());
        $g.bench_with_input(BenchmarkId::new("enc/L0", $n), $pt, |b, m| b.iter(|| seal(black_box(m))));
        $g.bench_with_input(BenchmarkId::new("enc/L0p", $n), $pt, |b, m| b.iter(|| seal_per_call(black_box(m))));
        let (ct, nonce) = seal($pt);
        $g.bench_with_input(BenchmarkId::new("dec/L0", $n), &ct, |b, ct| b.iter(|| open(black_box(ct), &nonce)));
    }};
}

fn bench(c: &mut Criterion) {
    for &(template, aead, _) in TEMPLATES {
        let f = CipherBench::new(template, aead);
        let mut g = c.benchmark_group(format!("cipher/{template}"));
        for &n in SIZES {
            let pt = vec![0x5a; n];
            g.throughput(Throughput::Bytes(n as u64));
            match template {
                "aes-128-gcm-128-96" => l0_group!(aes_gcm::Aes128Gcm, f, g, n, &pt),
                "aes-256-gcm-128-96" => l0_group!(aes_gcm::Aes256Gcm, f, g, n, &pt),
                "chacha20-poly1305" => l0_group!(chacha20poly1305::ChaCha20Poly1305, f, g, n, &pt),
                _ => {}
            }
            g.bench_with_input(BenchmarkId::new("enc/L1", n), &pt, |b, m| b.iter(|| f.provider_encrypt(black_box(m))));
            g.bench_with_input(BenchmarkId::new("enc/L2", n), &pt, |b, m| {
                b.iter(|| f.orchestrator_encrypt(black_box(m)))
            });
            g.bench_with_input(BenchmarkId::new("enc/L2ffi-wire", n), &pt, |b, m| {
                b.iter(|| f.orchestrator_encrypt_as_ffi(black_box(m), Encoding::WireV1))
            });
            let sealed = f.sealed(&pt);
            g.bench_function(BenchmarkId::new("dec/L1", n), |b| b.iter(|| f.provider_decrypt(black_box(&sealed))));
            g.bench_function(BenchmarkId::new("dec/L2", n), |b| b.iter(|| f.orchestrator_decrypt(black_box(&sealed))));
        }
        g.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
