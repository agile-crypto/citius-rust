//! The baselines missing from the first rounds (docs/performance.md §2.5),
//! all measured interleaved (F4):
//! - CBC and CTR: RustCrypto (L0) against our provider (L1) and orchestrator
//!   (L2 / L2ffi), encrypt and decrypt; L0z decrypts into a `Zeroizing`
//!   buffer like the adapter does (F2), to separate wiping from overhead
//! - digest signing (ECDSA prehashed, Ed25519ph): L0 / L0p / L1 / L2ffi
//! - verification of message signatures, every algorithm: L0 (public key
//!   parsed once) / L0p (parsed per call, as the adapter does) / L1 / L2ffi
//!
//! `cargo bench --features bench --bench baselines [-- ROUNDS [MS_PER_SLICE]]`

mod common;

use agilecrypto::bench_support::{CipherBench, DigestHash, Encoding, SignBench};
use cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, StreamCipher};
use common::{interleave, keep};
use std::time::Duration;
use zeroize::Zeroizing;

fn iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    getrandom::fill(&mut iv).unwrap();
    iv
}

fn cbc_enc(key: &[u8], pt: &[u8]) -> (Vec<u8>, [u8; 16]) {
    let iv = iv();
    let e = cbc::Encryptor::<aes::Aes256>::new_from_slices(key, &iv).unwrap();
    let mut buf = vec![0u8; (pt.len() / 16 + 1) * 16];
    buf[..pt.len()].copy_from_slice(pt);
    let n = e.encrypt_padded::<cipher::block_padding::Pkcs7>(&mut buf, pt.len()).unwrap().len();
    buf.truncate(n);
    (buf, iv)
}

fn cbc_dec(key: &[u8], iv: &[u8; 16], ct: &[u8]) -> Vec<u8> {
    let d = cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv).unwrap();
    let mut buf = ct.to_vec();
    let n = d.decrypt_padded::<cipher::block_padding::Pkcs7>(&mut buf).unwrap().len();
    buf.truncate(n);
    buf
}

fn ctr(key: &[u8], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut c = ctr::Ctr128BE::<aes::Aes256>::new_from_slices(key, iv).unwrap();
    let mut buf = data.to_vec();
    c.apply_keystream(&mut buf);
    buf
}

fn ciphers(rounds: usize, slice: Duration) {
    for n in [32usize, 16 * 1024, 1024 * 1024] {
        let pt = vec![0x5au8; n];
        // CBC
        let f = CipherBench::new("aes-256-cbc-pkcs7-128", false);
        let key = f.raw_key().to_vec();
        let (ct, civ) = cbc_enc(&key, &pt);
        let sealed = f.sealed(&pt);
        interleave(
            &format!("aes-256-cbc-pkcs7 {n} B"),
            rounds,
            slice,
            vec![
                ("enc L0", Box::new(|| keep(cbc_enc(&key, &pt)))),
                ("enc L1", Box::new(|| keep(f.provider_encrypt(&pt)))),
                ("enc L2ffi", Box::new(|| keep(f.orchestrator_encrypt_as_ffi(&pt, Encoding::WireV1)))),
                ("dec L0", Box::new(|| keep(cbc_dec(&key, &civ, &ct)))),
                ("dec L0z (zeroized buffer)", Box::new(|| keep(Zeroizing::new(cbc_dec(&key, &civ, &ct))))),
                ("dec L1", Box::new(|| keep(f.provider_decrypt(&sealed)))),
                ("dec L2", Box::new(|| keep(f.orchestrator_decrypt(&sealed)))),
            ],
        );
        // CTR
        let f = CipherBench::new("aes-256-ctr", false);
        let key = f.raw_key().to_vec();
        let tiv = iv();
        let ct = ctr(&key, &tiv, &pt);
        let sealed = f.sealed(&pt);
        interleave(
            &format!("aes-256-ctr {n} B"),
            rounds,
            slice,
            vec![
                ("enc L0 (incl. fresh IV)", Box::new(|| keep(ctr(&key, &iv(), &pt)))),
                ("enc L1", Box::new(|| keep(f.provider_encrypt(&pt)))),
                ("enc L2ffi", Box::new(|| keep(f.orchestrator_encrypt_as_ffi(&pt, Encoding::WireV1)))),
                ("dec L0", Box::new(|| keep(ctr(&key, &tiv, &ct)))),
                ("dec L0z (zeroized buffer)", Box::new(|| keep(Zeroizing::new(ctr(&key, &tiv, &ct))))),
                ("dec L1", Box::new(|| keep(f.provider_decrypt(&sealed)))),
                ("dec L2", Box::new(|| keep(f.orchestrator_decrypt(&sealed)))),
            ],
        );
    }
}

macro_rules! ecdsa_digest {
    ($curve:ident, $t:expr, $len:expr, $hash:expr, $rounds:expr, $slice:expr) => {{
        use $curve::ecdsa::signature::hazmat::RandomizedPrehashSigner;
        fn parse(der: &[u8]) -> $curve::ecdsa::SigningKey {
            $curve::ecdsa::SigningKey::from(&$curve::SecretKey::from_sec1_der(der).unwrap())
        }
        fn sign(k: &$curve::ecdsa::SigningKey, d: &[u8]) -> $curve::ecdsa::DerSignature {
            k.sign_prehash_with_rng(&mut getrandom::SysRng, d).unwrap()
        }
        let f = SignBench::new_prehashed($t);
        let der = f.private_der().to_vec();
        let k = parse(&der);
        let d = [0x5au8; $len];
        interleave(
            &format!("{} digest sign", $t),
            $rounds,
            $slice,
            vec![
                ("L0 (key parsed once)", Box::new(|| keep(sign(&k, &d)))),
                ("L0p (parse per call)", Box::new(|| keep(sign(&parse(&der), &d)))),
                ("L1 provider", Box::new(|| keep(f.provider_sign_digest(&d, $hash)))),
                ("L2ffi (as agc_digest_sign)", Box::new(|| keep(f.orchestrator_sign_digest_as_ffi(&d, $hash)))),
            ],
        );
    }};
}

fn digest_signing(rounds: usize, slice: Duration) {
    ecdsa_digest!(p256, "ecdsa-p256-prehashed-der", 32, DigestHash::Sha256, rounds, slice);
    ecdsa_digest!(p384, "ecdsa-p384-prehashed-der", 48, DigestHash::Sha384, rounds, slice);
    ecdsa_digest!(p521, "ecdsa-p521-prehashed-der", 64, DigestHash::Sha512, rounds, slice);
    // Ed25519ph: no L0 here; ed25519-dalek wants a hasher state, not digest bytes.
    let f = SignBench::new_prehashed("ed25519ph");
    let d = [0x5au8; 64];
    interleave(
        "ed25519ph digest sign",
        rounds,
        slice,
        vec![
            ("L1 provider", Box::new(|| keep(f.provider_sign_digest(&d, DigestHash::Sha512)))),
            (
                "L2ffi (as agc_digest_sign)",
                Box::new(|| keep(f.orchestrator_sign_digest_as_ffi(&d, DigestHash::Sha512))),
            ),
        ],
    );
}

macro_rules! ecdsa_verify {
    ($curve:ident, $hash:ty, $t:expr, $rounds:expr, $slice:expr) => {{
        use sha2::Digest;
        use $curve::ecdsa::signature::hazmat::PrehashVerifier;
        use $curve::pkcs8::DecodePublicKey;
        fn parse(spki: &[u8]) -> $curve::ecdsa::VerifyingKey {
            $curve::ecdsa::VerifyingKey::from_public_key_der(spki).unwrap()
        }
        fn verify(vk: &$curve::ecdsa::VerifyingKey, m: &[u8], sig: &[u8]) -> bool {
            let sig = $curve::ecdsa::DerSignature::from_bytes(sig).unwrap();
            vk.verify_prehash(&<$hash>::digest(m), &sig).is_ok()
        }
        verify_rows!($t, $rounds, $slice, parse, verify);
    }};
}

macro_rules! ml_dsa_verify {
    ($p:ty, $t:expr, $rounds:expr, $slice:expr) => {{
        fn parse(raw: &[u8]) -> ml_dsa::VerifyingKey<$p> {
            ml_dsa::VerifyingKey::<$p>::decode(&ml_dsa::EncodedVerifyingKey::<$p>::try_from(raw).unwrap())
        }
        fn verify(vk: &ml_dsa::VerifyingKey<$p>, m: &[u8], sig: &[u8]) -> bool {
            let sig = ml_dsa::Signature::<$p>::decode(&ml_dsa::EncodedSignature::<$p>::try_from(sig).unwrap()).unwrap();
            vk.verify_with_context(m, b"", &sig)
        }
        verify_rows!($t, $rounds, $slice, parse, verify);
    }};
}

/// L0 / L0p / L1 / L2ffi verification rows for one template; `parse` and
/// `verify` are the L0 functions for its public key and signatures.
macro_rules! verify_rows {
    ($t:expr, $rounds:expr, $slice:expr, $parse:ident, $verify:ident) => {{
        let f = SignBench::new($t);
        let m = [0x5au8; 1024];
        let sig1 = f.provider_sign(&m);
        let (sig2, md2) = f.orchestrator_signed(&m);
        let public = f.public_key().to_vec();
        let vk = $parse(&public);
        assert!(
            $verify(&vk, &m, &sig1) && f.provider_verify(&m, &sig1) && f.orchestrator_verify_as_ffi(&m, &sig2, &md2)
        );
        interleave(
            &format!("{} verify 1 KiB", $t),
            $rounds,
            $slice,
            vec![
                ("L0 (public key parsed once)", Box::new(|| keep($verify(&vk, &m, &sig1)))),
                ("L0p (parse per call)", Box::new(|| keep($verify(&$parse(&public), &m, &sig1)))),
                ("L1 provider", Box::new(|| keep(f.provider_verify(&m, &sig1)))),
                ("L2ffi (as agc_verify)", Box::new(|| keep(f.orchestrator_verify_as_ffi(&m, &sig2, &md2)))),
            ],
        );
    }};
}

fn verification(rounds: usize, slice: Duration) {
    {
        use ed25519_dalek::pkcs8::DecodePublicKey;
        fn parse(spki: &[u8]) -> ed25519_dalek::VerifyingKey {
            ed25519_dalek::VerifyingKey::from_public_key_der(spki).unwrap()
        }
        fn verify(vk: &ed25519_dalek::VerifyingKey, m: &[u8], sig: &[u8]) -> bool {
            vk.verify_strict(m, &ed25519_dalek::Signature::from_slice(sig).unwrap()).is_ok()
        }
        verify_rows!("ed25519", rounds, slice, parse, verify);
    }
    ecdsa_verify!(p256, sha2::Sha256, "ecdsa-p256-sha256-der", rounds, slice);
    ecdsa_verify!(p384, sha2::Sha384, "ecdsa-p384-sha384-der", rounds, slice);
    ecdsa_verify!(p521, sha2::Sha512, "ecdsa-p521-sha512-der", rounds, slice);
    ml_dsa_verify!(ml_dsa::MlDsa44, "ml-dsa-44", rounds, slice);
    ml_dsa_verify!(ml_dsa::MlDsa65, "ml-dsa-65", rounds, slice);
    ml_dsa_verify!(ml_dsa::MlDsa87, "ml-dsa-87", rounds, slice);
}

fn main() {
    let nums: Vec<f64> = std::env::args().skip(1).filter_map(|a| a.parse().ok()).collect();
    let rounds = nums.first().map(|&r| r as usize).unwrap_or(10);
    let slice = Duration::from_millis(nums.get(1).map(|&s| s as u64).unwrap_or(100));
    ciphers(rounds, slice);
    digest_signing(rounds, slice);
    verification(rounds, slice);
}
