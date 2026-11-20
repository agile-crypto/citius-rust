//! The rustcrypto provider's ciphers, with the Go software provider's output
//! conventions so that each can decrypt what the other encrypted:
//! - AES-GCM, (X)ChaCha20-Poly1305: `ciphertext ‖ tag`; AEAD output with the
//!   random nonce and the tag length, encoding "raw".
//! - AES-CBC: PKCS#7-padded ciphertext; block-cipher output with the random
//!   16-byte IV.
//! - AES-CTR: block-cipher output whose IV is the initial counter block,
//!   `random nonce ‖ zero counter`, counting as a 128-bit big-endian integer
//!   (Go's `cipher.NewCTR`).

use aes_gcm::aead::{AeadInOut, KeyInit};
use cipher::block_padding::{Padding, Pkcs7};
use cipher::{BlockModeDecrypt, BlockModeEncrypt, InOutBuf, KeyIvInit, StreamCipher};
use zeroize::Zeroizing;

use super::RustCrypto;
use crate::domain::core::{Code, Error};
use crate::domain::provider::{Cipher, EncryptParams, StoredKey};
use crate::proto::api::{self, algorithm_details::Algorithm, provider_output::AlgorithmOutput};

const OP: &str = "rustcrypto cipher";
const TAG_LEN: usize = 16;
const BLOCK: usize = 16;

fn err(code: Code, msg: impl Into<String>) -> Error {
    Error::new(code, OP, msg)
}

fn fill_random(b: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(b).map_err(|e| err(Code::InsufficientEntropy, format!("the OS random generator failed: {e}")))
}

/// The ciphers this provider implements, with the parameters that matter.
enum Mode {
    Gcm { key_bytes: usize },
    ChaCha { extended: bool },
    Cbc { key_bytes: usize },
    Ctr { key_bytes: usize, nonce_bytes: usize },
}

fn mode(algorithm: &api::AlgorithmDetails) -> Result<Mode, Error> {
    let aes = |bits: u32| match bits {
        128 | 192 | 256 => Ok(bits as usize / 8),
        b => Err(err(Code::InvalidArgument, format!("AES key size {b} is not 128, 192 or 256"))),
    };
    match algorithm.algorithm.as_ref() {
        Some(Algorithm::AesGcm(p)) => {
            if p.iv_size_bits != 96 || p.tag_size_bits != 128 {
                return Err(err(Code::NotImplemented, "only AES-GCM with a 96-bit nonce and a 128-bit tag"));
            }
            Ok(Mode::Gcm { key_bytes: aes(p.key_size_bits)? })
        }
        Some(Algorithm::Chacha20Poly1305(p)) => Ok(Mode::ChaCha { extended: p.extended_nonce }),
        Some(Algorithm::AesCbc(p)) => Ok(Mode::Cbc { key_bytes: aes(p.key_size_bits)? }),
        Some(Algorithm::AesCtr(p)) => {
            if p.nonce_size_bits % 8 != 0 || p.nonce_size_bits > 128 {
                return Err(err(Code::NotImplemented, format!("AES-CTR nonce of {} bits", p.nonce_size_bits)));
            }
            Ok(Mode::Ctr { key_bytes: aes(p.key_size_bits)?, nonce_bytes: p.nonce_size_bits as usize / 8 })
        }
        _ => Err(err(Code::NotImplemented, "algorithm not supported for encryption by the rustcrypto provider")),
    }
}

/// The raw symmetric key, checked against the template's size.
fn raw_key<'a>(key: StoredKey<'a>, len: usize) -> Result<&'a [u8], Error> {
    key.check_encoding(crate::domain::provider::Encoding::Raw)?;
    if key.private.len() != len {
        return Err(err(Code::InvalidKeyMaterial, format!("key is {} bytes, the template needs {len}", key.private.len())));
    }
    Ok(key.private)
}

fn aead_output(nonce: Vec<u8>) -> api::ProviderOutput {
    api::ProviderOutput {
        encoding: "raw".into(),
        algorithm_output: Some(AlgorithmOutput::AeadOutput(api::AeadOutput { nonce, tag_length_bytes: TAG_LEN as u32 })),
    }
}

fn block_output(iv: Vec<u8>) -> api::ProviderOutput {
    api::ProviderOutput {
        encoding: "raw".into(),
        algorithm_output: Some(AlgorithmOutput::BlockCipherOutput(api::BlockCipherOutput { iv })),
    }
}

fn aad(params: &EncryptParams, aead: bool) -> Result<&[u8], Error> {
    match (params, aead) {
        (EncryptParams::Aead { aad }, true) => Ok(aad),
        (EncryptParams::None, false) => Ok(&[]),
        (_, true) => Err(err(Code::InvalidArgument, "an AEAD key needs AEAD parameters")),
        (_, false) => Err(err(Code::InvalidArgument, "this cipher takes no AEAD parameters")),
    }
}

/// The caller's buffer is shorter than the sizing promised: a bug in the
/// caller, refused before anything is written.
fn short_output() -> Error {
    err(Code::Internal, "the output buffer is shorter than its size query said")
}

/// Seals `pt` into `out` as `ciphertext ‖ tag`, reading `pt` and writing
/// `out` directly (no copy of the plaintext).
fn aead_seal<C: KeyInit + AeadInOut>(
    key: &[u8],
    nonce: &[u8],
    pt: &[u8],
    aad: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let c = C::new_from_slice(key).map_err(|_| err(Code::InvalidKeyMaterial, "wrong key length"))?;
    let nonce = nonce.try_into().map_err(|_| err(Code::InvalidArgument, "wrong nonce length"))?;
    let (body, rest) = out.split_at_mut_checked(pt.len()).ok_or_else(short_output)?;
    let tag_out = rest.get_mut(..TAG_LEN).ok_or_else(short_output)?;
    let buf = InOutBuf::new(pt, body).expect("equal lengths");
    let tag = c.encrypt_inout_detached(nonce, aad, buf).map_err(|_| err(Code::Internal, "AEAD encryption failed"))?;
    tag_out.copy_from_slice(&tag);
    Ok(pt.len() + TAG_LEN)
}

/// Opens `ciphertext ‖ tag` into `out`. The crates check the tag over the
/// ciphertext before they decrypt (aes-gcm 0.11, chacha20poly1305 0.11:
/// `decrypt_inout_detached`), so a failure leaves `out` untouched.
fn aead_open<C: KeyInit + AeadInOut>(
    key: &[u8],
    nonce: &[u8],
    ct: &[u8],
    aad: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let c = C::new_from_slice(key).map_err(|_| err(Code::InvalidKeyMaterial, "wrong key length"))?;
    let nonce = nonce.try_into().map_err(|_| err(Code::InvalidArgument, "the metadata's nonce has the wrong length"))?;
    // One error for every failure: tampered data, wrong tag, wrong AAD, too short.
    let failed = || err(Code::AuthenticationFailed, "authentication failed");
    let (body, tag) = ct.split_at_checked(ct.len().checked_sub(TAG_LEN).ok_or_else(failed)?).ok_or_else(failed)?;
    let out = out.get_mut(..body.len()).ok_or_else(short_output)?;
    let buf = InOutBuf::new(body, out).expect("equal lengths");
    c.decrypt_inout_detached(nonce, aad, buf, tag.try_into().expect("TAG_LEN bytes")).map_err(|_| failed())?;
    Ok(body.len())
}

impl Cipher for RustCrypto {
    fn ciphertext_len(&self, algorithm: &api::AlgorithmDetails, n: usize) -> Result<usize, Error> {
        Ok(match mode(algorithm)? {
            Mode::Gcm { .. } | Mode::ChaCha { .. } => n + TAG_LEN,
            // PKCS#7 always adds 1..=16 bytes.
            Mode::Cbc { .. } => (n / BLOCK + 1) * BLOCK,
            Mode::Ctr { .. } => n,
        })
    }

    fn plaintext_len_bound(&self, algorithm: &api::AlgorithmDetails, n: usize) -> Result<usize, Error> {
        Ok(match mode(algorithm)? {
            Mode::Gcm { .. } | Mode::ChaCha { .. } => n.saturating_sub(TAG_LEN),
            Mode::Cbc { .. } => n.saturating_sub(1),
            Mode::Ctr { .. } => n,
        })
    }

    fn output_shape(&self, algorithm: &api::AlgorithmDetails) -> Result<api::ProviderOutput, Error> {
        Ok(match mode(algorithm)? {
            Mode::Gcm { .. } | Mode::ChaCha { extended: false } => aead_output(vec![0; 12]),
            Mode::ChaCha { extended: true } => aead_output(vec![0; 24]),
            Mode::Cbc { .. } | Mode::Ctr { .. } => block_output(vec![0; BLOCK]),
        })
    }

    fn encrypt_into(
        &self,
        key: StoredKey<'_>,
        algorithm: &api::AlgorithmDetails,
        pt: &[u8],
        params: &EncryptParams,
        out: &mut [u8],
    ) -> Result<(usize, api::ProviderOutput), Error> {
        match mode(algorithm)? {
            Mode::Gcm { key_bytes } => {
                let (k, aad) = (raw_key(key, key_bytes)?, aad(params, true)?);
                let mut nonce = vec![0u8; 12];
                fill_random(&mut nonce)?;
                let n = match key_bytes {
                    16 => aead_seal::<aes_gcm::Aes128Gcm>(k, &nonce, pt, aad, out)?,
                    24 => {
                        type Aes192Gcm = aes_gcm::AesGcm<aes::Aes192, aes_gcm::aead::consts::U12>;
                        aead_seal::<Aes192Gcm>(k, &nonce, pt, aad, out)?
                    }
                    _ => aead_seal::<aes_gcm::Aes256Gcm>(k, &nonce, pt, aad, out)?,
                };
                Ok((n, aead_output(nonce)))
            }
            Mode::ChaCha { extended } => {
                let (k, aad) = (raw_key(key, 32)?, aad(params, true)?);
                let mut nonce = vec![0u8; if extended { 24 } else { 12 }];
                fill_random(&mut nonce)?;
                let n = if extended {
                    aead_seal::<chacha20poly1305::XChaCha20Poly1305>(k, &nonce, pt, aad, out)?
                } else {
                    aead_seal::<chacha20poly1305::ChaCha20Poly1305>(k, &nonce, pt, aad, out)?
                };
                Ok((n, aead_output(nonce)))
            }
            Mode::Cbc { key_bytes } => {
                let k = raw_key(key, key_bytes)?;
                aad(params, false)?;
                let mut iv = [0u8; BLOCK];
                fill_random(&mut iv)?;
                let n = match key_bytes {
                    16 => cbc_encrypt::<aes::Aes128>(k, &iv, pt, out),
                    24 => cbc_encrypt::<aes::Aes192>(k, &iv, pt, out),
                    _ => cbc_encrypt::<aes::Aes256>(k, &iv, pt, out),
                }?;
                Ok((n, block_output(iv.to_vec())))
            }
            Mode::Ctr { key_bytes, nonce_bytes } => {
                let k = raw_key(key, key_bytes)?;
                aad(params, false)?;
                let mut iv = [0u8; BLOCK];
                fill_random(&mut iv[..nonce_bytes])?;
                ctr_apply(k, &iv, pt, out)?;
                Ok((pt.len(), block_output(iv.to_vec())))
            }
        }
    }

    fn decrypt_into(
        &self,
        key: StoredKey<'_>,
        algorithm: &api::AlgorithmDetails,
        ct: &[u8],
        output: &api::ProviderOutput,
        params: &EncryptParams,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let arm = output.algorithm_output.as_ref();
        match mode(algorithm)? {
            Mode::Gcm { key_bytes } => {
                let (k, aad) = (raw_key(key, key_bytes)?, aad(params, true)?);
                let nonce = aead_nonce(arm)?;
                match key_bytes {
                    16 => aead_open::<aes_gcm::Aes128Gcm>(k, nonce, ct, aad, out),
                    24 => aead_open::<aes_gcm::AesGcm<aes::Aes192, aes_gcm::aead::consts::U12>>(k, nonce, ct, aad, out),
                    _ => aead_open::<aes_gcm::Aes256Gcm>(k, nonce, ct, aad, out),
                }
            }
            Mode::ChaCha { extended } => {
                let (k, aad) = (raw_key(key, 32)?, aad(params, true)?);
                let nonce = aead_nonce(arm)?;
                if extended {
                    aead_open::<chacha20poly1305::XChaCha20Poly1305>(k, nonce, ct, aad, out)
                } else {
                    aead_open::<chacha20poly1305::ChaCha20Poly1305>(k, nonce, ct, aad, out)
                }
            }
            Mode::Cbc { key_bytes } => {
                let k = raw_key(key, key_bytes)?;
                aad(params, false)?;
                let iv = block_iv(arm)?;
                match key_bytes {
                    16 => cbc_decrypt::<aes::Aes128>(k, iv, ct, out),
                    24 => cbc_decrypt::<aes::Aes192>(k, iv, ct, out),
                    _ => cbc_decrypt::<aes::Aes256>(k, iv, ct, out),
                }
            }
            Mode::Ctr { key_bytes, .. } => {
                let k = raw_key(key, key_bytes)?;
                aad(params, false)?;
                let iv: &[u8; BLOCK] = block_iv(arm)?.try_into().expect("checked by block_iv");
                // Unauthenticated: nothing can fail after the parameter checks.
                ctr_apply(k, iv, ct, out)?;
                Ok(ct.len())
            }
        }
    }
}

fn aead_nonce(arm: Option<&AlgorithmOutput>) -> Result<&[u8], Error> {
    match arm {
        Some(AlgorithmOutput::AeadOutput(o)) if o.tag_length_bytes as usize == TAG_LEN => Ok(&o.nonce),
        Some(AlgorithmOutput::AeadOutput(_)) => Err(err(Code::InvalidArgument, "the metadata's tag length does not match")),
        _ => Err(err(Code::InvalidArgument, "the metadata does not carry AEAD output")),
    }
}

fn block_iv(arm: Option<&AlgorithmOutput>) -> Result<&[u8], Error> {
    match arm {
        Some(AlgorithmOutput::BlockCipherOutput(o)) if o.iv.len() == BLOCK => Ok(&o.iv),
        _ => Err(err(Code::InvalidArgument, "the metadata does not carry a 16-byte IV")),
    }
}

fn cbc_encrypt<C>(key: &[u8], iv: &[u8; BLOCK], pt: &[u8], out: &mut [u8]) -> Result<usize, Error>
where
    C: cipher::BlockCipherEncrypt + cipher::KeyInit + cipher::BlockSizeUser<BlockSize = cipher::consts::U16>,
{
    let e = cbc::Encryptor::<C>::new_from_slices(key, iv).map_err(|_| err(Code::InvalidKeyMaterial, "wrong key length"))?;
    let n = e.encrypt_padded_b2b::<Pkcs7>(pt, out).map_err(|_| short_output())?.len();
    Ok(n)
}

/// CBC is not authenticated: a padding error says nothing reliable about the
/// key or the data, and is reported like any other malformed ciphertext.
///
/// The padding is checked first: the last block is decrypted on the stack
/// (its IV is the block before it), and only a valid padding lets anything
/// reach `out`. The timing difference reveals nothing the error does not.
fn cbc_decrypt<C>(key: &[u8], iv: &[u8], ct: &[u8], out: &mut [u8]) -> Result<usize, Error>
where
    C: cipher::BlockCipherDecrypt + cipher::KeyInit + cipher::BlockSizeUser<BlockSize = cipher::consts::U16>,
{
    let malformed = || err(Code::InvalidArgument, "the ciphertext does not decrypt");
    let decryptor = |iv: &[u8]| {
        cbc::Decryptor::<C>::new_from_slices(key, iv).map_err(|_| err(Code::InvalidKeyMaterial, "wrong key length"))
    };
    if ct.is_empty() || !ct.len().is_multiple_of(BLOCK) {
        return Err(malformed());
    }
    let (body, last) = ct.split_at(ct.len() - BLOCK);
    let last_iv = body.last_chunk::<BLOCK>().map_or(iv, |b| b.as_slice());
    let mut block = Zeroizing::new(cipher::Block::<C>::default());
    decryptor(last_iv)?.decrypt_block_b2b(last.try_into().expect("one block"), &mut block);
    let tail = Pkcs7::unpad(&block).map_err(|_| malformed())?;

    let out = out.get_mut(..body.len() + tail.len()).ok_or_else(short_output)?;
    let (out_body, out_tail) = out.split_at_mut(body.len());
    let (blocks, rest) = InOutBuf::new(body, out_body).expect("equal lengths").into_chunks();
    debug_assert!(rest.is_empty(), "whole blocks");
    decryptor(iv)?.decrypt_blocks_inout(blocks);
    out_tail.copy_from_slice(tail);
    Ok(out.len())
}

/// AES-CTR from `input` into `output`, which holds at least as many bytes.
fn ctr_apply(key: &[u8], iv: &[u8; BLOCK], input: &[u8], output: &mut [u8]) -> Result<(), Error> {
    fn run<C>(key: &[u8], iv: &[u8; BLOCK], input: &[u8], output: &mut [u8]) -> Result<(), Error>
    where
        C: cipher::BlockCipherEncrypt + cipher::KeyInit + cipher::BlockSizeUser<BlockSize = cipher::consts::U16>,
    {
        let mut c = ctr::Ctr128BE::<C>::new_from_slices(key, iv).map_err(|_| err(Code::InvalidKeyMaterial, "wrong key length"))?;
        c.apply_keystream_b2b(input, output);
        Ok(())
    }
    let output = output.get_mut(..input.len()).ok_or_else(short_output)?;
    match key.len() {
        16 => run::<aes::Aes128>(key, iv, input, output),
        24 => run::<aes::Aes192>(key, iv, input, output),
        _ => run::<aes::Aes256>(key, iv, input, output),
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::provider::GeneratedKey;
    /// D2: every cipher state this provider builds from a key wipes itself
    /// when dropped. Compiles only while the crates' "zeroize" features are
    /// on (Cargo.toml); without them, round keys and GHASH/Poly1305 keys
    /// outlive each operation in freed stack and heap memory.
    #[test]
    fn every_keyed_cipher_state_is_wiped_on_drop() {
        fn wiped<T: zeroize::ZeroizeOnDrop>() {}
        wiped::<aes::Aes128>();
        wiped::<aes::Aes192>();
        wiped::<aes::Aes256>();
        wiped::<aes_gcm::Aes128Gcm>();
        wiped::<aes_gcm::Aes256Gcm>();
        wiped::<aes_gcm::AesGcm<aes::Aes192, aes_gcm::aead::consts::U12>>();
        wiped::<chacha20poly1305::ChaCha20Poly1305>();
        wiped::<chacha20poly1305::XChaCha20Poly1305>();
        wiped::<cbc::Encryptor<aes::Aes256>>();
        wiped::<cbc::Decryptor<aes::Aes256>>();
        wiped::<ctr::Ctr128BE<aes::Aes256>>();
        // Ed25519's SHA-512 over the secret, and RFC 6979's HMAC: Hmac has no
        // marker of its own but is made of these cores and a block buffer,
        // which wipe themselves with the features on.
        wiped::<sha2::Sha512>();
        wiped::<<sha2::Sha256 as hmac::digest::block_api::EagerHash>::Core>();
        wiped::<<sha2::Sha512 as hmac::digest::block_api::EagerHash>::Core>();
        // poly1305::Poly1305 wipes itself in Drop when its "zeroize" feature
        // is on, without the marker trait, so it cannot be checked here.
    }

    use super::*;
    use crate::domain::provider::Backend;
    use crate::domain::template::parse_catalog;

    fn algorithm(id: &str) -> api::AlgorithmDetails {
        let catalog = parse_catalog(include_str!("../../../catalog/standard_algorithms.json")).unwrap();
        catalog.into_iter().find(|t| t.id() == id).unwrap().info().algorithm.clone().unwrap()
    }

    fn key(id: &str) -> GeneratedKey {
        RustCrypto.generate_key(&algorithm(id)).unwrap()
    }

    const AEADS: [&str; 5] =
        ["aes-128-gcm-128-96", "aes-192-gcm-128-96", "aes-256-gcm-128-96", "chacha20-poly1305", "xchacha20-poly1305"];
    const PLAIN: [&str; 6] =
        ["aes-128-cbc-pkcs7-128", "aes-192-cbc-pkcs7-128", "aes-256-cbc-pkcs7-128", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr"];

    fn params(id: &str) -> EncryptParams {
        if AEADS.contains(&id) { EncryptParams::Aead { aad: b"context".to_vec() } } else { EncryptParams::None }
    }

    #[test]
    fn every_cipher_round_trips_with_the_sizes_it_predicts() {
        for id in AEADS.iter().chain(&PLAIN) {
            let (alg, k, p) = (algorithm(id), key(id), params(id));
            for n in [0usize, 1, 15, 16, 17, 1000] {
                let pt: Vec<u8> = (0..n).map(|i| i as u8).collect();
                let (ct, out) = RustCrypto.encrypt(k.as_stored(), &alg, &pt, &p).unwrap();
                assert_eq!(ct.len(), RustCrypto.ciphertext_len(&alg, n).unwrap(), "{id} {n}");
                assert!(RustCrypto.plaintext_len_bound(&alg, ct.len()).unwrap() >= n, "{id} {n}");
                let shape = RustCrypto.output_shape(&alg).unwrap();
                assert_eq!(
                    std::mem::discriminant(out.algorithm_output.as_ref().unwrap()),
                    std::mem::discriminant(shape.algorithm_output.as_ref().unwrap()),
                    "{id}: the shape has the real output's kind"
                );
                assert_eq!(*RustCrypto.decrypt(k.as_stored(), &alg, &ct, &out, &p).unwrap(), pt, "{id} {n}");
            }
        }
    }

    #[test]
    fn encryptions_differ_and_carry_their_parameters() {
        for id in AEADS.iter().chain(&PLAIN) {
            let (alg, k, p) = (algorithm(id), key(id), params(id));
            let (a, oa) = RustCrypto.encrypt(k.as_stored(), &alg, b"same plaintext", &p).unwrap();
            let (b, ob) = RustCrypto.encrypt(k.as_stored(), &alg, b"same plaintext", &p).unwrap();
            assert_ne!(a, b, "{id}: a fresh nonce or IV each time");
            assert_ne!(oa, ob, "{id}");
            assert_eq!(oa.encoding, "raw");
        }
    }

    #[test]
    fn tampering_is_detected_and_releases_nothing() {
        for id in AEADS {
            let (alg, k, p) = (algorithm(id), key(id), params(id));
            let (ct, out) = RustCrypto.encrypt(k.as_stored(), &alg, b"secret", &p).unwrap();
            for i in [0, ct.len() - 1] {
                let mut bad = ct.clone();
                bad[i] ^= 1;
                let e = RustCrypto.decrypt(k.as_stored(), &alg, &bad, &out, &p).unwrap_err();
                assert_eq!(e.code(), Code::AuthenticationFailed, "{id}");
            }
            let other = EncryptParams::Aead { aad: b"other".to_vec() };
            let e = RustCrypto.decrypt(k.as_stored(), &alg, &ct, &out, &other).unwrap_err();
            assert_eq!(e.code(), Code::AuthenticationFailed);
            let e = RustCrypto.decrypt(key(id).as_stored(), &alg, &ct, &out, &p).unwrap_err();
            assert_eq!(e.code(), Code::AuthenticationFailed);
        }
    }

    const UNTOUCHED: u8 = 0xA5;

    /// Decrypts into a sentinel-filled buffer one byte longer than the bound.
    fn decrypt_into(
        id: &str,
        k: &GeneratedKey,
        ct: &[u8],
        out: &api::ProviderOutput,
        p: &EncryptParams,
    ) -> (Result<usize, Error>, Vec<u8>) {
        let alg = algorithm(id);
        let mut buf = vec![UNTOUCHED; RustCrypto.plaintext_len_bound(&alg, ct.len()).unwrap() + 1];
        (RustCrypto.decrypt_into(k.as_stored(), &alg, ct, out, p, &mut buf), buf)
    }

    /// A failed decryption writes nothing; a successful one writes exactly
    /// the plaintext.
    #[test]
    fn decrypt_into_writes_the_plaintext_or_nothing() {
        for id in AEADS.iter().chain(&PLAIN) {
            let (alg, k, p) = (algorithm(id), key(id), params(id));
            for n in [1usize, 16, 33] {
                let pt = vec![7u8; n];
                let (ct, out) = RustCrypto.encrypt(k.as_stored(), &alg, &pt, &p).unwrap();
                let (r, buf) = decrypt_into(id, &k, &ct, &out, &p);
                assert_eq!(r.unwrap(), n, "{id} {n}");
                assert_eq!(&buf[..n], &pt[..], "{id} {n}");
                assert!(buf[n..].iter().all(|&b| b == UNTOUCHED), "{id} {n}: nothing past the plaintext");
                if AEADS.contains(id) {
                    let mut bad = ct.clone();
                    bad[0] ^= 1;
                    let (r, buf) = decrypt_into(id, &k, &bad, &out, &p);
                    assert_eq!(r.unwrap_err().code(), Code::AuthenticationFailed, "{id}");
                    assert!(buf.iter().all(|&b| b == UNTOUCHED), "{id}: a forgery writes nothing");
                }
            }
        }
    }

    /// CBC checks the padding before the first byte is written; every
    /// malformed padding and length is refused alike.
    #[test]
    fn cbc_refuses_bad_padding_before_writing() {
        use aes::cipher::{BlockModeEncrypt as _, block_padding::NoPadding};
        let id = "aes-128-cbc-pkcs7-128";
        let k = key(id);
        let iv = [3u8; BLOCK];
        // Raw CBC of chosen last blocks: the padding is whatever we put there.
        let raw = |blocks: &[[u8; BLOCK]]| {
            let e = cbc::Encryptor::<aes::Aes128>::new_from_slices(&k.private, &iv).unwrap();
            let mut buf = blocks.as_flattened().to_vec();
            let n = buf.len();
            e.encrypt_padded::<NoPadding>(&mut buf, n).unwrap();
            buf
        };
        let out = block_output(iv.to_vec());
        let mut last = [9u8; BLOCK];
        for pad in [0u8, 17, 255] {
            last[15] = pad;
            let (r, buf) = decrypt_into(id, &k, &raw(&[[1; BLOCK], last]), &out, &EncryptParams::None);
            assert_eq!(r.unwrap_err().code(), Code::InvalidArgument, "pad {pad}");
            assert!(buf.iter().all(|&b| b == UNTOUCHED), "pad {pad}: nothing written");
        }
        // Inconsistent padding bytes: 3 3 2.
        last[13..].copy_from_slice(&[3, 2, 3]);
        let (r, buf) = decrypt_into(id, &k, &raw(&[last]), &out, &EncryptParams::None);
        assert!(r.is_err() && buf.iter().all(|&b| b == UNTOUCHED));
        // A full block of padding decrypts to the blocks before it.
        let (r, buf) = decrypt_into(id, &k, &raw(&[[1; BLOCK], [16; BLOCK]]), &out, &EncryptParams::None);
        assert_eq!((r.unwrap(), &buf[..BLOCK]), (BLOCK, &[1; BLOCK][..]));
        for len in [0, 15, 17] {
            let (r, buf) = decrypt_into(id, &k, &vec![0; len], &out, &EncryptParams::None);
            assert_eq!(r.unwrap_err().code(), Code::InvalidArgument, "{len} bytes");
            assert!(buf.iter().all(|&b| b == UNTOUCHED));
        }
    }

    /// A buffer shorter than the sizing promised is refused, not overrun.
    #[test]
    fn a_short_output_buffer_is_refused() {
        for id in AEADS.iter().chain(&PLAIN) {
            let (alg, k, p) = (algorithm(id), key(id), params(id));
            let mut small = [UNTOUCHED; 8];
            let e = RustCrypto.encrypt_into(k.as_stored(), &alg, &[1; 20], &p, &mut small).unwrap_err();
            assert_eq!(e.code(), Code::Internal, "{id}");
            let (ct, out) = RustCrypto.encrypt(k.as_stored(), &alg, &[1; 20], &p).unwrap();
            let e = RustCrypto.decrypt_into(k.as_stored(), &alg, &ct, &out, &p, &mut small).unwrap_err();
            assert_eq!(e.code(), Code::Internal, "{id}");
            assert_eq!(small, [UNTOUCHED; 8], "{id}");
        }
    }

    #[test]
    fn ctr_counts_the_whole_block_like_go() {
        // The IV is nonce ‖ zero counter; the keystream for block i is
        // AES(IV + i) over the full 128 bits.
        let alg = algorithm("aes-128-ctr");
        let k = key("aes-128-ctr");
        let (ct, out) = RustCrypto.encrypt(k.as_stored(), &alg, &[0u8; 32], &EncryptParams::None).unwrap();
        let Some(AlgorithmOutput::BlockCipherOutput(o)) = out.algorithm_output else { panic!() };
        assert_eq!(&o.iv[12..], &[0, 0, 0, 0], "a 96-bit nonce and a zero counter");
        use aes::cipher::{BlockCipherEncrypt, KeyInit as _};
        let aes = aes::Aes128::new_from_slice(&k.private).unwrap();
        for (i, chunk) in ct.chunks(16).enumerate() {
            let mut block = aes::Block::try_from(&o.iv[..]).unwrap();
            block[15] += i as u8;
            aes.encrypt_block(&mut block);
            assert_eq!(chunk, &block[..], "block {i}");
        }
    }

    #[test]
    fn wrong_parameters_and_metadata_are_refused() {
        let alg = algorithm("aes-256-gcm-128-96");
        let k = key("aes-256-gcm-128-96");
        let e = RustCrypto.encrypt(k.as_stored(), &alg, b"x", &EncryptParams::None).unwrap_err();
        assert_eq!(e.code(), Code::InvalidArgument);
        let (ct, _) = RustCrypto.encrypt(k.as_stored(), &alg, b"x", &params("aes-256-gcm-128-96")).unwrap();
        let cbc_meta = block_output(vec![0; 16]);
        let e = RustCrypto.decrypt(k.as_stored(), &alg, &ct, &cbc_meta, &params("aes-256-gcm-128-96")).unwrap_err();
        assert_eq!(e.code(), Code::InvalidArgument);
        let short_key = GeneratedKey { private: zeroize::Zeroizing::new(vec![0; 16]), ..k };
        let e = RustCrypto.encrypt(short_key.as_stored(), &alg, b"x", &params("aes-256-gcm-128-96")).unwrap_err();
        assert_eq!(e.code(), Code::InvalidKeyMaterial);
    }
}
