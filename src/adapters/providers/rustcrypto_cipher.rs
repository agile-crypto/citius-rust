//! The rustcrypto provider's ciphers, with the Go software provider's output
//! conventions so that each can decrypt what the other encrypted:
//! - AES-GCM, (X)ChaCha20-Poly1305: `ciphertext ‖ tag`; AEAD output with the
//!   random nonce and the tag length, encoding "raw".
//! - AES-CBC: PKCS#7-padded ciphertext; block-cipher output with the random
//!   16-byte IV.
//! - AES-CTR: block-cipher output whose IV is the initial counter block,
//!   `random nonce ‖ zero counter`, counting as a 128-bit big-endian integer
//!   (Go's `cipher.NewCTR`).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, StreamCipher};
use zeroize::Zeroizing;

use super::RustCrypto;
use crate::domain::core::{Code, Error};
use crate::domain::provider::{Cipher, EncryptParams, GeneratedKey};
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
fn raw_key(key: &GeneratedKey, len: usize) -> Result<&[u8], Error> {
    key.check_encoding(crate::domain::provider::Encoding::Raw)?;
    if key.private.len() != len {
        return Err(err(Code::InvalidKeyMaterial, format!("key is {} bytes, the template needs {len}", key.private.len())));
    }
    Ok(&key.private)
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

fn aead_seal<C: KeyInit + Aead>(key: &[u8], nonce: &[u8], pt: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let c = C::new_from_slice(key).map_err(|_| err(Code::InvalidKeyMaterial, "wrong key length"))?;
    let nonce = nonce.try_into().map_err(|_| err(Code::InvalidArgument, "wrong nonce length"))?;
    c.encrypt(nonce, Payload { msg: pt, aad }).map_err(|_| err(Code::Internal, "AEAD encryption failed"))
}

fn aead_open<C: KeyInit + Aead>(key: &[u8], nonce: &[u8], ct: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let c = C::new_from_slice(key).map_err(|_| err(Code::InvalidKeyMaterial, "wrong key length"))?;
    let nonce = nonce.try_into().map_err(|_| err(Code::InvalidArgument, "the metadata's nonce has the wrong length"))?;
    // One error for every failure: tampered data, wrong tag, wrong AAD.
    c.decrypt(nonce, Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| err(Code::AuthenticationFailed, "authentication failed"))
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

    fn encrypt(
        &self,
        key: &GeneratedKey,
        algorithm: &api::AlgorithmDetails,
        pt: &[u8],
        params: &EncryptParams,
    ) -> Result<(Vec<u8>, api::ProviderOutput), Error> {
        match mode(algorithm)? {
            Mode::Gcm { key_bytes } => {
                let (k, aad) = (raw_key(key, key_bytes)?, aad(params, true)?);
                let mut nonce = vec![0u8; 12];
                fill_random(&mut nonce)?;
                let ct = match key_bytes {
                    16 => aead_seal::<aes_gcm::Aes128Gcm>(k, &nonce, pt, aad)?,
                    24 => aead_seal::<aes_gcm::AesGcm<aes::Aes192, aes_gcm::aead::consts::U12>>(k, &nonce, pt, aad)?,
                    _ => aead_seal::<aes_gcm::Aes256Gcm>(k, &nonce, pt, aad)?,
                };
                Ok((ct, aead_output(nonce)))
            }
            Mode::ChaCha { extended } => {
                let (k, aad) = (raw_key(key, 32)?, aad(params, true)?);
                let mut nonce = vec![0u8; if extended { 24 } else { 12 }];
                fill_random(&mut nonce)?;
                let ct = if extended {
                    aead_seal::<chacha20poly1305::XChaCha20Poly1305>(k, &nonce, pt, aad)?
                } else {
                    aead_seal::<chacha20poly1305::ChaCha20Poly1305>(k, &nonce, pt, aad)?
                };
                Ok((ct, aead_output(nonce)))
            }
            Mode::Cbc { key_bytes } => {
                let k = raw_key(key, key_bytes)?;
                aad(params, false)?;
                let mut iv = [0u8; BLOCK];
                fill_random(&mut iv)?;
                let ct = match key_bytes {
                    16 => cbc_encrypt::<aes::Aes128>(k, &iv, pt),
                    24 => cbc_encrypt::<aes::Aes192>(k, &iv, pt),
                    _ => cbc_encrypt::<aes::Aes256>(k, &iv, pt),
                }?;
                Ok((ct, block_output(iv.to_vec())))
            }
            Mode::Ctr { key_bytes, nonce_bytes } => {
                let k = raw_key(key, key_bytes)?;
                aad(params, false)?;
                let mut iv = [0u8; BLOCK];
                fill_random(&mut iv[..nonce_bytes])?;
                let mut buf = pt.to_vec();
                ctr_apply(k, &iv, &mut buf)?;
                Ok((buf, block_output(iv.to_vec())))
            }
        }
    }

    fn decrypt(
        &self,
        key: &GeneratedKey,
        algorithm: &api::AlgorithmDetails,
        ct: &[u8],
        output: &api::ProviderOutput,
        params: &EncryptParams,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let arm = output.algorithm_output.as_ref();
        match mode(algorithm)? {
            Mode::Gcm { key_bytes } => {
                let (k, aad) = (raw_key(key, key_bytes)?, aad(params, true)?);
                let nonce = aead_nonce(arm)?;
                match key_bytes {
                    16 => aead_open::<aes_gcm::Aes128Gcm>(k, nonce, ct, aad),
                    24 => aead_open::<aes_gcm::AesGcm<aes::Aes192, aes_gcm::aead::consts::U12>>(k, nonce, ct, aad),
                    _ => aead_open::<aes_gcm::Aes256Gcm>(k, nonce, ct, aad),
                }
            }
            Mode::ChaCha { extended } => {
                let (k, aad) = (raw_key(key, 32)?, aad(params, true)?);
                let nonce = aead_nonce(arm)?;
                if extended {
                    aead_open::<chacha20poly1305::XChaCha20Poly1305>(k, nonce, ct, aad)
                } else {
                    aead_open::<chacha20poly1305::ChaCha20Poly1305>(k, nonce, ct, aad)
                }
            }
            Mode::Cbc { key_bytes } => {
                let k = raw_key(key, key_bytes)?;
                aad(params, false)?;
                let iv = block_iv(arm)?;
                match key_bytes {
                    16 => cbc_decrypt::<aes::Aes128>(k, iv, ct),
                    24 => cbc_decrypt::<aes::Aes192>(k, iv, ct),
                    _ => cbc_decrypt::<aes::Aes256>(k, iv, ct),
                }
            }
            Mode::Ctr { key_bytes, .. } => {
                let k = raw_key(key, key_bytes)?;
                aad(params, false)?;
                let iv: &[u8; BLOCK] = block_iv(arm)?.try_into().expect("checked by block_iv");
                let mut buf = Zeroizing::new(ct.to_vec());
                ctr_apply(k, iv, &mut buf)?;
                Ok(buf)
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

fn cbc_encrypt<C>(key: &[u8], iv: &[u8; BLOCK], pt: &[u8]) -> Result<Vec<u8>, Error>
where
    C: cipher::BlockCipherEncrypt + cipher::KeyInit + cipher::BlockSizeUser<BlockSize = cipher::consts::U16>,
{
    let e = cbc::Encryptor::<C>::new_from_slices(key, iv).map_err(|_| err(Code::InvalidKeyMaterial, "wrong key length"))?;
    let mut buf = vec![0u8; (pt.len() / BLOCK + 1) * BLOCK];
    buf[..pt.len()].copy_from_slice(pt);
    let n = e
        .encrypt_padded::<cipher::block_padding::Pkcs7>(&mut buf, pt.len())
        .map_err(|_| err(Code::Internal, "padding failed"))?
        .len();
    buf.truncate(n);
    Ok(buf)
}

/// CBC is not authenticated: a padding error says nothing reliable about the
/// key or the data, and is reported like any other malformed ciphertext.
fn cbc_decrypt<C>(key: &[u8], iv: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error>
where
    C: cipher::BlockCipherDecrypt + cipher::KeyInit + cipher::BlockSizeUser<BlockSize = cipher::consts::U16>,
{
    let d = cbc::Decryptor::<C>::new_from_slices(key, iv).map_err(|_| err(Code::InvalidKeyMaterial, "wrong key length"))?;
    let mut buf = Zeroizing::new(ct.to_vec());
    let n = d
        .decrypt_padded::<cipher::block_padding::Pkcs7>(&mut buf)
        .map_err(|_| err(Code::InvalidArgument, "the ciphertext does not decrypt"))?
        .len();
    buf.truncate(n);
    Ok(buf)
}

fn ctr_apply(key: &[u8], iv: &[u8; BLOCK], buf: &mut [u8]) -> Result<(), Error> {
    fn run<C>(key: &[u8], iv: &[u8; BLOCK], buf: &mut [u8]) -> Result<(), Error>
    where
        C: cipher::BlockCipherEncrypt + cipher::KeyInit + cipher::BlockSizeUser<BlockSize = cipher::consts::U16>,
    {
        let mut c = ctr::Ctr128BE::<C>::new_from_slices(key, iv).map_err(|_| err(Code::InvalidKeyMaterial, "wrong key length"))?;
        c.apply_keystream(buf);
        Ok(())
    }
    match key.len() {
        16 => run::<aes::Aes128>(key, iv, buf),
        24 => run::<aes::Aes192>(key, iv, buf),
        _ => run::<aes::Aes256>(key, iv, buf),
    }
}

#[cfg(test)]
mod tests {
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
                let (ct, out) = RustCrypto.encrypt(&k, &alg, &pt, &p).unwrap();
                assert_eq!(ct.len(), RustCrypto.ciphertext_len(&alg, n).unwrap(), "{id} {n}");
                assert!(RustCrypto.plaintext_len_bound(&alg, ct.len()).unwrap() >= n, "{id} {n}");
                let shape = RustCrypto.output_shape(&alg).unwrap();
                assert_eq!(
                    std::mem::discriminant(out.algorithm_output.as_ref().unwrap()),
                    std::mem::discriminant(shape.algorithm_output.as_ref().unwrap()),
                    "{id}: the shape has the real output's kind"
                );
                assert_eq!(*RustCrypto.decrypt(&k, &alg, &ct, &out, &p).unwrap(), pt, "{id} {n}");
            }
        }
    }

    #[test]
    fn encryptions_differ_and_carry_their_parameters() {
        for id in AEADS.iter().chain(&PLAIN) {
            let (alg, k, p) = (algorithm(id), key(id), params(id));
            let (a, oa) = RustCrypto.encrypt(&k, &alg, b"same plaintext", &p).unwrap();
            let (b, ob) = RustCrypto.encrypt(&k, &alg, b"same plaintext", &p).unwrap();
            assert_ne!(a, b, "{id}: a fresh nonce or IV each time");
            assert_ne!(oa, ob, "{id}");
            assert_eq!(oa.encoding, "raw");
        }
    }

    #[test]
    fn tampering_is_detected_and_releases_nothing() {
        for id in AEADS {
            let (alg, k, p) = (algorithm(id), key(id), params(id));
            let (ct, out) = RustCrypto.encrypt(&k, &alg, b"secret", &p).unwrap();
            for i in [0, ct.len() - 1] {
                let mut bad = ct.clone();
                bad[i] ^= 1;
                let e = RustCrypto.decrypt(&k, &alg, &bad, &out, &p).unwrap_err();
                assert_eq!(e.code(), Code::AuthenticationFailed, "{id}");
            }
            let other = EncryptParams::Aead { aad: b"other".to_vec() };
            assert_eq!(RustCrypto.decrypt(&k, &alg, &ct, &out, &other).unwrap_err().code(), Code::AuthenticationFailed);
            assert_eq!(RustCrypto.decrypt(&key(id), &alg, &ct, &out, &p).unwrap_err().code(), Code::AuthenticationFailed);
        }
    }

    #[test]
    fn ctr_counts_the_whole_block_like_go() {
        // The IV is nonce ‖ zero counter; the keystream for block i is
        // AES(IV + i) over the full 128 bits.
        let alg = algorithm("aes-128-ctr");
        let k = key("aes-128-ctr");
        let (ct, out) = RustCrypto.encrypt(&k, &alg, &[0u8; 32], &EncryptParams::None).unwrap();
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
        assert_eq!(RustCrypto.encrypt(&k, &alg, b"x", &EncryptParams::None).unwrap_err().code(), Code::InvalidArgument);
        let (ct, _) = RustCrypto.encrypt(&k, &alg, b"x", &params("aes-256-gcm-128-96")).unwrap();
        let cbc_meta = block_output(vec![0; 16]);
        let e = RustCrypto.decrypt(&k, &alg, &ct, &cbc_meta, &params("aes-256-gcm-128-96")).unwrap_err();
        assert_eq!(e.code(), Code::InvalidArgument);
        let short_key = GeneratedKey { private: Zeroizing::new(vec![0; 16]), ..k };
        let e = RustCrypto.encrypt(&short_key, &alg, b"x", &params("aes-256-gcm-128-96")).unwrap_err();
        assert_eq!(e.code(), Code::InvalidKeyMaterial);
    }
}
