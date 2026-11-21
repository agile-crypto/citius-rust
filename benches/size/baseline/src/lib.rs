//! Size baseline: a native RustCrypto client exposed to C, one entry point
//! per algorithm family, so the linker keeps exactly what is used.
use aes_gcm::aead::{Aead, KeyInit, Payload};

fn out(v: Vec<u8>, o: *mut u8, cap: usize) -> isize {
    if v.len() > cap { return -1 }
    // SAFETY: the caller passes a writable region of `cap` bytes.
    unsafe { std::ptr::copy_nonoverlapping(v.as_ptr(), o, v.len()) };
    v.len() as isize
}

/// # Safety
/// Pointers valid for the given lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rc_aes256gcm_seal(k: *const u8, pt: *const u8, n: usize, o: *mut u8, cap: usize) -> isize {
    let (k, pt) = unsafe { (std::slice::from_raw_parts(k, 32), std::slice::from_raw_parts(pt, n)) };
    let c = aes_gcm::Aes256Gcm::new_from_slice(k).unwrap();
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).unwrap();
    out(c.encrypt((&nonce[..]).try_into().unwrap(), Payload { msg: pt, aad: b"" }).unwrap(), o, cap)
}

#[cfg(feature = "all")]
mod all {
    use super::out;
    use std::slice::from_raw_parts as sl;
    macro_rules! ecdsa {
        ($f:ident, $c:ident, $h:ty) => {
            /// # Safety
            /// Pointers valid for the given lengths.
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn $f(der: *const u8, dn: usize, m: *const u8, n: usize, o: *mut u8, cap: usize) -> isize {
                use $c::ecdsa::signature::{SignatureEncoding, hazmat::RandomizedPrehashSigner};
                use sha2::Digest;
                let (der, m) = unsafe { (sl(der, dn), sl(m, n)) };
                let k = $c::ecdsa::SigningKey::from(&$c::SecretKey::from_sec1_der(der).unwrap());
                let s: $c::ecdsa::DerSignature = k.sign_prehash_with_rng(&mut getrandom::SysRng, &<$h>::digest(m)).unwrap();
                out(s.to_vec(), o, cap)
            }
        };
    }
    ecdsa!(rc_p256_sign, p256, sha2::Sha256);
    ecdsa!(rc_p384_sign, p384, sha2::Sha384);
    ecdsa!(rc_p521_sign, p521, sha2::Sha512);
    macro_rules! mldsa {
        ($f:ident, $p:ty) => {
            /// # Safety
            /// Pointers valid for the given lengths.
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn $f(der: *const u8, dn: usize, m: *const u8, n: usize, o: *mut u8, cap: usize) -> isize {
                use ml_dsa::pkcs8::DecodePrivateKey;
                let (der, m) = unsafe { (sl(der, dn), sl(m, n)) };
                let k = ml_dsa::SigningKey::<$p>::from_pkcs8_der(der).unwrap();
                out(k.expanded_key().sign_randomized(m, b"", &mut getrandom::SysRng).unwrap().encode().to_vec(), o, cap)
            }
        };
    }
    mldsa!(rc_mldsa44_sign, ml_dsa::MlDsa44);
    mldsa!(rc_mldsa65_sign, ml_dsa::MlDsa65);
    mldsa!(rc_mldsa87_sign, ml_dsa::MlDsa87);
    /// # Safety
    /// Pointers valid for the given lengths.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rc_ed25519_sign(der: *const u8, dn: usize, m: *const u8, n: usize, o: *mut u8, cap: usize) -> isize {
        use ed25519_dalek::{Signer, pkcs8::DecodePrivateKey};
        let (der, m) = unsafe { (sl(der, dn), sl(m, n)) };
        out(ed25519_dalek::SigningKey::from_pkcs8_der(der).unwrap().sign(m).to_bytes().to_vec(), o, cap)
    }
    /// # Safety
    /// Pointers valid for the given lengths.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rc_chacha_seal(k: *const u8, pt: *const u8, n: usize, o: *mut u8, cap: usize) -> isize {
        use chacha20poly1305::aead::{Aead, KeyInit};
        let (k, pt) = unsafe { (sl(k, 32), sl(pt, n)) };
        let c = chacha20poly1305::ChaCha20Poly1305::new_from_slice(k).unwrap();
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).unwrap();
        out(c.encrypt((&nonce[..]).try_into().unwrap(), pt).unwrap(), o, cap)
    }
}
