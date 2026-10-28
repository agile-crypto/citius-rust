use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use elliptic_curve::Generate;
use ml_dsa::signature::Keypair;
use zeroize::Zeroizing;

use crate::domain::core::{Code, Error};
use crate::domain::provider::{Backend, Capability, Channels, Cipher, Encoding, GeneratedKey, Transfer};
use crate::proto::api::{self, algorithm_details::Algorithm};

/// The software provider, built on the RustCrypto crates. Stateless: the
/// key material it generates is returned to the core, which stores it
/// (Go: the `software` provider).
///
/// It serves Go's software provider's templates except RSA: the RustCrypto
/// `rsa` crate has an open timing side channel (RUSTSEC-2023-0071).
pub struct RustCrypto;

pub const RUSTCRYPTO_NAME: &str = "rustcrypto";

const TEMPLATES: &[&str] = &[
    "ecdsa-p256-sha256-der",
    "ecdsa-p384-sha384-der",
    "ecdsa-p521-sha512-der",
    "ecdsa-p256-prehashed-der",
    "ecdsa-p384-prehashed-der",
    "ecdsa-p521-prehashed-der",
    "ed25519",
    "ed25519ph",
    "ml-dsa-44",
    "ml-dsa-65",
    "ml-dsa-87",
    "aes-128-gcm-128-96",
    "aes-192-gcm-128-96",
    "aes-256-gcm-128-96",
    "aes-128-cbc-pkcs7-128",
    "aes-192-cbc-pkcs7-128",
    "aes-256-cbc-pkcs7-128",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "chacha20-poly1305",
    "xchacha20-poly1305",
];

impl Backend for RustCrypto {
    fn name(&self) -> &str {
        RUSTCRYPTO_NAME
    }

    fn kind(&self) -> &str {
        "software"
    }

    fn supported_templates(&self) -> &[&'static str] {
        TEMPLATES
    }

    fn capabilities(&self) -> &[Capability] {
        &[Capability::Sign, Capability::Cipher]
    }

    /// Only what can be substantiated: Rust is memory safe. No FIPS
    /// validation, no audit, and no constant-time or side-channel claims:
    /// the crates aim for constant time but make no audited guarantee, and
    /// the post-quantum ones are new.
    fn implementation(&self) -> api::ImplementationProperties {
        api::ImplementationProperties {
            implementation_language: "rust".into(),
            memory_safe_language: Some(true),
            ..Default::default()
        }
    }

    /// Stateless: every key it generates is the payload the core stores, and
    /// it takes such payloads back, in the encoding it generates them in.
    /// No plaintext export or import, no key wrapping (yet).
    fn transfer(&self, algorithm: &api::AlgorithmDetails) -> Transfer {
        let encoding = match algorithm.algorithm.as_ref() {
            Some(Algorithm::Ecdsa(_)) => Encoding::Sec1Der,
            Some(Algorithm::Ed25519(_) | Algorithm::MlDsa(_)) => Encoding::Pkcs8Der,
            Some(Algorithm::AesGcm(_) | Algorithm::AesCbc(_) | Algorithm::AesCtr(_) | Algorithm::Chacha20Poly1305(_)) => {
                Encoding::Raw
            }
            _ => return Transfer::default(),
        };
        let stored = Channels { stored_payload: vec![encoding], ..Default::default() };
        Transfer { emit: stored.clone(), accept: stored }
    }

    fn as_cipher(&self) -> Option<&dyn Cipher> {
        Some(self)
    }

    fn generate_key(&self, algorithm: &api::AlgorithmDetails) -> Result<GeneratedKey, Error> {
        const OP: &str = "RustCrypto::generate_key";
        match algorithm.algorithm.as_ref() {
            Some(Algorithm::AesGcm(p)) => symmetric(aes_key_bytes(p.key_size_bits)?),
            Some(Algorithm::AesCbc(p)) => symmetric(aes_key_bytes(p.key_size_bits)?),
            Some(Algorithm::AesCtr(p)) => symmetric(aes_key_bytes(p.key_size_bits)?),
            Some(Algorithm::Chacha20Poly1305(_)) => symmetric(32),
            Some(Algorithm::Ed25519(_)) => ed25519(),
            Some(Algorithm::Ecdsa(p)) => match api::EllipticCurve::try_from(p.curve) {
                Ok(api::EllipticCurve::P256) => ecdsa::<p256::NistP256>(),
                Ok(api::EllipticCurve::P384) => ecdsa::<p384::NistP384>(),
                Ok(api::EllipticCurve::P521) => ecdsa::<p521::NistP521>(),
                _ => Err(Error::new(Code::NotImplemented, OP, format!("ECDSA curve {} is not supported", p.curve))),
            },
            Some(Algorithm::MlDsa(p)) => match api::MlDsaParameterSet::try_from(p.parameter_set) {
                Ok(api::MlDsaParameterSet::MlDsa44) => ml_dsa::<ml_dsa::MlDsa44>(),
                Ok(api::MlDsaParameterSet::MlDsa65) => ml_dsa::<ml_dsa::MlDsa65>(),
                Ok(api::MlDsaParameterSet::MlDsa87) => ml_dsa::<ml_dsa::MlDsa87>(),
                _ => Err(Error::new(
                    Code::NotImplemented,
                    OP,
                    format!("ML-DSA parameter set {} is not supported", p.parameter_set),
                )),
            },
            _ => Err(Error::new(Code::NotImplemented, OP, "algorithm not supported by the rustcrypto provider")),
        }
    }
}

/// `n` bytes from the operating system's CSPRNG.
fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>, Error> {
    let mut b = Zeroizing::new([0u8; N]);
    getrandom::fill(b.as_mut_slice()).map_err(|e| entropy_error(&e))?;
    Ok(b)
}

fn entropy_error(e: &getrandom::Error) -> Error {
    Error::new(Code::InsufficientEntropy, "rustcrypto", format!("the OS random generator failed: {e}"))
}

fn aes_key_bytes(bits: u32) -> Result<usize, Error> {
    match bits {
        128 | 192 | 256 => Ok(bits as usize / 8),
        other => Err(Error::new(Code::InvalidArgument, "rustcrypto", format!("AES key size {other} is not 128, 192 or 256"))),
    }
}

fn symmetric(len: usize) -> Result<GeneratedKey, Error> {
    let mut key = Zeroizing::new(vec![0u8; len]);
    getrandom::fill(&mut key).map_err(|e| entropy_error(&e))?;
    Ok(GeneratedKey { private: key, private_encoding: Encoding::Raw, public: None })
}

fn encoding_failed(what: &str) -> Error {
    Error::new(Code::Internal, "rustcrypto", format!("encoding the {what} failed"))
}

/// Private: PKCS#8; public: SPKI (as Go's software provider).
fn ed25519() -> Result<GeneratedKey, Error> {
    let seed = random::<32>()?;
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let private = key.to_pkcs8_der().map_err(|_| encoding_failed("Ed25519 private key"))?;
    let public = key.verifying_key().to_public_key_der().map_err(|_| encoding_failed("Ed25519 public key"))?;
    Ok(GeneratedKey {
        private: Zeroizing::new(private.as_bytes().to_vec()),
        private_encoding: Encoding::Pkcs8Der,
        public: Some((public.as_bytes().to_vec(), Encoding::SpkiDer)),
    })
}

/// Private: SEC1 DER; public: SPKI (as Go's software provider).
fn ecdsa<C>() -> Result<GeneratedKey, Error>
where
    C: elliptic_curve::CurveArithmetic + elliptic_curve::point::PointCompression + pkcs8::AssociatedOid,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
    elliptic_curve::AffinePoint<C>: elliptic_curve::sec1::FromSec1Point<C> + elliptic_curve::sec1::ToSec1Point<C>,
{
    // The scalar must be sampled in range, so this takes the RNG itself
    // rather than a fixed-size seed.
    let key = elliptic_curve::SecretKey::<C>::try_generate_from_rng(&mut getrandom::SysRng)
        .map_err(|e| entropy_error(&e))?;
    let private = key.to_sec1_der().map_err(|_| encoding_failed("ECDSA private key"))?;
    let public = key.public_key().to_public_key_der().map_err(|_| encoding_failed("ECDSA public key"))?;
    Ok(GeneratedKey {
        private,
        private_encoding: Encoding::Sec1Der,
        public: Some((public.as_bytes().to_vec(), Encoding::SpkiDer)),
    })
}

/// Private: PKCS#8 holding the 32-byte seed; public: the raw encoded key (as
/// Go's software provider).
fn ml_dsa<P>() -> Result<GeneratedKey, Error>
where
    P: ml_dsa::MlDsaParams + pkcs8::spki::AssociatedAlgorithmIdentifier<Params = der::AnyRef<'static>>,
{
    let seed = random::<32>()?;
    let key = ml_dsa::SigningKey::<P>::from_seed(&(*seed).into());
    let private = key.to_pkcs8_der().map_err(|_| encoding_failed("ML-DSA private key"))?;
    Ok(GeneratedKey {
        private: Zeroizing::new(private.as_bytes().to_vec()),
        private_encoding: Encoding::Pkcs8Der,
        public: Some((key.verifying_key().encode().to_vec(), Encoding::Raw)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::storage::InMemoryTemplateRegistry;
    use crate::domain::template::TemplateRegistry;
    use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey};

    /// The algorithm details the catalog gives a template.
    fn algorithm(id: &str) -> api::AlgorithmDetails {
        let catalog = InMemoryTemplateRegistry::standard();
        catalog.get(id).unwrap_or_else(|| panic!("{id} is not in the catalog")).info().algorithm.clone().unwrap()
    }

    fn generate(id: &str) -> GeneratedKey {
        RustCrypto.generate_key(&algorithm(id)).unwrap_or_else(|e| panic!("{id}: {e}"))
    }

    #[test]
    #[cfg_attr(miri, ignore = "third-party asymmetric key generation: far too slow under Miri; covered natively")]
    fn every_advertised_template_generates_a_key() {
        for id in TEMPLATES {
            let a = generate(id);
            let b = generate(id);
            assert_ne!(a.private, b.private, "{id}: two keys must differ");
        }
    }

    #[test]
    fn symmetric_keys_have_the_template_size() {
        for (id, len) in [("aes-128-gcm-128-96", 16), ("aes-192-ctr", 24), ("aes-256-cbc-pkcs7-128", 32), ("xchacha20-poly1305", 32)] {
            let k = generate(id);
            assert_eq!((k.private.len(), k.private_encoding, k.public.is_none()), (len, Encoding::Raw, true), "{id}");
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "third-party asymmetric key generation: far too slow under Miri; covered natively")]
    fn ed25519_is_pkcs8_and_spki() {
        let k = generate("ed25519");
        assert_eq!(k.private_encoding, Encoding::Pkcs8Der);
        let sk = ed25519_dalek::SigningKey::from_pkcs8_der(&k.private).unwrap();
        let (public, enc) = k.public.unwrap();
        assert_eq!(enc, Encoding::SpkiDer);
        assert_eq!(ed25519_dalek::VerifyingKey::from_public_key_der(&public).unwrap(), sk.verifying_key());
    }

    #[test]
    #[cfg_attr(miri, ignore = "third-party asymmetric key generation: far too slow under Miri; covered natively")]
    fn ecdsa_is_sec1_and_spki_on_the_right_curve() {
        fn check<C>(id: &str)
        where
            C: elliptic_curve::CurveArithmetic + elliptic_curve::point::PointCompression + pkcs8::AssociatedOid,
            elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
            elliptic_curve::AffinePoint<C>:
                elliptic_curve::sec1::FromSec1Point<C> + elliptic_curve::sec1::ToSec1Point<C>,
        {
            let k = generate(id);
            assert_eq!(k.private_encoding, Encoding::Sec1Der, "{id}");
            let sk = elliptic_curve::SecretKey::<C>::from_sec1_der(&k.private).unwrap();
            let (public, enc) = k.public.unwrap();
            assert_eq!(enc, Encoding::SpkiDer);
            assert_eq!(elliptic_curve::PublicKey::<C>::from_public_key_der(&public).unwrap(), sk.public_key(), "{id}");
        }
        check::<p256::NistP256>("ecdsa-p256-sha256-der");
        check::<p384::NistP384>("ecdsa-p384-prehashed-der");
        check::<p521::NistP521>("ecdsa-p521-sha512-der");
    }

    #[test]
    #[cfg_attr(miri, ignore = "third-party asymmetric key generation: far too slow under Miri; covered natively")]
    fn ml_dsa_is_a_pkcs8_seed_and_a_raw_public_key() {
        fn check<P>(id: &str)
        where
            P: ml_dsa::MlDsaParams + pkcs8::spki::AssociatedAlgorithmIdentifier<Params = der::AnyRef<'static>>,
        {
            let k = generate(id);
            assert_eq!(k.private_encoding, Encoding::Pkcs8Der);
            let sk = ml_dsa::SigningKey::<P>::from_pkcs8_der(&k.private).unwrap();
            let (public, enc) = k.public.unwrap();
            assert_eq!((public, enc), (sk.verifying_key().encode().to_vec(), Encoding::Raw), "{id}");
        }
        check::<ml_dsa::MlDsa44>("ml-dsa-44");
        check::<ml_dsa::MlDsa65>("ml-dsa-65");
        check::<ml_dsa::MlDsa87>("ml-dsa-87");
    }

    #[test]
    fn unsupported_algorithms_are_not_implemented() {
        for id in ["ml-kem-768", "hmac-sha256-256", "rsa-pss-sha256-mgf1-32-2048"] {
            let e = RustCrypto.generate_key(&algorithm(id)).unwrap_err();
            assert_eq!(e.code(), Code::NotImplemented, "{id}");
        }
    }

    #[test]
    fn claims_nothing_it_cannot_substantiate() {
        let i = RustCrypto.implementation();
        assert_eq!(i.memory_safe_language, Some(true));
        assert!(i.fips_140.is_none() && i.constant_time.is_none() && i.no_known_cve.is_none());
        assert!(i.side_channel_hardened.is_none() && i.formally_verified.is_none() && i.audits.is_empty());
    }
}
