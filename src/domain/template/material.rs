use crate::domain::core::{Code, Error};
use crate::proto::api::{self, algorithm_details::Algorithm};

/// The key-defining part of an algorithm: two templates whose profiles are
/// equal can use the same key material (Go: `KeyMaterialProfile`). Operation
/// parameters such as hash, padding, nonce size or signature encoding are
/// deliberately not part of it: an ECDSA P-256 key signs as well with
/// SHA-256 as prehashed; an AES-256 key serves GCM, CBC and CTR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterialProfile {
    pub family: &'static str,
    pub shape: String,
}

/// The profile of an algorithm, from its typed details. Fails closed for
/// algorithms whose material shape is not known here.
///
/// Go also requires the template to declare a `key_material_family` and
/// checks it against this derivation; the pinned API version predates that
/// field, so the derivation alone decides.
pub fn material_profile(details: &api::AlgorithmDetails) -> Result<MaterialProfile, Error> {
    let p = |family, shape: String| Ok(MaterialProfile { family, shape });
    match details.algorithm.as_ref() {
        Some(Algorithm::Ecdsa(a)) => p("ECDSA", format!("curve={}", a.curve)),
        Some(Algorithm::Ed25519(_)) => p("Ed25519", String::new()),
        Some(Algorithm::Ed448(_)) => p("Ed448", String::new()),
        Some(Algorithm::MlDsa(a)) => p("ML-DSA", format!("parameter-set={}", a.parameter_set)),
        Some(Algorithm::MlKem(a)) => p("ML-KEM", format!("parameter-set={}", a.parameter_set)),
        Some(Algorithm::RsaPss(a)) => p("RSA", format!("modulus-bits={}", a.key_size_bits)),
        Some(Algorithm::RsaPkcs1v15(a)) => p("RSA", format!("modulus-bits={}", a.key_size_bits)),
        Some(Algorithm::RsaOaep(a)) => p("RSA", format!("modulus-bits={}", a.key_size_bits)),
        Some(Algorithm::AesGcm(a)) => p("AES", format!("key-bits={}", a.key_size_bits)),
        Some(Algorithm::AesCbc(a)) => p("AES", format!("key-bits={}", a.key_size_bits)),
        Some(Algorithm::AesCtr(a)) => p("AES", format!("key-bits={}", a.key_size_bits)),
        Some(Algorithm::AesCcm(a)) => p("AES", format!("key-bits={}", a.key_size_bits)),
        Some(Algorithm::AesKeyWrap(a)) => p("AES", format!("key-bits={}", a.key_size_bits)),
        Some(Algorithm::AesXts(a)) => p("AES-XTS", format!("total-key-bits={}", a.key_size_bits)),
        Some(Algorithm::Chacha20Poly1305(_)) => p("ChaCha20", String::new()),
        Some(Algorithm::X25519(_)) => p("X25519", String::new()),
        Some(Algorithm::X448(_)) => p("X448", String::new()),
        Some(Algorithm::Ecdh(a)) => p("ECDH", format!("curve={}", a.curve)),
        _ => Err(Error::new(
            Code::IncompatibleParameters,
            "material_profile",
            "the key material of this algorithm cannot be reused",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::template::parse_catalog;

    fn profile(id: &str) -> Result<MaterialProfile, Error> {
        let catalog = parse_catalog(include_str!("../../../catalog/standard_algorithms.json")).unwrap();
        let t = catalog.iter().find(|t| t.id() == id).unwrap();
        material_profile(t.info().algorithm.as_ref().unwrap())
    }

    #[test]
    fn compatible_templates_share_a_profile() {
        for (a, b) in [
            ("ecdsa-p256-sha256-der", "ecdsa-p256-prehashed-der"),
            ("ed25519", "ed25519ph"),
            ("aes-256-gcm-128-96", "aes-256-cbc-pkcs7-128"),
            ("aes-128-gcm-128-96", "aes-128-ctr"),
            ("chacha20-poly1305", "xchacha20-poly1305"),
        ] {
            assert_eq!(profile(a).unwrap(), profile(b).unwrap(), "{a} / {b}");
        }
    }

    #[test]
    fn incompatible_templates_differ() {
        for (a, b) in [
            ("ecdsa-p256-sha256-der", "ecdsa-p384-sha384-der"),
            ("ml-dsa-44", "ml-dsa-65"),
            ("aes-128-gcm-128-96", "aes-256-gcm-128-96"),
            ("ed25519", "ml-dsa-65"),
            ("aes-256-gcm-128-96", "chacha20-poly1305"),
        ] {
            assert_ne!(profile(a).unwrap(), profile(b).unwrap(), "{a} / {b}");
        }
    }
}
