//! Cross-checks with the Go software provider (citius-server), run by
//! `cargo xtask interop`: `export` writes signatures and ciphertexts made
//! here for Go to verify and decrypt; Go writes its own, which `import`
//! verifies and decrypts here. Key material travels in the encodings both
//! providers store (G14); algorithm details, provider outputs and metadata
//! as protobuf, so each side parses them with its own generated code.
//!
//! Both tests are ignored: they need the exchange directory the task sets
//! up (`AGC_INTEROP_DIR`).

use std::collections::BTreeMap;
use std::path::PathBuf;

use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use zeroize::Zeroizing;

use super::RustCrypto;
use crate::adapters::storage::InMemoryTemplateRegistry;
use crate::wire::metadata::{self, MetadataEncoding};
use crate::domain::provider::{Backend, EncryptParams, Encoding, GeneratedKey, SignContext};
use crate::domain::template::TemplateRegistry;
use crate::proto::api::{self, HashAlgorithm, algorithm_details::Algorithm};

/// One artifact and everything needed to check it. Bytes are hex.
#[derive(Serialize, Deserialize)]
struct Case {
    template: String,
    /// "sign", "digest_sign" or "encrypt".
    kind: String,
    algorithm: String,
    private: String,
    private_encoding: String,
    public: String,
    public_encoding: String,
    /// A domain context; absent means none.
    context: Option<String>,
    /// The message, digest or plaintext.
    input: String,
    hash: i32,
    /// AEAD additional data; absent means no parameters.
    aad: Option<String>,
    /// The signature or ciphertext.
    artifact: String,
    provider_output: String,
    /// The operation's `OperationMetadata`, protobuf, without the
    /// encoding byte.
    metadata: String,
}

#[derive(Serialize, Deserialize)]
struct Vectors {
    producer: String,
    cases: Vec<Case>,
}

fn dir() -> PathBuf {
    PathBuf::from(std::env::var("AGC_INTEROP_DIR").expect("AGC_INTEROP_DIR is set by cargo xtask interop"))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn encoding_name(e: Encoding) -> &'static str {
    match e {
        Encoding::Raw => "RAW",
        Encoding::Sec1Der => "SEC1",
        Encoding::Pkcs8Der => "PKCS8",
        Encoding::SpkiDer => "SPKI",
    }
}

fn encoding_of(name: &str) -> Encoding {
    match name {
        "RAW" => Encoding::Raw,
        "SEC1" => Encoding::Sec1Der,
        "PKCS8" => Encoding::Pkcs8Der,
        "SPKI" => Encoding::SpkiDer,
        other => panic!("unknown key encoding {other}"),
    }
}

/// What each template is exercised with: the operation, and for digest
/// signing the hash.
fn kind_of(a: &api::AlgorithmDetails) -> (&'static str, HashAlgorithm) {
    match a.algorithm.as_ref() {
        Some(Algorithm::Ecdsa(p)) if p.hash == HashAlgorithm::Unspecified as i32 => {
            let hash = match api::EllipticCurve::try_from(p.curve) {
                Ok(api::EllipticCurve::P256) => HashAlgorithm::Sha256,
                Ok(api::EllipticCurve::P384) => HashAlgorithm::Sha384,
                _ => HashAlgorithm::Sha512,
            };
            ("digest_sign", hash)
        }
        Some(Algorithm::Ed25519(p)) if p.variant == api::Ed25519Variant::Ph as i32 => {
            ("digest_sign", HashAlgorithm::Sha512)
        }
        Some(Algorithm::Ecdsa(_) | Algorithm::Ed25519(_) | Algorithm::MlDsa(_)) => ("sign", HashAlgorithm::Unspecified),
        _ => ("encrypt", HashAlgorithm::Unspecified),
    }
}

fn digest(hash: HashAlgorithm, m: &[u8]) -> Vec<u8> {
    match hash {
        HashAlgorithm::Sha256 => sha2::Sha256::digest(m).to_vec(),
        HashAlgorithm::Sha384 => sha2::Sha384::digest(m).to_vec(),
        _ => sha2::Sha512::digest(m).to_vec(),
    }
}

fn is_aead(a: &api::AlgorithmDetails) -> bool {
    matches!(a.algorithm, Some(Algorithm::AesGcm(_) | Algorithm::Chacha20Poly1305(_)))
}

const MESSAGE: &[u8] = b"agilecrypto <-> citius-server interop";

fn export_case(template: &str, algorithm: &api::AlgorithmDetails, context: Option<&[u8]>) -> Case {
    let key = RustCrypto.generate_key(algorithm).unwrap();
    let sign_context = context.map_or(SignContext::None, |c| SignContext::Domain(c.to_vec()));
    let (kind, hash) = kind_of(algorithm);
    let signer = RustCrypto.as_signer().unwrap();
    let cipher = RustCrypto.as_cipher().unwrap();
    let mut aad = None;
    let (input, (artifact, output)) = match kind {
        "sign" => (MESSAGE.to_vec(), signer.sign(key.as_stored(), algorithm, MESSAGE, &sign_context).unwrap()),
        "digest_sign" => {
            let d = digest(hash, MESSAGE);
            let signed = signer.sign_digest(key.as_stored(), algorithm, &d, hash, &sign_context).unwrap();
            (d, signed)
        }
        _ => {
            let params = if is_aead(algorithm) {
                aad = Some(b"header".to_vec());
                EncryptParams::Aead { aad: b"header".to_vec() }
            } else {
                EncryptParams::None
            };
            (MESSAGE.to_vec(), cipher.encrypt(key.as_stored(), algorithm, MESSAGE, &params).unwrap())
        }
    };
    let md = api::OperationMetadata {
        key_version: 1,
        provider_output: Some(output.clone()),
        // What the library stamps (app::API_VERSION; adapters may not
        // import the app layer).
        api_version: "1.0".into(),
        user_context: BTreeMap::from([("tenant".to_owned(), "acme".to_owned())]),
        // Digest signing records its hash, as the library does.
        digest_hash: if kind == "digest_sign" { hash as i32 } else { HashAlgorithm::Unspecified as i32 },
    };
    let encoded = metadata::encode(&md, MetadataEncoding::Protobuf).unwrap();
    let (public, public_encoding) = key.public.clone().unwrap_or_default_pair();
    Case {
        template: template.to_owned(),
        kind: kind.to_owned(),
        algorithm: hex(&algorithm.encode_to_vec()),
        private: hex(&key.private),
        private_encoding: encoding_name(key.private_encoding).to_owned(),
        public: hex(&public),
        public_encoding: public_encoding.to_owned(),
        context: context.map(hex),
        input: hex(&input),
        hash: hash as i32,
        aad: aad.as_deref().map(hex),
        artifact: hex(&artifact),
        provider_output: hex(&output.encode_to_vec()),
        metadata: hex(&encoded[1..]),
    }
}

trait PublicPair {
    fn unwrap_or_default_pair(self) -> (Vec<u8>, &'static str);
}

impl PublicPair for Option<(Vec<u8>, Encoding)> {
    fn unwrap_or_default_pair(self) -> (Vec<u8>, &'static str) {
        self.map_or((Vec::new(), ""), |(b, e)| (b, encoding_name(e)))
    }
}

#[test]
#[ignore = "run by cargo xtask interop"]
fn export() {
    let templates = InMemoryTemplateRegistry::standard();
    let mut cases = Vec::new();
    for id in RustCrypto.supported_templates() {
        let algorithm = templates.get(id).unwrap().info().algorithm.clone().unwrap();
        cases.push(export_case(id, &algorithm, None));
        if matches!(algorithm.algorithm, Some(Algorithm::MlDsa(_))) {
            cases.push(export_case(id, &algorithm, Some(b"interop-context")));
        }
    }
    let v = Vectors { producer: "agilecrypto rustcrypto provider".into(), cases };
    std::fs::write(dir().join("rust.json"), serde_json::to_vec_pretty(&v).unwrap()).unwrap();
}

/// Checks one Go case; returns a failure description, if any.
fn check_go_case(c: &Case) -> Result<(), String> {
    let algorithm = api::AlgorithmDetails::decode(&*unhex(&c.algorithm)).map_err(|e| format!("algorithm: {e}"))?;
    let output = api::ProviderOutput::decode(&*unhex(&c.provider_output)).map_err(|e| format!("output: {e}"))?;
    let public = (!c.public.is_empty()).then(|| (unhex(&c.public), encoding_of(&c.public_encoding)));
    let key = GeneratedKey {
        private: Zeroizing::new(unhex(&c.private)),
        private_encoding: encoding_of(&c.private_encoding),
        public,
    };
    let context = c.context.as_deref().map_or(SignContext::None, |h| SignContext::Domain(unhex(h)));
    let hash = HashAlgorithm::try_from(c.hash).map_err(|_| format!("hash {}", c.hash))?;
    let (input, artifact) = (unhex(&c.input), unhex(&c.artifact));
    let mut tampered = artifact.clone();
    *tampered.last_mut().unwrap() ^= 1;
    let signer = RustCrypto.as_signer().unwrap();
    match c.kind.as_str() {
        "sign" | "digest_sign" => {
            let verify = |sig: &[u8]| match c.kind.as_str() {
                "sign" => signer.verify(key.as_stored(), &algorithm, &input, sig, &context),
                _ => signer.verify_digest(key.as_stored(), &algorithm, &input, hash, sig, &context),
            };
            if !verify(&artifact).map_err(|e| format!("verify: {e:?}"))? {
                return Err("Go's signature does not verify".into());
            }
            if verify(&tampered).map_err(|e| format!("verify: {e:?}"))? {
                return Err("a tampered Go signature verifies".into());
            }
        }
        _ => {
            let params =
                c.aad.as_deref().map_or(EncryptParams::None, |aad| EncryptParams::Aead { aad: unhex(aad) });
            let plain = RustCrypto
                .as_cipher()
                .unwrap()
                .decrypt(key.as_stored(), &algorithm, &artifact, &output, &params)
                .map_err(|e| format!("decrypt: {e:?}"))?;
            if *plain != input {
                return Err("Go's ciphertext decrypts to something else".into());
            }
        }
    }
    // The metadata as the Go server builds it: digest signing records the
    // hash in digest_hash (api v0.3.0), which the strict decoder now accepts.
    let md = metadata::decode_body(MetadataEncoding::Protobuf, &unhex(&c.metadata))
        .map_err(|e| format!("metadata: {e:?}"))?;
    let want_hash = if c.kind == "digest_sign" { hash as i32 } else { HashAlgorithm::Unspecified as i32 };
    if md.key_version != 1 || md.provider_output.as_ref() != Some(&output) || md.digest_hash != want_hash {
        return Err(format!("metadata decoded to {md:?}"));
    }
    Ok(())
}

#[test]
#[ignore = "run by cargo xtask interop"]
fn import() {
    let v: Vectors = serde_json::from_slice(&std::fs::read(dir().join("go.json")).unwrap()).unwrap();
    let rust: Vectors = serde_json::from_slice(&std::fs::read(dir().join("rust.json")).unwrap()).unwrap();
    assert_eq!(v.cases.len(), rust.cases.len(), "Go answers every case");
    let failures: Vec<String> = v
        .cases
        .iter()
        .filter_map(|c| check_go_case(c).err().map(|e| format!("{} ({}): {e}", c.template, c.kind)))
        .collect();
    assert!(failures.is_empty(), "{} of {} Go cases failed:\n{}", failures.len(), v.cases.len(), failures.join("\n"));
    println!("interop: {} Go cases verified/decrypted here", v.cases.len());
}
