//! Fixtures for `benches/` (feature `bench`, off by default). They expose the
//! provider adapter (layer L1) and the orchestrators (layer L2) of
//! docs/performance.md through a small opaque API, so the crate's modules
//! stay private.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::domain::core::ProviderState;
use crate::adapters::providers::RustCrypto;
use crate::adapters::storage::{InMemoryKeyRepository, InMemoryPolicyRepository, InMemoryTemplateRegistry};
use crate::app::{
    CryptoOrchestrator, DecryptRequest, EncryptRequest, Encrypted, KeyOrchestrator, SignInput, SignRequest,
    VerifyRequest,
};
use crate::domain::core::{Error, KeyCreationSpec, ProviderRequirements, Scope, ScopeSpecification};
use crate::wire::metadata::{self, MetadataEncoding};
use crate::domain::policy::{Enforcer, Manager};
use crate::domain::provider::{Backend, Cipher, EncryptParams, GeneratedKey, ProviderRegistry, SignContext, Signer};
use crate::domain::template::TemplateRegistry;
use crate::proto::api;

const KEY: &str = "k";

/// The FFI's size check, which a bench's large enough buffers always pass.
fn admit(_: crate::app::Sizes) -> Result<(), Error> {
    Ok(())
}

const POLICY: &str = r#"{"version": "1",
    "allowed_templates": ["ed25519", "ecdsa-p256-sha256-der", "ecdsa-p384-sha384-der", "ecdsa-p521-sha512-der",
        "ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "aes-128-gcm-128-96", "aes-256-gcm-128-96", "chacha20-poly1305",
        "aes-256-cbc-pkcs7-128", "aes-256-ctr", "ecdsa-p256-prehashed-der", "ecdsa-p384-prehashed-der",
        "ecdsa-p521-prehashed-der", "ed25519ph"],
    "allowed_operations": {"key_operations": ["create_key", "sign", "verify", "digest_sign", "digest_verify",
        "encrypt", "decrypt"]}}"#;

/// The hash of a caller's digest.
#[derive(Clone, Copy, Debug)]
pub enum DigestHash {
    Sha256,
    Sha384,
    Sha512,
}

impl From<DigestHash> for api::HashAlgorithm {
    fn from(h: DigestHash) -> Self {
        match h {
            DigestHash::Sha256 => api::HashAlgorithm::Sha256,
            DigestHash::Sha384 => api::HashAlgorithm::Sha384,
            DigestHash::Sha512 => api::HashAlgorithm::Sha512,
        }
    }
}

/// The metadata encoding, as the C caller picks it.
#[derive(Clone, Copy, Debug)]
pub enum Encoding {
    WireV1,
    Protobuf,
}

impl From<Encoding> for MetadataEncoding {
    fn from(e: Encoding) -> Self {
        match e {
            Encoding::WireV1 => MetadataEncoding::WireV1,
            Encoding::Protobuf => MetadataEncoding::Protobuf,
        }
    }
}

fn algorithm(template: &str) -> api::AlgorithmDetails {
    let reg = InMemoryTemplateRegistry::standard();
    reg.get(template).expect("a standard template").info().algorithm.clone().expect("templates have an algorithm")
}

/// An in-memory context with one key named "k" made from `template`.
fn world(template: &str, scope: Scope) -> CryptoOrchestrator {
    let repo = Arc::new(InMemoryKeyRepository::new());
    let templates = InMemoryTemplateRegistry::standard();
    let mut registry = ProviderRegistry::new();
    registry.register(Arc::new(RustCrypto)).expect("register RustCrypto");
    let providers = Arc::new(registry);
    let policy = Arc::new(Enforcer::new(Arc::new(InMemoryPolicyRepository::new())));
    policy.create_policy("p", POLICY).expect("the bench policy is valid");
    let keys = KeyOrchestrator::new(repo.clone(), templates.clone(), providers.clone(), policy.clone());
    keys.create_key_admitting::<Error>(
        KeyCreationSpec {
            name: KEY.into(),
            policy: "p".into(),
            template_id: Some(template.into()),
            scope_spec: ScopeSpecification::any_of(scope),
            provider_id: None,
            provider_requirements: ProviderRequirements::default(),
        },
        |_| Ok(()),
    )
    .expect("create the bench key");
    CryptoOrchestrator::new(repo, templates, providers, policy)
}

/// Signing with one template, at layers L1 and L2.
pub struct SignBench {
    key: GeneratedKey,
    /// What a key version keeps (its public key), so L1 measures the path
    /// the library takes.
    cache: ProviderState,
    algorithm: api::AlgorithmDetails,
    crypto: CryptoOrchestrator,
}

impl SignBench {
    /// `template` takes the standard signature scope (message signing, no context).
    pub fn new(template: &str) -> Self {
        let algorithm = algorithm(template);
        let key = RustCrypto.generate_key(&algorithm).expect("generate a key");
        let crypto = world(template, Scope::Signature(crate::domain::core::SignatureScope::Standard));
        SignBench { key, cache: ProviderState::default(), algorithm, crypto }
    }

    /// For a prehashed template (`ecdsa-*-prehashed-der`, `ed25519ph`): digest
    /// signing, with the prehashed signature scope.
    pub fn new_prehashed(template: &str) -> Self {
        let algorithm = algorithm(template);
        let key = RustCrypto.generate_key(&algorithm).expect("generate a key");
        let crypto = world(template, Scope::Signature(crate::domain::core::SignatureScope::Prehashed));
        SignBench { key, cache: ProviderState::default(), algorithm, crypto }
    }

    /// The public key as the provider stores it (SPKI DER, or raw for
    /// ML-DSA), for L0 verification.
    pub fn public_key(&self) -> &[u8] {
        &self.key.public.as_ref().expect("a signing key has a public key").0
    }

    /// L1 verification with the L1 key.
    pub fn provider_verify(&self, message: &[u8], signature: &[u8]) -> bool {
        RustCrypto.verify(self.key.as_stored().with_state(&self.cache), &self.algorithm, message, signature, &SignContext::None).expect("verify")
    }

    /// L1 digest signing.
    pub fn provider_sign_digest(&self, digest: &[u8], hash: DigestHash) -> Vec<u8> {
        RustCrypto.sign_digest(self.key.as_stored().with_state(&self.cache), &self.algorithm, digest, hash.into(), &SignContext::None).expect("sign").0
    }

    fn digest_request<'a>(digest: &'a [u8], hash: DigestHash) -> SignRequest<'a> {
        SignRequest {
            key_name: KEY,
            input: SignInput::Digest { digest, hash: hash.into() },
            context: SignContext::None,
            user_context: BTreeMap::new(),
        }
    }

    /// L2 digest signing as `agc_digest_sign` drives it: sizes, sign, encode
    /// the metadata (PROTOBUF: WIRE_V1 cannot carry the digest hash).
    pub fn orchestrator_sign_digest_as_ffi(&self, digest: &[u8], hash: DigestHash) -> (Vec<u8>, Vec<u8>) {
        let enc = MetadataEncoding::Protobuf;
        let s = self.crypto.sign_admitting(Self::digest_request(digest, hash), enc, admit).expect("sign");
        let md = metadata::encode(&s.metadata, enc).expect("encode");
        (s.signature, md)
    }

    /// A signature and its WIRE_V1 metadata from the L2 key, for
    /// `orchestrator_verify_as_ffi`.
    pub fn orchestrator_signed(&self, message: &[u8]) -> (Vec<u8>, Vec<u8>) {
        self.orchestrator_sign_as_ffi(message, Encoding::WireV1)
    }

    /// L2 verification as `agc_verify` drives it when the caller wants no
    /// metadata back (the C harness's case): decode the caller's metadata,
    /// verify with the version it names.
    pub fn orchestrator_verify_as_ffi(&self, message: &[u8], signature: &[u8], md: &[u8]) -> bool {
        let enc = MetadataEncoding::from_byte(md[0]).expect("an encoding byte");
        let decoded = metadata::decode(enc, md).expect("decode");
        let req = VerifyRequest {
            key_name: KEY,
            input: SignInput::Message(message),
            signature,
            key_version: Some(decoded.key_version),
            context: SignContext::None,
            user_context: BTreeMap::new(),
        };
        self.crypto.verify(req).expect("verify").valid
    }

    /// The private key as the provider stores it (PKCS#8 or SEC1 DER), for L0.
    pub fn private_der(&self) -> &[u8] {
        &self.key.private
    }

    /// L1: the provider adapter, given the decoded key material.
    pub fn provider_sign(&self, message: &[u8]) -> Vec<u8> {
        RustCrypto.sign(self.key.as_stored().with_state(&self.cache), &self.algorithm, message, &SignContext::None).expect("sign").0
    }

    fn request<'a>(message: &'a [u8]) -> SignRequest<'a> {
        SignRequest {
            key_name: KEY,
            input: SignInput::Message(message),
            context: SignContext::None,
            user_context: BTreeMap::new(),
        }
    }

    /// L2: `CryptoOrchestrator::sign` alone.
    pub fn orchestrator_sign(&self, message: &[u8]) -> Vec<u8> {
        self.crypto.sign(Self::request(message)).expect("sign").signature
    }

    /// L2 as `agc_sign` drives it (`ffi/exports/sign.rs`, `sign_into`): sizes,
    /// sign, encode the metadata.
    pub fn orchestrator_sign_as_ffi(&self, message: &[u8], enc: Encoding) -> (Vec<u8>, Vec<u8>) {
        let enc = enc.into();
        let s = self.crypto.sign_admitting(Self::request(message), enc, admit).expect("sign");
        let md = metadata::encode(&s.metadata, enc).expect("encode");
        (s.signature, md)
    }
}

/// Encryption with one template, at layers L1 and L2.
pub struct CipherBench {
    key: GeneratedKey,
    cache: ProviderState,
    algorithm: api::AlgorithmDetails,
    crypto: CryptoOrchestrator,
    aead: bool,
}

/// A ciphertext and what decrypting it needs, made by `CipherBench::sealed`.
pub struct Sealed {
    l1: (Vec<u8>, api::ProviderOutput),
    l2: Encrypted,
}

impl CipherBench {
    /// `aead` picks the standard AEAD scope (with AAD), else the symmetric
    /// cipher scope (CBC, CTR).
    pub fn new(template: &str, aead: bool) -> Self {
        let algorithm = algorithm(template);
        let key = RustCrypto.generate_key(&algorithm).expect("generate a key");
        let scope = if aead {
            Scope::Aead(crate::domain::core::AeadScope::Standard)
        } else {
            Scope::SymmetricCipher(crate::domain::core::SymmetricCipherScope::Unspecified)
        };
        CipherBench { key, cache: ProviderState::default(), algorithm, crypto: world(template, scope), aead }
    }

    /// The raw key bytes, for L0.
    pub fn raw_key(&self) -> &[u8] {
        &self.key.private
    }

    fn params(&self) -> EncryptParams {
        if self.aead { EncryptParams::Aead { aad: b"ad".to_vec() } } else { EncryptParams::None }
    }

    /// L1 encryption.
    pub fn provider_encrypt(&self, pt: &[u8]) -> Vec<u8> {
        RustCrypto.encrypt(self.key.as_stored().with_state(&self.cache), &self.algorithm, pt, &self.params()).expect("encrypt").0
    }

    /// L2 encryption alone.
    pub fn orchestrator_encrypt(&self, pt: &[u8]) -> Vec<u8> {
        self.crypto.encrypt(self.encrypt_request(pt)).expect("encrypt").ciphertext
    }

    fn encrypt_request<'a>(&self, pt: &'a [u8]) -> EncryptRequest<'a> {
        EncryptRequest { key_name: KEY, plaintext: pt, params: self.params(), user_context: BTreeMap::new() }
    }

    /// L2 as `agc_encrypt` drives it: sizes, encrypt into the caller's
    /// region (a buffer reused across calls, as a C caller's would be),
    /// encode the metadata. Returns the ciphertext length and the metadata.
    pub fn orchestrator_encrypt_as_ffi(&self, pt: &[u8], enc: Encoding) -> (usize, Vec<u8>) {
        thread_local! {
            static REGION: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
        }
        let enc = enc.into();
        REGION.with_borrow_mut(|region| {
            let w = self
                .crypto
                .encrypt_admitting(self.encrypt_request(pt), enc, |sizes| {
                    if region.len() < sizes.artifact {
                        region.resize(sizes.artifact, 0);
                    }
                    Ok::<_, Error>(&mut region[..sizes.artifact])
                })
                .expect("encrypt");
            (w.len, metadata::encode(&w.metadata, enc).expect("encode"))
        })
    }

    /// A ciphertext of `pt` for the decryption benches.
    pub fn sealed(&self, pt: &[u8]) -> Sealed {
        let l1 = RustCrypto.encrypt(self.key.as_stored().with_state(&self.cache), &self.algorithm, pt, &self.params()).expect("encrypt");
        let l2 = self.crypto.encrypt(self.encrypt_request(pt)).expect("encrypt");
        Sealed { l1, l2 }
    }

    /// L1 decryption.
    pub fn provider_decrypt(&self, s: &Sealed) -> usize {
        RustCrypto.decrypt(self.key.as_stored().with_state(&self.cache), &self.algorithm, &s.l1.0, &s.l1.1, &self.params()).expect("decrypt").len()
    }

    /// L2 decryption. The metadata is cloned into the request, as the FFI
    /// does after decoding it.
    pub fn orchestrator_decrypt(&self, s: &Sealed) -> usize {
        let req = DecryptRequest {
            key_name: KEY,
            ciphertext: &s.l2.ciphertext,
            metadata: s.l2.metadata.clone(),
            params: self.params(),
            user_context: BTreeMap::new(),
        };
        self.crypto.decrypt(req).expect("decrypt").plaintext.len()
    }
}

/// L1 key generation (the provider's `generate_key`), for the stack depth
/// bench. Returns the private key's length.
pub fn provider_generate(template: &str) -> usize {
    RustCrypto.generate_key(&algorithm(template)).expect("generate a key").private.len()
}

/// The parts of a context, built as `ffi::context::Context::open` builds them
/// (in-memory store), each boxed so a caller can measure what it retains.
pub mod context_parts {
    use std::any::Any;
    use std::sync::Arc;

    use crate::adapters::providers::RustCrypto;
    use crate::adapters::storage::{InMemoryKeyRepository, InMemoryPolicyRepository, InMemoryTemplateRegistry};
    use crate::app::{CryptoOrchestrator, Discovery, KeyOrchestrator, PolicyAdmin, validate_providers};
    use crate::domain::policy::Enforcer;
    use crate::domain::provider::ProviderRegistry;

    pub type Held = Box<dyn Any>;

    /// The template registry parsed from the compiled-in catalog.
    pub fn templates() -> Held {
        Box::new(InMemoryTemplateRegistry::standard())
    }

    /// The provider registry with RustCrypto (no catalog).
    pub fn providers() -> Held {
        let mut p = ProviderRegistry::new();
        p.register(Arc::new(RustCrypto)).expect("register");
        Box::new(p)
    }

    /// The policy engine over an empty repository, and an empty key repository.
    pub fn repositories() -> Held {
        Box::new((Enforcer::new(Arc::new(InMemoryPolicyRepository::new())), InMemoryKeyRepository::new()))
    }

    /// Everything, as `Context::open` with an in-memory store.
    pub fn whole() -> Held {
        let templates = InMemoryTemplateRegistry::standard();
        let mut providers = ProviderRegistry::new();
        providers.register(Arc::new(RustCrypto)).expect("register");
        validate_providers(&providers, templates.as_ref()).expect("valid");
        let keys = Arc::new(InMemoryKeyRepository::new());
        let policy = Arc::new(Enforcer::new(Arc::new(InMemoryPolicyRepository::new())));
        let providers = Arc::new(providers);
        Box::new((
            KeyOrchestrator::new(keys.clone(), templates.clone(), providers.clone(), policy.clone()),
            CryptoOrchestrator::new(keys.clone(), templates.clone(), providers.clone(), policy.clone()),
            Discovery::new(templates, providers),
            PolicyAdmin::new(policy, keys),
        ))
    }
}
