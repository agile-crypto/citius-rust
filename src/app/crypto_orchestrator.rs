use std::collections::BTreeMap;
use std::sync::Arc;

use zeroize::Zeroizing;

use super::key_orchestrator::not_found;
use crate::domain::core::{Code, Error, Operation, Scope};
use crate::domain::crypto::metadata::{self, MetadataEncoding};
use crate::domain::key::{Key, KeyRepository, Version};
use crate::domain::policy::Evaluator;
use crate::domain::provider::{Backend, Cipher, EncryptParams, GeneratedKey, ProviderRegistry, Signer};
use crate::domain::template::{Template, TemplateRegistry};
use crate::proto::api::{self, provider_output::AlgorithmOutput};

/// The API version stamped into every metadata (agc_abi.h
/// AGC_API_VERSION_STRING; checked equal by the FFI layer's tests).
pub const API_VERSION: &str = "2.0";

/// Runs one crypto operation (Go: CryptoOrchestrator): loads the key,
/// applies its lifecycle rule and policy, and dispatches to the provider
/// that created the version, resolving the template into algorithm details.
/// Nothing is chosen at operation time: everything is looked up.
pub struct CryptoOrchestrator {
    keys: Arc<dyn KeyRepository>,
    templates: Arc<dyn TemplateRegistry>,
    providers: Arc<ProviderRegistry>,
    policy: Arc<dyn Evaluator>,
}

/// An encryption request (the inputs of agc_encrypt).
pub struct EncryptRequest<'a> {
    pub key_name: &'a str,
    pub plaintext: &'a [u8],
    pub params: EncryptParams,
    pub user_context: BTreeMap<String, String>,
}

/// What an operation produces besides its artifact: the metadata to store
/// with it and hand back to the consuming operation.
pub struct Encrypted {
    pub ciphertext: Vec<u8>,
    pub metadata: api::OperationMetadata,
}

/// A decryption request (the inputs of agc_decrypt).
pub struct DecryptRequest<'a> {
    pub key_name: &'a str,
    pub ciphertext: &'a [u8],
    /// The metadata the encryption returned, decoded.
    pub metadata: api::OperationMetadata,
    pub params: EncryptParams,
    pub user_context: BTreeMap<String, String>,
}

pub struct Decrypted {
    pub plaintext: Zeroizing<Vec<u8>>,
    pub metadata: api::OperationMetadata,
}

/// A key version resolved for an operation.
pub(super) struct Resolved {
    pub(super) version: Version,
    template: Template,
    provider: Arc<dyn Backend>,
}

impl Resolved {
    pub(super) fn algorithm(&self) -> &api::AlgorithmDetails {
        self.template.info().algorithm.as_ref().expect("templates always have an algorithm")
    }

    pub(super) fn material(&self) -> Result<GeneratedKey, Error> {
        GeneratedKey::from_bytes(self.version.material())
    }

    fn cipher(&self) -> Result<&dyn Cipher, Error> {
        self.provider.as_cipher().ok_or_else(|| {
            Error::new(Code::NotImplemented, "CryptoOrchestrator", format!("provider {} cannot encrypt", self.provider.name()))
        })
    }

    pub(super) fn signer(&self) -> Result<&dyn Signer, Error> {
        self.provider.as_signer().ok_or_else(|| {
            Error::new(Code::NotImplemented, "CryptoOrchestrator", format!("provider {} cannot sign", self.provider.name()))
        })
    }
}

/// Which lifecycle rule an operation follows.
#[derive(Clone, Copy)]
pub(super) enum Direction {
    /// Creates protected data: sign, encrypt. Only an ACTIVE key.
    Originating,
    /// Processes existing protected data: verify, decrypt. Also SUSPENDED and
    /// DEACTIVATED keys, so existing data stays usable.
    Receiving,
}

impl CryptoOrchestrator {
    pub fn new(
        keys: Arc<dyn KeyRepository>,
        templates: Arc<dyn TemplateRegistry>,
        providers: Arc<ProviderRegistry>,
        policy: Arc<dyn Evaluator>,
    ) -> Self {
        CryptoOrchestrator { keys, templates, providers, policy }
    }

    /// The common steps of every keyed operation (Go: Sign/Encrypt steps
    /// 2-6): the key, its lifecycle rule, the version (current, or the one
    /// the metadata names), the policy, the template's declaration of the
    /// operation for the version's scope, and the version's provider.
    pub(super) fn resolve(
        &self,
        key_name: &str,
        version: Option<u32>,
        direction: Direction,
        op: Operation,
        declared: api::CryptoOperation,
    ) -> Result<(Key, Resolved), Error> {
        const OP: &str = "CryptoOrchestrator";
        if key_name.is_empty() {
            return Err(Error::new(Code::InvalidArgument, OP, "a key name is required"));
        }
        let key = self.keys.get_by_name(key_name)?.ok_or_else(|| not_found(OP, key_name))?;
        match direction {
            Direction::Originating => key.can_originate()?,
            Direction::Receiving => key.can_receive()?,
        }
        let version = match version {
            None => key.current().clone(),
            Some(n) => key
                .version(n)
                .cloned()
                .ok_or_else(|| Error::new(Code::KeyNotFound, OP, format!("key {key_name} has no version {n}")))?,
        };
        self.policy.validate_operation(key.policy(), op, Some(version.template_id()))?;
        let template = self.templates.get(version.template_id()).cloned().ok_or_else(|| {
            Error::new(Code::TemplateNotFound, OP, format!("the key's template {} is gone", version.template_id()))
        })?;
        if !template.supports_operation(&version.scope_spec().scope, declared) {
            return Err(Error::new(
                Code::KeyOperationNotAllowed,
                OP,
                format!("template {} does not declare {declared:?} for {:?}", template.id(), version.scope_spec().scope),
            ));
        }
        let provider = self.providers.get(version.provider()).ok_or_else(|| {
            Error::new(Code::ProviderNotFound, OP, format!("the key's provider {} is not registered", version.provider()))
        })?;
        Ok((key, Resolved { version, template, provider }))
    }

    /// The parameters must fit the version's scope (Go:
    /// validateEncryptionScopeParams): AEAD parameters for a standard AEAD
    /// key, none for a block or stream cipher key.
    fn check_encrypt_params(r: &Resolved, params: &EncryptParams) -> Result<(), Error> {
        let scope = r.version.scope_spec().scope;
        let fits = match params {
            EncryptParams::Aead { .. } => scope == Scope::Aead(api::AeadScope::Standard),
            EncryptParams::None => matches!(scope, Scope::SymmetricCipher(_)),
        };
        if !fits {
            return Err(Error::new(
                Code::InvalidArgument,
                "CryptoOrchestrator",
                format!("the encryption parameters do not fit the key's scope {scope:?}"),
            ));
        }
        Ok(())
    }

    /// The metadata of an operation. `digest_hash` is set by digest signing
    /// only (`with_digest_hash`); UNSPECIFIED otherwise.
    pub(super) fn metadata(version: u32, output: api::ProviderOutput, user_context: BTreeMap<String, String>) -> api::OperationMetadata {
        api::OperationMetadata {
            key_version: version,
            provider_output: Some(output),
            api_version: API_VERSION.into(),
            user_context,
            digest_hash: api::HashAlgorithm::Unspecified as i32,
        }
    }

    /// What `encrypt` will produce in size: the ciphertext and the encoded
    /// metadata, exactly, with no provider work and no randomness.
    pub fn encrypt_sizes(&self, req: &EncryptRequest, enc: MetadataEncoding) -> Result<(usize, usize), Error> {
        non_empty(req.plaintext, "plaintext")?;
        let (_, r) = self.resolve(req.key_name, None, Direction::Originating, Operation::Encrypt, api::CryptoOperation::Encrypt)?;
        Self::check_encrypt_params(&r, &req.params)?;
        let cipher = r.cipher()?;
        let ct = cipher.ciphertext_len(r.algorithm(), req.plaintext.len())?;
        let shape = Self::metadata(r.version.number(), cipher.output_shape(r.algorithm())?, req.user_context.clone());
        Ok((ct, metadata::encode(&shape, enc)?.len()))
    }

    /// Encrypts with the key's current version (Go: Encrypt).
    pub fn encrypt(&self, req: EncryptRequest) -> Result<Encrypted, Error> {
        non_empty(req.plaintext, "plaintext")?;
        let (_, r) = self.resolve(req.key_name, None, Direction::Originating, Operation::Encrypt, api::CryptoOperation::Encrypt)?;
        Self::check_encrypt_params(&r, &req.params)?;
        let (ciphertext, output) = r.cipher()?.encrypt(&r.material()?, r.algorithm(), req.plaintext, &req.params)?;
        require_output(&output)?;
        Ok(Encrypted { ciphertext, metadata: Self::metadata(r.version.number(), output, req.user_context) })
    }

    /// What `decrypt` needs room for: the most plaintext the ciphertext can
    /// hold, and the encoded metadata of the decryption.
    pub fn decrypt_sizes(&self, req: &DecryptRequest, enc: MetadataEncoding) -> Result<(usize, usize), Error> {
        let r = self.resolve_decrypt(req)?;
        let pt = r.cipher()?.plaintext_len_bound(r.algorithm(), req.ciphertext.len())?;
        let md = Self::metadata(r.version.number(), no_output(), req.user_context.clone());
        Ok((pt, metadata::encode(&md, enc)?.len()))
    }

    fn resolve_decrypt(&self, req: &DecryptRequest) -> Result<Resolved, Error> {
        non_empty(req.ciphertext, "ciphertext")?;
        if req.metadata.key_version == 0 {
            return Err(Error::new(Code::InvalidArgument, "CryptoOrchestrator", "the metadata names no key version"));
        }
        let (_, r) = self.resolve(
            req.key_name,
            Some(req.metadata.key_version),
            Direction::Receiving,
            Operation::Decrypt,
            api::CryptoOperation::Decrypt,
        )?;
        Self::check_encrypt_params(&r, &req.params)?;
        Ok(r)
    }

    /// An upper bound on the encoded metadata any operation on `key_name`
    /// produces in `enc` with `user_context` (agc_metadata_max_encoded_len):
    /// the largest output shape over the key's versions, with the largest
    /// key version, so the bound survives later rotations. A sizing aid
    /// only: no lifecycle or policy check, as for a size query.
    pub fn metadata_max_len(
        &self,
        key_name: &str,
        enc: MetadataEncoding,
        user_context: &BTreeMap<String, String>,
    ) -> Result<usize, Error> {
        let key = self.keys.get_by_name(key_name)?.ok_or_else(|| not_found("CryptoOrchestrator", key_name))?;
        let mut shapes = vec![no_output()];
        for v in key.versions() {
            let Some(template) = self.templates.get(v.template_id()) else { continue };
            let Some(provider) = self.providers.get(v.provider()) else { continue };
            let algorithm = template.info().algorithm.as_ref().expect("templates always have an algorithm");
            let shape = match v.scope_spec().scope {
                Scope::Signature(_) => provider.as_signer().map(|s| s.output_shape(algorithm)),
                Scope::Aead(_) | Scope::SymmetricCipher(_) => provider.as_cipher().map(|c| c.output_shape(algorithm)),
                _ => None,
            };
            if let Some(Ok(shape)) = shape {
                shapes.push(shape);
            }
        }
        let mut max = 0;
        for shape in shapes {
            let md = Self::metadata(u32::MAX, shape, user_context.clone());
            max = max.max(metadata::encode(&md, enc)?.len());
        }
        Ok(max)
    }

    /// Decrypts with the version the metadata names (Go: Decrypt). On an
    /// authentication failure no plaintext is released.
    pub fn decrypt(&self, req: DecryptRequest) -> Result<Decrypted, Error> {
        let r = self.resolve_decrypt(&req)?;
        let output = req
            .metadata
            .provider_output
            .as_ref()
            .ok_or_else(|| Error::new(Code::InvalidArgument, "CryptoOrchestrator", "the metadata has no provider output"))?;
        let plaintext = r.cipher()?.decrypt(&r.material()?, r.algorithm(), req.ciphertext, output, &req.params)?;
        Ok(Decrypted { plaintext, metadata: Self::metadata(r.version.number(), no_output(), req.user_context) })
    }
}

/// Empty input is refused, as in Go: it protects nothing.
pub(super) fn non_empty(b: &[u8], what: &str) -> Result<(), Error> {
    if b.is_empty() {
        return Err(Error::new(Code::InvalidArgument, "CryptoOrchestrator", format!("{what} must not be empty")));
    }
    Ok(())
}

pub(super) fn no_output() -> api::ProviderOutput {
    api::ProviderOutput { encoding: String::new(), algorithm_output: Some(AlgorithmOutput::NoOutput(api::NoAlgorithmOutput {})) }
}

/// A provider must always set an output kind (Go: requireProviderOutput).
pub(super) fn require_output(o: &api::ProviderOutput) -> Result<(), Error> {
    if o.algorithm_output.is_none() {
        return Err(Error::new(Code::ProviderContractViolation, "CryptoOrchestrator", "the provider returned no output kind"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::providers::RustCrypto;
    use crate::adapters::storage::{InMemoryKeyRepository, InMemoryPolicyRepository, InMemoryTemplateRegistry};
    use crate::app::KeyOrchestrator;
    use crate::domain::core::{KeyCreationSpec, ProviderRequirements, ScopeSpecification};
    use crate::domain::policy::{Enforcer, Manager};

    const POLICY: &str = r#"{"version": "1",
        "allowed_templates": ["aes-256-gcm-128-96", "aes-128-cbc-pkcs7-128"],
        "allowed_operations": {"key_operations": ["create_key", "encrypt", "decrypt"]}}"#;

    struct World {
        keys: KeyOrchestrator,
        crypto: CryptoOrchestrator,
        repo: Arc<InMemoryKeyRepository>,
        policy: Arc<Enforcer>,
    }

    fn world() -> World {
        let repo = Arc::new(InMemoryKeyRepository::new());
        let templates = Arc::new(InMemoryTemplateRegistry::standard());
        let mut registry = ProviderRegistry::new();
        registry.register(Arc::new(RustCrypto)).unwrap();
        let providers = Arc::new(registry);
        let policy = Arc::new(Enforcer::new(Arc::new(InMemoryPolicyRepository::new())));
        policy.create_policy("p", POLICY).unwrap();
        World {
            keys: KeyOrchestrator::new(repo.clone(), templates.clone(), providers.clone(), policy.clone()),
            crypto: CryptoOrchestrator::new(repo.clone(), templates, providers, policy.clone()),
            repo,
            policy,
        }
    }

    fn create(w: &World, name: &str, scope: Scope) {
        w.keys
            .create_key(KeyCreationSpec {
                name: name.into(),
                policy: "p".into(),
                template_id: None,
                scope_spec: ScopeSpecification::any_of(scope),
                provider_id: None,
                provider_requirements: ProviderRequirements::default(),
            })
            .unwrap();
    }

    const AEAD: Scope = Scope::Aead(api::AeadScope::Unspecified);

    fn aead() -> EncryptParams {
        EncryptParams::Aead { aad: b"ad".to_vec() }
    }

    fn encrypt<'a>(name: &'a str, pt: &'a [u8], params: EncryptParams) -> EncryptRequest<'a> {
        EncryptRequest { key_name: name, plaintext: pt, params, user_context: BTreeMap::new() }
    }

    fn decrypt<'a>(name: &'a str, e: &'a Encrypted, params: EncryptParams) -> DecryptRequest<'a> {
        DecryptRequest {
            key_name: name,
            ciphertext: &e.ciphertext,
            metadata: e.metadata.clone(),
            params,
            user_context: BTreeMap::new(),
        }
    }

    #[test]
    fn encrypt_and_decrypt_with_metadata() {
        let w = world();
        create(&w, "k", AEAD);
        let mut req = encrypt("k", b"hello", aead());
        req.user_context.insert("tenant".into(), "acme".into());
        let sizes = w.crypto.encrypt_sizes(&req, MetadataEncoding::WireV1).unwrap();
        let e = w.crypto.encrypt(req).unwrap();
        assert_eq!(sizes.0, e.ciphertext.len());
        assert_eq!(sizes.1, metadata::encode(&e.metadata, MetadataEncoding::WireV1).unwrap().len(), "exact");
        assert_eq!((e.metadata.key_version, e.metadata.api_version.as_str()), (1, API_VERSION));
        assert_eq!(e.metadata.user_context.get("tenant").map(String::as_str), Some("acme"));

        let d = w.crypto.decrypt(decrypt("k", &e, aead())).unwrap();
        assert_eq!(*d.plaintext, b"hello");
        assert_eq!(d.metadata.key_version, 1);
    }

    #[test]
    fn decryption_uses_the_version_the_metadata_names() {
        let w = world();
        create(&w, "k", AEAD);
        let old = w.crypto.encrypt(encrypt("k", b"before", aead())).unwrap();
        w.keys
            .transform_key(crate::app::TransformSpec {
                key_name: "k".into(),
                retain: false,
                scope_spec: None,
                template_id: None,
            })
            .unwrap();
        let new = w.crypto.encrypt(encrypt("k", b"after", aead())).unwrap();
        assert_eq!((old.metadata.key_version, new.metadata.key_version), (1, 2));
        assert_eq!(*w.crypto.decrypt(decrypt("k", &old, aead())).unwrap().plaintext, b"before");
        assert_eq!(*w.crypto.decrypt(decrypt("k", &new, aead())).unwrap().plaintext, b"after");
        // Version 1's metadata on version 2's ciphertext: authentication fails.
        let mut mixed = decrypt("k", &new, aead());
        mixed.metadata.key_version = 1;
        assert_eq!(w.crypto.decrypt(mixed).err().unwrap().code(), Code::AuthenticationFailed);
    }

    #[test]
    fn parameters_must_fit_the_scope() {
        let w = world();
        create(&w, "aead", AEAD);
        create(&w, "cbc", Scope::SymmetricCipher(api::SymmetricCipherScope::Unspecified));
        let code = |r: Result<Encrypted, Error>| r.err().unwrap().code();
        assert_eq!(code(w.crypto.encrypt(encrypt("aead", b"x", EncryptParams::None))), Code::InvalidArgument);
        assert_eq!(code(w.crypto.encrypt(encrypt("cbc", b"x", aead()))), Code::InvalidArgument);
        let e = w.crypto.encrypt(encrypt("cbc", b"block cipher", EncryptParams::None)).unwrap();
        assert_eq!(*w.crypto.decrypt(decrypt("cbc", &e, EncryptParams::None)).unwrap().plaintext, b"block cipher");
    }

    #[test]
    fn lifecycle_and_policy_apply() {
        let w = world();
        create(&w, "k", AEAD);
        let e = w.crypto.encrypt(encrypt("k", b"x", aead())).unwrap();

        // A suspended key decrypts what exists but encrypts nothing new.
        let mut k = w.repo.get_by_name("k").unwrap().unwrap();
        k.transition(api::KeyLifecycleState::Suspended, std::time::SystemTime::now()).unwrap();
        w.repo.update(k).unwrap();
        assert_eq!(w.crypto.encrypt(encrypt("k", b"x", aead())).err().unwrap().code(), Code::KeyOperationNotAllowed);
        assert!(w.crypto.decrypt(decrypt("k", &e, aead())).is_ok());

        // Tightening the policy affects existing keys.
        w.policy
            .update_policy(
                "p",
                r#"{"version": "1", "allowed_templates": ["aes-256-gcm-128-96"],
                    "allowed_operations": {"key_operations": ["create_key", "encrypt"]}}"#,
                0,
            )
            .unwrap();
        assert_eq!(w.crypto.decrypt(decrypt("k", &e, aead())).err().unwrap().code(), Code::PolicyViolation);
        assert_eq!(w.crypto.encrypt(encrypt("nope", b"x", aead())).err().unwrap().code(), Code::KeyNotFound);
    }
}
