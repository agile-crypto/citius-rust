use std::collections::BTreeMap;
use std::sync::Arc;

use crate::secret::SecretVec;

use super::key_orchestrator::not_found;
use crate::domain::core::{Code, Error, Operation, Scope};
use crate::domain::crypto::metadata::{self, MetadataEncoding};
use crate::domain::key::{Key, KeyRepository, Version};
use crate::domain::policy::Evaluator;
use crate::domain::provider::{Backend, Cipher, EncryptParams, ProviderRegistry, Signer, StoredKey};
use crate::domain::template::{Template, TemplateRegistry};
use crate::proto::api::{self, provider_output::AlgorithmOutput};

/// The API version stamped into every metadata (agc_abi.h
/// AGC_API_VERSION_STRING; checked equal by the FFI layer's tests).
pub const API_VERSION: &str = "1.0";

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
#[cfg_attr(not(test), allow(dead_code, reason = "for Rust callers; the C API writes into its regions (*_admitting)"))]
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

#[cfg_attr(not(test), allow(dead_code, reason = "for Rust callers; the C API writes into its regions (*_admitting)"))]
pub struct Decrypted {
    pub plaintext: SecretVec,
    pub metadata: api::OperationMetadata,
}

/// What an operation wrote into the caller's region (`*_admitting`): its
/// length, and the metadata to return with it.
pub struct Written {
    pub len: usize,
    pub metadata: api::OperationMetadata,
}

/// What an operation will write (agc_crypto.h, SIZE QUERIES): its artifact
/// (ciphertext, plaintext or signature; a bound where the length varies)
/// and its encoded metadata (0 when the caller does not want it back).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sizes {
    pub artifact: usize,
    pub metadata: usize,
}

/// A key version resolved for an operation. It borrows the stored key from
/// the key store's current snapshot (`with_resolved`), and the template and
/// provider from the orchestrator: resolving copies nothing and writes
/// nothing shared, and the locked material stays where it is.
pub(super) struct Resolved<'a> {
    key: &'a Key,
    /// Index of the resolved version in `key.versions()`.
    at: usize,
    template: &'a Template,
    provider: &'a dyn Backend,
}

impl Resolved<'_> {
    pub(super) fn version(&self) -> &Version {
        &self.key.versions()[self.at]
    }

    pub(super) fn algorithm(&self) -> &api::AlgorithmDetails {
        self.template.info().algorithm.as_ref().expect("templates always have an algorithm")
    }

    /// The version's material, read in place from its locked pages.
    pub(super) fn material(&self) -> Result<StoredKey<'_>, Error> {
        Ok(StoredKey::parse(self.version().material())?.with_state(self.version().provider_state()))
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
    /// Runs `then` with `key_name`'s version resolved for an operation: the
    /// key looked up in place in the store's snapshot (`inspect_by_name`),
    /// its lifecycle, the policy and the template checked, the provider
    /// found. The operation runs inside the lookup, on the borrowed key: one
    /// lookup per call, and nothing written that other threads share (F7).
    pub(super) fn with_resolved<R, E: From<Error>>(
        &self,
        key_name: &str,
        version: Option<u32>,
        direction: Direction,
        op: Operation,
        declared: api::CryptoOperation,
        then: impl FnOnce(Resolved<'_>) -> Result<R, E>,
    ) -> Result<R, E> {
        const OP: &str = "CryptoOrchestrator";
        if key_name.is_empty() {
            return Err(Error::new(Code::InvalidArgument, OP, "a key name is required").into());
        }
        let (mut then, mut result) = (Some(then), None);
        self.keys.inspect_by_name(key_name, &mut |key| {
            let then = then.take().expect("a store calls `f` at most once");
            result = Some(self.resolved(key, version, direction, op, declared).map_err(E::from).and_then(then));
        })?;
        result.unwrap_or_else(|| Err(not_found(OP, key_name).into()))
    }

    fn resolved<'a>(
        &'a self,
        key: &'a Key,
        version: Option<u32>,
        direction: Direction,
        op: Operation,
        declared: api::CryptoOperation,
    ) -> Result<Resolved<'a>, Error> {
        const OP: &str = "CryptoOrchestrator";
        match direction {
            Direction::Originating => key.can_originate()?,
            Direction::Receiving => key.can_receive()?,
        }
        let at = match version {
            None => key.versions().len() - 1,
            Some(n) => n
                .checked_sub(1)
                .map(|i| i as usize)
                .filter(|&i| i < key.versions().len())
                .ok_or_else(|| Error::new(Code::KeyNotFound, OP, format!("key {} has no version {n}", key.name())))?,
        };
        let version = &key.versions()[at];
        self.policy.validate_operation(key.policy(), op, Some(version.template_id()))?;
        let template = self.templates.get(version.template_id()).ok_or_else(|| {
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
        let provider = provider.as_ref();
        Ok(Resolved { key, at, template, provider })
    }

    /// The parameters must fit the version's scope (Go:
    /// validateEncryptionScopeParams): AEAD parameters for a standard AEAD
    /// key, none for a block or stream cipher key.
    fn check_encrypt_params(r: &Resolved, params: &EncryptParams) -> Result<(), Error> {
        let scope = r.version().scope_spec().scope;
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

    /// Encrypts with the key's current version (Go: Encrypt).
    #[cfg_attr(not(test), allow(dead_code, reason = "for Rust callers; the C API sizes first (*_admitting)"))]
    pub fn encrypt(&self, req: EncryptRequest) -> Result<Encrypted, Error> {
        self.with_encrypt(req, |r, req| {
            let mut ciphertext = vec![0; r.cipher()?.ciphertext_len(r.algorithm(), req.plaintext.len())?];
            let w = Self::encrypt_resolved(&r, req, &mut ciphertext)?;
            ciphertext.truncate(w.len);
            Ok(Encrypted { ciphertext, metadata: w.metadata })
        })
    }

    /// `encrypt` into the caller's memory, for a caller that must see the
    /// sizes first (the C API's size query). `admit` gets them after every
    /// check, before the key is touched or randomness drawn, and returns the
    /// region the ciphertext goes to (at least `sizes.artifact` bytes); its
    /// error ends the call. Sizes and ciphertext come from one lookup of the
    /// key, so a concurrent change to it cannot make the result larger than
    /// what was admitted.
    pub fn encrypt_admitting<'b, E: From<Error>>(
        &self,
        req: EncryptRequest,
        enc: MetadataEncoding,
        admit: impl FnOnce(Sizes) -> Result<&'b mut [u8], E>,
    ) -> Result<Written, E> {
        self.with_encrypt(req, |r, req| {
            let cipher = r.cipher()?;
            let shape =
                Self::metadata(r.version().number(), cipher.output_shape(r.algorithm())?, req.user_context.clone());
            let out = admit(Sizes {
                artifact: cipher.ciphertext_len(r.algorithm(), req.plaintext.len())?,
                metadata: metadata::encode(&shape, enc)?.len(),
            })?;
            Ok(Self::encrypt_resolved(&r, req, out)?)
        })
    }

    /// The encoded length of metadata that carries no provider output
    /// (decryption, verification).
    pub(super) fn metadata_len(
        version: u32,
        user_context: &BTreeMap<String, String>,
        enc: MetadataEncoding,
    ) -> Result<usize, Error> {
        Ok(metadata::encode(&Self::metadata(version, no_output(), user_context.clone()), enc)?.len())
    }

    /// `with_resolved` for an encryption, which gets the request back.
    fn with_encrypt<R, E: From<Error>>(
        &self,
        req: EncryptRequest,
        then: impl FnOnce(Resolved<'_>, EncryptRequest) -> Result<R, E>,
    ) -> Result<R, E> {
        non_empty(req.plaintext, "plaintext")?;
        let (op, declared) = (Operation::Encrypt, api::CryptoOperation::Encrypt);
        self.with_resolved(req.key_name, None, Direction::Originating, op, declared, |r| {
            Self::check_encrypt_params(&r, &req.params)?;
            then(r, req)
        })
    }

    fn encrypt_resolved(r: &Resolved<'_>, req: EncryptRequest, out: &mut [u8]) -> Result<Written, Error> {
        let (len, output) = r.cipher()?.encrypt_into(r.material()?, r.algorithm(), req.plaintext, &req.params, out)?;
        require_output(&output)?;
        Ok(Written { len, metadata: Self::metadata(r.version().number(), output, req.user_context) })
    }

    /// `with_resolved` for a decryption, which gets the request back.
    fn with_decrypt<R, E: From<Error>>(
        &self,
        req: DecryptRequest,
        then: impl FnOnce(Resolved<'_>, DecryptRequest) -> Result<R, E>,
    ) -> Result<R, E> {
        non_empty(req.ciphertext, "ciphertext")?;
        if req.metadata.key_version == 0 {
            let e = Error::new(Code::InvalidArgument, "CryptoOrchestrator", "the metadata names no key version");
            return Err(e.into());
        }
        let (op, declared) = (Operation::Decrypt, api::CryptoOperation::Decrypt);
        let version = Some(req.metadata.key_version);
        self.with_resolved(req.key_name, version, Direction::Receiving, op, declared, |r| {
            Self::check_encrypt_params(&r, &req.params)?;
            then(r, req)
        })
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
    #[cfg_attr(not(test), allow(dead_code, reason = "for Rust callers; the C API sizes first (*_admitting)"))]
    pub fn decrypt(&self, req: DecryptRequest) -> Result<Decrypted, Error> {
        self.with_decrypt(req, |r, req| {
            let bound = r.cipher()?.plaintext_len_bound(r.algorithm(), req.ciphertext.len())?;
            let mut plaintext = SecretVec::from(vec![0; bound]);
            let w = Self::decrypt_resolved(&r, req, &mut plaintext)?;
            plaintext.truncate(w.len);
            Ok(Decrypted { plaintext, metadata: w.metadata })
        })
    }

    /// `decrypt` into the caller's memory, for a caller that must see the
    /// sizes first, as `encrypt_admitting`. The plaintext size is a bound;
    /// the metadata's is measured in `enc`, or 0 when the caller does not
    /// want it back. On any failure the region `admit` returned is
    /// untouched: the provider decides every failure before it writes.
    ///
    /// A decryption's metadata does not depend on the plaintext, so it is
    /// encoded here, before decrypting, and handed to `admit` with the
    /// sizes: nothing that could fail is left for after the plaintext is
    /// written.
    pub fn decrypt_admitting<'b, E: From<Error>>(
        &self,
        req: DecryptRequest,
        enc: Option<MetadataEncoding>,
        admit: impl FnOnce(Sizes, Option<Vec<u8>>) -> Result<&'b mut [u8], E>,
    ) -> Result<Written, E> {
        self.with_decrypt(req, |r, req| {
            let encoded = match enc {
                Some(enc) => {
                    let md = Self::metadata(r.version().number(), no_output(), req.user_context.clone());
                    Some(metadata::encode(&md, enc)?)
                }
                None => None,
            };
            let sizes = Sizes {
                artifact: r.cipher()?.plaintext_len_bound(r.algorithm(), req.ciphertext.len())?,
                metadata: encoded.as_ref().map_or(0, Vec::len),
            };
            let out = admit(sizes, encoded)?;
            Ok(Self::decrypt_resolved(&r, req, out)?)
        })
    }

    fn decrypt_resolved(r: &Resolved, req: DecryptRequest, out: &mut [u8]) -> Result<Written, Error> {
        let output = req
            .metadata
            .provider_output
            .as_ref()
            .ok_or_else(|| Error::new(Code::InvalidArgument, "CryptoOrchestrator", "the metadata has no provider output"))?;
        let len = r.cipher()?.decrypt_into(r.material()?, r.algorithm(), req.ciphertext, output, &req.params, out)?;
        Ok(Written { len, metadata: Self::metadata(r.version().number(), no_output(), req.user_context) })
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
pub(super) mod tests {
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
        let templates = InMemoryTemplateRegistry::standard();
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
        let (mut sizes, mut buf) = (None, [0u8; 64]);
        let written = w
            .crypto
            .encrypt_admitting(req, MetadataEncoding::WireV1, |z| {
                sizes = Some(z);
                Ok::<_, Error>(&mut buf[..])
            })
            .unwrap();
        let e = Encrypted { ciphertext: buf[..written.len].to_vec(), metadata: written.metadata };
        let sizes = sizes.expect("admit saw the sizes");
        assert_eq!(sizes.artifact, e.ciphertext.len());
        assert_eq!(sizes.metadata, metadata::encode(&e.metadata, MetadataEncoding::WireV1).unwrap().len(), "exact");
        assert_eq!((e.metadata.key_version, e.metadata.api_version.as_str()), (1, API_VERSION));
        assert_eq!(e.metadata.user_context.get("tenant").map(String::as_str), Some("acme"));

        let d = w.crypto.decrypt(decrypt("k", &e, aead())).unwrap();
        assert_eq!(&*d.plaintext, b"hello");
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
        assert_eq!(&*w.crypto.decrypt(decrypt("k", &old, aead())).unwrap().plaintext, b"before");
        assert_eq!(&*w.crypto.decrypt(decrypt("k", &new, aead())).unwrap().plaintext, b"after");
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
        assert_eq!(&*w.crypto.decrypt(decrypt("cbc", &e, EncryptParams::None)).unwrap().plaintext, b"block cipher");
    }

    #[test]
    fn lifecycle_and_policy_apply() {
        let w = world();
        create(&w, "k", AEAD);
        let e = w.crypto.encrypt(encrypt("k", b"x", aead())).unwrap();

        // A suspended key decrypts what exists but encrypts nothing new.
        let mut k = Arc::unwrap_or_clone(w.repo.get_by_name("k").unwrap().unwrap());
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

    /// Counts lookups. Every *_admitting operation must size and run from
    /// one lookup: with two, a concurrent change to the key between them
    /// (e.g. a transform to a longer-signature algorithm) produced output
    /// larger than the caller's admitted buffer (D1).
    pub(in crate::app) struct Counting {
        pub(in crate::app) inner: Arc<InMemoryKeyRepository>,
        pub(in crate::app) lookups: std::sync::atomic::AtomicUsize,
    }

    impl KeyRepository for Counting {
        fn create(&self, k: crate::domain::key::Key) -> Result<crate::domain::key::Key, Error> {
            self.inner.create(k)
        }
        fn update(&self, k: crate::domain::key::Key) -> Result<crate::domain::key::Key, Error> {
            self.inner.update(k)
        }
        fn get_by_id(&self, id: &crate::domain::key::KeyId) -> Result<Option<Arc<Key>>, Error> {
            self.inner.get_by_id(id)
        }
        fn get_by_name(&self, name: &str) -> Result<Option<Arc<Key>>, Error> {
            self.lookups.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.inner.get_by_name(name)
        }
        fn inspect_by_name(&self, name: &str, f: &mut dyn FnMut(&Key)) -> Result<(), Error> {
            self.lookups.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.inner.inspect_by_name(name, f)
        }
        fn delete(&self, id: &crate::domain::key::KeyId) -> Result<(), Error> {
            self.inner.delete(id)
        }
        fn list(&self) -> Result<Vec<Arc<Key>>, Error> {
            self.inner.list()
        }
    }

    #[test]
    fn resolving_borrows_the_stored_key() {
        let w = world();
        create(&w, "k", AEAD);
        let (op, declared) = (Operation::Encrypt, api::CryptoOperation::Encrypt);
        let stored = w.repo.get_by_name("k").unwrap().unwrap();
        w.crypto
            .with_resolved("k", None, Direction::Originating, op, declared, |r| {
                assert!(std::ptr::eq(r.key, &*stored), "no copy of the key, its versions or their material");
                assert!(std::ptr::eq(r.version(), stored.current()));
                Ok::<(), Error>(())
            })
            .unwrap();
        let nothing = |_: Resolved<'_>| Ok::<(), Error>(());
        let missing = w.crypto.with_resolved("nope", None, Direction::Originating, op, declared, nothing);
        assert_eq!(missing.unwrap_err().code(), Code::KeyNotFound);
    }

    #[test]
    fn sizing_and_the_operation_share_one_lookup() {
        let w = world();
        create(&w, "k", AEAD);
        let counting = Arc::new(Counting { inner: w.repo.clone(), lookups: Default::default() });
        let mut registry = ProviderRegistry::new();
        registry.register(Arc::new(RustCrypto)).unwrap();
        let crypto = CryptoOrchestrator::new(
            counting.clone(),
            InMemoryTemplateRegistry::standard(),
            Arc::new(registry),
            w.policy.clone(),
        );
        let lookups = || counting.lookups.swap(0, std::sync::atomic::Ordering::Relaxed);
        let mut buf = [0u8; 64];
        let w = crypto
            .encrypt_admitting(encrypt("k", b"x", aead()), MetadataEncoding::Protobuf, |_| Ok::<_, Error>(&mut buf[..]))
            .unwrap();
        assert_eq!(lookups(), 1, "encrypt");
        let e = Encrypted { ciphertext: buf[..w.len].to_vec(), metadata: w.metadata };
        let (mut out, md) = ([0u8; 64], Some(MetadataEncoding::Protobuf));
        crypto.decrypt_admitting(decrypt("k", &e, aead()), md, |_, _| Ok::<_, Error>(&mut out[..])).unwrap();
        assert_eq!(lookups(), 1, "decrypt");
    }
}
