use std::collections::BTreeMap;

use super::crypto_orchestrator::{CryptoOrchestrator, Direction, Resolved, no_output, non_empty, require_output};
use crate::domain::core::{Code, Error, Operation, Scope, hash_output_len};
use crate::domain::crypto::metadata::{self, MetadataEncoding};
use crate::domain::provider::SignContext;
use crate::proto::api::{self, HashAlgorithm, SignatureScope};

const OP: &str = "CryptoOrchestrator";

/// What is signed: a message the provider hashes (Sign), or a digest the
/// caller computed (DigestSign).
#[derive(Clone, Copy)]
pub enum SignInput<'a> {
    Message(&'a [u8]),
    Digest { digest: &'a [u8], hash: HashAlgorithm },
}

impl SignInput<'_> {
    fn operations(&self, verify: bool) -> (Operation, api::CryptoOperation) {
        match (self, verify) {
            (SignInput::Message(_), false) => (Operation::Sign, api::CryptoOperation::Sign),
            (SignInput::Message(_), true) => (Operation::Verify, api::CryptoOperation::Verify),
            (SignInput::Digest { .. }, false) => (Operation::DigestSign, api::CryptoOperation::DigestSign),
            (SignInput::Digest { .. }, true) => (Operation::DigestVerify, api::CryptoOperation::DigestVerify),
        }
    }

    /// The request-shape rules, before any lookup: a message is not empty; a
    /// digest names its hash and has that hash's length. The length check
    /// is what stops a SHA-1 digest passing as SHA-256 past a policy
    /// (agc_digest_sign_request), so it is the core's, not a provider's.
    fn check(&self) -> Result<(), Error> {
        match *self {
            SignInput::Message(m) => non_empty(m, "message"),
            SignInput::Digest { digest, hash } => {
                if hash == HashAlgorithm::Unspecified {
                    return Err(Error::new(Code::InvalidArgument, OP, "the digest's hash algorithm is required"));
                }
                let Some(len) = hash_output_len(hash) else {
                    return Err(Error::new(
                        Code::InvalidArgument,
                        OP,
                        format!("{hash:?} has no fixed digest length; digest signing needs one"),
                    ));
                };
                if digest.len() != len {
                    return Err(Error::new(
                        Code::InvalidArgument,
                        OP,
                        format!("a {hash:?} digest has {len} bytes, not {}", digest.len()),
                    ));
                }
                Ok(())
            }
        }
    }
}

/// A sign or digest-sign request (agc_sign, agc_digest_sign).
pub struct SignRequest<'a> {
    pub key_name: &'a str,
    pub input: SignInput<'a>,
    pub context: SignContext,
    pub user_context: BTreeMap<String, String>,
}

pub struct Signed {
    pub signature: Vec<u8>,
    pub metadata: api::OperationMetadata,
}

/// A verify or digest-verify request (agc_verify, agc_digest_verify).
pub struct VerifyRequest<'a> {
    pub key_name: &'a str,
    pub input: SignInput<'a>,
    pub signature: &'a [u8],
    /// The version the signing metadata names; `None` is the current one.
    pub key_version: Option<u32>,
    pub context: SignContext,
    pub user_context: BTreeMap<String, String>,
}

/// The outcome of a verification that could be evaluated. `valid == false`
/// is the cryptographic answer, not an error (Go's rule); the FFI layer
/// turns it into AGC_ERR_CRYPTO_SIGNATURE_INVALID as well.
pub struct Verified {
    pub valid: bool,
    pub metadata: api::OperationMetadata,
}

impl CryptoOrchestrator {
    /// The parameters must fit the version's scope (Go:
    /// validateSignatureScopeParams): a context exactly for the WITH_CONTEXT
    /// scopes, and the entry point (message or digest) the scope is for.
    fn check_sign_params(r: &Resolved, input: &SignInput, context: &SignContext) -> Result<(), Error> {
        let scope = r.version.scope_spec().scope;
        let (prehashed, with_context) = match scope {
            Scope::Signature(SignatureScope::Standard) => (false, false),
            Scope::Signature(SignatureScope::WithContext) => (false, true),
            Scope::Signature(SignatureScope::Prehashed) => (true, false),
            Scope::Signature(SignatureScope::PrehashedWithContext) => (true, true),
            other => {
                return Err(Error::new(
                    Code::KeyOperationNotAllowed,
                    OP,
                    format!("a key of scope {other:?} does not sign"),
                ));
            }
        };
        let digest = matches!(input, SignInput::Digest { .. });
        if prehashed != digest {
            return Err(Error::new(
                Code::KeyOperationNotAllowed,
                OP,
                format!("a key of scope {scope:?} signs {}", if prehashed { "digests" } else { "messages" }),
            ));
        }
        if with_context != matches!(context, SignContext::Domain(_)) {
            return Err(Error::new(
                Code::InvalidArgument,
                OP,
                format!("a key of scope {scope:?} takes {} domain context", if with_context { "a" } else { "no" }),
            ));
        }
        Ok(())
    }

    fn resolve_sign(
        &self,
        key_name: &str,
        version: Option<u32>,
        input: &SignInput,
        context: &SignContext,
        verify: bool,
    ) -> Result<Resolved, Error> {
        input.check()?;
        let (op, declared) = input.operations(verify);
        let direction = if verify { Direction::Receiving } else { Direction::Originating };
        let (_, r) = self.resolve(key_name, version, direction, op, declared)?;
        Self::check_sign_params(&r, input, context)?;
        if let SignInput::Digest { digest, hash } = *input {
            r.signer()?.check_digest(r.algorithm(), digest, hash)?;
        }
        Ok(r)
    }

    /// What `sign` needs room for: the longest signature, and the encoded
    /// metadata exactly. No key material, no randomness.
    pub fn sign_sizes(&self, req: &SignRequest, enc: MetadataEncoding) -> Result<(usize, usize), Error> {
        let r = self.resolve_sign(req.key_name, None, &req.input, &req.context, false)?;
        let signer = r.signer()?;
        let md = Self::metadata(r.version.number(), signer.output_shape(r.algorithm())?, req.user_context.clone());
        Ok((signer.signature_len_bound(r.algorithm())?, metadata::encode(&md, enc)?.len()))
    }

    /// Signs with the key's current version (Go: Sign, DigestSign).
    pub fn sign(&self, req: SignRequest) -> Result<Signed, Error> {
        let r = self.resolve_sign(req.key_name, None, &req.input, &req.context, false)?;
        let signer = r.signer()?;
        let key = r.material()?;
        let (signature, output) = match req.input {
            SignInput::Message(m) => signer.sign(&key, r.algorithm(), m, &req.context)?,
            SignInput::Digest { digest, hash } => {
                signer.sign_digest(&key, r.algorithm(), digest, hash, &req.context)?
            }
        };
        require_output(&output)?;
        if signature.len() > signer.signature_len_bound(r.algorithm())? {
            return Err(Error::new(Code::ProviderContractViolation, OP, "the signature exceeds the provider's bound"));
        }
        Ok(Signed { signature, metadata: Self::metadata(r.version.number(), output, req.user_context) })
    }

    /// The encoded length of the verification's metadata.
    pub fn verify_sizes(&self, req: &VerifyRequest, enc: MetadataEncoding) -> Result<usize, Error> {
        let r = self.resolve_sign(req.key_name, req.key_version, &req.input, &req.context, true)?;
        let md = Self::metadata(r.version.number(), no_output(), req.user_context.clone());
        Ok(metadata::encode(&md, enc)?.len())
    }

    /// Verifies against the version the metadata names, or the current one
    /// (Go: Verify, DigestVerify).
    pub fn verify(&self, req: VerifyRequest) -> Result<Verified, Error> {
        non_empty(req.signature, "signature")?;
        let r = self.resolve_sign(req.key_name, req.key_version, &req.input, &req.context, true)?;
        let signer = r.signer()?;
        let key = r.material()?;
        let valid = match req.input {
            SignInput::Message(m) => signer.verify(&key, r.algorithm(), m, req.signature, &req.context)?,
            SignInput::Digest { digest, hash } => {
                signer.verify_digest(&key, r.algorithm(), digest, hash, req.signature, &req.context)?
            }
        };
        Ok(Verified { valid, metadata: Self::metadata(r.version.number(), no_output(), req.user_context) })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sha2::Digest;

    use super::*;
    use crate::adapters::providers::RustCrypto;
    use crate::adapters::storage::{InMemoryKeyRepository, InMemoryPolicyRepository, InMemoryTemplateRegistry};
    use crate::app::{KeyOrchestrator, TransformSpec};
    use crate::domain::core::{KeyCreationSpec, ProviderRequirements, ScopeSpecification};
    use crate::domain::key::KeyRepository;
    use crate::domain::policy::{Enforcer, Manager};
    use crate::domain::provider::ProviderRegistry;

    const POLICY: &str = r#"{"version": "1",
        "allowed_templates": ["ed25519", "ecdsa-p256-prehashed-der", "ml-dsa-44", "aes-256-gcm-128-96"],
        "allowed_operations": {"key_operations":
            ["create_key", "sign", "verify", "digest_sign", "digest_verify", "encrypt"]}}"#;

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

    fn create(w: &World, name: &str, template: &str, scope: SignatureScope) {
        w.keys
            .create_key(KeyCreationSpec {
                name: name.into(),
                policy: "p".into(),
                template_id: Some(template.into()),
                scope_spec: ScopeSpecification::any_of(Scope::Signature(scope)),
                provider_id: None,
                provider_requirements: ProviderRequirements::default(),
            })
            .unwrap();
    }

    fn sign<'a>(name: &'a str, input: SignInput<'a>, context: SignContext) -> SignRequest<'a> {
        SignRequest { key_name: name, input, context, user_context: BTreeMap::new() }
    }

    fn verify<'a>(name: &'a str, input: SignInput<'a>, s: &'a Signed, context: SignContext) -> VerifyRequest<'a> {
        VerifyRequest {
            key_name: name,
            input,
            signature: &s.signature,
            key_version: Some(s.metadata.key_version),
            context,
            user_context: BTreeMap::new(),
        }
    }

    fn code<T>(r: Result<T, Error>) -> Code {
        r.err().expect("an error").code()
    }

    #[test]
    #[cfg_attr(miri, ignore = "third-party signing is too slow under Miri")]
    fn sign_and_verify_with_metadata() {
        let w = world();
        create(&w, "k", "ed25519", SignatureScope::Standard);
        let mut req = sign("k", SignInput::Message(b"hello"), SignContext::None);
        req.user_context.insert("tenant".into(), "acme".into());
        let (bound, md_len) = w.crypto.sign_sizes(&req, MetadataEncoding::Protobuf).unwrap();
        let s = w.crypto.sign(req).unwrap();
        assert_eq!(bound, s.signature.len(), "Ed25519 signatures have one length");
        assert_eq!(md_len, metadata::encode(&s.metadata, MetadataEncoding::Protobuf).unwrap().len(), "exact");
        assert_eq!(s.metadata.provider_output.as_ref().unwrap().encoding, "raw");

        let v = w.crypto.verify(verify("k", SignInput::Message(b"hello"), &s, SignContext::None)).unwrap();
        assert!(v.valid);
        assert_eq!(v.metadata.key_version, 1);
        let v = w.crypto.verify(verify("k", SignInput::Message(b"hellO"), &s, SignContext::None)).unwrap();
        assert!(!v.valid, "a wrong message is invalid, not an error");
    }

    #[test]
    #[cfg_attr(miri, ignore = "third-party signing is too slow under Miri")]
    fn verification_uses_the_named_version_or_the_current_one() {
        let w = world();
        create(&w, "k", "ed25519", SignatureScope::Standard);
        let old = w.crypto.sign(sign("k", SignInput::Message(b"m"), SignContext::None)).unwrap();
        w.keys
            .transform_key(TransformSpec { key_name: "k".into(), retain: false, scope_spec: None, template_id: None })
            .unwrap();
        let mut req = verify("k", SignInput::Message(b"m"), &old, SignContext::None);
        assert!(w.crypto.verify(req).unwrap().valid, "version 1 still verifies");
        req = verify("k", SignInput::Message(b"m"), &old, SignContext::None);
        req.key_version = None;
        let v = w.crypto.verify(req).unwrap();
        assert!(!v.valid && v.metadata.key_version == 2, "the latest version is a different key");
        req = verify("k", SignInput::Message(b"m"), &old, SignContext::None);
        req.key_version = Some(9);
        assert_eq!(code(w.crypto.verify(req)), Code::KeyNotFound);
    }

    #[test]
    #[cfg_attr(miri, ignore = "third-party signing is too slow under Miri")]
    fn digest_sign_checks_the_declared_hash() {
        let w = world();
        create(&w, "pre", "ecdsa-p256-prehashed-der", SignatureScope::Prehashed);
        let digest = sha2::Sha384::digest(b"m");
        let input = SignInput::Digest { digest: &digest, hash: HashAlgorithm::Sha384 };
        let (bound, _) = w.crypto.sign_sizes(&sign("pre", input, SignContext::None), MetadataEncoding::WireV1).unwrap();
        let s = w.crypto.sign(sign("pre", input, SignContext::None)).unwrap();
        assert!(s.signature.len() <= bound);
        assert_eq!(s.metadata.provider_output.as_ref().unwrap().encoding, "der");
        assert!(w.crypto.verify(verify("pre", input, &s, SignContext::None)).unwrap().valid);
        // The same bytes declared as another hash do not verify: the hash is bound.
        let as512 = SignInput::Digest { digest: &digest, hash: HashAlgorithm::Sha512 };
        assert_eq!(code(w.crypto.verify(verify("pre", as512, &s, SignContext::None))), Code::InvalidArgument);

        let short = SignInput::Digest { digest: &digest[..32], hash: HashAlgorithm::Sha384 };
        assert_eq!(code(w.crypto.sign(sign("pre", short, SignContext::None))), Code::InvalidArgument);
        let sha1 = [0u8; 20];
        #[allow(deprecated)]
        let weak = SignInput::Digest { digest: &sha1, hash: HashAlgorithm::Sha1 };
        assert_eq!(
            code(w.crypto.sign_sizes(&sign("pre", weak, SignContext::None), MetadataEncoding::WireV1)),
            Code::InvalidArgument
        );
        let unspecified = SignInput::Digest { digest: &digest, hash: HashAlgorithm::Unspecified };
        assert_eq!(code(w.crypto.sign(sign("pre", unspecified, SignContext::None))), Code::InvalidArgument);
        let xof = SignInput::Digest { digest: &digest, hash: HashAlgorithm::Shake256 };
        assert_eq!(code(w.crypto.sign(sign("pre", xof, SignContext::None))), Code::InvalidArgument);
    }

    #[test]
    #[cfg_attr(miri, ignore = "third-party signing is too slow under Miri")]
    fn the_scope_decides_entry_point_and_context() {
        let w = world();
        create(&w, "ed", "ed25519", SignatureScope::Standard);
        create(&w, "pre", "ecdsa-p256-prehashed-der", SignatureScope::Prehashed);
        create(&w, "ml", "ml-dsa-44", SignatureScope::Standard);
        create(&w, "mlctx", "ml-dsa-44", SignatureScope::WithContext);
        let digest = sha2::Sha256::digest(b"m");
        let d = SignInput::Digest { digest: &digest, hash: HashAlgorithm::Sha256 };
        let m = SignInput::Message(b"m");
        let ctx = || SignContext::Domain(b"app".to_vec());

        // The template does not declare the other entry point.
        assert_eq!(code(w.crypto.sign(sign("ed", d, SignContext::None))), Code::KeyOperationNotAllowed);
        assert_eq!(code(w.crypto.sign(sign("pre", m, SignContext::None))), Code::KeyOperationNotAllowed);
        // A context exactly for the WITH_CONTEXT scope.
        assert_eq!(code(w.crypto.sign(sign("ml", m, ctx()))), Code::InvalidArgument);
        assert_eq!(code(w.crypto.sign(sign("mlctx", m, SignContext::None))), Code::InvalidArgument);
        let s = w.crypto.sign(sign("mlctx", m, ctx())).unwrap();
        assert!(w.crypto.verify(verify("mlctx", m, &s, ctx())).unwrap().valid);
        let other = SignContext::Domain(b"other".to_vec());
        assert!(!w.crypto.verify(verify("mlctx", m, &s, other)).unwrap().valid);
    }

    #[test]
    #[cfg_attr(miri, ignore = "third-party signing is too slow under Miri")]
    fn lifecycle_policy_and_key_kind_apply() {
        let w = world();
        create(&w, "k", "ed25519", SignatureScope::Standard);
        let s = w.crypto.sign(sign("k", SignInput::Message(b"m"), SignContext::None)).unwrap();

        // A suspended key verifies what exists but signs nothing new.
        let mut k = w.repo.get_by_name("k").unwrap().unwrap();
        k.transition(api::KeyLifecycleState::Suspended, std::time::SystemTime::now()).unwrap();
        w.repo.update(k).unwrap();
        assert_eq!(
            code(w.crypto.sign(sign("k", SignInput::Message(b"m"), SignContext::None))),
            Code::KeyOperationNotAllowed
        );
        assert!(w.crypto.verify(verify("k", SignInput::Message(b"m"), &s, SignContext::None)).unwrap().valid);

        // Verification is its own policy operation.
        w.policy
            .update_policy(
                "p",
                r#"{"version": "1", "allowed_templates": ["ed25519"],
                    "allowed_operations": {"key_operations": ["create_key", "sign"]}}"#,
            )
            .unwrap();
        assert_eq!(
            code(w.crypto.verify(verify("k", SignInput::Message(b"m"), &s, SignContext::None))),
            Code::PolicyViolation
        );

        // An encryption key does not sign.
        w.policy.update_policy("p", POLICY).unwrap();
        w.keys
            .create_key(KeyCreationSpec {
                name: "aead".into(),
                policy: "p".into(),
                template_id: None,
                scope_spec: ScopeSpecification::any_of(Scope::Aead(api::AeadScope::Unspecified)),
                provider_id: None,
                provider_requirements: ProviderRequirements::default(),
            })
            .unwrap();
        assert_eq!(
            code(w.crypto.sign(sign("aead", SignInput::Message(b"m"), SignContext::None))),
            Code::KeyOperationNotAllowed
        );
    }

    #[test]
    fn request_shape_is_checked_first() {
        let w = world();
        assert_eq!(
            code(w.crypto.sign(sign("nope", SignInput::Message(b""), SignContext::None))),
            Code::InvalidArgument
        );
        assert_eq!(code(w.crypto.sign(sign("nope", SignInput::Message(b"m"), SignContext::None))), Code::KeyNotFound);
        let s = Signed { signature: vec![], metadata: Default::default() };
        assert_eq!(
            code(w.crypto.verify(verify("nope", SignInput::Message(b"m"), &s, SignContext::None))),
            Code::InvalidArgument
        );
    }
}
