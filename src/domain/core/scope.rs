use std::collections::BTreeMap;

use super::{Code, Error};
use crate::proto::api::{self, scope_specification::ScopeSpec};

/// The kind of intent a key serves: the primitive family whose scopes it can
/// be used for. Every key is created for exactly one kind. In the order of
/// Go's `core.Scope`; the proto's asymmetric-encryption family is not one
/// (Go has no such scope), so it is refused where it enters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScopeKind {
    Signature,
    Aead,
    Mac,
    Kem,
    KeyAgreement,
    Kdf,
    Hash,
    KeyWrapping,
    SymmetricCipher,
    DiskEncryption,
    GenericSecret,
}

/// An intent with fixed operation-time inputs and outputs, e.g. "sign a
/// message" (`Signature(Standard)`) or "sign a digest" (`Signature(Prehashed)`).
/// The family's `Unspecified` value means "any scope of this kind".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    Signature(api::SignatureScope),
    Aead(api::AeadScope),
    Mac(api::MacScope),
    Kem(api::KemScope),
    KeyAgreement(api::KeyAgreementScope),
    Kdf(api::KdfScope),
    Hash(api::HashScope),
    KeyWrapping(api::KeyWrappingScope),
    SymmetricCipher(api::SymmetricCipherScope),
    DiskEncryption(api::DiskEncryptionScope),
    GenericSecret(api::GenericSecretScope),
}

impl Scope {
    pub fn kind(&self) -> ScopeKind {
        match self {
            Scope::Signature(_) => ScopeKind::Signature,
            Scope::Aead(_) => ScopeKind::Aead,
            Scope::Mac(_) => ScopeKind::Mac,
            Scope::Kem(_) => ScopeKind::Kem,
            Scope::KeyAgreement(_) => ScopeKind::KeyAgreement,
            Scope::Kdf(_) => ScopeKind::Kdf,
            Scope::Hash(_) => ScopeKind::Hash,
            Scope::KeyWrapping(_) => ScopeKind::KeyWrapping,
            Scope::SymmetricCipher(_) => ScopeKind::SymmetricCipher,
            Scope::DiskEncryption(_) => ScopeKind::DiskEncryption,
            Scope::GenericSecret(_) => ScopeKind::GenericSecret,
        }
    }

    /// The family's `Unspecified` value: any scope of this kind.
    pub fn is_any(&self) -> bool {
        self.value() == 0
    }

    /// The proto enum value within the family.
    pub fn value(&self) -> i32 {
        match *self {
            Scope::Signature(s) => s as i32,
            Scope::Aead(s) => s as i32,
            Scope::Mac(s) => s as i32,
            Scope::Kem(s) => s as i32,
            Scope::KeyAgreement(s) => s as i32,
            Scope::Kdf(s) => s as i32,
            Scope::Hash(s) => s as i32,
            Scope::KeyWrapping(s) => s as i32,
            Scope::SymmetricCipher(s) => s as i32,
            Scope::DiskEncryption(s) => s as i32,
            Scope::GenericSecret(s) => s as i32,
        }
    }

    /// Every scope, in the order of Go's `core.Scope` (core.ListScopes):
    /// what ListScopes returns them in.
    pub const ALL: [Scope; 28] = {
        use api::*;
        [
            Scope::Signature(SignatureScope::Standard),
            Scope::Signature(SignatureScope::WithContext),
            Scope::Signature(SignatureScope::Prehashed),
            Scope::Signature(SignatureScope::PrehashedWithContext),
            Scope::Aead(AeadScope::Standard),
            Scope::Aead(AeadScope::Deterministic),
            Scope::Aead(AeadScope::Streaming),
            Scope::Mac(MacScope::Standard),
            Scope::Mac(MacScope::Streaming),
            Scope::Kem(KemScope::Standard),
            Scope::Kem(KemScope::Hybrid),
            Scope::KeyAgreement(KeyAgreementScope::Standard),
            Scope::KeyAgreement(KeyAgreementScope::Hybrid),
            Scope::Kdf(KdfScope::ExtractExpand),
            Scope::Kdf(KdfScope::Password),
            Scope::Kdf(KdfScope::Agreement),
            Scope::Kdf(KdfScope::Counter),
            Scope::Kdf(KdfScope::Tls),
            Scope::Kdf(KdfScope::Gost),
            Scope::Kdf(KdfScope::Vendor),
            Scope::Hash(HashScope::Standard),
            Scope::Hash(HashScope::Xof),
            Scope::KeyWrapping(KeyWrappingScope::Standard),
            Scope::KeyWrapping(KeyWrappingScope::WithPadding),
            Scope::SymmetricCipher(SymmetricCipherScope::Block),
            Scope::SymmetricCipher(SymmetricCipherScope::Stream),
            Scope::DiskEncryption(DiskEncryptionScope::Standard),
            Scope::GenericSecret(GenericSecretScope::Standard),
        ]
    };

    /// The scope's name, as Go's `core.Scope.String()` gives it; `None` for
    /// a family's "any" value, which is not a scope.
    pub fn name(&self) -> Option<&'static str> {
        const NAMES: [&str; 28] = [
            "signature_standard",
            "signature_with_context",
            "signature_prehashed",
            "signature_prehashed_with_context",
            "aead_standard",
            "aead_deterministic",
            "aead_streaming",
            "mac_standard",
            "mac_streaming",
            "kem_standard",
            "kem_hybrid",
            "key_agreement_standard",
            "key_agreement_hybrid",
            "kdf_extract_expand",
            "kdf_password",
            "kdf_agreement",
            "kdf_counter",
            "kdf_tls",
            "kdf_gost",
            "kdf_vendor",
            "hash_standard",
            "hash_xof",
            "key_wrapping_standard",
            "key_wrapping_with_padding",
            "symmetric_cipher_block",
            "symmetric_cipher_stream",
            "disk_encryption_standard",
            "generic_secret_standard",
        ];
        Scope::ALL.iter().position(|s| s == self).map(|i| NAMES[i])
    }

    /// Whether a template or key serving `self` serves the scope `want`:
    /// same kind, and the same scope unless `want` is any scope of the kind.
    pub fn serves(&self, want: &Scope) -> bool {
        self.kind() == want.kind() && (want.is_any() || self == want)
    }
}

/// `UniversalSecurityProperties`. On the request side every field is a
/// filter (0 / Unspecified / None mean "don't care"); on a template it is
/// what the algorithm provides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SecurityProperties {
    pub strength_bits: u32,
    pub nist_level: api::NistSecurityLevel,
    pub quantum_safe: Option<bool>,
    pub nist_status: api::NistStatus,
    pub fips_approved: Option<bool>,
}

/// Properties that only some scope kinds have. Each is a filter on the
/// request side and a fact on a template; one that does not apply to the
/// scope's kind is ignored.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PrimitiveProperties {
    pub non_malleable: Option<bool>,
    pub deterministic: Option<bool>,
    pub nonce_misuse_resistant: Option<bool>,
    pub forward_secrecy: Option<bool>,
    pub memory_hard: Option<bool>,
    /// Digest hashes a prehashed signature scope accepts, preferred first.
    /// Template: what it can sign; request: a requirement (every entry must
    /// be accepted); key version: what it accepts. Empty for other scopes.
    pub accepted_digest_hashes: Vec<api::HashAlgorithm>,
}

/// What a caller asks for (as a filter), or what a template offers: a scope
/// plus the properties that narrow it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeSpecification {
    pub scope: Scope,
    pub security: Option<SecurityProperties>,
    pub properties: PrimitiveProperties,
    pub additional: BTreeMap<String, String>,
}

impl ScopeSpecification {
    /// Any scope of `kind`, with no further requirements.
    pub fn any_of(scope: Scope) -> Self {
        ScopeSpecification {
            scope,
            security: None,
            properties: PrimitiveProperties::default(),
            additional: BTreeMap::new(),
        }
    }

    /// Whether `self`, as offered by a template, satisfies the filter `want`.
    /// The rules of Go's `template.MatchesScope`:
    /// - the scope serves `want.scope` (same kind; same scope unless any);
    /// - security: if `want` has any, `self` must have them; integers are
    ///   minimums, a wanted `true` must be `true`, a wanted status must equal;
    /// - primitive properties: a wanted `true` must be `true`;
    /// - additional properties: every wanted pair must be present.
    pub fn satisfies(&self, want: &ScopeSpecification) -> bool {
        self.scope.serves(&want.scope)
            && security_satisfies(self.security.as_ref(), want.security.as_ref())
            && properties_satisfy(&self.properties, &want.properties)
            && want.additional.iter().all(|(k, v)| self.additional.get(k) == Some(v))
    }

    /// From the API message. Unknown enum values are rejected: this is where
    /// numbers from outside become domain values.
    pub fn from_proto(p: &api::ScopeSpecification) -> Result<Self, Error> {
        const OP: &str = "ScopeSpecification::from_proto";
        let spec = p
            .scope_spec
            .as_ref()
            .ok_or_else(|| Error::new(Code::InvalidArgument, OP, "scope specification has no scope"))?;

        fn known<E: TryFrom<i32>>(v: i32, what: &str) -> Result<E, Error> {
            E::try_from(v).map_err(|_| Error::new(Code::InvalidArgument, OP, format!("unknown {what} {v}")))
        }
        let mut props = PrimitiveProperties::default();
        let (scope, security, additional) = match spec {
            ScopeSpec::Signature(s) => {
                props.non_malleable = s.non_malleable;
                props.deterministic = s.deterministic;
                props.accepted_digest_hashes = s
                    .accepted_digest_hashes
                    .iter()
                    .map(|&h| known(h, "accepted digest hash"))
                    .collect::<Result<_, _>>()?;
                (Scope::Signature(known(s.scope, "signature scope")?), &s.security, &s.additional_properties)
            }
            ScopeSpec::Aead(s) => {
                props.nonce_misuse_resistant = s.nonce_misuse_resistant;
                (Scope::Aead(known(s.scope, "AEAD scope")?), &s.security, &s.additional_properties)
            }
            ScopeSpec::Mac(s) => (Scope::Mac(known(s.scope, "MAC scope")?), &s.security, &s.additional_properties),
            ScopeSpec::Kem(s) => (Scope::Kem(known(s.scope, "KEM scope")?), &s.security, &s.additional_properties),
            ScopeSpec::KeyAgreement(s) => {
                props.forward_secrecy = s.forward_secrecy;
                (Scope::KeyAgreement(known(s.scope, "key agreement scope")?), &s.security, &s.additional_properties)
            }
            ScopeSpec::Kdf(s) => {
                props.memory_hard = s.memory_hard;
                (Scope::Kdf(known(s.scope, "KDF scope")?), &s.security, &s.additional_properties)
            }
            ScopeSpec::Hash(s) => (Scope::Hash(known(s.scope, "hash scope")?), &s.security, &s.additional_properties),
            ScopeSpec::KeyWrapping(s) => {
                (Scope::KeyWrapping(known(s.scope, "key wrapping scope")?), &s.security, &s.additional_properties)
            }
            ScopeSpec::SymmetricCipher(s) => (
                Scope::SymmetricCipher(known(s.scope, "symmetric cipher scope")?),
                &s.security,
                &s.additional_properties,
            ),
            ScopeSpec::GenericSecret(s) => {
                (Scope::GenericSecret(known(s.scope, "generic secret scope")?), &s.security, &s.additional_properties)
            }
            ScopeSpec::DiskEncryption(s) => {
                (Scope::DiskEncryption(known(s.scope, "disk encryption scope")?), &s.security, &s.additional_properties)
            }
            // Go's core.ScopeFromProto knows no asymmetric-encryption scope.
            ScopeSpec::AsymmetricEncryption(_) => {
                return Err(Error::new(Code::InvalidArgument, OP, "unrecognized scope: asymmetric encryption"));
            }
        };
        let security = security
            .as_ref()
            .map(|s| {
                Ok::<_, Error>(SecurityProperties {
                    strength_bits: s.security_strength_bits,
                    nist_level: known(s.nist_security_level, "NIST security level")?,
                    quantum_safe: s.quantum_safe,
                    nist_status: known(s.nist_status, "NIST status")?,
                    fips_approved: s.fips_approved,
                })
            })
            .transpose()?;
        Ok(ScopeSpecification {
            scope,
            security,
            properties: props,
            additional: additional.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        })
    }
}

fn wanted_true_is_true(got: Option<bool>, want: Option<bool>) -> bool {
    want != Some(true) || got == Some(true)
}

fn security_satisfies(got: Option<&SecurityProperties>, want: Option<&SecurityProperties>) -> bool {
    let Some(want) = want else { return true };
    let Some(got) = got else { return false };
    wanted_true_is_true(got.fips_approved, want.fips_approved)
        && wanted_true_is_true(got.quantum_safe, want.quantum_safe)
        && (want.nist_level == api::NistSecurityLevel::Unspecified || got.nist_level as i32 >= want.nist_level as i32)
        && got.strength_bits >= want.strength_bits
        && (want.nist_status == api::NistStatus::Unspecified || got.nist_status == want.nist_status)
}

fn properties_satisfy(got: &PrimitiveProperties, want: &PrimitiveProperties) -> bool {
    wanted_true_is_true(got.non_malleable, want.non_malleable)
        && wanted_true_is_true(got.deterministic, want.deterministic)
        && wanted_true_is_true(got.nonce_misuse_resistant, want.nonce_misuse_resistant)
        && wanted_true_is_true(got.forward_secrecy, want.forward_secrecy)
        && wanted_true_is_true(got.memory_hard, want.memory_hard)
        // A requested digest-hash list is a requirement (Go: matcher.go).
        && want.accepted_digest_hashes.iter().all(|h| got.accepted_digest_hashes.contains(h))
}

#[cfg(test)]
mod tests {
    use super::*;
    use api::{AeadScope, NistSecurityLevel, NistStatus, SignatureScope};

    fn sig(s: SignatureScope) -> ScopeSpecification {
        ScopeSpecification::any_of(Scope::Signature(s))
    }

    fn with_security(mut spec: ScopeSpecification, sec: SecurityProperties) -> ScopeSpecification {
        spec.security = Some(sec);
        spec
    }

    // Ported from citius-core template/matcher_test.go, TestMatchesScope_tabledriven.

    #[test]
    fn exact_scope_matches() {
        assert!(sig(SignatureScope::Standard).satisfies(&sig(SignatureScope::Standard)));
    }

    #[test]
    fn other_scope_of_the_same_kind_does_not_match() {
        assert!(!sig(SignatureScope::Standard).satisfies(&sig(SignatureScope::Prehashed)));
    }

    #[test]
    fn other_kind_does_not_match() {
        let aead = ScopeSpecification::any_of(Scope::Aead(AeadScope::Standard));
        assert!(!sig(SignatureScope::Standard).satisfies(&aead));
    }

    #[test]
    fn unspecified_scope_matches_any_scope_of_the_kind() {
        // Go's zero ScopeSpecification matches across kinds; the C API always
        // names a kind, so "any" here means any scope of that kind.
        assert!(sig(SignatureScope::Prehashed).satisfies(&sig(SignatureScope::Unspecified)));
        let any_aead = ScopeSpecification::any_of(Scope::Aead(AeadScope::Unspecified));
        assert!(!sig(SignatureScope::Prehashed).satisfies(&any_aead));
    }

    // Ported from TestMatchesScope_securityFilters_tabledriven.

    fn offered() -> ScopeSpecification {
        with_security(
            sig(SignatureScope::Standard),
            SecurityProperties {
                strength_bits: 128,
                nist_level: NistSecurityLevel::NistSecurityLevel3,
                quantum_safe: Some(true),
                nist_status: NistStatus::Approved,
                fips_approved: Some(false),
            },
        )
    }

    #[test]
    fn security_filter_without_template_security_does_not_match() {
        let want = with_security(sig(SignatureScope::Standard), SecurityProperties::default());
        assert!(!sig(SignatureScope::Standard).satisfies(&want));
    }

    #[test]
    fn security_integers_are_minimums() {
        let at = |bits, level| {
            with_security(
                sig(SignatureScope::Standard),
                SecurityProperties { strength_bits: bits, nist_level: level, ..Default::default() },
            )
        };
        assert!(offered().satisfies(&at(128, NistSecurityLevel::NistSecurityLevel3)));
        assert!(offered().satisfies(&at(112, NistSecurityLevel::NistSecurityLevel1)));
        assert!(!offered().satisfies(&at(192, NistSecurityLevel::Unspecified)));
        assert!(!offered().satisfies(&at(0, NistSecurityLevel::NistSecurityLevel5)));
    }

    #[test]
    fn wanted_true_must_be_true_wanted_false_is_no_filter() {
        let want = |qs, fips| {
            with_security(
                sig(SignatureScope::Standard),
                SecurityProperties { quantum_safe: qs, fips_approved: fips, ..Default::default() },
            )
        };
        assert!(offered().satisfies(&want(Some(true), None)));
        assert!(!offered().satisfies(&want(None, Some(true))));
        assert!(offered().satisfies(&want(Some(false), Some(false))));
    }

    #[test]
    fn wanted_status_must_be_equal() {
        let want = |status| {
            with_security(
                sig(SignatureScope::Standard),
                SecurityProperties { nist_status: status, ..Default::default() },
            )
        };
        assert!(offered().satisfies(&want(NistStatus::Approved)));
        assert!(!offered().satisfies(&want(NistStatus::Recommended)));
    }

    #[test]
    fn primitive_property_wanted_true_must_be_true() {
        let mut got = sig(SignatureScope::Standard);
        got.properties.deterministic = Some(true);
        let mut want = sig(SignatureScope::Standard);
        want.properties.deterministic = Some(true);
        assert!(got.satisfies(&want));
        want.properties.non_malleable = Some(true);
        assert!(!got.satisfies(&want));
    }

    #[test]
    fn additional_properties_must_all_be_present() {
        let mut got = sig(SignatureScope::Standard);
        got.additional.insert("vendor".into(), "x".into());
        let mut want = sig(SignatureScope::Standard);
        assert!(got.satisfies(&want));
        want.additional.insert("vendor".into(), "x".into());
        assert!(got.satisfies(&want));
        want.additional.insert("vendor".into(), "y".into());
        assert!(!got.satisfies(&want));
    }

    #[test]
    fn from_proto_rejects_unknown_values_and_missing_scope() {
        use api::scope_specification::ScopeSpec;
        let bad = api::ScopeSpecification {
            scope_spec: Some(ScopeSpec::Signature(api::SignatureScopeSpec { scope: 99, ..Default::default() })),
        };
        assert_eq!(ScopeSpecification::from_proto(&bad).unwrap_err().code(), Code::InvalidArgument);
        let empty = api::ScopeSpecification { scope_spec: None };
        assert_eq!(ScopeSpecification::from_proto(&empty).unwrap_err().code(), Code::InvalidArgument);
    }
}

#[cfg(test)]
mod go_scope_tests {
    use super::*;

    /// Go's core.Scope: every scope once, in order, each named, no "any".
    #[test]
    fn all_scopes_are_go_s_in_go_s_order() {
        let names: Vec<&str> = Scope::ALL.iter().map(|s| s.name().expect("named")).collect();
        assert_eq!(names.len(), 28);
        assert_eq!((names[0], names[27]), ("signature_standard", "generic_secret_standard"));
        let mut unique = names.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 28, "names are unique");
        assert!(Scope::ALL.iter().all(|s| !s.is_any()));
        assert_eq!(Scope::Signature(api::SignatureScope::Unspecified).name(), None);
        // Kinds appear in contiguous runs, in ScopeKind order.
        let kinds: Vec<ScopeKind> = Scope::ALL.iter().map(Scope::kind).collect();
        let mut runs = kinds.clone();
        runs.dedup();
        assert_eq!(runs.len(), 11, "each kind once, contiguously");
    }

    #[test]
    fn asymmetric_encryption_is_not_a_scope() {
        let p = api::ScopeSpecification {
            scope_spec: Some(ScopeSpec::AsymmetricEncryption(api::AsymmetricEncryptionScopeSpec {
                scope: api::AsymmetricEncryptionScope::Standard as i32,
                ..Default::default()
            })),
        };
        assert_eq!(ScopeSpecification::from_proto(&p).unwrap_err().code(), Code::InvalidArgument);
    }
}
