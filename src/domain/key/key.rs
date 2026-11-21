use std::fmt::Debug;
use std::sync::Arc;
use std::time::SystemTime;

use crate::domain::core::{Code, Error, ProviderState, ScopeKind, ScopeSpecification, new_id};
use crate::proto::api::HashAlgorithm;
use crate::proto::api::KeyLifecycleState as State;
use crate::secret::SecretBytes;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyId(String);

impl KeyId {
    pub fn new(id: impl Into<String>) -> Self {
        KeyId(id.into())
    }

    /// A fresh, globally unique id.
    pub fn generate() -> Self {
        KeyId(new_id("key_"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Where a version's material came from, and what may still be done with
/// it. Material that was not extractable, or lost its approved lineage,
/// never regains either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// The material may leave its provider in plaintext (stored by the core
    /// or exported). Needed to move it to another provider.
    pub extractable: bool,
    /// Generated, and only ever held, by approved (FIPS) modules.
    pub approved_lineage: bool,
    pub origin: Origin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    Generated,
    Imported,
    /// The previous version's material, kept by the same provider.
    Retained { source_version: u32 },
    /// Another version's material, moved to another provider.
    Transferred { source_version: u32, source_provider: String },
}

/// One version of a key's material: the template and provider that
/// produced it, the intent it serves, and the material itself, opaque to
/// everyone but that provider.
#[derive(Clone)]
pub struct Version {
    number: u32,
    template_id: String,
    provider: String,
    scope_spec: ScopeSpecification,
    /// Held as a secret, and shared by every clone of the version (and so
    /// of the key).
    material: SecretBytes,
    /// What the version's provider keeps with it (opaque to the domain).
    provider_state: Arc<ProviderState>,
    provenance: Provenance,
    created_at: SystemTime,
}

impl Version {
    /// The material comes already held as a secret: how (locked or not,
    /// `require_locked_memory`) is the caller's choice, not the model's.
    pub fn new(
        number: u32,
        template_id: String,
        provider: String,
        scope_spec: ScopeSpecification,
        material: SecretBytes,
        provenance: Provenance,
        created_at: SystemTime,
    ) -> Self {
        let provider_state = Arc::default();
        Version { number, template_id, provider, scope_spec, material, provider_state, provenance, created_at }
    }

    pub fn number(&self) -> u32 {
        self.number
    }

    pub fn template_id(&self) -> &str {
        &self.template_id
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn scope_spec(&self) -> &ScopeSpecification {
        &self.scope_spec
    }

    pub fn material(&self) -> &[u8] {
        &self.material
    }

    /// Whether this version signs digests made with `hash`: only the hashes
    /// it recorded when it was created (Go: validateDigestHash).
    pub fn check_digest_hash(&self, hash: HashAlgorithm) -> Result<(), Error> {
        const OP: &str = "Version::check_digest_hash";
        let accepted = &self.scope_spec.properties.accepted_digest_hashes;
        if accepted.is_empty() {
            let msg = format!("key version {} records no accepted digest hash", self.number);
            return Err(Error::new(Code::Internal, OP, msg));
        }
        if !accepted.contains(&hash) {
            let msg = format!(
                "key version {} does not accept digest hash {hash:?} (accepted: {accepted:?})",
                self.number
            );
            return Err(Error::new(Code::InvalidArgument, OP, msg));
        }
        Ok(())
    }

    pub fn provider_state(&self) -> &ProviderState {
        &self.provider_state
    }

    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    pub fn created_at(&self) -> SystemTime {
        self.created_at
    }
}

impl Debug for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.debug_struct("Version")
            .field("number", &self.number)
            .field("template_id", &self.template_id)
            .field("provider", &self.provider)
            .field("provenance", &self.provenance)
            .finish_non_exhaustive()
    }
}

/// The Key aggregate: a named key bound to one policy and one kind of
/// intent, with its versions. Invariants (Go: `key.Key`, `key.Version`):
/// - a key has at least one version; versions are numbered 1, 2, ... and
///   the last one is current;
/// - every version serves the key's kind;
/// - the lifecycle follows NIST SP 800-57 (`transition`).
#[derive(Clone, Debug)]
pub struct Key {
    id: KeyId,
    name: String,
    policy: String,
    kind: ScopeKind,
    state: State,
    versions: Vec<Version>,
    created_at: SystemTime,
    updated_at: SystemTime,
    /// Bumped by the repository on every write; an update based on an older
    /// revision is refused (`Code::ConcurrentAccess`).
    revision: u64,
}

impl Key {
    /// A new, ACTIVE key whose first version is `first`.
    pub fn new(id: KeyId, name: &str, policy: &str, first: Version) -> Result<Key, Error> {
        const OP: &str = "Key::new";
        if name.is_empty() || policy.is_empty() {
            return Err(Error::new(Code::InvalidArgument, OP, "a key needs a name and a policy"));
        }
        if first.number != 1 {
            return Err(Error::new(Code::InvalidArgument, OP, "a key's first version is version 1"));
        }
        Ok(Key {
            id,
            name: name.to_owned(),
            policy: policy.to_owned(),
            kind: first.scope_spec.scope.kind(),
            state: State::Active,
            created_at: first.created_at,
            updated_at: first.created_at,
            versions: vec![first],
            revision: 0,
        })
    }

    /// A key as a store recorded it, for storage adapters only. The same
    /// invariants as `new` and `add_version` are checked, so a damaged or
    /// edited record is refused rather than trusted: versions numbered 1, 2,
    /// ... in order and all of the key's kind, and a name and a policy.
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        id: KeyId,
        name: &str,
        policy: &str,
        state: State,
        versions: Vec<Version>,
        created_at: SystemTime,
        updated_at: SystemTime,
        revision: u64,
    ) -> Result<Key, Error> {
        const OP: &str = "Key::restore";
        let mut versions = versions.into_iter();
        let first = versions.next().ok_or_else(|| Error::new(Code::Internal, OP, "a stored key has no version"))?;
        let mut k = Key::new(id, name, policy, first).map_err(|e| Error::new(Code::Internal, OP, e.message().to_owned()))?;
        for v in versions {
            k.add_version(v).map_err(|e| Error::new(Code::Internal, OP, e.message().to_owned()))?;
        }
        k.state = state;
        k.created_at = created_at;
        k.updated_at = updated_at;
        k.revision = revision;
        Ok(k)
    }

    pub fn id(&self) -> &KeyId {
        &self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn policy(&self) -> &str {
        &self.policy
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn created_at(&self) -> SystemTime {
        self.created_at
    }

    pub fn updated_at(&self) -> SystemTime {
        self.updated_at
    }

    pub fn current(&self) -> &Version {
        self.versions.last().expect("a key always has a version")
    }

    /// Every version, oldest first.
    pub fn versions(&self) -> &[Version] {
        &self.versions
    }

    /// Version `n`, 1-based.
    pub fn version(&self, n: u32) -> Option<&Version> {
        n.checked_sub(1).and_then(|i| self.versions.get(i as usize))
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// For repositories: moves this copy to the revision it is stored under
    /// next. A new key (`stored` is `None`) gets revision 1. A changed key
    /// must still be at the revision of `stored`, the copy now in the store,
    /// and gets the one after; a stale copy is refused (`ConcurrentAccess`),
    /// so two concurrent changes cannot silently overwrite each other.
    pub fn advance_revision(&mut self, op: &'static str, stored: Option<&Key>) -> Result<(), Error> {
        match stored {
            None => self.revision = 1,
            Some(s) if s.id == self.id && s.revision == self.revision => self.revision += 1,
            Some(s) if s.id != self.id => {
                return Err(Error::new(Code::Internal, op, format!("key {} is not key {}", self.name, s.name)));
            }
            Some(_) => {
                let msg = format!("key {} changed since it was read; retry", self.name);
                return Err(Error::new(Code::ConcurrentAccess, op, msg));
            }
        }
        Ok(())
    }

    /// Appends the next version, which becomes current. Only an ACTIVE key
    /// gets new versions (Go: `CanRotate`).
    pub fn add_version(&mut self, v: Version) -> Result<(), Error> {
        const OP: &str = "Key::add_version";
        self.require(self.state == State::Active, "add a version")?;
        if v.number != self.current().number + 1 {
            return Err(Error::new(Code::InvalidArgument, OP, format!("next version is {}", self.current().number + 1)));
        }
        if v.scope_spec.scope.kind() != self.kind {
            return Err(Error::new(Code::InvalidArgument, OP, "a key's versions all serve its kind"));
        }
        self.updated_at = v.created_at;
        self.versions.push(v);
        Ok(())
    }

    /// Moves the key to `to` if NIST SP 800-57 allows it from its state.
    #[cfg_attr(not(test), expect(dead_code, reason = "G30: reachable once Go implements UpdateKeyState"))]
    pub fn transition(&mut self, to: State, now: SystemTime) -> Result<(), Error> {
        use State::*;
        let allowed: &[State] = match self.state {
            PreActive => &[Active, Destroyed],
            Active => &[Suspended, Deactivated, Compromised],
            Suspended => &[Active, Deactivated, Compromised],
            Deactivated => &[Destroyed, Compromised],
            Compromised => &[Destroyed, DestroyedCompromised],
            Destroyed | DestroyedCompromised | Unspecified => &[],
        };
        if !allowed.contains(&to) {
            return Err(Error::new(
                Code::KeyOperationNotAllowed,
                "Key::transition",
                format!("key {} cannot go from {:?} to {to:?}", self.name, self.state),
            ));
        }
        self.state = to;
        self.updated_at = now;
        Ok(())
    }

    /// Sign, encrypt, wrap: only an ACTIVE key.
    pub fn can_originate(&self) -> Result<(), Error> {
        self.require(self.state == State::Active, "originate (sign, encrypt, wrap)")
    }

    /// Verify, decrypt, unwrap: also SUSPENDED and DEACTIVATED keys, so that
    /// existing signatures and ciphertexts stay usable.
    pub fn can_receive(&self) -> Result<(), Error> {
        self.require(
            matches!(self.state, State::Active | State::Suspended | State::Deactivated),
            "receive (verify, decrypt, unwrap)",
        )
    }

    #[cfg_attr(not(test), expect(dead_code, reason = "G30: reachable once Go implements UpdateKeyState"))]
    pub fn is_terminal(&self) -> bool {
        matches!(self.state, State::Destroyed | State::DestroyedCompromised)
    }

    fn require(&self, ok: bool, what: &str) -> Result<(), Error> {
        if ok {
            return Ok(());
        }
        Err(Error::new(
            Code::KeyOperationNotAllowed,
            "Key",
            format!("key {} is {:?} and cannot {what}", self.name, self.state),
        ))
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::domain::core::Scope;
    use crate::proto::api::AeadScope;

    pub fn version(n: u32) -> Version {
        Version::new(
            n,
            "aes-256-gcm-128-96".into(),
            "fake".into(),
            ScopeSpecification::any_of(Scope::Aead(AeadScope::Standard)),
            SecretBytes::new_with(&[n as u8; 32], crate::secret::Locking::BestEffort).unwrap(),
            Provenance { extractable: true, approved_lineage: false, origin: Origin::Generated },
            SystemTime::UNIX_EPOCH,
        )
    }

    pub fn key(id: &str, name: &str) -> Key {
        Key::new(KeyId::new(id), name, "p", version(1)).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{key, version};
    use super::*;
    use crate::domain::core::Scope;
    use crate::proto::api::SignatureScope;

    #[test]
    fn a_version_signs_only_the_digest_hashes_it_recorded() {
        let mut spec = ScopeSpecification::any_of(Scope::Signature(SignatureScope::Prehashed));
        spec.properties.accepted_digest_hashes = vec![HashAlgorithm::Sha384];
        let v = Version::new(
            1,
            "t".into(),
            "p".into(),
            spec,
            SecretBytes::new_with(&[1; 32], crate::secret::Locking::BestEffort).unwrap(),
            Provenance { extractable: false, approved_lineage: false, origin: Origin::Generated },
            SystemTime::UNIX_EPOCH,
        );
        assert!(v.check_digest_hash(HashAlgorithm::Sha384).is_ok());
        assert_eq!(v.check_digest_hash(HashAlgorithm::Sha256).unwrap_err().code(), Code::InvalidArgument);
        assert_eq!(version(1).check_digest_hash(HashAlgorithm::Sha256).unwrap_err().code(), Code::Internal);
    }

    #[test]
    fn revisions_advance_one_at_a_time_and_refuse_stale_copies() {
        let mut k = key("k1", "a");
        assert_eq!(k.revision(), 0);
        k.advance_revision("t", None).unwrap();
        assert_eq!(k.revision(), 1);
        let stored = k.clone();
        let mut stale = k.clone();
        k.advance_revision("t", Some(&stored)).unwrap();
        assert_eq!(k.revision(), 2);
        assert_eq!(stale.advance_revision("t", Some(&k)).unwrap_err().code(), Code::ConcurrentAccess);
        assert_eq!(stale.revision(), 1, "a refused copy keeps its revision");
        let other = key("k2", "b");
        assert_eq!(k.advance_revision("t", Some(&other)).unwrap_err().code(), Code::Internal);
    }

    #[test]
    fn a_new_key_is_active_at_version_1() {
        let k = key("k1", "n");
        assert_eq!((k.state(), k.current().number()), (State::Active, 1));
        assert!(Key::new(KeyId::new("k"), "n", "p", version(2)).is_err());
        assert!(Key::new(KeyId::new("k"), "", "p", version(1)).is_err());
    }

    #[test]
    fn versions_are_contiguous_and_of_the_keys_kind() {
        let mut k = key("k1", "n");
        assert!(k.add_version(version(3)).is_err());
        k.add_version(version(2)).unwrap();
        assert_eq!(k.current().number(), 2);
        assert_eq!(k.version(1).unwrap().number(), 1);
        assert!(k.version(0).is_none() && k.version(3).is_none());

        let mut sig = version(3);
        sig.scope_spec = ScopeSpecification::any_of(Scope::Signature(SignatureScope::Standard));
        assert!(k.add_version(sig).is_err());
    }

    #[test]
    fn lifecycle_follows_nist_sp_800_57() {
        let now = SystemTime::UNIX_EPOCH;
        let mut k = key("k1", "n");
        k.transition(State::Suspended, now).unwrap();
        assert!(k.can_originate().is_err() && k.can_receive().is_ok());
        assert_eq!(k.add_version(version(2)).unwrap_err().code(), Code::KeyOperationNotAllowed);
        k.transition(State::Active, now).unwrap();
        k.transition(State::Deactivated, now).unwrap();
        assert!(k.can_receive().is_ok());
        assert!(k.transition(State::Active, now).is_err(), "no way back from DEACTIVATED");
        k.transition(State::Compromised, now).unwrap();
        assert!(k.can_receive().is_err());
        k.transition(State::DestroyedCompromised, now).unwrap();
        assert!(k.is_terminal());
        for to in [State::Active, State::Destroyed, State::Compromised] {
            assert_eq!(k.transition(to, now).unwrap_err().code(), Code::KeyOperationNotAllowed);
        }
    }

    #[test]
    fn debug_never_shows_material() {
        let s = format!("{:?}", key("k1", "n"));
        assert!(!s.contains("material"), "{s}");
    }
}
