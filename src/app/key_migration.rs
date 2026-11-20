use std::sync::Arc;
use std::time::SystemTime;

use super::key_orchestrator::{approved, not_found, security_info};
use super::{KeyMetadata, KeyOrchestrator, TransformSpec};
use crate::domain::core::{Code, Error, Operation};
use crate::domain::key::{Key, Origin, Provenance, Version};
use crate::domain::provider::{Backend, Requirements, StoredKey, transfer_of};
use crate::domain::template::Template;
use crate::proto::api::{self, MigrationStrategy as Strategy};

/// Where a key should go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrateTarget {
    /// A provider by its registered name.
    Instance(String),
    /// The first provider of this kind that qualifies (Go: provider type).
    ProviderKind(String),
    /// Any provider other than the current one (assessments only).
    Any,
}

/// What a migration asks for (Go: MigrateKeySpec). A migration keeps the
/// key's template and scope: only custody changes.
#[derive(Debug, Clone)]
pub struct MigrateSpec {
    pub key_name: String,
    pub target: MigrateTarget,
    pub strategy: Strategy,
}

/// The outcome of a migration (Go: MigrationResult).
#[derive(Debug, Clone)]
pub struct MigrationResult {
    pub key: KeyMetadata,
    pub strategy: Strategy,
    /// The material moved unchanged (PROVIDER_SWITCH).
    pub key_bytes_preserved: bool,
    pub source_kind: String,
    pub source_instance: String,
    /// The version that stays on the source provider; for REKEY_AND_ARCHIVE
    /// it is the archived material, addressed by the key's name and number.
    #[cfg_attr(not(test), expect(dead_code, reason = "Go's MigrationResult.SourceVersion; the C response has no field for it"))]
    pub source_version: u32,
    pub target_kind: String,
    pub target_instance: String,
    pub target_implementation: api::ImplementationProperties,
}

/// One strategy assessed for a key (Go: StrategyAssessment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrategyAssessment {
    pub strategy: Strategy,
    pub feasible: bool,
    /// Why not, if not.
    pub reason: String,
    pub target_instance: Option<String>,
    /// What the strategy implies for the key's material and the data it
    /// protects, whether or not it is feasible (Go: SecurityNotes).
    pub security_notes: Vec<String>,
}

/// A migration pre-flight (Go: MigrationValidation).
#[derive(Debug, Clone)]
pub struct MigrationValidation {
    pub template_id: String,
    /// `None` when the version's provider is no longer registered.
    pub source_kind: Option<String>,
    pub source_instance: String,
    pub extractable: bool,
    pub source_implementation: Option<api::ImplementationProperties>,
    pub options: Vec<StrategyAssessment>,
    /// `Unspecified` when no assessed strategy is feasible.
    pub recommended: Strategy,
    pub recommendation_reason: String,
}

const STRATEGIES: [Strategy; 5] = [
    Strategy::ProviderSwitch,
    Strategy::ExtractAndImport,
    Strategy::WrappedTransfer,
    Strategy::RekeyAndArchive,
    Strategy::RekeyAndDestroy,
];

/// What each strategy implies, word for word as Go's strategySecurityNotes
/// (citius-core service/key_migrate_validate.go). None for a transform.
fn security_notes(s: Strategy) -> Vec<String> {
    let notes: &[&str] = match s {
        Strategy::ProviderSwitch => &[
            "the same material stays in the key's earlier version on the source provider; destroy that version to keep a single copy",
        ],
        Strategy::ExtractAndImport => &["the material leaves the source provider in plaintext"],
        Strategy::WrappedTransfer => &["the material leaves the source provider only encrypted under a transport key"],
        Strategy::RekeyAndArchive => &[
            "new material: the public key changes",
            "data the current version protects stays usable only through that version, on the source provider",
        ],
        Strategy::RekeyAndDestroy => &[
            "new material: the public key changes",
            "data the current version protects becomes unusable once it is destroyed",
        ],
        _ => &[],
    };
    notes.iter().map(|n| (*n).to_owned()).collect()
}

/// The strategies `migrate_key` carries out (as in Go).
fn implemented(s: Strategy) -> bool {
    matches!(s, Strategy::ProviderSwitch | Strategy::RekeyAndArchive)
}

fn transfers_material(s: Strategy) -> bool {
    matches!(s, Strategy::ProviderSwitch | Strategy::ExtractAndImport | Strategy::WrappedTransfer)
}

fn not_feasible(msg: String) -> Error {
    Error::new(Code::MigrationNotFeasible, "KeyOrchestrator::migrate_key", msg)
}

/// What every strategy of a key's migration starts from (Go: migration).
struct Migration {
    key: Key,
    version: Version,
    template: Template,
    /// `None` when the version's provider is no longer registered.
    source: Option<Arc<dyn Backend>>,
}

impl KeyOrchestrator {
    /// Moves a key to another provider (Go: MigrateKey), adding a version
    /// there with the same template and scope:
    /// - PROVIDER_SWITCH copies the stored material unchanged. The version
    ///   must be extractable, and the source must release and the target
    ///   accept the material's encoding.
    /// - REKEY_AND_ARCHIVE generates new material on the target. The previous
    ///   version stays on its provider for data it protects.
    ///
    /// The other strategies are not implemented (as in Go). `admit` is
    /// checked before anything is stored.
    pub fn migrate_key_admitting<E: From<Error>>(
        &self,
        spec: MigrateSpec,
        admit: impl FnOnce(&MigrationResult) -> Result<(), E>,
    ) -> Result<MigrationResult, E> {
        const OP: &str = "KeyOrchestrator::migrate_key";
        if matches!(spec.target, MigrateTarget::Any) {
            return Err(Error::new(Code::InvalidArgument, OP, "a migration needs a target").into());
        }
        check_strategy(spec.strategy)?;
        if !implemented(spec.strategy) {
            return Err(Error::new(Code::NotImplemented, OP, format!("{:?} is not implemented", spec.strategy)).into());
        }
        let Migration { mut key, version, template, source } = self.load_migration(&spec.key_name)?;
        let target = self.check_migration(&key, &version, &template, source.as_ref(), &spec)?;
        let algorithm = template.info().algorithm.as_ref().expect("templates always have an algorithm");

        let (material, provenance, preserved) = match spec.strategy {
            Strategy::ProviderSwitch => {
                let was = version.provenance();
                let provenance = Provenance {
                    extractable: was.extractable && transfer_of(target.as_ref(), algorithm).releases_material(),
                    approved_lineage: was.approved_lineage && approved(target.as_ref()),
                    origin: Origin::Transferred {
                        source_version: version.number(),
                        source_provider: version.provider().to_owned(),
                    },
                };
                (zeroize::Zeroizing::new(version.material().to_vec()), provenance, true)
            }
            _ => {
                let provenance = Provenance {
                    extractable: transfer_of(target.as_ref(), algorithm).releases_material(),
                    approved_lineage: approved(target.as_ref()),
                    origin: Origin::Generated,
                };
                (target.generate_key(algorithm)?.to_bytes(), provenance, false)
            }
        };
        key.add_version(Version::new(
            version.number() + 1,
            template.id().to_owned(),
            target.name().to_owned(),
            version.scope_spec().clone(),
            material,
            provenance,
            SystemTime::now(),
            self.locking,
        )?)?;
        let result = MigrationResult {
            key: KeyMetadata::of(&key, key.current(), &self.providers),
            strategy: spec.strategy,
            key_bytes_preserved: preserved,
            source_kind: source.as_ref().map_or_else(String::new, |s| s.kind().to_owned()),
            source_instance: version.provider().to_owned(),
            source_version: version.number(),
            target_kind: target.kind().to_owned(),
            target_instance: target.name().to_owned(),
            target_implementation: target.implementation(),
        };
        admit(&result)?;
        // Fails with CONCURRENT_ACCESS if the key changed since it was read.
        self.keys.update(key)?;
        Ok(result)
    }

    #[cfg(test)]
    pub fn migrate_key(&self, spec: MigrateSpec) -> Result<MigrationResult, Error> {
        self.migrate_key_admitting(spec, |_| Ok::<(), Error>(()))
    }

    /// Assesses migrating a key to `target` with each strategy, or just
    /// `strategy` (Go: ValidateMigration): what `migrate_key` would refuse,
    /// and why, with no side effect. Recommends a feasible strategy.
    pub fn validate_migration(
        &self,
        key_name: &str,
        target: MigrateTarget,
        strategy: Option<Strategy>,
    ) -> Result<MigrationValidation, Error> {
        let strategies = match strategy {
            Some(s) => {
                check_strategy(s)?;
                vec![s]
            }
            None => STRATEGIES.to_vec(),
        };
        let Migration { key, version, template, source } = self.load_migration(key_name)?;
        let mut options = Vec::new();
        for s in strategies {
            let spec = MigrateSpec { key_name: key_name.to_owned(), target: target.clone(), strategy: s };
            let o = match self.check_migration(&key, &version, &template, source.as_ref(), &spec) {
                Ok(_) if !implemented(s) => StrategyAssessment {
                    strategy: s,
                    feasible: false,
                    reason: format!("{s:?} is not implemented"),
                    target_instance: None,
                    security_notes: security_notes(s),
                },
                Ok(t) => StrategyAssessment {
                    strategy: s,
                    feasible: true,
                    reason: String::new(),
                    target_instance: Some(t.name().to_owned()),
                    security_notes: security_notes(s),
                },
                // Refusals become reasons; anything else is a failure to assess.
                Err(e) if is_refusal(e.code()) => StrategyAssessment {
                    strategy: s,
                    feasible: false,
                    reason: e.message().to_owned(),
                    target_instance: None,
                    security_notes: security_notes(s),
                },
                Err(e) => return Err(e),
            };
            options.push(o);
        }
        let (recommended, recommendation_reason) = recommend(&options);
        Ok(MigrationValidation {
            template_id: template.id().to_owned(),
            source_kind: source.as_ref().map(|s| s.kind().to_owned()),
            source_instance: version.provider().to_owned(),
            extractable: version.provenance().extractable,
            source_implementation: source.as_ref().map(|s| s.implementation()),
            options,
            recommended,
            recommendation_reason,
        })
    }

    /// Assesses a transform (the TRANSFORM intent of ValidateKeyOperation),
    /// with no side effect, as a report with one option of strategy
    /// `Unspecified`. With `retain` as a preference: if the material cannot
    /// be kept but new material can be generated, the transform is feasible
    /// and the reason says so.
    pub fn validate_transform(&self, spec: TransformSpec) -> Result<MigrationValidation, Error> {
        let key = self.keys.get_by_name(&spec.key_name)?.ok_or_else(|| not_found("validate_transform", &spec.key_name))?;
        let version = key.current();
        let source = self.providers.get(version.provider()).cloned();
        let refused = |e: Error| -> Result<String, Error> {
            if is_refusal(e.code()) || matches!(e.code(), Code::IncompatibleParameters | Code::KeyOperationNotAllowed)
                || matches!(e.code(), Code::NoMatchingTemplate | Code::TemplateNotFound | Code::TemplateDeprecated | Code::TemplateForbidden)
            {
                Ok(e.message().to_owned())
            } else {
                Err(e)
            }
        };
        let (feasible, reason, recommendation_reason) = match self.plan_transform(spec.clone()) {
            Ok(_) => (true, String::new(), String::new()),
            Err(e) => {
                let why = refused(e)?;
                if spec.retain {
                    match self.plan_transform(TransformSpec { retain: false, ..spec }) {
                        Ok(_) => (true, String::new(), format!("the material cannot be kept ({why}); new material would be generated")),
                        Err(e) => (false, refused(e)?, String::new()),
                    }
                } else {
                    (false, why, String::new())
                }
            }
        };
        Ok(MigrationValidation {
            template_id: version.template_id().to_owned(),
            source_kind: source.as_ref().map(|s| s.kind().to_owned()),
            source_instance: version.provider().to_owned(),
            extractable: version.provenance().extractable,
            source_implementation: source.as_ref().map(|s| s.implementation()),
            options: vec![StrategyAssessment {
                strategy: Strategy::Unspecified,
                feasible,
                reason,
                target_instance: None,
                security_notes: Vec::new(),
            }],
            recommended: Strategy::Unspecified,
            recommendation_reason,
        })
    }

    fn load_migration(&self, key_name: &str) -> Result<Migration, Error> {
        const OP: &str = "KeyOrchestrator::migrate_key";
        // An owned copy: the migration adds a version to it.
        let key = Arc::unwrap_or_clone(self.keys.get_by_name(key_name)?.ok_or_else(|| not_found(OP, key_name))?);
        // A migration adds a version, which only an ACTIVE key gets.
        key.can_originate()?;
        let version = key.current().clone();
        let template = self.templates.get(version.template_id()).cloned().ok_or_else(|| {
            Error::new(Code::TemplateNotFound, OP, format!("the key's template {} is gone", version.template_id()))
        })?;
        let source = self.providers.get(version.provider()).cloned();
        Ok(Migration { key, version, template, source })
    }

    /// Resolves the target and checks everything that can refuse the
    /// migration, before any side effect (Go: checkMigration).
    fn check_migration(
        &self,
        key: &Key,
        version: &Version,
        template: &Template,
        source: Option<&Arc<dyn Backend>>,
        spec: &MigrateSpec,
    ) -> Result<Arc<dyn Backend>, Error> {
        const OP: &str = "KeyOrchestrator::migrate_key";
        let source_instance = version.provider();
        if spec.target == MigrateTarget::Instance(source_instance.to_owned()) {
            return Err(not_feasible(format!("the key is already on provider {source_instance}")));
        }
        let implementation = self.policy.provider_requirements(key.policy())?;
        let custody = |name: &str| Requirements {
            template_id: template.id().to_owned(),
            pinned: Some(name.to_owned()),
            implementation,
        };
        if transfers_material(spec.strategy) && implementation.approved_generation && !version.provenance().approved_lineage
        {
            return Err(Error::new(
                Code::PolicyViolation,
                OP,
                "the policy requires material of approved lineage; this key's material is not",
            ));
        }
        // What the version and its source decide refuses the migration
        // whatever the target, so it is checked once, first.
        source_feasibility(spec.strategy, source, version, template)?;
        let candidate = |name: &str| -> Result<Arc<dyn Backend>, Error> {
            let target = self.providers.select(&custody(name))?;
            target_feasibility(spec.strategy, source, target.as_ref(), version, template)?;
            Ok(target)
        };
        let target = match &spec.target {
            MigrateTarget::Instance(name) => candidate(name)?,
            kind_or_any => {
                // Go: firstMigrationTarget. Preferred providers first, then in
                // registration order; a refused one is passed over.
                let wanted = |p: &Arc<dyn Backend>| {
                    p.name() != source_instance
                        && match kind_or_any {
                            MigrateTarget::ProviderKind(k) => p.kind() == k,
                            _ => true,
                        }
                };
                let preferred = |p: &Arc<dyn Backend>| {
                    implementation.prefer_hardware_accelerated && p.implementation().hardware_accelerated == Some(true)
                };
                let all: Vec<&Arc<dyn Backend>> = self.providers.list().iter().filter(|p| wanted(p)).collect();
                if all.is_empty() {
                    return Err(Error::new(Code::ProviderNotFound, OP, format!("no other provider of {kind_or_any:?}")));
                }
                let ranked = all.iter().filter(|p| preferred(p)).chain(all.iter().filter(|p| !preferred(p)));
                let mut passed_over = Vec::new();
                let mut found = None;
                for p in ranked {
                    match candidate(p.name()) {
                        Ok(t) => {
                            found = Some(t);
                            break;
                        }
                        Err(e) if is_refusal(e.code()) => passed_over.push(format!("{}: {}", p.name(), e.message())),
                        Err(e) => return Err(e),
                    }
                }
                found.ok_or_else(|| not_feasible(format!("no provider can take the key ({})", passed_over.join("; "))))?
            }
        };
        // A migration is authorized if creating the same key on the target is.
        self.policy.validate_operation(key.policy(), Operation::CreateKey, Some(template.id()))?;
        self.policy.check_template_security(key.policy(), &security_info(template, version.scope_spec()))?;
        Ok(target)
    }
}

fn check_strategy(s: Strategy) -> Result<(), Error> {
    if s == Strategy::Unspecified {
        return Err(Error::new(Code::InvalidArgument, "KeyOrchestrator::migrate_key", "a migration strategy is required"));
    }
    Ok(())
}

/// Codes that mean "this migration is refused" rather than "something broke".
fn is_refusal(c: Code) -> bool {
    matches!(
        c,
        Code::MigrationNotFeasible
            | Code::KeyNotExtractable
            | Code::ProviderNotFound
            | Code::ProviderIncompatible
            | Code::NoMatchingProvider
            | Code::PolicyViolation
            | Code::NotImplemented
    )
}

/// Go: sourceFeasibility. Rekeying needs nothing from the source.
fn source_feasibility(
    s: Strategy,
    source: Option<&Arc<dyn Backend>>,
    version: &Version,
    template: &Template,
) -> Result<(), Error> {
    if !transfers_material(s) {
        return Ok(());
    }
    let algorithm = template.info().algorithm.as_ref().expect("templates always have an algorithm");
    let source = source.ok_or_else(|| {
        not_feasible(format!("provider {} is not registered, so nothing vouches for its material", version.provider()))
    })?;
    let emit = transfer_of(source.as_ref(), algorithm).emit;
    match s {
        Strategy::WrappedTransfer if emit.wrapped.is_empty() => {
            return Err(not_feasible(format!("provider {} wraps no key for {}", source.name(), template.id())));
        }
        Strategy::WrappedTransfer => return Ok(()),
        _ => {}
    }
    if !version.provenance().extractable {
        return Err(Error::new(
            Code::KeyNotExtractable,
            "KeyOrchestrator::migrate_key",
            format!("version {} of the key is not extractable", version.number()),
        ));
    }
    if s == Strategy::ExtractAndImport {
        if emit.plaintext.is_empty() {
            return Err(not_feasible(format!("provider {} exports no key for {}", source.name(), template.id())));
        }
        return Ok(());
    }
    let encoding = StoredKey::parse(version.material())?.private_encoding;
    if !emit.stored_payload.contains(&encoding) {
        return Err(not_feasible(format!("provider {} does not release {encoding:?} material", source.name())));
    }
    Ok(())
}

/// Go: targetFeasibility, assuming `source_feasibility` holds.
fn target_feasibility(
    s: Strategy,
    source: Option<&Arc<dyn Backend>>,
    target: &dyn Backend,
    version: &Version,
    template: &Template,
) -> Result<(), Error> {
    let algorithm = template.info().algorithm.as_ref().expect("templates always have an algorithm");
    let accept = transfer_of(target, algorithm).accept;
    let emit = source.map(|s| transfer_of(s.as_ref(), algorithm).emit).unwrap_or_default();
    let refused = |why: String| Err(not_feasible(format!("{s:?} to provider {} is not possible: {why}", target.name())));
    match s {
        Strategy::RekeyAndArchive | Strategy::RekeyAndDestroy => Ok(()),
        Strategy::WrappedTransfer if !shares(&emit.wrapped, &accept.wrapped) => refused("no common key wrapping".into()),
        Strategy::ExtractAndImport if !shares(&emit.plaintext, &accept.plaintext) => {
            refused("no common plaintext key encoding".into())
        }
        Strategy::ProviderSwitch => {
            let encoding = StoredKey::parse(version.material())?.private_encoding;
            if accept.stored_payload.contains(&encoding) {
                Ok(())
            } else {
                refused(format!("it does not take {encoding:?} material for {}", template.id()))
            }
        }
        _ => Ok(()),
    }
}

/// Whether `a` and `b` have an element in common (Go: sharesAny).
fn shares<T: PartialEq>(a: &[T], b: &[T]) -> bool {
    a.iter().any(|x| b.contains(x))
}

/// Go: recommendMigration.
fn recommend(options: &[StrategyAssessment]) -> (Strategy, String) {
    let feasible = |s| options.iter().any(|o| o.strategy == s && o.feasible);
    if feasible(Strategy::ProviderSwitch) {
        return (
            Strategy::ProviderSwitch,
            "the key's material moves unchanged, so data it protects needs no re-encryption or re-signing".into(),
        );
    }
    if feasible(Strategy::RekeyAndArchive) {
        let mut reason = String::from(
            "new material is generated on the target, so the public key changes; \
             the current version stays on its provider for data it protects",
        );
        if options.iter().any(|o| o.strategy == Strategy::ProviderSwitch) {
            reason = format!("the key's material cannot move unchanged; {reason}");
        }
        return (Strategy::RekeyAndArchive, reason);
    }
    (Strategy::Unspecified, "none of the assessed strategies can migrate the key to the target".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::storage::{InMemoryKeyRepository, InMemoryPolicyRepository, InMemoryTemplateRegistry};
    use crate::domain::core::{KeyCreationSpec, ProviderRequirements, Scope, ScopeSpecification};
    use crate::domain::policy::{Enforcer, Manager};
    use crate::domain::provider::testing::FakeProvider;
    use crate::domain::provider::{Channels, ProviderRegistry, Transfer};
    use crate::proto::api::AeadScope;

    const POLICY: &str = r#"{"version": "1", "allowed_templates": ["chacha20-poly1305"],
        "allowed_operations": {"key_operations": ["create_key"]}}"#;

    fn orchestrator(providers: Vec<FakeProvider>) -> KeyOrchestrator {
        let enforcer = Arc::new(Enforcer::new(Arc::new(InMemoryPolicyRepository::new())));
        enforcer.create_policy("p", POLICY).unwrap();
        let mut registry = ProviderRegistry::new();
        for p in providers {
            registry.register(Arc::new(p)).unwrap();
        }
        KeyOrchestrator::new(
            Arc::new(InMemoryKeyRepository::new()),
            InMemoryTemplateRegistry::standard(),
            Arc::new(registry),
            enforcer,
        )
    }

    fn fake(name: &'static str) -> FakeProvider {
        FakeProvider::new(name, &["chacha20-poly1305"])
    }

    /// A key "k" on provider "a".
    fn with_key(ko: &KeyOrchestrator) {
        ko.create_key(KeyCreationSpec {
            name: "k".into(),
            policy: "p".into(),
            template_id: None,
            scope_spec: ScopeSpecification::any_of(Scope::Aead(AeadScope::Standard)),
            provider_id: Some("a".into()),
            provider_requirements: ProviderRequirements::default(),
        })
        .unwrap();
    }

    fn migrate(target: MigrateTarget, strategy: Strategy) -> MigrateSpec {
        MigrateSpec { key_name: "k".into(), target, strategy }
    }

    fn to(name: &str) -> MigrateTarget {
        MigrateTarget::Instance(name.into())
    }

    fn code(r: Result<MigrationResult, Error>) -> Code {
        r.unwrap_err().code()
    }

    fn stored(ko: &KeyOrchestrator) -> Arc<Key> {
        ko.keys.get_by_name("k").unwrap().unwrap()
    }

    #[test]
    fn provider_switch_moves_the_material_unchanged() {
        let ko = orchestrator(vec![fake("a"), fake("b")]);
        with_key(&ko);
        let r = ko.migrate_key(migrate(to("b"), Strategy::ProviderSwitch)).unwrap();
        assert!(r.key_bytes_preserved);
        assert_eq!((r.source_instance.as_str(), r.target_instance.as_str(), r.source_version), ("a", "b", 1));
        assert_eq!((r.key.version, r.key.provider.as_str()), (2, "b"));

        let k = stored(&ko);
        assert_eq!(k.version(1).unwrap().material(), k.current().material());
        assert_eq!(k.version(1).unwrap().provider(), "a", "the old version stays where it was");
        assert_eq!(
            k.current().provenance().origin,
            Origin::Transferred { source_version: 1, source_provider: "a".into() }
        );
    }

    #[test]
    fn rekey_and_archive_generates_on_the_target() {
        let ko = orchestrator(vec![fake("a"), fake("b")]);
        with_key(&ko);
        let r = ko.migrate_key(migrate(to("b"), Strategy::RekeyAndArchive)).unwrap();
        assert!(!r.key_bytes_preserved);
        let k = stored(&ko);
        assert_ne!(k.version(1).unwrap().material(), k.current().material());
        assert_eq!(k.current().provenance().origin, Origin::Generated);
    }

    #[test]
    fn refusals() {
        let ko = orchestrator(vec![fake("a"), fake("b")]);
        with_key(&ko);
        assert_eq!(code(ko.migrate_key(migrate(to("a"), Strategy::ProviderSwitch))), Code::MigrationNotFeasible);
        assert_eq!(code(ko.migrate_key(migrate(to("zz"), Strategy::ProviderSwitch))), Code::ProviderNotFound);
        assert_eq!(code(ko.migrate_key(migrate(to("b"), Strategy::WrappedTransfer))), Code::NotImplemented);
        assert_eq!(code(ko.migrate_key(migrate(to("b"), Strategy::Unspecified))), Code::InvalidArgument);
        assert_eq!(code(ko.migrate_key(migrate(MigrateTarget::Any, Strategy::ProviderSwitch))), Code::InvalidArgument);
        let mut missing = migrate(to("b"), Strategy::ProviderSwitch);
        missing.key_name = "nope".into();
        assert_eq!(code(ko.migrate_key(missing)), Code::KeyNotFound);
        assert_eq!(stored(&ko).current().number(), 1, "nothing was added");
    }

    #[test]
    fn material_that_cannot_leave_its_provider_stays() {
        let hsm = fake("a").with_transfer(Transfer::default()); // emits nothing
        let ko = orchestrator(vec![hsm, fake("b")]);
        with_key(&ko);
        assert!(!stored(&ko).current().provenance().extractable);
        assert_eq!(code(ko.migrate_key(migrate(to("b"), Strategy::ProviderSwitch))), Code::KeyNotExtractable);
        // New material on the target needs nothing from the source.
        ko.migrate_key(migrate(to("b"), Strategy::RekeyAndArchive)).unwrap();
    }

    #[test]
    fn the_target_must_take_the_material() {
        let picky = fake("b").with_transfer(Transfer {
            emit: Channels::default(),
            accept: Channels { stored_payload: vec![crate::domain::provider::Encoding::Pkcs8Der], ..Default::default() },
        });
        let ko = orchestrator(vec![fake("a"), picky]);
        with_key(&ko);
        let e = ko.migrate_key(migrate(to("b"), Strategy::ProviderSwitch)).unwrap_err();
        assert_eq!(e.code(), Code::MigrationNotFeasible);
        assert!(e.message().contains("Raw"), "{}", e.message());
    }

    #[test]
    fn a_fips_level_3_target_takes_no_plaintext_material() {
        let hsm = fake("hsm").with(|i| {
            i.fips_140 = Some(api::Fips140Certification { certified: true, level: 3, ..Default::default() })
        });
        let ko = orchestrator(vec![fake("a"), hsm]);
        with_key(&ko);
        assert_eq!(code(ko.migrate_key(migrate(to("hsm"), Strategy::ProviderSwitch))), Code::MigrationNotFeasible);
        // ...but it can generate the key itself.
        let r = ko.migrate_key(migrate(to("hsm"), Strategy::RekeyAndArchive)).unwrap();
        assert!(!r.key.extractable);
    }

    #[test]
    fn a_provider_kind_picks_the_first_other_qualifying_provider() {
        let ko = orchestrator(vec![fake("a"), fake("b"), fake("c")]);
        with_key(&ko);
        let r = ko.migrate_key(migrate(MigrateTarget::ProviderKind("fake".into()), Strategy::ProviderSwitch)).unwrap();
        assert_eq!(r.target_instance, "b");
        assert_eq!(
            code(ko.migrate_key(migrate(MigrateTarget::ProviderKind("hsm".into()), Strategy::ProviderSwitch))),
            Code::ProviderNotFound
        );
    }

    #[test]
    fn validation_assesses_every_strategy_without_side_effects() {
        let ko = orchestrator(vec![fake("a"), fake("b")]);
        with_key(&ko);
        let v = ko.validate_migration("k", to("b"), None).unwrap();
        assert_eq!((v.template_id.as_str(), v.source_instance.as_str(), v.extractable), ("chacha20-poly1305", "a", true));
        let feasible: Vec<_> = v.options.iter().filter(|o| o.feasible).map(|o| o.strategy).collect();
        assert_eq!(feasible, [Strategy::ProviderSwitch, Strategy::RekeyAndArchive]);
        assert!(v.options.iter().all(|o| o.feasible || !o.reason.is_empty()));
        assert_eq!(v.recommended, Strategy::ProviderSwitch);
        assert_eq!(stored(&ko).current().number(), 1, "assessing changes nothing");
    }

    #[test]
    fn validation_recommends_rekeying_when_the_material_cannot_move() {
        let ko = orchestrator(vec![fake("a").with_transfer(Transfer::default()), fake("b")]);
        with_key(&ko);
        let v = ko.validate_migration("k", MigrateTarget::Any, None).unwrap();
        assert_eq!(v.recommended, Strategy::RekeyAndArchive);
        assert!(v.recommendation_reason.starts_with("the key's material cannot move unchanged"));
        assert!(v.options.iter().all(|o| o.security_notes == security_notes(o.strategy) && !o.security_notes.is_empty()),
            "every assessed strategy carries Go's notes, feasible or not");
        let switch = v.options.iter().find(|o| o.strategy == Strategy::ProviderSwitch).unwrap();
        assert!(!switch.feasible && switch.reason.contains("not extractable"), "{}", switch.reason);
        // Only one strategy, on request.
        let one = ko.validate_migration("k", to("b"), Some(Strategy::RekeyAndArchive)).unwrap();
        assert_eq!(one.options.len(), 1);
    }

    #[test]
    fn planning_a_transform_changes_nothing() {
        let ko = orchestrator(vec![fake("a")]);
        with_key(&ko);
        let spec = TransformSpec { key_name: "k".into(), retain: false, scope_spec: None, template_id: None };
        assert!(ko.plan_transform(spec).is_ok());
        assert_eq!(stored(&ko).current().number(), 1);
    }
}
