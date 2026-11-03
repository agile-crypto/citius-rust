use std::collections::BTreeMap;
use std::sync::Arc;

use crate::domain::core::{Code, Error, ProviderRequirements, Scope, ScopeSpecification};
use crate::domain::provider::{Backend, Candidate, ProviderRegistry};
use crate::domain::template::{Template, TemplateRegistry};
use crate::proto::api;

const OP: &str = "Discovery";

/// The read-only services over the catalog and the providers (Go:
/// `AlgorithmDiscoveryHandler` and the read half of `ProviderHandler`, whose
/// logic this keeps out of the FFI layer).
///
/// Providers and instances, as Go defines them: every registered backend is
/// an instance, named by `Backend::name`, of the provider `Backend::kind`.
/// Instance CRUD is not implemented (G30), so every instance is enabled and
/// has no stored configuration.
pub struct Discovery {
    templates: Arc<dyn TemplateRegistry>,
    providers: Arc<ProviderRegistry>,
}

/// The filters of ListTemplates; each one set narrows the result.
#[derive(Default)]
pub struct TemplateFilter {
    pub scope_spec: Option<ScopeSpecification>,
    pub allowed_statuses: Vec<api::TemplateStatus>,
    pub required_standards: Vec<String>,
}

/// A provider (a backend kind) and its instances, in instance-name order.
pub struct ProviderView {
    pub id: String,
    instances: Vec<Arc<dyn Backend>>,
}

impl ProviderView {
    /// The templates its instances serve, sorted, each with the instances
    /// that serve it (Go: `providerInfo`).
    pub fn template_support(&self) -> Vec<(&'static str, Vec<&str>)> {
        let mut served: BTreeMap<&'static str, Vec<&str>> = BTreeMap::new();
        for b in &self.instances {
            for t in b.supported_templates() {
                let names = served.entry(t).or_default();
                if !names.contains(&b.name()) {
                    names.push(b.name());
                }
            }
        }
        served.into_iter().collect()
    }
}

/// A provider instance as the API describes it: what an `InstanceView`
/// shows of a backend.
pub struct InstanceView {
    pub instance_id: String,
    pub provider_id: String,
    pub implementation: api::ImplementationProperties,
}

impl InstanceView {
    fn of(b: &dyn Backend) -> Self {
        InstanceView {
            instance_id: b.name().to_owned(),
            provider_id: b.kind().to_owned(),
            implementation: b.implementation(),
        }
    }
}

/// One scope ListScopes returns (Go: `scopeInfo`). Go sets no description
/// or use cases, so neither exists here.
pub struct ScopeView {
    pub scope: Scope,
    pub name: &'static str,
    pub supported_operations: Vec<api::CryptoOperation>,
}

/// One instance MatchProviders returns.
pub struct Match {
    pub instance: InstanceView,
    pub resolved_implementation: api::ImplementationProperties,
    pub score: i32,
}

/// Go's match scores (provider/match.go); only their order matters.
const SCORE_PREFERRED: i32 = 2;
const SCORE_MEETS: i32 = 1;

impl Discovery {
    pub fn new(templates: Arc<dyn TemplateRegistry>, providers: Arc<ProviderRegistry>) -> Self {
        Discovery { templates, providers }
    }

    /// Ordered by id. Without filters every template is returned, whatever
    /// its status (Go: ListTemplates).
    pub fn list_templates(&self, f: &TemplateFilter) -> Vec<api::TemplateInfo> {
        let mut out: Vec<&Template> = self
            .templates
            .list()
            .into_iter()
            .filter(|t| f.allowed_statuses.is_empty() || f.allowed_statuses.contains(&t.status()))
            .filter(|t| f.required_standards.iter().all(|s| t.info().standards.contains(s)))
            .filter(|t| f.scope_spec.as_ref().is_none_or(|want| t.matches(want)))
            .collect();
        out.sort_by(|a, b| a.id().cmp(b.id()));
        out.into_iter().map(|t| t.info().clone()).collect()
    }

    pub fn get_template(&self, id: &str) -> Result<api::TemplateInfo, Error> {
        if id.is_empty() {
            return Err(Error::new(Code::InvalidArgument, OP, "template_id is required"));
        }
        self.templates
            .get(id)
            .map(|t| t.info().clone())
            .ok_or_else(|| Error::new(Code::TemplateNotFound, OP, format!("template not found: {id}")))
    }

    /// Every scope some template offers, in Go's scope order, with the
    /// operations offered under it, sorted (Go: ListScopes). A scope no
    /// template offers cannot serve a key, so it is left out.
    pub fn list_scopes(&self) -> Vec<ScopeView> {
        let mut offered: BTreeMap<usize, Vec<api::CryptoOperation>> = BTreeMap::new();
        for t in self.templates.list() {
            for c in t.capabilities() {
                let Some(i) = Scope::ALL.iter().position(|s| *s == c.spec.scope) else { continue };
                let ops = offered.entry(i).or_default();
                for &op in &c.operations {
                    if !ops.contains(&op) {
                        ops.push(op);
                    }
                }
            }
        }
        offered
            .into_iter()
            .map(|(i, mut ops)| {
                // In enum order, as Go sorts them.
                ops.sort_unstable_by_key(|&o| o as i32);
                let scope = Scope::ALL[i];
                ScopeView { scope, name: scope.name().expect("ALL holds named scopes"), supported_operations: ops }
            })
            .collect()
    }

    /// The registered backends, ordered by instance name (Go: `registered`).
    fn registered(&self) -> Vec<Arc<dyn Backend>> {
        let mut all = self.providers.list().to_vec();
        all.sort_by(|a, b| a.name().cmp(b.name()));
        all
    }

    fn by_kind(&self) -> BTreeMap<String, Vec<Arc<dyn Backend>>> {
        let mut out: BTreeMap<String, Vec<Arc<dyn Backend>>> = BTreeMap::new();
        for b in self.registered() {
            out.entry(b.kind().to_owned()).or_default().push(b);
        }
        out
    }

    /// Ordered by id. A provider is kept if one of its instances both serves
    /// `template_id` (when given) and meets every hard requirement (Go:
    /// ListProviders).
    pub fn list_providers(&self, template_id: Option<&str>, required: &ProviderRequirements) -> Vec<ProviderView> {
        self.by_kind()
            .into_iter()
            .filter(|(_, instances)| {
                instances.iter().any(|b| {
                    crate::domain::provider::unmet(&b.implementation(), required).is_empty()
                        && template_id.is_none_or(|t| b.supported_templates().contains(&t))
                })
            })
            .map(|(id, instances)| ProviderView { id, instances })
            .collect()
    }

    pub fn get_provider(&self, id: &str) -> Result<ProviderView, Error> {
        if id.is_empty() {
            return Err(Error::new(Code::InvalidArgument, OP, "provider_id is required"));
        }
        self.by_kind()
            .remove(id)
            .map(|instances| ProviderView { id: id.to_owned(), instances })
            .ok_or_else(|| Error::new(Code::ProviderNotFound, OP, format!("provider not found: {id}")))
    }

    /// Ordered by instance id; `provider_id` keeps that provider's instances,
    /// requirements those meeting every hard requirement. Every instance is
    /// enabled, so `enabled_only` changes nothing (Go: ListProviderInstances).
    pub fn list_instances(&self, provider_id: Option<&str>, required: &ProviderRequirements) -> Vec<InstanceView> {
        self.registered()
            .into_iter()
            .filter(|b| provider_id.is_none_or(|p| b.kind() == p))
            .filter(|b| crate::domain::provider::unmet(&b.implementation(), required).is_empty())
            .map(|b| InstanceView::of(b.as_ref()))
            .collect()
    }

    pub fn get_instance(&self, id: &str) -> Result<InstanceView, Error> {
        if id.is_empty() {
            return Err(Error::new(Code::InvalidArgument, OP, "instance_id is required"));
        }
        self.providers
            .get(id)
            .map(|b| InstanceView::of(b.as_ref()))
            .ok_or_else(|| Error::new(Code::ProviderNotFound, OP, format!("provider not found: {id}")))
    }

    /// The instances that can hold a key of `template_id` and meet every hard
    /// requirement, best first: the order key creation picks in, so the
    /// first match is the provider `create_key` would use when the request
    /// names none and no policy adds requirements (Go: MatchProviders).
    pub fn match_providers(&self, template_id: &str, required: &ProviderRequirements) -> Result<Vec<Match>, Error> {
        if template_id.is_empty() {
            return Err(Error::new(Code::InvalidArgument, OP, "template_id is required"));
        }
        Ok(self
            .providers
            .rank(template_id, required)
            .into_iter()
            .take_while(Candidate::eligible)
            .map(|c| Match {
                instance: InstanceView::of(c.backend.as_ref()),
                score: if c.preferred { SCORE_PREFERRED } else { SCORE_MEETS },
                resolved_implementation: c.implementation,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::providers::RustCrypto;
    use crate::adapters::storage::InMemoryTemplateRegistry;
    use crate::domain::provider::testing::FakeProvider;

    fn discovery(extra: Vec<FakeProvider>) -> Discovery {
        let mut providers = ProviderRegistry::new();
        providers.register(Arc::new(RustCrypto)).unwrap();
        for p in extra {
            providers.register(Arc::new(p)).unwrap();
        }
        Discovery::new(Arc::new(InMemoryTemplateRegistry::standard()), Arc::new(providers))
    }

    #[test]
    fn templates_are_ordered_and_filtered_like_go() {
        let d = discovery(vec![]);
        let all = d.list_templates(&TemplateFilter::default());
        assert_eq!(all.len(), 72, "every catalog template, whatever its status");
        assert!(all.windows(2).all(|w| w[0].template_id < w[1].template_id), "ordered by id");

        // The catalog has 64 ACTIVE and 8 ACCEPTABLE templates.
        let acceptable = d.list_templates(&TemplateFilter {
            allowed_statuses: vec![api::TemplateStatus::Acceptable],
            ..Default::default()
        });
        assert_eq!(acceptable.len(), 8);
        assert!(acceptable.iter().all(|t| t.status == api::TemplateStatus::Acceptable as i32));
        let none = d.list_templates(&TemplateFilter {
            allowed_statuses: vec![api::TemplateStatus::Deprecated],
            ..Default::default()
        });
        assert!(none.is_empty());

        let rfc8032 =
            d.list_templates(&TemplateFilter { required_standards: vec!["RFC 8032".into()], ..Default::default() });
        assert!(rfc8032.iter().any(|t| t.template_id == "ed25519"));
        assert!(rfc8032.iter().all(|t| t.standards.contains(&"RFC 8032".to_owned())));

        let prehashed = d.list_templates(&TemplateFilter {
            scope_spec: Some(ScopeSpecification::any_of(Scope::Signature(api::SignatureScope::Prehashed))),
            ..Default::default()
        });
        assert!(prehashed.iter().any(|t| t.template_id == "ed25519ph"));
        assert!(!prehashed.iter().any(|t| t.template_id == "ed25519"));
    }

    #[test]
    fn get_template_errors_like_go() {
        let d = discovery(vec![]);
        assert_eq!(d.get_template("ed25519").unwrap().template_id, "ed25519");
        assert_eq!(d.get_template("").unwrap_err().code(), Code::InvalidArgument);
        assert_eq!(d.get_template("nope").unwrap_err().code(), Code::TemplateNotFound);
    }

    #[test]
    fn scopes_are_go_s_names_in_go_s_order_with_sorted_operations() {
        let scopes = discovery(vec![]).list_scopes();
        let names: Vec<&str> = scopes.iter().map(|s| s.name).collect();
        let order: Vec<usize> =
            names.iter().map(|n| Scope::ALL.iter().position(|s| s.name() == Some(n)).unwrap()).collect();
        assert!(order.windows(2).all(|w| w[0] < w[1]), "Go's order: {names:?}");
        assert!(names.contains(&"signature_prehashed") && names.contains(&"aead_standard"));
        let sig = scopes.iter().find(|s| s.name == "signature_standard").unwrap();
        assert_eq!(sig.supported_operations, vec![api::CryptoOperation::Sign, api::CryptoOperation::Verify]);
        assert!(scopes.iter().all(|s| s.supported_operations.windows(2).all(|w| (w[0] as i32) < (w[1] as i32))));
    }

    #[test]
    fn providers_are_backend_kinds_and_instances_are_backends() {
        let hsm = FakeProvider::new("hsm-a", &["aes-256-gcm-128-96"]).kind("hsm");
        let d = discovery(vec![hsm]);
        let ids: Vec<String> = d.list_providers(None, &ProviderRequirements::default()).into_iter().map(|p| p.id).collect();
        assert_eq!(ids, ["hsm", "software"]);
        let software = d.get_provider("software").unwrap();
        let support = software.template_support();
        assert!(support.iter().any(|(t, by)| *t == "ed25519" && by == &["rustcrypto"]));
        assert!(support.windows(2).all(|w| w[0].0 < w[1].0), "sorted by template");

        // A template filter keeps only providers that serve it.
        let ed = d.list_providers(Some("ed25519"), &ProviderRequirements::default());
        assert_eq!(ed.iter().map(|p| p.id.as_str()).collect::<Vec<_>>(), ["software"]);

        let inst: Vec<String> = d.list_instances(None, &ProviderRequirements::default()).into_iter().map(|i| i.instance_id).collect();
        assert_eq!(inst, ["hsm-a", "rustcrypto"], "ordered by instance id");
        let hsm_only = d.list_instances(Some("hsm"), &ProviderRequirements::default());
        assert_eq!(hsm_only.len(), 1);
        assert_eq!(d.get_instance("rustcrypto").unwrap().provider_id, "software");
        assert_eq!(d.get_instance("nope").err().unwrap().code(), Code::ProviderNotFound);
        assert_eq!(d.get_provider("nope").err().unwrap().code(), Code::ProviderNotFound);
    }

    #[test]
    fn requirements_filter_providers_and_instances() {
        let d = discovery(vec![]);
        let fips = ProviderRequirements { fips_140_certified: true, ..Default::default() };
        assert!(d.list_providers(None, &fips).is_empty(), "rustcrypto is not FIPS certified");
        assert!(d.list_instances(None, &fips).is_empty());
        assert!(d.match_providers("ed25519", &fips).unwrap().is_empty());
        let memory_safe = ProviderRequirements { memory_safe: true, ..Default::default() };
        assert_eq!(d.list_instances(None, &memory_safe).len(), 1);
    }

    #[test]
    fn matching_agrees_with_selection() {
        let accelerated =
            FakeProvider::new("fast", &["aes-256-gcm-128-96"]).with(|i| i.hardware_accelerated = Some(true));
        let d = discovery(vec![accelerated]);
        let none = ProviderRequirements::default();
        let m = d.match_providers("aes-256-gcm-128-96", &none).unwrap();
        assert_eq!(m.iter().map(|m| m.instance.instance_id.as_str()).collect::<Vec<_>>(), ["rustcrypto", "fast"]);
        assert!(m.iter().all(|m| m.score == SCORE_MEETS));

        let prefer = ProviderRequirements { prefer_hardware_accelerated: true, ..Default::default() };
        let m = d.match_providers("aes-256-gcm-128-96", &prefer).unwrap();
        assert_eq!((m[0].instance.instance_id.as_str(), m[0].score), ("fast", SCORE_PREFERRED));
        assert_eq!(m[1].score, SCORE_MEETS);
        // The first match is what selection picks.
        let picked = d
            .providers
            .select(&crate::domain::provider::Requirements {
                template_id: "aes-256-gcm-128-96".into(),
                pinned: None,
                implementation: prefer,
            })
            .unwrap();
        assert_eq!(picked.name(), m[0].instance.instance_id);

        assert!(d.match_providers("not-served-by-anyone", &none).unwrap().is_empty());
        assert_eq!(d.match_providers("", &none).err().unwrap().code(), Code::InvalidArgument);
    }
}
