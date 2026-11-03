use std::sync::Arc;

use super::Backend;
use crate::domain::core::{Code, Error, ProviderRequirements};
use crate::proto::api;

/// What a key needs from its provider (Go: `provider.Requirements`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirements {
    pub template_id: String,
    /// A provider named by the caller: used, or the call fails. Never
    /// silently substituted.
    pub pinned: Option<String>,
    /// The policy's provider requirements merged with the request's.
    pub implementation: ProviderRequirements,
}

/// The requirements a provider's implementation does not meet, by their
/// policy-document names (Go: `provider.Unmet`).
pub fn unmet(props: &api::ImplementationProperties, required: &ProviderRequirements) -> Vec<&'static str> {
    let fips_certified = props.fips_140.as_ref().is_some_and(|f| f.certified);
    let fips_level = props.fips_140.as_ref().filter(|f| f.certified).map_or(0, |f| f.level);
    let yes = |b: Option<bool>| b == Some(true);
    [
        ("fips_140_certified", required.fips_140_certified, fips_certified),
        (
            "min_fips_level",
            required.min_fips_140_level > 0,
            i64::from(fips_level) >= i64::from(required.min_fips_140_level),
        ),
        ("common_criteria_certified", required.common_criteria_certified, yes(props.common_criteria_certified)),
        ("formally_verified", required.formally_verified, yes(props.formally_verified)),
        ("memory_safe", required.memory_safe, yes(props.memory_safe_language)),
        ("constant_time", required.constant_time, yes(props.constant_time)),
        ("side_channel_hardened", required.side_channel_hardened, yes(props.side_channel_hardened)),
        ("no_known_cve", required.no_known_cve, yes(props.no_known_cve) && props.unpatched_cves.is_empty()),
        ("approved_generation", required.approved_generation, fips_certified),
    ]
    .into_iter()
    .filter(|&(_, required, met)| required && !met)
    .map(|(name, _, _)| name)
    .collect()
}

/// One provider judged against requirements (Go: `provider.Candidate`).
pub struct Candidate {
    pub backend: Arc<dyn Backend>,
    /// The properties the judgement used.
    pub implementation: api::ImplementationProperties,
    /// Whether it serves the template; true for every provider when no
    /// template is given.
    pub advertises: bool,
    /// The hard requirements it misses.
    pub unmet: Vec<&'static str>,
    /// Whether it has a property the requirements prefer.
    pub preferred: bool,
}

impl Candidate {
    /// It serves the template and meets every hard requirement.
    pub fn eligible(&self) -> bool {
        self.advertises && self.unmet.is_empty()
    }
}

/// Holds the providers and matches one to a key's requirements. Filled at
/// startup, then shared without a lock.
pub struct ProviderRegistry {
    providers: Vec<Arc<dyn Backend>>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        ProviderRegistry { providers: Vec::new() }
    }

    /// Registration order is the tie-break order for matching.
    pub fn register(&mut self, p: Arc<dyn Backend>) -> Result<(), Error> {
        if self.get(p.name()).is_some() {
            return Err(Error::new(
                Code::AlreadyExists,
                "ProviderRegistry::register",
                format!("provider {} is already registered", p.name()),
            ));
        }
        self.providers.push(p);
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn Backend>> {
        self.providers.iter().find(|p| p.name() == name).cloned()
    }

    pub fn list(&self) -> &[Arc<dyn Backend>] {
        &self.providers
    }

    /// Every provider judged against `template_id` (empty: any) and the
    /// requirements, in the order selection uses (Go: `provider.Rank`):
    /// eligible ones with a preferred property, then the other eligible
    /// ones, then the ineligible ones, each group in registration order.
    pub fn rank(&self, template_id: &str, required: &ProviderRequirements) -> Vec<Candidate> {
        let (mut preferred, mut eligible, mut ineligible) = (Vec::new(), Vec::new(), Vec::new());
        for p in &self.providers {
            let implementation = p.implementation();
            let c = Candidate {
                backend: p.clone(),
                advertises: template_id.is_empty() || p.supported_templates().contains(&template_id),
                unmet: unmet(&implementation, required),
                preferred: required.prefer_hardware_accelerated && implementation.hardware_accelerated == Some(true),
                implementation,
            };
            match (c.eligible(), c.preferred) {
                (true, true) => preferred.push(c),
                (true, false) => eligible.push(c),
                _ => ineligible.push(c),
            }
        }
        preferred.into_iter().chain(eligible).chain(ineligible).collect()
    }

    /// The provider for a new key (Go: `Registry.Match`):
    /// - pinned: that provider, if it serves the template and meets the
    ///   requirements, else an error naming why;
    /// - otherwise the providers serving the template, preferred ones first
    ///   (`prefer_hardware_accelerated`), then in registration order; the
    ///   first that meets every requirement.
    ///
    /// At operation time there is no matching: a key version records the
    /// provider that made it.
    pub fn select(&self, req: &Requirements) -> Result<Arc<dyn Backend>, Error> {
        const OP: &str = "ProviderRegistry::select";
        let serves = |p: &Arc<dyn Backend>| p.supported_templates().contains(&req.template_id.as_str());

        if let Some(name) = &req.pinned {
            let p = self
                .get(name)
                .ok_or_else(|| Error::new(Code::ProviderNotFound, OP, format!("no provider named {name}")))?;
            if !serves(&p) {
                return Err(Error::new(
                    Code::ProviderIncompatible,
                    OP,
                    format!("provider {name} does not serve template {}", req.template_id),
                ));
            }
            let missing = unmet(&p.implementation(), &req.implementation);
            if !missing.is_empty() {
                return Err(Error::new(
                    Code::NoMatchingProvider,
                    OP,
                    format!("provider {name} does not meet: {}", missing.join(", ")),
                ));
            }
            return Ok(p);
        }

        let ranked = self.rank(&req.template_id, &req.implementation);
        match ranked.into_iter().next() {
            Some(c) if c.eligible() => Ok(c.backend),
            Some(_) if self.providers.iter().any(serves) => Err(Error::new(
                Code::NoMatchingProvider,
                OP,
                format!("no provider meets the requirements for template {}", req.template_id),
            )),
            _ => Err(Error::new(Code::NoMatchingProvider, OP, format!("no provider serves template {}", req.template_id))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::provider::testing::FakeProvider;

    fn registry(providers: Vec<FakeProvider>) -> ProviderRegistry {
        let mut r = ProviderRegistry::new();
        for p in providers {
            r.register(Arc::new(p)).unwrap();
        }
        r
    }

    fn req(template: &str, pinned: Option<&str>, implementation: ProviderRequirements) -> Requirements {
        Requirements { template_id: template.into(), pinned: pinned.map(String::from), implementation }
    }

    fn picked(r: &ProviderRegistry, q: &Requirements) -> Result<String, Code> {
        r.select(q).map(|p| p.name().to_owned()).map_err(|e| e.code())
    }

    const NONE: ProviderRequirements = ProviderRequirements {
        fips_140_certified: false,
        min_fips_140_level: 0,
        common_criteria_certified: false,
        formally_verified: false,
        memory_safe: false,
        constant_time: false,
        side_channel_hardened: false,
        no_known_cve: false,
        approved_generation: false,
        prefer_hardware_accelerated: false,
    };

    #[test]
    fn first_registered_serving_provider_wins() {
        let r = registry(vec![FakeProvider::new("a", &["t"]), FakeProvider::new("b", &["t", "u"])]);
        assert_eq!(picked(&r, &req("t", None, NONE)), Ok("a".into()));
        assert_eq!(picked(&r, &req("u", None, NONE)), Ok("b".into()));
        assert_eq!(picked(&r, &req("v", None, NONE)), Err(Code::NoMatchingProvider));
    }

    #[test]
    fn requirements_filter_providers() {
        let memory_safe = ProviderRequirements { memory_safe: true, ..NONE };
        let r = registry(vec![
            FakeProvider::new("unsafe", &["t"]),
            FakeProvider::new("safe", &["t"]).with(|i| i.memory_safe_language = Some(true)),
        ]);
        assert_eq!(picked(&r, &req("t", None, memory_safe)), Ok("safe".into()));
        let fips = ProviderRequirements { min_fips_140_level: 2, ..NONE };
        assert_eq!(picked(&r, &req("t", None, fips)), Err(Code::NoMatchingProvider));
    }

    #[test]
    fn preferred_providers_rank_first_but_must_still_qualify() {
        let prefer = ProviderRequirements { prefer_hardware_accelerated: true, ..NONE };
        let r = registry(vec![
            FakeProvider::new("sw", &["t"]),
            FakeProvider::new("hw", &["t"]).with(|i| i.hardware_accelerated = Some(true)),
        ]);
        assert_eq!(picked(&r, &req("t", None, NONE)), Ok("sw".into()));
        assert_eq!(picked(&r, &req("t", None, prefer)), Ok("hw".into()));
        let strict = ProviderRequirements { constant_time: true, ..prefer };
        assert_eq!(picked(&r, &req("t", None, strict)), Err(Code::NoMatchingProvider));
    }

    #[test]
    fn a_pinned_provider_is_used_or_the_call_fails() {
        let r = registry(vec![FakeProvider::new("a", &["t"]), FakeProvider::new("b", &["t"])]);
        assert_eq!(picked(&r, &req("t", Some("b"), NONE)), Ok("b".into()));
        assert_eq!(picked(&r, &req("t", Some("zz"), NONE)), Err(Code::ProviderNotFound));
        assert_eq!(picked(&r, &req("u", Some("b"), NONE)), Err(Code::ProviderIncompatible));
        let ct = ProviderRequirements { constant_time: true, ..NONE };
        assert_eq!(picked(&r, &req("t", Some("b"), ct)), Err(Code::NoMatchingProvider));
    }

    #[test]
    fn duplicate_names_are_rejected() {
        let mut r = registry(vec![FakeProvider::new("a", &["t"])]);
        let e = r.register(Arc::new(FakeProvider::new("a", &["u"]))).unwrap_err();
        assert_eq!(e.code(), Code::AlreadyExists);
    }

    #[test]
    fn unmet_follows_go() {
        let mut props = api::ImplementationProperties::default();
        let all = ProviderRequirements {
            fips_140_certified: true,
            min_fips_140_level: 2,
            no_known_cve: true,
            approved_generation: true,
            ..NONE
        };
        assert_eq!(unmet(&props, &all), ["fips_140_certified", "min_fips_level", "no_known_cve", "approved_generation"]);
        props.fips_140 = Some(api::Fips140Certification { certified: true, level: 3, ..Default::default() });
        props.no_known_cve = Some(true);
        assert!(unmet(&props, &all).is_empty());
        props.unpatched_cves = vec!["CVE-1".into()];
        assert_eq!(unmet(&props, &all), ["no_known_cve"]);
        // A level without certification counts for nothing.
        props.fips_140 = Some(api::Fips140Certification { certified: false, level: 4, ..Default::default() });
        assert!(unmet(&props, &ProviderRequirements { min_fips_140_level: 1, ..NONE }).contains(&"min_fips_level"));
    }
}
