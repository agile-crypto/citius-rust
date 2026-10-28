use crate::domain::core::{Code, Error, Scope, ScopeSpecification, SecurityProperties};
use crate::proto::api;

/// An algorithm template: a fully specified algorithm, the scopes it serves
/// and the operations it allows in each. Immutable reference data.
///
/// Wraps the API's `TemplateInfo`, as Go's `template.Template` does: the
/// algorithm details are deeply nested and only providers interpret them.
/// Unlike Go, the scoped capabilities are parsed once, when the template is
/// created, so a malformed catalog fails at load time and not on a request.
#[derive(Debug, Clone)]
pub struct Template {
    info: api::TemplateInfo,
    capabilities: Vec<Capability>,
}

/// One scope a template serves, and the operations it allows there.
#[derive(Debug, Clone)]
pub struct Capability {
    pub spec: ScopeSpecification,
    pub operations: Vec<api::CryptoOperation>,
}

impl Template {
    pub fn new(info: api::TemplateInfo) -> Result<Self, Error> {
        const OP: &str = "Template::new";
        let id = info.template_id.clone();
        let invalid = |msg: String| Error::new(Code::InvalidArgument, OP, format!("template {id:?}: {msg}"));
        if info.template_id.is_empty() {
            return Err(invalid("template_id is empty".into()));
        }
        if info.algorithm.is_none() {
            return Err(invalid("no algorithm".into()));
        }
        if info.scoped_capabilities.is_empty() {
            return Err(invalid("no scoped capabilities".into()));
        }
        api::TemplateStatus::try_from(info.status).map_err(|_| invalid(format!("unknown status {}", info.status)))?;
        let capabilities = info
            .scoped_capabilities
            .iter()
            .map(|c| {
                let scope = c.scope.as_ref().ok_or_else(|| invalid("a scoped capability has no scope".into()))?;
                let spec = ScopeSpecification::from_proto(scope).map_err(|e| invalid(e.message().to_owned()))?;
                let operations = c
                    .operations
                    .iter()
                    .map(|&o| api::CryptoOperation::try_from(o).map_err(|_| invalid(format!("unknown operation {o}"))))
                    .collect::<Result<_, _>>()?;
                Ok(Capability { spec, operations })
            })
            .collect::<Result<_, Error>>()?;
        Ok(Template { info, capabilities })
    }

    pub fn id(&self) -> &str {
        &self.info.template_id
    }

    pub fn status(&self) -> api::TemplateStatus {
        api::TemplateStatus::try_from(self.info.status).expect("checked in new")
    }

    /// Whether intent-based selection may pick this template. Deprecated,
    /// forbidden and experimental templates are never picked implicitly.
    pub fn is_selectable(&self) -> bool {
        matches!(self.status(), api::TemplateStatus::Active | api::TemplateStatus::Acceptable)
    }

    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    /// Whether any of the template's scopes satisfies `want` (Go: MatchesScope).
    pub fn matches(&self, want: &ScopeSpecification) -> bool {
        self.capabilities.iter().any(|c| c.spec.satisfies(want))
    }

    /// The concrete scope this template serves for `want`: the scope of its
    /// first capability that satisfies it. Resolves "any scope of the kind".
    pub fn scope_for(&self, want: &ScopeSpecification) -> Option<Scope> {
        self.capabilities.iter().find(|c| c.spec.satisfies(want)).map(|c| c.spec.scope)
    }

    /// The security properties of the first capability that satisfies `want`:
    /// what the template provides for that intent.
    pub fn security_for(&self, want: &ScopeSpecification) -> Option<SecurityProperties> {
        self.capabilities.iter().find(|c| c.spec.satisfies(want)).and_then(|c| c.spec.security)
    }

    /// Whether the template allows `operation` in `scope` (Go: SupportsOperation).
    pub fn supports_operation(&self, scope: &Scope, operation: api::CryptoOperation) -> bool {
        self.capabilities.iter().any(|c| &c.spec.scope == scope && c.operations.contains(&operation))
    }

    pub fn info(&self) -> &api::TemplateInfo {
        &self.info
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::proto::api::{scope_specification::ScopeSpec, AeadScopeSpec, SignatureScopeSpec};

    /// A minimal valid template serving `scope`, for tests.
    pub fn template(id: &str, scope: Scope, status: api::TemplateStatus) -> Template {
        let spec = match scope {
            Scope::Signature(s) => ScopeSpec::Signature(SignatureScopeSpec { scope: s as i32, ..Default::default() }),
            Scope::Aead(s) => ScopeSpec::Aead(AeadScopeSpec { scope: s as i32, ..Default::default() }),
            other => panic!("test helper does not build {other:?}"),
        };
        Template::new(api::TemplateInfo {
            template_id: id.into(),
            scoped_capabilities: vec![api::ScopedCapabilities {
                scope: Some(api::ScopeSpecification { scope_spec: Some(spec) }),
                operations: vec![api::CryptoOperation::Sign as i32],
                ..Default::default()
            }],
            algorithm: Some(Default::default()),
            status: status as i32,
            ..Default::default()
        })
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::template;
    use super::*;
    use api::{SignatureScope, TemplateStatus};

    #[test]
    fn invalid_templates_are_rejected_at_creation() {
        let base = template("t", Scope::Signature(SignatureScope::Standard), TemplateStatus::Active).info().clone();
        for broken in [
            api::TemplateInfo { template_id: String::new(), ..base.clone() },
            api::TemplateInfo { algorithm: None, ..base.clone() },
            api::TemplateInfo { scoped_capabilities: vec![], ..base.clone() },
            api::TemplateInfo { status: 99, ..base.clone() },
        ] {
            assert_eq!(Template::new(broken).unwrap_err().code(), Code::InvalidArgument);
        }
    }

    #[test]
    fn only_active_and_acceptable_are_selectable() {
        let t = |s| template("t", Scope::Signature(SignatureScope::Standard), s).is_selectable();
        assert!(t(TemplateStatus::Active) && t(TemplateStatus::Acceptable));
        assert!(!t(TemplateStatus::Deprecated) && !t(TemplateStatus::Forbidden));
        assert!(!t(TemplateStatus::Experimental) && !t(TemplateStatus::Unspecified));
    }

    #[test]
    fn supports_only_declared_operations_in_declared_scopes() {
        let t = template("t", Scope::Signature(SignatureScope::Standard), TemplateStatus::Active);
        let standard = Scope::Signature(SignatureScope::Standard);
        assert!(t.supports_operation(&standard, api::CryptoOperation::Sign));
        assert!(!t.supports_operation(&standard, api::CryptoOperation::Verify));
        assert!(!t.supports_operation(&Scope::Signature(SignatureScope::Prehashed), api::CryptoOperation::Sign));
    }
}
