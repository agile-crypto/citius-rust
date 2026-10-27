use crate::domain::core::{Code, Error};
use crate::domain::provider::{Capability, ProviderRegistry};
use crate::domain::template::TemplateRegistry;

/// Cross-checks providers against the catalog once, when a context is
/// opened (Go: `app.ValidateAllProviders`, run by the server at startup).
/// Every template a provider advertises must exist, and the provider must
/// have the capabilities that template's operations need. That is why
/// matching never re-checks capabilities per request: a provider that
/// advertises a template it cannot serve is a configuration error.
pub fn validate_providers(providers: &ProviderRegistry, templates: &dyn TemplateRegistry) -> Result<(), Error> {
    const OP: &str = "validate_providers";
    for p in providers.list() {
        for id in p.supported_templates() {
            let t = templates.get(id).ok_or_else(|| {
                Error::new(Code::Internal, OP, format!("provider {} advertises unknown template {id}", p.name()))
            })?;
            let needed = t.capabilities().iter().flat_map(|c| &c.operations).flat_map(|&op| Capability::needed_for(op));
            if let Some(missing) = needed.into_iter().find(|c| !p.capabilities().contains(c)) {
                return Err(Error::new(
                    Code::Internal,
                    OP,
                    format!("provider {} advertises {id} but lacks the {missing:?} capability", p.name()),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::adapters::providers::RustCrypto;
    use crate::adapters::storage::InMemoryTemplateRegistry;
    use crate::domain::provider::testing::FakeProvider;

    fn registry(p: Arc<dyn crate::domain::provider::Backend>) -> ProviderRegistry {
        let mut r = ProviderRegistry::new();
        r.register(p).unwrap();
        r
    }

    #[test]
    fn the_shipped_providers_match_the_catalog() {
        validate_providers(&registry(Arc::new(RustCrypto)), &InMemoryTemplateRegistry::standard()).unwrap();
    }

    #[test]
    fn an_unknown_template_is_a_configuration_error() {
        let r = registry(Arc::new(FakeProvider::new("f", &["no-such-template"])));
        let e = validate_providers(&r, &InMemoryTemplateRegistry::standard()).unwrap_err();
        assert!(e.message().contains("no-such-template"), "{e}");
    }
}
