use std::collections::BTreeMap;

use super::Template;
use crate::domain::core::{Code, Error};
use crate::proto::api::TemplateInfo;

/// The JSON form of a template catalog (citius-server's
/// standard_algorithms.json): templates keyed by id, in protobuf JSON.
#[derive(serde::Deserialize)]
struct Catalog {
    templates: BTreeMap<String, TemplateInfo>,
}

/// Parses a catalog into templates, ordered by id. Loading is a startup
/// concern (Go: `template.LoadStandardCatalog`), so it is not on the
/// registry interface. Any invalid entry fails the whole catalog.
pub fn parse_catalog(json: &str) -> Result<Vec<Template>, Error> {
    const OP: &str = "template::parse_catalog";
    let catalog: Catalog = serde_json::from_str(json)
        .map_err(|e| Error::new(Code::InvalidArgument, OP, format!("catalog is not valid: {e}")))?;
    catalog
        .templates
        .into_iter()
        .map(|(key, info)| {
            if key != info.template_id {
                return Err(Error::new(
                    Code::InvalidArgument,
                    OP,
                    format!("catalog key {key:?} differs from its templateId {:?}", info.template_id),
                ));
            }
            Template::new(info)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mismatched_key_is_rejected() {
        let json = r#"{"templates": {"a": {"templateId": "b"}}}"#;
        assert_eq!(parse_catalog(json).unwrap_err().code(), Code::InvalidArgument);
    }

    #[test]
    fn malformed_json_is_rejected() {
        assert_eq!(parse_catalog("{").unwrap_err().code(), Code::InvalidArgument);
    }
}
