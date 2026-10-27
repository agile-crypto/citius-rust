use serde::Deserialize;

use crate::domain::core::{MAX_FIPS_140_LEVEL, Operation, ProviderRequirements};
use crate::proto::api::TemplateStatus;

/// A policy's rules (rules JSON, schema version 1), parsed and validated.
///
/// Semantics (Go's `SimpleRulesEvaluator`):
/// - allow lists (`allowed_templates`, `allowed_operations`) deny by
///   default: absent or empty allows nothing;
/// - requirement sections (`security_requirements`,
///   `provider_requirements`) are constraints: absent requires nothing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Rules {
    allowed_templates: Vec<String>,
    allowed_operations: Vec<Operation>,
    security: SecurityFloor,
    provider: ProviderRequirements,
}

/// What `security_requirements` demands of a template.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SecurityFloor {
    pub fips_approved: bool,
    pub quantum_safe: bool,
    pub min_strength_bits: u32,
    pub block_deprecated: bool,
}

/// What the policy needs to know about a template to check its security
/// floor: a small transfer type, so that `policy` does not import
/// `template` (Go: `policy.TemplateSecurityInfo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateSecurityInfo {
    pub template_id: String,
    pub status: TemplateStatus,
    pub fips_approved: bool,
    pub quantum_safe: bool,
    pub strength_bits: u32,
}

// --- The document as written --------------------------------------------
//
// Unknown fields are an error at every depth: a misspelt section would
// otherwise be silently unenforced. Sections that Go parses but does not
// evaluate are read only to reject them with a precise message.

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Document {
    version: Option<String>,
    allowed_templates: Option<Vec<String>>,
    allowed_operations: Option<OperationRule>,
    security_requirements: Option<SecurityRule>,
    provider_requirements: Option<ProviderRule>,
    allowed_scopes: Option<serde_json::Value>,
    allowed_providers: Option<serde_json::Value>,
    key_configuration: Option<serde_json::Value>,
    allowed_transformations: Option<serde_json::Value>,
    allowed_migrations: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationRule {
    key_operations: Option<Vec<String>>,
    keyless_operations: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecurityRule {
    min_security_strength_bits: Option<u32>,
    fips_approved: Option<bool>,
    quantum_safe: Option<bool>,
    min_nist_status: Option<serde_json::Value>,
    block_deprecated: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderRule {
    #[serde(default)]
    fips_140_certified: bool,
    #[serde(default)]
    min_fips_level: u32,
    #[serde(default)]
    common_criteria_certified: bool,
    #[serde(default)]
    formally_verified: bool,
    #[serde(default)]
    memory_safe: bool,
    #[serde(default)]
    constant_time: bool,
    #[serde(default)]
    side_channel_hardened: bool,
    #[serde(default)]
    no_known_cve: bool,
    #[serde(default)]
    approved_generation: bool,
}

impl Rules {
    /// Parses and validates a rules document. An empty document is valid and
    /// allows nothing. Fails with a message for the policy author.
    pub fn parse(document: &str) -> Result<Rules, String> {
        if document.trim().is_empty() {
            return Ok(Rules::default());
        }
        let d: Document = serde_json::from_str(document).map_err(|e| format!("rules document: {e}"))?;

        let not_enforced = [
            ("allowed_scopes", d.allowed_scopes.is_some()),
            ("allowed_providers", d.allowed_providers.is_some()),
            ("key_configuration", d.key_configuration.is_some()),
            ("allowed_transformations", d.allowed_transformations.is_some()),
            ("allowed_migrations", d.allowed_migrations.is_some()),
            (
                "allowed_operations.keyless_operations",
                d.allowed_operations.as_ref().is_some_and(|o| o.keyless_operations.is_some()),
            ),
            (
                "security_requirements.min_nist_status",
                d.security_requirements.as_ref().is_some_and(|s| s.min_nist_status.is_some()),
            ),
        ];
        if let Some((section, _)) = not_enforced.iter().find(|(_, present)| *present) {
            return Err(format!("{section} is not enforced by this library; remove it rather than rely on it"));
        }

        let has_sections = d.allowed_templates.is_some()
            || d.allowed_operations.is_some()
            || d.security_requirements.is_some()
            || d.provider_requirements.is_some();
        match d.version.as_deref() {
            None if has_sections => return Err("version is required when the policy has rule sections".into()),
            Some(v) if v != "1" => return Err(format!("unsupported policy version {v:?} (supported: \"1\")")),
            _ => {}
        }

        let allowed_templates = d.allowed_templates.unwrap_or_default();
        if let Some(i) = allowed_templates.iter().position(String::is_empty) {
            return Err(format!("allowed_templates[{i}]: template id must not be empty"));
        }

        let allowed_operations = d
            .allowed_operations
            .and_then(|o| o.key_operations)
            .unwrap_or_default()
            .iter()
            .enumerate()
            .map(|(i, name)| {
                Operation::from_name(name)
                    .ok_or_else(|| format!("allowed_operations.key_operations[{i}]: unknown operation {name:?}"))
            })
            .collect::<Result<_, _>>()?;

        let security = d
            .security_requirements
            .map(|s| SecurityFloor {
                fips_approved: s.fips_approved == Some(true),
                quantum_safe: s.quantum_safe == Some(true),
                min_strength_bits: s.min_security_strength_bits.unwrap_or(0),
                block_deprecated: s.block_deprecated == Some(true),
            })
            .unwrap_or_default();

        let provider = match d.provider_requirements {
            None => ProviderRequirements::default(),
            Some(p) => {
                if p.min_fips_level > MAX_FIPS_140_LEVEL {
                    return Err(format!(
                        "provider_requirements.min_fips_level: {} is not a level from 1 to {MAX_FIPS_140_LEVEL}",
                        p.min_fips_level
                    ));
                }
                ProviderRequirements {
                    fips_140_certified: p.fips_140_certified,
                    min_fips_140_level: p.min_fips_level,
                    common_criteria_certified: p.common_criteria_certified,
                    formally_verified: p.formally_verified,
                    memory_safe: p.memory_safe,
                    constant_time: p.constant_time,
                    side_channel_hardened: p.side_channel_hardened,
                    no_known_cve: p.no_known_cve,
                    approved_generation: p.approved_generation,
                    prefer_hardware_accelerated: false,
                }
            }
        };

        Ok(Rules { allowed_templates, allowed_operations, security, provider })
    }

    /// The allowed templates, in the policy's order of preference.
    pub fn allowed_templates(&self) -> &[String] {
        &self.allowed_templates
    }

    pub fn allows_template(&self, id: &str) -> bool {
        self.allowed_templates.iter().any(|t| t == id)
    }

    pub fn allows_operation(&self, op: Operation) -> bool {
        self.allowed_operations.contains(&op)
    }

    pub fn provider_requirements(&self) -> ProviderRequirements {
        self.provider
    }

    /// `Err` names the first requirement the template does not meet.
    pub fn check_security(&self, t: &TemplateSecurityInfo) -> Result<(), String> {
        let s = &self.security;
        let id = &t.template_id;
        if s.fips_approved && !t.fips_approved {
            return Err(format!("policy requires FIPS-approved algorithms; template {id} is not"));
        }
        if s.quantum_safe && !t.quantum_safe {
            return Err(format!("policy requires quantum-safe algorithms; template {id} is not"));
        }
        if t.strength_bits < s.min_strength_bits {
            return Err(format!(
                "policy requires {} bits of security; template {id} has {}",
                s.min_strength_bits, t.strength_bits
            ));
        }
        if s.block_deprecated && matches!(t.status, TemplateStatus::Deprecated | TemplateStatus::Forbidden) {
            return Err(format!("policy blocks deprecated and forbidden algorithms; template {id} is {:?}", t.status));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"{
        "version": "1",
        "allowed_templates": ["ml-dsa-65", "ecdsa-p256-sha256-der"],
        "allowed_operations": {"key_operations": ["create_key", "sign", "verify"]},
        "security_requirements": {"min_security_strength_bits": 128, "quantum_safe": true},
        "provider_requirements": {"min_fips_level": 3, "constant_time": true}
    }"#;

    fn info(id: &str) -> TemplateSecurityInfo {
        TemplateSecurityInfo {
            template_id: id.into(),
            status: TemplateStatus::Active,
            fips_approved: false,
            quantum_safe: true,
            strength_bits: 192,
        }
    }

    #[test]
    fn the_deck_example_parses() {
        let r = Rules::parse(FULL).unwrap();
        assert_eq!(r.allowed_templates(), ["ml-dsa-65", "ecdsa-p256-sha256-der"]);
        assert!(r.allows_template("ml-dsa-65") && !r.allows_template("ed25519"));
        assert!(r.allows_operation(Operation::Sign) && !r.allows_operation(Operation::Encrypt));
        assert_eq!(r.provider_requirements().min_fips_140_level, 3);
        assert!(r.provider_requirements().constant_time);
    }

    #[test]
    fn empty_and_absent_sections_allow_nothing() {
        for doc in ["", "{}", r#"{"version": "1", "allowed_templates": [], "allowed_operations": {}}"#] {
            let r = Rules::parse(doc).unwrap();
            assert!(!r.allows_template("ml-dsa-65"), "{doc}");
            assert!(!r.allows_operation(Operation::CreateKey), "{doc}");
            assert_eq!(r.provider_requirements(), ProviderRequirements::default());
            assert_eq!(r.check_security(&info("x")), Ok(()));
        }
    }

    #[test]
    fn invalid_documents_are_rejected() {
        for (doc, why) in [
            ("{", "not JSON"),
            (r#"{"version": "1", "alowed_templates": []}"#, "misspelt section"),
            (r#"{"version": "1", "allowed_operations": {"key_operations": ["sing"]}}"#, "unknown operation"),
            (r#"{"allowed_templates": ["a"]}"#, "missing version"),
            (r#"{"version": "2", "allowed_templates": ["a"]}"#, "unsupported version"),
            (r#"{"version": "1", "allowed_templates": [""]}"#, "empty template id"),
            (r#"{"version": "1", "provider_requirements": {"min_fips_level": 5}}"#, "FIPS level"),
            (r#"{"version": "1", "security_requirements": {"fips": true}}"#, "unknown nested field"),
        ] {
            assert!(Rules::parse(doc).is_err(), "{why}: {doc}");
        }
    }

    #[test]
    fn sections_this_library_does_not_enforce_are_rejected() {
        for section in [
            r#""allowed_scopes": []"#,
            r#""allowed_providers": {}"#,
            r#""key_configuration": {}"#,
            r#""allowed_transformations": {"enabled": true}"#,
            r#""allowed_migrations": {"enabled": true}"#,
            r#""allowed_operations": {"keyless_operations": []}"#,
            r#""security_requirements": {"min_nist_status": "approved"}"#,
        ] {
            let err = Rules::parse(&format!(r#"{{"version": "1", {section}}}"#)).unwrap_err();
            assert!(err.contains("not enforced"), "{section}: {err}");
        }
    }

    #[test]
    fn security_floor() {
        let r = Rules::parse(FULL).unwrap();
        assert_eq!(r.check_security(&info("ml-dsa-65")), Ok(()));
        let weak = TemplateSecurityInfo { strength_bits: 112, ..info("weak") };
        assert!(r.check_security(&weak).unwrap_err().contains("112"));
        let classical = TemplateSecurityInfo { quantum_safe: false, ..info("ecdsa") };
        assert!(r.check_security(&classical).unwrap_err().contains("quantum-safe"));

        let strict = Rules::parse(
            r#"{"version": "1", "security_requirements": {"fips_approved": true, "block_deprecated": true}}"#,
        )
        .unwrap();
        assert!(strict.check_security(&info("x")).unwrap_err().contains("FIPS"));
        let deprecated =
            TemplateSecurityInfo { fips_approved: true, status: TemplateStatus::Deprecated, ..info("old") };
        assert!(strict.check_security(&deprecated).unwrap_err().contains("deprecated"));
    }
}
