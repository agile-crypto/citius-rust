use std::sync::Arc;
use std::time::SystemTime;

use super::{Policy, PolicyRepository, TemplateSecurityInfo};
use crate::domain::core::{Code, Error, Operation, ProviderRequirements};

/// The half of the policy engine the orchestrators use. Denial is the error
/// (`PolicyViolation`); an unknown policy is `PolicyNotFound`. There is no
/// "no policy" bypass: every call names one.
pub trait Evaluator: Send + Sync {
    /// Whether `op` is allowed, and if a template is given, whether it is.
    fn validate_operation(&self, policy: &str, op: Operation, template_id: Option<&str>) -> Result<(), Error>;

    /// The templates the policy allows, in its order of preference.
    fn allowed_templates(&self, policy: &str) -> Result<Vec<String>, Error>;

    fn provider_requirements(&self, policy: &str) -> Result<ProviderRequirements, Error>;

    /// Whether the template meets the policy's security requirements.
    fn check_template_security(&self, policy: &str, info: &TemplateSecurityInfo) -> Result<(), Error>;
}

/// The half of the policy engine that administers policies.
pub trait Manager: Send + Sync {
    fn create_policy(&self, name: &str, document: &str) -> Result<Policy, Error>;
    fn get_policy(&self, name: &str) -> Result<Policy, Error>;
    /// `expected_version` > 0 makes the update conditional on the stored
    /// version; 0 means last writer wins.
    fn update_policy(&self, name: &str, document: &str, expected_version: i64) -> Result<Policy, Error>;
    fn delete_policy(&self, name: &str) -> Result<(), Error>;
    /// Ordered by name.
    fn list_policies(&self) -> Result<Vec<Policy>, Error>;
}

/// The policy engine: both halves over a repository (Go: `policy.Enforcer`).
pub struct Enforcer {
    policies: Arc<dyn PolicyRepository>,
}

impl Enforcer {
    pub fn new(policies: Arc<dyn PolicyRepository>) -> Self {
        Enforcer { policies }
    }

    fn policy(&self, name: &str, op: &'static str) -> Result<Policy, Error> {
        if name.is_empty() {
            return Err(Error::new(Code::InvalidArgument, op, "a policy name is required"));
        }
        self.policies
            .get(name)?
            .ok_or_else(|| Error::new(Code::PolicyNotFound, op, format!("no policy named {name}")))
    }
}

impl Evaluator for Enforcer {
    fn validate_operation(&self, policy: &str, op: Operation, template_id: Option<&str>) -> Result<(), Error> {
        const OP: &str = "Enforcer::validate_operation";
        let p = self.policy(policy, OP)?;
        if let Some(t) = template_id
            && !p.rules().allows_template(t)
        {
            return Err(Error::new(Code::PolicyViolation, OP, format!("template {t} is not allowed by policy {policy}")));
        }
        if !p.rules().allows_operation(op) {
            return Err(Error::new(
                Code::PolicyViolation,
                OP,
                format!("operation {} is not allowed by policy {policy}", op.as_str()),
            ));
        }
        Ok(())
    }

    fn allowed_templates(&self, policy: &str) -> Result<Vec<String>, Error> {
        Ok(self.policy(policy, "Enforcer::allowed_templates")?.rules().allowed_templates().to_vec())
    }

    fn provider_requirements(&self, policy: &str) -> Result<ProviderRequirements, Error> {
        Ok(self.policy(policy, "Enforcer::provider_requirements")?.rules().provider_requirements())
    }

    fn check_template_security(&self, policy: &str, info: &TemplateSecurityInfo) -> Result<(), Error> {
        const OP: &str = "Enforcer::check_template_security";
        self.policy(policy, OP)?
            .rules()
            .check_security(info)
            .map_err(|m| Error::new(Code::PolicyViolation, OP, format!("{m} (policy {policy})")))
    }
}

impl Manager for Enforcer {
    fn create_policy(&self, name: &str, document: &str) -> Result<Policy, Error> {
        let p = Policy::new(name, document, SystemTime::now())?;
        self.policies.create(p.clone())?;
        Ok(p)
    }

    fn get_policy(&self, name: &str) -> Result<Policy, Error> {
        self.policy(name, "Enforcer::get_policy")
    }

    fn update_policy(&self, name: &str, document: &str, expected_version: i64) -> Result<Policy, Error> {
        const OP: &str = "Enforcer::update_policy";
        if expected_version < 0 {
            return Err(Error::new(
                Code::InvalidArgument,
                OP,
                format!("expected_version must not be negative, got {expected_version}"),
            ));
        }
        let p = self.policy(name, OP)?.with_document(document, SystemTime::now())?;
        self.policies.update(p.clone(), expected_version)?;
        Ok(p)
    }

    fn delete_policy(&self, name: &str) -> Result<(), Error> {
        self.policies.delete(name)
    }

    fn list_policies(&self) -> Result<Vec<Policy>, Error> {
        self.policies.list()
    }
}
