use std::time::SystemTime;

use super::Rules;
use crate::domain::core::{Code, Error};

/// A named crypto policy: what the system allows for the keys bound to it.
/// Not access control (who may call what is the application's business).
///
/// The document is kept as written, for reading back; the rules are parsed
/// and validated when the policy is written, so a policy that exists is a
/// valid one and evaluating it never parses JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    name: String,
    document: String,
    rules: Rules,
    /// 1 when created, one more on each update (Go: `Policy.Version`).
    version: i64,
    created_at: SystemTime,
    updated_at: SystemTime,
}

impl Policy {
    pub fn new(name: &str, document: &str, now: SystemTime) -> Result<Policy, Error> {
        const OP: &str = "Policy::new";
        if name.is_empty() {
            return Err(Error::new(Code::InvalidArgument, OP, "policy name must not be empty"));
        }
        Ok(Policy {
            name: name.to_owned(),
            document: document.to_owned(),
            rules: parse(name, document, OP)?,
            version: 1,
            created_at: now,
            updated_at: now,
        })
    }

    /// This policy with a new document, at the next version; the name and
    /// creation time stay.
    pub fn with_document(&self, document: &str, now: SystemTime) -> Result<Policy, Error> {
        Ok(Policy {
            document: document.to_owned(),
            rules: parse(&self.name, document, "Policy::with_document")?,
            version: self.version + 1,
            updated_at: now,
            ..self.clone()
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn document(&self) -> &str {
        &self.document
    }

    pub fn rules(&self) -> &Rules {
        &self.rules
    }

    pub fn version(&self) -> i64 {
        self.version
    }

    pub fn created_at(&self) -> SystemTime {
        self.created_at
    }

    pub fn updated_at(&self) -> SystemTime {
        self.updated_at
    }
}

fn parse(name: &str, document: &str, op: &'static str) -> Result<Rules, Error> {
    Rules::parse(document).map_err(|e| Error::new(Code::InvalidArgument, op, format!("policy {name}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn invalid_name_or_document_is_rejected() {
        let now = SystemTime::now();
        assert_eq!(Policy::new("", "{}", now).unwrap_err().code(), Code::InvalidArgument);
        assert_eq!(Policy::new("p", "{", now).unwrap_err().code(), Code::InvalidArgument);
    }

    #[test]
    fn a_new_document_keeps_name_and_creation_time() {
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let t1 = t0 + Duration::from_secs(5);
        let p = Policy::new("p", "{}", t0).unwrap();
        let q = p.with_document(r#"{"version": "1", "allowed_templates": ["a"]}"#, t1).unwrap();
        assert_eq!((q.name(), q.created_at(), q.updated_at()), ("p", t0, t1));
        assert!(q.rules().allows_template("a"));
        assert_eq!(p.with_document("{", t1).unwrap_err().code(), Code::InvalidArgument);
    }
}
