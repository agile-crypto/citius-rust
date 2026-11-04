use super::Policy;
use crate::domain::core::Error;

/// Persists policies by name. Writes are atomic per call, so two concurrent
/// creates of one name cannot both succeed (Go's enforcer checks, then puts).
pub trait PolicyRepository: Send + Sync {
    /// Fails with `AlreadyExists` if the name is taken.
    fn create(&self, p: Policy) -> Result<(), Error>;
    /// Replaces the policy of the same name; `PolicyNotFound` if there is none.
    /// Stores `p` if the stored policy is still at `p.version() - 1`, the
    /// version `p` was derived from (`Policy::with_document`), and, when
    /// `expected_version` > 0, at that version too. `PolicyVersionConflict`
    /// otherwise, and then nothing is stored; `PolicyNotFound` if it is gone.
    fn update(&self, p: Policy, expected_version: i64) -> Result<(), Error>;
    fn get(&self, name: &str) -> Result<Option<Policy>, Error>;
    /// `PolicyNotFound` if there is none.
    fn delete(&self, name: &str) -> Result<(), Error>;
    /// Every policy, ordered by name.
    fn list(&self) -> Result<Vec<Policy>, Error>;
}
