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
    /// A copy of the stored policy, for administration.
    fn get(&self, name: &str) -> Result<Option<Policy>, Error>;
    /// Calls `f` once with the stored policy, in place, if there is one by
    /// that name. Every operation checks a policy: this copies nothing and,
    /// in the store here, writes nothing shared (no lock word, no reference
    /// count) that all threads using the policy (one serves many keys) would
    /// contend on (docs/performance.md F7).
    fn inspect(&self, name: &str, f: &mut dyn FnMut(&Policy)) -> Result<(), Error>;
    /// `PolicyNotFound` if there is none.
    fn delete(&self, name: &str) -> Result<(), Error>;
    /// Every policy, ordered by name.
    fn list(&self) -> Result<Vec<Policy>, Error>;
}
