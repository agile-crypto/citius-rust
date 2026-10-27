/// What a caller or a policy requires of the provider that holds a key.
/// Requirements select providers only, never templates (Go:
/// `core.ProviderRequirements`). `false` / 0 means "not required".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProviderRequirements {
    pub fips_140_certified: bool,
    pub min_fips_140_level: u32,
    pub common_criteria_certified: bool,
    pub formally_verified: bool,
    pub memory_safe: bool,
    pub constant_time: bool,
    pub side_channel_hardened: bool,
    pub no_known_cve: bool,
    pub approved_generation: bool,
    /// A preference, not a requirement: ranks providers, excludes none.
    pub prefer_hardware_accelerated: bool,
}

pub const MAX_FIPS_140_LEVEL: u32 = 4;

impl ProviderRequirements {
    /// Both sets of requirements at once. A request can add to a policy's
    /// requirements but never relax them, whichever side `self` is.
    pub fn merge(&self, o: &ProviderRequirements) -> ProviderRequirements {
        ProviderRequirements {
            fips_140_certified: self.fips_140_certified || o.fips_140_certified,
            min_fips_140_level: self.min_fips_140_level.max(o.min_fips_140_level),
            common_criteria_certified: self.common_criteria_certified || o.common_criteria_certified,
            formally_verified: self.formally_verified || o.formally_verified,
            memory_safe: self.memory_safe || o.memory_safe,
            constant_time: self.constant_time || o.constant_time,
            side_channel_hardened: self.side_channel_hardened || o.side_channel_hardened,
            no_known_cve: self.no_known_cve || o.no_known_cve,
            approved_generation: self.approved_generation || o.approved_generation,
            prefer_hardware_accelerated: self.prefer_hardware_accelerated || o.prefer_hardware_accelerated,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_adds_and_never_relaxes() {
        let policy = ProviderRequirements { min_fips_140_level: 3, constant_time: true, ..Default::default() };
        let request = ProviderRequirements { min_fips_140_level: 1, memory_safe: true, ..Default::default() };
        let merged = request.merge(&policy);
        assert_eq!(merged, policy.merge(&request), "symmetric");
        assert_eq!(merged.min_fips_140_level, 3);
        assert!(merged.constant_time && merged.memory_safe);
    }
}
