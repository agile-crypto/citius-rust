use super::{Backend, Encoding};
use crate::proto::api;

/// How key material for one algorithm can move: as the payload the core
/// stores, as plaintext export/import, or wrapped under a mechanism.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Channels {
    pub stored_payload: Vec<Encoding>,
    pub plaintext: Vec<Encoding>,
    pub wrapped: Vec<String>,
}

/// What a provider releases (`emit`) and takes in (`accept`) for one
/// algorithm (Go: `provider.Transfer`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Transfer {
    pub emit: Channels,
    pub accept: Channels,
}

impl Transfer {
    /// Whether material leaves the provider in plaintext: stored by the core
    /// or exported. Decides whether a version is extractable.
    pub fn releases_material(&self) -> bool {
        !self.emit.stored_payload.is_empty() || !self.emit.plaintext.is_empty()
    }
}

/// What `p` advertises for `algorithm`, minus the plaintext channels when it
/// is a FIPS 140 module at level 3 or 4, which does not let keys in or out
/// in plaintext (Go: `provider.TransferOf`).
pub fn transfer_of(p: &dyn Backend, algorithm: &api::AlgorithmDetails) -> Transfer {
    let mut t = p.transfer(algorithm);
    let level = p.implementation().fips_140.filter(|f| f.certified).map(|f| f.level);
    if level.is_some_and(|l| l >= 3) {
        for c in [&mut t.emit, &mut t.accept] {
            c.stored_payload.clear();
            c.plaintext.clear();
        }
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::provider::testing::FakeProvider;

    #[test]
    fn fips_level_3_modules_move_no_plaintext() {
        let alg = api::AlgorithmDetails::default();
        let sw = FakeProvider::new("sw", &["t"]);
        assert!(transfer_of(&sw, &alg).releases_material());
        let hsm = FakeProvider::new("hsm", &["t"]).with(|i| {
            i.fips_140 = Some(api::Fips140Certification { certified: true, level: 3, ..Default::default() })
        });
        let t = transfer_of(&hsm, &alg);
        assert!(!t.releases_material() && t.accept.stored_payload.is_empty());
        let l2 = FakeProvider::new("l2", &["t"]).with(|i| {
            i.fips_140 = Some(api::Fips140Certification { certified: true, level: 2, ..Default::default() })
        });
        assert!(transfer_of(&l2, &alg).releases_material());
    }
}
