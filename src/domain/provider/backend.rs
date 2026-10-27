use super::GeneratedKey;
use crate::domain::core::Error;
use crate::proto::api;

/// A kind of operation a provider can perform. A template's operations need
/// the matching capabilities; startup validation checks that every provider
/// has those its advertised templates need.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    Sign,
    Cipher,
    Mac,
    Hash,
    Random,
    KeyEstablishment,
}

impl Capability {
    /// The capabilities a provider needs to perform `op` on a key; none for
    /// key management, which the core does itself. Dual-function operations
    /// need both of theirs.
    pub fn needed_for(op: api::CryptoOperation) -> &'static [Capability] {
        use api::CryptoOperation as O;
        use Capability as C;
        match op {
            O::Sign | O::Verify | O::DigestSign | O::DigestVerify => &[C::Sign],
            O::Encrypt | O::Decrypt => &[C::Cipher],
            O::GenerateMac | O::VerifyMac => &[C::Mac],
            O::Digest => &[C::Hash],
            O::GenerateRandom | O::SeedRandom => &[C::Random],
            O::WrapKey | O::UnwrapKey | O::DeriveKey | O::KeyAgreement | O::Encapsulate | O::Decapsulate => {
                &[C::KeyEstablishment]
            }
            O::DigestEncrypt | O::DecryptDigest => &[C::Hash, C::Cipher],
            O::SignEncrypt | O::DecryptVerify => &[C::Sign, C::Cipher],
            O::Unspecified
            | O::CreateKey
            | O::ReadKey
            | O::DeleteKey
            | O::RotateKey
            | O::TransformKey
            | O::ImportKey
            | O::ExportKey
            | O::UpdateKeyPolicy
            | O::MigrateKey => &[],
        }
    }
}

/// The contract every crypto provider implements (Go: `provider.Backend`).
/// Providers are shared by every thread of a context.
///
/// Requests and results are Rust types rather than the `caas.provider.v1`
/// messages Go uses: providers here are in process. An adapter for a remote
/// provider would translate.
pub trait Backend: Send + Sync {
    /// The registry key, stored on every key version this provider creates,
    /// so it must be stable.
    fn name(&self) -> &str;

    /// The kind of provider, e.g. "software".
    fn kind(&self) -> &str;

    /// The template ids this provider serves. Startup validation rejects ids
    /// the catalog does not have.
    fn supported_templates(&self) -> &[&'static str];

    fn capabilities(&self) -> &[Capability];

    /// What the provider can substantiate about itself. It must not claim
    /// certifications or properties a real audit would contradict.
    fn implementation(&self) -> api::ImplementationProperties;

    /// New key material for the algorithm a template describes.
    fn generate_key(&self, algorithm: &api::AlgorithmDetails) -> Result<GeneratedKey, Error>;

    /// Whether material for `algorithm` leaves this provider in plaintext:
    /// stored by the core, or exportable. A stateless software provider's
    /// material does; an HSM's non-extractable keys do not. Decides whether
    /// a version is extractable (Go: `releasesMaterial` over the provider's
    /// transfer description).
    fn releases_material(&self, algorithm: &api::AlgorithmDetails) -> bool;
}
