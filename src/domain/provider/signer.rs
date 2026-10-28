use super::GeneratedKey;
use crate::domain::core::Error;
use crate::proto::api;

/// The context a signature is bound to (the C API's `agc_sign_params`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignContext {
    /// No context: ECDSA, Ed25519, ML-DSA's standard scope.
    None,
    /// A domain-separation context of 0-255 bytes (Ed25519ctx, ML-DSA).
    Domain(Vec<u8>),
}

/// The sign/verify capability of a provider (Go: `provider.Signer`).
///
/// A signature that does not verify is `Ok(false)`, never an error: errors
/// mean the request could not be evaluated (Go's rule).
pub trait Signer: Send + Sync {
    /// The longest signature the algorithm produces (DER-encoded ECDSA
    /// signatures vary in length).
    fn signature_len_bound(&self, algorithm: &api::AlgorithmDetails) -> Result<usize, Error>;

    /// The output a signature carries (the "no output" kind, with the
    /// signature's encoding): the shape of the metadata, for sizing it.
    fn output_shape(&self, algorithm: &api::AlgorithmDetails) -> Result<api::ProviderOutput, Error>;

    /// Whether a digest of `hash` with this length is one the algorithm
    /// signs: the check `sign_digest` makes, without key or randomness, so
    /// a size query fails exactly as the operation would.
    fn check_digest(
        &self,
        algorithm: &api::AlgorithmDetails,
        digest: &[u8],
        hash: api::HashAlgorithm,
    ) -> Result<(), Error>;

    fn sign(
        &self,
        key: &GeneratedKey,
        algorithm: &api::AlgorithmDetails,
        message: &[u8],
        context: &SignContext,
    ) -> Result<(Vec<u8>, api::ProviderOutput), Error>;

    fn verify(
        &self,
        key: &GeneratedKey,
        algorithm: &api::AlgorithmDetails,
        message: &[u8],
        signature: &[u8],
        context: &SignContext,
    ) -> Result<bool, Error>;

    /// Signs a digest the caller computed with `hash`.
    fn sign_digest(
        &self,
        key: &GeneratedKey,
        algorithm: &api::AlgorithmDetails,
        digest: &[u8],
        hash: api::HashAlgorithm,
        context: &SignContext,
    ) -> Result<(Vec<u8>, api::ProviderOutput), Error>;

    fn verify_digest(
        &self,
        key: &GeneratedKey,
        algorithm: &api::AlgorithmDetails,
        digest: &[u8],
        hash: api::HashAlgorithm,
        signature: &[u8],
        context: &SignContext,
    ) -> Result<bool, Error>;
}
