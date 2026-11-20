use crate::secret::SecretVec;

use super::StoredKey;
use crate::domain::core::Error;
use crate::proto::api;

/// Operation-time parameters of an encryption (the C API's
/// `agc_encrypt_params` oneof, for the arms providers implement).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptParams {
    /// Ciphers without per-message parameters (CBC, CTR).
    None,
    /// AEAD: associated data, authenticated but not encrypted.
    Aead { aad: Vec<u8> },
}

/// The encrypt/decrypt capability of a provider (Go: `provider.Cipher`).
///
/// The sizing methods let the core answer a size query exactly, without any
/// provider work or randomness (agc_crypto_types.h, SIZE QUERIES).
pub trait Cipher: Send + Sync {
    /// The ciphertext length for a plaintext of `plaintext_len` bytes.
    fn ciphertext_len(&self, algorithm: &api::AlgorithmDetails, plaintext_len: usize) -> Result<usize, Error>;

    /// The largest plaintext a ciphertext of `ciphertext_len` bytes can hold.
    fn plaintext_len_bound(&self, algorithm: &api::AlgorithmDetails, ciphertext_len: usize) -> Result<usize, Error>;

    /// The output an encryption produces, its system parameters zeroed: the
    /// shape (kind and lengths) of the metadata, for sizing it.
    fn output_shape(&self, algorithm: &api::AlgorithmDetails) -> Result<api::ProviderOutput, Error>;

    /// Encrypts, generating the system parameters (nonce, IV) it returns in
    /// the output. Every successful encryption sets an output kind.
    fn encrypt(
        &self,
        key: StoredKey<'_>,
        algorithm: &api::AlgorithmDetails,
        plaintext: &[u8],
        params: &EncryptParams,
    ) -> Result<(Vec<u8>, api::ProviderOutput), Error>;

    /// Decrypts with the system parameters the encryption returned. An
    /// authentication failure is `AuthenticationFailed`, and no plaintext
    /// is released.
    fn decrypt(
        &self,
        key: StoredKey<'_>,
        algorithm: &api::AlgorithmDetails,
        ciphertext: &[u8],
        output: &api::ProviderOutput,
        params: &EncryptParams,
    ) -> Result<SecretVec, Error>;
}
