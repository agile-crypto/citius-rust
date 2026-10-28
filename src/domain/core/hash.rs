use crate::proto::api::HashAlgorithm;

/// The digest length of a fixed-output hash; `None` for XOFs and for hashes
/// without a fixed length here.
// SHA-1 and MD5 are deprecated in the API but still have a defined length.
#[allow(deprecated)]
pub fn hash_output_len(h: HashAlgorithm) -> Option<usize> {
    use HashAlgorithm as H;
    Some(match h {
        H::Sha224 | H::Sha512224 | H::Sha3224 | H::Blake2s224 => 28,
        H::Sha256 | H::Sha512256 | H::Sha3256 | H::Blake2b256 | H::Blake2s256 | H::Blake3 => 32,
        H::Sha384 | H::Sha3384 | H::Blake2b384 => 48,
        H::Sha512 | H::Sha3512 | H::Blake2b512 => 64,
        H::Blake2s160 | H::Sha1 => 20,
        H::Md5 => 16,
        H::GostR341194 | H::GostR34112012256 => 32,
        H::GostR34112012512 => 64,
        H::Unspecified | H::Shake128 | H::Shake256 | H::Other => return None,
    })
}
