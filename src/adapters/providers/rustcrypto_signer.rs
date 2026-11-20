//! The RustCrypto provider's sign/verify capability.
//!
//! - ECDSA P-256/384/521: DER signatures, hedged (RFC 6979 nonces mixed with
//!   fresh randomness, as Go's `crypto/ecdsa`). Messages are hashed with the
//!   template's hash; digests are signed as given.
//! - Ed25519 (RFC 8032): pure, and Ed25519ph over a caller's SHA-512 digest.
//!   Verification is strict (no small-order points, canonical S), matching
//!   the catalog's `nonMalleable: true`.
//! - ML-DSA-44/65/87 (FIPS 204): hedged unless the template asks for the
//!   deterministic variant (as Go), with an optional context.

use ed25519_dalek::hazmat::{ExpandedSecretKey, raw_sign, raw_sign_prehashed};
use elliptic_curve::{CurveArithmetic, NonZeroScalar, pkcs8::AssociatedOid};
use ml_dsa::signature::SignatureEncoding;
use sha2::Digest;
use zeroize::Zeroizing;

use super::RustCrypto;
use super::stack_budget::{self, EcCurve, MlDsaOp, ml_dsa_kib};
use crate::domain::core::{Code, Error, hash_output_len};
use crate::domain::provider::{Cached, Encoding, SignContext, Signer, StoredKey};
use crate::proto::api::{self, HashAlgorithm, algorithm_details::Algorithm, provider_output::AlgorithmOutput};

const OP: &str = "RustCrypto::sign";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Curve {
    P256,
    P384,
    P521,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MlDsa {
    L44,
    L65,
    L87,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Scheme {
    /// `hash` is the template's message hash; prehashed templates have none.
    Ecdsa {
        curve: Curve,
        hash: Option<HashAlgorithm>,
    },
    Ed25519 {
        prehashed: bool,
    },
    MlDsa {
        level: MlDsa,
        deterministic: bool,
    },
}

/// Runs a scheme's operation where it has the stack it needs (F12): ML-DSA
/// by its measured budget, ECDSA so that a curve's first use gets room for
/// its table, Ed25519 inline.
fn on_stack<T: Send>(s: Scheme, op: MlDsaOp, f: impl FnOnce() -> Result<T, Error> + Send) -> Result<T, Error> {
    match s {
        Scheme::MlDsa { level, .. } => {
            let level = match level {
                MlDsa::L44 => 44,
                MlDsa::L65 => 65,
                MlDsa::L87 => 87,
            };
            stack_budget::run(ml_dsa_kib(level, op), f)
        }
        Scheme::Ecdsa { curve, .. } => stack_budget::ecdsa(
            match curve {
                Curve::P256 => EcCurve::P256,
                Curve::P384 => EcCurve::P384,
                Curve::P521 => EcCurve::P521,
            },
            f,
        ),
        Scheme::Ed25519 { .. } => f(),
    }
}

fn not_supported(what: impl std::fmt::Display) -> Error {
    Error::new(Code::NotImplemented, OP, format!("{what} is not supported by the rustcrypto provider"))
}

fn scheme(algorithm: &api::AlgorithmDetails) -> Result<Scheme, Error> {
    match algorithm.algorithm.as_ref() {
        Some(Algorithm::Ecdsa(p)) => {
            if api::SignatureFormat::try_from(p.signature_format) != Ok(api::SignatureFormat::Der) {
                return Err(not_supported(format_args!("ECDSA signature format {}", p.signature_format)));
            }
            let curve = match api::EllipticCurve::try_from(p.curve) {
                Ok(api::EllipticCurve::P256) => Curve::P256,
                Ok(api::EllipticCurve::P384) => Curve::P384,
                Ok(api::EllipticCurve::P521) => Curve::P521,
                _ => return Err(not_supported(format_args!("ECDSA curve {}", p.curve))),
            };
            let hash = match HashAlgorithm::try_from(p.hash) {
                Ok(HashAlgorithm::Unspecified) => None,
                Ok(h @ (HashAlgorithm::Sha256 | HashAlgorithm::Sha384 | HashAlgorithm::Sha512)) => Some(h),
                _ => return Err(not_supported(format_args!("ECDSA message hash {}", p.hash))),
            };
            // A message hash at least as strong as the curve (Go: curveMinHash).
            if let Some(h) = hash
                && !accepted_digests(Scheme::Ecdsa { curve, hash: None }).contains(&h)
            {
                return Err(Error::new(
                    Code::InvalidArgument,
                    OP,
                    format!("{h:?} is weaker than the curve {curve:?} requires"),
                ));
            }
            Ok(Scheme::Ecdsa { curve, hash })
        }
        Some(Algorithm::Ed25519(p)) => match api::Ed25519Variant::try_from(p.variant) {
            Ok(api::Ed25519Variant::Pure) => Ok(Scheme::Ed25519 { prehashed: false }),
            Ok(api::Ed25519Variant::Ph) => Ok(Scheme::Ed25519 { prehashed: true }),
            _ => Err(not_supported(format_args!("Ed25519 variant {}", p.variant))),
        },
        Some(Algorithm::MlDsa(p)) => {
            let level = match api::MlDsaParameterSet::try_from(p.parameter_set) {
                Ok(api::MlDsaParameterSet::MlDsa44) => MlDsa::L44,
                Ok(api::MlDsaParameterSet::MlDsa65) => MlDsa::L65,
                Ok(api::MlDsaParameterSet::MlDsa87) => MlDsa::L87,
                _ => return Err(not_supported(format_args!("ML-DSA parameter set {}", p.parameter_set))),
            };
            Ok(Scheme::MlDsa { level, deterministic: p.deterministic })
        }
        _ => Err(not_supported("this algorithm for signing")),
    }
}

/// The hashes whose digests a prehashed template signs. The pinned catalog
/// does not carry this list; it follows the current citius-server catalog
/// (DEVIATIONS.md): a digest at least as strong as the curve.
fn accepted_digests(s: Scheme) -> &'static [HashAlgorithm] {
    use HashAlgorithm as H;
    match s {
        Scheme::Ecdsa { curve: Curve::P256, hash: None } => &[H::Sha256, H::Sha384, H::Sha512],
        Scheme::Ecdsa { curve: Curve::P384, hash: None } => &[H::Sha384, H::Sha512],
        Scheme::Ecdsa { curve: Curve::P521, hash: None } => &[H::Sha512],
        Scheme::Ed25519 { prehashed: true } => &[H::Sha512],
        _ => &[],
    }
}

fn check_digest(s: Scheme, digest: &[u8], hash: HashAlgorithm) -> Result<(), Error> {
    if !accepted_digests(s).contains(&hash) {
        return Err(Error::new(
            Code::InvalidArgument,
            OP,
            format!("{hash:?} digests are not accepted by this key's algorithm (accepted: {:?})", accepted_digests(s)),
        ));
    }
    if hash_output_len(hash) != Some(digest.len()) {
        return Err(Error::new(
            Code::InvalidArgument,
            OP,
            format!("a {hash:?} digest has {:?} bytes, not {}", hash_output_len(hash), digest.len()),
        ));
    }
    Ok(())
}

/// Message signing on a prehashed template, or the reverse, is refused: the
/// template decides which entry point a key serves.
fn check_entry(s: Scheme, digest: bool) -> Result<(), Error> {
    let prehashed = match s {
        Scheme::Ecdsa { hash, .. } => hash.is_none(),
        Scheme::Ed25519 { prehashed } => prehashed,
        Scheme::MlDsa { .. } => false,
    };
    if prehashed != digest {
        let what = if digest { "digest" } else { "message" };
        return Err(Error::new(
            Code::KeyOperationNotAllowed,
            OP,
            format!("this key's algorithm does not sign a {what}"),
        ));
    }
    Ok(())
}

/// The context each scheme takes: ECDSA and pure Ed25519 none (Ed25519ctx is
/// not offered), Ed25519ph and ML-DSA up to 255 bytes.
fn context(s: Scheme, c: &SignContext) -> Result<Option<&[u8]>, Error> {
    match (s, c) {
        (_, SignContext::None) => Ok(None),
        (Scheme::Ed25519 { prehashed: true } | Scheme::MlDsa { .. }, SignContext::Domain(c)) if c.len() <= 255 => {
            Ok(Some(c))
        }
        (Scheme::Ed25519 { prehashed: true } | Scheme::MlDsa { .. }, SignContext::Domain(c)) => {
            Err(Error::new(Code::InvalidArgument, OP, format!("a context has at most 255 bytes, not {}", c.len())))
        }
        (_, SignContext::Domain(_)) => {
            Err(Error::new(Code::InvalidArgument, OP, "this key's algorithm takes no domain context"))
        }
    }
}

fn sha(hash: HashAlgorithm, message: &[u8]) -> Vec<u8> {
    match hash {
        HashAlgorithm::Sha256 => sha2::Sha256::digest(message).to_vec(),
        HashAlgorithm::Sha384 => sha2::Sha384::digest(message).to_vec(),
        HashAlgorithm::Sha512 => sha2::Sha512::digest(message).to_vec(),
        _ => unreachable!("scheme() admits SHA-2 message hashes only"),
    }
}

fn bad_key(what: &str) -> Error {
    Error::new(Code::InvalidKeyMaterial, OP, format!("the stored {what} does not parse"))
}

fn public<'a>(key: StoredKey<'a>, want: Encoding) -> Result<&'a [u8], Error> {
    match &key.public {
        Some((bytes, enc)) if *enc == want => Ok(bytes),
        _ => Err(bad_key("public key")),
    }
}

fn randomness_failed() -> Error {
    Error::new(Code::InsufficientEntropy, OP, "signing failed: the OS random generator failed")
}

/// The private scalar of a SEC1 `ECPrivateKey`. Unlike
/// `SecretKey::from_sec1_der` it does not check the embedded public key
/// against the scalar: that is a scalar multiplication per call, and signing
/// never reads the public key. Wiped when dropped.
fn ec_scalar<C>(key: StoredKey<'_>) -> Result<Zeroizing<NonZeroScalar<C>>, Error>
where
    C: CurveArithmetic + AssociatedOid,
{
    key.check_encoding(Encoding::Sec1Der)?;
    let sec1 = sec1::EcPrivateKey::try_from(key.private).map_err(|_| bad_key("ECDSA private key"))?;
    if sec1.parameters.is_some_and(|p| p.named_curve() != Some(C::OID)) {
        return Err(bad_key("ECDSA private key (another curve)"));
    }
    let secret =
        elliptic_curve::SecretKey::<C>::from_slice(sec1.private_key).map_err(|_| bad_key("ECDSA private key"))?;
    Ok(Zeroizing::new(secret.to_nonzero_scalar()))
}

/// Hedged ECDSA over a digest, DER-encoded: RFC 6979 nonces mixed with the
/// randomness `fill` gives. This is what `SigningKey::sign_prehash_with_rng`
/// does, minus deriving the public key it never uses for signing.
macro_rules! ecdsa_sign {
    ($curve:ident :: $c:ident, $key:expr, $prehash:expr, $fill:expr) => {{
        type C = $curve::$c;
        let d = ec_scalar::<C>($key)?;
        let mut ad = elliptic_curve::FieldBytes::<C>::default();
        $fill(&mut ad)?;
        let (sig, _) =
            ecdsa::hazmat::sign_prehashed_rfc6979::<C, <C as ecdsa::DigestAlgorithm>::Digest>(&d, $prehash, &ad);
        $curve::ecdsa::DerSignature::from(sig).to_vec()
    }};
}

/// The public key, decoded once per version.
macro_rules! ecdsa_verify {
    ($curve:ident, $key:expr, $prehash:expr, $sig:expr) => {{
        use $curve::ecdsa::signature::hazmat::PrehashVerifier;
        use $curve::pkcs8::DecodePublicKey;
        let vk = $key.public_value(|| {
            $curve::ecdsa::VerifyingKey::from_public_key_der(public($key, Encoding::SpkiDer)?)
                .map_err(|_| bad_key("ECDSA public key"))
        })?;
        match $curve::ecdsa::DerSignature::from_bytes($sig) {
            Ok(sig) => vk.verify_prehash($prehash, &sig).is_ok(),
            Err(_) => false,
        }
    }};
}

fn ecdsa_sign(curve: Curve, key: StoredKey<'_>, prehash: &[u8]) -> Result<Vec<u8>, Error> {
    ecdsa_sign_with(curve, key, prehash, |ad| getrandom::fill(ad).map_err(|_| randomness_failed()))
}

fn ecdsa_sign_with(
    curve: Curve,
    key: StoredKey<'_>,
    prehash: &[u8],
    fill: impl FnOnce(&mut [u8]) -> Result<(), Error>,
) -> Result<Vec<u8>, Error> {
    Ok(match curve {
        Curve::P256 => ecdsa_sign!(p256::NistP256, key, prehash, fill),
        Curve::P384 => ecdsa_sign!(p384::NistP384, key, prehash, fill),
        Curve::P521 => ecdsa_sign!(p521::NistP521, key, prehash, fill),
    })
}

fn ecdsa_verify(curve: Curve, key: StoredKey<'_>, prehash: &[u8], sig: &[u8]) -> Result<bool, Error> {
    Ok(match curve {
        Curve::P256 => ecdsa_verify!(p256, key, prehash, sig),
        Curve::P384 => ecdsa_verify!(p384, key, prehash, sig),
        Curve::P521 => ecdsa_verify!(p521, key, prehash, sig),
    })
}

/// A SHA-512 digest the caller computed, presented to ed25519-dalek as the
/// already-finished hash it asks for: `finalize` returns it unchanged.
/// Feeding it more data is a bug, so `update` refuses rather than mixing it
/// in silently.
#[derive(Clone)]
struct Sha512Digest([u8; 64]);

impl Default for Sha512Digest {
    fn default() -> Self {
        Sha512Digest([0; 64])
    }
}

impl sha2::digest::HashMarker for Sha512Digest {}

impl sha2::digest::OutputSizeUser for Sha512Digest {
    type OutputSize = sha2::digest::consts::U64;
}

impl sha2::digest::Update for Sha512Digest {
    fn update(&mut self, _: &[u8]) {
        unreachable!("a precomputed digest takes no further input");
    }
}

impl sha2::digest::FixedOutput for Sha512Digest {
    fn finalize_into(self, out: &mut sha2::digest::Output<Self>) {
        out.copy_from_slice(&self.0);
    }
}

/// The expanded secret (scalar and nonce prefix), from the PKCS#8 seed: one
/// SHA-512, no curve arithmetic. Wiped when dropped.
fn ed25519_secret(key: StoredKey<'_>) -> Result<ExpandedSecretKey, Error> {
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    key.check_encoding(Encoding::Pkcs8Der)?;
    let pair =
        ed25519_dalek::pkcs8::KeypairBytes::from_pkcs8_der(key.private).map_err(|_| bad_key("Ed25519 private key"))?;
    Ok(ExpandedSecretKey::from(&pair.secret_key))
}

/// The public key, derived from the secret once per version. Signing must
/// use the key that belongs to the secret: a signature made with another
/// public key leaks the secret (the double-public-key oracle), so it is
/// never taken from the stored copy. The stored copy, which verification
/// would otherwise use, must match it.
fn ed25519_public<'a>(key: StoredKey<'a>) -> Result<Cached<'a, ed25519_dalek::VerifyingKey>, Error> {
    use ed25519_dalek::pkcs8::DecodePublicKey;
    key.public_value(|| {
        let vk = ed25519_dalek::VerifyingKey::from(&ed25519_secret(key)?);
        if let Some((spki, Encoding::SpkiDer)) = key.public
            && ed25519_dalek::VerifyingKey::from_public_key_der(spki).ok() != Some(vk)
        {
            return Err(Error::new(
                Code::InvalidKeyMaterial,
                OP,
                "the stored Ed25519 public key is not the private key's",
            ));
        }
        Ok(vk)
    })
}

fn ed25519_digest(digest: &[u8]) -> Sha512Digest {
    Sha512Digest(digest.try_into().expect("check_digest admits 64-byte SHA-512 digests only"))
}

fn ml_dsa_sign<P: ml_dsa::MlDsaParams>(
    key: StoredKey<'_>,
    message: &[u8],
    ctx: &[u8],
    deterministic: bool,
) -> Result<Vec<u8>, Error>
where
    ml_dsa::SigningKey<P>: ml_dsa::pkcs8::DecodePrivateKey,
{
    use ml_dsa::pkcs8::DecodePrivateKey;
    key.check_encoding(Encoding::Pkcs8Der)?;
    let sk = ml_dsa::SigningKey::<P>::from_pkcs8_der(key.private).map_err(|_| bad_key("ML-DSA private key"))?;
    let sig = if deterministic {
        // The context length is checked before, so this cannot fail.
        sk.expanded_key()
            .sign_deterministic(message, ctx)
            .map_err(|_| Error::new(Code::Internal, OP, "ML-DSA signing failed"))?
    } else {
        // The context length is checked before; what remains is the RNG.
        sk.expanded_key().sign_randomized(message, ctx, &mut getrandom::SysRng).map_err(|_| randomness_failed())?
    };
    Ok(sig.encode().to_vec())
}

fn ml_dsa_verify<P: ml_dsa::MlDsaParams>(
    key: StoredKey<'_>,
    message: &[u8],
    ctx: &[u8],
    sig: &[u8],
) -> Result<bool, Error> {
    let public = public(key, Encoding::Raw)?;
    let encoded = ml_dsa::EncodedVerifyingKey::<P>::try_from(public).map_err(|_| bad_key("ML-DSA public key"))?;
    let vk = ml_dsa::VerifyingKey::<P>::decode(&encoded);
    let Some(sig) = ml_dsa::EncodedSignature::<P>::try_from(sig).ok().and_then(|s| ml_dsa::Signature::<P>::decode(&s))
    else {
        return Ok(false);
    };
    Ok(vk.verify_with_context(message, ctx, &sig))
}

/// The longest DER `ECDSA-Sig-Value` for a field of `n` bytes: two INTEGERs
/// of up to n+1 bytes (a leading zero) in a SEQUENCE.
const fn der_max(n: usize) -> usize {
    let content = 2 * (2 + n + 1);
    content + if content < 128 { 2 } else { 3 }
}

fn no_output(encoding: &str) -> api::ProviderOutput {
    api::ProviderOutput {
        encoding: encoding.into(),
        algorithm_output: Some(AlgorithmOutput::NoOutput(api::NoAlgorithmOutput {})),
    }
}

impl RustCrypto {
    fn sign_message(
        &self,
        s: Scheme,
        key: StoredKey<'_>,
        message: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        match s {
            Scheme::Ecdsa { curve, hash: Some(h) } => ecdsa_sign(curve, key, &sha(h, message)),
            Scheme::Ed25519 { prehashed: false } => {
                let vk = ed25519_public(key)?;
                Ok(raw_sign::<sha2::Sha512>(&ed25519_secret(key)?, message, &vk).to_bytes().to_vec())
            }
            Scheme::MlDsa { level, deterministic: d } => {
                let ctx = ctx.unwrap_or_default();
                match level {
                    MlDsa::L44 => ml_dsa_sign::<ml_dsa::MlDsa44>(key, message, ctx, d),
                    MlDsa::L65 => ml_dsa_sign::<ml_dsa::MlDsa65>(key, message, ctx, d),
                    MlDsa::L87 => ml_dsa_sign::<ml_dsa::MlDsa87>(key, message, ctx, d),
                }
            }
            _ => unreachable!("check_entry admits message schemes only"),
        }
    }

    fn verify_message(
        &self,
        s: Scheme,
        key: StoredKey<'_>,
        message: &[u8],
        sig: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<bool, Error> {
        match s {
            Scheme::Ecdsa { curve, hash: Some(h) } => ecdsa_verify(curve, key, &sha(h, message), sig),
            Scheme::Ed25519 { prehashed: false } => {
                let vk = ed25519_public(key)?;
                Ok(ed25519_dalek::Signature::from_slice(sig).is_ok_and(|sig| vk.verify_strict(message, &sig).is_ok()))
            }
            Scheme::MlDsa { level, .. } => {
                let ctx = ctx.unwrap_or_default();
                match level {
                    MlDsa::L44 => ml_dsa_verify::<ml_dsa::MlDsa44>(key, message, ctx, sig),
                    MlDsa::L65 => ml_dsa_verify::<ml_dsa::MlDsa65>(key, message, ctx, sig),
                    MlDsa::L87 => ml_dsa_verify::<ml_dsa::MlDsa87>(key, message, ctx, sig),
                }
            }
            _ => unreachable!("check_entry admits message schemes only"),
        }
    }
}

impl Signer for RustCrypto {
    fn signature_len_bound(&self, algorithm: &api::AlgorithmDetails) -> Result<usize, Error> {
        Ok(match scheme(algorithm)? {
            Scheme::Ecdsa { curve: Curve::P256, .. } => der_max(32),
            Scheme::Ecdsa { curve: Curve::P384, .. } => der_max(48),
            Scheme::Ecdsa { curve: Curve::P521, .. } => der_max(66),
            Scheme::Ed25519 { .. } => ed25519_dalek::SIGNATURE_LENGTH,
            Scheme::MlDsa { level: MlDsa::L44, .. } => 2420,
            Scheme::MlDsa { level: MlDsa::L65, .. } => 3309,
            Scheme::MlDsa { level: MlDsa::L87, .. } => 4627,
        })
    }

    fn output_shape(&self, algorithm: &api::AlgorithmDetails) -> Result<api::ProviderOutput, Error> {
        Ok(match scheme(algorithm)? {
            Scheme::Ecdsa { .. } => no_output("der"),
            Scheme::Ed25519 { .. } | Scheme::MlDsa { .. } => no_output("raw"),
        })
    }

    fn check_digest(&self, algorithm: &api::AlgorithmDetails, digest: &[u8], hash: HashAlgorithm) -> Result<(), Error> {
        let s = scheme(algorithm)?;
        check_entry(s, true)?;
        check_digest(s, digest, hash)
    }

    fn sign(
        &self,
        key: StoredKey<'_>,
        algorithm: &api::AlgorithmDetails,
        message: &[u8],
        c: &SignContext,
    ) -> Result<(Vec<u8>, api::ProviderOutput), Error> {
        let s = scheme(algorithm)?;
        check_entry(s, false)?;
        let ctx = context(s, c)?;
        let signature = on_stack(s, MlDsaOp::Sign, || self.sign_message(s, key, message, ctx))?;
        Ok((signature, self.output_shape(algorithm)?))
    }

    fn verify(
        &self,
        key: StoredKey<'_>,
        algorithm: &api::AlgorithmDetails,
        message: &[u8],
        signature: &[u8],
        c: &SignContext,
    ) -> Result<bool, Error> {
        let s = scheme(algorithm)?;
        check_entry(s, false)?;
        let ctx = context(s, c)?;
        on_stack(s, MlDsaOp::Verify, || self.verify_message(s, key, message, signature, ctx))
    }

    fn sign_digest(
        &self,
        key: StoredKey<'_>,
        algorithm: &api::AlgorithmDetails,
        digest: &[u8],
        hash: HashAlgorithm,
        c: &SignContext,
    ) -> Result<(Vec<u8>, api::ProviderOutput), Error> {
        self.check_digest(algorithm, digest, hash)?;
        let s = scheme(algorithm)?;
        let ctx = context(s, c)?;
        let sig = match s {
            Scheme::Ecdsa { curve, .. } => on_stack(s, MlDsaOp::Sign, || ecdsa_sign(curve, key, digest))?,
            Scheme::Ed25519 { .. } => {
                let vk = ed25519_public(key)?;
                raw_sign_prehashed::<sha2::Sha512, _>(&ed25519_secret(key)?, ed25519_digest(digest), &vk, ctx)
                    .map_err(|_| Error::new(Code::Internal, OP, "Ed25519ph signing failed"))?
                    .to_bytes()
                    .to_vec()
            }
            Scheme::MlDsa { .. } => unreachable!("check_digest refuses ML-DSA"),
        };
        Ok((sig, self.output_shape(algorithm)?))
    }

    fn verify_digest(
        &self,
        key: StoredKey<'_>,
        algorithm: &api::AlgorithmDetails,
        digest: &[u8],
        hash: HashAlgorithm,
        signature: &[u8],
        c: &SignContext,
    ) -> Result<bool, Error> {
        self.check_digest(algorithm, digest, hash)?;
        let s = scheme(algorithm)?;
        let ctx = context(s, c)?;
        match s {
            Scheme::Ecdsa { curve, .. } => on_stack(s, MlDsaOp::Verify, || ecdsa_verify(curve, key, digest, signature)),
            Scheme::Ed25519 { .. } => {
                let vk = ed25519_public(key)?;
                Ok(ed25519_dalek::Signature::from_slice(signature)
                    .is_ok_and(|sig| vk.verify_prehashed_strict(ed25519_digest(digest), ctx, &sig).is_ok()))
            }
            Scheme::MlDsa { .. } => unreachable!("check_digest refuses ML-DSA"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::storage::InMemoryTemplateRegistry;
    use crate::domain::provider::Backend;
    use crate::domain::provider::GeneratedKey;
    use crate::domain::template::TemplateRegistry;

    fn algorithm(id: &str) -> api::AlgorithmDetails {
        let reg = InMemoryTemplateRegistry::standard();
        reg.get(id).unwrap().info().algorithm.clone().unwrap()
    }

    fn key(id: &str) -> (GeneratedKey, api::AlgorithmDetails) {
        let a = algorithm(id);
        (RustCrypto.generate_key(&a).unwrap(), a)
    }

    const MESSAGE_TEMPLATES: &[&str] = &[
        "ecdsa-p256-sha256-der",
        "ecdsa-p384-sha384-der",
        "ecdsa-p521-sha512-der",
        "ed25519",
        "ml-dsa-44",
        "ml-dsa-65",
        "ml-dsa-87",
    ];

    #[test]
    #[cfg_attr(miri, ignore = "third-party signing is too slow under Miri")]
    fn messages_sign_and_verify_within_the_bound() {
        for id in MESSAGE_TEMPLATES {
            let (k, a) = key(id);
            let (sig, out) = RustCrypto.sign(k.as_stored(), &a, b"message", &SignContext::None).unwrap();
            assert!(sig.len() <= RustCrypto.signature_len_bound(&a).unwrap(), "{id}");
            assert_eq!(out, RustCrypto.output_shape(&a).unwrap(), "{id}");
            assert!(RustCrypto.verify(k.as_stored(), &a, b"message", &sig, &SignContext::None).unwrap(), "{id}");
            assert!(
                !RustCrypto.verify(k.as_stored(), &a, b"messagf", &sig, &SignContext::None).unwrap(),
                "{id}: other message"
            );
            let mut flipped = sig.clone();
            *flipped.last_mut().unwrap() ^= 1;
            assert!(
                !RustCrypto.verify(k.as_stored(), &a, b"message", &flipped, &SignContext::None).unwrap(),
                "{id}: flipped"
            );
            // Malformed signatures are invalid, not errors.
            for bad in [&[][..], &sig[..sig.len() - 1], &[0u8; 5000][..]] {
                assert!(
                    !RustCrypto.verify(k.as_stored(), &a, b"message", bad, &SignContext::None).unwrap(),
                    "{id}: {}",
                    bad.len()
                );
            }
            let (other, _) = key(id);
            assert!(
                !RustCrypto.verify(other.as_stored(), &a, b"message", &sig, &SignContext::None).unwrap(),
                "{id}: other key"
            );
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "third-party signing is too slow under Miri")]
    fn ecdsa_and_ml_dsa_are_hedged_ed25519_is_deterministic() {
        for id in ["ecdsa-p256-sha256-der", "ml-dsa-44", "ed25519"] {
            let (k, a) = key(id);
            let one = RustCrypto.sign(k.as_stored(), &a, b"m", &SignContext::None).unwrap().0;
            let two = RustCrypto.sign(k.as_stored(), &a, b"m", &SignContext::None).unwrap().0;
            assert_eq!(one == two, id == "ed25519", "{id}");
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "third-party signing is too slow under Miri")]
    fn ml_dsa_honours_the_deterministic_flag() {
        let (k, mut a) = key("ml-dsa-44");
        if let Some(Algorithm::MlDsa(p)) = a.algorithm.as_mut() {
            p.deterministic = true;
        }
        let one = RustCrypto.sign(k.as_stored(), &a, b"m", &SignContext::None).unwrap().0;
        assert_eq!(one, RustCrypto.sign(k.as_stored(), &a, b"m", &SignContext::None).unwrap().0);
        assert!(RustCrypto.verify(k.as_stored(), &a, b"m", &one, &SignContext::None).unwrap());
    }

    #[test]
    fn an_ecdsa_message_hash_weaker_than_the_curve_is_refused() {
        let mut a = algorithm("ecdsa-p384-sha384-der");
        if let Some(Algorithm::Ecdsa(p)) = a.algorithm.as_mut() {
            p.hash = HashAlgorithm::Sha256 as i32;
        }
        assert_eq!(scheme(&a).unwrap_err().code(), Code::InvalidArgument);
    }

    #[test]
    fn der_bounds_are_the_longest_encodings() {
        assert_eq!((der_max(32), der_max(48), der_max(66)), (72, 104, 141));
    }

    #[test]
    #[cfg_attr(miri, ignore = "third-party signing is too slow under Miri")]
    fn ml_dsa_binds_the_context() {
        let (k, a) = key("ml-dsa-65");
        let ctx = SignContext::Domain(b"app-v1".to_vec());
        let (sig, _) = RustCrypto.sign(k.as_stored(), &a, b"m", &ctx).unwrap();
        assert!(RustCrypto.verify(k.as_stored(), &a, b"m", &sig, &ctx).unwrap());
        assert!(!RustCrypto.verify(k.as_stored(), &a, b"m", &sig, &SignContext::None).unwrap());
        assert!(!RustCrypto.verify(k.as_stored(), &a, b"m", &sig, &SignContext::Domain(b"app-v2".to_vec())).unwrap());
        let long = SignContext::Domain(vec![0; 256]);
        assert_eq!(RustCrypto.sign(k.as_stored(), &a, b"m", &long).unwrap_err().code(), Code::InvalidArgument);
    }

    #[test]
    #[cfg_attr(miri, ignore = "third-party signing is too slow under Miri")]
    fn context_is_refused_where_the_algorithm_has_none() {
        for id in ["ecdsa-p256-sha256-der", "ed25519"] {
            let (k, a) = key(id);
            let err = RustCrypto.sign(k.as_stored(), &a, b"m", &SignContext::Domain(b"c".to_vec())).unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument, "{id}");
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "third-party signing is too slow under Miri")]
    fn digests_sign_and_verify_with_accepted_hashes() {
        let cases: &[(&str, &[HashAlgorithm])] = &[
            ("ecdsa-p256-prehashed-der", &[HashAlgorithm::Sha256, HashAlgorithm::Sha384, HashAlgorithm::Sha512]),
            ("ecdsa-p384-prehashed-der", &[HashAlgorithm::Sha384, HashAlgorithm::Sha512]),
            ("ecdsa-p521-prehashed-der", &[HashAlgorithm::Sha512]),
            ("ed25519ph", &[HashAlgorithm::Sha512]),
        ];
        for (id, hashes) in cases {
            let (k, a) = key(id);
            for h in *hashes {
                let digest = sha(*h, b"message");
                let (sig, _) = RustCrypto.sign_digest(k.as_stored(), &a, &digest, *h, &SignContext::None).unwrap();
                assert!(sig.len() <= RustCrypto.signature_len_bound(&a).unwrap());
                assert!(
                    RustCrypto.verify_digest(k.as_stored(), &a, &digest, *h, &sig, &SignContext::None).unwrap(),
                    "{id} {h:?}"
                );
                let other = sha(*h, b"other");
                assert!(
                    !RustCrypto.verify_digest(k.as_stored(), &a, &other, *h, &sig, &SignContext::None).unwrap(),
                    "{id} {h:?}"
                );
            }
            // SHA-224 is too weak for every curve here; a SHA-256-length
            // digest declared as SHA-512 is refused by length.
            let short = sha(HashAlgorithm::Sha256, b"m");
            let err = RustCrypto
                .sign_digest(k.as_stored(), &a, &short[..28], HashAlgorithm::Sha224, &SignContext::None)
                .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument, "{id}");
            let err = RustCrypto
                .sign_digest(k.as_stored(), &a, &short, HashAlgorithm::Sha512, &SignContext::None)
                .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument, "{id}");
        }
    }

    /// Ed25519ph over a caller's digest is the RFC 8032 Ed25519ph of the
    /// message (the precomputed-digest adapter adds nothing).
    #[test]
    #[cfg_attr(miri, ignore = "third-party signing is too slow under Miri")]
    fn ed25519ph_matches_rfc8032_test_vector() {
        // RFC 8032 section 7.3, TEST abc.
        let sk = hex("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42");
        let msg = b"abc";
        let want = hex("98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae41\
             31f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406");
        let signing = ed25519_dalek::SigningKey::from_bytes(&sk.try_into().unwrap());
        let sig = signing.sign_prehashed(ed25519_digest(&sha(HashAlgorithm::Sha512, msg)), None).unwrap();
        assert_eq!(sig.to_bytes().to_vec(), want);
    }

    #[test]
    fn message_and_digest_entry_points_are_separate() {
        let ecdsa = scheme(&algorithm("ecdsa-p256-sha256-der")).unwrap();
        let pre = scheme(&algorithm("ecdsa-p256-prehashed-der")).unwrap();
        assert_eq!(check_entry(ecdsa, true).unwrap_err().code(), Code::KeyOperationNotAllowed);
        assert_eq!(check_entry(pre, false).unwrap_err().code(), Code::KeyOperationNotAllowed);
        let ml = scheme(&algorithm("ml-dsa-44")).unwrap();
        assert_eq!(check_entry(ml, true).unwrap_err().code(), Code::KeyOperationNotAllowed);
    }

    /// The randomness `ecdsa_sign` mixes in, fixed for a test.
    struct Fixed(Vec<u8>);

    impl p256::ecdsa::signature::rand_core::TryRng for Fixed {
        type Error = std::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            unreachable!("ECDSA draws bytes")
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            unreachable!("ECDSA draws bytes")
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            dst.copy_from_slice(&self.0[..dst.len()]);
            Ok(())
        }
    }

    impl p256::ecdsa::signature::rand_core::TryCryptoRng for Fixed {}

    /// Signing from the scalar gives the very signature the full signing
    /// key gave (the same RFC 6979 nonce from the same randomness), and it
    /// verifies under the stored public key.
    #[test]
    #[cfg_attr(miri, ignore = "third-party signing is too slow under Miri")]
    fn ecdsa_from_the_scalar_is_byte_identical() {
        use p256::ecdsa::signature::hazmat::RandomizedPrehashSigner;
        macro_rules! old {
            ($curve:ident, $k:expr, $z:expr, $ad:expr) => {{
                let secret = $curve::SecretKey::from_sec1_der(&$k.private).unwrap();
                let sig: $curve::ecdsa::DerSignature =
                    $curve::ecdsa::SigningKey::from(&secret).sign_prehash_with_rng(&mut Fixed($ad), $z).unwrap();
                sig.to_vec()
            }};
        }
        let ad = (0..66u8).collect::<Vec<_>>();
        for (id, curve) in [
            ("ecdsa-p256-prehashed-der", Curve::P256),
            ("ecdsa-p384-prehashed-der", Curve::P384),
            ("ecdsa-p521-prehashed-der", Curve::P521),
        ] {
            let (k, a) = key(id);
            let z = sha(HashAlgorithm::Sha512, b"message");
            let new = ecdsa_sign_with(curve, k.as_stored(), &z, |out| {
                out.copy_from_slice(&ad[..out.len()]);
                Ok(())
            })
            .unwrap();
            let want = match curve {
                Curve::P256 => old!(p256, k, &z, ad.clone()),
                Curve::P384 => old!(p384, k, &z, ad.clone()),
                Curve::P521 => old!(p521, k, &z, ad.clone()),
            };
            assert_eq!(new, want, "{id}");
            let ok = RustCrypto.verify_digest(k.as_stored(), &a, &z, HashAlgorithm::Sha512, &new, &SignContext::None);
            assert!(ok.unwrap(), "{id}");
        }
    }

    /// The hazmat path gives the signatures the full signing key gave, pure
    /// and prehashed (Ed25519 is deterministic).
    #[test]
    #[cfg_attr(miri, ignore = "third-party signing is too slow under Miri")]
    fn ed25519_from_the_expanded_secret_is_byte_identical() {
        use ed25519_dalek::Signer as _;
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        for id in ["ed25519", "ed25519ph"] {
            let (k, a) = key(id);
            let full = ed25519_dalek::SigningKey::from_pkcs8_der(&k.private).unwrap();
            let (sig, want) = if id == "ed25519" {
                (RustCrypto.sign(k.as_stored(), &a, b"m", &SignContext::None).unwrap().0, full.sign(b"m"))
            } else {
                let digest = sha(HashAlgorithm::Sha512, b"m");
                let ctx = SignContext::Domain(b"c".to_vec());
                let sig = RustCrypto.sign_digest(k.as_stored(), &a, &digest, HashAlgorithm::Sha512, &ctx).unwrap().0;
                (sig, full.sign_prehashed(ed25519_digest(&digest), Some(b"c")).unwrap())
            };
            assert_eq!(sig, want.to_bytes(), "{id}");
        }
    }

    /// A stored public key that is not the private key's is refused for
    /// signing and verifying: signing with a wrong public key would leak the
    /// secret.
    #[test]
    #[cfg_attr(miri, ignore = "third-party signing is too slow under Miri")]
    fn ed25519_refuses_a_public_key_that_is_not_the_secrets() {
        let (mut k, a) = key("ed25519");
        let (other, _) = key("ed25519");
        k.public = other.public;
        let sign = RustCrypto.sign(k.as_stored(), &a, b"m", &SignContext::None).unwrap_err();
        assert_eq!(sign.code(), Code::InvalidKeyMaterial);
        let verify = RustCrypto.verify(k.as_stored(), &a, b"m", &[0; 64], &SignContext::None).unwrap_err();
        assert_eq!(verify.code(), Code::InvalidKeyMaterial);
    }

    /// With a key version, the public key is derived once and kept on the
    /// version; signing and verifying keep working from it.
    #[test]
    #[cfg_attr(miri, ignore = "third-party signing is too slow under Miri")]
    fn a_versions_public_key_is_derived_once() {
        use crate::domain::core::{Scope, ScopeSpecification};
        use crate::domain::key::{Locking, Origin, Provenance, Version};
        for id in ["ed25519", "ecdsa-p256-sha256-der"] {
            let (k, a) = key(id);
            let v = Version::new(
                1,
                id.into(),
                "rustcrypto".into(),
                ScopeSpecification::any_of(Scope::Signature(api::SignatureScope::Standard)),
                k.to_bytes(),
                Provenance { extractable: false, approved_lineage: false, origin: Origin::Generated },
                std::time::SystemTime::UNIX_EPOCH,
                Locking::BestEffort,
            )
            .unwrap();
            let stored = StoredKey::parse(v.material()).unwrap().with_cache(v.cache());
            let (sig, _) = RustCrypto.sign(stored, &a, b"m", &SignContext::None).unwrap();
            assert!(RustCrypto.verify(stored, &a, b"m", &sig, &SignContext::None).unwrap(), "{id}");
            assert!(format!("{:?}", v.cache()).contains("filled: true"), "{id}");
        }
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
}
