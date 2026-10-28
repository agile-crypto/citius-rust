use zeroize::Zeroizing;

use crate::domain::core::{Code, Error};

/// How key bytes are encoded, recorded next to them so that the provider
/// picks the right parser instead of guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Encoding {
    /// The bytes as the algorithm defines them (symmetric keys, raw public keys).
    Raw = 1,
    /// SEC1 `ECPrivateKey` (RFC 5915), DER.
    Sec1Der = 2,
    /// PKCS#8 `PrivateKeyInfo` (RFC 5208), DER.
    Pkcs8Der = 3,
    /// X.509 `SubjectPublicKeyInfo` (RFC 5280), DER.
    SpkiDer = 4,
}

impl Encoding {
    fn from_byte(b: u8) -> Option<Encoding> {
        [Encoding::Raw, Encoding::Sec1Der, Encoding::Pkcs8Der, Encoding::SpkiDer].into_iter().find(|e| *e as u8 == b)
    }
}

/// What a provider returns from key generation. The private half is opaque
/// to everyone but the provider that made it: the core stores it as-is and
/// hands it back on every operation (Go: the serialized GenerateKeyResponse).
/// A provider that keeps keys inside itself (an HSM) returns a handle here.
#[derive(Clone, PartialEq, Eq)]
pub struct GeneratedKey {
    pub private: Zeroizing<Vec<u8>>,
    pub private_encoding: Encoding,
    pub public: Option<(Vec<u8>, Encoding)>,
}

impl std::fmt::Debug for GeneratedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.debug_struct("GeneratedKey")
            .field("private", &format_args!("<{} bytes>", self.private.len()))
            .field("private_encoding", &self.private_encoding)
            .field("public", &self.public.as_ref().map(|(b, e)| (b.len(), e)))
            .finish()
    }
}

const FORMAT_V1: u8 = 1;

impl GeneratedKey {
    /// Fails unless the private half is encoded as `want`: a provider parses
    /// stored material by its recorded encoding, never by guessing.
    pub fn check_encoding(&self, want: Encoding) -> Result<(), Error> {
        if self.private_encoding != want {
            return Err(Error::new(
                Code::InvalidKeyMaterial,
                "GeneratedKey::check_encoding",
                format!("key material is {:?}, expected {want:?}", self.private_encoding),
            ));
        }
        Ok(())
    }

    /// The bytes a key version stores. Self-describing and versioned:
    /// `1 | enc | len u32 BE | private | 0 or enc | [len u32 BE | public]`.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(16 + self.private.len()));
        out.push(FORMAT_V1);
        out.push(self.private_encoding as u8);
        put(&mut out, &self.private);
        match &self.public {
            None => out.push(0),
            Some((bytes, enc)) => {
                out.push(*enc as u8);
                put(&mut out, bytes);
            }
        }
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<GeneratedKey, Error> {
        let bad = || Error::new(Code::Internal, "GeneratedKey::from_bytes", "stored key material is malformed");
        let mut r = Reader(b);
        if r.byte()? != FORMAT_V1 {
            return Err(bad());
        }
        let private_encoding = Encoding::from_byte(r.byte()?).ok_or_else(bad)?;
        let private = Zeroizing::new(r.chunk()?.to_vec());
        let public = match r.byte()? {
            0 => None,
            e => Some((r.chunk()?.to_vec(), Encoding::from_byte(e).ok_or_else(bad)?)),
        };
        if !r.0.is_empty() {
            return Err(bad());
        }
        Ok(GeneratedKey { private, private_encoding, public })
    }
}

fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("key material is far below 4 GiB");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn err() -> Error {
        Error::new(Code::Internal, "GeneratedKey::from_bytes", "stored key material is malformed")
    }

    fn byte(&mut self) -> Result<u8, Error> {
        let (&b, rest) = self.0.split_first().ok_or_else(Self::err)?;
        self.0 = rest;
        Ok(b)
    }

    fn chunk(&mut self) -> Result<&'a [u8], Error> {
        let (len, rest) = self.0.split_first_chunk::<4>().ok_or_else(Self::err)?;
        let len = u32::from_be_bytes(*len) as usize;
        if rest.len() < len {
            return Err(Self::err());
        }
        let (chunk, rest) = rest.split_at(len);
        self.0 = rest;
        Ok(chunk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_with_and_without_public_half() {
        let pair = GeneratedKey {
            private: Zeroizing::new(vec![1, 2, 3]),
            private_encoding: Encoding::Pkcs8Der,
            public: Some((vec![9; 40], Encoding::SpkiDer)),
        };
        let symmetric =
            GeneratedKey { private: Zeroizing::new(vec![7; 32]), private_encoding: Encoding::Raw, public: None };
        for k in [pair, symmetric] {
            assert_eq!(GeneratedKey::from_bytes(&k.to_bytes()).unwrap(), k);
        }
    }

    #[test]
    fn malformed_bytes_are_rejected() {
        let good = GeneratedKey { private: Zeroizing::new(vec![1]), private_encoding: Encoding::Raw, public: None }
            .to_bytes();
        let mut trailing = good.to_vec();
        trailing.push(0);
        for bad in [&[][..], &[2, 1, 0, 0, 0, 0, 0], &good[..good.len() - 1], &trailing, &[1, 99, 0, 0, 0, 0, 0]] {
            assert_eq!(GeneratedKey::from_bytes(bad).unwrap_err().code(), Code::Internal, "{bad:?}");
        }
    }

    #[test]
    fn debug_never_shows_key_bytes() {
        let k = GeneratedKey { private: Zeroizing::new(vec![0xAB; 4]), private_encoding: Encoding::Raw, public: None };
        let s = format!("{k:?}");
        assert!(!s.contains("171") && !s.contains("ab") && s.contains("4 bytes"), "{s}");
    }
}
