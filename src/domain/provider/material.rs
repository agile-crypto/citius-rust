use std::any::Any;

use zeroize::Zeroizing;

use crate::domain::core::{Cached, Code, Error, VersionCache};
use crate::secret::extend_secret;

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
    /// The bytes a key version stores. Self-describing and versioned:
    /// `1 | enc | len u32 BE | private | 0 or enc | [len u32 BE | public]`.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        // Sized exactly, so the private key is never in a buffer that a
        // reallocation hands back to the allocator unwiped.
        let public_len = self.public.as_ref().map_or(0, |(b, _)| 4 + b.len());
        let mut out = Zeroizing::new(Vec::with_capacity(3 + 4 + self.private.len() + public_len));
        extend_secret(&mut out, &[FORMAT_V1, self.private_encoding as u8]);
        put(&mut out, &self.private);
        match &self.public {
            None => extend_secret(&mut out, &[0]),
            Some((bytes, enc)) => {
                extend_secret(&mut out, &[*enc as u8]);
                put(&mut out, bytes);
            }
        }
        out
    }

    /// An owned copy of stored material, for tests. The library reads
    /// stored material with `StoredKey::parse`, which copies nothing.
    #[cfg(test)]
    pub fn from_bytes(b: &[u8]) -> Result<GeneratedKey, Error> {
        let k = StoredKey::parse(b)?;
        Ok(GeneratedKey {
            private: Zeroizing::new(k.private.to_vec()),
            private_encoding: k.private_encoding,
            public: k.public.map(|(b, e)| (b.to_vec(), e)),
        })
    }

    /// This key as a provider operates with it (tests drive providers
    /// with freshly generated keys).
    #[cfg(test)]
    pub fn as_stored(&self) -> StoredKey<'_> {
        StoredKey {
            private: &self.private,
            private_encoding: self.private_encoding,
            public: self.public.as_ref().map(|(b, e)| (b.as_slice(), *e)),
            cache: None,
        }
    }
}

/// A key version's material as a provider operates with it: both halves
/// read in place from the stored bytes (`GeneratedKey::to_bytes`), which
/// for a key version are its locked, never-dumped pages. Borrowing, it
/// copies no byte of the private key into ordinary memory (D3).
#[derive(Clone, Copy)]
pub struct StoredKey<'a> {
    pub private: &'a [u8],
    pub private_encoding: Encoding,
    pub public: Option<(&'a [u8], Encoding)>,
    /// The version's cache; none when the material is read outside an
    /// operation (and in provider tests), so every call derives afresh.
    cache: Option<&'a VersionCache>,
}

impl<'a> StoredKey<'a> {
    /// The same key with the cache of the version it belongs to.
    pub fn with_cache(self, cache: &'a VersionCache) -> StoredKey<'a> {
        StoredKey { cache: Some(cache), ..self }
    }

    /// A public value the provider derives from this key, made once per
    /// version (`PublicCache`) if its `bytes` fit the cache budget. `make`
    /// must derive it from this key alone, and it must be public: the cache
    /// is ordinary memory.
    pub fn public_value<T: Any + Send + Sync>(
        &self,
        bytes: usize,
        make: impl FnOnce() -> Result<T, Error>,
    ) -> Result<Cached<'a, T>, Error> {
        match self.cache {
            Some(cache) => cache.public.get_or_try_init(bytes, make),
            None => make().map(Cached::Fresh),
        }
    }

    /// A secret the provider derives from this key, made once per version
    /// and kept in sealed pages (`SecretCache`) if they can be had; else
    /// made per call. `make` must derive it from this key alone.
    ///
    /// # Safety
    /// `T` keeps all its state inline (`secret::Sealed::new`).
    pub unsafe fn secret_value<T: Send + Sync + 'static>(
        &self,
        make: impl Fn() -> Result<T, Error>,
    ) -> Result<Cached<'a, T>, Error> {
        match self.cache {
            // SAFETY: forwarded from this function's contract.
            Some(cache) => unsafe { cache.secret.get_or_try_init(make) },
            None => make().map(Cached::Fresh),
        }
    }

    pub fn parse(b: &'a [u8]) -> Result<StoredKey<'a>, Error> {
        let mut r = Reader(b);
        if r.byte()? != FORMAT_V1 {
            return Err(Reader::err());
        }
        let private_encoding = Encoding::from_byte(r.byte()?).ok_or_else(Reader::err)?;
        let private = r.chunk()?;
        let public = match r.byte()? {
            0 => None,
            e => Some((r.chunk()?, Encoding::from_byte(e).ok_or_else(Reader::err)?)),
        };
        if !r.0.is_empty() {
            return Err(Reader::err());
        }
        Ok(StoredKey { private, private_encoding, public, cache: None })
    }

    /// Fails unless the private half is encoded as `want`: a provider parses
    /// stored material by its recorded encoding, never by guessing.
    pub fn check_encoding(&self, want: Encoding) -> Result<(), Error> {
        if self.private_encoding != want {
            return Err(Error::new(
                Code::InvalidKeyMaterial,
                "StoredKey::check_encoding",
                format!("key material is {:?}, expected {want:?}", self.private_encoding),
            ));
        }
        Ok(())
    }
}

impl std::fmt::Debug for StoredKey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.debug_struct("StoredKey")
            .field("private", &format_args!("<{} bytes>", self.private.len()))
            .field("private_encoding", &self.private_encoding)
            .field("public", &self.public.map(|(b, e)| (b.len(), e)))
            .field("cached", &self.cache.is_some())
            .finish()
    }
}

fn put(out: &mut Zeroizing<Vec<u8>>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("key material is far below 4 GiB");
    extend_secret(out, &len.to_be_bytes());
    extend_secret(out, bytes);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn err() -> Error {
        Error::new(Code::Internal, "StoredKey::parse", "stored key material is malformed")
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
    fn a_stored_key_reads_both_halves_in_place() {
        let k = GeneratedKey {
            private: Zeroizing::new(vec![7; 32]),
            private_encoding: Encoding::Pkcs8Der,
            public: Some((vec![9; 4], Encoding::SpkiDer)),
        };
        let stored = k.to_bytes();
        let view = StoredKey::parse(&stored).unwrap();
        let within = |b: &[u8]| stored.as_ptr_range().contains(&b.as_ptr()) && b.len() <= stored.len();
        assert!(within(view.private) && view.private == [7; 32], "the private half is borrowed, not copied");
        assert!(view.public.is_some_and(|(b, e)| within(b) && b == [9; 4] && e == Encoding::SpkiDer));
        assert_eq!(view.private_encoding, Encoding::Pkcs8Der);
        assert!(view.check_encoding(Encoding::Raw).is_err());
        assert!(!format!("{view:?}").contains('7'), "never printed");
    }

    #[test]
    fn debug_never_shows_key_bytes() {
        let k = GeneratedKey { private: Zeroizing::new(vec![0xAB; 4]), private_encoding: Encoding::Raw, public: None };
        let s = format!("{k:?}");
        assert!(!s.contains("171") && !s.contains("ab") && s.contains("4 bytes"), "{s}");
    }

    #[test]
    #[cfg(not(miri))]
    fn encoding_leaves_no_copy_of_the_private_key_behind() {
        use crate::secret::leak_check::{CANARY, leaks_during};
        // A public key longer than everything before it: before the fix the
        // buffer outgrew its capacity after the private key was written.
        let leaks = leaks_during(|| {
            let k = GeneratedKey {
                private: Zeroizing::new(CANARY.to_vec()),
                private_encoding: Encoding::Pkcs8Der,
                public: Some((vec![7; 2592], Encoding::Raw)),
            };
            let bytes = k.to_bytes();
            let back = GeneratedKey::from_bytes(&bytes).unwrap();
            assert_eq!(&*back.private, &CANARY[..]);
        });
        assert_eq!(leaks, 0);
    }
}
