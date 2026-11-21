//! The model's own enumerations. They have the numbers of the API's enums
//! of the same names (caas.crypto.v1), so a value crosses the boundary as
//! its number (`as i32`, `TryFrom<i32>`) at no cost, but the model does not
//! change when the generated code does: `wire::vocabulary` checks at compile
//! time that both sides still agree.

/// Defines a model enum with explicit numbers; the first value is the
/// default, as in protobuf. `TryFrom<i32>` gives back an unknown number.
macro_rules! vocabulary {
    ($($(#[$m:meta])* $name:ident { $first:ident = $n0:literal $(, $v:ident = $n:literal)* $(,)? })+) => {$(
        $(#[$m])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
        #[repr(i32)]
        pub enum $name {
            #[default]
            $first = $n0,
            $($v = $n,)*
        }

        impl TryFrom<i32> for $name {
            type Error = i32;
            fn try_from(v: i32) -> Result<Self, i32> {
                match v {
                    $n0 => Ok($name::$first),
                    $($n => Ok($name::$v),)*
                    _ => Err(v),
                }
            }
        }
    )+};
}

vocabulary! {
    /// The variants of the signature scope family.
    SignatureScope { Unspecified = 0, Standard = 1, WithContext = 2, Prehashed = 3, PrehashedWithContext = 4 }
    AeadScope { Unspecified = 0, Standard = 1, Deterministic = 2, Streaming = 3 }
    MacScope { Unspecified = 0, Standard = 1, Streaming = 2 }
    KemScope { Unspecified = 0, Standard = 1, Hybrid = 2 }
    KeyAgreementScope { Unspecified = 0, Standard = 1, Hybrid = 2 }
    KdfScope {
        Unspecified = 0, ExtractExpand = 1, Password = 2, Agreement = 3, Counter = 4, Tls = 5, Gost = 6, Vendor = 7,
    }
    HashScope { Unspecified = 0, Standard = 1, Xof = 2 }
    KeyWrappingScope { Unspecified = 0, Standard = 1, WithPadding = 2 }
    SymmetricCipherScope { Unspecified = 0, Block = 1, Stream = 2 }
    DiskEncryptionScope { Unspecified = 0, Standard = 1 }
    GenericSecretScope { Unspecified = 0, Standard = 1 }
    /// NIST post-quantum security categories 1-5.
    NistSecurityLevel {
        Unspecified = 0,
        NistSecurityLevel1 = 1,
        NistSecurityLevel2 = 2,
        NistSecurityLevel3 = 3,
        NistSecurityLevel4 = 4,
        NistSecurityLevel5 = 5,
    }
    /// An algorithm's standing with NIST.
    NistStatus { Unspecified = 0, Approved = 1, Recommended = 2, Acceptable = 3, Deprecated = 4, Forbidden = 5 }
    /// A key's lifecycle state (NIST SP 800-57).
    KeyLifecycleState {
        Unspecified = 0,
        PreActive = 1,
        Active = 2,
        Suspended = 3,
        Deactivated = 4,
        Compromised = 5,
        Destroyed = 6,
        DestroyedCompromised = 7,
    }
    /// A template's standing in the catalog.
    TemplateStatus { Unspecified = 0, Active = 1, Acceptable = 2, Deprecated = 3, Forbidden = 4, Experimental = 5 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_round_trip_and_unknown_ones_come_back() {
        assert_eq!(KdfScope::try_from(KdfScope::Gost as i32), Ok(KdfScope::Gost));
        assert_eq!(KeyLifecycleState::try_from(99), Err(99));
        assert_eq!(NistStatus::default(), NistStatus::Unspecified);
    }
}
