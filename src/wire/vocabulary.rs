//! Compile-time proof that the model's enums (`domain::core::vocabulary`)
//! and the API's enums of the same names agree, value for value and number
//! for number. An exhaustive match fails to compile when the API gains a
//! value, and an assertion fails when a number differs.

use crate::domain::core as model;
use crate::proto::api;

macro_rules! agree {
    ($($name:ident { $($v:ident),+ $(,)? })+) => {$(
        const _: () = {
            #[allow(dead_code)]
            const fn every_api_value_is_in_the_model(a: api::$name) -> model::$name {
                match a { $(api::$name::$v => model::$name::$v,)+ }
            }
            $(assert!(api::$name::$v as i32 == model::$name::$v as i32);)+
        };
    )+};
}

agree! {
    SignatureScope { Unspecified, Standard, WithContext, Prehashed, PrehashedWithContext }
    AeadScope { Unspecified, Standard, Deterministic, Streaming }
    MacScope { Unspecified, Standard, Streaming }
    KemScope { Unspecified, Standard, Hybrid }
    KeyAgreementScope { Unspecified, Standard, Hybrid }
    KdfScope { Unspecified, ExtractExpand, Password, Agreement, Counter, Tls, Gost, Vendor }
    HashScope { Unspecified, Standard, Xof }
    KeyWrappingScope { Unspecified, Standard, WithPadding }
    SymmetricCipherScope { Unspecified, Block, Stream }
    DiskEncryptionScope { Unspecified, Standard }
    GenericSecretScope { Unspecified, Standard }
    NistSecurityLevel {
        Unspecified, NistSecurityLevel1, NistSecurityLevel2, NistSecurityLevel3, NistSecurityLevel4, NistSecurityLevel5,
    }
    NistStatus { Unspecified, Approved, Recommended, Acceptable, Deprecated, Forbidden }
    KeyLifecycleState { Unspecified, PreActive, Active, Suspended, Deactivated, Compromised, Destroyed, DestroyedCompromised }
    TemplateStatus { Unspecified, Active, Acceptable, Deprecated, Forbidden, Experimental }
}
