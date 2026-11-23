use std::ffi::c_char;
use std::ptr;
use std::time::SystemTime;

use crate::app::{Encoding, KeyMetadata, POLICY_FORMAT, Policy};
use crate::bindings::*;
use crate::domain::core::{Scope, ScopeKind, ScopeSpecification, SecurityProperties};
use crate::ffi::error::FfiError;
use crate::proto::api;

use super::{c_guarantees, c_template_info, strs};
use crate::ffi::versioned;

/// Lays out a record's variable-length data (strings, byte strings, arrays)
/// in the caller's storage region, and hands back pointers into it, which
/// the caller reads after we return.
///
/// It runs twice over the same code: first measuring, with no memory behind
/// it, then writing. Running the same code both times is what keeps the
/// reported size and the written layout in step. The measure pass assumes
/// the worst alignment padding, so the write pass always fits.
///
/// Every write and returned pointer derives from the one raw `base` pointer.
/// Going through a `&mut [u8]` instead would make each returned pointer a
/// reborrow that the next write invalidates (found by Miri).
pub struct Packer {
    base: *mut u8,
    cap: usize,
    pos: usize,
    measuring: Measure,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Measure {
    /// Writing for real.
    No,
    /// Base address unknown: assume the worst alignment padding (a bound).
    WorstCase,
    /// Exact, for a region starting at this address.
    At(usize),
}

impl Packer {
    pub fn measuring() -> Self {
        Packer { base: ptr::null_mut(), cap: usize::MAX, pos: 0, measuring: Measure::WorstCase }
    }

    /// Measures exactly what writing into a region at `base` needs. A NULL
    /// region (a size query) is measured as if suitably aligned.
    pub fn measuring_at(base: *const u8) -> Self {
        Packer { base: ptr::null_mut(), cap: usize::MAX, pos: 0, measuring: Measure::At(base as usize) }
    }

    /// The bytes laid out so far (while measuring: the size needed).
    pub fn used(&self) -> usize {
        self.pos
    }

    /// Reserves `len` bytes aligned to `align`, returning where they start
    /// (NULL while measuring).
    fn reserve(&mut self, len: usize, align: usize) -> *mut u8 {
        match self.measuring {
            Measure::WorstCase => {
                // Unknown base alignment: assume the worst padding.
                self.pos += align - 1 + len;
                return ptr::null_mut();
            }
            Measure::At(base) => {
                let addr = base + self.pos;
                self.pos += (addr.next_multiple_of(align) - addr) + len;
                return ptr::null_mut();
            }
            Measure::No => {}
        }
        let addr = self.base as usize + self.pos;
        let start = self.pos + (addr.next_multiple_of(align) - addr);
        let end = start + len;
        // `pack` sized the region with the measure pass; overflow is a bug here.
        assert!(end <= self.cap, "storage packer overflow");
        self.pos = end;
        // SAFETY: start..end lies within the cap bytes the region holds.
        unsafe { self.base.add(start) }
    }

    /// A NUL-terminated copy of `s`.
    pub fn str(&mut self, s: &str) -> *const c_char {
        let p = self.reserve(s.len() + 1, 1);
        if !p.is_null() {
            // SAFETY: p has s.len() + 1 writable bytes (reserve); s is a
            // separate Rust allocation.
            unsafe {
                ptr::copy_nonoverlapping(s.as_ptr(), p, s.len());
                p.add(s.len()).write(0);
            }
        }
        p.cast_const().cast()
    }

    /// A copy of `b` as a slice; empty is `{NULL, 0}`.
    pub fn bytes(&mut self, b: &[u8]) -> agc_slice {
        if b.is_empty() {
            return agc_slice { data: ptr::null(), len: 0 };
        }
        let p = self.reserve(b.len(), 1);
        if !p.is_null() {
            // SAFETY: p has b.len() writable bytes (reserve).
            unsafe { ptr::copy_nonoverlapping(b.as_ptr(), p, b.len()) };
        }
        agc_slice { data: p.cast_const(), len: b.len() }
    }

    /// An array of `T`; empty is NULL.
    pub fn array<T: Copy>(&mut self, items: &[T]) -> *const T {
        if items.is_empty() {
            return ptr::null();
        }
        let p = self.reserve(size_of_val(items), align_of::<T>()).cast::<T>();
        if !p.is_null() {
            // SAFETY: p is aligned for T and has room for items.len() elements (reserve).
            unsafe { ptr::copy_nonoverlapping(items.as_ptr(), p, items.len()) };
        }
        p.cast_const()
    }

    /// Room for `n` elements of `T`, aligned, to fill in later with `fill`
    /// (NULL while measuring, and for n == 0).
    pub fn reserve_array<T>(&mut self, n: usize) -> *mut T {
        if n == 0 {
            return ptr::null_mut();
        }
        self.reserve(n * size_of::<T>(), align_of::<T>()).cast()
    }

    /// Writes `items` into an array from `reserve_array`.
    pub fn fill_array<T: Copy>(&mut self, slot: *mut T, items: &[T]) {
        if !slot.is_null() {
            // SAFETY: slot came from reserve_array for items.len() elements
            // of T, aligned, in this region.
            unsafe { ptr::copy_nonoverlapping(items.as_ptr(), slot, items.len()) };
        }
    }

    /// A key-value list of copied strings.
    pub fn kv_list<'a>(&mut self, kvs: impl Iterator<Item = (&'a String, &'a String)>) -> agc_kv_list {
        let entries: Vec<agc_kv> = kvs.map(|(k, v)| agc_kv { key: self.str(k), value: self.str(v) }).collect();
        agc_kv_list { items: self.array(&entries), count: entries.len() }
    }
}

/// The STORAGE CONTRACT (agc_key_types.h and every *_types.h): a record's
/// variable-length data goes into the caller's `storage` region and the
/// record points into it. `storage_used` is always set: to the size needed
/// if the region is NULL or too small (then nothing else is written and the
/// result is `BufferTooSmall`), else to the bytes used.
///
/// `fill` lays the data out with the `Packer` it is given and returns what
/// to write into the record; it runs once to measure and once to write.
pub fn pack<R>(storage: agc_buf, storage_used: &mut usize, fill: impl Fn(&mut Packer) -> R) -> Result<R, FfiError> {
    let mut m = Packer::measuring();
    fill(&mut m);
    let needed = m.pos;
    *storage_used = needed;
    if storage.data.is_null() || storage.cap < needed {
        return Err(FfiError::BufferTooSmall { needed });
    }
    let mut w = Packer { base: storage.data, cap: storage.cap, pos: 0, measuring: Measure::No };
    let r = fill(&mut w);
    *storage_used = w.pos;
    Ok(r)
}

/// `pack` with an exact requirement, for read-only operations whose size
/// must be exact: measured for the caller's actual region address (a NULL
/// region is measured as if suitably aligned).
pub fn pack_exact<R>(storage: agc_buf, storage_used: &mut usize, fill: impl Fn(&mut Packer) -> R) -> Result<R, FfiError> {
    let mut m = Packer::measuring_at(storage.data);
    fill(&mut m);
    let needed = m.pos;
    *storage_used = needed;
    if needed > 0 && (storage.data.is_null() || storage.cap < needed) {
        return Err(FfiError::BufferTooSmall { needed });
    }
    let mut w = Packer { base: storage.data, cap: storage.cap, pos: 0, measuring: Measure::No };
    let r = fill(&mut w);
    debug_assert_eq!(w.pos, needed, "the exact measure and the write agree");
    Ok(r)
}

/// `pack` for a fixed set of strings, returning one pointer per string.
pub fn pack_strings<const N: usize>(
    storage: agc_buf,
    storage_used: &mut usize,
    strings: [&str; N],
) -> Result<[*const c_char; N], FfiError> {
    pack(storage, storage_used, |p| strings.map(|s| p.str(s)))
}

/// An absent optional timestamp.
pub fn c_no_timestamp() -> agc_timestamp {
    agc_timestamp { seconds: 0, nanos: 0, present: 0 }
}

/// A time as the C API's optional timestamp.
pub fn c_timestamp(t: SystemTime) -> agc_timestamp {
    // Times before 1970 do not occur here (they come from the system clock).
    let d = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    agc_timestamp { seconds: i64::try_from(d.as_secs()).unwrap_or(i64::MAX), nanos: d.subsec_nanos() as i32, present: 1 }
}

/// The C value of a domain scope kind.
pub fn c_scope_kind(kind: ScopeKind) -> agc_scope_kind {
    match kind {
        ScopeKind::Signature => agc_scope_kind_AGC_SCOPE_KIND_SIGNATURE,
        ScopeKind::Aead => agc_scope_kind_AGC_SCOPE_KIND_AEAD,
        ScopeKind::Mac => agc_scope_kind_AGC_SCOPE_KIND_MAC,
        ScopeKind::Kem => agc_scope_kind_AGC_SCOPE_KIND_KEM,
        ScopeKind::KeyAgreement => agc_scope_kind_AGC_SCOPE_KIND_KEY_AGREEMENT,
        ScopeKind::Kdf => agc_scope_kind_AGC_SCOPE_KIND_KDF,
        ScopeKind::Hash => agc_scope_kind_AGC_SCOPE_KIND_HASH,
        ScopeKind::KeyWrapping => agc_scope_kind_AGC_SCOPE_KIND_KEY_WRAPPING,
        ScopeKind::SymmetricCipher => agc_scope_kind_AGC_SCOPE_KIND_SYMMETRIC_CIPHER,
        ScopeKind::GenericSecret => agc_scope_kind_AGC_SCOPE_KIND_GENERIC_SECRET,
        ScopeKind::DiskEncryption => agc_scope_kind_AGC_SCOPE_KIND_DISK_ENCRYPTION,
    }
}

pub fn c_tribool(v: Option<bool>) -> agc_tribool {
    match v {
        None => agc_tribool_AGC_UNSET,
        Some(false) => agc_tribool_AGC_FALSE,
        Some(true) => agc_tribool_AGC_TRUE,
    }
}

fn c_security(s: Option<&SecurityProperties>) -> agc_security_properties {
    let s = s.copied().unwrap_or_default();
    agc_security_properties {
        security_strength_bits: s.strength_bits,
        // agc_types.h is generated from the proto: the numbers are the same.
        nist_security_level: s.nist_level as u32,
        quantum_safe: c_tribool(s.quantum_safe),
        nist_status: s.nist_status as u32,
        fips_approved: c_tribool(s.fips_approved),
    }
}

/// The C form of a scope specification; its additional properties go into
/// storage.
pub fn c_scope_spec(spec: &ScopeSpecification, p: &mut Packer) -> agc_scope_spec {
    // SAFETY: all-zero is a valid agc_scope_spec (integers and raw pointers).
    let mut c: agc_scope_spec = unsafe { std::mem::zeroed() };
    c.struct_size = size_of::<agc_scope_spec>();
    c.kind = c_scope_kind(spec.scope.kind());
    let security = c_security(spec.security.as_ref());
    let additional = p.kv_list(spec.additional.iter());
    let scope = spec.scope.value() as u32;
    let props = &spec.properties;
    // Writing a union member is safe; `kind` above names the one written.
    macro_rules! set {
        ($field:ident { $($extra:ident: $value:expr),* }) => {{
            c.u.$field.scope = scope;
            c.u.$field.security = security;
            c.u.$field.additional_properties = additional;
            $(c.u.$field.$extra = $value;)*
        }};
    }
    match spec.scope {
        Scope::Signature(_) => {
            let hashes: Vec<agc_hash_algorithm> = props.accepted_digest_hashes.iter().map(|&h| h as u32).collect();
            set!(signature {
                non_malleable: c_tribool(props.non_malleable),
                deterministic: c_tribool(props.deterministic),
                accepted_digest_hashes: p.array(&hashes),
                accepted_digest_hashes_count: hashes.len()
            })
        }
        Scope::Aead(_) => set!(aead { nonce_misuse_resistant: c_tribool(props.nonce_misuse_resistant) }),
        Scope::KeyAgreement(_) => set!(key_agreement { forward_secrecy: c_tribool(props.forward_secrecy) }),
        Scope::Kdf(_) => set!(kdf { memory_hard: c_tribool(props.memory_hard) }),
        Scope::Mac(_) => set!(mac {}),
        Scope::Kem(_) => set!(kem {}),
        Scope::Hash(_) => set!(hash {}),
        Scope::KeyWrapping(_) => set!(key_wrapping {}),
        Scope::SymmetricCipher(_) => set!(symmetric_cipher {}),
        Scope::GenericSecret(_) => set!(generic_secret {}),
        Scope::DiskEncryption(_) => set!(disk_encryption {}),
    }
    c
}

pub fn c_key_format(e: Encoding) -> agc_key_format {
    match e {
        Encoding::Raw => agc_key_format_AGC_KEY_FORMAT_RAW,
        Encoding::Sec1Der => agc_key_format_AGC_KEY_FORMAT_SEC1,
        Encoding::Pkcs8Der => agc_key_format_AGC_KEY_FORMAT_PKCS8,
        Encoding::SpkiDer => agc_key_format_AGC_KEY_FORMAT_SPKI,
    }
}

/// The C summary of a provider's implementation properties; the language
/// string goes into storage.
pub fn c_impl_props(i: &api::ImplementationProperties, p: &mut Packer) -> agc_impl_props {
    let fips = i.fips_140.as_ref();
    let certified = fips.filter(|f| f.certified);
    let audits: Vec<agc_audit_report> = i
        .audits
        .iter()
        .map(|a| agc_audit_report {
            auditor: p.str(&a.auditor),
            report_date: c_proto_timestamp(a.report_date.as_ref()),
            report_id: p.str(&a.report_id),
            scope: p.str(&a.scope),
            findings_summary: p.str(&a.findings_summary),
            report_url: p.str(&a.report_url),
        })
        .collect();
    let (hardware_features, hardware_features_count) = strs(p, &i.hardware_features);
    let (unpatched_cves, unpatched_cves_count) = strs(p, &i.unpatched_cves);
    agc_impl_props {
        fips_certified: i32::from(certified.is_some()),
        fips_level: certified.map_or(0, |f| f.level as u32),
        fips_certificate_number: p.str(fips.map_or("", |f| &f.certificate_number)),
        fips_module_name: p.str(fips.map_or("", |f| &f.module_name)),
        fips_validation_date: c_proto_timestamp(fips.and_then(|f| f.validation_date.as_ref())),
        fips_expiration_date: c_proto_timestamp(fips.and_then(|f| f.expiration_date.as_ref())),
        common_criteria_certified: c_tribool(i.common_criteria_certified),
        audits: p.array(&audits),
        audits_count: audits.len(),
        formally_verified: c_tribool(i.formally_verified),
        verification_framework: p.str(&i.verification_framework),
        memory_safe_language: c_tribool(i.memory_safe_language),
        implementation_language: p.str(&i.implementation_language),
        constant_time: c_tribool(i.constant_time),
        side_channel_hardened: c_tribool(i.side_channel_hardened),
        hardware_accelerated: c_tribool(i.hardware_accelerated),
        hardware_features,
        hardware_features_count,
        no_known_cve: c_tribool(i.no_known_cve),
        unpatched_cves,
        unpatched_cves_count,
        additional: p.kv_list(i.additional.iter()),
    }
}

/// A protobuf timestamp as the C API's optional timestamp.
pub fn c_proto_timestamp(t: Option<&pbjson_types::Timestamp>) -> agc_timestamp {
    t.map_or_else(c_no_timestamp, |t| agc_timestamp { seconds: t.seconds, nanos: t.nanos, present: 1 })
}

/// The C record of a key version, its variable-length data in storage.
pub fn c_key_info(k: &KeyMetadata, p: &mut Packer) -> agc_key_info {
    let (public_key, public_key_format) = match &k.public_key {
        Some((bytes, enc)) => (p.bytes(bytes), c_key_format(*enc)),
        None => (agc_slice { data: ptr::null(), len: 0 }, agc_key_format_AGC_KEY_FORMAT_UNSPECIFIED),
    };
    agc_key_info {
        struct_size: size_of::<agc_key_info>(),
        key_name: p.str(&k.name),
        version: k.version,
        key_id: p.str(k.id.as_str()),
        template_id: p.str(&k.template_id),
        provider_id: p.str(&k.provider),
        policy_name: p.str(&k.policy),
        created_time: c_timestamp(k.created_at),
        updated_time: c_timestamp(k.updated_at),
        extractable: i32::from(k.extractable),
        lifecycle_state: k.state as u32,
        scope_spec: c_scope_spec(&k.scope_spec, p),
        public_key,
        public_key_format,
        provider_metadata: agc_kv_list { items: ptr::null(), count: 0 },
        implementation_props: c_impl_props(&k.implementation, p),
        // No cryptoperiod is scheduled: create_key refuses one, as Go does.
        activation_time: c_no_timestamp(),
        expiration_time: c_no_timestamp(),
        origin: k.origin as u32,
    }
}

/// What a key response carries besides the key's record: the version's
/// template, when the caller asked for it (KeyMetadata.template_info), and
/// CreateKey's security guarantees (agc_key_info_response).
#[derive(Debug, Default)]
pub struct KeyExtras {
    pub template: Option<api::TemplateInfo>,
    pub guarantees: Option<api::SecurityGuarantees>,
}

/// The records of a key response, laid out in its one region.
pub struct KeyRecords {
    pub info: agc_key_info,
    pub template: Option<agc_template_info>,
    pub guarantees: Option<agc_security_guarantees>,
}

pub fn c_key_records(k: &KeyMetadata, x: &KeyExtras, p: &mut Packer) -> KeyRecords {
    KeyRecords {
        info: c_key_info(k, p),
        template: x.template.as_ref().map(|t| c_template_info(t, p)),
        guarantees: x.guarantees.as_ref().map(|g| c_guarantees(g, p)),
    }
}

/// Writes `key` and `extras` into `resp` under the STORAGE CONTRACT (see
/// `pack`).
///
/// `resp` is this library's copy of the caller's struct (see `versioned`),
/// and its `template_info` passed `wants_template`.
pub fn fill_key_info_response(
    resp: &mut agc_key_info_response,
    key: &KeyMetadata,
    extras: &KeyExtras,
) -> Result<(), FfiError> {
    let r = pack(resp.storage, &mut resp.storage_used, |p| c_key_records(key, extras, p))?;
    resp.key_info = r.info;
    resp.has_security_guarantees = i32::from(r.guarantees.is_some());
    // SAFETY: integers and raw pointers only, for which all zeros is valid:
    // "no claim", as AGC_INIT leaves it.
    resp.security_guarantees = r.guarantees.unwrap_or_else(|| unsafe { std::mem::zeroed() });
    // SAFETY: template_info passed wants_template (see above).
    resp.has_template_info = unsafe { write_template(resp.template_info, r.template) };
    Ok(())
}

/// The storage `fill_key_info_response` needs for `key` and `extras`.
pub fn key_info_size(key: &KeyMetadata, extras: &KeyExtras) -> usize {
    let mut m = Packer::measuring();
    c_key_records(key, extras, &mut m);
    m.pos
}

/// Checks a key response's `template_info`: NULL, or the caller's
/// agc_template_info, AGC_INIT'ed. Returns whether the caller asked for the
/// template, so a bad pointer fails before any work.
///
/// # Safety
/// `p` is NULL or points to the caller's agc_template_info with
/// `struct_size` accessible bytes.
pub unsafe fn wants_template(p: *mut agc_template_info) -> Result<bool, FfiError> {
    if p.is_null() {
        return Ok(false);
    }
    // SAFETY: as the caller guarantees.
    unsafe { versioned::read(p.cast_const(), "template_info") }?;
    Ok(true)
}

/// Writes `t` through the caller's `template_info`, when there are both;
/// returns the matching `has_template_info`.
///
/// # Safety
/// `p` is NULL or passed `wants_template`.
pub unsafe fn write_template(p: *mut agc_template_info, t: Option<agc_template_info>) -> i32 {
    match t {
        Some(t) if !p.is_null() => {
            // SAFETY: p passed versioned::read in wants_template.
            unsafe { versioned::write_back(p, &t) };
            1
        }
        _ => 0,
    }
}

/// Writes `policy` into `resp` under the STORAGE CONTRACT.
pub fn fill_read_policy_response(resp: &mut agc_read_policy_response, policy: &Policy) -> Result<(), FfiError> {
    let [name, document, format] =
        pack_strings(resp.storage, &mut resp.storage_used, [policy.name(), policy.document(), POLICY_FORMAT])?;
    resp.name = name;
    resp.policy_document = document;
    resp.format = format;
    resp.version = policy.version();
    resp.created_at = c_timestamp(policy.created_at());
    resp.updated_at = c_timestamp(policy.updated_at());
    Ok(())
}

/// Writes one policy summary (as listed) into `resp` under the STORAGE CONTRACT.
pub fn fill_policy_summary_response(resp: &mut agc_policy_summary_response, policy: &Policy) -> Result<(), FfiError> {
    let [name, format] = pack_strings(resp.storage, &mut resp.storage_used, [policy.name(), POLICY_FORMAT])?;
    resp.summary = agc_policy_summary {
        struct_size: size_of::<agc_policy_summary>(),
        name,
        created_at: c_timestamp(policy.created_at()),
        updated_at: c_timestamp(policy.updated_at()),
        version: policy.version(),
        format,
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ffi::CStr;

    use super::*;
    use crate::domain::key::KeyId;
    use crate::ffi::translation::scope_spec;
    use crate::domain::core::{AeadScope, KeyLifecycleState, SignatureScope};

    fn metadata() -> KeyMetadata {
        let mut spec = ScopeSpecification::any_of(Scope::Signature(SignatureScope::Prehashed));
        spec.properties.deterministic = Some(true);
        spec.security = Some(SecurityProperties { strength_bits: 128, quantum_safe: Some(false), ..Default::default() });
        spec.additional = BTreeMap::from([("a".into(), "1".into()), ("b".into(), "2".into())]);
        KeyMetadata {
            id: KeyId::new("key-0"),
            name: "my-key".into(),
            policy: "default".into(),
            state: KeyLifecycleState::Active,
            created_at: SystemTime::UNIX_EPOCH + std::time::Duration::new(10, 5),
            updated_at: SystemTime::UNIX_EPOCH + std::time::Duration::new(20, 0),
            version: 3,
            template_id: "ed25519ph".into(),
            provider: "fake".into(),
            scope_spec: spec,
            extractable: true,
            public_key: Some((vec![0xAB; 44], Encoding::SpkiDer)),
            implementation: api::ImplementationProperties {
                implementation_language: "rust".into(),
                memory_safe_language: Some(true),
                ..Default::default()
            },
            origin: api::KeyOrigin::Generated,
        }
    }

    /// What the C caller does: AGC_INIT(&resp), then point `storage` at its own buffer.
    fn response(storage: &mut [u8]) -> agc_key_info_response {
        // SAFETY: integers and raw pointers only; all zeros is AGC_INIT's state.
        let mut resp: agc_key_info_response = unsafe { std::mem::zeroed() };
        resp.struct_size = size_of::<agc_key_info_response>();
        resp.storage = agc_buf { data: storage.as_mut_ptr(), cap: storage.len() };
        resp
    }

    fn read(p: *const c_char) -> &'static str {
        assert!(!p.is_null(), "pointer field was not set");
        // SAFETY: only called on pointers into a test's live storage buffer;
        // every string the packer writes is NUL-terminated.
        unsafe { CStr::from_ptr(p) }.to_str().unwrap()
    }

    #[test]
    fn fills_every_field() {
        let mut storage = [0u8; 512];
        let mut resp = response(&mut storage);
        fill_key_info_response(&mut resp, &metadata(), &KeyExtras::default()).unwrap();

        let i = &resp.key_info;
        assert_eq!((read(i.key_name), read(i.key_id), read(i.template_id)), ("my-key", "key-0", "ed25519ph"));
        assert_eq!((read(i.provider_id), read(i.policy_name)), ("fake", "default"));
        assert_eq!(
            (i.version, i.extractable, i.lifecycle_state),
            (3, 1, agc_key_lifecycle_state_AGC_KEY_LIFECYCLE_STATE_ACTIVE)
        );
        assert_eq!((i.created_time.seconds, i.created_time.nanos, i.created_time.present), (10, 5, 1));
        assert_eq!(i.updated_time.seconds, 20);
        assert_eq!((i.public_key.len, i.public_key_format), (44, agc_key_format_AGC_KEY_FORMAT_SPKI));
        // SAFETY: the slice points into `storage`, which is alive.
        assert!(unsafe { std::slice::from_raw_parts(i.public_key.data, 44) }.iter().all(|&b| b == 0xAB));
        let props = &i.implementation_props;
        assert_eq!((read(props.implementation_language), props.memory_safe_language), ("rust", agc_tribool_AGC_TRUE));
        assert_eq!(props.fips_certified, 0);
        assert!(resp.storage_used <= storage.len());
    }

    #[test]
    fn implementation_properties_carry_every_proto_field() {
        let ts = |seconds| Some(pbjson_types::Timestamp { seconds, nanos: 0 });
        let i = api::ImplementationProperties {
            fips_140: Some(api::Fips140Certification {
                certified: true,
                level: api::Fips140Level::Fips140Level3 as i32,
                certificate_number: "4282".into(),
                module_name: "hsm-module".into(),
                validation_date: ts(100),
                expiration_date: None,
            }),
            common_criteria_certified: Some(false),
            audits: vec![api::AuditReport {
                auditor: "lab".into(),
                report_date: ts(7),
                report_id: "r-1".into(),
                scope: "aead".into(),
                findings_summary: "none".into(),
                report_url: "https://example.org/r-1".into(),
            }],
            verification_framework: "HACL*".into(),
            hardware_features: vec!["aes-ni".into(), "avx2".into()],
            no_known_cve: Some(true),
            unpatched_cves: vec!["CVE-2026-0001".into()],
            additional: [("k".to_owned(), "v".to_owned())].into(),
            ..Default::default()
        };
        let mut storage = [0u8; 1024];
        let mut used = 0;
        let c = pack(agc_buf { data: storage.as_mut_ptr(), cap: storage.len() }, &mut used, |p| c_impl_props(&i, p)).unwrap();

        assert_eq!((c.fips_certified, c.fips_level), (1, 3));
        assert_eq!((read(c.fips_certificate_number), read(c.fips_module_name)), ("4282", "hsm-module"));
        assert_eq!((c.fips_validation_date.seconds, c.fips_validation_date.present), (100, 1));
        assert_eq!(c.fips_expiration_date.present, 0, "absent stays absent");
        assert_eq!((c.common_criteria_certified, c.no_known_cve), (agc_tribool_AGC_FALSE, agc_tribool_AGC_TRUE));
        assert_eq!(c.audits_count, 1);
        // SAFETY: audits points at one record in `storage`, which is alive.
        let a = unsafe { &*c.audits };
        assert_eq!((read(a.auditor), read(a.report_id), read(a.scope)), ("lab", "r-1", "aead"));
        assert_eq!((read(a.findings_summary), read(a.report_url), a.report_date.seconds), ("none", "https://example.org/r-1", 7));
        assert_eq!(read(c.verification_framework), "HACL*");
        // SAFETY: both arrays point into `storage` with the counts given.
        let (hw, cves) = unsafe {
            (std::slice::from_raw_parts(c.hardware_features, 2), std::slice::from_raw_parts(c.unpatched_cves, 1))
        };
        assert_eq!((c.hardware_features_count, read(hw[0]), read(hw[1])), (2, "aes-ni", "avx2"));
        assert_eq!((c.unpatched_cves_count, read(cves[0])), (1, "CVE-2026-0001"));
        assert_eq!(c.additional.count, 1);
        // SAFETY: one item in `storage`.
        let kv = unsafe { &*c.additional.items };
        assert_eq!((read(kv.key), read(kv.value)), ("k", "v"));
        assert!(used <= storage.len());
    }

    #[test]
    fn unset_implementation_properties_are_empty_not_null() {
        let mut storage = [0u8; 64];
        let mut used = 0;
        let c = pack(agc_buf { data: storage.as_mut_ptr(), cap: storage.len() }, &mut used, |p| {
            c_impl_props(&api::ImplementationProperties::default(), p)
        })
        .unwrap();
        assert_eq!((read(c.verification_framework), read(c.fips_certificate_number)), ("", ""));
        assert!(c.audits.is_null() && c.audits_count == 0);
        assert!(c.hardware_features.is_null() && c.unpatched_cves.is_null() && c.additional.count == 0);
        assert_eq!((c.no_known_cve, c.common_criteria_certified), (agc_tribool_AGC_UNSET, agc_tribool_AGC_UNSET));
    }

    #[test]
    fn the_scope_spec_round_trips_through_c() {
        let mut storage = [0u8; 512];
        let mut resp = response(&mut storage);
        let k = metadata();
        fill_key_info_response(&mut resp, &k, &KeyExtras::default()).unwrap();
        // SAFETY: the record points into `storage`, which is alive.
        assert_eq!(unsafe { scope_spec(&resp.key_info.scope_spec) }.unwrap(), k.scope_spec);

        let aead = ScopeSpecification::any_of(Scope::Aead(AeadScope::Streaming));
        let mut p = Packer::measuring();
        let c = c_scope_spec(&aead, &mut p);
        assert_eq!(p.pos, 0, "nothing to store");
        // SAFETY: no pointers to follow (empty lists).
        assert_eq!(unsafe { scope_spec(&c) }.unwrap(), aead);
    }

    #[test]
    fn the_measured_size_is_enough_and_one_byte_less_is_not() {
        let k = metadata();
        let needed = key_info_size(&k, &KeyExtras::default());
        let mut exact = vec![0u8; needed];
        fill_key_info_response(&mut response(&mut exact), &k, &KeyExtras::default()).unwrap();
        let mut short = vec![0xAAu8; needed - 1];
        let mut resp = response(&mut short);
        let r = fill_key_info_response(&mut resp, &k, &KeyExtras::default());
        assert!(matches!(r, Err(FfiError::BufferTooSmall { needed: n }) if n == needed));
        // STORAGE CONTRACT: nothing else written.
        assert!(resp.key_info.key_name.is_null());
        assert!(short.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn null_storage_is_a_size_query() {
        let mut resp = response(&mut []);
        resp.storage = agc_buf { data: ptr::null_mut(), cap: 0 };
        let r = fill_key_info_response(&mut resp, &metadata(), &KeyExtras::default());
        assert!(matches!(r, Err(FfiError::BufferTooSmall { .. })));
        assert_eq!(resp.storage_used, key_info_size(&metadata(), &KeyExtras::default()));
    }

    #[test]
    fn arrays_are_aligned_whatever_the_region_alignment() {
        // An odd start for the region forces padding before the kv array.
        let k = metadata();
        let mut storage = vec![0u8; key_info_size(&k, &KeyExtras::default()) + 1];
        let mut resp = response(&mut storage[1..]);
        fill_key_info_response(&mut resp, &k, &KeyExtras::default()).unwrap();
        // SAFETY: reading the union member kind selects.
        let kvs = unsafe { resp.key_info.scope_spec.u.signature.additional_properties };
        assert_eq!(kvs.items as usize % align_of::<agc_kv>(), 0);
        assert_eq!(kvs.count, 2);
    }

    #[test]
    fn scope_kinds_round_trip() {
        use crate::ffi::translation::scope_kind;
        for k in [ScopeKind::Signature, ScopeKind::Aead, ScopeKind::Kem, ScopeKind::GenericSecret] {
            assert_eq!(scope_kind(c_scope_kind(k)).unwrap(), k);
        }
        assert!(scope_kind(agc_scope_kind_AGC_SCOPE_KIND_ASYMMETRIC_ENCRYPTION).is_err(), "Go has no such scope");
    }
}
