use std::ffi::c_char;
use std::time::SystemTime;

use crate::bindings::*;
use crate::domain::core::ScopeKind;
use crate::domain::key::Key;
use crate::domain::policy::Policy;
use crate::ffi::error::FfiError;

/// Packs strings into the caller's storage region and hands back pointers
/// into it, which the caller reads after we return.
///
/// Every write and every returned pointer derives from the one raw `base`
/// pointer. Going through a `&mut [u8]` instead would make each returned
/// pointer a reborrow that the next write invalidates (found by Miri).
struct StorageWriter {
    base: *mut u8,
    cap: usize,
    pos: usize,
}

impl StorageWriter {
    /// # Safety
    /// `base` points to `cap` bytes the caller lets us write during this call,
    /// which nothing else accesses until we return.
    unsafe fn new(base: *mut u8, cap: usize) -> Self {
        StorageWriter { base, cap, pos: 0 }
    }

    fn put_str(&mut self, s: &str) -> *const c_char {
        let end = self.pos + s.len() + 1;
        // Callers size the region first; running past it is a bug in this library.
        assert!(end <= self.cap, "storage writer overflow");
        // SAFETY: pos..end lies within the cap bytes `new` was given, and s is
        // a separate Rust allocation.
        let start = unsafe { self.base.add(self.pos) };
        // SAFETY: as above; start + s.len() is the last byte before end.
        unsafe {
            std::ptr::copy_nonoverlapping(s.as_ptr(), start, s.len());
            start.add(s.len()).write(0);
        }
        self.pos = end;
        start.cast_const().cast()
    }
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
        ScopeKind::AsymmetricEncryption => agc_scope_kind_AGC_SCOPE_KIND_ASYMMETRIC_ENCRYPTION,
    }
}

/// The STORAGE CONTRACT (agc_key_types.h and every *_types.h): a record's
/// strings go into the caller's `storage` region, each NUL-terminated, and
/// the record points into it. `storage_used` is always set to the size
/// needed; if the region is NULL or smaller, nothing else is written and the
/// result is `BufferTooSmall`.
///
/// Returns one pointer per string, in order.
pub fn pack_strings<const N: usize>(
    storage: agc_buf,
    storage_used: &mut usize,
    strings: [&str; N],
) -> Result<[*const c_char; N], FfiError> {
    let needed = strings.iter().map(|s| s.len() + 1).sum();
    *storage_used = needed;
    if storage.data.is_null() || storage.cap < needed {
        return Err(FfiError::BufferTooSmall { needed });
    }
    // SAFETY: by the STORAGE CONTRACT the caller's region holds `cap` writable
    // bytes for the duration of this call and nothing else uses it meanwhile.
    let mut writer = unsafe { StorageWriter::new(storage.data, storage.cap) };
    Ok(strings.map(|s| writer.put_str(s)))
}

/// A time as the C API's optional timestamp.
pub fn c_timestamp(t: SystemTime) -> agc_timestamp {
    // Times before 1970 do not occur here (they come from the system clock).
    let d = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    agc_timestamp {
        seconds: i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        nanos: d.subsec_nanos() as i32,
        present: 1,
    }
}

/// Writes `key` into `resp` under the STORAGE CONTRACT (see `pack_strings`).
///
/// `resp` is this library's copy of the caller's struct (see `versioned`).
pub fn fill_key_info_response(resp: &mut agc_key_info_response, key: &Key) -> Result<(), FfiError> {
    let [name, id, template, provider, policy] = pack_strings(
        resp.storage,
        &mut resp.storage_used,
        [key.get_name(), key.get_id().as_str(), key.get_template_id(), key.get_provider(), key.get_policy()],
    )?;
    let info = &mut resp.key_info;
    info.key_name = name;
    info.key_id = id;
    info.template_id = template;
    info.provider_id = provider;
    info.policy_name = policy;

    info.struct_size = size_of::<agc_key_info>();
    info.version = key.get_version();
    info.lifecycle_state = agc_key_lifecycle_state_AGC_KEY_LIFECYCLE_STATE_ACTIVE;
    info.scope_spec.struct_size = size_of::<agc_scope_spec>();
    info.scope_spec.kind = c_scope_kind(key.get_scope_kind());

    Ok(())
}

/// Writes `policy` into `resp` under the STORAGE CONTRACT.
pub fn fill_read_policy_response(resp: &mut agc_read_policy_response, policy: &Policy) -> Result<(), FfiError> {
    let [name, document] = pack_strings(resp.storage, &mut resp.storage_used, [policy.name(), policy.document()])?;
    resp.name = name;
    resp.policy_document = document;
    Ok(())
}

/// Writes one policy summary (as listed) into `resp` under the STORAGE CONTRACT.
pub fn fill_policy_summary_response(resp: &mut agc_policy_summary_response, policy: &Policy) -> Result<(), FfiError> {
    let [name] = pack_strings(resp.storage, &mut resp.storage_used, [policy.name()])?;
    resp.summary = agc_policy_summary {
        struct_size: size_of::<agc_policy_summary>(),
        name,
        created_at: c_timestamp(policy.created_at()),
        updated_at: c_timestamp(policy.updated_at()),
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::key::KeyId;
    use std::ffi::CStr;

    fn key() -> Key {
        Key::new(
            KeyId::new("key-0"),
            String::from("my-key"),
            1,
            String::from("aes-256-gcm"),
            String::from("stub"),
            String::from("default"),
            vec![0; 32].into(),
            ScopeKind::Aead,
        )
    }

    /// What the C caller does: AGC_INIT(&resp), then point `storage` at its own buffer.
    /// `storage` must outlive every use of `resp` (the raw pointer is not tracked by the borrow checker).
    fn response(storage: &mut [u8]) -> agc_key_info_response {
        // SAFETY: agc_key_info_response consists only of integers, raw pointers and C enums,
        // for which all-zero bytes are valid; this is exactly what AGC_INIT's memset does.
        let mut resp: agc_key_info_response = unsafe { std::mem::zeroed() };
        resp.struct_size = size_of::<agc_key_info_response>();
        resp.storage.data = storage.as_mut_ptr();
        resp.storage.cap = storage.len();
        resp
    }

    /// Reads a C string written by fill_key_info_response.
    fn read(p: *const c_char) -> &'static str {
        assert!(!p.is_null(), "pointer field was not set");
        // SAFETY: only called on pointers into a test's storage buffer that is still alive,
        // and put_str NUL-terminates every string.
        unsafe { CStr::from_ptr(p) }.to_str().unwrap()
    }

    // "my-key\0" + "key-0\0" + "aes-256-gcm\0" + "stub\0" + "default\0"
    const NEEDED: usize = 7 + 6 + 12 + 5 + 8;

    #[test]
    fn fills_strings_and_scalars() {
        let mut storage = [0xAAu8; 64];
        let mut resp = response(&mut storage);

        fill_key_info_response(&mut resp, &key()).unwrap();

        let info = &resp.key_info;
        assert_eq!(read(info.key_name), "my-key");
        assert_eq!(read(info.key_id), "key-0");
        assert_eq!(read(info.template_id), "aes-256-gcm");
        assert_eq!(read(info.provider_id), "stub");
        assert_eq!(read(info.policy_name), "default");

        assert_eq!(info.struct_size, size_of::<agc_key_info>());
        assert_eq!(info.version, 1);
        assert_eq!(info.lifecycle_state, agc_key_lifecycle_state_AGC_KEY_LIFECYCLE_STATE_ACTIVE);
        assert_eq!(info.scope_spec.struct_size, size_of::<agc_scope_spec>());
        assert_eq!(info.scope_spec.kind, agc_scope_kind_AGC_SCOPE_KIND_AEAD);
        assert_eq!(resp.storage_used, NEEDED);
    }

    #[test]
    fn strings_are_packed_into_storage_in_order() {
        let mut storage = [0xAAu8; 64];
        let mut resp = response(&mut storage);
        fill_key_info_response(&mut resp, &key()).unwrap();
        let base = storage.as_ptr();

        // Every pointer points into the caller's storage, at the expected offset.
        let offset = |p: *const c_char| {
            // SAFETY: both pointers are into the same `storage` array.
            unsafe { p.cast::<u8>().offset_from(base) }
        };
        assert_eq!(offset(resp.key_info.key_name), 0);
        assert_eq!(offset(resp.key_info.key_id), 7);
        assert_eq!(offset(resp.key_info.template_id), 13);
        assert_eq!(offset(resp.key_info.provider_id), 25);
        assert_eq!(offset(resp.key_info.policy_name), 30);

        assert_eq!(&storage[..NEEDED], b"my-key\0key-0\0aes-256-gcm\0stub\0default\0");
        // Nothing written past what storage_used reports.
        assert!(storage[NEEDED..].iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn exact_size_buffer_is_enough() {
        let mut storage = [0u8; NEEDED];
        let mut resp = response(&mut storage);
        fill_key_info_response(&mut resp, &key()).unwrap();
        assert_eq!(read(resp.key_info.policy_name), "default");
    }

    #[test]
    fn too_small_buffer_reports_needed_and_writes_nothing_else() {
        let mut storage = [0xAAu8; NEEDED - 1];
        let mut resp = response(&mut storage);

        let r = fill_key_info_response(&mut resp, &key());

        assert!(matches!(r, Err(FfiError::BufferTooSmall { needed: NEEDED })));
        assert_eq!(resp.storage_used, NEEDED);
        // STORAGE CONTRACT: "writes no other field of the record".
        assert!(resp.key_info.key_name.is_null());
        assert_eq!(resp.key_info.struct_size, 0);
        assert_eq!(resp.key_info.lifecycle_state, agc_key_lifecycle_state_AGC_KEY_LIFECYCLE_STATE_UNSPECIFIED);
        assert!(storage.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn null_storage_is_a_size_query() {
        let mut resp = response(&mut []);
        resp.storage.data = std::ptr::null_mut();
        resp.storage.cap = 0;

        let r = fill_key_info_response(&mut resp, &key());

        assert!(matches!(r, Err(FfiError::BufferTooSmall { needed: NEEDED })));
        assert_eq!(resp.storage_used, NEEDED);
    }

    #[test]
    fn scope_kinds_round_trip() {
        use crate::ffi::translation::scope_kind;
        for k in [ScopeKind::Signature, ScopeKind::Aead, ScopeKind::Kem, ScopeKind::AsymmetricEncryption] {
            assert_eq!(scope_kind(c_scope_kind(k)).unwrap(), k);
        }
    }
}
