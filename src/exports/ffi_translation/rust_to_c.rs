use std::ffi::c_char;

use crate::{
    bindings::{
        agc_key_info, agc_key_info_response,
        agc_key_lifecycle_state_AGC_KEY_LIFECYCLE_STATE_ACTIVE, agc_scope_spec,
    },
    exports::{
        error::Error::{self, AbiMismatch},
        key::Key,
    },
};

struct StorageWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> StorageWriter<'a> {
    fn put_str(&mut self, s: &str) -> *const c_char {
        let start = self.pos;
        self.buf[self.pos..self.pos + s.len()].copy_from_slice(s.as_bytes());
        self.buf[self.pos + s.len()] = b'\0';
        self.pos += s.len() + 1;
        self.buf[start..].as_ptr().cast()
    }
}

pub fn fill_key_info_response(resp: &mut agc_key_info_response, key: &Key) -> Result<(), Error> {
    if resp.struct_size < size_of::<agc_key_info_response>() {
        return Err(AbiMismatch);
    }
    let needed = key.get_name().len()
        + 1
        + key.get_id().as_str().len()
        + 1
        + key.get_template_id().len()
        + 1
        + key.get_provider().len()
        + 1
        + key.get_policy().len()
        + 1;
    resp.storage_used = needed;
    if resp.storage.data.is_null() || resp.storage.cap < needed {
        return Err(Error::BufferTooSmall { needed });
    }
    // SAFETY: The caller owns the storage region and it has cap space during this call and it is not used elsewhere during the call
    let buf = unsafe { std::slice::from_raw_parts_mut(resp.storage.data, resp.storage.cap) };
    let mut writer = StorageWriter { buf, pos: 0 };
    let info = &mut resp.key_info;
    info.key_name = writer.put_str(key.get_name());
    info.key_id = writer.put_str(key.get_id().as_str());
    info.template_id = writer.put_str(key.get_template_id());
    info.provider_id = writer.put_str(key.get_provider());
    info.policy_name = writer.put_str(key.get_policy());

    info.struct_size = size_of::<agc_key_info>();
    info.version = key.get_version();
    info.lifecycle_state = agc_key_lifecycle_state_AGC_KEY_LIFECYCLE_STATE_ACTIVE;
    info.scope_spec.struct_size = size_of::<agc_scope_spec>();
    info.scope_spec.kind = key.get_scope_kind();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bindings::{agc_scope_kind_AGC_SCOPE_KIND_AEAD, agc_key_lifecycle_state_AGC_KEY_LIFECYCLE_STATE_UNSPECIFIED};
    use crate::exports::key::KeyId;
    use std::ffi::CStr;

    fn key() -> Key {
        Key::new(
            KeyId::new("key-0"),
            String::from("my-key"),
            1,
            String::from("aes-256-gcm"),
            String::from("stub"),
            String::from("default"),
            vec![0; 32],
            agc_scope_kind_AGC_SCOPE_KIND_AEAD,
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
        // SAFETY (for offset_from): both pointers are into the same `storage` array.
        let offset = |p: *const c_char| unsafe { p.cast::<u8>().offset_from(base) };
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

        assert!(matches!(r, Err(Error::BufferTooSmall { needed: NEEDED })));
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

        assert!(matches!(r, Err(Error::BufferTooSmall { needed: NEEDED })));
        assert_eq!(resp.storage_used, NEEDED);
    }

    #[test]
    fn smaller_struct_size_is_rejected() {
        let mut storage = [0u8; 64];
        let mut resp = response(&mut storage);
        resp.struct_size = size_of::<agc_key_info_response>() - 1;

        let r = fill_key_info_response(&mut resp, &key());

        assert!(matches!(r, Err(AbiMismatch)));
    }
}
