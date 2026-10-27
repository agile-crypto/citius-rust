//! The exports called the way C calls them: raw pointers, caller-owned
//! structs and buffers. Written in Rust so that Miri can check the whole path
//! (context pointer, versioned structs, storage writer, error record) for
//! undefined behaviour, which it cannot do for the C tests.

use std::ffi::{CStr, c_char};
use std::ptr;

use crate::bindings::*;
// Explicit, so the names mean our implementations, not bindgen's declarations.
use super::{
    agc_create_key, agc_create_policy, agc_ctx_close, agc_ctx_open, agc_delete_policy, agc_last_error,
    agc_list_policies, agc_policy_iter_free, agc_policy_iter_next, agc_rc_message, agc_rc_name, agc_read_policy,
    agc_update_policy,
};

/// The policy `open()` creates as "default": AEAD keys with one template.
const DEFAULT_POLICY: &CStr = cr#"{"version": "1",
    "allowed_templates": ["aes-128-gcm-128-96"],
    "allowed_operations": {"key_operations": ["create_key"]}}"#;

fn s(p: *const c_char) -> &'static str {
    assert!(!p.is_null());
    // SAFETY: only called on pointers the library returned into live storage
    // or its static / thread-local strings.
    unsafe { CStr::from_ptr(p) }.to_str().unwrap()
}

fn zeroed<T>() -> T {
    // SAFETY: only used for bindgen structs (integers and raw pointers), for
    // which all zeros is the AGC_INIT state.
    unsafe { std::mem::zeroed() }
}

fn open_with(cfg: &agc_ctx_config) -> *mut agc_ctx {
    let mut ctx = ptr::null_mut();
    // SAFETY: cfg and ctx are live locals.
    assert_eq!(unsafe { agc_ctx_open(cfg, &mut ctx) }, AGC_OK as agc_rc);
    assert!(!ctx.is_null());
    ctx
}

/// A context with the policy "default" (DEFAULT_POLICY).
fn open() -> *mut agc_ctx {
    let mut cfg: agc_ctx_config = zeroed();
    cfg.struct_size = size_of::<agc_ctx_config>();
    let ctx = open_with(&cfg);
    assert_eq!(create_policy(ctx, c"default", DEFAULT_POLICY), AGC_OK as agc_rc);
    ctx
}

fn create_policy(ctx: *mut agc_ctx, name: &CStr, document: &CStr) -> agc_rc {
    let mut req: agc_create_policy_request = zeroed();
    req.struct_size = size_of::<agc_create_policy_request>();
    req.name = name.as_ptr();
    req.policy_document = document.as_ptr();
    // SAFETY: ctx is open; req and its strings are live.
    unsafe { agc_create_policy(ctx, &req) }
}

fn close(ctx: *mut agc_ctx) {
    // SAFETY: ctx came from agc_ctx_open and is closed once.
    unsafe { agc_ctx_close(ctx) };
}

fn params(name: &CStr) -> agc_create_key_params {
    let mut p: agc_create_key_params = zeroed();
    p.struct_size = size_of::<agc_create_key_params>();
    p.key_name = name.as_ptr();
    p.policy_name = c"default".as_ptr();
    p.scope_spec.struct_size = size_of::<agc_scope_spec>();
    p.scope_spec.kind = agc_scope_kind_AGC_SCOPE_KIND_AEAD;
    p
}

fn response(storage: &mut [u8]) -> agc_key_info_response {
    let mut r: agc_key_info_response = zeroed();
    r.struct_size = size_of::<agc_key_info_response>();
    r.storage.data = storage.as_mut_ptr();
    r.storage.cap = storage.len();
    r
}

fn create(ctx: *mut agc_ctx, p: &agc_create_key_params, resp: &mut agc_key_info_response) -> agc_rc {
    // SAFETY: ctx is open; p's strings are 'static literals; resp.storage
    // points to a buffer the test keeps alive.
    unsafe { agc_create_key(ctx, p, resp) }
}

fn last_error() -> agc_error_detail {
    let mut d: agc_error_detail = zeroed();
    d.struct_size = size_of::<agc_error_detail>();
    // SAFETY: d is a live local.
    assert_eq!(unsafe { agc_last_error(&mut d) }, AGC_OK as agc_rc);
    d
}

#[test]
fn create_key_end_to_end() {
    let ctx = open();
    let mut storage = [0u8; 256];
    let mut resp = response(&mut storage);

    assert_eq!(create(ctx, &params(c"k1"), &mut resp), AGC_OK as agc_rc);

    let info = &resp.key_info;
    assert_eq!(s(info.key_name), "k1");
    assert_eq!(s(info.policy_name), "default");
    assert_eq!(s(info.template_id), "aes-128-gcm-128-96");
    assert!(s(info.key_id).starts_with("key_"));
    assert_eq!(info.version, 1);
    close(ctx);
}

#[test]
fn too_small_storage_writes_only_the_size() {
    let ctx = open();
    let mut storage = [0xAAu8; 4];
    let mut resp = response(&mut storage);

    assert_eq!(create(ctx, &params(c"k1"), &mut resp), AGC_ERR_BUFFER_TOO_SMALL);
    assert!(resp.storage_used > 4);
    assert!(resp.key_info.key_name.is_null());
    assert_eq!(storage, [0xAA; 4]);
    close(ctx);
}

#[test]
fn errors_are_reported_through_last_error() {
    let ctx = open();
    let mut storage = [0u8; 256];
    let mut resp = response(&mut storage);
    assert_eq!(create(ctx, &params(c"dup"), &mut resp), AGC_OK as agc_rc);
    assert_eq!(create(ctx, &params(c"dup"), &mut resp), AGC_ERR_ALREADY_EXISTS);

    let d = last_error();
    assert_eq!(d.rc, AGC_ERR_ALREADY_EXISTS);
    assert!(s(d.message).contains("dup"));
    close(ctx);
}

#[test]
fn older_params_struct_is_read_only_up_to_its_size() {
    // An older caller's struct ends before template_id; the bytes after it
    // belong to someone else and must not be read.
    #[repr(C)]
    struct Frame {
        p: agc_create_key_params,
    }
    let mut frame = Frame { p: params(c"older") };
    let known = std::mem::offset_of!(agc_create_key_params, template_id);
    frame.p.struct_size = known;
    frame.p.template_id = c"not-a-template".as_ptr(); // would fail selection if read

    let ctx = open();
    let mut storage = [0u8; 256];
    let mut resp = response(&mut storage);
    assert_eq!(create(ctx, &frame.p, &mut resp), AGC_OK as agc_rc);
    assert_eq!(s(resp.key_info.template_id), "aes-128-gcm-128-96");
    close(ctx);
}

#[test]
fn null_arguments_are_rejected() {
    let ctx = open();
    let mut storage = [0u8; 256];
    let mut resp = response(&mut storage);
    let p = params(c"k");
    // SAFETY: NULL is allowed for each pointer argument; the others are live.
    unsafe {
        assert_eq!(agc_create_key(ptr::null_mut(), &p, &mut resp), AGC_ERR_INVALID_ARGUMENT);
        assert_eq!(agc_create_key(ctx, ptr::null(), &mut resp), AGC_ERR_INVALID_ARGUMENT);
        assert_eq!(agc_create_key(ctx, &p, ptr::null_mut()), AGC_ERR_INVALID_ARGUMENT);
        assert_eq!(agc_ctx_open(ptr::null(), ptr::null_mut()), AGC_ERR_INVALID_ARGUMENT);
        assert_eq!(agc_last_error(ptr::null_mut()), AGC_ERR_INVALID_ARGUMENT);
        agc_ctx_close(ptr::null_mut());
    }
    close(ctx);
}

#[test]
fn concurrent_use_of_one_context() {
    let ctx = open();
    // A raw pointer is not Send; the address is what C threads share.
    let addr = ctx as usize;
    std::thread::scope(|scope| {
        for t in 0..4 {
            scope.spawn(move || {
                for i in 0..5 {
                    let name = std::ffi::CString::new(format!("t{t}-k{i}")).unwrap();
                    let mut storage = [0u8; 256];
                    let mut resp = response(&mut storage);
                    let mut p = params(c"x");
                    p.key_name = name.as_ptr();
                    assert_eq!(create(addr as *mut agc_ctx, &p, &mut resp), AGC_OK as agc_rc);
                }
            });
        }
    });
    close(ctx);
}

#[test]
fn rc_helpers_return_static_strings() {
    assert_eq!(s(agc_rc_name(AGC_ERR_INTERNAL)), "AGC_ERR_INTERNAL");
    assert_eq!(s(agc_rc_message(AGC_OK as agc_rc)), "success");
    assert_eq!(s(agc_rc_name(424242)), "(unknown agc_rc)");
}

// --- Policies ---------------------------------------------------------------

#[test]
fn policy_crud() {
    let ctx = open();
    assert_eq!(create_policy(ctx, c"p", c"{}"), AGC_OK as agc_rc);
    assert_eq!(create_policy(ctx, c"p", c"{}"), AGC_ERR_ALREADY_EXISTS);
    assert_eq!(create_policy(ctx, c"bad", c"{"), AGC_ERR_INVALID_ARGUMENT);

    let mut storage = [0u8; 256];
    let mut resp: agc_read_policy_response = zeroed();
    resp.struct_size = size_of::<agc_read_policy_response>();
    resp.storage = agc_buf { data: storage.as_mut_ptr(), cap: storage.len() };
    // SAFETY: ctx is open; resp and its storage are live.
    assert_eq!(unsafe { agc_read_policy(ctx, c"p".as_ptr(), &mut resp) }, AGC_OK as agc_rc);
    assert_eq!((s(resp.name), s(resp.policy_document)), ("p", "{}"));

    let mut upd: agc_update_policy_request = zeroed();
    upd.struct_size = size_of::<agc_update_policy_request>();
    upd.name = c"p".as_ptr();
    upd.policy_document = c"".as_ptr(); // an empty document is valid: it allows nothing
    // SAFETY: ctx is open; upd and its strings are live.
    assert_eq!(unsafe { agc_update_policy(ctx, &upd) }, AGC_OK as agc_rc);
    upd.name = c"missing".as_ptr();
    // SAFETY: as above.
    assert_eq!(unsafe { agc_update_policy(ctx, &upd) }, AGC_ERR_CRYPTO_POLICY_NOT_FOUND);

    // SAFETY: ctx is open; the names are static.
    unsafe {
        assert_eq!(agc_delete_policy(ctx, c"p".as_ptr()), AGC_OK as agc_rc);
        assert_eq!(agc_delete_policy(ctx, c"p".as_ptr()), AGC_ERR_CRYPTO_POLICY_NOT_FOUND);
        assert_eq!(agc_read_policy(ctx, c"p".as_ptr(), &mut resp), AGC_ERR_CRYPTO_POLICY_NOT_FOUND);
    }
    close(ctx);
}

#[test]
fn a_policy_with_keys_cannot_be_deleted() {
    let ctx = open();
    let mut storage = [0u8; 256];
    let mut resp = response(&mut storage);
    assert_eq!(create(ctx, &params(c"k"), &mut resp), AGC_OK as agc_rc);
    // SAFETY: ctx is open; the name is static.
    assert_eq!(unsafe { agc_delete_policy(ctx, c"default".as_ptr()) }, AGC_ERR_CRYPTO_POLICY_VIOLATION);
    assert!(s(last_error().message).contains("still bound"));
    close(ctx);
}

#[test]
fn listing_policies_by_prefix_and_retrying_a_small_buffer() {
    let ctx = open();
    for name in [c"team-b", c"team-a", c"other"] {
        assert_eq!(create_policy(ctx, name, c"{}"), AGC_OK as agc_rc);
    }
    let mut req: agc_list_policies_request = zeroed();
    req.struct_size = size_of::<agc_list_policies_request>();
    req.name_prefix = c"team-".as_ptr();
    let mut it = ptr::null_mut();
    // SAFETY: ctx is open; req and it are live.
    assert_eq!(unsafe { agc_list_policies(ctx, &req, &mut it) }, AGC_OK as agc_rc);

    let mut out: agc_policy_summary_response = zeroed();
    out.struct_size = size_of::<agc_policy_summary_response>();
    let mut names = Vec::new();
    let mut storage = [0u8; 64];
    // A NULL region first: BUFFER_TOO_SMALL, and the cursor stays.
    // SAFETY: it is live; out is a live local.
    assert_eq!(unsafe { agc_policy_iter_next(it, &mut out) }, AGC_ERR_BUFFER_TOO_SMALL);
    assert_eq!(out.storage_used, "team-a".len() + 1);
    out.storage = agc_buf { data: storage.as_mut_ptr(), cap: storage.len() };
    loop {
        // SAFETY: as above; out.storage points to `storage`.
        match unsafe { agc_policy_iter_next(it, &mut out) } {
            rc if rc == AGC_OK as agc_rc => {
                assert_eq!(out.summary.created_at.present, 1);
                names.push(s(out.summary.name).to_owned());
            }
            rc => {
                assert_eq!(rc, AGC_ERR_ITERATOR_EXHAUSTED);
                break;
            }
        }
    }
    assert_eq!(names, ["team-a", "team-b"]);
    // SAFETY: it came from agc_list_policies; freeing NULL is allowed.
    unsafe {
        agc_policy_iter_free(it);
        agc_policy_iter_free(ptr::null_mut());
    }
    close(ctx);
}

#[test]
fn an_iterator_outlives_its_context() {
    let ctx = open();
    let mut req: agc_list_policies_request = zeroed();
    req.struct_size = size_of::<agc_list_policies_request>();
    let mut it = ptr::null_mut();
    // SAFETY: ctx is open; req and it are live.
    assert_eq!(unsafe { agc_list_policies(ctx, &req, &mut it) }, AGC_OK as agc_rc);
    close(ctx);

    let mut storage = [0u8; 64];
    let mut out: agc_policy_summary_response = zeroed();
    out.struct_size = size_of::<agc_policy_summary_response>();
    out.storage = agc_buf { data: storage.as_mut_ptr(), cap: storage.len() };
    // SAFETY: it holds a snapshot, not the closed context.
    assert_eq!(unsafe { agc_policy_iter_next(it, &mut out) }, AGC_OK as agc_rc);
    assert_eq!(s(out.summary.name), "default");
    // SAFETY: freed once.
    unsafe { agc_policy_iter_free(it) };
}

#[test]
fn the_configured_default_policy_applies_when_a_call_names_none() {
    let mut cfg: agc_ctx_config = zeroed();
    cfg.struct_size = size_of::<agc_ctx_config>();
    cfg.default_policy = c"fallback".as_ptr();
    let ctx = open_with(&cfg);
    assert_eq!(create_policy(ctx, c"fallback", DEFAULT_POLICY), AGC_OK as agc_rc);

    let mut storage = [0u8; 256];
    let mut resp = response(&mut storage);
    let mut p = params(c"k");
    p.policy_name = ptr::null();
    assert_eq!(create(ctx, &p, &mut resp), AGC_OK as agc_rc);
    assert_eq!(s(resp.key_info.policy_name), "fallback");
    close(ctx);
}
