//! The exports called the way C calls them: raw pointers, caller-owned
//! structs and buffers. Written in Rust so that Miri can check the whole path
//! (context pointer, versioned structs, storage writer, error record) for
//! undefined behaviour, which it cannot do for the C tests.

use std::ffi::{CStr, c_char};
use std::ptr;

use crate::bindings::*;
// Explicit, so the names mean our implementations, not bindgen's declarations.
use super::{
    agc_create_key, agc_ctx_close, agc_ctx_open, agc_last_error, agc_rc_message, agc_rc_name,
};

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

fn open() -> *mut agc_ctx {
    let mut cfg: agc_ctx_config = zeroed();
    cfg.struct_size = size_of::<agc_ctx_config>();
    let mut ctx = ptr::null_mut();
    // SAFETY: cfg and ctx are live locals.
    assert_eq!(unsafe { agc_ctx_open(&cfg, &mut ctx) }, AGC_OK as agc_rc);
    assert!(!ctx.is_null());
    ctx
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
    assert_eq!(s(info.template_id), "aes-256-gcm");
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
    assert_eq!(s(resp.key_info.template_id), "aes-256-gcm");
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
