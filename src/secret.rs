//! Memory for secrets (agc_core.h, "Memory hygiene"): the allocator behind
//! agc_secure_alloc, and `SecretBytes`, which holds key material.
//!
//! A technical primitive below every layer, like `zeroize`: the domain may
//! use it (tests/architecture.rs), and it uses nothing of the crate.
//!
//! Every allocation is its own page-aligned anonymous mapping, locked in RAM
//! (best effort) and excluded from core dumps where the platform allows.
//! Sharing pages with ordinary heap data, as malloc + mlock does, would let
//! one `munlock` unlock someone else's secret and let the heap reuse pages
//! that held key material.
//!
//! ```text
//! base                      base + HEADER                 base + total
//! | total: usize | padding  | caller's n bytes | unused ... |
//! ```
//! The caller gets `base + HEADER`; HEADER keeps it 16-byte aligned, as
//! malloc's result is.

use std::fmt;
use std::ops::Deref;
use std::ptr;
use std::sync::Arc;

use zeroize::Zeroize;

const HEADER: usize = 16;

#[cfg(not(miri))]
fn page_size() -> usize {
    // SAFETY: sysconf has no preconditions.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(size).ok().filter(|&s| s > 0).unwrap_or(4096)
}

#[cfg(miri)]
fn page_size() -> usize {
    4096
}

/// `n` bytes of zeroed memory, or NULL if `n` is 0 or no memory is available.
pub fn alloc(n: usize) -> *mut u8 {
    if n == 0 {
        return ptr::null_mut();
    }
    let page = page_size();
    let Some(total) = n.checked_add(HEADER).and_then(|t| t.checked_next_multiple_of(page)) else {
        return ptr::null_mut();
    };
    let base = map(total, page);
    if base.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the mapping is page-aligned and at least HEADER bytes long.
    unsafe { base.cast::<usize>().write(total) };
    // SAFETY: HEADER < total, so the result is inside the mapping.
    unsafe { base.add(HEADER) }
}

/// Zeroes and releases memory from `alloc`. The whole allocation is zeroed,
/// whatever `n` says: `n` is part of the C signature for symmetry with
/// `agc_secure_zero`, and trusting it could leave a secret's tail behind.
///
/// # Safety
/// `p` is NULL or was returned by `alloc` and not freed yet.
pub unsafe fn free(p: *mut u8, _n: usize) {
    if p.is_null() {
        return;
    }
    // SAFETY: p came from alloc, so p - HEADER is the mapping's base.
    let base = unsafe { p.sub(HEADER) };
    // SAFETY: alloc wrote the mapping's size at its base.
    let total = unsafe { base.cast::<usize>().read() };
    // SAFETY: [base, base + total) is the whole mapping, which only this
    // allocation uses.
    unsafe { std::slice::from_raw_parts_mut(base, total) }.zeroize();
    // SAFETY: base and total describe a mapping from `map`, not used again.
    unsafe { unmap(base, total, page_size()) };
}

/// A fresh, zeroed, page-aligned region of `total` bytes, locked in RAM and
/// kept out of core dumps where possible; NULL if none is available.
#[cfg(not(miri))]
fn map(total: usize, _page: usize) -> *mut u8 {
    // SAFETY: a fresh anonymous private mapping; no existing memory is affected.
    let base = unsafe {
        libc::mmap(
            ptr::null_mut(),
            total,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if base == libc::MAP_FAILED {
        return ptr::null_mut();
    }
    // Best effort, like the header says: without RLIMIT_MEMLOCK headroom the
    // memory is still usable, just swappable.
    // SAFETY: [base, base + total) is the mapping just created.
    let _ = unsafe { libc::mlock(base, total) };
    #[cfg(target_os = "linux")]
    // SAFETY: as above.
    let _ = unsafe { libc::madvise(base, total, libc::MADV_DONTDUMP) };
    base.cast()
}

/// # Safety
/// `base` and `total` are a region from `map`, not used afterwards.
#[cfg(not(miri))]
unsafe fn unmap(base: *mut u8, total: usize, _page: usize) {
    // SAFETY: by this function's contract.
    unsafe {
        libc::munlock(base.cast(), total);
        libc::munmap(base.cast(), total);
    }
}

// Miri cannot execute mmap/mlock. A page-aligned heap block has the same
// layout, so everything above it is still checked.
#[cfg(miri)]
fn map(total: usize, page: usize) -> *mut u8 {
    let layout = std::alloc::Layout::from_size_align(total, page).unwrap();
    // SAFETY: total > 0.
    unsafe { std::alloc::alloc_zeroed(layout) }
}

#[cfg(miri)]
unsafe fn unmap(base: *mut u8, total: usize, page: usize) {
    let layout = std::alloc::Layout::from_size_align(total, page).unwrap();
    // SAFETY: allocated by `map` with this layout.
    unsafe { std::alloc::dealloc(base, layout) }
}

/// Bytes that must stay secret, such as a key version's material: one
/// allocation from `alloc` (its own pages, locked in RAM and kept out of core
/// dumps where the platform allows), zeroed and released when the last clone
/// is dropped. Cloning shares the allocation; it never copies the secret.
#[derive(Clone)]
pub struct SecretBytes(Arc<Region>);

/// An allocation from `alloc` (NULL for no bytes), written once at creation.
struct Region {
    ptr: *mut u8,
    len: usize,
}

// SAFETY: a Region owns its allocation alone and nothing writes to it after
// SecretBytes::new, so handing it, and shared reads of it, to other threads
// is sound.
unsafe impl Send for Region {}
// SAFETY: as above: after creation the bytes are only ever read.
unsafe impl Sync for Region {}

impl SecretBytes {
    /// A locked copy of `bytes`. Fails only where a `Vec` would: when no
    /// memory is left, through `handle_alloc_error`.
    pub fn new(bytes: &[u8]) -> SecretBytes {
        if bytes.is_empty() {
            return SecretBytes(Arc::new(Region { ptr: ptr::null_mut(), len: 0 }));
        }
        let p = alloc(bytes.len());
        if p.is_null() {
            let layout = std::alloc::Layout::from_size_align(bytes.len(), 16).unwrap_or(std::alloc::Layout::new::<u8>());
            std::alloc::handle_alloc_error(layout);
        }
        // SAFETY: p is a fresh allocation of bytes.len() writable bytes, so
        // it cannot overlap `bytes`.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len()) };
        SecretBytes(Arc::new(Region { ptr: p, len: bytes.len() }))
    }
}

impl Deref for SecretBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        let r = &*self.0;
        if r.ptr.is_null() {
            return &[];
        }
        // SAFETY: ptr holds len initialised bytes, alive as long as the
        // Region and never written after creation.
        unsafe { std::slice::from_raw_parts(r.ptr, r.len) }
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        // SAFETY: ptr is NULL or came from `alloc` and is freed only here.
        unsafe { free(self.ptr, self.len) };
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the secret.
        write!(f, "<{} secret bytes>", self.0.len)
    }
}

/// Overwrites `n` bytes at `p` with zeros in a way the optimiser may not
/// remove (zeroize: volatile writes plus a compiler fence).
///
/// # Safety
/// `p` is NULL or valid for writing `n` bytes.
pub unsafe fn zero(p: *mut u8, n: usize) {
    if p.is_null() || n == 0 {
        return;
    }
    // SAFETY: p is non-null and valid for n bytes (contract).
    unsafe { std::slice::from_raw_parts_mut(p, n) }.zeroize();
}

/// Whether the `n` bytes at `a` and `b` are equal, in time that does not
/// depend on where they differ. NULL is never equal to anything, as in the C
/// stub.
///
/// # Safety
/// `a` and `b` are NULL or valid for reading `n` bytes.
pub unsafe fn ct_equal(a: *const u8, b: *const u8, n: usize) -> bool {
    use subtle::ConstantTimeEq;
    if a.is_null() || b.is_null() {
        return false;
    }
    // SAFETY: both non-null and readable for n bytes (contract).
    let (a, b) = unsafe { (std::slice::from_raw_parts(a, n), std::slice::from_raw_parts(b, n)) };
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_is_zeroed_aligned_and_usable() {
        for n in [1, 15, 16, 4096 - HEADER, 4096, 100_000] {
            let p = alloc(n);
            assert!(!p.is_null());
            assert_eq!(p as usize % 16, 0);
            // SAFETY: p has n bytes, just allocated.
            let s = unsafe { std::slice::from_raw_parts_mut(p, n) };
            assert!(s.iter().all(|&b| b == 0));
            s.fill(0x5A);
            // SAFETY: p came from alloc.
            unsafe { free(p, n) };
        }
    }

    #[test]
    fn zero_size_and_null_are_harmless() {
        assert!(alloc(0).is_null());
        assert!(alloc(usize::MAX).is_null());
        // SAFETY: NULL is allowed.
        unsafe {
            free(ptr::null_mut(), 0);
            zero(ptr::null_mut(), 8);
        }
    }

    #[test]
    fn secret_bytes_share_one_allocation_and_hide_their_content() {
        let a = SecretBytes::new(b"key material");
        let b = a.clone();
        assert_eq!(&*b, b"key material");
        assert_eq!(a.as_ptr(), b.as_ptr(), "a clone shares, never copies");
        assert_eq!(a.as_ptr() as usize % 16, 0);
        assert_eq!(format!("{a:?}"), "<12 secret bytes>");
        drop(a);
        assert_eq!(&*b, b"key material", "the last clone keeps it alive");
        assert!(SecretBytes::new(&[]).is_empty());
    }

    #[test]
    fn zero_clears() {
        let mut buf = [0xFFu8; 33];
        // SAFETY: buf is 33 writable bytes.
        unsafe { zero(buf.as_mut_ptr(), buf.len()) };
        assert_eq!(buf, [0; 33]);
    }

    #[test]
    fn ct_equal_compares() {
        let a = *b"secret-tag";
        let mut b = a;
        // SAFETY: a and b are 10 readable bytes, or NULL.
        unsafe {
            assert!(ct_equal(a.as_ptr(), b.as_ptr(), a.len()));
            b[9] ^= 1;
            assert!(!ct_equal(a.as_ptr(), b.as_ptr(), a.len()));
            assert!(ct_equal(a.as_ptr(), b.as_ptr(), 0));
            assert!(!ct_equal(ptr::null(), b.as_ptr(), 0));
        }
    }
}
