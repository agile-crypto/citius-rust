//! Memory for secrets (agc_core.h, "Memory hygiene").
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

use std::ptr;

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
