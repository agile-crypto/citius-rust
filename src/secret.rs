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
use std::marker::PhantomData;
use std::mem::{MaybeUninit, align_of, size_of};
use std::ops::Deref;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

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

/// Whether memory for secrets must be locked in RAM (`require_locked_memory`
/// in agc_core.h) or only should be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Locking {
    /// Locked if the system allows; otherwise usable but swappable.
    BestEffort,
    /// Locked, or the allocation fails.
    Required,
}

/// Why an allocation for secrets failed.
#[derive(Debug, PartialEq, Eq)]
pub enum AllocError {
    /// No memory was available.
    NoMemory,
    /// The memory could not be locked in RAM (`RLIMIT_MEMLOCK` used up) and
    /// `Locking::Required` was asked for.
    NotLocked,
    /// The memory could not be kept out of forked children (a Linux kernel
    /// before 4.14, without MADV_WIPEONFORK) and `Locking::Required` was
    /// asked for: a child would hold an unlocked copy of the secret.
    InheritedByChildren,
}

/// What a forked child gets of a `SecretBytes` allocation. Locks are not
/// inherited across fork(2), so a copied page would hold the secret
/// unlocked, and a forked child never needs the library's secrets: an
/// inherited context is poisoned, and `agc_ctx_reinit_after_fork` opens a
/// fresh one from the configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Inheritance {
    /// The child sees the pages zeroed (Linux MADV_WIPEONFORK).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Wiped,
    /// The child has no mapping there at all (macOS VM_INHERIT_NONE).
    Absent,
    /// The child gets an ordinary copy (the system offers neither).
    Copied,
}

/// The mapping's total size for an allocation of `n` bytes.
fn total_for(n: usize) -> Option<usize> {
    n.checked_add(HEADER).and_then(|t| t.checked_next_multiple_of(page_size()))
}

/// Keeps `[base, base + total)`, a mapping from `map`, out of forked children.
#[cfg(all(target_os = "linux", not(miri)))]
fn keep_out_of_children(base: *mut u8, total: usize) -> Inheritance {
    // SAFETY: the range is a whole mapping from `map`.
    match unsafe { libc::madvise(base.cast(), total, libc::MADV_WIPEONFORK) } {
        0 => Inheritance::Wiped,
        _ => Inheritance::Copied,
    }
}

#[cfg(all(target_os = "macos", not(miri)))]
fn keep_out_of_children(base: *mut u8, total: usize) -> Inheritance {
    // <sys/mman.h>; the libc crate does not bind it. VM_INHERIT_NONE is 2
    // (<mach/vm_inherit.h>).
    unsafe extern "C" {
        fn minherit(addr: *mut libc::c_void, len: libc::size_t, inherit: libc::c_int) -> libc::c_int;
    }
    const VM_INHERIT_NONE: libc::c_int = 2;
    // SAFETY: the range is a whole mapping from `map`.
    match unsafe { minherit(base.cast(), total, VM_INHERIT_NONE) } {
        0 => Inheritance::Absent,
        _ => Inheritance::Copied,
    }
}

#[cfg(all(not(miri), not(any(target_os = "linux", target_os = "macos"))))]
fn keep_out_of_children(_base: *mut u8, _total: usize) -> Inheritance {
    Inheritance::Copied
}

/// Miri cannot fork: no child will ever see the allocation.
#[cfg(miri)]
fn keep_out_of_children(_base: *mut u8, _total: usize) -> Inheritance {
    Inheritance::Absent
}

/// `n` bytes of zeroed memory, locked best effort; NULL if `n` is 0 or no
/// memory is available (agc_secure_alloc).
pub fn alloc(n: usize) -> *mut u8 {
    alloc_with(n, Locking::BestEffort).unwrap_or(ptr::null_mut())
}

/// `n` bytes of zeroed memory, locked as `locking` asks; NULL for `n` = 0.
pub fn alloc_with(n: usize, locking: Locking) -> Result<*mut u8, AllocError> {
    if n == 0 {
        return Ok(ptr::null_mut());
    }
    let page = page_size();
    let Some(total) = total_for(n) else {
        return Err(AllocError::NoMemory);
    };
    let (base, locked) = map(total, page);
    if base.is_null() {
        return Err(AllocError::NoMemory);
    }
    if locking == Locking::Required && !locked {
        // SAFETY: base and total are the mapping just created, unused.
        unsafe { unmap(base, total, page) };
        return Err(AllocError::NotLocked);
    }
    // SAFETY: the mapping is page-aligned and at least HEADER bytes long.
    unsafe { base.cast::<usize>().write(total) };
    // SAFETY: HEADER < total, so the result is inside the mapping.
    Ok(unsafe { base.add(HEADER) })
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

/// A fresh, zeroed, page-aligned region of `total` bytes, kept out of core
/// dumps where possible, and whether it could be locked in RAM; NULL if none
/// is available.
#[cfg(not(miri))]
fn map(total: usize, _page: usize) -> (*mut u8, bool) {
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
        return (ptr::null_mut(), false);
    }
    // Without RLIMIT_MEMLOCK headroom the memory is still usable, just
    // swappable; the caller decides whether that is acceptable.
    // SAFETY: [base, base + total) is the mapping just created.
    let locked = unsafe { libc::mlock(base, total) } == 0;
    // Best effort: a kernel without MADV_DONTDUMP still gets a locked page.
    #[cfg(target_os = "linux")]
    // SAFETY: as above.
    let _ = unsafe { libc::madvise(base, total, libc::MADV_DONTDUMP) };
    (base.cast(), locked)
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
fn map(total: usize, page: usize) -> (*mut u8, bool) {
    let layout = std::alloc::Layout::from_size_align(total, page).unwrap();
    // SAFETY: total > 0. Miri has no swap: count the block as locked.
    (unsafe { std::alloc::alloc_zeroed(layout) }, true)
}

#[cfg(miri)]
unsafe fn unmap(base: *mut u8, total: usize, page: usize) {
    let layout = std::alloc::Layout::from_size_align(total, page).unwrap();
    // SAFETY: allocated by `map` with this layout.
    unsafe { std::alloc::dealloc(base, layout) }
}

/// Bytes that must stay secret, such as a key version's material: one
/// allocation from `alloc` (its own pages, locked in RAM, kept out of core
/// dumps and out of forked children where the platform allows), zeroed and
/// released when the last clone is dropped. Cloning shares the allocation;
/// it never copies the secret.
#[derive(Clone)]
pub struct SecretBytes(Arc<Region>);

/// An allocation from `alloc` (NULL for no bytes), written once at creation.
struct Region {
    ptr: *mut u8,
    len: usize,
    /// The process that allocated it; another pid is a forked child.
    pid: u32,
    /// What a forked child holds of it.
    inherited: Inheritance,
}

// SAFETY: a Region owns its allocation alone and nothing writes to it after
// its owner (SecretBytes::new_with, Sealed::new) filled it, so handing it,
// and shared reads of it, to other threads is sound.
unsafe impl Send for Region {}
// SAFETY: as above: after creation the bytes are only ever read (a Sealed<T>
// hands out &T only, and is Sync only for T: Sync).
unsafe impl Sync for Region {}

impl Region {
    /// A fresh allocation of `len` > 0 zeroed bytes from `alloc_with`, kept
    /// out of forked children; with `Required`, never one a child would get
    /// an unlocked copy of.
    fn new(len: usize, locking: Locking) -> Result<Region, AllocError> {
        let pid = std::process::id();
        let p = alloc_with(len, locking)?;
        let total = total_for(len).expect("alloc_with computed it");
        // SAFETY: p came from alloc_with, so p - HEADER is the mapping's base.
        let inherited = keep_out_of_children(unsafe { p.sub(HEADER) }, total);
        if locking == Locking::Required && inherited == Inheritance::Copied {
            // SAFETY: p came from alloc_with and holds nothing yet.
            unsafe { free(p, len) };
            return Err(AllocError::InheritedByChildren);
        }
        Ok(Region { ptr: p, len, pid, inherited })
    }
}

impl SecretBytes {
    /// A copy of `bytes`, locked as `locking` asks. With `Required` it fails
    /// rather than keep the secret in swappable memory.
    pub fn new_with(bytes: &[u8], locking: Locking) -> Result<SecretBytes, AllocError> {
        if bytes.is_empty() {
            let pid = std::process::id();
            let empty = Region { ptr: ptr::null_mut(), len: 0, pid, inherited: Inheritance::Absent };
            return Ok(SecretBytes(Arc::new(empty)));
        }
        let r = Region::new(bytes.len(), locking)?;
        // SAFETY: r.ptr is a fresh allocation of bytes.len() writable bytes,
        // so it cannot overlap `bytes`.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), r.ptr, bytes.len()) };
        Ok(SecretBytes(Arc::new(r)))
    }
}

/// Appends `bytes` to a buffer that holds secrets. `Vec::extend_from_slice`
/// would reallocate when the capacity runs out and hand the old buffer, with
/// the secret in it, back to the allocator unwiped; only the last buffer is
/// zeroized when the `Zeroizing` drops. Here the buffer moves to a bigger
/// one first, and the old one is wiped as it drops.
pub fn extend_secret(buf: &mut zeroize::Zeroizing<Vec<u8>>, bytes: &[u8]) {
    let needed = buf.len().checked_add(bytes.len()).expect("a secret buffer fits in memory");
    if needed > buf.capacity() {
        let mut bigger = zeroize::Zeroizing::new(Vec::with_capacity(needed.max(buf.capacity().saturating_mul(2))));
        bigger.extend_from_slice(buf);
        // The old buffer is zeroized as `bigger` replaces it.
        *buf = bigger;
    }
    buf.extend_from_slice(bytes);
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
        if self.ptr.is_null() {
            return;
        }
        if std::process::id() == self.pid {
            // SAFETY: ptr came from `alloc_with` and is freed only here.
            unsafe { free(self.ptr, self.len) };
            return;
        }
        // A forked child (dropping a poisoned context). Its view of the
        // mapping is not the parent's, so `free`'s header cannot be trusted.
        match self.inherited {
            // Zero pages, header included: unmap by the size we know.
            Inheritance::Wiped => {
                let total = total_for(self.len).expect("computed at allocation");
                // SAFETY: the child's own copy of the mapping, which only
                // this Region uses; ptr - HEADER is its base.
                unsafe { unmap(self.ptr.sub(HEADER), total, page_size()) };
            }
            // Nothing is mapped there in the child.
            Inheritance::Absent => {}
            // An ordinary copy: wipe and release it like the parent would.
            // SAFETY: as in the parent; the copy has the header intact.
            Inheritance::Copied => unsafe { free(self.ptr, self.len) },
        }
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the secret.
        write!(f, "<{} secret bytes>", self.0.len)
    }
}

/// One value held like `SecretBytes`: in pages of its own, locked in RAM,
/// kept out of core dumps and out of forked children. For a secret derived
/// from key material and kept as long as the key, such as an expanded
/// signing key (docs/improvement-plan.md, phase 7). Dropping it runs the
/// value's own `Drop` (its wipe), then zeroes and unmaps the pages.
///
/// Sealing never falls back to swappable memory: a value that cannot be
/// locked, or does not fit `SEALED`'s budget, is handed back. All sealed
/// values together take at most half of `RLIMIT_MEMLOCK`, so that key
/// material, which needs the rest, never fails to lock because of them.
pub struct Sealed<T> {
    region: Region,
    _bytes: Reservation,
    _value: PhantomData<T>,
}

/// The locked memory sealed values may take, and take now.
pub struct SealedBudget {
    cap: OnceLock<usize>,
    fixed: usize,
    used: AtomicUsize,
}

/// The process's budget for sealed values: half of `RLIMIT_MEMLOCK`'s soft
/// limit, or 64 MiB when there is no limit.
pub static SEALED: SealedBudget = SealedBudget { cap: OnceLock::new(), fixed: 0, used: AtomicUsize::new(0) };

const UNLIMITED_SEALED_CAP: usize = 64 << 20;

impl SealedBudget {
    #[cfg(test)]
    const fn fixed(cap: usize) -> SealedBudget {
        SealedBudget { cap: OnceLock::new(), fixed: cap, used: AtomicUsize::new(0) }
    }

    /// The bytes (whole pages) sealed values may take.
    pub fn cap(&self) -> usize {
        if self.fixed > 0 {
            return self.fixed;
        }
        *self.cap.get_or_init(|| memlock_limit().map_or(UNLIMITED_SEALED_CAP, |limit| limit / 2))
    }

    /// The bytes (whole pages) sealed values take now.
    #[cfg_attr(not(test), allow(dead_code, reason = "for tests and diagnostics"))]
    pub fn used(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }

    fn reserve(&'static self, bytes: usize) -> Option<Reservation> {
        let cap = self.cap();
        self.used
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |u| u.checked_add(bytes).filter(|&t| t <= cap))
            .ok()
            .map(|_| Reservation { budget: self, bytes })
    }
}

/// `RLIMIT_MEMLOCK`'s soft limit in bytes; None without a limit.
#[cfg(not(miri))]
fn memlock_limit() -> Option<usize> {
    let mut r = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: r is a plain out-parameter.
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut r) } != 0 || r.rlim_cur == libc::RLIM_INFINITY {
        return None;
    }
    usize::try_from(r.rlim_cur).ok()
}

#[cfg(miri)]
fn memlock_limit() -> Option<usize> {
    None
}

/// Bytes taken from a budget, given back when dropped.
struct Reservation {
    budget: &'static SealedBudget,
    bytes: usize,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

impl<T> Sealed<T> {
    /// `value`, moved into fresh sealed pages; handed back if it cannot be
    /// sealed (no budget left, the pages cannot be locked or kept out of
    /// forked children).
    ///
    /// The bytes it occupied in this function are wiped once they are copied.
    /// The caller's own temporaries are beyond its reach: a value built on
    /// the stack and passed in may leave a copy there (DEVIATIONS.md).
    ///
    /// # Safety
    /// `T` keeps all its state inline: it owns no heap memory, descriptor or
    /// other resource. A forked child never runs `T`'s `Drop` (its view of
    /// the pages is wiped or absent) and only unmaps them, which is sound
    /// only if nothing outside the pages belongs to the value.
    pub unsafe fn new(value: T) -> Result<Sealed<T>, T> {
        // SAFETY: forwarded from this function's contract.
        unsafe { Self::new_within(&SEALED, value) }
    }

    /// # Safety
    /// As `new`.
    unsafe fn new_within(budget: &'static SealedBudget, value: T) -> Result<Sealed<T>, T> {
        const { assert!(align_of::<T>() <= HEADER, "pages hand out HEADER-aligned memory") };
        let size = size_of::<T>().max(1);
        let Some(total) = total_for(size) else { return Err(value) };
        let Some(reservation) = budget.reserve(total) else { return Err(value) };
        let Ok(region) = Region::new(size, Locking::Required) else { return Err(value) };
        let mut slot = MaybeUninit::new(value);
        // SAFETY: region.ptr is HEADER-aligned (enough for T, asserted above)
        // with size_of::<T>() writable bytes, fresh, so it cannot overlap
        // `slot`.
        unsafe { ptr::copy_nonoverlapping(slot.as_ptr(), region.ptr.cast::<T>(), 1) };
        // The value lives in the pages now. Wipe this frame's copy; as a
        // MaybeUninit it is never dropped or read as a T again.
        // SAFETY: slot's own size_of::<T>() bytes, writable.
        unsafe { std::slice::from_raw_parts_mut(slot.as_mut_ptr().cast::<u8>(), size_of::<T>()) }.zeroize();
        Ok(Sealed { region, _bytes: reservation, _value: PhantomData })
    }
}

impl<T> Deref for Sealed<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: the pages hold the T `new` wrote, alive until drop.
        unsafe { &*self.region.ptr.cast::<T>() }
    }
}

impl<T> Drop for Sealed<T> {
    fn drop(&mut self) {
        // In a forked child the pages are wiped or absent, and T owns nothing
        // outside them (`new`'s contract): there is nothing to drop. `region`
        // then zeroes and unmaps the pages, or unmaps the child's view.
        if std::process::id() == self.region.pid {
            // SAFETY: the pages hold the T `new` wrote; dropped only here.
            unsafe { ptr::drop_in_place(self.region.ptr.cast::<T>()) };
        }
    }
}

impl<T> fmt::Debug for Sealed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the secret.
        write!(f, "<sealed {} bytes>", size_of::<T>())
    }
}

/// Secret bytes on the ordinary heap, wiped when dropped: the bytes and the
/// spare capacity behind them. For data as large as the caller's input,
/// such as a decrypted plaintext, which is not worth its own locked pages
/// and must not cost a byte-by-byte wipe either (`Zeroizing<Vec<u8>>` wipes
/// element by element, ~0.4 ms per MiB; this wipes at memset speed).
///
/// It cannot grow: growing reallocates and would leave an unwiped copy
/// behind. Build it from the finished `Vec`, then only shorten it.
pub struct SecretVec(Vec<u8>);

impl SecretVec {
    /// Shortens to `len` bytes; the bytes cut off are wiped now, not at drop.
    pub fn truncate(&mut self, len: usize) {
        if len < self.0.len() {
            self.0[len..].zeroize();
            self.0.truncate(len);
        }
    }
}

impl From<Vec<u8>> for SecretVec {
    fn from(v: Vec<u8>) -> Self {
        SecretVec(v)
    }
}

impl std::ops::Deref for SecretVec {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::DerefMut for SecretVec {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Drop for SecretVec {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();
        self.0.spare_capacity_mut().zeroize();
    }
}

impl fmt::Debug for SecretVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the secret.
        write!(f, "<{} secret bytes>", self.0.len())
    }
}

/// Overwrites `n` bytes at `p` with zeros in a way the optimiser may not
/// remove (zeroize: `fill` behind an optimisation barrier).
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

/// For tests: detects secrets that reach the allocator unwiped. While a
/// `leaks_during` closure runs, every freed heap block is searched for
/// `CANARY`; tests put the canary where a secret goes and count the frees
/// that still hold it. Not under Miri (whose allocator is its own).
#[cfg(all(test, not(miri)))]
pub(crate) mod leak_check {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};

    pub const CANARY: [u8; 32] = *b"agc-leak-canary:wipe-before-free";

    static ARMED: AtomicBool = AtomicBool::new(false);
    static FOUND: AtomicUsize = AtomicUsize::new(0);
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

    struct Scanning;

    // SAFETY: forwards to System; `realloc` keeps the trait's default
    // (alloc, copy, dealloc), so an outgrown block passes through `dealloc`.
    unsafe impl GlobalAlloc for Scanning {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the caller upholds GlobalAlloc::alloc's contract.
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            if ARMED.load(SeqCst) && layout.size() >= CANARY.len() {
                // SAFETY: the block is still allocated and layout.size() long.
                let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
                if block.windows(CANARY.len()).any(|w| w == CANARY) {
                    FOUND.fetch_add(1, SeqCst);
                }
            }
            // SAFETY: ptr came from System.alloc with this layout.
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    #[global_allocator]
    static ALLOCATOR: Scanning = Scanning;

    /// How many freed blocks still held `CANARY` while `f` ran.
    pub fn leaks_during(f: impl FnOnce()) -> usize {
        let _one = ONE_AT_A_TIME.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        FOUND.store(0, SeqCst);
        ARMED.store(true, SeqCst);
        f();
        ARMED.store(false, SeqCst);
        FOUND.load(SeqCst)
    }
}

/// Tests that fork(2) hold this exclusively; tests that hold a file store's
/// lock descriptor open hold it shared. A child forked while another test's
/// store is open inherits that descriptor, and with it the store's lock,
/// until it exits: the other test's reopen would then fail at random.
#[cfg(test)]
pub(crate) static FORKING: std::sync::RwLock<()> = std::sync::RwLock::new(());

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
        let a = SecretBytes::new_with(b"key material", Locking::BestEffort).unwrap();
        let b = a.clone();
        assert_eq!(&*b, b"key material");
        assert_eq!(a.as_ptr(), b.as_ptr(), "a clone shares, never copies");
        assert_eq!(a.as_ptr() as usize % 16, 0);
        assert_eq!(format!("{a:?}"), "<12 secret bytes>");
        drop(a);
        assert_eq!(&*b, b"key material", "the last clone keeps it alive");
        assert!(SecretBytes::new_with(&[], Locking::BestEffort).unwrap().is_empty());
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

    #[test]
    #[cfg(not(miri))]
    fn growing_a_secret_buffer_leaves_no_copy_behind() {
        use super::leak_check::{CANARY, leaks_during};
        // The detector works: a plain Vec that outgrows its capacity frees
        // the old buffer, canary and all.
        let plain = leaks_during(|| {
            let mut v = zeroize::Zeroizing::new(Vec::with_capacity(32));
            v.extend_from_slice(&CANARY);
            v.extend_from_slice(&[0; 4096]);
        });
        assert!(plain >= 1, "the plain Vec's outgrown buffer held the canary");
        let ours = leaks_during(|| {
            let mut v = zeroize::Zeroizing::new(Vec::new());
            extend_secret(&mut v, &CANARY);
            for _ in 0..64 {
                extend_secret(&mut v, &[0; 1024]);
            }
        });
        assert_eq!(ours, 0);
    }

    #[test]
    fn required_locking_is_honoured_or_fails() {
        // Locking works in the test environment (unlimited RLIMIT_MEMLOCK
        // on developer machines) or the allocation says it did not.
        match SecretBytes::new_with(b"secret", Locking::Required) {
            Ok(s) => assert_eq!(&*s, b"secret"),
            Err(e) => assert_eq!(e, AllocError::NotLocked),
        }
        assert_eq!(&*SecretBytes::new_with(b"secret", Locking::BestEffort).unwrap(), b"secret");
        assert!(SecretBytes::new_with(b"", Locking::Required).unwrap().is_empty());
    }

    /// Waits for a forked child; true if it exited 0, false if a signal
    /// ended it.
    #[cfg(not(miri))]
    fn child_ok(pid: libc::pid_t) -> bool {
        let mut status = 0;
        // SAFETY: pid is our child; status is a plain out-parameter.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        if libc::WIFSIGNALED(status) {
            return false;
        }
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0, "child status {status}");
        true
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot fork")]
    #[cfg(not(miri))]
    fn secret_vecs_wipe_their_bytes_and_spare_capacity() {
        use super::leak_check::{CANARY, leaks_during};
        // The bytes, and a canary already in the spare capacity when the
        // Vec is handed over (a provider truncated it): drop wipes both.
        let leaks = leaks_during(|| {
            let mut v = Vec::with_capacity(4 * CANARY.len());
            v.extend_from_slice(&CANARY);
            v.extend_from_slice(&CANARY);
            v.truncate(1);
            let s = SecretVec::from(v);
            assert_eq!(s.len(), 1);
        });
        assert_eq!(leaks, 0, "drop wipes the spare capacity");
        let leaks = leaks_during(|| drop(SecretVec::from(CANARY.to_vec())));
        assert_eq!(leaks, 0, "drop wipes the bytes");
        assert_eq!(format!("{:?}", SecretVec::from(vec![1, 2])), "<2 secret bytes>");
    }

    /// A value with a wipe of its own, inline like an expanded signing key.
    struct Inline([u8; 32]);

    impl Drop for Inline {
        fn drop(&mut self) {
            self.0.zeroize();
        }
    }

    #[test]
    fn a_sealed_value_lives_in_its_own_locked_pages() {
        static B: SealedBudget = SealedBudget::fixed(1 << 20);
        // SAFETY: Inline is a plain array.
        let s = unsafe { Sealed::new_within(&B, Inline([7; 32])) }.unwrap_or_else(|_| panic!("sealed"));
        assert_eq!(s.0, [7; 32]);
        assert_eq!(&*s as *const Inline as usize % page_size(), HEADER, "at the start of its own mapping");
        assert_eq!(B.used(), page_size(), "one page taken from the budget");
        assert_eq!(format!("{s:?}"), "<sealed 32 bytes>");
        drop(s);
        assert_eq!(B.used(), 0, "given back");
    }

    #[test]
    fn past_the_budget_a_value_is_handed_back() {
        static B: SealedBudget = SealedBudget::fixed(4096);
        // SAFETY: Inline is a plain array.
        let first = unsafe { Sealed::new_within(&B, Inline([1; 32])) };
        if page_size() > 4096 {
            assert!(first.is_err(), "a page larger than the whole budget");
            return;
        }
        let first = first.unwrap_or_else(|_| panic!("fits"));
        // SAFETY: as above.
        let second = unsafe { Sealed::new_within(&B, Inline([2; 32])) };
        assert_eq!(second.err().map(|v| v.0), Some([2; 32]), "handed back, intact");
        drop(first);
        // SAFETY: as above.
        assert!(unsafe { Sealed::new_within(&B, Inline([3; 32])) }.is_ok(), "room again");
    }

    #[test]
    fn the_process_budget_is_half_the_memlock_limit() {
        match memlock_limit() {
            Some(limit) => assert_eq!(SEALED.cap(), limit / 2),
            None => assert_eq!(SEALED.cap(), UNLIMITED_SEALED_CAP),
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn sealing_leaves_no_copy_on_the_heap() {
        use super::leak_check::{CANARY, leaks_during};
        static B: SealedBudget = SealedBudget::fixed(1 << 20);
        let leaks = leaks_during(|| {
            // Made on the heap, as a provider's parse may: the box is freed
            // after the value moved out of it, and the sealed copy is wiped
            // by the value's own Drop.
            let boxed = Box::new(Inline(CANARY));
            // SAFETY: Inline is a plain array.
            let s = unsafe { Sealed::new_within(&B, *boxed) }.unwrap_or_else(|_| panic!("sealed"));
            assert_eq!(s.0, CANARY);
        });
        assert_eq!(leaks, 1, "only the caller's own box, which sealing cannot reach (DEVIATIONS.md)");
        let leaks = leaks_during(|| {
            // SAFETY: Inline is a plain array.
            drop(unsafe { Sealed::new_within(&B, Inline(CANARY)) });
        });
        assert_eq!(leaks, 0, "the sealed value never touches the heap");
    }

    #[test]
    fn truncating_a_secret_vec_wipes_what_it_cuts_off_at_once() {
        let mut s = SecretVec::from([[7u8; 8], [9; 8]].concat());
        s.truncate(8);
        assert_eq!(&s[..], &[7; 8]);
        // SAFETY: these 8 spare bytes were initialised before the truncation.
        assert!(s.0.spare_capacity_mut()[..8].iter().all(|b| unsafe { b.assume_init() } == 0));
        s.truncate(9);
        assert_eq!(s.len(), 8, "truncate never lengthens");
    }

    #[test]
    fn a_forked_child_gets_no_copy_of_a_secret() {
        #[cfg(not(miri))]
        {
            let _no_store_open = super::FORKING.write().unwrap_or_else(std::sync::PoisonError::into_inner);
            let s = SecretBytes::new_with(&[0x5a; 64], Locking::BestEffort).unwrap();
            let inherited = s.0.inherited;
            let p = s.as_ptr();
            // SAFETY: the child only reads one byte and exits, without
            // allocating or unwinding.
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                // SAFETY: Wiped: a zero page; Absent: faults, as intended.
                let b = unsafe { std::ptr::read_volatile(p) };
                // SAFETY: ends the child without running the test harness.
                unsafe { libc::_exit(i32::from(b != 0)) };
            }
            let read_back = child_ok(pid);
            match inherited {
                Inheritance::Wiped => assert!(read_back, "the child read zeros"),
                Inheritance::Absent => assert!(!read_back, "the child has no mapping to read"),
                Inheritance::Copied => {} // a platform with neither mechanism
            }
            #[cfg(target_os = "linux")]
            assert_eq!(inherited, Inheritance::Wiped);
            #[cfg(target_os = "macos")]
            assert_eq!(inherited, Inheritance::Absent);

            // Dropping it in the child, as agc_ctx_reinit_after_fork does
            // with the inherited context, must not touch the parent's view.
            // SAFETY: as above; the drop only unmaps (or does nothing).
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                drop(s.clone());
                drop(s);
                // SAFETY: ends the child without running the test harness.
                unsafe { libc::_exit(0) };
            }
            assert!(child_ok(pid), "the child dropped its view cleanly");
            assert_eq!(&*s, &[0x5a; 64][..], "the parent's secret is untouched");

            // A sealed value: the child drops it without running its Drop
            // (no pages to run it on) and the parent's stays intact.
            // SAFETY: Inline is a plain array.
            let sealed = unsafe { Sealed::new(Inline([0x6b; 32])) }.unwrap_or_else(|_| panic!("sealed"));
            // SAFETY: the child only drops the value and exits.
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                drop(sealed);
                // SAFETY: ends the child without running the test harness.
                unsafe { libc::_exit(0) };
            }
            assert!(child_ok(pid), "the child dropped its sealed view cleanly");
            assert_eq!(sealed.0, [0x6b; 32]);
        }
    }
}
