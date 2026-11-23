//! Running stack-hungry code on a stack that is big enough.
//!
//! Some RustCrypto operations keep large arrays on the stack: an ML-DSA-87
//! key generation needs ~630 KiB, a signature ~510 KiB (twice that in a debug
//! build), and the first use of a P-521 curve builds its basepoint tables in
//! ~130 KiB. The caller's thread may be much smaller: musl gives new threads
//! 128 KiB, macOS 512 KiB, an RTOS often less. Overflowing it hits the guard
//! page, and SIGSEGV/SIGBUS kills the whole process: `catch_unwind` cannot
//! catch it (docs/performance.md F12).
//!
//! `with_stack(need, f)` runs `f` on the current thread when at least `need`
//! bytes of stack are left, and otherwise on a short-lived helper thread with
//! a stack of its own, so a small caller stack never decides whether the
//! library crashes. The check costs a comparison: the thread's stack bounds
//! are looked up once per thread and cached.
//!
//! A technical primitive below every layer, like `secret`: adapters may use
//! it (tests/architecture.rs), and it uses nothing of the crate.

use std::cell::Cell;

/// Kept free below what an operation is expected to need: signal handlers,
/// the libc frames of the calls the operation makes, estimation error, and
/// the guard page some systems count into the stack size (macOS).
pub const MARGIN: usize = 64 * 1024;

/// Why `with_stack` could not run the closure.
#[derive(Debug)]
pub struct NoStack(pub std::io::Error);

/// Runs `f` with at least `need` bytes of stack: inline if the current
/// thread has them left, else on a helper thread with `2 * need` bytes,
/// joined before returning. A panic in `f` resumes on the calling thread.
/// Fails only if the helper thread cannot be started.
pub fn with_stack<R: Send>(need: usize, f: impl FnOnce() -> R + Send) -> Result<R, NoStack> {
    if remaining().is_some_and(|left| left >= need.saturating_add(MARGIN)) {
        return Ok(f());
    }
    std::thread::scope(|s| {
        let helper = std::thread::Builder::new()
            .name("agc-big-stack".into())
            .stack_size(need.saturating_mul(2).max(1 << 20))
            .spawn_scoped(s, f)
            .map_err(NoStack)?;
        match helper.join() {
            Ok(r) => Ok(r),
            Err(panic) => std::panic::resume_unwind(panic),
        }
    })
}

/// The stack bytes left below the current frame, or `None` where they cannot
/// be known: an unsupported platform, a thread whose bounds the system does
/// not report, or a stack pointer outside them (a coroutine's own stack).
pub fn remaining() -> Option<usize> {
    let (low, high) = bounds()?;
    let marker = 0u8;
    let sp = std::hint::black_box(&marker) as *const u8 as usize;
    (low < sp && sp <= high).then(|| sp - low)
}

thread_local! {
    /// This thread's stack as [low, high), looked up on first use. `(0, 0)`:
    /// not looked up yet; `(1, 0)`: unknown.
    static BOUNDS: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
}

fn bounds() -> Option<(usize, usize)> {
    BOUNDS
        .try_with(|b| {
            if b.get() == (0, 0) {
                b.set(query().unwrap_or((1, 0)));
            }
            let (low, high) = b.get();
            (high > low).then_some((low, high))
        })
        .ok()
        .flatten()
}

#[cfg(all(target_os = "macos", not(miri)))]
fn query() -> Option<(usize, usize)> {
    // SAFETY: both calls only read the calling thread's own attributes.
    let (top, size) = unsafe {
        (
            libc::pthread_get_stackaddr_np(libc::pthread_self()) as usize,
            libc::pthread_get_stacksize_np(libc::pthread_self()),
        )
    };
    (top > size && size > 0).then(|| (top - size, top))
}

#[cfg(all(target_os = "linux", not(miri)))]
fn query() -> Option<(usize, usize)> {
    // SAFETY: attr is initialised by pthread_getattr_np before it is read,
    // and destroyed once; addr and size are plain out-parameters.
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        if libc::pthread_getattr_np(libc::pthread_self(), &mut attr) != 0 {
            return None;
        }
        let mut addr: *mut libc::c_void = std::ptr::null_mut();
        let mut size: libc::size_t = 0;
        let rc = libc::pthread_attr_getstack(&attr, &mut addr, &mut size);
        libc::pthread_attr_destroy(&mut attr);
        let low = addr as usize;
        (rc == 0 && size > 0 && low > 0).then(|| (low, low.saturating_add(size)))
    }
}

/// Elsewhere the bounds are unknown, so `with_stack` always uses a helper
/// thread. Under Miri, which cannot call these functions and whose stacks
/// are not the machine's, it runs everything inline.
#[cfg(all(not(miri), not(any(target_os = "macos", target_os = "linux"))))]
fn query() -> Option<(usize, usize)> {
    None
}

#[cfg(miri)]
fn query() -> Option<(usize, usize)> {
    Some((1, usize::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hint::black_box;

    /// Uses about `kib` KiB of stack, in frames the optimiser cannot drop.
    fn burn(kib: usize) -> u8 {
        let buf = black_box([kib as u8; 1024]);
        if kib <= 1 { buf[0] } else { burn(kib - 1).wrapping_add(black_box(buf)[1023]) }
    }

    fn on_thread<R: Send + 'static>(stack: usize, f: impl FnOnce() -> R + Send + 'static) -> R {
        std::thread::Builder::new().stack_size(stack).spawn(f).unwrap().join().unwrap()
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not model the machine's stack bounds")]
    fn remaining_reflects_the_thread_stack() {
        // At least what was asked for is there. A thread may get more: glibc
        // hands out a cached, bigger stack from a finished thread. What is
        // left is never more than the stack the system reports.
        let (left, (low, high)) = on_thread(1 << 20, || (remaining().expect("bounds known"), bounds().unwrap()));
        assert!(left > 600 * 1024 && left <= high - low, "{left} of {}", high - low);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not model the machine's stack bounds")]
    fn a_small_stack_hands_the_work_to_a_helper() {
        // ≥ 300 KiB of frames (several times that in a debug build) would
        // overflow a 128 KiB thread inline; the helper gets 2 × 4 MiB.
        let r = on_thread(128 * 1024, || with_stack(4 << 20, || burn(300)).unwrap());
        assert_eq!(r, on_thread(16 << 20, || burn(300)));
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not model the machine's stack bounds")]
    fn enough_stack_runs_inline_and_too_little_does_not() {
        let (small, big) = on_thread(4 << 20, || {
            let here = std::thread::current().id();
            let small = with_stack(64 * 1024, move || std::thread::current().id() == here).unwrap();
            let big = with_stack(16 << 20, move || std::thread::current().id() == here).unwrap();
            (small, big)
        });
        assert!(small, "64 KiB fit in a 4 MiB thread: inline");
        assert!(!big, "16 MiB do not: a helper thread");
    }

    #[test]
    fn a_panic_reaches_the_caller() {
        // 16 MiB is more than the test thread has: the panic crosses the helper.
        let r = std::panic::catch_unwind(|| with_stack(16 << 20, || panic!("inside")));
        assert!(r.is_err());
    }
}
