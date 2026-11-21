//! Heap allocations per operation and layer (docs/performance.md): a
//! counting global allocator around the system one. Prints a table:
//! allocations, bytes allocated, and peak live bytes above the start, per op.

use agilecrypto::bench_support::{CipherBench, Encoding, SignBench, context_parts};
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

struct Counting;

static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards to System; only counts.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        BYTES.fetch_add(l.size(), Relaxed);
        let live = LIVE.fetch_add(l.size(), Relaxed) + l.size();
        PEAK.fetch_max(live, Relaxed);
        // SAFETY: the caller upholds alloc's contract.
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Relaxed);
        // SAFETY: the caller upholds dealloc's contract.
        unsafe { System.dealloc(p, l) }
    }
}

#[global_allocator]
static A: Counting = Counting;

/// Runs `op` once to warm up, then once measured (allocation counts are
/// deterministic per call). Prints allocs, bytes, peak transient bytes.
fn measure(what: &str, mut op: impl FnMut()) {
    op();
    let (a, b) = (ALLOCS.load(Relaxed), BYTES.load(Relaxed));
    let live = LIVE.load(Relaxed);
    PEAK.store(live, Relaxed);
    op();
    let peak = PEAK.load(Relaxed) - live;
    println!("{what:<48} {:>7} {:>10} {:>10}", ALLOCS.load(Relaxed) - a, BYTES.load(Relaxed) - b, peak);
}

/// Builds `make()` and keeps it: what it retains (live bytes afterwards),
/// its transient peak, and its allocation count.
fn retained(what: &str, make: fn() -> context_parts::Held) {
    drop(make()); // warm-up: lazy statics
    let (a, live) = (ALLOCS.load(Relaxed), LIVE.load(Relaxed));
    PEAK.store(live, Relaxed);
    let held = make();
    let kept = LIVE.load(Relaxed) - live;
    let (n, peak) = (ALLOCS.load(Relaxed) - a, PEAK.load(Relaxed) - live);
    drop(held);
    let t = std::time::Instant::now();
    for _ in 0..50 {
        drop(black_box(make()));
    }
    let us = t.elapsed().as_secs_f64() * 1e6 / 50.0;
    println!("{what:<48} {n:>7} {kept:>10} {peak:>10} {us:>9.1}");
}

fn main() {
    println!("{:<48} {:>7} {:>10} {:>10}", "context part (held)", "allocs", "retained", "peak");
    println!("{:<48} {:>7} {:>10} {:>10} {:>9}", "", "", "bytes", "bytes", "µs build");
    retained("template registry (72 templates from JSON)", context_parts::templates);
    retained("provider registry (RustCrypto)", context_parts::providers);
    retained("policy engine + key repository (empty)", context_parts::repositories);
    retained("whole context (as Context::open, memory store)", context_parts::whole);
    println!();
    println!("{:<48} {:>7} {:>10} {:>10}", "operation", "allocs", "bytes", "peak");
    let msg = vec![0x5a; 1024];
    for t in ["ed25519", "ecdsa-p256-sha256-der", "ml-dsa-65"] {
        let f = SignBench::new(t);
        measure(&format!("sign/{t}/1KiB/L1"), || drop(black_box(f.provider_sign(&msg))));
        measure(&format!("sign/{t}/1KiB/L2"), || drop(black_box(f.orchestrator_sign(&msg))));
        measure(&format!("sign/{t}/1KiB/L2ffi-wire"), || {
            drop(black_box(f.orchestrator_sign_as_ffi(&msg, Encoding::WireV1)))
        });
    }
    for n in [1024, 1024 * 1024] {
        let pt = vec![0x5a; n];
        for (t, aead) in [("aes-256-gcm-128-96", true), ("chacha20-poly1305", true), ("aes-256-cbc-pkcs7-128", false)] {
            let f = CipherBench::new(t, aead);
            let s = f.sealed(&pt);
            measure(&format!("enc/{t}/{n}/L1"), || drop(black_box(f.provider_encrypt(&pt))));
            measure(&format!("enc/{t}/{n}/L2ffi-wire"), || {
                drop(black_box(f.orchestrator_encrypt_as_ffi(&pt, Encoding::WireV1)))
            });
            measure(&format!("dec/{t}/{n}/L1"), || {
                black_box(f.provider_decrypt(&s));
            });
            measure(&format!("dec/{t}/{n}/L2"), || {
                black_box(f.orchestrator_decrypt(&s));
            });
        }
    }
}
