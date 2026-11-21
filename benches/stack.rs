//! Stack high-water marks per layer (docs/performance.md F12): RustCrypto
//! directly (L0) against our provider (L1) and the orchestrator (L2ffi).
//! The C path (L3) is `cargo xtask bench --only stack`.
//!
//! Each job runs on a pthread whose stack we mmap'd and filled with a
//! pattern; the deepest overwritten byte is the depth, minus an empty job.

use agilecrypto::bench_support::{Encoding, SignBench, provider_generate};
use std::hint::black_box;

const SIZE: usize = 8 << 20;

// POSIX, but the libc crate does not bind it on Apple targets.
unsafe extern "C" {
    fn pthread_attr_setstack(
        attr: *mut libc::pthread_attr_t,
        addr: *mut libc::c_void,
        size: libc::size_t,
    ) -> libc::c_int;
}

extern "C" fn tramp(arg: *mut libc::c_void) -> *mut libc::c_void {
    // SAFETY: `depth` passes a live `&mut &mut dyn FnMut()`.
    let f = unsafe { &mut *(arg as *mut &mut dyn FnMut()) };
    f();
    std::ptr::null_mut()
}

fn depth(mut job: impl FnMut()) -> usize {
    // SAFETY: plain libc calls on memory we own; the thread is joined before
    // the mapping is read or unmapped.
    unsafe {
        let base = libc::mmap(
            std::ptr::null_mut(),
            SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        ) as *mut u8;
        assert!(base as isize != -1, "mmap");
        std::ptr::write_bytes(base, 0xA5, SIZE);
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        libc::pthread_attr_init(&mut attr);
        assert_eq!(pthread_attr_setstack(&mut attr, base.cast(), SIZE), 0);
        let mut f: &mut dyn FnMut() = &mut job;
        let mut t: libc::pthread_t = std::mem::zeroed();
        assert_eq!(libc::pthread_create(&mut t, &attr, tramp, (&mut f as *mut &mut dyn FnMut()).cast()), 0);
        libc::pthread_join(t, std::ptr::null_mut());
        libc::pthread_attr_destroy(&mut attr);
        let mem = std::slice::from_raw_parts(base, SIZE);
        let used = SIZE - mem.iter().position(|&b| b != 0xA5).unwrap_or(SIZE);
        libc::munmap(base.cast(), SIZE);
        used
    }
}

macro_rules! ml_dsa_rows {
    ($base:expr, $p:ty, $t:expr) => {{
        use ml_dsa::pkcs8::DecodePrivateKey;
        let f = SignBench::new($t);
        let der = f.private_der().to_vec();
        let sk = ml_dsa::SigningKey::<$p>::from_pkcs8_der(&der).unwrap();
        let m = [0x5au8; 1024];
        row(
            $base,
            &format!("{}/L0 key from seed (keygen core)", $t),
            depth(|| {
                black_box(ml_dsa::SigningKey::<$p>::from_seed(&Default::default()));
            }),
        );
        row(
            $base,
            &format!("{}/L0 parse PKCS#8", $t),
            depth(|| {
                black_box(ml_dsa::SigningKey::<$p>::from_pkcs8_der(&der).unwrap());
            }),
        );
        row(
            $base,
            &format!("{}/L0 sign, key parsed once", $t),
            depth(|| {
                for _ in 0..3 {
                    black_box(sk.expanded_key().sign_randomized(&m, b"", &mut getrandom::SysRng).unwrap());
                }
            }),
        );
        row(
            $base,
            &format!("{}/L1 generate_key", $t),
            depth(|| {
                black_box(provider_generate($t));
            }),
        );
        row(
            $base,
            &format!("{}/L1 sign", $t),
            depth(|| {
                for _ in 0..3 {
                    black_box(f.provider_sign(&m));
                }
            }),
        );
        row(
            $base,
            &format!("{}/L2ffi sign", $t),
            depth(|| {
                for _ in 0..3 {
                    black_box(f.orchestrator_sign_as_ffi(&m, Encoding::WireV1));
                }
            }),
        );
    }};
}

fn row(base: usize, name: &str, d: usize) {
    let b = d - base;
    println!("{name:<44} {b:>10} {:>8.1}", b as f64 / 1024.0);
}

fn main() {
    let base = depth(|| {});
    println!("empty job: {base} bytes (subtracted)");
    println!("{:<44} {:>10} {:>8}", "job", "bytes", "KiB");
    ml_dsa_rows!(base, ml_dsa::MlDsa44, "ml-dsa-44");
    ml_dsa_rows!(base, ml_dsa::MlDsa65, "ml-dsa-65");
    ml_dsa_rows!(base, ml_dsa::MlDsa87, "ml-dsa-87");

    for t in ["ed25519", "ecdsa-p256-sha256-der", "ecdsa-p521-sha512-der"] {
        let f = SignBench::new(t);
        let m = [0x5au8; 1024];
        row(
            base,
            &format!("{t}/L1 generate_key"),
            depth(|| {
                black_box(provider_generate(t));
            }),
        );
        row(
            base,
            &format!("{t}/L1 sign"),
            depth(|| {
                black_box(f.provider_sign(&m));
            }),
        );
        row(
            base,
            &format!("{t}/L2ffi sign"),
            depth(|| {
                black_box(f.orchestrator_sign_as_ffi(&m, Encoding::WireV1));
            }),
        );
    }
    {
        use p521::elliptic_curve::Generate;
        row(
            base,
            "ecdsa-p521/L0 SecretKey::generate",
            depth(|| {
                black_box(p521::SecretKey::generate());
            }),
        );
    }
}
