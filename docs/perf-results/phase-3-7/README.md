# Phases 3–7 and the read-mostly stores, before and after (2026-11-21, macOS arm64)

Same machine (8 performance + 4 efficiency cores, 16 KiB pages, `RLIMIT_MEMLOCK` unlimited), same
session, one side after the other.

- `before`: `main` at 9bb1d53 (phases 0–2) + benches (measure/hot-path 5f2c206).
- `after`: improve/key-caches at 5c07f20 + benches (measure/key-caches): phases 3–7, the review
  fixes and the CBC key-schedule fix. `allocs`, `baselines`, `memory` and
  `c-latency-after-phase7.txt` ran on ea6c5b1, before the review fixes. Those changed no hot path;
  the one near one, ML-DSA sealing, affects only the first signature per key. `c-latency-after.txt`
  is the final code.
- `read-mostly`: improve/read-mostly at 9f4ad66 + benches (measure/read-mostly): the key index and
  the policy store as `arc-swap` snapshots (F7).

| file | command |
|---|---|
| `allocs-*` | `cargo bench --features bench --bench allocs` |
| `baselines-*` | `cargo bench --features bench --bench baselines -- 10 100` |
| `c-latency-*` | `cargo xtask bench --only latency` |
| `c-memory-*` | `cargo xtask bench --only memory` |
| `c-threads-*` | `cargo xtask bench --only threads` (`after` and `read-mostly` add decryption, which draws no randomness) |
| `entropy.c`, `entropy-out.txt` | `getentropy` alone across threads (`cc -O2`) |
| `rw.rs`, `rwlock-out.txt` | a shared `std::sync::RwLock` read (and an `Arc` clone) across threads (`rustc -O`) |

## Results (p50 of the C path, µs)

| operation (1 KiB) | before | after | change |
|---|---|---|---|
| sign Ed25519 | 67.3 | 33.6 | −50 % |
| sign ECDSA P-256 / P-384 / P-521 | 201 / 476 / 364 | 70 / 174 / 139 | −62 to −65 % |
| sign ML-DSA-44 / 65 / 87 | 242 / 420 / 536 | 153 / 270 / 300 | −35 to −44 % |
| verify ML-DSA-44 / 65 / 87 | 64 / 104 / 171 | 28 / 39 / 56 | −56 to −67 % |
| verify Ed25519 / ECDSA | | | −9 % / within ±5 % |
| AES-GCM-256 encrypt / decrypt 1 MiB | 545 / 563 | 410 / 407 | −25 / −28 % |
| AES-CTR encrypt / decrypt 1 MiB | 343 / 359 | 258 / 256 | −25 / −29 % |
| AES-CBC decrypt 1 MiB | 414 | 359 | −13 % |
| small messages (32 B–1 KiB) | | | within ±0.1 µs, decrypt up to −17 % |

Verification through the C path is now within ~1 µs of RustCrypto alone (`baselines-after.txt`:
ML-DSA +0.5 µs, Ed25519 −0.2 µs).

## Allocations and memory

- ML-DSA-65 signing: 117 KB allocated per call → 8.4 KB (the expanded key is sealed per key
  version, phase 7).
- `agc_encrypt` at 1 MiB: the library held a 1 MiB ciphertext → 200 bytes in all (written into
  the caller's buffer, phase 5).
- A context after the first: 217,229 allocations, 358 KiB → 7 allocations, 512 B (catalog parsed
  once per process, phase 6).
- Unchanged: RSS per key (one locked 16 KiB page). The first context still pays the one catalog
  parse.

## Threads (total ops/s, AES-256-GCM 32 B)

| | 1 | 4 | 8 | 12 threads |
|---|---|---|---|---|
| encrypt, after (own key) | 0.41 M | 1.61 M | 1.33 M | 1.12 M |
| `getentropy` alone | 0.83 M | 1.86 M | 1.45 M | 1.10 M |
| decrypt, after (own key) | 1.15 M | 4.14 M | 2.65 M | 1.37 M |
| decrypt, read-mostly (own key) | 1.19 M | 4.69 M | 9.28 M | 11.97 M |
| decrypt, read-mostly (shared key) | 1.19 M | 4.64 M | 7.33 M | 9.47 M |

- **Encryption on macOS is capped by the kernel's random source.** Each encryption draws a nonce
  with `getentropy`, which alone peaks at ~2 M calls/s and degrades with more threads. Changing
  that is F5's deferred item (a userspace generator), which needs a security review. Linux with
  vDSO `getrandom` should not have this limit (to measure).
- **Decryption was capped by our shared locks.** A shared `RwLock` read writes its reader count,
  and that cache line alone caps all readers at ~5 M/s on 8 threads (`rwlock-out.txt`). With
  read-mostly snapshots, decryption scales to 9–12 M ops/s.
- Ed25519 signing scales linearly to 8 threads before and after; per thread it doubled.
