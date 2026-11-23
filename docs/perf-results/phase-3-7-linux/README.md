# Phases 0–7 and the read-mostly stores on Linux, before and after (2026-11-23)

Linux arm64 VM: Colima (Apple Virtualization framework) with 8 vCPUs on an M4 Pro, Debian 12,
glibc 2.36, kernel 6.8, `RLIMIT_MEMLOCK` 8 MiB, 4 KiB pages. Both sides were measured in one
session, one after the other. The thread runs alternate between the sides (before, after, before,
after).

- `before`: de34b0b, the code after the defect fixes (F8, F12, B1) and before any improvement, with
  the benches.
- `after`: `main` at ecc88ef (phases 0–7, the read-mostly stores, the DDD changes) with the benches.

Both sides use the same harness: `benches/c/bench.c` with the decryption thread run, and `xtask
bench` clearing `LD_LIBRARY_PATH` (below).

| file | command |
|---|---|
| `glibc-*.txt` | `cargo xtask bench` (all sections) |
| `threads-*-{1,2}.txt` | `cargo xtask bench --only threads` |
| `musl-default-stack.txt` | `benches/c/default_stack.c` in Alpine: create and 200 signatures on a default 128 KiB thread |
| `stack-hop.c` | ML-DSA sign p50 on threads with 16 MiB, 512 KiB and 128 KiB stacks (results for macOS in `../phase-3-7/stack-hop-macos.txt`) |

A VM is not bare metal. The relative changes carry over; absolute times and tails are only
indicative.

## Results (p50 of the C path, µs)

| operation (1 KiB) | before | after | change |
|---|---|---|---|
| sign Ed25519 | 47.2 | 23.1 | −51 % |
| sign ECDSA P-256 / P-384 / P-521 | 127 / 334 / 330 | 44 / 119 / 112 | −64 to −66 % |
| sign ML-DSA-44 / 65 / 87 | 165 / 290 / 366 | 101 / 183 / 199 | −37 to −46 % |
| verify ML-DSA-44 / 65 / 87 | 43 / 68 / 111 | 19 / 27 / 39 | −56 to −65 % |
| verify Ed25519 / ECDSA | | | −4 % / within +6 % |
| AES-GCM-256 encrypt / decrypt 32 B | 2.21 / 2.00 | 1.08 / 0.71 | −51 / −65 % |
| AES-GCM-256 encrypt / decrypt 1 MiB | 411 / 651 | 339 / 338 | −18 / −48 % |
| AES-CTR encrypt / decrypt 1 MiB | 229 / 482 | 200 / 199 | −13 / −59 % |
| AES-CBC decrypt 1 MiB | 515 | 228 | −56 % |
| ChaCha20-Poly1305 decrypt 1 MiB | 1182 | 918 | −22 % |
| two-call protocol (L3b − L3a), small messages | ~1.0 | ~0.5 | |

Unchanged within noise: CBC encryption (inherently serial), ChaCha20 encryption at 1 MiB, ECDSA
and Ed25519 verification. Key creation in the memory store is 7–27 % slower (5.1 against 4.0 µs
for AES), from the per-version caches a new version sets up.

## Threads (total ops/s, 8 vCPUs; 12 threads equal 8)

| | 1 | 4 | 8 threads |
|---|---|---|---|
| AES-GCM 32 B encrypt, before | 0.41 M | 1.21–1.50 M | 2.04–2.15 M |
| AES-GCM 32 B encrypt, after | 0.87 M | 3.37 M | 6.39–6.46 M (7.3×) |
| AES-GCM 32 B decrypt, before | 0.47 M | 1.59–1.63 M | 2.18–2.19 M |
| AES-GCM 32 B decrypt, after | 1.30 M | 4.98–5.02 M | 8.96–9.02 M (6.9×) |
| Ed25519 sign, before / after | 0.02 / 0.04 M | 0.08 / 0.17 M | 0.15–0.16 / 0.31–0.32 M (7.2×) |

One key per thread; a shared key gives the same within ±3 %. **On Linux, encryption scales like
decryption**: glibc's `getrandom` costs ~0.2 µs and does not serialize threads, so macOS's
`getentropy` limit (F5) does not exist here.

## Memory, first calls, syscalls

- Every context after the first: +220 KiB resident before, 0 after (the catalog is parsed once per
  process). The first context is unchanged (~1.6 MiB, mostly shared code pages).
- Per key: one locked 4 KiB page, before and after; `RLIMIT_MEMLOCK` (8 MiB) is reached at 2048
  keys either way.
- First calls in a cold process: `agc_ctx_open` 262 → 358 µs, first key 36 → 44 µs, first sign
  94 → 116 µs (each sets up a cache once); the second sign 49 → 28 µs.
- Syscalls: `getpid` 0.12 µs and `getrandom` 0.21 µs, unchanged (F5).

## Stack (KiB)

| operation | before | after |
|---|---|---|
| ML-DSA-44 / 65 / 87 sign | 227 / 310 / 519 | 71 / 98 / 130 |
| ML-DSA-44 / 65 / 87 verify | 86 / 131 / 203 | 75 / 122 / 192 |
| ML-DSA-44 / 65 / 87 create key | 276 / 355 / 649 | 277 / 356 / 650 |
| `agc_ctx_open` | 16 | 7 |
| ciphers, Ed25519/ECDSA sign | 9–12 | 5–12 |

Signing no longer expands the key, so it needs a quarter of the stack. On musl's 128 KiB default
threads every operation succeeded before and after (the stack guard, F12).

## A harness defect found on the way (fixed)

The first run showed the "after" side 5–500× slower. `cargo xtask bench` runs under `cargo run`,
which puts `target/debug` on `LD_LIBRARY_PATH`. On Linux that outranks the harness's `RUNPATH`, and
the after side's target directory held a debug `libagilecrypto.so.1` from earlier test runs, so
the debug library was measured. `xtask bench` now removes `LD_LIBRARY_PATH` before starting the
harness; the raw output of that run is not kept. macOS was not affected: there cargo sets only
`DYLD_FALLBACK_LIBRARY_PATH`, which ranks below the rpath.
