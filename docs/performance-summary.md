# What `agc_*` costs you: a performance summary for clients

This page is for teams that call the citius C API (`agc_*`, implemented by citius-rust) and care
about speed, memory or real-time behaviour. It compares the API with calling RustCrypto directly,
which is what citius-rust uses underneath. The full study, with methods and raw data, is
`docs/performance.md`; the section and finding numbers below (§, F1–F12) point into it.

Measured 2026-11-21 to 2026-11-23 on `main`. macOS figures are from an Apple M4 Pro; Linux figures
from an arm64 VM (8 vCPUs) on the same machine. The relative results carry over to other machines;
the absolute times are indicative, and Linux tails from a VM more so.

## In short

- **Time:** an `agc_*` call costs what a well-written native RustCrypto client pays, within about
  1 µs for most operations. Small symmetric operations add a fixed 0.3–0.7 µs.
- **Real time:** latency is tight except for ML-DSA signing, whose spread comes from the algorithm
  itself (the same in plain RustCrypto). Budget it by its p99.9, not its median.
- **Threads:** operations scale with the cores. On macOS only, encryption is capped at about
  1.6 M ops/s in total by the operating system's random source.
- **Memory:** one locked memory page per key, about 512 bytes per context after the first, and
  10–20 small heap allocations per call.
- **Stack:** 5–12 KiB for most operations, up to 130 KiB for ML-DSA signing and 650 KiB for ML-DSA
  key creation. Too small a thread never crashes; the work moves to a helper thread.
- **Keep off the hot path:** `agc_ctx_open`, key creation and rotation (milliseconds with the file
  store), and the first signature per key version.

## Time compared with RustCrypto

Median per call, macOS. "RustCrypto" is a native client that parses its key once and keeps it.

| operation | RustCrypto | `agc_*` | difference |
|---|---|---|---|
| sign Ed25519 (1 KiB) | 33 µs | 34 µs | ≈ 0 |
| sign ECDSA P-256 / P-384 (digest) | 69 / 171 µs | 70 / 172 µs | +1 µs |
| sign ECDSA P-521 (digest) | 129 µs | 138 µs | +7 % |
| sign ML-DSA-65 (1 KiB) | 262 µs | 270 µs | +3 %, within noise |
| verify Ed25519, ML-DSA-44/65/87 | 35, 28 / 38 / 55 µs | 35, 28 / 39 / 56 µs | ≤ +1 µs |
| verify ECDSA P-256 / P-384 / P-521 | 235 / 628 / 382 µs | 234 / 636 / 408 µs | 0 to +7 % |
| AES-CTR 32 B encrypt / decrypt | 1.5 / 0.2 µs | 2.1 / 0.5 µs | +0.6 / +0.3 µs |
| AES-CBC, AES-CTR 1 MiB | | | equal or a few % faster |

- A client that keeps keys serialized and parses them per call pays far more than `agc_*`: 2.5–2.8×
  for ECDSA signing and 2.2–3.0× for ML-DSA verification (§2.5). The library keeps each key version's
  parsed form, so you don't have to.
- The C boundary itself costs nothing measurable.
- **Two-call sizing** (ask for the output size, then call again) adds about 0.5 µs per small
  operation. If you know the output size, pass a large enough buffer the first time.
- Decryption leaves no plaintext behind in the library. At 1 MiB, AES-CBC and AES-CTR decryption
  through `agc_*` is as fast as plain RustCrypto and twice as fast as a native client that wipes
  its own buffer with `zeroize`.

The same changes held on Linux: for example Ed25519 signing 23 µs, AES-GCM 32 B encrypt 1.1 µs and
decrypt 0.7 µs (§7.4).

## Latency tails (real-time budgets)

| C path, macOS, µs | p50 | p99 | p99.9 |
|---|---|---|---|
| sign Ed25519 1 KiB | 34 | 41 | 54 |
| sign ECDSA P-256 1 KiB | 70 | 78 | 88 |
| sign ML-DSA-65 1 KiB | 270 | 1424 | 2004 |
| verify ML-DSA-65 1 KiB | 39 | 45 | 51 |
| AES-256-GCM 32 B encrypt / decrypt | 2.3 / 0.8 | 2.8 / 1.0 | 3.6 / 1.1 |

- **ML-DSA signing** has a p99.9 of 6–8× its median. FIPS 204 signing repeats a step a random
  number of times; RustCrypto alone shows the same spread (p99.9 2023 µs), and deterministic
  signing does not remove it (F10). Budget about 2 ms for ML-DSA-65 and -87 and about 1.2 ms for
  ML-DSA-44 on this machine. If you need a tight bound, use Ed25519 or ECDSA.
- ML-DSA verification has no such loop and stays tight.
- The tails come from a desktop machine; a bare-metal Linux host with isolated CPUs is still to be
  measured.

## Threads

Total operations per second, AES-256-GCM 32 B, one key per thread (a shared key is within a few
percent on Linux, ~20 % lower on macOS):

| | 1 thread | 4 | 8 |
|---|---|---|---|
| decrypt, macOS | 1.2 M | 4.7 M | 9.3 M (12 M on 12 threads) |
| decrypt, Linux | 1.3 M | 5.0 M | 9.0 M |
| encrypt, Linux | 0.9 M | 3.4 M | 6.4 M |
| encrypt, macOS | 0.4 M | 1.6 M | 1.3 M |

- Reads take no shared lock, so decryption, verification and signing scale with the cores.
- **macOS encryption** draws its nonce from `getentropy`, which on macOS peaks at about 2 M calls/s
  across the whole process and degrades with more threads. Linux's `getrandom` has no such limit.
  A userspace random generator would remove it and is under security review (F5).
- Signing scales linearly too: Ed25519 0.31 M signatures/s on 8 threads on Linux.

## Memory

- **Per key:** one locked memory page for its secret (16 KiB on macOS, 4 KiB on Linux), plus the
  parsed form of each version as it is used. Locking is best effort by default: on Linux it stops
  at `RLIMIT_MEMLOCK` (often 8 MiB, about 2000 keys). Set `require_locked_memory` if an operation
  must fail rather than run with unlocked secrets (F8).
- **Per context:** the first in a process pages in about 1.6 MiB, mostly shared library code. Each
  further context costs about 512 bytes.
- **Heap allocations:** 11–20 small ones per C call (Ed25519 signing 11, AES-GCM encryption 19),
  a few hundred bytes in all, plus 8 KiB for ML-DSA signing. Not zero: if your real-time code bans
  `malloc` after start-up, keep `agc_*` calls outside that section.
- **Message size:** there is no streaming yet; messages are processed whole, in memory. The library
  writes into your buffer and keeps no extra copy of the plaintext or ciphertext.
- **Binary size:** each C client grows by about 2.2 MiB, whatever it uses, because algorithms are
  chosen at run time and cannot be stripped (F11).

## Stack

| operation | stack needed |
|---|---|
| symmetric ciphers, Ed25519, ECDSA | 5–12 KiB |
| `agc_ctx_open` | 7 KiB |
| ML-DSA-44 / 65 / 87 sign | 73 / 99 / 130 KiB |
| ML-DSA-44 / 65 / 87 verify | 58 / 65 / 83 KiB with the public key cached (macOS); up to 75 / 122 / 192 KiB (Linux, first call not separated) |
| ML-DSA-44 / 65 / 87 key creation, and a version's first signature | 277 / 356 / 650 KiB |

- If the calling thread has too little stack left, the operation runs on a helper thread instead.
  That costs about 30 µs and never crashes the process (F12).
- **Advice:** give threads that sign with ML-DSA at least 320 KiB and keep keys in a context. Then
  only key creation and a version's first signature need the helper thread; every later signature
  runs inline. macOS's default 512 KiB threads are enough for that; musl's default 128 KiB threads
  are not, so there every ML-DSA call takes the helper thread.

## System calls and I/O

- One random-number call per encryption and per hedged signature (`getentropy` about 1.2 µs on
  macOS, `getrandom` about 0.2 µs on Linux). None for decryption, verification or Ed25519.
- On Linux, one `getpid` per call (about 0.1 µs), for fork safety.
- No disk access on sign, verify, encrypt or decrypt. With the file store, creating or rotating a
  key syncs to disk: about 8 ms on macOS (F9).

## Start-up and first calls

Linux, cold process: `agc_ctx_open` about 360 µs, the first key 44 µs, the first signature 116 µs
(it sets up the key's cache), the second 28 µs. Opening a file store costs about 30 µs per stored
key. Do these before your real-time section starts.

## Not covered by these measurements

- Constant-time behaviour is inherited from RustCrypto and was not measured here.
- x86-64 and bare-metal Linux figures are still to come.
