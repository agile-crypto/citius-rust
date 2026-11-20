# Performance of citius-rust compared with RustCrypto

Status: **measurements done (2026-11-19/20) on macOS (Rust layers and the C path) and Linux in an
arm64 VM; defects fixed on `main` (2026-11-20)**. This file collects every finding as the basis
for a discussion about improvements. The performance findings are unchanged in the library and
open for that discussion. The defects they uncovered are fixed: F8 (keys silently unlocked), F12
(stack overflows) and B1 (the build needed rustfmt), plus the related defects in §4.1.

Goal: tell clients who care about performance, or who have real-time constraints, how much using
`agc_*` (citius-c-api) through citius-rust costs them, compared with calling RustCrypto directly.
The costs covered are time, memory, allocations and predictability.

## 1. Setup

- Machine: Apple M4 Pro, 12 cores, macOS (Darwin 25.5), rustc 1.98.1, release profile.
- Benches: `benches/sign.rs`, `benches/cipher.rs` (criterion, medians), `benches/allocs.rs`
  (a counting global allocator), `benches/interleave.rs` (layers interleaved, for small
  differences, F4), `benches/tail.rs` (per-call ML-DSA distributions,
  `cargo bench --features bench --bench tail -- SECONDS`), `benches/stack.rs` (stack depth per
  layer). Binary size: `benches/size/measure.sh`. The fixtures are in `src/bench_support.rs`, behind the `bench`
  feature, which is off by default.
- Run:
  ```sh
  cargo bench --features bench --bench sign   -- --warm-up-time 1 --measurement-time 2
  cargo bench --features bench --bench cipher -- --warm-up-time 1 --measurement-time 2
  cargo bench --features bench --bench allocs
  ```
- Profiles: samply (`~/.cargo/bin/samply`), sampling at 4 kHz. The benches are built with
  `CARGO_PROFILE_BENCH_DEBUG=true` and run under criterion's `--profile-time 6`. The profiles are
  aggregated with `benches/fold_samply.py`:
  ```sh
  CARGO_PROFILE_BENCH_DEBUG=true cargo bench --features bench --no-run
  samply record -s --unstable-presymbolicate -r 4000 -o p.json.gz \
      target/release/deps/sign-<hash> --bench --profile-time 6 'sign/ed25519/L2ffi-wire/1024$'
  python3 benches/fold_samply.py p.json.gz 60
  ```
  Caveat: heavy inlining blurs the attribution of frames. Percentages that disagree with the
  timing deltas (for example getrandom appearing around ML-DSA signing) are symbolication
  artefacts, not facts.

### Layers

A layer's overhead is the difference to the layer below.

| Layer | What runs | Answers |
|---|---|---|
| L0 | RustCrypto directly, key object parsed **once** | the ideal a native client gets |
| L0p | RustCrypto directly, key parsed from DER **per call** | a fair baseline for a client that stores keys serialized |
| L1 | our provider adapter (`RustCrypto.sign/encrypt` on a `GeneratedKey`) | adapter cost |
| L2 | `CryptoOrchestrator::sign/encrypt/decrypt` | orchestration: resolve, policy, metadata |
| L2ffi | L2 the way `agc_sign`/`agc_encrypt` drive it: `*_sizes` + operation + `metadata::encode` (`ffi/exports/sign.rs` `sign_into`) | everything except the C boundary |
| L3a | `agc_*` called from C, one call with buffers already big enough | §2.3 |
| L3b | the same with the two-call protocol (size query, then the call) | §2.3 |

The C harness is `benches/c/bench.c`. Run it with
`cargo xtask bench [--quick] [--csv FILE] [--only memory|first|latency|threads|file|syscalls]` (plus `--only contention --threads N [--shared] --seconds S` for profiling); the task
builds the release library first. It times every iteration on its own and prints
min/p50/p90/p99/p99.9/max/mean. On macOS the clock is `CLOCK_UPTIME_RAW`, whose ticks are
~42 ns; `CLOCK_MONOTONIC` only resolves to 1 µs there. Raw output of the first full run:
`docs/perf-results/2026-11-19-macos-m4pro-c.{txt,csv}`.

## 2. Results: time

### 2.1 Signing (message, 1 KiB; 32 B and 16 KiB behave the same)

| Algorithm | L0 | L0p | L1 | L2 | L2ffi | L2ffi / L0 | Share of key parsing in L2ffi |
|---|---|---|---|---|---|---|---|
| Ed25519 | 32.6 µs | 67.5 µs | 66.7 µs | 68.4 µs | 70.1 µs | **2.15×** | 50 % |
| ECDSA P-256 | 64.0 µs | 173.6 µs | 175.3 µs | 188.6 µs* | 194.8 µs | **3.05×** (2.8× interleaved, F4) | 56 % |
| ECDSA P-384 | 171.1 µs | 482.8 µs | 487.5 µs | 489.2 µs | 489.8 µs | **2.86×** | 64 % |
| ECDSA P-521 | 129.2 µs | 343.4 µs | 363.4 µs | 364.6 µs | 366.3 µs | **2.84×** | 58 % |
| ML-DSA-44 | 205.4 µs | 294.2 µs | 299.2 µs | 303.9 µs | 297.0 µs | 1.45× | 30 % |
| ML-DSA-65 | 331.8 µs | 483.7 µs | 486.7 µs | 484.7 µs | 491.9 µs | 1.48× | 31 % |
| ML-DSA-87 | 372.4 µs | 614.1 µs | 605.3 µs | 614.5 µs | 612.4 µs | 1.64× | 39 % |

WireV1 and Protobuf metadata cost the same within noise (≤ 2 µs).

\* These are block measurements: each variant ran in its own block. For ECDSA they carry ±10–15 %
of order and code-layout effects (F4). Interleaved, P-256 L2 is 192.5 µs, +2 µs over L1, and the
ECDSA penalties are 2.7–3.0×.

### 2.2 Encryption and decryption

AES-256-GCM (the other AEADs behave the same; CBC and CTR have no L0 yet):

| Size | enc L0 | enc L1 | enc L2 | enc L2ffi | dec L0 | dec L1 | dec L2 |
|---|---|---|---|---|---|---|---|
| 32 B | 1.32 µs | 1.65 µs | 3.18 µs | 5.04 µs | 0.10 µs | 0.40 µs | 2.05 µs |
| 1 KiB | 1.84 µs | 2.19 µs | 3.75 µs | 5.65 µs | 0.60 µs | 1.31 µs | 3.05 µs |
| 16 KiB | 9.38 µs | 9.77 µs | 11.33 µs | 13.29 µs | 8.11 µs | 14.86 µs | 16.49 µs |
| 1 MiB | 521 µs | 530 µs | 529 µs | 531 µs | 518 µs | **930 µs** | 930 µs |

- Fixed cost of encryption through `agc_encrypt` (L2ffi − L1): **3.3–3.6 µs per call** for every
  cipher (GCM, ChaCha20-Poly1305, CBC, CTR). About 1.5 µs is one resolve plus orchestration
  (L2 − L1). The other ~1.9 µs is the second resolve in `encrypt_sizes` plus the metadata encoding
  (L2ffi − L2).
- Fixed cost of decryption (L2 − L1): 1.6–1.7 µs.
- Decryption costs an extra **~0.4 ms per MiB** at L1 for every cipher:
  - GCM-256: 930 µs against 518 µs
  - ChaCha20-Poly1305: 1.90 ms against 1.50 ms
  - CTR: 730 µs to decrypt against 332 µs to encrypt

  See finding F2.
- Encryption at L0 includes ~1.2 µs for a fresh nonce from `getentropy` (compare enc L0 with
  dec L0 at 32 B). We pay the same, so it is not overhead against RustCrypto. It is still a
  syscall on every operation (see §5).

### 2.3 The C path (L3), one thread, in-memory store, WIRE_V1 metadata

Selected rows, in µs (all rows are in `docs/perf-results/`):

| Operation | L0 (Rust, median) | L3a p50 | L3a p99 | L3a p99.9 | L3b p50 | L3a / L0 |
|---|---|---|---|---|---|---|
| sign Ed25519 1 KiB | 32.6 | 69.6 | 79.7 | 96.6 | 71.0 | 2.1× |
| sign ECDSA P-256 1 KiB | 64.0 | 193.7 | 210.0 | 231.9 | 195.2 | 3.0× |
| sign ML-DSA-65 1 KiB | 331.8 | 421.6 | **1407** | **2325** | 423.7 | see F10 |
| verify Ed25519 1 KiB | – | 39.6 | 45.9 | 56.3 | – | – |
| verify ML-DSA-65 1 KiB | – | 104.3 | 110.2 | 125.1 | – | – |
| enc AES-256-GCM 32 B | 1.32 | 4.50 | 4.83 | 6.42 | 6.08 | **3.4×** (L3b 4.6×) |
| dec AES-256-GCM 32 B | 0.10 | 3.12 | 3.29 | 3.96 | 4.75 | 31× (+3 µs) |
| enc AES-256-GCM 1 MiB | 521 | 544 | 564 | 644 | 545 | 1.04× |
| dec AES-256-GCM 1 MiB | 518 | 944 | 964 | 1076 | 946 | **1.8×** (F2) |
| enc ChaCha20-Poly1305 32 B | 1.82 | 4.62 | 4.92 | 7.12 | 6.12 | 2.5× |
| dec ChaCha20-Poly1305 1 MiB | 1500 | 1916 | 1967 | 2354 | 1918 | 1.3× (F2) |

- L3a agrees with L2ffi (§2.1/§2.2) within ~0.5 µs for sign and encrypt. **The C boundary itself
  costs almost nothing.**
- Decrypt from C costs ~1.1 µs more than L2. That is decoding the caller's metadata, sizing the
  plaintext and copying it out.
- The two-call protocol (L3b) adds **~1.5 µs** to every call (encrypt +1.6, decrypt +1.6,
  sign +1.4). The size query does a full resolve (F3). Callers who keep their buffers big enough
  avoid it.
- Max values of 20–70 µs on µs-scale operations are scheduler and timer interrupts on macOS, not
  library behaviour. For worst-case numbers, use Linux with isolated CPUs (§6).
- P-521 measured L3a 424 µs against L3b 384 µs. That is a measurement artefact; interleaved,
  L3a ≈ L3b ≈ 367 µs (F4).

### 2.4 First calls, key creation, file key store

| Measurement | Value |
|---|---|
| `agc_ctx_open` + 12 policies, cold process | 544 µs |
| first `agc_create_key` (Ed25519) | 87 µs |
| first size query + sign, compared with steady state | 97 µs vs 70 µs |
| `agc_create_key`, in memory, p50 / p99: AES-256-GCM | 11–15 / 20–27 µs |
| … Ed25519 | 46 / 52–60 µs |
| … ML-DSA-65 | 185 / 195–210 µs |
| `agc_create_key`, file store, p50 / p99 | **8.0 / 10–12 ms** (flat from 1 to 1000 keys) |
| `agc_ctx_open`, file store with 100 / 1000 keys | 3.7 / 29.5 ms (~30 µs per key) |

### 2.5 Baselines for CBC/CTR, digest signing and verification (interleaved)

Measured 2026-11-20 with `cargo bench --features bench --bench baselines -- 10 100`. All variants
run interleaved (F4), and the full output is in
`docs/perf-results/2026-11-20-macos-m4pro-baselines.txt`. Medians in µs.

**CBC and CTR** (AES-256):
- L0 includes a fresh IV from `getentropy`, as the adapter does.
- L0z decrypts into a `Zeroizing` buffer, like the adapter.

| Operation | L0 | L0z | L1 | L2 / L2ffi |
|---|---|---|---|---|
| CBC enc 32 B | 1.6 | – | 1.6 | 5.3 (ffi) |
| CBC enc 1 MiB | 1769 | – | 1771 | 1774 (ffi) |
| CBC dec 32 B | 0.2 | 0.2 | 0.2 | 2.1 |
| CBC dec 16 KiB | 6.0 | 12.3 | 12.4 | 14.2 |
| CBC dec 1 MiB | **381** | 783 | 785 | 788 |
| CTR enc 32 B | 1.5 | – | 1.5 | 5.0 (ffi) |
| CTR enc 1 MiB | 340 | – | 325 | 328 (ffi) |
| CTR dec 1 MiB | **339** | 741 | 726 | 731 |

- The adapter adds nothing to encryption (L1 = L0). The C path adds the fixed ~3.5–3.9 µs of F3.
- For decryption, **L1 = L0z exactly**. Our whole gap to RustCrypto is the wipe (F2), now
  confirmed for CBC and CTR as well: ~0.4 ms/MiB. That doubles CBC and CTR decryption of large
  data.

**Digest signing** (`agc_digest_sign`, PROTOBUF metadata):

| Template | L0 | L0p | L1 | L2ffi | L2ffi / L0 |
|---|---|---|---|---|---|
| ecdsa-p256-prehashed-der (SHA-256 digest) | 68.7 | 190.0 | 190.0 | 194.4 | 2.83× |
| ecdsa-p384-prehashed-der (SHA-384) | 171.0 | 484.4 | 478.5 | 482.7 | 2.82× |
| ecdsa-p521-prehashed-der (SHA-512) | 128.1 | 337.8 | 360.9 | 367.5 | 2.87× |
| ed25519ph (SHA-512) | – | – | 65.1 | 70.8 | (≈ 2.1×, as Ed25519) |

The same picture as message signing: the key is parsed per call (F1). The orchestrator adds
4–7 µs, a little more than for message signing because the metadata is PROTOBUF.

**Verification** (message, 1 KiB):
- L0 parses the public key once.
- L0p parses it per call, which is what our adapter does.

| Template | L0 | L0p | L1 | L2ffi | L2ffi / L0 |
|---|---|---|---|---|---|
| Ed25519 | 35.4 | 38.9 | 39.0 | 40.3 | 1.14× |
| ECDSA P-256 | 231.9 | 232.4 | 232.1 | 234.2 | 1.01× |
| ECDSA P-384 | 632.3 | 633.7 | 627.2 | 628.8 | 0.99× |
| ECDSA P-521 | 379.1 | 388.9 | 412.7 | 406.0 | 1.07× (layout, F4) |
| ML-DSA-44 | **27.5** | 62.7 | 62.5 | 65.2 | **2.4×** |
| ML-DSA-65 | **38.3** | 103.5 | 102.8 | 104.9 | **2.7×** |
| ML-DSA-87 | **55.4** | 170.5 | 170.0 | 171.9 | **3.1×** |

- ECDSA and Ed25519 verification cost about what RustCrypto costs: parsing a public key is cheap
  next to the verification.
- **ML-DSA verification is 2.4–3.1× slower**, the verification side of F1.
  `ml_dsa::VerifyingKey::decode` (`rustcrypto_signer.rs`, `ml_dsa_verify`) does more work than
  the verification itself: 35–115 µs, presumably expanding the public key's matrix. And we run
  it on every call.

### 2.6 Linux (arm64 VM): the Linux-specific questions

Measured 2026-11-20 in a Colima VM on the same Mac:
- Apple virtualization framework, 8 vCPUs, Linux 6.8;
- Debian 12 with glibc 2.36 (4 KiB pages, `RLIMIT_MEMLOCK` 8 MiB), plus Alpine (musl);
- rustc 1.100, against 1.98 on macOS.

Output is in `docs/perf-results/2026-11-20-linux-vm-arm64-{glibc.txt,musl-stack.txt}`. A VM
answers the functional questions (syscalls, limits, stacks). Its timings are indicative only, and
the published figures still need a bare-metal (x86-64) host (§6).

How to reproduce:
- `brew install colima docker && colima start --cpu 8 --memory 8 --vm-type vz`
- an image `rust:1-bookworm` + `clang libclang-dev strace` + `rustup component add rustfmt` (see B1)
- the repository mounted, `target/` on a Docker volume
- `cargo xtask bench --only …` and `strace -f -c -e trace=getpid,getrandom,…`

| Question | Linux result |
|---|---|
| `getpid` per `agc_*` call (F5) | **a real syscall: 192 ns** in the VM. `strace` counts exactly 1 per call, 2 for the two-call protocol. |
| `getrandom` per encrypt or hedged signature (F5) | 1 per operation, **333 ns** (macOS `getentropy`: 1.2 µs) |
| Other syscalls in steady state | none (no futex; mmap/brk only during setup) |
| Locked memory per key (F8) | `VmLck` grows one 4 KiB page per key and **stops at exactly 8192 KiB, the `RLIMIT_MEMLOCK`**. That happens after ~2000 keys; later keys are created normally but **not locked, and nothing tells the caller**. |
| Resident memory per key (F8) | 4.9 KiB (AES, Ed25519), 5.4 KiB (ML-DSA-65): a 4 KiB page plus ~1 KiB |
| Memory per context (F8) | resident +1.8 MiB on the first open, as on macOS |
| Stack per operation (F12) | the same as macOS within 3 %: ML-DSA-87 sign 523 KiB, keygen 649 KiB; first P-521 key 130 KiB; symmetric operations 9–11 KiB |
| glibc default thread stack (8 MiB) | everything fits |
| **musl default thread stack (128 KiB)** | **every ML-DSA operation segfaults** on a default thread (create and sign, -44/-65/-87), and so does the first P-521 key creation. Ed25519 and P-256, and P-521 signing once the curve's table exists, are fine. |
| AES-256-GCM 32 B encrypt, p50 L3a / L3b | 3.50 / 4.96 µs (macOS 4.50 / 6.08); the cheaper `getrandom` more than offsets the `getpid` syscall |
| Ed25519 sign 1 KiB, p50 | 77.6 µs |
| Threads, AES-256-GCM 32 B, 8T (F7) | 4.45× (shared key), 5.09× (own key); Ed25519 7.26×. The same saturation as on macOS. |

## 3. Results: heap allocations (benches/allocs.rs)

The counts are per call and deterministic. "Peak" is the largest number of live bytes above the
level at the start of the call.

| Operation (1 KiB) | L1 allocs / bytes | L2 allocs / bytes | L2ffi allocs / bytes / peak |
|---|---|---|---|
| sign Ed25519 | 2 / 67 | 49 / 1,925 | 101 / 3,709 / 1,133 |
| sign ECDSA P-256 | 3 / 106 | 50 / 2,123 | 102 / 3,981 / 1,161 |
| sign ML-DSA-65 | 7 / **117,200** | 55 / 121,270 | 108 / 123,387 / 120,146 |
| enc AES-256-GCM | 4 / 1,057 | – | 114 / 4,904 / 1,777 |
| dec AES-256-GCM | 2 / 1,042 | 53 / 2,910 | – |
| enc ChaCha20-Poly1305 | 4 / 1,057 | – | 110 / 4,806 / 1,729 |
| enc AES-256-CBC | 3 / 1,059 | – | 114 / 5,000 / 1,821 |

At 1 MiB the counts stay the same and the bytes grow with the message. The peak is about one copy
of the message plus ~1 KB at every layer. The C path (§6) adds the copy into the caller's
buffer on top of that.

## 4. Findings, ranked by impact

Each finding has the evidence for it, its status, and a candidate fix with its expected gain.
The performance fixes are for later discussion and have not been implemented. The defects are
fixed on `main`.

| # | Finding | Status (2026-11-20) |
|---|---|---|
| F1 | Key parsed and expanded on every operation | open, for discussion: biggest gain (signing 1.5–3×, ML-DSA verify 2.4–3.1×, ML-DSA stack) |
| F2 | Wiping the decrypted plaintext, ~0.4 ms/MiB | open, for discussion (with F6) |
| F3 | Two lookups and copies of key/policy/template per call | open, for discussion |
| F4 | ECDSA layer gaps | resolved: measurement artefacts |
| F5 | Syscalls: `getentropy`; `getpid` on Linux | open, for discussion |
| F6 | Data copies | partly fixed: the copies left unwiped by outgrown buffers (§4.1); the rest open |
| F7 | Small operations scale to ~5× across threads | open, for discussion |
| F8 | Memory per key and context; **keys silently unlocked past `RLIMIT_MEMLOCK`** | **locking fixed** (`require_locked_memory`); memory per key/context open |
| F9 | File store create ~8 ms (2× F_FULLFSYNC) | open (by design for durability) |
| F10 | ML-DSA latency tail | inherent to FIPS 204 |
| F11 | Binary size ~2.2 MiB per client | open, for discussion |
| F12 | **Stack overflows crash the process** (ML-DSA, first P-521 use) | **fixed** (stack guard); depth itself open (F1) |
| B1 | **The build needed rustfmt** | **fixed** |

### F1. The private key is decoded and expanded on every operation (biggest cost for signatures)
- Code:
  - `Resolved::material` → `GeneratedKey::from_bytes` copies the secret (`domain/provider/material.rs:81`).
  - Then on every call the provider parses the DER and rebuilds the key object:
    - `ed25519_dalek::SigningKey::from_pkcs8_der` (`adapters/providers/rustcrypto_signer.rs:272`)
    - `SecretKey::from_sec1_der` + `SigningKey::from` (the `ecdsa_sign!` macro)
    - `ml_dsa::SigningKey::from_pkcs8_der` (`rustcrypto_signer.rs:296`)
- Profiles:
  - Ed25519: `from_pkcs8_der` takes 48 % of `agc_sign`. That is the derivation of the public key
    (`mul_base`).
  - P-256: `from_secret_scalar` / `mul_by_generator` take ~60 %, and `validate_public_key` takes
    a further share of the parse.
  - ML-DSA-65: `from_seed` takes 30 %, because ml-dsa 0.1.1 re-expands the whole signing key from
    the seed on every parse. It also allocates the 117 KB.
- Status: **confirmed**. It accounts for nearly the whole penalty of 1.5–3× for signing
  (L0p ≈ L1 ≈ L2ffi), for digest signing too (§2.5).
- **The same holds for ML-DSA verification** (§2.5, 2026-11-20). The raw public key is decoded
  into `ml_dsa::VerifyingKey` on every call, and that takes longer than the verification. As a
  result, verification is 2.4× (-44), 2.7× (-65) and 3.1× (-87) slower than with a decoded key.
  ECDSA and Ed25519 public keys are cheap to parse (≤ 1.14×).
- Candidate fix: cache the parsed key object per key version, inside the provider or the key
  material. Expected gain: signing drops to about L0 + a few µs, i.e. 2–3× faster for ECDSA and
  Ed25519 and ~1.5× for ML-DSA, and the 117 KB per ML-DSA signature disappears.
  Caching the decoded verifying key per version makes ML-DSA verification ~2.4–3.1× faster. That
  cache has no secrecy trade-off, because the key is public.
  Trade-off for the signing side: a long-lived copy of the parsed secret in ordinary heap memory. It is outside the
  `agc_secure_alloc` pages, unless the cache lives in locked memory too, which is hard because
  RustCrypto owns those types. See also [copying discussion](#f6-data-copies).

### F2. Wiping the decrypted plaintext costs ~0.4 ms/MiB (biggest cost for decrypting large data)
- Code: `aead_open`, `cbc_decrypt` and the CTR path return the plaintext in a
  `Zeroizing<Vec<u8>>` (`adapters/providers/rustcrypto_cipher.rs:102, 233, 278`). Dropping it
  wipes the buffer with zeroize's volatile writes, one byte at a time.
- Profile: in `dec AES-256-GCM 1 MiB L1`, 47 % of the samples are on the line where the result is
  dropped (`bench_support.rs:195`, the `Zeroizing` drop). That matches the measured
  +410 µs/MiB (≈ 2.6 GB/s for the wipe).
- Status: **confirmed**. Decrypt is ~1.8× slower than RustCrypto for large messages (GCM, ChaCha),
  and CTR/CBC decrypt is slower than their encrypt.
- Candidate fixes, best first:
  1. Decrypt in place into the caller's `agc_buf`. There is then no internal copy and nothing of
     ours to wipe; the caller owns the plaintext. This also removes one plaintext copy (F6).
  2. Keep the internal buffer but wipe it with a wide wipe (`memset_s`/`explicit_bzero` or a
     word-wise volatile loop): about 20–50 µs/MiB instead of 400.

  Expected gain: decrypt ≈ L0 for large messages.
- Note for clients: a native RustCrypto user who also wipes plaintext with `zeroize` pays the
  same. L0 does not wipe.

### F3. `agc_*` resolves the key twice per call and copies the key, policy and template each time
- Code:
  - `sign_into`/`encrypt_into` call `*_sizes` and then the operation. Each runs `resolve`
    (`app/crypto_orchestrator.rs:113`), which clones:
    - the `Key` with all its versions (`get_by_name` → `.cloned()`, `memory_keys.rs:63`, `file_keys.rs:249`)
    - the `Version`
    - the `Policy` (`memory_policies.rs:50`, via `Enforcer::policy`)
    - the `Template` (`crypto_orchestrator.rs:138`)
    - `user_context`
  - The metadata is built and encoded twice.
- Profile (enc AES-256-GCM 32 B, L2ffi, 5.0 µs):

  | Part | Share | Time |
  |---|---|---|
  | malloc/free (inclusive) | 44 % | ≈ 2.2 µs |
  | `resolve` | 41 % | |
  | `encrypt_sizes` | 35 % | |
  | `clone` | 27 % | |
  | `validate_operation` (policy lookup and clone) | 18 % | |
  | `RwLock` reads | ~14 % (attribution uncertain) | |
  | `getentropy` | 23 % | (also in L0) |
  | metadata encoding | 7 % | |
  | the AES-GCM itself | 6 % | ≈ 0.3 µs |

- Allocations: ~50 per orchestrator call, **~100–114 per `agc_*` call**, against 2–7 for
  RustCrypto.
- Status: **confirmed**. The cost is 3.3–3.6 µs per encrypt and ~2–5 µs per sign: negligible for
  signatures and large messages, but **3.8×** for a 32-byte AES-GCM message (1.3 µs → 5.0 µs).
- Candidate fixes:
  - Resolve once per `agc_*` call: compute the sizes from the same `Resolved`.
  - Make repositories return `Arc<Key>` / `Arc<Policy>` / `&Template` instead of clones.
  - Precompute the length of the metadata encoding without building it.

  Expected gain: ~2–2.5 µs per call, and allocations from ~100 down to ~10.

### F4. ECDSA layer gaps were measurement artefacts: resolved; block measurements are ±10–15 % here
- Two unexplained numbers:
  - P-256 L2 − L1 was 13–18 µs in the criterion runs, against ≤ 2 µs for the other curves;
  - P-521 measured L3a 424 µs against L3b 384 µs in the C run (L3b does strictly more work).
- Re-measured (2026-11-20) with the variants **interleaved**: each runs a 100 ms slice in turn,
  for 10–20 rounds, starting at a rotating position. Drift then hits every variant alike, and the
  spread of the per-round medians shows how stable a single block is.
  - Rust layers: `cargo bench --features bench --bench interleave -- ROUNDS MS`.
  - The C path: `cargo xtask bench --only interleave`.
  - Output in `docs/perf-results/2026-11-20-macos-m4pro-ecdsa-interleaved.txt`.

  | Median µs, interleaved | L0 | L0p | L1 | L2 | L2ffi | L3a | L3b |
  |---|---|---|---|---|---|---|---|
  | P-256 | 69.2 | 190.5 | 190.5 | 192.5 | 194.4 | 193.8–194.6 | 195.5–196.3 |
  | P-384 | 172.3 | 485.9 | 487.1 | 489.2 | 491.0 | – | – |
  | P-521, default build | 136.8 | 362.8 | **423.7** | 366.5 | 367.5 | 366.8–369.0 | 367.4–369.8 |
  | P-521, code aligned to 64 bytes | 129.1 | 339.1 | 367.4 | 365.6 | 365.8 | – | – |

- **P-256:** interleaved, L2 − L1 is +2 µs, as for the other curves; **the 13 µs was an order
  effect.**
  - P-256 switches between ~171 µs and ~191 µs from round to round, and that also happens in plain
    RustCrypto (L0p). It does not depend on the key (4 keys) or on where the input key sits
    (offsets 1/8/64).
  - It is not the CPU clock: an integer loop interleaved with it is flat (458.7 µs in every
    round).
  - It lasts for a whole 100 ms round, so it is probably where the temporary allocations of that
    round land. Not pursued further: it is inside RustCrypto or the CPU and affects every layer
    alike.
- **P-521:** the differences between layers follow the **code layout**, not our layers.
  - The same RustCrypto routine runs as several machine-code copies: statically dispatched and
    inlined into the bench helper (L1), or through the `dyn Signer` vtable (L2). Those copies take
    339, 367 or 424 µs.
  - Adding unrelated code to the bench binary moved L1 from 424 to 384 µs.
  - With every function and block aligned to 64 bytes
    (`-C llvm-args=-align-all-functions=6 -C llvm-args=-align-all-nofallthru-blocks=6`),
    L1 = L2 = L2ffi ≈ 366 µs.
- **C, L3a vs L3b:** interleaved, in three separate processes, L3b − L3a = **+0.6 to +1.7 µs**,
  as expected from the size query (§2.3). The 424 µs was a slow state that lasted for that whole
  block.
- Consequences for this study:
  - The ECDSA penalties are 2.7–3.0× (P-256 2.8×, P-384 2.85×, P-521 2.7–2.8×), not "3.05×" as
    the block runs of §2.1 suggested.
  - Every conclusion that rests on differences of a few µs on top of ECDSA (≈ 200–500 µs) needs
    interleaved measurement. The overhead figures for symmetric operations (F3) are much larger
    than this noise relative to their cost, and they agree between criterion, the C harness and
    the profiles.
  - For clients: the same build on the same machine can run P-256/P-521 signing 10–15 % slower or
    faster depending on layout and state. Budget for that; it is in RustCrypto as much as in our
    layers.

### F5. Syscalls per call: exactly one `getentropy` per randomized operation, nothing else
- Measured (2026-11-19, `bench --only syscalls`): macOS `task_info(TASK_EVENTS_INFO)` counts
  this task's Unix and Mach syscalls, page faults and context switches, and needs no root.
  Positive control: 1000 `getentropy` calls count as 1000. Results, as means over 2000 calls
  after warm-up:

  | Operation (from C) | Unix syscalls | Mach syscalls | Page faults | Context switches |
  |---|---|---|---|---|
  | sign Ed25519 (deterministic), L3a and L3b | 0 | 0 | 0.001 | 0.001 |
  | sign ECDSA P-256 / ML-DSA-65 (hedged) | **1** | 0 | 0 | ≤ 0.006 |
  | encrypt AES-GCM / ChaCha20-Poly1305 / CBC / CTR (fresh nonce or IV), 32 B and 1 MiB | **1** | 0 | ≤ 0.002 | 0 |
  | verify (all), decrypt (all) | 0 | 0 | ≤ 0.001 | ≤ 0.001 |

- The one syscall is `getentropy`: 1.2 µs on macOS whatever the size (12 or 32 bytes), 25 % of
  a 32-byte AES-GCM encrypt, and ~2 µs under 8 threads (F7). It is in L0 too. A userspace CSPRNG
  seeded from the OS once per context would remove it. That is a design decision: fork safety,
  reseeding, and what a FIPS boundary wants.
- **Refuted on macOS: `getpid` per call.** `std::process::id()` runs on every `agc_*` call
  (`ffi/exports/core.rs:65`, fork detection). It costs 2 ns and makes no syscall, because macOS
  libc caches the pid. **Linux is different (confirmed 2026-11-20, §2.6):** glibc ≥ 2.25 no
  longer caches it, so it is a real syscall, 192 ns in an arm64 VM (typically 50–100 ns on bare
  metal, more with speculative-execution mitigations). `strace` counts one per `agc_*` call. On
  Linux it is therefore the second syscall of every operation, and the only one for verify and
  decrypt. A cheaper alternative independent of the
  platform: a flag set by a `pthread_atfork` child handler, or a pid cached at open and checked
  against one updated in the child handler.
- Steady state has no page faults even at 1 MiB, because the allocator reuses its pages. After
  warm-up, no operation goes to the kernel except for randomness. That is a good property for
  real-time clients, and worth stating.

### F6. Data copies
The parked "copying" topic. Copies per operation, as far as traced so far:
- Key material: repository → `GeneratedKey::from_bytes` (`Zeroizing` copy) → the parsed
  RustCrypto key object (F1).
- Decrypt: the plaintext goes into an internal `Zeroizing<Vec>`, then is copied into the caller's
  buffer (F2).
- Encrypt and sign: the ciphertext or signature goes into a `Vec`, then is copied into the
  caller's buffer. Metadata goes into a `Vec`, then is copied.
- The sign context is copied into a `Vec` (`SignContext::Domain(... .to_vec())`, `ffi/exports/sign.rs`).

Memory overhead for large messages is therefore about one extra message-sized buffer.

Fixed (2026-11-20, §4.1): two buffers that hold key material on its way, the stored record and
`GeneratedKey::to_bytes`, used to outgrow their capacity and hand earlier buffers, private keys
included, back to the allocator unwiped. The copies listed above are open for the copying
discussion.

### F7. Small operations stop scaling at ~5× across threads, even with one key per thread
- Measured: one context, 1..12 threads (M4 Pro: 8 performance and 4 efficiency cores).

  | Workload | 4T | 8T | 12T | p50 latency, 1T → 8T |
  |---|---|---|---|---|
  | Ed25519 sign 1 KiB, shared key | 3.98× | 7.50× | 8.78× | flat |
  | Ed25519 sign 1 KiB, own key | 3.97× | 7.84× | 9.09× | flat |
  | AES-256-GCM 32 B, shared key | 3.58× | 4.68× | 4.91× | 4.5 → 7.6 µs |
  | AES-256-GCM 32 B, own key | 3.80× | 5.38× | 5.15× | 4.5 → 6.5 µs |

  The AES-GCM peak is ~1.1 M ops/s.
- Ed25519 scales linearly to 8 threads; beyond 8, efficiency cores join. The 32-byte encrypt
  saturates although each thread has its own key, so the contention is on something every call
  shares.
- Max latencies of 2–23 ms at 12 threads come from the OS: every core is busy, including the
  harness's own threads.
- Status: **profiled, causes confirmed** (2026-11-19).
  - Profiles: `bench --only contention --threads N [--shared] --seconds 5` under samply, against a
    release library built with `CARGO_PROFILE_RELEASE_DEBUG=true`.
  - Compared with `benches/contend_samply.py`: worker threads only, share of samples × wall time
    per operation per thread.
  - Wall time per op per thread: 4.82 µs (1 thread) → 7.70 µs (8 threads, own keys) → 8.67 µs
    (8 threads, one shared key).

  | Where the time goes (µs per op) | 1T | 8T own key | 8T shared key | Grows by (own) |
  |---|---|---|---|---|
  | `getentropy` (kernel, nonce per call) | 1.22 | 2.00 | 1.91 | +0.78 |
  | `RwLock::try_read` on the repositories (inclusive) | 0.46 | 1.53 | 2.02 | +1.07 |
  | of which spinning on the lock word (`atomic_load` leaf) | 0.02 | 0.41 | 0.94 | +0.39 |
  | malloc/free (libsystem_malloc leaf) | 1.54 | 1.90 | 2.06 | +0.36 |
  | memmove (the clones) | 0.41 | 0.88 | 0.85 | +0.47 |
  | `Arc` refcount drop + clone of the shared key's material | 0.04 | 0.36 | 0.99 | only when shared |
  | the AES-GCM itself (`aead_seal`) | 0.31 | 0.40 | 0.36 | ≈ flat |

  Lock waits (`__psynch_*`) do not appear: no thread ever blocks. The cost is cache lines
  bouncing between cores, plus a kernel entropy source that does not scale.
- Causes, ranked:
  1. **Every read takes an `RwLock` on the key and policy repositories.** Each read acquire and
     release writes the same lock word, so the lock's cache line moves between all cores, even
     when every thread uses a different key. Code: `memory_keys.rs:62` and `file_keys.rs:248`
     (`state.read()`), `memory_policies.rs:49`, and twice per call (F3).
  2. **`getentropy` per nonce** gets ~65 % slower under 8 threads. It is also in L0, so a native
     client that uses `OsRng` per call pays the same; a client with a userspace RNG
     (`rand::rng()`, a ChaCha DRBG) pays ~0.1 µs.
  3. **Allocation and copying** (F3): ~100 mallocs per call and the clones of `Key`, `Policy` and
     `Template`. Both get slower under parallel load (allocator, cache pressure).
  4. **The shared key's `Arc` refcount**: cloning a `Key` increments and decrements the
     `Arc<SecretBytes>` count, which is one cache line shared by all threads using that key. This
     is the whole gap between shared key and own key.
- Candidate fixes:
  - Lock-free read snapshots for the repositories, e.g. `arc-swap` over an immutable map (writes
    copy and swap; reads are thread-local in the fast path), or a sharded map. Return `&Key`/guards
    instead of clones (F3). That removes causes 1, 3 and 4.
  - A per-context or per-thread CSPRNG seeded from the OS, with reseeding and fork detection (F5).
    That removes cause 2 and ~1.2 µs per call even at one thread.

  Expected: 8-thread per-op cost close to the 1-thread cost, and the 1-thread cost from ~4.8 µs to
  ~1.5–2 µs together with F3.

### F8. Each key costs ~16–17 KiB of resident memory: one locked page per secret (silent unlocking fixed)
- Measured, in a fresh process: 1000 keys add 16.1–17.6 MiB, the same for AES-256, Ed25519 and
  ML-DSA-65. The page size on Apple silicon is 16 KiB, and `secret.rs` gives every secret its own
  page-aligned, mlock'd mapping.
- A fresh context with 12 policies adds ~1.8 MiB RSS. **Attributed** (2026-11-19):
  - measured from C, step by step: `cargo xtask bench --only context [--vmmap]`;
  - each part of a context built and held under a counting allocator: `benches/allocs.rs`;
  - output in `docs/perf-results/2026-11-19-macos-m4pro-context.txt`.

  | Part of the first `agc_ctx_open` + policies | KiB | per context? | kind |
  |---|---|---|---|
  | Library code paged in for the first time (`__TEXT` resident +1024; +112 for policy parsing) | ~1140 | no, once per process | clean, mapped from the file, shared between processes, evictable |
  | **The parsed template registry** (72 templates, 2404 allocations, 217 KB requested) | **228** | **yes** | heap |
  | malloc pages dirtied by the parse's transient peak (358 KB), then freed and kept by malloc for reuse | ~300 | no, reused later | dirty, private |
  | malloc metadata and tiny-zone pages | ~50 | no | dirty, private |
  | 12 policies | 10 | per policy (~0.8 KiB each) | heap |
  | provider registry, policy engine, empty key repository, orchestrators | < 1 | yes | heap |

  - Contexts #2–#10 add exactly **228 KiB of heap each** (footprint +288 for #2, then 1:1).
    Closing a context frees it all.
  - On macOS the memory a process is charged for (phys_footprint) grows by ~560 KiB for the first
    context, not 1.8 MiB. The rest of the RSS growth is shared library code.
- **The per-context cost is the catalog.** `Context::open` parses the compiled-in 150 KB JSON
  catalog into proto structures every time (`InMemoryTemplateRegistry::standard()`,
  `ffi/context.rs`). That is ~3 KiB of heap and ~33 allocations per template, and
  **~300–340 µs**, which is most of `agc_ctx_open`'s time (§2.4).
- Candidate fixes:
  1. Parse once per process and share: an `Arc<InMemoryTemplateRegistry>` in a `OnceLock`. The
     registry is immutable, and `catalog_path` is refused anyway. Each further context then costs
     < 1 KiB and ~0 µs; the first keeps the parse.
  2. Compile the catalog into static Rust data at build time (build.rs generates it from the
     JSON). Then no parse, no heap, no transient peak and no 300 µs at all. It also takes the
     catalog's share of the pbjson/serde code out of the binary (F11); the policy JSON still
     needs a parser.
- Consequences for clients:
  - memory per key ≈ one page (4 KiB on most Linux x86, 16 KiB on Apple, 64 KiB on some ARM
    servers);
  - locked memory per key is the same page. On Linux the default `RLIMIT_MEMLOCK` (often 8 MiB)
    is reached after ~2000 keys with 4 KiB pages. Beyond that, locking quietly stops, because it
    is best effort (DEVIATIONS C4). **Confirmed on Linux (§2.6):** `VmLck` stops at exactly
    8192 KiB. Every later key is created normally, unlocked, and nothing tells the caller.
  - **Fixed (2026-11-20, commits `2816175`, `0abdc52`).** `require_locked_memory` is honoured
    (DEVIATIONS C4):
    - `agc_ctx_open` fails with `AGC_ERR_OUT_OF_MEMORY` if memory cannot be locked, or if the
      file store's wrapping key or a stored key cannot be;
    - create, rotate and migrate fail the same way and store nothing when the new material
      cannot be locked;
    - forked children get no copy of the secrets (wiped on Linux, not mapped on macOS), because
      locks do not survive fork.

    Without the flag, locking stays best effort, as the header allows.
    `tests/c/test_locked_memory.c` checks it under a lowered `RLIMIT_MEMLOCK`.
- Candidate fix: a slab of secrets sharing locked pages, with care for the munlock problem that
  `secret.rs` documents, or one locked arena per context. Expected gain: ~100 B per AES key
  instead of a page.

### F9. Creating a key in the file store costs ~8 ms on macOS (two full fsyncs)
- Code: `FileKeyRepository::write` (`adapters/storage/file_keys.rs:152`) writes a temporary file,
  calls `sync_all`, renames it, then syncs the directory. On Apple platforms Rust's `sync_all` is
  `fcntl(F_FULLFSYNC)`, which flushes the drive's cache. That costs ~4 ms each.
- It stays flat with the number of keys (one file per key). Reopening costs ~30 µs per key
  (unwrap and parse), so 1000 keys take 30 ms at `agc_ctx_open`.
- Status: **confirmed** on macOS. Linux `fsync` on NVMe is typically 10× cheaper; to be measured.
- For clients: keep key creation and rotation off the real-time path. Reads never touch the disk.

### F10. ML-DSA signing has a heavy latency tail, and it is RustCrypto's (inherent to FIPS 204)
- Measured from C: ML-DSA-65 p50 422 µs, p99 1407 µs, p99.9 2325 µs (3.3× and 5.5× the median).
  ML-DSA-44 and -87 behave the same way. Verification is tight (p99/p50 ≈ 1.06).
- Checked against RustCrypto (2026-11-19). `benches/tail.rs` times every call on its own; the
  raw output is in `docs/perf-results/2026-11-19-macos-m4pro-mldsa-tail.txt`. Results in µs:

  | ML-DSA-65 | min | p50 | p90 | p99 | p99.9 | p99/p50 |
  |---|---|---|---|---|---|---|
  | L0 hedged (RustCrypto, key parsed once) | 88 | 262 | 673 | 1370 | 2023 | 5.2 |
  | L0 deterministic, a new message per call | 86 | 260 | 669 | 1265 | 1892 | 4.9 |
  | L0 deterministic, the same message every call | 722 | 727 | 733 | 771 | 797 | 1.06 |
  | L0p hedged (key parsed per call) | 236 | 412 | 822 | 1462 | 1976 | 3.6 |
  | L2ffi (as `agc_sign`) | 249 | 425 | 837 | 1443 | 2038 | 3.4 |
  | control: Ed25519 L0 | 32 | 33 | 33 | 41 | 50 | 1.27 |

  ML-DSA-44 and -87 look the same: an L0 p99/p50 of 4.8–5.3.
- Status: **confirmed inherent**.
  - RustCrypto alone has the same spread. FIPS 204 signing is a rejection-sampling loop whose
    number of iterations is random, and a single iteration costs ~60–120 µs (the min column).
  - Our layers add a roughly constant ~150 µs to every percentile (the key parse, F1). They do not
    widen the tail; p99/p50 looks smaller only because the median grows.
- Deterministic signing does **not** remove the tail. The iteration count is a function of
  (key, message):
  - one fixed message on one key always takes the same time, which is the tight 1.06 row;
  - over changing messages the spread equals the hedged one;
  - across two runs with fresh keys, the same fixed message took 201 µs once and 727 µs the next
    time.
- For real-time clients:
  - budget ML-DSA signing by its p99.9: about 2 ms for ML-DSA-65 and -87, and 1.1–1.3 ms for -44,
    on this machine;
  - the mean is 1.3× and the p99.9 6–8× the median;
  - fixing F1 lowers every percentile by the constant (~90/150/240 µs for -44/-65/-87), not the
    shape;
  - there is no fix on our side. Only a different algorithm (e.g. Ed25519, or SLH-DSA, which has
    no rejection loop but is far slower) changes the shape.
  - Verification has no loop and stays tight.

### F11. Binary size: ~2.3 MB stripped for any C client, even one that uses only AES-GCM
- Measured (2026-11-19, `benches/size/measure.sh`; output in
  `docs/perf-results/2026-11-19-macos-m4pro-size.txt`). The clients are linked statically with
  `-dead_strip`, and the sizes are stripped Mach-O on arm64:

  | Artefact | default release | fat LTO, 1 CGU | LTO + opt-level=s |
  |---|---|---|---|
  | `libagilecrypto.dylib` | 2.53 MiB (`__text` 1.67) | 2.37 MiB | 2.18 MiB (`__text` 1.29) |
  | minimal C client, one AEAD encrypt (`benches/size/min_aead.c`) | **2.20 MiB** | 2.14 MiB | 2.36 MiB |
  | C client using every operation (the bench harness) | 2.27 MiB | 2.21 MiB | 2.43 MiB |
  | RustCrypto only, AES-GCM only (`benches/size/baseline`) | **0.31 MiB** | – | – |
  | RustCrypto only, the same algorithms as our provider | **0.94 MiB** | – | – |

- Dead-stripping removes almost nothing: the AEAD-only client is 97 % the size of the
  everything client. Algorithms are chosen at run time (catalog → template → provider →
  `dyn Signer/Cipher`), so every algorithm the provider implements is reachable from
  `agc_ctx_open`.
- Compared with RustCrypto on its own:
  - **+1.3 MiB** over a native client with the same algorithms;
  - **7×** a native client that only needs AES-GCM.
- Where it goes (`benches/size/crate_sizes.py`, `__text` of the default dylib, 1.67 MiB):

  | Part | Size | Share |
  |---|---|---|
  | agilecrypto's own code | 565 KiB | 33 % |
  | … of which pbjson/serde code generated for the proto types (JSON catalog, policies) | 215 KiB | |
  | … of which providers | 64 KiB | |
  | … of which the FFI exports (inlined into `ffi::guard`) | 54 KiB | |
  | … of which storage | 38 KiB | |
  | `core` / `alloc` monomorphizations | 322 KiB | 19 % |
  | `hybrid_array` (ML-DSA, generic arrays) | 118 KiB | |
  | serde_json | 92 KiB | |
  | ml_dsa + module_lattice | 88 KiB | |
  | primeorder + crypto_bigint + ecdsa (ECDSA) | 143 KiB | |
  | std's backtrace symbolizer (gimli, addr2line, rustc_demangle) | ~58 KiB | |

  `__data` adds 195 KiB: the P-256/384/521 basepoint tables (25 + 55 + 113 KiB).
- LTO saves ~7 %. `opt-level=s` shrinks `__text` by 23 % but grows unwind tables, so the
  stripped file gains little (and is slower; not measured).
- Candidate reductions (for discussion):
  - Cargo features per algorithm family, so that a build contains only the families its catalog
    needs. This is the only way to approach the RustCrypto figures; an AEAD-only build would
    lose ECDSA, ML-DSA, the tables and most of `hybrid_array`.
  - Replace pbjson/serde_json for the catalog and policy JSON with a hand-written parser, or a
    binary catalog compiled in at build time: −300 KiB.
  - `panic = "abort"` is not an option: `ffi::guard` relies on `catch_unwind`. Building std with
    `panic_immediate_abort` is not either.

### F12. Stack: ML-DSA needs up to 631 KiB; small threads crashed (fixed: helper thread)
- Measured (2026-11-19). Each operation runs on a thread whose 8 MiB stack is ours and filled
  with a pattern, and the deepest overwritten byte is taken, net of an empty thread. C path:
  `cargo xtask bench --only stack`; Rust layers: `cargo bench --features bench --bench stack`.
  Output in `docs/perf-results/2026-11-19-macos-m4pro-stack.txt`. Results in KiB:

  | Operation | RustCrypto (L0) | our provider (L1) | via `agc_*` (L3) |
  |---|---|---|---|
  | ML-DSA-44 / 65 / 87 sign, key parsed once | 66 / 92 / 120 | – | – |
  | ML-DSA-44 / 65 / 87 parse the key (expand from the seed) | 211 / 275 / 491 | – | – |
  | ML-DSA-44 / 65 / 87 **sign** | – | 218 / 284 / 503 | **221 / 287 / 507** |
  | ML-DSA-44 / 65 / 87 verify | – | – | 86 / 128 / 200 |
  | ML-DSA-44 / 65 / 87 **create key** | ≥ 211 / 275 / 491 (`from_seed`) | 263 / 323 / 626 | **268 / 328 / 631** |
  | Ed25519, ECDSA sign | – | 5–8 | 12 |
  | ECDSA verify (P-256 / 384 / 521) | – | – | 14 / 18 / 24 |
  | ECDSA create key, first use of the curve in the process | – | – | 35 / 68 / 128 |
  | ECDSA create key, afterwards | – | – | 9–10 |
  | AES-GCM, ChaCha20-Poly1305, CBC, CTR encrypt / decrypt (32 B and 1 MiB alike) | – | – | 10 / 12 |
  | `agc_ctx_open` + 12 policies | – | – | 16 |

- **Confirmed crash (before the fix):** `agc_create_key` for ML-DSA-87 on a thread with the default macOS
  secondary-thread stack (512 KiB) kills the process with SIGBUS (exit 138; stack overflow into
  the guard page). `catch_unwind` cannot catch it. ML-DSA-87 signing (507 KiB) still fits, with
  ~5 KiB to spare for the caller's own frames. Reproduce with `benches/c/default_stack.c`.
- Why ours is deeper than RustCrypto's:
  - **Signing** re-parses the key on every call (F1), and the parse, which expands the key from
    the seed, is the deepest part: 491 KiB against 120 KiB for the signature itself. With F1
    fixed (the expanded key cached, with expansion done once, e.g. at create or open), signing
    would need ~120 KiB for ML-DSA-87. That is **4.2× less**, and below the 512 KiB macOS
    default.
  - **Key generation** needs `from_seed` in any implementation (≥ 491 KiB for -87). Our provider
    adds ~135 KiB on top (encoding and the public key). That part is inherent to the RustCrypto
    crate, which keeps its large arrays on the stack.
- The ECDSA first-use depth is RustCrypto building its basepoint tables lazily, once per
  process, on whichever thread uses the curve first. A real-time client should warm each curve
  at init, for latency as well.
- Other platforms' default stacks make it worse:
  - musl (Alpine): 128 KiB. **Confirmed (2026-11-20, §2.6):** on a default musl thread, every
    ML-DSA create and sign (-44/-65/-87) and the first P-521 key creation **segfault** (stack
    overflow). Ed25519, P-256, and P-521 signing after the first use are fine. For Alpine-based
    deployments, ML-DSA is unusable on default threads.
  - glibc: 8 MiB, from `RLIMIT_STACK`, and safe.
  - RTOS / embedded threads are often 8–64 KiB. Only the symmetric operations and ECDSA/Ed25519
    signing fit (10–12 KiB).
- **Fixed (2026-11-20, commit `1dccd1d`): the crashes.** `src/stack.rs` checks how much stack the
  caller's thread has left (its bounds are looked up once per thread). An operation that would not
  fit runs on a short-lived helper thread with its own stack. The budgets
  (`adapters/providers/stack_budget.rs`) come from the table above: ×1.5 in release, ×4 in debug.
  - ML-DSA keygen, sign and verify use these budgets.
  - ECDSA uses one only for a curve's first use, which builds the curve's table on the big stack.
  - Ed25519, ECDSA after first use, and the ciphers run inline with no check.
  - `tests/c/test_small_stacks.c` runs every signature algorithm on a 128 KiB thread. Before the
    fix it died with SIGBUS; now it passes on macOS, glibc and musl.
- **The cost of the fix: one thread start per operation that does not fit**, ~25–45 µs, which is
  11–15 % of an ML-DSA signature. Measured as the median over 400 signatures; raw output in
  `docs/perf-results/2026-11-20-macos-m4pro-stack-hop.txt`:

  | ML-DSA sign p50 | 16 MiB thread (inline) | 512 KiB (macOS default) | 128 KiB (musl default) |
  |---|---|---|---|
  | ML-DSA-44 | 161–164 µs | 154–159 µs (fits, inline) | 184–194 µs (hop) |
  | ML-DSA-87 | 336–341 µs | 374–386 µs (hop) | 374 µs (hop) |

  On threads with enough stack (glibc's 8 MiB default, the main thread) nothing changes.
- Still open, for discussion:
  1. F1: cache the expanded ML-DSA key. Signing then needs ~120 KiB instead of 507, fits a
     512 KiB thread inline, and the hop is gone for signing.
  2. Document the stack needed per operation in the C API (e.g. in `agc_crypto.h` and the
     catalog), so real-time callers can size threads and avoid the hop.
  3. Upstream: ask RustCrypto `ml-dsa` to box its large intermediates, or to offer a
     heap-backed expansion.

## 4.1 Related defects found while fixing F8, F12 and B1

Searched for after the defects above: code that is affected by them, and code that fails the same
way (a secret left where it is not protected, stack depth decided by something other than the
library, a silent fallback, text parsing of generated output). All are fixed on `main`, with a
regression test that fails on the old code.

| Defect | Pattern | Fix (commit) |
|---|---|---|
| The file store's **wrapping key**, which seals every stored key, was a `Zeroizing<[u8; 32]>` on the ordinary heap: swappable and in core dumps, while the keys it protects are locked and excluded | secret not protected | now a `SecretBytes` like the key material (`2816175`) |
| `GeneratedKey::to_bytes` reserved `16 + private.len()` and then appended the public key: for **every asymmetric key** the private key was left in freed heap memory | secret reaches the allocator unwiped | exact size, and `secret::extend_secret` moves to a bigger zeroizing buffer before growing (`2816175`) |
| The file store's **record encoder** grew from empty, leaving earlier versions' material in freed buffers | as above | `extend_secret` for every write (`2816175`) |
| **Forked children** held unlocked copies of every secret: locks do not survive fork (found in code review) | silent loss of a guarantee | pages wiped in the child (Linux `MADV_WIPEONFORK`) or not mapped (macOS `VM_INHERIT_NONE`); `Required` fails where neither exists (`0abdc52`) |
| `build.rs`'s `rc_table` reads `agc_types.h` as text and skips lines it does not recognise: a reformatted header would silently drop codes from `agc_rc_name` | text parsing of generated input | the build fails if a result code in the bindings is missing from the table (`6c8ce7f`) |
| `agc_metadata_storage_len` promises an "exact" size, but the requirement depends on the storage's alignment, which no header states | contract gap, safe (the library refuses and writes nothing) | reported to the header team (docs/header-team-issues.md, item 6) |

How the leaks are tested: a scanning global allocator for unit tests (`secret::leak_check`)
searches every freed heap block for a canary.

Checked and found sound:
- policy JSON nesting: bounded at ~40 KiB of stack by serde_json's recursion limit, so it fits
  a musl thread;
- the remaining `let _ =` uses: test clean-up, a Miri stub, and `agc_ctx_close`, which returns
  `void`.

New checks for out-of-bounds access inside the library, which the C side's ASan does not see:
- `tests/c/test_buffer_bounds.c` puts every caller buffer, slice, string and versioned struct
  against a guard page, sweeps every output capacity against the size-query contract, and uses
  every `struct_size` (6243 calls).
- `cargo xtask memcheck` runs all C tests under Guard Malloc (macOS) and valgrind (Linux).

Neither found an out-of-bounds access.

## 5. What performance-sensitive and real-time clients will want to know

| Topic | Status |
|---|---|
| Mean time per operation, overhead compared with RustCrypto | §2.1–2.3; the C boundary itself is ≈ free |
| Tail latency and jitter (p50/p99/p99.9/max) | §2.3 on macOS; F10 (the ML-DSA tail is inherent, the same in RustCrypto); Linux with isolated CPUs is pending |
| Heap allocations on the hot path (hard RT often bans malloc after init) | §3: ~100 per call; F3 could bring it to ~10, never 0 with `Vec` outputs |
| Syscalls on the hot path | F5: exactly one `getentropy` (1.2 µs macOS, 0.33 µs Linux) per encrypt or hedged signature; 0 for verify, decrypt and Ed25519; no page faults in steady state. `getpid` is cached on macOS, but on Linux it is a real syscall on every call (0.19 µs) |
| Blocking I/O | F9: ~8 ms per create on macOS (2× F_FULLFSYNC); never on sign/encrypt/decrypt |
| Lock contention and multi-core scaling | F7: large operations scale linearly; 32-byte operations saturate at ~5× (repository `RwLock` cache-line bouncing, `getentropy`, malloc) |
| Startup and warm-up (`agc_ctx_open`, file store load, first call compared with steady state, ML-DSA keygen) | §2.4 |
| Static footprint: RSS per context and per key, mlock'd pages per key (`RLIMIT_MEMLOCK`), binary size | F8: 228 KiB heap per context (the parsed catalog), plus ~1.5 MiB once per process (mostly shared code pages); one page per key. F11: ~2.2 MiB stripped per client, whatever it uses (RustCrypto: 0.3–0.9 MiB) |
| Cost of the two-call sizing protocol | §2.3: +~1.5 µs per call |
| Stack high-water mark (ML-DSA is stack heavy; small RT thread stacks) | F12: 10–12 KiB for symmetric operations and ECDSA/Ed25519; ML-DSA up to 507 KiB (sign) and 631 KiB (keygen). Small threads no longer crash: such work moves to a helper thread (+25–45 µs) |
| Size scaling: no streaming (the `*_init/update/final` functions are stubs), whole messages in memory, one extra copy | §3, F6 |
| Constant-time behaviour | inherited from RustCrypto, not measured |
| Fork and thread-safety guarantees | documented elsewhere (DEVIATIONS, code review); forked children get no copy of the library's secrets (§4.1) |
| Locked memory for keys | best effort by default; with `require_locked_memory` guaranteed or the operation fails with `AGC_ERR_OUT_OF_MEMORY` (F8) |

Short version for clients so far:
- Signatures cost 1.5–3× a well-written native RustCrypto client (ECDSA 2.7–3.0×, Ed25519 2.1×,
  ML-DSA 1.5×; the same for digest signing), because we re-parse the key per call (F1).
- Verification costs what RustCrypto costs for ECDSA and Ed25519 (≤ 1.14×), but 2.4–3.1× for
  ML-DSA, because the public key is decoded per call (F1).
- Small symmetric operations carry a fixed ~3 µs, plus ~1.5 µs with the two-call protocol.
- Large decryptions pay ~0.4 ms/MiB for wiping the plaintext (F2). That is 1.8× for GCM and 2×
  for CBC and CTR at 1 MiB; it is our only decryption overhead besides the fixed cost.
- The C boundary itself is negligible.
- Expect ~100 small heap allocations per call.
- Small operations scale to ~5× across threads, because of shared locks and the entropy syscall (F7).
- One syscall (`getentropy`, ~1.2 µs) per encrypt or hedged signature, none otherwise, on macOS;
  on Linux add one `getpid` syscall per call (~0.2 µs). No page faults in steady state (F5).
- Each context costs 228 KiB of heap and ~300 µs, both for parsing the built-in catalog
  again; the first one also pages in ~1 MiB of shared library code (F8).
- Each key takes one memory page, locked (F8). By default locking is best effort: on Linux it
  stops at `RLIMIT_MEMLOCK` (8 MiB, ~2000 keys). With `require_locked_memory`, an operation that
  cannot lock fails instead.
- Each C client grows by ~2.2 MiB whatever it uses, because dead-stripping can't remove
  algorithms that are selected at run time (F11).
- Stack: 10–12 KiB for symmetric operations and ECDSA/Ed25519, but up to 507 KiB for ML-DSA
  signing and 631 KiB for ML-DSA key creation. On a thread too small for that (macOS default
  512 KiB, musl 128 KiB) the operation runs on a helper thread. That costs ~25–45 µs, but no
  longer crashes the process (F12). Real-time clients that size their threads ≥ 1 MiB avoid the
  hop.
- Creating a key in the file store takes milliseconds (F9).
- ML-DSA signing has a p99.9 of 6–8× its median. That is inherent to the algorithm, the same in
  plain RustCrypto, and deterministic signing doesn't help (F10).

## 6. Still to do (from the plan)

Done: the C harness (`benches/c/bench.c`, `cargo xtask bench`), covering L3a/L3b, per-call
distributions, first calls, threads, RSS and the file store. Also: `cargo test --workspace` and
`cargo xtask test-c` pass after the `rlib` change.

1. (Done: F7 profiled.) Optionally, an L0 thread-scaling run, to show what a native client's
   `getentropy` scaling looks like on its own.
2. (Done on macOS: F5.) Linux: `strace -c` for the getpid syscall and the counts per operation.
3. Rotate in the lifecycle benches. `ctx_open` with 10k keys.
4. (Done: §2.5 CBC/CTR, digest signing and verification baselines; the ML-DSA L0 distribution,
   F10.)
5. (Done: binary size F11, stack depth F12, per-context memory F8, the Linux/musl stack §2.6.)
6. (Done in an arm64 VM, §2.6: `strace -c`, getpid, `RLIMIT_MEMLOCK` with many keys, the musl
   stack, the full harness.) Still open for the published figures: a bare-metal Linux host,
   ideally x86-64. There: isolated CPUs for tail latencies, `perf stat`, cachegrind
   (deterministic instruction counts, usable as a CI gate), heaptrack. Measure layer differences
   interleaved.
7. (Done: F4 resolved by interleaved measurement.)
8. (Done 2026-11-20: the defects F8, F12, B1 and §4.1 fixed on `main`, with regression tests.)
   Next: the improvement discussion over the open findings, starting with F1. Fixing it would
   also remove most of F12's helper-thread hops.

### Build issue found on the way

**B1. The build needed `rustfmt`. Fixed (2026-11-20, commit `532749d`):** the constant is now
read as a parsed `const` item, and a build in a container without rustfmt succeeds. The original
finding:

Without rustfmt, bindgen emits unformatted bindings, e.g.
`pub const AGC_API_VERSION_MAJOR : u32 = 1 ;`. `set_library_name` in `build.rs:421` only matches
the formatted spelling, so the build panics with "the bindings define AGC_API_VERSION_MAJOR".
That hits minimal toolchains, such as the `rust:1-*` Docker images and CI images without the
rustfmt component. Fix: parse whitespace-tolerantly, or read the constant from bindgen's typed
output (e.g. a generated `const`) rather than from text.
