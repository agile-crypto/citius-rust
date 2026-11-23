# Improvement plan for the performance findings

Agreed on 2026-11-20 after a three-round design discussion between four reviewers: key
handling (F1/F12), the per-call hot path (F3/F7/F5), memory and copies (F2/F6/F8/F11), and a
sceptical reviewer who checked the claims against the code and the dependency sources. The
findings are in `docs/performance.md`. This plan orders the work by efficiency impact per risk,
with defects first.

The guiding rule is to fix causes, not symptoms. The changes should make the code simpler to
read: one key lookup per call, keys parsed where they live, buffers whose types say what they
hold.

## Status (2026-11-21)

| Phases | Branch | State |
|---|---|---|
| 0–2 | merged into `main` (9bb1d53), pushed to the public repository | done |
| 3–7 | merged into `main` | done, reviewed |
| deferred F7 stage 2 (arc-swap) | merged into `main` | done |
| deferred F5 (userspace randomness on macOS) | none | open: needs the security review this plan asks for |
| deferred: fork detection without `getpid`, binary size (F11) | none | open: only if clients ask |

Results: `docs/perf-results/phase-0-2/`, `docs/perf-results/phase-3-7/` and (Linux)
`docs/perf-results/phase-3-7-linux/`; summary in
`docs/performance.md` §7.

How the work differs from this plan:

- **Phase 1:** `admit` returns the region the artifact goes to (`Result<&mut [u8], E>`), not
  a set of output slices. The metadata is still encoded separately and copied with a
  bounds-checked `put`. For decryption, the metadata is encoded before decrypting, so nothing
  that can fail runs after the plaintext is written.
- **Phases 3/4:**
  - The per-version cache is `domain::core::PublicCache`, with a 64 MiB process budget for
    every cached value, not only ML-DSA's.
  - Providers fill it through `StoredKey::public_value`.
  - It holds one type per version, which is checked at run time, not in the type.
  - Ed25519 verification derives its public key from the secret too, and a stored copy that
    is not the secret's is `InvalidKeyMaterial`.
- **Phase 5:** done in its own commit after phase 1, not together with it.
- **Phase 7:** `secret::Sealed<T>` is sealed by a bitwise copy from where the value lives
  (`copy_of`, an `unsafe fn` with an "inline only" contract), not by moving a `T: ZeroizeOnDrop`.
  Sealed values are only ever locked: no swappable fallback, whatever `require_locked_memory`
  says. Whether a version's secret is sealed is decided at its first use.
- **Stack budgets** were not re-measured. The sealing path puts no extra copy on the stack,
  and the fallback is `main`'s heap path, so they can only have shrunk.
- **F7 stage 2:**
  - The trigger was measured: decryption, which draws no randomness, collapsed past 4 threads.
  - A shared `std::sync::RwLock` read caps at ~5 M/s on 8 threads on its own.
  - Encryption's limit on macOS is `getentropy` (F5), not the locks.

## Phase 0: defects found during the discussion (must do first)

| # | Defect | Fix |
|---|---|---|
| D1 | **Buffer overflow under concurrency.** `put()` (`ffi/exports/crypto.rs:41`) copies without checking `cap`. The sizes come from a first key lookup (`*_sizes`) and the bytes from a second. A concurrent `agc_transform_key` (e.g. Ed25519 → ML-DSA-65, same scope) between them writes ~3.3 KB past a 64-byte signature buffer in release builds. Also reachable through a template change for decrypt, and the PROTOBUF key-version varint. | `put` refuses `len > cap` (a backstop that stays). The structural fix is phase 1. Regression test without threads: a `KeyRepository` double whose second `get_by_name` returns a changed key. |
| D2 | **AES/ChaCha key schedules are not wiped.** The `zeroize` features of `aes`, `aes-gcm`, `chacha20poly1305`, `cbc` and `ctr` are off, so every operation drops its expanded key (the first round key *is* the key) unwiped. | Enable the features, after the zeroize bump (D3) so the wipe is fast. |
| D3 | **Private key copied into unlocked heap on every operation** (`Resolved::material` → `GeneratedKey::from_bytes`). | A borrowed `StoredKey<'a>` view of the locked material, for signers and ciphers (phase 2). |

## Phase 1: one key lookup per call (F3, closes D1)

- **Shape.** The existing `*_admitting` idiom (`create_key_admitting`, `transform_key_admitting`)
  replaces the `*_sizes` + operation pairs:
  ```rust
  pub fn encrypt_admitting<'b, E: From<Error>>(&self, req: EncryptRequest, enc: MetadataEncoding,
      admit: impl FnOnce(Sizes) -> Result<Outputs<'b>, E>) -> Result<Written, E>
  ```
  It resolves once and computes the sizes. `admit` (in the FFI) checks the caller's capacities,
  then hands back the output slices, before any key material or randomness is touched. The
  sizes and the bytes therefore come from the same snapshot. The `*_sizes` functions become
  private, and `encrypt(req)` stays a thin wrapper for Rust callers.
- **Repositories** store `Arc<Key>`, so a lookup takes one refcount increment instead of deep
  clones of the key, policy and template:
  - the policy is checked in place under its lock (no `Arc<Policy>`: one policy serves many
    keys, so its refcount would be a new hot line);
  - templates and the provider are borrowed;
  - the two key stores' duplicated state becomes one `KeyIndex`.
- **Metadata** is encoded once to measure it, then checked for length equality before a
  bounds-checked copy. A `Sink` writer that encodes straight into the caller's buffer is
  deferred: it saves ~0.3 µs.
- **Expected:** fixed cost per call ~3.5 → ~1–1.5 µs, the two-call protocol +1.5 → ~+0.5 µs,
  allocations ~100 → ~15. Check with `allocs`, `interleave` and `xtask bench --only contention`.

## Phase 2: fast wipes and borrowed keys (F2, D2, D3)

- **zeroize 1.9.1 → 1.9.2.** `[u8]::zeroize` becomes `fill(0)` plus an asm barrier, which makes
  `secret::free` and `agc_secure_zero` memset-speed. `Zeroizing<Vec<u8>>` stays per-byte (the
  generic `Vec<Z>` impl), so add `secret::SecretVec`: `Drop` wipes the slice and the spare
  capacity.
  - Required at the decrypt plaintext sites (`rustcrypto_cipher.rs:102, 233, 273`,
    `Cipher::decrypt`, `Decrypted.plaintext`).
  - Optional, as one consistent rule, at the key-sized buffers.
- **Then enable the cipher crates' zeroize features (D2).** Measure at 32 B with `baselines`.
- **`StoredKey<'a>`** borrows the material from the locked pages (D3); `GeneratedKey` stays the
  generate/store type.
- **Expected:** decrypt +0.4 ms/MiB → ~+30 µs/MiB (GCM 930 → ~550 µs/MiB, CBC/CTR ~2× faster
  at 1 MiB). No private-key copy per call.

## Phase 3: Ed25519 and ECDSA without re-parsing, and without a secret cache (F1, part 1)

- **The cost is in deriving the public key.** Sign from a cheap per-call scalar parse instead:
  - **ECDSA:** decode the SEC1 scalar (no `validate_public_key`), then
    `ecdsa::hazmat::sign_prehashed_rfc6979(d, z, ad = random)`. That is exactly what
    `sign_prehash_with_rng` does today, so the signatures stay byte-identical (test with a fixed
    RNG).
  - **Ed25519:** `ExpandedSecretKey` from the seed (~0.3 µs), then `hazmat::raw_sign(esk, msg,
    vk)` (feature `hazmat`).
- **The signing `vk` is derived once from the secret** and cached on the ordinary heap. It is
  public, and it is never taken from the stored SPKI: a mismatched `vk` leaks the private key
  (the double-public-key oracle).
  - At load, the stored SPKI is compared with the derived key; a mismatch is
    `InvalidKeyMaterial`.
- **Where the cache lives.** It is on the version, never on the material: a retained transform
  reuses bytes under another template.
  - It is a small typed API in `domain::key`. `Version::handle::<T>(which, load)` hides one
    `OnceLock<Box<dyn Any + Send + Sync>>`; only the app layer fills it, with one type.
  - The cache is shared by every clone of the version, and released with it.
  - It is borrowed per call from the `Arc<Key>` of phase 1, with no extra refcount.
- **Expected:** signing ~L0 + ~1 µs:

  | Algorithm | Now | Expected |
  |---|---|---|
  | Ed25519 | 70 µs | ~36 µs |
  | P-256 | 195 µs | ~68 µs |
  | P-384 | 490 µs | ~175 µs |
  | P-521 | 366 µs | ~133 µs |

  No locked-memory cost.

## Phase 4: ML-DSA verifying-key cache (F1, part 2)

- Cache the decoded `ml_dsa::VerifyingKey` (public) per version, lazily.
- It is bounded by a process-wide heap byte cap, without eviction: past the cap, verification
  decodes per call as today. An ML-DSA-87 key holds ~56 KiB of `A_hat`.
- **Expected:** ML-DSA verify 2.4–3.1× faster (-65: 105 → ~41 µs).

## Phase 5: decrypt into and encrypt from the caller's buffers (F2/F6, structural)

Done together with phase 1's FFI rewrite, so `ffi/exports/crypto.rs` changes once.
- **The trait.** `Cipher::decrypt_into(..., plaintext: &mut [u8]) -> Result<usize>` and
  `encrypt_into`. Every failure is decided before the first write, as a documented and tested
  contract:
  - AEAD: detached tag check before decrypting;
  - CBC: the last block is decrypted into a 16-byte stack buffer and the padding checked first,
    then the remaining blocks are decrypted straight into the caller's buffer;
  - CTR: cannot fail after the parameter checks.
- **Overlapping caller buffers.** The FFI checks the raw pointers before any `&mut` slice exists
  and copies the input if it overlaps the output (safe code). An in-place fast path comes later,
  and only if a client needs it.
- **Gain.** Mainly structural: no internal plaintext, no allocation that grows with the message,
  and no overflow possible by construction. ~10–20 µs/MiB less copying.

## Phase 6: catalog parsed once per process (F8)

`InMemoryTemplateRegistry::standard() -> Arc<Self>` from a static `OnceLock`. Test registries
and a future `catalog_path` build their own. Each context after the first costs < 1 KiB and
~0 µs instead of 228 KiB and ~300 µs.

## Phase 7: the ML-DSA expanded-key cache in locked memory (F1, part 3; the riskiest step)

- **Where it lives.** `secret::Sealed<T: ZeroizeOnDrop>` holds one value in its own locked page
  mapping, built on `Region`, so the fork handling is one code path.
  - It is instantiated only for `ml_dsa::ExpandedSigningKey<P>`, which is inline: checked in
    `ml-dsa 0.1.1 signing.rs:235-248`. `SigningKey` and `VerifyingKey` are not inline (they use
    `MaybeBox`), so they are not cached this way.
  - A counting-allocator test checks that sealing leaves no heap block.
- **Budget.** A process-wide cap at 50 % of `RLIMIT_MEMLOCK`, with no eviction. Past the cap,
  signing parses per call as today. The other half always stays free for key material, so
  `require_locked_memory` never starts failing because of the cache. A counter makes the cap
  visible.
- **Under `require_locked_memory`,** a key that cannot be sealed is not cached; signing still
  works.
- **Expected:** ML-DSA signing 1.5× faster; ML-DSA-87 sign stack 507 → ~120 KiB, so it runs
  inline on a 512 KiB macOS thread (no helper-thread hop). Re-measure the stack budgets: the
  first sign per key still needs the old depth.
- **Remaining gap** (DEVIATIONS): `from_seed` leaves one unwiped stack copy at construction,
  once per key instead of on every call as today.

## Deferred: measure first after phase 1–3

- **arc-swap read-mostly maps (F7, stage 2).** Only if `--only contention` still shows lock
  bouncing after `Arc<Key>`.
- **Platform userspace randomness on macOS (F5).** `CCRandomGenerateBytes` would save ~1 µs on
  macOS only and needs a security review. Linux already gets vDSO `getrandom` on current
  glibc and kernels. No own DRBG (fork, VM snapshots).
- **Fork detection without `getpid` (F5).** A per-context `MADV_WIPEONFORK` mark saves 0.05–0.19
  µs on Linux, at the cost of new unsafe code. Not worth it now.
- **Binary size (F11).** A prost-binary catalog and Cargo features per algorithm family, only if
  size matters to clients.

## Decided points of contention

- **`Plan<'o, R>` op object vs the `*_admitting` closure.** Closure: it is the existing idiom and
  needs no lifetimes on the orchestrator's types.
- **CBC: padding first vs decrypt all, then wipe on failure.** Padding first: "written on success
  only" holds, and the timing difference reveals nothing the error code does not already reveal.
  CBC and CTR stay unauthenticated (DEVIATIONS: use an external MAC).
- **Secret cache for Ed25519/ECDSA.** None. Hazmat signing with a cached, derived public key
  keeps their secrets in `SecretBytes` only.
- **Generic `unsafe trait InlineSecret` vs one sealed type.** `Sealed<T>`, used for one type
  family, with one SAFETY argument.
- **An LRU for caches.** No: it means bookkeeping on the hot path and re-parse jitter. A cap
  without eviction instead.
