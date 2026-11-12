# Issues for the citius-c-api header owners

From the Rust implementation of the C API (`agilecrypto`, github.ibm.com/citius/rust-api).
The library now exports all 212 functions the headers declare, and the build checks each
against its header signature. Everything below was found while doing that against:

- **Headers:** citius-c-api `main` at `0857bea`, the merge of PR #1 (caller-allocated outputs). Its headers are identical to `340e0f1`, the tip of `refactor/caller-allocated-only`.
- **Descriptor:** `conformance/api_descriptor.binpb` at the same commit.
- **Go code:** citius-core `755b8a9`, citius-server `08bfab4`, citius-api-go `v0.3.0`.

Ordered by impact. Each issue lists the evidence and a concrete proposal. The rust-api
column in `DEVIATIONS.md` gives our interim behaviour.

## 1. The pinned API is behind Go for digest signing (high)

**What.** Go has two proto fields that the pinned descriptor and the C headers lack:

| Field | Message | Go definition (citius-api-go v0.3.0) |
|---|---|---|
| `accepted_digest_hashes` (5, repeated `HashAlgorithm`) | `SignatureScopeSpec` | Hashes a prehashed scope accepts, in order of preference |
| `digest_hash` (5, `HashAlgorithm`) | `OperationMetadata` | The hash that produced a DigestSign digest; DigestVerify reads it from here |

citius-core uses both:
- `CreateKey` / `TransformKey` record the accepted list per key version: the template's list, optionally narrowed by the request.
- `DigestSign` refuses any other hash with `InvalidArgument`.
- `DigestVerify` takes the hash from the metadata, not from the request.

**Why it matters.**
- **Interoperability.** Metadata produced by the Go server's DigestSign does not decode under the pinned C contract. A strict decoder sees field 5 as unknown and must reject it (`agc_metadata_decode` is strict canonical). Our Go interop check confirms this: Rust refuses every DigestSign metadata blob Go produces.
- **Semantics.** C callers cannot read which hashes a key accepts, cannot narrow the list when creating a key, and have to pass `hash_algorithm` again to `agc_digest_verify`. In Go, that value comes from the signing metadata.

**Proposal.** Re-pin the descriptor to include both fields, then:
- **`agc_signature_scope_spec`:** add `const agc_hash_algorithm *accepted_digest_hashes; size_t accepted_digest_hashes_count;`, appended per the `struct_size` rules. It is an input on `agc_create_key_params` / `agc_transform_key_params`, and an output in `agc_key_info` and `agc_template_info`.
- **`agc_metadata`:** add `agc_hash_algorithm digest_hash;`, appended.
- **WIRE_V1 cannot carry it.** The body header (`representing_metadata.md` §6.2) has no slot, and §6.7 rules out growth within v1 by design. So a digest-signing metadata needs either:
  - a new `agc_encoding` value (a WIRE_V2 with a `digest_hash` byte), or
  - a rule that WIRE_V1 cannot encode digest-signing metadata, and encoding it fails (as for an inexpressible `encoding` token today).
- **`agc_digest_verify_request.hash_algorithm`:** decide whether it stays required (and must equal the metadata's value) or becomes optional when metadata is given. Go uses only the metadata.

**Status: done, in a bump to api v0.3.0.** The descriptor is pinned to `citius/api` v0.3.0 and the headers mirror it. (This was briefly numbered C API 2.0; before the first public release the version was reset to 1.0.)
- The digest-hash fields are in `agc_signature_scope_spec` and `agc_metadata`.
- `agc_digest_verify` takes the hash from the metadata.
- WIRE_V1 cannot carry `digest_hash` (DV-15), so digest signing requires PROTOBUF.

citius-rust records each key version's accepted hashes, from the v0.3.0 catalog. Go's DigestSign metadata now decodes, as the interop check confirms.

## 2. No configuration field for a persistent key store (high)

**What.** `agc_ctx_config` has `catalog_path` and `provider_config_path`, but nothing names where keys live. In EMBEDDED mode, a context's keys exist only in memory and are lost on `agc_ctx_close`. That's unusable for production.

**Proposal.** Append `agc_str key_store_uri;` to `agc_ctx_config`. NULL means in-memory, as today. A `file:` URI names a directory owned by the library. Other schemes are reserved and rejected with `AGC_ERR_NOT_IMPLEMENTED`.

Open points for you:
- How a process using two contexts on one store is expected to behave. Our proposal is single-writer, refusing with an error on contention.
- Whether at-rest protection of stored material (a wrapping key source) belongs in the same struct or in a follow-up.

No file-backed key repository exists yet; only the in-memory one does. (An earlier version of this note said one was ready. That was wrong.)

**Status: header field added** in citius-c-api `main` (PR #2, `6094f00`). citius-rust reads it and refuses every non-NULL value with `AGC_ERR_NOT_IMPLEMENTED` until at-rest protection is agreed (C7).

## 3. Asymmetric-encryption scope: defined in C and proto, unsupported in Go (medium)

**What.**
- **Defined:** `agc_scope.h` defines `AGC_SCOPE_KIND_ASYMMETRIC_ENCRYPTION` (12) and `agc_asymmetric_encryption_scope_spec`. The proto defines `AsymmetricEncryptionScope` (STANDARD, RAW).
- **Unsupported:** Go's `core.Scope` has no such scope, and `extractProtoScopeSpec` handles 11 of the 12 oneof arms. A spec of this kind fails with `InvalidArgument` ("unrecognized scope").
- **Unused:** no catalog template uses it.

**Why it matters.** A C caller sees a documented scope kind that every implementation refuses.

**Proposal.** Decide with the Go owners. Either:
- (a) Go adds the scope, which needs a template and provider work; or
- (b) the headers mark the kind reserved / not yet supported, so the refusal is documented rather than surprising.

**Status: done, option (b).** citius-c-api `main` (PR #2, `6094f00`) marks the kind reserved. citius-rust refuses it with `AGC_ERR_INVALID_ARGUMENT`, as Go does (G31).

## 4. Fork handling: the header prescribes a mechanism, not a behaviour (low)

**What.** `agc_core.h` FORK says "the library installs a `pthread_atfork` handler that marks every open context POISONED in the child". That fixes an implementation: a global registry of open contexts, plus work done inside the atfork handler, where very little is async-signal-safe.

**Proposal.** State the observable contract only:
- in a forked child, every call on an inherited context fails with `AGC_ERR_INVALID_HANDLE`;
- `agc_ctx_reinit_after_fork` yields a fresh context from the same configuration.

**Status: done.** citius-c-api `main` (PR #2, `6094f00`) states the contract and leaves the mechanism unspecified. citius-rust records the pid that opened each context and compares it on every call; a C test with a real `fork()` covers it.

## 5. `agc_ctx_config` fields that no implementation honours yet (low)

**What.** Our rule is that an unhonoured setting is refused, never silently ignored. Accepting one would promise a guarantee the library does not give. These are refused with `AGC_ERR_NOT_IMPLEMENTED`:
- `fips_mode`: no FIPS-validated provider exists in EMBEDDED mode.
- `catalog_path`: the catalog is compiled in.
- `provider_config_path`: providers are not configurable.
- `require_locked_memory`: key material is not yet held in locked memory.

**Status: done.** citius-c-api `main` (PR #2, `6094f00`) states, at `agc_ctx_open`, that a setting the build cannot honour is refused with `AGC_ERR_NOT_IMPLEMENTED`, never ignored.

---

## Not issues, for the record

- **`agc_poly1305_params` with only `reserved`** is correct. The pinned `Poly1305Params` has no fields, and C has no empty structs. (We briefly reported this as a defect; it was our misreading.)
- **Header names that differ from the proto's enum prefix**, e.g. `AGC_ML_KEM_768` for `ML_KEM_PARAMETER_SET_ML_KEM_768`. The values agree, and the generated name helpers round-trip, so this is cosmetic.
