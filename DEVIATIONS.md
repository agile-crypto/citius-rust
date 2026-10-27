# Deliberate deviations

Every place this library knowingly differs from the Go implementation
(citius-core / citius-server) or from the C stub in citius-c-api, with the
reason. Anything that differs and is not listed here is a bug.

## From the Go implementation

| # | Go | Here | Why |
|---|---|---|---|
| G1 | Orchestrators, repositories and the policy engine are built per request by factories. | Built once per `agc_ctx`, shared through `Arc`; the context is used concurrently. | A library has no requests; the deck's verdict (slides 36, 41). Go's per-request repository lock serialised nothing. |
| G2 | One error type maps to gRPC status in `ToStatusError`; `errors` imports gRPC codes. | `domain::core::Error` knows no transport; `ffi/error.rs` alone maps to `agc_rc`. | Keeps the domain free of the C boundary, as Go intends but does not achieve. |
| G3 | Domain `Code` has 14 values; several C-distinct cases share one. | `Code` is as fine as the C error set needs, e.g. `NoMatchingTemplate` vs `TemplateNotFound`. | The C API reports these separately. |
| G4 | `template.Registry.Select` documents "first matching active template" but does not filter by status. | Selection skips inactive templates. | Implements the documented contract. |

## From the C stub (citius-c-api/src)

| # | Stub | Here | Why |
|---|---|---|---|
| C1 | `agc_rc_message` returns "unknown result code" for every `AGC_ERR_CRYPTO_*` code. | Crypto codes get their name in words, e.g. "key not found". | A defined code is not unknown. Local codes keep the header's text. |
| C2 | A panic does not exist in C. | A panic inside any export is caught and returned as `AGC_ERR_INTERNAL`; state behind a lock it poisoned fails closed from then on. | Never unwind into C, never abort the host. |
| C3 | `agc_secure_alloc` is `malloc` + best-effort `mlock`; `agc_secure_free` zeroes `n` bytes and `munlock`s. | Each allocation is its own page-aligned anonymous mapping: locked (best effort), excluded from core dumps on Linux, the whole mapping zeroed and unmapped on free regardless of `n`. | `munlock` on a malloc'd block unlocks every other secret sharing its pages, and freed heap pages are reused; trusting `n` could leave a secret's tail behind. |
| C4 | `require_locked_memory` is honoured by probing `mlock` at `agc_ctx_open`. | `agc_ctx_open` returns `AGC_ERR_NOT_IMPLEMENTED` for it until key material is held in locked memory. | Accepting the flag would promise a protection the library does not yet give. |
