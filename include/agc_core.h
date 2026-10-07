/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_core.h — Abstract Cryptographic API, C binding: core runtime.
 *
 * HAND-WRITTEN. Defines the idioms the rest of the C binding is built from:
 * the context, errors, sessions, and the opaque handles that later headers
 * (agc_key.h, agc_crypto.h, ...) attach accessors to as their own commits
 * land. See RECONCILIATION_PLAN.md §1 (D1-D20) for the rationale behind
 * every convention below.
 *
 * THE CONVENTIONS
 * ----------------
 * 1. Every call returns agc_rc. AGC_OK == 0. Nothing else is a success.
 * 2. Every byte output uses the two-call convention (agc_buf, agc_abi.h).
 *    The library never allocates a buffer the caller frees with free().
 * 3. Every rich message output is an opaque handle with typed accessors,
 *    freed with its own agc_*_free. Deep aggregate structs never cross the
 *    ABI (D6) — that is what keeps the algorithm catalog out of the ABI.
 * 4. Every struct passed by pointer begins with `size_t struct_size`. Use
 *    AGC_INIT() to zero it and set the size.
 * 5. Nothing in this API allocates on the caller's allocator or frees on it.
 *
 * THREADING
 * ---------
 * agc_ctx is thread-safe: any number of threads may issue operations on one
 * context concurrently. agc_session (a streaming operation) is NOT
 * thread-safe and must be confined to one thread at a time, exactly as a
 * PKCS#11 session without CKF_OS_LOCKING_OK. Handles obtained from a context
 * become invalid when that context is closed.
 *
 * FORK
 * ----
 * After fork(2) the child MUST NOT use any handle inherited from the parent.
 * The library installs a pthread_atfork handler that marks every open
 * context POISONED in the child; operations on a poisoned context fail with
 * AGC_ERR_INVALID_HANDLE rather than silently reusing state the parent also
 * holds. Call agc_ctx_reinit_after_fork() in the child to obtain a fresh,
 * usable context built from the same configuration.
 *
 * DEPLOYMENT MODE
 * ----------------
 * This reconciliation implements AGC_MODE_EMBEDDED only: direct calls into
 * the in-process stub backend (src/stub/, wired in from commit 8 onward). No
 * transport exists for AGC_MODE_LOCAL/AGC_MODE_REMOTE in this tree;
 * agc_ctx_open() returns AGC_ERR_NOT_IMPLEMENTED for them. The design is
 * still mode-shaped (D13): a later transport layer plugs in at
 * agc_ctx_open() without changing any call site, which is the entire point
 * of making mode a context property rather than a compile-time choice.
 */

#ifndef AGC_CORE_H
#define AGC_CORE_H

#include "agc_abi.h"
#include "agc_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Opaque handles
 *
 * Forward-declared here even though most gain accessors only once their
 * owning commit lands (agc_metadata: commit 6; agc_key_info and the
 * migration/feasibility reports: commit 7; agc_impl_props, agc_template_info,
 * agc_scope_info: commit 11; agc_policy_decision: commit 11) — every service
 * header needs to name these as pointer types before then.
 * -------------------------------------------------------------------------- */

/* The service surface. One context binds a policy engine, a template
 * catalog and a set of provider instances. It is the C analogue of "a
 * connection to the service", except that in AGC_MODE_EMBEDDED there is no
 * connection: calls are direct function calls into the stub backend. */
typedef struct agc_ctx agc_ctx;

/* A stateful multi-part or message-based operation. Replaces the proto's
 * request-supplied `operation_id` string as the primary handle in this local
 * API; the string form is still available via agc_session_id() (and
 * accepted as an optional caller-supplied id at Init, matching the proto)
 * for cross-process correlation and for relaying a session elsewhere. */
typedef struct agc_session agc_session;

/* OperationMetadata is NOT an opaque handle any more: it is the
 * caller-allocated struct defined in agc_metadata.h, and operations return
 * it encoded into caller regions. This forward declaration remains only so
 * that headers not yet converted (agc_stream.h, agc_establish.h; see
 * docs/implementation_progress.md) still parse. */
typedef struct agc_metadata agc_metadata;

typedef struct agc_scope_info agc_scope_info;


/* Iterator cursors. Each hides paging bookkeeping (D12). */
typedef struct agc_key_iter               agc_key_iter;
typedef struct agc_template_iter          agc_template_iter;
typedef struct agc_policy_iter            agc_policy_iter;
typedef struct agc_provider_iter          agc_provider_iter;
typedef struct agc_provider_instance_iter agc_provider_instance_iter;

/* --------------------------------------------------------------------------
 * Library lifecycle
 * -------------------------------------------------------------------------- */

AGC_API void         agc_version(int *major, int *minor, int *patch);
AGC_API const char  *agc_version_string(void);
AGC_API const char  *agc_build_info(void);

/* --------------------------------------------------------------------------
 * Context
 * -------------------------------------------------------------------------- */

typedef enum agc_mode {
    AGC_MODE_EMBEDDED = 0,  /* direct function calls; no serialisation, no IPC */
    AGC_MODE_LOCAL    = 1,  /* same host, out-of-process -- NOT IMPLEMENTED here */
    AGC_MODE_REMOTE   = 2   /* networked service (gRPC) -- NOT IMPLEMENTED here */
    AGC_ENUM32(agc_mode)
} agc_mode;

typedef struct agc_ctx_config {
    size_t   struct_size;

    agc_mode mode;

    /* AGC_MODE_LOCAL / AGC_MODE_REMOTE: endpoint URI. Unused in EMBEDDED. */
    agc_str  endpoint;

    /* Path to the template catalog. NULL uses the catalog compiled into the
     * library (commit 11). */
    agc_str  catalog_path;

    /* Default policy name applied when a call does not name one. May be
     * NULL, in which case operations that require a policy must name one
     * explicitly. */
    agc_str  default_policy;

    /* Provider instance configuration source. NULL uses the built-in stub
     * provider only. */
    agc_str  provider_config_path;

    /* Idle TTL, in seconds, after which a streaming session is expired and
     * its state zeroized. 0 selects the implementation default. */
    uint32_t session_idle_ttl_seconds;

    /* If non-zero, the library attempts to mlock() key material and
     * streaming state, and fails context creation if it cannot. */
    int      require_locked_memory;

    /* If non-zero, only FIPS-validated providers are eligible, regardless
     * of per-request ProviderRequirements. */
    int      fips_mode;

    /* Opaque caller identity forwarded to the policy engine for
     * authorization. In EMBEDDED mode this is the process's own credential
     * material. */
    agc_slice caller_identity;
} agc_ctx_config;

/* All agc_str/agc_slice fields of *cfg are copied; the caller need not keep
 * them alive past this call. Returns AGC_ERR_NOT_IMPLEMENTED for
 * AGC_MODE_LOCAL/AGC_MODE_REMOTE in this build. */
AGC_API agc_rc agc_ctx_open(const agc_ctx_config *cfg, agc_ctx **out_ctx);

/* Destroys the context. All handles derived from it become invalid. Any
 * outstanding session is cancelled and its state zeroized. Idempotent on
 * NULL. */
AGC_API void   agc_ctx_close(agc_ctx *ctx);

/* Re-establishes a usable context in a forked child. The inherited context
 * is closed; a fresh one is opened from the same configuration. Fails with
 * AGC_ERR_INVALID_ARGUMENT if `poisoned` was not actually poisoned (i.e. was
 * never forked, or belongs to a different process). */
AGC_API agc_rc agc_ctx_reinit_after_fork(agc_ctx *poisoned, agc_ctx **out_ctx);

/* Returns the mode this context was opened in. */
AGC_API agc_mode agc_ctx_mode(const agc_ctx *ctx);

/* --------------------------------------------------------------------------
 * Errors
 * -------------------------------------------------------------------------- */

typedef struct agc_error_detail {
    size_t      struct_size;
    agc_rc      rc;
    const char *message;        /* NUL-terminated, thread-local storage */
    const char *domain;         /* "caas.crypto.v1" for generated codes */
    const char *reason;         /* e.g. "CRYPTO_ERROR_KEY_NOT_FOUND" */
    const char *provider_id;    /* provider that produced the failure, or NULL */
    int64_t     provider_code;  /* native provider code */
    const char *failed_check;   /* policy: which check denied the operation */
} agc_error_detail;

/* Fills *out with the detail for the last failing call on THIS thread. The
 * string pointers remain valid until the next failing call on this thread.
 * Returns AGC_OK even when there is no error recorded (rc field will be
 * AGC_OK and every string NULL). */
AGC_API agc_rc agc_last_error(agc_error_detail *out);

/* Clears the thread-local error record. */
AGC_API void   agc_clear_error(void);

/* --------------------------------------------------------------------------
 * Memory hygiene
 * -------------------------------------------------------------------------- */

/* Erases n bytes at p. Not elided by the optimiser (implemented via a
 * volatile-pointer write loop, which the C standard guarantees is an
 * observable side effect the compiler cannot remove). */
AGC_API void agc_secure_zero(void *p, size_t n);

/* Constant-time (in structure, not a hardware guarantee) comparison. Returns
 * 1 if equal, 0 otherwise. Callers verifying a MAC or signature out-of-band
 * must use this rather than memcmp. */
AGC_API int  agc_ct_equal(const void *a, const void *b, size_t n);

/* Page-locked allocation for sensitive buffers (mlock, best-effort: returns
 * a normal allocation if locking is unavailable and require_locked_memory
 * was not requested on the context that will use it). agc_secure_free
 * zeroizes before releasing. Returns NULL on failure. */
AGC_API void *agc_secure_alloc(size_t n);
AGC_API void  agc_secure_free(void *p, size_t n);

/* --------------------------------------------------------------------------
 * OperationMetadata
 *
 * Moved to agc_metadata.h as a caller-allocated struct with two byte
 * encodings. The former opaque handle, its agc_metadata_free/new and its
 * accessors are gone (docs/representing_metadata.md, docs/agc_crypto.md).
 * Only the algorithm-output discriminant stays here because agc_metadata.h
 * and every service header need it.
 * -------------------------------------------------------------------------- */

/* Tag values are the proto field numbers of ProviderOutput.algorithm_output
 * (10-16), verified against the pinned descriptor by
 * conformance/tier1c_oneof_tags.py. AGC_ALGORITHM_OUTPUT_NONE (0) is the
 * "oneof unset" sentinel: it never appears in metadata a caller can hold --
 * an unset oneof is a provider bug and is rejected with
 * AGC_ERR_PROVIDER_CONTRACT_VIOLATION. A value this header does not name is
 * rejected by agc_metadata_decode() (agc_metadata.h, contract point 7). */
typedef enum agc_algorithm_output_kind {
    AGC_ALGORITHM_OUTPUT_NONE          = 0,   /* provider bug: oneof unset */
    AGC_ALGORITHM_OUTPUT_NO_OUTPUT     = 10,  /* explicit "no system-generated params" */
    AGC_ALGORITHM_OUTPUT_AEAD          = 11,
    AGC_ALGORITHM_OUTPUT_BLOCK_CIPHER  = 12,
    AGC_ALGORITHM_OUTPUT_COUNTER_MODE  = 13,
    AGC_ALGORITHM_OUTPUT_STREAM_CIPHER = 14,
    AGC_ALGORITHM_OUTPUT_KDF           = 15,
    AGC_ALGORITHM_OUTPUT_VENDOR        = 16
    AGC_ENUM32(agc_algorithm_output_kind)
} agc_algorithm_output_kind;

/* --------------------------------------------------------------------------
 * Sessions (StreamingCryptoService, commit 9)
 * -------------------------------------------------------------------------- */

/* The (client-supplied or library-generated) operation_id backing this
 * session. Needed only when relaying a session across a process boundary or
 * correlating with audit logs. */
AGC_API const char *agc_session_id(const agc_session *s);

/* Which operation this session performs, for defensive assertions. */
AGC_API agc_crypto_operation agc_session_operation(const agc_session *s);

/* Template the service selected for this session, when the session was
 * opened by intent rather than by key (DigestInit, XofInit). NULL
 * otherwise. */
AGC_API const char *agc_session_selected_template_id(const agc_session *s);

/* Aborts a session and releases all state (CancelOperation-shaped, though
 * CancelOperation itself is not an RPC -- see docs/PROTO_RFCS.md RFC-14).
 * Idempotent; cancelling an unknown or already-closed session succeeds.
 * `reason` may be NULL. The handle is invalid afterwards. */
AGC_API agc_rc agc_session_cancel(agc_session *s, const char *reason);

/* Releases the handle. If the session is still open it is cancelled first,
 * so an early return from a function cannot leak provider state. */
AGC_API void   agc_session_free(agc_session *s);

/* Adopts a session created elsewhere by its operation_id. Fails with
 * AGC_ERR_CRYPTO_OPERATION_EXPIRED if unknown. */
AGC_API agc_rc agc_session_attach(agc_ctx *ctx, const char *operation_id,
                                   agc_session **out_session);

#ifdef __cplusplus
}
#endif
#endif /* AGC_CORE_H */
