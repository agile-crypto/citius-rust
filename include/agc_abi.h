/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_abi.h — Abstract Cryptographic API, C binding: ABI infrastructure.
 *
 * HAND-WRITTEN. Never generated. This is the small, stable set of macros every
 * other header depends on: symbol visibility, the version constants, and (from
 * commit 3 onward) the scalar and presence types that have no protobuf source
 * of their own (agc_slice, agc_buf, agc_tribool, ...).
 *
 * Kept separate from agc_types.h so that the "GENERATED — DO NOT EDIT" banner
 * on agc_types.h is actually true. Mixing hand-written scalar idioms into a
 * generated vocabulary file is how that banner stops being trustworthy — see
 * RECONCILIATION_PLAN.md §9 and C_API_COMPARISON.md finding B1.
 */

#ifndef AGC_ABI_H
#define AGC_ABI_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Buffer-length bounds
 * -------------------------------------------------------------------------- */

#define AGC_API_VERSION_MAX_LEN     8      /* "{0..255}.{0..255}" + NUL */
#define AGC_OUTPUT_ENCODING_MAX_LEN 16     /* output encoding token + NUL: "raw", "der", "jws", "cbor" */
/* NUL-terminated provider identifier capacity in responses that name the
 * provider that served a request. */
#define AGC_PROVIDER_ID_MAX         64
#define AGC_TEMPLATE_ID_MAX         64
/* --------------------------------------------------------------------------
 * ABI / API version
 * -------------------------------------------------------------------------- */

#define AGC_API_VERSION_MAJOR 1
#define AGC_API_VERSION_MINOR 0
#define AGC_API_VERSION_PATCH 0

/* Matches OperationMetadata.api_version ("major.minor"). */
#define AGC_API_VERSION_STRING "1.0"

#if defined(_WIN32)
#  if defined(AGC_BUILDING_DLL)
#    define AGC_API __declspec(dllexport)
#  elif !defined(AGC_STATIC)
#    define AGC_API __declspec(dllimport)
#  else
#    define AGC_API
#  endif
#else
#  define AGC_API __attribute__((visibility("default")))
#endif

/* Forces int32 storage for every enum regardless of -fshort-enums, so the C
 * enum width matches the protobuf wire type on every conforming compiler.
 * Used by every generated enum in agc_types.h. */
#define AGC_ENUM32(n) , n##_FORCE32 = 0x7fffffff

/* Every struct passed by pointer begins with `size_t struct_size`. Callers
 * MUST set it to sizeof(the struct they compiled against); the library uses
 * it to decide which trailing fields are present. This is the C substitute
 * for protobuf's free forward compatibility (RECONCILIATION_PLAN.md D7): a
 * caller built against 1.0 passing a smaller struct to a 1.1 library gets
 * defaults for the tail; a 1.1 caller passing a larger struct to a 1.0
 * library gets AGC_ERR_ABI_MISMATCH rather than a misread field. */
#define AGC_INIT(p) \
    do { memset((p), 0, sizeof(*(p))); (p)->struct_size = sizeof(*(p)); } while (0)

/* True if `field` lies entirely within the first `(p)->struct_size` bytes of
 * *p. The library uses this before writing any field of a versioned OUTPUT
 * struct, so a caller compiled against an older (smaller) header never has a
 * value written past the tail of the struct they actually allocated -- the
 * other half of the AGC_INIT contract (D7): an old caller gets defaults
 * (here: simply un-written, still-zeroed-by-them fields) for a field a newer
 * library knows about but the old header didn't declare. */
#define AGC_FIELD_FITS(p, field) \
    (offsetof(__typeof__(*(p)), field) + sizeof((p)->field) <= (p)->struct_size)


/* --------------------------------------------------------------------------
 * Presence: three-valued booleans
 *
 * proto3 `optional bool` is a THREE-valued type: absent / false / true, and
 * absence is semantically load-bearing throughout this API -- in a request an
 * absent filter means "don't care", while `false` means "must NOT have this
 * property". Collapsing it to C `bool` would silently turn every "don't care"
 * into a hard "must be false" (RECONCILIATION_PLAN.md D8; this is precisely
 * the bug in the citius_* draft's own shipped example, C_API_COMPARISON.md
 * finding A4).
 *
 * AGC_UNSET == 0 so a zeroed struct means "no filters", which is the safe
 * default a caller gets from AGC_INIT() without having to set anything.
 * -------------------------------------------------------------------------- */

typedef enum agc_tribool {
    AGC_UNSET = 0,   /* proto field absent */
    AGC_FALSE = 1,   /* proto field present, value false */
    AGC_TRUE  = 2    /* proto field present, value true  */
    AGC_ENUM32(agc_tribool)
} agc_tribool;

/* --------------------------------------------------------------------------
 * Scalar value types
 * -------------------------------------------------------------------------- */

/* Borrowed, immutable byte range. Maps proto `bytes` in the INPUT direction.
 * Never owns memory; never freed. A zero-length slice with data == NULL is
 * the canonical "empty bytes" and is distinct from absence (see
 * agc_optional_slice). */
typedef struct agc_slice {
    const uint8_t *data;
    size_t         len;
} agc_slice;

/* Explicit-presence bytes. Required wherever the proto uses `optional bytes`
 * and distinguishes absent from empty -- HkdfOperationParams.salt,
 * Pbkdf2OperationParams.salt and Argon2OperationParams.salt, where absent
 * means "server generates a random salt" (RFC 5869 §2.2 for HKDF) and empty
 * means an intentional all-zero-length salt. A single agc_slice{NULL,0}
 * cannot distinguish these; collapsing them turns a deterministic derivation
 * into a random one, or vice versa, silently. */
typedef struct agc_optional_slice {
    agc_slice slice;
    int       present;   /* 0 = absent, non-zero = present (possibly empty) */
} agc_optional_slice;

/* Mutable, caller-owned output region. Maps proto `bytes` in the OUTPUT
 * direction under the two-call size-query convention: pass data = NULL to
 * learn the required length in *out_len, then call again with a buffer of
 * that size. The library never allocates a buffer the caller frees with
 * free() -- allocator symmetry across a shared-library boundary, and the
 * caller alone decides when a plaintext is erased. */
typedef struct agc_buf {
    uint8_t *data;      /* NULL => size query */
    size_t   cap;       /* capacity of data in bytes */
} agc_buf;

/* Borrowed, immutable NUL-terminated UTF-8 string. Maps proto `string`. */
typedef const char *agc_str;

/* One entry of a proto map<string, string>. */
typedef struct agc_kv {
    agc_str key;
    agc_str value;
} agc_kv;

/* A proto map<string, string> as a flat array. Order is not significant and
 * is not preserved across a round trip through the wire format. Duplicate
 * keys are rejected with AGC_ERR_INVALID_ARGUMENT. */
typedef struct agc_kv_list {
    const agc_kv *items;
    size_t        count;
} agc_kv_list;

/* One entry of a proto map<string, bytes> (VendorOutput.parameters,
 * NoAlgorithmOutput.parameters). */
typedef struct agc_kb {
    agc_str   key;
    agc_slice value;
} agc_kb;

typedef struct agc_kb_list {
    const agc_kb *items;
    size_t        count;
} agc_kb_list;

/* Borrowed array of NUL-terminated strings. Maps proto `repeated string`. */
typedef struct agc_str_list {
    const agc_str *items;
    size_t         count;
} agc_str_list;

/* google.protobuf.Timestamp with explicit presence. time_t is deliberately
 * avoided: it is 32-bit on some targets and Timestamp fields here
 * (KeyMetadata.created_time, Fips140Certification.validation_date, ...) are
 * `optional` on the wire, so presence must be representable independent of
 * the value. */
typedef struct agc_timestamp {
    int64_t seconds;    /* seconds since 1970-01-01T00:00:00Z */
    int32_t nanos;      /* [0, 999999999] */
    int     present;    /* 0 = field absent */
} agc_timestamp;

#ifdef __cplusplus
}
#endif
#endif /* AGC_ABI_H */
