/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_scope.h — Abstract Cryptographic API, C binding: ScopeSpecification.
 *
 * HAND-WRITTEN. Depends on agc_types.h for the 12 generated per-primitive
 * scope enums and agc_fips140_level; the value structs here (and the tag
 * enum agc_scope_kind) have no generator behind them because a oneof has no
 * EnumDescriptorProto of its own — the "tag == proto field number" mapping
 * below is a hand-derived convention, cross-checked against the pinned
 * descriptor by conformance/tier1c_oneof_tags.py rather than left to eyeball
 * review (see RECONCILIATION_PLAN.md §2.5, §4 DV entries, and the "oneof tag
 * numbers" caution in that plan review section).
 *
 * ScopeSpecification is used with a DUAL INTERPRETATION, preserved exactly:
 * the same agc_scope_spec is a *requirement filter* in a request (properties
 * are minima) and a *capability declaration* inside a TemplateInfo (§2.7 of
 * the plan). One type, not two that must be kept in sync.
 */

#ifndef AGC_SCOPE_H
#define AGC_SCOPE_H

#include "agc_abi.h"
#include "agc_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* UniversalSecurityProperties (api/types/common.proto). Dual-interpretation
 * as above: minima in a request, provided characteristics in a template.
 * Never passed by pointer on its own (only embedded in a *ScopeSpec, which is
 * itself embedded in agc_scope_spec), so it does not carry its own
 * struct_size — the outer agc_scope_spec.struct_size is what a 1.0/1.1
 * mismatch is checked against (D7). */
typedef struct agc_security_properties {
    uint32_t                security_strength_bits;  /* 0 = unspecified */
    agc_nist_security_level nist_security_level;
    agc_tribool             quantum_safe;
    agc_nist_status         nist_status;
    agc_tribool             fips_approved;
} agc_security_properties;

/* ==========================================================================
 * The 12 *ScopeSpec messages (api/types/common.proto)
 * ========================================================================== */

typedef struct agc_signature_scope_spec {
    agc_signature_scope     scope;
    agc_security_properties security;
    agc_tribool             non_malleable;
    agc_tribool             deterministic;
    agc_kv_list             additional_properties;
} agc_signature_scope_spec;

typedef struct agc_aead_scope_spec {
    agc_aead_scope          scope;
    agc_security_properties security;
    agc_tribool             nonce_misuse_resistant;
    agc_kv_list             additional_properties;
} agc_aead_scope_spec;

typedef struct agc_mac_scope_spec {
    agc_mac_scope           scope;
    agc_security_properties security;
    agc_kv_list             additional_properties;
} agc_mac_scope_spec;

typedef struct agc_kem_scope_spec {
    agc_kem_scope           scope;
    agc_security_properties security;
    agc_kv_list             additional_properties;
} agc_kem_scope_spec;

typedef struct agc_key_agreement_scope_spec {
    agc_key_agreement_scope scope;
    agc_security_properties security;
    agc_tribool             forward_secrecy;
    agc_kv_list             additional_properties;
} agc_key_agreement_scope_spec;

typedef struct agc_kdf_scope_spec {
    agc_kdf_scope           scope;
    agc_security_properties security;
    agc_tribool             memory_hard;
    agc_kv_list             additional_properties;
} agc_kdf_scope_spec;

typedef struct agc_hash_scope_spec {
    agc_hash_scope          scope;
    agc_security_properties security;
    agc_kv_list             additional_properties;
} agc_hash_scope_spec;

typedef struct agc_key_wrapping_scope_spec {
    agc_key_wrapping_scope  scope;
    agc_security_properties security;
    agc_kv_list             additional_properties;
} agc_key_wrapping_scope_spec;

typedef struct agc_symmetric_cipher_scope_spec {
    agc_symmetric_cipher_scope scope;
    agc_security_properties    security;
    agc_kv_list                additional_properties;
} agc_symmetric_cipher_scope_spec;

typedef struct agc_disk_encryption_scope_spec {
    agc_disk_encryption_scope scope;
    agc_security_properties   security;
    agc_kv_list               additional_properties;
} agc_disk_encryption_scope_spec;

typedef struct agc_generic_secret_scope_spec {
    agc_generic_secret_scope scope;
    agc_security_properties  security;
    agc_kv_list              additional_properties;
} agc_generic_secret_scope_spec;

typedef struct agc_asymmetric_encryption_scope_spec {
    agc_asymmetric_encryption_scope scope;
    agc_security_properties         security;
    agc_kv_list                     additional_properties;
} agc_asymmetric_encryption_scope_spec;

/* ==========================================================================
 * ScopeSpecification (api/types/common.proto) — the central type
 * ========================================================================== */

/* Discriminant for the ScopeSpecification oneof. VALUES ARE THE PROTO FIELD
 * NUMBERS of the oneof arms (verified against api/types/common.proto and
 * cross-checked by conformance/tier1c_oneof_tags.py), not an independent
 * enum: a wire encoder can use the tag directly, and reordering the proto
 * arms is caught by that check rather than only by eyeball review. */
typedef enum agc_scope_kind {
    AGC_SCOPE_KIND_NONE                  = 0,
    AGC_SCOPE_KIND_SIGNATURE             = 1,
    AGC_SCOPE_KIND_AEAD                  = 2,
    AGC_SCOPE_KIND_MAC                   = 3,
    AGC_SCOPE_KIND_KEM                   = 4,
    AGC_SCOPE_KIND_KEY_AGREEMENT         = 5,
    AGC_SCOPE_KIND_KDF                   = 6,
    AGC_SCOPE_KIND_HASH                  = 7,
    AGC_SCOPE_KIND_KEY_WRAPPING          = 8,
    AGC_SCOPE_KIND_SYMMETRIC_CIPHER      = 9,
    AGC_SCOPE_KIND_GENERIC_SECRET        = 10,
    AGC_SCOPE_KIND_DISK_ENCRYPTION       = 11,
    AGC_SCOPE_KIND_ASYMMETRIC_ENCRYPTION = 12
    AGC_ENUM32(agc_scope_kind)
} agc_scope_kind;

/* kind == AGC_SCOPE_KIND_NONE is rejected wherever the proto marks the oneof
 * required (buf.validate.oneof.required = true). */
typedef struct agc_scope_spec {
    size_t         struct_size;
    agc_scope_kind kind;
    union {
        agc_signature_scope_spec             signature;
        agc_aead_scope_spec                  aead;
        agc_mac_scope_spec                   mac;
        agc_kem_scope_spec                   kem;
        agc_key_agreement_scope_spec         key_agreement;
        agc_kdf_scope_spec                   kdf;
        agc_hash_scope_spec                  hash;
        agc_key_wrapping_scope_spec          key_wrapping;
        agc_symmetric_cipher_scope_spec      symmetric_cipher;
        agc_generic_secret_scope_spec        generic_secret;
        agc_disk_encryption_scope_spec       disk_encryption;
        agc_asymmetric_encryption_scope_spec asymmetric_encryption;
    } u;
} agc_scope_spec;

/* ==========================================================================
 * ProviderRequirements (api/types/implementation.proto)
 * ========================================================================== */

typedef struct agc_provider_requirements {
    size_t            struct_size;
    agc_tribool       fips_140_certified;
    agc_fips140_level min_fips_level;
    agc_tribool       common_criteria_certified;
    agc_tribool       formally_verified;
    agc_tribool       memory_safe;
    agc_tribool       constant_time;
    agc_tribool       side_channel_hardened;
    agc_tribool       no_known_cve;
    agc_tribool       prefer_hardware_accelerated;  /* soft preference, not a filter */
    agc_kv_list       additional;
} agc_provider_requirements;

#ifdef __cplusplus
}
#endif
#endif /* AGC_SCOPE_H */
