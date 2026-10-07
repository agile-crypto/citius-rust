/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_key.h — KeyManagementService (11 RPCs; api/services/key_management_service.proto).
 *
 * Functions only. Every request, record and response type they name is
 * defined in agc_key_types.h, which also states the STORAGE CONTRACT that
 * governs every caller-allocated record below: a NULL or too-small
 * `storage` region returns AGC_ERR_BUFFER_TOO_SMALL with `storage_used` set
 * to the requirement, and for a mutating operation that requirement is a
 * bound computed without performing the operation.
 *
 * Every function takes the context first, then one const request pointer,
 * then the caller-allocated output. The library allocates nothing the caller
 * sees and there is nothing to free, except the one iterator handle.
 *
 * SELECTION MODES
 * ---------------
 * CreateKey/TransformKey support the proto's two selection modes in one
 * struct: set scope_spec (intent-based, recommended) or template_id
 * (explicit), or both -- when both are set they must agree, else
 * AGC_ERR_CRYPTO_NO_MATCHING_TEMPLATE. This is a struct with a documented
 * precedence rule rather than two functions, so an operator pinning a
 * template in policy does not require a call-site code change.
 *
 * STATUS: declarations only. Implementation follows; see
 * docs/implementation_progress.md.
 */

#ifndef AGC_KEY_H
#define AGC_KEY_H

#include "agc_core.h"
#include "agc_key_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * CreateKey
 * -------------------------------------------------------------------------- */

/* CreateKeyResponse has 5 fields; success/message collapse into agc_rc (D4).
 * implementation_properties is resp->key_info.implementation_props.
 * security_guarantees is not exposed by this reconciliation: it is reachable
 * via the key's template, never duplicated. */
AGC_API agc_rc agc_create_key(agc_ctx *ctx, const agc_create_key_params *params,
                               agc_key_info_response *resp);

/* --------------------------------------------------------------------------
 * ReadKey / ListKeys
 * -------------------------------------------------------------------------- */

/* version == 0 reads the latest (proto: optional uint32 version, absent =
 * latest; versions start at 1, so 0 is an unambiguous sentinel). */
AGC_API agc_rc agc_read_key(agc_ctx *ctx, const char *key_name, uint32_t version,
                             agc_key_info_response *resp);

/* The iterator is a library-owned handle (it has a lifecycle: paging
 * bookkeeping, D12); the records it yields are caller-allocated. */
AGC_API agc_rc agc_list_keys(agc_ctx *ctx, const agc_list_keys_params *params,
                              agc_key_iter **out_iter);

/* Fills *out with the next key. On AGC_ERR_BUFFER_TOO_SMALL the cursor does
 * not advance, so the caller may resize out->storage and call again for the
 * same key. AGC_ERR_ITERATOR_EXHAUSTED at the end. A caller may reuse one
 * record and one storage region across the whole loop. */
AGC_API agc_rc agc_key_iter_next(agc_key_iter *it, agc_key_info_response *out);
AGC_API void   agc_key_iter_free(agc_key_iter *it);

/* --------------------------------------------------------------------------
 * DeleteKey
 * -------------------------------------------------------------------------- */

/* Zeroizes key material in the provider -- irreversible. */
AGC_API agc_rc agc_delete_key(agc_ctx *ctx, const char *key_name);

/* --------------------------------------------------------------------------
 * RotateKey
 * -------------------------------------------------------------------------- */

/* RotateKeyRequest is `{name}` on the wire.
 * *resp describes the new version's metadata. */
AGC_API agc_rc agc_rotate_key(agc_ctx *ctx, const char *key_name, agc_key_info_response *resp);

/* --------------------------------------------------------------------------
 * TransformKey
 * -------------------------------------------------------------------------- */

AGC_API agc_rc agc_transform_key(agc_ctx *ctx, const agc_transform_key_params *params,
                                  agc_key_info_response *resp);

/* --------------------------------------------------------------------------
 * UpdateKeyPolicy
 * -------------------------------------------------------------------------- */

AGC_API agc_rc agc_update_key_policy(agc_ctx *ctx, const char *key_name, const char *new_policy_name,
                                      agc_key_info_response *resp);

/* --------------------------------------------------------------------------
 * MigrateKey
 * -------------------------------------------------------------------------- */

/* Set resp->want_key_info and resp->want_report to choose which records come
 * back; both are opt-in, so a zeroed response migrates the key and reports
 * only the return code. resp->storage covers whichever records are requested
 * and is size-checked before the migration is attempted; on
 * AGC_ERR_BUFFER_TOO_SMALL storage_used holds the bound and no key has been
 * touched. */
AGC_API agc_rc agc_migrate_key(agc_ctx *ctx, const agc_migrate_key_params *params,
                                agc_migrate_key_response *resp);

/* --------------------------------------------------------------------------
 * ValidateKeyOperation — pre-flight feasibility
 * -------------------------------------------------------------------------- */

/* Read-only: performs no key operation, so its storage requirement is exact. */
AGC_API agc_rc agc_validate_key_operation(agc_ctx *ctx, const agc_validate_key_op_params *params,
                                           agc_validate_key_op_response *out_report);

/* --------------------------------------------------------------------------
 * ExportKey / ImportKey
 * -------------------------------------------------------------------------- */

/* SECURITY: the caller owns the exported material and MUST agc_secure_zero
 * it -- the library cannot know when the caller is finished with it, which
 * is precisely why the buffer is caller-owned. Set resp->want_key_info to
 * receive the key's record as well; left zero, the call returns only the
 * material and needs no storage. Both resp->material and resp->storage are
 * size-checked before any material is produced; on
 * AGC_ERR_BUFFER_TOO_SMALL every length field is set and no material has
 * left the provider. */
AGC_API agc_rc agc_export_key(agc_ctx *ctx, const agc_export_key_params *params,
                               agc_export_key_response *resp);

AGC_API agc_rc agc_import_key(agc_ctx *ctx, const agc_import_key_params *params,
                               agc_key_info_response *resp);

#ifdef __cplusplus
}
#endif
#endif /* AGC_KEY_H */
