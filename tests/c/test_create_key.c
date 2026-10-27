/* agc_key.h: agc_create_key, its storage contract and error reporting. */
#include <stddef.h>

#include "agc_test.h"

static agc_rc create(agc_ctx *ctx, const char *name, uint8_t *storage, size_t cap,
                     agc_key_info_response *resp)
{
    agc_create_key_params p = AEAD_KEY_PARAMS(name);
    AGC_INIT(resp);
    resp->storage.data = storage;
    resp->storage.cap = cap;
    return agc_create_key(ctx, &p, resp);
}

static void creates_an_aead_key(agc_ctx *ctx)
{
    uint8_t storage[256];
    agc_key_info_response resp;
    CHECK_RC(create(ctx, "aead-1", storage, sizeof storage, &resp), AGC_OK);

    CHECK_STR(resp.key_info.key_name, "aead-1");
    CHECK_STR(resp.key_info.policy_name, "default");
    CHECK_STR(resp.key_info.template_id, "aes-128-gcm-128-96");
    CHECK(strncmp(resp.key_info.key_id, "key_", 4) == 0);
    CHECK(resp.key_info.version == 1);
    CHECK(resp.key_info.lifecycle_state == AGC_KEY_LIFECYCLE_STATE_ACTIVE);
    CHECK(resp.key_info.scope_spec.kind == AGC_SCOPE_KIND_AEAD);
    /* Every string lives in the caller's storage. */
    CHECK((const uint8_t *)resp.key_info.key_name >= storage);
    CHECK((const uint8_t *)resp.key_info.key_name < storage + resp.storage_used);
}

static void duplicate_name_is_rejected(agc_ctx *ctx)
{
    uint8_t storage[256];
    agc_key_info_response resp;
    CHECK_RC(create(ctx, "dup", storage, sizeof storage, &resp), AGC_OK);
    CHECK_RC(create(ctx, "dup", storage, sizeof storage, &resp), AGC_ERR_ALREADY_EXISTS);

    agc_error_detail d;
    AGC_INIT(&d);
    CHECK_RC(agc_last_error(&d), AGC_OK);
    CHECK(d.rc == AGC_ERR_ALREADY_EXISTS);
    CHECK(d.message != NULL);
}

static void no_template_is_a_crypto_error_with_reason(agc_ctx *ctx)
{
    agc_create_key_params p = {
        .struct_size = sizeof p,
        .key_name = "hash-0",
        .policy_name = "default",
        .scope_spec = {.struct_size = sizeof(agc_scope_spec), .kind = AGC_SCOPE_KIND_HASH}, /* none in the catalog */
    };
    uint8_t storage[256];
    agc_key_info_response resp;
    AGC_INIT(&resp);
    resp.storage = (agc_buf){storage, sizeof storage};
    CHECK_RC(agc_create_key(ctx, &p, &resp), AGC_ERR_CRYPTO_NO_MATCHING_TEMPLATE);

    agc_error_detail d;
    AGC_INIT(&d);
    CHECK_RC(agc_last_error(&d), AGC_OK);
    CHECK_STR(d.domain, "caas.crypto.v1");
    CHECK_STR(d.reason, "CRYPTO_ERROR_NO_MATCHING_TEMPLATE");
}

static void too_small_storage_reports_the_size(agc_ctx *ctx)
{
    uint8_t storage[4];
    agc_key_info_response resp;
    CHECK_RC(create(ctx, "small", storage, sizeof storage, &resp), AGC_ERR_BUFFER_TOO_SMALL);
    CHECK(resp.storage_used > sizeof storage);
    CHECK(resp.key_info.key_name == NULL);

    agc_key_info_response query;
    CHECK_RC(create(ctx, "small-query", NULL, 0, &query), AGC_ERR_BUFFER_TOO_SMALL);
    CHECK(query.storage_used > 0);
}

static void invalid_arguments(agc_ctx *ctx)
{
    uint8_t storage[256];
    agc_key_info_response resp;
    AGC_INIT(&resp);
    resp.storage = (agc_buf){storage, sizeof storage};

    agc_create_key_params no_name = AEAD_KEY_PARAMS(NULL);
    CHECK_RC(agc_create_key(ctx, &no_name, &resp), AGC_ERR_INVALID_ARGUMENT);

    agc_create_key_params ok = AEAD_KEY_PARAMS("args");
    CHECK_RC(agc_create_key(NULL, &ok, &resp), AGC_ERR_INVALID_ARGUMENT);
    CHECK_RC(agc_create_key(ctx, NULL, &resp), AGC_ERR_INVALID_ARGUMENT);
    CHECK_RC(agc_create_key(ctx, &ok, NULL), AGC_ERR_INVALID_ARGUMENT);
}

static void older_params_struct_is_accepted(agc_ctx *ctx)
{
    /* A caller whose params end before template_id: the library must treat
     * the missing tail as "not given", not read past struct_size. */
    agc_create_key_params p = AEAD_KEY_PARAMS("older");
    p.struct_size = offsetof(agc_create_key_params, template_id);
    uint8_t storage[256];
    agc_key_info_response resp;
    AGC_INIT(&resp);
    resp.storage = (agc_buf){storage, sizeof storage};
    CHECK_RC(agc_create_key(ctx, &p, &resp), AGC_OK);
    CHECK_STR(resp.key_info.template_id, "aes-128-gcm-128-96");
}

static agc_rc create_with(agc_ctx *ctx, agc_create_key_params *p, agc_key_info_response *resp, uint8_t *storage,
                          size_t cap)
{
    AGC_INIT(resp);
    resp->storage = (agc_buf){storage, cap};
    return agc_create_key(ctx, p, resp);
}

static void selection_by_intent(agc_ctx *ctx)
{
    uint8_t storage[512];
    agc_key_info_response resp;

    /* Signatures that must be quantum safe: a classical template no longer qualifies. */
    agc_create_key_params pq = {
        .struct_size = sizeof pq,
        .key_name = "pq-sig",
        .policy_name = "default",
        .scope_spec = {.struct_size = sizeof(agc_scope_spec),
                       .kind = AGC_SCOPE_KIND_SIGNATURE,
                       .u.signature = {.scope = AGC_SIGNATURE_SCOPE_STANDARD,
                                       .security = {.quantum_safe = AGC_TRUE}}},
    };
    CHECK_RC(create_with(ctx, &pq, &resp, storage, sizeof storage), AGC_OK);
    CHECK(strncmp(resp.key_info.template_id, "ecdsa", 5) != 0);

    /* An explicit template must serve the requested intent. */
    agc_create_key_params wrong = AEAD_KEY_PARAMS("explicit-wrong");
    wrong.template_id = "hmac-sha256-256";
    CHECK_RC(create_with(ctx, &wrong, &resp, storage, sizeof storage), AGC_ERR_CRYPTO_NO_MATCHING_TEMPLATE);

    agc_create_key_params unknown = AEAD_KEY_PARAMS("explicit-unknown");
    unknown.template_id = "no-such-template";
    CHECK_RC(create_with(ctx, &unknown, &resp, storage, sizeof storage), AGC_ERR_CRYPTO_TEMPLATE_NOT_FOUND);

    agc_create_key_params chosen = AEAD_KEY_PARAMS("explicit-ok");
    chosen.template_id = "chacha20-poly1305";
    CHECK_RC(create_with(ctx, &chosen, &resp, storage, sizeof storage), AGC_OK);
    CHECK_STR(resp.key_info.template_id, "chacha20-poly1305");

    /* No template in the catalog serves this kind. */
    agc_create_key_params hash = {
        .struct_size = sizeof hash,
        .key_name = "hash-1",
        .policy_name = "default",
        .scope_spec = {.struct_size = sizeof(agc_scope_spec), .kind = AGC_SCOPE_KIND_HASH},
    };
    CHECK_RC(create_with(ctx, &hash, &resp, storage, sizeof storage), AGC_ERR_CRYPTO_NO_MATCHING_TEMPLATE);
}

static void invalid_scope_values(agc_ctx *ctx)
{
    uint8_t storage[512];
    agc_key_info_response resp;
    agc_create_key_params bad_tribool = {
        .struct_size = sizeof bad_tribool,
        .key_name = "bad-1",
        .policy_name = "default",
        .scope_spec = {.struct_size = sizeof(agc_scope_spec),
                       .kind = AGC_SCOPE_KIND_AEAD,
                       .u.aead = {.nonce_misuse_resistant = (agc_tribool)7}},
    };
    CHECK_RC(create_with(ctx, &bad_tribool, &resp, storage, sizeof storage), AGC_ERR_INVALID_ARGUMENT);

    agc_kv dup[] = {{"k", "1"}, {"k", "2"}};
    agc_create_key_params bad_kv = {
        .struct_size = sizeof bad_kv,
        .key_name = "bad-2",
        .policy_name = "default",
        .scope_spec = {.struct_size = sizeof(agc_scope_spec),
                       .kind = AGC_SCOPE_KIND_AEAD,
                       .u.aead = {.additional_properties = {dup, 2}}},
    };
    CHECK_RC(create_with(ctx, &bad_kv, &resp, storage, sizeof storage), AGC_ERR_INVALID_ARGUMENT);
}

int main(void)
{
    agc_ctx *ctx = open_embedded();
    creates_an_aead_key(ctx);
    duplicate_name_is_rejected(ctx);
    no_template_is_a_crypto_error_with_reason(ctx);
    too_small_storage_reports_the_size(ctx);
    invalid_arguments(ctx);
    older_params_struct_is_accepted(ctx);
    selection_by_intent(ctx);
    invalid_scope_values(ctx);
    agc_ctx_close(ctx);
    return 0;
}
