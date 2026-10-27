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
    CHECK_STR(resp.key_info.template_id, "aes-256-gcm");
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
        .key_name = "kem-1",
        .policy_name = "default",
        .scope_spec = {.struct_size = sizeof(agc_scope_spec), .kind = AGC_SCOPE_KIND_KEM},
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
    CHECK_STR(resp.key_info.template_id, "aes-256-gcm");
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
    agc_ctx_close(ctx);
    return 0;
}
