/* agc_key.h: agc_read_key and agc_list_keys. */
#include "agc_test.h"

static void create(agc_ctx *ctx, const char *name, agc_scope_kind kind)
{
    agc_create_key_params p = {
        .struct_size = sizeof p,
        .key_name = name,
        .policy_name = "default",
        .scope_spec = {.struct_size = sizeof(agc_scope_spec), .kind = kind},
    };
    uint8_t storage[4096];
    agc_key_info_response resp;
    AGC_INIT(&resp);
    resp.storage = (agc_buf){storage, sizeof storage};
    CHECK_RC(agc_create_key(ctx, &p, &resp), AGC_OK);
}

static void reading(agc_ctx *ctx)
{
    uint8_t storage[4096];
    agc_key_info_response r;
    AGC_INIT(&r);
    r.storage = (agc_buf){storage, sizeof storage};

    /* A signature key: the policy's first signature template, with a public key. */
    CHECK_RC(agc_read_key(ctx, "sig", 0, &r), AGC_OK); /* 0 = current version */
    CHECK_STR(r.key_info.key_name, "sig");
    CHECK_STR(r.key_info.template_id, "ecdsa-p256-sha256-der");
    CHECK(r.key_info.version == 1);
    CHECK(r.key_info.lifecycle_state == AGC_KEY_LIFECYCLE_STATE_ACTIVE);
    CHECK(r.key_info.scope_spec.kind == AGC_SCOPE_KIND_SIGNATURE);
    CHECK(r.key_info.public_key_format == AGC_KEY_FORMAT_SPKI);
    CHECK(r.key_info.public_key.len == 91); /* SPKI of a P-256 point */
    CHECK(r.key_info.created_time.present && r.key_info.updated_time.present);
    CHECK(r.key_info.extractable == 1);
    CHECK_STR(r.key_info.implementation_props.implementation_language, "rust");
    CHECK(r.key_info.implementation_props.memory_safe_language == AGC_TRUE);
    CHECK(r.key_info.implementation_props.fips_certified == 0);

    CHECK_RC(agc_read_key(ctx, "sig", 1, &r), AGC_OK);
    CHECK_RC(agc_read_key(ctx, "sig", 2, &r), AGC_ERR_CRYPTO_KEY_NOT_FOUND);
    CHECK_RC(agc_read_key(ctx, "missing", 0, &r), AGC_ERR_CRYPTO_KEY_NOT_FOUND);
    CHECK_RC(agc_read_key(ctx, NULL, 0, &r), AGC_ERR_INVALID_ARGUMENT);

    /* A symmetric key has no public half. */
    CHECK_RC(agc_read_key(ctx, "aead", 0, &r), AGC_OK);
    CHECK(r.key_info.public_key.len == 0 && r.key_info.public_key.data == NULL);
}

static int list(agc_ctx *ctx, const agc_list_keys_params *p, const char **names, int max)
{
    agc_key_iter *it = NULL;
    CHECK_RC(agc_list_keys(ctx, p, &it), AGC_OK);
    agc_key_info_response r;
    AGC_INIT(&r); /* first call with no storage: size query, then retry */
    uint8_t storage[4096];
    int n = 0;
    agc_rc rc;
    while ((rc = agc_key_iter_next(it, &r)) != AGC_ERR_ITERATOR_EXHAUSTED) {
        if (rc == AGC_ERR_BUFFER_TOO_SMALL) {
            CHECK(r.storage_used <= sizeof storage);
            r.storage = (agc_buf){storage, sizeof storage};
            continue;
        }
        CHECK_RC(rc, AGC_OK);
        CHECK(n < max);
        CHECK_STR(r.key_info.key_name, names[n]);
        n++;
    }
    agc_key_iter_free(it);
    return n;
}

static void listing(agc_ctx *ctx)
{
    agc_list_keys_params p;
    AGC_INIT(&p);
    const char *all[] = {"aead", "sig"};
    CHECK(list(ctx, &p, all, 2) == 2);

    agc_scope_spec sig = {.struct_size = sizeof sig, .kind = AGC_SCOPE_KIND_SIGNATURE};
    p.scope_spec = &sig;
    const char *sigs[] = {"sig"};
    CHECK(list(ctx, &p, sigs, 1) == 1);

    AGC_INIT(&p);
    p.policy = "other";
    CHECK(list(ctx, &p, NULL, 0) == 0);

    AGC_INIT(&p);
    p.provider_id = "rustcrypto";
    p.lifecycle_state = AGC_KEY_LIFECYCLE_STATE_ACTIVE;
    CHECK(list(ctx, &p, all, 2) == 2);

    p.lifecycle_state = (agc_key_lifecycle_state)99;
    agc_key_iter *it = NULL;
    CHECK_RC(agc_list_keys(ctx, &p, &it), AGC_ERR_INVALID_ARGUMENT);
}

int main(void)
{
    agc_ctx *ctx = open_embedded();
    create(ctx, "sig", AGC_SCOPE_KIND_SIGNATURE);
    create(ctx, "aead", AGC_SCOPE_KIND_AEAD);
    reading(ctx);
    listing(ctx);
    agc_ctx_close(ctx);
    return 0;
}
