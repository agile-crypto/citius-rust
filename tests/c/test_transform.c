/* agc_key.h: agc_transform_key, algorithm agility under one key name. */
#include "agc_test.h"

static uint8_t storage[8192];

static agc_rc create(agc_ctx *ctx, const char *name, const char *policy, agc_scope_kind kind, const char *template_id)
{
    agc_create_key_params p = {
        .struct_size = sizeof p,
        .key_name = name,
        .policy_name = policy,
        .scope_spec = {.struct_size = sizeof(agc_scope_spec), .kind = kind},
        .template_id = template_id,
    };
    agc_key_info_response resp;
    AGC_INIT(&resp);
    resp.storage = (agc_buf){storage, sizeof storage};
    return agc_create_key(ctx, &p, &resp);
}

static agc_rc transform(agc_ctx *ctx, agc_transform_key_params *p, agc_key_info_response *resp, size_t cap)
{
    AGC_INIT(resp);
    resp->storage = (agc_buf){storage, cap};
    return agc_transform_key(ctx, p, resp);
}

static uint32_t current_version(agc_ctx *ctx, const char *name)
{
    agc_key_info_response r;
    AGC_INIT(&r);
    r.storage = (agc_buf){storage, sizeof storage};
    CHECK_RC(agc_read_key(ctx, name, 0, &r), AGC_OK);
    return r.key_info.version;
}

static void classical_to_post_quantum(agc_ctx *ctx)
{
    /* The deck's example: same name, same intent, new algorithm. */
    CHECK_RC(create(ctx, "invoice-signing", "default", AGC_SCOPE_KIND_SIGNATURE, "ecdsa-p256-sha256-der"), AGC_OK);

    agc_transform_key_params p;
    AGC_INIT(&p);
    p.key_name = "invoice-signing";
    p.template_id = "ml-dsa-65";
    agc_key_info_response resp;

    /* Too small a region adds no version, and says how much is needed. */
    CHECK_RC(transform(ctx, &p, &resp, 64), AGC_ERR_BUFFER_TOO_SMALL);
    CHECK(resp.storage_used > 1952); /* the ML-DSA-65 public key alone */
    CHECK(current_version(ctx, "invoice-signing") == 1);

    CHECK_RC(transform(ctx, &p, &resp, sizeof storage), AGC_OK);
    CHECK(resp.key_info.version == 2);
    CHECK_STR(resp.key_info.template_id, "ml-dsa-65");
    CHECK_STR(resp.key_info.provider_id, "rustcrypto");
    CHECK(resp.key_info.public_key.len == 1952);

    /* Version 1 is still there for verifying old signatures. */
    agc_key_info_response v1;
    AGC_INIT(&v1);
    v1.storage = (agc_buf){storage, sizeof storage};
    CHECK_RC(agc_read_key(ctx, "invoice-signing", 1, &v1), AGC_OK);
    CHECK_STR(v1.key_info.template_id, "ecdsa-p256-sha256-der");
}

static void retaining_material(agc_ctx *ctx)
{
    CHECK_RC(create_policy(ctx, "agile",
                           "{\"version\": \"1\","
                           " \"allowed_templates\": [\"chacha20-poly1305\", \"xchacha20-poly1305\", \"aes-128-gcm-128-96\"],"
                           " \"allowed_operations\": {\"key_operations\": [\"create_key\"]}}"),
             AGC_OK);
    CHECK_RC(create(ctx, "stream", "agile", AGC_SCOPE_KIND_AEAD, "chacha20-poly1305"), AGC_OK);

    agc_transform_key_params p;
    AGC_INIT(&p);
    p.key_name = "stream";
    p.template_id = "xchacha20-poly1305";
    p.retain_key_bytes = 1;
    agc_key_info_response resp;
    CHECK_RC(transform(ctx, &p, &resp, sizeof storage), AGC_OK);
    CHECK_STR(resp.key_info.template_id, "xchacha20-poly1305");

    /* An AES key cannot become a ChaCha20 key. */
    CHECK_RC(create(ctx, "aes", "agile", AGC_SCOPE_KIND_AEAD, "aes-128-gcm-128-96"), AGC_OK);
    p.key_name = "aes";
    p.template_id = "chacha20-poly1305";
    CHECK_RC(transform(ctx, &p, &resp, sizeof storage), AGC_ERR_CRYPTO_INCOMPATIBLE_PARAMETERS);

    /* Retaining needs an explicit target. */
    p.template_id = NULL;
    CHECK_RC(transform(ctx, &p, &resp, sizeof storage), AGC_ERR_INVALID_ARGUMENT);
}

static void rules(agc_ctx *ctx)
{
    agc_transform_key_params p;
    AGC_INIT(&p);
    agc_key_info_response resp;

    /* A transform keeps the key's scope. */
    agc_scope_spec aead = {.struct_size = sizeof aead, .kind = AGC_SCOPE_KIND_AEAD};
    p.key_name = "invoice-signing";
    p.scope_spec = &aead;
    CHECK_RC(transform(ctx, &p, &resp, sizeof storage), AGC_ERR_CRYPTO_INCOMPATIBLE_PARAMETERS);

    /* The policy decides the target. */
    p.scope_spec = NULL;
    p.template_id = "ed25519";
    CHECK_RC(transform(ctx, &p, &resp, sizeof storage), AGC_ERR_CRYPTO_POLICY_VIOLATION);

    p.key_name = "missing";
    CHECK_RC(transform(ctx, &p, &resp, sizeof storage), AGC_ERR_CRYPTO_KEY_NOT_FOUND);
    CHECK_RC(transform(ctx, NULL, &resp, sizeof storage), AGC_ERR_INVALID_ARGUMENT);
}

int main(void)
{
    agc_ctx *ctx = open_embedded();
    classical_to_post_quantum(ctx);
    retaining_material(ctx);
    rules(ctx);
    agc_ctx_close(ctx);
    return 0;
}
