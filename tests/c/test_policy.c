/* agc_policy.h: policy CRUD and listing, and how policies govern create_key. */
#include "agc_test.h"

static void crud(agc_ctx *ctx)
{
    CHECK_RC(create_policy(ctx, "p", "{}"), AGC_OK);
    CHECK_RC(create_policy(ctx, "p", "{}"), AGC_ERR_ALREADY_EXISTS);
    CHECK_RC(create_policy(ctx, NULL, "{}"), AGC_ERR_INVALID_ARGUMENT);
    CHECK_RC(create_policy(ctx, "q", NULL), AGC_ERR_INVALID_ARGUMENT);

    /* Invalid documents fail when they are written, not when they are used. */
    CHECK_RC(create_policy(ctx, "bad", "{\"version\": \"1\", \"alowed_templates\": []}"), AGC_ERR_INVALID_ARGUMENT);
    agc_error_detail d;
    AGC_INIT(&d);
    CHECK_RC(agc_last_error(&d), AGC_OK);
    CHECK(strstr(d.message, "alowed_templates") != NULL);
    /* A section this library does not enforce is refused, not ignored. */
    CHECK_RC(create_policy(ctx, "bad", "{\"version\": \"1\", \"allowed_scopes\": []}"), AGC_ERR_INVALID_ARGUMENT);

    uint8_t storage[256];
    agc_read_policy_response r;
    AGC_INIT(&r);
    CHECK_RC(agc_read_policy(ctx, "p", &r), AGC_ERR_BUFFER_TOO_SMALL); /* size query */
    CHECK(r.storage_used == strlen("p") + 1 + strlen("{}") + 1 + strlen("json") + 1);
    r.storage = (agc_buf){storage, sizeof storage};
    CHECK_RC(agc_read_policy(ctx, "p", &r), AGC_OK);
    CHECK_STR(r.name, "p");
    CHECK_STR(r.policy_document, "{}");
    CHECK_STR(r.format, "json");
    CHECK(r.version == 1 && r.created_at.present && r.updated_at.present);

    agc_update_policy_request u;
    AGC_INIT(&u);
    u.name = "p";
    u.policy_document = DEFAULT_POLICY;
    int64_t version = 0;
    CHECK_RC(agc_update_policy(ctx, &u, &version), AGC_OK);
    CHECK(version == 2);
    CHECK_RC(agc_read_policy(ctx, "p", &r), AGC_OK);
    CHECK_STR(r.policy_document, DEFAULT_POLICY);
    u.name = "missing";
    CHECK_RC(agc_update_policy(ctx, &u, NULL), AGC_ERR_CRYPTO_POLICY_NOT_FOUND);

    CHECK_RC(agc_delete_policy(ctx, "p"), AGC_OK);
    CHECK_RC(agc_delete_policy(ctx, "p"), AGC_ERR_CRYPTO_POLICY_NOT_FOUND);
}

static void listing(agc_ctx *ctx)
{
    CHECK_RC(create_policy(ctx, "team-b", "{}"), AGC_OK);
    CHECK_RC(create_policy(ctx, "team-a", "{}"), AGC_OK);

    agc_list_policies_request req;
    AGC_INIT(&req);
    req.name_prefix = "team-";
    agc_policy_iter *it = NULL;
    CHECK_RC(agc_list_policies(ctx, &req, &it), AGC_OK);

    /* One record and one region reused for the whole loop (agc_policy.h). */
    uint8_t storage[64];
    agc_policy_summary_response s;
    AGC_INIT(&s);
    s.storage = (agc_buf){storage, sizeof storage};
    const char *want[] = {"team-a", "team-b"};
    int n = 0;
    agc_rc rc;
    while ((rc = agc_policy_iter_next(it, &s)) == AGC_OK) {
        CHECK(n < 2);
        CHECK_STR(s.summary.name, want[n]);
        CHECK(s.summary.created_at.present && s.summary.updated_at.present);
        n++;
    }
    CHECK(rc == AGC_ERR_ITERATOR_EXHAUSTED);
    CHECK(n == 2);
    agc_policy_iter_free(it);
    agc_policy_iter_free(NULL);
}

static agc_rc create(agc_ctx *ctx, agc_create_key_params *p)
{
    uint8_t storage[512];
    agc_key_info_response resp;
    AGC_INIT(&resp);
    resp.storage = (agc_buf){storage, sizeof storage};
    return agc_create_key(ctx, p, &resp);
}

static void policies_govern_key_creation(agc_ctx *ctx)
{
    agc_create_key_params p = AEAD_KEY_PARAMS("governed");

    /* A template the policy does not allow is a violation, even when named. */
    p.template_id = "aes-256-gcm-128-96";
    CHECK_RC(create(ctx, &p), AGC_ERR_CRYPTO_POLICY_VIOLATION);

    /* Unknown policy. */
    p.template_id = NULL;
    p.policy_name = "nope";
    CHECK_RC(create(ctx, &p), AGC_ERR_CRYPTO_POLICY_NOT_FOUND);

    /* Creating keys must itself be allowed. */
    CHECK_RC(create_policy(ctx, "read-only",
                           "{\"version\": \"1\", \"allowed_templates\": [\"chacha20-poly1305\"],"
                           " \"allowed_operations\": {\"key_operations\": [\"sign\"]}}"),
             AGC_OK);
    p.policy_name = "read-only";
    CHECK_RC(create(ctx, &p), AGC_ERR_CRYPTO_POLICY_VIOLATION);

    /* A policy still bound to keys cannot be deleted. */
    p.policy_name = "default";
    CHECK_RC(create(ctx, &p), AGC_OK);
    CHECK_RC(agc_delete_policy(ctx, "default"), AGC_ERR_CRYPTO_POLICY_VIOLATION);
}

static void default_policy_from_config(void)
{
    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    cfg.default_policy = "fallback";
    agc_ctx *ctx = NULL;
    CHECK_RC(agc_ctx_open(&cfg, &ctx), AGC_OK);
    CHECK_RC(create_policy(ctx, "fallback", DEFAULT_POLICY), AGC_OK);

    agc_create_key_params p = AEAD_KEY_PARAMS("k");
    p.policy_name = NULL;
    CHECK_RC(create(ctx, &p), AGC_OK);
    agc_ctx_close(ctx);

    /* Without a configured default, a policy must be named. */
    ctx = open_embedded();
    CHECK_RC(create(ctx, &p), AGC_ERR_INVALID_ARGUMENT);
    agc_ctx_close(ctx);
}

int main(void)
{
    agc_ctx *ctx = open_embedded();
    crud(ctx);
    listing(ctx);
    policies_govern_key_creation(ctx);
    agc_ctx_close(ctx);
    default_policy_from_config();
    return 0;
}
