/* agc_core.h: context lifecycle, the error record, rc helpers. */
#include <stddef.h>

#include "agc_test.h"

static void open_and_close(void)
{
    agc_ctx *ctx = open_embedded();
    agc_ctx_close(ctx);
    agc_ctx_close(NULL); /* idempotent on NULL */
}

static void remote_modes_are_not_implemented(void)
{
    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    agc_ctx *ctx = NULL;
    cfg.mode = AGC_MODE_LOCAL;
    CHECK_RC(agc_ctx_open(&cfg, &ctx), AGC_ERR_NOT_IMPLEMENTED);
    CHECK(ctx == NULL);
    cfg.mode = AGC_MODE_REMOTE;
    CHECK_RC(agc_ctx_open(&cfg, &ctx), AGC_ERR_NOT_IMPLEMENTED);
    CHECK(ctx == NULL);

    agc_error_detail d;
    AGC_INIT(&d);
    CHECK_RC(agc_last_error(&d), AGC_OK);
    CHECK(d.rc == AGC_ERR_NOT_IMPLEMENTED);
    CHECK(d.message != NULL);
    CHECK(d.domain == NULL); /* a local code, not a caas.crypto.v1 one */
}

static void bad_arguments(void)
{
    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    agc_ctx *ctx = NULL;
    CHECK_RC(agc_ctx_open(&cfg, NULL), AGC_ERR_INVALID_ARGUMENT);
    CHECK_RC(agc_ctx_open(NULL, &ctx), AGC_ERR_INVALID_ARGUMENT);

    agc_ctx_config forgot_init = {0};
    CHECK_RC(agc_ctx_open(&forgot_init, &ctx), AGC_ERR_INVALID_ARGUMENT);

    agc_ctx_config tiny = {.struct_size = 1};
    CHECK_RC(agc_ctx_open(&tiny, &ctx), AGC_ERR_ABI_MISMATCH);
}

static void older_config_struct_is_accepted(void)
{
    /* A caller compiled against a header whose config ended after `mode`. */
    agc_ctx_config cfg;
    memset(&cfg, 0xAB, sizeof cfg); /* the "newer" tail is garbage the library must not read */
    cfg.struct_size = offsetof(agc_ctx_config, mode) + sizeof(cfg.mode);
    cfg.mode = AGC_MODE_EMBEDDED;
    agc_ctx *ctx = NULL;
    CHECK_RC(agc_ctx_open(&cfg, &ctx), AGC_OK);
    agc_ctx_close(ctx);
}

static void clear_error(void)
{
    agc_ctx *ctx = NULL;
    CHECK_RC(agc_ctx_open(NULL, &ctx), AGC_ERR_INVALID_ARGUMENT);
    agc_clear_error();

    agc_error_detail d;
    AGC_INIT(&d);
    CHECK_RC(agc_last_error(&d), AGC_OK);
    CHECK(d.rc == AGC_OK);
    CHECK(d.message == NULL);
}

static void older_error_detail_gets_only_its_fields(void)
{
    agc_ctx *ctx = NULL;
    CHECK_RC(agc_ctx_open(NULL, &ctx), AGC_ERR_INVALID_ARGUMENT);

    agc_error_detail d;
    memset(&d, 0, sizeof d);
    const char *sentinel = "untouched";
    d.domain = sentinel;
    d.struct_size = offsetof(agc_error_detail, domain); /* knows rc and message only */
    CHECK_RC(agc_last_error(&d), AGC_OK);
    CHECK(d.rc == AGC_ERR_INVALID_ARGUMENT);
    CHECK(d.message != NULL);
    CHECK(d.domain == sentinel);
    CHECK(d.struct_size == offsetof(agc_error_detail, domain));

    CHECK_RC(agc_last_error(NULL), AGC_ERR_INVALID_ARGUMENT);
}

static void rc_names_and_messages(void)
{
    CHECK_STR(agc_rc_name(AGC_OK), "AGC_OK");
    CHECK_STR(agc_rc_name(AGC_ERR_CRYPTO_KEY_NOT_FOUND), "AGC_ERR_CRYPTO_KEY_NOT_FOUND");
    CHECK_STR(agc_rc_name(424242), "(unknown agc_rc)");
    CHECK_STR(agc_rc_message(AGC_OK), "success");
    CHECK_STR(agc_rc_message(AGC_ERR_ITERATOR_EXHAUSTED), "normal end of a list iteration");
    CHECK_STR(agc_rc_message(424242), "unknown result code");
}

int main(void)
{
    open_and_close();
    remote_modes_are_not_implemented();
    bad_arguments();
    older_config_struct_is_accepted();
    clear_error();
    older_error_detail_gets_only_its_fields();
    rc_names_and_messages();
    return 0;
}
