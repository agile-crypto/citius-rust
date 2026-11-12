/* agc_core.h: version, memory hygiene; agc_types.h: enum name helpers. */
#include <stddef.h>

#include "agc_test.h"

static void version(void)
{
    int major = -1, minor = -1, patch = -1;
    agc_version(&major, &minor, &patch);
    CHECK(major == AGC_API_VERSION_MAJOR && minor == AGC_API_VERSION_MINOR && patch == AGC_API_VERSION_PATCH);
    agc_version(NULL, NULL, NULL); /* each output is optional */

    char want[16];
    snprintf(want, sizeof want, "%d.%d.%d", major, minor, patch);
    CHECK_STR(agc_version_string(), want);
    CHECK(strstr(agc_build_info(), "fips=0") != NULL);
}

static void secure_memory(void)
{
    CHECK(agc_secure_alloc(0) == NULL);
    CHECK(agc_secure_alloc((size_t)-1) == NULL);

    uint8_t *p = agc_secure_alloc(100);
    CHECK(p != NULL);
    CHECK(((uintptr_t)p & 15) == 0);
    for (int i = 0; i < 100; i++) CHECK(p[i] == 0);
    memset(p, 0x5A, 100);
    agc_secure_zero(p, 50);
    CHECK(p[0] == 0 && p[49] == 0 && p[50] == 0x5A);
    agc_secure_free(p, 100);
    agc_secure_free(NULL, 0);
    agc_secure_zero(NULL, 10);
}

static void constant_time_equal(void)
{
    uint8_t a[32], b[32];
    memset(a, 7, sizeof a);
    memcpy(b, a, sizeof b);
    CHECK(agc_ct_equal(a, b, sizeof a) == 1);
    b[31] ^= 1;
    CHECK(agc_ct_equal(a, b, sizeof a) == 0);
    CHECK(agc_ct_equal(a, b, 31) == 1);
    CHECK(agc_ct_equal(NULL, b, 0) == 0);
    CHECK(agc_ct_equal(a, NULL, sizeof a) == 0);
    b[31] ^= 1;
    b[0] ^= 1; /* a difference in the first byte counts as much as in the last */
    CHECK(agc_ct_equal(a, b, sizeof a) == 0);
}

static void enum_names(void)
{
    CHECK_STR(agc_aead_scope_name(AGC_AEAD_SCOPE_STANDARD), "AEAD_SCOPE_STANDARD");
    CHECK_STR(agc_aead_scope_name((agc_aead_scope)999), "(unknown)");

    agc_aead_scope s = AGC_AEAD_SCOPE_UNSPECIFIED;
    CHECK_RC(agc_aead_scope_from_name("AEAD_SCOPE_DETERMINISTIC", &s), AGC_OK);
    CHECK(s == AGC_AEAD_SCOPE_DETERMINISTIC);
    CHECK_RC(agc_aead_scope_from_name("aead_scope_standard", &s), AGC_ERR_INVALID_ARGUMENT); /* exact match only */
    CHECK_RC(agc_aead_scope_from_name(NULL, &s), AGC_ERR_INVALID_ARGUMENT);
    CHECK(s == AGC_AEAD_SCOPE_DETERMINISTIC);

    agc_key_lifecycle_state st;
    CHECK_RC(agc_key_lifecycle_state_from_name("KEY_LIFECYCLE_STATE_ACTIVE", &st), AGC_OK);
    CHECK(st == AGC_KEY_LIFECYCLE_STATE_ACTIVE);
}

/* Settings this build cannot honour are refused, never ignored (agc_core.h). */
static void unhonoured_settings_are_refused(void)
{
    for (int i = 0; i < 4; i++) {
        agc_ctx_config cfg;
        AGC_INIT(&cfg);
        switch (i) {
        case 0: cfg.require_locked_memory = 1; break;
        case 1: cfg.fips_mode = 1; break;
        case 2: cfg.catalog_path = "/etc/agc/catalog.json"; break;
        case 3: cfg.provider_config_path = "/etc/agc/providers.json"; break;
        }
        agc_ctx *ctx = (agc_ctx *)&cfg; /* deliberately non-NULL */
        CHECK_RC(agc_ctx_open(&cfg, &ctx), AGC_ERR_NOT_IMPLEMENTED);
    }
    /* A file: store without its wrapping key is a configuration error
     * (test_key_store covers the store itself). */
    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    cfg.key_store_uri = "file:/var/lib/agc";
    agc_ctx *ctx = NULL;
    CHECK_RC(agc_ctx_open(&cfg, &ctx), AGC_ERR_INVALID_ARGUMENT);
}

/* A caller built against headers without key_store_uri passes a shorter
 * struct: the missing field reads as NULL, so keys stay in memory. */
static void older_config_without_key_store_uri_opens(void)
{
    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    cfg.key_store_uri = "file:/must-not-be-read";
    cfg.struct_size = offsetof(agc_ctx_config, key_store_uri);
    agc_ctx *ctx = NULL;
    CHECK_RC(agc_ctx_open(&cfg, &ctx), AGC_OK);
    agc_ctx_close(ctx);
}

int main(void)
{
    version();
    secure_memory();
    constant_time_equal();
    enum_names();
    unhonoured_settings_are_refused();
    older_config_without_key_store_uri_opens();
    return 0;
}
