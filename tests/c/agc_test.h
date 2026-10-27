/* Minimal assertion helpers for the C tests. Each test is its own program;
 * the first failed check prints where and exits non-zero. */
#ifndef AGC_TEST_H
#define AGC_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agilecrypto.h"

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
            exit(1);                                                         \
        }                                                                    \
    } while (0)

#define CHECK_RC(expr, want)                                                 \
    do {                                                                     \
        agc_rc got_ = (expr);                                                \
        if (got_ != (want)) {                                                \
            fprintf(stderr, "%s:%d: %s returned %s (%d), want %s\n", __FILE__, \
                    __LINE__, #expr, agc_rc_name(got_), (int)got_, #want);  \
            exit(1);                                                         \
        }                                                                    \
    } while (0)

#define CHECK_STR(got, want)                                                 \
    do {                                                                     \
        const char *g_ = (got);                                              \
        if (!g_ || strcmp(g_, (want)) != 0) {                                \
            fprintf(stderr, "%s:%d: %s is \"%s\", want \"%s\"\n", __FILE__,   \
                    __LINE__, #got, g_ ? g_ : "(null)", (want));             \
            exit(1);                                                         \
        }                                                                    \
    } while (0)

static inline agc_ctx *open_embedded(void)
{
    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    cfg.mode = AGC_MODE_EMBEDDED;
    agc_ctx *ctx = NULL;
    CHECK_RC(agc_ctx_open(&cfg, &ctx), AGC_OK);
    CHECK(ctx != NULL);
    return ctx;
}

/* create_key params for an AEAD key. scope_spec is a const member, so the
 * whole request is built in one initializer. */
#define AEAD_KEY_PARAMS(name)                                                \
    {                                                                        \
        .struct_size = sizeof(agc_create_key_params),                        \
        .key_name = (name),                                                  \
        .policy_name = "default",                                            \
        .scope_spec = {.struct_size = sizeof(agc_scope_spec),                \
                       .kind = AGC_SCOPE_KIND_AEAD},                         \
    }

#endif
