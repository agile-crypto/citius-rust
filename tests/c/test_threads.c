/* agc_core.h THREADING: "any number of threads may issue operations on one
 * context concurrently". */
#include <pthread.h>

#include "agc_test.h"

enum { THREADS = 8, KEYS_PER_THREAD = 50 };

static agc_ctx *ctx;

static void *create_distinct(void *arg)
{
    int t = (int)(intptr_t)arg;
    for (int i = 0; i < KEYS_PER_THREAD; i++) {
        char name[32];
        snprintf(name, sizeof name, "t%d-k%d", t, i);
        agc_create_key_params p = AEAD_KEY_PARAMS(name);
        uint8_t storage[256];
        agc_key_info_response resp;
        AGC_INIT(&resp);
        resp.storage = (agc_buf){storage, sizeof storage};
        CHECK_RC(agc_create_key(ctx, &p, &resp), AGC_OK);
        CHECK_STR(resp.key_info.key_name, name);
    }
    return NULL;
}

static void *create_same(void *arg)
{
    (void)arg;
    agc_create_key_params p = AEAD_KEY_PARAMS("contended");
    uint8_t storage[256];
    agc_key_info_response resp;
    AGC_INIT(&resp);
    resp.storage = (agc_buf){storage, sizeof storage};
    agc_rc rc = agc_create_key(ctx, &p, &resp);
    CHECK(rc == AGC_OK || rc == AGC_ERR_ALREADY_EXISTS);
    if (rc == AGC_ERR_ALREADY_EXISTS) {
        /* The error record is this thread's own. */
        agc_error_detail d;
        AGC_INIT(&d);
        CHECK_RC(agc_last_error(&d), AGC_OK);
        CHECK(d.rc == AGC_ERR_ALREADY_EXISTS);
    }
    return (void *)(intptr_t)(rc == AGC_OK);
}

static void run(void *(*fn)(void *), int *succeeded)
{
    pthread_t th[THREADS];
    for (int t = 0; t < THREADS; t++)
        CHECK(pthread_create(&th[t], NULL, fn, (void *)(intptr_t)t) == 0);
    for (int t = 0; t < THREADS; t++) {
        void *r;
        CHECK(pthread_join(th[t], &r) == 0);
        if (succeeded) *succeeded += (int)(intptr_t)r;
    }
}

int main(void)
{
    ctx = open_embedded();
    run(create_distinct, NULL);

    int succeeded = 0;
    run(create_same, &succeeded);
    CHECK(succeeded == 1);

    agc_ctx_close(ctx);
    return 0;
}
