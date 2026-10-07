/*
 * Tiny C consumer of the AGC C API, implemented in Rust.
 *
 * Build and run (from the crate root):
 *   cargo build
 *   cc -Wall -Wextra -I include examples/c/main.c -L target/debug -lapi_test_extended -o target/c_example
 *   ./target/c_example
 */

#include <stdio.h>

#include "agc_key.h"

static const char *or_null(const char *s) {
    return s ? s : "(null)";
}

int main(void) {
    /* No agc_ctx_open on the Rust side yet, so there is no real context to
     * pass. Any non-NULL pointer stands in for one until then. */
    int dummy = 0;
    agc_ctx *ctx = (agc_ctx *)&dummy;

    /* scope_spec is a const member, so it cannot be assigned after
     * AGC_INIT(); the whole request is set in the initializer instead. */
    agc_create_key_params params = {
        .struct_size = sizeof params,
        .key_name    = "my-first-key",
        .policy_name = "default",
        .scope_spec  = {
            .struct_size = sizeof(agc_scope_spec),
            .kind        = AGC_SCOPE_KIND_AEAD,
        },
    };

    /* The library copies the record's strings into this caller-owned region. */
    uint8_t storage[512];

    agc_key_info_response resp;
    AGC_INIT(&resp);
    resp.storage.data = storage;
    resp.storage.cap  = sizeof storage;

    agc_rc rc = agc_create_key(ctx, &params, &resp);
    printf("agc_create_key -> %d\n", (int)rc);

    if (rc == AGC_ERR_BUFFER_TOO_SMALL) {
        printf("storage too small: need %zu bytes, have %zu\n", resp.storage_used, sizeof storage);
        return 1;
    }
    if (rc != AGC_OK) {
        return 1;
    }

    printf("storage used: %zu bytes\n", resp.storage_used);
    printf("key_name:     %s\n", or_null(resp.key_info.key_name));
    printf("key_id:       %s\n", or_null(resp.key_info.key_id));
    printf("template_id:  %s\n", or_null(resp.key_info.template_id));
    printf("provider_id:  %s\n", or_null(resp.key_info.provider_id));
    printf("policy_name:  %s\n", or_null(resp.key_info.policy_name));
    printf("version:      %u\n", resp.key_info.version);
    return 0;
}
