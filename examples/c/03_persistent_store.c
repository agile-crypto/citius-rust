/* Keep keys across runs in a file key store.
 *
 * key_store_uri names a directory; every key in it is sealed with AES-256-GCM
 * under a 32-byte wrapping key read from key_store_wrapping_key_path. That
 * file must be readable by its owner only. Losing it loses the keys.
 *
 * Policies are not stored: the application creates them on every open. */
/* mkdtemp is POSIX 2008: glibc hides it under -std=c11 unless asked, and
 * macOS hides it again once a POSIX level is set, unless _DARWIN_C_SOURCE. */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "example.h"

static const char *POLICY =
    "{\"version\": \"1\", \"allowed_templates\": [\"aes-256-gcm-128-96\"],"
    " \"allowed_operations\": {\"key_operations\": [\"create_key\", \"encrypt\"]}}";

static agc_ctx *open_store(const char *uri, const char *wrapping_key)
{
    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    cfg.key_store_uri = uri;
    cfg.key_store_wrapping_key_path = wrapping_key;
    agc_ctx *ctx = NULL;
    check(agc_ctx_open(&cfg, &ctx), "agc_ctx_open");
    add_policy(ctx, "app", POLICY);
    return ctx;
}

int main(void)
{
    char dir[] = "/tmp/agc-example-XXXXXX";
    if (!mkdtemp(dir))
        return 1;
    char uri[64], wrapping_key[64];
    snprintf(uri, sizeof uri, "file:%s/keys", dir);
    snprintf(wrapping_key, sizeof wrapping_key, "%s/wrapping.key", dir);

    /* A real deployment gets the wrapping key from its secret management.
     * Here: 32 bytes from the OS, written owner-only. */
    uint8_t key[32];
    FILE *rnd = fopen("/dev/urandom", "rb");
    if (!rnd || fread(key, 1, sizeof key, rnd) != sizeof key)
        return 1;
    fclose(rnd);
    int fd = open(wrapping_key, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0 || write(fd, key, sizeof key) != (ssize_t)sizeof key)
        return 1;
    close(fd);
    agc_secure_zero(key, sizeof key);

    /* First run: create a key. */
    agc_ctx *ctx = open_store(uri, wrapping_key);
    agc_create_key_params kp = {
        .struct_size = sizeof kp,
        .key_name = "customer-data",
        .policy_name = "app",
        .scope_spec = {.struct_size = sizeof(agc_scope_spec), .kind = AGC_SCOPE_KIND_AEAD},
    };
    agc_key_info_response info;
    AGC_INIT(&info); /* no storage: a size query; no key is created */
    size_query(agc_create_key(ctx, &kp, &info), "agc_create_key");
    info.storage = (agc_buf){xmalloc(info.storage_used), info.storage_used};
    check(agc_create_key(ctx, &kp, &info), "agc_create_key");
    printf("created %s (id %s)\n", info.key_info.key_name, info.key_info.key_id);
    free(info.storage.data);
    agc_ctx_close(ctx);

    /* Second run: the key is still there. */
    ctx = open_store(uri, wrapping_key);
    AGC_INIT(&info); /* a size query; for a read the size is exact */
    size_query(agc_read_key(ctx, "customer-data", 0, &info), "agc_read_key");
    info.storage = (agc_buf){xmalloc(info.storage_used), info.storage_used};
    check(agc_read_key(ctx, "customer-data", 0, &info), "agc_read_key");
    printf("reopened: %s, version %u, template %s\n", info.key_info.key_name, info.key_info.version,
           info.key_info.template_id);
    free(info.storage.data);
    agc_ctx_close(ctx);

    char rm[128];
    snprintf(rm, sizeof rm, "rm -rf '%s'", dir);
    return system(rm);
}
