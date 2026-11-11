/* agc_core.h: key_store_uri = "file:<directory>" with a wrapping key. */
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "agc_test.h"

static char dir[256], wk[256], wk2[256];

static void write_key(const char *path, unsigned char fill, size_t len, mode_t mode)
{
    unsigned char b[64];
    memset(b, fill, sizeof b);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    CHECK(fd >= 0);
    CHECK(write(fd, b, len) == (ssize_t)len);
    close(fd);
    CHECK(chmod(path, mode) == 0);
}

static agc_rc open_store(const char *key_path, agc_ctx **ctx)
{
    char uri[300];
    snprintf(uri, sizeof uri, "file:%s", dir);
    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    cfg.mode = AGC_MODE_EMBEDDED;
    cfg.key_store_uri = uri;
    cfg.key_store_wrapping_key_path = key_path;
    *ctx = NULL;
    return agc_ctx_open(&cfg, ctx);
}

static void encrypt_once(agc_ctx *ctx, uint8_t *ct, size_t *ct_len, uint8_t *md, size_t *md_len)
{
    agc_encrypt_params ep;
    AGC_INIT(&ep);
    ep.kind = AGC_ENCRYPT_PARAMS_AEAD;
    agc_encrypt_request er;
    AGC_INIT(&er);
    er.key_name = "persistent";
    er.plaintext = (agc_slice){(const uint8_t *)"kept", 4};
    er.params = &ep;
    er.metadata_encoding = AGC_ENCODING_WIRE_V1;
    agc_encrypt_response resp;
    AGC_INIT(&resp);
    resp.ciphertext = (agc_buf){ct, 64};
    resp.metadata = (agc_buf){md, 128};
    CHECK_RC(agc_encrypt(ctx, &er, &resp), AGC_OK);
    *ct_len = resp.ciphertext_len;
    *md_len = resp.metadata_len;
}

int main(void)
{
    char tmpl[] = "/tmp/agc-key-store-XXXXXX";
    CHECK(mkdtemp(tmpl) != NULL);
    snprintf(dir, sizeof dir, "%s/store", tmpl);
    snprintf(wk, sizeof wk, "%s/wrapping.key", tmpl);
    snprintf(wk2, sizeof wk2, "%s/other.key", tmpl);
    write_key(wk, 0x11, 32, 0600);
    write_key(wk2, 0x22, 32, 0600);

    /* A key written by one context ... */
    agc_ctx *ctx;
    CHECK_RC(open_store(wk, &ctx), AGC_OK);
    CHECK_RC(create_policy(ctx, "default", DEFAULT_POLICY), AGC_OK);
    agc_create_key_params p = AEAD_KEY_PARAMS("persistent");
    uint8_t storage[1024];
    agc_key_info_response kr;
    AGC_INIT(&kr);
    kr.storage = (agc_buf){storage, sizeof storage};
    CHECK_RC(agc_create_key(ctx, &p, &kr), AGC_OK);

    /* ... and only one context at a time on the store. */
    agc_ctx *second;
    CHECK_RC(open_store(wk, &second), AGC_ERR_CRYPTO_CONCURRENT_ACCESS);
    CHECK(second == NULL);

    /* A forked child cannot take over the store while the parent has it. */
    fflush(NULL);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        agc_ctx *fresh = NULL;
        CHECK_RC(agc_ctx_reinit_after_fork(ctx, &fresh), AGC_ERR_CRYPTO_CONCURRENT_ACCESS);
        CHECK(fresh == NULL);
        _exit(0);
    }
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);

    /* Once the parent has closed the store, the child takes it over: its
     * own inherited copy of the lock must not keep it out. */
    int go[2];
    CHECK(pipe(go) == 0);
    fflush(NULL);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        char c;
        close(go[1]);
        CHECK(read(go[0], &c, 1) == 1);
        agc_ctx *fresh = NULL;
        CHECK_RC(agc_ctx_reinit_after_fork(ctx, &fresh), AGC_OK);
        CHECK_RC(create_policy(fresh, "default", DEFAULT_POLICY), AGC_OK);
        agc_key_info_response child_kr;
        AGC_INIT(&child_kr);
        child_kr.storage = (agc_buf){storage, sizeof storage};
        CHECK_RC(agc_read_key(fresh, "persistent", 0, &child_kr), AGC_OK);
        agc_ctx_close(fresh);
        _exit(0);
    }
    close(go[0]);
    agc_ctx_close(ctx);
    CHECK(write(go[1], "x", 1) == 1);
    close(go[1]);
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);

    /* ... is there after reopening. Policies live in memory, so the caller
     * restores them (the key names its policy by name). */
    CHECK_RC(open_store(wk, &ctx), AGC_OK);
    CHECK_RC(create_policy(ctx, "default",
                           "{\"version\": \"1\", \"allowed_templates\": [\"aes-128-gcm-128-96\"],"
                           " \"allowed_operations\": {\"key_operations\": [\"create_key\", \"encrypt\"]}}"),
             AGC_OK);
    AGC_INIT(&kr);
    kr.storage = (agc_buf){storage, sizeof storage};
    CHECK_RC(agc_read_key(ctx, "persistent", 0, &kr), AGC_OK);
    CHECK(kr.key_info.version == 1 && kr.key_info.origin == AGC_KEY_ORIGIN_GENERATED);
    uint8_t ct[64], md[128];
    size_t ct_len, md_len;
    encrypt_once(ctx, ct, &ct_len, md, &md_len);
    agc_ctx_close(ctx);

    /* Another wrapping key opens nothing; a readable one is refused; the
     * key is required with a file: store. */
    CHECK_RC(open_store(wk2, &ctx), AGC_ERR_INTERNAL);
    CHECK(chmod(wk, 0644) == 0);
    CHECK_RC(open_store(wk, &ctx), AGC_ERR_INVALID_ARGUMENT);
    CHECK(chmod(wk, 0600) == 0);
    CHECK_RC(open_store(NULL, &ctx), AGC_ERR_INVALID_ARGUMENT);

    /* Other schemes are reserved. */
    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    cfg.key_store_uri = "s3://bucket/keys";
    cfg.key_store_wrapping_key_path = wk;
    CHECK_RC(agc_ctx_open(&cfg, &ctx), AGC_ERR_NOT_IMPLEMENTED);

    char rm[600];
    snprintf(rm, sizeof rm, "rm -rf '%s'", tmpl);
    CHECK(system(rm) == 0);
    puts("test_key_store: ok");
    return 0;
}
