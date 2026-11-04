/* What is not available, and how it says so:
 * - operations the Go server stubs return AGC_ERR_NOT_IMPLEMENTED
 *   (DEVIATIONS G30), keeping the fail-safe output rules;
 * - session functions, with no session able to exist;
 * - agc_ctx_mode, and contexts inherited across fork() (agc_core.h FORK). */
#include <sys/wait.h>
#include <unistd.h>

#include "agc_test.h"

static void check_last_error(const char *needle)
{
    agc_error_detail d;
    AGC_INIT(&d);
    CHECK_RC(agc_last_error(&d), AGC_OK);
    CHECK(d.rc == AGC_ERR_NOT_IMPLEMENTED);
    CHECK(strstr(d.message, needle) != NULL);
}

static void stubs(agc_ctx *ctx)
{
    CHECK_RC(agc_delete_key(ctx, "k", 0), AGC_ERR_NOT_IMPLEMENTED);
    check_last_error("DeleteKey");

    uint8_t buf[16];
    CHECK_RC(agc_random_bytes(ctx, buf, sizeof buf), AGC_ERR_NOT_IMPLEMENTED);
    check_last_error("GenerateRandom");

    /* A verify-shaped stub still fails closed: valid is cleared (D9). */
    agc_verify_mac_request vr;
    AGC_INIT(&vr);
    agc_verify_response resp;
    AGC_INIT(&resp);
    resp.valid = 1;
    CHECK_RC(agc_verify_mac(ctx, &vr, &resp), AGC_ERR_NOT_IMPLEMENTED);
    CHECK(resp.valid == 0);

    /* A session-creating stub leaves no dangling handle behind. */
    agc_encrypt_init_request er;
    AGC_INIT(&er);
    agc_session *s = (agc_session *)&er; /* deliberately non-NULL */
    CHECK_RC(agc_encrypt_init(ctx, &er, &s), AGC_ERR_NOT_IMPLEMENTED);
    CHECK(s == NULL);
    check_last_error("EncryptInit");

    /* A NULL context is still an invalid argument, not "not implemented". */
    CHECK_RC(agc_delete_key(NULL, "k", 0), AGC_ERR_INVALID_ARGUMENT);
}

static void sessions(agc_ctx *ctx)
{
    agc_session *s = (agc_session *)ctx; /* deliberately non-NULL */
    CHECK_RC(agc_session_attach(ctx, "op-1", &s), AGC_ERR_CRYPTO_OPERATION_EXPIRED);
    CHECK(s == NULL);
    /* Unknown sessions: cancel succeeds, free is a no-op, accessors say none. */
    CHECK_RC(agc_session_cancel(NULL, NULL), AGC_OK);
    agc_session_free(NULL);
    CHECK(agc_session_id(NULL) == NULL);
    CHECK(agc_session_selected_template_id(NULL) == NULL);
    CHECK(agc_session_operation(NULL) == AGC_CRYPTO_OPERATION_UNSPECIFIED);
}

/* A key the child can try to use through the inherited context. */
static void create_key(agc_ctx *ctx)
{
    agc_create_key_params p = AEAD_KEY_PARAMS("inherited");
    uint8_t storage[1024];
    agc_key_info_response resp;
    AGC_INIT(&resp);
    resp.storage = (agc_buf){storage, sizeof storage};
    CHECK_RC(agc_create_key(ctx, &p, &resp), AGC_OK);
}

static agc_rc read_key(agc_ctx *ctx, const char *name)
{
    uint8_t storage[1024];
    agc_key_info_response resp;
    AGC_INIT(&resp);
    resp.storage = (agc_buf){storage, sizeof storage};
    return agc_read_key(ctx, name, 0, &resp); /* 0: the current version */
}

static void fork_poisons_the_context(agc_ctx *ctx)
{
    create_key(ctx);
    /* Not poisoned in the process that opened it. */
    agc_ctx *fresh = NULL;
    CHECK_RC(agc_ctx_reinit_after_fork(ctx, &fresh), AGC_ERR_INVALID_ARGUMENT);
    CHECK(fresh == NULL);

    fflush(NULL);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        /* The child: the inherited context is refused ... */
        CHECK_RC(read_key(ctx, "inherited"), AGC_ERR_INVALID_HANDLE);
        /* ... until it is re-initialised: a fresh context from the same
         * configuration, sharing none of the parent's state. */
        CHECK_RC(agc_ctx_reinit_after_fork(ctx, &fresh), AGC_OK);
        CHECK(fresh != NULL);
        CHECK(agc_ctx_mode(fresh) == AGC_MODE_EMBEDDED);
        CHECK_RC(read_key(fresh, "inherited"), AGC_ERR_CRYPTO_KEY_NOT_FOUND);
        CHECK_RC(create_policy(fresh, "default", DEFAULT_POLICY), AGC_OK);
        create_key(fresh);
        agc_ctx_close(fresh);
        _exit(0);
    }
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    /* The parent's context is unaffected. */
    CHECK_RC(read_key(ctx, "inherited"), AGC_OK);
}

int main(void)
{
    agc_ctx *ctx = open_embedded();
    CHECK(agc_ctx_mode(ctx) == AGC_MODE_EMBEDDED);
    stubs(ctx);
    sessions(ctx);
    fork_poisons_the_context(ctx);
    agc_ctx_close(ctx);
    puts("test_unavailable: ok");
    return 0;
}
