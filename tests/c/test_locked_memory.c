/* agc_core.h: require_locked_memory. With it, key material and the file
 * store's wrapping key must be locked in RAM: context creation fails if
 * memory cannot be locked at all, and an operation whose new key material
 * cannot be locked fails with AGC_ERR_OUT_OF_MEMORY and stores nothing.
 * Without it, locking is best effort (docs/performance.md F8: past
 * RLIMIT_MEMLOCK keys used to be created unlocked, silently).
 *
 * The test lowers RLIMIT_MEMLOCK for its own process to provoke the failures. */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#define _DEFAULT_SOURCE /* glibc: MAP_ANON */
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "agc_test.h"

static void set_memlock(rlim_t bytes)
{
    struct rlimit r;
    CHECK(getrlimit(RLIMIT_MEMLOCK, &r) == 0);
    r.rlim_cur = bytes;
    CHECK(setrlimit(RLIMIT_MEMLOCK, &r) == 0);
}

/* Whether mlock can fail here once RLIMIT_MEMLOCK is 0. Not under ASan or
 * TSan, which intercept mlock process-wide and make it succeed, nor for a
 * privileged process (Linux CAP_IPC_LOCK, e.g. root in a container). */
static int mlock_can_fail(void)
{
    long page = sysconf(_SC_PAGESIZE);
    void *p = mmap(NULL, (size_t)page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    CHECK(p != MAP_FAILED);
    int locked = mlock(p, (size_t)page) == 0;
    if (locked)
        munlock(p, (size_t)page);
    munmap(p, (size_t)page);
    return !locked;
}

static agc_rc open_ctx(int require_locked, const char *uri, const char *wrapping_key, agc_ctx **ctx)
{
    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    cfg.require_locked_memory = require_locked;
    cfg.key_store_uri = uri;
    cfg.key_store_wrapping_key_path = wrapping_key;
    *ctx = (agc_ctx *)&cfg; /* deliberately non-NULL: a failed open must clear it */
    agc_rc rc = agc_ctx_open(&cfg, ctx);
    if (rc != AGC_OK)
        CHECK(*ctx == NULL);
    return rc;
}

static agc_rc create_key(agc_ctx *ctx, const char *name)
{
    agc_create_key_params p = AEAD_KEY_PARAMS(name);
    uint8_t storage[512];
    agc_key_info_response resp;
    AGC_INIT(&resp);
    resp.storage = (agc_buf){storage, sizeof storage};
    return agc_create_key(ctx, &p, &resp);
}

static int key_exists(agc_ctx *ctx, const char *name)
{
    uint8_t storage[512];
    agc_key_info_response resp;
    AGC_INIT(&resp);
    resp.storage = (agc_buf){storage, sizeof storage};
    agc_rc rc = agc_read_key(ctx, name, 0, &resp);
    CHECK(rc == AGC_OK || rc == AGC_ERR_CRYPTO_KEY_NOT_FOUND);
    return rc == AGC_OK;
}

int main(void)
{
    struct rlimit original;
    CHECK(getrlimit(RLIMIT_MEMLOCK, &original) == 0);
    long page = sysconf(_SC_PAGESIZE);
    agc_ctx *ctx;

    /* Enough lockable memory: required locking works like the default. */
    CHECK_RC(open_ctx(1, NULL, NULL, &ctx), AGC_OK);
    CHECK_RC(create_policy(ctx, "default", DEFAULT_POLICY), AGC_OK);
    CHECK_RC(create_key(ctx, "locked"), AGC_OK);

    /* A forked child gets no (unlocked) copy of the secrets: the poisoned
     * context is replaced, dropping it must work, and the child's fresh
     * context locks its own keys again. */
    fflush(NULL);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        agc_ctx *fresh = NULL;
        if (agc_ctx_reinit_after_fork(ctx, &fresh) != AGC_OK)
            _exit(2);
        if (create_policy(fresh, "default", DEFAULT_POLICY) != AGC_OK || create_key(fresh, "child") != AGC_OK)
            _exit(3);
        agc_ctx_close(fresh);
        _exit(0);
    }
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(key_exists(ctx, "locked")); /* the parent is unaffected */
    agc_ctx_close(ctx);

    set_memlock(0);
    if (!mlock_can_fail()) {
        printf("test_locked_memory: mlock cannot fail in this environment "
               "(sanitizer or privileged process); limit cases skipped\n");
        return 0;
    }
    CHECK(setrlimit(RLIMIT_MEMLOCK, &original) == 0);

    /* Nothing can be locked: a required context does not open; the default
     * one does, and its keys are best effort. */
    set_memlock(0);
    CHECK_RC(open_ctx(1, NULL, NULL, &ctx), AGC_ERR_OUT_OF_MEMORY);
    CHECK_RC(open_ctx(0, NULL, NULL, &ctx), AGC_OK);
    CHECK_RC(create_policy(ctx, "default", DEFAULT_POLICY), AGC_OK);
    CHECK_RC(create_key(ctx, "unlocked"), AGC_OK);
    agc_ctx_close(ctx);

    /* Locked memory runs out later: the key that cannot be locked fails
     * with AGC_ERR_OUT_OF_MEMORY, nothing is stored, the context stays
     * usable, and keys work again once memory is freed. */
    set_memlock((rlim_t)page * 4);
    CHECK_RC(open_ctx(1, NULL, NULL, &ctx), AGC_OK);
    CHECK_RC(create_policy(ctx, "default", DEFAULT_POLICY), AGC_OK);
    int created = 0;
    agc_rc rc = AGC_OK;
    char name[32];
    for (int i = 0; i < 64 && rc == AGC_OK; i++) {
        snprintf(name, sizeof name, "k%d", i);
        rc = create_key(ctx, name);
        if (rc == AGC_OK)
            created++;
    }
    CHECK_RC(rc, AGC_ERR_OUT_OF_MEMORY);
    agc_error_detail d;
    AGC_INIT(&d);
    CHECK_RC(agc_last_error(&d), AGC_OK);
    CHECK(d.rc == AGC_ERR_OUT_OF_MEMORY);
    CHECK(strstr(d.message, "locked") != NULL);
    CHECK(created >= 1 && created <= 4);
    CHECK(!key_exists(ctx, name)); /* the failed one was not stored */
    CHECK(key_exists(ctx, "k0"));
    agc_ctx_close(ctx); /* frees every locked page */

    /* A file store: its wrapping key is locked too, and a store whose keys
     * cannot all be locked does not open with require_locked_memory. */
    CHECK(setrlimit(RLIMIT_MEMLOCK, &original) == 0);
    char dir[] = "/tmp/agc-locked-XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    char uri[64], wk[64];
    snprintf(uri, sizeof uri, "file:%s/keys", dir);
    snprintf(wk, sizeof wk, "%s/wrapping.key", dir);
    int fd = open(wk, O_WRONLY | O_CREAT | O_EXCL, 0600);
    CHECK(fd >= 0);
    uint8_t key[32];
    memset(key, 0x5a, sizeof key);
    CHECK(write(fd, key, sizeof key) == (ssize_t)sizeof key);
    close(fd);
    CHECK_RC(open_ctx(1, uri, wk, &ctx), AGC_OK);
    CHECK_RC(create_policy(ctx, "default", DEFAULT_POLICY), AGC_OK);
    for (int i = 0; i < 6; i++) {
        snprintf(name, sizeof name, "stored%d", i);
        CHECK_RC(create_key(ctx, name), AGC_OK);
    }
    agc_ctx_close(ctx);
    set_memlock((rlim_t)page * 3); /* the wrapping key and two of six keys */
    CHECK_RC(open_ctx(1, uri, wk, &ctx), AGC_ERR_OUT_OF_MEMORY);
    CHECK_RC(open_ctx(0, uri, wk, &ctx), AGC_OK);
    CHECK(key_exists(ctx, "stored5"));
    agc_ctx_close(ctx);
    CHECK(setrlimit(RLIMIT_MEMLOCK, &original) == 0);

    char cmd[96];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
    CHECK(system(cmd) == 0);
    return 0;
}
