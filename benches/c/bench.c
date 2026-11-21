/* The C side of docs/performance.md: the real agc_* path (layer L3).
 *
 *   L3a  one call with buffers already big enough (the fast path a
 *        latency-sensitive caller uses)
 *   L3b  the two-call protocol: a size query, then the call
 *
 * Every iteration is timed on its own, so the output has the distribution
 * (min, p50, p90, p99, p99.9, max), not only a mean. Also: the first call in
 * the process and on a fresh key, throughput and latency under 1..N threads
 * on one shared key and on one key per thread, resident memory per context
 * and per key, and the file key store (create, reopen).
 *
 * Run with `cargo xtask bench [--quick] [--csv FILE] [--only SECTION]`
 * (`--only contention --threads N [--shared] --seconds S` is one thread
 * configuration on its own, for a profiler); it builds the release
 * library first. Results go to stdout; --csv also writes one row per
 * measurement. */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#define _DEFAULT_SOURCE /* glibc: MAP_ANON, getentropy */
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h> /* getentropy */
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#ifdef __APPLE__
#include <mach/mach.h>
#include <malloc/malloc.h>
#endif

#include "agilecrypto.h"

/* ------------------------------------------------------------------------ */
/* Plumbing                                                                  */
/* ------------------------------------------------------------------------ */

static double run_seconds = 1.0; /* per measurement; --quick: 0.25 */
static FILE *csv;

static void die(agc_rc rc, const char *what)
{
    agc_error_detail d;
    AGC_INIT(&d);
    agc_last_error(&d);
    fprintf(stderr, "bench: %s: %s (%s)\n", what, agc_rc_name(rc), d.message ? d.message : "");
    exit(1);
}

static void check(agc_rc rc, const char *what)
{
    if (rc != AGC_OK)
        die(rc, what);
}

static void size_query(agc_rc rc, const char *what)
{
    if (rc != AGC_ERR_BUFFER_TOO_SMALL)
        die(rc, what);
}

static void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p) {
        fprintf(stderr, "bench: out of memory\n");
        exit(1);
    }
    return p;
}

/* Monotonic nanoseconds. On macOS clock_gettime(CLOCK_MONOTONIC) resolves to
 * 1 µs only; CLOCK_UPTIME_RAW is the mach tick (~42 ns on Apple silicon). */
static uint64_t now_ns(void)
{
#ifdef __APPLE__
    return clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
#endif
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
}

/* Resident set size of the process, in bytes. */
static size_t rss_bytes(void)
{
#ifdef __APPLE__
    mach_task_basic_info_data_t info;
    mach_msg_type_number_t n = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info, &n) != KERN_SUCCESS)
        return 0;
    return (size_t)info.resident_size;
#else
    long pages = 0, resident = 0;
    FILE *f = fopen("/proc/self/statm", "r");
    if (!f)
        return 0;
    if (fscanf(f, "%ld %ld", &pages, &resident) != 2)
        resident = 0;
    fclose(f);
    return (size_t)resident * (size_t)sysconf(_SC_PAGESIZE);
#endif
}

/* ------------------------------------------------------------------------ */
/* Statistics                                                                */
/* ------------------------------------------------------------------------ */

typedef struct {
    uint64_t *v;
    size_t n, cap;
} samples;

static void push(samples *s, uint64_t x)
{
    if (s->n == s->cap) {
        s->cap = s->cap ? s->cap * 2 : 4096;
        s->v = realloc(s->v, s->cap * sizeof *s->v);
        if (!s->v) {
            fprintf(stderr, "bench: out of memory\n");
            exit(1);
        }
    }
    s->v[s->n++] = x;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

static uint64_t pct(const samples *s, double p)
{
    size_t i = (size_t)(p * (double)s->n);
    return s->v[i >= s->n ? s->n - 1 : i];
}

static void print_header(void)
{
    printf("%-44s %8s %9s %9s %9s %9s %9s %9s %9s\n", "measurement (µs)", "n", "min", "p50", "p90", "p99",
           "p99.9", "max", "mean");
}

/* Sorts and prints one row; also to the CSV. */
static void report(const char *name, samples *s)
{
    qsort(s->v, s->n, sizeof *s->v, cmp_u64);
    double sum = 0;
    for (size_t i = 0; i < s->n; i++)
        sum += (double)s->v[i];
    double us = 1e-3;
    printf("%-44s %8zu %9.2f %9.2f %9.2f %9.2f %9.2f %9.2f %9.2f\n", name, s->n, s->v[0] * us, pct(s, .5) * us,
           pct(s, .9) * us, pct(s, .99) * us, pct(s, .999) * us, s->v[s->n - 1] * us, sum / (double)s->n * us);
    if (csv)
        fprintf(csv, "%s,%zu,%llu,%llu,%llu,%llu,%llu,%llu,%.0f\n", name, s->n, (unsigned long long)s->v[0],
                (unsigned long long)pct(s, .5), (unsigned long long)pct(s, .9), (unsigned long long)pct(s, .99),
                (unsigned long long)pct(s, .999), (unsigned long long)s->v[s->n - 1], sum / (double)s->n);
    fflush(stdout);
}

/* ------------------------------------------------------------------------ */
/* Keys and policies                                                         */
/* ------------------------------------------------------------------------ */

typedef enum { SIGN, AEAD, PLAIN } kind;

typedef struct {
    const char *template_id;
    kind kind;
} algo;

static const algo SIGNERS[] = {
    {"ed25519", SIGN},          {"ecdsa-p256-sha256-der", SIGN}, {"ecdsa-p384-sha384-der", SIGN},
    {"ecdsa-p521-sha512-der", SIGN}, {"ml-dsa-44", SIGN},        {"ml-dsa-65", SIGN},
    {"ml-dsa-87", SIGN},
};
static const algo CIPHERS[] = {
    {"aes-128-gcm-128-96", AEAD},
    {"aes-256-gcm-128-96", AEAD},
    {"chacha20-poly1305", AEAD},
    {"aes-256-cbc-pkcs7-128", PLAIN},
    {"aes-256-ctr", PLAIN},
};

/* One policy per template, named after it, that allows only that template:
 * a key created under it gets exactly this algorithm. */
static void add_policy(agc_ctx *ctx, const char *template_id)
{
    char doc[512];
    snprintf(doc, sizeof doc,
             "{\"version\": \"1\", \"allowed_templates\": [\"%s\"], \"allowed_operations\": {\"key_operations\":"
             " [\"create_key\", \"sign\", \"verify\", \"encrypt\", \"decrypt\"]}}",
             template_id);
    agc_create_policy_request req;
    AGC_INIT(&req);
    req.name = template_id;
    req.policy_document = doc;
    check(agc_create_policy(ctx, &req, NULL), "agc_create_policy");
}

static void add_policies(agc_ctx *ctx)
{
    for (size_t i = 0; i < sizeof SIGNERS / sizeof *SIGNERS; i++)
        add_policy(ctx, SIGNERS[i].template_id);
    for (size_t i = 0; i < sizeof CIPHERS / sizeof *CIPHERS; i++)
        add_policy(ctx, CIPHERS[i].template_id);
}

/* Creates `name` for `a`; checks the policy picked the template. */
static void create_key(agc_ctx *ctx, const algo *a, const char *name)
{
    agc_create_key_params kp;
    AGC_INIT(&kp);
    kp.key_name = name;
    kp.policy_name = a->template_id;
    AGC_INIT(&kp.scope_spec);
    switch (a->kind) {
    case SIGN:
        kp.scope_spec.kind = AGC_SCOPE_KIND_SIGNATURE;
        kp.scope_spec.u.signature.scope = AGC_SIGNATURE_SCOPE_STANDARD;
        break;
    case AEAD:
        kp.scope_spec.kind = AGC_SCOPE_KIND_AEAD;
        break;
    case PLAIN:
        kp.scope_spec.kind = AGC_SCOPE_KIND_SYMMETRIC_CIPHER;
        break;
    }
    static _Thread_local uint8_t storage[16384]; /* ML-DSA key info is ~1.4 KB */
    agc_key_info_response info;
    AGC_INIT(&info);
    info.storage = (agc_buf){storage, sizeof storage};
    check(agc_create_key(ctx, &kp, &info), "agc_create_key");
    if (strcmp(info.key_info.template_id, a->template_id) != 0) {
        fprintf(stderr, "bench: %s got template %s\n", a->template_id, info.key_info.template_id);
        exit(1);
    }
}

/* ------------------------------------------------------------------------ */
/* Operations                                                                */
/* ------------------------------------------------------------------------ */

/* Everything one operation needs, with outputs sized once up front. */
typedef struct {
    agc_ctx *ctx;
    const char *key;
    kind kind;
    size_t n;
    uint8_t *input;
    agc_sign_params sp;
    agc_encrypt_params ep;
    /* outputs */
    uint8_t *out, *md;
    size_t out_cap, md_cap;
    /* a ciphertext or signature of `input` and its metadata, for the reverse operation */
    uint8_t *ct, *ct_md;
    size_t ct_len, ct_md_len;
    uint8_t *pt;
    size_t pt_cap;
} op_state;

typedef void (*op_fn)(op_state *);

static agc_sign_request sign_req(op_state *s)
{
    agc_sign_request r;
    AGC_INIT(&r);
    r.key_name = s->key;
    r.input = (agc_slice){s->input, s->n};
    r.params = &s->sp;
    r.metadata_encoding = AGC_ENCODING_WIRE_V1;
    return r;
}

static agc_encrypt_request enc_req(op_state *s)
{
    agc_encrypt_request r;
    AGC_INIT(&r);
    r.key_name = s->key;
    r.plaintext = (agc_slice){s->input, s->n};
    r.params = &s->ep;
    r.metadata_encoding = AGC_ENCODING_WIRE_V1;
    return r;
}

static agc_decrypt_request dec_req(op_state *s)
{
    agc_decrypt_request r;
    AGC_INIT(&r);
    r.key_name = s->key;
    r.ciphertext = (agc_slice){s->ct, s->ct_len};
    r.metadata = (agc_slice){s->ct_md, s->ct_md_len};
    r.params = &s->ep;
    return r;
}

static void op_sign(op_state *s) /* L3a */
{
    agc_sign_request r = sign_req(s);
    agc_sign_response o;
    AGC_INIT(&o);
    o.signature = (agc_buf){s->out, s->out_cap};
    o.metadata = (agc_buf){s->md, s->md_cap};
    check(agc_sign(s->ctx, &r, &o), "agc_sign");
}

static void op_sign2(op_state *s) /* L3b */
{
    agc_sign_request r = sign_req(s);
    agc_sign_response o;
    AGC_INIT(&o);
    size_query(agc_sign(s->ctx, &r, &o), "agc_sign (size)");
    o.signature = (agc_buf){s->out, o.signature_len};
    o.metadata = (agc_buf){s->md, o.metadata_len};
    check(agc_sign(s->ctx, &r, &o), "agc_sign");
}

static void op_verify(op_state *s)
{
    agc_verify_request r;
    AGC_INIT(&r);
    r.key_name = s->key;
    r.input = (agc_slice){s->input, s->n};
    r.signature = (agc_slice){s->ct, s->ct_len};
    r.metadata = (agc_slice){s->ct_md, s->ct_md_len};
    r.params = &s->sp;
    agc_verify_response o;
    AGC_INIT(&o);
    check(agc_verify(s->ctx, &r, &o), "agc_verify");
    if (!o.valid)
        die(AGC_ERR_INTERNAL, "agc_verify: not valid");
}

static void op_encrypt(op_state *s)
{
    agc_encrypt_request r = enc_req(s);
    agc_encrypt_response o;
    AGC_INIT(&o);
    o.ciphertext = (agc_buf){s->out, s->out_cap};
    o.metadata = (agc_buf){s->md, s->md_cap};
    check(agc_encrypt(s->ctx, &r, &o), "agc_encrypt");
}

static void op_encrypt2(op_state *s)
{
    agc_encrypt_request r = enc_req(s);
    agc_encrypt_response o;
    AGC_INIT(&o);
    size_query(agc_encrypt(s->ctx, &r, &o), "agc_encrypt (size)");
    o.ciphertext = (agc_buf){s->out, o.ciphertext_len};
    o.metadata = (agc_buf){s->md, o.metadata_len};
    check(agc_encrypt(s->ctx, &r, &o), "agc_encrypt");
}

static void op_decrypt(op_state *s)
{
    agc_decrypt_request r = dec_req(s);
    agc_decrypt_response o;
    AGC_INIT(&o);
    o.plaintext = (agc_buf){s->pt, s->pt_cap};
    check(agc_decrypt(s->ctx, &r, &o), "agc_decrypt");
}

static void op_decrypt2(op_state *s)
{
    agc_decrypt_request r = dec_req(s);
    agc_decrypt_response o;
    AGC_INIT(&o);
    size_query(agc_decrypt(s->ctx, &r, &o), "agc_decrypt (size)");
    o.plaintext = (agc_buf){s->pt, o.plaintext_len};
    check(agc_decrypt(s->ctx, &r, &o), "agc_decrypt");
}

/* Sizes the outputs with a size query and makes one signature or
 * ciphertext for verify/decrypt. */
static void op_init(op_state *s, agc_ctx *ctx, const char *key, kind k, size_t n)
{
    memset(s, 0, sizeof *s);
    s->ctx = ctx;
    s->key = key;
    s->kind = k;
    s->n = n;
    s->input = xmalloc(n);
    for (size_t i = 0; i < n; i++)
        s->input[i] = (uint8_t)(i * 31 + 7);
    AGC_INIT(&s->sp);
    s->sp.kind = AGC_SIGN_PARAMS_NO_CONTEXT;
    AGC_INIT(&s->ep);
    if (k == AEAD) {
        s->ep.kind = AGC_ENCRYPT_PARAMS_AEAD;
        s->ep.u.aead.aad = (agc_slice){(const uint8_t *)"ad", 2};
    } else {
        s->ep.kind = AGC_ENCRYPT_PARAMS_NO_PARAMS;
    }

    if (k == SIGN) {
        agc_sign_request r = sign_req(s);
        agc_sign_response o;
        AGC_INIT(&o);
        size_query(agc_sign(ctx, &r, &o), "agc_sign (size)");
        s->out_cap = o.signature_len;
        s->md_cap = o.metadata_len;
    } else {
        agc_encrypt_request r = enc_req(s);
        agc_encrypt_response o;
        AGC_INIT(&o);
        size_query(agc_encrypt(ctx, &r, &o), "agc_encrypt (size)");
        s->out_cap = o.ciphertext_len;
        s->md_cap = o.metadata_len;
    }
    s->out = xmalloc(s->out_cap);
    s->md = xmalloc(s->md_cap);
    s->ct = xmalloc(s->out_cap);
    s->ct_md = xmalloc(s->md_cap);

    if (k == SIGN) {
        agc_sign_request r = sign_req(s);
        agc_sign_response o;
        AGC_INIT(&o);
        o.signature = (agc_buf){s->ct, s->out_cap};
        o.metadata = (agc_buf){s->ct_md, s->md_cap};
        check(agc_sign(ctx, &r, &o), "agc_sign");
        s->ct_len = o.signature_len;
        s->ct_md_len = o.metadata_len;
    } else {
        agc_encrypt_request r = enc_req(s);
        agc_encrypt_response o;
        AGC_INIT(&o);
        o.ciphertext = (agc_buf){s->ct, s->out_cap};
        o.metadata = (agc_buf){s->ct_md, s->md_cap};
        check(agc_encrypt(ctx, &r, &o), "agc_encrypt");
        s->ct_len = o.ciphertext_len;
        s->ct_md_len = o.metadata_len;
        agc_decrypt_request dr = dec_req(s);
        agc_decrypt_response d;
        AGC_INIT(&d);
        size_query(agc_decrypt(ctx, &dr, &d), "agc_decrypt (size)");
        s->pt_cap = d.plaintext_len;
        s->pt = xmalloc(s->pt_cap);
    }
}

static void op_free(op_state *s)
{
    free(s->input);
    free(s->out);
    free(s->md);
    free(s->ct);
    free(s->ct_md);
    free(s->pt);
}

/* Warms up for a tenth of the run, then times single iterations until
 * run_seconds have passed (at least 50 samples). */
static void measure(const char *name, op_fn fn, op_state *s)
{
    uint64_t start = now_ns(), warm = (uint64_t)(run_seconds * 1e8);
    while (now_ns() - start < warm)
        fn(s);
    samples smp = {0};
    uint64_t budget = (uint64_t)(run_seconds * 1e9);
    start = now_ns();
    while (smp.n < 50 || now_ns() - start < budget) {
        uint64_t t0 = now_ns();
        fn(s);
        push(&smp, now_ns() - t0);
    }
    report(name, &smp);
    free(smp.v);
}

/* ------------------------------------------------------------------------ */
/* Sections                                                                  */
/* ------------------------------------------------------------------------ */

static agc_ctx *open_memory_ctx(void)
{
    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    agc_ctx *ctx = NULL;
    check(agc_ctx_open(&cfg, &ctx), "agc_ctx_open");
    add_policies(ctx);
    return ctx;
}

/* The very first operations in the process, before anything is warm. */
static void first_calls(void)
{
    printf("\n== first calls (cold process) ==\n");
    uint64_t t0 = now_ns();
    agc_ctx *ctx = open_memory_ctx();
    uint64_t t1 = now_ns();
    create_key(ctx, &SIGNERS[0], "first");
    uint64_t t2 = now_ns();
    op_state s;
    op_init(&s, ctx, "first", SIGN, 1024); /* a size query and one sign */
    uint64_t t3 = now_ns();
    op_sign(&s);
    uint64_t t4 = now_ns();
    printf("agc_ctx_open + %zu policies      %10.1f µs\n", sizeof SIGNERS / sizeof *SIGNERS +
           sizeof CIPHERS / sizeof *CIPHERS, (t1 - t0) * 1e-3);
    printf("first agc_create_key (ed25519)  %10.1f µs\n", (t2 - t1) * 1e-3);
    printf("first size query + sign         %10.1f µs\n", (t3 - t2) * 1e-3);
    printf("second sign                     %10.1f µs\n", (t4 - t3) * 1e-3);
    op_free(&s);
    agc_ctx_close(ctx);
}

static void latency(agc_ctx *ctx)
{
    printf("\n== latency per call, one thread, in-memory store (WIRE_V1 metadata) ==\n");
    print_header();
    char name[96];
    for (size_t i = 0; i < sizeof SIGNERS / sizeof *SIGNERS; i++) {
        const algo *a = &SIGNERS[i];
        create_key(ctx, a, a->template_id);
        op_state s;
        op_init(&s, ctx, a->template_id, SIGN, 1024);
        snprintf(name, sizeof name, "sign/%s/1024/L3a", a->template_id);
        measure(name, op_sign, &s);
        snprintf(name, sizeof name, "sign/%s/1024/L3b", a->template_id);
        measure(name, op_sign2, &s);
        snprintf(name, sizeof name, "verify/%s/1024", a->template_id);
        measure(name, op_verify, &s);
        op_free(&s);
    }
    static const size_t sizes[] = {32, 1024, 16384, 1048576};
    for (size_t i = 0; i < sizeof CIPHERS / sizeof *CIPHERS; i++) {
        const algo *a = &CIPHERS[i];
        create_key(ctx, a, a->template_id);
        for (size_t j = 0; j < sizeof sizes / sizeof *sizes; j++) {
            op_state s;
            op_init(&s, ctx, a->template_id, a->kind, sizes[j]);
            snprintf(name, sizeof name, "enc/%s/%zu/L3a", a->template_id, sizes[j]);
            measure(name, op_encrypt, &s);
            snprintf(name, sizeof name, "enc/%s/%zu/L3b", a->template_id, sizes[j]);
            measure(name, op_encrypt2, &s);
            snprintf(name, sizeof name, "dec/%s/%zu/L3a", a->template_id, sizes[j]);
            measure(name, op_decrypt, &s);
            snprintf(name, sizeof name, "dec/%s/%zu/L3b", a->template_id, sizes[j]);
            measure(name, op_decrypt2, &s);
            op_free(&s);
        }
    }
}

/* A start barrier (macOS has no pthread_barrier_t). */
typedef struct {
    pthread_mutex_t m;
    pthread_cond_t c;
    int waiting, total;
} barrier;

static void barrier_init(barrier *b, int total)
{
    pthread_mutex_init(&b->m, NULL);
    pthread_cond_init(&b->c, NULL);
    b->waiting = 0;
    b->total = total;
}

static void barrier_wait(barrier *b)
{
    pthread_mutex_lock(&b->m);
    if (++b->waiting == b->total)
        pthread_cond_broadcast(&b->c);
    while (b->waiting < b->total)
        pthread_cond_wait(&b->c, &b->m);
    pthread_mutex_unlock(&b->m);
}

static void barrier_destroy(barrier *b)
{
    pthread_mutex_destroy(&b->m);
    pthread_cond_destroy(&b->c);
}

/* Threads: each runs `fn` for run_seconds on its own op_state and keeps its
 * latencies; the main thread merges them. */
typedef struct {
    op_state s;
    op_fn fn;
    samples smp;
    barrier *go;
} worker;

static void *work(void *arg)
{
    worker *w = arg;
    barrier_wait(w->go);
    uint64_t start = now_ns(), budget = (uint64_t)(run_seconds * 1e9);
    while (now_ns() - start < budget) {
        uint64_t t0 = now_ns();
        w->fn(&w->s);
        push(&w->smp, now_ns() - t0);
    }
    return NULL;
}

/* Which key layouts `scaling` runs. */
enum { BOTH, SHARED_ONLY, OWN_ONLY };

static void scaling(agc_ctx *ctx, const algo *a, size_t n, op_fn fn, const char *label, const int *counts,
                    size_t ncounts, int layouts)
{
    double base = 0;
    for (int shared = 1; shared >= 0; shared--) {
        if ((shared && layouts == OWN_ONLY) || (!shared && layouts == SHARED_ONLY))
            continue;
        for (size_t c = 0; c < ncounts; c++) {
            int t = counts[c];
            worker *w = calloc((size_t)t, sizeof *w);
            pthread_t *th = calloc((size_t)t, sizeof *th);
            barrier go;
            barrier_init(&go, t);
            char keys[12][64];
            for (int i = 0; i < t; i++) {
                snprintf(keys[i], sizeof keys[i], "%s-t%d", a->template_id, i);
                const char *key = shared ? a->template_id : keys[i];
                w[i].fn = fn;
                w[i].go = &go;
                op_init(&w[i].s, ctx, key, a->kind, n);
            }
            for (int i = 0; i < t; i++)
                pthread_create(&th[i], NULL, work, &w[i]);
            samples all = {0};
            for (int i = 0; i < t; i++) {
                pthread_join(th[i], NULL);
                for (size_t j = 0; j < w[i].smp.n; j++)
                    push(&all, w[i].smp.v[j]);
                free(w[i].smp.v);
                op_free(&w[i].s);
            }
            double ops = (double)all.n / run_seconds;
            if (t == 1 && base == 0)
                base = ops;
            char name[128];
            snprintf(name, sizeof name, "%s/%s/%dT", label, shared ? "shared-key" : "own-key", t);
            report(name, &all);
            if (base > 0)
                printf("%-44s %8.0f ops/s (%.0f per thread), %.2fx of 1 thread\n", "", ops, ops / t, ops / base);
            else
                printf("%-44s %8.0f ops/s (%.0f per thread)\n", "", ops, ops / t);
            if (csv)
                fprintf(csv, "%s/ops_per_s,%.0f\n", name, ops);
            free(all.v);
            barrier_destroy(&go);
            free(w);
            free(th);
        }
    }
}

/* Creates the per-thread keys "<template>-t<i>" for `threads` and `contention`. */
static void thread_keys(agc_ctx *ctx)
{
    for (int i = 0; i < 12; i++) {
        char k[64];
        snprintf(k, sizeof k, "%s-t%d", SIGNERS[0].template_id, i);
        create_key(ctx, &SIGNERS[0], k);
        snprintf(k, sizeof k, "%s-t%d", CIPHERS[1].template_id, i);
        create_key(ctx, &CIPHERS[1], k);
    }
}

static const int COUNTS[] = {1, 2, 4, 8, 12};

static void threads(agc_ctx *ctx)
{
    printf("\n== threads: one context, a shared key vs one key per thread ==\n");
    print_header();
    thread_keys(ctx);
    size_t nc = sizeof COUNTS / sizeof *COUNTS;
    scaling(ctx, &SIGNERS[0], 1024, op_sign, "threads/sign/ed25519/1024", COUNTS, nc, BOTH);
    scaling(ctx, &CIPHERS[1], 32, op_encrypt, "threads/enc/aes-256-gcm/32", COUNTS, nc, BOTH);
    /* Decryption draws no randomness: what remains is the library's own
     * shared state (key index, policy store). */
    scaling(ctx, &CIPHERS[1], 32, op_decrypt, "threads/dec/aes-256-gcm/32", COUNTS, nc, BOTH);
}

/* One configuration of the AES-GCM 32 B scaling run, for profiling:
 * `--only contention --threads N [--shared] [--seconds S]`. */
static int contention_threads = 8, contention_shared;

static void contention(agc_ctx *ctx)
{
    printf("\n== contention: AES-256-GCM 32 B, %d thread(s), %s ==\n", contention_threads,
           contention_shared ? "shared key" : "own key");
    print_header();
    thread_keys(ctx);
    scaling(ctx, &CIPHERS[1], 32, op_encrypt, "contention/enc/aes-256-gcm/32", &contention_threads, 1,
            contention_shared ? SHARED_ONLY : OWN_ONLY);
}

/* Locked memory of this process in KiB (Linux: VmLck), or -1. */
static long locked_kib(void)
{
#ifdef __linux__
    FILE *f = fopen("/proc/self/status", "r");
    if (!f)
        return -1;
    char line[256];
    long kib = -1;
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "VmLck: %ld kB", &kib) == 1)
            break;
    fclose(f);
    return kib;
#else
    return -1;
#endif
}

static int memory_keys = 1000; /* --keys N */

static void memory(void)
{
    printf("\n== resident memory ==\n");
    struct rlimit rl;
    if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
        if (rl.rlim_cur == RLIM_INFINITY)
            printf("RLIMIT_MEMLOCK: unlimited\n");
        else
            printf("RLIMIT_MEMLOCK: %llu KiB\n", (unsigned long long)rl.rlim_cur / 1024);
    }
    printf("page size: %ld bytes\n", sysconf(_SC_PAGESIZE));
    size_t before = rss_bytes();
    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    agc_ctx *ctx = NULL;
    check(agc_ctx_open(&cfg, &ctx), "agc_ctx_open");
    add_policies(ctx);
    size_t opened = rss_bytes();
    printf("context (open + 12 policies): %+.1f KiB\n", (double)(opened - before) / 1024);
    const algo *which[] = {&CIPHERS[1], &SIGNERS[0], &SIGNERS[5]};
    const int N = memory_keys;
    if (locked_kib() >= 0)
        printf("locked before keys: %ld KiB\n", locked_kib());
    for (size_t w = 0; w < 3; w++) {
        size_t r0 = rss_bytes();
        samples smp = {0};
        for (int i = 0; i < N; i++) {
            char k[64];
            snprintf(k, sizeof k, "mem-%s-%d", which[w]->template_id, i);
            uint64_t t0 = now_ns();
            create_key(ctx, which[w], k);
            push(&smp, now_ns() - t0);
        }
        size_t r1 = rss_bytes();
        printf("%d keys %-24s %+9.1f KiB  = %.2f KiB per key\n", N, which[w]->template_id,
               (double)(r1 - r0) / 1024, (double)(r1 - r0) / 1024 / N);
        if (locked_kib() >= 0)
            printf("locked memory now: %ld KiB (%.2f KiB per key so far)\n", locked_kib(),
                   (double)locked_kib() / (double)(N * (int)(w + 1)));
        char name[96];
        snprintf(name, sizeof name, "create_key/memory/%s", which[w]->template_id);
        print_header();
        report(name, &smp);
        free(smp.v);
    }
    agc_ctx_close(ctx);
}

/* The file key store: create keys (each one written and fsynced), then
 * reopen the store with them. */
static void file_store(void)
{
    printf("\n== file key store ==\n");
    char dir[] = "/tmp/agc-bench-XXXXXX";
    if (!mkdtemp(dir)) {
        perror("mkdtemp");
        exit(1);
    }
    char uri[96], wk[96];
    snprintf(uri, sizeof uri, "file:%s/keys", dir);
    snprintf(wk, sizeof wk, "%s/wrapping.key", dir);
    uint8_t key[32];
    for (size_t i = 0; i < sizeof key; i++)
        key[i] = (uint8_t)(i * 7 + 1);
    int fd = open(wk, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0 || write(fd, key, sizeof key) != (ssize_t)sizeof key) {
        perror("wrapping key");
        exit(1);
    }
    close(fd);

    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    cfg.key_store_uri = uri;
    cfg.key_store_wrapping_key_path = wk;
    static const int totals[] = {100, 1000};
    int have = 0;
    print_header();
    for (size_t t = 0; t < sizeof totals / sizeof *totals; t++) {
        agc_ctx *ctx = NULL;
        check(agc_ctx_open(&cfg, &ctx), "agc_ctx_open (file)");
        add_policies(ctx);
        samples smp = {0};
        for (; have < totals[t]; have++) {
            char k[64];
            snprintf(k, sizeof k, "file-%d", have);
            uint64_t t0 = now_ns();
            create_key(ctx, &CIPHERS[1], k);
            push(&smp, now_ns() - t0);
        }
        char name[96];
        snprintf(name, sizeof name, "create_key/file/up-to-%d", totals[t]);
        report(name, &smp);
        free(smp.v);
        agc_ctx_close(ctx);

        samples op = {0};
        for (int r = 0; r < 5; r++) {
            uint64_t t0 = now_ns();
            check(agc_ctx_open(&cfg, &ctx), "agc_ctx_open (file)");
            push(&op, now_ns() - t0);
            agc_ctx_close(ctx);
        }
        snprintf(name, sizeof name, "ctx_open/file/%d-keys", totals[t]);
        report(name, &op);
        free(op.v);
    }
    char cmd[128];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
    if (system(cmd) != 0)
        fprintf(stderr, "bench: could not remove %s\n", dir);
}

/* Syscalls per operation and the cost of the ones the library makes.
 * macOS: task_info(TASK_EVENTS_INFO) counts this task's Unix and Mach
 * syscalls, page faults and context switches without root. Elsewhere this
 * section only times the calls (use `strace -c` for counts). */
typedef struct {
    uint64_t unix_sc, mach_sc, faults, csw;
} events;

static int task_events(events *e)
{
#ifdef __APPLE__
    task_events_info_data_t i;
    mach_msg_type_number_t n = TASK_EVENTS_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_EVENTS_INFO, (task_info_t)&i, &n) != KERN_SUCCESS)
        return 0;
    e->unix_sc = (uint64_t)i.syscalls_unix;
    e->mach_sc = (uint64_t)i.syscalls_mach;
    e->faults = (uint64_t)i.faults;
    e->csw = (uint64_t)i.csw;
    return 1;
#else
    (void)e;
    return 0;
#endif
}

/* Mean ns per call of `body` over `n` calls. */
#define TIME_LOOP(label, n, body)                                                                  \
    do {                                                                                           \
        uint64_t t0_ = now_ns();                                                                   \
        for (long i_ = 0; i_ < (n); i_++) {                                                        \
            body;                                                                                  \
        }                                                                                          \
        printf("%-44s %9.1f ns\n", label, (double)(now_ns() - t0_) / (double)(n));                \
    } while (0)

static void count_op(const char *name, op_fn fn, op_state *s, events *overhead)
{
    enum { N = 2000 };
    for (int i = 0; i < 200; i++)
        fn(s);
    events a, b;
    if (!task_events(&a))
        return;
    for (int i = 0; i < N; i++)
        fn(s);
    task_events(&b);
    double u = (double)(b.unix_sc - a.unix_sc - overhead->unix_sc) / N;
    double m = (double)(b.mach_sc - a.mach_sc - overhead->mach_sc) / N;
    printf("%-44s %9.2f %9.2f %9.3f %9.3f\n", name, u, m, (double)(b.faults - a.faults) / N,
           (double)(b.csw - a.csw) / N);
    if (csv)
        fprintf(csv, "syscalls/%s,%d,%.3f,%.3f,%.4f,%.4f\n", name, N, u, m, (double)(b.faults - a.faults) / N,
                (double)(b.csw - a.csw) / N);
}

static void syscalls(void)
{
    printf("\n== syscalls ==\n");
    volatile pid_t sink = 0;
    uint8_t buf[32];
    TIME_LOOP("getpid()", 1000000, sink += getpid());
    TIME_LOOP("getentropy(12 bytes)  (one AEAD nonce)", 200000, if (getentropy(buf, 12)) exit(1));
    TIME_LOOP("getentropy(32 bytes)  (one hedge)", 200000, if (getentropy(buf, 32)) exit(1));
    TIME_LOOP("now_ns() (the harness clock)", 1000000, sink += (pid_t)now_ns());
    (void)sink;

    events a, b, overhead = {0};
    if (!task_events(&a)) {
        printf("(per-operation syscall counts need macOS task_info; use strace -c on Linux)\n");
        return;
    }
    task_events(&b);
    overhead.unix_sc = b.unix_sc - a.unix_sc; /* the counting call itself */
    overhead.mach_sc = b.mach_sc - a.mach_sc;
    {
        events c, d;
        task_events(&c);
        for (int i = 0; i < 1000; i++)
            sink += getpid();
        task_events(&d);
        printf("check: 1000 getpid() counted as %llu Unix syscalls (libc caches the pid)\n",
               (unsigned long long)(d.unix_sc - c.unix_sc - overhead.unix_sc));
        task_events(&c);
        for (int i = 0; i < 1000; i++)
            if (getentropy(buf, 12))
                exit(1);
        task_events(&d);
        printf("check: 1000 getentropy() counted as %llu Unix syscalls\n",
               (unsigned long long)(d.unix_sc - c.unix_sc - overhead.unix_sc));
    }

    printf("\nper operation (mean over 2000 calls, after warm-up)\n");
    printf("%-44s %9s %9s %9s %9s\n", "operation", "unix", "mach", "faults", "ctx-sw");
    agc_ctx *ctx = open_memory_ctx();
    static const struct {
        const algo *a;
        size_t n;
    } ops[] = {{&SIGNERS[0], 1024}, {&SIGNERS[1], 1024}, {&SIGNERS[5], 1024}, {&CIPHERS[1], 32},
               {&CIPHERS[1], 1048576}, {&CIPHERS[2], 32}, {&CIPHERS[3], 32}, {&CIPHERS[4], 32}};
    char name[96];
    for (size_t i = 0; i < sizeof ops / sizeof *ops; i++) {
        const algo *a = ops[i].a;
        if (i == 0 || ops[i - 1].a != a)
            create_key(ctx, a, a->template_id);
        op_state s;
        op_init(&s, ctx, a->template_id, a->kind, ops[i].n);
        if (a->kind == SIGN) {
            snprintf(name, sizeof name, "sign/%s/%zu/L3a", a->template_id, ops[i].n);
            count_op(name, op_sign, &s, &overhead);
            snprintf(name, sizeof name, "sign/%s/%zu/L3b", a->template_id, ops[i].n);
            count_op(name, op_sign2, &s, &overhead);
            snprintf(name, sizeof name, "verify/%s/%zu", a->template_id, ops[i].n);
            count_op(name, op_verify, &s, &overhead);
        } else {
            snprintf(name, sizeof name, "enc/%s/%zu/L3a", a->template_id, ops[i].n);
            count_op(name, op_encrypt, &s, &overhead);
            snprintf(name, sizeof name, "enc/%s/%zu/L3b", a->template_id, ops[i].n);
            count_op(name, op_encrypt2, &s, &overhead);
            snprintf(name, sizeof name, "dec/%s/%zu/L3a", a->template_id, ops[i].n);
            count_op(name, op_decrypt, &s, &overhead);
        }
        op_free(&s);
    }
    agc_ctx_close(ctx);
}

/* Stack high-water mark: run the job on a thread whose stack we mmap'd and
 * filled with a pattern; the deepest overwritten byte is the depth. An empty
 * job's depth (thread start-up) is subtracted. */
enum { STACK_SIZE = 8 << 20 };

typedef struct {
    void (*fn)(void *);
    void *arg;
} stack_job;

static void *stack_tramp(void *p)
{
    stack_job *j = p;
    j->fn(j->arg);
    return NULL;
}

static size_t stack_depth(void (*fn)(void *), void *arg)
{
    uint8_t *base = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (base == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    memset(base, 0xA5, STACK_SIZE);
    pthread_attr_t a;
    pthread_attr_init(&a);
    if (pthread_attr_setstack(&a, base, STACK_SIZE) != 0) {
        fprintf(stderr, "bench: pthread_attr_setstack failed\n");
        exit(1);
    }
    stack_job j = {fn, arg};
    pthread_t t;
    pthread_create(&t, &a, stack_tramp, &j);
    pthread_join(t, NULL);
    pthread_attr_destroy(&a);
    size_t i = 0;
    while (i < STACK_SIZE && base[i] == 0xA5)
        i++;
    munmap(base, STACK_SIZE);
    return STACK_SIZE - i;
}

static void nothing(void *arg)
{
    (void)arg;
}

typedef struct {
    op_fn fn;
    op_state *s;
} op_job;

static void run_op_job(void *p)
{
    op_job *j = p;
    for (int i = 0; i < 3; i++) /* the first call in a thread sets up its thread-locals */
        j->fn(j->s);
}

typedef struct {
    agc_ctx *ctx;
    const algo *a;
    const char *name;
} create_job;

static void run_create_job(void *p)
{
    create_job *j = p;
    create_key(j->ctx, j->a, j->name);
}

static void run_open_job(void *p)
{
    agc_ctx *ctx = open_memory_ctx();
    *(agc_ctx **)p = ctx;
}

static void stack(void)
{
    printf("\n== stack high-water mark (bytes, net of an empty thread) ==\n");
    size_t base = stack_depth(nothing, NULL);
    printf("empty thread start-up: %zu bytes (subtracted below)\n", base);
    printf("%-44s %10s %8s\n", "operation", "bytes", "KiB");
#define ROW(label, bytes)                                                                          \
    do {                                                                                           \
        size_t b_ = (bytes) - base;                                                                \
        printf("%-44s %10zu %8.1f\n", label, b_, (double)b_ / 1024);                              \
        if (csv)                                                                                   \
            fprintf(csv, "stack/%s,%zu\n", label, b_);                                             \
    } while (0)
    agc_ctx *opened = NULL;
    ROW("agc_ctx_open + 12 policies", stack_depth(run_open_job, &opened));
    agc_ctx *ctx = opened;
    char name[96];
    for (size_t i = 0; i < sizeof SIGNERS / sizeof *SIGNERS; i++) {
        const algo *a = &SIGNERS[i];
        create_job cj = {ctx, a, a->template_id};
        snprintf(name, sizeof name, "create_key/%s (first use)", a->template_id);
        ROW(name, stack_depth(run_create_job, &cj));
        char again[80];
        snprintf(again, sizeof again, "%s-again", a->template_id);
        create_job cj2 = {ctx, a, again};
        snprintf(name, sizeof name, "create_key/%s (again)", a->template_id);
        ROW(name, stack_depth(run_create_job, &cj2));
        op_state s;
        op_init(&s, ctx, a->template_id, SIGN, 1024);
        op_job j = {op_sign, &s};
        snprintf(name, sizeof name, "sign/%s/1024/L3a", a->template_id);
        ROW(name, stack_depth(run_op_job, &j));
        j.fn = op_verify;
        snprintf(name, sizeof name, "verify/%s/1024", a->template_id);
        ROW(name, stack_depth(run_op_job, &j));
        op_free(&s);
    }
    for (size_t i = 0; i < sizeof CIPHERS / sizeof *CIPHERS; i++) {
        const algo *a = &CIPHERS[i];
        create_job cj = {ctx, a, a->template_id};
        snprintf(name, sizeof name, "create_key/%s", a->template_id);
        ROW(name, stack_depth(run_create_job, &cj));
        static const size_t sizes[] = {32, 1048576};
        for (size_t k = 0; k < 2; k++) {
            op_state s;
            op_init(&s, ctx, a->template_id, a->kind, sizes[k]);
            op_job j = {op_encrypt, &s};
            snprintf(name, sizeof name, "enc/%s/%zu/L3a", a->template_id, sizes[k]);
            ROW(name, stack_depth(run_op_job, &j));
            j.fn = op_decrypt;
            snprintf(name, sizeof name, "dec/%s/%zu/L3a", a->template_id, sizes[k]);
            ROW(name, stack_depth(run_op_job, &j));
            op_free(&s);
        }
    }
#undef ROW
    agc_ctx_close(ctx);
}

/* What a context costs in memory, step by step (docs/performance.md F8).
 * resident: all resident pages, including clean pages of the library file
 * that every process using the library shares; footprint: macOS
 * phys_footprint, the dirty memory charged to this process (what jetsam and
 * Activity Monitor count); heap: bytes in use in malloc; faults: page faults
 * taken by the step. --vmmap also prints `vmmap --summary` after each step. */
typedef struct {
    size_t resident, footprint, heap;
    uint64_t faults;
} mem_point;

static mem_point mem_now(void)
{
    mem_point m = {rss_bytes(), 0, 0, 0};
#ifdef __APPLE__
    task_vm_info_data_t vi;
    mach_msg_type_number_t n = TASK_VM_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&vi, &n) == KERN_SUCCESS)
        m.footprint = (size_t)vi.phys_footprint;
    malloc_statistics_t st;
    malloc_zone_statistics(NULL, &st);
    m.heap = st.size_in_use;
    events e;
    if (task_events(&e))
        m.faults = e.faults;
#endif
    return m;
}

static int with_vmmap;

static void mem_step(const char *label, mem_point *prev)
{
    mem_point m = mem_now();
    printf("%-40s %+10.1f %+10.1f %+10.1f %8llu\n", label, ((double)m.resident - (double)prev->resident) / 1024,
           ((double)m.footprint - (double)prev->footprint) / 1024, ((double)m.heap - (double)prev->heap) / 1024,
           (unsigned long long)(m.faults - prev->faults));
    if (csv)
        fprintf(csv, "context/%s,%lld,%lld,%lld,%llu\n", label, (long long)m.resident - (long long)prev->resident,
                (long long)m.footprint - (long long)prev->footprint, (long long)m.heap - (long long)prev->heap,
                (unsigned long long)(m.faults - prev->faults));
    if (with_vmmap) {
        char cmd[64];
        snprintf(cmd, sizeof cmd, "vmmap --summary %d | sed -n '/^REGION TYPE/,/^TOTAL/p'", (int)getpid());
        fflush(stdout);
        if (system(cmd) != 0)
            printf("(vmmap failed)\n");
    }
    *prev = m;
}

static void context_cost(void)
{
    printf("\n== memory per context, step by step (KiB; deltas) ==\n");
    printf("%-40s %10s %10s %10s %8s\n", "step", "resident", "footprint", "heap", "faults");
    mem_point p = mem_now();
    printf("%-40s %10.1f %10.1f %10.1f\n", "(absolute at start)", p.resident / 1024.0, p.footprint / 1024.0,
           p.heap / 1024.0);
    (void)agc_rc_name(AGC_OK);
    mem_step("first trivial agc_* call", &p);
    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    agc_ctx *ctx = NULL;
    check(agc_ctx_open(&cfg, &ctx), "agc_ctx_open");
    mem_step("agc_ctx_open #1", &p);
    add_policies(ctx);
    mem_step("12 policies", &p);
    create_key(ctx, &CIPHERS[1], "k");
    mem_step("first key (AES-256-GCM)", &p);
    op_state s;
    op_init(&s, ctx, "k", AEAD, 32);
    op_encrypt(&s);
    mem_step("first encrypt (+ harness buffers)", &p);
    agc_ctx *ctx2 = NULL;
    check(agc_ctx_open(&cfg, &ctx2), "agc_ctx_open");
    mem_step("agc_ctx_open #2 (while #1 is open)", &p);
    agc_ctx *more[8];
    for (int i = 0; i < 8; i++)
        check(agc_ctx_open(&cfg, &more[i]), "agc_ctx_open");
    mem_step("agc_ctx_open #3..#10", &p);
    for (int i = 0; i < 8; i++)
        agc_ctx_close(more[i]);
    agc_ctx_close(ctx2);
    mem_step("close #2..#10", &p);
    op_free(&s);
    agc_ctx_close(ctx);
    mem_step("close #1", &p);
}

/* L3a and L3b of one algorithm, interleaved in 100 ms slices over many
 * rounds, so drift hits both alike (docs/performance.md F4). Prints each
 * variant's overall median and the range of its per-round medians. */
static uint64_t slice_median(op_fn fn, op_state *s, double secs, samples *all)
{
    samples r = {0};
    uint64_t start = now_ns(), budget = (uint64_t)(secs * 1e9);
    while (r.n < 5 || now_ns() - start < budget) {
        uint64_t t0 = now_ns();
        fn(s);
        uint64_t d = now_ns() - t0;
        push(&r, d);
        push(all, d);
    }
    qsort(r.v, r.n, sizeof *r.v, cmp_u64);
    uint64_t m = r.v[r.n / 2];
    free(r.v);
    return m;
}

static void interleaved(void)
{
    printf("\n== L3a vs L3b, interleaved: 20 rounds x 100 ms ==\n");
    printf("%-44s %8s %10s %10s %10s\n", "variant", "n", "median µs", "round min", "round max");
    agc_ctx *ctx = open_memory_ctx();
    const algo *which[] = {&SIGNERS[1], &SIGNERS[3]};
    for (size_t w = 0; w < 2; w++) {
        const algo *a = which[w];
        create_key(ctx, a, a->template_id);
        op_state s;
        op_init(&s, ctx, a->template_id, SIGN, 1024);
        op_fn fns[2] = {op_sign, op_sign2};
        samples all[2] = {{0}, {0}};
        uint64_t lo[2] = {UINT64_MAX, UINT64_MAX}, hi[2] = {0, 0};
        for (int r = 0; r < 20; r++)
            for (int k = 0; k < 2; k++) {
                int i = (k + r) % 2;
                uint64_t m = slice_median(fns[i], &s, 0.1, &all[i]);
                lo[i] = m < lo[i] ? m : lo[i];
                hi[i] = m > hi[i] ? m : hi[i];
            }
        for (int i = 0; i < 2; i++) {
            qsort(all[i].v, all[i].n, sizeof *all[i].v, cmp_u64);
            char name[96];
            snprintf(name, sizeof name, "sign/%s/1024/%s", a->template_id, i ? "L3b" : "L3a");
            printf("%-44s %8zu %10.1f %10.1f %10.1f\n", name, all[i].n, all[i].v[all[i].n / 2] * 1e-3, lo[i] * 1e-3,
                   hi[i] * 1e-3);
            free(all[i].v);
        }
        op_free(&s);
    }
    agc_ctx_close(ctx);
}

int main(int argc, char **argv)
{
    const char *only = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--quick") == 0)
            run_seconds = 0.25;
        else if (strcmp(argv[i], "--csv") == 0 && i + 1 < argc) {
            csv = fopen(argv[++i], "w");
            if (!csv) {
                perror(argv[i]);
                return 1;
            }
            fprintf(csv, "name,n,min_ns,p50_ns,p90_ns,p99_ns,p999_ns,max_ns,mean_ns\n");
        } else if (strcmp(argv[i], "--only") == 0 && i + 1 < argc)
            only = argv[++i];
        else if (strcmp(argv[i], "--seconds") == 0 && i + 1 < argc)
            run_seconds = atof(argv[++i]);
        else if (strcmp(argv[i], "--threads") == 0 && i + 1 < argc)
            contention_threads = atoi(argv[++i]);
        else if (strcmp(argv[i], "--keys") == 0 && i + 1 < argc)
            memory_keys = atoi(argv[++i]);
        else if (strcmp(argv[i], "--vmmap") == 0)
            with_vmmap = 1;
        else if (strcmp(argv[i], "--shared") == 0)
            contention_shared = 1;
        else {
            fprintf(stderr, "usage: bench [--quick] [--seconds S] [--csv FILE]\n"
                            "             [--only memory|first|latency|threads|file|syscalls|stack|context [--vmmap]|interleave]\n"
                            "             [--only contention [--threads N] [--shared]]\n");
            return 2;
        }
    }
#define WANT(s) (!only || strcmp(only, s) == 0)
    /* Memory first: once other sections have grown the heap, the allocator
     * reuses that space and resident-size deltas read low. */
    if (WANT("context"))
        context_cost(); /* first of all: it starts from a fresh process */
    if (WANT("memory"))
        memory();
    if (WANT("first"))
        first_calls();
    if (WANT("latency") || WANT("threads")) {
        agc_ctx *ctx = open_memory_ctx();
        if (WANT("latency"))
            latency(ctx);
        else
            for (size_t i = 0; i < 2; i++)
                create_key(ctx, i ? &CIPHERS[1] : &SIGNERS[0], i ? CIPHERS[1].template_id : SIGNERS[0].template_id);
        if (WANT("threads"))
            threads(ctx);
        agc_ctx_close(ctx);
    }
    if (WANT("file"))
        file_store();
    if (WANT("syscalls"))
        syscalls();
    if (WANT("stack"))
        stack();
    if (only && strcmp(only, "interleave") == 0)
        interleaved();
    if (only && strcmp(only, "contention") == 0) { /* never part of the full run */
        agc_ctx *ctx = open_memory_ctx();
        create_key(ctx, &CIPHERS[1], CIPHERS[1].template_id);
        contention(ctx);
        agc_ctx_close(ctx);
    }
    if (csv)
        fclose(csv);
    return 0;
}
