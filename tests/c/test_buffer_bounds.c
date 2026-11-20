/* Buffer bounds at the C boundary, checked from outside the library.
 *
 * ASan in the C tests instruments only this side; the Rust library runs
 * uninstrumented. Guard pages need no instrumentation: every buffer, slice,
 * string and versioned struct handed to the library here ends exactly at a
 * PROT_NONE page (or, for slices, also starts right after one), so a read or
 * write one byte out of bounds anywhere in the library faults at once.
 *
 * 1. Capacity sweep (agc_crypto_types.h, SIZE QUERIES): for every output
 *    region, capacities 0 .. need+1. Below the need: AGC_ERR_BUFFER_TOO_SMALL,
 *    every *_len set to its requirement, nothing written (all buffers keep
 *    their canary fill). At or above it: AGC_OK, *_len <= cap, and nothing
 *    written beyond *_len.
 * 2. Inputs at the edge: slices (message, AAD, ciphertext, metadata,
 *    signature, digest) and NUL-terminated strings end at a guard page, so
 *    the library may read exactly what the caller passed.
 * 3. Versioned structs (agc_abi.h, struct_size): requests and responses end at
 *    a guard page with struct_size from the size field alone up to the full
 *    struct plus a zero tail (an older and a newer caller). The library may
 *    read and write back only struct_size bytes. */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#define _DEFAULT_SOURCE /* glibc: MAP_ANON */
#include <stddef.h>
#include <stdint.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include "agc_test.h"

/* ---------------------------------------------------------------------- */
/* Guarded memory                                                          */
/* ---------------------------------------------------------------------- */

enum side { END, START };
enum { CANARY = 0xA5, MAX_MAPS = 512 };

static size_t page;
static struct {
    uint8_t *base, *p;
    size_t len;
} maps[MAX_MAPS];

/* n accessible bytes; the byte after them (END) or before them (START) is
 * PROT_NONE. Filled with CANARY. n = 0 gives a pointer at the guard page. */
static void *edge(size_t n, enum side s)
{
    size_t data = (n + page - 1) / page;
    if (data == 0)
        data = 1;
    size_t len = (data + 2) * page;
    uint8_t *base = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    CHECK(base != MAP_FAILED);
    CHECK(mprotect(base, page, PROT_NONE) == 0);
    CHECK(mprotect(base + len - page, page, PROT_NONE) == 0);
    memset(base + page, CANARY, data * page);
    uint8_t *p = s == END ? base + len - page - n : base + page;
    for (int i = 0; i < MAX_MAPS; i++)
        if (!maps[i].base) {
            maps[i].base = base;
            maps[i].p = p;
            maps[i].len = len;
            return p;
        }
    CHECK(!"too many guarded mappings");
    return NULL;
}

/* n bytes as close to the guard page as an `align`-aligned start allows;
 * *slack receives the bytes between them and the guard (canary-filled). */
static void *edge_aligned(size_t n, size_t align, size_t *slack)
{
    uint8_t *p = edge(n + align - 1, END);
    uint8_t *end = p + n + align - 1;
    uint8_t *q = (uint8_t *)(((uintptr_t)(end - n)) & ~(uintptr_t)(align - 1));
    *slack = (size_t)(end - (q + n));
    for (int i = 0; i < MAX_MAPS; i++)
        if (maps[i].base && maps[i].p == p)
            maps[i].p = q;
    return q;
}

static void edge_free(const void *p)
{
    if (!p)
        return;
    for (int i = 0; i < MAX_MAPS; i++)
        if (maps[i].base && maps[i].p == p) {
            munmap(maps[i].base, maps[i].len);
            maps[i].base = NULL;
            return;
        }
    CHECK(!"edge_free of an unknown pointer");
}

static void *edge_copy(const void *src, size_t n, enum side s)
{
    void *p = edge(n, s);
    if (n)
        memcpy(p, src, n);
    return p;
}

/* A string whose NUL is the last byte before the guard page. */
static const char *edge_str(const char *s)
{
    return edge_copy(s, strlen(s) + 1, END);
}

/* A copy of a versioned struct, ending at a guard page, claiming `size`
 * bytes: fewer than the struct (an older caller) or more, zero-filled (a
 * newer caller that set none of the newer fields). */
static void *edge_struct(const void *v, size_t full, size_t size)
{
    uint8_t *p = edge(size, END);
    memset(p, 0, size);
    memcpy(p, v, size < full ? size : full);
    memcpy(p, &size, sizeof size);
    return p;
}

static int untouched(const uint8_t *p, size_t from, size_t to)
{
    for (size_t i = from; i < to; i++)
        if (p[i] != CANARY)
            return 0;
    return 1;
}

/* ---------------------------------------------------------------------- */
/* The capacity sweep                                                      */
/* ---------------------------------------------------------------------- */

/* One call with up to two output regions (b, cap). Returns the rc and the
 * two *_len values the response reported. */
typedef agc_rc (*call_fn)(void *state, uint8_t *b0, size_t c0, uint8_t *b1, size_t c1, size_t *len0,
                          size_t *len1);

enum { UNUSED = 0, ALIGN_ANY = 1, ALIGN_STORAGE = 8 };
static size_t calls;

/* `exact`: a successful call writes exactly the need (else at most).
 * `align`: where the output regions start (1: anywhere, so they end exactly
 * at the guard page; 8: as malloc'd storage, which item arrays need). */
static void sweep(const char *what, call_fn f, void *state, int regions, int exact, size_t align)
{
    size_t need[2] = {0, 0};
    /* The size query with regions present but empty (non-NULL, cap 0, at a
     * guard page): {NULL, 0} means "not wanted" for verify's metadata. */
    size_t zs;
    uint8_t *z0 = edge_aligned(0, align, &zs), *z1 = edge_aligned(0, align, &zs);
    agc_rc q = f(state, z0, 0, regions > 1 ? z1 : NULL, 0, &need[0], &need[1]);
    edge_free(z0);
    edge_free(z1);
    if (q != AGC_ERR_BUFFER_TOO_SMALL) {
        agc_error_detail d;
        AGC_INIT(&d);
        agc_last_error(&d);
        fprintf(stderr, "%s: the size query returned %s (%s)\n", what, agc_rc_name(q), d.message ? d.message : "");
        exit(1);
    }
    for (int which = 0; which < regions; which++) {
        size_t n = need[which];
        for (size_t cap = 0; cap <= n + 1; cap++) {
            /* Every capacity near both ends; in between, a sample. */
            if (cap > 48 && cap + 48 < n && cap % 97 != 0)
                continue;
            size_t caps[2] = {need[0], need[1]};
            caps[which] = cap;
            uint8_t *b[2] = {NULL, NULL};
            size_t slack[2] = {0, 0};
            for (int i = 0; i < regions; i++)
                b[i] = edge_aligned(caps[i], align, &slack[i]);
            size_t len[2] = {0, 0};
            agc_rc rc = f(state, b[0], caps[0], b[1], caps[1], &len[0], &len[1]);
            calls++;
            if (cap < n) {
                if (rc != AGC_ERR_BUFFER_TOO_SMALL) {
                    fprintf(stderr, "%s: region %d cap %zu < need %zu returned %s\n", what, which, cap, n,
                            agc_rc_name(rc));
                    exit(1);
                }
                for (int i = 0; i < regions; i++) {
                    if (len[i] != need[i]) { /* every *_len reports its requirement */
                        fprintf(stderr, "%s: region %d cap %zu: BUFFER_TOO_SMALL reported %zu, the size query %zu\n",
                                what, i, caps[i], len[i], need[i]);
                        exit(1);
                    }
                    CHECK(untouched(b[i], 0, caps[i] + slack[i])); /* nothing written */
                }
            } else {
                if (rc != AGC_OK) {
                    fprintf(stderr, "%s: region %d cap %zu >= need %zu returned %s\n", what, which, cap, n,
                            agc_rc_name(rc));
                    exit(1);
                }
                for (int i = 0; i < regions; i++) {
                    CHECK(len[i] <= caps[i]);
                    if (exact && len[i] != need[i]) {
                        fprintf(stderr, "%s: region %d wrote %zu bytes, the size query said %zu\n", what, i, len[i],
                                need[i]);
                        exit(1);
                    }
                    CHECK(untouched(b[i], len[i], caps[i] + slack[i])); /* nothing beyond *_len */
                }
            }
            for (int i = 0; i < regions; i++)
                edge_free(b[i]);
        }
    }
}

/* ---------------------------------------------------------------------- */
/* Fixtures                                                                */
/* ---------------------------------------------------------------------- */

static agc_ctx *ctx;

#define POLICY                                                                                       \
    "{\"version\": \"1\","                                                                           \
    " \"allowed_templates\": [\"aes-256-gcm-128-96\", \"aes-256-cbc-pkcs7-128\", \"aes-256-ctr\","    \
    "   \"chacha20-poly1305\", \"ed25519\", \"ecdsa-p256-sha256-der\", \"ml-dsa-44\","                \
    "   \"ecdsa-p256-prehashed-der\"],"                                                              \
    " \"allowed_operations\": {\"key_operations\": [\"create_key\", \"sign\", \"verify\","           \
    "   \"digest_sign\", \"digest_verify\", \"encrypt\", \"decrypt\"]}}"

static void create(const char *name, const char *template_id, agc_scope_kind kind, agc_signature_scope sig)
{
    agc_create_key_params p;
    AGC_INIT(&p);
    p.key_name = edge_str(name);
    p.policy_name = edge_str("bounds");
    p.template_id = edge_str(template_id);
    AGC_INIT(&p.scope_spec);
    p.scope_spec.kind = kind;
    if (kind == AGC_SCOPE_KIND_SIGNATURE)
        p.scope_spec.u.signature.scope = sig;
    agc_create_key_params *pp = edge_copy(&p, sizeof p, END);
    agc_key_info_response r;
    AGC_INIT(&r);
    r.storage = (agc_buf){edge(4096, END), 4096};
    agc_key_info_response *rp = edge_copy(&r, sizeof r, END);
    CHECK_RC(agc_create_key(ctx, pp, rp), AGC_OK);
    edge_free(rp->storage.data);
    edge_free(rp);
    edge_free(pp);
    edge_free(p.key_name);
    edge_free(p.policy_name);
    edge_free(p.template_id);
}

/* ---------------------------------------------------------------------- */
/* Encrypt / decrypt                                                       */
/* ---------------------------------------------------------------------- */

typedef struct {
    const char *key;
    int aead;
    enum side side;
    const uint8_t *pt;
    size_t pt_len;
    /* for decrypt */
    const uint8_t *ct, *md;
    size_t ct_len, md_len;
} cipher_state;

static agc_encrypt_params *edge_params(const cipher_state *s)
{
    agc_encrypt_params ep;
    AGC_INIT(&ep);
    if (s->aead) {
        ep.kind = AGC_ENCRYPT_PARAMS_AEAD;
        ep.u.aead.aad = (agc_slice){edge_copy("associated", 10, s->side), 10};
    } else {
        ep.kind = AGC_ENCRYPT_PARAMS_NO_PARAMS;
    }
    return edge_copy(&ep, sizeof ep, END);
}

static void free_params(agc_encrypt_params *ep)
{
    if (ep->kind == AGC_ENCRYPT_PARAMS_AEAD)
        edge_free(ep->u.aead.aad.data);
    edge_free(ep);
}

static agc_rc do_encrypt(void *state, uint8_t *b0, size_t c0, uint8_t *b1, size_t c1, size_t *l0, size_t *l1)
{
    cipher_state *s = state;
    agc_encrypt_params *ep = edge_params(s);
    agc_encrypt_request r;
    AGC_INIT(&r);
    r.key_name = edge_str(s->key);
    r.plaintext = (agc_slice){s->pt, s->pt_len};
    r.params = ep;
    r.metadata_encoding = AGC_ENCODING_WIRE_V1;
    agc_encrypt_request *rp = edge_copy(&r, sizeof r, END);
    agc_encrypt_response o;
    AGC_INIT(&o);
    o.ciphertext = (agc_buf){b0, c0};
    o.metadata = (agc_buf){b1, c1};
    agc_encrypt_response *op = edge_copy(&o, sizeof o, END);
    agc_rc rc = agc_encrypt(ctx, rp, op);
    *l0 = op->ciphertext_len;
    *l1 = op->metadata_len;
    edge_free(op);
    edge_free(r.key_name);
    edge_free(rp);
    free_params(ep);
    return rc;
}

static agc_rc do_decrypt(void *state, uint8_t *b0, size_t c0, uint8_t *b1, size_t c1, size_t *l0, size_t *l1)
{
    (void)b1;
    (void)c1;
    cipher_state *s = state;
    agc_encrypt_params *ep = edge_params(s);
    agc_decrypt_request r;
    AGC_INIT(&r);
    r.key_name = edge_str(s->key);
    r.ciphertext = (agc_slice){s->ct, s->ct_len};
    r.metadata = (agc_slice){s->md, s->md_len};
    r.params = ep;
    agc_decrypt_request *rp = edge_copy(&r, sizeof r, END);
    agc_decrypt_response o;
    AGC_INIT(&o);
    o.plaintext = (agc_buf){b0, c0}; /* metadata {NULL, 0}: not wanted */
    agc_decrypt_response *op = edge_copy(&o, sizeof o, END);
    agc_rc rc = agc_decrypt(ctx, rp, op);
    *l0 = op->plaintext_len;
    *l1 = UNUSED;
    if (rc == AGC_OK)
        CHECK(op->plaintext_len == s->pt_len && memcmp(b0, s->pt, s->pt_len) == 0);
    edge_free(op);
    edge_free(r.key_name);
    edge_free(rp);
    free_params(ep);
    return rc;
}

static void ciphers(void)
{
    static const struct {
        const char *t;
        int aead;
    } list[] = {{"aes-256-gcm-128-96", 1}, {"chacha20-poly1305", 1}, {"aes-256-cbc-pkcs7-128", 0}, {"aes-256-ctr", 0}};
    static const size_t sizes[] = {1, 15, 16, 17, 100}; /* empty plaintext is refused */
    for (size_t i = 0; i < sizeof list / sizeof *list; i++) {
        create(list[i].t, list[i].t, list[i].aead ? AGC_SCOPE_KIND_AEAD : AGC_SCOPE_KIND_SYMMETRIC_CIPHER, 0);
        for (size_t j = 0; j < sizeof sizes / sizeof *sizes; j++)
            for (enum side side = END; side <= START; side++) {
                uint8_t plain[100];
                for (size_t k = 0; k < sizeof plain; k++)
                    plain[k] = (uint8_t)(k * 7 + 1);
                cipher_state s = {list[i].t, list[i].aead, side, edge_copy(plain, sizes[j], side), sizes[j],
                                  NULL, NULL, 0, 0};
                char what[96];
                snprintf(what, sizeof what, "encrypt %s %zu B", list[i].t, sizes[j]);
                sweep(what, do_encrypt, &s, 2, 1, ALIGN_ANY);

                /* A ciphertext for decrypt, its slices at the edge too. */
                uint8_t ct[256], md[256];
                size_t ct_len, md_len;
                CHECK_RC(do_encrypt(&s, ct, sizeof ct, md, sizeof md, &ct_len, &md_len), AGC_OK);
                s.ct = edge_copy(ct, ct_len, side);
                s.ct_len = ct_len;
                s.md = edge_copy(md, md_len, side);
                s.md_len = md_len;
                snprintf(what, sizeof what, "decrypt %s %zu B", list[i].t, sizes[j]);
                sweep(what, do_decrypt, &s, 1, 0, ALIGN_ANY);
                edge_free(s.ct);
                edge_free(s.md);
                edge_free(s.pt);
            }
    }
}

/* ---------------------------------------------------------------------- */
/* Sign / verify / digest sign                                             */
/* ---------------------------------------------------------------------- */

typedef struct {
    const char *key;
    enum side side;
    const uint8_t *msg;
    size_t msg_len;
    int digest; /* agc_digest_sign with a SHA-256 digest in msg */
    const uint8_t *sig, *md;
    size_t sig_len, md_len;
} sign_state;

static agc_sign_params *edge_sign_params(void)
{
    agc_sign_params sp;
    AGC_INIT(&sp);
    sp.kind = AGC_SIGN_PARAMS_NO_CONTEXT;
    return edge_copy(&sp, sizeof sp, END);
}

static agc_rc do_sign(void *state, uint8_t *b0, size_t c0, uint8_t *b1, size_t c1, size_t *l0, size_t *l1)
{
    sign_state *s = state;
    agc_sign_params *sp = edge_sign_params();
    const char *key = edge_str(s->key);
    agc_sign_response o;
    AGC_INIT(&o);
    o.signature = (agc_buf){b0, c0};
    o.metadata = (agc_buf){b1, c1};
    agc_sign_response *op = edge_copy(&o, sizeof o, END);
    agc_rc rc;
    if (s->digest) {
        agc_digest_sign_request r;
        AGC_INIT(&r);
        r.key_name = key;
        r.digest = (agc_slice){s->msg, s->msg_len};
        r.params = sp;
        r.hash_algorithm = AGC_HASH_ALGORITHM_SHA256;
        r.metadata_encoding = AGC_ENCODING_PROTOBUF;
        agc_digest_sign_request *rp = edge_copy(&r, sizeof r, END);
        rc = agc_digest_sign(ctx, rp, op);
        edge_free(rp);
    } else {
        agc_sign_request r;
        AGC_INIT(&r);
        r.key_name = key;
        r.input = (agc_slice){s->msg, s->msg_len};
        r.params = sp;
        r.metadata_encoding = AGC_ENCODING_WIRE_V1;
        agc_sign_request *rp = edge_copy(&r, sizeof r, END);
        rc = agc_sign(ctx, rp, op);
        edge_free(rp);
    }
    *l0 = op->signature_len;
    *l1 = op->metadata_len;
    edge_free(op);
    edge_free(key);
    edge_free(sp);
    return rc;
}

/* Verification with its metadata wanted back: the one output region. */
static agc_rc do_verify(void *state, uint8_t *b0, size_t c0, uint8_t *b1, size_t c1, size_t *l0, size_t *l1)
{
    (void)b1;
    (void)c1;
    sign_state *s = state;
    agc_sign_params *sp = edge_sign_params();
    const char *key = edge_str(s->key);
    agc_verify_response o;
    AGC_INIT(&o);
    o.metadata = (agc_buf){b0, c0};
    agc_verify_response *op = edge_copy(&o, sizeof o, END);
    agc_rc rc;
    if (s->digest) {
        agc_digest_verify_request r;
        AGC_INIT(&r);
        r.key_name = key;
        r.digest = (agc_slice){s->msg, s->msg_len};
        r.signature = (agc_slice){s->sig, s->sig_len};
        r.metadata = (agc_slice){s->md, s->md_len};
        r.params = sp;
        agc_digest_verify_request *rp = edge_copy(&r, sizeof r, END);
        rc = agc_digest_verify(ctx, rp, op);
        edge_free(rp);
    } else {
        agc_verify_request r;
        AGC_INIT(&r);
        r.key_name = key;
        r.input = (agc_slice){s->msg, s->msg_len};
        r.signature = (agc_slice){s->sig, s->sig_len};
        r.metadata = (agc_slice){s->md, s->md_len};
        r.params = sp;
        agc_verify_request *rp = edge_copy(&r, sizeof r, END);
        rc = agc_verify(ctx, rp, op);
        edge_free(rp);
    }
    if (rc == AGC_OK)
        CHECK(op->valid == 1);
    *l0 = op->metadata_len;
    *l1 = UNUSED;
    edge_free(op);
    edge_free(key);
    edge_free(sp);
    return rc;
}

static void signatures(void)
{
    static const struct {
        const char *t;
        int digest;
    } list[] = {{"ed25519", 0}, {"ecdsa-p256-sha256-der", 0}, {"ml-dsa-44", 0}, {"ecdsa-p256-prehashed-der", 1}};
    for (size_t i = 0; i < sizeof list / sizeof *list; i++) {
        create(list[i].t, list[i].t, AGC_SCOPE_KIND_SIGNATURE,
               list[i].digest ? AGC_SIGNATURE_SCOPE_PREHASHED : AGC_SIGNATURE_SCOPE_STANDARD);
        for (enum side side = END; side <= START; side++) {
            uint8_t msg[32];
            for (size_t k = 0; k < sizeof msg; k++)
                msg[k] = (uint8_t)k;
            size_t n = list[i].digest ? 32 : 17;
            sign_state s = {list[i].t, side, edge_copy(msg, n, side), n, list[i].digest, NULL, NULL, 0, 0};
            char what[96];
            snprintf(what, sizeof what, "sign %s", list[i].t);
            sweep(what, do_sign, &s, 2, 0, ALIGN_ANY); /* signature lengths are a bound */

            uint8_t sig[4096], md[512];
            size_t sig_len, md_len;
            CHECK_RC(do_sign(&s, sig, sizeof sig, md, sizeof md, &sig_len, &md_len), AGC_OK);
            s.sig = edge_copy(sig, sig_len, side);
            s.sig_len = sig_len;
            s.md = edge_copy(md, md_len, side);
            s.md_len = md_len;
            snprintf(what, sizeof what, "verify %s", list[i].t);
            sweep(what, do_verify, &s, 1, 1, ALIGN_ANY);
            edge_free(s.sig);
            edge_free(s.md);
            edge_free(s.msg);
        }
    }
}

/* ---------------------------------------------------------------------- */
/* Storage regions: key info, policy, template, metadata decode/encode      */
/* ---------------------------------------------------------------------- */

static int created_ok;

static agc_rc do_create_key(void *state, uint8_t *b0, size_t c0, uint8_t *b1, size_t c1, size_t *l0, size_t *l1)
{
    (void)state;
    (void)b1;
    (void)c1;
    char name[32];
    snprintf(name, sizeof name, "sweep-%d", created_ok);
    agc_create_key_params p;
    AGC_INIT(&p);
    p.key_name = edge_str(name);
    p.policy_name = edge_str("bounds");
    AGC_INIT(&p.scope_spec);
    p.scope_spec.kind = AGC_SCOPE_KIND_AEAD;
    agc_create_key_params *pp = edge_copy(&p, sizeof p, END);
    agc_key_info_response r;
    AGC_INIT(&r);
    r.storage = (agc_buf){b0, c0};
    agc_key_info_response *rp = edge_copy(&r, sizeof r, END);
    agc_rc rc = agc_create_key(ctx, pp, rp);
    *l0 = rp->storage_used;
    *l1 = UNUSED;
    if (rc == AGC_OK) {
        CHECK_STR(rp->key_info.key_name, name);
        created_ok++;
    } else {
        /* "Performed no provider work": the key does not exist. */
        agc_key_info_response q;
        AGC_INIT(&q);
        CHECK_RC(agc_read_key(ctx, name, 0, &q), AGC_ERR_CRYPTO_KEY_NOT_FOUND);
    }
    edge_free(rp);
    edge_free(pp);
    edge_free(p.key_name);
    edge_free(p.policy_name);
    return rc;
}

static agc_rc do_read_key(void *state, uint8_t *b0, size_t c0, uint8_t *b1, size_t c1, size_t *l0, size_t *l1)
{
    (void)b1;
    (void)c1;
    const char *name = edge_str(state);
    agc_key_info_response r;
    AGC_INIT(&r);
    r.storage = (agc_buf){b0, c0};
    agc_key_info_response *rp = edge_copy(&r, sizeof r, END);
    agc_rc rc = agc_read_key(ctx, name, 0, rp);
    *l0 = rp->storage_used;
    *l1 = UNUSED;
    edge_free(rp);
    edge_free(name);
    return rc;
}

static agc_rc do_read_policy(void *state, uint8_t *b0, size_t c0, uint8_t *b1, size_t c1, size_t *l0, size_t *l1)
{
    (void)state;
    (void)b1;
    (void)c1;
    const char *name = edge_str("bounds");
    agc_read_policy_response r;
    AGC_INIT(&r);
    r.storage = (agc_buf){b0, c0};
    agc_read_policy_response *rp = edge_copy(&r, sizeof r, END);
    agc_rc rc = agc_read_policy(ctx, name, rp);
    *l0 = rp->storage_used;
    *l1 = UNUSED;
    if (rc == AGC_OK)
        CHECK_STR(rp->name, "bounds");
    edge_free(rp);
    edge_free(name);
    return rc;
}

static agc_rc do_get_template(void *state, uint8_t *b0, size_t c0, uint8_t *b1, size_t c1, size_t *l0, size_t *l1)
{
    (void)b1;
    (void)c1;
    const char *id = edge_str(state);
    agc_template_info_response r;
    AGC_INIT(&r);
    r.storage = (agc_buf){b0, c0};
    agc_template_info_response *rp = edge_copy(&r, sizeof r, END);
    agc_rc rc = agc_get_template(ctx, id, rp);
    *l0 = rp->storage_used;
    *l1 = UNUSED;
    edge_free(rp);
    edge_free(id);
    return rc;
}

typedef struct {
    const uint8_t *md;
    size_t md_len;
    agc_encoding enc;
} decode_state;

static agc_rc do_decode(void *state, uint8_t *b0, size_t c0, uint8_t *b1, size_t c1, size_t *l0, size_t *l1)
{
    (void)b1;
    (void)c1;
    decode_state *s = state;
    agc_decode_metadata_result r;
    AGC_INIT(&r);
    r.storage = (agc_buf){b0, c0};
    agc_decode_metadata_result *rp = edge_copy(&r, sizeof r, END);
    agc_rc rc = agc_metadata_decode(s->enc, (agc_slice){s->md, s->md_len}, rp);
    *l0 = rp->storage_used;
    *l1 = UNUSED;
    /* Re-encode what was decoded: agc_metadata_encode's output is swept
     * too, below, from this result. */
    edge_free(rp);
    return rc;
}

typedef struct {
    agc_metadata md;
    agc_encoding enc;
} encode_state;

static agc_rc do_encode(void *state, uint8_t *b0, size_t c0, uint8_t *b1, size_t c1, size_t *l0, size_t *l1)
{
    (void)b1;
    (void)c1;
    encode_state *s = state;
    agc_metadata *md = edge_copy(&s->md, sizeof s->md, END);
    size_t *len = edge(sizeof *len, END);
    agc_rc rc = agc_metadata_encode(md, s->enc, (agc_buf){b0, c0}, len);
    *l0 = *len;
    *l1 = UNUSED;
    edge_free(len);
    edge_free(md);
    return rc;
}

static void storage_regions(void)
{
    /* A storage requirement is an upper bound that includes the worst
     * alignment padding (docs/agc_crypto.md): not exact. */
    sweep("create_key storage", do_create_key, NULL, 1, 0, ALIGN_STORAGE);
    sweep("read_key storage", do_read_key, "ml-dsa-44", 1, 0, ALIGN_STORAGE);
    sweep("read_policy storage", do_read_policy, NULL, 1, 0, ALIGN_STORAGE);
    sweep("get_template storage", do_get_template, "ml-dsa-44", 1, 0, ALIGN_STORAGE);
    sweep("get_template storage", do_get_template, "aes-256-gcm-128-96", 1, 0, ALIGN_STORAGE);

    /* Metadata with a nonce and user context, from a real encryption. */
    static const agc_encoding encs[] = {AGC_ENCODING_WIRE_V1, AGC_ENCODING_PROTOBUF};
    for (size_t e = 0; e < 2; e++) {
        agc_encrypt_params ep;
        AGC_INIT(&ep);
        ep.kind = AGC_ENCRYPT_PARAMS_AEAD;
        agc_kv kv[2] = {{"tenant", "acme"}, {"region", "eu-central"}};
        agc_encrypt_request r;
        AGC_INIT(&r);
        r.key_name = "aes-256-gcm-128-96";
        r.plaintext = (agc_slice){(const uint8_t *)"x", 1};
        r.params = &ep;
        r.metadata_encoding = encs[e];
        r.user_context = (agc_kv_list){kv, 2};
        uint8_t ct[64], md[512];
        agc_encrypt_response o;
        AGC_INIT(&o);
        o.ciphertext = (agc_buf){ct, sizeof ct};
        o.metadata = (agc_buf){md, sizeof md};
        CHECK_RC(agc_encrypt(ctx, &r, &o), AGC_OK);
        for (enum side side = END; side <= START; side++) {
            decode_state d = {edge_copy(md, o.metadata_len, side), o.metadata_len, encs[e]};
            sweep(e ? "metadata_decode protobuf" : "metadata_decode wire_v1", do_decode, &d, 1, 0, ALIGN_STORAGE);
            /* agc_metadata_storage_len is exact for aligned storage. */
            size_t exact = 0, used = 0, dummy = 0;
            CHECK_RC(agc_metadata_storage_len(encs[e], (agc_slice){d.md, d.md_len}, &exact), AGC_OK);
            uint8_t *aligned = edge_aligned(exact, ALIGN_STORAGE, &dummy);
            CHECK_RC(do_decode(&d, aligned, exact, NULL, 0, &used, &dummy), AGC_OK);
            CHECK(used == exact);
            edge_free(aligned);
            /* Decode once more for agc_metadata_encode's input. */
            static uint8_t storage[1024];
            agc_decode_metadata_result res;
            AGC_INIT(&res);
            res.storage = (agc_buf){storage, sizeof storage};
            CHECK_RC(agc_metadata_decode(encs[e], (agc_slice){d.md, d.md_len}, &res), AGC_OK);
            encode_state es = {res.metadata, encs[e]};
            sweep(e ? "metadata_encode protobuf" : "metadata_encode wire_v1", do_encode, &es, 1, 1, ALIGN_ANY);
            edge_free(d.md);
        }
    }
}

/* ---------------------------------------------------------------------- */
/* Versioned structs at the edge, every struct_size                        */
/* ---------------------------------------------------------------------- */

/* Each struct_size from the size field alone to the full struct plus a zero
 * tail. Any rc is fine; what matters is that the library touches only the
 * struct_size bytes, which here are all that is mapped. */
static void struct_sizes(void)
{
    uint8_t ct[64], md[256], pt[64], sig[128];
    agc_encrypt_params ep;
    AGC_INIT(&ep);
    ep.kind = AGC_ENCRYPT_PARAMS_AEAD;
    agc_encrypt_request er;
    AGC_INIT(&er);
    er.key_name = "aes-256-gcm-128-96";
    er.plaintext = (agc_slice){(const uint8_t *)"abc", 3};
    er.params = &ep;
    er.metadata_encoding = AGC_ENCODING_WIRE_V1;
    agc_encrypt_response eo;
    AGC_INIT(&eo);
    eo.ciphertext = (agc_buf){ct, sizeof ct};
    eo.metadata = (agc_buf){md, sizeof md};
    CHECK_RC(agc_encrypt(ctx, &er, &eo), AGC_OK);
    agc_decrypt_request dr;
    AGC_INIT(&dr);
    dr.key_name = er.key_name;
    dr.ciphertext = (agc_slice){ct, eo.ciphertext_len};
    dr.metadata = (agc_slice){md, eo.metadata_len};
    dr.params = &ep;
    agc_decrypt_response dout;
    AGC_INIT(&dout);
    dout.plaintext = (agc_buf){pt, sizeof pt};

    agc_sign_params sp;
    AGC_INIT(&sp);
    sp.kind = AGC_SIGN_PARAMS_NO_CONTEXT;
    agc_sign_request sr;
    AGC_INIT(&sr);
    sr.key_name = "ed25519";
    sr.input = (agc_slice){(const uint8_t *)"abc", 3};
    sr.params = &sp;
    sr.metadata_encoding = AGC_ENCODING_WIRE_V1;
    agc_sign_response so;
    AGC_INIT(&so);
    so.signature = (agc_buf){sig, sizeof sig};
    so.metadata = (agc_buf){md, sizeof md};

    agc_error_detail ed;
    AGC_INIT(&ed);
    agc_ctx_config cfg;
    AGC_INIT(&cfg);

    const size_t step = sizeof(size_t);
#define EACH_SIZE(T, v, body)                                                                        \
    for (size_t size_ = sizeof(size_t); size_ <= sizeof(T) + 2 * step; size_ += step) {              \
        T *v##_at = edge_struct(&v, sizeof v, size_);                                                \
        body;                                                                                        \
        edge_free(v##_at);                                                                           \
        calls++;                                                                                     \
    }
    /* Requests, nested params, responses, each in turn. */
    EACH_SIZE(agc_encrypt_request, er, (void)agc_encrypt(ctx, er_at, &eo));
    EACH_SIZE(agc_encrypt_params, ep, {
        agc_encrypt_request r2 = er;
        r2.params = ep_at;
        (void)agc_encrypt(ctx, &r2, &eo);
    });
    EACH_SIZE(agc_encrypt_response, eo, (void)agc_encrypt(ctx, &er, eo_at));
    EACH_SIZE(agc_decrypt_request, dr, (void)agc_decrypt(ctx, dr_at, &dout));
    EACH_SIZE(agc_decrypt_response, dout, (void)agc_decrypt(ctx, &dr, dout_at));
    EACH_SIZE(agc_sign_request, sr, (void)agc_sign(ctx, sr_at, &so));
    EACH_SIZE(agc_sign_params, sp, {
        agc_sign_request r2 = sr;
        r2.params = sp_at;
        (void)agc_sign(ctx, &r2, &so);
    });
    EACH_SIZE(agc_sign_response, so, (void)agc_sign(ctx, &sr, so_at));
    EACH_SIZE(agc_error_detail, ed, (void)agc_last_error(ed_at));
    EACH_SIZE(agc_ctx_config, cfg, {
        agc_ctx *c2 = NULL;
        if (agc_ctx_open(cfg_at, &c2) == AGC_OK)
            agc_ctx_close(c2);
    });
#undef EACH_SIZE

    /* The exact size and a zero tail behave like the normal call; a non-zero
     * tail is a newer caller's field this library would ignore: refused. */
    agc_encrypt_request *exact = edge_struct(&er, sizeof er, sizeof er);
    CHECK_RC(agc_encrypt(ctx, exact, &eo), AGC_OK);
    edge_free(exact);
    agc_encrypt_request *newer = edge_struct(&er, sizeof er, sizeof er + step);
    CHECK_RC(agc_encrypt(ctx, newer, &eo), AGC_OK);
    ((uint8_t *)newer)[sizeof er] = 1;
    CHECK_RC(agc_encrypt(ctx, newer, &eo), AGC_ERR_ABI_MISMATCH);
    edge_free(newer);
}

/* The harness itself: one byte past (and before) a guarded region faults. */
static void guards_catch_one_byte(void)
{
    printf("test_buffer_bounds: two deliberate one-byte overflows in child processes follow "
           "(a sanitizer may report them)\n");
    fflush(stdout);
    for (enum side side = END; side <= START; side++) {
        uint8_t *p = edge(10, side);
        pid_t pid = fork();
        CHECK(pid >= 0);
        if (pid == 0) {
            /* No core file for this expected crash (valgrind honours it too). */
            struct rlimit none = {0, 0};
            setrlimit(RLIMIT_CORE, &none);
            volatile uint8_t *q = p;
            if (side == END)
                q[10] = 1;
            else
                q[-1] = 1;
            _exit(0); /* not reached if the guard works */
        }
        int status = 0;
        CHECK(waitpid(pid, &status, 0) == pid);
        /* Killed by SIGSEGV/SIGBUS, or by a sanitizer that caught it
         * (SIGABRT or a non-zero exit): never the _exit(0). */
        CHECK(!(WIFEXITED(status) && WEXITSTATUS(status) == 0));
        edge_free(p);
    }
}

int main(void)
{
    page = (size_t)sysconf(_SC_PAGESIZE);
    guards_catch_one_byte();
    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    CHECK_RC(agc_ctx_open(&cfg, &ctx), AGC_OK);
    agc_create_policy_request pr;
    AGC_INIT(&pr);
    pr.name = edge_str("bounds");
    pr.policy_document = edge_str(POLICY);
    agc_create_policy_request *prp = edge_copy(&pr, sizeof pr, END);
    CHECK_RC(agc_create_policy(ctx, prp, NULL), AGC_OK);

    ciphers();
    signatures();
    storage_regions();
    struct_sizes();

    agc_ctx_close(ctx);
    printf("test_buffer_bounds: %zu guarded calls\n", calls);
    return 0;
}
