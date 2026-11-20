/* Stack-hungry operations on a thread with a small stack (docs/performance.md
 * F12). ML-DSA keeps large arrays on the stack (an ML-DSA-87 key generation
 * needs ~630 KiB), and the first use of a P-521 curve builds a table in
 * ~130 KiB. musl gives new threads 128 KiB, macOS 512 KiB: before the fix,
 * these calls overflowed the stack and killed the process. The library must
 * move such work to a stack of its own; this test runs everything on a
 * 128 KiB thread, and the curves are first used there. */
#include <pthread.h>

#include "agc_test.h"

/* A ThreadSanitizer build of the library uses several times the stack in
 * every frame, including the frames that run on the caller's thread before
 * the library can move anything. */
#if defined(__SANITIZE_THREAD__)
#define TSAN 1
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define TSAN 1
#endif
#endif
#ifdef TSAN
enum { SMALL_STACK = 512 * 1024 };
#else
enum { SMALL_STACK = 128 * 1024 };
#endif

#define POLICY                                                                                       \
    "{\"version\": \"1\","                                                                           \
    " \"allowed_templates\": [\"ecdsa-p521-sha512-der\", \"ecdsa-p384-sha384-der\","                 \
    "   \"ecdsa-p256-sha256-der\", \"ed25519\", \"ml-dsa-44\", \"ml-dsa-65\", \"ml-dsa-87\","          \
    "   \"ecdsa-p521-prehashed-der\"],"                                                              \
    " \"allowed_operations\": {\"key_operations\": [\"create_key\", \"sign\", \"verify\","           \
    "   \"digest_sign\", \"digest_verify\"]}}"

static agc_ctx *ctx;

static void create(const char *template_id, agc_signature_scope scope)
{
    agc_create_key_params p = {
        .struct_size = sizeof p,
        .key_name = template_id,
        .policy_name = "sig",
        .template_id = template_id,
        .scope_spec = {.struct_size = sizeof(agc_scope_spec),
                       .kind = AGC_SCOPE_KIND_SIGNATURE,
                       .u.signature.scope = scope},
    };
    static uint8_t storage[16384];
    agc_key_info_response resp;
    AGC_INIT(&resp);
    resp.storage = (agc_buf){storage, sizeof storage};
    CHECK_RC(agc_create_key(ctx, &p, &resp), AGC_OK);
    CHECK_STR(resp.key_info.template_id, template_id);
}

static void sign_and_verify(const char *key)
{
    static const uint8_t msg[] = "a message signed on a small stack";
    agc_sign_params none;
    AGC_INIT(&none);
    none.kind = AGC_SIGN_PARAMS_NO_CONTEXT;
    agc_sign_request sr;
    AGC_INIT(&sr);
    sr.key_name = key;
    sr.input = (agc_slice){msg, sizeof msg};
    sr.params = &none;
    sr.metadata_encoding = AGC_ENCODING_WIRE_V1;
    static uint8_t sig[8192], md[1024];
    agc_sign_response out;
    AGC_INIT(&out);
    out.signature = (agc_buf){sig, sizeof sig};
    out.metadata = (agc_buf){md, sizeof md};
    CHECK_RC(agc_sign(ctx, &sr, &out), AGC_OK);

    agc_verify_request vr;
    AGC_INIT(&vr);
    vr.key_name = key;
    vr.input = sr.input;
    vr.signature = (agc_slice){sig, out.signature_len};
    vr.metadata = (agc_slice){md, out.metadata_len};
    vr.params = &none;
    agc_verify_response v;
    AGC_INIT(&v);
    CHECK_RC(agc_verify(ctx, &vr, &v), AGC_OK);
    CHECK(v.valid == 1);
}

static void digest_sign_and_verify(const char *key)
{
    uint8_t digest[64];
    for (size_t i = 0; i < sizeof digest; i++)
        digest[i] = (uint8_t)i;
    agc_sign_params none;
    AGC_INIT(&none);
    none.kind = AGC_SIGN_PARAMS_NO_CONTEXT;
    agc_digest_sign_request r;
    AGC_INIT(&r);
    r.key_name = key;
    r.digest = (agc_slice){digest, sizeof digest};
    r.params = &none;
    r.hash_algorithm = AGC_HASH_ALGORITHM_SHA512;
    r.metadata_encoding = AGC_ENCODING_PROTOBUF;
    static uint8_t sig[1024], md[1024];
    agc_sign_response out;
    AGC_INIT(&out);
    out.signature = (agc_buf){sig, sizeof sig};
    out.metadata = (agc_buf){md, sizeof md};
    CHECK_RC(agc_digest_sign(ctx, &r, &out), AGC_OK);

    agc_digest_verify_request vr;
    AGC_INIT(&vr);
    vr.key_name = key;
    vr.digest = r.digest;
    vr.signature = (agc_slice){sig, out.signature_len};
    vr.metadata = (agc_slice){md, out.metadata_len};
    vr.params = &none;
    agc_verify_response v;
    AGC_INIT(&v);
    CHECK_RC(agc_digest_verify(ctx, &vr, &v), AGC_OK);
    CHECK(v.valid == 1);
}

static void *on_small_stack(void *arg)
{
    (void)arg;
    /* P-521 first: its first use in this process happens here. */
    static const char *const message_templates[] = {
        "ecdsa-p521-sha512-der", "ecdsa-p384-sha384-der", "ecdsa-p256-sha256-der", "ed25519",
        "ml-dsa-44",             "ml-dsa-65",             "ml-dsa-87",
    };
    for (size_t i = 0; i < sizeof message_templates / sizeof *message_templates; i++) {
        create(message_templates[i], AGC_SIGNATURE_SCOPE_STANDARD);
        sign_and_verify(message_templates[i]);
        sign_and_verify(message_templates[i]); /* again, once warm */
    }
    create("ecdsa-p521-prehashed-der", AGC_SIGNATURE_SCOPE_PREHASHED);
    digest_sign_and_verify("ecdsa-p521-prehashed-der");
    return NULL;
}

int main(void)
{
    ctx = open_embedded();
    CHECK_RC(create_policy(ctx, "sig", POLICY), AGC_OK);

    pthread_attr_t attr;
    CHECK(pthread_attr_init(&attr) == 0);
    CHECK(pthread_attr_setstacksize(&attr, SMALL_STACK) == 0);
    pthread_t t;
    CHECK(pthread_create(&t, &attr, on_small_stack, NULL) == 0);
    CHECK(pthread_join(t, NULL) == 0);
    pthread_attr_destroy(&attr);

    agc_ctx_close(ctx);
    return 0;
}
