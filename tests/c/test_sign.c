/* agc_crypto.h: agc_sign, agc_verify, agc_digest_sign, agc_digest_verify,
 * agc_hash_algorithm_output_len; agc_metadata.h: agc_metadata_max_encoded_len. */
#include "agc_test.h"

#define SIGN_POLICY                                                                                  \
    "{\"version\": \"1\","                                                                           \
    " \"allowed_templates\": [\"ecdsa-p256-sha256-der\", \"ecdsa-p384-sha384-der\","                 \
    "   \"ecdsa-p521-sha512-der\", \"ed25519\", \"ml-dsa-44\", \"ml-dsa-65\", \"ml-dsa-87\","          \
    "   \"ecdsa-p256-prehashed-der\", \"ecdsa-p384-prehashed-der\", \"ed25519ph\"],"                 \
    " \"allowed_operations\": {\"key_operations\": [\"create_key\", \"sign\", \"verify\","           \
    "   \"digest_sign\", \"digest_verify\"]}}"

static void create(agc_ctx *ctx, const char *name, const char *template_id, agc_signature_scope scope)
{
    agc_create_key_params p = {
        .struct_size = sizeof p,
        .key_name = name,
        .policy_name = "sig",
        .scope_spec = {.struct_size = sizeof(agc_scope_spec),
                       .kind = AGC_SCOPE_KIND_SIGNATURE,
                       .u.signature.scope = scope},
        .template_id = template_id,
    };
    uint8_t storage[8192]; /* ML-DSA-87 public keys are 2592 bytes */
    agc_key_info_response resp;
    AGC_INIT(&resp);
    resp.storage = (agc_buf){storage, sizeof storage};
    CHECK_RC(agc_create_key(ctx, &p, &resp), AGC_OK);
}

static const char *msg = "the quick brown fox jumps over the lazy dog";

static agc_sign_params no_context(void)
{
    agc_sign_params sp;
    AGC_INIT(&sp);
    sp.kind = AGC_SIGN_PARAMS_NO_CONTEXT;
    return sp;
}

static agc_sign_params domain_context(const char *c)
{
    agc_sign_params sp;
    AGC_INIT(&sp);
    sp.kind = AGC_SIGN_PARAMS_DOMAIN_CONTEXT;
    sp.u.domain_context.context_len = (uint8_t)strlen(c);
    memcpy(sp.u.domain_context.context, c, strlen(c));
    return sp;
}

typedef struct {
    uint8_t sig[8192];
    size_t sig_len;
    uint8_t md[512];
    size_t md_len;
} signed_msg;

/* Signs msg with `key`, size-querying first. */
static void sign(agc_ctx *ctx, const char *key, const agc_sign_params *sp, agc_encoding enc, signed_msg *out)
{
    agc_sign_request sr;
    AGC_INIT(&sr);
    sr.key_name = key;
    sr.input = (agc_slice){(const uint8_t *)msg, strlen(msg)};
    sr.params = sp;
    sr.metadata_encoding = enc;

    agc_sign_response resp;
    AGC_INIT(&resp); /* NULL regions: a size query */
    CHECK_RC(agc_sign(ctx, &sr, &resp), AGC_ERR_BUFFER_TOO_SMALL);
    CHECK(resp.signature_len > 0 && resp.signature_len <= sizeof out->sig);
    CHECK(resp.metadata_len > 0 && resp.metadata_len <= sizeof out->md);
    CHECK(resp.key_version == 0);
    size_t bound = resp.signature_len, want_md = resp.metadata_len;

    resp.signature = (agc_buf){out->sig, bound};
    resp.metadata = (agc_buf){out->md, want_md};
    CHECK_RC(agc_sign(ctx, &sr, &resp), AGC_OK);
    CHECK(resp.signature_len > 0 && resp.signature_len <= bound); /* DER ECDSA can be shorter */
    CHECK(resp.metadata_len == want_md);                          /* the metadata query is exact */
    CHECK(resp.key_version == 1);
    CHECK(out->md[0] == enc);
    out->sig_len = resp.signature_len;
    out->md_len = resp.metadata_len;
}

/* Verifies `s` over `message`; returns rc, with *valid and the response
 * metadata's encoding byte (0 if none was written). */
static agc_rc verify(agc_ctx *ctx, const char *key, const char *message, const agc_sign_params *sp, const signed_msg *s,
                     int with_metadata, int *valid, uint8_t *md_enc)
{
    agc_verify_request vr;
    AGC_INIT(&vr);
    vr.key_name = key;
    vr.input = (agc_slice){(const uint8_t *)message, strlen(message)};
    vr.signature = (agc_slice){s->sig, s->sig_len};
    if (with_metadata)
        vr.metadata = (agc_slice){s->md, s->md_len};
    vr.params = sp;
    uint8_t md[512] = {0};
    agc_verify_response resp;
    AGC_INIT(&resp);
    resp.valid = 1; /* the library must clear it */
    resp.metadata = (agc_buf){md, sizeof md};
    agc_rc rc = agc_verify(ctx, &vr, &resp);
    *valid = resp.valid;
    *md_enc = resp.metadata_len ? md[0] : 0;
    /* D9: either signal alone is enough, and they agree. */
    CHECK((rc == AGC_OK) == (resp.valid == 1));
    return rc;
}

static void message_signatures(agc_ctx *ctx)
{
    static const char *templates[] = {"ecdsa-p256-sha256-der", "ecdsa-p384-sha384-der", "ecdsa-p521-sha512-der",
                                      "ed25519", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87"};
    agc_sign_params sp = no_context();
    for (size_t i = 0; i < sizeof templates / sizeof *templates; i++) {
        create(ctx, templates[i], templates[i], AGC_SIGNATURE_SCOPE_STANDARD);
        static signed_msg s;
        sign(ctx, templates[i], &sp, AGC_ENCODING_WIRE_V1, &s);

        int valid;
        uint8_t enc;
        CHECK_RC(verify(ctx, templates[i], msg, &sp, &s, 1, &valid, &enc), AGC_OK);
        CHECK(valid == 1 && enc == AGC_ENCODING_WIRE_V1);
        /* Without metadata: the latest version, response in WIRE_V1. */
        CHECK_RC(verify(ctx, templates[i], msg, &sp, &s, 0, &valid, &enc), AGC_OK);
        CHECK(valid == 1 && enc == AGC_ENCODING_WIRE_V1);

        /* Another message, a flipped bit, a truncated signature: invalid,
         * never an error of another kind. */
        CHECK_RC(verify(ctx, templates[i], "another message", &sp, &s, 1, &valid, &enc),
                 AGC_ERR_CRYPTO_SIGNATURE_INVALID);
        CHECK(valid == 0 && enc == 0);
        s.sig[s.sig_len / 2] ^= 0x01;
        CHECK_RC(verify(ctx, templates[i], msg, &sp, &s, 1, &valid, &enc), AGC_ERR_CRYPTO_SIGNATURE_INVALID);
        s.sig[s.sig_len / 2] ^= 0x01;
        s.sig_len--;
        CHECK_RC(verify(ctx, templates[i], msg, &sp, &s, 1, &valid, &enc), AGC_ERR_CRYPTO_SIGNATURE_INVALID);
        CHECK(valid == 0);
    }
}

static void protobuf_metadata_round_trips(agc_ctx *ctx)
{
    agc_sign_params sp = no_context();
    signed_msg s;
    sign(ctx, "ed25519", &sp, AGC_ENCODING_PROTOBUF, &s);
    int valid;
    uint8_t enc;
    CHECK_RC(verify(ctx, "ed25519", msg, &sp, &s, 1, &valid, &enc), AGC_OK);
    CHECK(valid == 1 && enc == AGC_ENCODING_PROTOBUF); /* the request's encoding */

    agc_decode_metadata_result r;
    AGC_INIT(&r);
    uint8_t storage[256];
    r.storage = (agc_buf){storage, sizeof storage};
    CHECK_RC(agc_metadata_decode(AGC_ENCODING_PROTOBUF, (agc_slice){s.md, s.md_len}, &r), AGC_OK);
    CHECK(r.metadata.key_version == 1);
    CHECK(r.metadata.provider_output.kind == AGC_ALGORITHM_OUTPUT_NO_OUTPUT);
    CHECK_STR(r.metadata.provider_output.encoding, "raw");
}

static void contexts(agc_ctx *ctx)
{
    create(ctx, "mlctx", "ml-dsa-65", AGC_SIGNATURE_SCOPE_WITH_CONTEXT);
    agc_sign_params app = domain_context("app-v1"), other = domain_context("app-v2"), none = no_context();
    signed_msg s;
    sign(ctx, "mlctx", &app, AGC_ENCODING_WIRE_V1, &s);
    int valid;
    uint8_t enc;
    CHECK_RC(verify(ctx, "mlctx", msg, &app, &s, 1, &valid, &enc), AGC_OK);
    CHECK_RC(verify(ctx, "mlctx", msg, &other, &s, 1, &valid, &enc), AGC_ERR_CRYPTO_SIGNATURE_INVALID);
    /* The scope decides whether a context is taken. */
    CHECK_RC(verify(ctx, "mlctx", msg, &none, &s, 1, &valid, &enc), AGC_ERR_INVALID_ARGUMENT);
    agc_sign_request sr;
    AGC_INIT(&sr);
    sr.key_name = "ed25519";
    sr.input = (agc_slice){(const uint8_t *)msg, strlen(msg)};
    sr.params = &app;
    sr.metadata_encoding = AGC_ENCODING_WIRE_V1;
    agc_sign_response resp;
    AGC_INIT(&resp);
    CHECK_RC(agc_sign(ctx, &sr, &resp), AGC_ERR_INVALID_ARGUMENT);
}

static agc_rc digest_sign(agc_ctx *ctx, const char *key, const uint8_t *digest, size_t len, agc_hash_algorithm h,
                          signed_msg *out)
{
    agc_sign_params sp = no_context();
    agc_digest_sign_request dr;
    AGC_INIT(&dr);
    dr.key_name = key;
    dr.digest = (agc_slice){digest, len};
    dr.params = &sp;
    dr.hash_algorithm = h;
    dr.metadata_encoding = AGC_ENCODING_WIRE_V1;
    agc_sign_response resp;
    AGC_INIT(&resp);
    resp.signature = (agc_buf){out->sig, sizeof out->sig};
    resp.metadata = (agc_buf){out->md, sizeof out->md};
    agc_rc rc = agc_digest_sign(ctx, &dr, &resp);
    out->sig_len = resp.signature_len;
    out->md_len = resp.metadata_len;
    return rc;
}

static agc_rc digest_verify(agc_ctx *ctx, const char *key, const uint8_t *digest, size_t len, agc_hash_algorithm h,
                            const signed_msg *s, int *valid)
{
    agc_sign_params sp = no_context();
    agc_digest_verify_request dr;
    AGC_INIT(&dr);
    dr.key_name = key;
    dr.digest = (agc_slice){digest, len};
    dr.signature = (agc_slice){s->sig, s->sig_len};
    dr.metadata = (agc_slice){s->md, s->md_len};
    dr.params = &sp;
    dr.hash_algorithm = h;
    agc_verify_response resp;
    AGC_INIT(&resp); /* metadata {NULL, 0}: opted out */
    resp.valid = 1;
    agc_rc rc = agc_digest_verify(ctx, &dr, &resp);
    *valid = resp.valid;
    CHECK(resp.metadata_len == 0);
    return rc;
}

static void digest_signatures(agc_ctx *ctx)
{
    create(ctx, "p256pre", "ecdsa-p256-prehashed-der", AGC_SIGNATURE_SCOPE_PREHASHED);
    create(ctx, "p384pre", "ecdsa-p384-prehashed-der", AGC_SIGNATURE_SCOPE_PREHASHED);
    create(ctx, "edph", "ed25519ph", AGC_SIGNATURE_SCOPE_PREHASHED);
    uint8_t digest[64];
    for (size_t i = 0; i < sizeof digest; i++)
        digest[i] = (uint8_t)(i * 7 + 1);
    signed_msg s;
    int valid;

    struct {
        const char *key;
        agc_hash_algorithm h;
    } ok[] = {{"p256pre", AGC_HASH_ALGORITHM_SHA256}, {"p256pre", AGC_HASH_ALGORITHM_SHA512},
              {"p384pre", AGC_HASH_ALGORITHM_SHA384}, {"edph", AGC_HASH_ALGORITHM_SHA512}};
    for (size_t i = 0; i < sizeof ok / sizeof *ok; i++) {
        size_t len = agc_hash_algorithm_output_len(ok[i].h);
        CHECK_RC(digest_sign(ctx, ok[i].key, digest, len, ok[i].h, &s), AGC_OK);
        CHECK_RC(digest_verify(ctx, ok[i].key, digest, len, ok[i].h, &s, &valid), AGC_OK);
        CHECK(valid == 1);
        digest[0] ^= 1;
        CHECK_RC(digest_verify(ctx, ok[i].key, digest, len, ok[i].h, &s, &valid), AGC_ERR_CRYPTO_SIGNATURE_INVALID);
        CHECK(valid == 0);
        digest[0] ^= 1;
    }

    /* The declared hash must match the digest's length ... */
    CHECK_RC(digest_sign(ctx, "p256pre", digest, 32, AGC_HASH_ALGORITHM_SHA384, &s), AGC_ERR_INVALID_ARGUMENT);
    CHECK_RC(digest_sign(ctx, "p256pre", digest, 32, AGC_HASH_ALGORITHM_UNSPECIFIED, &s), AGC_ERR_INVALID_ARGUMENT);
    /* ... and be one the algorithm accepts: no SHA-1, nothing weaker than the curve. */
    CHECK_RC(digest_sign(ctx, "p256pre", digest, 20, AGC_HASH_ALGORITHM_SHA1, &s),
             AGC_ERR_CRYPTO_INCOMPATIBLE_PARAMETERS);
    CHECK_RC(digest_sign(ctx, "p384pre", digest, 32, AGC_HASH_ALGORITHM_SHA256, &s),
             AGC_ERR_CRYPTO_INCOMPATIBLE_PARAMETERS);
    CHECK_RC(digest_sign(ctx, "edph", digest, 48, AGC_HASH_ALGORITHM_SHA384, &s),
             AGC_ERR_CRYPTO_INCOMPATIBLE_PARAMETERS);
    /* A message key does not sign digests, nor a digest key messages. */
    CHECK_RC(digest_sign(ctx, "ed25519", digest, 64, AGC_HASH_ALGORITHM_SHA512, &s),
             AGC_ERR_CRYPTO_KEY_OPERATION_NOT_ALLOWED);
    agc_sign_params sp = no_context();
    agc_sign_request sr;
    AGC_INIT(&sr);
    sr.key_name = "edph";
    sr.input = (agc_slice){(const uint8_t *)msg, strlen(msg)};
    sr.params = &sp;
    sr.metadata_encoding = AGC_ENCODING_WIRE_V1;
    agc_sign_response resp;
    AGC_INIT(&resp);
    CHECK_RC(agc_sign(ctx, &sr, &resp), AGC_ERR_CRYPTO_KEY_OPERATION_NOT_ALLOWED);
}

static void verify_fails_closed(agc_ctx *ctx)
{
    agc_verify_response resp;
    AGC_INIT(&resp);
    resp.valid = 1;
    CHECK_RC(agc_verify(ctx, NULL, &resp), AGC_ERR_INVALID_ARGUMENT);
    CHECK(resp.valid == 0);

    /* A short metadata region: BUFFER_TOO_SMALL with the length, valid 0. */
    agc_sign_params sp = no_context();
    signed_msg s;
    sign(ctx, "ed25519", &sp, AGC_ENCODING_WIRE_V1, &s);
    agc_verify_request vr;
    AGC_INIT(&vr);
    vr.key_name = "ed25519";
    vr.input = (agc_slice){(const uint8_t *)msg, strlen(msg)};
    vr.signature = (agc_slice){s.sig, s.sig_len};
    vr.params = &sp;
    uint8_t md[2];
    resp.valid = 1;
    resp.metadata = (agc_buf){md, sizeof md};
    CHECK_RC(agc_verify(ctx, &vr, &resp), AGC_ERR_BUFFER_TOO_SMALL);
    CHECK(resp.valid == 0 && resp.metadata_len > sizeof md);
}

static void sizing_helpers(agc_ctx *ctx)
{
    CHECK(agc_hash_algorithm_output_len(AGC_HASH_ALGORITHM_SHA256) == 32);
    CHECK(agc_hash_algorithm_output_len(AGC_HASH_ALGORITHM_SHA384) == 48);
    CHECK(agc_hash_algorithm_output_len(AGC_HASH_ALGORITHM_SHA3_512) == 64);
    CHECK(agc_hash_algorithm_output_len(AGC_HASH_ALGORITHM_SHAKE256) == 0);
    CHECK(agc_hash_algorithm_output_len(AGC_HASH_ALGORITHM_OTHER) == 0);

    agc_kv items[] = {{"tenant", "acme"}};
    agc_kv_list uc = {items, 1};
    size_t max = agc_metadata_max_encoded_len(ctx, "ecdsa-p256-sha256-der", AGC_ENCODING_PROTOBUF, uc);
    agc_sign_params sp = no_context();
    agc_sign_request sr;
    AGC_INIT(&sr);
    sr.key_name = "ecdsa-p256-sha256-der";
    sr.input = (agc_slice){(const uint8_t *)msg, strlen(msg)};
    sr.params = &sp;
    sr.user_context = uc;
    sr.metadata_encoding = AGC_ENCODING_PROTOBUF;
    agc_sign_response resp;
    AGC_INIT(&resp);
    CHECK_RC(agc_sign(ctx, &sr, &resp), AGC_ERR_BUFFER_TOO_SMALL);
    CHECK(max >= resp.metadata_len && resp.metadata_len > 0);
    CHECK(agc_metadata_max_encoded_len(ctx, "no such key", AGC_ENCODING_PROTOBUF, uc) == 0);
}

int main(void)
{
    agc_ctx *ctx = open_embedded();
    CHECK_RC(create_policy(ctx, "sig", SIGN_POLICY), AGC_OK);
    message_signatures(ctx);
    protobuf_metadata_round_trips(ctx);
    contexts(ctx);
    digest_signatures(ctx);
    verify_fails_closed(ctx);
    sizing_helpers(ctx);
    agc_ctx_close(ctx);
    puts("test_sign: ok");
    return 0;
}
