/* agc_crypto.h: agc_encrypt and agc_decrypt. */
#include "agc_test.h"

#define CRYPTO_POLICY                                                                          \
    "{\"version\": \"1\","                                                                     \
    " \"allowed_templates\": [\"aes-256-gcm-128-96\", \"chacha20-poly1305\","                  \
    "   \"aes-128-cbc-pkcs7-128\", \"aes-128-ctr\"],"                                          \
    " \"allowed_operations\": {\"key_operations\": [\"create_key\", \"encrypt\", \"decrypt\"]}}"

static void create(agc_ctx *ctx, const char *name, agc_scope_kind kind, const char *template_id)
{
    agc_create_key_params p = {
        .struct_size = sizeof p,
        .key_name = name,
        .policy_name = "crypto",
        .scope_spec = {.struct_size = sizeof(agc_scope_spec), .kind = kind},
        .template_id = template_id,
    };
    uint8_t storage[1024];
    agc_key_info_response resp;
    AGC_INIT(&resp);
    resp.storage = (agc_buf){storage, sizeof storage};
    CHECK_RC(agc_create_key(ctx, &p, &resp), AGC_OK);
}

static const char *msg = "the quick brown fox jumps over the lazy dog";

static agc_encrypt_params aead_params(const char *aad)
{
    agc_encrypt_params ep;
    AGC_INIT(&ep);
    ep.kind = AGC_ENCRYPT_PARAMS_AEAD;
    ep.u.aead.aad = (agc_slice){(const uint8_t *)aad, strlen(aad)};
    return ep;
}

/* Encrypts msg with `key`, size-querying first; returns the lengths. */
static void encrypt(agc_ctx *ctx, const char *key, const agc_encrypt_params *ep, agc_encoding enc, uint8_t *ct,
                    size_t *ct_len, uint8_t *md, size_t *md_len)
{
    agc_encrypt_request er;
    AGC_INIT(&er);
    er.key_name = key;
    er.plaintext = (agc_slice){(const uint8_t *)msg, strlen(msg)};
    er.params = ep;
    er.metadata_encoding = enc;

    agc_encrypt_response resp;
    AGC_INIT(&resp); /* NULL regions: a size query */
    CHECK_RC(agc_encrypt(ctx, &er, &resp), AGC_ERR_BUFFER_TOO_SMALL);
    CHECK(resp.ciphertext_len > 0 && resp.metadata_len > 0);
    size_t want_ct = resp.ciphertext_len, want_md = resp.metadata_len;

    /* A real region one byte short is refused the same way, with the exact
     * sizes, and nothing is written to it. */
    memset(ct, 0xEE, want_ct);
    resp.ciphertext = (agc_buf){ct, want_ct - 1};
    resp.metadata = (agc_buf){md, want_md};
    CHECK_RC(agc_encrypt(ctx, &er, &resp), AGC_ERR_BUFFER_TOO_SMALL);
    CHECK(resp.ciphertext_len == want_ct && resp.metadata_len == want_md);
    for (size_t i = 0; i < want_ct; i++)
        CHECK(ct[i] == 0xEE);

    resp.ciphertext = (agc_buf){ct, want_ct};
    resp.metadata = (agc_buf){md, want_md};
    CHECK_RC(agc_encrypt(ctx, &er, &resp), AGC_OK);
    CHECK(resp.ciphertext_len == want_ct && resp.metadata_len == want_md); /* the query was exact */
    CHECK(resp.key_version >= 1);
    CHECK(md[0] == enc);
    *ct_len = resp.ciphertext_len;
    *md_len = resp.metadata_len;
}

static agc_rc decrypt(agc_ctx *ctx, const char *key, const agc_encrypt_params *ep, const uint8_t *ct, size_t ct_len,
                      const uint8_t *md, size_t md_len, uint8_t *pt, size_t pt_cap, size_t *pt_len)
{
    agc_decrypt_request dr;
    AGC_INIT(&dr);
    dr.key_name = key;
    dr.ciphertext = (agc_slice){ct, ct_len};
    dr.metadata = (agc_slice){md, md_len};
    dr.params = ep;
    agc_decrypt_response resp;
    AGC_INIT(&resp); /* metadata {NULL, 0}: not wanted */
    resp.plaintext = (agc_buf){pt, pt_cap};
    agc_rc rc = agc_decrypt(ctx, &dr, &resp);
    *pt_len = resp.plaintext_len;
    return rc;
}

static void aead_round_trip(agc_ctx *ctx, agc_encoding enc)
{
    agc_encrypt_params ep = aead_params("context-v1");
    uint8_t ct[256], md[128], pt[256];
    size_t ct_len, md_len, pt_len;
    encrypt(ctx, "gcm", &ep, enc, ct, &ct_len, md, &md_len);
    CHECK(ct_len == strlen(msg) + 16);

    /* The metadata decodes: AEAD output, a 12-byte nonce, key version 1. */
    agc_decode_metadata_result r;
    uint8_t storage[64];
    AGC_INIT(&r);
    r.storage = (agc_buf){storage, sizeof storage};
    CHECK_RC(agc_metadata_decode(enc, (agc_slice){md, md_len}, &r), AGC_OK);
    CHECK(r.metadata.key_version == 1);
    CHECK(r.metadata.provider_output.kind == AGC_ALGORITHM_OUTPUT_AEAD);
    CHECK(r.metadata.provider_output.u.aead.nonce.len == 12);
    CHECK_STR(r.metadata.provider_output.encoding, "raw");

    /* A plaintext region too small is refused before any work. */
    CHECK_RC(decrypt(ctx, "gcm", &ep, ct, ct_len, md, md_len, pt, 4, &pt_len), AGC_ERR_BUFFER_TOO_SMALL);
    CHECK(pt_len == strlen(msg));
    CHECK_RC(decrypt(ctx, "gcm", &ep, ct, ct_len, md, md_len, pt, sizeof pt, &pt_len), AGC_OK);
    CHECK(pt_len == strlen(msg) && memcmp(pt, msg, pt_len) == 0);

    /* Tampering is detected and releases nothing. */
    ct[0] ^= 1;
    memset(pt, 0xAA, sizeof pt);
    CHECK_RC(decrypt(ctx, "gcm", &ep, ct, ct_len, md, md_len, pt, sizeof pt, &pt_len),
             AGC_ERR_CRYPTO_AUTHENTICATION_FAILED);
    CHECK(pt_len == 0);
    for (size_t i = 0; i < sizeof pt; i++) CHECK(pt[i] == 0xAA);
    ct[0] ^= 1;

    /* The associated data is authenticated, not just carried along. */
    agc_encrypt_params other = aead_params("context-v2");
    CHECK_RC(decrypt(ctx, "gcm", &other, ct, ct_len, md, md_len, pt, sizeof pt, &pt_len),
             AGC_ERR_CRYPTO_AUTHENTICATION_FAILED);
}

static void decrypt_with_metadata_out(agc_ctx *ctx)
{
    agc_encrypt_params ep = aead_params("x");
    uint8_t ct[256], md[128], pt[256], md_out[128];
    size_t ct_len, md_len;
    encrypt(ctx, "chacha", &ep, AGC_ENCODING_PROTOBUF, ct, &ct_len, md, &md_len);

    agc_decrypt_request dr;
    AGC_INIT(&dr);
    dr.key_name = "chacha";
    dr.ciphertext = (agc_slice){ct, ct_len};
    dr.metadata = (agc_slice){md, md_len};
    dr.params = &ep;
    agc_decrypt_response resp;
    AGC_INIT(&resp);
    resp.plaintext = (agc_buf){pt, sizeof pt};
    resp.metadata = (agc_buf){md_out, 1}; /* present but too small */
    CHECK_RC(agc_decrypt(ctx, &dr, &resp), AGC_ERR_BUFFER_TOO_SMALL);
    resp.metadata = (agc_buf){md_out, sizeof md_out};
    CHECK_RC(agc_decrypt(ctx, &dr, &resp), AGC_OK);
    CHECK(resp.key_version == 1 && resp.metadata_len > 0 && md_out[0] == AGC_ENCODING_PROTOBUF);
}

static void block_and_stream_ciphers(agc_ctx *ctx)
{
    agc_encrypt_params none;
    AGC_INIT(&none);
    none.kind = AGC_ENCRYPT_PARAMS_NO_PARAMS;
    const char *keys[] = {"cbc", "ctr"};
    for (int i = 0; i < 2; i++) {
        uint8_t ct[256], md[128], pt[256];
        size_t ct_len, md_len, pt_len;
        encrypt(ctx, keys[i], &none, AGC_ENCODING_WIRE_V1, ct, &ct_len, md, &md_len);
        CHECK_RC(decrypt(ctx, keys[i], &none, ct, ct_len, md, md_len, pt, sizeof pt, &pt_len), AGC_OK);
        CHECK(pt_len == strlen(msg) && memcmp(pt, msg, pt_len) == 0);
    }
}

static void bad_requests(agc_ctx *ctx)
{
    uint8_t ct[256], md[128];
    agc_encrypt_request er;
    AGC_INIT(&er);
    er.key_name = "gcm";
    er.plaintext = (agc_slice){(const uint8_t *)msg, strlen(msg)};
    er.metadata_encoding = AGC_ENCODING_WIRE_V1;
    agc_encrypt_response resp;
    AGC_INIT(&resp);
    resp.ciphertext = (agc_buf){ct, sizeof ct};
    resp.metadata = (agc_buf){md, sizeof md};

    CHECK_RC(agc_encrypt(ctx, &er, &resp), AGC_ERR_INVALID_ARGUMENT); /* params are required */
    agc_encrypt_params none;
    AGC_INIT(&none);
    none.kind = AGC_ENCRYPT_PARAMS_NO_PARAMS;
    er.params = &none;
    CHECK_RC(agc_encrypt(ctx, &er, &resp), AGC_ERR_INVALID_ARGUMENT); /* an AEAD key needs AEAD params */
    agc_encrypt_params xts;
    AGC_INIT(&xts);
    xts.kind = AGC_ENCRYPT_PARAMS_XTS;
    er.params = &xts;
    CHECK_RC(agc_encrypt(ctx, &er, &resp), AGC_ERR_NOT_IMPLEMENTED);

    agc_encrypt_params ep = aead_params("");
    er.params = &ep;
    er.metadata_encoding = AGC_ENCODING_UNSPECIFIED;
    CHECK_RC(agc_encrypt(ctx, &er, &resp), AGC_ERR_INVALID_ARGUMENT);
    er.metadata_encoding = AGC_ENCODING_WIRE_V1;
    er.plaintext = (agc_slice){NULL, 0};
    CHECK_RC(agc_encrypt(ctx, &er, &resp), AGC_ERR_INVALID_ARGUMENT); /* nothing to protect */
    er.plaintext = (agc_slice){(const uint8_t *)msg, strlen(msg)};
    er.key_name = "missing";
    CHECK_RC(agc_encrypt(ctx, &er, &resp), AGC_ERR_CRYPTO_KEY_NOT_FOUND);
}

static void old_ciphertext_after_transform(agc_ctx *ctx)
{
    agc_encrypt_params ep = aead_params("ad");
    uint8_t ct[256], md[128], pt[256];
    size_t ct_len, md_len, pt_len;
    encrypt(ctx, "gcm", &ep, AGC_ENCODING_WIRE_V1, ct, &ct_len, md, &md_len);

    agc_transform_key_params tp;
    AGC_INIT(&tp);
    tp.key_name = "gcm";
    tp.template_id = "chacha20-poly1305";
    uint8_t storage[1024];
    agc_key_info_response kr;
    AGC_INIT(&kr);
    kr.storage = (agc_buf){storage, sizeof storage};
    CHECK_RC(agc_transform_key(ctx, &tp, &kr), AGC_OK);
    CHECK(kr.key_info.version == 2);

    /* The stored metadata names version 1, which still decrypts. */
    CHECK_RC(decrypt(ctx, "gcm", &ep, ct, ct_len, md, md_len, pt, sizeof pt, &pt_len), AGC_OK);
    CHECK(memcmp(pt, msg, pt_len) == 0);
    /* New encryptions use version 2. */
    uint8_t ct2[256], md2[128];
    size_t ct2_len, md2_len;
    encrypt(ctx, "gcm", &ep, AGC_ENCODING_WIRE_V1, ct2, &ct2_len, md2, &md2_len);
    uint32_t v = 0;
    CHECK_RC(agc_metadata_peek_key_version(AGC_ENCODING_WIRE_V1, (agc_slice){md2, md2_len}, &v), AGC_OK);
    CHECK(v == 2);
}

int main(void)
{
    agc_ctx *ctx = open_embedded();
    CHECK_RC(create_policy(ctx, "crypto", CRYPTO_POLICY), AGC_OK);
    create(ctx, "gcm", AGC_SCOPE_KIND_AEAD, "aes-256-gcm-128-96");
    create(ctx, "chacha", AGC_SCOPE_KIND_AEAD, "chacha20-poly1305");
    create(ctx, "cbc", AGC_SCOPE_KIND_SYMMETRIC_CIPHER, "aes-128-cbc-pkcs7-128");
    create(ctx, "ctr", AGC_SCOPE_KIND_SYMMETRIC_CIPHER, "aes-128-ctr");
    aead_round_trip(ctx, AGC_ENCODING_WIRE_V1);
    aead_round_trip(ctx, AGC_ENCODING_PROTOBUF);
    decrypt_with_metadata_out(ctx);
    block_and_stream_ciphers(ctx);
    bad_requests(ctx);
    old_ciphertext_after_transform(ctx);
    agc_ctx_close(ctx);
    return 0;
}
