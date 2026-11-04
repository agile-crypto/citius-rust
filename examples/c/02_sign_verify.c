/* Sign a message with Ed25519; sign a digest with ECDSA P-256.
 *
 * Verification fails closed twice: `valid` is 0 unless the signature
 * checks, and a bad signature also returns AGC_ERR_CRYPTO_SIGNATURE_INVALID,
 * so checking either one is enough. */
#include "example.h"

static void create(agc_ctx *ctx, const char *name, const char *template_id, agc_signature_scope scope)
{
    agc_create_key_params kp = {
        .struct_size = sizeof kp,
        .key_name = name,
        .policy_name = "signing",
        .scope_spec = {.struct_size = sizeof(agc_scope_spec),
                       .kind = AGC_SCOPE_KIND_SIGNATURE,
                       .u.signature.scope = scope},
        .template_id = template_id,
    };
    uint8_t storage[2048];
    agc_key_info_response key;
    AGC_INIT(&key);
    key.storage = (agc_buf){storage, sizeof storage};
    check(agc_create_key(ctx, &kp, &key), "agc_create_key");
}

int main(void)
{
    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    agc_ctx *ctx = NULL;
    check(agc_ctx_open(&cfg, &ctx), "agc_ctx_open");
    add_policy(ctx, "signing",
               "{\"version\": \"1\", \"allowed_templates\": [\"ed25519\", \"ecdsa-p256-prehashed-der\"],"
               " \"allowed_operations\": {\"key_operations\": [\"create_key\", \"sign\", \"verify\","
               " \"digest_sign\", \"digest_verify\"]}}");
    create(ctx, "release", "ed25519", AGC_SIGNATURE_SCOPE_STANDARD);
    create(ctx, "firmware", "ecdsa-p256-prehashed-der", AGC_SIGNATURE_SCOPE_PREHASHED);

    agc_sign_params no_context;
    AGC_INIT(&no_context);
    no_context.kind = AGC_SIGN_PARAMS_NO_CONTEXT;

    /* Sign a message. Ed25519 signatures are always 64 bytes. */
    const char *msg = "release 2.0.0";
    agc_sign_request sr;
    AGC_INIT(&sr);
    sr.key_name = "release";
    sr.input = (agc_slice){(const uint8_t *)msg, strlen(msg)};
    sr.params = &no_context;
    sr.metadata_encoding = AGC_ENCODING_WIRE_V1;
    uint8_t sig[128], md[128];
    agc_sign_response signed_msg;
    AGC_INIT(&signed_msg);
    signed_msg.signature = (agc_buf){sig, sizeof sig};
    signed_msg.metadata = (agc_buf){md, sizeof md};
    check(agc_sign(ctx, &sr, &signed_msg), "agc_sign");

    agc_verify_request vr;
    AGC_INIT(&vr);
    vr.key_name = "release";
    vr.input = sr.input;
    vr.signature = (agc_slice){sig, signed_msg.signature_len};
    vr.metadata = (agc_slice){md, signed_msg.metadata_len};
    vr.params = &no_context;
    agc_verify_response verdict;
    AGC_INIT(&verdict);
    check(agc_verify(ctx, &vr, &verdict), "agc_verify");
    printf("message signature: %zu bytes, valid=%d\n", signed_msg.signature_len, verdict.valid);

    /* Sign a digest the caller computed. The key's accepted hashes come from
     * agc_read_key (here: SHA-256, SHA-384, SHA-512); the metadata records the
     * one used, so verification needs the metadata, and only PROTOBUF can
     * carry that hash. A fixed demo digest stands in for a real SHA-256. */
    uint8_t digest[32];
    for (size_t i = 0; i < sizeof digest; i++)
        digest[i] = (uint8_t)i;
    agc_digest_sign_request dsr;
    AGC_INIT(&dsr);
    dsr.key_name = "firmware";
    dsr.digest = (agc_slice){digest, sizeof digest};
    dsr.params = &no_context;
    dsr.hash_algorithm = AGC_HASH_ALGORITHM_SHA256;
    dsr.metadata_encoding = AGC_ENCODING_PROTOBUF;
    agc_sign_response signed_digest;
    AGC_INIT(&signed_digest);
    signed_digest.signature = (agc_buf){sig, sizeof sig};
    signed_digest.metadata = (agc_buf){md, sizeof md};
    check(agc_digest_sign(ctx, &dsr, &signed_digest), "agc_digest_sign");

    agc_digest_verify_request dvr;
    AGC_INIT(&dvr);
    dvr.key_name = "firmware";
    dvr.digest = dsr.digest;
    dvr.signature = (agc_slice){sig, signed_digest.signature_len};
    dvr.metadata = (agc_slice){md, signed_digest.metadata_len};
    dvr.params = &no_context;
    AGC_INIT(&verdict);
    check(agc_digest_verify(ctx, &dvr, &verdict), "agc_digest_verify");
    printf("digest signature: %zu bytes (DER), valid=%d\n", signed_digest.signature_len, verdict.valid);

    /* A changed digest does not verify. */
    digest[0] ^= 1;
    agc_rc rc = agc_digest_verify(ctx, &dvr, &verdict);
    printf("changed digest: %s, valid=%d\n", agc_rc_name(rc), verdict.valid);

    agc_ctx_close(ctx);
    return rc == AGC_ERR_CRYPTO_SIGNATURE_INVALID && verdict.valid == 0 ? 0 : 1;
}
