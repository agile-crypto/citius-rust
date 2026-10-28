/* agc_metadata.h: the OperationMetadata codec and envelopes, from C. */
#include "agc_test.h"

/* The "aead" golden vector (citius-c-api tests/golden, the real protobuf
 * library): key_version 3, encoding "raw", AEAD nonce 01..0c, tag 16,
 * api "1.0", user context {tenant: acme}. Encoding byte first. */
static const uint8_t golden_aead[] = {
    0x01, 0x08, 0x03, 0x12, 0x17, 0x0a, 0x03, 0x72, 0x61, 0x77, 0x5a, 0x10, 0x0a, 0x0c, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x10, 0x10, 0x1a, 0x03, 0x31, 0x2e, 0x30, 0x22,
    0x0e, 0x0a, 0x06, 0x74, 0x65, 0x6e, 0x61, 0x6e, 0x74, 0x12, 0x04, 0x61, 0x63, 0x6d, 0x65};

static void decode_and_reencode(void)
{
    agc_slice in = {golden_aead, sizeof golden_aead};

    /* Size query, then the exact size (malloc returns aligned memory). */
    size_t needed = 0;
    CHECK_RC(agc_metadata_storage_len(AGC_ENCODING_PROTOBUF, in, &needed), AGC_OK);
    agc_decode_metadata_result r;
    AGC_INIT(&r);
    CHECK_RC(agc_metadata_decode(AGC_ENCODING_PROTOBUF, in, &r), AGC_ERR_BUFFER_TOO_SMALL);
    CHECK(r.storage_used == needed);
    void *storage = malloc(needed);
    r.storage = (agc_buf){storage, needed};
    CHECK_RC(agc_metadata_decode(AGC_ENCODING_PROTOBUF, in, &r), AGC_OK);

    const agc_metadata *md = &r.metadata;
    CHECK(md->key_version == 3);
    CHECK_STR(md->api_version, "1.0");
    CHECK_STR(md->provider_output.encoding, "raw");
    CHECK(md->provider_output.kind == AGC_ALGORITHM_OUTPUT_AEAD);
    CHECK(md->provider_output.u.aead.nonce.len == 12);
    CHECK(md->provider_output.u.aead.nonce.data[0] == 0x01 && md->provider_output.u.aead.nonce.data[11] == 0x0c);
    CHECK(md->provider_output.u.aead.tag_len == 16);
    CHECK(md->user_context.count == 1);
    CHECK_STR(md->user_context.items[0].key, "tenant");
    CHECK_STR(md->user_context.items[0].value, "acme");

    /* Back to the same protobuf bytes... */
    uint8_t out[256];
    size_t len = 0;
    CHECK_RC(agc_metadata_encode(md, AGC_ENCODING_PROTOBUF, (agc_buf){NULL, 0}, &len), AGC_ERR_BUFFER_TOO_SMALL);
    CHECK(len == sizeof golden_aead);
    CHECK_RC(agc_metadata_encode(md, AGC_ENCODING_PROTOBUF, (agc_buf){out, sizeof out}, &len), AGC_OK);
    CHECK(len == sizeof golden_aead && memcmp(out, golden_aead, len) == 0);

    /* ...and to WIRE_V1: 26 bytes plus the user-context entry. */
    CHECK_RC(agc_metadata_encode(md, AGC_ENCODING_WIRE_V1, (agc_buf){out, sizeof out}, &len), AGC_OK);
    CHECK(out[0] == AGC_ENCODING_WIRE_V1);
    CHECK(len == 26 + 2 + 6 + 2 + 4);
    uint32_t v = 0;
    CHECK_RC(agc_metadata_peek_key_version(AGC_ENCODING_WIRE_V1, (agc_slice){out, len}, &v), AGC_OK);
    CHECK(v == 3);
    free(storage);
}

static void envelopes(void)
{
    /* encoding byte | len | WIRE_V1 body | ciphertext */
    uint8_t md[64];
    size_t md_len = 0;
    agc_metadata m;
    AGC_INIT(&m);
    m.key_version = 9;
    strcpy(m.api_version, "1.0");
    m.provider_output.kind = AGC_ALGORITHM_OUTPUT_NO_OUTPUT;
    CHECK_RC(agc_metadata_encode(&m, AGC_ENCODING_WIRE_V1, (agc_buf){md, sizeof md}, &md_len), AGC_OK);

    uint8_t env[128];
    size_t body_len = md_len - 1;
    env[0] = md[0];
    env[1] = (uint8_t)(body_len >> 8);
    env[2] = (uint8_t)body_len;
    memcpy(env + 3, md + 1, body_len);
    memcpy(env + 3 + body_len, "CT", 2);

    agc_encoding enc;
    agc_slice body, ct;
    CHECK_RC(agc_envelope_split((agc_slice){env, 3 + body_len + 2}, &enc, &body, &ct), AGC_OK);
    CHECK(enc == AGC_ENCODING_WIRE_V1 && body.len == body_len && ct.len == 2 && ct.data[0] == 'C');

    agc_decode_metadata_result r;
    AGC_INIT(&r); /* NO_OUTPUT and no user context: no storage needed */
    CHECK_RC(agc_metadata_decode_body(enc, body, &r), AGC_OK);
    CHECK(r.metadata.key_version == 9 && r.storage_used == 0);
}

static void bad_input(void)
{
    agc_decode_metadata_result r;
    AGC_INIT(&r);
    agc_slice in = {golden_aead, sizeof golden_aead};
    CHECK_RC(agc_metadata_decode(AGC_ENCODING_WIRE_V1, in, &r), AGC_ERR_INVALID_ARGUMENT); /* byte mismatch */
    CHECK_RC(agc_metadata_decode(AGC_ENCODING_UNSPECIFIED, in, &r), AGC_ERR_INVALID_ARGUMENT);

    uint8_t truncated[sizeof golden_aead - 1];
    memcpy(truncated, golden_aead, sizeof truncated);
    CHECK_RC(agc_metadata_decode(AGC_ENCODING_PROTOBUF, (agc_slice){truncated, sizeof truncated}, &r),
             AGC_ERR_INVALID_ARGUMENT);

    agc_metadata m;
    AGC_INIT(&m); /* kind NONE: an unset output is never valid */
    size_t len;
    CHECK_RC(agc_metadata_encode(&m, AGC_ENCODING_PROTOBUF, (agc_buf){NULL, 0}, &len), AGC_ERR_INVALID_ARGUMENT);
    m.provider_output.kind = AGC_ALGORITHM_OUTPUT_NO_OUTPUT;
    strcpy(m.provider_output.encoding, "p1363"); /* fine in protobuf, not in WIRE_V1 */
    strcpy(m.api_version, "1.0");
    CHECK_RC(agc_metadata_encode(&m, AGC_ENCODING_PROTOBUF, (agc_buf){NULL, 0}, &len), AGC_ERR_BUFFER_TOO_SMALL);
    CHECK_RC(agc_metadata_encode(&m, AGC_ENCODING_WIRE_V1, (agc_buf){NULL, 0}, &len), AGC_ERR_INVALID_ARGUMENT);

    agc_encoding enc;
    agc_slice body, ct;
    uint8_t short_env[] = {0x02, 0x00, 0x09, 0x00};
    CHECK_RC(agc_envelope_split((agc_slice){short_env, sizeof short_env}, &enc, &body, &ct), AGC_ERR_INVALID_ARGUMENT);
}

int main(void)
{
    decode_and_reencode();
    envelopes();
    bad_input();
    return 0;
}
