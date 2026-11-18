/* Create an AES-GCM key, encrypt with it, decrypt again.
 *
 * Shows the caller-allocated style of the API: every output goes into a
 * buffer the caller owns. A call with NULL buffers is a size query: it
 * reports the lengths needed and does no work. */
#include "example.h"

int main(void)
{
    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    agc_ctx *ctx = NULL;
    check(agc_ctx_open(&cfg, &ctx), "agc_ctx_open");

    add_policy(ctx, "app",
               "{\"version\": \"1\", \"allowed_templates\": [\"aes-256-gcm-128-96\"],"
               " \"allowed_operations\": {\"key_operations\": [\"create_key\", \"encrypt\", \"decrypt\"]}}");

    /* A key for authenticated encryption. The policy picks the template. */
    agc_create_key_params kp = {
        .struct_size = sizeof kp,
        .key_name = "orders",
        .policy_name = "app",
        .scope_spec = {.struct_size = sizeof(agc_scope_spec), .kind = AGC_SCOPE_KIND_AEAD},
    };
    agc_key_info_response key;
    AGC_INIT(&key); /* no storage: a size query; no key is created */
    size_query(agc_create_key(ctx, &kp, &key), "agc_create_key");
    key.storage = (agc_buf){xmalloc(key.storage_used), key.storage_used};
    check(agc_create_key(ctx, &kp, &key), "agc_create_key");
    printf("created %s, template %s\n", key.key_info.key_name, key.key_info.template_id);
    free(key.storage.data);

    /* Encrypt, with associated data that is authenticated but not secret. */
    const char *plaintext = "ship 3 crates to Basel";
    const char *aad = "order-4711";
    agc_encrypt_params ep;
    AGC_INIT(&ep);
    ep.kind = AGC_ENCRYPT_PARAMS_AEAD;
    ep.u.aead.aad = (agc_slice){(const uint8_t *)aad, strlen(aad)};
    agc_encrypt_request er;
    AGC_INIT(&er);
    er.key_name = "orders";
    er.plaintext = (agc_slice){(const uint8_t *)plaintext, strlen(plaintext)};
    er.params = &ep;
    er.metadata_encoding = AGC_ENCODING_WIRE_V1;

    agc_encrypt_response enc;
    AGC_INIT(&enc); /* NULL buffers: a size query */
    size_query(agc_encrypt(ctx, &er, &enc), "agc_encrypt");
    uint8_t *ciphertext = xmalloc(enc.ciphertext_len);
    uint8_t *metadata = xmalloc(enc.metadata_len);
    enc.ciphertext = (agc_buf){ciphertext, enc.ciphertext_len};
    enc.metadata = (agc_buf){metadata, enc.metadata_len};
    check(agc_encrypt(ctx, &er, &enc), "agc_encrypt");
    printf("encrypted %zu bytes into %zu, metadata %zu bytes, key version %u\n", strlen(plaintext),
           enc.ciphertext_len, enc.metadata_len, enc.key_version);

    /* Decrypt. The metadata carries the nonce and the key version, so it is
     * stored with the ciphertext and handed back here. */
    agc_decrypt_request dr;
    AGC_INIT(&dr);
    dr.key_name = "orders";
    dr.ciphertext = (agc_slice){ciphertext, enc.ciphertext_len};
    dr.metadata = (agc_slice){metadata, enc.metadata_len};
    dr.params = &ep;
    agc_decrypt_response dec;
    AGC_INIT(&dec); /* NULL plaintext: a size query; metadata {NULL, 0}: not wanted back */
    size_query(agc_decrypt(ctx, &dr, &dec), "agc_decrypt");
    uint8_t *out = xmalloc(dec.plaintext_len);
    dec.plaintext = (agc_buf){out, dec.plaintext_len};
    check(agc_decrypt(ctx, &dr, &dec), "agc_decrypt");
    printf("decrypted: %.*s\n", (int)dec.plaintext_len, out);

    /* Tampering is detected: no plaintext is released. */
    ciphertext[0] ^= 1;
    agc_rc rc = agc_decrypt(ctx, &dr, &dec);
    printf("after tampering: %s\n", agc_rc_name(rc));

    free(out);
    free(ciphertext);
    free(metadata);
    agc_ctx_close(ctx);
    return rc == AGC_ERR_CRYPTO_AUTHENTICATION_FAILED ? 0 : 1;
}
