/* The smallest useful client: open a context, one policy, one AEAD key, encrypt. */
#include "agilecrypto.h"
int main(void)
{
    agc_ctx_config cfg; AGC_INIT(&cfg);
    agc_ctx *ctx = 0;
    if (agc_ctx_open(&cfg, &ctx) != AGC_OK) return 1;
    agc_create_policy_request pr; AGC_INIT(&pr);
    pr.name = "p";
    pr.policy_document = "{\"version\": \"1\", \"allowed_templates\": [\"aes-256-gcm-128-96\"],"
        " \"allowed_operations\": {\"key_operations\": [\"create_key\", \"encrypt\"]}}";
    if (agc_create_policy(ctx, &pr, 0) != AGC_OK) return 1;
    agc_create_key_params kp; AGC_INIT(&kp);
    kp.key_name = "k"; kp.policy_name = "p";
    AGC_INIT(&kp.scope_spec); kp.scope_spec.kind = AGC_SCOPE_KIND_AEAD;
    static unsigned char st[4096]; agc_key_info_response ki; AGC_INIT(&ki);
    ki.storage = (agc_buf){st, sizeof st};
    if (agc_create_key(ctx, &kp, &ki) != AGC_OK) return 1;
    agc_encrypt_params ep; AGC_INIT(&ep); ep.kind = AGC_ENCRYPT_PARAMS_AEAD;
    agc_encrypt_request er; AGC_INIT(&er);
    er.key_name = "k"; er.plaintext = (agc_slice){(const uint8_t *)"hi", 2}; er.params = &ep;
    er.metadata_encoding = AGC_ENCODING_WIRE_V1;
    static unsigned char ct[64], md[256]; agc_encrypt_response eo; AGC_INIT(&eo);
    eo.ciphertext = (agc_buf){ct, sizeof ct}; eo.metadata = (agc_buf){md, sizeof md};
    int rc = agc_encrypt(ctx, &er, &eo) != AGC_OK;
    agc_ctx_close(ctx);
    return rc;
}
