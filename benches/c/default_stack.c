/* Build: cc -std=c11 -O2 -I ../citius-c-api/include/agc benches/c/default_stack.c -L target/release -lagilecrypto -Wl,-rpath,$PWD/target/release -pthread
 * Run: ./a.out ml-dsa-87 [sign]   (exit 138 = SIGBUS: the default thread stack overflowed) */
/* Does creating / signing with an ML-DSA-87 key work on a thread with the platform's default stack? */
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include "agilecrypto.h"
static agc_ctx *ctx;
static const char *tmpl;
static int sign_mode;
static void *job(void *arg)
{
    (void)arg;
    agc_create_key_params kp; AGC_INIT(&kp);
    kp.key_name = tmpl; kp.policy_name = "p";
    AGC_INIT(&kp.scope_spec); kp.scope_spec.kind = AGC_SCOPE_KIND_SIGNATURE;
    kp.scope_spec.u.signature.scope = AGC_SIGNATURE_SCOPE_STANDARD;
    static unsigned char st[16384]; agc_key_info_response ki; AGC_INIT(&ki);
    ki.storage = (agc_buf){st, sizeof st};
    agc_rc rc;
    if (sign_mode) {
        agc_sign_params sp; AGC_INIT(&sp); sp.kind = AGC_SIGN_PARAMS_NO_CONTEXT;
        agc_sign_request r; AGC_INIT(&r); r.key_name = tmpl; r.params = &sp;
        r.input = (agc_slice){(const uint8_t *)"m", 1}; r.metadata_encoding = AGC_ENCODING_WIRE_V1;
        static unsigned char sig[8192], md[1024]; agc_sign_response o; AGC_INIT(&o);
        o.signature = (agc_buf){sig, sizeof sig}; o.metadata = (agc_buf){md, sizeof md};
        rc = AGC_OK;
        for (int i = 0; i < 200 && rc == AGC_OK; i++) rc = agc_sign(ctx, &r, &o);
        printf("200x sign %s on a default thread: %s\n", tmpl, agc_rc_name(rc));
    } else {
        rc = agc_create_key(ctx, &kp, &ki);
        printf("create %s on a default thread: %s\n", tmpl, agc_rc_name(rc));
    }
    fflush(stdout);
    return NULL;
}
int main(int argc, char **argv)
{
    tmpl = argc > 1 ? argv[1] : "ml-dsa-87";
    agc_ctx_config cfg; AGC_INIT(&cfg);
    agc_ctx_open(&cfg, &ctx);
    char doc[300];
    snprintf(doc, sizeof doc, "{\"version\": \"1\", \"allowed_templates\": [\"%s\"], \"allowed_operations\": {\"key_operations\": [\"create_key\", \"sign\"]}}", tmpl);
    agc_create_policy_request pr; AGC_INIT(&pr); pr.name = "p"; pr.policy_document = doc;
    agc_create_policy(ctx, &pr, 0);
    if (argc > 2) {
        job(NULL); /* create the key on the main thread (8 MiB stack) */
        sign_mode = 1;
    }
    pthread_attr_t a; pthread_attr_init(&a); size_t sz; pthread_attr_getstacksize(&a, &sz);
    printf("default secondary-thread stack: %zu KiB\n", sz / 1024);
    pthread_t t; pthread_create(&t, NULL, job, NULL); pthread_join(t, NULL);
    return 0;
}
