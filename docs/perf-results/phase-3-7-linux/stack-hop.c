/* ML-DSA sign p50 over 400 calls on threads with 16 MiB, 512 KiB and 128 KiB
 * stacks (the stack guard's helper-thread cost). bench.c with main renamed. */
#define main bench_main
#include "bench.c"
#undef main
typedef struct { op_state *s; double p50; } hop_job;
static void *hop_run(void *p)
{
    hop_job *j = p;
    uint64_t t[400];
    for (int i = 0; i < 400; i++) {
        uint64_t a = now_ns();
        op_sign(j->s);
        t[i] = now_ns() - a;
    }
    qsort(t, 400, sizeof *t, cmp_u64);
    j->p50 = t[200] / 1e3;
    return NULL;
}
int main(void)
{
    agc_ctx *ctx = open_memory_ctx();
    const char *ids[] = {"ml-dsa-44", "ml-dsa-87"};
    for (int k = 0; k < 2; k++) {
        const algo *a = NULL;
        for (size_t i = 0; i < sizeof SIGNERS / sizeof *SIGNERS; i++)
            if (strcmp(SIGNERS[i].template_id, ids[k]) == 0) a = &SIGNERS[i];
        create_key(ctx, a, a->template_id);
        op_state s;
        op_init(&s, ctx, a->template_id, SIGN, 1024);
        printf("%s sign p50:", ids[k]);
        size_t sizes[] = {16u << 20, 512u << 10, 128u << 10};
        for (int z = 0; z < 3; z++) {
            pthread_attr_t at;
            pthread_attr_init(&at);
            pthread_attr_setstacksize(&at, sizes[z]);
            hop_job j = {&s, 0};
            pthread_t t;
            pthread_create(&t, &at, hop_run, &j);
            pthread_join(t, NULL);
            printf(" %zu KiB %.1f us%s", sizes[z] >> 10, j.p50, z < 2 ? " |" : "\n");
        }
        op_free(&s);
    }
    agc_ctx_close(ctx);
    return 0;
}
