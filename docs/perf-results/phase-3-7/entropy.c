/* N threads drawing 12-byte nonces with getentropy for 1 s each. */
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/random.h>
static atomic_int stop;
static void *run(void *p) {
    unsigned char b[12]; long n = 0;
    while (!atomic_load_explicit(&stop, memory_order_relaxed)) { getentropy(b, sizeof b); n++; }
    *(long *)p = n; return NULL;
}
int main(void) {
    int counts[] = {1, 2, 4, 8, 12};
    for (int c = 0; c < 5; c++) {
        int t = counts[c]; pthread_t th[12]; long n[12];
        atomic_store(&stop, 0);
        for (int i = 0; i < t; i++) pthread_create(&th[i], NULL, run, &n[i]);
        sleep(1); atomic_store(&stop, 1);
        long sum = 0; for (int i = 0; i < t; i++) { pthread_join(th[i], NULL); sum += n[i]; }
        printf("getentropy 12 B, %2d threads: %9ld ops/s\n", t, sum);
    }
}
