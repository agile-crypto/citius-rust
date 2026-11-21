#include <stddef.h>
#include <stdint.h>
long rc_aes256gcm_seal(const uint8_t *, const uint8_t *, size_t, uint8_t *, size_t);
int main(void) { uint8_t k[32] = {0}, o[64]; return rc_aes256gcm_seal(k, (const uint8_t *)"hi", 2, o, sizeof o) < 0; }
