#include <stddef.h>
#include <stdint.h>
typedef long (*signf)(const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *, size_t);
long rc_aes256gcm_seal(const uint8_t *, const uint8_t *, size_t, uint8_t *, size_t);
long rc_chacha_seal(const uint8_t *, const uint8_t *, size_t, uint8_t *, size_t);
long rc_p256_sign(const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *, size_t);
long rc_p384_sign(const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *, size_t);
long rc_p521_sign(const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *, size_t);
long rc_ed25519_sign(const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *, size_t);
long rc_mldsa44_sign(const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *, size_t);
long rc_mldsa65_sign(const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *, size_t);
long rc_mldsa87_sign(const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *, size_t);
/* Referenced through a volatile table so the linker keeps them all. */
volatile signf table[] = {rc_p256_sign, rc_p384_sign, rc_p521_sign, rc_ed25519_sign, rc_mldsa44_sign, rc_mldsa65_sign, rc_mldsa87_sign};
int main(void) { uint8_t k[32] = {0}, o[64]; return (rc_aes256gcm_seal(k, k, 2, o, 64) < 0) + (rc_chacha_seal(k, k, 2, o, 64) < 0) + (table[0] == 0); }
