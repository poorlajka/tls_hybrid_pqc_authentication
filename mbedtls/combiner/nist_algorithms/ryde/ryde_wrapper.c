#include <api.h>
#include <stdlib.h>
#include <stdio.h>
#include "randombytes.h"

int ryde_crypto_secretkeybytes(void) {
    return CRYPTO_SECRETKEYBYTES;
}

int ryde_crypto_publickeybytes(void) {
    return CRYPTO_PUBLICKEYBYTES;
}

int ryde_crypto_bytes(void) {
    return CRYPTO_BYTES;
}

int ryde_crypto_sign_keypair(unsigned char *pk, unsigned char *sk) {
    unsigned char seed[48] = {0};
//    (void)syscall(SYS_getrandom, seed, 48, 0);
    RYDE_randombytes_init(seed, NULL, 256);
    return RYDE_crypto_sign_keypair(pk, sk);
}

int ryde_crypto_sign(unsigned char **sm, unsigned long long *smlen,
            const unsigned char *m, unsigned long long mlen,
            const unsigned char *sk) {
    *sm = malloc(sizeof(**sm) * (mlen + CRYPTO_BYTES)); 

    return RYDE_crypto_sign(*sm, smlen, m, mlen, sk);
}

int ryde_crypto_sign_open(unsigned char **m, unsigned long long *mlen,
                 const unsigned char *sm, unsigned long long smlen,
                 const unsigned char *pk) {

    //*m = malloc(sizeof(**m) * (orig_msg_len + CRYPTO_BYTES) * hybrid_len);
    *m = malloc(sizeof(*m) * smlen - CRYPTO_BYTES);
    return RYDE_crypto_sign_open(*m, mlen, sm, smlen, pk);
}
