#include "sign.h"
#include <stdlib.h>
#include <stdio.h>

int dilithium_crypto_secretkeybytes(void) {
    return CRYPTO_SECRETKEYBYTES;
}

int dilithium_crypto_publickeybytes(void) {
    return CRYPTO_PUBLICKEYBYTES;
}

int dilithium_crypto_bytes(void) {
    return CRYPTO_BYTES;
}

int dilithium_crypto_sign_keypair(unsigned char *pk, unsigned char *sk) {
    return crypto_sign_keypair(pk, sk);
}

int dilithium_crypto_sign(unsigned char **sm, unsigned long long *smlen,
            const unsigned char *m, unsigned long long mlen,
            const unsigned char *sk) {
    *sm = malloc(sizeof(**sm) * (mlen + CRYPTO_BYTES)); 

    return crypto_sign(*sm, (size_t*)smlen, m, mlen, NULL, 0, sk);
}

int dilithium_crypto_sign_open(unsigned char **m, unsigned long long *mlen,
                 const unsigned char *sm, unsigned long long smlen,
                 const unsigned char *pk) {

    //*m = malloc(sizeof(**m) * (orig_msg_len + CRYPTO_BYTES) * hybrid_len);
    *m = malloc(sizeof(*m) * smlen - CRYPTO_BYTES);
    return crypto_sign_open(*m, (size_t*)mlen, sm, smlen, NULL, 0, pk);
}
