#include "ed25519.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define CRYPTO_SECRETKEYBYTES 64
#define CRYPTO_PUBLICKEYBYTES 32
#define CRYPTO_BYTES 64

unsigned char seed[32], public_key[32];

void ed25519_load_public_key(unsigned char *pk) {
    memcpy(public_key, pk, 32);
}

int ed25519_crypto_secretkeybytes(void) {
    return CRYPTO_SECRETKEYBYTES;
}

int ed25519_crypto_publickeybytes(void) {
    return CRYPTO_PUBLICKEYBYTES;
}

int ed25519_crypto_bytes(void) {
    return CRYPTO_BYTES;
}

int ed25519_crypto_sign_keypair(unsigned char *pk, unsigned char *sk) {
    if (ed25519_create_seed(seed)) {
        return 1;
    }
    ed25519_create_keypair(public_key, sk, seed);
    memcpy(pk, public_key, CRYPTO_PUBLICKEYBYTES);
    return 0;
}

int ed25519_crypto_sign(unsigned char **sm, unsigned long long *smlen,
            const unsigned char *m, unsigned long long mlen,
            const unsigned char *sk) {
    *smlen = mlen + CRYPTO_BYTES;
    *sm = malloc(*smlen); 
    ed25519_sign(*sm, m, mlen, public_key, sk);
    memcpy((*sm) + CRYPTO_BYTES, m, mlen);

    return 0;
}

int ed25519_crypto_sign_open(unsigned char **m, unsigned long long *mlen,
                 const unsigned char *sm, unsigned long long smlen,
                 const unsigned char *pk) {

    *mlen = smlen - CRYPTO_BYTES;
    *m = malloc(*mlen);
    memcpy(*m, sm + CRYPTO_BYTES, *mlen);

    int sig_accept = ed25519_verify(sm, *m, *mlen, public_key);
    if (!sig_accept) {
        memset(*m, 0, *mlen);
    }
    return 0;
}
