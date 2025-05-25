#include <api.h>
#include <stdlib.h>
#include <stdio.h>
#include <csprng_hash.h>

int cross_crypto_secretkeybytes(void) {
    return CRYPTO_SECRETKEYBYTES;
}

int cross_crypto_publickeybytes(void) {
    return CRYPTO_PUBLICKEYBYTES;
}

int cross_crypto_bytes(void) {
    return CRYPTO_BYTES;
}

int cross_crypto_sign_keypair(unsigned char *pk, unsigned char *sk) {
    // TODO: Get a better understanding of the seeding and posssible impact on performance!
    csprng_initialize(&platform_csprng_state,
                      (const unsigned char *)"012345678912345",
                      16,
                      0);

	return crypto_sign_keypair(pk, sk);
}

int cross_crypto_sign(unsigned char **sm, unsigned long long *smlen,
            const unsigned char *m, unsigned long long mlen,
            const unsigned char *sk) {
    *sm = malloc(sizeof(**sm) * (mlen + CRYPTO_BYTES)); 
    if (!*sm) {
        perror("Malloc failed allocating memory for signing!");
        return -1;
    }

	return crypto_sign(*sm, (unsigned long long*)smlen, m, mlen, sk);
}

int cross_crypto_sign_open(unsigned char **m, unsigned long long *mlen,
                 const unsigned char *sm, unsigned long long smlen,
                 const unsigned char *pk) {

    //*m = malloc(sizeof(**m) * (orig_msg_len + CRYPTO_BYTES) * hybrid_len);
    *m = malloc(sizeof(*m) * smlen - CRYPTO_BYTES);
    if (!*m) {
        perror("Malloc failed allocating memory for verifying!");
        return -1;
    }
	return crypto_sign_open(*m, (unsigned long long*)mlen, sm, smlen, pk);
}
