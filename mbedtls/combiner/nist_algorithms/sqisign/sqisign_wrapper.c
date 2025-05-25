#include <api.h>
#include <stdlib.h>
#include <stdio.h>

int sqisign_crypto_secretkeybytes(void) {
    return CRYPTO_SECRETKEYBYTES;
}

int sqisign_crypto_publickeybytes(void) {
    return CRYPTO_PUBLICKEYBYTES;
}

int sqisign_crypto_bytes(void) {
    return CRYPTO_BYTES;
}

int sqisign_crypto_sign_keypair(unsigned char *pk, unsigned char *sk) {
	return crypto_sign_keypair(pk, sk);
}

int sqisign_crypto_sign(unsigned char **sm, unsigned long long *smlen,
            const unsigned char *m, unsigned long long mlen,
            const unsigned char *sk) {
    *sm = malloc(sizeof(**sm) * (mlen + CRYPTO_BYTES)); 

    unsigned char* pk2 = malloc(CRYPTO_PUBLICKEYBYTES);
    unsigned char* sk2 = malloc(CRYPTO_SECRETKEYBYTES);
    crypto_sign_keypair(pk2, sk2);

	return crypto_sign(*sm, smlen, m, mlen, sk);
}

int sqisign_crypto_sign_open(unsigned char **m, unsigned long long *mlen,
                 const unsigned char *sm, unsigned long long smlen,
                 const unsigned char *pk) {

    //*m = malloc(sizeof(**m) * (orig_msg_len + CRYPTO_BYTES) * hybrid_len);
    *m = malloc(sizeof(*m) * smlen - CRYPTO_BYTES);
	return crypto_sign_open(*m, mlen, sm, smlen, pk);
}
