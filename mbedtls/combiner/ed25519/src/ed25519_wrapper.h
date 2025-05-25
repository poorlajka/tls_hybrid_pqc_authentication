#pragma once

#include <stdlib.h>

void ed25519_load_public_key(unsigned char *pk);

int ed25519_crypto_secretkeybytes(void);

int ed25519_crypto_publickeybytes(void);

int ed25519_crypto_bytes(void);

int ed25519_crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

int ed25519_crypto_sign(unsigned char **sm, unsigned long long *smlen,
            const unsigned char *m, unsigned long long mlen,
            const unsigned char *sk);

int ed25519_crypto_sign_open(unsigned char **m, unsigned long long *mlen,
                 const unsigned char *sm, unsigned long long smlen,
                 const unsigned char *pk);

