#pragma once

#include <stdlib.h>

int dilithium_crypto_secretkeybytes(void);

int dilithium_crypto_publickeybytes(void);

int dilithium_crypto_bytes(void);

int dilithium_crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

int dilithium_crypto_sign(unsigned char **sm, unsigned long long *smlen,
            const unsigned char *m, unsigned long long mlen,
            const unsigned char *sk);

int dilithium_crypto_sign_open(unsigned char **m, unsigned long long *mlen,
                 const unsigned char *sm, unsigned long long smlen,
                 const unsigned char *pk);
