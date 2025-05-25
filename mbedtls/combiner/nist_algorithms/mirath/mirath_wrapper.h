#pragma once

#include <stdlib.h>

int mirath_crypto_secretkeybytes(void);

int mirath_crypto_publickeybytes(void);

int mirath_crypto_bytes(void);

int mirath_crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

int mirath_crypto_sign(unsigned char **sm, unsigned long long *smlen,
            const unsigned char *m, unsigned long long mlen,
            const unsigned char *sk);

int mirath_crypto_sign_open(unsigned char **m, unsigned long long *mlen,
                 const unsigned char *sm, unsigned long long smlen,
                 const unsigned char *pk);

