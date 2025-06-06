#pragma once

#include "qruov.h"

//  Set these three values apropriately for your algorithm
#define CRYPTO_SECRETKEYBYTES 64
#define CRYPTO_PUBLICKEYBYTES 173676
#define CRYPTO_BYTES          392

// Change the algorithm name
#define CRYPTO_ALGNAME "qruov5q127L3v306m105avx2a"

int
QRUOV_crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

int
QRUOV_crypto_sign(unsigned char *sm, unsigned long long *smlen,
            const unsigned char *m, unsigned long long mlen,
            const unsigned char *sk);

int
QRUOV_crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                 const unsigned char *sm, unsigned long long smlen,
                 const unsigned char *pk);
