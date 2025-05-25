/**
 * @file api.h
 * @brief NIST SIGN API
 */


#ifndef RYDE_5S_API_H
#define RYDE_5S_API_H

#include "parameters.h"

#define CRYPTO_ALGNAME "RYDE-5S"

#define CRYPTO_PUBLICKEYBYTES RYDE_5S_PUBLIC_KEY_BYTES
#define CRYPTO_SECRETKEYBYTES RYDE_5S_SECRET_KEY_BYTES
#define CRYPTO_BYTES          RYDE_5S_SIGNATURE_BYTES

int RYDE_crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int RYDE_crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen, const unsigned char *sk);
int RYDE_crypto_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen, const unsigned char *pk);


#endif //RYDE_5S_API_H
