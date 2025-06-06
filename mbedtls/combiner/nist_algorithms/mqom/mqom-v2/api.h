#ifndef __MQOM_API_H__
#define __MQOM_API_H__

#include "common.h"
#include "fields.h"

#define CRYPTO_SECRETKEYBYTES ((long) MQOM2_SK_SIZE)
#define CRYPTO_PUBLICKEYBYTES ((long) MQOM2_PK_SIZE)
#define CRYPTO_BYTES ((long) MQOM2_SIG_SIZE)

#define CRYPTO_ALGNAME MQOM2_PARAM_LABEL
#define CRYPTO_VERSION "1.00"

/*************************************************
* Name:        MQOM_crypto_sign_keypair
*
* Description: Generates public and private key.
*
* Arguments:   - uint8_t *pk: pointer to output public key (allocated
*                             array of CRYPTO_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key (allocated
*                             array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int MQOM_crypto_sign_keypair(unsigned char* pk, unsigned char* sk);

/*************************************************
* Name:        MQOM_crypto_sign_signature
*
* Description: Computes signature.
*
* Arguments:   - uint8_t *sig:   pointer to output signature (of length CRYPTO_BYTES)
*              - size_t *siglen: pointer to output length of signature
*              - uint8_t *m:     pointer to message to be signed
*              - size_t mlen:    length of message
*              - uint8_t *sk:    pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
int MQOM_crypto_sign_signature(unsigned char *sig, unsigned long long *siglen, const unsigned char *m,
                          unsigned long long mlen, const unsigned char *sk);

/*************************************************
* Name:        MQOM_crypto_sign
*
* Description: Compute signed message.
*
* Arguments:   - uint8_t *sm: pointer to output signed message (allocated
*                             array with CRYPTO_BYTES + mlen bytes),
*                             can be equal to m
*              - size_t *smlen: pointer to output length of signed
*                               message
*              - const uint8_t *m: pointer to message to be signed
*              - size_t mlen: length of message
*              - const uint8_t *sk: pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
int MQOM_crypto_sign(unsigned char* sm, unsigned long long* smlen, const unsigned char* m,
                unsigned long long mlen, const unsigned char* sk);

/*************************************************
* Name:        MQOM_crypto_sign_verify
*
* Description: Verifies signature.
*
* Arguments:   - uint8_t *m: pointer to input signature
*              - size_t siglen: length of signature
*              - const uint8_t *m: pointer to message
*              - size_t mlen: length of message
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signature could be verified correctly and -1 otherwise
**************************************************/
int MQOM_crypto_sign_verify(const unsigned char *sig, unsigned long long siglen, const unsigned char *m,
                       unsigned long long mlen, const unsigned char *pk);

/*************************************************
* Name:        MQOM_crypto_sign_open
*
* Description: Verify signed message.
*
* Arguments:   - uint8_t *m: pointer to output message (allocated
*                            array with smlen bytes), can be equal to sm
*              - size_t *mlen: pointer to output length of message
*              - const uint8_t *sm: pointer to signed message
*              - size_t smlen: length of signed message
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signed message could be verified correctly and -1 otherwise
**************************************************/
int MQOM_crypto_sign_open(unsigned char* m, unsigned long long* mlen, const unsigned char* sm,
                     unsigned long long smlen, const unsigned char* pk);

#endif /* __MQOM_API_H__ */
