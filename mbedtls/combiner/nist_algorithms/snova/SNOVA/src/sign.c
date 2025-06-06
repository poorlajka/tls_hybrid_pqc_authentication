#include "api.h"
#include "snova.h"
#include "nistkat/rng.h"

int SNOVA_crypto_sign_keypair(unsigned char *pk, unsigned char *sk) {
    uint8_t seed_pair[seed_length];
    uint8_t *pt_private_key_seed;
    uint8_t *pt_public_key_seed;

    randombytes(seed_pair, seed_length);
    pt_public_key_seed = seed_pair;
    pt_private_key_seed = seed_pair + seed_length_public;

#if sk_is_seed
    SNOVA_generate_keys_ssk(pk, sk, pt_public_key_seed, pt_private_key_seed);
#else
    SNOVA_generate_keys_esk(pk, sk, pt_public_key_seed, pt_private_key_seed);
#endif

    return 0;
}

int SNOVA_crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk) {
    uint8_t digest[64];
    uint8_t salt[bytes_salt];
    // hash
    SNOVA_shake256(m, mlen, digest, 64);

    // sign
    // create_salt(salt);
    randombytes(salt, bytes_salt);
#if sk_is_seed
    SNOVA_sign_digest_ssk(sm, digest, 64, salt, sk);
#else
    SNOVA_sign_digest_esk(sm, digest, 64, salt, sk);
#endif

    memcpy(sm + CRYPTO_BYTES, m, mlen);
    *smlen = CRYPTO_BYTES + mlen;
    return 0;
}

int SNOVA_crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk) {
    uint8_t digest[64];
    if (smlen < CRYPTO_BYTES) {
        return -1;
    }

    // hash
    SNOVA_shake256(sm + CRYPTO_BYTES, smlen - CRYPTO_BYTES, digest, 64);

    int r = SNOVA_verify_signture(digest, 64, sm, pk);
    if (r) {
        return -1;
    }

    memcpy(m, sm + CRYPTO_BYTES, smlen - CRYPTO_BYTES);
    *mlen = smlen - CRYPTO_BYTES;

    return 0;
}