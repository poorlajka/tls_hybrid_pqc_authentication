
/**
 * @file symmetric.c
 * @brief Implementation of the symmetric functions
 */

#include "symmetric.h"
#include "parameters.h"

#if (SECURITY_BYTES == 16)
#define PERK_Keccak_HashInitialize_SHAKE PERK_Keccak_HashInitialize_PERK_SHAKE128  // PERK_SHAKE128
#define PERK_Keccak_HashInitialize_SHA3  PERK_Keccak_HashInitialize_PERK_SHA3_256
#elif (SECURITY_BYTES == 24)
#define PERK_Keccak_HashInitialize_SHAKE PERK_Keccak_HashInitialize_PERK_SHAKE256  // PERK_SHAKE256
#define PERK_Keccak_HashInitialize_SHA3  PERK_Keccak_HashInitialize_PERK_SHA3_384
#elif (SECURITY_BYTES == 32)
#define PERK_Keccak_HashInitialize_SHAKE PERK_Keccak_HashInitialize_PERK_SHAKE256  // PERK_SHAKE256
#define PERK_Keccak_HashInitialize_SHA3  PERK_Keccak_HashInitialize_PERK_SHA3_512
#endif

void sig_perk_prg_init(sig_perk_prg_state_t *state, const uint8_t domain, const salt_t salt, const seed_t seed) {
    PERK_Keccak_HashInitialize_SHAKE(state);
    if (salt != NULL) {
        PERK_Keccak_HashUpdate(state, salt, sizeof(salt_t) * 8);
    }
    if (seed != NULL) {
        PERK_Keccak_HashUpdate(state, seed, sizeof(seed_t) * 8);
    }
    PERK_Keccak_HashUpdate(state, &domain, 1 * 8);
    PERK_Keccak_HashFinal(state, NULL);
}

void sig_perk_prg(sig_perk_prg_state_t *state, uint8_t *output, size_t outlen) {
    PERK_Keccak_HashSqueeze(state, output, outlen * 8);
}

void sig_perk_hash_init(sig_perk_hash_state_t *state, const salt_t salt, const uint8_t *tau, const uint8_t *n) {
    PERK_Keccak_HashInitialize_SHA3(state);
    PERK_Keccak_HashUpdate(state, salt, sizeof(salt_t) * 8);

    uint8_t counters[2];
    int j = 0;
    if (tau != NULL) {
        counters[j] = *tau;
        j++;
    }
    if (n != NULL) {
        counters[j] = *n;
        j++;
    }
    if (j != 0) {
        PERK_Keccak_HashUpdate(state, counters, j * 8);
    }
}

void sig_perk_hash_update(sig_perk_hash_state_t *state, const uint8_t *message, const size_t message_size) {
    PERK_Keccak_HashUpdate(state, message, message_size * 8);
}

void sig_perk_hash_final(sig_perk_hash_state_t *state, digest_t digest, const uint8_t domain) {
    PERK_Keccak_HashUpdate(state, &domain, 1 * 8);
    PERK_Keccak_HashFinal(state, digest);
}
