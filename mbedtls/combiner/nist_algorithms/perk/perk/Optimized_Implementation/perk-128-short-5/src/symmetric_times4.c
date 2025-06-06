
/**
 * @file symmetric_times4.c
 * @brief Implementation of the symmetric times4 functions
 */

#include "symmetric_times4.h"
#include "parameters.h"

#if (SECURITY_BYTES == 16)
#define PERK_Keccak_HashInitializetimes4_SHAKE PERK_Keccak_HashInitializetimes4_PERK_SHAKE128  // PERK_SHAKE128
#define PERK_Keccak_HashInitializetimes4_SHA3  PERK_Keccak_HashInitializetimes4_PERK_SHA3_256
#elif (SECURITY_BYTES == 24)
#define PERK_Keccak_HashInitializetimes4_SHAKE PERK_Keccak_HashInitializetimes4_PERK_SHAKE256  // PERK_SHAKE256
#define PERK_Keccak_HashInitializetimes4_SHA3  PERK_Keccak_HashInitializetimes4_PERK_SHA3_384
#elif (SECURITY_BYTES == 32)
#define PERK_Keccak_HashInitializetimes4_SHAKE PERK_Keccak_HashInitializetimes4_PERK_SHAKE256  // PERK_SHAKE256
#define PERK_Keccak_HashInitializetimes4_SHA3  PERK_Keccak_HashInitializetimes4_PERK_SHA3_512
#endif

void sig_perk_prg_times4_init(sig_perk_prg_times4_state_t *state, const uint8_t domain, const salt_t salt,
                              const uint8_t *seed4[4]) {
    const uint8_t *domain4[] = {&domain, &domain, &domain, &domain};
    PERK_Keccak_HashInitializetimes4_SHAKE(state);
    if (salt != NULL) {
        const uint8_t *salt4[] = {salt, salt, salt, salt};
        PERK_Keccak_HashUpdatetimes4(state, salt4, sizeof(salt_t) * 8);
    }
    if (seed4 != NULL) {
        PERK_Keccak_HashUpdatetimes4(state, seed4, sizeof(seed_t) * 8);
    }
    PERK_Keccak_HashUpdatetimes4(state, domain4, 1 * 8);
    PERK_Keccak_HashFinaltimes4(state, NULL);
}

void sig_perk_prg_times4(sig_perk_prg_times4_state_t *state, uint8_t *output4[4], size_t outlen) {
    PERK_Keccak_HashSqueezetimes4(state, output4, outlen * 8);
}

void sig_perk_hash_times4_init(sig_perk_hash_times4_state_t *state, const salt_t salt, const uint8_t tau4[4],
                               const uint8_t n4[4]) {
    const uint8_t *salt4[] = {salt, salt, salt, salt};
    PERK_Keccak_HashInitializetimes4_SHA3(state);
    PERK_Keccak_HashUpdatetimes4(state, salt4, sizeof(salt_t) * 8);

    uint8_t counters[4][2];
    int j = 0;
    if (tau4 != NULL) {
        for (int i = 0; i < 4; i++) {
            counters[i][j] = tau4[i];
        }
        j++;
    }
    if (n4 != NULL) {
        for (int i = 0; i < 4; i++) {
            counters[i][j] = n4[i];
        }
        j++;
    }
    if (j != 0) {
        const uint8_t *counters4[] = {counters[0], counters[1], counters[2], counters[3]};
        PERK_Keccak_HashUpdatetimes4(state, counters4, j * 8);
    }
}

void sig_perk_hash_times4_update(sig_perk_hash_times4_state_t *state, const uint8_t *message4[4],
                                 const size_t message_size) {
    PERK_Keccak_HashUpdatetimes4(state, message4, message_size * 8);
}

void sig_perk_hash_times4_final(sig_perk_hash_times4_state_t *state, uint8_t *digest4[4], const uint8_t domain) {
    const uint8_t *domain4[] = {&domain, &domain, &domain, &domain};
    PERK_Keccak_HashUpdatetimes4(state, domain4, 1 * 8);
    PERK_Keccak_HashFinaltimes4(state, digest4);
}