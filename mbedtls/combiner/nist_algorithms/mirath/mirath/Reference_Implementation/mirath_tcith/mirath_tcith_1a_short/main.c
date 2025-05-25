#define _GNU_SOURCE

#include <unistd.h>
#include <sys/syscall.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "rng.h"
#include "api.h"

inline static uint64_t cpucyclesStart (void) {
    unsigned hi, lo;
    __asm__ __volatile__ (	"CPUID\n\t"
                              "RDTSC\n\t"
                              "mov %%edx, %0\n\t"
                              "mov %%eax, %1\n\t"
            : "=r" (hi), "=r" (lo)
            :
            : "%rax", "%rbx", "%rcx", "%rdx");

    return ((uint64_t) lo) ^ (((uint64_t) hi) << 32);
}

inline static uint64_t cpucyclesStop (void) {
    unsigned hi, lo;
    __asm__ __volatile__(	"RDTSCP\n\t"
                             "mov %%edx, %0\n\t"
                             "mov %%eax, %1\n\t"
                             "CPUID\n\t"
            : "=r" (hi), "=r" (lo)
            :
            : "%rax", "%rbx", "%rcx", "%rdx");

    return ((uint64_t) lo) ^ (((uint64_t) hi) << 32);
}

int main(void) {

    unsigned long long mirath1as_mlen = 22;
    unsigned long long mirath1as_smlen;

    unsigned char mirath1as_m[] = {0x52, 0x61, 0x6e, 0x6b, 0x20, 0x73, 0x59, 0x6e, 0x64, 0x72, 0x6f, 0x6d,
                                  0x65, 0x20, 0x44, 0x45, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67};

    unsigned char mirath1as_pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char mirath1as_sk[CRYPTO_SECRETKEYBYTES];
    unsigned char mirath1as_sm[CRYPTO_BYTES + mirath1as_mlen];

    unsigned long long t1, t2, t3, t4, t5, t6;



    unsigned char seed[48] = {0};
//    (void)syscall(SYS_getrandom, seed, 48, 0);
    MIRATH_randombytes_init(seed, NULL, 256);



    /***************/
    /* Mirath-1a-s */
    /***************/



    t1 = cpucyclesStart();
    if (MIRATH_crypto_sign_keypair(mirath1as_pk, mirath1as_sk) == -1) {
        printf("\nnFailed\n\n");
        return -1;
    }
    t2 = cpucyclesStop();

    t3 = cpucyclesStart();
    if (MIRATH_crypto_sign(mirath1as_sm, &mirath1as_smlen, mirath1as_m, mirath1as_mlen, mirath1as_sk) != 0) {
        printf("\nnFailed\n\n");
        return -1;
    }
    t4 = cpucyclesStart();

    t5 = cpucyclesStart();
    if (MIRATH_crypto_sign_open(mirath1as_m, &mirath1as_mlen, mirath1as_sm, mirath1as_smlen, mirath1as_pk) == -1) {
        printf("\nnFailed\n\n");
        return -1;
    }
    t6 = cpucyclesStart();

    printf("\n Mirath-1a-s");
    printf("\n  MIRATH_crypto_sign_keypair: %lld CPU cycles", t2 - t1);
    printf("\n  MIRATH_crypto_sign:         %lld CPU cycles", t4 - t3);
    printf("\n  MIRATH_crypto_sign_open:    %lld CPU cycles", t6 - t5);
    printf("\n\n");
    printf("\n sk: "); for(int k = 0 ; k < CRYPTO_SECRETKEYBYTES ; ++k) printf("%02x", mirath1as_sk[k]);
    printf("\n pk: "); for(int k = 0 ; k < CRYPTO_PUBLICKEYBYTES ; ++k) printf("%02x", mirath1as_pk[k]);
    printf("\n  m: "); for(int k = 0 ; k < (int)mirath1as_mlen ; ++k) printf("%02x", mirath1as_m[k]);
    printf("\n sm: "); for(int k = 0 ; k < ((int)mirath1as_smlen) ; ++k) printf("%02x", mirath1as_sm[k]);

    printf("\n\n");
    return 0;
}

