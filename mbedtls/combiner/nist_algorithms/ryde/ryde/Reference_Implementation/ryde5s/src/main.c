#define _GNU_SOURCE

#include <unistd.h>
#include <sys/syscall.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "randombytes.h"
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

    #ifdef VERBOSE
    printf("# RYDE-5S");
    #endif

    unsigned long long ryde_5s_mlen = 22;
    unsigned long long ryde_5s_smlen;

    // Message corresponds with: Rank sYndrome DEcoding
    unsigned char ryde_5s_m[] = {0x52, 0x61, 0x6e, 0x6b, 0x20, 0x73, 0x59, 0x6e, 0x64, 0x72, 0x6f, 0x6d,
                                  0x65, 0x20, 0x44, 0x45, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67};

    unsigned char ryde_5s_pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char ryde_5s_sk[CRYPTO_SECRETKEYBYTES];
    unsigned char ryde_5s_sm[CRYPTO_BYTES + ryde_5s_mlen];

    unsigned long long t1, t2, t3, t4, t5, t6;



    unsigned char seed[48] = {0};
//    (void)syscall(SYS_getrandom, seed, 48, 0);
    RYDE_randombytes_init(seed, NULL, 256);



    /*************/
    /* RYDE-5S */
    /*************/



    t1 = cpucyclesStart();
    if (RYDE_crypto_sign_keypair(ryde_5s_pk, ryde_5s_sk) == -1) {
        printf("\nnFailed\n\n");
        return -1;
    }
    t2 = cpucyclesStop();

    t3 = cpucyclesStart();
    if (RYDE_crypto_sign(ryde_5s_sm, &ryde_5s_smlen, ryde_5s_m, ryde_5s_mlen, ryde_5s_sk) != 0) {
        printf("\nnFailed\n\n");
        return -1;
    };
    t4 = cpucyclesStart();

    t5 = cpucyclesStart();
    if (RYDE_crypto_sign_open(ryde_5s_m, &ryde_5s_mlen, ryde_5s_sm, ryde_5s_smlen, ryde_5s_pk) == -1) {
        printf("\nnFailed\n\n");
        return -1;
    }
    t6 = cpucyclesStart();




    #ifndef VERBOSE
    printf("\n RYDE-5S");
    printf("\n  RYDE_crypto_sign_keypair: %lld CPU cycles", t2 - t1);
    printf("\n  RYDE_crypto_sign:         %lld CPU cycles", t4 - t3);
    printf("\n  RYDE_crypto_sign_open:    %lld CPU cycles", t6 - t5);
    printf("\n\n");
    printf("\n sk: "); for(int k = 0 ; k < CRYPTO_SECRETKEYBYTES ; ++k) printf("%02x", ryde_5s_sk[k]);
    printf("\n pk: "); for(int k = 0 ; k < CRYPTO_PUBLICKEYBYTES ; ++k) printf("%02x", ryde_5s_pk[k]);
    printf("\n  m: "); for(int k = 0 ; k < (int)ryde_5s_mlen ; ++k) printf("%02x", ryde_5s_m[k]);
    printf("\n sm: "); for(int k = 0 ; k < ((int)ryde_5s_smlen) ; ++k) printf("%02x", ryde_5s_sm[k]);
    #endif

    // To avoid warning in VERBOSE mode
    t1 -= t1;
    t2 -= t2;
    t3 -= t3;
    t4 -= t4;
    t5 -= t5;
    t6 -= t6;

    printf("\n\n");
    return 0;
}

