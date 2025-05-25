#define _GNU_SOURCE

#include <unistd.h>
#include <sys/syscall.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "randombytes.h"
#include "api.h"


#define NB_TEST 25
#define NB_SAMPLES 25



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

    unsigned long long ryde_3s_mlen = 1;
    unsigned long long ryde_3s_smlen;
    unsigned char ryde_3s_m[ryde_3s_mlen];
    ryde_3s_m[0] = 0;

    unsigned char ryde_3s_pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char ryde_3s_sk[CRYPTO_SECRETKEYBYTES];
    unsigned char ryde_3s_sm[CRYPTO_BYTES + ryde_3s_mlen];

    unsigned long long timer, t1, t2;
    unsigned long long ryde_3s_keypair_mean = 0, ryde_3s_RYDE_crypto_sign_mean = 0, ryde_3s_RYDE_crypto_sign_open_mean = 0;
    int ryde_3s_failures = 0;



    unsigned char seed[48] = {0};
//    (void)syscall(SYS_getrandom, seed, 48, 0);
    RYDE_randombytes_init(seed, NULL, 256);



    /*************/
    /* RYDE-3S */
    /*************/

    // Cache memory heating
    for(size_t i = 0 ; i < NB_TEST ; i++) {
        RYDE_crypto_sign_keypair(ryde_3s_pk, ryde_3s_sk);
    }



    // Measurement
    for(size_t i = 0 ; i < NB_SAMPLES ; i++) {
        printf("Benchmark (RYDE_crypto_sign_keypair):\t");
        printf("%2lu%%", 100 * i / NB_SAMPLES);
        fflush(stdout);
        printf("\r\x1b[K");

        timer = 0;

        for(size_t j = 0 ; j < NB_TEST ; j++) {
            RYDE_randombytes(seed, 48);
            RYDE_randombytes_init(seed, NULL, 256);

            t1 = cpucyclesStart();
            RYDE_crypto_sign_keypair(ryde_3s_pk, ryde_3s_sk);
            t2 = cpucyclesStop();

            timer += t2 - t1;
        }

        ryde_3s_keypair_mean += timer / NB_TEST;
    }
    printf("\nBenchmark (RYDE_crypto_sign_keypair)\n");



    for(size_t i = 0 ; i < NB_SAMPLES ; i++) {
        printf("Benchmark (RYDE_crypto_sign):\t");
        printf("%2lu%%", 100 * i / NB_SAMPLES);
        fflush(stdout);
        printf("\r\x1b[K");

        RYDE_randombytes(seed, 48);
        RYDE_randombytes_init(seed, NULL, 256);

        RYDE_crypto_sign_keypair(ryde_3s_pk, ryde_3s_sk);
        timer = 0;

        for(size_t j = 0 ; j < NB_TEST ; j++) {
            RYDE_randombytes(seed, 48);
            RYDE_randombytes_init(seed, NULL, 256);

            t1 = cpucyclesStart();
            RYDE_crypto_sign(ryde_3s_sm, &ryde_3s_smlen, ryde_3s_m, ryde_3s_mlen, ryde_3s_sk);
            t2 = cpucyclesStop();

            timer += t2 - t1;
        }

        ryde_3s_RYDE_crypto_sign_mean += timer / NB_TEST;
    }
    printf("Benchmark (RYDE_crypto_sign)\n");



    for(size_t i = 0 ; i < NB_SAMPLES ; i++) {
        printf("Benchmark (RYDE_crypto_sign_open):\t");
        printf("%2lu%%", 100 * i / NB_SAMPLES);
        fflush(stdout);
        printf("\r\x1b[K");

        RYDE_randombytes(seed, 48);
        RYDE_randombytes_init(seed, NULL, 256);

        RYDE_crypto_sign_keypair(ryde_3s_pk, ryde_3s_sk);
        RYDE_crypto_sign(ryde_3s_sm, &ryde_3s_smlen, ryde_3s_m, ryde_3s_mlen, ryde_3s_sk);
        if (RYDE_crypto_sign_open(ryde_3s_m, &ryde_3s_mlen, ryde_3s_sm, ryde_3s_smlen, ryde_3s_pk) == -1) { ryde_3s_failures++; }
        timer = 0;

        for(size_t j = 0 ; j < NB_TEST ; j++) {
            RYDE_randombytes(seed, 48);
            RYDE_randombytes_init(seed, NULL, 256);

            t1 = cpucyclesStart();
            RYDE_crypto_sign_open(ryde_3s_m, &ryde_3s_mlen, ryde_3s_sm, ryde_3s_smlen, ryde_3s_pk);
            t2 = cpucyclesStop();

            timer += t2 - t1;
        }

        ryde_3s_RYDE_crypto_sign_open_mean += timer / NB_TEST;
    }
    printf("Benchmark (RYDE_crypto_sign_open)\n");



    printf("\n RYDE-3S");
    printf("\n  Failures: %i", ryde_3s_failures);
    printf("\n  RYDE_crypto_sign_keypair: %lld CPU cycles", ryde_3s_keypair_mean / NB_SAMPLES);
    printf("\n  RYDE_crypto_sign:         %lld CPU cycles", ryde_3s_RYDE_crypto_sign_mean / NB_SAMPLES);
    printf("\n  RYDE_crypto_sign_open:    %lld CPU cycles", ryde_3s_RYDE_crypto_sign_open_mean / NB_SAMPLES);
    printf("\n\n");

    return 0;
}

