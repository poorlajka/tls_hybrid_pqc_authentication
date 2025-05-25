#include <combiner.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


// Ugliest function I've ever written in my entire life i stg
int print_bytes(const void *ptr, size_t n) {
    const unsigned char *byte = (const unsigned char *)ptr;
    int ret = 0;
    int k = n;
    if (n >= 500) {
        k = 500;
        ret = 500;
    }
    else {
        ret = n;
    }
    for (size_t i = 0; i < k; i++) {
        printf("%02X", byte[i]); 
    }
    return n;
}

int test_hybrid(combiner_t combiner, size_t hybrid_len, scheme_t* schemes) {

    hybrid_t hybrid;
    hybrid.len = hybrid_len;
    hybrid.combiner = combiner;
    hybrid.schemes = schemes;

    int ret;
    ret = combiner_keygen(&hybrid);
    //ret = combiner_read_keyfile(&hybrid, "hybrid_keypair.key");
    //ret = combiner_keygen(&hybrid);
    if (ret < 0) {
        printf("\033[0;31mKeys not successfully generated\033[0;37m\n");
        return -1;
    }
    /*
    ret = combiner_write_keyfile(&hybrid, "combiner_keypair.key");
    if (ret < 0) {
        printf("\033[0;31mKeys not successfully written\033[0;37m\n");
        return -1;
    }
    */
    //ret = combiner_read_keyfile(&hybrid, "hybrid_keypair.key");
    if (ret < 0) {
        printf("\033[0;31mKeys not successfully read\033[0;37m\n");
        return -1;
    }

    printf("\033[0;32mKeys successfully generated\033[0;37m\n");

    char* text = "Test message to be signed which is very important information pertaining to events of interest :)";
    msg_t message = {
        .content = (unsigned char*)text,
        .len = strlen(text)
    };
    ret = combiner_sign(&hybrid, message);
    if (ret != 0) {
        printf("\033[0;31mMsg not successfully signed\033[0;37m\n");
        return -1;
    }
    else {
        printf("\033[0;32mMsg successfully signed\033[0;37m\n\n");
    }

    if (hybrid.combiner == STRONG_NESTING) {
        printf("\033[0;32mFirst 500 bytes of nested signature with size %d\033[0;37m\n\n", hybrid.signature.nesting.len);
        print_bytes(hybrid.signature.nesting.content, hybrid.signature.nesting.len);
        printf("\n\n");
    }
    if (hybrid.combiner == CONCATENATION) {
        int sig_len = 0;
        for (int i = 0; i < hybrid.len; ++i) {
            sig_len += hybrid.signature.concat.lens[i];
        }
        printf("\033[0;32mFirst 500 bytes of concat signature of size %d\033[0;37m\n\n", sig_len);
        int remaining = 500;
        for (int i = 0; i < hybrid.len; ++i) {
            remaining -= print_bytes(hybrid.signature.concat.contents[i], hybrid.signature.concat.lens[i]);
            if (remaining <= 0) {
                break;
            }
        }
        printf("\n\n");
    }

    bool sig_pass = combiner_verify(hybrid, message);
    if (!sig_pass) {
        printf("\034[0;31mSig verify did not pass\033[0;37m\n");
        return -1;
    }
    else {
        printf("\033[0;32mSig successfully verified!\033[0;37m\n");
        return 0;
    }
}

int test_concat(scheme_t* schemes, int hybrid_len) {
    printf("\033[0;33mTesting concat hybrid!\033[0;37m\n");
    if (test_hybrid(CONCATENATION, hybrid_len, schemes) == 0) {
        printf("\033[0;32mConcatenation test passed!\033[0;37m\n\n");
        return 0;
    }
    else {
        printf("\033[0;31mConcatenation test failed!\033[0;37m\n\n");
        return -1;
    }
}

int test_nesting(scheme_t* schemes, int hybrid_len) {
    printf("\033[0;33mTesting nesting hybrid!\033[0;37m\n");
    if (test_hybrid(STRONG_NESTING, hybrid_len, schemes) == 0) {
        printf("\033[0;32mNesting test passed!\033[0;37m\n\n");
        return 0;
    }
    else {
        printf("\033[0;31mNesting test failed!\033[0;37m\n\n");
        return -1;
    }
}

int main (void) {
    srand(time(NULL));
    int hybrid_len = 2;
    int iterations = 10000;
    for (int i = 0; i < iterations; ++i) {
        scheme_t* schemes = malloc(hybrid_len * sizeof(scheme_t));
        scheme_t available_schemes[] = {
            CROSS,
            SNOVA,
            MAYO,
            QRUOV,
            UOV,
            SDITH,
            FAEST,
            SQISIGN,
            MIRATH,
            PERK,
            RYDE,
            MQOM,
            FALCON,
            SPHINCS,
            HAWK,
            DILITHIUM,
        };

        printf("\033[0;37m\n\n");
        printf("\033[0;33mRandom hybrid generated: ");
        /*
        for (size_t i = 0; i < hybrid_len; ++i) {
            schemes[i] = available_schemes[rand() % (sizeof(available_schemes)/sizeof(scheme_t))];
            printf("%s ", scheme_t_to_str(schemes[i]), schemes[i]);
        }
        */
        printf("\033[0;37m\n");
        schemes[0] = LESS;
        schemes[1] = MAYO;

        printf("\n\n");
        if (test_concat(schemes, hybrid_len) != 0) {
            return -1;
        }
        /*
        if (test_nesting(schemes, hybrid_len) != 0) {
            return -1;
        }
        */
    }
}
