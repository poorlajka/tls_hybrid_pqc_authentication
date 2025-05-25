#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "combiner.h"

#include "mayo_wrapper.h"
#include "less_wrapper.h"
#include "cross_wrapper.h"
#include "snova_wrapper.h"
#include "qruov_wrapper.h"
#include "uov_wrapper.h"
#include "sdith_wrapper.h"
#include "faest_wrapper.h"
#include "sqisign_wrapper.h"
#include "mirath_wrapper.h"
#include "perk_wrapper.h"
#include "ryde_wrapper.h"
#include "mqom_wrapper.h"
#include "falcon_wrapper.h"
#include "dilithium_wrapper.h"
#include "sphincs_wrapper.h"
#include "hawk_wrapper.h"
#include "ed25519_wrapper.h"

void print_b (const void *ptr, size_t n) {
    const unsigned char *byte = (const unsigned char *)ptr;
    for (size_t i = 0; i < n; i++) {
        printf("%02X", byte[i]); 
    }
    printf("\n");
}

const char* comb_to_str(int comb) {
    switch(comb) {
        case CONCATENATION:
            return "CONCATENATION";
        case STRONG_NESTING:
            return "STRONG_NESTING";
    }
    return "Unknown";
}

// Ugly ugly ugly
char* schemes_to_str (hybrid_t* hybrid) {
    size_t buf_max = 1000;
    char* buf = malloc(sizeof(*buf) * buf_max);
    size_t offset = 0;
    for (int i = 0; i < hybrid->len; ++i) {
        char* scheme_str = scheme_t_to_str(hybrid->schemes[i]);
        memcpy(buf + offset, scheme_str, strlen(scheme_str));
        offset += strlen(scheme_str);
        buf[offset] = '_';
        offset += 1;
    }
    buf[offset-1] = '\0';

    return buf;
}

char* scheme_t_to_str (scheme_t scheme) {
    switch (scheme) {
        case CROSS:
            return "CROSS";
        case LESS:
            return "LESS";
        case MAYO:
            return "MAYO";
        case SNOVA:
            return "SNOVA";
        case QRUOV:
            return "QRUOV";
        case UOV:
            return "UOV";
        case SDITH:
            return "SDITH";
        case FAEST:
            return "FAEST";
        case SQISIGN:
            return "SQISIGN";
        case MIRATH:
            return "MIRATH";
        case PERK:
            return "PERK";
        case RYDE:
            return "RYDE";
        case MQOM:
            return "MQOM";
        case FALCON:
            return "FALCON";
        case DILITHIUM:
            return "DILITHIUM";
        case SPHINCS:
            return "SPHINCS";
        case HAWK:
            return "HAWK";
        case ED25519:
            return "ED25519";
    }
    return "Unknown!";
}

scheme_t str_to_scheme_t (char* str) {
    if (strncmp(str, "CROSS", strlen(str)) == 0) {
        return CROSS;
    }
    else if (strncmp(str, "LESS", strlen(str)) == 0) {
        return LESS;
    }
    else if (strncmp(str, "MAYO", strlen(str)) == 0) {
        return MAYO;
    }
    else if (strncmp(str, "SNOVA", strlen(str)) == 0) {
        return SNOVA;
    }
    else if (strncmp(str, "QRUOV", strlen(str)) == 0) {
        return QRUOV;
    }
    else if (strncmp(str, "UOV", strlen(str)) == 0) {
        return UOV;
    }
    else if (strncmp(str, "SDITH", strlen(str)) == 0) {
        return SDITH;
    }
    else if (strncmp(str, "FAEST", strlen(str)) == 0) {
        return FAEST;
    }
    else if (strncmp(str, "SQISIGN", strlen(str)) == 0) {
        return SQISIGN;
    }
    else if (strncmp(str, "MIRATH", strlen(str)) == 0) {
        return MIRATH;
    }
    else if (strncmp(str, "PERK", strlen(str)) == 0) {
        return PERK;
    }
    else if (strncmp(str, "RYDE", strlen(str)) == 0) {
        return RYDE;
    }
    else if (strncmp(str, "MQOM", strlen(str)) == 0) {
        return MQOM;
    }
    else if (strncmp(str, "FALCON", strlen(str)) == 0) {
        return FALCON;
    }
    else if (strncmp(str, "DILITHIUM", strlen(str)) == 0) {
        return DILITHIUM;
    }
    else if (strncmp(str, "SPHINCS", strlen(str)) == 0) {
        return SPHINCS;
    }
    else if (strncmp(str, "HAWK", strlen(str)) == 0) {
        return HAWK;
    }
    else if (strncmp(str, "ED25519", strlen(str)) == 0) {
        return ED25519;
    }
}

typedef int (*crypto_sign_keypair_t)(unsigned char *pk, unsigned char *sk);

typedef int (*crypto_sign_t)(unsigned char **sm, unsigned long long *smlen, 
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *sk);

typedef int (*crypto_sign_open_t)(unsigned char **m, unsigned long long *mlen, 
    const unsigned char *sm, unsigned long long smlen,
    const unsigned char *pk);

crypto_sign_keypair_t crypto_sign_keypair_algorithms[] = {
    cross_crypto_sign_keypair,
    less_crypto_sign_keypair,
    snova_crypto_sign_keypair,
    mayo_crypto_sign_keypair,
    qruov_crypto_sign_keypair,
    uov_crypto_sign_keypair,
    sdith_crypto_sign_keypair,
    faest_crypto_sign_keypair,
    sqisign_crypto_sign_keypair,
    mirath_crypto_sign_keypair,
    perk_crypto_sign_keypair,
    ryde_crypto_sign_keypair,
    mqom_crypto_sign_keypair,
    falcon_crypto_sign_keypair,
    dilithium_crypto_sign_keypair,
    sphincs_crypto_sign_keypair,
    hawk_crypto_sign_keypair,
    ed25519_crypto_sign_keypair,
};

crypto_sign_t crypto_sign_algorithms[] = {
    cross_crypto_sign,
    less_crypto_sign,
    snova_crypto_sign,
    mayo_crypto_sign,
    qruov_crypto_sign,
    uov_crypto_sign,
    sdith_crypto_sign,
    faest_crypto_sign,
    sqisign_crypto_sign,
    mirath_crypto_sign,
    perk_crypto_sign,
    ryde_crypto_sign,
    mqom_crypto_sign,
    falcon_crypto_sign,
    dilithium_crypto_sign,
    sphincs_crypto_sign,
    hawk_crypto_sign,
    ed25519_crypto_sign,
};

crypto_sign_open_t crypto_sign_open_algorithms[] = {
    cross_crypto_sign_open,
    less_crypto_sign_open,
    snova_crypto_sign_open,
    mayo_crypto_sign_open,
    qruov_crypto_sign_open,
    uov_crypto_sign_open,
    sdith_crypto_sign_open,
    faest_crypto_sign_open,
    sqisign_crypto_sign_open,
    mirath_crypto_sign_open,
    perk_crypto_sign_open,
    ryde_crypto_sign_open,
    mqom_crypto_sign_open,
    falcon_crypto_sign_open,
    dilithium_crypto_sign_open,
    sphincs_crypto_sign_open,
    hawk_crypto_sign_open,
    ed25519_crypto_sign_open,
};

int (*crypto_secretkeybytes_constants[]) (void) = {
    cross_crypto_secretkeybytes,
    less_crypto_secretkeybytes,
    snova_crypto_secretkeybytes,
    mayo_crypto_secretkeybytes,
    qruov_crypto_secretkeybytes,
    uov_crypto_secretkeybytes,
    sdith_crypto_secretkeybytes,
    faest_crypto_secretkeybytes,
    sqisign_crypto_secretkeybytes,
    mirath_crypto_secretkeybytes,
    perk_crypto_secretkeybytes,
    ryde_crypto_secretkeybytes,
    mqom_crypto_secretkeybytes,
    falcon_crypto_secretkeybytes,
    dilithium_crypto_secretkeybytes,
    sphincs_crypto_secretkeybytes,
    hawk_crypto_secretkeybytes,
    ed25519_crypto_secretkeybytes,
};

int (*crypto_publickeybytes_constants[]) (void) = {
    cross_crypto_publickeybytes,
    less_crypto_publickeybytes,
    snova_crypto_publickeybytes,
    mayo_crypto_publickeybytes,
    qruov_crypto_publickeybytes,
    uov_crypto_publickeybytes,
    sdith_crypto_publickeybytes,
    faest_crypto_publickeybytes,
    sqisign_crypto_publickeybytes,
    mirath_crypto_publickeybytes,
    perk_crypto_publickeybytes,
    ryde_crypto_publickeybytes,
    mqom_crypto_publickeybytes,
    falcon_crypto_publickeybytes,
    dilithium_crypto_publickeybytes,
    sphincs_crypto_publickeybytes,
    hawk_crypto_publickeybytes,
    ed25519_crypto_publickeybytes,
};

int (*crypto_bytes_constants[]) (void) = {
    cross_crypto_bytes,
    less_crypto_bytes,
    snova_crypto_bytes,
    mayo_crypto_bytes,
    qruov_crypto_bytes,
    uov_crypto_bytes,
    sdith_crypto_bytes,
    faest_crypto_bytes,
    sqisign_crypto_bytes,
    mirath_crypto_bytes,
    perk_crypto_bytes,
    ryde_crypto_bytes,
    mqom_crypto_bytes,
    falcon_crypto_bytes,
    dilithium_crypto_bytes,
    sphincs_crypto_bytes,
    hawk_crypto_bytes,
    ed25519_crypto_bytes,
};

int combiner_keygen (hybrid_t* hybrid) {

    size_t public_key_len = 0, secret_key_len = 0;
    for (int i = 0; i < hybrid->len; ++i) {
        scheme_t scheme = hybrid->schemes[i];
        public_key_len += crypto_publickeybytes_constants[scheme]();
        secret_key_len += crypto_secretkeybytes_constants[scheme]();
    }

    printf("\nSize of public key: %zu\n", public_key_len);
    printf("\nSize of secret key: %zu\n", secret_key_len);

    hybrid->keypair.public_key_len = public_key_len;
    hybrid->keypair.secret_key_len = secret_key_len;

    hybrid->keypair.public_key = malloc(sizeof(*hybrid->keypair.public_key) * public_key_len);
    hybrid->keypair.secret_key = malloc(sizeof(*hybrid->keypair.secret_key) * secret_key_len);

    int ret;
    size_t pk_offset = 0, sk_offset = 0;
    for (int i = 0; i < hybrid->len; ++i) {
        scheme_t scheme = hybrid->schemes[i];
        ret = crypto_sign_keypair_algorithms[hybrid->schemes[i]](
            hybrid->keypair.public_key + pk_offset,
            hybrid->keypair.secret_key + sk_offset
        );

        if (ret != 0) {
            fprintf(stderr, "Keypair generation failed!\n");
            return ret;
        }

        pk_offset += crypto_publickeybytes_constants[scheme]();
        sk_offset += crypto_secretkeybytes_constants[scheme]();
    }
    return 0;
}

int concat_sign (hybrid_t* hybrid, unsigned char* secret_key,
                   msg_t message) {
    hybrid->signature.concat.contents = malloc(hybrid->len * sizeof(unsigned char*));
    hybrid->signature.concat.lens = malloc(hybrid->len * sizeof(size_t));

    unsigned char* signature;
    unsigned long long signature_len;
    int ret;
    size_t sk_offset = 0;
    for (int i = 0; i < hybrid->len; ++i) {
        scheme_t scheme = hybrid->schemes[i];
        ret = crypto_sign_algorithms[hybrid->schemes[i]](
            &signature,
            &signature_len,
            message.content,
            message.len,
            secret_key + sk_offset
        );

        if (ret != 0) {
            fprintf(stderr, "Concat signature generation failed!\n");
            return ret;
        } 

        hybrid->signature.concat.contents[i] = signature;
        hybrid->signature.concat.lens[i] = signature_len;

        sk_offset += crypto_secretkeybytes_constants[scheme]();
    }
    printf("\nskeysize = %d\n", hybrid->keypair.secret_key_len);
    return 0;
}

int nesting_sign (hybrid_t* hybrid, unsigned char* secret_key,
                   msg_t message) {
    unsigned char* signature;
    unsigned long long signature_len;

    int ret;
    ret = crypto_sign_algorithms[hybrid->schemes[0]](
        &signature,
        &signature_len,
        message.content,
        message.len,
        secret_key
    );

    if (ret != 0) {
        fprintf(stderr, "Nesting signature generation failed!\n");
        return ret;
    } 

    msg_t original_message = message;

    unsigned char* new_message;
    size_t sk_offset = crypto_secretkeybytes_constants[hybrid->schemes[0]]();
    for (int i = 1; i < hybrid->len; ++i) {
        scheme_t scheme = hybrid->schemes[i];
        new_message = malloc(
            sizeof(*new_message) * (original_message.len + signature_len)
        );
        if (new_message == NULL) {
            fprintf(stderr, "Malloc failed in nesting_sign!\n");
            return -1;
        }

        memcpy(
            new_message, 
            original_message.content, 
            sizeof(*original_message.content) * original_message.len
        );
        memcpy(
            new_message + sizeof(*message.content) * original_message.len, 
            signature, 
            sizeof(*signature) * signature_len
        );

        message.len = original_message.len + signature_len;
        message.content = new_message;

        //printf("\nkey len = %zu\n", hybrid->keypair.secret_key_len);
        printf("\nskey offset = %zu\n", sk_offset);

        ret = crypto_sign_algorithms[hybrid->schemes[i]](
            &signature,
            &signature_len,
            message.content,
            message.len,
            secret_key + sk_offset
        );

        sk_offset += crypto_secretkeybytes_constants[scheme]();
        if (ret != 0) {
            fprintf(stderr, "Nesting signature generation failed!\n");
            return ret;
        } 

        if (new_message != NULL) {
            free(new_message);
        }
    }

    hybrid->signature.nesting.content = signature;
    hybrid->signature.nesting.len = signature_len;
    return 0;
}

int combiner_sign (hybrid_t* hybrid, msg_t message) {
    switch (hybrid->combiner) {
        case CONCATENATION:
            return concat_sign(hybrid, hybrid->keypair.secret_key, message);
        case STRONG_NESTING:
            return nesting_sign(hybrid, hybrid->keypair.secret_key, message);
    }
    return -1;
}

int concat_verify (const hybrid_t hybrid, unsigned char* public_key,
                    msg_t message) {

    unsigned char* decrypted_msg;
    unsigned long long decrypted_msg_len;
    int ret;

    size_t pk_offset = 0;
    for (int i = 0; i < hybrid.len; ++i) {
        scheme_t scheme = hybrid.schemes[i];
        unsigned char* signature = hybrid.signature.concat.contents[i];
        unsigned long long signature_len = hybrid.signature.concat.lens[i];

        ret = crypto_sign_open_algorithms[hybrid.schemes[i]](
            &decrypted_msg,
            &decrypted_msg_len,
            signature,
            signature_len,
            public_key + pk_offset
        );

        if (ret != 0) {
            fprintf(stderr, "Concat signature verification failed!\n");
        }

        if (decrypted_msg_len != message.len
            || memcmp(decrypted_msg, message.content, message.len) != 0) {
            return 0;
        }
        printf("Recovered msg: \"%.*s\"\n", decrypted_msg_len, decrypted_msg);
        pk_offset += crypto_publickeybytes_constants[scheme]();
    }
    return 1;
}

int nesting_verify (hybrid_t hybrid, unsigned char* public_key, 
                     msg_t message) {

    unsigned char* signature = hybrid.signature.nesting.content;
    unsigned long long signature_len = hybrid.signature.nesting.len;
    unsigned char* decrypted_msg;
    unsigned long long decrypted_msg_len;
    int ret;

    size_t pk_offset = hybrid.keypair.public_key_len;
    for (int i = hybrid.len-1; i > -1; i--) {
        scheme_t scheme = hybrid.schemes[i];
        pk_offset -= crypto_publickeybytes_constants[scheme]();

        ret = crypto_sign_open_algorithms[hybrid.schemes[i]](
            &decrypted_msg,
            &decrypted_msg_len,
            signature,
            signature_len,
            public_key + pk_offset
        );

        if (ret != 0) {
            fprintf(stderr, "Nesting signature verification failed!\n");
        }

        signature = decrypted_msg + message.len;
        signature_len = decrypted_msg_len - message.len;
    }

    if (decrypted_msg_len == message.len
        && memcmp(decrypted_msg, message.content, message.len) == 0) {
        printf("Recovered msg: \"%.*s\"\n", decrypted_msg_len, decrypted_msg);
        return 1;
    }
    return 0;
}

int combiner_verify (hybrid_t hybrid, msg_t message) {
    switch (hybrid.combiner) {
        case CONCATENATION:
            return concat_verify(hybrid, hybrid.keypair.public_key, message);
        case STRONG_NESTING:
            return nesting_verify(hybrid, hybrid.keypair.public_key, message);
    }
    return 0;
}

int combiner_write_keyfile(const hybrid_t* hybrid, const char* file_name) {

    const size_t key_buf_len = 
        sizeof(hybrid->combiner) + 
        sizeof(hybrid->len) + 
        sizeof(*hybrid->schemes) * hybrid->len +
        sizeof(*hybrid->keypair.secret_key) * hybrid->keypair.secret_key_len +
        sizeof(*hybrid->keypair.public_key) * hybrid->keypair.public_key_len;

    unsigned char key_buf[key_buf_len];

    memcpy(key_buf, &hybrid->combiner, sizeof(hybrid->combiner));

    size_t offset = sizeof(hybrid->combiner);
    memcpy(key_buf + offset, &hybrid->len, sizeof(hybrid->len));
    offset += sizeof(hybrid->len);

    memcpy(key_buf + offset, hybrid->schemes, 
           sizeof(*hybrid->schemes) * hybrid->len);
    offset += sizeof(*hybrid->schemes) * hybrid->len;

    memcpy(key_buf + offset, hybrid->keypair.secret_key, 
           sizeof(*hybrid->keypair.secret_key) * hybrid->keypair.secret_key_len);

    offset += sizeof(*hybrid->keypair.secret_key) * hybrid->keypair.secret_key_len;

    memcpy(key_buf + offset, hybrid->keypair.public_key, 
           sizeof(*hybrid->keypair.public_key) * hybrid->keypair.public_key_len);


    FILE* fstream;
    if ((fstream = fopen(file_name, "wb")) == NULL) {
        return -1;
    }

    if (fwrite(key_buf, sizeof(*key_buf), 
               sizeof(key_buf), fstream) != sizeof(key_buf)) {

        fclose(fstream);
        return -1;
    }

    fclose(fstream);
    return 0;
}

int combiner_read_keyfile(hybrid_t* hybrid, const char* file_name) {

    FILE* fstream;
    if ((fstream = fopen(file_name, "rb")) == NULL) {
        return -1;
    }
    fseek(fstream, 0, SEEK_END);
    const size_t keyfile_size = ftell(fstream);
    rewind(fstream);

    unsigned char key_buf[keyfile_size];
    if (fread(key_buf, sizeof(*key_buf), 
               sizeof(key_buf), fstream) != sizeof(key_buf)) {

        fclose(fstream);
        return -1;
    }

    memcpy(&hybrid->combiner, key_buf, sizeof(hybrid->combiner));
    size_t offset = sizeof(hybrid->combiner);

    memcpy(&hybrid->len, key_buf + offset, sizeof(hybrid->len));
    offset += sizeof(hybrid->len);

    hybrid->schemes = malloc(sizeof(*hybrid->schemes) * hybrid->len);
    memcpy(hybrid->schemes, key_buf + offset, 
           sizeof(*hybrid->schemes) * hybrid->len);

    offset += sizeof(*hybrid->schemes) * hybrid->len;

    size_t secret_key_len = 0, public_key_len = 0;
    int edd25519_offset = -1;
    for (int i = 0; i < hybrid->len; ++i) {
        scheme_t scheme = hybrid->schemes[i];
        if (scheme == ED25519) {
            edd25519_offset = public_key_len;
        }
        public_key_len += crypto_publickeybytes_constants[scheme]();
        secret_key_len += crypto_secretkeybytes_constants[scheme]();
    }
    hybrid->keypair.public_key_len = public_key_len;
    hybrid->keypair.secret_key_len = secret_key_len;

    hybrid->keypair.secret_key = malloc(sizeof(*hybrid->keypair.secret_key) * hybrid->keypair.secret_key_len);
    hybrid->keypair.public_key = malloc(sizeof(*hybrid->keypair.public_key) * hybrid->keypair.public_key_len);

    memcpy(hybrid->keypair.secret_key, key_buf + offset, 
           sizeof(*hybrid->keypair.secret_key) * hybrid->keypair.secret_key_len);
    offset += sizeof(*hybrid->keypair.secret_key) * hybrid->keypair.secret_key_len;

    memcpy(hybrid->keypair.public_key, key_buf + offset, 
           sizeof(*hybrid->keypair.public_key) * hybrid->keypair.public_key_len);

    if (edd25519_offset != -1) {
        ed25519_load_public_key(hybrid->keypair.public_key + edd25519_offset);
    }

    return 0;
}

int combiner_write_signature(hybrid_t* hybrid, unsigned char* sig, size_t* sig_size) {
    switch (hybrid->combiner) {
        case CONCATENATION:
            size_t concat_size = 0;
            for (int i = 0; i < hybrid->len; ++i) {
                concat_size += sizeof(size_t) + hybrid->signature.concat.lens[i];
            }
            *sig_size = concat_size;

            size_t sig_offset = 0;
            for (int i = 0; i < hybrid->len; ++i) {
                scheme_t scheme = hybrid->schemes[i];
                memcpy(sig + sig_offset, &hybrid->signature.concat.lens[i], sizeof(size_t));
                memcpy(sig + (sig_offset + sizeof(size_t)), hybrid->signature.concat.contents[i], hybrid->signature.concat.lens[i]);
                sig_offset += hybrid->signature.concat.lens[i] + sizeof(size_t);
            }
            break;
        case STRONG_NESTING:
            memcpy(sig, hybrid->signature.nesting.content, hybrid->signature.nesting.len);
            *sig_size = hybrid->signature.nesting.len;
    }
    return 0;
}

int combiner_parse_signature(hybrid_t* hybrid, msg_t sig, msg_t hash) {
    switch (hybrid->combiner) {
        case CONCATENATION:
            hybrid->signature.concat.lens = malloc(sizeof(*hybrid->signature.concat.lens) * hybrid->len);
            hybrid->signature.concat.contents = malloc(sizeof(*hybrid->signature.concat.contents) * hybrid->len);

            size_t sig_offset = 0;
            for (int i = 0; i < hybrid->len; ++i) {
                scheme_t scheme = hybrid->schemes[i];
                size_t sig_len;
                memcpy(&sig_len, sig.content + sig_offset, sizeof(size_t));

                hybrid->signature.concat.lens[i] = sig_len;
                hybrid->signature.concat.contents[i] = malloc(sig_len);
                memcpy(hybrid->signature.concat.contents[i], sig.content + (sig_offset + sizeof(size_t)), sig_len);

                sig_offset += sig_len + sizeof(size_t);
            }
            break;
        case STRONG_NESTING:
            hybrid->signature.nesting.len = sig.len; 
            hybrid->signature.nesting.content = sig.content; 
            break;
    }
    return 0;
}

int combiner_write_pubkey (const hybrid_t* hybrid, unsigned char* output_buf, 
                           const size_t output_buf_size) {

    size_t required_len = sizeof(hybrid->combiner) + sizeof(hybrid->len) + sizeof(*hybrid->schemes) * hybrid->len +
        sizeof(*hybrid->keypair.public_key) * hybrid->keypair.public_key_len;
    if (required_len > output_buf_size) {
        return -1;
    }

    memcpy(output_buf, &(hybrid->combiner), sizeof(hybrid->combiner));
    size_t offset = sizeof(hybrid->combiner);
    memcpy(output_buf + offset, &(hybrid->len), sizeof(hybrid->len));
    offset += sizeof(hybrid->len);

    size_t schemes_size = sizeof(*hybrid->schemes) * hybrid->len;
    memcpy(output_buf + offset, hybrid->schemes, schemes_size);
    offset += schemes_size;

    memcpy(output_buf + offset, hybrid->keypair.public_key, sizeof(*hybrid->keypair.public_key) * hybrid->keypair.public_key_len);

    return required_len;
}

int combiner_parse_pubkey (hybrid_t* hybrid, const unsigned char* input_buf, 
                           const size_t input_buf_size) {
    // the fuck is this even, why did I write this ?????
    if (input_buf_size <= sizeof(hybrid->len)) {
        return -1;
    }
    memcpy(&(hybrid->combiner), input_buf, sizeof(hybrid->combiner));
    size_t offset = sizeof(hybrid->combiner);

    memcpy(&(hybrid->len), input_buf + offset, sizeof(hybrid->len));
    offset += sizeof(hybrid->len);

    // schemes 
    size_t schemes_size = sizeof(*hybrid->schemes) * hybrid->len;
    if (input_buf_size - offset <= schemes_size) {
        return -1;
    }
    hybrid->schemes = malloc(schemes_size);
    memcpy(hybrid->schemes, input_buf+offset, schemes_size);
    offset += schemes_size;

    // public key 
    printf("\nsize of hybrid %d\n", (int) hybrid->len);
    size_t public_key_len = 0;
    int edd25519_offset = -1;
    for (int i = 0; i < hybrid->len; ++i) {
        scheme_t scheme = hybrid->schemes[i];
        if (scheme == ED25519) {
            edd25519_offset = public_key_len;
        }
        public_key_len += crypto_publickeybytes_constants[scheme]();
    }
    hybrid->keypair.public_key_len = public_key_len;

    size_t keysize = sizeof(*hybrid->keypair.public_key) * hybrid->keypair.public_key_len;
    if (input_buf_size - offset < keysize) {
        return -1;
    }
    hybrid->keypair.public_key = malloc(sizeof(*hybrid->keypair.public_key) * hybrid->keypair.public_key_len);
    memcpy(hybrid->keypair.public_key, input_buf+offset, keysize);
    if (edd25519_offset != -1) {
        ed25519_load_public_key(hybrid->keypair.public_key + edd25519_offset);
    }

    return 0;
}

