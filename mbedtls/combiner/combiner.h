#pragma once 

#include <stddef.h>
#include <stdio.h>

void print_b(const void *ptr, size_t n);

extern int (*crypto_publickeybytes_constants[]) (void);
extern int (*crypto_privatekeybytes_constants[]) (void);
extern int (*crypto_bytes_constants[]) (void);

typedef enum {
    CROSS,
    LESS,
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
    DILITHIUM,
    SPHINCS,
    HAWK,

    ED25519,

    NUMBER_OF_SCHEMES,
} scheme_t;

typedef enum {
    CONCATENATION,
    STRONG_NESTING,
} combiner_t;

typedef struct {
    unsigned char* public_key;
    size_t public_key_len;
    unsigned char* secret_key;
    size_t secret_key_len;
} keypair_t;

typedef union {
    struct {
        unsigned char** contents;
        size_t* lens;
    } concat;
    struct {
        unsigned char* content;
        size_t len;
    } nesting;
} signature_t;

typedef struct {
    size_t len;
    scheme_t* schemes;
    combiner_t combiner; 
    signature_t signature;
    keypair_t keypair;
} hybrid_t;

typedef struct {
    const unsigned char* content;
    size_t len;
} msg_t;

const char* comb_to_str(int comb);

char* scheme_t_to_str (scheme_t scheme);

scheme_t str_to_scheme_t (char* str);

int combiner_keygen (hybrid_t* hybrid);

int combiner_sign (hybrid_t* hybrid, msg_t message);

int combiner_verify (const hybrid_t hybrid, msg_t message);

int combiner_read_keyfile(hybrid_t* hybrid, const char* file_name);

int combiner_write_keyfile(const hybrid_t* hybrid, const char* file_name);

int combiner_write_signature(hybrid_t* hybrid, unsigned char* sig, size_t* sig_size);

int combiner_parse_signature(hybrid_t* hybrid, msg_t sig, msg_t hash);

int combiner_write_pubkey(const hybrid_t* hybrid, unsigned char* output_buf, const size_t output_buf_size);

int combiner_parse_pubkey(hybrid_t* hybrid, const unsigned char* input_buf, const size_t input_buf_size);

char* schemes_to_str (hybrid_t* hybrid);


