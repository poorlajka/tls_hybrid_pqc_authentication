#include "KeccakHash.h"
#include <string.h>
#include <stdlib.h>
#include "hash.h"

void MIRATH_hash_init(hash_ctx_t *ctx)
{
#if MIRATH_SECURITY_BYTES == 16
    MIRATH_Keccak_HashInitialize_SHA3_256(ctx);
#elif MIRATH_SECURITY_BYTES == 24
    MIRATH_Keccak_HashInitialize_SHA3_384(ctx);
#elif MIRATH_SECURITY_BYTES == 32
	MIRATH_Keccak_HashInitialize_SHA3_512(ctx);
#else
#error "HASH_SIZE not implemented!"
#endif
}

/// taken from the kyber impl.
/// Description: Compare two arrays for equality in constant time.
///
/// Arguments:   const uint8_t *a: pointer to first byte array
///              const uint8_t *b: pointer to second byte array
///              size_t len:       length of the byte arrays
///
/// Returns 0 if the byte arrays are equal, 1 otherwise
int MIRATH_verify(const uint8_t *a,
           const uint8_t *b,
           const size_t len) {
    uint8_t r = 0;

    for(size_t i=0;i<len;i++) {
        r |= a[i] ^ b[i];
    }

    return (-(uint64_t)r) >> 63;
}

/// length in byte
void MIRATH_hash_update(hash_ctx_t *ctx, const uint8_t *data, size_t length)
{
    MIRATH_Keccak_HashUpdate(ctx, data, length*8);
}

void hash_finalize(hash_t hash, hash_ctx_t *ctx)
{
    MIRATH_Keccak_HashFinal(ctx, hash);
    memset(ctx, 0, sizeof(hash_ctx_t));
}

int hash_equal(hash_t hash1, hash_t hash2)
{
    const uint32_t ret = MIRATH_verify(hash1, hash2, 2 * MIRATH_SECURITY_BYTES);
    return ret == 0;
}

void hash_tree_digest(hash_t hash, const uint8_t *domain_separator, const uint8_t *salt, const uint8_t *e, const uint8_t *node) {
    hash_ctx_t ctx;

    MIRATH_hash_init(&ctx);
    MIRATH_hash_update(&ctx, domain_separator, sizeof(uint8_t));
    MIRATH_hash_update(&ctx, salt, 2 * MIRATH_SECURITY_BYTES);
    MIRATH_hash_update(&ctx, e, sizeof(uint8_t));
    MIRATH_hash_update(&ctx, node, MIRATH_SECURITY_BYTES);
    hash_finalize(hash, &ctx);
}
