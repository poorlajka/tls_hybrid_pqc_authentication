#include "ed25519.h"
#include <stdio.h>
#include <string.h>

int main () {
    unsigned char seed[32], public_key[32], private_key[64], signature[64];
    unsigned char other_public_key[32], other_private_key[64], shared_secret[32];
    char message[] = "Test message to be signed which is very important information pertaining to events of interest :)";

    /* create a random seed, and a key pair out of that seed */
    if (ed25519_create_seed(seed)) {
        printf("error while generating seed\n");
        return 0;
    }

    ed25519_create_keypair(public_key, private_key, seed);

    /* create signature on the message with the key pair */
    ed25519_sign(signature, message, sizeof(message), public_key, private_key);

    /* verify the signature */
    if (ed25519_verify(signature, message, sizeof(message), public_key)) {
        printf("valid signature\n");
    } else {
        printf("invalid signature\n");
    }
    return 0;
}
