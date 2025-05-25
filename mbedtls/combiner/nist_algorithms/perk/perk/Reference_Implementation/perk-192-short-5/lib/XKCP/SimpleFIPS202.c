/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

Keccak, designed by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche.

Implementation by Gilles Van Assche, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#include "KeccakSponge.h"
#include "SimpleFIPS202.h"

int PERK_SHAKE128(unsigned char *output, size_t outputByteLen, const unsigned char *input, size_t inputByteLen)
{
    return PERK_KeccakWidth1600_Sponge(1344, 256, input, inputByteLen, 0x1F, output, outputByteLen);
}

int PERK_SHAKE256(unsigned char *output, size_t outputByteLen, const unsigned char *input, size_t inputByteLen)
{
    return PERK_KeccakWidth1600_Sponge(1088, 512, input, inputByteLen, 0x1F, output, outputByteLen);
}

int PERK_SHA3_224(unsigned char *output, const unsigned char *input, size_t inputByteLen)
{
    return PERK_KeccakWidth1600_Sponge(1152, 448, input, inputByteLen, 0x06, output, 224/8);
}

int PERK_SHA3_256(unsigned char *output, const unsigned char *input, size_t inputByteLen)
{
    return PERK_KeccakWidth1600_Sponge(1088, 512, input, inputByteLen, 0x06, output, 256/8);
}

int PERK_SHA3_384(unsigned char *output, const unsigned char *input, size_t inputByteLen)
{
    return PERK_KeccakWidth1600_Sponge( 832, 768, input, inputByteLen, 0x06, output, 384/8);
}

int PERK_SHA3_512(unsigned char *output, const unsigned char *input, size_t inputByteLen)
{
    return PERK_KeccakWidth1600_Sponge(576, 1024, input, inputByteLen, 0x06, output, 512/8);
}
