/*
Implementation by the Keccak Team, namely, Guido Bertoni, Joan Daemen,
Michaël Peeters, Gilles Van Assche and Ronny Van Keer,
hereby denoted as "the implementer".

For more information, feedback or questions, please refer to our website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#include <string.h>
#include "KeccakHashtimes4.h"

#if defined(SUPERCOP)
#define KECCAK_FAIL FAIL
#define KECCAK_SUCCESS SUCCESS
#endif

/* ---------------------------------------------------------------- */

HashReturn PERK_Keccak_HashInitializetimes4(PERK_Keccak_HashInstancetimes4 *instance, unsigned int rate, unsigned int capacity, unsigned int hashbitlen, unsigned char delimitedSuffix)
{
    HashReturn result;

    if (delimitedSuffix == 0)
        return KECCAK_FAIL;
    result = (HashReturn)PERK_KeccakWidth1600times4_SpongeInitialize(&instance->sponge, rate, capacity);
    if (result != KECCAK_SUCCESS)
        return result;
    instance->fixedOutputLength = hashbitlen;
    instance->delimitedSuffix = delimitedSuffix;
    return KECCAK_SUCCESS;
}

/* ---------------------------------------------------------------- */

HashReturn PERK_Keccak_HashUpdatetimes4(PERK_Keccak_HashInstancetimes4 *instance, const BitSequence **data, BitLength databitlen)
{
    if ((databitlen % 8) != 0)
        return KECCAK_FAIL;
    return (HashReturn)PERK_KeccakWidth1600times4_SpongeAbsorb(&instance->sponge, data, databitlen/8);
}

/* ---------------------------------------------------------------- */

HashReturn PERK_Keccak_HashFinaltimes4(PERK_Keccak_HashInstancetimes4 *instance, BitSequence **hashval)
{
    HashReturn ret = (HashReturn)PERK_KeccakWidth1600times4_SpongeAbsorbLastFewBits(&instance->sponge, instance->delimitedSuffix);
    if (ret == KECCAK_SUCCESS)
        return (HashReturn)PERK_KeccakWidth1600times4_SpongeSqueeze(&instance->sponge, hashval, instance->fixedOutputLength/8);
    else
        return ret;
}

/* ---------------------------------------------------------------- */

HashReturn PERK_Keccak_HashSqueezetimes4(PERK_Keccak_HashInstancetimes4 *instance, BitSequence **data, BitLength databitlen)
{
    if ((databitlen % 8) != 0)
        return KECCAK_FAIL;
    return (HashReturn)PERK_KeccakWidth1600times4_SpongeSqueeze(&instance->sponge, data, databitlen/8);
}
