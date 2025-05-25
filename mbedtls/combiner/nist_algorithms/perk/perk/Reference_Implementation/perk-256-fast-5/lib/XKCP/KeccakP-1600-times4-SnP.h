/*
The Keccak-p permutations, designed by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche.

Implementation by Gilles Van Assche, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/

---

Please refer to PlSnP-documentation.h for more details.
*/

#ifndef _KeccakP_1600_times4_SnP_h_
#define _KeccakP_1600_times4_SnP_h_

#include "KeccakP-1600-SnP.h"

#define PERK_KeccakP1600times4_implementation        "fallback on serial implementation (" PERK_KeccakP1600_implementation ")"
#define PERK_KeccakP1600times4_statesSizeInBytes     (((PERK_KeccakP1600_stateSizeInBytes+(PERK_KeccakP1600_stateAlignment-1))/PERK_KeccakP1600_stateAlignment)*PERK_KeccakP1600_stateAlignment*4)
#define PERK_KeccakP1600times4_statesAlignment       PERK_KeccakP1600_stateAlignment
#define PERK_KeccakP1600times4_isFallback

void PERK_KeccakP1600times4_StaticInitialize( void );
void PERK_KeccakP1600times4_InitializeAll(void *states);
void PERK_KeccakP1600times4_AddByte(void *states, unsigned int instanceIndex, unsigned char data, unsigned int offset);
void PERK_KeccakP1600times4_AddBytes(void *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length);
void PERK_KeccakP1600times4_AddLanesAll(void *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
void PERK_KeccakP1600times4_OverwriteBytes(void *states, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length);
void PERK_KeccakP1600times4_OverwriteLanesAll(void *states, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
void PERK_KeccakP1600times4_OverwriteWithZeroes(void *states, unsigned int instanceIndex, unsigned int byteCount);
void PERK_KeccakP1600times4_PermuteAll_4rounds(void *states);
void PERK_KeccakP1600times4_PermuteAll_6rounds(void *states);
void PERK_KeccakP1600times4_PermuteAll_12rounds(void *states);
void PERK_KeccakP1600times4_PermuteAll_24rounds(void *states);
void PERK_KeccakP1600times4_ExtractBytes(const void *states, unsigned int instanceIndex, unsigned char *data, unsigned int offset, unsigned int length);
void PERK_KeccakP1600times4_ExtractLanesAll(const void *states, unsigned char *data, unsigned int laneCount, unsigned int laneOffset);
void PERK_KeccakP1600times4_ExtractAndAddBytes(const void *states, unsigned int instanceIndex,  const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length);
void PERK_KeccakP1600times4_ExtractAndAddLanesAll(const void *states, const unsigned char *input, unsigned char *output, unsigned int laneCount, unsigned int laneOffset);

#endif
