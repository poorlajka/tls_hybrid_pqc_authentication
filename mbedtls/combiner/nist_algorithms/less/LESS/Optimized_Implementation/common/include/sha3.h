/**
 *
 * Reference ISO-C11 Implementation of LESS.
 *
 * @version 1.1 (March 2023)
 *
 * @author Alessandro Barenghi <alessandro.barenghi@polimi.it>
 * @author Gerardo Pelosi <gerardo.pelosi@polimi.it>
 *
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 **/

#pragma once

#if defined(SHA_3_LIBKECCAK)
#include <libkeccak.a.headers/KeccakHash.h>

// %%%%%%%%%%%%%%%%%% LibKeccak SHAKE Wrappers %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

#define SHAKE_STATE_STRUCT Keccak_HashInstance
static inline
void xof_shake_init(SHAKE_STATE_STRUCT *state, int val)
{
	(void)val;
   if (val == 128)
      /* will result in a zero-length output for Keccak_HashFinal */
      Keccak_HashInitialize_SHAKE128(state);
   else
      /* will result in a zero-length output for Keccak_HashFinal */
      Keccak_HashInitialize_SHAKE256(state);
}

static inline
void xof_shake_update(SHAKE_STATE_STRUCT *state,
                      const unsigned char *input,
                      unsigned int inputByteLen)
{
   Keccak_HashUpdate(state,
                     (const BitSequence *) input,
                     (BitLength) inputByteLen*8 );
}

static inline
void xof_shake_final(SHAKE_STATE_STRUCT *state)
{
   Keccak_HashFinal(state, NULL);
}

static inline
void xof_shake_extract(SHAKE_STATE_STRUCT *state,
                       unsigned char *output,
                       unsigned int outputByteLen)
{
   Keccak_HashSqueeze(state,
                      (BitSequence *) output,
                      (BitLength) outputByteLen*8 );
}

// %%%%%%%%%%%%%%%%%% LibKeccak SHA-3 Wrappers %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

#define SHA3_STATE_STRUCT Keccak_HashInstance
static inline
void sha3_256(unsigned char *output,
              const unsigned char *input,
              unsigned int inputByteLen)
{
   SHA3_STATE_STRUCT state;
   Keccak_HashInitialize(&state, 1088,  512, 256, 0x06);
   Keccak_HashUpdate(&state, input, inputByteLen*8);
   Keccak_HashFinal(&state, output);
}

/**
  *  Function to compute SHA3-384 on the input message.
  *  The output length is fixed to 48 bytes.
  */
static inline
void sha3_384(unsigned char *output,
              const unsigned char *input,
              unsigned int inputByteLen)
{
   SHA3_STATE_STRUCT state;
   Keccak_HashInitialize(&state, 832,  768, 384, 0x06);
   Keccak_HashUpdate(&state, input, inputByteLen*8);
   Keccak_HashFinal(&state, output);
}

/**
  *  Function to compute SHA3-512 on the input message.
  *  The output length is fixed to 64 bytes.
  */
static inline
void sha3_512(unsigned char *output,
              const unsigned char *input,
              unsigned int inputByteLen)
{
   SHA3_STATE_STRUCT state;
   Keccak_HashInitialize(&state, 576,  1024, 512, 0x06);
   Keccak_HashUpdate(&state, input, inputByteLen*8);
   Keccak_HashFinal(&state, output);
}

#else
#include "fips202.h"

/* standalone SHA-3 implementation has no visible state for single-call SHA-3 */
// #define SHA3_STATE_STRUCT shake256ctx
/* and has different states for SHAKE depending on security level*/
#if CATEGORY == 252
#define SHAKE_STATE_STRUCT shake128incctx
#else
#define SHAKE_STATE_STRUCT shake256incctx
#endif
// %%%%%%%%%%%%%%%%%% Self-contained SHAKE Wrappers %%%%%%%%%%%%%%%%%%%%%%%%%%%%

static inline
void xof_shake_init(SHAKE_STATE_STRUCT *state, int val) {
	(void)val;
#if CATEGORY == 252
   shake128_inc_init(state);
#else
   shake256_inc_init(state);
#endif
}

static inline
void xof_shake_update(SHAKE_STATE_STRUCT *state,
                      const unsigned char *input,
                      unsigned int inputByteLen) {
#if CATEGORY == 252
   shake128_inc_absorb(state,
                       (const uint8_t *)input,
                       inputByteLen);
#else
   shake256_inc_absorb(state,
                       (const uint8_t *)input,
                       inputByteLen);
#endif
}

static inline
void xof_shake_final(SHAKE_STATE_STRUCT *state) {
#if CATEGORY == 252
   shake128_inc_finalize(state);
#else
   shake256_inc_finalize(state);
#endif
}

static inline
void xof_shake_extract(SHAKE_STATE_STRUCT *state,
                       unsigned char *output,
                       unsigned int outputByteLen) {
#if CATEGORY == 252
   shake128_inc_squeeze(output, outputByteLen, state);
#else
   shake256_inc_squeeze(output, outputByteLen, state);
#endif
}


// This abstract away the SHA3 interface.
#if (HASH_DIGEST_LENGTH*8 == 256)
#define LESS_SHA3_INC_CTX                     sha3_256incctx
#define LESS_SHA3_INC_INIT(state)             sha3_256_inc_init(state)
#define LESS_SHA3_INC_ABSORB(state, ptr, len) sha3_256_inc_absorb(state, ptr, len)
#define LESS_SHA3_INC_FINALIZE(output, state) sha3_256_inc_finalize(output, state)
#elif (HASH_DIGEST_LENGTH*8 == 384)
#define LESS_SHA3_INC_CTX                     sha3_384incctx
#define LESS_SHA3_INC_INIT(state)             sha3_384_inc_init(state)
#define LESS_SHA3_INC_ABSORB(state, ptr, len) sha3_384_inc_absorb(state, ptr, len)
#define LESS_SHA3_INC_FINALIZE(output, state) sha3_384_inc_finalize(output, state)
#elif (HASH_DIGEST_LENGTH*8 == 512)
#define LESS_SHA3_INC_CTX                     sha3_512incctx
#define LESS_SHA3_INC_INIT(state)             sha3_512_inc_init(state)
#define LESS_SHA3_INC_ABSORB(state, ptr, len) sha3_512_inc_absorb(state, ptr, len)
#define LESS_SHA3_INC_FINALIZE(output, state) sha3_512_inc_finalize(output, state)
#else
#error digest length unsupported by SHA-3
#endif


#endif
