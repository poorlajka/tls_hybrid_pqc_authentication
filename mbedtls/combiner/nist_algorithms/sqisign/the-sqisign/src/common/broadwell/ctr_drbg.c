/* Copyright (c) 2017, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

/***************************************************************************
 * Small modification by Nir Drucker and Shay Gueron
 * AWS Cryptographic Algorithms Group
 * (ndrucker@amazon.com, gueron@amazon.com)
 * include:
 * 1) Use memcpy/memset instead of OPENSSL_memcpy/memset
 * 2) Include aes.h as the underlying aes code
 * 3) Modifying the drbg structure
 * ***************************************************************************/

#include "ctr_drbg.h"
#include <string.h>


// Section references in this file refer to SP 800-90Ar1:
// http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf

int CTR_DRBG_init(CTR_DRBG_STATE *drbg,
                  const uint8_t entropy[CTR_DRBG_ENTROPY_LEN],
                  const uint8_t *personalization, size_t personalization_len) {
  // Section 10.2.1.3.1
  if (personalization_len > CTR_DRBG_ENTROPY_LEN) {
    return 0;
  }

  uint8_t seed_material[CTR_DRBG_ENTROPY_LEN];
  memcpy(seed_material, entropy, CTR_DRBG_ENTROPY_LEN);

  for (size_t i = 0; i < personalization_len; i++) {
    seed_material[i] ^= personalization[i];
  }

  // Section 10.2.1.2
  // kInitMask is the result of encrypting blocks with big-endian value 1, 2
  // and 3 with the all-zero AES-256 key.
  static const uint8_t kInitMask[CTR_DRBG_ENTROPY_LEN] = {
      0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1,
      0xc4, 0xcb, 0x73, 0x8b, 0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
      0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18, 0x72, 0x60, 0x03, 0xca,
      0x37, 0xa6, 0x2a, 0x74, 0xd1, 0xa2, 0xf5, 0x8e, 0x75, 0x06, 0x35, 0x8e,
  };

  for (size_t i = 0; i < sizeof(kInitMask); i++) {
    seed_material[i] ^= kInitMask[i];
  }

  aes256_key_t key;
  memcpy(key.raw, seed_material, 32);
  memcpy(drbg->counter.bytes, seed_material + 32, 16);

  aes256_key_expansion(&drbg->ks, &key);
  drbg->reseed_counter = 1;

  return 1;
}

// ctr_inc adds |n| to the last four bytes of |drbg->counter|, treated as a
// big-endian number.
static void ctr32_add(CTR_DRBG_STATE *drbg, uint32_t n) {
  drbg->counter.words[3] =
      CRYPTO_bswap4(CRYPTO_bswap4(drbg->counter.words[3]) + n);
}

static int ctr_drbg_update(CTR_DRBG_STATE *drbg, const uint8_t *data,
                           size_t data_len) {
  // Per section 10.2.1.2, |data_len| must be |CTR_DRBG_ENTROPY_LEN|. Here, we
  // allow shorter inputs and right-pad them with zeros. This is equivalent to
  // the specified algorithm but saves a copy in |CTR_DRBG_generate|.
  if (data_len > CTR_DRBG_ENTROPY_LEN) {
    return 0;
  }

  uint8_t temp[CTR_DRBG_ENTROPY_LEN];
  for (size_t i = 0; i < CTR_DRBG_ENTROPY_LEN; i += AES_BLOCK_SIZE) {
    ctr32_add(drbg, 1);
    aes256_enc(temp + i, drbg->counter.bytes, &drbg->ks);
  }

  for (size_t i = 0; i < data_len; i++) {
    temp[i] ^= data[i];
  }

  aes256_key_t key;
  memcpy(key.raw, temp, 32);
  memcpy(drbg->counter.bytes, temp + 32, 16);
  aes256_key_expansion(&drbg->ks, &key);

  return 1;
}

int CTR_DRBG_reseed(CTR_DRBG_STATE *drbg,
                    const uint8_t entropy[CTR_DRBG_ENTROPY_LEN],
                    const uint8_t *additional_data,
                    size_t additional_data_len) {
  // Section 10.2.1.4
  uint8_t entropy_copy[CTR_DRBG_ENTROPY_LEN];

  if (additional_data_len > 0) {
    if (additional_data_len > CTR_DRBG_ENTROPY_LEN) {
      return 0;
    }

    memcpy(entropy_copy, entropy, CTR_DRBG_ENTROPY_LEN);
    for (size_t i = 0; i < additional_data_len; i++) {
      entropy_copy[i] ^= additional_data[i];
    }

    entropy = entropy_copy;
  }

  if (!ctr_drbg_update(drbg, entropy, CTR_DRBG_ENTROPY_LEN)) {
    return 0;
  }

  drbg->reseed_counter = 1;

  return 1;
}

int CTR_DRBG_generate(CTR_DRBG_STATE *drbg, uint8_t *out, size_t out_len,
                      const uint8_t *additional_data,
                      size_t additional_data_len) {
  if (additional_data_len != 0 &&
      !ctr_drbg_update(drbg, additional_data, additional_data_len)) {
    return 0;
  }

  // kChunkSize is used to interact better with the cache. Since the AES-CTR
  // code assumes that it's encrypting rather than just writing keystream, the
  // buffer has to be zeroed first. Without chunking, large reads would zero
  // the whole buffer, flushing the L1 cache, and then do another pass (missing
  // the cache every time) to “encrypt” it. The code can avoid this by
  // chunking.
  static const size_t kChunkSize = 8 * 1024;

  while (out_len >= AES_BLOCK_SIZE) {
    size_t todo = kChunkSize;
    if (todo > out_len) {
      todo = out_len;
    }

    todo &= ~(AES_BLOCK_SIZE - 1);

    const size_t num_blocks = todo / AES_BLOCK_SIZE;
    if (1) {
      memset(out, 0, todo);
      ctr32_add(drbg, 1);
#ifdef VAES512
      aes256_ctr_enc512(out, drbg->counter.bytes, num_blocks, &drbg->ks);
#elif defined(VAES256)
      aes256_ctr_enc256(out, drbg->counter.bytes, num_blocks, &drbg->ks);
#else
      aes256_ctr_enc(out, drbg->counter.bytes, num_blocks, &drbg->ks);
#endif
      ctr32_add(drbg, num_blocks - 1);
    } else {
      for (size_t i = 0; i < todo; i += AES_BLOCK_SIZE) {
        ctr32_add(drbg, 1);
        aes256_enc(&out[i], drbg->counter.bytes, &drbg->ks);
      }
    }

    out += todo;
    out_len -= todo;
  }

  if (out_len > 0) {
    uint8_t block[AES_BLOCK_SIZE];
    ctr32_add(drbg, 1);
    aes256_enc(block, drbg->counter.bytes, &drbg->ks);

    memcpy(out, block, out_len);
  }

  // Right-padding |additional_data| in step 2.2 is handled implicitly by
  // |ctr_drbg_update|, to save a copy.
  if (!ctr_drbg_update(drbg, additional_data, additional_data_len)) {
    return 0;
  }

  drbg->reseed_counter++;
  return 1;
}

void CTR_DRBG_clear(CTR_DRBG_STATE *drbg) {
  secure_clean((uint8_t *)drbg, sizeof(CTR_DRBG_STATE));
}
