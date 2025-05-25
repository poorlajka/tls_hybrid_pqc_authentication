/**
 * \file rbc_67_elt.c
 * \brief Implementation of rbc_67_elt.h
 */

#include "rbc_67.h"
#include "rbc_67_elt.h"

static uint8_t rbc_67_init_field = 0;
uint64_t RBC_67_SQR_LOOKUP_TABLE[256];



/**
 * \fn void rbc_67_field_init(void)
 * \brief This function initializes various constants used to perform finite field arithmetic.
 *
 */
void rbc_67_field_init(void) {
  uint8_t bit = 0;
  uint64_t mask = 0;

  if(rbc_67_init_field == 0) {
    memset(RBC_67_SQR_LOOKUP_TABLE, 0, 8 * 256);
    for(size_t i = 0 ; i < 256 ; ++i) {
      for(size_t j = 0 ; j < 8 ; ++j) {
        mask = 1 << j;
        bit = (mask & i) >> j;
        RBC_67_SQR_LOOKUP_TABLE[i] ^= bit << (2 * j);
      }
    }

    rbc_67_init_field = 1;
  }
}



/**
 * \fn void rbc_67_elt_set_zero(rbc_67_elt o)
 * \brief This function sets a finite field element to zero.
 *
 * \param[out] o rbc_67_elt
 */
void rbc_67_elt_set_zero(rbc_67_elt o) {
  for(uint8_t i = 0 ; i < RBC_67_ELT_SIZE ; i++) {
    o[i] = 0;
  }
}



/**
 * \fn void rbc_67_elt_set_one(rbc_67_elt o)
 * \brief This function sets a finite field element to one.
 *
 * \param[out] o rbc_67_elt
 */
void rbc_67_elt_set_one(rbc_67_elt o) {
  o[0] = 1;
  for(uint8_t i = 1 ; i < RBC_67_ELT_SIZE ; i++) {
    o[i] = 0;
  }
}



/**
 * \fn void rbc_67_elt_set(rbc_67_elt o, const rbc_67_elt e)
 * \brief This function copies a finite field element into another one.
 *
 * \param[out] o rbc_67_elt
 * \param[in] e rbc_67_elt
 */
void rbc_67_elt_set(rbc_67_elt o, const rbc_67_elt e) {
  for(uint8_t i = 0 ; i < RBC_67_ELT_SIZE ; i++) {
    o[i] = e[i];
  }
}

/**
* \fn void rbc_67_elt_set_mask1(rbc_67_elt o, const rbc_67_elt e1, const rbc_67_elt e2, uint32_t mask)
* \brief This function copies either e1 or e2 into o depending on the mask value
*
* \param[out] o rbc_67_elt
* \param[in] e1 rbc_67_elt
* \param[in] e2 rbc_67_elt_n* \param[in] mask 1 to copy e1 and 0 to copy e2
*/
void rbc_67_elt_set_mask1(rbc_67_elt o, const rbc_67_elt e1, const rbc_67_elt e2, uint32_t mask) {
  for(uint8_t i = 0 ; i < RBC_67_ELT_SIZE ; i++) {
    o[i] = mask * e1[i] + (1 - mask) * e2[i];
  }
}

/**
 * \fn void rbc_67_elt_set_from_uint64(rbc_67_elt o, uint64_t* rbc_67_elt e)
 * \brief This function set a finite field element from a pointer to uint64_t.
 *
 * \param[out] o rbc_67_elt
 * \param[in] e Pointer to uint64_t
 */
void rbc_67_elt_set_from_uint64(rbc_67_elt o, const uint64_t* e) {
  rbc_67_elt_set(o, e);
}

/**
 * \fn uint8_t rbc_67_elt_is_zero(const rbc_67_elt e)
 * \brief This function tests if a finite field element is equal to zero.
 * 
 * \param[in] e rbc_67_elt
 * \return 1 if <b>e</b> is equal to zero, 0 otherwise
 */
uint8_t rbc_67_elt_is_zero(const rbc_67_elt e) {
  int8_t result = 1;
  for(int i = RBC_67_ELT_DATA_SIZE - 1 ; i >= 0 ; i--) {
    result &= (e[i] == 0);
  }

  return result;
}

/**
 * \fn uint8_t rbc_67_elt_is_equal_to(const rbc_67_elt e1, const rbc_67_elt e2)
 * \brief This function tests if two finite field elements are equal.
 *
 * \param[in] e1 rbc_67_elt
 * \param[in] e2 rbc_67_elt
 * \return 1 if <b>e1</b> and <b>e2</b> are equal, 0 otherwise
 */
uint8_t rbc_67_elt_is_equal_to(const rbc_67_elt e1, const rbc_67_elt e2) {
  int8_t result = 1;
  for(uint8_t i = 0 ; i < RBC_67_ELT_DATA_SIZE ; i++) {
    result &= (e1[i] == e2[i]);
  }
 return result;
}

/**
 * \fn int32_t rbc_67_elt_get_degree(const rbc_67_elt e)
 * \brief This function returns the degree of a finite field element.
 *
 * \param[in] e rbc_67_elt
 * \return Degree of <b>e</b> 
 */
int32_t rbc_67_elt_get_degree(const rbc_67_elt e) {
  int64_t index = 0, result = -1;
  int8_t mask = 0;

  for(uint8_t i = 0 ; i < RBC_67_ELT_DATA_SIZE ; i++) {
    __asm__ volatile("bsr %1,%0;" : "=r"(index) : "r"(e[i]));
    mask = (e[i] != 0);
    result = mask * (index + 64 * i) + (1 - mask) * result;
  }

  return result;
}

/**
 * \fn uint8_t rbc_67_elt_get_coefficient(const rbc_67_elt e, uint32_t index)
 * \brief This function returns the coefficient of the polynomial <b>e</b> at a given index.
 *
 * \param[in] e rbc_67_elt
 * \param[in] index Index of the coefficient
 * \return Coefficient of <b>e</b> at the given index
 */
uint8_t rbc_67_elt_get_coefficient(const rbc_67_elt e, uint32_t index) {
  uint64_t w = 0;

  for(uint8_t i = 0 ; i < RBC_67_ELT_DATA_SIZE ; i++) {
    w |= -((i ^ (index >> 6)) == 0) & e[i];
  }

  return (w >> (index & 63)) & 1;
}

/**
 * \fn void rbc_67_elt_set_coefficient_vartime(rbc_67_elt o, uint32_t index, uint64_t bit)
 * \brief This function set a coefficient of the polynomial <b>e</b>.
 *
 * \param[in] e rbc_67_elt
 * \param[in] index Index of the coefficient
 * \param[in] bit Value of the coefficient
 */
void rbc_67_elt_set_coefficient_vartime(rbc_67_elt o, uint32_t index, uint8_t bit) {
  size_t position = index / 64;
  o[position] |= (uint64_t) bit << (index % 64);
}

/**
 * \fn rbc_67_elt_add(rbc_67_elt o, const rbc_67_elt e1, const rbc_67_elt e2)
 * \brief This function adds two finite field elements.
 *
 * \param[out] o Sum of <b>e1</b> and <b>e2</b>
 * \param[in] e1 rbc_67_elt
 * \param[in] e2 rbc_67_elt
 */
void rbc_67_elt_add(rbc_67_elt o, const rbc_67_elt e1, const rbc_67_elt e2) {
  for(uint8_t i = 0 ; i < RBC_67_ELT_SIZE ; i++) {
    o[i] = e1[i] ^ e2[i];
  }
}


/**
 * \fn void rbc_67_elt_mul(rbc_67_elt o, const rbc_67_elt e1, const rbc_67_elt e2)
 * \brief This function multiplies two finite field elements.
 *
 * \param[out] o Product of <b>e1</b> and <b>e2</b>
 * \param[in] e1 rbc_67_elt
 * \param[in] e2 rbc_67_elt
 */
void rbc_67_elt_mul(rbc_67_elt o, const rbc_67_elt e1, const rbc_67_elt e2) {
  rbc_67_elt_ur tmp;
  rbc_67_elt_ur_mul(tmp, e1, e2);
  rbc_67_elt_reduce(o, tmp);
}



/**
 * \fn void rbc_67_elt_sqr(rbc_67_elt o, const rbc_67_elt e)
 * \brief This function computes the square of a finite field element.
 *
 * \param[out] o rbc_67_elt equal to \f$ e^{2} \f$
 * \param[in] e rbc_67_elt
 */
void rbc_67_elt_sqr(rbc_67_elt o, const rbc_67_elt e) {
  /*
  if(rbc_67_init_field == 0) {
    printf("Call to rbc_67_elt_sqr with uninitialized field\n");
    exit(1);
  }
  */

  rbc_67_elt_ur tmp;
  rbc_67_elt_ur_sqr(tmp, e);
  rbc_67_elt_reduce(o, tmp);
}

/**
 * \fn void rbc_67_elt_reduce(rbc_67_elt o, const rbc_67_elt_ur e)
 * \brief This function reduces a finite field element.
 *
 * \param[out] o rbc_67_elt equal to $ e \pmod f $
 * \param[in] e rbc_67_elt
 */
void rbc_67_elt_reduce(rbc_67_elt o, const rbc_67_elt_ur e) {
  uint64_t tmp = (e[1] >> 62) ^ (e[2] << 2);
  o[1] = e[1] ^ tmp ^ (tmp >> 3) ^ (tmp >> 4) ^ (tmp >> 5);

  tmp = (o[1] >> 3) ^ (e[2] << 61);
  o[0] = e[0] ^ tmp ^ (tmp << 1) ^ (tmp << 2) ^ (tmp << 5);

  o[1] &= 0x0000000000000007;
}

/**
 * \fn void rbc_67_elt_print(const rbc_67_elt e)
 * \brief This function displays a finite field element.
 *
 * \param[in] e rbc_67_elt
 */
void rbc_67_elt_print(const rbc_67_elt e) {
  printf("[");
  printf(" %16" PRIx64 " %16" PRIx64 , e[0], e[1]);
  printf(" ]");
}

/**
 * \fn void rbc_67_elt_ur_set(rbc_67_elt_ur o, const rbc_67_elt_ur e)
 * \brief This function copies an unreduced finite field element into another one.
 *
 * \param[out] o rbc_67_elt
 * \param[in] e rbc_67_elt
 */
void rbc_67_elt_ur_set(rbc_67_elt_ur o, const rbc_67_elt_ur e) {
  for(uint8_t i = 0 ; i < RBC_67_ELT_UR_SIZE - 1 ; i++) {
    o[i] = e[i];
  }
  o[RBC_67_ELT_SIZE - 1] = 0;
}

/**
 * \fn void rbc_67_elt_ur_set_zero(rbc_67_elt_ur o)
 * \brief This function sets an unreduced finite field element to zero.
 *
 * \param[out] o rbc_67_elt_ur
 */
void rbc_67_elt_ur_set_zero(rbc_67_elt_ur o) {
  for(uint8_t i = 0 ; i < RBC_67_ELT_UR_SIZE ; i++) {
    o[i] = 0;
  }
}

/**
 * \fn void rbc_67_elt_ur_mul(rbc_67_elt_ur o, const rbc_67_elt e1, const rbc_67_elt e2)
 * \brief This function computes the unreduced multiplication of two finite field elements.
 *
 * \param[out] o rbc_67_elt equal to \f$ e_1 \times e_2 $
 * \param[in] e1 rbc_67_elt
 * \param[in] e2 rbc_67_elt
 */
void rbc_67_elt_ur_mul(rbc_67_elt_ur o, const rbc_67_elt e1, const rbc_67_elt e2) {
  __m128i a = _mm_load_si128((__m128i*) e1);
  __m128i b = _mm_load_si128((__m128i*) e2);

  __m128i a0_b0 = _mm_clmulepi64_si128(a, b, 0x00);

  __m128i a0_b1 = _mm_clmulepi64_si128(a, b, 0x10);
  __m128i a1_b0 = _mm_clmulepi64_si128(a, b, 0x01);

  __m128i a1_b1 = _mm_clmulepi64_si128(a, b, 0x11);

  __m128i c1 = _mm_xor_si128(a0_b1, a1_b0);

  o[0] = _mm_extract_epi64(a0_b0, 0);
  o[1] = _mm_extract_epi64(a0_b0, 1) ^ _mm_extract_epi64(c1, 0);
  o[2] = _mm_extract_epi64(a1_b1, 0) ^ _mm_extract_epi64(c1, 1);
  o[3] = _mm_extract_epi64(a1_b1, 1);
}

/**
 * \fn void rbc_67_elt_ur_sqr(rbc_67_elt o, const rbc_67_elt e)
 * \brief This function computes the unreduced square of a finite field element.
 *
 * \param[out] o rbc_67_elt_ur equal to $ e^{2} $
 * \param[in]  e rbc_67_elt
*/
void rbc_67_elt_ur_sqr(rbc_67_elt_ur o, const rbc_67_elt e) {
  __m128i tmp1, e_l, e_h;
  __m128i tmp2[2];

  tmp1 = _mm_load_si128((__m128i*) e);
  e_l = _mm_and_si128(tmp1, RBC_67_ELT_SQR_MASK_128);
  e_h = _mm_and_si128(_mm_srli_epi64(tmp1, 4), RBC_67_ELT_SQR_MASK_128);

  e_l = _mm_shuffle_epi8(RBC_67_ELT_SQR_LOOKUP_TABLE_128, e_l);
  e_h = _mm_shuffle_epi8(RBC_67_ELT_SQR_LOOKUP_TABLE_128, e_h);

  tmp2[0] = _mm_unpacklo_epi8(e_l, e_h);
  tmp2[1] = _mm_unpackhi_epi8(e_l, e_h);

  _mm_store_si128((__m128i*) o, tmp2[0]);
  _mm_store_si128((__m128i*) (o + 2), tmp2[1]);}




/**
 * \fn void rbc_67_elt_to_string(uint8_t* str, const rbc_67_elt e)
 * \brief This function parses a finite field element into a string.
 *
 * \param[out] str Output string
 * \param[in] e rbc_67_elt
 */
void rbc_67_elt_to_string(uint8_t* str, const rbc_67_elt e) {
  uint32_t bytes1 = RBC_67_FIELD_M / 8;
  uint32_t bytes2 = RBC_67_FIELD_M % 8;

  memset(str, 0, RBC_67_ELT_UINT8_SIZE);
  memcpy(str, e, bytes1);

  uint8_t k = 0;
  for(size_t j = 1 ; j <= bytes2 ; j++) {
    uint8_t bit = rbc_67_elt_get_coefficient(e, RBC_67_FIELD_M - j);
    *(str + bytes1) |= (bit << k % 8);
    k++;
    if(k % 8 == 0) bytes1++;
  }
}

