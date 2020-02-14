/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * The license is detailed in the file LICENSE.md, and applies to this file.
 *
 * The original Rainbow code from
 * https://csrc.nist.gov/CSRC/media/Projects/Post-Quantum-Cryptography/documents/round-2/submissions/Rainbow-Round2.zip
 *
 * is adapted by Nir Drucker and Shay Gueron
 * AWS Cryptographic Algorithms Group.
 * (ndrucker@amazon.com, gueron@amazon.com)
 */

#include <assert.h>
#include <immintrin.h>

#include "gfni.h"
#include "rainbow_config.h"

#define LOAD(in)        (_mm512_loadu_si512((const void *)(in)))
#define STORE(mem, reg) (_mm512_storeu_si512((void *)(mem), reg))
#define GFMUL(a, b)     (_mm512_gf2p8mul_epi8(a, b))
#define SET1(byte)      (_mm512_set1_epi8(byte))
#define CMPZ(a)         (_mm512_cmpeq_epu8_mask(a, _mm512_setzero_si512()))

#define MLOAD(k, in)        (_mm512_maskz_loadu_epi8(k, (const void *)(in)))
#define MSTORE(mem, k, reg) (_mm512_mask_storeu_epi8((void *)(mem), k, reg))
#define MXOR(src, k, a, b)  (_mm512_mask_xor_epi64(src, k, a, b))

#define MATRIX_A     (0xf1f0a6869e3ab4ba)
#define MATRIX_A_INV (0x03349c68700cdea0)
#define MATRIX_I     (0x0102040810204080)

#define ZMM_BYTES       (64)
#define NINE_ELEMS_MASK (0xfffffffff)

_INLINE_ __mmask64 split_to_zmm_regs(OUT size_t *      zmm_num,
                                     IN const uint32_t byte_len)
{

    const size_t rem_byte_len = byte_len & 0x3f;

    *zmm_num = byte_len >> 6;
    return (1ULL << rem_byte_len) - 1;
}

_INLINE_ void convert(OUT uint8_t *out,
                      IN const uint8_t *in,
                      IN const size_t   byte_len,
                      IN const uint64_t A64)
{
    __m512i A = _mm512_set1_epi64(A64);
    size_t  zmm_num;
    __m512i tmp;

    const __mmask64 k = split_to_zmm_regs(&zmm_num, byte_len);

    for(size_t i = 0; i < zmm_num; i++, in += ZMM_BYTES, out += ZMM_BYTES) {
        tmp = LOAD(in);
        tmp = _mm512_gf2p8affine_epi64_epi8(tmp, A, 0);
        STORE(out, tmp);
    }

    tmp = MLOAD(k, (in));
    tmp = _mm512_gf2p8affine_epi64_epi8(tmp, A, 0);
    MSTORE(out, k, tmp);
}

void to_gfni(uint8_t *out, const uint8_t *in, const size_t byte_len)
{
    convert(out, in, byte_len, MATRIX_A);
}

void from_gfni(uint8_t *out, const uint8_t *in, const size_t byte_len)
{
    convert(out, in, byte_len, MATRIX_A_INV);
}

// Calculates accu_b[i] = accu_b[i] ^ a[i] where accu_b and a are two byte_len
// vectors
void gf256_add(IN OUT uint8_t *accu_b,
               IN const uint8_t *a,
               IN const size_t   byte_len)
{
    size_t          zmm_num;
    const __mmask64 k = split_to_zmm_regs(&zmm_num, byte_len);

    for(size_t i = 0; i < zmm_num; i++, a += ZMM_BYTES, accu_b += ZMM_BYTES) {
        STORE(accu_b, LOAD(a) ^ LOAD(accu_b));
    }

    // Handle the tail (less than a full ZMM register)
    MSTORE(accu_b, k, MLOAD(k, a) ^ MLOAD(k, accu_b));
}

// Calculates accu_c[i] = accu_c[i] ^ (a[i] * b) where accu_c and a are two
// byte_len vectors
void gf256_madd(IN OUT uint8_t *accu_c,
                IN const uint8_t *a,
                IN uint8_t        b,
                IN const size_t   byte_len)
{
    size_t          zmm_num;
    const __mmask64 k  = split_to_zmm_regs(&zmm_num, byte_len);
    __m512i         bv = SET1(b);

    for(size_t i = 0; i < zmm_num; i++, a += ZMM_BYTES, accu_c += ZMM_BYTES) {
        STORE(accu_c, LOAD(accu_c) ^ GFMUL(LOAD(a), bv));
    }

    // Tail
    MSTORE(accu_c, k, MLOAD(k, accu_c) ^ GFMUL(MLOAD(k, a), bv));
}

// Calculates a[i] = a[i] * b[i] where a and b are two byte_len vectors
void gf256_mul(IN OUT uint8_t *a, IN const uint8_t b, IN const size_t byte_len)
{
    size_t          zmm_num;
    const __mmask64 k    = split_to_zmm_regs(&zmm_num, byte_len);
    const __m512i   b512 = _mm512_set1_epi8(b);

    for(size_t i = 0; i < zmm_num; i++, a += ZMM_BYTES) {
        STORE(a, GFMUL(LOAD(a), b512));
    }

    // Tail
    MSTORE(a, k, GFMUL(MLOAD(k, a), b512));
}

// Calculates a = a^{-1} in GF(2^8)
uint8_t gf256_inv(IN OUT uint8_t *a)
{
    const __m512i   I = _mm512_set1_epi64(MATRIX_I);
    const __mmask64 k = 1;

    __m512i av = MLOAD(k, a);

    // av = I * (av)^{-1} + 0
    av = _mm512_maskz_gf2p8affineinv_epi64_epi8(k, av, I, 0);
    MSTORE(a, k, av);

    return *a;
}

void gfmat_prod_native(uint8_t *      c,
                       const uint8_t *matA,
                       uint32_t       n_A_vec_byte,
                       uint32_t       n_A_width,
                       const uint8_t *b)
{
    const size_t    num_zmm = n_A_vec_byte >> 6;
    const size_t    zmm_rem = n_A_vec_byte & 0x3f;
    const __mmask64 k       = (1ULL << zmm_rem) - 1;

    memset(c, 0, n_A_vec_byte);
    for(size_t i = 0; i < n_A_width; i++, matA += zmm_rem) {
        uint8_t *c2 = c;
        __m512i  bv = SET1(b[i]);

        for(size_t j = 0; j < num_zmm; j++, matA += ZMM_BYTES, c2 += ZMM_BYTES) {
            STORE(c2, LOAD(c2) ^ GFMUL(LOAD(matA), bv));
        }

        MSTORE(c2, k, MLOAD(k, c2) ^ GFMUL(MLOAD(k, matA), bv));
    }
}

#if(O1 == 36) && (O2 == 36)
#    define ELEMS 36
#else
#    error "The functions below are optimized for O1=O2=36"
#endif

// Returns in |c| the dot product calculations of a matrix |A| with a vector |b|
// The size of A is 36x36 bytes and the size of b is 36 bytes
_INLINE_
void gfmat_prod_36(OUT uint8_t *c, IN const uint8_t *A, IN const uint8_t *b)
{
    const __mmask64 k = NINE_ELEMS_MASK;

    __m512i cv = MLOAD(k, c);

    for(size_t i = 0; i < ELEMS; i++, A += ELEMS) {
        cv ^= GFMUL(MLOAD(k, A), SET1(b[i]));
    }

    MSTORE(c, k, cv);
}

#define ROUNDS (16ULL)

_INLINE_
void gfmat_prod_36_16(OUT uint8_t *c, IN const uint8_t *A, IN const uint8_t *b)
{
    const __mmask64 k = NINE_ELEMS_MASK;
    __m512i         cv[ROUNDS];

    for(size_t j = 0; j < ROUNDS; j++) {
        cv[j] = MLOAD(k, &c[j * O1]);
    }

    for(size_t i = 0; i < O1; i++) {
        const __m512i av = MLOAD(k, &A[i * ELEMS]);
        for(size_t j = 0; j < ROUNDS; j++) {
            cv[j] ^= GFMUL(av, SET1(b[(j * O2) + i]));
        }
    }

    for(size_t j = 0; j < ROUNDS; j++) {
        MSTORE(&c[j * O1], k, cv[j]);
    }
}

void obsfucate_l1_polys(OUT uint8_t *l1_polys,
                        IN const uint8_t *l2_polys,
                        IN uint32_t       n_terms,
                        IN const uint8_t *s1)
{
    while(n_terms > ROUNDS) {
        gfmat_prod_36_16(l1_polys, s1, l2_polys);
        l1_polys += (O1 * ROUNDS);
        l2_polys += (O2 * ROUNDS);
        n_terms -= ROUNDS;
    }

    while(n_terms--) {
        gfmat_prod_36(l1_polys, s1, l2_polys);
        l1_polys += O1;
        l2_polys += O2;
    }
}

void multab_trimat_36(uint8_t *      y,
                      const uint8_t *trimat,
                      const uint8_t *x,
                      uint32_t       dim)
{
    memset(y, 0, ELEMS);
    const __mmask64 k = NINE_ELEMS_MASK;

    for(size_t i = 0; i < dim; i++) {
        __m512i tmp = _mm512_setzero_si512();

        for(size_t j = i; j < dim; j++) {
            tmp = tmp ^ GFMUL(MLOAD(k, trimat), SET1(x[j]));
            trimat += ELEMS;
        }

        MSTORE(y, k, MLOAD(k, y) ^ GFMUL(tmp, SET1(x[i])));
    }
}

#if((O1 == 36) && (O2 == 36))
// Here PUB_M=72, ZMM1 holds 64 bytes and ZMM2 holds 8 bytes (mask=0xff)
#    define ZMM2_BYTES_MASK      (0xffULL)
#    define LOAD_ZMM1(in)        (LOAD(in))
#    define LOAD_ZMM2(in)        (MLOAD(ZMM2_BYTES_MASK, &(in)[64]))
#    define STORE_ZMM1(mem, reg) (STORE(mem, reg))
#    define STORE_ZMM2(mem, reg) (MSTORE(&(mem)[64], ZMM2_BYTES_MASK, reg))

#else
#    error "The functions below are optimized for O1=O2=36"
#endif

#ifdef SPECIAL_PIPELINING
#    define PIPE1 (11ULL)
#    define PIPE2 (5ULL)
#    define PIPE3 (3ULL)
_INLINE_ const uint8_t *mul_line(OUT __m512i out[2],
                                 IN const uint8_t *pk_mat,
                                 IN const uint8_t *w,
                                 IN const size_t   line)
{
    const __m512i zero = _mm512_setzero_si512();
    out[0]             = zero;
    out[1]             = zero;
    size_t j           = line;
    for(; j < (PUB_N - PIPE1); j += PIPE1, pk_mat += PUB_M * PIPE1) {

        __asm__("vpbroadcastb  0(%[W]), %%zmm0\n"
                "vpbroadcastb  1(%[W]), %%zmm1\n"
                "vpbroadcastb  2(%[W]), %%zmm2\n"
                "vpbroadcastb  3(%[W]), %%zmm3\n"
                "vpbroadcastb  4(%[W]), %%zmm4\n"
                "vpbroadcastb  5(%[W]), %%zmm5\n"
                "vpbroadcastb  6(%[W]), %%zmm6\n"
                "vpbroadcastb  7(%[W]), %%zmm7\n"
                "vpbroadcastb  8(%[W]), %%zmm8\n"
                "vpbroadcastb  9(%[W]), %%zmm9\n"
                "vpbroadcastb 10(%[W]), %%zmm10\n"
                "vgf2p8mulb   (72 *  0)(%[PK]), %%zmm0,  %%zmm11\n"
                "vgf2p8mulb   (72 *  1)(%[PK]), %%zmm1,  %%zmm12\n"
                "vgf2p8mulb   (72 *  2)(%[PK]), %%zmm2,  %%zmm13\n"
                "vgf2p8mulb   (72 *  3)(%[PK]), %%zmm3,  %%zmm14\n"
                "vgf2p8mulb   (72 *  4)(%[PK]), %%zmm4,  %%zmm15\n"
                "vgf2p8mulb   (72 *  5)(%[PK]), %%zmm5,  %%zmm16\n"
                "vgf2p8mulb   (72 *  6)(%[PK]), %%zmm6,  %%zmm17\n"
                "vgf2p8mulb   (72 *  7)(%[PK]), %%zmm7,  %%zmm18\n"
                "vgf2p8mulb   (72 *  8)(%[PK]), %%zmm8,  %%zmm19\n"
                "vgf2p8mulb   (72 *  9)(%[PK]), %%zmm9,  %%zmm20\n"
                "vgf2p8mulb   (72 * 10)(%[PK]), %%zmm10, %%zmm21\n"
                "vpxorq       %[T0_IN], %%zmm11,  %%zmm22\n"
                "vpxorq       %%zmm12,  %%zmm13, %%zmm23\n"
                "vpxorq       %%zmm14,  %%zmm15, %%zmm24\n"
                "vpxorq       %%zmm16,  %%zmm17, %%zmm25\n"
                "vpxorq       %%zmm18,  %%zmm19, %%zmm26\n"
                "vpxorq       %%zmm20,  %%zmm21, %%zmm27\n"
                "vpxorq       %%zmm22,  %%zmm23, %%zmm22\n"
                "vpxorq       %%zmm24,  %%zmm25, %%zmm23\n"
                "vpxorq       %%zmm26,  %%zmm27, %%zmm24\n"
                "vpxorq       %%zmm22,  %%zmm23, %%zmm23\n"
                "vpxorq       %%zmm23,  %%zmm24, %[T0]\n"
                "vgf2p8mulb  (72 *  0)+64(%[PK]), %%zmm0,  %%zmm11 %{%[K]}%{z}\n"
                "vgf2p8mulb  (72 *  1)+64(%[PK]), %%zmm1,  %%zmm12 %{%[K]}%{z}\n"
                "vgf2p8mulb  (72 *  2)+64(%[PK]), %%zmm2,  %%zmm13 %{%[K]}%{z}\n"
                "vgf2p8mulb  (72 *  3)+64(%[PK]), %%zmm3,  %%zmm14 %{%[K]}%{z}\n"
                "vgf2p8mulb  (72 *  4)+64(%[PK]), %%zmm4,  %%zmm15 %{%[K]}%{z}\n"
                "vgf2p8mulb  (72 *  5)+64(%[PK]), %%zmm5,  %%zmm16 %{%[K]}%{z}\n"
                "vgf2p8mulb  (72 *  6)+64(%[PK]), %%zmm6,  %%zmm17 %{%[K]}%{z}\n"
                "vgf2p8mulb  (72 *  7)+64(%[PK]), %%zmm7,  %%zmm18 %{%[K]}%{z}\n"
                "vgf2p8mulb  (72 *  8)+64(%[PK]), %%zmm8,  %%zmm19 %{%[K]}%{z}\n"
                "vgf2p8mulb  (72 *  9)+64(%[PK]), %%zmm9,  %%zmm20 %{%[K]}%{z}\n"
                "vgf2p8mulb  (72 * 10)+64(%[PK]), %%zmm10, %%zmm21 %{%[K]}%{z}\n"
                "vpxorq       %[T1_IN], %%zmm11,  %%zmm22\n"
                "vpxorq       %%zmm12,  %%zmm13, %%zmm23\n"
                "vpxorq       %%zmm14,  %%zmm15, %%zmm24\n"
                "vpxorq       %%zmm16,  %%zmm17, %%zmm25\n"
                "vpxorq       %%zmm18,  %%zmm19, %%zmm26\n"
                "vpxorq       %%zmm20,  %%zmm21, %%zmm27\n"
                "vpxorq       %%zmm22,  %%zmm23, %%zmm22\n"
                "vpxorq       %%zmm24,  %%zmm25, %%zmm23\n"
                "vpxorq       %%zmm26,  %%zmm27, %%zmm24\n"
                "vpxorq       %%zmm22,  %%zmm23, %%zmm23\n"
                "vpxorq       %%zmm23,  %%zmm24, %[T1]\n"
                : [T0] "=v"(out[0]), [T1] "=v"(out[1])
                : [W] "r"(&w[j]), [PK] "r"(pk_mat), [K] "Yk"(ZMM2_BYTES_MASK),
                  [T0_IN] "v"(out[0]), [T1_IN] "v"(out[1])

                : "zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7",
                  "zmm8", "zmm9", "zmm10", "zmm11", "zmm12", "zmm13", "zmm14",
                  "zmm15", "zmm16", "zmm17", "zmm18", "zmm19", "zmm20", "zmm21",
                  "zmm22", "zmm23", "zmm24", "zmm25", "zmm26", "zmm27");
    }
    for(; j < (PUB_N - PIPE2); j += PIPE2, pk_mat += PUB_M * PIPE2) {
        __asm__("vpbroadcastb  0(%[W]), %%zmm0\n"
                "vpbroadcastb  1(%[W]), %%zmm1\n"
                "vpbroadcastb  2(%[W]), %%zmm2\n"
                "vpbroadcastb  3(%[W]), %%zmm3\n"
                "vpbroadcastb  4(%[W]), %%zmm4\n"
                "vgf2p8mulb   (72 *  0)(%[PK]), %%zmm0,  %%zmm5\n"
                "vgf2p8mulb   (72 *  1)(%[PK]), %%zmm1,  %%zmm6\n"
                "vgf2p8mulb   (72 *  2)(%[PK]), %%zmm2,  %%zmm7\n"
                "vgf2p8mulb   (72 *  3)(%[PK]), %%zmm3,  %%zmm8\n"
                "vgf2p8mulb   (72 *  4)(%[PK]), %%zmm4,  %%zmm9\n"
                "vpxorq       %[T0_IN], %%zmm5,  %%zmm10\n"
                "vpxorq       %%zmm6,   %%zmm7,  %%zmm11\n"
                "vpxorq       %%zmm8,   %%zmm9,  %%zmm12\n"
                "vpxorq       %%zmm10,  %%zmm11, %%zmm11\n"
                "vpxorq       %%zmm11,  %%zmm12, %[T0]\n"
                "vgf2p8mulb  (72 *  0)+64(%[PK]), %%zmm0,  %%zmm5 %{%[K]}%{z}\n"
                "vgf2p8mulb  (72 *  1)+64(%[PK]), %%zmm1,  %%zmm6 %{%[K]}%{z}\n"
                "vgf2p8mulb  (72 *  2)+64(%[PK]), %%zmm2,  %%zmm7 %{%[K]}%{z}\n"
                "vgf2p8mulb  (72 *  3)+64(%[PK]), %%zmm3,  %%zmm8 %{%[K]}%{z}\n"
                "vgf2p8mulb  (72 *  4)+64(%[PK]), %%zmm4,  %%zmm9 %{%[K]}%{z}\n"
                "vpxorq       %[T1_IN], %%zmm5,  %%zmm10\n"
                "vpxorq       %%zmm6,   %%zmm7,  %%zmm11\n"
                "vpxorq       %%zmm8,   %%zmm9,  %%zmm12\n"
                "vpxorq       %%zmm10,  %%zmm11, %%zmm11\n"
                "vpxorq       %%zmm11,  %%zmm12, %[T1]\n"
                : [T0] "=v"(out[0]), [T1] "=v"(out[1])
                : [W] "r"(&w[j]), [PK] "r"(pk_mat), [K] "Yk"(ZMM2_BYTES_MASK),
                  [T0_IN] "v"(out[0]), [T1_IN] "v"(out[1])

                : "zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7",
                  "zmm8", "zmm9", "zmm10", "zmm11", "zmm12");
    }
    for(; j < (PUB_N - PIPE3); j += PIPE3, pk_mat += PUB_M * PIPE3) {
        __asm__("vpbroadcastb  0(%[W]), %%zmm0\n"
                "vpbroadcastb  1(%[W]), %%zmm1\n"
                "vpbroadcastb  2(%[W]), %%zmm2\n"
                "vgf2p8mulb   (72 *  0)(%[PK]), %%zmm0,  %%zmm3\n"
                "vgf2p8mulb   (72 *  1)(%[PK]), %%zmm1,  %%zmm4\n"
                "vgf2p8mulb   (72 *  2)(%[PK]), %%zmm2,  %%zmm5\n"
                "vpxorq       %[T0_IN], %%zmm3,  %%zmm6\n"
                "vpxorq       %%zmm4,   %%zmm5,  %%zmm7\n"
                "vpxorq       %%zmm6,  %%zmm7, %[T0]\n"
                "vgf2p8mulb  (72 *  0)+64(%[PK]), %%zmm0,  %%zmm3 %{%[K]}%{z}\n"
                "vgf2p8mulb  (72 *  1)+64(%[PK]), %%zmm1,  %%zmm4 %{%[K]}%{z}\n"
                "vgf2p8mulb  (72 *  2)+64(%[PK]), %%zmm2,  %%zmm5 %{%[K]}%{z}\n"
                "vpxorq       %[T1_IN], %%zmm3,  %%zmm6\n"
                "vpxorq       %%zmm4,   %%zmm5,  %%zmm7\n"
                "vpxorq       %%zmm6,  %%zmm7, %[T1]\n"
                : [T0] "=v"(out[0]), [T1] "=v"(out[1])
                : [W] "r"(&w[j]), [PK] "r"(pk_mat), [K] "Yk"(ZMM2_BYTES_MASK),
                  [T0_IN] "v"(out[0]), [T1_IN] "v"(out[1])

                : "zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7");
    }
    for(; j < PUB_N; j++) {
        __m512i b512 = SET1(w[j]);
        __m512i inp0 = LOAD_ZMM1(pk_mat);
        __m512i inp1 = LOAD_ZMM2(pk_mat);

        out[0] ^= GFMUL(inp0, b512);
        out[1] ^= GFMUL(inp1, b512);
        pk_mat += PUB_M;
    }

    return pk_mat;
}

#else  // !SPECIAL_PIPELINING

_INLINE_ const uint8_t *mul_line(OUT __m512i out[2],
                                 IN const uint8_t *pk_mat,
                                 IN const uint8_t *w,
                                 IN const size_t   line)
{
    const __m512i zero = _mm512_setzero_si512();
    out[0]             = zero;
    out[1]             = zero;
    for(size_t j = line; j < PUB_N; j++) {
        __m512i b512 = SET1(w[j]);
        __m512i inp0 = LOAD_ZMM1(pk_mat);
        __m512i inp1 = LOAD_ZMM2(pk_mat);

        out[0] ^= GFMUL(inp0, b512);
        out[1] ^= GFMUL(inp1, b512);
        pk_mat += PUB_M;
    }
    return pk_mat;
}
#endif // SPECIAL_PIPELINING

void mq_gf256_n140_m72(uint8_t *z, const uint8_t *pk_mat, const uint8_t *w)
{
    const __m512i zero = _mm512_setzero_si512();
    __m512i       r0   = zero;
    __m512i       r1   = zero;

    for(size_t i = 0; i < (PUB_N - 1); i++) {
        if(0 == w[i]) {
            pk_mat += PUB_M * (PUB_N - i);
            continue;
        }
        __m512i temp[2];

        pk_mat = mul_line(temp, pk_mat, w, i);

        __m512i b512 = SET1(w[i]);
        r0 ^= GFMUL(temp[0], b512);
        r1 ^= GFMUL(temp[1], b512);
    }

    __m512i b512 = SET1(w[PUB_N - 1]);
    b512         = GFMUL(b512, b512);

    // last column
    __m512i inp0 = LOAD_ZMM1(pk_mat);
    __m512i inp1 = LOAD_ZMM2(pk_mat);

    r0 ^= GFMUL(inp0, b512);
    r1 ^= GFMUL(inp1, b512);

    STORE_ZMM1(z, r0);
    STORE_ZMM2(z, r1);
}

_INLINE_
uint32_t _gf256mat_gauss_elim(uint8_t *mat, uint32_t h, uint32_t w_64, uint32_t w)
{
    uint32_t r8 = 1;

    for(size_t i = 0; i < h; i++) {
        uint8_t *ai     = &mat[w_64 * i];
        __m512i  aiv[2] = {LOAD(ai), LOAD(ai + 64)};

        for(size_t j = i + 1; j < h; j++) {
            __m512i ajv[2] = {LOAD(ai), LOAD(ai + 64)};

            __mmask64 is_madd = CMPZ(aiv[0]) ^ CMPZ(ajv[0]);
            is_madd           = 0 - (!!(is_madd & (1ULL << i)));

            aiv[0] = MXOR(aiv[0], is_madd, ajv[0], aiv[0]);
            aiv[1] = MXOR(aiv[1], is_madd, ajv[1], aiv[1]);
        }

        STORE(ai, aiv[0]);
        STORE(ai + 64, aiv[1]);

        // Check if ai[i] is not zero
        r8 &= !!ai[i];

        uint8_t pivot = ai[i];
        pivot         = gf256_inv(&pivot);

        // Every line has w_64 elements but in fact only w are not redundant
        gf256_mul(ai, pivot, w);

        for(size_t j = 0; j < h; j++) {
            if(i == j) {
                continue;
            }
            uint8_t *aj = &mat[w_64 * j];
            gf256_madd(aj, ai, aj[i], w);
        }
    }

    return r8;
}

_INLINE_
void to_redundant_mat_representation(OUT uint8_t *out,
                                     IN const uint8_t *in,
                                     IN const uint32_t h,
                                     IN const uint32_t w,
                                     IN const uint32_t w_64)
{
    for(size_t i = 0; i < h; i++) {
        memcpy(&out[(i * w_64)], &in[i * w], w);
    }
}

_INLINE_
void from_redundant_mat_representation(OUT uint8_t *out,
                                       IN const uint8_t *in,
                                       IN const uint32_t h,
                                       IN const uint32_t w,
                                       IN const uint32_t w_64)
{
    for(size_t i = 0; i < h; i++) {
        memcpy(&out[i * w], &in[(i * w_64)], w);
    }
}

uint32_t
gf256mat_gauss_elim(IN OUT uint8_t *mat, IN const uint32_t h, IN const uint32_t w)
{
    // This function is optimized for the following parameters
    assert(h < ZMM_BYTES);
    assert((w < (2 * ZMM_BYTES)) && (ZMM_BYTES < w));

    // The size of _mat is 36 * w_64, where here w_64 = 2*ZMM_BYTES
    ALIGN(64) uint8_t _mat[(2 * ZMM_BYTES) * O1];
    const uint32_t    w_64 = ((w + 63) >> 6) << 6;

    to_redundant_mat_representation(_mat, mat, h, w, w_64);

    uint32_t r = _gf256mat_gauss_elim(_mat, h, w_64, w);

    from_redundant_mat_representation(mat, _mat, h, w, w_64);

    return r;
}
