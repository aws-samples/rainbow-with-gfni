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

#include <immintrin.h>
#include <stdlib.h>

#include "gfni.h"
#include "keypair_computation.h"

// Calculate the corresponding index in an array for an upper-triangle(UT)
// matrix.
_INLINE_ uint32_t idx_of_trimat(IN const uint32_t i_row,
                                IN const uint32_t j_col,
                                IN const uint32_t dim)
{
    return (dim + dim - i_row + 1) * i_row / 2 + j_col - i_row;
}

_INLINE_
void convert_type1(OUT pk_t *pk,
                   IN const uint8_t *idx_l1,
                   IN const uint8_t *idx_l2,
                   IN const size_t   outer_from,
                   IN const size_t   outer_to,
                   IN const size_t   inner_from,
                   IN const size_t   inner_to)
{
    for(uint32_t i = outer_from; i < outer_to; i++) {
        for(uint32_t j = inner_from; j < inner_to; j++) {
            uint32_t pub_idx = idx_of_trimat(i, j, PUB_N);
            memcpy(&pk->pk[PUB_M * pub_idx], idx_l1, O1);
            memcpy((&pk->pk[PUB_M * pub_idx]) + O1, idx_l2, O2);
            idx_l1 += O1;
            idx_l2 += O2;
        }
    }
}

_INLINE_
void convert_type2(OUT pk_t *pk,
                   IN const uint8_t *idx_l1,
                   IN const uint8_t *idx_l2,
                   IN const size_t   outer_from,
                   IN const size_t   to)
{
    for(uint32_t i = outer_from; i < to; i++) {
        for(uint32_t j = i; j < to; j++) {
            uint32_t pub_idx = idx_of_trimat(i, j, PUB_N);
            memcpy(&pk->pk[PUB_M * pub_idx], idx_l1, O1);
            memcpy((&pk->pk[PUB_M * pub_idx]) + O1, idx_l2, O2);
            idx_l1 += O1;
            idx_l2 += O2;
        }
    }
}

void extcpk_to_pk(OUT pk_t *pk, IN const ext_cpk_t *cpk)
{
    convert_type1(pk, cpk->l1_Q2, cpk->l2_Q2, 0, V1, V1, V1 + O1);
    convert_type1(pk, cpk->l1_Q3, cpk->l2_Q3, 0, V1, V1 + O1, PUB_N);
    convert_type1(pk, cpk->l1_Q6, cpk->l2_Q6, V1, V1 + O1, V1 + O1, PUB_N);

    convert_type2(pk, cpk->l1_Q1, cpk->l2_Q1, 0, V1);
    convert_type2(pk, cpk->l1_Q5, cpk->l2_Q5, V1, V1 + O1);
    convert_type2(pk, cpk->l1_Q9, cpk->l2_Q9, V1 + O1, PUB_N);
}

_INLINE_
void UpperTrianglize(uint8_t *      btriC,
                     const uint8_t *bA,
                     uint32_t       Awidth,
                     size_t         size_batch)
{
    uint8_t *runningC = btriC;
    uint32_t Aheight  = Awidth;
    for(uint32_t i = 0; i < Aheight; i++) {
        for(uint32_t j = 0; j < i; j++) {
            uint32_t idx = idx_of_trimat(j, i, Aheight);
            gf256_add(btriC + idx * size_batch,
                      bA + size_batch * (i * Awidth + j), size_batch);
        }
        gf256_add(runningC, bA + size_batch * (i * Awidth + i),
                  size_batch * (Aheight - i));
        runningC += size_batch * (Aheight - i);
    }
}

_INLINE_
void madd_upto_512(uint8_t *accu_c, const uint8_t *a, uint8_t b, size_t byte_len)
{
    const __mmask64 k0 = (1ULL << byte_len) - 1;
    const __m512i   bv = _mm512_set1_epi8(b);
    const __m512i   av = _mm512_maskz_loadu_epi8(k0, &a[0]);
    __m512i         cv = _mm512_maskz_loadu_epi8(k0, &accu_c[0]);

    cv ^= _mm512_gf2p8mul_epi8(av, bv);
    _mm512_mask_storeu_epi8(&accu_c[0], k0, cv);
}

void madd_matTr(uint8_t *      bC,
                const uint8_t *A_to_tr,
                uint32_t       Aheight,
                uint32_t       size_Acolvec,
                uint32_t       Awidth,
                const uint8_t *bB,
                uint32_t       Bwidth,
                size_t         size_batch)
{
    uint32_t Atr_height = Awidth;
    uint32_t Atr_width  = Aheight;
    for(uint32_t i = 0; i < Atr_height; i++) {
        for(uint32_t j = 0; j < Atr_width; j++) {
            gf256_madd(bC, &bB[j * Bwidth * size_batch],
                       (&A_to_tr[size_Acolvec * i])[j], size_batch * Bwidth);
        }
        bC += size_batch * Bwidth;
    }
}

_INLINE_
void madd_trimat(uint8_t *      bC,
                 const uint8_t *btriA,
                 const uint8_t *B,
                 uint32_t       Bheight,
                 uint32_t       size_Bcolvec,
                 uint32_t       Bwidth,
                 size_t         size_batch)
{
    uint32_t Awidth  = Bheight;
    uint32_t Aheight = Awidth;
    for(uint32_t i = 0; i < Aheight; i++) {
        for(uint32_t j = 0; j < Bwidth; j++) {
            for(uint32_t k = 0; k < Bheight; k++) {
                if(k < i) {
                    continue;
                }
                madd_upto_512(bC, &btriA[(k - i) * size_batch],
                              (&B[j * size_Bcolvec])[k], size_batch);
            }
            bC += size_batch;
        }
        btriA += (Aheight - i) * size_batch;
    }
}
void madd_trimatTr(uint8_t *      bC,
                   const uint8_t *btriA,
                   const uint8_t *B,
                   uint32_t       Bheight,
                   uint32_t       size_Bcolvec,
                   uint32_t       Bwidth,
                   size_t         size_batch)
{
    uint32_t Aheight = Bheight;
    for(uint32_t i = 0; i < Aheight; i++) {
        for(uint32_t j = 0; j < Bwidth; j++) {
            for(uint32_t k = 0; k < Bheight; k++) {
                if(i < k) {
                    continue;
                }
                gf256_madd(bC,
                           &btriA[size_batch * (idx_of_trimat(k, i, Aheight))],
                           (&B[j * size_Bcolvec])[k], size_batch);
            }
            bC += size_batch;
        }
    }
}

void madd_mat(uint8_t *      bC,
              const uint8_t *bA,
              uint32_t       Aheight,
              const uint8_t *B,
              uint32_t       Bheight,
              uint32_t       size_Bcolvec,
              uint32_t       Bwidth,
              size_t         size_batch)
{
    uint32_t Awidth = Bheight;
    for(uint32_t i = 0; i < Aheight; i++) {
        for(uint32_t j = 0; j < Bwidth; j++) {
            for(uint32_t k = 0; k < Bheight; k++) {
                gf256_madd(bC, &bA[k * size_batch], (&B[j * size_Bcolvec])[k],
                           size_batch);
            }
            bC += size_batch;
        }
        bA += (Awidth)*size_batch;
    }
}

void madd_bmatTr(uint8_t *      bC,
                 const uint8_t *bA_to_tr,
                 uint32_t       Awidth_before_tr,
                 const uint8_t *B,
                 uint32_t       Bheight,
                 uint32_t       size_Bcolvec,
                 uint32_t       Bwidth,
                 size_t         size_batch)
{
    const uint8_t *bA      = bA_to_tr;
    uint32_t       Aheight = Awidth_before_tr;
    for(uint32_t i = 0; i < Aheight; i++) {
        for(uint32_t j = 0; j < Bwidth; j++) {
            for(uint32_t k = 0; k < Bheight; k++) {
                gf256_madd(bC, &bA[size_batch * (i + k * Aheight)],
                           (&B[j * size_Bcolvec])[k], size_batch);
            }
            bC += size_batch;
        }
    }
}

#if O1 == O2
#    define TEMP_SIZE (O1 * O1 * O1)
#else
#    define MAX(a, b) ((a > b) ? a : b)
#    define TEMP_SIZE                                                            \
        (MAX(O1 * O1 * O1, MAX(O2 * O1 * O1, MAX(O2 * O2 * O1, O2 * O2 * O2))) + \
         32)
#endif

void calc_pk(OUT ext_cpk_t *epk, IN const sk_t *sk)
{
    uint8_t tempQ[TEMP_SIZE] = {0};

    // Layer 1
    memcpy(epk->l1_Q1, sk->l1_F1, L1_F1_BYTE_LEN);
    memcpy(epk->l1_Q2, sk->l1_F2, L1_F2_BYTE_LEN);
    memset(epk->l1_Q3, 0, L1_Q3_BYTE_LEN);
    memset(epk->l1_Q5, 0, L1_Q5_BYTE_LEN);
    memset(epk->l1_Q6, 0, L1_Q6_BYTE_LEN);
    memset(epk->l1_Q9, 0, L1_Q9_BYTE_LEN);

    // 1) Q2    = (F1 * T1) + F2
    // 2) tempQ = T1' * Q2 = T1' + (F1 * T1 + F2)
    // 3) Q2    = (F1' * T1) + Q2 = (F1' * T1) + ((F1 * T1) + F2)
    // 4) Q5    = UT(T1' * (F1 * T1 + F2))
    madd_trimat(epk->l1_Q2, sk->l1_F1, sk->t1, V1, V1, O1, O1);
    madd_matTr(tempQ, sk->t1, V1, V1, O1, epk->l1_Q2, O1, O1);
    madd_trimatTr(epk->l1_Q2, sk->l1_F1, sk->t1, V1, V1, O1, O1);
    UpperTrianglize(epk->l1_Q5, tempQ, O1, O1);

    // 5) Q3 = F1 * T2 = F1 * T4
    // 6) Q3 = (F1 * T2) + (F2 * T3)
    // 7) Q9 = T2' * Q3 = UT(T2' * ( F1 * T2 + F2 * T3 ))
    // 8) Q3 = F1' * T2 + Q3 = (F1' * T2) + (F1 * T2) + (F2 * T3)
    // 9) Q6 = (T1 * Q3) + F2' * T2
    madd_trimat(epk->l1_Q3, sk->l1_F1, sk->t4, V1, V1, O2, O1);
    madd_mat(epk->l1_Q3, sk->l1_F2, V1, sk->t3, O1, O1, O2, O1);
    memset(tempQ, 0, O1 * O2 * O2);
    madd_matTr(tempQ, sk->t4, V1, V1, O2, epk->l1_Q3, O2, O1);
    UpperTrianglize(epk->l1_Q9, tempQ, O2, O1);
    madd_trimatTr(epk->l1_Q3, sk->l1_F1, sk->t4, V1, V1, O2, O1);
    madd_bmatTr(epk->l1_Q6, sk->l1_F2, O1, sk->t4, V1, V1, O2, O1);
    madd_matTr(epk->l1_Q6, sk->t1, V1, V1, O1, epk->l1_Q3, O2, O1);

    // Layer 2

    memset(tempQ, 0, O2 * O1 * O1);
    memcpy(epk->l2_Q1, sk->l2_F1, L2_Q1_BYTE_LEN);
    memcpy(epk->l2_Q2, sk->l2_F2, L2_Q2_BYTE_LEN);
    memcpy(epk->l2_Q3, sk->l2_F3, L2_Q3_BYTE_LEN);
    memcpy(epk->l2_Q5, sk->l2_F5, L2_Q5_BYTE_LEN);
    memcpy(epk->l2_Q6, sk->l2_F6, L2_Q6_BYTE_LEN);
    memset(epk->l2_Q9, 0, L2_Q9_BYTE_LEN);

    // 1) Q2 = (F1 * T1) + F2
    // 2) tempQ = T1' * ((F1 * T1) + F2)
    // 3) Q5 = UT(tempQ) = UT(T1' * ((F1 * T1) + F2))
    // 4) Q2 = Q2 + F1*T1 = (F1 * T1) + F2 + F1*T1
    madd_trimat(epk->l2_Q2, sk->l2_F1, sk->t1, V1, V1, O1, O2);
    madd_matTr(tempQ, sk->t1, V1, V1, O1, epk->l2_Q2, O1, O2);
    UpperTrianglize(epk->l2_Q5, tempQ, O1, O2);
    madd_trimatTr(epk->l2_Q2, sk->l2_F1, sk->t1, V1, V1, O1, O2);

    // 5) Q3 = (F1 * T4) + F3
    // 6) Q3 = Q3 + (F2 * T3) = (F1 * T4) + (F2 * T3) + F3
    // 7) tempQ = T2' * Q3 = T2' ((F1 * T4) + (F2 * T3) + F3)
    // 8) Q6 = F5*T3 + F6
    // 9) tempQ = tempQ + T3' * Q6
    // 10) Q9 = UT(tempQ)
    // 11) Q3 = F1*T2 + Q3 = F1' * T2 + (F1 * T4) + (F2 * T3) + F3
    // 12) Q6 = F2' * T4 + Q6 = (F2' * T4) + (F5 * T3) + F6
    // 13) Q6 = Q6 + F5' * T3
    // 14) Q6 = Q6 + (T1'*Q3)
    memset(tempQ, 0, O2 * O2 * O2);
    madd_trimat(epk->l2_Q3, sk->l2_F1, sk->t4, V1, V1, O2, O2);
    madd_mat(epk->l2_Q3, sk->l2_F2, V1, sk->t3, O1, O1, O2, O2);
    madd_matTr(tempQ, sk->t4, V1, V1, O2, epk->l2_Q3, O2, O2);
    madd_trimat(epk->l2_Q6, sk->l2_F5, sk->t3, O1, O1, O2, O2);
    madd_matTr(tempQ, sk->t3, O1, O1, O2, epk->l2_Q6, O2, O2);
    UpperTrianglize(epk->l2_Q9, tempQ, O2, O2);
    madd_trimatTr(epk->l2_Q3, sk->l2_F1, sk->t4, V1, V1, O2, O2);
    madd_bmatTr(epk->l2_Q6, sk->l2_F2, O1, sk->t4, V1, V1, O2, O2);
    madd_trimatTr(epk->l2_Q6, sk->l2_F5, sk->t3, O1, O1, O2, O2);
    madd_matTr(epk->l2_Q6, sk->t1, V1, V1, O1, epk->l2_Q3, O2, O2);

    memset(tempQ, 0, sizeof(tempQ));
}
