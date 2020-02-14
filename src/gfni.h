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

#pragma once

#include "defs.h"

EXTERNC_BEGIN

void to_gfni(uint8_t *out, const uint8_t *in, size_t byte_len);

void from_gfni(uint8_t *out, const uint8_t *in, size_t byte_len);

void obsfucate_l1_polys(uint8_t *      l1_polys,
                        const uint8_t *l2_polys,
                        uint32_t       n_terms,
                        const uint8_t *s1);

void gfmat_prod_native(uint8_t *      c,
                       const uint8_t *matA,
                       uint32_t       n_A_vec_byte,
                       uint32_t       n_A_width,
                       const uint8_t *b);

// Calculates accu_c[i] = accu_c[i] ^ (a[i] * b) where accu_c and a are two
// byte_len vectors
void gf256_madd(IN OUT uint8_t *accu_c,
                IN const uint8_t *a,
                IN uint8_t        b,
                IN size_t         byte_len);

// Calculate accu_b[i] = accu_b[i] ^ a[i] where accu_b and a are two byte_len
// vectors
void gf256_add(IN OUT uint8_t *accu_b, IN const uint8_t *a, IN size_t byte_len);

// Calculates a[i] = a[i] * b[i] where a and b are two byte_len vectors
void gf256_mul(IN OUT uint8_t *a, IN uint8_t b, IN size_t byte_len);

// Calculates a = a^{-1} in GF(2^8)
uint8_t gf256_inv(uint8_t *a);

void multab_trimat_36(uint8_t *      y,
                      const uint8_t *trimat,
                      const uint8_t *x,
                      uint32_t       dim);

void mq_gf256_n140_m72(uint8_t *z, const uint8_t *pk_mat, const uint8_t *w);

uint32_t gf256mat_gauss_elim(IN OUT uint8_t *mat, IN uint32_t h, IN uint32_t w);

EXTERNC_END
