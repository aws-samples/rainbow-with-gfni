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

#define O1 36
#define O2 36
#define V1 68
#define V2 ((V1) + (O1))

#define PUB_N (V1 + O1 + O2)
#define PUB_M (O1 + O2)

#define HASH_BYTE_LEN   48
#define SKSEED_BYTE_LEN 32
#define SALT_BYTE_LEN   16
#define SIG_BYTE_LEN    (PUB_N + SALT_BYTE_LEN)

#define N_TRIANGLE_TERMS(n_var) ((n_var) * ((n_var) + 1) / 2)

#define S1_BYTE_LEN (O1 * O2)
#define T1_BYTE_LEN (V1 * O1)
#define T4_BYTE_LEN (V1 * O2)
#define T3_BYTE_LEN (O1 * O2)

#define L1_F1_BYTE_LEN (O1 * N_TRIANGLE_TERMS(V1))
#define L1_F2_BYTE_LEN (O1 * V1 * O1)
#define L2_F1_BYTE_LEN (O2 * N_TRIANGLE_TERMS(V1))
#define L2_F2_BYTE_LEN (O2 * V1 * O1)
#define L2_F3_BYTE_LEN (O2 * V1 * O2)
#define L2_F5_BYTE_LEN (O2 * N_TRIANGLE_TERMS(O1))
#define L2_F6_BYTE_LEN (O2 * O1 * O2)

typedef struct pk_st {
    uint8_t pk[(PUB_M)*N_TRIANGLE_TERMS(PUB_N)];
} pk_t;

typedef struct sk_st {
    // Seed for generating secret key.
    // Generating S, T, and F for classic rainbow.
    // Generating S and T only for cyclic rainbow.
    uint8_t sk_seed[SKSEED_BYTE_LEN];

    uint8_t s1[S1_BYTE_LEN]; // Part of S map
    uint8_t t1[T1_BYTE_LEN]; // Part of T map
    uint8_t t4[T4_BYTE_LEN]; // Part of T map
    uint8_t t3[T3_BYTE_LEN]; // Part of T map

    uint8_t l1_F1[L1_F1_BYTE_LEN]; // Part of C-map, F1, Layer1
    uint8_t l1_F2[L1_F2_BYTE_LEN]; // Part of C-map, F2, Layer1

    uint8_t l2_F1[L2_F1_BYTE_LEN]; // Part of C-map, F1, Layer2
    uint8_t l2_F2[L2_F2_BYTE_LEN]; // Part of C-map, F2, Layer2

    uint8_t l2_F3[L2_F3_BYTE_LEN]; // Part of C-map, F3, Layer2
    uint8_t l2_F5[L2_F5_BYTE_LEN]; // Part of C-map, F5, Layer2
    uint8_t l2_F6[L2_F6_BYTE_LEN]; // Part of C-map, F6, Layer2
} sk_t;

typedef struct digest_salt_st {
    uint8_t digest[HASH_BYTE_LEN];
    uint8_t salt[SALT_BYTE_LEN];
} digest_salt_t;

EXTERNC_END
