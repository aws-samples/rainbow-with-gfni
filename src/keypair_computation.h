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

#include "rainbow_config.h"

EXTERNC_BEGIN

#define L1_Q1_BYTE_LEN (O1 * N_TRIANGLE_TERMS(V1))
#define L1_Q2_BYTE_LEN (O1 * V1 * O1)
#define L1_Q3_BYTE_LEN (O1 * V1 * O2)
#define L1_Q5_BYTE_LEN (O1 * N_TRIANGLE_TERMS(O1))
#define L1_Q6_BYTE_LEN (O1 * O1 * O2)
#define L1_Q9_BYTE_LEN (O1 * N_TRIANGLE_TERMS(O2))

#define L2_Q1_BYTE_LEN (O2 * N_TRIANGLE_TERMS(V1))
#define L2_Q2_BYTE_LEN (O2 * V1 * O1)
#define L2_Q3_BYTE_LEN (O2 * V1 * O2)
#define L2_Q5_BYTE_LEN (O2 * N_TRIANGLE_TERMS(O1))
#define L2_Q6_BYTE_LEN (O2 * O1 * O2)
#define L2_Q9_BYTE_LEN (O2 * N_TRIANGLE_TERMS(O2))

// Internal public key structure
typedef struct rainbow_extend_publickey {
    uint8_t l1_Q1[L1_Q1_BYTE_LEN];
    uint8_t l1_Q2[L1_Q2_BYTE_LEN];
    uint8_t l1_Q3[L1_Q3_BYTE_LEN];
    uint8_t l1_Q5[L1_Q5_BYTE_LEN];
    uint8_t l1_Q6[L1_Q6_BYTE_LEN];
    uint8_t l1_Q9[L1_Q9_BYTE_LEN];

    uint8_t l2_Q1[L1_Q1_BYTE_LEN];
    uint8_t l2_Q2[L2_Q2_BYTE_LEN];
    uint8_t l2_Q3[L2_Q3_BYTE_LEN];
    uint8_t l2_Q5[L2_Q5_BYTE_LEN];
    uint8_t l2_Q6[L2_Q6_BYTE_LEN];
    uint8_t l2_Q9[L2_Q9_BYTE_LEN];
} ext_cpk_t;

void calc_pk(OUT ext_cpk_t *epk, IN const sk_t *sk);
void extcpk_to_pk(OUT pk_t *pk, IN const ext_cpk_t *cpk);

EXTERNC_END
