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

#include "gfni.h"
#include "keypair_computation.h"
#include "rainbow_config.h"
#include "utils_prng.h"

_INLINE_
void generate_S_T(OUT uint8_t *s_and_t, IN OUT prng_t *prng0)
{
    s_and_t += prng_gen(prng0, s_and_t, S1_BYTE_LEN);
    s_and_t += prng_gen(prng0, s_and_t, T1_BYTE_LEN);
    s_and_t += prng_gen(prng0, s_and_t, T4_BYTE_LEN);
    s_and_t += prng_gen(prng0, s_and_t, T3_BYTE_LEN);
}

_INLINE_
void generate_B1_B2(OUT uint8_t *sk, IN OUT prng_t *prng0)
{
    sk += prng_gen(prng0, sk, L1_F1_BYTE_LEN);
    sk += prng_gen(prng0, sk, L1_F2_BYTE_LEN);
    sk += prng_gen(prng0, sk, L2_F1_BYTE_LEN);
    sk += prng_gen(prng0, sk, L2_F2_BYTE_LEN);
    sk += prng_gen(prng0, sk, L2_F3_BYTE_LEN);
    sk += prng_gen(prng0, sk, L2_F5_BYTE_LEN);
    sk += prng_gen(prng0, sk, L2_F6_BYTE_LEN);
}

_INLINE_
void calculate_t4(OUT uint8_t *t2_to_t4,
                  IN const uint8_t *t1,
                  IN const uint8_t *t3)
{
    // t4 = T_sk.t1 * T_sk.t3 - T_sk.t2
    uint8_t  temp[V1];
    uint8_t *t4 = t2_to_t4;
    for(uint32_t i = 0; i < O2; i++) {
        gfmat_prod_native(temp, t1, V1, O1, t3);
        gf256_add(t4, temp, V1);
        t4 += V1;
        t3 += O1;
    }
}

_INLINE_
void gen_sk(OUT sk_t *sk, IN const uint8_t *sk_seed)
{
    memcpy(sk->sk_seed, sk_seed, SKSEED_BYTE_LEN);

    // Set up prng
    prng_t prng0;
    prng_set(&prng0, sk_seed, SKSEED_BYTE_LEN);

    // Generating secret key with prng.
    generate_S_T(sk->s1, &prng0);
    generate_B1_B2(sk->l1_F1, &prng0);

    // Clean prng
    memset(&prng0, 0, sizeof(prng_t));
}

void rainbow_keypair(OUT pk_t *pk, OUT sk_t *sk, IN const uint8_t *sk_seed)
{
    gen_sk(sk, sk_seed);

#ifndef USE_AES_FIELD
    to_gfni((uint8_t *)sk, (uint8_t *)sk, sizeof(*sk));
#endif
    ext_cpk_t epk;

    // Compute the public key in ext_cpk_t format.
    calc_pk(&epk, sk);
    calculate_t4(sk->t4, sk->t1, sk->t3);

    obsfucate_l1_polys(epk.l1_Q1, epk.l2_Q1, N_TRIANGLE_TERMS(V1), sk->s1);
    obsfucate_l1_polys(epk.l1_Q2, epk.l2_Q2, V1 * O1, sk->s1);
    obsfucate_l1_polys(epk.l1_Q3, epk.l2_Q3, V1 * O2, sk->s1);
    obsfucate_l1_polys(epk.l1_Q5, epk.l2_Q5, N_TRIANGLE_TERMS(O1), sk->s1);
    obsfucate_l1_polys(epk.l1_Q6, epk.l2_Q6, O1 * O2, sk->s1);
    obsfucate_l1_polys(epk.l1_Q9, epk.l2_Q9, N_TRIANGLE_TERMS(O2), sk->s1);

#ifndef USE_AES_FIELD
    from_gfni((uint8_t *)sk, (uint8_t *)sk, sizeof(*sk));
    from_gfni((uint8_t *)&epk, (uint8_t *)&epk, sizeof(epk));
#endif

    extcpk_to_pk(pk, &epk);
}
