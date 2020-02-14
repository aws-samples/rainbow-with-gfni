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

#include <stdlib.h>

#include "gfni.h"
#include "rainbow_config.h"
#include "utils_prng.h"

#define MAX_ATTEMPT_FRMAT 128
#if O1 == O2
#    define MAX_O O1
#else
#    define MAX_O ((O1 > O2) ? O1 : O2)
#endif

_INLINE_ void
setup_prng(OUT prng_t *prng_sign, IN const sk_t *sk, IN const uint8_t *_digest)
{
    uint8_t prng_preseed[SKSEED_BYTE_LEN + HASH_BYTE_LEN];
    uint8_t prng_seed[HASH_BYTE_LEN];

    // prng_preseed = sk_seed || digest
    memcpy(prng_preseed, sk->sk_seed, SKSEED_BYTE_LEN);
    memcpy(prng_preseed + SKSEED_BYTE_LEN, _digest, HASH_BYTE_LEN);
    hash_msg(prng_seed, HASH_BYTE_LEN, prng_preseed,
             HASH_BYTE_LEN + SKSEED_BYTE_LEN);

    // seed = H( sk_seed || digest )
    prng_set(prng_sign, prng_seed, HASH_BYTE_LEN);

    secure_clean(prng_preseed, sizeof(prng_preseed));
    secure_clean(prng_seed, sizeof(prng_seed));
}

_INLINE_
void gf256mat_submat(uint8_t *      mat2,
                     uint32_t       w2,
                     uint32_t       st,
                     const uint8_t *mat,
                     uint32_t       w,
                     uint32_t       h)
{
    for(size_t i = 0; i < h; i++) {
        memcpy(&mat2[i * w2], &mat[i * w + st], w2);
    }
}

_INLINE_
uint32_t gf256mat_inv(OUT uint8_t *inv_a, IN const uint8_t *a, IN uint32_t H)
{
    uint8_t mat_buffer[2 * MAX_O * MAX_O];

    for(uint32_t i = 0; i < H; i++) {
        uint8_t *ai = &mat_buffer[i * 2 * H];
        memset(ai, 0, 2ULL * H);
        gf256_add(ai, &a[i * H], H);
        ai[H + i] = 1;
    }

    uint8_t r8 = gf256mat_gauss_elim(mat_buffer, H, 2 * H);

    gf256mat_submat(inv_a, H, H, mat_buffer, 2 * H, H);

    secure_clean(mat_buffer, sizeof(mat_buffer));

    return r8;
}

// Generate vinegars and the linear equations for layer 1
// Break when the linear equations are solvable
//
// Returns the number of attempts made
_INLINE_ uint32_t roll_vinegars(IN OUT prng_t *prng_sign,
                                OUT uint8_t *vinegar,
                                OUT uint8_t *mat_l1,
                                IN const sk_t *sk)
{
    uint32_t attempts = 0;
    uint32_t l1_succ  = 0;

    for(; (!l1_succ) && (attempts < MAX_ATTEMPT_FRMAT); attempts++) {
        prng_gen(prng_sign, vinegar, V1);

#ifndef USE_AES_FIELD
        // In order to match the official KATs the vinegar must be transformed to
        // the AES field Note that in any other case this is not required because
        // the vinegar are random and are only used for signing.
        to_gfni(vinegar, vinegar, V1);
#endif

        gfmat_prod_native(mat_l1, sk->l1_F2, O1 * O1, V1, vinegar);
        l1_succ = gf256mat_inv(mat_l1, mat_l1, O1);
    }

    return attempts;
}

int rainbow_sign(uint8_t *signature, const sk_t *sk, const uint8_t *_digest)
{
    uint8_t           mat_l1[O1 * O1];
    uint8_t           mat_l2[O2 * O2];
    ALIGN(32) uint8_t vinegar[V1];
    prng_t            prng_sign;

    // Pre-compute variables needed for layer 2
    uint8_t r_l1_F1[O1] = {0};
    uint8_t r_l2_F1[O2] = {0};
    uint8_t mat_l2_F3[O2 * O2];
    uint8_t mat_l2_F2[O1 * O2];

    digest_salt_t ds;
    memcpy(ds.digest, _digest, sizeof(ds.digest));

    // Must set the prng before converting to the GFNI because the original
    // sk->sk_seed should be used.
    setup_prng(&prng_sign, sk, _digest);

#ifdef USE_AES_FIELD
    const sk_t *_sk = sk;
#else
    sk_t  sk_tmp;
    sk_t *_sk = &sk_tmp;
    to_gfni((uint8_t *)_sk, (const uint8_t *)sk, sizeof(*sk));
#endif // USE_AES_FIELD

    uint32_t attempts = roll_vinegars(&prng_sign, vinegar, mat_l1, _sk);

    multab_trimat_36(r_l1_F1, _sk->l1_F1, vinegar, V1);
    multab_trimat_36(r_l2_F1, _sk->l2_F1, vinegar, V1);
    gfmat_prod_native(mat_l2_F3, _sk->l2_F3, O2 * O2, V1, vinegar);
    gfmat_prod_native(mat_l2_F2, _sk->l2_F2, O1 * O2, V1, vinegar);

    // Some local variables.
    uint8_t  _z[PUB_M];
    uint8_t  y[PUB_M];
    uint8_t *x_v1 = vinegar;
    uint8_t  x_o1[O1];
    uint8_t  x_o2[O1];

    uint8_t  temp_o[MAX_O] = {0};
    uint32_t succ          = 0;
    while(!succ) {
        if(MAX_ATTEMPT_FRMAT <= attempts) {
            break;
        }
        // The computation:  H(digest||salt)  -->   z   --S-->   y  --C-map-->   x
        // --T-->   w

        // Roll the salt
        prng_gen(&prng_sign, ds.salt, sizeof(ds.salt));

        hash_msg(_z, PUB_M, (const uint8_t *)&ds, sizeof(ds));

#ifndef USE_AES_FIELD
        to_gfni(_z, _z, sizeof(_z));
#endif

        // y = S^-1 * z
        // Identity part of S
        memcpy(y, _z, PUB_M);
        gfmat_prod_native(temp_o, _sk->s1, O1, O2, &_z[O1]);
        gf256_add(y, temp_o, O1);

        // Central Map:
        // Layer 1: calculate x_o1
        memcpy(temp_o, r_l1_F1, O1);
        gf256_add(temp_o, y, O1);
        gfmat_prod_native(x_o1, mat_l1, O1, O1, temp_o);

        // Layer 2: calculate x_o2
        memset(temp_o, 0, O2);
        // F2
        gfmat_prod_native(temp_o, mat_l2_F2, O2, O1, x_o1);
        // F5
        multab_trimat_36(mat_l2, _sk->l2_F5, x_o1, O1);
        gf256_add(temp_o, mat_l2, O2);
        // F1
        gf256_add(temp_o, r_l2_F1, O2);
        gf256_add(temp_o, y + O1, O2);

        // Generate inv_mat
        // F6
        gfmat_prod_native(mat_l2, _sk->l2_F6, O2 * O2, O1, x_o1);
        // F3
        gf256_add(mat_l2, mat_l2_F3, O2 * O2);
        succ = gf256mat_inv(mat_l2, mat_l2, O2);

        // Solve l2 eqs
        gfmat_prod_native(x_o2, mat_l2, O2, O2, temp_o);

        attempts++;
    };
    // w = T^-1 * y
    uint8_t w[PUB_N];
    // Identity part of T.
    memcpy(w, x_v1, V1);
    memcpy(&w[V1], x_o1, O1);
    memcpy(&w[V2], x_o2, O2);

    // Compute T1
    gfmat_prod_native(y, _sk->t1, V1, O1, x_o1);
    gf256_add(w, y, V1);

    // Compute T4
    gfmat_prod_native(y, _sk->t4, V1, O2, x_o2);
    gf256_add(w, y, V1);

    // Compute T3
    gfmat_prod_native(y, _sk->t3, O1, O2, x_o2);
    gf256_add(&w[V1], y, O1);

    prng_clear(&prng_sign);
    secure_clean(mat_l1, sizeof(mat_l1));
    secure_clean(mat_l2, sizeof(mat_l2));
    secure_clean(vinegar, sizeof(vinegar));
    secure_clean(r_l1_F1, sizeof(r_l1_F1));
    secure_clean(r_l2_F1, sizeof(r_l2_F1));
    secure_clean(mat_l2_F3, sizeof(mat_l2_F3));
    secure_clean(mat_l2_F2, sizeof(mat_l2_F2));
    secure_clean(_z, sizeof(_z));
    secure_clean(y, sizeof(y));
    secure_clean(x_o1, sizeof(x_o1));
    secure_clean(x_o2, sizeof(x_o2));
    secure_clean(temp_o, sizeof(temp_o));

    // Return: copy w and salt to the signature.
    if(MAX_ATTEMPT_FRMAT <= attempts) {
        memset(signature, 0, SIG_BYTE_LEN);
        return -1;
    }

#ifndef USE_AES_FIELD
    from_gfni(w, w, sizeof(w));
#endif

    memcpy(signature, w, PUB_N);
    memcpy(signature + PUB_N, ds.salt, sizeof(ds.salt));

    return 0;
}
