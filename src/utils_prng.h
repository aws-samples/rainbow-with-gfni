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
 * Written by Nir Drucker and Shay Gueron
 * AWS Cryptographic Algorithms Group.
 * (ndrucker@amazon.com, gueron@amazon.com)
 *
 * Based on the original Rainbow code from
 * https://csrc.nist.gov/CSRC/media/Projects/Post-Quantum-Cryptography/documents/round-2/submissions/Rainbow-Round2.zip
 */

#pragma once

EXTERNC_BEGIN

#include "utils_hash.h"

#ifdef USE_ORIG_RNG
#    include "rng.h"
#    define CTR_DRBG_ENTROPY_LEN (48)

typedef AES256_CTR_DRBG_struct prng_t;

#else
#    include "ctr_drbg/ctr_drbg.h"

typedef CTR_DRBG_STATE prng_t;
#endif

_INLINE_
int prng_set(OUT prng_t *prng,
             IN const uint8_t *prng_seed,
             IN const uint64_t prng_seedlen)
{
    uint8_t      seed[CTR_DRBG_ENTROPY_LEN];
    const size_t rem = CTR_DRBG_ENTROPY_LEN - prng_seedlen;

    if(prng_seedlen >= CTR_DRBG_ENTROPY_LEN) {
        memcpy(seed, prng_seed, CTR_DRBG_ENTROPY_LEN);
    } else {
        memcpy(seed, prng_seed, prng_seedlen);
        hash_msg(seed + prng_seedlen, rem, prng_seed, prng_seedlen);
    }

#ifdef USE_ORIG_RNG
    randombytes_init_with_state(prng, seed);
#else
    CTR_DRBG_init(prng, seed, NULL, 0);
#endif

    return SUCCESS;
}

#ifdef USE_ORIG_RNG

_INLINE_
uint32_t prng_gen(IN OUT prng_t *prng, OUT uint8_t *out, IN const uint64_t outlen)
{
    randombytes_with_state(prng, out, outlen);
    return outlen;
}

#else

_INLINE_
uint32_t prng_gen(IN OUT prng_t *prng, OUT uint8_t *out, IN const uint64_t outlen)
{
    const size_t max_len  = CTR_DRBG_MAX_GENERATE_LENGTH;
    size_t       curr_out = outlen;

    int ctr;
    for(ctr = 0; curr_out > max_len; ctr++) {
        GUARD(CTR_DRBG_generate(prng, &out[ctr * max_len], max_len, NULL, 0));
        curr_out -= max_len;
    }
    GUARD(CTR_DRBG_generate(prng, &out[ctr * max_len], curr_out, NULL, 0));

    return outlen;
}

#endif

_INLINE_
void prng_clear(OUT prng_t *prng)
{
#ifdef USE_ORIG_RNG
    // Because prng is unsed
    (void)(prng);
    return;
#else
    CTR_DRBG_clear(prng);
#endif
}

EXTERNC_END
