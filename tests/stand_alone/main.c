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
 * The code was written by Nir Drucker and Shay Gueron
 * AWS Cryptographic Algorithms Group.
 * (ndrucker@amazon.com, gueron@amazon.com)
 */

#include "api.h"
#include "utils_hash.h"
#include <stdio.h>
#include <stdlib.h>

#include "measurements.h"

_INLINE_ int crypto_sign_keypair(OUT uint8_t *pk, OUT uint8_t *sk)
{
    uint8_t sk_seed[SKSEED_BYTE_LEN] = {0};
    rainbow_keypair((pk_t *)pk, (sk_t *)sk, sk_seed);
    return 0;
}

_INLINE_ int crypto_sign(OUT uint8_t *sm,
                         OUT uint64_t *smlen,
                         IN const uint8_t *m,
                         IN const uint64_t mlen,
                         IN const uint8_t *sk)
{
    uint8_t digest[HASH_BYTE_LEN];
    hash_msg(digest, HASH_BYTE_LEN, m, mlen);

    memcpy(sm, m, mlen);
    *smlen = mlen + SIG_BYTE_LEN;

    return rainbow_sign(sm + mlen, (const sk_t *)sk, digest);
}

_INLINE_ int crypto_sign_open(OUT uint8_t *m,
                              OUT uint64_t *mlen,
                              IN const uint8_t *sm,
                              IN const uint64_t smlen,
                              IN const uint8_t *pk)
{
    if(SIG_BYTE_LEN > smlen) {
        return -1;
    }

    memcpy(m, sm, smlen - SIG_BYTE_LEN);
    *mlen = smlen - SIG_BYTE_LEN;

    uint8_t digest[HASH_BYTE_LEN];
    hash_msg(digest, HASH_BYTE_LEN, m, *mlen);

    return rainbow_verify(digest, sm + (*mlen), (const pk_t *)pk);
}

int main(void)
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES] = {0};
    uint8_t sk[CRYPTO_SECRETKEYBYTES] = {0};

    uint8_t  m[]   = "This is the message to be signed.";
    uint8_t *m1    = NULL;
    uint8_t *sm    = NULL;
    uint64_t mlen  = sizeof(m);
    uint64_t mlen1 = 0;
    uint64_t smlen = 0;
    int      ret   = 0;

    m1 = (uint8_t *)malloc(mlen);
    sm = (uint8_t *)malloc(mlen + CRYPTO_BYTES);

    MEASURE("Keypair", ret = crypto_sign_keypair(pk, sk););
    if(0 != ret) {
        printf("crypto_sign_keypair failed\n");
        goto out;
    }

    MEASURE("Sign", ret = crypto_sign(sm, &smlen, m, sizeof(m), sk););
    if(0 != ret) {
        printf("crypto_sign failed\n");
        goto out;
    }

    MEASURE("Verify", ret = crypto_sign_open(m1, &mlen1, sm, smlen, pk););
    if(0 != ret) {
        printf("crypto_sign_open failed\n");
        goto out;
    }

    printf("Success\n");

out:
    free(sm);
    free(m1);

    return ret;
}
