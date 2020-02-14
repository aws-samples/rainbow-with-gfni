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

#include "utils_hash.h"
#include <openssl/sha.h>

_INLINE_
int _hash(OUT uint8_t *digest, IN const uint8_t *m, IN const uint64_t mlen)
{
#ifdef MSAN
    // OpenSSL is not compiled with MSAN
    memset(digest, 0, HASH_BYTE_LEN);
#endif
    SHA256_CTX sha256;
    if(!SHA256_Init(&sha256) || !SHA256_Update(&sha256, m, mlen) ||
       !SHA256_Final(digest, &sha256)) {
        return ERROR;
    }

    return SUCCESS;
}

_INLINE_
int expand_hash(OUT uint8_t *digest, IN uint32_t n_digest, IN const uint8_t *hash)
{
    if(HASH_BYTE_LEN >= n_digest) {
        memcpy(digest, hash, n_digest);
        return 0;
    }

    memcpy(digest, hash, HASH_BYTE_LEN);
    n_digest -= HASH_BYTE_LEN;

    while(HASH_BYTE_LEN <= n_digest) {
        GUARD(_hash(&digest[HASH_BYTE_LEN], digest, HASH_BYTE_LEN));

        n_digest -= HASH_BYTE_LEN;
        digest += HASH_BYTE_LEN;
    }

    if(n_digest) {
        uint8_t temp[HASH_BYTE_LEN];
        GUARD(_hash(temp, digest, HASH_BYTE_LEN));
        memcpy(&digest[HASH_BYTE_LEN], temp, n_digest);
    }

    return SUCCESS;
}

int hash_msg(uint8_t *      digest,
             uint32_t       len_digest,
             const uint8_t *m,
             uint64_t       mlen)
{
    uint8_t buf[HASH_BYTE_LEN];
    GUARD(_hash(buf, m, mlen));

    return expand_hash(digest, len_digest, buf);
}
