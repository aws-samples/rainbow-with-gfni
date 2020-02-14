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
#include "rainbow_config.h"
#include "utils_hash.h"

int rainbow_verify(IN const uint8_t *digest,
                   IN const uint8_t *sig,
                   IN const pk_t *pk)
{
    uint8_t digest_ck[PUB_M];

#ifdef USE_AES_FIELD
    const uint8_t *_sig = sig;
    const pk_t *   _pk  = pk;
#else
    uint8_t _sig[PUB_N];
    pk_t    pk_tmp;
    pk_t *  _pk = &pk_tmp;

    to_gfni((uint8_t *)_pk, (const uint8_t *)pk, sizeof(*_pk));
    to_gfni(_sig, sig, sizeof(_sig));
#endif

    mq_gf256_n140_m72(digest_ck, _pk->pk, _sig);

#ifndef USE_AES_FIELD
    from_gfni(digest_ck, digest_ck, PUB_M);
#endif

    uint8_t       correct[PUB_M];
    digest_salt_t ds;
    memcpy(ds.digest, digest, sizeof(ds.digest));
    memcpy(ds.salt, sig + PUB_N, sizeof(ds.salt));

    // H( digest || salt )
    hash_msg(correct, PUB_M, (uint8_t *)&ds, sizeof(ds));

    // Check consistancy.
    uint8_t cc = 0;
    for(size_t i = 0; i < PUB_M; i++) {
        cc |= (digest_ck[i] ^ correct[i]);
    }
    return (0 == cc) ? 0 : -1;
}
