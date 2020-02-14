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

#define CRYPTO_SECRETKEYBYTES sizeof(sk_t)
#define CRYPTO_PUBLICKEYBYTES sizeof(pk_t)
#define CRYPTO_BYTES          SIG_BYTE_LEN

void rainbow_keypair(pk_t *pk, sk_t *sk, const uint8_t *sk_seed);
int  rainbow_sign(uint8_t *signature, const sk_t *sk, const uint8_t *digest);
int  rainbow_verify(const uint8_t *digest,
                    const uint8_t *signature,
                    const pk_t *   pk);

EXTERNC_END
