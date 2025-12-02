/**
 * @file rsa.h
 * @brief RSA Public Key Signature Verification Header
 *
 * This header defines the data structures and functions for RSA signature
 * verification using 2048-bit keys. It's part of the mincrypt library,
 * optimized for embedded systems like Android bootloaders.
 *
 * ## Overview
 * RSA (Rivest-Shamir-Adleman) is an asymmetric cryptographic algorithm.
 * This implementation:
 * - Supports RSA-2048 (2048-bit keys = 256-byte signatures)
 * - Uses PKCS#1 v1.5 padding scheme
 * - Works with SHA-1 or SHA-256 hashes
 * - Supports public exponents 3 and 65537
 *
 * ## Key Structure
 * The RSAPublicKey structure contains precomputed values to speed up
 * modular exponentiation using Montgomery multiplication:
 * - n: The RSA modulus (public key component)
 * - n0inv: Precomputed value for Montgomery reduction
 * - rr: Precomputed R^2 mod n for Montgomery conversion
 *
 * ## Usage in DJI Firmware
 * DJI uses RSA-2048 with SHA-256 to sign firmware headers:
 * 1. Compute SHA-256 hash of the firmware header
 * 2. Verify RSA signature using the public key (PRAK, GFAK, or SLAK)
 * 3. If verification passes, the firmware is authentic
 *
 * @author The Android Open Source Project
 * @copyright 2008 Google Inc., BSD License
 * @see rsa.c for implementation details
 */

/* rsa.h
**
** Copyright 2008, The Android Open Source Project
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are met:
**     * Redistributions of source code must retain the above copyright
**       notice, this list of conditions and the following disclaimer.
**     * Redistributions in binary form must reproduce the above copyright
**       notice, this list of conditions and the following disclaimer in the
**       documentation and/or other materials provided with the distribution.
**     * Neither the name of Google Inc. nor the names of its contributors may
**       be used to endorse or promote products derived from this software
**       without specific prior written permission.
**
** THIS SOFTWARE IS PROVIDED BY Google Inc. ``AS IS'' AND ANY EXPRESS OR
** IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
** MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
** EVENT SHALL Google Inc. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
** PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
** OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
** WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
** OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
** ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _EMBEDDED_RSA_H_
#define _EMBEDDED_RSA_H_

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief RSA key length in bytes (2048 bits / 8)
 *
 * This implementation only supports RSA-2048, which provides
 * approximately 112 bits of security.
 */
#define RSANUMBYTES 256           /* 2048 bit key length */

/**
 * @brief RSA key length in 32-bit words
 *
 * Since we work with 32-bit words internally, we need 64 words
 * to represent a 2048-bit number.
 */
#define RSANUMWORDS (RSANUMBYTES / sizeof(uint32_t))

/**
 * @brief RSA public key structure with precomputed values
 *
 * This structure contains the public key and precomputed values
 * needed for efficient Montgomery multiplication.
 *
 * ## Fields Explained
 *
 * ### len (int)
 * Number of 32-bit words in the modulus. Always 64 for RSA-2048.
 *
 * ### n0inv (uint32_t)
 * Precomputed value: -1/n[0] mod 2^32
 * Used in Montgomery reduction to eliminate the low-order word.
 * Calculated once when the key is generated.
 *
 * ### n[RSANUMWORDS] (uint32_t[64])
 * The RSA modulus N, stored as a little-endian array of 32-bit words.
 * n[0] is the least significant word, n[63] is the most significant.
 *
 * ### rr[RSANUMWORDS] (uint32_t[64])
 * Precomputed value: R^2 mod n, where R = 2^2048
 * Used to convert numbers to Montgomery representation.
 * aR = a * R^2 * R^(-1) mod n = a * R mod n
 *
 * ### exponent (int)
 * Public exponent e. Either 3 (fast but less secure) or 65537 (standard).
 * 65537 = 0x10001 is the most common choice (Fermat prime F4).
 *
 * @note The precomputed values (n0inv, rr) make verification ~10x faster
 *       but require offline computation when generating the key structure.
 */
typedef struct RSAPublicKey {
    int len;                  /* Length of n[] in number of uint32_t */
    uint32_t n0inv;           /* -1 / n[0] mod 2^32 */
    uint32_t n[RSANUMWORDS];  /* modulus as little endian array */
    uint32_t rr[RSANUMWORDS]; /* R^2 as little endian array */
    int exponent;             /* 3 or 65537 */
} RSAPublicKey;

/**
 * @brief Verify an RSA PKCS#1 v1.5 signature
 *
 * Verifies that a signature was created with the private key
 * corresponding to the given public key.
 *
 * @param key Pointer to the RSA public key structure
 * @param signature The signature bytes (256 bytes for RSA-2048)
 * @param len Length of signature (must equal RSANUMBYTES)
 * @param hash The expected hash value that was signed
 * @param hash_len Length of hash (20 for SHA-1, 32 for SHA-256)
 *
 * @return 1 if signature is valid, 0 if verification failed
 *
 * @note Only RSA-2048 is supported
 * @note Only exponents 3 and 65537 are supported
 */
int RSA_verify(const RSAPublicKey *key,
               const uint8_t* signature,
               const int len,
               const uint8_t* hash,
               const int hash_len);

#ifdef __cplusplus
}
#endif

#endif
