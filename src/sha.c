/**
 * @file sha.c
 * @brief SHA-1 Cryptographic Hash Implementation
 *
 * This file implements the SHA-1 (Secure Hash Algorithm 1) hash function.
 * SHA-1 produces a 160-bit (20-byte) hash value, typically rendered as
 * a 40-character hexadecimal string.
 *
 * ## WARNING: SHA-1 is Deprecated for Security
 * SHA-1 is considered cryptographically broken and unsuitable for security
 * applications since 2017. This implementation is kept for compatibility
 * with legacy systems. For new applications, use SHA-256 (sha256.c).
 *
 * ## Algorithm Overview
 * SHA-1 processes data in 512-bit (64-byte) blocks and maintains
 * a 160-bit state as five 32-bit words (A, B, C, D, E).
 *
 * For each block:
 * 1. Expand 16 message words to 80 words (message schedule)
 * 2. Perform 80 rounds of mixing using bitwise operations
 * 3. Add result back to running state
 *
 * The 80 rounds use four different mixing functions:
 * - Rounds 0-19:  Ch(B,C,D) = (B AND C) XOR (NOT B AND D) + 0x5A827999
 * - Rounds 20-39: Parity(B,C,D) = B XOR C XOR D + 0x6ED9EBA1
 * - Rounds 40-59: Maj(B,C,D) = (B AND C) XOR (B AND D) XOR (C AND D) + 0x8F1BBCDC
 * - Rounds 60-79: Parity(B,C,D) = B XOR C XOR D + 0xCA62C1D6
 *
 * ## Usage Example
 * ```c
 * uint8_t hash[SHA_DIGEST_SIZE];  // 20 bytes
 * SHA_hash(data, data_length, hash);
 * // hash now contains the 20-byte SHA-1 digest
 * ```
 *
 * ## API
 * - SHA_init(): Initialize context
 * - SHA_update(): Add data to hash
 * - SHA_final(): Finalize and get hash
 * - SHA_hash(): One-shot convenience function
 *
 * @author The Android Open Source Project
 * @copyright 2013, BSD License
 * @see FIPS PUB 180-4 for the SHA-1 specification
 * @see sha256.c for the recommended alternative
 *
 * @note Optimized for minimal code size in embedded systems
 */

/* sha.c
**
** Copyright 2013, The Android Open Source Project
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

// Optimized for minimal code size.

#include "mincrypt/sha.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/**
 * @brief Rotate left (circular shift)
 *
 * Rotates a 32-bit value left by the specified number of bits.
 * Bits shifted out on the left re-enter on the right.
 *
 * @param bits Number of positions to rotate (0-31)
 * @param value The 32-bit value to rotate
 * @return The rotated value
 *
 * Example: rol(1, 0x80000000) = 0x00000001
 */
#define rol(bits, value) (((value) << (bits)) | ((value) >> (32 - (bits))))

/**
 * @brief SHA-1 block transformation (core compression function)
 *
 * Processes a single 512-bit (64-byte) block and updates the hash state.
 * This is the heart of SHA-1 where all the cryptographic mixing happens.
 *
 * ## Algorithm Steps:
 * 1. Message Schedule Expansion:
 *    - Copy 16 words from input block to W[0..15]
 *    - Expand to 80 words: W[t] = ROL(1, W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16])
 *
 * 2. Initialize working variables from current state
 *
 * 3. Perform 80 rounds of mixing:
 *    For each round t:
 *    - temp = ROL(5,A) + f(t,B,C,D) + E + W[t] + K[t]
 *    - E=D, D=C, C=ROL(30,B), B=A, A=temp
 *
 *    Where f(t,B,C,D) varies by round:
 *    - Rounds 0-19:  Ch = (B & C) ^ (~B & D)  [choose between C/D based on B]
 *    - Rounds 20-39: Parity = B ^ C ^ D
 *    - Rounds 40-59: Maj = (B & C) | (B & D) | (C & D)  [majority function]
 *    - Rounds 60-79: Parity = B ^ C ^ D
 *
 * 4. Add working variables back to state
 *
 * @param ctx SHA context containing the block buffer and running state
 */
static void SHA1_Transform(SHA_CTX* ctx) {
    uint32_t W[80];       /* Expanded message schedule array */
    uint32_t A, B, C, D, E; /* Working variables */
    uint8_t* p = ctx->buf;
    int t;

    /* Expand the 16-word input block to 80 words */
    for(t = 0; t < 16; ++t) {
        /* Convert 4 bytes to 32-bit word (big-endian) */
        uint32_t tmp =  *p++ << 24;
        tmp |= *p++ << 16;
        tmp |= *p++ << 8;
        tmp |= *p++;
        W[t] = tmp;
    }

    /* Generate words 16-79 by XOR and rotate */
    for(; t < 80; t++) {
        W[t] = rol(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
    }

    /* Initialize working variables with current hash state */
    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];

    /* 80 rounds of mixing */
    for(t = 0; t < 80; t++) {
        uint32_t tmp = rol(5,A) + E + W[t];

        /* Select mixing function and constant based on round number */
        if (t < 20)
            tmp += (D^(B&(C^D))) + 0x5A827999;    /* Ch function */
        else if ( t < 40)
            tmp += (B^C^D) + 0x6ED9EBA1;          /* Parity function */
        else if ( t < 60)
            tmp += ((B&C)|(D&(B|C))) + 0x8F1BBCDC; /* Maj function */
        else
            tmp += (B^C^D) + 0xCA62C1D6;          /* Parity function */

        /* Rotate working variables */
        E = D;
        D = C;
        C = rol(30,B);
        B = A;
        A = tmp;
    }

    /* Add working variables back to running state */
    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
    ctx->state[4] += E;
}

/**
 * @brief Virtual function table for the hash interface
 *
 * Allows treating different hash algorithms uniformly through
 * function pointers. Used by the HASH_* macros.
 */
static const HASH_VTAB SHA_VTAB = {
    SHA_init,
    SHA_update,
    SHA_final,
    SHA_hash,
    SHA_DIGEST_SIZE
};

/**
 * @brief Initialize a SHA-1 hash context
 *
 * Sets up the context with the standard SHA-1 initial hash values.
 * These "magic numbers" are defined in FIPS 180-4 and come from
 * the fractional parts of the square roots of 2, 3, 5, 7, 11.
 *
 * @param ctx The SHA context to initialize
 */
void SHA_init(SHA_CTX* ctx) {
    ctx->f = &SHA_VTAB;
    /* Initial hash values (FIPS 180-4 section 5.3.1) */
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count = 0;
}


/**
 * @brief Add data to the hash computation
 *
 * Accumulates data in the internal buffer and processes complete
 * 64-byte blocks. Partial blocks are saved for later.
 *
 * @param ctx The SHA context
 * @param data Pointer to data to add
 * @param len Number of bytes to add
 */
void SHA_update(SHA_CTX* ctx, const void* data, int len) {
    int i = (int) (ctx->count & 63);  /* Current position in buffer */
    const uint8_t* p = (const uint8_t*)data;

    ctx->count += len;  /* Update total byte count */

    while (len--) {
        ctx->buf[i++] = *p++;
        if (i == 64) {
            /* Buffer full - process this block */
            SHA1_Transform(ctx);
            i = 0;
        }
    }
}


/**
 * @brief Finalize the hash and return the digest
 *
 * Performs the final padding and processing according to SHA-1 spec:
 * 1. Append 0x80 (a single 1 bit followed by zeros)
 * 2. Pad with zeros until message length is 56 mod 64
 * 3. Append original message length as 64-bit big-endian
 * 4. Process final block(s)
 * 5. Convert state to big-endian byte array
 *
 * @param ctx The SHA context
 * @return Pointer to the 20-byte digest (stored in ctx->buf)
 */
const uint8_t* SHA_final(SHA_CTX* ctx) {
    uint8_t *p = ctx->buf;
    uint64_t cnt = ctx->count * 8;  /* Message length in bits */
    int i;

    /* Append 0x80 padding byte */
    SHA_update(ctx, (uint8_t*)"\x80", 1);
    /* Pad with zeros until length is 56 mod 64 */
    while ((ctx->count & 63) != 56) {
        SHA_update(ctx, (uint8_t*)"\0", 1);
    }
    /* Append message length as 64-bit big-endian */
    for (i = 0; i < 8; ++i) {
        uint8_t tmp = (uint8_t) (cnt >> ((7 - i) * 8));
        SHA_update(ctx, &tmp, 1);
    }

    /* Convert state to big-endian byte array in output buffer */
    for (i = 0; i < 5; i++) {
        uint32_t tmp = ctx->state[i];
        *p++ = tmp >> 24;
        *p++ = tmp >> 16;
        *p++ = tmp >> 8;
        *p++ = tmp >> 0;
    }

    return ctx->buf;
}

/**
 * @brief Convenience function for one-shot hashing
 *
 * Computes the SHA-1 hash of a complete message in one call.
 * More convenient than the init/update/final sequence when
 * you have all data available at once.
 *
 * @param data Pointer to the data to hash
 * @param len Length of the data in bytes
 * @param digest Buffer to receive the 20-byte hash (must be >= SHA_DIGEST_SIZE)
 * @return Pointer to the digest buffer
 */
/* Convenience function */
const uint8_t* SHA_hash(const void* data, int len, uint8_t* digest) {
    SHA_CTX ctx;
    SHA_init(&ctx);
    SHA_update(&ctx, data, len);
    memcpy(digest, SHA_final(&ctx), SHA_DIGEST_SIZE);
    return digest;
}
