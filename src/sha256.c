/**
 * @file sha256.c
 * @brief SHA-256 Cryptographic Hash Implementation
 *
 * This file implements the SHA-256 hash algorithm, which produces a
 * 256-bit (32-byte) hash value. SHA-256 is part of the SHA-2 family
 * and is widely used for security applications including firmware signing.
 *
 * ## Why SHA-256?
 * - Stronger security than SHA-1 (no known practical attacks)
 * - 32-byte output matches AES-256 key size
 * - Standard for TLS, SSL certificates, cryptocurrencies, etc.
 * - Required by NIST for government applications
 *
 * ## Algorithm Overview
 * SHA-256 processes data in 512-bit (64-byte) blocks:
 *
 * 1. Initialize hash state with 8 specific 32-bit values
 * 2. For each 512-bit block:
 *    a. Expand 16 input words to 64 words (message schedule)
 *    b. Perform 64 rounds of compression using:
 *       - Bitwise operations (AND, OR, XOR, NOT)
 *       - Rotations and shifts
 *       - Addition modulo 2^32
 *    c. Add compressed values to running hash state
 * 3. Output the 8 state words as 32 bytes
 *
 * ## The 64 Round Constants (K)
 * These are the first 32 bits of the fractional parts of the cube roots
 * of the first 64 prime numbers (2, 3, 5, 7, 11, ..., 311).
 *
 * ## The 8 Initial Hash Values
 * These are the first 32 bits of the fractional parts of the square roots
 * of the first 8 prime numbers (2, 3, 5, 7, 11, 13, 17, 19).
 *
 * ## DJI Usage
 * DJI uses SHA-256 to:
 * - Hash firmware headers before RSA signing
 * - Create payload digests for integrity verification
 *
 * @author The Android Open Source Project
 * @copyright 2013, BSD License
 * @see FIPS PUB 180-4 for the SHA-256 specification
 * @see verify.c for how SHA-256 is used in DJI firmware verification
 */

/* sha256.c
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

#include "mincrypt/sha256.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/**
 * @brief Rotate right (circular shift right)
 *
 * Rotates a 32-bit value right by the specified number of bits.
 * Bits shifted out on the right re-enter on the left.
 * SHA-256 uses this extensively in its compression function.
 *
 * @param value The 32-bit value to rotate
 * @param bits Number of positions to rotate (0-31)
 * @return The rotated value
 */
#define ror(value, bits) (((value) >> (bits)) | ((value) << (32 - (bits))))

/**
 * @brief Shift right (logical right shift)
 *
 * Shifts a value right, filling with zeros on the left.
 * Unlike rotation, bits shifted out are lost.
 *
 * @param value The value to shift
 * @param bits Number of positions to shift
 * @return The shifted value
 */
#define shr(value, bits) ((value) >> (bits))

/**
 * @brief SHA-256 round constants K[0..63]
 *
 * These 64 constant values are used once each in the 64 rounds
 * of the SHA-256 compression function. They are derived from
 * the fractional parts of the cube roots of the first 64 primes.
 *
 * For example:
 * - K[0] = 0x428a2f98 comes from cube_root(2)
 * - K[1] = 0x71374491 comes from cube_root(3)
 * - etc.
 */
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

/**
 * @brief SHA-256 block transformation (compression function)
 *
 * Processes one 512-bit (64-byte) block and updates the hash state.
 * This is where the cryptographic mixing happens.
 *
 * ## Algorithm:
 *
 * ### Message Schedule (W)
 * Expand 16 input words to 64 words:
 * - W[0..15] = input block (16 words from ctx->buf)
 * - W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]  for t=16..63
 *
 * Where:
 * - σ0(x) = ROTR(7,x) XOR ROTR(18,x) XOR SHR(3,x)
 * - σ1(x) = ROTR(17,x) XOR ROTR(19,x) XOR SHR(10,x)
 *
 * ### Compression Loop (64 rounds)
 * For each round t=0..63:
 * - Σ0(a) = ROTR(2,a) XOR ROTR(13,a) XOR ROTR(22,a)
 * - Maj(a,b,c) = (a AND b) XOR (a AND c) XOR (b AND c)
 * - Σ1(e) = ROTR(6,e) XOR ROTR(11,e) XOR ROTR(25,e)
 * - Ch(e,f,g) = (e AND f) XOR (NOT e AND g)
 * - T1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]
 * - T2 = Σ0(a) + Maj(a,b,c)
 * - Rotate: h=g, g=f, f=e, e=d+T1, d=c, c=b, b=a, a=T1+T2
 *
 * @param ctx SHA-256 context with block buffer and state
 */
static void SHA256_Transform(SHA256_CTX* ctx) {
    uint32_t W[64];       /* Message schedule array */
    uint32_t A, B, C, D, E, F, G, H;  /* Working variables */
    uint8_t* p = ctx->buf;
    int t;

    /* Load first 16 words from input block (big-endian conversion) */
    for(t = 0; t < 16; ++t) {
        uint32_t tmp =  *p++ << 24;
        tmp |= *p++ << 16;
        tmp |= *p++ << 8;
        tmp |= *p++;
        W[t] = tmp;
    }

    /* Expand to 64 words using σ0 and σ1 functions */
    for(; t < 64; t++) {
        uint32_t s0 = ror(W[t-15], 7) ^ ror(W[t-15], 18) ^ shr(W[t-15], 3);
        uint32_t s1 = ror(W[t-2], 17) ^ ror(W[t-2], 19) ^ shr(W[t-2], 10);
        W[t] = W[t-16] + s0 + W[t-7] + s1;
    }

    /* Initialize working variables from current state */
    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];

    /* 64 rounds of compression */
    for(t = 0; t < 64; t++) {
        /* Σ0(a) - "big sigma 0" on a */
        uint32_t s0 = ror(A, 2) ^ ror(A, 13) ^ ror(A, 22);
        /* Maj(a,b,c) - majority function */
        uint32_t maj = (A & B) ^ (A & C) ^ (B & C);
        uint32_t t2 = s0 + maj;
        /* Σ1(e) - "big sigma 1" on e */
        uint32_t s1 = ror(E, 6) ^ ror(E, 11) ^ ror(E, 25);
        /* Ch(e,f,g) - choose function */
        uint32_t ch = (E & F) ^ ((~E) & G);
        uint32_t t1 = H + s1 + ch + K[t] + W[t];

        /* Rotate working variables */
        H = G;
        G = F;
        F = E;
        E = D + t1;
        D = C;
        C = B;
        B = A;
        A = t1 + t2;
    }

    /* Add working variables back to state */
    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
    ctx->state[4] += E;
    ctx->state[5] += F;
    ctx->state[6] += G;
    ctx->state[7] += H;
}

/**
 * @brief Virtual function table for generic hash interface
 */
static const HASH_VTAB SHA256_VTAB = {
    SHA256_init,
    SHA256_update,
    SHA256_final,
    SHA256_hash,
    SHA256_DIGEST_SIZE
};

/**
 * @brief Initialize SHA-256 context
 *
 * Sets up the context with the standard SHA-256 initial hash values.
 * These come from the fractional parts of the square roots of the
 * first 8 primes (2, 3, 5, 7, 11, 13, 17, 19).
 *
 * @param ctx The SHA-256 context to initialize
 */
void SHA256_init(SHA256_CTX* ctx) {
    ctx->f = &SHA256_VTAB;
    /* Initial hash values from FIPS 180-4 section 5.3.3 */
    ctx->state[0] = 0x6a09e667;  /* sqrt(2) */
    ctx->state[1] = 0xbb67ae85;  /* sqrt(3) */
    ctx->state[2] = 0x3c6ef372;  /* sqrt(5) */
    ctx->state[3] = 0xa54ff53a;  /* sqrt(7) */
    ctx->state[4] = 0x510e527f;  /* sqrt(11) */
    ctx->state[5] = 0x9b05688c;  /* sqrt(13) */
    ctx->state[6] = 0x1f83d9ab;  /* sqrt(17) */
    ctx->state[7] = 0x5be0cd19;  /* sqrt(19) */
    ctx->count = 0;
}


/**
 * @brief Add data to the hash computation
 *
 * Buffers input data and processes complete 64-byte blocks.
 *
 * @param ctx The SHA-256 context
 * @param data Pointer to data to hash
 * @param len Number of bytes to process
 */
void SHA256_update(SHA256_CTX* ctx, const void* data, int len) {
    int i = (int) (ctx->count & 63);  /* Position in buffer */
    const uint8_t* p = (const uint8_t*)data;

    ctx->count += len;

    while (len--) {
        ctx->buf[i++] = *p++;
        if (i == 64) {
            SHA256_Transform(ctx);
            i = 0;
        }
    }
}


/**
 * @brief Finalize hash and return digest
 *
 * Applies SHA-256 padding:
 * 1. Append bit '1' (0x80 byte)
 * 2. Pad with zeros to 56 bytes mod 64
 * 3. Append 64-bit message length in bits (big-endian)
 * 4. Process final block(s)
 *
 * @param ctx The SHA-256 context
 * @return Pointer to the 32-byte digest (in ctx->buf)
 */
const uint8_t* SHA256_final(SHA256_CTX* ctx) {
    uint8_t *p = ctx->buf;
    uint64_t cnt = ctx->count * 8;  /* Total bits */
    int i;

    /* Append padding */
    SHA256_update(ctx, (uint8_t*)"\x80", 1);
    while ((ctx->count & 63) != 56) {
        SHA256_update(ctx, (uint8_t*)"\0", 1);
    }
    /* Append length */
    for (i = 0; i < 8; ++i) {
        uint8_t tmp = (uint8_t) (cnt >> ((7 - i) * 8));
        SHA256_update(ctx, &tmp, 1);
    }

    /* Convert state to bytes (big-endian) */
    for (i = 0; i < 8; i++) {
        uint32_t tmp = ctx->state[i];
        *p++ = tmp >> 24;
        *p++ = tmp >> 16;
        *p++ = tmp >> 8;
        *p++ = tmp >> 0;
    }

    return ctx->buf;
}

/**
 * @brief One-shot SHA-256 hash function
 *
 * Convenience function to hash data in a single call.
 *
 * @param data Pointer to data to hash
 * @param len Length in bytes
 * @param digest Buffer for 32-byte result (must be >= SHA256_DIGEST_SIZE)
 * @return Pointer to digest
 *
 * @code
 * uint8_t hash[SHA256_DIGEST_SIZE];
 * SHA256_hash(firmware_header, header_size, hash);
 * @endcode
 */
/* Convenience function */
const uint8_t* SHA256_hash(const void* data, int len, uint8_t* digest) {
    SHA256_CTX ctx;
    SHA256_init(&ctx);
    SHA256_update(&ctx, data, len);
    memcpy(digest, SHA256_final(&ctx), SHA256_DIGEST_SIZE);
    return digest;
}
