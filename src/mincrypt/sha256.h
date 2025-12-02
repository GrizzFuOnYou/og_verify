/**
 * @file sha256.h
 * @brief SHA-256 Cryptographic Hash Function Header
 *
 * This header defines the interface for SHA-256 (Secure Hash Algorithm 256),
 * which produces a 256-bit (32-byte) hash value.
 *
 * ## Overview
 * SHA-256 is part of the SHA-2 family and is the recommended hash function
 * for security applications. It provides:
 * - 256-bit output (32 bytes)
 * - Strong collision resistance
 * - Preimage resistance
 *
 * ## DJI Firmware Usage
 * DJI uses SHA-256 for:
 * 1. Hashing the firmware header before RSA signing
 * 2. Creating the payload digest for integrity verification
 *
 * ## API Usage
 * ```c
 * SHA256_CTX ctx;
 * uint8_t digest[SHA256_DIGEST_SIZE];
 *
 * // Option 1: Incremental hashing
 * SHA256_init(&ctx);
 * SHA256_update(&ctx, data1, len1);
 * SHA256_update(&ctx, data2, len2);
 * memcpy(digest, SHA256_final(&ctx), SHA256_DIGEST_SIZE);
 *
 * // Option 2: One-shot hashing
 * SHA256_hash(data, len, digest);
 * ```
 *
 * @author Marius Schilder <mschilder@google.com>
 * @copyright 2011 Google Inc. All Rights Reserved.
 * @see FIPS PUB 180-4 for the official specification
 */

// Copyright 2011 Google Inc. All Rights Reserved.
// Author: mschilder@google.com (Marius Schilder)

#ifndef SECURITY_UTIL_LITE_SHA256_H__
#define SECURITY_UTIL_LITE_SHA256_H__

#include <stdint.h>
#include "hash-internal.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @brief SHA-256 context type
 *
 * This is an alias for the generic HASH_CTX structure.
 * SHA-256 uses all 8 state words.
 */
typedef HASH_CTX SHA256_CTX;

/**
 * @brief Initialize a SHA-256 hash context
 *
 * Sets up the context with the standard SHA-256 initial hash values
 * (derived from the fractional parts of the square roots of the first
 * 8 prime numbers).
 *
 * @param ctx Pointer to context to initialize
 */
void SHA256_init(SHA256_CTX* ctx);

/**
 * @brief Add data to the SHA-256 hash computation
 *
 * Can be called multiple times to hash data incrementally.
 * Internally buffers data until a full 64-byte block is available.
 *
 * @param ctx Initialized SHA-256 context
 * @param data Pointer to data to hash
 * @param len Number of bytes to hash
 */
void SHA256_update(SHA256_CTX* ctx, const void* data, int len);

/**
 * @brief Finalize the hash and return the digest
 *
 * Applies the standard SHA-256 padding:
 * 1. Append '1' bit (0x80 byte)
 * 2. Pad with zeros to 56 bytes mod 64
 * 3. Append 64-bit message length in bits
 *
 * @param ctx SHA-256 context
 * @return Pointer to 32-byte digest (stored in ctx->buf)
 */
const uint8_t* SHA256_final(SHA256_CTX* ctx);

/**
 * @brief Compute SHA-256 hash in a single call
 *
 * Convenience function for hashing data all at once.
 *
 * @param data Pointer to data to hash
 * @param len Number of bytes to hash
 * @param digest Buffer for 32-byte result (must be >= SHA256_DIGEST_SIZE)
 * @return Pointer to digest
 */
// Convenience method. Returns digest address.
const uint8_t* SHA256_hash(const void* data, int len, uint8_t* digest);

/**
 * @brief SHA-256 digest size in bytes (256 bits)
 */
#define SHA256_DIGEST_SIZE 32

#ifdef __cplusplus
}
#endif // __cplusplus

#endif  // SECURITY_UTIL_LITE_SHA256_H__
