/**
 * @file sha.h
 * @brief SHA-1 Cryptographic Hash Function Header
 *
 * This header defines the interface for SHA-1 (Secure Hash Algorithm 1),
 * which produces a 160-bit (20-byte) hash value.
 *
 * ## WARNING: SHA-1 is Cryptographically Broken
 * SHA-1 should NOT be used for security-critical applications as of 2017.
 * Collision attacks have been demonstrated (SHAttered attack).
 * Use SHA-256 instead for new applications.
 *
 * This implementation is kept for compatibility with legacy systems and
 * for the RSA signature verification padding hash (which is not security
 * critical in this context).
 *
 * ## API Usage
 * ```c
 * SHA_CTX ctx;
 * uint8_t digest[SHA_DIGEST_SIZE];
 *
 * // Option 1: Incremental hashing
 * SHA_init(&ctx);
 * SHA_update(&ctx, data1, len1);
 * SHA_update(&ctx, data2, len2);
 * memcpy(digest, SHA_final(&ctx), SHA_DIGEST_SIZE);
 *
 * // Option 2: One-shot hashing
 * SHA_hash(data, len, digest);
 * ```
 *
 * @author Marius Schilder <mschilder@google.com>
 * @copyright 2005 Google Inc. All Rights Reserved.
 * @see sha256.h for the recommended alternative
 */

// Copyright 2005 Google Inc. All Rights Reserved.
// Author: mschilder@google.com (Marius Schilder)

#ifndef SECURITY_UTIL_LITE_SHA1_H__
#define SECURITY_UTIL_LITE_SHA1_H__

#include <stdint.h>
#include "hash-internal.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @brief SHA-1 context type
 *
 * This is an alias for the generic HASH_CTX structure.
 * The SHA-1 implementation uses 5 of the 8 state words.
 */
typedef HASH_CTX SHA_CTX;

/**
 * @brief Initialize a SHA-1 hash context
 *
 * Sets up the context with initial hash values and clears the buffer.
 *
 * @param ctx Pointer to context to initialize
 */
void SHA_init(SHA_CTX* ctx);

/**
 * @brief Add data to the SHA-1 hash computation
 *
 * Can be called multiple times to hash data incrementally.
 *
 * @param ctx Initialized SHA-1 context
 * @param data Pointer to data to hash
 * @param len Number of bytes to hash
 */
void SHA_update(SHA_CTX* ctx, const void* data, int len);

/**
 * @brief Finalize the hash and return the digest
 *
 * Applies final padding and returns pointer to the 20-byte digest.
 * After calling this, the context should not be used again without
 * re-initialization.
 *
 * @param ctx SHA-1 context
 * @return Pointer to 20-byte digest (stored in ctx->buf)
 */
const uint8_t* SHA_final(SHA_CTX* ctx);

/**
 * @brief Compute SHA-1 hash in a single call
 *
 * Convenience function that combines init, update, and final.
 *
 * @param data Pointer to data to hash
 * @param len Number of bytes to hash
 * @param digest Buffer to receive 20-byte digest (must be >= SHA_DIGEST_SIZE)
 * @return Pointer to digest
 *
 * @note digest needs to hold SHA_DIGEST_SIZE bytes.
 */
// Convenience method. Returns digest address.
// NOTE: *digest needs to hold SHA_DIGEST_SIZE bytes.
const uint8_t* SHA_hash(const void* data, int len, uint8_t* digest);

/**
 * @brief SHA-1 digest size in bytes (160 bits)
 */
#define SHA_DIGEST_SIZE 20

#ifdef __cplusplus
}
#endif // __cplusplus

#endif  // SECURITY_UTIL_LITE_SHA1_H__
