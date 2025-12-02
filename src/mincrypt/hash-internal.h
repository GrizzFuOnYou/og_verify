/**
 * @file hash-internal.h
 * @brief Internal Hash Algorithm Interface
 *
 * This header defines a generic interface for hash functions used in the
 * mincrypt library. It provides a polymorphic interface that allows the
 * same code to work with different hash algorithms (SHA-1, SHA-256, etc.).
 *
 * ## Design Pattern
 * This uses a virtual function table (vtable) pattern - the HASH_VTAB
 * struct contains function pointers that can point to different hash
 * implementations. This allows writing generic code that works with
 * any hash algorithm without knowing which one it's using.
 *
 * ## Usage Example
 * ```c
 * HASH_CTX ctx;
 * SHA256_init(&ctx);  // Sets up ctx.f to point to SHA256 functions
 * 
 * // Now can use generic macros
 * HASH_update(&ctx, data, len);  // Calls ctx->f->update(ctx, data, len)
 * HASH_final(&ctx);              // Calls ctx->f->final(ctx)
 * ```
 *
 * ## Components
 * - HASH_VTAB: Virtual function table with pointers to hash operations
 * - HASH_CTX: Hash context with state, buffer, and vtable pointer
 * - HASH_* macros: Generic interface that dispatches through vtable
 *
 * @author Marius Schilder <mschilder@google.com>
 * @copyright 2007 Google Inc. All Rights Reserved.
 */

// Copyright 2007 Google Inc. All Rights Reserved.
// Author: mschilder@google.com (Marius Schilder)

#ifndef SECURITY_UTIL_LITE_HASH_INTERNAL_H__
#define SECURITY_UTIL_LITE_HASH_INTERNAL_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

struct HASH_CTX;  // forward decl

/**
 * @brief Virtual function table for hash algorithms
 *
 * Contains function pointers for all hash operations. Each hash algorithm
 * (SHA-1, SHA-256) provides its own HASH_VTAB with pointers to its
 * implementation functions.
 *
 * @note 'const' on the function pointers makes them read-only once set
 */
typedef struct HASH_VTAB {
  void (* const init)(struct HASH_CTX*);              /**< Initialize context */
  void (* const update)(struct HASH_CTX*, const void*, int);  /**< Add data */
  const uint8_t* (* const final)(struct HASH_CTX*);   /**< Finalize and get hash */
  const uint8_t* (* const hash)(const void*, int, uint8_t*);  /**< One-shot hash */
  int size;  /**< Digest size in bytes (20 for SHA-1, 32 for SHA-256) */
} HASH_VTAB;

/**
 * @brief Generic hash context structure
 *
 * This structure holds all state for an ongoing hash computation.
 * It's designed to accommodate both SHA-1 (5 state words, 20-byte digest)
 * and SHA-256 (8 state words, 32-byte digest).
 *
 * Fields:
 *   f:     Pointer to vtable for this hash algorithm
 *   count: Total bytes hashed so far (used for padding)
 *   buf:   Buffer for partial blocks (64 bytes = 512 bits)
 *   state: Hash state (5 words for SHA-1, 8 for SHA-256)
 *
 * @note buf is also used to hold the final digest after calling final()
 */
typedef struct HASH_CTX {
  const HASH_VTAB * f;    /**< Virtual function table pointer */
  uint64_t count;         /**< Total bytes processed */
  uint8_t buf[64];        /**< Block buffer / final digest */
  uint32_t state[8];      /**< Hash state (up to 8 words for SHA-256) */
} HASH_CTX;

/**
 * @name Generic Hash Macros
 * @{
 *
 * These macros provide a generic interface to hash functions.
 * They dispatch calls through the vtable pointer, allowing
 * algorithm-agnostic code.
 */
#define HASH_init(ctx) (ctx)->f->init(ctx)
#define HASH_update(ctx, data, len) (ctx)->f->update(ctx, data, len)
#define HASH_final(ctx) (ctx)->f->final(ctx)
#define HASH_hash(data, len, digest) (ctx)->f->hash(data, len, digest)
#define HASH_size(ctx) (ctx)->f->size
/** @} */

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // SECURITY_UTIL_LITE_HASH_INTERNAL_H__
