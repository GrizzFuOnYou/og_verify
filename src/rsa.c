/**
 * @file rsa.c
 * @brief RSA Digital Signature Verification Implementation
 *
 * This file implements RSA signature verification using the PKCS#1 v1.5
 * padding scheme. It is optimized for embedded systems and specifically
 * designed to verify DJI firmware signatures.
 *
 * ## Overview
 * RSA (Rivest-Shamir-Adleman) is an asymmetric cryptographic algorithm.
 * DJI uses RSA-2048 with SHA-256 to sign firmware images:
 * 1. The firmware header is hashed with SHA-256 (32 bytes)
 * 2. The hash is padded using PKCS#1 v1.5 (to 256 bytes)
 * 3. The padded hash is encrypted with DJI's private key (the "signature")
 *
 * To verify:
 * 1. Decrypt the signature using the public key (modular exponentiation)
 * 2. Check that the decrypted value matches the expected PKCS#1 padding
 * 3. Verify the hash at the end matches our computed hash
 *
 * ## Montgomery Multiplication
 * This implementation uses Montgomery multiplication for efficient modular
 * arithmetic. Instead of computing (a * b) mod n directly (which requires
 * expensive division), Montgomery multiplication transforms numbers into
 * a special representation where modular multiplication becomes faster.
 *
 * The key insight is that division by 2^k is just a bit shift, so if we
 * choose our representation carefully, we can avoid expensive divisions.
 *
 * ## Key Components
 * - n0inv: Precomputed value for Montgomery reduction (-1/n[0] mod 2^32)
 * - rr[]: Precomputed R^2 mod n for converting to Montgomery form
 * - modpow(): Computes signature^exponent mod n using repeated squaring
 *
 * @author The Android Open Source Project
 * @copyright 2012, BSD License
 * @see https://en.wikipedia.org/wiki/Montgomery_modular_multiplication
 * @see https://en.wikipedia.org/wiki/PKCS_1
 *
 * @note This code comes from Android's mincrypt library, optimized for
 *       embedded boot verification where code size matters.
 */

/* rsa.c
**
** Copyright 2012, The Android Open Source Project
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

#include "mincrypt/rsa.h"
#include "mincrypt/sha.h"
#include "mincrypt/sha256.h"

/* ==========================================================================
 * MONTGOMERY ARITHMETIC FUNCTIONS
 * ==========================================================================
 * These functions implement Montgomery multiplication, an efficient method
 * for computing (a * b) mod n without expensive division operations.
 *
 * Montgomery representation: For a number x, its Montgomery form is (x * R) mod n
 * where R = 2^(32 * len) for a len-word modulus.
 *
 * The key operations are:
 * - montMulAdd: Add a * b * R^(-1) mod n to an accumulator
 * - montMul: Compute a * b * R^(-1) mod n
 * - subM: Subtract the modulus if result >= modulus
 * - geM: Check if a value >= modulus
 * ========================================================================== */

/**
 * @brief Subtract the modulus from a number
 *
 * Computes a[] = a[] - n where n is the RSA modulus.
 * Used when a result might be >= n and needs to be reduced.
 *
 * @param key RSA public key containing the modulus n
 * @param a Array to subtract from (modified in place)
 *
 * @note Uses signed arithmetic to handle borrow propagation
 */
// a[] -= mod
static void subM(const RSAPublicKey* key,
                 uint32_t* a) {
    int64_t A = 0;
    int i;
    for (i = 0; i < key->len; ++i) {
        A += (uint64_t)a[i] - key->n[i];
        a[i] = (uint32_t)A;
        A >>= 32;  /* Propagate borrow to next word */
    }
}

/**
 * @brief Check if a number is greater than or equal to the modulus
 *
 * Compares a[] against n[] to determine if a reduction is needed.
 * Comparison is done from most significant word to least significant.
 *
 * @param key RSA public key containing the modulus n
 * @param a Array to compare
 * @return 1 if a >= n, 0 otherwise
 */
// return a[] >= mod
static int geM(const RSAPublicKey* key,
               const uint32_t* a) {
    int i;
    for (i = key->len; i;) {
        --i;
        if (a[i] < key->n[i]) return 0;
        if (a[i] > key->n[i]) return 1;
    }
    return 1;  // equal
}

/**
 * @brief Montgomery multiply-add operation
 *
 * Computes c[] = c[] + (a * b[] * R^(-1)) mod n
 *
 * This is the core operation of Montgomery multiplication. It:
 * 1. Multiplies scalar 'a' by array 'b[]'
 * 2. Adds the result to accumulator 'c[]'
 * 3. Reduces modulo n using Montgomery reduction
 *
 * The reduction works by:
 * 1. Computing d0 = (low word of result) * n0inv mod 2^32
 * 2. Adding d0 * n to make the low word zero
 * 3. Shifting right by 32 bits (dividing by 2^32)
 *
 * @param key RSA public key containing modulus and n0inv
 * @param c Accumulator array (modified in place)
 * @param a Scalar multiplier
 * @param b Array to multiply
 *
 * @note n0inv = -1/n[0] mod 2^32, precomputed for this modulus
 */
// montgomery c[] += a * b[] / R % mod
static void montMulAdd(const RSAPublicKey* key,
                       uint32_t* c,
                       const uint32_t a,
                       const uint32_t* b) {
    uint64_t A = (uint64_t)a * b[0] + c[0];
    uint32_t d0 = (uint32_t)A * key->n0inv;  /* Montgomery reduction factor */
    uint64_t B = (uint64_t)d0 * key->n[0] + (uint32_t)A;
    int i;

    for (i = 1; i < key->len; ++i) {
        A = (A >> 32) + (uint64_t)a * b[i] + c[i];
        B = (B >> 32) + (uint64_t)d0 * key->n[i] + (uint32_t)A;
        c[i - 1] = (uint32_t)B;
    }

    A = (A >> 32) + (B >> 32);

    c[i - 1] = (uint32_t)A;

    /* If there was a carry, subtract the modulus */
    if (A >> 32) {
        subM(key, c);
    }
}

/**
 * @brief Montgomery multiplication
 *
 * Computes c[] = (a[] * b[]) * R^(-1) mod n
 *
 * Multiplies two numbers in Montgomery representation and returns
 * the product, still in Montgomery representation.
 *
 * @param key RSA public key containing the modulus
 * @param c Output array for the product
 * @param a First multiplicand array
 * @param b Second multiplicand array
 */
// montgomery c[] = a[] * b[] / R % mod
static void montMul(const RSAPublicKey* key,
                    uint32_t* c,
                    const uint32_t* a,
                    const uint32_t* b) {
    int i;
    /* Initialize accumulator to zero */
    for (i = 0; i < key->len; ++i) {
        c[i] = 0;
    }
    /* Multiply word by word, accumulating with Montgomery reduction */
    for (i = 0; i < key->len; ++i) {
        montMulAdd(key, c, a[i], b);
    }
}

/**
 * @brief In-place modular exponentiation for RSA
 *
 * Computes inout[] = inout[]^exponent mod n
 *
 * This is the core RSA operation. For signature verification,
 * we compute signature^e mod n where e is the public exponent.
 *
 * ## Algorithm
 * Uses Montgomery multiplication with square-and-multiply:
 * 1. Convert input to Montgomery form: aR = a * R mod n
 * 2. For e=65537 = 2^16 + 1:
 *    - Square 16 times to get a^(2^16) in Montgomery form
 *    - Multiply by original a to get a^(2^16 + 1) = a^65537
 * 3. Convert back from Montgomery form
 *
 * For e=3:
 * - Compute a^2, then a^3 = a^2 * a
 *
 * @param key RSA public key with modulus, rr[], exponent
 * @param inout Big-endian byte array (input signature, output decrypted)
 *
 * @note The rr[] field contains R^2 mod n, precomputed for efficiency.
 *       Multiplying by rr converts a number to Montgomery form.
 */
// In-place public exponentiation.
// Input and output big-endian byte array in inout.
static void modpow(const RSAPublicKey* key,
                   uint8_t* inout) {
    uint32_t a[RSANUMWORDS];     /* Input in little-endian word form */
    uint32_t aR[RSANUMWORDS];    /* a in Montgomery form */
    uint32_t aaR[RSANUMWORDS];   /* Temp for squaring */
    uint32_t* aaa = 0;           /* Final result pointer */
    int i;

    /* Convert from big-endian byte array to little-endian word array */
    for (i = 0; i < key->len; ++i) {
        uint32_t tmp =
            (inout[((key->len - 1 - i) * 4) + 0] << 24) |
            (inout[((key->len - 1 - i) * 4) + 1] << 16) |
            (inout[((key->len - 1 - i) * 4) + 2] << 8) |
            (inout[((key->len - 1 - i) * 4) + 3] << 0);
        a[i] = tmp;
    }

    if (key->exponent == 65537) {
        /*
         * Compute a^65537 = a^(2^16) * a
         * 65537 = 0x10001 in binary, so we need 16 squarings and one multiply
         */
        aaa = aaR;  /* Re-use location for final result */
        montMul(key, aR, a, key->rr);  /* aR = a * R mod n (convert to Montgomery form) */
        for (i = 0; i < 16; i += 2) {
            montMul(key, aaR, aR, aR);  /* aaR = aR^2 / R mod n */
            montMul(key, aR, aaR, aaR);  /* aR = aaR^2 / R mod n (two squarings per loop) */
        }
        montMul(key, aaa, aR, a);  /* aaa = aR * a / R = a^65537 mod n (convert back) */
    } else if (key->exponent == 3) {
        /*
         * Compute a^3 = a^2 * a
         */
        aaa = aR;  /* Re-use location */
        montMul(key, aR, a, key->rr);  /* aR = a * R mod n */
        montMul(key, aaR, aR, aR);     /* aaR = aR^2 / R = a^2 * R mod n */
        montMul(key, aaa, aaR, a);     /* aaa = aaR * a / R = a^3 mod n */
    }

    /* Ensure result is less than modulus (reduce if needed) */
    // Make sure aaa < mod; aaa is at most 1x mod too large.
    if (geM(key, aaa)) {
        subM(key, aaa);
    }

    /* Convert back to big-endian byte array */
    // Convert to bigendian byte array
    for (i = key->len - 1; i >= 0; --i) {
        uint32_t tmp = aaa[i];
        *inout++ = tmp >> 24;
        *inout++ = tmp >> 16;
        *inout++ = tmp >> 8;
        *inout++ = tmp >> 0;
    }
}

/* ==========================================================================
 * PKCS#1 v1.5 PADDING VERIFICATION
 * ==========================================================================
 * PKCS#1 v1.5 defines a standard format for RSA signature padding:
 *
 * 0x00 0x01 [0xFF padding bytes...] 0x00 [DigestInfo] [Hash]
 *
 * Where DigestInfo is an ASN.1 structure identifying the hash algorithm.
 *
 * For SHA-256 with RSA-2048 (256 bytes total):
 * - Bytes 0-1: 0x00 0x01 (block type for signature)
 * - Bytes 2-203: 0xFF padding (202 bytes)
 * - Byte 204: 0x00 (separator)
 * - Bytes 205-223: DigestInfo for SHA-256
 * - Bytes 224-255: 32-byte SHA-256 hash
 *
 * To verify without storing the full 256-byte padding template:
 * 1. XOR the hash bytes with zero (making them all-zero)
 * 2. Hash the resulting buffer with SHA-256
 * 3. Compare against a precomputed hash of the expected padding
 *
 * This saves ~200 bytes of constant data at the cost of an extra hash.
 * ========================================================================== */

/**
 * Expected PKCS#1 v1.5 signature padding bytes for SHA-1 (commented out)
 *
 * This 256-byte template shows the full padding structure:
 * - 0x00 0x01: Block type
 * - 0xFF...: Padding (varies by hash size)
 * - 0x00: Separator
 * - 0x30 0x21 0x30 0x09...: ASN.1 DigestInfo for SHA-1
 * - Last 20 bytes: Hash placeholder (zeros)
 */
// Expected PKCS1.5 signature padding bytes, for a keytool RSA signature.
// Has the 0-length optional parameter encoded in the ASN1 (as opposed to the
// other flavor which omits the optional parameter entirely). This code does not
// accept signatures without the optional parameter.

/*
static const uint8_t sha_padding[RSANUMBYTES] = {
    0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x30, 0x21, 0x30,
    0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a,
    0x05, 0x00, 0x04, 0x14,

    // 20 bytes of hash go here.
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};
*/

/**
 * @brief Precomputed SHA-1 hash of the PKCS#1 SHA-1 padding (with zero hash)
 *
 * Instead of storing the full 256-byte padding template, we store just
 * the 20-byte SHA-1 hash of that template (with the hash portion zeroed).
 * This saves memory at the cost of one extra hash computation.
 */
// SHA-1 of PKCS1.5 signature sha_padding for 2048 bit, as above.
// At the location of the bytes of the hash all 00 are hashed.
static const uint8_t kExpectedPadShaRsa2048[SHA_DIGEST_SIZE] = {
    0xdc, 0xbd, 0xbe, 0x42, 0xd5, 0xf5, 0xa7, 0x2e,
    0x6e, 0xfc, 0xf5, 0x5d, 0xaf, 0x9d, 0xea, 0x68,
    0x7c, 0xfb, 0xf1, 0x67
};

/**
 * Expected PKCS#1 v1.5 signature padding bytes for SHA-256 (commented out)
 *
 * Similar to sha_padding but with SHA-256 DigestInfo:
 * - Different ASN.1 OID for SHA-256
 * - 32 bytes for hash instead of 20
 */
/*
static const uint8_t sha256_padding[RSANUMBYTES] = {
    0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x30, 0x31, 0x30,
    0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,

    // 32 bytes of hash go here.
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
};
*/

/**
 * @brief Precomputed SHA-256 hash of the PKCS#1 SHA-256 padding (with zero hash)
 *
 * This is the SHA-256 hash of the full 256-byte PKCS#1 padding template
 * shown above, where the 32-byte hash portion is filled with zeros.
 *
 * Used to verify correct padding without storing the full template.
 */
// SHA-256 of PKCS1.5 signature sha256_padding for 2048 bit, as above.
// At the location of the bytes of the hash all 00 are hashed.
static const uint8_t kExpectedPadSha256Rsa2048[SHA256_DIGEST_SIZE] = {
    0xab, 0x28, 0x8d, 0x8a, 0xd7, 0xd9, 0x59, 0x92,
    0xba, 0xcc, 0xf8, 0x67, 0x20, 0xe1, 0x15, 0x2e,
    0x39, 0x8d, 0x80, 0x36, 0xd6, 0x6f, 0xf0, 0xfd,
    0x90, 0xe8, 0x7d, 0x8b, 0xe1, 0x7c, 0x87, 0x59,
};

/* ==========================================================================
 * PUBLIC API
 * ========================================================================== */

/**
 * @brief Verify an RSA PKCS#1 v1.5 signature
 *
 * This is the main public function for signature verification. It verifies
 * that a signature was created by the holder of the corresponding private key.
 *
 * ## Verification Process:
 * 1. Validate inputs (key length, signature length, hash type)
 * 2. Decrypt the signature using the public key (modular exponentiation)
 * 3. XOR the expected hash location with the provided hash (makes it zeros)
 * 4. Hash the entire decrypted block
 * 5. Compare against the precomputed expected padding hash
 *
 * ## Why this approach?
 * Instead of comparing the decrypted signature byte-by-byte against
 * the expected PKCS#1 padding, we:
 * 1. XOR the hash bytes (zeroing them out)
 * 2. Hash the result
 * 3. Compare against a precomputed hash of the expected padding
 *
 * This is a space optimization for embedded systems - we only need to
 * store a 32-byte hash instead of a 256-byte padding template.
 *
 * @param key Pointer to the RSA public key to verify with
 * @param signature The 256-byte RSA signature to verify
 * @param len Length of the signature (must be RSANUMBYTES = 256)
 * @param hash The expected hash value that was signed
 * @param hash_len Length of the hash (20 for SHA-1, 32 for SHA-256)
 *
 * @return 1 if signature is valid, 0 if verification failed
 *
 * @note Only supports RSA-2048 keys (len = 64 words)
 * @note Only supports exponents 3 and 65537
 * @note Only supports SHA-1 (20 bytes) and SHA-256 (32 bytes) hashes
 */
// Verify a 2048-bit RSA PKCS1.5 signature against an expected hash.
// Both e=3 and e=65537 are supported.  hash_len may be
// SHA_DIGEST_SIZE (== 20) to indicate a SHA-1 hash, or
// SHA256_DIGEST_SIZE (== 32) to indicate a SHA-256 hash.  No other
// values are supported.
//
// Returns 1 on successful verification, 0 on failure.
int RSA_verify(const RSAPublicKey *key,
               const uint8_t *signature,
               const int len,
               const uint8_t *hash,
               const int hash_len) {
    uint8_t buf[RSANUMBYTES];
    int i;
    const uint8_t* padding_hash;

    /* Validate key length - only support RSA-2048 */
    if (key->len != RSANUMWORDS) {
        return 0;  // Wrong key passed in.
    }

    /* Validate signature length */
    if (len != sizeof(buf)) {
        return 0;  // Wrong input length.
    }

    /* Validate hash type */
    if (hash_len != SHA_DIGEST_SIZE &&
        hash_len != SHA256_DIGEST_SIZE) {
        return 0;  // Unsupported hash.
    }

    /* Validate exponent */
    if (key->exponent != 3 && key->exponent != 65537) {
        return 0;  // Unsupported exponent.
    }

    /* Copy signature to local buffer for in-place processing */
    for (i = 0; i < len; ++i) {  // Copy input to local workspace.
        buf[i] = signature[i];
    }

    /* Decrypt: compute signature^e mod n */
    modpow(key, buf);  // In-place exponentiation.

    /*
     * XOR the hash portion with the expected hash
     * If the signature is valid, this zeroes out the hash bytes
     */
    // Xor sha portion, so it all becomes 00 iff equal.
    for (i = len - hash_len; i < len; ++i) {
        buf[i] ^= *hash++;
    }

    /*
     * Hash the result and compare against expected padding
     * The hash portion should now be zeros if the signature was valid
     */
    // Hash resulting buf, in-place.
    switch (hash_len) {
        case SHA_DIGEST_SIZE:
            padding_hash = kExpectedPadShaRsa2048;
            SHA_hash(buf, len, buf);
            break;
        case SHA256_DIGEST_SIZE:
            padding_hash = kExpectedPadSha256Rsa2048;
            SHA256_hash(buf, len, buf);
            break;
        default:
            return 0;
    }

    /* Compare computed hash against expected padding hash */
    // Compare against expected hash value.
    for (i = 0; i < hash_len; ++i) {
        if (buf[i] != padding_hash[i]) {
            return 0;
        }
    }

    return 1;  // All checked out OK.
}
