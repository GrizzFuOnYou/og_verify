/**
 * @file verify.c
 * @brief DJI Firmware Image Verification and Decryption Tool
 *
 * This file contains the main logic for verifying and decrypting DJI firmware
 * images. It is part of the og_verify project, which allows users to verify
 * the cryptographic signatures of DJI firmware files and optionally decrypt
 * their contents.
 *
 * ## Purpose
 * DJI firmware images are cryptographically signed and often encrypted to
 * prevent unauthorized modifications. This tool:
 * 1. Verifies the RSA signature of the firmware header using SHA-256
 * 2. Validates the payload digest (hash) to ensure integrity
 * 3. Optionally decrypts the payload using AES encryption
 * 4. Outputs the decrypted firmware data
 *
 * ## How It Works
 * DJI firmware images consist of:
 * - A header containing metadata (magic number, version, sizes, encryption keys, etc.)
 * - An RSA signature of the header
 * - The encrypted or unencrypted payload (the actual firmware data)
 *
 * The verification process:
 * 1. Parse the header and validate the magic number "IM*H"
 * 2. Look up the appropriate RSA public key based on the auth_key field
 * 3. Compute SHA-256 hash of the header
 * 4. Verify the RSA signature matches the computed hash
 * 5. Compute SHA-256 hash of the payload and compare with stored digest
 * 6. If outputting, decrypt using AES if needed (using scramble key decryption)
 *
 * ## Key Types
 * - PRAK: Production Release Authentication Key (for official firmware)
 * - GFAK: Ground Factory Authentication Key
 * - SLAK: Slack Authentication Key (used by this project for custom signing)
 * - PUEK: Production Unit Encryption Key
 * - SLEK: Slack Encryption Key (used by this project for custom encryption)
 *
 * ## Usage
 * ```
 * og_verify -n <image_name> [-c <chunk_name>] [-H <header_file>] [-o <output>] <input_file>
 * ```
 *
 * @author Jan Dumon <jan@crossbar.net>
 * @copyright Copyright (C) 2018, GPL-3.0 License
 *
 * @note This tool is part of the Open Goggles (OG) project for DJI firmware
 *       modification. It is intended for educational and research purposes.
 */

/*  Copyright (C) 2018  Jan Dumon <jan@crossbar.net>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* ==========================================================================
 * INCLUDE HEADERS
 * ========================================================================== */

#include <stdlib.h>
#include <stdio.h>      /* printf, fprintf for console output */
#include <unistd.h>     /* write, close for file operations */
#include <stdint.h>     /* uint8_t, uint32_t, uint64_t for fixed-width integers */
#include <getopt.h>     /* getopt_long for command-line argument parsing */
#include <fcntl.h>      /* open, O_RDONLY, O_CREAT for file operations */
#include <string.h>     /* strcmp, memcmp for string/memory operations */
#include <sys/stat.h>   /* fstat for getting file information */
#include <sys/mman.h>   /* mmap for memory-mapping files */
#include <errno.h>      /* errno, strerror for error handling */

/* Project-specific cryptographic library headers */
#include "mincrypt/rsa.h"    /* RSA signature verification */
#include "mincrypt/sha256.h" /* SHA-256 hashing */
#include "aes.h"             /* AES encryption/decryption */

/* ==========================================================================
 * UTILITY MACROS
 * ========================================================================== */

/**
 * @brief Returns the minimum of two values
 * @param a First value
 * @param b Second value
 * @return The smaller of a or b
 */
#define min(a, b) ((a) < (b) ? (a) : (b))

/* ==========================================================================
 * DJI IMAGE STRUCTURES
 * ==========================================================================
 * These structures define the binary layout of DJI firmware image headers.
 * All multi-byte fields are little-endian as DJI devices use ARM processors.
 * ========================================================================== */

/**
 * @brief Chunk attribute flags for DJI image chunks
 *
 * DJI_IMAGE_CHUNK_CLEAR indicates that the chunk is NOT encrypted and can
 * be read directly without AES decryption. If this flag is not set, the
 * chunk data must be decrypted using the scramble key.
 */
enum dji_image_chunk_attr {
    DJI_IMAGE_CHUNK_CLEAR = 0x1,  /**< Chunk is unencrypted (cleartext) */
};

/**
 * @brief DJI image chunk descriptor
 *
 * A firmware image can contain multiple chunks (segments). Each chunk has
 * its own ID, size, memory address, and attributes. The chunk structure
 * follows immediately after the main header in memory.
 *
 * @note Chunks can be loaded to different memory addresses on the target device
 * @note The 'reserved' field is unused but must be present for alignment
 */
struct dji_image_chunk {
    uint32_t id;        /**< 4-character chunk identifier (e.g., "0100" for main firmware) */
    uint32_t offset;    /**< Offset of this chunk's data from start of payload */
    uint32_t size;      /**< Size of the chunk data in bytes */
    uint32_t attr;      /**< Chunk attributes (see dji_image_chunk_attr) */
    uint64_t addr;      /**< Target memory address where chunk should be loaded */
    uint64_t reserved;  /**< Reserved for future use, should be 0 */
};

typedef struct dji_image_chunk dji_image_chunk_t;

/**
 * @brief DJI firmware image header structure
 *
 * This is the main header structure for DJI firmware images. It contains
 * all metadata needed to verify, decrypt, and load the firmware.
 *
 * ## Header Layout (192 bytes base + variable chunk array):
 * - Bytes 0-3:   Magic number "IM*H"
 * - Bytes 4-7:   Header version (typically 1)
 * - Bytes 8-11:  Total image size
 * - Bytes 16-19: Header size (192 bytes + chunk array)
 * - Bytes 20-23: Signature size (256 bytes for RSA-2048)
 * - Bytes 24-27: Payload size (encrypted/compressed firmware data)
 * - Bytes 40-43: Authentication key identifier (e.g., "PRAK", "SLAK")
 * - Bytes 44-47: Encryption key identifier (e.g., "PUEK", "SLEK")
 * - Bytes 48-63: Scramble key (AES key encrypted with enc_key)
 * - Bytes 64-95: Image name (null-terminated string)
 * - Bytes 160-191: SHA-256 digest of payload
 *
 * @note The chunk[] array is variable-length based on chunk_num
 */
struct dji_image_header {
    uint32_t magic_num;       /**< Magic number: "IM*H" (0x482A4D49 little-endian) */
    uint32_t header_version;  /**< Header format version (1 = current) */
    uint32_t size;            /**< Total image size: header + signature + payload */
    uint32_t reserved;        /**< Reserved, should be 0 */
    uint32_t header_size;     /**< Size of header including chunk descriptors */
    uint32_t signature_size;  /**< RSA signature size (256 bytes for RSA-2048) */
    uint32_t payload_size;    /**< Size of the payload data */
    uint32_t target_size;     /**< Expected size after decompression */
    uint8_t os;               /**< Target OS (0=bare metal, 1=Linux, etc.) */
    uint8_t arch;             /**< Target architecture (0=ARM, etc.) */
    uint8_t compression;      /**< Compression type (0=none, 1=gzip, etc.) */
    uint8_t anti_version;     /**< Anti-rollback version counter */
    uint32_t auth_alg;        /**< Authentication algorithm (1=RSA-SHA256) */
    uint32_t auth_key;        /**< Authentication key ID (e.g., 'PRAK', 'SLAK') */
    uint32_t enc_key;         /**< Encryption key ID (e.g., 'PUEK', 'SLEK') */
    uint8_t scram_key[16];    /**< AES-128 scramble key (encrypted with enc_key) */
    uint8_t name[32];         /**< Null-terminated image name */
    uint32_t type;            /**< Image type identifier */
    uint32_t version;         /**< Firmware version (BCD encoded) */
    uint32_t date;            /**< Build date (BCD encoded: YYYYMMDD) */
    uint32_t reserved2[5];    /**< Reserved fields */
    uint32_t userdata[4];     /**< User-defined data fields */
    uint64_t entry;           /**< Entry point address for executable images */
    uint32_t reserved3;       /**< Reserved */
    uint32_t chunk_num;       /**< Number of chunks in the chunk array */
    uint8_t payload_digest[32]; /**< SHA-256 hash of the payload for integrity */
    dji_image_chunk_t chunk[];  /**< Variable-length array of chunk descriptors */
};

typedef struct dji_image_header dji_image_header_t;

/* ==========================================================================
 * BYTE ORDER CONVERSION MACROS
 * ==========================================================================
 * DJI uses 4-character identifiers stored as 32-bit integers. These macros
 * convert between string literals and their integer representations.
 * ========================================================================== */

/**
 * @brief Swap bytes in a 32-bit integer (little-endian <-> big-endian)
 *
 * This macro reverses the byte order of a 32-bit value. For example:
 * - Input:  0x12345678
 * - Output: 0x78563412
 *
 * @param i 32-bit integer to swap
 * @return Byte-swapped 32-bit integer
 */
#define SWAP(i) (((i) >> 24) | (((i) & 0x00ff0000 )>> 8) | (((i) & 0x0000ff00) << 8) | ((i) << 24))

/**
 * @brief Convert a 4-character string literal to a 32-bit identifier
 *
 * DJI uses 4-character codes like "PRAK", "SLAK", "IM*H" as identifiers.
 * This macro converts these to their integer form for comparison.
 *
 * Example: STR2ID('IM*H') produces the magic number for header validation.
 *
 * @param n 4-character string (as multi-char literal)
 * @return 32-bit integer representation
 */
#define STR2ID(n) SWAP((uint32_t)n)

/* ==========================================================================
 * CRYPTOGRAPHIC KEYS
 * ==========================================================================
 * These are the encryption and authentication keys used by DJI firmware.
 * Different keys are used for different purposes and device families.
 *
 * SECURITY NOTE: These keys are extracted from DJI firmware and hardware.
 * They are included here for educational and research purposes only.
 * ========================================================================== */

/**
 * @brief PUEK - Production Unit Encryption Key (commented out)
 *
 * This was the encryption key used for Goggles RE (Racing Edition).
 * Different DJI product lines use different encryption keys.
 */
/* GogglesRE */
//static uint8_t PUEK[16] = { 0x77, 0x0d, 0xe4, 0xe3, 0xcc, 0x0c, 0x95, 0x7b, 0x03, 0x00, 0x6f, 0xfe, 0x02, 0xa3, 0xd4, 0x66 };

/**
 * @brief PUEK - Production Unit Encryption Key (Mavic)
 *
 * This 16-byte AES-128 key is used to decrypt the scramble key stored
 * in the firmware header. The scramble key is then used to decrypt
 * the actual firmware payload.
 *
 * This specific key is for Mavic series drones.
 */
/* Mavic */
static uint8_t PUEK[16] = { 0x63, 0xc4, 0x8e, 0x83, 0x26, 0x7e, 0xee, 0xc0, 0x3f, 0x33, 0x30, 0xad, 0xb2, 0x38, 0xdd, 0x6b };

/**
 * @brief SLEK - Slack Encryption Key
 *
 * This is the encryption key used by the og_verify project for custom
 * firmware signing. When you sign firmware with sign.py, it uses this
 * key to encrypt the scramble key.
 *
 * "Slack" refers to the Slack community where this project originated.
 */
static uint8_t SLEK[16] = { 0x56, 0x79, 0x6C, 0x0E, 0xEE, 0x0F, 0x38, 0x05, 0x20, 0xE0, 0xBE, 0x70, 0xF2, 0x77, 0xD9, 0x0B };

/**
 * @brief PRAK - Production Release Authentication Key
 *
 * This is the RSA-2048 public key used by DJI to sign official firmware.
 * The firmware header is hashed with SHA-256 and the hash is signed with
 * the corresponding private key (which only DJI possesses).
 *
 * ## RSAPublicKey Structure Explained:
 * - len: Number of 32-bit words in the modulus (64 for 2048-bit RSA)
 * - n0inv: Precomputed value for Montgomery multiplication optimization
 *          This is -1/n[0] mod 2^32, used to speed up modular arithmetic
 * - n[]: The RSA modulus (public key N) as a little-endian array
 * - rr[]: Precomputed R^2 mod N for Montgomery multiplication
 *         R = 2^(32*len), this speeds up the modular exponentiation
 * - exponent: Public exponent (65537 is standard, 3 is also supported)
 *
 * @note These precomputed values allow signature verification to be
 *       performed efficiently without expensive division operations.
 */
static RSAPublicKey PRAK = {
    .len = 64,
    .n0inv = 0x411615c3l,
    .n = {
        0x44307d15, 0x5889ee8f, 0x2e3384d6, 0x3c21288b, 0x23c905db, 0x2dfe6ae0, 0x481b3713, 0x2f87c287,
        0x4974d67f, 0x1700250e, 0xcf9f3a18, 0xdd9f10b4, 0x5f556ad8, 0x8db074c8, 0xb7c41964, 0xb8037efa,
        0x8fa006f1, 0x268c1e57, 0x23fc32a5, 0x7f0ddde1, 0x5296d4e4, 0x50bc083b, 0x6b8a23d9, 0x377db5aa,
        0xfd3a3fa1, 0x8b4c2891, 0x5eb4e298, 0xcbbd87cb, 0x76d891e6, 0x2977904f, 0x0d6c230b, 0xebb2f48d,
        0x66f3a23b, 0xee7a9671, 0x63c24efb, 0x50d7e4c9, 0x607fd906, 0x4888eba5, 0x7d70424b, 0xa1b9280a,
        0xcf6a5216, 0x7e8ec98b, 0x9aa0aa97, 0xb6c8e2a5, 0x2c7aabaa, 0x733c2821, 0xd7ec68d6, 0xebb824f0,
        0xa578f2ba, 0x64a0b687, 0x03075d52, 0x8d2eb6c5, 0x5956b6f7, 0xff87cb13, 0x78e56eb9, 0x9c32a5d8,
        0xc11c8393, 0xa4047185, 0x5b9dbaf2, 0x03a55500, 0x466fc405, 0x1a64d49a, 0x948fa91f, 0x94fdbd92 },
    .rr = {
        0xfccb94e0, 0x4bb05ad9, 0x0040f3d7, 0x20edde10, 0x1d36cdcf, 0xda5f2fdb, 0x28a7ad87, 0xd79cfb5a,
        0xda531952, 0x88b273db, 0xec00fbed, 0x789e76dd, 0x9442cad2, 0xc1906564, 0xb854598d, 0xfd0bd046,
        0xf9302e68, 0x1f0de170, 0x24e760e9, 0x47053a02, 0xd98ca64e, 0x2f588d73, 0x561839cb, 0xa65bc83a,
        0xff647941, 0x0a71f1fa, 0x875d2f3d, 0x7624500b, 0xabc21248, 0xf84cf26f, 0x20d2e60e, 0x37a316c7,
        0xc9d9bca4, 0x5e7be104, 0xf66e229f, 0x06354a99, 0x7a8cee35, 0x20d8136f, 0x1e7cb8f9, 0x6e20baf8,
        0x7ee15678, 0xd67e9a1d, 0x7c3cb2b7, 0x969d0014, 0xde75a722, 0x1ddc5f57, 0xdf579ed1, 0x815cc690,
        0x5fb00ca8, 0x808031a7, 0x9bff1da6, 0x6722850d, 0xfdc6e8d6, 0x87271e53, 0x29ffb7ba, 0xf2388a81,
        0x16b4c2e6, 0x3b1cf198, 0xc64a0c2a, 0x426a966a, 0x7cce3bce, 0xcc1e5f8d, 0x55ff4395, 0x3bdf09f3 },
    .exponent = 65537
};

/**
 * @brief GFAK - Ground Factory Authentication Key
 *
 * This RSA-2048 public key is used for factory firmware images.
 * The structure is identical to PRAK but with different key values.
 */
static RSAPublicKey GFAK = {
    .len = 64,
    .n0inv = 0x88a8579b,
    .n = {
        0x043ec96d, 0x8e80141e, 0x3710d838, 0x4869976d, 0x4a4b78e8, 0x814846c0, 0x99abc3fc, 0x397512c6,
        0xeb63c91e, 0x6a3d8ed5, 0xfc60c44e, 0x27dbe11a, 0x70f89c0d, 0x639e87fc, 0xe699713b, 0x2e87f4a2,
        0xf21dfcfa, 0x02b37473, 0x213f3519, 0x752e97d8, 0x0a04b5fe, 0x2f48b250, 0xdf916525, 0x56aac663,
        0xb20633a6, 0x8f11ce96, 0x152e3ab4, 0x455aa392, 0x13490479, 0xc6a17fa4, 0x05fa3f84, 0x7d1bb47f,
        0x5da9e409, 0x39bc8a21, 0x96e26cc6, 0xa8e82586, 0xf9fe6542, 0xaab8ba51, 0x9f85b223, 0x4226fcdf,
        0xc98dce6a, 0x634cdd3f, 0x7468f584, 0xc83bdd40, 0xd69e18c7, 0xb5a963d4, 0x704d8f46, 0x76fd4dd5,
        0xc8ad80e6, 0x94c384ff, 0x1f7d6e41, 0xf978233a, 0x8ac4ef93, 0xcd5a9929, 0x06305817, 0xc370a274,
        0x1dccea0c, 0x523f8af6, 0xe81267ca, 0x44cfbaea, 0xb91905f1, 0x903120e3, 0xa9e8e8c4, 0xc9f187bf },
    .rr = {
        0xf0382849, 0x662ca4e7, 0x4d147351, 0xf175d403, 0x939447d9, 0x80dab27b, 0xd0ceb697, 0xaa70d3f9,
        0x2ca98a57, 0xcd197a29, 0xe954085a, 0xd3a9f57c, 0x8145665f, 0x1807169a, 0x0207c2f6, 0x40425dd3,
        0x240d9bae, 0x73590684, 0xb4dd0e89, 0x19beb4a8, 0xccd7cda8, 0x07715552, 0xc12f5da6, 0x7ac8e3bf,
        0xad685d16, 0x3901592f, 0xfbc04101, 0xb2f7aef1, 0x75dd9ea8, 0x649b5707, 0x4eb98783, 0x5cf1e2ba,
        0x5e1efe96, 0x85ccf8cf, 0xf6a673ce, 0x0b26d77c, 0x079838c7, 0xbaedbaec, 0x8a169305, 0x48bbee03,
        0xb5c2fc05, 0xe3162bb7, 0x62978efd, 0x0be17bfc, 0x8dd98574, 0x13a88609, 0xa8fe77d7, 0x7e6d2408,
        0x87592a1a, 0xc2dddd17, 0x683d0151, 0x8e305e78, 0x1362d436, 0x6aa0d39f, 0x3b49c7d0, 0x82951a1a,
        0x5596d7de, 0x5539fd88, 0x1391ea56, 0x477c14a8, 0x5ae4afed, 0xdab7a830, 0x9eed0dce, 0x80933247 },
    .exponent = 65537
};

/**
 * @brief SLAK - Slack Authentication Key
 *
 * This RSA-2048 public key corresponds to the private key embedded in
 * sign.py. It's used for custom firmware signing by the og_verify project.
 *
 * When you sign firmware with sign.py, the signature can be verified
 * using this public key. This allows custom/modified firmware to pass
 * signature verification when using og_verify.
 *
 * @note The corresponding private key is in sign.py as SLAK (PEM format)
 */
static RSAPublicKey SLAK = {
    .len = 64,
    .n0inv = 0x4dccc885,
    .n = {
        0x56d00fb3, 0x1efc92b2, 0x062e908a, 0x663197ef, 0xefe0714c, 0x8e583b2a, 0xb148acc7, 0xde4597fa,
        0x3890bf3b, 0x8776d728, 0x424907be, 0x4861a406, 0x48975931, 0xe9adc62a, 0x4518651c, 0x152e72e9,
        0x9bbd7fe9, 0xd692d9df, 0x371d14b2, 0xf8e9f085, 0xb984f906, 0x674157b4, 0x31f64067, 0xc575b465,
        0xf9ddb9f3, 0x908f2037, 0x1f35ba58, 0x0156313f, 0x80c56e52, 0x0b87e08b, 0x0ebddd39, 0x7a6d581e,
        0x210a3639, 0xd594e4b6, 0x362af9c1, 0x7d15d72b, 0x6552b5c4, 0xdc946f2b, 0xc929a794, 0x7c79955e,
        0x7b456193, 0x328d7678, 0x002b6e4f, 0xbb2711e7, 0xe34c442b, 0xacd8f454, 0x3f6dca18, 0x0f83e28d,
        0x94409794, 0x6c480fa0, 0x49c91c83, 0xa2b1f5f4, 0x936fa327, 0x53ea01be, 0xe2f845cf, 0x8681aaca,
        0x8745faef, 0x614dbb3d, 0xa7731236, 0x9c39f62d, 0xd59a4f17, 0xc5069fff, 0x668e20b5, 0xbb005e6d },
    .rr = {
        0x9cbb3077, 0xd852ac69, 0x5981f6c4, 0x635a16c3, 0x23445267, 0x8e818a79, 0x8968319b, 0x04926e22,
        0x2d4697e1, 0x0c86bf58, 0x80bf97f9, 0x255c8866, 0xa1b4ea26, 0x700ede02, 0x2ded0917, 0x0a3bd64b,
        0xefcc595c, 0x8321d8f3, 0x64687297, 0x9144198e, 0x0eda692a, 0x69861c64, 0x50176a76, 0x4c428793,
        0x7de983b0, 0x83b970cc, 0x14e8930c, 0x35809f46, 0xb1da3724, 0x164ca941, 0xe07af8f0, 0xaf680f31,
        0x72f89566, 0xa8c32e99, 0x2400bca0, 0xdeac27f7, 0x186d0286, 0xa3081315, 0x1384eff0, 0x6c5d922a,
        0xfac35cab, 0xe96eef63, 0xbe291e71, 0x2a29645a, 0x524d30eb, 0x64b0f34c, 0x94aa772f, 0x975aed87,
        0x7cff46a7, 0x78b1711b, 0x8b828e68, 0x24a45e86, 0x89f64464, 0x53db98c7, 0xc411f61a, 0x3243ea50,
        0xd3e0932c, 0xca218e23, 0x7fec8a84, 0x3aa9a221, 0x826d608c, 0xeef4f611, 0xb95e7c18, 0x07d4dd42 },
    .exponent = 65537
};

/* ==========================================================================
 * KEY LOOKUP TABLES
 * ==========================================================================
 * These tables map 4-character key identifiers to their actual key data.
 * When the firmware header specifies a key ID, we look it up here.
 * ========================================================================== */

/**
 * @brief Encryption key lookup table entry
 *
 * Maps encryption key identifiers (like "PUEK", "SLEK") to the actual
 * 16-byte AES keys used for decrypting the scramble key.
 */
static struct enc_key_entry {
    uint32_t key_id;  /**< 4-character key identifier as uint32_t */
    uint8_t  *key;    /**< Pointer to the 16-byte AES key */
} enc_keys[] = {
    { STR2ID('PUEK'), PUEK },  /**< Production Unit Encryption Key */
    { STR2ID('SLEK'), SLEK },  /**< Slack Encryption Key */
    { 0, NULL },               /**< Sentinel (end of list marker) */
};

/**
 * @brief Authentication key lookup table entry
 *
 * Maps authentication key identifiers (like "PRAK", "SLAK") to the actual
 * RSA public keys used for signature verification.
 */
static struct auth_key_entry {
    uint32_t key_id;      /**< 4-character key identifier as uint32_t */
    RSAPublicKey *key;    /**< Pointer to the RSA public key structure */
} auth_keys[] = {
    { STR2ID('PRAK'), &PRAK },  /**< Production Release Authentication Key */
    { STR2ID('GFAK'), &GFAK },  /**< Ground Factory Authentication Key */
    { STR2ID('SLAK'), &SLAK },  /**< Slack Authentication Key */
    { 0, NULL },                /**< Sentinel (end of list marker) */
};

/* ==========================================================================
 * UTILITY FUNCTIONS
 * ========================================================================== */

/**
 * @brief Convert a 32-bit key identifier to a printable string
 *
 * This function takes a 4-character key identifier stored as a uint32_t
 * and returns it as a null-terminated string for printing.
 *
 * @param key The 32-bit key identifier (e.g., 'PRAK', 'SLAK')
 * @return Pointer to a static buffer containing the 4-character string
 *
 * @warning The returned pointer is to a static buffer. Do not call this
 *          function multiple times in a single printf() as the buffer
 *          will be overwritten.
 *
 * @code
 * printf("Auth key: %s\n", id2str(hdr->auth_key));  // OK
 * printf("%s vs %s\n", id2str(a), id2str(b));       // BAD - second call overwrites first
 * @endcode
 */
static char *id2str(uint32_t key) {
    static char buffer[5];
    *(uint32_t *)buffer = key;
    return buffer;
}

/**
 * @brief Display help message and exit
 *
 * Shows usage information for the og_verify command-line tool and exits
 * with the specified exit code.
 *
 * @param name Program name (argv[0]) for display in usage message
 * @param exitvalue Exit code (0 for normal help, -1 for error)
 */
static void help(const char *name, int exitvalue) {
    printf("verify image\n"
           "       %s [option] -o <out_file> <in_file>\n"
           "option:\n"
           "  -h, --help              show this help messagen\n"
           "  -n, --name              image name\n"
           "  -c, --chunk             chunk id in string\n"
           "  -H, --header=FILE       input seperated header file name,\n"
           "                          in such case, in_file is payload only\n"
           "  -o, --output=FILE       output file name,\n"
           "                          output to stdout by default\n"
           "\n"
           "[Slack OG edition]\n",
           name);
    exit(exitvalue);
}

/**
 * @brief Long option definitions for getopt_long()
 *
 * Defines the command-line options supported by this program:
 * - help: Show usage information
 * - name: Specify the expected image name for validation
 * - chunk: Specify the expected chunk ID for validation
 * - header: Use a separate header file (for split header/payload)
 * - output: Specify the output file for decrypted data
 */
static const struct option longopts[] =
{
  { "help",   no_argument,       NULL, 'h' },
  { "name",   required_argument, NULL, 'n' },
  { "chunk",  required_argument, NULL, 'c' },
  { "header", required_argument, NULL, 'H' },
  { "output", required_argument, NULL, 'o' },
  { NULL,     0,                 NULL, 0 }
};

/**
 * @brief Print a hexadecimal dump of a byte array
 *
 * Useful for debugging - displays bytes as two-digit hex values separated
 * by spaces, followed by a newline.
 *
 * @param p Pointer to the byte array
 * @param len Number of bytes to display
 *
 * @code
 * hexdump(hdr->scram_key, 16);  // Displays: "56 79 6c 0e ..."
 * @endcode
 */
static void hexdump(uint8_t *p, int len) {
    while (len--)
        printf("%02x ", *p++);
    printf("\n");
}

/**
 * @brief Print a hexadecimal dump of a 32-bit word array
 *
 * Similar to hexdump() but for 32-bit values. Each word is displayed
 * as an 8-digit hex value.
 *
 * @param p Pointer to the 32-bit word array
 * @param len Number of 32-bit words to display
 */
static void hexdump32(uint32_t *p, int len) {
    while (len--)
        printf("%08x ", *p++);
    printf("\n");
}

/**
 * @brief Memory-map a file for reading
 *
 * Opens a file and maps it into memory using mmap(). This is efficient
 * for large files as the OS handles paging data in/out of memory as needed.
 *
 * @param filename Path to the file to open
 * @return Pointer to the memory-mapped file contents
 *
 * @warning Exits the program with error if the file cannot be opened.
 *          The caller does not need to free the returned pointer, but
 *          should call munmap() when done (not implemented in this program
 *          as we exit after use).
 *
 * ## How mmap() works:
 * Instead of reading the entire file into a buffer, mmap() tells the OS
 * to make the file appear as a region of memory. When you access bytes
 * in this region, the OS loads the corresponding parts of the file.
 * This is:
 * - Efficient: Only loads pages you actually access
 * - Simple: Access file like an array
 * - Fast: No explicit read() calls needed
 */
static void *map_file(char *filename) {
    int fd = open(filename, O_RDONLY);
    struct stat statbuf;
    char *buffer = NULL;

    if (fd >= 0) {
        fstat(fd, &statbuf);
        buffer = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
    }
    else {
        printf("Could not open file %s: (%d) (%s)\n", filename, errno, strerror(errno));
        exit(1);
    }

    return buffer;
}

/* ==========================================================================
 * MAIN PROGRAM
 * ==========================================================================
 * The main function orchestrates the entire verification and decryption
 * process. Here's the high-level flow:
 *
 * 1. Parse command-line arguments
 * 2. Load the firmware image (header + payload)
 * 3. Validate the magic number
 * 4. Verify the RSA signature on the header
 * 5. Verify the SHA-256 digest of the payload
 * 6. Optionally decrypt and output the payload
 * ========================================================================== */

/**
 * @brief Main entry point for og_verify
 *
 * Verifies a DJI firmware image file by checking its cryptographic
 * signature and optionally decrypts the payload to an output file.
 *
 * ## Verification Process:
 *
 * ### Step 1: Signature Verification
 * The header (including chunk descriptors) is hashed with SHA-256.
 * This hash is then verified against the RSA signature using the
 * public key specified in the header (PRAK, GFAK, or SLAK).
 *
 * ### Step 2: Payload Integrity
 * The SHA-256 hash of the payload is computed and compared against
 * the hash stored in the header (payload_digest field).
 *
 * ### Step 3: Decryption (if -o specified)
 * If the chunk is encrypted (CHUNK_CLEAR flag not set):
 * 1. Decrypt the scramble key using the encryption key (PUEK/SLEK)
 * 2. Use the scramble key with AES-CBC to decrypt the payload
 * 3. Write the decrypted data to the output file
 *
 * @param argc Number of command-line arguments
 * @param argv Array of command-line argument strings
 * @return 0 on success, exits with 1 on failure
 */
int main(int argc, const char **argv) {
    int opt;
    int ret = 0;
    int verbose = 0;
    char *input = NULL;       /* Input firmware file path */
    char *output = NULL;      /* Output file path for decrypted data */
    char *header = NULL;      /* Separate header file path (optional) */
    char *image_name = NULL;  /* Expected image name for validation */
    char *chunk_name = NULL;  /* Expected chunk name for validation */

    /* ======================================================================
     * COMMAND-LINE ARGUMENT PARSING
     * ======================================================================
     * Parse options using getopt_long() for both short (-h) and long
     * (--help) option formats. Required options:
     * - -n/--name: Image name to match against header
     * Optional:
     * - -o/--output: Output decrypted payload to file
     * - -H/--header: Use separate header file
     * - -c/--chunk: Chunk name to validate
     * - -v: Verbose output (print header fields)
     * ====================================================================== */
    while ((opt = getopt_long(argc, (char * const *)argv, "o:H:n:c:hv", longopts, 0)) != -1) {
        switch (opt) {
            case 'o':
                output = optarg;
                break;
            case 'H':
                header = optarg;
                break;
            case 'n':
                image_name = optarg;
                break;
            case 'c':
                chunk_name = optarg;
                break;
            case 'h':
                help(argv[0], 0);
                break;
            case 'v':
                verbose = 1;
                break;
            default:
                printf("unknown option : -%c\n", opt);
                help(argv[0], -1);
        }
    }

    /* Validate required arguments */
    if (optind == argc) {
        printf("must input source image\n");
        help(argv[0], -1);
    }
    else {
        input = (char *)argv[optind];
    }

    if (!image_name) {
        printf("must input image name\n");
        help(argv[0], -1);
    }

    /* ======================================================================
     * FILE LOADING
     * ======================================================================
     * Load the firmware image into memory. Two modes are supported:
     *
     * 1. Combined mode (default): Header and payload in the same file
     *    - The header is at the start of the file
     *    - The signature follows the header
     *    - The payload follows the signature
     *
     * 2. Separate mode (-H option): Header in one file, payload in another
     *    - Useful when header/signature need to be updated independently
     *    - The input file contains only the payload
     * ====================================================================== */
    unsigned char *hdr_buffer = NULL;
    unsigned char *payload = NULL;
    dji_image_header_t *hdr = NULL;

    if (header) {
        /* Separate header mode: load header and payload from different files */
        hdr_buffer = map_file(header);
        hdr = (dji_image_header_t *)hdr_buffer;
        payload = map_file(input);
    }
    else {
        /* Combined mode: header and payload in the same file */
        hdr_buffer = map_file(input);
        hdr = (dji_image_header_t *)hdr_buffer;
        /* Payload starts after header + signature */
        payload = hdr_buffer + hdr->header_size + hdr->signature_size;
    }

    /* ======================================================================
     * MAGIC NUMBER VALIDATION
     * ======================================================================
     * The first 4 bytes of a valid DJI firmware header must be "IM*H"
     * (stored as 0x482A4D49 in little-endian). This is a quick sanity
     * check before doing expensive cryptographic operations.
     * ====================================================================== */
    if (hdr->magic_num != STR2ID('IM*H')) {
        printf("Invalid header magic!\n");
        exit(1);
    }

    /* ======================================================================
     * VERBOSE OUTPUT
     * ======================================================================
     * When -v is specified, print all header fields for debugging.
     * This is useful for understanding the firmware image structure
     * and diagnosing issues with verification or decryption.
     * ====================================================================== */
    if (verbose) {
        printf("magic:          %s\n", id2str(hdr->magic_num));
        printf("header_version: %d\n", hdr->header_version);
        printf("size:           %d\n", hdr->size);
        printf("reserved:       %08x\n", hdr->reserved);
        printf("header_size:    %d / %lu\n", hdr->header_size, sizeof(*hdr));
        printf("signature_size: %d\n", hdr->signature_size);
        printf("payload_size:   %d\n", hdr->payload_size);
        printf("target_size:    %d\n", hdr->target_size);
        printf("os:             %d\n", hdr->os);
        printf("arch:           %d\n", hdr->arch);
        printf("compression:    %d\n", hdr->compression);
        printf("anti_version:   %d\n", hdr->anti_version);
        printf("auth_alg:       %d\n", hdr->auth_alg);
        printf("auth_key:       %s\n", id2str(hdr->auth_key));
        printf("enc_key:        %s\n", id2str(hdr->enc_key));
        printf("scram_key:      ");
        hexdump(hdr->scram_key, 16);
        printf("name:           %s\n", hdr->name);
        printf("type:           %d\n", hdr->type);
        printf("version:        %08x\n", hdr->version);
        printf("date:           %08x\n", hdr->date);
        printf("reserved2:      ");
        hexdump32(hdr->reserved2, 5);
        printf("userdata:       ");
        hexdump32(hdr->userdata, 4);
        printf("entry:          %016llx\n", hdr->entry);
        printf("reserved3:      %08x\n", hdr->reserved3);
        printf("chunk_num:      %d\n", hdr->chunk_num);
        printf("payload_digest: ");
        hexdump(hdr->payload_digest, 32);
    }

    /* ======================================================================
     * IMAGE NAME VALIDATION
     * ======================================================================
     * Verify that the image name in the header matches the expected name
     * provided via -n. This prevents accidentally processing the wrong
     * firmware file.
     * ====================================================================== */
    if (strcmp((const char *)hdr->name, image_name) != 0) {
        printf("Invalid image name!\n");
        exit(1);
    }

    /* Optionally validate chunk name if -c was specified */
    if (chunk_name && (strcmp(id2str(hdr->chunk[0].id), chunk_name) != 0)) {
        printf("Invalid chunk name!\n");
        exit(1);
    }

    /* Print chunk info in verbose mode */
    if (verbose) {
        printf("chunk id:       %s\n", id2str(hdr->chunk[0].id));
        printf("chunk offset:   %d\n", hdr->chunk[0].offset);
        printf("chunk size:     %d\n", hdr->chunk[0].size);
        printf("chunk attr:     %08x\n", hdr->chunk[0].attr);
    }

    /* ======================================================================
     * RSA SIGNATURE VERIFICATION
     * ======================================================================
     * This is the core security check. We need to verify that the header
     * was signed by DJI (or by us using SLAK).
     *
     * Process:
     * 1. Look up the RSA public key based on the auth_key field
     * 2. Compute SHA-256 hash of the header (including chunk descriptors)
     * 3. Verify the signature using the public key
     *
     * The signature is located immediately after the header in the file.
     * For RSA-2048, it's 256 bytes long.
     *
     * If verification fails, the firmware has been tampered with or is
     * signed with an unknown key.
     * ====================================================================== */
    RSAPublicKey *auth_key;
    struct auth_key_entry *auth_iter = auth_keys;
    
    /* Search for the matching authentication key */
    while ((auth_key = auth_iter->key) && auth_iter->key_id != 0 && auth_iter->key_id != hdr->auth_key)
        auth_iter++;

    if (!auth_key) {
        printf("Unsupported auth key: %s\n", id2str(hdr->auth_key));
        exit(1);
    }

    /* Compute SHA-256 hash of the header and verify RSA signature */
    unsigned char hash[32];
    SHA256_hash(hdr, hdr->header_size, hash);
    ret = RSA_verify(auth_key,
               (const unsigned char*)hdr + hdr->header_size,  /* Signature location */
               hdr->signature_size,
               hash,
               sizeof(hash));

    if (ret != 1) {
        printf("Header signature verification failed\n");
        exit(1);
    }

    /* ======================================================================
     * PAYLOAD DIGEST VERIFICATION
     * ======================================================================
     * Even if the header signature is valid, we need to verify that the
     * payload hasn't been modified. The header contains a SHA-256 hash
     * of the payload that we can check.
     *
     * This ensures end-to-end integrity: the header is signed, and the
     * header contains the hash of the payload.
     * ====================================================================== */
    SHA256_hash(payload, hdr->payload_size, hash);
    if (memcmp(hash, hdr->payload_digest, 32) != 0) {
        printf("Digest verification failed\n");
        exit(1);
    }

    /* ======================================================================
     * PAYLOAD DECRYPTION AND OUTPUT
     * ======================================================================
     * If an output file was specified (-o), write the decrypted payload.
     *
     * Two cases:
     * 1. DJI_IMAGE_CHUNK_CLEAR flag is set: Payload is not encrypted
     *    - Simply copy the payload to the output file
     *
     * 2. Flag is not set: Payload is AES-128-CBC encrypted
     *    - First, decrypt the scramble key using the encryption key
     *      (PUEK or SLEK) in ECB mode
     *    - Then, use the scramble key to decrypt the payload in CBC mode
     *    - The IV (initialization vector) is all zeros
     *
     * ## AES Encryption Layers:
     * Layer 1: scram_key is encrypted with PUEK/SLEK using AES-ECB
     * Layer 2: payload is encrypted with scram_key using AES-CBC (IV=0)
     *
     * This two-layer approach allows the firmware to use a unique
     * per-image key (scram_key) while still allowing verification tools
     * to decrypt using a shared master key (PUEK/SLEK).
     * ====================================================================== */
    if (output) {
        /* Open output file for writing */
        int fd2 = open(output, O_CREAT | O_TRUNC | O_WRONLY, 0644);
        
        if (hdr->chunk[0].attr & DJI_IMAGE_CHUNK_CLEAR) {
            /* Unencrypted payload - write directly */
            write(fd2, payload, hdr->chunk[0].size);
        }
        else {
            /* Encrypted payload - need to decrypt first */
            
            /* Look up the encryption key based on enc_key field */
            uint8_t *enc_key;
            struct enc_key_entry *enc_iter = enc_keys;
            while ((enc_key = enc_iter->key) && enc_iter->key_id != 0 && enc_iter->key_id != hdr->enc_key)
                enc_iter++;

            if (!enc_key) {
                printf("Unsupported encryption key: %s\n", id2str(hdr->enc_key));
                exit(1);
            }

            /* 
             * Step 1: Decrypt the scramble key
             * The scram_key in the header is encrypted with the master key.
             * We decrypt it to get the actual AES key for the payload.
             */
            uint8_t scram_key[16];
            unsigned char iv[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            AesCtx ctx;

            /* Initialize AES context with the master key (ECB mode for key decryption) */
            if( AesCtxIni(&ctx, NULL, enc_key, KEY128, EBC) < 0) {
                printf("Failed to init AES\n");
                exit(1);
            }

            /* Decrypt the 16-byte scramble key */
            if (AesDecrypt(&ctx, hdr->scram_key, scram_key, sizeof(scram_key)) < 0) {
                printf("Failed to decrypt\n");
                exit(1);
            }

            /*
             * Step 2: Decrypt the payload
             * Now use the decrypted scramble key with CBC mode.
             * CBC (Cipher Block Chaining) provides better security than ECB
             * by XORing each block with the previous ciphertext block.
             */
            if( AesCtxIni(&ctx, iv, scram_key, KEY128, CBC) < 0) {
                printf("Failed to init AES\n");
                exit(1);
            }

            /* Allocate buffer for decryption (process 1KB at a time) */
            unsigned char *outbuf = malloc(1024);
            if (!outbuf) {
                printf("Failed to allocate 1024 bytes\n");
                exit(1);
            }

            /*
             * Decrypt and write in chunks
             * 
             * AES works on 16-byte blocks, so we need to round up the size.
             * We decrypt the padded length but only write the actual data size.
             */
            int padded_len = (((hdr->chunk[0].size + 15) / 16) * 16);
            int pos = 0;
            while (padded_len) {
                int n = min(padded_len, 1024);
                if (AesDecrypt(&ctx, payload + pos, outbuf, n) < 0) {
                    printf("Failed to decrypt\n");
                    exit(1);
                }
                pos += n;
                padded_len -= n;

                /* Don't write more than the actual chunk size (handle padding) */
                if (pos > hdr->chunk[0].size)
                n = hdr->chunk[0].size - (pos - n);
                write(fd2, outbuf, n);
            }
        }
        close(fd2);
    }

    printf("Slack OG Done !\n");

    exit(0);

    return ret;
}

/* vim: expandtab:ts=4:sw=4
*/
