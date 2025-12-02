/**
 * @file aes.h
 * @brief AES (Advanced Encryption Standard) Header File
 *
 * This header defines the AES cryptographic functions and data structures
 * for encrypting and decrypting data using the AES algorithm.
 *
 * ## What is AES?
 * AES (Advanced Encryption Standard) is a symmetric block cipher that
 * encrypts data in fixed-size 128-bit (16-byte) blocks. It's the
 * standard encryption algorithm used worldwide for securing data.
 *
 * ## Key Features
 * - **Symmetric**: Same key for encryption and decryption
 * - **Block cipher**: Works on fixed 16-byte blocks
 * - **Key sizes**: 128, 192, or 256 bits (this implementation supports all)
 * - **Modes**: ECB (Electronic Codebook) and CBC (Cipher Block Chaining)
 *
 * ## DJI Usage
 * DJI firmware uses AES-128 in two layers:
 * 1. **ECB mode**: Decrypt the scramble key from the header
 * 2. **CBC mode**: Decrypt the actual firmware payload
 *
 * ## Modes Explained
 * 
 * ### ECB (Electronic Codebook)
 * - Each block is encrypted independently
 * - Same plaintext block = same ciphertext block
 * - Simpler but less secure for large data
 * - Used for encrypting single blocks (like the scramble key)
 *
 * ### CBC (Cipher Block Chaining)
 * - Each block is XORed with the previous ciphertext before encryption
 * - Requires an Initialization Vector (IV) for the first block
 * - More secure for bulk data encryption
 * - Used for encrypting the firmware payload
 *
 * ## API Usage Example
 * ```c
 * AesCtx ctx;
 * uint8_t iv[16] = {0};  // Initialization vector (all zeros)
 * uint8_t key[16] = {...};  // Your 128-bit key
 * 
 * // Initialize for decryption in CBC mode
 * AesCtxIni(&ctx, iv, key, KEY128, CBC);
 * 
 * // Decrypt data (must be multiple of 16 bytes)
 * AesDecrypt(&ctx, ciphertext, plaintext, data_length);
 * ```
 *
 * @note This source is in the public domain
 * @see aes.c for implementation details
 */

/*
 * AES Cryptographic Algorithm Header File. Include this header file in
 * your source which uses these given APIs. (This source is kept under
 * public domain)
 */

/* ==========================================================================
 * AES CONTEXT STRUCTURE
 * ========================================================================== */

/**
 * @brief AES encryption/decryption context
 *
 * This structure holds all the state needed for AES operations:
 * - Expanded key schedules for encryption and decryption
 * - The current IV (Initialization Vector) for CBC mode
 * - Number of rounds (depends on key size)
 * - Operating mode (ECB or CBC)
 *
 * ## Key Schedule
 * AES doesn't use the raw key directly. Instead, it expands the key into
 * a "key schedule" - a series of round keys derived from the original.
 * - 128-bit key → 11 round keys (10 rounds + initial)
 * - 192-bit key → 13 round keys (12 rounds + initial)
 * - 256-bit key → 15 round keys (14 rounds + initial)
 *
 * @note Always initialize with AesCtxIni() before use
 */
// AES context structure
typedef struct {
    unsigned int Ek[60];   /**< Encryption key schedule (up to 60 words for 256-bit) */
    unsigned int Dk[60];   /**< Decryption key schedule (inverse of Ek) */
    unsigned int Iv[4];    /**< Initialization Vector for CBC mode (4 words = 16 bytes) */
    unsigned char Nr;      /**< Number of rounds (10, 12, or 14 based on key size) */
    unsigned char Mode;    /**< Operating mode: EBC (0) or CBC (1) */
} AesCtx;

/* ==========================================================================
 * KEY SIZE CONSTANTS
 * ========================================================================== */

/**
 * @name Key length constants (in bytes)
 * @{
 */
// key length in bytes
#define KEY128 16  /**< 128-bit key (16 bytes) - 10 rounds */
#define KEY192 24  /**< 192-bit key (24 bytes) - 12 rounds */
#define KEY256 32  /**< 256-bit key (32 bytes) - 14 rounds */
/** @} */

/**
 * @brief AES block size in bytes
 *
 * AES always operates on 128-bit (16-byte) blocks regardless of key size.
 * Data to encrypt/decrypt must be a multiple of this size.
 */
// block size in bytes
#define BLOCKSZ 16

/* ==========================================================================
 * MODE CONSTANTS
 * ========================================================================== */

/**
 * @name Operating mode constants
 * @{
 */
// mode
#define EBC 0  /**< Electronic Codebook - each block independent */
#define CBC 1  /**< Cipher Block Chaining - blocks linked via XOR */
/** @} */

/* ==========================================================================
 * API FUNCTION PROTOTYPES
 * ========================================================================== */

// AES API function prototype

/**
 * @brief Initialize AES context
 *
 * Sets up the AES context with key schedule and mode. Must be called
 * before any encryption or decryption operations.
 *
 * @param pCtx Pointer to AES context to initialize
 * @param pIV Pointer to 16-byte IV (can be NULL for ECB mode)
 * @param pKey Pointer to the encryption key
 * @param KeyLen Key length: KEY128, KEY192, or KEY256
 * @param Mode Operating mode: EBC or CBC
 * @return 0 on success, -1 on error (invalid parameters)
 */
int AesCtxIni(AesCtx *pCtx, unsigned char *pIV, unsigned char *pKey, unsigned int KeyLen, unsigned char Mode);

/**
 * @brief Encrypt data with AES
 *
 * Encrypts plaintext data using the initialized context.
 *
 * @param pCtx Initialized AES context
 * @param pData Pointer to plaintext data
 * @param pCipher Pointer to buffer for ciphertext (can be same as pData)
 * @param DataLen Length of data (must be multiple of BLOCKSZ=16)
 * @return Number of bytes encrypted, or -1 on error
 */
int AesEncrypt(AesCtx *pCtx, unsigned char *pData, unsigned char *pCipher, unsigned int DataLen);

/**
 * @brief Decrypt data with AES
 *
 * Decrypts ciphertext data using the initialized context.
 *
 * @param pCtx Initialized AES context
 * @param pCipher Pointer to ciphertext data
 * @param pData Pointer to buffer for plaintext (can be same as pCipher)
 * @param CipherLen Length of data (must be multiple of BLOCKSZ=16)
 * @return Number of bytes decrypted, or -1 on error
 */
int AesDecrypt(AesCtx *pCtx, unsigned char *pCipher, unsigned char *pData, unsigned int CipherLen);

/* vim: expandtab:ts=4:sw=4
*/
