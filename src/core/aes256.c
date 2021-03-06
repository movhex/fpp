/* 
 * This file is part of FPP (File Protection Program).
 *
 * See LICENSE for licensing information.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#include "aes256.h"


fpp_err_t
fpp_encrypt_aes256_cbc(const uint8_t *in_data, uint32_t in_len,
    uint8_t *out_data, uint32_t *out_len, const uint8_t *key,
    const uint8_t *iv)
{
    EVP_CIPHER_CTX *ctx;
    int32_t current_len;
    uint32_t result_len;

    /* Create and initialise the context. */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        goto failed;
    }

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher.
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits.
     */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        goto failed;
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary.
     */
    if (EVP_EncryptUpdate(ctx, out_data, &current_len, in_data, in_len) != 1) {
        goto failed;
    }

    result_len = current_len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (EVP_EncryptFinal_ex(ctx, out_data + current_len, &current_len) != 1) {
        goto failed;
    }

    result_len += current_len;

    EVP_CIPHER_CTX_free(ctx);

    *out_len = result_len;

    return FPP_OK;

failed:
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return FPP_FAILURE;
}

fpp_err_t
fpp_decrypt_aes256_cbc(const uint8_t *in_data, uint32_t in_len,
    uint8_t *out_data, uint32_t *out_len, const uint8_t *key,
    const uint8_t *iv)
{
    EVP_CIPHER_CTX *ctx;
    int32_t current_len;
    uint32_t result_len;

    /* Create and initialise the context. */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        goto failed;
    }

    /* 
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher.
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits.
     */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        goto failed;
    }


    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if (EVP_DecryptUpdate(ctx, out_data, &current_len, in_data, in_len) != 1) {
        goto failed;
    }

    result_len = current_len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (EVP_DecryptFinal_ex(ctx, out_data + current_len, &current_len) != 1) {
        goto failed;
    }

    result_len += current_len;

    EVP_CIPHER_CTX_free(ctx);

    *out_len = result_len;

    return FPP_OK;

failed:
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return FPP_FAILURE;
}
