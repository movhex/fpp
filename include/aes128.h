/* 
 * This file is part of FPP (File Protection Program).
 *
 * See LICENSE for licensing information.
 */

#ifndef AES128_H
#define AES128_H

#include <openssl/aes.h>

#include "errcodes.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FPP_IVSIZE_AES128   16
#define FPP_KEYSIZE_AES128  32
#define FPP_AES_BLOCK_SIZE  AES_BLOCK_SIZE


fpp_err_t fpp_encrypt_aes128_cbc(const uint8_t *in_data, uint32_t in_len,
    uint8_t *out_data, uint32_t *out_len,
    const uint8_t *key, const uint8_t *iv);

fpp_err_t fpp_decrypt_aes128_cbc(const uint8_t *in_data, uint32_t in_len,
    uint8_t *out_data, uint32_t *out_len,
    const uint8_t *key, const uint8_t *iv);

#ifdef __cplusplus
}
#endif

#endif /* AES128_H */
