/* 
 * This file is part of FPP (File Protection Program).
 *
 * See LICENSE for licensing information.
 */

#ifndef CAMELLIA256_H
#define CAMELLIA256_H

#include <openssl/camellia.h>

#include "errcodes.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FPP_IVSIZE_CAMELLIA256      16
#define FPP_KEYSIZE_CAMELLIA256     16
#define FPP_CAMELLIA256_BLOCK_SIZE  CAMELLIA_BLOCK_SIZE


fpp_err_t fpp_encrypt_camellia256_cbc(const uint8_t *in_data, uint32_t in_len,
    uint8_t *out_data, uint32_t *out_len,
    const uint8_t *key, const uint8_t *iv);

fpp_err_t fpp_decrypt_camellia256_cbc(const uint8_t *in_data, uint32_t in_len,
    uint8_t *out_data, uint32_t *out_len,
    const uint8_t *key, const uint8_t *iv);

#ifdef __cplusplus
}
#endif

#endif /* CAMELLIA256_H */
