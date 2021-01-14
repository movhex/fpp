/* 
 * This file is part of FPP (File Protection Program).
 *
 * See LICENSE for licensing information.
 */

#ifndef CAST5_H
#define CAST5_H

#include <openssl/cast.h>

#include "errcodes.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FPP_IVSIZE_CAST5      16
#define FPP_KEYSIZE_CAST5     16
#define FPP_CAST5_BLOCK_SIZE  CAST_BLOCK


fpp_err_t fpp_encrypt_cast5_cbc(const uint8_t *in_data, uint32_t in_len,
    uint8_t *out_data, uint32_t *out_len,
    const uint8_t *key, const uint8_t *iv);

fpp_err_t fpp_decrypt_cast5_cbc(const uint8_t *in_data, uint32_t in_len,
    uint8_t *out_data, uint32_t *out_len,
    const uint8_t *key, const uint8_t *iv);

#ifdef __cplusplus
}
#endif

#endif /* CAST5_H */
