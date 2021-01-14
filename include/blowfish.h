/* 
 * This file is part of FPP (File Protection Program).
 *
 * See LICENSE for licensing information.
 */

#ifndef BLOWFISH_H
#define BLOWFISH_H

#include <openssl/blowfish.h>

#include "errcodes.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FPP_IVSIZE_BLOWFISH      16
#define FPP_KEYSIZE_BLOWFISH     16
#define FPP_BLOWFISH_BLOCK_SIZE  BF_BLOCK


fpp_err_t fpp_encrypt_blowfish_cbc(const uint8_t *in_data, uint32_t in_len,
    uint8_t *out_data, uint32_t *out_len,
    const uint8_t *key, const uint8_t *iv);

fpp_err_t fpp_decrypt_blowfish_cbc(const uint8_t *in_data, uint32_t in_len,
    uint8_t *out_data, uint32_t *out_len,
    const uint8_t *key, const uint8_t *iv);

#ifdef __cplusplus
}
#endif

#endif /* BLOWFISH_H */
