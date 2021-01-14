/* 
 * This file is part of FPP (File Protection Program).
 *
 * See LICENSE for licensing information.
 */

#ifndef PBKDF2_H
#define PBKDF2_H

#include "errcodes.h"

#ifdef __cplusplus
extern "C" {
#endif

fpp_err_t fpp_pkcs5_pbkdf2_hmac_sha256(const char *pass, size_t passlen,
    const uint8_t *salt, size_t saltlen, uint32_t iter, uint8_t *out,
    size_t outlen);

fpp_err_t fpp_pkcs5_pbkdf2_hmac_sha384(const char *pass, size_t passlen,
    const uint8_t *salt, size_t saltlen, uint32_t iter, uint8_t *out,
    size_t outlen);

fpp_err_t fpp_pkcs5_pbkdf2_hmac_sha512(const char *pass, size_t passlen,
    const uint8_t *salt, size_t saltlen, uint32_t iter, uint8_t *out,
    size_t outlen);

#ifdef __cplusplus
}
#endif

#endif /* PBKDF2_H */
