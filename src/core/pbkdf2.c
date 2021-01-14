/* 
 * This file is part of FPP (File Protection Program).
 *
 * See LICENSE for licensing information.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#include "pbkdf2.h"

fpp_err_t
fpp_pkcs5_pbkdf2_hmac_sha256(const char *pass, size_t passlen,
    const uint8_t *salt, size_t saltlen, uint32_t iter,
    uint8_t *out, size_t outlen)
{
    if (!PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen,
            iter, EVP_sha256(), outlen, out)) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

fpp_err_t
fpp_pkcs5_pbkdf2_hmac_sha384(const char *pass, size_t passlen,
    const uint8_t *salt, size_t saltlen, uint32_t iter,
    uint8_t *out, size_t outlen)
{
    if (!PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen,
            iter, EVP_sha384(), outlen, out)) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

fpp_err_t
fpp_pkcs5_pbkdf2_hmac_sha512(const char *pass, size_t passlen,
    const uint8_t *salt, size_t saltlen, uint32_t iter,
    uint8_t *out, size_t outlen)
{
    if (!PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen,
            iter, EVP_sha512(), outlen, out)) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
