/* 
 * This file is part of FPP (File Protection Program).
 *
 * See LICENSE for licensing information.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <openssl/evp.h>


/* Return 256 bit (32 byte) */
uint8_t *
fpp_hash_sha3_256_ex(const uint8_t *in_data, size_t in_size, uint8_t *buf)
{
    const EVP_MD *algo;
    EVP_MD_CTX *mdctx;
    uint32_t hash_len;

    mdctx = NULL;
    algo = EVP_sha3_256();

    mdctx = EVP_MD_CTX_create();
    if (!mdctx) {
        goto failed;
    }
    /* Returns 1 if successful */
    if (EVP_DigestInit_ex(mdctx, algo, NULL) != 1) {
        goto failed;
    }
    /* Returns 1 if successful */
    if (EVP_DigestUpdate(mdctx, in_data, in_size) != 1) {
        goto failed;
    }
    hash_len = EVP_MD_size(algo);
    /* Returns 1 if successful */
    if (EVP_DigestFinal_ex(mdctx, buf, &hash_len) != 1) {
        goto failed;
    }

    EVP_MD_CTX_destroy(mdctx);
    return buf;

failed:
    if (mdctx) {
        EVP_MD_CTX_destroy(mdctx);
    }
    return NULL;
}
