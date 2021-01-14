/* 
 * This file is part of FPP (File Protection Program).
 *
 * See LICENSE for licensing information.
 */

#ifndef ENCRYPT_FILE_H
#define ENCRYPT_FILE_H

#include "errcodes.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FPP_UNKNOWN_ALGO         0x00000000
#define FPP_ALGO_AES128          0x00000001
#define FPP_ALGO_AES256          0x00000002
#define FPP_ALGO_BLOWFISH        0x00000003
#define FPP_ALGO_CAST5           0x00000004
#define FPP_ALGO_CAMELLIA128     0x00000005
#define FPP_ALGO_CAMELLIA256     0x00000006


typedef struct {
    const char *in_fname;
    const char *out_fname;
    const char *header_fname;
    const char *text_passwd;
    const char *algo_name;
    uint32_t iter;
} fpp_crypto_params_t;

typedef struct {
    char magic_word[8];
    uint8_t iv[16];
    uint8_t salt[44]; // TODO: Which salt size need to use?
    uint32_t iter;
    uint32_t algo;
} fpp_crypto_header_t;


fpp_err_t fpp_encrypt_file(fpp_crypto_params_t *params);
fpp_err_t fpp_decrypt_file(fpp_crypto_params_t *params);

#ifdef __cplusplus
}
#endif

#endif /* ENCRYPT_FILE_H */
