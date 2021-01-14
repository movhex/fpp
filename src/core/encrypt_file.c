/* 
 * This file is part of FPP (File Protection Program).
 *
 * See LICENSE for licensing information.
 */

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "encrypt_file.h"
#include "pbkdf2.h"
#include "aes128.h"
#include "aes256.h"
#include "blowfish.h"
#include "cast5.h"
#include "camellia128.h"
#include "camellia256.h"
#include "random.h"
#include "memory.h"
#include "log.h"

static const char magic_word[8] = "FPPv1";

#define fpp_padding_size(size, block_size) \
    ((size/block_size + 1) * block_size)

static bool
fpp_is_file_exist(const char *fname)
{
    FILE *fd = fopen(fname, "rb");
    if (!fd) {
        return false;
    }
    fclose(fd);
    return true;
}

static uint32_t
fpp_get_algo_magic_word(const char *name)
{
    if (strcmp(name, "aes128") == 0) {
        return FPP_ALGO_AES128;
    }
    else if (strcmp(name, "aes256") == 0) {
        return FPP_ALGO_AES256;
    }
    else if (strcmp(name, "blowfish") == 0) {
        return FPP_ALGO_BLOWFISH;
    }
    else if (strcmp(name, "cast5") == 0) {
        return FPP_ALGO_CAST5;
    }
    else if (strcmp(name, "camellia128") == 0) {
        return FPP_ALGO_CAMELLIA128;
    }
    else if (strcmp(name, "camellia256") == 0) {
        return FPP_ALGO_CAMELLIA256;
    }
    else {
        return FPP_UNKNOWN_ALGO;
    }
}

fpp_err_t
fpp_encrypt_file(fpp_crypto_params_t *params)
{
    static uint8_t key[FPP_KEYSIZE_AES256];

    FILE *in_fd = NULL;
    FILE *out_fd = NULL;
    FILE *head_fd = NULL;
    uint8_t *data = NULL;
    uint8_t *edata = NULL;
    size_t data_size;
    size_t edata_size;
    size_t bytes_read;
    size_t bytes_written;
    uint32_t algo_magic_word;

    /*
     * We already know encrypted data size by padding size function
     */
    uint32_t dummy_len;

    fpp_crypto_header_t header;
    fpp_err_t err;


    memset(&header, 0, sizeof(header));
    memmove(header.magic_word, magic_word, sizeof(header.magic_word));
    header.iter = params->iter;

    in_fd = fopen(params->in_fname, "rb");
    if (!in_fd) {
        err = fpp_get_os_errno();
        fpp_log_error(err, "Failed to open input file \"%s\"",
            params->in_fname);
        goto failed;
    }

    /*
     * In fopen(), the open mode "wbx" is sometimes preferred "wb"
     * because if "wb" is used, old contents of file are erased and
     * a new empty file is created. When wx is used, fopen() returns
     * NULL if file already exists
     */
    if (fpp_is_file_exist(params->out_fname)) {
        fpp_log_error(FPP_ERR_IO_EXIST, "Output file \"%s\" already exists",
            params->out_fname);
        goto failed;
    }

    if (params->header_fname) {
        if (fpp_is_file_exist(params->header_fname)) {
            fpp_log_error(FPP_ERR_IO_EXIST,
                "Header file \"%s\" already exists", params->header_fname);
            goto failed;
        }
    }

    algo_magic_word = fpp_get_algo_magic_word(params->algo_name);
    if (algo_magic_word == FPP_UNKNOWN_ALGO) {
        fpp_log_error(FPP_ERR_IO_ARGV, "Unknown algorithm \"%s\"",
            params->algo_name);
        goto failed;
    }
    header.algo = algo_magic_word;

    fseek(in_fd, 0, SEEK_END);
    data_size = ftell(in_fd);
    fseek(in_fd, 0, SEEK_SET);

    /* Stack size may not be enough */
    data = malloc(data_size * sizeof(uint8_t));
    if (!data) {
        err = fpp_get_os_errno();
        fpp_log_error(err, "Failed to allocate memory");
        goto failed;
    }

    bytes_read = fread(data, sizeof(uint8_t), data_size, in_fd);
    if (bytes_read != data_size) {
        err = fpp_get_os_errno();
        fpp_log_error(err, "Failed to read data from input file \"%s\"",
            params->in_fname);
        goto failed;
    }

    /* Generate random IV */
    if (fpp_random_bytes(header.iv, sizeof(header.iv)) != FPP_OK) {
        err = fpp_get_openssl_errno();
        fpp_log_error(err, "Failed to generate random IV");
        goto failed;
    }

    /* Genereate salt */
    if (fpp_random_bytes(header.salt,
        sizeof(header.salt)) != FPP_OK)
    {
        err = fpp_get_openssl_errno();
        fpp_log_error(err, "Failed to generate random salt");
        goto failed;
    }

    /* Genereate key */
    if (fpp_pkcs5_pbkdf2_hmac_sha512(params->text_passwd,
        strlen(params->text_passwd), header.salt, sizeof(header.salt),
        params->iter, key, sizeof(key)) != FPP_OK)
    {
        err = fpp_get_openssl_errno();
        fpp_log_error(err, "fpp_pkcs5_pbkdf2_hmac_sha256() failed");
        goto failed;
    }

    if (algo_magic_word == FPP_ALGO_AES128) {
        edata_size = fpp_padding_size(data_size, FPP_AES_BLOCK_SIZE);
        edata = malloc(edata_size * sizeof(uint8_t));
        if (!edata) {
            err = fpp_get_os_errno();
            fpp_log_error(err, "Failed to allocate memory");
            goto failed;
        }
        err = fpp_encrypt_aes128_cbc(data, data_size,
            edata, &dummy_len, key, header.iv);
    }
    else if (algo_magic_word == FPP_ALGO_AES256) {
        edata_size = fpp_padding_size(data_size, FPP_AES_BLOCK_SIZE);
        edata = malloc(edata_size * sizeof(uint8_t));
        if (!edata) {
            err = fpp_get_os_errno();
            fpp_log_error(err, "Failed to allocate memory");
            goto failed;
        }
        err = fpp_encrypt_aes256_cbc(data, data_size,
            edata, &dummy_len, key, header.iv);
    }
    else if (algo_magic_word == FPP_ALGO_BLOWFISH) {
        edata_size = fpp_padding_size(data_size, FPP_BLOWFISH_BLOCK_SIZE);
        edata = malloc(edata_size * sizeof(uint8_t));
        if (!edata) {
            err = fpp_get_os_errno();
            fpp_log_error(err, "Failed to allocate memory");
            goto failed;
        }
        err = fpp_encrypt_blowfish_cbc(data, data_size,
            edata, &dummy_len, key, header.iv);
    }
    else if (algo_magic_word == FPP_ALGO_CAST5) {
        edata_size = fpp_padding_size(data_size, FPP_CAST5_BLOCK_SIZE);
        edata = malloc(edata_size * sizeof(uint8_t));
        if (!edata) {
            err = fpp_get_os_errno();
            fpp_log_error(err, "Failed to allocate memory");
            goto failed;
        }
        err = fpp_encrypt_cast5_cbc(data, data_size,
            edata, &dummy_len, key, header.iv);
    }
    else if (algo_magic_word == FPP_ALGO_CAMELLIA128) {
        edata_size = fpp_padding_size(data_size, FPP_CAMELLIA128_BLOCK_SIZE);
        edata = malloc(edata_size * sizeof(uint8_t));
        if (!edata) {
            err = fpp_get_os_errno();
            fpp_log_error(err, "Failed to allocate memory");
            goto failed;
        }
        err = fpp_encrypt_camellia128_cbc(data, data_size,
            edata, &dummy_len, key, header.iv);
    }
    else if (algo_magic_word == FPP_ALGO_CAMELLIA256) {
        edata_size = fpp_padding_size(data_size, FPP_CAMELLIA256_BLOCK_SIZE);
        edata = malloc(edata_size * sizeof(uint8_t));
        if (!edata) {
            err = fpp_get_os_errno();
            fpp_log_error(err, "Failed to allocate memory");
            goto failed;
        }
        err = fpp_encrypt_camellia256_cbc(data, data_size,
            edata, &dummy_len, key, header.iv);
    }

    if (err != FPP_OK) {
        err = fpp_get_openssl_errno();
        fpp_log_error(err, "Failed to encrypt data");
        goto failed;
    }

    out_fd = fopen(params->out_fname, "wb");
    if (!out_fd) {
        err = fpp_get_os_errno();
        fpp_log_error(err, "Failed to open output file \"%s\"",
            params->out_fname);
        goto failed;
    }

    if (params->header_fname) {
        head_fd = fopen(params->header_fname, "wb");
        if (!head_fd) {
            err = fpp_get_os_errno();
            fpp_log_error(err, "Failed to open header file \"%s\"",
                params->header_fname);
            goto failed;
        }
    }

    if (params->header_fname) {
        bytes_written = fwrite(&header, sizeof(uint8_t),
            sizeof(header), head_fd);
    }
    else {
        bytes_written = fwrite(&header, sizeof(uint8_t),
            sizeof(header), out_fd);
    }
    if (bytes_written != sizeof(header)) {
        err = fpp_get_os_errno();
        fpp_log_error(err, "Failed to write header to output file \"%s\"",
            params->out_fname);
        goto failed;
    }

    bytes_written = fwrite(edata, sizeof(uint8_t), edata_size, out_fd);
    if (bytes_written != edata_size) {
        err = fpp_get_os_errno();
        fpp_log_error(err, "Failed to write data to output file \"%s\"",
            params->out_fname);
        goto failed;
    }

    fpp_explicit_memzero(key, sizeof(key));

    fclose(in_fd);
    fclose(out_fd);
    if (head_fd) {
        fclose(head_fd);
    }

    free(data);
    free(edata);
    return FPP_OK;

failed:
    if (in_fd) {
        fclose(in_fd);
    }
    if (out_fd) {
        fclose(out_fd);
    }
    if (head_fd) {
        fclose(head_fd);
    }
    if (data) {
        free(data);
    }
    if (edata) {
        free(edata);
    }
    return FPP_FAILURE;
}


fpp_err_t
fpp_decrypt_file(fpp_crypto_params_t *params)
{
    static uint8_t key[FPP_KEYSIZE_AES256];

    FILE *in_fd = NULL;
    FILE *out_fd = NULL;
    FILE *head_fd = NULL;
    uint8_t *data = NULL;
    uint8_t *ddata = NULL;
    uint32_t ddata_size;

    size_t bytes_read;
    size_t bytes_written;
    size_t data_size;

    fpp_crypto_header_t header;
    fpp_err_t err;


    memset(&header, 0, sizeof(header));

    in_fd = fopen(params->in_fname, "rb");
    if (!in_fd) {
        err = fpp_get_os_errno();
        fpp_log_error(err, "Failed to open input file \"%s\"",
            params->in_fname);
        goto failed;
    }

    if (fpp_is_file_exist(params->out_fname)) {
        fpp_log_error(FPP_ERR_IO_EXIST, "Output file \"%s\" already exists",
            params->out_fname);
        goto failed;
    }

    if (params->header_fname) {
        head_fd = fopen(params->header_fname, "rb");
        if (!head_fd) {
            err = fpp_get_os_errno();
            fpp_log_error(err, "Failed to open header file \"%s\"",
                params->header_fname);
            goto failed;
        }
    }

    fseek(in_fd, 0, SEEK_END);
    if (params->header_fname) {
        data_size = ftell(in_fd);
    }
    else {
        data_size = ftell(in_fd) - sizeof(header);
    }
    fseek(in_fd, 0, SEEK_SET);

    if (params->header_fname) {
        bytes_read = fread(&header, sizeof(uint8_t), sizeof(header), head_fd);
    }
    else {
        bytes_read = fread(&header, sizeof(uint8_t), sizeof(header), in_fd);
    }
    if (bytes_read != sizeof(header)) {
        err = fpp_get_os_errno();
        fpp_log_error(err, "Failed to read header \"%s\"",
            params->header_fname);
        goto failed;
    }

    if (strncmp(header.magic_word, magic_word, sizeof(header.magic_word)) ||
        bytes_read != sizeof(header))
    {
        fpp_log_error(FPP_ERR_IO_FORMAT, "Failed to recognize file format");
        goto failed;
    }

    /* Stack size may not be enough */
    data = malloc(data_size * sizeof(uint8_t));
    if (!data) {
        err = fpp_get_os_errno();
        fpp_log_error(err, "Failed to allocate memory");
        goto failed;
    }

    bytes_read = fread(data, sizeof(uint8_t), data_size, in_fd);
    if (bytes_read != data_size) {
        err = fpp_get_os_errno();
        fpp_log_error(err, "Failed to read data from input file \"%s\"",
            params->in_fname);
        goto failed;
    }

    /* Genereate key */
    if (fpp_pkcs5_pbkdf2_hmac_sha512(params->text_passwd,
        strlen(params->text_passwd), header.salt, sizeof(header.salt),
        header.iter, key, sizeof(key)) != FPP_OK)
    {
        err = fpp_get_openssl_errno();
        fpp_log_error(err, "fpp_pkcs5_pbkdf2_hmac_sha256() failed");
        goto failed;
    }

    ddata = malloc(data_size * sizeof(uint8_t));
    if (!ddata) {
        err = fpp_get_os_errno();
        fpp_log_error(err, "Failed to allocate memory");
        goto failed;
    }

    if (header.algo == FPP_ALGO_AES128) {
        err = fpp_decrypt_aes128_cbc(data, data_size,
            ddata, &ddata_size, key, header.iv);
    }
    else if (header.algo == FPP_ALGO_AES256) {
        err = fpp_decrypt_aes256_cbc(data, data_size,
            ddata, &ddata_size, key, header.iv);
    }
    else if (header.algo == FPP_ALGO_BLOWFISH) {
        err = fpp_decrypt_blowfish_cbc(data, data_size,
            ddata, &ddata_size, key, header.iv);
    }
    else if (header.algo == FPP_ALGO_CAST5) {
        err = fpp_decrypt_cast5_cbc(data, data_size,
            ddata, &ddata_size, key, header.iv);
    }
    else if (header.algo == FPP_ALGO_CAMELLIA128) {
        err = fpp_decrypt_camellia128_cbc(data, data_size,
            ddata, &ddata_size, key, header.iv);
    }
    else if (header.algo == FPP_ALGO_CAMELLIA256) {
        err = fpp_decrypt_camellia256_cbc(data, data_size,
            ddata, &ddata_size, key, header.iv);
    }
    else {
        fpp_log_error(FPP_FAILURE, "Unrecognized magic word of algorithm");
        goto failed;
    }

    if (err != FPP_OK) {
        err = fpp_get_openssl_errno();
        fpp_log_error(err, "Failed to decrypt data");
        goto failed;
    }

    out_fd = fopen(params->out_fname, "wb");
    if (!out_fd) {
        err = fpp_get_os_errno();
        fpp_log_error(err, "Failed to open output file \"%s\"",
            params->out_fname);
        goto failed;
    }

    bytes_written = fwrite(ddata, sizeof(uint8_t), ddata_size, out_fd);
    if (bytes_written != ddata_size) {
        err = fpp_get_os_errno();
        fpp_log_error(err, "Failed to write data to output file \"%s\"",
            params->out_fname);
        goto failed;
    }

    fpp_explicit_memzero(key, sizeof(key));

    fclose(in_fd);
    fclose(out_fd);
    if (head_fd) {
        fclose(head_fd);
    }

    free(data);
    free(ddata);
    return FPP_OK;

failed:
    if (in_fd) {
        fclose(in_fd);
    }
    if (out_fd) {
        fclose(out_fd);
    }
    if (head_fd) {
        fclose(head_fd);
    }
    if (data) {
        free(data);
    }
    if (ddata) {
        free(ddata);
    }
    return FPP_FAILURE;
}
