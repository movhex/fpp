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
#include <unistd.h>
#include <stdbool.h>
#include <openssl/crypto.h>

#include "encrypt_file.h"
#include "getpass.h"
#include "memory.h"
#include "errcodes.h"
#include "log.h"
#include "version.h"

#define FPP_MAX_PATHLEN  4096

static bool encrypt_mode;
static bool decrypt_mode;
static bool show_version;
static bool show_help;
static bool quiet_mode;

static size_t iter = 50180;
static const char *in_fname;
static const char *out_fname;
static const char *header_fname;
static const char *algo_name = "aes256";


static fpp_err_t
fpp_parse_argv(size_t argc, const char *const *argv)
{
    size_t i, saved_index;
    const char *p;
    bool long_option;

    for (i = 1; i < argc; ++i) {

        saved_index = i;
        p = argv[i];

        if (*p++ != '-' || *p == '\0') {
            return EXIT_FAILURE;
        }

        while (*p) {

            long_option = false;

            switch (*p++) {
            case 'h':
                show_help = true;
                break;

            case 'v':
                show_version = true;
                break;

            case 'q':
                quiet_mode = true;
                break;

            case 'i':
                iter = atoi(argv[i]);
                break;

            case 'e':
                if (argv[++i]) {
                    encrypt_mode = true;
                    in_fname = argv[i];
                }
                else {
                    goto missing_argment;
                }
                break;

            case 'd':
                if (argv[++i]) {
                    decrypt_mode = true;
                    in_fname = argv[i];
                }
                else {
                    goto missing_argment;
                }
                break;

            case 'o':
                if (argv[++i]) {
                    out_fname = argv[i];
                }
                else {
                    goto missing_argment;
                }
                break;

            case 'a':
                if (argv[++i]) {
                    algo_name = argv[i];
                }
                else {
                    goto missing_argment;
                }
                break;

            case 'y':
                if (argv[++i]) {
                    header_fname = argv[i];
                }
                else {
                    goto missing_argment;
                }
                break;

            case '-':
                long_option = true;
                break;

            default:
                goto invalid_option;
            }

            if (!long_option) {
                continue;
            }

            if (strcmp(p, "help") == 0) {
                show_help = true;
                p += sizeof("help") - 1;
                continue;
            }

            if (strcmp(p, "version") == 0) {
                show_version = true;
                p += sizeof("version") - 1;
                continue;
            }

            if (strcmp(p, "quiet") == 0) {
                quiet_mode = true;
                p += sizeof("quiet") - 1;
                continue;
            }

            if (strcmp(p, "encrypt") == 0) {
                if (argv[++i]) {
                    encrypt_mode = true;
                    in_fname = argv[i];
                    p += sizeof("encrypt") - 1;
                    continue;
                }
                else {
                    goto missing_argment;
                }
            }

            if (strcmp(p, "decrypt") == 0) {
                if (argv[++i]) {
                    decrypt_mode = true;
                    in_fname = argv[i];
                    p += sizeof("decrypt") - 1;
                    continue;
                }
                else {
                    goto missing_argment;
                }
            }

            if (strcmp(p, "algorithm") == 0) {
                if (argv[++i]) {
                    algo_name = argv[i];
                    p += sizeof("algorithm") - 1;
                    continue;
                }
                else {
                    goto missing_argment;
                }
            }

            if (strcmp(p, "output-file") == 0) {
                if (argv[++i]) {
                    out_fname = argv[i];
                    p += sizeof("output-file") - 1;
                    continue;
                }
                else {
                    goto missing_argment;
                }
            }

            if (strcmp(p, "header") == 0) {
                if (argv[++i]) {
                    header_fname = argv[i];
                    p += sizeof("header") - 1;
                    continue;
                }
                else {
                    goto missing_argment;
                }
            }

            if (strcmp(p, "iter") == 0) {
                if (argv[++i]) {
                    iter = atoi(argv[i]);
                    p += sizeof("iter") - 1;
                    continue;
                }
                else {
                    goto missing_argment;
                }
            }

            goto invalid_option;
        }
    }

    return EXIT_SUCCESS;

invalid_option:
    fprintf(stderr, "fpp: invalid option -- \"%s\"\n", argv[saved_index]);
    return EXIT_FAILURE;

missing_argment:
    fprintf(stderr, "fpp: missing argment for option -- \"%s\"\n",
        argv[saved_index]);
    return EXIT_FAILURE;
}

static void
show_version_info(void)
{
    fprintf(stdout, "fpp, version %s\n", FPP_VERSION_STR);
#ifdef FPP_COMPILER
    fprintf(stdout, "   compiled %s on %s\n", FPP_BUILD_DATE, FPP_COMPILER);
#endif
    fprintf(stdout, "   using %s\n", SSLeay_version(SSLEAY_VERSION));
}

static void
fpp_show_help_info(void)
{
    fprintf(stdout,
        "Usage: fpp [options...] [argments...]\n"
        "FPP (Files Protect Program) version %s %s\n\n"
        "Options:\n"
        "  -h, --help                     Displays this message.\n"
        "  -v, --version                  Displays version information.\n"
        "  -q, --quiet                    Suppress non-error messages.\n"
        "  -e, --encrypt <file>           Specify file to encrypt.\n"
        "  -d, --decrypt <file>           Specify file to decrypt.\n"
        "  -a, --algorithm                Specify algorithm.\n"
        "  -o, --output-file <file>       Specify output file.\n"
        "  -y, --header <file>            Specify header file.\n"
        "  -i, --iter <n>                 Specify number of iteration.\n",
        FPP_VERSION_STR, FPP_BUILD_DATE);
}

int
main(int argc, const char *const *argv)
{
    static char temp_fname[FPP_MAX_PATHLEN];
    char *passwd1 = NULL, *passwd2 = NULL;
    fpp_crypto_params_t params; 
    fpp_err_t err;

    if ((err = fpp_parse_argv(argc, argv)) != EXIT_SUCCESS) {
        fpp_show_help_info();
        goto failed;
    }

    if (show_version) {
        show_version_info();
        return 0;
    }

    if (show_help) {
        fpp_show_help_info();
        return 0;
    }

    if (quiet_mode) {
        fpp_enable_quite_mode();
    }

    if (!in_fname) {
        fpp_log_error(FPP_FAILURE, "Empty input file name");
        goto failed;
    }

    if (encrypt_mode) {
        passwd1 = fpp_getpass("Enter pass phrase: ");
        passwd2 = fpp_getpass("Verifying - Enter pass phrase: ");
        if (!passwd1 || !passwd2) {
            fpp_log_error(FPP_FAILURE, "Invalid input passwords");
            goto failed;
        }

        if (strcmp(passwd1, passwd2) != 0) {
            fpp_log_error(FPP_FAILURE, "The entered passwords don't match");
            goto failed;
        }

        if (!out_fname) {
            snprintf(temp_fname, sizeof(temp_fname), "%s.fpp", in_fname);
            out_fname = temp_fname;
        }

        params.in_fname = in_fname;
        params.out_fname = out_fname;
        params.header_fname = header_fname;
        params.text_passwd = passwd1;
        params.iter = iter;
        params.algo_name = algo_name;

        err = fpp_encrypt_file(&params);
        if (err != EXIT_SUCCESS) {
            fpp_log_message("Failed to encrypt file");
            goto failed;
        }

        if (header_fname) {
            fpp_log_message("Files successfully saved:\n"
                "   encrypted file: \"%s\"\n   header file: \"%s\"",
                out_fname, header_fname);
        }
        else {
            fpp_log_message("File successfully saved: \"%s\"", out_fname);
        }
    }
    else if (decrypt_mode) {
        passwd1 = fpp_getpass("Enter pass phrase: ");
        if (!passwd1) {
            fpp_log_error(FPP_FAILURE, "Invalid input passwords");
            goto failed;
        }

        if (!out_fname) {
            snprintf(temp_fname, strlen(in_fname) - 3, "%s", in_fname);
            out_fname = temp_fname;
        }

        params.in_fname = in_fname;
        params.out_fname = out_fname;
        params.header_fname = header_fname;
        params.text_passwd = passwd1;
        params.iter = iter;

        err = fpp_decrypt_file(&params);
        if (err != EXIT_SUCCESS) {
            fpp_log_message("Failed to decrypt file");
            goto failed;
        }

        fpp_log_message("File successfully saved: %s", out_fname);
    }

    if (passwd1) {
        fpp_explicit_memzero((uint8_t *) passwd1, strlen(passwd1));
        free(passwd1);
    }
    if (passwd2) {
        fpp_explicit_memzero((uint8_t *) passwd2, strlen(passwd2));
        free(passwd2);
    }

    return 0;

failed:
    if (passwd2) {
        fpp_explicit_memzero((uint8_t *) passwd2, strlen(passwd2));
        free(passwd2);
    }
    if (passwd1) {
        fpp_explicit_memzero((uint8_t *) passwd1, strlen(passwd1));
        free(passwd1);
    }

#if (_WIN32)
    system("pause");
#endif
    return 1;
}
