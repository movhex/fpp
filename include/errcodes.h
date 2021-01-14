/* 
 * This file is part of FPP (File Protection Program).
 *
 * See LICENSE for licensing information.
 */

#ifndef ERRCODES_H
#define ERRCODES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>
#include <openssl/err.h>
#if (_WIN32)
#include <windows.h>
#endif

#if (_WIN32)
#define fpp_get_os_errno()           GetLastError()
#else
#define fpp_get_os_errno()           errno
#endif

#define fpp_get_openssl_errno()      ERR_get_error()

#define FPP_MAX_ERRSTRLEN            2048


#define FPP_APPLICATION_START_ERROR  20000

#define FPP_ERR_IO                   (FPP_APPLICATION_START_ERROR + 0)
#define FPP_ERR_IO_ARGV              (FPP_ERR_IO + 1)
#define FPP_ERR_IO_EXIST             (FPP_ERR_IO + 2)
#define FPP_ERR_IO_FORMAT            (FPP_ERR_IO + 3)

#define FPP_OK                       0
#define FPP_FAILURE                 -1


typedef int fpp_err_t;

const char *fpp_strerror(fpp_err_t errcode);

#ifdef __cplusplus
}
#endif

#endif /* ERRCODES_H */
