/* 
 * This file is part of FPP (File Protection Program).
 *
 * See LICENSE for licensing information.
 */

#ifndef GETPASS_H
#define GETPASS_H

#ifdef __cplusplus
extern "C" {
#endif

#define FPP_PASSWORD_BUFSIZE  256

char *fpp_getpass(const char *promt);

#ifdef __cplusplus
}
#endif

#endif /* GETPASS_H */
