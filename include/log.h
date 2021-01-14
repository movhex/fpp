/* 
 * This file is part of FPP (File Protection Program).
 *
 * See LICENSE for licensing information.
 */

#ifndef LOG_H
#define LOG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

#include "errcodes.h"

void fpp_enable_quite_mode(void);
void fpp_disable_quite_mode(void);
bool fpp_is_quite_mode(void);

void fpp_log_message(const char *fmt, ...);
void fpp_log_error(fpp_err_t errcode, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif /* LOG_H */
