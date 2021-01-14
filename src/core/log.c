/* 
 * This file is part of FPP (File Protection Program).
 *
 * See LICENSE for licensing information.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "log.h"


static bool fpp_quite_mode;

void
fpp_enable_quite_mode(void)
{
    fpp_quite_mode = true;
}

void
fpp_disable_quite_mode(void)
{
    fpp_quite_mode = false;
}

bool
fpp_is_quite_mode(void)
{
    return fpp_quite_mode;
}

void
fpp_log_message(const char *fmt, ...)
{
    char errstr[FPP_MAX_ERRSTRLEN];
    va_list args;

    if (fpp_is_quite_mode()) {
        return;
    }

    va_start(args, fmt);
    vsnprintf(errstr, FPP_MAX_ERRSTRLEN, fmt, args);
    va_end(args);

    fprintf(stdout, "%s\n", errstr);
}

void
fpp_log_error(fpp_err_t errcode, const char *fmt, ...)
{
    char errstr[FPP_MAX_ERRSTRLEN];
    va_list args;

    va_start(args, fmt);
    vsnprintf(errstr, FPP_MAX_ERRSTRLEN, fmt, args);
    va_end(args);

    fprintf(stdout, "Error %d: %s\n", errcode, errstr);
}
