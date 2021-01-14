/* 
 * This file is part of FPP (File Protection Program).
 *
 * See LICENSE for licensing information.
 */

#include "errcodes.h"


const char *
fpp_strerror(fpp_err_t errcode)
{
    switch (errcode) {
    case FPP_ERR_IO_ARGV:
        return "Invalid input argument.";
    case FPP_ERR_IO_EXIST:
        return "File already exist.";
    case FPP_ERR_IO_FORMAT:
        return "Failed to determine file format.";
    default:
        return "Unknow error code.";
    }
}
