/* 
 * This file is part of FPP (File Protection Program).
 *
 * See LICENSE for licensing information.
 */

#ifndef RANDOM_H
#define RANDOM_H

#include "errcodes.h"

#ifdef __cplusplus
extern "C" {
#endif

fpp_err_t fpp_random_bytes(uint8_t *buf, size_t in_len);

#ifdef __cplusplus
}
#endif

#endif /* RANDOM_H */
