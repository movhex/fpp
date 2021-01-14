/* 
 * This file is part of FPP (File Protection Program).
 *
 * See LICENSE for licensing information.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "memory.h"


void
fpp_explicit_memzero(uint8_t *buf, size_t n)
{
    memset(buf, 0, n);
    fpp_memory_barrier();
}
