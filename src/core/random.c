/* 
 * This file is part of FPP (File Protection Program).
 *
 * See LICENSE for licensing information.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

#include "random.h"

fpp_err_t
fpp_random_bytes(uint8_t *buf, size_t in_len)
{
    RAND_poll();

    if (RAND_status() != 1) {
        return EXIT_FAILURE;
    }
    if (RAND_bytes(buf, in_len) != 1) {
        return EXIT_FAILURE;
    }

    RAND_cleanup();
    return EXIT_SUCCESS;
}
