/* 
 * This file is part of FPP (File Protection Program).
 *
 * See LICENSE for licensing information.
 */

#ifndef SHA3_256_H
#define SHA3_256_H

#ifdef __cplusplus
extern "C" {
#endif

#define FPP_SHA3_256_BUFSIZE  32

uint8_t *fpp_hash_sha3_256_ex(const uint8_t *in_data, size_t in_size,
    uint8_t *buf);

#ifdef __cplusplus
}
#endif

#endif /* SHA3_256_H */
