/* 
 * This file is part of FPP (File Protection Program).
 *
 * See LICENSE for licensing information.
 */

#ifndef MEMORY_H
#define MEMORY_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__)
#define fpp_memory_barrier() __sync_synchronize()
#else
#define fpp_memory_barrier()
#endif

void fpp_explicit_memzero(uint8_t *buf, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* MEMORY_H */
