#ifndef XMSS_RANDOMBYTES_H
#define XMSS_RANDOMBYTES_H
 
#include "randombytes.h"
 
#include <stdint.h>
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
 
#include <wolfssl/wolfcrypt/visibility.h>


#include <wolfssl/wolfcrypt/random.h>
 
 
#include <stdio.h>
/**
 * Tries to read xlen bytes from a source of randomness, and writes them to x.
 */
WOLFSSL_API void randombytes(unsigned char *x, unsigned long long xlen);
WOLFSSL_API int generate_random_bytes(byte *buf, word32 size);

#endif
