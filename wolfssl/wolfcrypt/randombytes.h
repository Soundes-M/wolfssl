#ifndef XMSS_RANDOMBYTES_H
#define XMSS_RANDOMBYTES_H
 
#include "randombytes.h"

#include "config.h"
#include <wolfssl/wolfcrypt/visibility.h>

/**
 * Tries to read xlen bytes from a source of randomness, and writes them to x.
 */
WOLFSSL_API void randombytes(unsigned char *x, unsigned long long xlen);

#endif
