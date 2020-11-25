#ifndef XMSS_UTILS_H
#define XMSS_UTILS_H

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
 
#include <wolfssl/wolfcrypt/visibility.h>

/**
 * Converts the value of 'in' to 'outlen' bytes in big-endian byte order.
 */
WOLFSSL_API void ull_to_bytes(unsigned char *out, unsigned int outlen,
                  unsigned long long in);

/**
 * Converts the inlen bytes in 'in' from big-endian byte order to an integer.
 */
WOLFSSL_API unsigned long long bytes_to_ull(const unsigned char *in, unsigned int inlen);

#endif
