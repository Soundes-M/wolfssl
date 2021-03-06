#ifndef XMSS_H
#define XMSS_H

#include <stdint.h>
#include <stdint.h>
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
 
#include <wolfssl/wolfcrypt/visibility.h>

/**
 * Generates a XMSS key pair for a given parameter set.
 * Format sk: [OID || (32bit) idx || SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [OID || root || PUB_SEED]
 */
WOLFSSL_API int xmss_keypair(unsigned char *pk, unsigned char *sk, const uint32_t oid);

/**
 * Signs a message using an XMSS secret key.
 * Returns
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 */
WOLFSSL_API int xmss_sign(unsigned char *sk,
              unsigned char *sm, unsigned long long *smlen,
              const unsigned char *m, unsigned long long mlen);

/**
 * Verifies a given message signature pair using a given public key.
 *
 * Note: m and mlen are pure outputs which carry the message in case
 * verification succeeds. The (input) message is assumed to be contained in sm
 * which has the form [signature || message].
 */
WOLFSSL_API int xmss_sign_open(unsigned char *m, unsigned long long *mlen,
                   const unsigned char *sm, unsigned long long smlen,
                   const unsigned char *pk);

/*
 * Generates a XMSSMT key pair for a given parameter set.
 * Format sk: [OID || (ceil(h/8) bit) idx || SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [OID || root || PUB_SEED]
 */
WOLFSSL_API int xmssmt_keypair(unsigned char *pk, unsigned char *sk, const uint32_t oid);

/**
 * Signs a message using an XMSSMT secret key.
 * Returns
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 */
WOLFSSL_API int xmssmt_sign(unsigned char *sk,
                unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen);

/**
 * Verifies a given message signature pair using a given public key.
 *
 * Note: m and mlen are pure outputs which carry the message in case
 * verification succeeds. The (input) message is assumed to be contained in sm
 * which has the form [signature || message].
 */
WOLFSSL_API int xmssmt_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk);

#endif
 
