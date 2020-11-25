#ifndef SIGN_H
#define SIGN_H

#include <stddef.h>
#include <stdint.h>
#include <wolfssl/wolfcrypt/DILITHIUM/params.h>
#include <wolfssl/wolfcrypt/DILITHIUM/polyvec.h>
#include <wolfssl/wolfcrypt/DILITHIUM/poly.h> 

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
 
#include <wolfssl/wolfcrypt/visibility.h>
 
#define challenge DILITHIUM_NAMESPACE(_challenge)
WOLFSSL_API void challenge(poly *c, const uint8_t seed[SEEDBYTES]);

#define crypto_sign_keypair DILITHIUM_NAMESPACE(_keypair)
WOLFSSL_API int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

#define crypto_sign_signature DILITHIUM_NAMESPACE(_signature)
WOLFSSL_API int crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *sk);

#define crypto_sign DILITHIUM_NAMESPACE()
WOLFSSL_API int crypto_sign(uint8_t *sm, size_t *smlen,
                const uint8_t *m, size_t mlen,
                const uint8_t *sk);

#define crypto_sign_verify DILITHIUM_NAMESPACE(_verify)
WOLFSSL_API int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen,
                       const uint8_t *pk);

#define crypto_sign_open DILITHIUM_NAMESPACE(_open)
WOLFSSL_API int crypto_sign_open(uint8_t *m, size_t *mlen,
                     const uint8_t *sm, size_t smlen,
                     const uint8_t *pk);

#endif
