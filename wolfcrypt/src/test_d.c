
#include <stdint.h>
#include <wolfssl/wolfcrypt/test_d.h> 

#include <stdio.h>

/* This file provides wrapper functions that take keys that include OIDs to
identify the parameter set to be used. After setting the parameters accordingly
it falls back to the regular XMSS core functions. */

int crypto_addd(int a)
{
    return a;
}
 
