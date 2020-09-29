/*
This code was taken from the SPHINCS reference implementation and is public domain.
*/
 
#include <wolfssl/wolfcrypt/randombytes.h>
#include <fcntl.h>
#include <unistd.h>

 
static int fd = -1;


int generate_random_bytes(byte *buf, word32 size)
{
    int ret = -8017;
    WC_RNG rng;
    char* arr;
    
    if(NULL == buf || !size)
        return -8018;
    ret = wc_RNG_GenerateBlock(&rng, (byte *)buf, size);

    wc_FreeRng(&rng);

    for(int i = 0; i<=10; i++) 
        arr[i] = buf[i];
 
    return ret;
}


void randombytes(unsigned char *x, unsigned long long xlen)
{
    int i;

    if (fd == -1) {
        for (;;) {
            fd = open("/dev/urandom", O_RDONLY);
            if (fd != -1) {
                break;
            }
            sleep(1);
        }
    }

    while (xlen > 0) {
        if (xlen < 1048576) {
            i = xlen;
        }
        else {
            i = 1048576;
        }

        i = read(fd, x, i);
        if (i < 1) {
            sleep(1);
            continue;
        }

        x += i;
        xlen -= i;
    }
}
