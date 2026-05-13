#include <stddef.h>

void qrx_secure_bzero(void *ptr, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while(len--) *p++ = 0;
}
