#ifndef _PRNG_
#define _PRNG_

#include "defines.h"
//#ifdef _M_ARM64
//#include "aes_small.h"
//#else
#include "aes_key.h"
//#endif

void cp_rand_add_seed(void *data, int size);
void cp_rand_reseed();
int  cp_rand_bytes(u8 *buf, int len);
int  cp_rand_init();

#endif