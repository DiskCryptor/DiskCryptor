#ifndef _AES_ASM_H_
#define _AES_ASM_H_

#include "aes_key.h"

#ifdef _M_IX86
 void _stdcall aes256_asm_set_key(const unsigned char *key, aes256_key *skey);
 void _stdcall aes256_asm_encrypt(const unsigned char *in, unsigned char *out, aes256_key *key);
 void _stdcall aes256_asm_decrypt(const unsigned char *in, unsigned char *out, aes256_key *key);
#elif defined(_M_ARM64)
 #define aes256_asm_set_key aes256_set_key
 /* ARM64: Use CE-accelerated functions from xts_aes_ce.c */
 void _stdcall aes256_arm64_encrypt(const unsigned char *in, unsigned char *out, aes256_key *key);
 void _stdcall aes256_arm64_decrypt(const unsigned char *in, unsigned char *out, aes256_key *key);
 #define aes256_asm_encrypt aes256_arm64_encrypt
 #define aes256_asm_decrypt aes256_arm64_decrypt
#else
 /* x64: Use assembly implementations */
 #define aes256_asm_set_key aes256_set_key
 void _stdcall aes256_asm_encrypt(const unsigned char *in, unsigned char *out, aes256_key *key);
 void _stdcall aes256_asm_decrypt(const unsigned char *in, unsigned char *out, aes256_key *key);
#endif

#endif