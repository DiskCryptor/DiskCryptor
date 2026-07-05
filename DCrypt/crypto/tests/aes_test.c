#include <windows.h>
#ifdef SMALL_CODE
	#include "aes_small.h"
	#include "aes_padlock_small.h"
#else
	#include "aes_key.h"
	#include "aes_asm.h"
	#ifndef _M_ARM64
		#include "aes_padlock.h"
	#endif
#endif

static const struct { /* see FIPS-197 */
	const __declspec(align(16)) unsigned char key[32];
	const __declspec(align(16)) unsigned char plaintext[16];
	const __declspec(align(16)) unsigned char ciphertext[16];
} aes256_vectors[] = {
	{
		{ 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
		  0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f },
		{ 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff },
		{ 0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89 }
	},
	{
		{ 0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c,
		  0x76,0x2e,0x71,0x60,0xf3,0x8b,0x4d,0xa5,0x6a,0x78,0x4d,0x90,0x45,0x19,0x0c,0xfe },
		{ 0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34 },
		{ 0x1a,0x6e,0x6c,0x2c,0x66,0x2e,0x7d,0xa6,0x50,0x1f,0xfb,0x62,0xbc,0x9e,0x93,0xf3 }
	}
};

int test_aes256()
{
	__declspec(align(16)) unsigned char tmp[16];
	aes256_key                          skey;
	int                                 i;
#if !defined(SMALL_CODE) && !defined(_M_ARM64)
	DWORD                               old_protect;
#endif

#ifdef SMALL_CODE
	// initialize AES tables
	aes256_gentab();
#elif !defined(_M_ARM64)
	// allow execute code from key buffer (x86/x64 only - uses self-modifying code)
	if (VirtualProtect(&skey, sizeof(skey), PAGE_EXECUTE_READWRITE, &old_protect) == FALSE) return 0;
#endif
	
	// test basic assembler inmpementation
	for (i = 0; i < _countof(aes256_vectors); i++) 
	{
#ifdef SMALL_CODE
		aes256_set_key(aes256_vectors[i].key, &skey);
		aes256_encrypt(aes256_vectors[i].plaintext, tmp, &skey);
#else
		aes256_asm_set_key(aes256_vectors[i].key, &skey);
		aes256_asm_encrypt(aes256_vectors[i].plaintext, tmp, &skey);
#endif
		if (memcmp(aes256_vectors[i].ciphertext, tmp, sizeof(tmp)) != 0) return 0;
#ifdef SMALL_CODE
		aes256_decrypt(aes256_vectors[i].ciphertext, tmp, &skey);
#else
		aes256_asm_decrypt(aes256_vectors[i].ciphertext, tmp, &skey);
#endif
		if (memcmp(aes256_vectors[i].plaintext, tmp, sizeof(tmp)) != 0) return 0;

		// test AES with VIA Padlock API (x86/x64 only)
#if (!defined(SMALL_CODE) || !defined(_M_X64)) && !defined(_M_ARM64)
		if (aes256_padlock_available() != 0)
		{
			aes256_padlock_rekey();
#ifdef SMALL_CODE
			aes256_padlock_encrypt(aes256_vectors[i].plaintext, tmp, &skey);
#else
			aes256_padlock_encrypt(aes256_vectors[i].plaintext, tmp, 1, &skey);
#endif
			if (memcmp(aes256_vectors[i].ciphertext, tmp, sizeof(tmp)) != 0) return 0;

			aes256_padlock_rekey();
#ifdef SMALL_CODE
			aes256_padlock_decrypt(aes256_vectors[i].ciphertext, tmp, &skey);
#else
			aes256_padlock_decrypt(aes256_vectors[i].ciphertext, tmp, 1, &skey);
#endif
			if (memcmp(aes256_vectors[i].plaintext, tmp, sizeof(tmp)) != 0) return 0;
		}
#endif
	}
	// all tests passed
	return 1;
}