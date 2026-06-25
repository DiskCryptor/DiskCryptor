#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include "sha512_test.h"
#include "sha512_hmac_test.h"
#include "pkcs5_test.h"
#include "argon2_test.h"
#include "aes_test.h"
#include "twofish_test.h"
#include "serpent_test.h"
#include "xts_test.h"
#ifdef SMALL_CODE
	#include "aes_padlock_small.h"
	#include "xts_aes_test.h"
#else
	#include "aes_padlock.h"
	#include "xts_fast.h"
	#include "xts_aes_ni.h"
	#include "xts_serpent_sse2.h"
	#include "xts_serpent_avx.h"
	#include "crc32_test.h"
	#include "sha512_hmac_drbg_test.h"
#endif

int main(int argc, char *argv[])
{
	BOOLEAN passed = TRUE;

#if !defined(SMALL_CODE) || !defined(_M_X64)
	printf("VIA-Padlock support: %d\n", aes256_padlock_available());
#endif
#ifndef SMALL_CODE
	printf("AES-NI support: %d\n", xts_aes_ni_available());
	printf("SSE2 support: %d\n", xts_serpent_sse2_available());
	printf("AVX  support: %d\n", xts_serpent_avx_available());
	printf("--------------------------\n");

	if ( test_crc32() ) {
		printf("crc32: PASSED\n");
	} else {
		printf("crc32: FAILED\n");
		passed = FALSE;
	}
#endif
	if ( test_sha512() ) {
		printf("sha512: PASSED\n");
	} else {
		printf("sha512: FAILED\n");
		passed = FALSE;
	}
	if ( test_sha512_hmac() ) {
		printf("SHA512-HMAC: PASSED\n");
	} else {
		printf("SHA512-HMAC: FAILED\n");
		passed = FALSE;
	}
#ifndef SMALL_CODE
	if ( test_sha512_hmac_drbg() ) {
		printf("SHA512-HMAC-DRBG: PASSED\n");
	} else {
		printf("SHA512-HMAC-DRBG: FAILED\n");
		passed = FALSE;
	}
#endif
	if ( test_pkcs5() ) {
		printf("pkcs5: PASSED\n");
	} else {
		printf("pkcs5: FAILED\n");
		passed = FALSE;
	}
	if ( test_argon2() ) {
		printf("Argon2: PASSED\n");
	} else {
		printf("Argon2: FAILED\n");
		passed = FALSE;
	}
	if ( test_aes256() ) {
		printf("Aes-256: PASSED\n");
	} else {
		printf("Aes-256: FAILED\n");
		passed = FALSE;
	}
	if ( test_twofish256() ) {
		printf("Twofish-256: PASSED\n");
	} else {
		printf("Twofish-256: FAILED\n");
		passed = FALSE;
	}
	if ( test_serpent256() ) {
		printf("Serpent-256: PASSED\n");
	} else {
		printf("Serpent-256: FAILED\n");
		passed = FALSE;
	}

	if ( test_xts_mode() ) {
		printf("XTS (all ciphers): PASSED\n");
	} else {
		printf("XTS (all ciphers): FAILED\n");
		passed = FALSE;
	}

#ifdef SMALL_CODE
	if ( test_xts_aes_only() ) {
		printf("XTS-AES: PASSED\n");
	} else {
		printf("XTS-AES: FAILED\n");
		passed = FALSE;
	}
#endif

	printf("--------------------------\n");
	printf("TOTAL: %s\n", passed ? "PASSED" : "FAILED");
	_getch();
	return 0;
}