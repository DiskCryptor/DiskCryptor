#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <io.h>      /* _isatty */
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
	#include "xts_fast.h"
	#ifdef _M_ARM64
		#include "xts_aes_ce.h"
		#include "xts_serpent_neon.h"
	#else
		/* crypto_lib has no VIA PadLock: it was x86-only, and crypto_lib is
		   amd64 and ARM64. It does have an AVX2 Serpent tier, which
		   crypto_fast never had. */
		#ifndef CRYPTO_LIB
			#include "aes_padlock.h"
		#endif
		#include "xts_aes_ni.h"
		#include "xts_serpent_sse2.h"
		#include "xts_serpent_avx.h"
		#ifdef CRYPTO_LIB
			#include "xts_serpent_avx2.h"
		#endif
	#endif
	#include "crc32_test.h"
	#include "sha512_hmac_drbg_test.h"
#endif

int main(int argc, char *argv[])
{
	BOOLEAN passed = TRUE;

#ifndef SMALL_CODE
	#ifdef _M_ARM64
	printf("ARM64 AES-CE support: %d\n", xts_aes_ce_available());
	printf("ARM64 NEON support: %d\n", xts_serpent_neon_available());
	#else
		#if !defined(_M_X64) && !defined(CRYPTO_LIB)
	printf("VIA-Padlock support: %d\n", aes256_padlock_available());
		#endif
	printf("AES-NI support: %d\n", xts_aes_ni_available());
	printf("SSE2 support: %d\n", xts_serpent_sse2_available());
		/*
		 * The two AVX tiers exist only where the library was built with
		 * CL_ENABLE_AVX / CL_ENABLE_AVX2 - user mode. The kernel and EFI builds
		 * omit them because MSVC will not take /arch:AVX with /kernel, and the
		 * dispatcher stays on SSE2 there.
		 */
		#if !defined(CRYPTO_LIB) || defined(CL_ENABLE_AVX)
	printf("AVX  support: %d\n", xts_serpent_avx_available());
		#endif
		#if defined(CRYPTO_LIB) && defined(CL_ENABLE_AVX2)
	printf("AVX2 support: %d\n", xts_serpent_avx2_available());
		#endif
	#endif
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

	/*
	 * Wait for a key only when a person is watching.
	 *
	 * _getch() reads the console directly rather than stdin, so a redirected or
	 * piped run cannot satisfy it and simply hangs - which is what happens to
	 * anything that tries to run this from a script. Checking whether stdout is
	 * still a console distinguishes the two cases without needing an argument.
	 */
	if (_isatty(_fileno(stdout))) {
		_getch();
	}

	/* and report the result in the one way a script can read */
	return passed ? 0 : 1;
}