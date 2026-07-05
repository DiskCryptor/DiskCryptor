/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2026
    * DavidXanatos <info@diskcryptor.org>
    * Copyright (c) 2012
    * ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
    *

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 3 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <ntifs.h>
#include "driver.h"
#include "debug.h"
#include "crypto_functions.h"
#ifdef _M_ARM64
//#include "xts_small.h"
//#include "sha512_pkcs5_2_small.h"
#include "xts_fast.h"
#include "sha512_pkcs5_2.h"
#include "xts_serpent_neon.h"
#include "xts_aes_ce.h"
#else
#include "xts_fast.h"
#include "aes_padlock.h"
#include "xts_serpent_sse2.h"
#include "xts_serpent_avx.h"
#include "sha512_pkcs5_2.h"
#endif
#include "..\crc32.h"
#include "misc_mem.h"
#include "..\crypto\Argon2\argon2.h"

typedef struct _XTS_TEST_CONTEXT {
	unsigned char  key[XTS_FULL_KEY];
	unsigned short test[XTS_SECTOR_SIZE*8 / sizeof(unsigned short)];
	unsigned short buff[XTS_SECTOR_SIZE*8 / sizeof(unsigned short)];
	xts_key        xkey;

} XTS_TEST_CONTEXT, *PXTS_TEST_CONTEXT;

static const struct { /* These values were obtained using Brian Gladman's XTS implementation */
	int alg;
	unsigned long e_crc;
	unsigned long d_crc;

} xts_crc_vectors[] = {
	{ CF_AES,                 0xd5faad12, 0xf78e1ee6 },
	{ CF_TWOFISH,             0x63f53fab, 0xf0bf3fe2 },
	{ CF_SERPENT,             0xc63098ff, 0xa27615ad },
	{ CF_AES_TWOFISH,         0xeb80c77a, 0x05c1f39c },
	{ CF_TWOFISH_SERPENT,     0x1f5b5c3a, 0x533b76ca },
	{ CF_SERPENT_AES,         0x1604a6b2, 0x637378c7 },
	{ CF_AES_TWOFISH_SERPENT, 0x48deea37, 0x02b2a064 }
};

static const struct {
  int          i_count;
  const char*  password;
  const char*  salt;
  int          dklen;
  const char*  key;
} pkcs5_vectors[] = {
	{ 5, "password", "\x12\x34\x56\x78", 4, "\x13\x64\xae\xf8" },
	{ 5, "password", "\x12\x34\x56\x78", 144, 
		"\x13\x64\xae\xf8\x0d\xf5\x57\x6c\x30\xd5\x71\x4c\xa7\x75\x3f\xfd"
		"\x00\xe5\x25\x8b\x39\xc7\x44\x7f\xce\x23\x3d\x08\x75\xe0\x2f\x48"
		"\xd6\x30\xd7\x00\xb6\x24\xdb\xe0\x5a\xd7\x47\xef\x52\xca\xa6\x34"
		"\x83\x47\xe5\xcb\xe9\x87\xf1\x20\x59\x6a\xe6\xa9\xcf\x51\x78\xc6"
		"\xb6\x23\xa6\x74\x0d\xe8\x91\xbe\x1a\xd0\x28\xcc\xce\x16\x98\x9a"
		"\xbe\xfb\xdc\x78\xc9\xe1\x7d\x72\x67\xce\xe1\x61\x56\x5f\x96\x68"
		"\xe6\xe1\xdd\xf4\xbf\x1b\x80\xe0\x19\x1c\xf4\xc4\xd3\xdd\xd5\xd5"
		"\x57\x2d\x83\xc7\xa3\x37\x87\xf4\x4e\xe0\xf6\xd8\x6d\x65\xdc\xa0"
		"\x52\xa3\x13\xbe\x81\xfc\x30\xbe\x7d\x69\x58\x34\xb6\xdd\x41\xc6" }
};

typedef struct {
	u32          t_cost;
	u32          m_cost;
	u32          parallelism;
	const char*  password;
	const char*  salt;
	argon2_type  type;
	int          dklen;
	const char*  key;
} argon2_test_vector;

static const argon2_test_vector argon2_vectors[] = {
	/* Argon2id test vectors - t, m, p*/
	{
		5, 384 * 1024, 4, "password", "somesalt", Argon2_id, 256, // Recommended
		"\xab\x78\x18\x67\x25\x0b\xe3\x80\xda\xd7\xd5\xea\xe7\xea\x13\x26"
		"\xac\x2e\xe3\x7c\x10\x25\x68\x3f\x09\x84\xde\x25\x9d\x18\x58\xdf"
		"\x23\x1f\x4e\x61\xd3\xc5\x88\xf8\xbb\x07\xdb\xf6\xbf\x97\xe2\x7e"
		"\xaa\x70\xd8\xdc\xb3\x77\x9a\x7d\x09\x83\xa9\x7e\x61\x8e\xa3\x6d"
		"\xc9\x25\x80\x91\xd8\x8d\xdd\xaf\x89\xbe\xd9\x02\x3f\x8c\xf8\xe4"
		"\x91\x0a\x81\xe9\xf5\x01\xb0\xfb\x04\xb6\xea\xc3\x3a\x3b\x2e\x0f"
		"\xf5\x93\x7c\x34\xec\xe6\x42\xac\x96\xc2\xa8\xa5\x11\xbd\xb3\xfb"
		"\x88\xd6\x94\xa5\x68\xa0\x53\x43\x90\x2f\xef\x6e\x4b\x61\x41\x1b"
		"\xef\xe9\x70\x79\x15\xac\xb0\x01\x9a\x61\x92\xbc\x6e\x0a\x2f\xaa"
		"\xd1\xc1\xf0\xdb\x29\x71\x65\xab\x37\x93\x5a\xfb\x82\xc6\x77\x3f"
		"\xed\xe5\xe6\xbf\x7d\xac\x9a\x3e\x3a\xad\x70\xe6\x4e\x28\x46\x29"
		"\xc6\x36\x16\x1d\x0b\xc4\xee\xdc\x6e\xbc\x43\x5e\x25\xe9\x8b\xa0"
		"\x95\x61\x4c\xe5\xee\x02\xbe\x04\x02\x4e\xed\xd9\x3f\x81\xe5\xb0"
		"\x99\x10\xc8\xdf\x5d\x0c\x39\xb2\x57\x6e\xb4\x89\x65\xea\xab\xcd"
		"\xb3\x7a\x39\x50\x84\xf1\x2b\xf3\xa9\x55\x5f\x38\xdd\xf1\x08\x88"
		"\x65\x24\x54\x60\x9a\xd0\x3d\xca\xf5\x9a\xaf\x0b\x92\xb4\x14\x14"
	},
};

static void dc_simple_encryption_test()
{
	PXTS_TEST_CONTEXT ctx;
	unsigned char     dk[256];
	unsigned long     e_crc, d_crc, i, resl;

	// test PBKDF2
	for (i = 0; i < (sizeof(pkcs5_vectors) / sizeof(pkcs5_vectors[0])); i++)
	{
		sha512_pkcs5_2(pkcs5_vectors[i].i_count,
			           pkcs5_vectors[i].password, strlen(pkcs5_vectors[i].password),
					   pkcs5_vectors[i].salt, strlen(pkcs5_vectors[i].salt),
					   dk, pkcs5_vectors[i].dklen);

		if (memcmp(dk, pkcs5_vectors[i].key, pkcs5_vectors[i].dklen) != 0)
		{
			KeBugCheckEx(STATUS_ENCRYPTION_FAILED, 'DCRP', i, 0, 0);
		}
	}
	DbgMsg("PBKDF2 test passed\n");

	// test Argon2id KDF
	for (i = 0; i < (sizeof(argon2_vectors) / sizeof(argon2_vectors[0])); i++)
	{
		resl = argon2_hash(argon2_vectors[i].t_cost, argon2_vectors[i].m_cost, argon2_vectors[i].parallelism,
			argon2_vectors[i].password, strlen(argon2_vectors[i].password),
			argon2_vectors[i].salt, strlen(argon2_vectors[i].salt),
			dk, argon2_vectors[i].dklen, argon2_vectors[i].type, ARGON2_VERSION_13, NULL);
		if (resl != ARGON2_OK) { break; }

		if (memcmp(dk, argon2_vectors[i].key, argon2_vectors[i].dklen) != 0) 
		{
			KeBugCheckEx(STATUS_ENCRYPTION_FAILED, 'DCRP', 0x0A00 | i, 0, 0);
		}
	}
	if (resl == ARGON2_OK) {
		SetFlag(dc_load_flags, DST_ARGON2_OK);
		DbgMsg("Argon2id selftest passed\n");
	}
	else { // note: if this fails, it may be due to insufficient memory
		DbgMsg("Argon2id failed at vector %u with error code %d\n", i, resl);
	}

	// test XTS engine if memory may be allocated
	if ( (KeGetCurrentIrql() <= DISPATCH_LEVEL) &&
		 (ctx = (PXTS_TEST_CONTEXT)mm_secure_alloc(sizeof(XTS_TEST_CONTEXT))) != NULL )
	{
		// fill key and test buffer
		for (i = 0; i < (sizeof(ctx->key) / sizeof(ctx->key[0])); i++) ctx->key[i] = (unsigned char)i;
		for (i = 0; i < (sizeof(ctx->test) / sizeof(ctx->test[0])); i++) ctx->test[i] = (unsigned short)i;

		// run test cases
		for (i = 0; i < (sizeof(xts_crc_vectors) / sizeof(xts_crc_vectors[0])); i++)
		{
			if (!xts_set_key(ctx->key, xts_crc_vectors[i].alg, &ctx->xkey)) 
			{
				KeBugCheckEx(STATUS_ENCRYPTION_FAILED, 'DCRP', 0xFF00 | i, 0, 0);
			}

			xts_encrypt((const unsigned char*)ctx->test, (unsigned char*)ctx->buff, sizeof(ctx->test), 0x3FFFFFFFC00, &ctx->xkey);
			e_crc = crc32((const unsigned char*)ctx->buff, sizeof(ctx->buff));

			xts_decrypt((const unsigned char*)ctx->test, (unsigned char*)ctx->buff, sizeof(ctx->test), 0x3FFFFFFFC00, &ctx->xkey);
			d_crc = crc32((const unsigned char*)ctx->buff, sizeof(ctx->buff));

			if ( e_crc != xts_crc_vectors[i].e_crc || d_crc != xts_crc_vectors[i].d_crc )
			{
				KeBugCheckEx(STATUS_ENCRYPTION_FAILED, 'DCRP', 0xFF00 | i, e_crc, d_crc);
			}
		}

		DbgMsg("XTS test passed\n");
		mm_secure_free(ctx);
	}
}

void dc_init_encryption()
{
	DbgMsg("dc_init_encryption\n");

#if defined(_M_IX86) || defined(_M_X64)
	if (aes256_padlock_available() != 0) {
		SetFlag(dc_load_flags, DST_VIA_PADLOCK);
		DbgMsg("CpuFlags_VIA_PadLock: Yes\n");
	} else {
		ClearFlag(dc_load_flags, DST_VIA_PADLOCK);
		DbgMsg("CpuFlags_VIA_PadLock: No\n");
	}
	
	if (xts_aes_ni_available() != 0) {
		SetFlag(dc_load_flags, DST_INTEL_NI);
		DbgMsg("CpuFlags_AES_NI: Yes\n");
	} else {
		ClearFlag(dc_load_flags, DST_INTEL_NI);
		DbgMsg("CpuFlags_AES_NI: No\n");
	}
#else
	ClearFlag(dc_load_flags, DST_VIA_PADLOCK);
	ClearFlag(dc_load_flags, DST_INTEL_NI);
#endif

#ifdef _M_IX86
	if (xts_serpent_sse2_available() != 0) {
		SetFlag(dc_load_flags, DST_INSTR_SSE2);
		DbgMsg("CpuFlags_SSE2: Yes\n");
	} else {
		ClearFlag(dc_load_flags, DST_INSTR_SSE2);
		DbgMsg("CpuFlags_SSE2: No\n");
	}
#else
	DbgMsg("CpuFlags_SSE2: Yes\n");
	SetFlag(dc_load_flags, DST_INSTR_SSE2);
#endif

#if defined(_M_IX86) || defined(_M_X64)
	if (xts_serpent_avx_available() != 0) {
		SetFlag(dc_load_flags, DST_INSTR_AVX);
		DbgMsg("CpuFlags_AVX: Yes\n");
	} else {
		ClearFlag(dc_load_flags, DST_INSTR_AVX);
		DbgMsg("CpuFlags_AVX: No\n");
	}
#else
	ClearFlag(dc_load_flags, DST_INSTR_AVX);
#endif

#ifdef _M_ARM64
	if (xts_aes_ce_available() != 0) {
		SetFlag(dc_load_flags, DST_ARM64_CE);
		DbgMsg("CpuFlags_ARM64_CE: Yes\n");
	} else {
		ClearFlag(dc_load_flags, DST_ARM64_CE);
		DbgMsg("CpuFlags_ARM64_CE: No\n");
	}

	if (xts_serpent_neon_available() != 0) {
		SetFlag(dc_load_flags, DST_ARM64_NEON);
		DbgMsg("CpuFlags_ARM64_NEON: Yes\n");
	} else {
		ClearFlag(dc_load_flags, DST_ARM64_NEON);
		DbgMsg("CpuFlags_ARM64_NEON: No\n");
	}
#else
	ClearFlag(dc_load_flags, DST_ARM64_CE);
	ClearFlag(dc_load_flags, DST_ARM64_NEON);
#endif

	// initialize XTS mode engine and run small encryption test
	xts_init(dc_conf_flags & CONF_HW_CRYPTO);
	dc_simple_encryption_test();
}

void dc_free_encryption()
{
}
