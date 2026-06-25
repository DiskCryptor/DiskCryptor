/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2026
    * DavidXanatos <info@diskcryptor.org>
    * Copyright (c) 2007-2011
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
#include "defines.h"
#include "driver.h"
#ifdef _M_ARM64
#include "xts_small.h"
#else
#include "xts_fast.h"
#endif
#include "prng.h"
#include "fast_crypt.h"
#include "benchmark.h"
#include "misc_mem.h"
#include "crypto_head.h"
#ifdef _M_ARM64
#include "sha512_pkcs5_2_small.h"
#else
#include "sha512_pkcs5_2.h"
#endif
#include "../Argon2/argon2.h"

#define TEST_BLOCK_LEN (1024*1024*8)
#define TEST_BLOCK_NUM (4)

int dc_k_benchmark(int cipher, dc_bench_info *info)
{
	UCHAR    dkey[DISKKEY_SIZE];	
	xts_key* xkey = NULL;
	PUCHAR   buff = NULL;
	int      resl = ST_NOMEM, i;
	u64      offs = 0, time;

	/* allocate memory */
	if ( (buff = mm_pool_alloc(TEST_BLOCK_LEN)) == NULL ) goto exit;
	if ( (xkey = mm_secure_alloc(sizeof(xts_key))) == NULL ) goto exit;
	
	/* setup initial test block and key */
	for (i = 0; i < TEST_BLOCK_LEN; i++) buff[i] = i % 256;
	for (i = 0; i < DISKKEY_SIZE; i++) dkey[i] = i % 256;
	if (!xts_set_key(dkey, cipher, xkey)) { resl = ST_INVALID_PARAM; goto exit; }
	/* query performance frequency */
	KeQueryPerformanceCounter((PLARGE_INTEGER)&info->cpufreq);
	if (info->cpufreq == 0) goto exit;

	/* repeat benchmark some times */
	for (info->enctime = 0, info->datalen = 0; ((info->enctime * 10) / info->cpufreq) < 5;)
	{
		/* do benchmark */
		time = KeQueryPerformanceCounter(NULL).QuadPart;

		for (i = 0; i < TEST_BLOCK_NUM; i++) {
			cp_fast_encrypt(buff, buff, TEST_BLOCK_LEN, offs, xkey);
			offs += TEST_BLOCK_LEN;
		}
		info->enctime += KeQueryPerformanceCounter(NULL).QuadPart - time;
		info->datalen += TEST_BLOCK_LEN * TEST_BLOCK_NUM;
	}
	resl = ST_OK;
exit:
	if (buff != NULL) mm_pool_free(buff);
	if (xkey != NULL) mm_secure_free(xkey);
	return resl;
}

int dc_k_benchmark_kdf(int kdf, dc_kdf_bench_info *info)
{
	u8   test_pass[32] = "benchmark_test_password_1234567";
	u8   test_salt[HEADER_SALT_SIZE];
	u8   dk[DISKKEY_SIZE];
	u64  start, end;
	int  i;
	int  resl = ST_OK;

	/* fill salt with test data */
	for (i = 0; i < HEADER_SALT_SIZE; i++)
		test_salt[i] = (u8)(i % 256);

	info->kdf = kdf;

	/* query performance frequency */
	KeQueryPerformanceCounter((PLARGE_INTEGER)&info->cpufreq);
	if (info->cpufreq == 0) return ST_ERROR;

	start = KeQueryPerformanceCounter(NULL).QuadPart;

	if (kdf == 0) {
		/* PBKDF2-SHA512 with 1000 iterations */
		info->memory_mib = 0;
		info->time_cost = 1000;

		sha512_pkcs5_2(1000, test_pass, sizeof(test_pass), test_salt, HEADER_SALT_SIZE, dk, PKCS_DERIVE_MAX);
	}
	else if (kdf > 0) {
		/* Argon2id - compute parameters from kdf */
		u32 memory_cost, time_cost, parallelism;
		argon2_mk_params(kdf, &memory_cost, &time_cost, &parallelism);

		info->memory_mib = memory_cost / 1024;
		info->time_cost = time_cost;
		info->parallelism = parallelism;

		resl = argon2id_hash_raw(time_cost, memory_cost, parallelism, test_pass, sizeof(test_pass),
		                  test_salt, HEADER_SALT_SIZE, dk, DISKKEY_SIZE, NULL);

		if (resl == ARGON2_MEMORY_ALLOCATION_ERROR) {
			info->elapsed_us = 0;
			return ST_OK;
		}
		
		if (resl != ARGON2_OK) {
			resl = ST_ERROR;
		}
	}

	end = KeQueryPerformanceCounter(NULL).QuadPart;

	/* calculate elapsed time in microseconds */
	info->elapsed_us = ((end - start) * 1000000) / info->cpufreq;

	return resl;
}