/*
    *
    * DiskCryptor - open source partition encryption tool
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
#include "prng.h"
#include "misc.h"
//#ifdef _M_ARM64
//#include "sha512_small.h"
//#include "aes_small.h"
//#define aes256_asm_set_key   aes256_set_key
//#define aes256_asm_encrypt   aes256_encrypt
//#define aes256_asm_decrypt   aes256_decrypt
//#else
#include "sha512.h"
#include "aes_key.h"
#include "aes_asm.h"
//#endif
#include "debug.h"
#include "misc_mem.h"

typedef struct _seed_data {
	PEPROCESS       seed1;
	HANDLE          seed2;
	PKTHREAD        seed3;
	HANDLE          seed4;
	ULONG           seed5;
	ULONGLONG       seed6;
	KPRIORITY       seed7;
	ULONG           seed8;
	ULONG           seed9;
	LARGE_INTEGER   seed10;
	ULONGLONG       seed11;
	KPROCESSOR_MODE seed12;
	PVOID           seed13;
	PIRP            seed14;
	MM_SYSTEMSIZE   seed15;
	LARGE_INTEGER   seed16;
	NTSTATUS        seed17;
	UUID            seed18;	
	ULONG           seed19;	
	LARGE_INTEGER   seed20;
	LARGE_INTEGER   seed21;
	ULONG_PTR       seed22;
	ULONG_PTR       seed23;
	KIRQL           seed24;
	ULONG           seed25;
	ULONG           seed26;
	LARGE_INTEGER   seed27;
	LARGE_INTEGER   seed28;
		  
} seed_data;

typedef struct _ext_seed {
	u64 seed1;
	u64 seed2;

} ext_seed;

#define RNG_POOL_SIZE 640

static u8          key_pool[AES_KEY_SIZE];  /* key for encrypt output data */
static u8          rnd_pool[RNG_POOL_SIZE]; /* random data pool            */
static int         rnd_pos;     /* position for add new data to pool */
static u64         reseed_cnt;  /* reseed counter  */
static u64         getrnd_cnt;  /* getrand counter */
static KMUTEX      rnd_mutex;
static aes256_key *rnd_key;

static void cp_rand_pool_mix()
{
	sha512_ctx sha_ctx;
	int        i, n;
	u8         hval[SHA512_DIGEST_SIZE];

	for (i = 0; i < RNG_POOL_SIZE; i += SHA512_DIGEST_SIZE)
	{
		sha512_init(&sha_ctx);
		sha512_hash(&sha_ctx, rnd_pool, sizeof(rnd_pool));
		sha512_done(&sha_ctx, hval);

		for (n = 0; n < SHA512_DIGEST_SIZE; n++) {
			rnd_pool[i + n] += hval[n];
		}
	}
	/* Prevent leaks */
	burn(hval, sizeof(hval));
	burn(&sha_ctx, sizeof(sha_ctx));
}

void cp_rand_add_seed(void *data, int size)
{
	sha512_ctx sha_ctx;
	ext_seed   seed;
	u8         hval[SHA512_DIGEST_SIZE];
	int        pos, i;

	/* add counter and timestamp to seed data to prevent hash recurrence */
	seed.seed1 = __rdtsc();
	seed.seed2 = reseed_cnt++;

	/* hash input data */
	sha512_init(&sha_ctx);
	sha512_hash(&sha_ctx, data, size);
	sha512_hash(&sha_ctx, pv(&seed), sizeof(seed));
	sha512_done(&sha_ctx, hval);

	/* add hash value to seed buffer */
	for (i = 0; i < SHA512_DIGEST_SIZE; i++)
	{
		if ( (pos = rnd_pos) >= RNG_POOL_SIZE) {
			pos = 0; 
		}
		rnd_pool[pos] += hval[i];
		rnd_pos        = pos + 1;
	}

	/* add hash value to key buffer */
	for (i = 0; i < SHA512_DIGEST_SIZE; i++) {
		key_pool[i % AES_KEY_SIZE] += hval[i];
	}	
	/* prevent leaks */
	burn(&sha_ctx, sizeof(sha_ctx));
	burn(&hval, sizeof(hval));
	burn(&seed, sizeof(seed));
}

void cp_rand_reseed()
{
	seed_data seed;

	KeQuerySystemTime(&seed.seed20);
	
	seed.seed1  = PsGetCurrentProcess();
	seed.seed2  = PsGetCurrentProcessId();
	seed.seed3  = KeGetCurrentThread();
	seed.seed4  = PsGetCurrentThreadId();
	seed.seed5  = KeGetCurrentProcessorNumber();
	seed.seed6  = KeQueryInterruptTime();
	seed.seed10 = KeQueryPerformanceCounter(NULL);
	seed.seed11 = __rdtsc();
	seed.seed12 = ExGetPreviousMode();	
	seed.seed14 = IoGetTopLevelIrp();
	seed.seed15 = MmQuerySystemSize();
	seed.seed24 = KeGetCurrentIrql();
	seed.seed25 = IoReadOperationCount;
	seed.seed26 = IoWriteOperationCount;
	seed.seed27 = IoReadTransferCount;
	seed.seed28 = IoWriteTransferCount;
	
	if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
		seed.seed7  = KeQueryPriorityThread(seed.seed3);
		seed.seed17 = ExUuidCreate(&seed.seed18);
		seed.seed19 = RtlRandom(&seed.seed8);
	}
	if (KeGetCurrentIrql() <= APC_LEVEL) {
		seed.seed13 = IoGetInitialStack();
		seed.seed16 = PsGetProcessExitTime();
		IoGetStackLimits(&seed.seed22, &seed.seed23);
	}	
	KeQueryTickCount(&seed.seed21);
	
	/* add collected seed */
	cp_rand_add_seed(&seed, sizeof(seed));
	/* add SharedUserData as additional seed */
	cp_rand_add_seed(SharedUserData, sizeof(KUSER_SHARED_DATA));
	
	/* Prevent leaks */	
	burn(&seed, sizeof(seed));
}

int cp_rand_bytes(u8 *buf, int len)
{
	sha512_ctx sha_ctx;
	u8         hval[SHA512_DIGEST_SIZE];
	int        c_len, idx, i;
	ext_seed   seed;
	int        fail;

	if (reseed_cnt < 256) {
		DbgMsg("RNG does not have sufficient entropy (%d reseeds), collect it now\n", reseed_cnt);
	}
	/* if RNG does not have sufficient entropy, then collect it now */
	while (reseed_cnt < 256) {
		dc_delay(1); /* wait 1 millisecond */
		cp_rand_reseed();
	}

	KeWaitForSingleObject(&rnd_mutex, Executive, KernelMode, FALSE, NULL);

	/* derive AES key from key pool */
	aes256_asm_set_key(key_pool, rnd_key);

	/* mix pool state before get data from it */
	cp_rand_pool_mix();

	/* idx - position for extraction pool data */
	idx = 0; fail = 0;
	do
	{
		c_len      = min(len, SHA512_DIGEST_SIZE);
		seed.seed1 = getrnd_cnt++;
		seed.seed2 = len;

		/* collect additional entropy before extract data block */
		cp_rand_reseed();

		sha512_init(&sha_ctx);
		sha512_hash(&sha_ctx, rnd_pool + idx, SHA512_DIGEST_SIZE);
		sha512_hash(&sha_ctx, pv(&seed), sizeof(seed));
		sha512_done(&sha_ctx, hval);

		/* encrypt hash value with AES in ECB mode */		
		for (i = 0; i < SHA512_DIGEST_SIZE; i += AES_BLOCK_SIZE) {
			aes256_asm_encrypt(hval + i, hval + i, rnd_key);
		}

		/* copy data to output */
		__try {
			memcpy(buf, hval, c_len);
		}
		__except(EXCEPTION_EXECUTE_HANDLER) {
			fail = 1;
		}

		/* increment extraction pointer */
		if ( (idx += SHA512_DIGEST_SIZE) == RNG_POOL_SIZE ) {
			/* if all data from pool extracted then 
			  mix pool for use new entropy added with reseeds */
			cp_rand_pool_mix(); idx = 0; 
		}

		/* collect additional entropy after extract data block */		
		cp_rand_reseed();

		/* update buffer pointer and remaining length */
		buf += c_len; len -= c_len;
	} while ( (len != 0) && (fail == 0) );

	/* mix pool after getting data to prevent "cold boot" attacks to generated keys */
	cp_rand_pool_mix();

	/* Prevent leaks */
	burn(rnd_key, sizeof(aes256_key));
	burn(&sha_ctx, sizeof(sha_ctx));
	burn(hval, sizeof(hval));
	burn(&seed, sizeof(seed));

	KeReleaseMutex(&rnd_mutex, FALSE);

	return fail == 0;
}

int cp_rand_init()
{
	if ( (rnd_key = mm_secure_alloc(sizeof(aes256_key))) == NULL ) {
		return ST_NOMEM;
	}
	KeInitializeMutex(&rnd_mutex, 0);
	cp_rand_reseed();

	return ST_OK;
}