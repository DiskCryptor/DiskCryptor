/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2026
    * DavidXanatos <info@diskcryptor.org>
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

#include <windows.h>
#include "benchmark.h"
#include "defines.h"
#include "dcapi.h"
#include "drv_ioctl.h"
#include "dc_header.h"
#include "misc.h"
//#ifdef _M_ARM64
//#include "xts_small.h"
//#include "sha512_pkcs5_2_small.h"
//#else
#include "xts_fast.h"
#include "sha512_pkcs5_2.h"
//#endif
#include "..\crypto\Argon2\argon2.h"

#define TEST_BLOCK_LEN (1024*1024*8)
#define TEST_BLOCK_NUM (4)
#define MAX_BENCH_THREADS 64

typedef struct _bench_thread_ctx {
	/* input */
	xts_key *xkey;
	HANDLE   start_event;
	volatile LONG *stop_flag;
	int      thread_id;
	/* output */
	u64      datalen;
} bench_thread_ctx;

static DWORD WINAPI bench_thread_proc(LPVOID param)
{
	bench_thread_ctx *ctx = (bench_thread_ctx*)param;
	u8      *buff = NULL;
	u64      offs;
	int      i;

	/* allocate per-thread buffer */
	buff = (u8*)VirtualAlloc(NULL, TEST_BLOCK_LEN, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (buff == NULL) return 1;

	/* initialize buffer */
	for (i = 0; i < TEST_BLOCK_LEN; i++) buff[i] = (u8)(i % 256);

	/* wait for start signal */
	WaitForSingleObject(ctx->start_event, INFINITE);

	/* encrypt until stop flag is set */
	offs = (u64)ctx->thread_id * TEST_BLOCK_LEN * TEST_BLOCK_NUM * 1024;
	ctx->datalen = 0;

	while (!(*ctx->stop_flag)) {
		for (i = 0; i < TEST_BLOCK_NUM; i++) {
			xts_encrypt(buff, buff, TEST_BLOCK_LEN, offs, ctx->xkey);
			offs += TEST_BLOCK_LEN;
		}
		ctx->datalen += TEST_BLOCK_LEN * TEST_BLOCK_NUM;
	}

	VirtualFree(buff, 0, MEM_RELEASE);
	return 0;
}

int dc_benchmark_um(int cipher, dc_bench_info *info)
{
	u8       dkey[DISKKEY_SIZE];
	xts_key *xkey = NULL;
	HANDLE   start_event = NULL;
	HANDLE   threads[MAX_BENCH_THREADS];
	bench_thread_ctx thread_ctx[MAX_BENCH_THREADS];
	volatile LONG stop_flag = 0;
	SYSTEM_INFO sysinfo;
	DWORD    num_threads, i;
	int      resl = ST_NOMEM;
	LARGE_INTEGER freq, start, end;

	dc_init_crypto();

	/* get number of CPU cores */
	GetSystemInfo(&sysinfo);
	num_threads = sysinfo.dwNumberOfProcessors;
	if (num_threads > MAX_BENCH_THREADS) num_threads = MAX_BENCH_THREADS;
	if (num_threads == 0) num_threads = 1;

	/* allocate key */
	if ((xkey = (xts_key*)secure_alloc(sizeof(xts_key))) == NULL) goto exit;

	/* setup key */
	for (i = 0; i < DISKKEY_SIZE; i++) dkey[i] = (u8)(i % 256);
	if (!xts_set_key(dkey, cipher, xkey)) { resl = ST_INVALID_PARAM; goto exit; }

	/* create start event (manual reset) */
	start_event = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (start_event == NULL) goto exit;

	/* create worker threads */
	for (i = 0; i < num_threads; i++) {
		thread_ctx[i].xkey = xkey;
		thread_ctx[i].start_event = start_event;
		thread_ctx[i].stop_flag = &stop_flag;
		thread_ctx[i].thread_id = i;
		thread_ctx[i].datalen = 0;

		threads[i] = CreateThread(NULL, 0, bench_thread_proc, &thread_ctx[i], 0, NULL);
		if (threads[i] == NULL) {
			/* cleanup already created threads */
			stop_flag = 1;
			SetEvent(start_event);
			for (DWORD j = 0; j < i; j++) {
				WaitForSingleObject(threads[j], INFINITE);
				CloseHandle(threads[j]);
			}
			goto exit;
		}
	}

	/* query performance frequency */
	if (!QueryPerformanceFrequency(&freq) || freq.QuadPart == 0) {
		stop_flag = 1;
		SetEvent(start_event);
		goto wait_threads;
	}
	info->cpufreq = freq.QuadPart;

	/* start timing and signal all threads to begin */
	QueryPerformanceCounter(&start);
	SetEvent(start_event);

	/* run for at least 0.5 seconds */
	do {
		Sleep(50);
		QueryPerformanceCounter(&end);
	} while (((end.QuadPart - start.QuadPart) * 10 / freq.QuadPart) < 5);

	/* stop all threads */
	stop_flag = 1;

wait_threads:
	/* wait for all threads to finish */
	WaitForMultipleObjects(num_threads, threads, TRUE, INFINITE);

	/* aggregate results */
	info->enctime = end.QuadPart - start.QuadPart;
	info->datalen = 0;
	for (i = 0; i < num_threads; i++) {
		info->datalen += thread_ctx[i].datalen;
		CloseHandle(threads[i]);
	}

	resl = ST_OK;

exit:
	if (start_event != NULL) CloseHandle(start_event);
	if (xkey != NULL) secure_free(xkey);
	burn(dkey, sizeof(dkey));
	return resl;
}

int dc_benchmark_kdf_um(int kdf, dc_kdf_bench_info *info)
{
	u8   test_pass[32] = "benchmark_test_password_1234567";
	u8   test_salt[HEADER_SALT_SIZE];
	u8   dk[DISKKEY_SIZE];
	LARGE_INTEGER freq, start, end;
	int  i;
	int  resl = ST_OK;

	/* fill salt with test data */
	for (i = 0; i < HEADER_SALT_SIZE; i++)
		test_salt[i] = (u8)(i % 256);

	info->kdf = kdf;

	/* query performance frequency */
	if (!QueryPerformanceFrequency(&freq) || freq.QuadPart == 0) return ST_ERROR;
	info->cpufreq = freq.QuadPart;

	QueryPerformanceCounter(&start);

	if (kdf == 0) {
		/* PBKDF2-SHA512 with 1000 iterations */
		info->memory_mib = 0;
		info->time_cost = 1000;
		info->parallelism = 1;

		sha512_pkcs5_2(1000, test_pass, sizeof(test_pass), test_salt, HEADER_SALT_SIZE, dk, PKCS_DERIVE_MAX);
	}
	else if (kdf > 0) {
		/* Argon2id - compute parameters from kdf_cost */
		u32 memory_cost, time_cost, parallelism;
		argon2_mk_params_um(kdf, &memory_cost, &time_cost, &parallelism);

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

	QueryPerformanceCounter(&end);

	/* calculate elapsed time in microseconds */
	info->elapsed_us = ((end.QuadPart - start.QuadPart) * 1000000) / info->cpufreq;

	burn(dk, sizeof(dk));
	return resl;
}
