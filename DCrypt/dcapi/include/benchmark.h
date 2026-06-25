#ifndef _DCAPI_BENCHMARK_
#define _DCAPI_BENCHMARK_

#include "dcapi.h"
#include "..\driver\include\driver.h"

/*
 * User-mode cipher benchmark
 * Runs encryption benchmark without requiring the driver
 */
int dc_api dc_benchmark_um(int cipher, dc_bench_info *info);

/*
 * User-mode KDF benchmark
 * Runs KDF benchmark (PBKDF2 or Argon2id) without requiring the driver
 * kdf: 0 for PBKDF2, 1-10 for Argon2id cost levels
 */
int dc_api dc_benchmark_kdf_um(int kdf, dc_kdf_bench_info *info);

#endif
