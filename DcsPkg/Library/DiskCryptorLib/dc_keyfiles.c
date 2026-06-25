/** @file
Keyfile handling for DiskCryptor UEFI bootloader

Supports both legacy v1 (additive) and modern v2 (canonical) keyfile mixing.

Copyright (c) 2026. DiskCryptor, David Xanatos

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/CommonLib.h>

#include "include/defines.h"
#include "include/dc_header.h"
#include "include/dc_keyfiles.h"

#ifdef SMALL
#include "crypto_small/sha512_small.h"
#else
#include "crypto_fast/sha512.h"
#endif

//
// Internal helpers
//

// Hash data with SHA512
static void dc_hash_data(const void *data, UINTN size, u8 *hash_out)
{
	sha512_ctx sha;

	sha512_init(&sha);
#ifdef SMALL
	sha512_add(&sha, (u8*)data, (unsigned long)size);
#else
	sha512_hash(&sha, (u8*)data, (unsigned long)size);
#endif
	sha512_done(&sha, hash_out);

	zeroauto(&sha, sizeof(sha));
}

// Compare function for sorting - lexicographic comparison of SHA512 hashes
static int hash_compare(const void *a, const void *b)
{
	const u8 *ha = (const u8*)a;
	const u8 *hb = (const u8*)b;

	for (int i = 0; i < DC_KF_HASH_SIZE; i++) {
		if (ha[i] < hb[i]) return -1;
		if (ha[i] > hb[i]) return 1;
	}
	return 0;
}

// Simple insertion sort for small arrays (avoids qsort dependency)
static void sort_hashes(u8 *hashes, int count)
{
	u8 temp[DC_KF_HASH_SIZE];
	int i, j;

	for (i = 1; i < count; i++) {
		memcpy(temp, hashes + i * DC_KF_HASH_SIZE, DC_KF_HASH_SIZE);
		j = i - 1;
		while (j >= 0 && hash_compare(hashes + j * DC_KF_HASH_SIZE, temp) > 0) {
			memcpy(hashes + (j + 1) * DC_KF_HASH_SIZE, hashes + j * DC_KF_HASH_SIZE, DC_KF_HASH_SIZE);
			j--;
		}
		memcpy(hashes + (j + 1) * DC_KF_HASH_SIZE, temp, DC_KF_HASH_SIZE);
	}

	zeroauto(temp, sizeof(temp));
}

// Ensure capacity for at least one more hash
static EFI_STATUS kf_mixer_ensure_capacity(dc_kf_mixer *ctx)
{
	if (ctx->count >= ctx->capacity) {
		int new_cap = ctx->capacity ? ctx->capacity * 2 : DC_KF_MIXER_INITIAL_CAPACITY;
		u8 *new_arr = AllocateZeroPool(new_cap * DC_KF_HASH_SIZE);
		if (new_arr == NULL) {
			return EFI_OUT_OF_RESOURCES;
		}
		if (ctx->hashes != NULL) {
			CopyMem(new_arr, ctx->hashes, ctx->count * DC_KF_HASH_SIZE);
			MEM_BURN(ctx->hashes, ctx->capacity * DC_KF_HASH_SIZE);
			FreePool(ctx->hashes);
		}
		ctx->hashes = new_arr;
		ctx->capacity = new_cap;
	}
	return EFI_SUCCESS;
}

// Add a pre-computed hash to the mixer
static EFI_STATUS kf_mixer_add_hash(dc_kf_mixer *ctx, const u8 *hash)
{
	EFI_STATUS ret = kf_mixer_ensure_capacity(ctx);
	if (EFI_ERROR(ret)) {
		return ret;
	}

	CopyMem(ctx->hashes + ctx->count * DC_KF_HASH_SIZE, hash, DC_KF_HASH_SIZE);
	ctx->count++;

	return EFI_SUCCESS;
}

//
// Legacy v1 keyfile functions (additive mixing)
//

EFI_STATUS
DCApplyKeyFile(
	IN OUT dc_pass *password,
	IN     CHAR16  *keyfilePath
)
{
	EFI_STATUS  ret = EFI_SUCCESS;
	UINT8      *fileData = NULL;
	UINTN       fileSize = 0;

	ret = FileLoad(NULL, keyfilePath, &fileData, &fileSize);
	if (EFI_ERROR(ret)) {
		return ret;
	}

	ret = DCApplyKeyData(password, fileData, fileSize);

	MEM_BURN(fileData, fileSize);
	MEM_FREE(fileData);

	return ret;
}

EFI_STATUS
DCApplyKeyData(
	IN OUT dc_pass *password,
	IN     UINT8   *fileData,
	IN     UINTN    fileSize
)
{
	u8 hash[DC_KF_HASH_SIZE];
	UINTN i;

	if (fileData == NULL || fileSize == 0) {
		return EFI_INVALID_PARAMETER;
	}

	dc_hash_data(fileData, fileSize, hash);

	// zero unused password buffer bytes
	zeroauto(p8(password->pass) + password->size, (MAX_PASSWORD*2) - password->size);

	// Mix the keyfile hash and password using u32 addition
	for (i = 0; i < (DC_KF_HASH_SIZE / sizeof(u32)); i++) {
		p32(password->pass)[i] += p32(hash)[i];
	}
	password->size = max(password->size, DC_KF_HASH_SIZE);

	// Prevent leaks
	zeroauto(hash, sizeof(hash));

	return EFI_SUCCESS;
}

//
// Modern v2 keyfile functions (canonical mixing)
//

EFI_STATUS dc_kf_mixer_init(dc_kf_mixer *ctx)
{
	if (ctx == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	ctx->hashes = NULL;
	ctx->count = 0;
	ctx->capacity = 0;

	return EFI_SUCCESS;
}

void dc_kf_mixer_free(dc_kf_mixer *ctx)
{
	if (ctx == NULL) {
		return;
	}

	if (ctx->hashes != NULL) {
		MEM_BURN(ctx->hashes, ctx->capacity * DC_KF_HASH_SIZE);
		FreePool(ctx->hashes);
	}

	ctx->hashes = NULL;
	ctx->count = 0;
	ctx->capacity = 0;
}

EFI_STATUS dc_kf_mixer_add_file(dc_kf_mixer *ctx, CHAR16 *path)
{
	EFI_STATUS  ret = EFI_SUCCESS;
	UINT8      *fileData = NULL;
	UINTN       fileSize = 0;
	u8          hash[DC_KF_HASH_SIZE];

	if (ctx == NULL || path == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	// Load the keyfile
	ret = FileLoad(NULL, path, &fileData, &fileSize);
	if (EFI_ERROR(ret)) {
		return ret;
	}

	if (fileSize == 0) {
		MEM_FREE(fileData);
		return EFI_NOT_FOUND;
	}

	// Hash the file contents
	dc_hash_data(fileData, fileSize, hash);

	// Secure cleanup of file data
	MEM_BURN(fileData, fileSize);
	MEM_FREE(fileData);

	// Add hash to collection
	ret = kf_mixer_add_hash(ctx, hash);

	zeroauto(hash, sizeof(hash));

	return ret;
}

EFI_STATUS dc_kf_mixer_add_data(dc_kf_mixer *ctx, const void *data, UINTN size)
{
	u8 hash[DC_KF_HASH_SIZE];
	EFI_STATUS ret;

	if (ctx == NULL || data == NULL || size == 0) {
		return EFI_INVALID_PARAMETER;
	}

	// Hash the data
	dc_hash_data(data, size, hash);

	// Add hash to collection
	ret = kf_mixer_add_hash(ctx, hash);

	zeroauto(hash, sizeof(hash));

	return ret;
}

EFI_STATUS dc_kf_mixer_combine(dc_pass *pass, u8* keyfiles_hash)
{
	sha512_ctx  sha;
	const char  context_string_pw[] = "DC2-PW-KF-v1";

	if (pass->size == 0) {
		// If no password bytes, just use the keyfiles hash directly
		CopyMem(pass->pass, keyfiles_hash, DC_KF_HASH_SIZE);
		pass->size = DC_KF_HASH_SIZE;
		return EFI_SUCCESS;
	}

	// Mix keyfiles hash into password using domain-separated hashing
	sha512_init(&sha);
#ifdef SMALL
	sha512_add(&sha, (u8*)context_string_pw, sizeof(context_string_pw) - 1);
	sha512_add(&sha, p8(pass->pass), pass->size);
	sha512_add(&sha, keyfiles_hash, DC_KF_HASH_SIZE);
#else
	sha512_hash(&sha, (u8*)context_string_pw, sizeof(context_string_pw) - 1);
	sha512_hash(&sha, p8(pass->pass), pass->size);
	sha512_hash(&sha, keyfiles_hash, DC_KF_HASH_SIZE);
#endif
	sha512_done(&sha, p8(pass->pass));
	pass->size = DC_KF_HASH_SIZE;

	MEM_BURN(&sha, sizeof(sha));

	return EFI_SUCCESS;
}

EFI_STATUS dc_kf_mixer_finish(dc_kf_mixer *ctx, dc_pass *pass)
{
	sha512_ctx  sha;
	int         i;
	const char  context_string_kf[] = "DC2-KFSET-v1";
	u8          keyfiles_hash[DC_KF_HASH_SIZE];

	if (ctx == NULL || pass == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	if (ctx->count == 0) {
		dc_kf_mixer_free(ctx);
		return EFI_NOT_FOUND;
	}

	// Sort hashes lexicographically for order-independent combining
	sort_hashes(ctx->hashes, ctx->count);

	// Remove duplicates in place
	for (i = 1; i < ctx->count; ) {
		if (hash_compare(ctx->hashes + (i - 1) * DC_KF_HASH_SIZE,
		                 ctx->hashes + i * DC_KF_HASH_SIZE) == 0) {
			// Duplicate found - shift remaining hashes down
			if (i + 1 < ctx->count) {
				CopyMem(ctx->hashes + i * DC_KF_HASH_SIZE,
				        ctx->hashes + (i + 1) * DC_KF_HASH_SIZE,
				        (ctx->count - i - 1) * DC_KF_HASH_SIZE);
			}
			ctx->count--;
		} else {
			i++;
		}
	}

	// Compute keyfiles hash: SHA512(context || h1 || h2 || ... || hn)
	sha512_init(&sha);
#ifdef SMALL
	sha512_add(&sha, (u8*)context_string_kf, sizeof(context_string_kf) - 1);
	for (i = 0; i < ctx->count; i++) {
		sha512_add(&sha, ctx->hashes + i * DC_KF_HASH_SIZE, DC_KF_HASH_SIZE);
	}
#else
	sha512_hash(&sha, (u8*)context_string_kf, sizeof(context_string_kf) - 1);
	for (i = 0; i < ctx->count; i++) {
		sha512_hash(&sha, ctx->hashes + i * DC_KF_HASH_SIZE, DC_KF_HASH_SIZE);
	}
#endif
	sha512_done(&sha, keyfiles_hash);

	MEM_BURN(&sha, sizeof(sha));

	dc_kf_mixer_combine(pass, keyfiles_hash);

	MEM_BURN(keyfiles_hash, sizeof(keyfiles_hash));

	dc_kf_mixer_free(ctx);

	return EFI_SUCCESS;
}
