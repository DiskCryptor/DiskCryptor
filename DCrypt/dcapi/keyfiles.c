/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2026
    * DavidXanatos <info@diskcryptor.org>
	* Copyright (c) 2008 
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

#include <windows.h>
#include <stdio.h>
#include "misc.h"
#include "keyfiles.h"
#include "volume_header.h"
#ifdef _M_ARM64
#include "sha512_small.h"
#else
#include "sha512.h"
#endif
#include "drv_ioctl.h"

#define KF_BLOCK_SIZE (64 * 1024)

typedef struct _kf_ctx {
	sha512_ctx sha;
	u8         kf_block[KF_BLOCK_SIZE];
	u8         hash[SHA512_DIGEST_SIZE];

} kf_ctx;

static
int dc_add_single_kf(dc_pass *pass, wchar_t *path)
{
	kf_ctx *k_ctx;
	HANDLE  h_file;
	int     resl, i;
	int     succs;
	u32     bytes;

	h_file = NULL; k_ctx = NULL;
	do
	{
		if ( (k_ctx = secure_alloc(sizeof(kf_ctx))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		h_file = CreateFile(
			path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

		if (h_file == INVALID_HANDLE_VALUE) {
			h_file = NULL; resl = ST_ACCESS_DENIED; break;
		}

		/* initialize sha512 for hashing keyfile */
		sha512_init(&k_ctx->sha);

		do
		{
			succs = ReadFile(h_file, k_ctx->kf_block, KF_BLOCK_SIZE, &bytes, NULL);

			if ( (succs == 0) || (bytes == 0) ) {
				break;
			}
			sha512_hash(&k_ctx->sha, k_ctx->kf_block, bytes);
		} while (1);		
	
		/* done hashing */
		sha512_done(&k_ctx->sha, k_ctx->hash);

		/* zero unused password buffer bytes */
		memset(p8(pass->pass) + pass->size, 0, (MAX_PASSWORD*2) - pass->size);

		/* mix the keyfile hash and password */
		for (i = 0; i < (SHA512_DIGEST_SIZE / sizeof(u32)); i++) {
			p32(pass->pass)[i] += p32(k_ctx->hash)[i];
		}
		pass->size = max(pass->size, SHA512_DIGEST_SIZE); 
		resl = ST_OK;		
	} while (0);

	if (h_file != NULL) {
		CloseHandle(h_file);
	}

	if (k_ctx != NULL) {
		secure_free(k_ctx);
	}

	return resl;
}

int dc_add_keyfiles(dc_pass *pass, wchar_t *path)
{
	WIN32_FIND_DATA find;
	wchar_t         name[MAX_PATH * 2];	
	HANDLE          h_find;
	int             resl;
	
	_snwprintf(
		name, countof(name), L"%s\\*", path);

	h_find = FindFirstFile(name, &find);

	if (h_find != INVALID_HANDLE_VALUE)
	{
		resl = ST_EMPTY_KEYFILES;
		do
		{
			if (find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				/* recurse folder scanning not needed */
				continue;
			}

			_snwprintf(
				name, countof(name), L"%s\\%s", path, find.cFileName);

			if ( (resl = dc_add_single_kf(pass, name)) != ST_OK ) {
				break;
			}
		} while (FindNextFile(h_find, &find) != 0);

		FindClose(h_find);
	} else {
		resl = dc_add_single_kf(pass, path);
	}

	/* prevent leaks */
	burn(&find, sizeof(find));
	burn(&name, sizeof(name));

	return resl;
}

/* Hash a single file and store result in hash_out (SHA512_DIGEST_SIZE bytes) */
static
int dc_hash_single_file(wchar_t *path, u8 *hash_out)
{
	kf_ctx *k_ctx;
	HANDLE  h_file;
	int     resl;
	int     succs;
	u32     bytes;

	h_file = NULL; k_ctx = NULL;
	do
	{
		if ( (k_ctx = secure_alloc(sizeof(kf_ctx))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		h_file = CreateFile(
			path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

		if (h_file == INVALID_HANDLE_VALUE) {
			h_file = NULL; resl = ST_ACCESS_DENIED; break;
		}

		sha512_init(&k_ctx->sha);

		do
		{
			succs = ReadFile(h_file, k_ctx->kf_block, KF_BLOCK_SIZE, &bytes, NULL);

			if ( (succs == 0) || (bytes == 0) ) {
				break;
			}
			sha512_hash(&k_ctx->sha, k_ctx->kf_block, bytes);
		} while (1);

		sha512_done(&k_ctx->sha, hash_out);
		resl = ST_OK;
	} while (0);

	if (h_file != NULL) {
		CloseHandle(h_file);
	}

	if (k_ctx != NULL) {
		secure_free(k_ctx);
	}

	return resl;
}

/* Compare function for qsort - lexicographic comparison of SHA512 hashes */
static int hash_compare(const void *a, const void *b) {
	return memcmp(a, b, SHA512_DIGEST_SIZE);
}

///* Hash file and add to array, growing if needed */
//static int hash_and_add(wchar_t *path, u8 **hashes, int *count, int *capacity)
//{
//	if (*count >= *capacity) {
//		int new_cap = *capacity ? *capacity * 2 : 16;
//		u8 *new_arr = secure_alloc(new_cap * SHA512_DIGEST_SIZE);
//		if (new_arr == NULL) return ST_NOMEM;
//		if (*hashes != NULL) {
//			memcpy(new_arr, *hashes, *count * SHA512_DIGEST_SIZE);
//			secure_free(*hashes);
//		}
//		*hashes = new_arr;
//		*capacity = new_cap;
//	}
//	int resl = dc_hash_single_file(path, *hashes + *count * SHA512_DIGEST_SIZE);
//	if (resl == ST_OK) (*count)++;
//	return resl;
//}
//
//int dc_hash_keyfiles(wchar_t **paths, int path_count, u8* out_hash)
//{
//	WIN32_FIND_DATA find;
//	wchar_t         name[MAX_PATH * 2];
//	HANDLE          h_find;
//	u8             *hashes = NULL;
//	int             hash_count = 0, hash_capacity = 0;
//	int             resl = ST_OK;
//	sha512_ctx      sha;
//	int             i;
//	const char		context_string[] = "DC2-KFSET-v1";
//
//	for (i = 0; i < path_count; i++)
//	{
//		if (paths[i][wcslen(paths[i]) - 1] == L'\\') {
//			_snwprintf(name, countof(name), L"%s*", paths[i]);
//			h_find = FindFirstFile(name, &find);
//		} else {
//			h_find = INVALID_HANDLE_VALUE;
//		}
//
//		if (h_find != INVALID_HANDLE_VALUE)
//		{
//			do {
//				if (find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
//					/* recurse folder scanning not needed */
//					continue;
//				}
//
//				_snwprintf(name, countof(name), L"%s\\%s", paths[i], find.cFileName);
//				if ((resl = hash_and_add(name, &hashes, &hash_count, &hash_capacity)) != ST_OK) {
//					FindClose(h_find);
//					goto cleanup;
//				}
//			} while (FindNextFile(h_find, &find) != 0);
//			FindClose(h_find);
//		}
//		
//		if (h_find == INVALID_HANDLE_VALUE) {
//			if ((resl = hash_and_add(paths[i], &hashes, &hash_count, &hash_capacity)) != ST_OK) {
//				goto cleanup;
//			}
//		}
//	}
//
//	if (hash_count == 0) {
//		resl = ST_EMPTY_KEYFILES;
//		goto cleanup;
//	}
//
//	/* Sort hashes lexicographically */
//	qsort(hashes, hash_count, SHA512_DIGEST_SIZE, hash_compare);
//
//	/* Remove duplicates in place */
//	for (i = 1; i < hash_count; ) {
//		if (memcmp(hashes + (i - 1) * SHA512_DIGEST_SIZE, hashes + i * SHA512_DIGEST_SIZE, SHA512_DIGEST_SIZE) == 0) {
//			memmove(hashes + i * SHA512_DIGEST_SIZE, hashes + (i + 1) * SHA512_DIGEST_SIZE, (hash_count - i - 1) * SHA512_DIGEST_SIZE);
//			hash_count--;
//		} else {
//			i++;
//		}
//	}
//
//	/* Compute S = SHA512(security_domain || password_bytes || h1 || h2 || ... || hn) */
//	sha512_init(&sha);
//
//	sha512_hash(&sha, (u8*)context_string, sizeof(context_string) - 1); // domain separation
//	for (i = 0; i < hash_count; i++) {
//		sha512_hash(&sha, hashes + i * SHA512_DIGEST_SIZE, SHA512_DIGEST_SIZE);
//	}
//
//	/* Store result directly in password buffer */
//	sha512_done(&sha, out_hash);
//
//cleanup:
//	burn(&find, sizeof(find));
//	burn(&name, sizeof(name));
//	burn(&sha, sizeof(sha));
//
//	if (hashes != NULL) {
//		secure_free(hashes);
//	}
//
//	return resl;
//}
//
//int dc_add_keyfiles_v2(dc_pass *pass, wchar_t **paths, int path_count)
//{
//	u8				keyfiles_hash[SHA512_DIGEST_SIZE];
//	int				resl;
//	sha512_ctx      sha;
//	const char		context_string[] = "DC2-PW-KF-v1";
//
//	resl = dc_hash_keyfiles(paths, path_count, keyfiles_hash);
//	if (resl != ST_OK) {
//		return resl;
//	}
//
//	if (pass->size == 0) {
//		/* If no password bytes, just use the keyfiles hash directly */
//		memcpy(pass->pass, keyfiles_hash, SHA512_DIGEST_SIZE);
//		pass->size = SHA512_DIGEST_SIZE;
//
//		burn(keyfiles_hash, sizeof(keyfiles_hash));
//
//		return ST_OK;
//	}
//
//	/* Mix keyfiles hash into password using domain-separated hashing */
//	sha512_init(&sha);
//
//	sha512_hash(&sha, (u8*)context_string, sizeof(context_string) - 1); // domain separation
//	sha512_hash(&sha, p8(pass->pass), pass->size); // existing password bytes
//	sha512_hash(&sha, keyfiles_hash, SHA512_DIGEST_SIZE); // keyfiles hash
//
//	sha512_done(&sha, p8(pass->pass));
//	pass->size = SHA512_DIGEST_SIZE;
//
//	burn(&sha, sizeof(sha));
//	burn(keyfiles_hash, sizeof(keyfiles_hash));
//
//	return ST_OK;
//}

int dc_hash_virtual_keyfile(u8 *data, u32 size, u8 *out_hash)
{
	sha512_ctx sha;

	if (data == NULL || size == 0 || out_hash == NULL) {
		return ST_ERROR;
	}

	sha512_init(&sha);
	sha512_hash(&sha, data, size);
	sha512_done(&sha, out_hash);

	burn(&sha, sizeof(sha));

	return ST_OK;
}

int dc_add_virtual_keyfile(dc_pass *pass, u8 *data, u32 size)
{
	u8         hash[SHA512_DIGEST_SIZE];
	int        resl;
	int        i;

	if (data == NULL || size == 0) {
		return ST_ERROR;
	}

	resl = dc_hash_virtual_keyfile(data, size, hash);
	if (resl != ST_OK) {
		return resl;
	}

	/* zero unused password buffer bytes */
	memset(p8(pass->pass) + pass->size, 0, (MAX_PASSWORD*2) - pass->size);

	/* mix the keyfile hash and password */
	for (i = 0; i < (SHA512_DIGEST_SIZE / sizeof(u32)); i++) {
		p32(pass->pass)[i] += p32(hash)[i];
	}
	pass->size = max(pass->size, SHA512_DIGEST_SIZE);

	burn(hash, sizeof(hash));

	return ST_OK;
}

//
// Context-based keyfile mixer API implementation
//

int dc_kf_mixer_init(dc_kf_mixer *ctx)
{
	if (ctx == NULL) {
		return ST_ERROR;
	}

	ctx->hashes = NULL;
	ctx->count = 0;
	ctx->capacity = 0;

	return ST_OK;
}

void dc_kf_mixer_free(dc_kf_mixer *ctx)
{
	if (ctx == NULL) {
		return;
	}

	if (ctx->hashes != NULL) {
		burn(ctx->hashes, ctx->capacity * SHA512_DIGEST_SIZE);
		secure_free(ctx->hashes);
	}

	ctx->hashes = NULL;
	ctx->count = 0;
	ctx->capacity = 0;
}

// Internal: ensure capacity for at least one more hash
static int kf_mixer_ensure_capacity(dc_kf_mixer *ctx)
{
	if (ctx->count >= ctx->capacity) {
		int new_cap = ctx->capacity ? ctx->capacity * 2 : DC_KF_MIXER_INITIAL_CAPACITY;
		u8 *new_arr = secure_alloc(new_cap * SHA512_DIGEST_SIZE);
		if (new_arr == NULL) {
			return ST_NOMEM;
		}
		if (ctx->hashes != NULL) {
			memcpy(new_arr, ctx->hashes, ctx->count * SHA512_DIGEST_SIZE);
			burn(ctx->hashes, ctx->capacity * SHA512_DIGEST_SIZE);
			secure_free(ctx->hashes);
		}
		ctx->hashes = new_arr;
		ctx->capacity = new_cap;
	}
	return ST_OK;
}

// Internal: add a pre-computed hash to the mixer
static int kf_mixer_add_hash(dc_kf_mixer *ctx, const u8 *hash)
{
	int resl = kf_mixer_ensure_capacity(ctx);
	if (resl != ST_OK) {
		return resl;
	}

	memcpy(ctx->hashes + ctx->count * SHA512_DIGEST_SIZE, hash, SHA512_DIGEST_SIZE);
	ctx->count++;

	return ST_OK;
}

int dc_kf_mixer_add_file(dc_kf_mixer *ctx, wchar_t *path)
{
	WIN32_FIND_DATA find;
	wchar_t         name[MAX_PATH * 2];
	HANDLE          h_find;
	u8              hash[SHA512_DIGEST_SIZE];
	int             resl = ST_OK;
	int             added_any = 0;

	if (ctx == NULL || path == NULL) {
		return ST_ERROR;
	}

	// Check if path is a folder (ends with backslash)
	if (path[wcslen(path) - 1] == L'\\') {
		_snwprintf(name, countof(name), L"%s*", path);
		h_find = FindFirstFile(name, &find);

		if (h_find != INVALID_HANDLE_VALUE) {
			do {
				if (find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
					continue;
				}

				_snwprintf(name, countof(name), L"%s%s", path, find.cFileName);
				resl = dc_hash_single_file(name, hash);
				if (resl != ST_OK) {
					FindClose(h_find);
					goto cleanup;
				}

				resl = kf_mixer_add_hash(ctx, hash);
				if (resl != ST_OK) {
					FindClose(h_find);
					goto cleanup;
				}
				added_any = 1;

			} while (FindNextFile(h_find, &find) != 0);
			FindClose(h_find);
		}

		if (!added_any) {
			resl = ST_EMPTY_KEYFILES;
		}
	} else {
		// Single file
		resl = dc_hash_single_file(path, hash);
		if (resl == ST_OK) {
			resl = kf_mixer_add_hash(ctx, hash);
		}
	}

cleanup:
	burn(&find, sizeof(find));
	burn(&name, sizeof(name));
	burn(hash, sizeof(hash));

	return resl;
}

int dc_kf_mixer_add_data(dc_kf_mixer *ctx, const void *data, u32 size)
{
	u8  hash[SHA512_DIGEST_SIZE];
	int resl;

	if (ctx == NULL || data == NULL || size == 0) {
		return ST_ERROR;
	}

	// Hash the data
	resl = dc_hash_virtual_keyfile((u8*)data, size, hash);
	if (resl != ST_OK) {
		return resl;
	}

	// Add hash to collection
	resl = kf_mixer_add_hash(ctx, hash);

	burn(hash, sizeof(hash));

	return resl;
}

void dc_kf_mixer_combine(dc_pass *pass, u8* keyfiles_hash)
{
	sha512_ctx  sha;
	const char  context_string_pw[] = "DC2-PW-KF-v1";

	if (pass->size == 0) {
		// If no password bytes, just use the keyfiles hash directly
		memcpy(pass->pass, keyfiles_hash, SHA512_DIGEST_SIZE);
		pass->size = SHA512_DIGEST_SIZE;
		return;
	}

	// Mix keyfiles hash into password
	sha512_init(&sha);
	sha512_hash(&sha, (u8*)context_string_pw, sizeof(context_string_pw) - 1);
	sha512_hash(&sha, p8(pass->pass), pass->size);
	sha512_hash(&sha, keyfiles_hash, SHA512_DIGEST_SIZE);
	sha512_done(&sha, p8(pass->pass));
	pass->size = SHA512_DIGEST_SIZE;

	burn(&sha, sizeof(sha));
}

int dc_kf_mixer_finish(dc_kf_mixer *ctx, dc_pass *pass)
{
	sha512_ctx  sha;
	int         i;
	const char  context_string_kf[] = "DC2-KFSET-v1";
	u8          keyfiles_hash[SHA512_DIGEST_SIZE];

	if (ctx == NULL || pass == NULL) {
		return ST_ERROR;
	}

	if (ctx->count == 0) {
		dc_kf_mixer_free(ctx);
		return ST_EMPTY_KEYFILES;
	}

	// Sort hashes lexicographically
	qsort(ctx->hashes, ctx->count, SHA512_DIGEST_SIZE, hash_compare);

	// Remove duplicates in place
	for (i = 1; i < ctx->count; ) {
		if (memcmp(ctx->hashes + (i - 1) * SHA512_DIGEST_SIZE,
		           ctx->hashes + i * SHA512_DIGEST_SIZE,
		           SHA512_DIGEST_SIZE) == 0) {
			memmove(ctx->hashes + i * SHA512_DIGEST_SIZE,
			        ctx->hashes + (i + 1) * SHA512_DIGEST_SIZE,
			        (ctx->count - i - 1) * SHA512_DIGEST_SIZE);
			ctx->count--;
		} else {
			i++;
		}
	}

	// Compute keyfiles hash: SHA512(context || h1 || h2 || ... || hn)
	sha512_init(&sha);
	sha512_hash(&sha, (u8*)context_string_kf, sizeof(context_string_kf) - 1);
	for (i = 0; i < ctx->count; i++) {
		sha512_hash(&sha, ctx->hashes + i * SHA512_DIGEST_SIZE, SHA512_DIGEST_SIZE);
	}
	sha512_done(&sha, keyfiles_hash);

	dc_kf_mixer_combine(pass, keyfiles_hash);

	// Cleanup
	burn(&sha, sizeof(sha));
	burn(keyfiles_hash, sizeof(keyfiles_hash));
	dc_kf_mixer_free(ctx);

	return ST_OK;
}