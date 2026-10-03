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

/*
 * What is left here is the part of keyfile handling that is about Windows:
 * opening files, walking directories, reading blocks. The mixing itself - both
 * the v1 additive scheme and the v2 canonical one - moved to
 * volume_lib/keyfile_mix.c, because DcsPkg had the same scheme written a second
 * time and firmware cannot use any of the code below.
 *
 * The exported names and signatures are unchanged, so gui/ and dccon/ are
 * unaffected.
 */

#include <windows.h>
#include <stdio.h>
#include "misc.h"
#include "keyfiles.h"
#include "volume_header.h"
#include "sha512.h"
#include "drv_ioctl.h"

/* volume_lib */
#include "keyfile_mix.h"

#define KF_BLOCK_SIZE (64 * 1024)

typedef struct _kf_ctx {
	sha512_ctx sha;
	u8         kf_block[KF_BLOCK_SIZE];
	u8         hash[SHA512_DIGEST_SIZE];

} kf_ctx;

/* ---------------------------------------------------------------------------
 * Reading a keyfile
 * ------------------------------------------------------------------------ */

/*
 * SHA-512 of a file's contents, read in 64 KiB blocks through a secure_alloc'd
 * context so that neither the block nor the digest lands in pageable memory.
 *
 * An empty file hashes to the digest of nothing, which is a valid keyfile; a
 * file that cannot be opened is an error.
 */
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

/* ---------------------------------------------------------------------------
 * v1 - one keyfile at a time
 * ------------------------------------------------------------------------ */

static
int dc_add_single_kf(dc_pass *pass, wchar_t *path)
{
	u8  hash[SHA512_DIGEST_SIZE];
	int resl;

	if ( (resl = dc_hash_single_file(path, hash)) == ST_OK ) {
		cp_kf_mix_additive(pass, hash);
	}

	burn(hash, sizeof(hash));
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

int dc_hash_virtual_keyfile(u8 *data, u32 size, u8 *out_hash)
{
	return cp_kf_hash_data(data, size, out_hash);
}

int dc_add_virtual_keyfile(dc_pass *pass, u8 *data, u32 size)
{
	u8  hash[SHA512_DIGEST_SIZE];
	int resl;

	if ( (resl = cp_kf_hash_data(data, size, hash)) == ST_OK ) {
		cp_kf_mix_additive(pass, hash);
	}

	burn(hash, sizeof(hash));
	return resl;
}

/* ---------------------------------------------------------------------------
 * v2 - the whole set at once
 *
 * The mixer itself is volume_lib's. What dcapi adds is the one thing that is
 * not portable: turning a path, which may name a file or a folder, into the
 * hashes that go in.
 * ------------------------------------------------------------------------ */

int dc_kf_mixer_init(dc_kf_mixer *ctx)
{
	return cp_kf_mixer_init(ctx);
}

void dc_kf_mixer_free(dc_kf_mixer *ctx)
{
	cp_kf_mixer_free(ctx);
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

	/* a trailing backslash is what marks a folder here; the caller built the
	   string, so this is a statement of intent rather than a guess */
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

				resl = cp_kf_mixer_add_hash(ctx, hash);
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
		resl = dc_hash_single_file(path, hash);
		if (resl == ST_OK) {
			resl = cp_kf_mixer_add_hash(ctx, hash);
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
	return cp_kf_mixer_add_data(ctx, data, size);
}

void dc_kf_mixer_combine(dc_pass *pass, u8* keyfiles_hash)
{
	cp_kf_mixer_combine(pass, keyfiles_hash);
}

int dc_kf_mixer_finish(dc_kf_mixer *ctx, dc_pass *pass)
{
	return cp_kf_mixer_finish(ctx, pass);
}
