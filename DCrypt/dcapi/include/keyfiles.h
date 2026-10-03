#ifndef _KEYFILES_H_
#define _KEYFILES_H_

#include "volume_header.h"

/*
 * The mixing lives in volume_lib now - DcsPkg had the same scheme written a
 * second time, and firmware cannot use dcapi's file reading. This header keeps
 * dcapi's exported names; keyfile_mix.h brings in dc_kf_mixer and the cp_kf_*
 * functions behind them.
 */
#include "keyfile_mix.h"

// Legacy keyfile mixing (v1) - processes files one at a time
int dc_api dc_add_keyfiles(dc_pass *pass, wchar_t *path);

// Add a virtual keyfile (data directly in memory) - legacy mode (v1)
int dc_api dc_add_virtual_keyfile(dc_pass *pass, u8 *data, u32 size);

// Hash virtual keyfile data and store in out_hash (SHA512_DIGEST_SIZE bytes)
int dc_api dc_hash_virtual_keyfile(u8 *data, u32 size, u8 *out_hash);

//
// Context-based keyfile mixer API (v2)
// Supports mixing both files and raw data uniformly
//
// dc_kf_mixer, DC_KF_HASH_SIZE and DC_KF_MIXER_INITIAL_CAPACITY come from
// keyfile_mix.h above.
//

// Initialize a keyfile mixer context
// Returns: ST_OK on success, error code on failure
int dc_api dc_kf_mixer_init(dc_kf_mixer *ctx);

// Add a file or folder to the mixer
// If path ends with '\', treats it as a folder and adds all files within
// Returns: ST_OK on success, error code on failure
int dc_api dc_kf_mixer_add_file(dc_kf_mixer *ctx, wchar_t *path);

// Add raw data to the mixer (for virtual keyfiles)
// The data is hashed and added to the hash collection
// Returns: ST_OK on success, error code on failure
int dc_api dc_kf_mixer_add_data(dc_kf_mixer *ctx, const void *data, u32 size);

// Combine the collected keyfile hashes and mix into the password
void dc_api dc_kf_mixer_combine(dc_pass *pass, u8* keyfiles_hash);

// Finalize the mixer and mix keyfiles into the password
// Sorts hashes, removes duplicates, and mixes into password
// Frees all internal resources (ctx can be reused after calling dc_kf_mixer_init)
// Returns: ST_OK on success, error code on failure
int dc_api dc_kf_mixer_finish(dc_kf_mixer *ctx, dc_pass *pass);

// Free mixer resources without mixing into password (for cleanup on error)
void dc_api dc_kf_mixer_free(dc_kf_mixer *ctx);

#endif
