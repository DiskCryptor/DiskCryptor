#ifndef _DC_KEYFILES_H_
#define _DC_KEYFILES_H_

#include "volume_header.h"

// Keyfile mixing modes
#define KEYFILE_MIX_LEGACY   0  // v1: Additive mixing (SHA512(keyfile) + password bytes)
#define KEYFILE_MIX_HASHED   1  // v2: Canonical mixing (sorted, deduplicated, domain-separated)

// SHA512 digest size
#define DC_KF_HASH_SIZE      64

// Initial capacity for keyfile hash array
#define DC_KF_MIXER_INITIAL_CAPACITY 8

// Keyfile mixer context for v2 (canonical) mixing
typedef struct _dc_kf_mixer {
	u8  *hashes;    // Array of SHA512 hashes (DC_KF_HASH_SIZE bytes each)
	int  count;     // Number of hashes in array
	int  capacity;  // Allocated capacity (number of hashes)
} dc_kf_mixer;

//
// Legacy v1 keyfile functions (additive mixing)
//

// Apply a single keyfile to password using legacy additive mixing
// Loads file from path, hashes with SHA512, and adds to password bytes
EFI_STATUS DCApplyKeyFile(
	IN OUT dc_pass *password,
	IN     CHAR16  *keyfilePath
);

// Apply keyfile data (already loaded) to password using legacy additive mixing
// Hashes data with SHA512 and adds to password bytes
EFI_STATUS DCApplyKeyData(
	IN OUT dc_pass *password,
	IN     UINT8   *fileData,
	IN     UINTN    fileSize
);

//
// Modern v2 keyfile functions (canonical mixing)
//
// Usage:
//   1. dc_kf_mixer_init(&mixer)
//   2. dc_kf_mixer_add_file(&mixer, path) or dc_kf_mixer_add_data(&mixer, data, size)
//   3. dc_kf_mixer_finish(&mixer, pass) - computes final result and frees mixer
//
// The v2 mixing provides:
// - Order-independent keyfile combining (sorted hashes)
// - Duplicate keyfile detection and removal
// - Domain-separated hashing to prevent cross-protocol attacks
//

// Initialize keyfile mixer context
EFI_STATUS dc_kf_mixer_init(dc_kf_mixer *ctx);

// Free keyfile mixer context (also called by dc_kf_mixer_finish)
void dc_kf_mixer_free(dc_kf_mixer *ctx);

// Add a keyfile from path to the mixer
// If path ends with '\' or '/', it's treated as a directory and all files are added
EFI_STATUS dc_kf_mixer_add_file(dc_kf_mixer *ctx, CHAR16 *path);

// Add in-memory data as a keyfile to the mixer
EFI_STATUS dc_kf_mixer_add_data(dc_kf_mixer *ctx, const void *data, UINTN size);

// Combine keyfiles with password
EFI_STATUS dc_kf_mixer_combine(dc_pass *pass, u8* keyfiles_hash);

// Finish mixing and apply to password
// Computes the canonical keyfile hash and mixes it with the password
// Frees the mixer context after completion
EFI_STATUS dc_kf_mixer_finish(dc_kf_mixer *ctx, dc_pass *pass);

#endif // _DC_KEYFILES_H_
