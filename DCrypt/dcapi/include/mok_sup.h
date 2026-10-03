#ifndef _MOK_SUP_
#define _MOK_SUP_

#include "dcapi.h"

/* Shim GUID namespace for MOK variables */
extern dc_api const wchar_t* mok_var_guid;

#define SB_PASSWORD_MAX 16

#define MOK_SALT_SIZE  16

/* MOK signature entry info returned by enumeration */
typedef struct _mok_sig_info {
	int    is_cert;        /* 1 = X.509 cert, 0 = hash */
	int    hash_algo_size; /* size of hash (0 for certs) */
	BYTE  *data;           /* pointer into siglist data (cert DER or hash bytes) */
	DWORD  data_size;      /* size of data */
	const wchar_t *type_name; /* "X.509", "SHA-256", etc. */
} mok_sig_info;

/* Callback for mok_enum_siglist. Return 0 to continue, non-zero to stop. */
typedef int (*mok_enum_cb)(int index, const mok_sig_info *info, void *param);

/* ---- EFI variable access ---- */

/* Read a shim MOK variable. Caller must free() the result. */
BYTE dc_api *dc_mok_get_var(const wchar_t *name, DWORD *out_size);

/* Read an EFI variable with explicit GUID. Caller must free() the result. */
BYTE dc_api *dc_mok_get_var_ex(const wchar_t *name, const wchar_t *guid, DWORD *out_size);

/* Write a shim MOK variable. */
int dc_api dc_mok_set_var(const wchar_t *name, BYTE *data, DWORD size);

/* Delete a shim MOK variable. */
int dc_api dc_mok_del_var(const wchar_t *name);

/* ---- Signature list operations ---- */

/* Enumerate entries in an EFI_SIGNATURE_LIST blob.
 * Calls cb for each signature entry. Returns total count. */
int dc_api dc_mok_enum_siglist(const BYTE *data, DWORD size, mok_enum_cb cb, void *param);

/* Build EFI_SIGNATURE_LIST from a DER certificate. Caller must free() result. */
BYTE dc_api *dc_mok_build_cert_siglist(const BYTE *cert_data, DWORD cert_size, DWORD *out_size);

/* Build EFI_SIGNATURE_LIST from a binary hash. hash_type is the EFI GUID for the hash algorithm.
 * Caller must free() result. */
BYTE dc_api *dc_mok_build_hash_siglist(const BYTE *hash, DWORD hash_size, const GUID *hash_type, DWORD *out_size);

/* Determine hash type GUID by hash length. Returns NULL if invalid. */
const GUID dc_api *dc_mok_hash_type_by_size(int hash_bytes);

/* Parse hex string to binary. Returns byte count or 0 on error. */
int dc_api dc_mok_parse_hex(const wchar_t *hex_str, BYTE *out, int max_out);

/* ---- Password / authentication ---- */

/* Build MokAuth/MokDelAuth SHA256 password hash for shim. Caller must free() result. */
BYTE dc_api *dc_mok_build_auth(const wchar_t *password, DWORD *out_size);

/* Build auth hash as SHA256(data + password_ucs2). Caller must free() result. */
BYTE dc_api *dc_mok_build_auth_ex(const BYTE *data, DWORD data_size,
	const wchar_t *password, DWORD *out_size);

/* SHA512-crypt password hashing (compatible with shim MokManager $6$ format). */
int dc_api dc_mok_hash_password(const wchar_t *password, int pw_chars,
	BYTE *salt, int salt_len, BYTE *out_hash, int hash_size);

/* Generate random salt bytes. */
int dc_api dc_mok_gen_salt(BYTE *salt, int len);

/* ---- Secure Boot state ---- */

/* Get shim validation state: 1 = disabled, 0 = enabled, -1 = not set */
int dc_api dc_mok_get_sb_state(void);

/* Get db usage state: 1 = ignored, 0 = used, -1 = not set */
int dc_api dc_mok_get_db_state(void);

/* Set shim validation toggle (MokSB). password is wide, pw_chars is char count. */
int dc_api dc_mok_set_validation(int enable, const wchar_t *password, int pw_chars);

/* Set db usage toggle (MokDB). */
int dc_api dc_mok_set_db_usage(int use_db, const wchar_t *password, int pw_chars);

/* ---- MOK enrollment/deletion ---- */

/* Build combined EFI_SIGNATURE_LIST from multiple DER cert files.
 * Caller must free() result. Returns NULL on error. */
BYTE dc_api *dc_mok_build_siglist_from_files(const wchar_t **file_paths, int file_count, DWORD *out_size);

/* Queue siglist data for enrollment (sets MokNew/MokXNew + auth).
 * is_x: use blacklist (MOKX) variables. */
int dc_api dc_mok_enroll(BYTE *siglist, DWORD siglist_size, const wchar_t *password, int is_x);

/* Queue cert files for enrollment. */
int dc_api dc_mok_enroll_files(const wchar_t **file_paths, int file_count, const wchar_t *password, int is_x);

/* Queue siglist data for deletion (sets MokDel/MokXDel + auth). */
int dc_api dc_mok_request_delete(BYTE *siglist, DWORD siglist_size, const wchar_t *password, int is_x);

/* Queue cert files for deletion. */
int dc_api dc_mok_request_delete_files(const wchar_t **file_paths, int file_count, const wchar_t *password, int is_x);

/* Revoke pending enrollment (delete MokNew+MokAuth or MokXNew+MokXAuth). */
int dc_api dc_mok_revoke_enroll(int is_x);

/* Revoke pending deletion (delete MokDel+MokDelAuth or MokXDel+MokXDelAuth). */
int dc_api dc_mok_revoke_delete(int is_x);

/* Queue MOK reset (sets MokNew to reset sentinel + auth). */
int dc_api dc_mok_reset(const wchar_t *password, int is_x);

/* Test if certificate (DER blob) is enrolled in MokListRT. Returns 1 if found. */
int dc_api dc_mok_test_cert(const BYTE *cert_data, DWORD cert_size);

/* ---- Simple variable setters ---- */

int dc_api dc_mok_set_password(const wchar_t *password, int pw_chars);
int dc_api dc_mok_clear_password(void);
int dc_api dc_mok_set_sbat_policy(BYTE policy_val);
int dc_api dc_mok_del_sbat_policy(void);
int dc_api dc_mok_set_byte_var(const wchar_t *name, BYTE val);
int dc_api dc_mok_set_timeout(INT32 val);

/* ---- SBAT ---- */

/* Get SBAT revocation data. Caller must free() result. Returns NULL if not found. */
BYTE dc_api *dc_mok_get_sbat(DWORD *out_size);

/* ---- Export ---- */

/* Export MOK entries to directory. Calls save_file for each entry.
 * Returns count of exported entries or negative error. */
int dc_api dc_mok_export(const wchar_t *dir_path, int is_x);

#endif
