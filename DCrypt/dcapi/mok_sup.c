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
#include <stdio.h>
#include <conio.h>
#include <wincrypt.h>
#include <ncrypt.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")
#include "defines.h"
#include "drv_ioctl.h"
#include "bootloader.h"
#include "misc.h"
#include "efiinst.h"
#include "mok_sup.h"
//#ifdef _M_ARM64
//#include "sha512_small.h"
//#else
#include "sha512.h"
//#endif

/* SetFirmwareEnvironmentVariableExW - Windows 8+ API */
typedef BOOL (WINAPI *PFN_SetFirmwareEnvironmentVariableExW)(
	LPCWSTR lpName,
	LPCWSTR lpGuid,
	PVOID pValue,
	DWORD nSize,
	DWORD dwAttributes
);

/* Shim GUID namespace */
const wchar_t* mok_var_guid = L"{605DAB50-E046-4300-ABB6-3DD810DD8B23}";

/* EFI variable attributes */
#define EFI_VAR_NV     0x00000001
#define EFI_VAR_BS     0x00000002
#define EFI_VAR_RT     0x00000004
#define MOK_VAR_ATTRS  (EFI_VAR_NV | EFI_VAR_BS | EFI_VAR_RT)

/* EFI signature type GUIDs */
static const GUID EFI_CERT_X509_GUID =
	{ 0xa5c059a1, 0x94e4, 0x4aa7, { 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72 } };
static const GUID EFI_CERT_SHA256_GUID =
	{ 0xc1c41626, 0x504c, 0x4092, { 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28 } };
static const GUID EFI_CERT_SHA1_GUID =
	{ 0x826ca512, 0xcf10, 0x4ac9, { 0xb1, 0x87, 0xbe, 0x01, 0x49, 0x66, 0x31, 0xbd } };
static const GUID EFI_CERT_SHA384_GUID =
	{ 0xff3e5307, 0x9fd0, 0x48c9, { 0x85, 0xf1, 0x8a, 0xd5, 0x6c, 0x70, 0x1e, 0x01 } };
static const GUID EFI_CERT_SHA512_GUID =
	{ 0x093e0fae, 0xa6c4, 0x4f50, { 0x9f, 0x1b, 0xd4, 0x1e, 0x2b, 0x89, 0xc1, 0x9a } };

/* Shim MOK owner GUID */
static const GUID shim_owner_guid =
	{ 0x605dab50, 0xe046, 0x4300, { 0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23 } };

/* SHA512-crypt constants */
#define SHA512_CRYPT_ROUNDS_DEFAULT 5000

/* ---- Internal helpers ---- */

static PFN_SetFirmwareEnvironmentVariableExW get_set_var_ex(void)
{
	return (PFN_SetFirmwareEnvironmentVariableExW)GetProcAddress(
		GetModuleHandleW(L"kernel32.dll"), "SetFirmwareEnvironmentVariableExW");
}

/* ---- EFI variable access ---- */

BYTE *dc_mok_get_var(const wchar_t *name, DWORD *out_size)
{
	return dc_mok_get_var_ex(name, mok_var_guid, out_size);
}

BYTE *dc_mok_get_var_ex(const wchar_t *name, const wchar_t *guid, DWORD *out_size)
{
	BYTE *buffer = NULL;
	DWORD buf_size = 4096;
	DWORD var_len;

	buffer = (BYTE*)malloc(buf_size);
	if (buffer == NULL) return NULL;

	while ((var_len = GetFirmwareEnvironmentVariableW(name, guid, buffer, buf_size)) == 0) {
		DWORD err = GetLastError();
		if (err == ERROR_INSUFFICIENT_BUFFER) {
			buf_size *= 2;
			free(buffer);
			buffer = (BYTE*)malloc(buf_size);
			if (buffer == NULL) return NULL;
		} else {
			free(buffer);
			return NULL;
		}
	}

	*out_size = var_len;
	return buffer;
}

int dc_mok_set_var(const wchar_t *name, BYTE *data, DWORD size)
{
	PFN_SetFirmwareEnvironmentVariableExW pSetEx = get_set_var_ex();

	if (pSetEx != NULL) {
		if (pSetEx(name, mok_var_guid, data, size, MOK_VAR_ATTRS))
			return ST_OK;
	} else {
		if (SetFirmwareEnvironmentVariableW(name, mok_var_guid, data, size))
			return ST_OK;
	}

	return ST_ERROR;
}

int dc_mok_del_var(const wchar_t *name)
{
	PFN_SetFirmwareEnvironmentVariableExW pSetEx = get_set_var_ex();

	if (pSetEx != NULL) {
		if (pSetEx(name, mok_var_guid, NULL, 0, MOK_VAR_ATTRS))
			return ST_OK;
	} else {
		if (SetFirmwareEnvironmentVariableW(name, mok_var_guid, NULL, 0))
			return ST_OK;
	}

	if (GetLastError() == ERROR_ENVVAR_NOT_FOUND)
		return ST_OK;
	return ST_ERROR;
}

/* ---- Signature list operations ---- */

int dc_mok_enum_siglist(const BYTE *data, DWORD size, mok_enum_cb cb, void *param)
{
	DWORD offset = 0;
	int index = 0;

	while (offset + 28 <= size) {
		GUID *sigType = (GUID*)(data + offset);
		DWORD sigListSize = *(DWORD*)(data + offset + 16);
		DWORD sigHeaderSize = *(DWORD*)(data + offset + 20);
		DWORD sigSize = *(DWORD*)(data + offset + 24);

		if (sigListSize == 0 || sigListSize > size - offset || sigListSize < 28)
			break;

		mok_sig_info info;
		memset(&info, 0, sizeof(info));

		if (memcmp(sigType, &EFI_CERT_X509_GUID, sizeof(GUID)) == 0) {
			info.is_cert = 1; info.type_name = L"X.509";
		} else if (memcmp(sigType, &EFI_CERT_SHA256_GUID, sizeof(GUID)) == 0) {
			info.hash_algo_size = 32; info.type_name = L"SHA-256";
		} else if (memcmp(sigType, &EFI_CERT_SHA1_GUID, sizeof(GUID)) == 0) {
			info.hash_algo_size = 20; info.type_name = L"SHA-1";
		} else if (memcmp(sigType, &EFI_CERT_SHA384_GUID, sizeof(GUID)) == 0) {
			info.hash_algo_size = 48; info.type_name = L"SHA-384";
		} else if (memcmp(sigType, &EFI_CERT_SHA512_GUID, sizeof(GUID)) == 0) {
			info.hash_algo_size = 64; info.type_name = L"SHA-512";
		} else {
			offset += sigListSize;
			continue;
		}

		DWORD sigDataSize = sigListSize - 28 - sigHeaderSize;
		if (sigSize == 0 || sigSize <= 16 || sigDataSize % sigSize != 0) {
			offset += sigListSize;
			continue;
		}

		DWORD numSigs = sigDataSize / sigSize;
		DWORD sigOffset = offset + 28 + sigHeaderSize;

		for (DWORD i = 0; i < numSigs && sigOffset + sigSize <= size; i++) {
			info.data = (BYTE*)data + sigOffset + 16;
			info.data_size = sigSize - 16;

			if (cb != NULL && cb(index, &info, param) != 0)
				return index + 1;

			index++;
			sigOffset += sigSize;
		}

		offset += sigListSize;
	}

	return index;
}

BYTE *dc_mok_build_cert_siglist(const BYTE *cert_data, DWORD cert_size, DWORD *out_size)
{
	DWORD sigSize = 16 + cert_size;
	DWORD sigListSize = 28 + sigSize;

	BYTE *buf = (BYTE*)malloc(sigListSize);
	if (buf == NULL) return NULL;

	memcpy(buf, &EFI_CERT_X509_GUID, 16);
	*(DWORD*)(buf + 16) = sigListSize;
	*(DWORD*)(buf + 20) = 0;
	*(DWORD*)(buf + 24) = sigSize;
	memcpy(buf + 28, &shim_owner_guid, 16);
	memcpy(buf + 28 + 16, cert_data, cert_size);

	*out_size = sigListSize;
	return buf;
}

BYTE *dc_mok_build_hash_siglist(const BYTE *hash, DWORD hash_size, const GUID *hash_type, DWORD *out_size)
{
	DWORD sigSize = 16 + hash_size;
	DWORD sigListSize = 28 + sigSize;

	BYTE *buf = (BYTE*)malloc(sigListSize);
	if (buf == NULL) return NULL;

	memcpy(buf, hash_type, 16);
	*(DWORD*)(buf + 16) = sigListSize;
	*(DWORD*)(buf + 20) = 0;
	*(DWORD*)(buf + 24) = sigSize;
	memcpy(buf + 28, &shim_owner_guid, 16);
	memcpy(buf + 28 + 16, hash, hash_size);

	*out_size = sigListSize;
	return buf;
}

const GUID *dc_mok_hash_type_by_size(int hash_bytes)
{
	if (hash_bytes == 32) return &EFI_CERT_SHA256_GUID;
	if (hash_bytes == 48) return &EFI_CERT_SHA384_GUID;
	if (hash_bytes == 64) return &EFI_CERT_SHA512_GUID;
	if (hash_bytes == 20) return &EFI_CERT_SHA1_GUID;
	return NULL;
}

int dc_mok_parse_hex(const wchar_t *hex_str, BYTE *out, int max_out)
{
	int len = (int)wcslen(hex_str);
	if (len % 2 != 0 || len / 2 > max_out)
		return 0;

	for (int i = 0; i < len / 2; i++) {
		unsigned int val;
		wchar_t tmp[3] = { hex_str[i*2], hex_str[i*2+1], 0 };
		if (swscanf_s(tmp, L"%x", &val) != 1)
			return 0;
		out[i] = (BYTE)val;
	}
	return len / 2;
}

/* ---- Password / authentication ---- */

BYTE *dc_mok_build_auth(const wchar_t *password, DWORD *out_size)
{
	return dc_mok_build_auth_ex(NULL, 0, password, out_size);
}

BYTE *dc_mok_build_auth_ex(const BYTE *data, DWORD data_size,
	const wchar_t *password, DWORD *out_size)
{
	/* Shim computes: SHA256(data + password_ucs2)
	 * where password_ucs2 = pw_length * sizeof(CHAR16), no NUL terminator. */
	int pw_len = (int)wcslen(password);
	DWORD pw_bytes = pw_len * sizeof(UINT16);

	BYTE hash[32];
	DWORD hashSize = sizeof(hash);
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	NTSTATUS status;

	status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
	if (status < 0) return NULL;

	status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
	if (status < 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return NULL; }

	if (data != NULL && data_size > 0)
		BCryptHashData(hHash, (BYTE*)data, data_size, 0);
	BCryptHashData(hHash, (BYTE*)password, pw_bytes, 0);
	BCryptFinishHash(hHash, hash, hashSize, 0);
	BCryptDestroyHash(hHash);
	BCryptCloseAlgorithmProvider(hAlg, 0);

	BYTE *buf = (BYTE*)malloc(hashSize);
	if (buf == NULL) return NULL;
	memcpy(buf, hash, hashSize);
	*out_size = hashSize;
	SecureZeroMemory(hash, sizeof(hash));
	return buf;
}

/*
 * SHA512-crypt password hashing (compatible with shim's MokManager)
 * Implements the $6$ algorithm from glibc crypt(3).
 */
static void sha512_crypt_raw(const BYTE *password, int pw_len,
                             const BYTE *salt, int salt_len,
                             BYTE *out_hash)
{
	sha512_ctx ctx_a, ctx_b;
	BYTE digest_a[SHA512_DIGEST_SIZE];
	BYTE digest_b[SHA512_DIGEST_SIZE];
	BYTE p_bytes[SHA512_DIGEST_SIZE];
	BYTE s_bytes[SHA512_DIGEST_SIZE];
	int rounds = SHA512_CRYPT_ROUNDS_DEFAULT;
	int i;

	sha512_init(&ctx_a);
	sha512_hash(&ctx_a, password, pw_len);
	sha512_hash(&ctx_a, salt, salt_len);

	sha512_init(&ctx_b);
	sha512_hash(&ctx_b, password, pw_len);
	sha512_hash(&ctx_b, salt, salt_len);
	sha512_hash(&ctx_b, password, pw_len);
	sha512_done(&ctx_b, digest_b);

	for (i = pw_len; i > SHA512_DIGEST_SIZE; i -= SHA512_DIGEST_SIZE)
		sha512_hash(&ctx_a, digest_b, SHA512_DIGEST_SIZE);
	sha512_hash(&ctx_a, digest_b, i);

	for (i = pw_len; i > 0; i >>= 1) {
		if (i & 1)
			sha512_hash(&ctx_a, digest_b, SHA512_DIGEST_SIZE);
		else
			sha512_hash(&ctx_a, password, pw_len);
	}

	sha512_done(&ctx_a, digest_a);

	sha512_init(&ctx_b);
	for (i = 0; i < pw_len; i++)
		sha512_hash(&ctx_b, password, pw_len);
	sha512_done(&ctx_b, p_bytes);

	BYTE *p_string = (BYTE*)malloc(pw_len);
	if (p_string == NULL) {
		memset(out_hash, 0, SHA512_DIGEST_SIZE);
		return;
	}
	for (i = 0; i < pw_len; i++)
		p_string[i] = p_bytes[i % SHA512_DIGEST_SIZE];

	sha512_init(&ctx_b);
	for (i = 0; i < 16 + (int)(unsigned char)digest_a[0]; i++)
		sha512_hash(&ctx_b, salt, salt_len);
	sha512_done(&ctx_b, s_bytes);

	BYTE *s_string = (BYTE*)malloc(salt_len);
	if (s_string == NULL) {
		free(p_string);
		memset(out_hash, 0, SHA512_DIGEST_SIZE);
		return;
	}
	for (i = 0; i < salt_len; i++)
		s_string[i] = s_bytes[i % SHA512_DIGEST_SIZE];

	for (i = 0; i < rounds; i++) {
		sha512_init(&ctx_b);

		if (i & 1)
			sha512_hash(&ctx_b, p_string, pw_len);
		else
			sha512_hash(&ctx_b, digest_a, SHA512_DIGEST_SIZE);

		if (i % 3)
			sha512_hash(&ctx_b, s_string, salt_len);

		if (i % 7)
			sha512_hash(&ctx_b, p_string, pw_len);

		if (i & 1)
			sha512_hash(&ctx_b, digest_a, SHA512_DIGEST_SIZE);
		else
			sha512_hash(&ctx_b, p_string, pw_len);

		sha512_done(&ctx_b, digest_a);
	}

	memcpy(out_hash, digest_a, SHA512_DIGEST_SIZE);

	SecureZeroMemory(digest_b, sizeof(digest_b));
	SecureZeroMemory(p_bytes, sizeof(p_bytes));
	SecureZeroMemory(s_bytes, sizeof(s_bytes));
	free(p_string);
	free(s_string);
}

int dc_mok_hash_password(const wchar_t *password, int pw_chars,
	BYTE *salt, int salt_len, BYTE *out_hash, int hash_size)
{
	char pw_utf8[512];
	int utf8_len = WideCharToMultiByte(CP_UTF8, 0, password, pw_chars, pw_utf8, sizeof(pw_utf8), NULL, NULL);
	if (utf8_len == 0)
		return ST_ERROR;

	if (hash_size < SHA512_DIGEST_SIZE)
		return ST_ERROR;

	sha512_crypt_raw((BYTE*)pw_utf8, utf8_len, salt, salt_len, out_hash);
	SecureZeroMemory(pw_utf8, sizeof(pw_utf8));
	return ST_OK;
}

int dc_mok_gen_salt(BYTE *salt, int len)
{
	NTSTATUS status = BCryptGenRandom(NULL, salt, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	return (status >= 0) ? ST_OK : ST_ERROR;
}

/* ---- Secure Boot state ---- */

int dc_mok_get_sb_state(void)
{
	DWORD sz;
	BYTE *data = dc_mok_get_var(L"MokSBStateRT", &sz);
	if (data == NULL) return -1;
	int val = (sz > 0 && data[0] == 1) ? 1 : 0;
	free(data);
	return val;
}

int dc_mok_get_db_state(void)
{
	DWORD sz;
	BYTE *data = dc_mok_get_var(L"MokIgnoreDB", &sz);
	if (data == NULL) return -1;
	int val = (sz > 0 && data[0] == 1) ? 1 : 0;
	free(data);
	return val;
}

static int mok_set_toggle(const wchar_t *var_name, UINT32 toggle_state,
                           const wchar_t *password, int pw_chars)
{
	/* MokSBvar: MokSBState(UINT32) + PWLen(UINT32) + Password(CHAR16[16]) = 40 bytes
	 * PWLen is character count (not byte length) — shim uses it as index into Password[] */
	DWORD var_size = sizeof(UINT32) + sizeof(UINT32) + SB_PASSWORD_MAX * sizeof(UINT16);
	BYTE *var_data = (BYTE*)malloc(var_size);
	if (var_data == NULL) return ST_NOMEM;

	memset(var_data, 0, var_size);
	*(UINT32*)(var_data) = toggle_state;
	*(UINT32*)(var_data + 4) = (UINT32)pw_chars;
	UINT16 *pw_dst = (UINT16*)(var_data + 8);
	for (int i = 0; i < pw_chars && i < SB_PASSWORD_MAX; i++)
		pw_dst[i] = password[i];

	int resl = dc_mok_set_var(var_name, var_data, var_size);
	SecureZeroMemory(var_data, var_size);
	free(var_data);
	return resl;
}

int dc_mok_set_validation(int enable, const wchar_t *password, int pw_chars)
{
	/* mokutil convention: disable_validation -> MokSBState=0, enable_validation -> MokSBState=1 */
	return mok_set_toggle(L"MokSB", enable ? 1 : 0, password, pw_chars);
}

int dc_mok_set_db_usage(int use_db, const wchar_t *password, int pw_chars)
{
	/* mokutil convention: ignore_db -> MokDBState=0, use_db -> MokDBState=1 */
	return mok_set_toggle(L"MokDB", use_db ? 1 : 0, password, pw_chars);
}

/* ---- MOK enrollment/deletion ---- */

/* Common helper: set data variable + auth hash variable */
static int mok_set_data_and_auth(const wchar_t *data_var, const wchar_t *auth_var,
	BYTE *siglist, DWORD siglist_size, const wchar_t *password)
{
	int resl = dc_mok_set_var(data_var, siglist, siglist_size);
	if (resl != ST_OK) return resl;

	DWORD auth_size;
	BYTE *auth_data = dc_mok_build_auth_ex(siglist, siglist_size, password, &auth_size);
	if (auth_data == NULL) {
		dc_mok_del_var(data_var);
		return ST_ERROR;
	}

	resl = dc_mok_set_var(auth_var, auth_data, auth_size);
	free(auth_data);

	if (resl != ST_OK)
		dc_mok_del_var(data_var);
	return resl;
}

BYTE *dc_mok_build_siglist_from_files(const wchar_t **file_paths, int file_count, DWORD *out_size)
{
	BYTE *combined = NULL;
	DWORD combined_size = 0;

	for (int i = 0; i < file_count; i++) {
		BYTE *cert_data = NULL;
		int cert_size = 0;
		if (load_file((wchar_t*)file_paths[i], (void**)&cert_data, &cert_size) != ST_OK || cert_data == NULL) {
			if (combined) free(combined);
			return NULL;
		}

		DWORD sl_size;
		BYTE *siglist = dc_mok_build_cert_siglist(cert_data, cert_size, &sl_size);
		my_free(cert_data);

		if (siglist == NULL) {
			if (combined) free(combined);
			return NULL;
		}

		BYTE *new_combined = (BYTE*)realloc(combined, combined_size + sl_size);
		if (new_combined == NULL) {
			free(siglist);
			if (combined) free(combined);
			return NULL;
		}
		combined = new_combined;
		memcpy(combined + combined_size, siglist, sl_size);
		combined_size += sl_size;
		free(siglist);
	}

	*out_size = combined_size;
	return combined;
}

int dc_mok_enroll(BYTE *siglist, DWORD siglist_size, const wchar_t *password, int is_x)
{
	return mok_set_data_and_auth(
		is_x ? L"MokXNew" : L"MokNew",
		is_x ? L"MokXAuth" : L"MokAuth",
		siglist, siglist_size, password);
}

int dc_mok_enroll_files(const wchar_t **file_paths, int file_count, const wchar_t *password, int is_x)
{
	DWORD sl_size;
	BYTE *siglist = dc_mok_build_siglist_from_files(file_paths, file_count, &sl_size);
	if (siglist == NULL || sl_size == 0)
		return ST_ERROR;

	int resl = dc_mok_enroll(siglist, sl_size, password, is_x);
	free(siglist);
	return resl;
}

int dc_mok_request_delete(BYTE *siglist, DWORD siglist_size, const wchar_t *password, int is_x)
{
	return mok_set_data_and_auth(
		is_x ? L"MokXDel" : L"MokDel",
		is_x ? L"MokXDelAuth" : L"MokDelAuth",
		siglist, siglist_size, password);
}

int dc_mok_request_delete_files(const wchar_t **file_paths, int file_count, const wchar_t *password, int is_x)
{
	DWORD sl_size;
	BYTE *siglist = dc_mok_build_siglist_from_files(file_paths, file_count, &sl_size);
	if (siglist == NULL || sl_size == 0)
		return ST_ERROR;

	int resl = dc_mok_request_delete(siglist, sl_size, password, is_x);
	free(siglist);
	return resl;
}

int dc_mok_revoke_enroll(int is_x)
{
	int resl;
	if (is_x) {
		resl = dc_mok_del_var(L"MokXNew");
		if (resl == ST_OK) resl = dc_mok_del_var(L"MokXAuth");
	} else {
		resl = dc_mok_del_var(L"MokNew");
		if (resl == ST_OK) resl = dc_mok_del_var(L"MokAuth");
	}
	return resl;
}

int dc_mok_revoke_delete(int is_x)
{
	int resl;
	if (is_x) {
		resl = dc_mok_del_var(L"MokXDel");
		if (resl == ST_OK) resl = dc_mok_del_var(L"MokXDelAuth");
	} else {
		resl = dc_mok_del_var(L"MokDel");
		if (resl == ST_OK) resl = dc_mok_del_var(L"MokDelAuth");
	}
	return resl;
}

int dc_mok_reset(const wchar_t *password, int is_x)
{
	const wchar_t *new_var = is_x ? L"MokXNew" : L"MokNew";
	const wchar_t *auth_var = is_x ? L"MokXAuth" : L"MokAuth";

	/* Reset = set MokAuth WITHOUT MokNew. MokManager sees MokAuth alone
	 * and shows "Reset MOK" instead of "Enroll MOK". */
	dc_mok_del_var(new_var);

	DWORD auth_size;
	BYTE *auth_data = dc_mok_build_auth(password, &auth_size);
	if (auth_data == NULL)
		return ST_ERROR;

	int resl = dc_mok_set_var(auth_var, auth_data, auth_size);
	free(auth_data);

	if (resl != ST_OK)
		dc_mok_del_var(auth_var);
	return resl;
}

int dc_mok_test_cert(const BYTE *cert_data, DWORD cert_size)
{
	DWORD var_size;
	BYTE *var_data = dc_mok_get_var(L"MokListRT", &var_size);
	if (var_data == NULL)
		return 0;

	DWORD offset = 0;
	int found = 0;

	while (offset + 28 <= var_size && !found) {
		GUID *sigType = (GUID*)(var_data + offset);
		DWORD sigListSize = *(DWORD*)(var_data + offset + 16);
		DWORD sigHeaderSize = *(DWORD*)(var_data + offset + 20);
		DWORD sigSize = *(DWORD*)(var_data + offset + 24);

		if (sigListSize == 0 || sigListSize > var_size - offset || sigListSize < 28)
			break;

		if (memcmp(sigType, &EFI_CERT_X509_GUID, sizeof(GUID)) == 0 && sigSize > 16) {
			DWORD sigOffset = offset + 28 + sigHeaderSize;
			DWORD sigDataEnd = offset + sigListSize;

			while (sigOffset + sigSize <= sigDataEnd) {
				BYTE *certPtr = var_data + sigOffset + 16;
				DWORD certLen = sigSize - 16;

				if (certLen == cert_size && memcmp(certPtr, cert_data, cert_size) == 0) {
					found = 1;
					break;
				}
				sigOffset += sigSize;
			}
		}

		offset += sigListSize;
	}

	free(var_data);
	return found;
}

/* ---- Simple variable setters ---- */

/* PASSWORD_CRYPT layout matching shim's passwordcrypt.h (packed, 172 bytes):
 *   UINT16 method;       // offset 0
 *   UINT64 iter_count;   // offset 2
 *   UINT16 salt_size;    // offset 10
 *   UINT8  salt[32];     // offset 12
 *   UINT8  hash[128];    // offset 44
 */
#define PW_CRYPT_METHOD_SHA512  4
#define PW_CRYPT_TOTAL_SIZE     172
#define PW_CRYPT_SALT_MAX       32
#define PW_CRYPT_HASH_MAX       128

int dc_mok_set_password(const wchar_t *password, int pw_chars)
{
	BYTE salt[MOK_SALT_SIZE];
	if (dc_mok_gen_salt(salt, sizeof(salt)) != ST_OK)
		return ST_ERROR;

	BYTE hash[SHA512_DIGEST_SIZE];
	int resl = dc_mok_hash_password(password, pw_chars, salt, sizeof(salt), hash, sizeof(hash));
	if (resl != ST_OK) return resl;

	BYTE pw_var[PW_CRYPT_TOTAL_SIZE];
	memset(pw_var, 0, sizeof(pw_var));

	*(UINT16*)(pw_var + 0)  = PW_CRYPT_METHOD_SHA512;
	*(UINT64*)(pw_var + 2)  = SHA512_CRYPT_ROUNDS_DEFAULT;
	*(UINT16*)(pw_var + 10) = MOK_SALT_SIZE;
	memcpy(pw_var + 12, salt, MOK_SALT_SIZE);
	memcpy(pw_var + 44, hash, SHA512_DIGEST_SIZE);

	resl = dc_mok_set_var(L"MokPW", pw_var, sizeof(pw_var));
	SecureZeroMemory(pw_var, sizeof(pw_var));
	SecureZeroMemory(hash, sizeof(hash));
	SecureZeroMemory(salt, sizeof(salt));
	return resl;
}

int dc_mok_clear_password(void)
{
	/* Set MokPW to all-zeros (PASSWORD_CRYPT_SIZE). MokManager detects this
	 * as the clear sentinel, prompts "Clear MOK password?", and deletes MokPWStore. */
	BYTE pw_var[PW_CRYPT_TOTAL_SIZE];
	memset(pw_var, 0, sizeof(pw_var));
	return dc_mok_set_var(L"MokPW", pw_var, sizeof(pw_var));
}

int dc_mok_set_sbat_policy(BYTE policy_val)
{
	return dc_mok_set_var(L"SbatPolicy", &policy_val, sizeof(policy_val));
}

int dc_mok_del_sbat_policy(void)
{
	return dc_mok_del_var(L"SbatPolicy");
}

int dc_mok_set_byte_var(const wchar_t *name, BYTE val)
{
	return dc_mok_set_var(name, &val, sizeof(val));
}

int dc_mok_set_timeout(INT16 val)
{
	return dc_mok_set_var(L"MokTimeout", (BYTE*)&val, sizeof(val));
}

/* ---- SBAT ---- */

BYTE *dc_mok_get_sbat(DWORD *out_size)
{
	BYTE *data = dc_mok_get_var(L"SbatLevelRT", out_size);
	if (data == NULL)
		data = dc_mok_get_var_ex(L"SbatLevel", mok_var_guid, out_size);
	return data;
}

/* ---- Export ---- */

int dc_mok_export(const wchar_t *dir_path, int is_x)
{
	const wchar_t *var_name = is_x ? L"MokListXRT" : L"MokListRT";
	DWORD var_size;
	BYTE *var_data = dc_mok_get_var(var_name, &var_size);

	if (var_data == NULL)
		return 0;

	CreateDirectoryW(dir_path, NULL);

	DWORD offset = 0;
	int entry_num = 0;

	while (offset + 28 <= var_size) {
		GUID *sigType = (GUID*)(var_data + offset);
		DWORD sigListSize = *(DWORD*)(var_data + offset + 16);
		DWORD sigHeaderSize = *(DWORD*)(var_data + offset + 20);
		DWORD sigSize = *(DWORD*)(var_data + offset + 24);

		if (sigListSize == 0 || sigListSize > var_size - offset || sigListSize < 28)
			break;

		int is_cert = (memcmp(sigType, &EFI_CERT_X509_GUID, sizeof(GUID)) == 0);
		const wchar_t *ext = is_cert ? L".der" : L".hash";

		DWORD sigDataSize = sigListSize - 28 - sigHeaderSize;
		if (sigSize == 0 || sigSize <= 16 || sigDataSize % sigSize != 0) {
			offset += sigListSize;
			continue;
		}

		DWORD numSigs = sigDataSize / sigSize;
		DWORD sigOffset = offset + 28 + sigHeaderSize;

		for (DWORD i = 0; i < numSigs && sigOffset + sigSize <= var_size; i++) {
			BYTE *dataPtr = var_data + sigOffset + 16;
			DWORD dataSize = sigSize - 16;

			wchar_t out_path[MAX_PATH];
			_snwprintf(out_path, MAX_PATH, L"%s\\MOK_%04d%s", dir_path, entry_num, ext);

			save_file(out_path, dataPtr, dataSize);
			entry_num++;
			sigOffset += sigSize;
		}

		offset += sigListSize;
	}

	free(var_data);
	return entry_num;
}
