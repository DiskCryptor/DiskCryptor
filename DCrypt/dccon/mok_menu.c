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
#include "defines.h"
#include "main.h"
#include "bootloader.h"
#include "misc.h"
#include "efiinst.h"
#include "mok_sup.h"
#include "console.h"

/* ---- CLI helpers ---- */

/* Prompt for MOK password interactively, or use -pass parameter if provided.
 * Returns wide-char length or 0 on failure. */
static int mok_prompt_password(wchar_t *pw_buf, int max_chars, int confirm)
{
	wchar_t *pass_param = get_param(L"-pass");
	if (pass_param != NULL) {
		int len = (int)wcslen(pass_param);
		if (len == 0 || len >= max_chars) return 0;
		wcscpy_s(pw_buf, max_chars, pass_param);
		return len;
	}

	int i;
	wint_t ch;
	wchar_t* default_pw = L"123";

	wprintf(L"Enter MOK password (%s): ", default_pw);
	i = 0;
	while ((ch = _getwch()) != L'\r' && ch != L'\n' && i < max_chars - 1) {
		if (ch == 8 && i > 0) {
			i--;
			wprintf(L"\b \b");
		} else if (ch >= 32) {
			pw_buf[i++] = (wchar_t)ch;
			wprintf(L"*");
		}
	}
	pw_buf[i] = 0;
	wprintf(L"\n");

	if (i == 0) {
		wcscpy_s(pw_buf, max_chars, default_pw);
		return (int)wcslen(pw_buf);
	}

	if (confirm) {
		wchar_t confirm_buf[256];
		int j = 0;

		wprintf(L"Confirm password: ");
		while ((ch = _getwch()) != L'\r' && ch != L'\n' && j < max_chars - 1) {
			if (ch == 8 && j > 0) {
				j--;
				wprintf(L"\b \b");
			} else if (ch >= 32) {
				confirm_buf[j++] = (wchar_t)ch;
				wprintf(L"*");
			}
		}
		confirm_buf[j] = 0;
		wprintf(L"\n");

		if (i != j || wcscmp(pw_buf, confirm_buf) != 0) {
			wprintf(L"Passwords do not match\n");
			SecureZeroMemory(confirm_buf, sizeof(confirm_buf));
			return 0;
		}
		SecureZeroMemory(confirm_buf, sizeof(confirm_buf));
	}

	return i;
}

/* Callback to print signature entries */
static int print_sig_entry(int index, const mok_sig_info *info, void *param)
{
	if (info->is_cert) {
		PCCERT_CONTEXT pCert = CertCreateCertificateContext(
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			info->data, info->data_size);

		if (pCert != NULL) {
			char cn[256] = {0};
			CertGetNameStringA(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
				0, NULL, cn, sizeof(cn));

			BYTE hash[20];
			DWORD hashSize = sizeof(hash);
			if (CryptHashCertificate(0, CALG_SHA1, 0,
				pCert->pbCertEncoded, pCert->cbCertEncoded,
				hash, &hashSize)) {
				printf("[%d] %-60s %02X%02X%02X%02X...%02X%02X\n", index, cn,
					hash[0], hash[1], hash[2], hash[3],
					hash[18], hash[19]);
			} else {
				printf("[%d] %s\n", index, cn);
			}
			CertFreeCertificateContext(pCert);
		} else {
			wprintf(L"[%d] <invalid certificate>\n", index);
		}
	} else {
		wprintf(L"[%d] [%s] ", index, info->type_name);
		DWORD print_size = info->data_size;
		if (info->hash_algo_size > 0 && (DWORD)info->hash_algo_size < print_size)
			print_size = info->hash_algo_size;
		for (DWORD h = 0; h < print_size; h++)
			wprintf(L"%02X", info->data[h]);
		wprintf(L"\n");
	}

	/* Track count in param if provided */
	if (param != NULL)
		(*(int*)param)++;

	return 0; /* continue enumeration */
}

/* Display signature list with label */
static void mok_print_siglist(const BYTE *data, DWORD size, const wchar_t *label)
{
	if (label != NULL)
		wprintf(L"%s:\n", label);

	int count = 0;
	dc_mok_enum_siglist(data, size, print_sig_entry, &count);

	if (count == 0)
		wprintf(L"  (empty)\n");
}

/* ---- Command handlers ---- */

static int mok_cmd_list(int argc, wchar_t *argv[])
{
	int is_x = is_param(L"-x");
	int is_new = is_param(L"-new");
	int is_del = is_param(L"-del");
	int is_pk = is_param(L"-pk");
	int is_kek = is_param(L"-kek");
	int is_db = is_param(L"-db");
	int is_dbx = is_param(L"-dbx");
	int is_all = is_param(L"-all");

	/* UEFI standard variables (read-only listing) */
	if (is_pk || is_all) {
		DWORD sz;
		BYTE *data = dc_mok_get_var_ex(L"PK", efi_var_guid, &sz);
		if (data) {
			mok_print_siglist(data, sz, L"Platform Key (PK)");
			my_free(data);
		} else {
			wprintf(L"Platform Key (PK):\n  (not set or unable to read)\n");
		}
	}

	if (is_kek || is_all) {
		DWORD sz;
		BYTE *data = dc_mok_get_var_ex(L"KEK", efi_var_guid, &sz);
		if (data) {
			mok_print_siglist(data, sz, L"\nKey Exchange Keys (KEK)");
			my_free(data);
		} else {
			wprintf(L"\nKey Exchange Keys (KEK):\n  (not set or unable to read)\n");
		}
	}

	if (is_db || is_all) {
		DWORD sz;
		BYTE *data = dc_mok_get_var_ex(L"db", sb_var_guid, &sz);
		if (data) {
			mok_print_siglist(data, sz, L"\nSignature Database (db)");
			my_free(data);
		} else {
			wprintf(L"\nSignature Database (db):\n  (not set or unable to read)\n");
		}
	}

	if (is_dbx || is_all) {
		DWORD sz;
		BYTE *data = dc_mok_get_var_ex(L"dbx", sb_var_guid, &sz);
		if (data) {
			mok_print_siglist(data, sz, L"\nForbidden Signatures (dbx)");
			my_free(data);
		} else {
			wprintf(L"\nForbidden Signatures (dbx):\n  (not set or unable to read)\n");
		}
	}

	if (is_pk || is_kek || is_db || is_dbx || is_all)
		return ST_OK;

	/* MOK variables */
	const wchar_t *var_name;
	const wchar_t *label;

	if (is_new) {
		var_name = is_x ? L"MokXNew" : L"MokNew";
		label = is_x ? L"Pending MOK blacklist additions (MokXNew)" : L"Pending MOK enrollment (MokNew)";
	} else if (is_del) {
		var_name = is_x ? L"MokXDel" : L"MokDel";
		label = is_x ? L"Pending MOK blacklist deletions (MokXDel)" : L"Pending MOK deletion (MokDel)";
	} else {
		var_name = is_x ? L"MokListXRT" : L"MokListRT";
		label = is_x ? L"Enrolled MOK blacklist (MokListXRT)" : L"Enrolled MOK certificates (MokListRT)";
	}

	DWORD var_size;
	BYTE *var_data = dc_mok_get_var(var_name, &var_size);

	if (var_data == NULL) {
		wprintf(L"%s:\n  (empty or not accessible)\n", label);
		return ST_OK;
	}

	mok_print_siglist(var_data, var_size, label);
	my_free(var_data);
	return ST_OK;
}

/* Shared handler for -import and -delete of certificate files */
static int mok_cmd_cert_action(int argc, wchar_t *argv[], int is_enroll)
{
	int is_x = is_param(L"-x");

	int file_count = 0;
	for (int i = 3; i < argc && argv[i][0] != L'-'; i++)
		file_count++;

	if (file_count == 0) {
		wprintf(L"Error: specify certificate file(s)\n");
		return ST_INVALID_PARAM;
	}

	const wchar_t **files = (const wchar_t **)&argv[3];
	
	wchar_t password[256];
	int pw_len = mok_prompt_password(password, 256, 1);
	if (pw_len == 0)
		return ST_CANCEL;

	int resl;
	if (is_enroll)
		resl = dc_mok_enroll_files(files, file_count, password, is_x);
	else
		resl = dc_mok_request_delete_files(files, file_count, password, is_x);
	SecureZeroMemory(password, sizeof(password));

	if (resl == ST_OK) {
		wprintf(L"\nCertificate(s) queued for %s. Reboot to complete.\n",
			is_enroll ? L"enrollment" : L"deletion");
	} else {
		wprintf(L"Error: %d\n", resl);
	}
	return resl;
}

/* Shared handler for -import-hash and -delete-hash */
static int mok_cmd_hash_action(int argc, wchar_t *argv[], int is_enroll)
{
	int is_x = is_param(L"-x");
	BYTE hash[64];

	if (argc < 4) {
		wprintf(L"Error: specify hash value\n");
		return ST_INVALID_PARAM;
	}

	int hash_len = dc_mok_parse_hex(argv[3], hash, sizeof(hash));
	const GUID *hash_type = dc_mok_hash_type_by_size(hash_len);

	if (hash_type == NULL) {
		wprintf(L"Error: invalid hash length (%d bytes). Expected 32 (SHA-256), 48 (SHA-384), or 64 (SHA-512)\n", hash_len);
		return ST_INVALID_PARAM;
	}

	DWORD sl_size;
	BYTE *siglist = dc_mok_build_hash_siglist(hash, hash_len, hash_type, &sl_size);
	if (siglist == NULL) return ST_NOMEM;

	wchar_t password[256];
	int pw_len = mok_prompt_password(password, 256, 1);
	if (pw_len == 0) {
		my_free(siglist);
		return ST_CANCEL;
	}

	int resl;
	if (is_enroll)
		resl = dc_mok_enroll(siglist, sl_size, password, is_x);
	else
		resl = dc_mok_request_delete(siglist, sl_size, password, is_x);
	SecureZeroMemory(password, sizeof(password));
	my_free(siglist);

	if (resl == ST_OK)
		wprintf(L"Hash queued for %s. Reboot to complete.\n",
			is_enroll ? L"enrollment" : L"deletion");
	else
		wprintf(L"Error: %d\n", resl);
	return resl;
}

static int mok_cmd_export(int argc, wchar_t *argv[])
{
	wchar_t *dir_path = get_param(L"-dir");
	int is_x = is_param(L"-x");

	if (dir_path == NULL) {
		wprintf(L"Error: specify -dir <path>\n");
		return ST_INVALID_PARAM;
	}

	int count = dc_mok_export(dir_path, is_x);
	if (count > 0)
		wprintf(L"Exported %d entries to %s\n", count, dir_path);
	else
		wprintf(L"No MOK certificates found\n");
	return ST_OK;
}

static int mok_cmd_revoke(int is_delete)
{
	int resl;
	if (is_delete) {
		resl = dc_mok_revoke_delete(0);
		if (resl == ST_OK) wprintf(L"Pending deletion request revoked\n");
	} else {
		resl = dc_mok_revoke_enroll(0);
		if (resl == ST_OK) wprintf(L"Pending enrollment request revoked\n");
	}
	return resl;
}

static int mok_cmd_reset(void)
{
	int is_x = is_param(L"-x");

	wprintf(L"This will clear the entire %s on next reboot.\n",
		is_x ? L"MOK blacklist" : L"MOK list");
	wprintf(L"Are you sure? (Y/N): ");

	if (tolower(_getch()) != 'y') {
		wprintf(L"\nCancelled\n");
		return ST_OK;
	}
	wprintf(L"\n");

	wchar_t password[256];
	int pw_len = mok_prompt_password(password, 256, 1);
	if (pw_len == 0)
		return ST_CANCEL;

	int resl = dc_mok_reset(password, is_x);
	SecureZeroMemory(password, sizeof(password));

	if (resl == ST_OK)
		wprintf(L"MOK reset queued. Reboot to complete.\n");
	else
		wprintf(L"Error queuing reset: %d\n", resl);
	return resl;
}

/* Extract signing certificate from a file. Handles DER certs, PEM certs,
 * PKCS#7, and signed PE/EFI binaries via CryptQueryObject.
 * Returns a cert context that must be freed with CertFreeCertificateContext,
 * or NULL on failure. */
static PCCERT_CONTEXT mok_extract_cert(const wchar_t *file_path)
{
	HCERTSTORE hStore = NULL;
	HCRYPTMSG hMsg = NULL;
	DWORD contentType = 0;
	PCCERT_CONTEXT pCert = NULL;

	/* Try as certificate file (DER or PEM) */
	if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, file_path,
		CERT_QUERY_CONTENT_FLAG_CERT,
		CERT_QUERY_FORMAT_FLAG_ALL, 0,
		NULL, &contentType, NULL, &hStore, NULL, NULL))
	{
		pCert = CertEnumCertificatesInStore(hStore, NULL);
		if (pCert != NULL)
			pCert = CertDuplicateCertificateContext(pCert);
		CertCloseStore(hStore, 0);
		return pCert;
	}

	/* Try as signed PE / Authenticode (PKCS#7 embedded signature) */
	if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, file_path,
		CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		CERT_QUERY_FORMAT_FLAG_BINARY, 0,
		NULL, &contentType, NULL, &hStore, &hMsg, NULL))
	{
		/* Get the signer certificate from the embedded signature */
		DWORD signer_size = 0;
		if (CryptMsgGetParam(hMsg, CMSG_SIGNER_CERT_ID_PARAM, 0, NULL, &signer_size)) {
			BYTE *signer_info = (BYTE*)malloc(signer_size);
			if (signer_info != NULL) {
				if (CryptMsgGetParam(hMsg, CMSG_SIGNER_CERT_ID_PARAM, 0, signer_info, &signer_size)) {
					CERT_ID *cert_id = (CERT_ID*)signer_info;
					pCert = CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
						0, CERT_FIND_CERT_ID, cert_id, NULL);
					if (pCert != NULL)
						pCert = CertDuplicateCertificateContext(pCert);
				}
				free(signer_info);
			}
		}

		/* Fallback: just get first cert from the store */
		if (pCert == NULL) {
			PCCERT_CONTEXT pFirst = CertEnumCertificatesInStore(hStore, NULL);
			if (pFirst != NULL)
				pCert = CertDuplicateCertificateContext(pFirst);
		}

		if (hMsg) CryptMsgClose(hMsg);
		CertCloseStore(hStore, 0);
		return pCert;
	}

	/* Try as standalone PKCS#7 file */
	if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, file_path,
		CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
		CERT_QUERY_FORMAT_FLAG_ALL, 0,
		NULL, &contentType, NULL, &hStore, NULL, NULL))
	{
		pCert = CertEnumCertificatesInStore(hStore, NULL);
		if (pCert != NULL)
			pCert = CertDuplicateCertificateContext(pCert);
		CertCloseStore(hStore, 0);
		return pCert;
	}

	return NULL;
}

static int mok_cmd_test(int argc, wchar_t *argv[])
{
	if (argc < 4) {
		wprintf(L"Error: specify certificate or signed file\n");
		return ST_INVALID_PARAM;
	}

	PCCERT_CONTEXT pCert = mok_extract_cert(argv[3]);
	if (pCert == NULL) {
		wprintf(L"Error: could not read certificate from: %s\n", argv[3]);
		wprintf(L"  Supported formats: DER cert, PEM cert, signed PE/EFI binary, PKCS#7\n");
		return ST_ERROR;
	}

	char cn[256] = {0};
	CertGetNameStringA(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, cn, sizeof(cn));

	int found = dc_mok_test_cert(pCert->pbCertEncoded, pCert->cbCertEncoded);
	CertFreeCertificateContext(pCert);

	if (found)
		printf("ENROLLED: %s\n", cn);
	else
		printf("NOT enrolled: %s\n", cn);

	return ST_OK;
}

static int mok_cmd_password(void)
{
	wchar_t password[256];
	int pw_len = mok_prompt_password(password, 256, 1);
	if (pw_len == 0)
		return ST_CANCEL;

	int resl = dc_mok_set_password(password, pw_len);
	SecureZeroMemory(password, sizeof(password));

	if (resl == ST_OK)
		wprintf(L"MOK password set. Reboot to apply.\n");
	else
		wprintf(L"Error setting password: %d\n", resl);
	return resl;
}

static int mok_cmd_clear_password(void)
{
	int resl = dc_mok_clear_password();
	if (resl == ST_OK)
		wprintf(L"MOK password cleared\n");
	return resl;
}

/*static int mok_cmd_generate_hash(void)
{
	wchar_t password[256];
	wchar_t *p_param = get_param(L"-p");
	int pw_len;

	if (p_param != NULL) {
		wcscpy_s(password, 256, p_param);
		pw_len = (int)wcslen(password);
	} else {
		pw_len = mok_prompt_password(password, 256, 0);
	}

	if (pw_len == 0) return ST_CANCEL;

	BYTE salt[MOK_SALT_SIZE];
	if (dc_mok_gen_salt(salt, sizeof(salt)) != ST_OK) {
		SecureZeroMemory(password, sizeof(password));
		return ST_ERROR;
	}

	BYTE hash[SHA512_DIGEST_SIZE];
	int resl = dc_mok_hash_password(password, pw_len, salt, sizeof(salt), hash, sizeof(hash));
	SecureZeroMemory(password, sizeof(password));

	if (resl != ST_OK) {
		wprintf(L"Error hashing password\n");
		return resl;
	}

	wprintf(L"Salt:  ");
	for (int i = 0; i < MOK_SALT_SIZE; i++)
		wprintf(L"%02x", salt[i]);
	wprintf(L"\nHash:  ");
	for (int i = 0; i < SHA512_DIGEST_SIZE; i++)
		wprintf(L"%02x", hash[i]);
	wprintf(L"\n");

	SecureZeroMemory(hash, sizeof(hash));
	return ST_OK;
}*/

static int mok_cmd_sb_state(void)
{
	int sb_enabled = dc_efi_is_secureboot();
	int sb_setup = dc_efi_is_sb_setupmode();
	wprintf(L"SecureBoot: %s\n", sb_setup ? L"Setup Mode" : (sb_enabled ? L"ENABLED" : L"DISABLED"));

	int sb_state = dc_mok_get_sb_state();
	if (sb_state >= 0)
		wprintf(L"Shim validation: %s\n", sb_state ? L"DISABLED" : L"ENABLED");
	else
		wprintf(L"Shim validation: ENABLED (default)\n");

	int db_state = dc_mok_get_db_state();
	if (db_state >= 0)
		wprintf(L"Use UEFI db: %s\n", db_state ? L"IGNORED" : L"USED");
	else
		wprintf(L"Use UEFI db: USED (default)\n");

	return ST_OK;
}

static int mok_cmd_validation(int enable, int is_db_toggle)
{
	wchar_t password[256];
	int pw_len = mok_prompt_password(password, 256, 1);
	if (pw_len == 0)
		return ST_CANCEL;

	int resl;
	if (is_db_toggle)
		resl = dc_mok_set_db_usage(enable, password, pw_len);
	else
		resl = dc_mok_set_validation(enable, password, pw_len);
	SecureZeroMemory(password, sizeof(password));

	if (resl == ST_OK) {
		if (is_db_toggle)
			wprintf(L"UEFI db will be %s on next reboot.\n", enable ? L"used" : L"ignored");
		else
			wprintf(L"Shim validation will be %s on next reboot.\n", enable ? L"enabled" : L"disabled");
	}
	return resl;
}

static int mok_cmd_sbat(void)
{
	DWORD sz;
	BYTE *data = dc_mok_get_sbat(&sz);
	if (data == NULL) {
		wprintf(L"No SBAT revocation data found\n");
		return ST_OK;
	}

	wprintf(L"SBAT revocations:\n");
	printf("%.*s", sz, data);
	if (sz > 0 && data[sz-1] != '\n')
		printf("\n");

	my_free(data);
	return ST_OK;
}

static int mok_cmd_sbat_policy(int argc, wchar_t *argv[])
{
	if (argc < 4) {
		wprintf(L"Error: specify policy (latest, automatic, previous, delete)\n");
		return ST_INVALID_PARAM;
	}

	wchar_t *policy = argv[3];
	int resl;

	if (_wcsicmp(policy, L"latest") == 0) {
		resl = dc_mok_set_sbat_policy(1);
	} else if (_wcsicmp(policy, L"automatic") == 0) {
		resl = dc_mok_set_sbat_policy(2);
	} else if (_wcsicmp(policy, L"previous") == 0) {
		resl = dc_mok_set_sbat_policy(3);
	} else if (_wcsicmp(policy, L"delete") == 0) {
		resl = dc_mok_del_sbat_policy();
	} else {
		wprintf(L"Error: invalid policy. Use: latest, automatic, previous, delete\n");
		return ST_INVALID_PARAM;
	}

	if (resl == ST_OK)
		wprintf(L"SBAT policy set to '%s'. Reboot to apply.\n", policy);
	return resl;
}

static int mok_cmd_verbosity(int argc, wchar_t *argv[], const wchar_t *var_name)
{
	if (argc < 4) {
		wprintf(L"Error: specify true or false\n");
		return ST_INVALID_PARAM;
	}

	BYTE val;
	if (_wcsicmp(argv[3], L"true") == 0) {
		val = 1;
	} else if (_wcsicmp(argv[3], L"false") == 0) {
		val = 0;
	} else {
		wprintf(L"Error: specify true or false\n");
		return ST_INVALID_PARAM;
	}

	/* Write as UINT32. shim reads SHIM_VERBOSE as UINT32 (masked to the stored
	 * size) and FALLBACK_VERBOSE as "any non-zero byte", so both tolerate 4
	 * bytes; but FB_NO_REBOOT is read as a UINT32 and compared == 1
	 * (fallback.c get_fallback_no_reboot), so a 1-byte write leaves 3
	 * uninitialized bytes and fails. Always write the full UINT32. */
	UINT32 dword_val = val;
	int resl = dc_mok_set_var(var_name, (BYTE*)&dword_val, sizeof(dword_val));
	if (resl == ST_OK)
		wprintf(L"Variable '%s' set to %s\n", var_name, val ? L"true" : L"false");
	return resl;
}

static int mok_cmd_timeout(int argc, wchar_t *argv[])
{
	if (argc < 4) {
		wprintf(L"Error: specify timeout value (-1 to 32767)\n");
		return ST_INVALID_PARAM;
	}

	int val = _wtoi(argv[3]);
	if (val < -1 || val > 32767) {
		wprintf(L"Error: timeout must be between -1 and 32767\n");
		return ST_INVALID_PARAM;
	}

	int resl = dc_mok_set_timeout((INT32)val);
	if (resl == ST_OK)
		wprintf(L"MOK timeout set to %d\n", val);
	return resl;
}

void print_mok_enroll(int from_file);
void show_mok_enroll(int from_file);

/* ---- Main dispatch ---- */

int mok_menu(int argc, wchar_t *argv[])
{
	int resl = ST_INVALID_PARAM;

	if (!dc_efi_check()) {
		wprintf(L"System is not running in EFI mode\n");
		return ST_OK;
	}

	do
	{
		if (argc < 3) break;

		if (wcscmp(argv[2], L"-list") == 0) {
			resl = mok_cmd_list(argc, argv);
			break;
		}

		if (wcscmp(argv[2], L"-import") == 0) {
			resl = mok_cmd_cert_action(argc, argv, 1);
			break;
		}

		if (wcscmp(argv[2], L"-import-hash") == 0) {
			resl = mok_cmd_hash_action(argc, argv, 1);
			break;
		}

		if (wcscmp(argv[2], L"-delete") == 0) {
			resl = mok_cmd_cert_action(argc, argv, 0);
			break;
		}

		if (wcscmp(argv[2], L"-delete-hash") == 0) {
			resl = mok_cmd_hash_action(argc, argv, 0);
			break;
		}

		if (wcscmp(argv[2], L"-export") == 0) {
			resl = mok_cmd_export(argc, argv);
			break;
		}

		if (wcscmp(argv[2], L"-revoke-import") == 0) {
			resl = mok_cmd_revoke(0);
			break;
		}

		if (wcscmp(argv[2], L"-revoke-delete") == 0) {
			resl = mok_cmd_revoke(1);
			break;
		}

		if (wcscmp(argv[2], L"-reset") == 0) {
			resl = mok_cmd_reset();
			break;
		}

		if (wcscmp(argv[2], L"-test") == 0) {
			resl = mok_cmd_test(argc, argv);
			break;
		}

		if (wcscmp(argv[2], L"-password") == 0) {
			resl = mok_cmd_password();
			break;
		}

		if (wcscmp(argv[2], L"-clear-password") == 0) {
			resl = mok_cmd_clear_password();
			break;
		}

		//if (wcscmp(argv[2], L"-generate-hash") == 0) {
		//	resl = mok_cmd_generate_hash();
		//	break;
		//}

		if (wcscmp(argv[2], L"-sb-state") == 0) {
			resl = mok_cmd_sb_state();
			break;
		}

		if (wcscmp(argv[2], L"-enable-validation") == 0) {
			resl = mok_cmd_validation(1, 0);
			break;
		}

		if (wcscmp(argv[2], L"-disable-validation") == 0) {
			resl = mok_cmd_validation(0, 0);
			break;
		}

		if (wcscmp(argv[2], L"-use-db") == 0) {
			resl = mok_cmd_validation(1, 1);
			break;
		}

		if (wcscmp(argv[2], L"-ignore-db") == 0) {
			resl = mok_cmd_validation(0, 1);
			break;
		}

		//if (wcscmp(argv[2], L"-sbat") == 0) {
		//	resl = mok_cmd_sbat();
		//	break;
		//}

		//if (wcscmp(argv[2], L"-sbat-policy") == 0) {
		//	resl = mok_cmd_sbat_policy(argc, argv);
		//	break;
		//}

		if (wcscmp(argv[2], L"-verbose") == 0) {
			resl = mok_cmd_verbosity(argc, argv, L"SHIM_VERBOSE");
			break;
		}

		if (wcscmp(argv[2], L"-fb-verbose") == 0) {
			resl = mok_cmd_verbosity(argc, argv, L"FALLBACK_VERBOSE");
			break;
		}

		if (wcscmp(argv[2], L"-fb-noreboot") == 0) {
			resl = mok_cmd_verbosity(argc, argv, L"FB_NO_REBOOT");
			break;
		}

		if (wcscmp(argv[2], L"-timeout") == 0) {
			resl = mok_cmd_timeout(argc, argv);
			break;
		}

		if (wcscmp(argv[2], L"-guide") == 0) {
			if(is_param(L"-print"))
				print_mok_enroll(1);
			else
				show_mok_enroll(1);
			resl = ST_OK;
			break;
		}

		//wprintf(L"Unknown MOK command: %s\n", argv[2]);

	} while (0);

	return resl;
}

#define MOK_SCREEN_HEIGHT 14


static const char mok_error_screen[MOK_SCREEN_HEIGHT][41] = {
"+--------------------------------------+",
"|                ERROR                 |",
"|                                      |",
"|     Verification failed: (0x1A)      |",
"|               Security Violation     |",
"|                                      |",
"|             +----------+             |",
"|             |  > OK <  |             |",
"|             +----------+             |",
"|                                      |",
"|                                      |",
"|                                      |",
"+--------------------------------------+",
"      Select OK and press Enter         "};

static const char mok_mgmt_screen[MOK_SCREEN_HEIGHT][41] = {
"+--------------------------------------+",
"|       Shim UEFI Key Management       |",
"|                                      |",
"|                                      |",
"|                                      |",
"|                                      |",
"|  Press any key to perform MOK mgmt.  |",
"|                                      |",
"|                                      |",
"|                                      |",
"|                                      |",
"| Booting in xx seconds                |",
"+--------------------------------------+",
" Press any key before the timer elapses "};

static const char mok_enroll_screen[MOK_SCREEN_HEIGHT][41] = {
"+--------------------------------------+",
"|        Perform MOK management        |",
"|                                      |",
"|                                      |",
"|       +----------------------+       |",
"|       |    Continue boot     |       |",
"|       |   > Enroll MOK  <    |       |",
"|       |Enroll key from disk  |       |",
"|       |Enroll hash from disk |       |",
"|       +----------------------+       |",
"|                                      |",
"|                                      |",
"+--------------------------------------+",
"    Select Enrok MOK and press Enter    "};

static const char mok_enroll_file_screen[MOK_SCREEN_HEIGHT][41] = {
"+--------------------------------------+",
"|        Perform MOK management        |",
"|                                      |",
"|                                      |",
"|     +--------------------------+     |",
"|     |     Continue boot        |     |",
"|     | > Enroll key from disk < |     |",
"|     |   Enroll hash from disk  |     |",
"|     +--------------------------+     |",
"|                                      |",
"|                                      |",
"|                                      |",
"+--------------------------------------+",
"    Select Enroll key and press Enter   "};

static const char mok_pass_screen[MOK_SCREEN_HEIGHT][41] = {
"+--------------------------------------+",
"|          Enroll the Key(s)?          |",
"|                                      |",
"|                                      |",
"|                                      |",
"|       +----------------------+       |",
"|       | Password: [123]      |       |",
"|       +----------------------+       |",
"|                                      |",
"|                                      |",
"|                                      |",
"|                                      |",
"+--------------------------------------+",
" Enter password (default: 123) [Enter] "};

static const char mok_reboot_screen[MOK_SCREEN_HEIGHT][41] = {
"+--------------------------------------+",
"|        Perform MOK management        |",
"|                                      |",
"|                                      |",
"|       +----------------------+       |",
"|       |     > Reboot <       |       |",
"|       |Enroll key from disk  |       |",
"|       |Enroll hash from disk |       |",
"|       +----------------------+       |",
"|                                      |",
"|                                      |",
"|                                      |",
"+--------------------------------------+",
"    Select Reboot key and press Enter   "};


static const char mok_browse_screen_1[MOK_SCREEN_HEIGHT][41] = {
"+--------------------------------------+",
"|             Select Key               |",
"|                                      |",
"|                                      |",
"|                                      |",
"| +----------------------------------+ |",
"| | > PciRoot(0)/Pci(...)/Path...  < | |",
"| +----------------------------------+ |",
"|                                      |",
"|                                      |",
"|                                      |",
"|                                      |",
"+--------------------------------------+",
"    Select OS Drive and press Enter     "};
static const char mok_browse_screen_2[MOK_SCREEN_HEIGHT][41] = {
"+--------------------------------------+",
"|             Select Key               |",
"|                                      |",
"|                                      |",
"|                                      |",
"| +----------------------------------+ |",
"| |             > EFI/ <             | |",
"| |    System Volume Information/    | |",
"| +----------------------------------+ |",
"|                                      |",
"|                                      |",
"|                                      |",
"+--------------------------------------+",
"       Select EFI and press Enter       "};
static const char mok_browse_screen_3[MOK_SCREEN_HEIGHT][41] = {
"+--------------------------------------+",
"|             Select Key               |",
"|                                      |",
"|                                      |",
"| +----------------------------------+ |",
"| |               ../                | |",
"| |            Microsoft/            | |",
"| |            > Boot/ <             | |",
"| |               DCS/               | |",
"| +----------------------------------+ |",
"|                                      |",
"|                                      |",
"+--------------------------------------+",
"      Select Boot and press Enter       "};
static const char mok_browse_screen_4[MOK_SCREEN_HEIGHT][41] = {
"+--------------------------------------+",
"|             Select Key               |",
"|                                      |",
"| +----------------------------------+ |",
"| |               ../                | |",
"| |           BOOTx64.efi            | |",
"| |      original_BOOTx64.efi        | |",
"| |           shimx64.efi            | |",
"| |            mmx64.efi             | |",
"| |       > CustomSigner.der <       | |",
"| |           grubx64.efi            | |",
"| +----------------------------------+ |",
"+--------------------------------------+",
"  Select CustomSigner and press Enter   "};


static const char mok_enroll_screen_1[MOK_SCREEN_HEIGHT][41] = {
"+--------------------------------------+",
"|            [Enroll MOK]              |",
"|                                      |",
"|                                      |",
"|                                      |",
"|          +----------------+          |",
"|          | > View Key 0 < |          |",
"|          |    Continue    |          |",
"|          +----------------+          |",
"|                                      |",
"|                                      |",
"|                                      |",
"+--------------------------------------+",
"   Select View Key 0 and press Enter   "};
static const char mok_enroll_screen_2[MOK_SCREEN_HEIGHT][41] = {
"+--------------------------------------+",
"|           [Serial Number]            |",
"|     52:C5:92:D4:C7:68:1B:4E:5B:...   |",
"|                                      |",
"|           [Issuer/Subject]           |",
"|   CN = Xanasoft Secure Boot Signer   |",
"|                                      |",
"|                                      |",
"|                                      |",
"|            [Fingerprint]             |",
"|    C7 EF 1E 69 BB 1B F0 F6 EB 17     |",
"|    6F C6 84 D5 49 77 FF D8 6C AB     |",
"+--------------------------------------+",
" Check Fingerprint and press Enter if ok"};

static const char mok_enroll_screen_3[MOK_SCREEN_HEIGHT][41] = {
"+--------------------------------------+",
"|            [Enroll MOK]              |",
"|                                      |",
"|                                      |",
"|                                      |",
"|          +----------------+          |",
"|          |   View Key 0   |          |",
"|          |  > Continue <  |          |",
"|          +----------------+          |",
"|                                      |",
"|                                      |",
"|                                      |",
"+--------------------------------------+",
"    Select Continue and press Enter     "};
static const char mok_enroll_screen_4[MOK_SCREEN_HEIGHT][41] = {
"+--------------------------------------+",
"|          Enroll the Key(s)?          |",
"|                                      |",
"|                                      |",
"|                                      |",
"|            +-----------+             |",
"|            |    No     |             |",
"|            |  > Yes <  |             |",
"|            +-----------+             |",
"|                                      |",
"|                                      |",
"|                                      |",
"+--------------------------------------+",
"      Select Yes and press Enter        "};

// Process flow to enrol a prepared MOK
static const char (*mok_auto_enroll[])[41] = {
	mok_mgmt_screen, mok_enroll_screen,
	/*mok_enroll_screen_1, mok_enroll_screen_2,*/ mok_enroll_screen_3, mok_enroll_screen_4,
	mok_pass_screen, mok_reboot_screen
};

// Process flow to enrol a mok manually from file
static const char (*mok_enroll_file[])[41] = {
	mok_error_screen,
	mok_mgmt_screen, mok_enroll_file_screen,
	mok_browse_screen_1, mok_browse_screen_2, mok_browse_screen_3, mok_browse_screen_4,
	/*mok_enroll_screen_1, mok_enroll_screen_2,*/ mok_enroll_screen_3, mok_enroll_screen_4,
	mok_reboot_screen
};

void show_mok_enroll(int from_file)
{
	CONSOLE_SCREEN_BUFFER_INFO info;
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	GetConsoleScreenBufferInfo(hConsole, &info);

	size_t count = from_file ? _countof(mok_enroll_file) : _countof(mok_auto_enroll);
	const char (*const *mok_enroll)[41] = from_file ? mok_enroll_file : mok_auto_enroll;
	for (size_t i = 0; i < count; i++) {
		SetConsoleCursorPosition(hConsole, info.dwCursorPosition);
		for (size_t row = 0; row < MOK_SCREEN_HEIGHT; row++) {
			printf("%s\n", mok_enroll[i][row]);
		}
		printf("\npress any key to continue...\n");
		_getch();
	}
}

void print_mok_enroll(int from_file)
{
	CONSOLE_SCREEN_BUFFER_INFO info;
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	GetConsoleScreenBufferInfo(hConsole, &info);
	SHORT columns = info.dwSize.X / 40;
	if(columns < 1) columns = 1;

	size_t count = from_file ? _countof(mok_enroll_file) : _countof(mok_auto_enroll);
	const char (*const *mok_enroll)[41] = from_file ? mok_enroll_file : mok_auto_enroll;
	for (size_t i = 0; i < count; i += columns) {
		for (size_t row = 0; row < MOK_SCREEN_HEIGHT; row++) {
			for (size_t col = 0; col < columns; col++) {
				if (i + col < count) {
					printf("%s", mok_enroll[i + col][row]);
				}
			}
			printf("\n");
		}
		printf("\n");
	}
}
