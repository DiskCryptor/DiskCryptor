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
#pragma comment(lib, "Advapi32.lib")
#include "defines.h"
#include "main.h"
#include "bootloader.h"
#include "misc.h"
#include "efiinst.h"
#include "console.h"

// EFI variable enumeration support
typedef enum _SYSTEM_ENVIRONMENT_INFORMATION_CLASS {
	SystemEnvironmentUnknownInformation,
	SystemEnvironmentNameInformation,
	SystemEnvironmentValueInformation,
	MaxSystemEnvironmentInfoClass
} SYSTEM_ENVIRONMENT_INFORMATION_CLASS;

typedef struct _VARIABLE_NAME {
	ULONG NextEntryOffset;
	GUID  VendorGuid;
	WCHAR Name[ANYSIZE_ARRAY];
} VARIABLE_NAME, *PVARIABLE_NAME;

typedef NTSTATUS (NTAPI *PFN_NtEnumerateSystemEnvironmentValuesEx)(
	ULONG InformationClass,
	PVOID Buffer,
	PULONG BufferLength
);

// SetFirmwareEnvironmentVariableExW - Windows 8+ API
typedef BOOL (WINAPI *PFN_SetFirmwareEnvironmentVariableExW)(
	LPCWSTR lpName,
	LPCWSTR lpGuid,
	PVOID pValue,
	DWORD nSize,
	DWORD dwAttributes
);

static void print_hex_dump(const BYTE *data, DWORD length)
{
	DWORD i, j;

	for (i = 0; i < length; i += 16) {
		// Print offset
		wprintf(L"%08X  ", i);

		// Print hex bytes
		for (j = 0; j < 16; j++) {
			if (j == 8) wprintf(L" ");
			if (i + j < length) {
				wprintf(L"%02X ", data[i + j]);
			} else {
				wprintf(L"   ");
			}
		}

		// Print ASCII representation
		wprintf(L" |");
		for (j = 0; j < 16 && i + j < length; j++) {
			BYTE c = data[i + j];
			if (c >= 0x20 && c < 0x7F) {
				wprintf(L"%c", c);
			} else {
				wprintf(L".");
			}
		}
		wprintf(L"|\n");
	}
}

int list_signer(const BYTE* hash, const char* name, PVOID param)
{
	/*printf("%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X %s\n",
	hash[0], hash[1], hash[2], hash[3],
	hash[4], hash[5], hash[6], hash[7],
	hash[8], hash[9], hash[10], hash[11],
	hash[12], hash[13], hash[14], hash[15],
	hash[16], hash[17], hash[18], hash[19],
	name);*/

	int* temp = (int*)param;
	char buf[65];
	strcpy_s(buf, sizeof(buf), name);

	if (temp && *temp) {
		if(--*temp == 0)
			strcat_s(buf, sizeof(buf), " *");
	}

	printf("%-64s%02X%02X%02X%02X...%02X%02X\n", buf,
		hash[0], hash[1], hash[2], hash[3],
		hash[18], hash[19]);
	return ST_OK;
}

static int efi_cmd_info(int argc, wchar_t *argv[])
{
	int sb_enabled = dc_efi_is_secureboot();
	int sb_setup = dc_efi_is_sb_setupmode();

	wprintf(L"Secure Boot is %s\n", sb_setup ? L"in Setup Mode" : (sb_enabled ? L"ENABLED" : L"DISABLED"));

	wprintf(L"\nPlatform Key (PK):\n");

	if (dc_efi_enum_var(L"PK", efi_var_guid, list_signer, NULL) != ST_OK) {
		wprintf(L"No Platform Key found or unable to read PK variable\n");
	}
	wprintf(L"\n");

#ifdef _DEBUG
	//wprintf(L"-------------------------------------------------------------------------------\n");
	wprintf(L"Key Exchange Keys (KEK):\n");
	//wprintf(L"-------------------------------------------------------------------------------\n");

	if (dc_efi_enum_var(L"KEK", efi_var_guid, list_signer, NULL) != ST_OK) {
		wprintf(L"No Key Exchange Key found or unable to read KEK variable\n");
	}
	wprintf(L"\n");
#endif

	int signer = dc_efi_dcs_is_signed();

	//wprintf(L"-------------------------------------------------------------------------------\n");
	wprintf(L"Allowed Signers (db):\n");
	//wprintf(L"-------------------------------------------------------------------------------\n");

	int temp = signer;
	dc_efi_enum_allowed_signers(list_signer, &temp);
	//dc_efi_enum_var(L"db", sb_var_guid, list_signer, &temp);

	wprintf(L"\n");
	if (signer) 
		wprintf(L"* used to sign EFI DCS Bootloader for Secure Boot on this system.\n");
	else {
		wprintf(L"EFI DCS Bootloader is currently NOT signed for Secure Boot on this system !!!\n");

		if(dc_efi_shim_available())
			wprintf(L"A shim loader is available to use for Secure Boot.\n");
		else
			wprintf(L"No shim loader is available in this installation!\n");
	}

#ifdef _DEBUG
	//wprintf(L"-------------------------------------------------------------------------------\n");
	wprintf(L"\nForbidden Signers (dbx):\n");
	//wprintf(L"-------------------------------------------------------------------------------\n");

	if (dc_efi_enum_var(L"dbx", sb_var_guid, list_signer, NULL) != ST_OK) {
		wprintf(L"No Forbidden Signer found or unable to read dbx variable\n");
	}
#endif

	return ST_OK;
}

static int efi_cmd_list(int argc, wchar_t *argv[])
{
	PFN_NtEnumerateSystemEnvironmentValuesEx pNtEnumEnvValuesEx;
	PVOID buffer = NULL;
	ULONG bufferLength = 0x1000; // Start with 4KB
	NTSTATUS status;
	int count = 0;

	pNtEnumEnvValuesEx = (PFN_NtEnumerateSystemEnvironmentValuesEx)
		GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtEnumerateSystemEnvironmentValuesEx");

	if (pNtEnumEnvValuesEx == NULL) {
		wprintf(L"Failed to get NtEnumerateSystemEnvironmentValuesEx\n");
		return ST_ERROR;
	}

	buffer = malloc(bufferLength);
	if (buffer == NULL) {
		return ST_NOMEM;
	}

	// Call with increasing buffer size until it fits
	while ((status = pNtEnumEnvValuesEx(SystemEnvironmentNameInformation, buffer, &bufferLength)) == 0x80000005L /*STATUS_BUFFER_OVERFLOW*/
		|| status == (NTSTATUS)0xC0000023L /*STATUS_BUFFER_TOO_SMALL*/) {
		free(buffer);
		buffer = malloc(bufferLength);
		if (buffer == NULL) {
			return ST_NOMEM;
		}
	}

	if (status < 0) {
		wprintf(L"Failed to enumerate EFI variables: 0x%08X\n", status);
		free(buffer);
		return ST_ERROR;
	}

	wprintf(L"EFI Variables:\n");
	wprintf(L"--------------------------------------------------------------------------------\n");
	wprintf(L"%-40s %s\n", L"Name", L"GUID");
	wprintf(L"--------------------------------------------------------------------------------\n");

	PVARIABLE_NAME varName = (PVARIABLE_NAME)buffer;
	while (varName != NULL) {
		wprintf(L"%-40s {%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}\n",
			varName->Name,
			varName->VendorGuid.Data1,
			varName->VendorGuid.Data2,
			varName->VendorGuid.Data3,
			varName->VendorGuid.Data4[0], varName->VendorGuid.Data4[1],
			varName->VendorGuid.Data4[2], varName->VendorGuid.Data4[3],
			varName->VendorGuid.Data4[4], varName->VendorGuid.Data4[5],
			varName->VendorGuid.Data4[6], varName->VendorGuid.Data4[7]);
		count++;

		if (varName->NextEntryOffset == 0)
			break;
		varName = (PVARIABLE_NAME)((PCHAR)varName + varName->NextEntryOffset);
	}

	wprintf(L"--------------------------------------------------------------------------------\n");
	wprintf(L"Total: %d variables\n", count);

	free(buffer);
	return ST_OK;
}

static int efi_cmd_get(int argc, wchar_t *argv[])
{
	int      resl = ST_OK;
	wchar_t *var_name = argv[3];
	wchar_t *var_guid = get_param(L"-guid");
	wchar_t *file_path = get_param(L"-file");
	int      dmp_hex = is_param(L"-dmp_hex");
	BYTE    *buffer = NULL;
	DWORD    buf_size = 4096;
	DWORD    var_len;

	if (var_guid == NULL) {
		var_guid = (wchar_t*)efi_var_guid;
	}

	// Dynamically allocate buffer, growing as needed
	buffer = malloc(buf_size);
	if (buffer == NULL) {
		return ST_NOMEM;
	}

	while ((var_len = GetFirmwareEnvironmentVariableW(var_name, var_guid, buffer, buf_size)) == 0) {
		DWORD err = GetLastError();
		if (err == ERROR_INSUFFICIENT_BUFFER) {
			// Double buffer size and retry
			buf_size *= 2;
			free(buffer);
			buffer = malloc(buf_size);
			if (buffer == NULL) {
				resl = ST_NOMEM; break;
			}
		} else if (err == ERROR_ENVVAR_NOT_FOUND) {
			wprintf(L"Variable '%s' not found\n", var_name);
			free(buffer);
			resl = ST_NF_FILE; break;
		} else {
			wprintf(L"Error reading variable '%s': %d (0x%08X)\n", var_name, err, err);
			free(buffer);
			resl = ST_ERROR; break;
		}
	}

	if (resl != ST_OK) {
		return resl;
	}

	if (file_path != NULL) {
		// Save to file
		resl = save_file(file_path, buffer, var_len);
		if (resl == ST_OK) {
			wprintf(L"Variable '%s' (%d bytes) saved to: %s\n", var_name, var_len, file_path);
		} else {
			wprintf(L"Error saving variable to file\n");
		}
	} else if (dmp_hex) {
		// Hex dump to screen
		wprintf(L"Variable '%s' (%d bytes):\n", var_name, var_len);
		print_hex_dump(buffer, var_len);
	} else {
		// Print as text to screen
		wprintf(L"Variable '%s' (%d bytes):\n", var_name, var_len);
		// Check if printable, otherwise show hex
		int printable = 1;
		for (DWORD i = 0; i < var_len; i++) {
			if (buffer[i] < 0x20 && buffer[i] != '\r' && buffer[i] != '\n' && buffer[i] != '\t' && buffer[i] != 0) {
				printable = 0;
				break;
			}
		}
		if (printable && var_len > 0) {
			// Try to print as string (could be ASCII or UTF-16)
			if (var_len >= 2 && buffer[1] == 0) {
				// Likely UTF-16
				wprintf(L"%s\n", (wchar_t*)buffer);
			} else {
				// ASCII
				printf("%.*s\n", var_len, buffer);
			}
		} else {
			// Binary data - show hex dump
			print_hex_dump(buffer, var_len);
		}
	}
	free(buffer);

	return resl;
}

static int efi_cmd_set(int argc, wchar_t *argv[])
{
	int      resl = ST_OK;
	wchar_t *var_name = argv[3];
	wchar_t *var_guid = get_param(L"-guid");
	wchar_t *file_path = get_param(L"-file");
	wchar_t *data_str = get_param(L"-data");
	BYTE    *buffer = NULL;
	DWORD    var_len = 0;

	if (var_guid == NULL) {
		var_guid = (wchar_t*)efi_var_guid;
	}

	if (file_path != NULL) {
		// Load from file
		u32 file_size;
		resl = load_file(file_path, &buffer, &file_size);
		if (resl != ST_OK) {
			wprintf(L"Error loading file: %s\n", file_path);
			return resl;
		}
		var_len = file_size;
	} else if (data_str != NULL) {
		// Use command line data (convert from wide to ASCII)
		var_len = (DWORD)wcslen(data_str);
		buffer = malloc(var_len + 1);
		if (buffer == NULL) {
			return ST_NOMEM;
		}
		for (DWORD i = 0; i <= var_len; i++) {
			buffer[i] = (BYTE)data_str[i];
		}
	} else {
		wprintf(L"Error: specify -file <path> or -data <string>\n");
		return ST_INVALID_PARAM;
	}

	if (!SetFirmwareEnvironmentVariableW(var_name, var_guid, buffer, var_len)) {
		DWORD err = GetLastError();
		wprintf(L"Error setting variable '%s': %d\n", var_name, err);
		resl = ST_ERROR;
	} else {
		wprintf(L"Variable '%s' set successfully (%d bytes)\n", var_name, var_len);
	}

	if (buffer != NULL) {
		my_free(buffer);
	}

	return resl;
}

static int efi_cmd_del(int argc, wchar_t *argv[])
{
	int      resl = ST_OK;
	wchar_t *var_name = argv[3];
	wchar_t *var_guid = get_param(L"-guid");

	if (var_guid == NULL) {
		var_guid = (wchar_t*)efi_var_guid;
	}

	// Delete variable by setting it with NULL buffer and 0 size
	if (!SetFirmwareEnvironmentVariableW(var_name, var_guid, NULL, 0)) {
		DWORD err = GetLastError();
		if (err == ERROR_ENVVAR_NOT_FOUND) {
			wprintf(L"Variable '%s' not found\n", var_name);
			resl = ST_NF_FILE;
		} else {
			wprintf(L"Error deleting variable '%s': %d (0x%08X)\n", var_name, err, err);
			resl = ST_ERROR;
		}
	} else {
		wprintf(L"Variable '%s' deleted successfully\n", var_name);
	}

	return resl;
}

static int efi_cmd_dump(int argc, wchar_t *argv[])
{
	int      resl;
	wchar_t *file_path = get_param(L"-file");
	BYTE    *var_data = NULL;
	DWORD    var_size = 0;
	int      entry_num = 0;

	if (file_path == NULL) {
		wprintf(L"Error: specify -file <path>\n");
		return ST_INVALID_PARAM; 
	}

	// Load from file
	u32 file_size;
	resl = load_file(file_path, &var_data, &file_size);
	if (resl != ST_OK) {
		wprintf(L"Error loading file: %s\n", file_path);
		return resl;
	}
	var_size = file_size;

	wprintf(L"Dumping signatures from: %s\n\n", file_path);

	// Parse the EFI signature database
	DWORD offset = 0;
	while (offset + 28 <= var_size) {
		GUID* sigType = (GUID*)(var_data + offset);
		DWORD sigListSize = *(DWORD*)(var_data + offset + 16);
		DWORD sigHeaderSize = *(DWORD*)(var_data + offset + 20);
		DWORD sigSize = *(DWORD*)(var_data + offset + 24);

		if (sigListSize == 0 || sigListSize > var_size - offset || sigListSize < 28) {
			break;
		}

		// Determine signature type
		int is_cert = 0;
		int hash_size = 0;
		const wchar_t* type_name = NULL;

		if (sigType->Data1 == 0xa5c059a1 && sigType->Data2 == 0x94e4 && sigType->Data3 == 0x4aa7) {
			is_cert = 1; type_name = L"X.509";
		}
		else if (sigType->Data1 == 0xc1c41626 && sigType->Data2 == 0x504c && sigType->Data3 == 0x4092) {
			hash_size = 32; type_name = L"SHA-256";
		}
		else if (sigType->Data1 == 0x826ca512 && sigType->Data2 == 0xcf10 && sigType->Data3 == 0x4ac9) {
			hash_size = 20; type_name = L"SHA-1";
		}
		else if (sigType->Data1 == 0x3c5766a8 && sigType->Data2 == 0x1a4c && sigType->Data3 == 0x4a99) {
			hash_size = 256; type_name = L"RSA-2048";
		}
		else if (sigType->Data1 == 0x3bd2a492 && sigType->Data2 == 0x96c0 && sigType->Data3 == 0x4079) {
			hash_size = 32; type_name = L"X509+SHA256"; // ToBeSignedHash
		}
		else if (sigType->Data1 == 0x7076876e && sigType->Data2 == 0x80c2 && sigType->Data3 == 0x4ee6) {
			hash_size = 48; type_name = L"X509+SHA384";
		}
		else if (sigType->Data1 == 0x446dbf63 && sigType->Data2 == 0x2502 && sigType->Data3 == 0x4cda) {
			hash_size = 64; type_name = L"X509+SHA512";
		}
		else {
			// Unknown - skip
			offset += sigListSize;
			continue;
		}

		// Calculate number of signatures
		DWORD sigDataSize = sigListSize - 28 - sigHeaderSize;
		if (sigSize == 0 || sigSize <= 16 || sigDataSize % sigSize != 0) {
			offset += sigListSize;
			continue;
		}

		DWORD numSigs = sigDataSize / sigSize;
		DWORD sigOffset = offset + 28 + sigHeaderSize;

		for (DWORD i = 0; i < numSigs && sigOffset + sigSize <= var_size; i++) {
			BYTE* dataPtr = var_data + sigOffset + 16; // Skip owner GUID
			DWORD dataSize = sigSize - 16;

			if (is_cert) {
				// Parse X.509 certificate to extract CN
				PCCERT_CONTEXT pCert = CertCreateCertificateContext(
					X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
					dataPtr, dataSize);

				if (pCert != NULL) {
					char cn[256] = {0};
					// Get subject name
					CertGetNameStringA(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
						0, NULL, cn, sizeof(cn));

					// Print in list_signer format: name + hash preview
					// Compute SHA-1 of cert for hash preview
					BYTE hash[20];
					DWORD hashSize = sizeof(hash);
					if (CryptHashCertificate(0, CALG_SHA1, 0,
						pCert->pbCertEncoded, pCert->cbCertEncoded,
						hash, &hashSize)) {
						printf("%-64s%02X%02X%02X%02X...%02X%02X\n", cn,
							hash[0], hash[1], hash[2], hash[3],
							hash[18], hash[19]);
					} else {
						printf("%s\n", cn);
					}
					CertFreeCertificateContext(pCert);
				} else {
					wprintf(L"[%d] %s: <invalid certificate>\n", entry_num, type_name);
				}
			} else {
				// Print hash - full hash value
				wprintf(L"[%s] ", type_name);
				for (DWORD h = 0; h < dataSize && h < (DWORD)hash_size; h++) {
					wprintf(L"%02X", dataPtr[h]);
				}
				wprintf(L"\n");
			}

			entry_num++;
			sigOffset += sigSize;
		}

		offset += sigListSize;
	}

	wprintf(L"\nTotal: %d entries\n", entry_num);

	if (var_data != NULL) {
		my_free(var_data);
	}
	
	return ST_OK;
}

static int efi_cmd_extract(int argc, wchar_t *argv[])
{

	int      resl;
	wchar_t *file_path = get_param(L"-file");
	wchar_t *dir_path = get_param(L"-dir");
	wchar_t *var_guid = get_param(L"-guid");
	BYTE    *var_data = NULL;
	DWORD    var_size = 0;
	DWORD    buf_size = 4096;
	int      entry_num = 0;

	if (file_path == NULL && dir_path == NULL) {
		wprintf(L"Error: specify -file <path> for input and -dir <path> for output\n");
		return ST_INVALID_PARAM;
	}

	if (dir_path == NULL) {
		wprintf(L"Error: specify -dir <path> for output directory\n");
		return ST_INVALID_PARAM;
	}

	// Create output directory if it doesn't exist
	CreateDirectoryW(dir_path, NULL);

	if (file_path != NULL) {
		// Load from file
		u32 file_size;
		resl = load_file(file_path, &var_data, &file_size);
		if (resl != ST_OK) {
			wprintf(L"Error loading file: %s\n", file_path);
			return resl;
		}
		var_size = file_size;
	} else {
		wprintf(L"Error: specify -file <path> for input file\n");
		return ST_INVALID_PARAM;
	}

	wprintf(L"Extracting signatures from: %s\n", file_path);
	wprintf(L"Output directory: %s\n\n", dir_path);

	// Parse the EFI signature database manually
	// Filename format: LLL_NNN_{GUID}.ext
	// LLL = list number, NNN = sig number within list, GUID = owner GUID
	DWORD offset = 0;
	int list_num = 0;
	while (offset + 28 <= var_size) { // sizeof(EFI_SIGNATURE_LIST) = 28
		// EFI_SIGNATURE_LIST structure
		GUID* sigType = (GUID*)(var_data + offset);
		DWORD sigListSize = *(DWORD*)(var_data + offset + 16);
		DWORD sigHeaderSize = *(DWORD*)(var_data + offset + 20);
		DWORD sigSize = *(DWORD*)(var_data + offset + 24);

		if (sigListSize == 0 || sigListSize > var_size - offset || sigListSize < 28) {
			break;
		}

		// Determine signature type and extension
		const wchar_t* ext = NULL;
		const wchar_t* type_name = NULL;

		// Check signature type GUIDs
		// EFI_CERT_X509_GUID = {a5c059a1-94e4-4aa7-87b5-ab155c2bf072}
		if (sigType->Data1 == 0xa5c059a1 && sigType->Data2 == 0x94e4 && sigType->Data3 == 0x4aa7) {
			ext = L".der"; type_name = L"X.509 Certificate";
		}
		// EFI_CERT_SHA256_GUID = {c1c41626-504c-4092-aca9-41f936934328}
		else if (sigType->Data1 == 0xc1c41626 && sigType->Data2 == 0x504c && sigType->Data3 == 0x4092) {
			ext = L".sha256"; type_name = L"SHA-256 Hash";
		}
		// EFI_CERT_SHA1_GUID = {826ca512-cf10-4ac9-b187-be01496631bd}
		else if (sigType->Data1 == 0x826ca512 && sigType->Data2 == 0xcf10 && sigType->Data3 == 0x4ac9) {
			ext = L".sha1"; type_name = L"SHA-1 Hash";
		}
		// EFI_CERT_RSA2048_GUID = {3c5766a8-1a4c-4a99-adb8-957f2cf94f0b}
		else if (sigType->Data1 == 0x3c5766a8 && sigType->Data2 == 0x1a4c && sigType->Data3 == 0x4a99) {
			ext = L".rsa2048"; type_name = L"RSA-2048 Key";
		}
		// EFI_CERT_RSA2048_SHA256_GUID = {e8663db0-69b0-4e30-a6c1-c83b3ab91f7e}
		else if (sigType->Data1 == 0xe8663db0 && sigType->Data2 == 0x69b0 && sigType->Data3 == 0x4e30) {
			ext = L".rsa2048sha256"; type_name = L"RSA-2048 + SHA-256";
		}
		// EFI_CERT_RSA2048_SHA1_GUID = {67f8444f-8743-48f1-a328-1eaab8736080}
		else if (sigType->Data1 == 0x67f8444f && sigType->Data2 == 0x8743 && sigType->Data3 == 0x48f1) {
			ext = L".rsa2048sha1"; type_name = L"RSA-2048 + SHA-1";
		}
		// EFI_CERT_X509_SHA256_GUID = {3bd2a492-96c0-4079-b420-fcf98ef103ed}
		else if (sigType->Data1 == 0x3bd2a492 && sigType->Data2 == 0x96c0 && sigType->Data3 == 0x4079) {
			ext = L".x509sha256"; type_name = L"X.509 + SHA-256";
		}
		// EFI_CERT_X509_SHA384_GUID = {7076876e-80c2-4ee6-aad2-28b349a6865b}
		else if (sigType->Data1 == 0x7076876e && sigType->Data2 == 0x80c2 && sigType->Data3 == 0x4ee6) {
			ext = L".x509sha384"; type_name = L"X.509 + SHA-384";
		}
		// EFI_CERT_X509_SHA512_GUID = {446dbf63-2502-4cda-bcfa-2465d2b0fe9d}
		else if (sigType->Data1 == 0x446dbf63 && sigType->Data2 == 0x2502 && sigType->Data3 == 0x4cda) {
			ext = L".x509sha512"; type_name = L"X.509 + SHA-512";
		}
		else {
			// Unknown signature type - skip (likely padding/garbage)
			wprintf(L"  Skipping unknown signature type {%08x-%04x-%04x-...} at offset %d\n",
				sigType->Data1, sigType->Data2, sigType->Data3, offset);
			offset += sigListSize;
			continue;
		}

		// Calculate number of signatures
		DWORD sigDataSize = sigListSize - 28 - sigHeaderSize;
		if (sigSize == 0 || sigDataSize % sigSize != 0) {
			offset += sigListSize;
			list_num++;
			continue;
		}

		DWORD numSigs = sigDataSize / sigSize;
		DWORD sigOffset = offset + 28 + sigHeaderSize;

		for (DWORD i = 0; i < numSigs && sigOffset + sigSize <= var_size; i++) {
			// Get SignatureOwner GUID (first 16 bytes)
			GUID* ownerGuid = (GUID*)(var_data + sigOffset);
			BYTE* dataPtr = var_data + sigOffset + 16;
			DWORD dataSize = sigSize - 16;

			// Generate output filename: LLL_NNN_{GUID}.ext
			wchar_t out_path[MAX_PATH];
			_snwprintf(out_path, MAX_PATH,
				L"%s\\%03d_%03d_{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}%s",
				dir_path, list_num, i,
				ownerGuid->Data1, ownerGuid->Data2, ownerGuid->Data3,
				ownerGuid->Data4[0], ownerGuid->Data4[1],
				ownerGuid->Data4[2], ownerGuid->Data4[3],
				ownerGuid->Data4[4], ownerGuid->Data4[5],
				ownerGuid->Data4[6], ownerGuid->Data4[7],
				ext);

			// Save to file
			if (save_file(out_path, dataPtr, dataSize) == ST_OK) {
				wprintf(L"  [%03d_%03d] %s (%d bytes)\n", list_num, i, type_name, dataSize);
			} else {
				wprintf(L"  [%03d_%03d] Error saving file\n", list_num, i);
			}

			entry_num++;
			sigOffset += sigSize;
		}
		list_num++;

		offset += sigListSize;
	}

	wprintf(L"\nExtracted %d entries\n", entry_num);

	if (var_data != NULL) {
		my_free(var_data);
	}

	return ST_OK;
}

static int efi_cmd_pack(int argc, wchar_t *argv[])
{

	int      resl = ST_OK;
	wchar_t *dir_path = get_param(L"-dir");
	wchar_t *file_path = get_param(L"-file");
	WIN32_FIND_DATAW findData;
	HANDLE	 hFind;
	wchar_t  searchPath[MAX_PATH];
	wchar_t  filePath[MAX_PATH];
	BYTE *   outBuffer = NULL;
	DWORD    outSize = 0;
	DWORD    outCapacity = 65536;
	int      entry_num = 0;

	// Signature type GUIDs
	static const GUID CERT_X509_GUID =
	{ 0xa5c059a1, 0x94e4, 0x4aa7, { 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72 } };
	static const GUID CERT_SHA256_GUID =
	{ 0xc1c41626, 0x504c, 0x4092, { 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28 } };
	static const GUID CERT_SHA1_GUID =
	{ 0x826ca512, 0xcf10, 0x4ac9, { 0xb1, 0x87, 0xbe, 0x01, 0x49, 0x66, 0x31, 0xbd } };
	static const GUID CERT_RSA2048_GUID =
	{ 0x3c5766a8, 0x1a4c, 0x4a99, { 0xad, 0xb8, 0x95, 0x7f, 0x2c, 0xf9, 0x4f, 0x0b } };
	static const GUID CERT_RSA2048_SHA256_GUID =
	{ 0xe8663db0, 0x69b0, 0x4e30, { 0xa6, 0xc1, 0xc8, 0x3b, 0x3a, 0xb9, 0x1f, 0x7e } };
	static const GUID CERT_RSA2048_SHA1_GUID =
	{ 0x67f8444f, 0x8743, 0x48f1, { 0xa3, 0x28, 0x1e, 0xaa, 0xb8, 0x73, 0x60, 0x80 } };
	static const GUID CERT_X509_SHA256_GUID =
	{ 0x3bd2a492, 0x96c0, 0x4079, { 0xb4, 0x20, 0xfc, 0xf9, 0x8e, 0xf1, 0x03, 0xed } };
	static const GUID CERT_X509_SHA384_GUID =
	{ 0x7076876e, 0x80c2, 0x4ee6, { 0xaa, 0xd2, 0x28, 0xb3, 0x49, 0xa6, 0x86, 0x5b } };
	static const GUID CERT_X509_SHA512_GUID =
	{ 0x446dbf63, 0x2502, 0x4cda, { 0xbc, 0xfa, 0x24, 0x65, 0xd2, 0xb0, 0xfe, 0x9d } };
	// Default owner GUID (Microsoft) - used only if filename doesn't contain GUID
	static const GUID DEFAULT_OWNER =
	{ 0x77fa9abd, 0x0359, 0x4d32, { 0xbd, 0x60, 0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b } };

	// Structure to hold file info for grouping
	typedef struct {
		int listNum;
		int sigNum;
		GUID ownerGuid;
		const GUID *sigType;
		const wchar_t *typeName;
		BYTE *data;
		DWORD dataSize;
		wchar_t fileName[MAX_PATH];
	} SIG_FILE_INFO;

#define MAX_SIG_FILES 1024
	SIG_FILE_INFO *sigFiles = NULL;
	int sigFileCount = 0;

	if (dir_path == NULL || file_path == NULL) {
		wprintf(L"Error: specify -dir <path> for input directory and -file <path> for output\n");
		return ST_INVALID_PARAM;
	}

	sigFiles = (SIG_FILE_INFO*)calloc(MAX_SIG_FILES, sizeof(SIG_FILE_INFO));
	if (sigFiles == NULL) {
		return ST_NOMEM;
	}

	wprintf(L"Packing signatures from: %s\n", dir_path);
	wprintf(L"Output file: %s\n\n", file_path);

	// First pass: collect all signature files
	_snwprintf(searchPath, MAX_PATH, L"%s\\*.*", dir_path);
	hFind = FindFirstFileW(searchPath, &findData);

	if (hFind == INVALID_HANDLE_VALUE) {
		wprintf(L"Error: cannot open directory %s\n", dir_path);
		free(sigFiles);
		return ST_NF_FILE;
	}

	do {
		if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			continue;
		if (sigFileCount >= MAX_SIG_FILES) {
			wprintf(L"Warning: too many files, limit is %d\n", MAX_SIG_FILES);
			break;
		}

		// Determine signature type from extension
		wchar_t *ext = wcsrchr(findData.cFileName, L'.');
		if (ext == NULL) continue;

		const GUID *sigType = NULL;
		const wchar_t *typeName = NULL;

		if (_wcsicmp(ext, L".der") == 0) {
			sigType = &CERT_X509_GUID; typeName = L"X.509";
		} else if (_wcsicmp(ext, L".sha256") == 0) {
			sigType = &CERT_SHA256_GUID; typeName = L"SHA-256";
		} else if (_wcsicmp(ext, L".sha1") == 0) {
			sigType = &CERT_SHA1_GUID; typeName = L"SHA-1";
		} else if (_wcsicmp(ext, L".rsa2048") == 0) {
			sigType = &CERT_RSA2048_GUID; typeName = L"RSA-2048";
		} else if (_wcsicmp(ext, L".rsa2048sha256") == 0) {
			sigType = &CERT_RSA2048_SHA256_GUID; typeName = L"RSA-2048+SHA256";
		} else if (_wcsicmp(ext, L".rsa2048sha1") == 0) {
			sigType = &CERT_RSA2048_SHA1_GUID; typeName = L"RSA-2048+SHA1";
		} else if (_wcsicmp(ext, L".x509sha256") == 0) {
			sigType = &CERT_X509_SHA256_GUID; typeName = L"X509+SHA256";
		} else if (_wcsicmp(ext, L".x509sha384") == 0) {
			sigType = &CERT_X509_SHA384_GUID; typeName = L"X509+SHA384";
		} else if (_wcsicmp(ext, L".x509sha512") == 0) {
			sigType = &CERT_X509_SHA512_GUID; typeName = L"X509+SHA512";
		} else {
			continue; // Skip unknown extensions
		}

		// Parse filename format: LLL_NNN_{GUID}.ext
		// Try to extract list number and owner GUID
		SIG_FILE_INFO *info = &sigFiles[sigFileCount];
		info->listNum = -1; // Default: no list grouping
		info->sigNum = 0;
		info->ownerGuid = DEFAULT_OWNER;
		info->sigType = sigType;
		info->typeName = typeName;
		wcscpy_s(info->fileName, MAX_PATH, findData.cFileName);

		// Try parsing: LLL_NNN_{GUID}.ext
		int listNum, sigNum;
		DWORD g1; WORD g2, g3;
		BYTE g4[8];
		if (swscanf_s(findData.cFileName, L"%d_%d_{%08x-%04hx-%04hx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx}",
			&listNum, &sigNum,
			&g1, &g2, &g3, &g4[0], &g4[1], &g4[2], &g4[3], &g4[4], &g4[5], &g4[6], &g4[7]) == 13) {
			info->listNum = listNum;
			info->sigNum = sigNum;
			info->ownerGuid.Data1 = g1;
			info->ownerGuid.Data2 = g2;
			info->ownerGuid.Data3 = g3;
			memcpy(info->ownerGuid.Data4, g4, 8);
		}

		// Load file
		_snwprintf(filePath, MAX_PATH, L"%s\\%s", dir_path, findData.cFileName);
		HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			wprintf(L"  Warning: cannot open %s\n", findData.cFileName);
			continue;
		}

		DWORD fileSize = GetFileSize(hFile, NULL);
		info->data = (BYTE*)malloc(fileSize);
		if (info->data == NULL) {
			CloseHandle(hFile);
			continue;
		}

		DWORD bytesRead;
		if (!ReadFile(hFile, info->data, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
			free(info->data);
			info->data = NULL;
			CloseHandle(hFile);
			continue;
		}
		CloseHandle(hFile);
		info->dataSize = fileSize;
		sigFileCount++;

	} while (FindNextFileW(hFind, &findData));

	FindClose(hFind);

	if (sigFileCount == 0) {
		wprintf(L"\nNo signature files found\n");
		free(sigFiles);
		return ST_NF_FILE;
	}

	// Sort files by listNum, then sigNum for proper grouping
	for (int i = 0; i < sigFileCount - 1; i++) {
		for (int j = i + 1; j < sigFileCount; j++) {
			int swap = 0;
			if (sigFiles[i].listNum > sigFiles[j].listNum) {
				swap = 1;
			} else if (sigFiles[i].listNum == sigFiles[j].listNum) {
				if (sigFiles[i].sigNum > sigFiles[j].sigNum) {
					swap = 1;
				}
			}
			if (swap) {
				SIG_FILE_INFO tmp = sigFiles[i];
				sigFiles[i] = sigFiles[j];
				sigFiles[j] = tmp;
			}
		}
	}

	// Allocate output buffer
	outBuffer = (BYTE*)malloc(outCapacity);
	if (outBuffer == NULL) {
		for (int i = 0; i < sigFileCount; i++) {
			if (sigFiles[i].data) free(sigFiles[i].data);
		}
		free(sigFiles);
		return ST_NOMEM;
	}

	// Group files by (listNum, sigType) and create signature lists
	int i = 0;
	while (i < sigFileCount) {
		int listNum = sigFiles[i].listNum;
		const GUID *sigType = sigFiles[i].sigType;
		const wchar_t *typeName = sigFiles[i].typeName;

		// Find all files in this group (same listNum and sigType)
		int groupStart = i;
		int groupEnd = i;
		DWORD maxDataSize = sigFiles[i].dataSize;

		while (groupEnd < sigFileCount &&
			sigFiles[groupEnd].listNum == listNum &&
			memcmp(sigFiles[groupEnd].sigType, sigType, sizeof(GUID)) == 0) {
			if (sigFiles[groupEnd].dataSize > maxDataSize)
				maxDataSize = sigFiles[groupEnd].dataSize;
			groupEnd++;
		}

		int numSigs = groupEnd - groupStart;

		// For X.509 certs, each can have different size - need separate lists
		// For hashes (SHA-256, etc.), all same size - can group
		int canGroup = 1;
		if (memcmp(sigType, &CERT_X509_GUID, sizeof(GUID)) == 0) {
			// Check if all X.509 certs are same size
			for (int j = groupStart; j < groupEnd; j++) {
				if (sigFiles[j].dataSize != sigFiles[groupStart].dataSize) {
					canGroup = 0;
					break;
				}
			}
		}

		if (canGroup && numSigs > 0) {
			// Create single list with multiple signatures
			DWORD sigDataSize = sigFiles[groupStart].dataSize;
			DWORD sigSize = 16 + sigDataSize; // Owner GUID + data
			DWORD sigListSize = 28 + (sigSize * numSigs);

			// Ensure buffer capacity
			while (outSize + sigListSize > outCapacity) {
				outCapacity *= 2;
				BYTE *newBuf = (BYTE*)realloc(outBuffer, outCapacity);
				if (newBuf == NULL) {
					wprintf(L"Error: out of memory\n");
					goto pack_cleanup;
				}
				outBuffer = newBuf;
			}

			// Write EFI_SIGNATURE_LIST header
			BYTE *p = outBuffer + outSize;
			memcpy(p, sigType, 16);           // SignatureType GUID
			*(DWORD*)(p + 16) = sigListSize;  // SignatureListSize
			*(DWORD*)(p + 20) = 0;            // SignatureHeaderSize
			*(DWORD*)(p + 24) = sigSize;      // SignatureSize
			p += 28;

			// Write all signatures
			for (int j = groupStart; j < groupEnd; j++) {
				memcpy(p, &sigFiles[j].ownerGuid, 16); // SignatureOwner GUID
				memcpy(p + 16, sigFiles[j].data, sigFiles[j].dataSize);
				wprintf(L"  [%03d_%03d] %s (%d bytes) <- %s\n",
					sigFiles[j].listNum, sigFiles[j].sigNum, typeName,
					sigFiles[j].dataSize, sigFiles[j].fileName);
				p += sigSize;
				entry_num++;
			}

			outSize += sigListSize;
		} else {
			// Create separate list for each signature (different sizes)
			for (int j = groupStart; j < groupEnd; j++) {
				DWORD sigSize = 16 + sigFiles[j].dataSize;
				DWORD sigListSize = 28 + sigSize;

				// Ensure buffer capacity
				while (outSize + sigListSize > outCapacity) {
					outCapacity *= 2;
					BYTE *newBuf = (BYTE*)realloc(outBuffer, outCapacity);
					if (newBuf == NULL) {
						wprintf(L"Error: out of memory\n");
						goto pack_cleanup;
					}
					outBuffer = newBuf;
				}

				BYTE *p = outBuffer + outSize;
				memcpy(p, sigType, 16);
				*(DWORD*)(p + 16) = sigListSize;
				*(DWORD*)(p + 20) = 0;
				*(DWORD*)(p + 24) = sigSize;

				memcpy(p + 28, &sigFiles[j].ownerGuid, 16);
				memcpy(p + 28 + 16, sigFiles[j].data, sigFiles[j].dataSize);

				wprintf(L"  [%03d_%03d] %s (%d bytes) <- %s\n",
					sigFiles[j].listNum, sigFiles[j].sigNum, typeName,
					sigFiles[j].dataSize, sigFiles[j].fileName);

				outSize += sigListSize;
				entry_num++;
			}
		}

		i = groupEnd;
	}

	if (entry_num > 0) {
		// Save output file
		resl = save_file(file_path, outBuffer, outSize);
		if (resl == ST_OK) {
			wprintf(L"\nPacked %d entries (%d bytes) to: %s\n", entry_num, outSize, file_path);
		} else {
			wprintf(L"\nError saving output file\n");
		}
	}

pack_cleanup:
	for (int k = 0; k < sigFileCount; k++) {
		if (sigFiles[k].data) free(sigFiles[k].data);
	}
	free(sigFiles);
	if (outBuffer) free(outBuffer);
	
	return resl;
}

static int efi_cmd_sb_set(int argc, wchar_t *argv[])
{
	int      resl = ST_OK;
	wchar_t *var_name = get_param(L"-name");
	wchar_t *var_guid_str = get_param(L"-guid");
	wchar_t *content_path = get_param(L"-file");
	wchar_t *cert_path = get_param(L"-cert");
	wchar_t *pass_str = get_param(L"-pass");
	int append_mode = is_param(L"-append");

	BYTE *content = NULL;
	u32 content_size = 0;
	HCERTSTORE hStore = NULL;
	PCCERT_CONTEXT pCert = NULL;
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey = 0;
	DWORD keySpec = 0;
	BOOL freeKey = FALSE;
	CRYPT_DATA_BLOB pfxBlob = {0};
	BYTE *authVar = NULL;
	DWORD authVarSize = 0;

	// EFI variable attributes for authenticated variables
#define EFI_VARIABLE_NON_VOLATILE                          0x00000001
#define EFI_VARIABLE_BOOTSERVICE_ACCESS                    0x00000002
#define EFI_VARIABLE_RUNTIME_ACCESS                        0x00000004
#define EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS 0x00000020
#define EFI_VARIABLE_APPEND_WRITE                          0x00000040

	// Secure Boot variable GUIDs
	// EFI_GLOBAL_VARIABLE: used for PK, KEK
	static const wchar_t* EFI_GLOBAL_VAR_GUID = L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";
	// EFI_IMAGE_SECURITY_DATABASE_GUID: used for db, dbx, dbt, dbr
	static const wchar_t* EFI_SECURITY_DB_GUID = L"{D719B2CB-3D3A-4596-A3BC-DAD00E67656F}";

	if (var_name == NULL) {
		wprintf(L"Error: specify -name <variable_name> (e.g., PK, KEK, db, dbx)\n");
		return ST_INVALID_PARAM;
	}

	if (content_path == NULL) {
		wprintf(L"Error: specify -file <content_path>\n");
		return ST_INVALID_PARAM;
	}

	if (cert_path == NULL) {
		wprintf(L"Error: specify -cert <pfx_path>\n");
		return ST_INVALID_PARAM;
	}

	// Auto-select GUID based on variable name if not specified
	if (var_guid_str == NULL) {
		if (_wcsicmp(var_name, L"PK") == 0 || _wcsicmp(var_name, L"KEK") == 0) {
			// PK and KEK use EFI Global Variable GUID
			var_guid_str = (wchar_t*)EFI_GLOBAL_VAR_GUID;
			wprintf(L"Using EFI Global Variable GUID for %s\n", var_name);
		} else if (_wcsicmp(var_name, L"db") == 0 || _wcsicmp(var_name, L"dbx") == 0 ||
			_wcsicmp(var_name, L"dbt") == 0 || _wcsicmp(var_name, L"dbr") == 0) {
			// db, dbx, dbt, dbr use EFI Image Security Database GUID
			var_guid_str = (wchar_t*)EFI_SECURITY_DB_GUID;
			wprintf(L"Using EFI Image Security Database GUID for %s\n", var_name);
		} else {
			wprintf(L"Error: unknown Secure Boot variable '%s'\n", var_name);
			wprintf(L"Known variables: PK, KEK, db, dbx, dbt, dbr\n");
			wprintf(L"For other variables, specify -guid manually\n");
			return ST_INVALID_PARAM;
		}
	}

	// Parse GUID from string
	GUID varGuid = {0};
	if (swscanf_s(var_guid_str, L"{%08X-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
		&varGuid.Data1, &varGuid.Data2, &varGuid.Data3,
		&varGuid.Data4[0], &varGuid.Data4[1], &varGuid.Data4[2], &varGuid.Data4[3],
		&varGuid.Data4[4], &varGuid.Data4[5], &varGuid.Data4[6], &varGuid.Data4[7]) != 11) {
		wprintf(L"Error: invalid GUID format\n");
		return ST_INVALID_PARAM;
	}

	// Load content file
	resl = load_file(content_path, &content, &content_size);
	if (resl != ST_OK) {
		wprintf(L"Error loading content file: %s\n", content_path);
		return resl;
	}

	// Load PFX file
	HANDLE hPfxFile = CreateFileW(cert_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hPfxFile == INVALID_HANDLE_VALUE) {
		wprintf(L"Error opening certificate file: %s\n", cert_path);
		my_free(content);
		return ST_NF_FILE;
	}

	pfxBlob.cbData = GetFileSize(hPfxFile, NULL);
	pfxBlob.pbData = (BYTE*)malloc(pfxBlob.cbData);
	if (pfxBlob.pbData == NULL) {
		CloseHandle(hPfxFile);
		my_free(content);
		return ST_NOMEM;
	}

	DWORD bytesRead;
	ReadFile(hPfxFile, pfxBlob.pbData, pfxBlob.cbData, &bytesRead, NULL);
	CloseHandle(hPfxFile);

	// Get password if needed
	wchar_t password[256] = {0};
	if (pass_str != NULL) {
		wcscpy_s(password, _countof(password), pass_str);
	} else if (!PFXIsPFXBlob(&pfxBlob) || PFXVerifyPassword(&pfxBlob, L"", 0) == FALSE) {
		wprintf(L"Enter PFX password: ");
		// Read password (simple implementation)
		int i = 0;
		wint_t ch;
		while ((ch = _getwch()) != L'\r' && ch != L'\n' && i < 255) {
			if (ch == 8 && i > 0) { // Backspace
				i--;
				wprintf(L"\b \b");
			} else if (ch >= 32) {
				password[i++] = (wchar_t)ch;
				wprintf(L"*");
			}
		}
		password[i] = 0;
		wprintf(L"\n");
	}

	// Import PFX
	hStore = PFXImportCertStore(&pfxBlob, password, CRYPT_EXPORTABLE | PKCS12_ALLOW_OVERWRITE_KEY);
	SecureZeroMemory(password, sizeof(password));
	free(pfxBlob.pbData);

	if (hStore == NULL) {
		wprintf(L"Error importing PFX: %d\n", GetLastError());
		my_free(content);
		return ST_ERROR;
	}

	// Find certificate with private key
	pCert = CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		0, CERT_FIND_HAS_PRIVATE_KEY, NULL, NULL);
	if (pCert == NULL) {
		wprintf(L"Error: no certificate with private key found in PFX\n");
		CertCloseStore(hStore, 0);
		my_free(content);
		return ST_ERROR;
	}

	// Get private key
	if (!CryptAcquireCertificatePrivateKey(pCert, CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
		NULL, &hKey, &keySpec, &freeKey)) {
		wprintf(L"Error acquiring private key: %d\n", GetLastError());
		CertFreeCertificateContext(pCert);
		CertCloseStore(hStore, 0);
		my_free(content);
		return ST_ERROR;
	}

	// Build timestamp
	SYSTEMTIME st;
	GetSystemTime(&st);
	BYTE timestamp[16] = {0};
	*(WORD*)(timestamp + 0) = st.wYear;
	*(BYTE*)(timestamp + 2) = (BYTE)st.wMonth;
	*(BYTE*)(timestamp + 3) = (BYTE)st.wDay;
	*(BYTE*)(timestamp + 4) = (BYTE)st.wHour;
	*(BYTE*)(timestamp + 5) = (BYTE)st.wMinute;
	*(BYTE*)(timestamp + 6) = (BYTE)st.wSecond;

	// Build data to sign: name + guid + attributes + timestamp + content
	DWORD nameLen = ((DWORD)wcslen(var_name) + 1) * sizeof(wchar_t);
	DWORD attrs = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
		EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
	if (append_mode) attrs |= EFI_VARIABLE_APPEND_WRITE;

	DWORD toSignSize = nameLen + 16 + 4 + 16 + content_size;
	BYTE *toSign = (BYTE*)malloc(toSignSize);
	if (toSign == NULL) {
		if (freeKey) {
			if (keySpec == CERT_NCRYPT_KEY_SPEC)
				NCryptFreeObject(hKey);
			else
				CryptReleaseContext(hKey, 0);
		}
		CertFreeCertificateContext(pCert);
		CertCloseStore(hStore, 0);
		my_free(content);
		return ST_NOMEM;
	}

	BYTE *p = toSign;
	memcpy(p, var_name, nameLen); p += nameLen;
	memcpy(p, &varGuid, 16); p += 16;
	memcpy(p, &attrs, 4); p += 4;
	memcpy(p, timestamp, 16); p += 16;
	memcpy(p, content, content_size);

	// Sign with PKCS#7
	CRYPT_SIGN_MESSAGE_PARA signPara = {0};
	signPara.cbSize = sizeof(signPara);
	signPara.dwMsgEncodingType = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;
	signPara.pSigningCert = pCert;
	signPara.HashAlgorithm.pszObjId = (LPSTR)szOID_NIST_sha256;
	signPara.cMsgCert = 1;
	signPara.rgpMsgCert = &pCert;

	const BYTE *rgpbToBeSigned[1] = { toSign };
	DWORD rgcbToBeSigned[1] = { toSignSize };
	DWORD signedSize = 0;

	// Get required size
	if (!CryptSignMessage(&signPara, TRUE, 1, rgpbToBeSigned, rgcbToBeSigned, NULL, &signedSize)) {
		wprintf(L"Error calculating signature size: %d\n", GetLastError());
		free(toSign);
		if (freeKey) {
			if (keySpec == CERT_NCRYPT_KEY_SPEC)
				NCryptFreeObject(hKey);
			else
				CryptReleaseContext(hKey, 0);
		}
		CertFreeCertificateContext(pCert);
		CertCloseStore(hStore, 0);
		my_free(content);
		return ST_ERROR;
	}

	BYTE *signedData = (BYTE*)malloc(signedSize);
	if (signedData == NULL) {
		free(toSign);
		if (freeKey) {
			if (keySpec == CERT_NCRYPT_KEY_SPEC)
				NCryptFreeObject(hKey);
			else
				CryptReleaseContext(hKey, 0);
		}
		CertFreeCertificateContext(pCert);
		CertCloseStore(hStore, 0);
		my_free(content);
		return ST_NOMEM;
	}

	if (!CryptSignMessage(&signPara, TRUE, 1, rgpbToBeSigned, rgcbToBeSigned, signedData, &signedSize)) {
		wprintf(L"Error signing data: %d\n", GetLastError());
		free(signedData);
		free(toSign);
		if (freeKey) {
			if (keySpec == CERT_NCRYPT_KEY_SPEC)
				NCryptFreeObject(hKey);
			else
				CryptReleaseContext(hKey, 0);
		}
		CertFreeCertificateContext(pCert);
		CertCloseStore(hStore, 0);
		my_free(content);
		return ST_ERROR;
	}

	free(toSign);

	// Build authenticated variable:
	// EFI_TIME (16 bytes) + WIN_CERTIFICATE_UEFI_GUID (header + signature) + content
	// WIN_CERTIFICATE_UEFI_GUID: dwLength(4) + wRevision(2) + wCertType(2) + CertType(16) + CertData
	static const GUID EFI_CERT_TYPE_PKCS7_GUID =
	{ 0x4aafd29d, 0x68df, 0x49ee, { 0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7 } };

	DWORD certHdrSize = 4 + 2 + 2 + 16; // dwLength + wRevision + wCertType + CertType GUID
	DWORD winCertSize = certHdrSize + signedSize;
	authVarSize = 16 + winCertSize + content_size; // timestamp + WIN_CERTIFICATE + content

	authVar = (BYTE*)malloc(authVarSize);
	if (authVar == NULL) {
		free(signedData);
		if (freeKey) {
			if (keySpec == CERT_NCRYPT_KEY_SPEC)
				NCryptFreeObject(hKey);
			else
				CryptReleaseContext(hKey, 0);
		}
		CertFreeCertificateContext(pCert);
		CertCloseStore(hStore, 0);
		my_free(content);
		return ST_NOMEM;
	}

	p = authVar;
	// EFI_TIME (timestamp)
	memcpy(p, timestamp, 16); p += 16;
	// WIN_CERTIFICATE_UEFI_GUID
	*(DWORD*)p = winCertSize; p += 4;        // dwLength
	*(WORD*)p = 0x0200; p += 2;              // wRevision
	*(WORD*)p = 0x0EF1; p += 2;              // wCertificateType (WIN_CERT_TYPE_EFI_GUID)
	memcpy(p, &EFI_CERT_TYPE_PKCS7_GUID, 16); p += 16; // CertType
	memcpy(p, signedData, signedSize); p += signedSize; // CertData (PKCS#7)
	// Content
	memcpy(p, content, content_size);

	free(signedData);

	// Set the variable - load function dynamically (Windows 8+ API)
	wprintf(L"Setting authenticated variable '%s'...\n", var_name);
	PFN_SetFirmwareEnvironmentVariableExW pSetFirmwareEnvVarEx =
		(PFN_SetFirmwareEnvironmentVariableExW)GetProcAddress(
			GetModuleHandleW(L"kernel32.dll"), "SetFirmwareEnvironmentVariableExW");

	if (pSetFirmwareEnvVarEx == NULL) {
		wprintf(L"Error: SetFirmwareEnvironmentVariableExW not available (requires Windows 8+)\n");
		resl = ST_ERROR;
	} else if (!pSetFirmwareEnvVarEx(var_name, var_guid_str, authVar, authVarSize, attrs)) {
		DWORD err = GetLastError();
		wprintf(L"Error setting variable: %d (0x%08X)\n", err, err);
		if (err == 0x00001392) { // ERROR_EFI_SECURITY_VIOLATION
			wprintf(L"Security violation - the signature may not be authorized by KEK/PK\n");
		}
		resl = ST_ERROR;
	} else {
		wprintf(L"Variable '%s' set successfully (%d bytes)\n", var_name, authVarSize);
	}

	free(authVar);
	if (freeKey) {
		if (keySpec == CERT_NCRYPT_KEY_SPEC)
			NCryptFreeObject(hKey);
		else
			CryptReleaseContext(hKey, 0);
	}
	CertFreeCertificateContext(pCert);
	CertCloseStore(hStore, 0);
	my_free(content);
	
	return resl;
}

int efi_menu(int argc, wchar_t* argv[])
{
	int        resl = ST_INVALID_PARAM;

	if (!dc_efi_check()) {
		wprintf(L"System is not running in EFI mode\n");
		return ST_OK;
	}

	do
	{
		if ((argc == 3) && (wcscmp(argv[2], L"-sb_info") == 0)) {
			resl = efi_cmd_info(argc, argv);
			break;
		}

		if ((argc >= 3) && (wcscmp(argv[2], L"-list") == 0)) {
			resl = efi_cmd_list(argc, argv);
			break;
		}

		if ((argc >= 4) && (wcscmp(argv[2], L"-get") == 0)) {
			resl = efi_cmd_get(argc, argv);
			break;
		}

		if ((argc >= 4) && (wcscmp(argv[2], L"-set") == 0)) {
			resl = efi_cmd_set(argc, argv);
			break;
		}

		if ((argc >= 4) && (wcscmp(argv[2], L"-del") == 0)) {
			resl = efi_cmd_del(argc, argv);
			break;
		}

		if ((argc >= 3) && (wcscmp(argv[2], L"-dump") == 0)) {
			resl = efi_cmd_dump(argc, argv);
			break;
		}

		if ((argc >= 3) && (wcscmp(argv[2], L"-extract") == 0)) {
			resl = efi_cmd_extract(argc, argv);
			break;
		}

		if ((argc >= 3) && (wcscmp(argv[2], L"-pack") == 0)) {
			resl = efi_cmd_pack(argc, argv);
			break;
		}

		if ((argc >= 3) && (wcscmp(argv[2], L"-sb_set") == 0)) {
			resl = efi_cmd_sb_set(argc, argv);
			break;
		}

		//wprintf(L"Unknown EFI command: %s\n", argv[2]);

	} while (0);

	return resl;
}
