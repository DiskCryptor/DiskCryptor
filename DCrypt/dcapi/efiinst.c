/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2019-2026
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
#include "misc/dirent.h"
#include <stdio.h>
#include <io.h>
#include <assert.h>
#include "dcconst.h"
#include "volume_header.h"
#include "bootloader.h"
#include "efiinst.h"
#include "dcres.h"
#include "misc.h"
#include "ntdll.h"
#include "iso_fs.h"
#include "drv_ioctl.h"
#include "misc/zip.h"
#include "misc/xml.h"
#include "misc/fs_sup.h"
#include "mok_sup.h"
#include "dc_header.h"

const wchar_t* efi_var_guid = L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";

static GUID efi_sys_partition = { 0xc12a7328, 0xf81f, 0x11d2, { 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b } }; /*c12a7328-f81f-11d2-ba4b-00a0c93ec93b*/

#if defined(_M_IX86)
static const wchar_t* efi_boot_file = L"\\EFI\\Boot\\BOOTia32.efi";
static const wchar_t* efi_boot_bak = L"\\EFI\\Boot\\original_BOOTia32.bin";
#elif defined(_M_ARM64)
static const wchar_t* efi_boot_file = L"\\EFI\\Boot\\BOOTaa64.efi";
static const wchar_t* efi_boot_bak = L"\\EFI\\Boot\\original_BOOTaa64.bin";
#else
static const wchar_t* efi_boot_file = L"\\EFI\\Boot\\BOOTx64.efi";
static const wchar_t* efi_boot_bak = L"\\EFI\\Boot\\original_BOOTx64.bin";
#endif

typedef struct
{
	wchar_t* source;
	wchar_t* target;
} efi_file_t;


#ifdef _M_IX86
static const wchar_t* dcs_zip_file = L"DcsPkg_IA32";
static const efi_file_t dcs_files[] = {
	{L"DcsBoot32.efi",		L"\\EFI\\DCS\\DcsBoot.efi"}, // boot file must be first
	{L"DcsInt32.dcs",		L"\\EFI\\DCS\\DcsInt.dcs"},
	{L"DcsTpm32.dcs",		L"\\EFI\\DCS\\DcsTpm.dcs"},
	{L"DcsBml32.dcs",		L"\\EFI\\DCS\\DcsBml.dcs"},
	{L"DcsInfo32.dcs",		L"\\EFI\\DCS\\DcsInfo.dcs"},
	//{L"DcsCfg32.dcs",		L"\\EFI\\DCS\\DcsCfg.dcs"},
	{L"LegacySpeaker32.dcs",L"\\EFI\\DCS\\LegacySpeaker.dcs"},
	{L"DcsRe32.efi",		L"\\EFI\\DCS\\DcsRe32.efi"},
};
#else
#ifdef _M_ARM64
static const wchar_t* dcs_zip_file = L"DcsPkg_AA64";
#else
static const wchar_t* dcs_zip_file = L"DcsPkg_X64";
#endif
static const efi_file_t dcs_files[] = {
	{L"DcsBoot.efi",		L"\\EFI\\DCS\\DcsBoot.efi"}, // boot file must be first
	{L"DcsInt.dcs",			L"\\EFI\\DCS\\DcsInt.dcs"},
	{L"DcsTpm.dcs",			L"\\EFI\\DCS\\DcsTpm.dcs"},
	{L"DcsBml.dcs",			L"\\EFI\\DCS\\DcsBml.dcs"},
	{L"DcsInfo.dcs",		L"\\EFI\\DCS\\DcsInfo.dcs"},
	//{L"DcsCfg.dcs",			L"\\EFI\\DCS\\DcsCfg.dcs"},
	{L"LegacySpeaker.dcs",	L"\\EFI\\DCS\\LegacySpeaker.dcs"},
	{L"DcsRe.efi",			L"\\EFI\\DCS\\DcsRe.efi"},
};
#endif
static const size_t dcs_files_count = _countof(dcs_files);
static const size_t dcs_re_index = _countof(dcs_files) - 1;

static const wchar_t* dcs_conf_file = L"\\EFI\\DCS\\DcsProp";
static const wchar_t* dcs_info_file = L"\\EFI\\DCS\\PlatformInfo";
static const wchar_t* dcs_test_file = L"\\EFI\\DCS\\TestHeader";

#define DCS_EMBEDDED_PROP_SIZE 0x7FFF

static const char dcs_efi_empty_config[] = 
	"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<DiskCrypto>\n"
	"\t<configuration>\n"
	"\t</configuration>\n"
	"</DiskCrypto>\n";

static const char dcs_efi_dummy_info[] = 
	"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<PlatformInfo>\n"
	"</PlatformInfo>\n";

static const char* dc_dcs_iso_label = "DCS Boot Disk";
static const char* dc_dcs_img_label = "EFI_BOOT";

static const wchar_t* dc_dcs_img_file = L"\\EFIBOOT.IMG";


// shim for secure boot
#ifdef _M_IX86
static const wchar_t* shim_zip_file = L"ShimPkg_IA32";
static const efi_file_t shim_files[] = {
	{L"shimia32.efi",		L"\\EFI\\Boot\\shimia32.efi"}, // shim
	{L"mmia32.efi",			L"\\EFI\\Boot\\mmia32.efi"},
	{L"CustomSigner.der",	L"\\EFI\\Boot\\CustomSigner.der"},
	{L"DcsLdr.efi",			L"\\EFI\\Boot\\DcsLdr.efi"}, // loader
};
static const wchar_t* shim_boot_file = L"\\EFI\\Boot\\grubia32.efi";
#elif defined(_M_ARM64)
static const wchar_t* shim_zip_file = L"ShimPkg_AA64";
static const efi_file_t shim_files[] = {
	{L"shimaa64.efi",		L"\\EFI\\Boot\\shimaa64.efi"}, // shim
	{L"mmaa64.efi",			L"\\EFI\\Boot\\mmaa64.efi"},
	{L"CustomSigner.der",	L"\\EFI\\Boot\\CustomSigner.der"},
	{L"DcsLdr.efi",			L"\\EFI\\Boot\\DcsLdr.efi"}, // loader
};
static const wchar_t* shim_boot_file = L"\\EFI\\Boot\\grubaa64.efi";
#else
static const wchar_t* shim_zip_file = L"ShimPkg_X64";
static const efi_file_t shim_files[] = {
	{L"shimx64.efi",		L"\\EFI\\Boot\\shimx64.efi"}, // shim
	{L"mmx64.efi",			L"\\EFI\\Boot\\mmx64.efi"},
	{L"CustomSigner.der",	L"\\EFI\\Boot\\CustomSigner.der"},
	{L"DcsLdr.efi",			L"\\EFI\\Boot\\DcsLdr.efi"}, // loader
};
static const wchar_t* shim_boot_file = L"\\EFI\\Boot\\grubx64.efi";
#endif
static const size_t shim_mok_index = 2;
static const size_t shim_files_count = _countof(shim_files);
static const size_t shim_ldr_index = _countof(shim_files) - 1;

static const wchar_t* msft_boot_file = L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi";
static const wchar_t* msft_boot_aux = L"\\EFI\\Microsoft\\Boot\\bootmgfw_ms.vc";

void dc_efi_init()
{
	enable_privilege(SE_SYSTEM_ENVIRONMENT_NAME);
}

int dc_efi_check()
{
	byte tempBuf[4];
	GetFirmwareEnvironmentVariableW(L" ", L"{00000000-0000-0000-0000-000000000000}", tempBuf, sizeof(tempBuf));
	DWORD error = GetLastError();
	assert(error != ERROR_PRIVILEGE_NOT_HELD); // forgot to call dc_efi_init first
	return error == ERROR_ENVVAR_NOT_FOUND;
}

int dc_efi_is_secureboot()
{
	byte tempBuf = 0;
	GetFirmwareEnvironmentVariableW(L"SecureBoot", efi_var_guid, &tempBuf, sizeof(tempBuf));
	return tempBuf != 0;
}

int dc_efi_file_exists(const wchar_t *root, const wchar_t* name) // works also on directories
{
	wchar_t path[MAX_PATH];
	swprintf_s(path, MAX_PATH, L"%s%s", root, name);
	if (_waccess(path, 0) != -1)
		return 1;
	return 0;
}

/* Helper to find Volume GUID path for a partition (better for file operations)
 * Returns ST_OK on success, ST_NF_DEVICE if not found */
int dc_efi_get_volume_guid_path(int dsk_num, int part_num, wchar_t *path, int max_len)
{
	wchar_t volume_name[MAX_PATH];
	HANDLE hFind;
	HANDLE hVolume;
	STORAGE_DEVICE_NUMBER sdn;
	DWORD bytes;
	int found = 0;

	hFind = FindFirstVolume(volume_name, MAX_PATH);
	if (hFind == INVALID_HANDLE_VALUE) {
		return ST_NF_DEVICE;
	}

	do {
		/* Remove trailing backslash for CreateFile */
		size_t len = wcslen(volume_name);
		if (len > 0 && volume_name[len - 1] == L'\\') {
			volume_name[len - 1] = L'\0';
		}

		hVolume = CreateFile(volume_name, 0,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		if (hVolume != INVALID_HANDLE_VALUE) {
			if (DeviceIoControl(hVolume, IOCTL_STORAGE_GET_DEVICE_NUMBER,
				NULL, 0, &sdn, sizeof(sdn), &bytes, NULL)) {
				if ((int)sdn.DeviceNumber == dsk_num && (int)sdn.PartitionNumber == part_num) {
					/* Found it - keep without trailing backslash */
					wcsncpy_s(path, max_len, volume_name, _TRUNCATE);
					found = 1;
				}
			}
			CloseHandle(hVolume);
		}

		if (found) break;

	} while (FindNextVolume(hFind, volume_name, MAX_PATH));

	FindVolumeClose(hFind);
	return found ? ST_OK : ST_NF_DEVICE;
}

int dc_efi_get_os_disk(void)
{
	wchar_t boot_dev[MAX_PATH];
	wchar_t volume_path[MAX_PATH];
	HANDLE hVolume;
	STORAGE_DEVICE_NUMBER sdn;
	DWORD bytes;
	int dsk_num = -1;

	/* Get boot device path */
	if (dc_get_boot_device(boot_dev) != ST_OK) {
		return -1;
	}

	/* Convert to Win32 path */
	swprintf_s(volume_path, MAX_PATH, L"\\\\?%s", &boot_dev[7]);

	/* Open volume and get device number */
	hVolume = CreateFile(volume_path, 0,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hVolume != INVALID_HANDLE_VALUE) {
		if (DeviceIoControl(hVolume, IOCTL_STORAGE_GET_DEVICE_NUMBER,
			NULL, 0, &sdn, sizeof(sdn), &bytes, NULL)) {
			dsk_num = (int)sdn.DeviceNumber;
		}
		CloseHandle(hVolume);
	}

	return dsk_num;
}

int dc_efi_get_sys_part(int dsk_num, int esp_part, wchar_t* path)
{
	wchar_t               disk[MAX_PATH];
	HANDLE                hdisk = NULL;
	int                   resl, succs;
	u32                   bytes;
	u8                    buff[sizeof(DRIVE_LAYOUT_INFORMATION_EX) + sizeof(PARTITION_INFORMATION_EX) * 127]; // 128 partitions must be enough
	PDRIVE_LAYOUT_INFORMATION_EX dli = pv(buff);
	int                   first_esp_part = -1;
	wchar_t               first_esp_path[MAX_PATH] = { 0 };

	// if dsk_num == -1 then use boot disk
	if (dsk_num == -1) {
		dsk_num = dc_efi_get_os_disk();
		if (dsk_num < 0) return ST_NF_DEVICE;
	}
	_snwprintf(disk, countof(disk), L"\\\\.\\PhysicalDrive%d", dsk_num);

	do
	{
		hdisk = CreateFile(disk, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (hdisk == INVALID_HANDLE_VALUE) {
			hdisk = NULL;
			resl = ST_ACCESS_DENIED; break;
		}

		succs = DeviceIoControl(hdisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, NULL, 0, dli, sizeof(buff), &bytes, NULL);
		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		resl = ST_NF_DEVICE;

		if (dli->PartitionStyle == 1) // GPT
		{
			// If specific partition requested, use it directly
			if (esp_part > 0) {
				for (DWORD i = 0; i < dli->PartitionCount; i++) {
					PPARTITION_INFORMATION_EX part = &dli->PartitionEntry[i];
					if (part->PartitionNumber == esp_part) {
						// Try Volume GUID path first (better for file operations)
						if (dc_efi_get_volume_guid_path(dsk_num, esp_part, path, MAX_PATH) == ST_OK) {
							resl = ST_OK;
						} else {
							// Fall back to GLOBALROOT path
							swprintf_s(path, MAX_PATH, L"\\\\?\\GLOBALROOT\\Device\\Harddisk%d\\Partition%d", dsk_num, part->PartitionNumber);
							resl = ST_OK;
						}
						break;
					}
				}
			}
			else {
				// Auto-detect: first look for ESP with \EFI\DCS, then fallback to first ESP
				for (DWORD i = 0; i < dli->PartitionCount; i++)
				{
					PPARTITION_INFORMATION_EX part = &dli->PartitionEntry[i];
					if (IsEqualGUID(&part->Gpt.PartitionType, &efi_sys_partition))
					{
						wchar_t temp_path[MAX_PATH];
						// Try Volume GUID path first
						if (dc_efi_get_volume_guid_path(dsk_num, part->PartitionNumber, temp_path, MAX_PATH) != ST_OK) {
							// Fall back to GLOBALROOT path
							swprintf_s(temp_path, MAX_PATH, L"\\\\?\\GLOBALROOT\\Device\\Harddisk%d\\Partition%d", dsk_num, part->PartitionNumber);
						}

						// Remember first ESP as fallback
						if (first_esp_part < 0) {
							first_esp_part = part->PartitionNumber;
							wcscpy_s(first_esp_path, MAX_PATH, temp_path);
						}

						// Check if this ESP has DCS installed
						if (dc_efi_file_exists(temp_path, L"\\EFI\\DCS")) {
							wcscpy_s(path, MAX_PATH, temp_path);
							resl = ST_OK;
							break;
						}
					}
				}
				// If no ESP with DCS found, use first ESP
				if (resl != ST_OK && first_esp_part > 0) {
					wcscpy_s(path, MAX_PATH, first_esp_path);
					resl = ST_OK;
				}
			}
		}
		else  if (dli->PartitionStyle == 0) // MBR
		{
			// find a FAT partition with an EFI directory
			for (DWORD i = 0; i < dli->PartitionCount; i++)
			{
				PPARTITION_INFORMATION_EX part = &dli->PartitionEntry[i];

				if (part->Mbr.PartitionType != PARTITION_FAT32
					&& part->Mbr.PartitionType != PARTITION_FAT32_XINT13
					&& part->Mbr.PartitionType != PARTITION_XINT13 // FAT
				  )
					continue;

				swprintf_s(path, MAX_PATH, L"\\\\?\\GLOBALROOT\\Device\\Harddisk%d\\Partition%d", dsk_num, part->PartitionNumber);

				if (dc_efi_file_exists(path, L"\\EFI")) {
					resl = ST_OK;
					break;
				}
			}
		}

	} while (0);

	if (hdisk != NULL) {
		CloseHandle(hdisk);
	}
	return resl;
} 

int dc_load_efi_file(const wchar_t *root, const wchar_t* fileName, void **data, int *size)
{
	wchar_t path[MAX_PATH];
	swprintf_s(path, MAX_PATH, L"%s%s", root, fileName);
	return load_file(path, data, size);
}

int dc_save_efi_file(const wchar_t *root, const wchar_t* fileName, void *data, int size)
{
	wchar_t path[MAX_PATH];
	swprintf_s(path, MAX_PATH, L"%s%s", root, fileName);
	return save_file(path, data, size);
}

int dc_delete_efi_file(const wchar_t* root, const wchar_t* fileName)
{
	wchar_t path[MAX_PATH];
	swprintf_s(path, MAX_PATH, L"%s%s", root, fileName);
	BOOL bRet = DeleteFile(path);
	//If an application attempts to delete a file that does not exist, the DeleteFile function fails with ERROR_FILE_NOT_FOUND. 
	//If the file is a read-only file, the function fails with ERROR_ACCESS_DENIED.
	if (!bRet && (GetLastError() != ERROR_FILE_NOT_FOUND))
		return ST_RW_ERR;
	return ST_OK;
}

int dc_copy_efi_file(const wchar_t* root, const wchar_t* srcFile, const wchar_t* targetFile)
{
	wchar_t path[MAX_PATH];
	swprintf_s(path, MAX_PATH, L"%s%s", root, srcFile);
	if (_waccess(path, 0) == -1)  // fail if source file does not exist
		return ST_NF_FILE;

	wchar_t new_path[MAX_PATH];
	swprintf_s(new_path, MAX_PATH, L"%s%s", root, targetFile);
	if (!CopyFile(path, new_path, 0)) // overwrite existing
		return ST_RW_ERR;
	return ST_OK;
}

int dc_ren_efi_file(const wchar_t* root, const wchar_t* srcFile, const wchar_t* targetFile)
{
	wchar_t path[MAX_PATH];
	swprintf_s(path, MAX_PATH, L"%s%s", root, srcFile);
	if (_waccess(path, 0) == -1)  // fail if source file does not exist
		return ST_NF_FILE;

	wchar_t new_path[MAX_PATH];
	swprintf_s(new_path, MAX_PATH, L"%s%s", root, targetFile);
	DeleteFile(new_path); // overwrite existing
	if (!MoveFile(path, new_path))
		return ST_RW_ERR;
	return ST_OK;
}

int dc_efi_mkdir(const wchar_t* root, const wchar_t* name)
{
	wchar_t path[MAX_PATH];
	swprintf_s(path, MAX_PATH, L"%s%s", root, name);
	BOOL bRet = CreateDirectory(path, NULL);
	if (!bRet && (GetLastError() != ERROR_ALREADY_EXISTS))
		return ST_RW_ERR;
	return ST_OK;
}

int dc_delete_efi_dir(const wchar_t* root, const wchar_t* dirName, int delFiles, int recursive)
{
	int     resl = ST_OK;
	DIR*    dir;
	dirent* entry;
	char	dir_path[MAX_PATH];
	wchar_t	path[MAX_PATH];
	int		is_empty = 1;
	
	sprintf_s(dir_path, MAX_PATH, "%S%S", root, dirName);
	if (!(dir = opendir(dir_path)))
		return ST_NO_OPEN_DIR;

	while ((entry = readdir(dir)) != NULL)
	{
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
			continue;
		swprintf_s(path, MAX_PATH, L"%s\\%S", dirName, entry->d_name);
		if (entry->d_type == DT_DIR) {
			if (recursive) {
				if (dc_delete_efi_dir(root, path, delFiles, recursive) == ST_OK)
					continue;
			}
		}
		else if (delFiles) {
			if (dc_delete_efi_file(root, path) == ST_OK)
				continue;
		}
		is_empty = 0;
	}
	closedir(dir);
	
	if (!is_empty) 
		return ST_DIR_NOT_EMPTY;
	if (!RemoveDirectoryA(dir_path))
		return ST_RW_ERR;
	return ST_OK;
}

int dc_copy_zip_to_efi_file(const wchar_t *root, struct zip_t *zip, const wchar_t* source, const wchar_t* target)
{
	int     resl = ST_OK;
	char	entryName[MAX_PATH];
	char	fileName[MAX_PATH];

	sprintf_s(entryName, MAX_PATH, "%S", source);
	sprintf_s(fileName, MAX_PATH, "%S\\%S", root, target);

	if (_access(fileName, 0) != -1) { // file already exists
		if (!DeleteFileA(fileName)) { // and cant be deleted
			return ST_RW_ERR;
		}
	}

	if (zip_entry_open(zip, entryName) != 0)
		resl = ST_NF_FILE;
	else
	{
		if (zip_entry_fread(zip, fileName) != 0)
			resl = ST_RW_ERR;

		zip_entry_close(zip);
	}

	return resl;
}

int dc_copy_zip_to_efi_files(const wchar_t *root, struct zip_t *zip, const efi_file_t* files, size_t count)
{
	int     resl = ST_OK;
	for (size_t i = 0; i < count && resl == ST_OK; i++){
		resl = dc_copy_zip_to_efi_file(root, zip, files[i].source, files[i].target);
	}
	return resl;
}

int dc_open_zip(const wchar_t* fileName, struct zip_t **zip)
{
	char	path[MAX_PATH];
	sprintf_s(path, MAX_PATH, "%S", fileName);

	*zip = zip_open(path, 0, 'r');
	if (*zip == NULL) 
		return ST_NF_FILE; 
	return ST_OK;
}

static int dc_zip_load_file(struct zip_t* zip, const wchar_t* fileName, void** buffer, size_t* bufsize)
{
	int     resl;
	char    entryName[MAX_PATH];
	ssize_t bytes_read;
	sprintf_s(entryName, MAX_PATH, "%S", fileName);

	do
	{
		if (zip_entry_open(zip, entryName) != 0) {
			resl = ST_NF_FILE;
			break;
		}

		bytes_read = zip_entry_read(zip, buffer, bufsize);
		zip_entry_close(zip);

		if (bytes_read < 0 || buffer == NULL) {
			resl = ST_RW_ERR;
			break;
		}

	} while (0);

	return resl;
}

int dc_copy_file(const wchar_t *path, const wchar_t *root, const wchar_t* source, const wchar_t* target)
{
	wchar_t src_path[MAX_PATH];
	swprintf_s(src_path, MAX_PATH, L"%s%s", path, source);
	if (_waccess(src_path, 0) == -1)  // fail if source file does not exist
		return ST_NF_FILE;

	wchar_t dest_path[MAX_PATH];
	swprintf_s(dest_path, MAX_PATH, L"%s%s", root, target);
	if (!CopyFile(src_path, dest_path, 0)) // overwrite existing
		return ST_RW_ERR;
	return ST_OK;
}

int dc_copy_pkg_to_efi_files(const wchar_t *path, const wchar_t *root, const efi_file_t* files, size_t count)
{
	int     resl = ST_OK;
	for (size_t i = 0; i < count && resl == ST_OK; i++){
		resl = dc_copy_file(path, root, files[i].source, files[i].target);
	}
	return resl;
}

int dc_copy_pkt_files(const wchar_t *root, const wchar_t* zip_file, const efi_file_t* files, size_t count)
{
	int     resl;
	struct zip_t *zip = NULL;
	TCHAR	source_path[MAX_PATH], *p;
	DWORD	length;
	int 	use_pkg;

	if (g_inst_dll == NULL || (length = GetModuleFileName(g_inst_dll, source_path, _countof(source_path))) == 0) return ST_NF_FILE;
	if (length >= _countof(source_path) - 1 || (p = wcsrchr(source_path, '\\')) == NULL) return ST_NF_FILE;
	if (wcscpy_s(p + 1, _countof(source_path) - (p - source_path) - 1, zip_file) != 0) return ST_NOMEM;
	use_pkg = dc_efi_file_exists(source_path, L"");
	if (use_pkg) {
		if (wcscat_s(source_path, _countof(source_path), L"\\") != 0) return ST_NOMEM;
	} else {
		if (wcscat_s(source_path, _countof(source_path), L".zip") != 0) return ST_NOMEM;
	}

	do
	{
		if (use_pkg) 
		{
			resl = dc_copy_pkg_to_efi_files(source_path, root, files, count);
			if (resl != ST_OK) break;
		}
		else
		{
			resl = dc_open_zip(source_path, &zip);
			if (resl != ST_OK) break;

			resl = dc_copy_zip_to_efi_files(root, zip, files, count);
			if (resl != ST_OK) break;
		}

	} while (0);

	if (zip != NULL) {
		zip_close(zip);
	}
	return resl;
}

int dc_copy_efi_shim(const wchar_t *root)
{
	int      resl;

	do
	{
		resl = dc_copy_pkt_files(root, shim_zip_file, shim_files, shim_files_count);
		if (resl != ST_OK) break;

	} while (0);

	return resl;
}

int dc_copy_efi_dcs(const wchar_t *root, int recovery)
{
	int     resl;

	do
	{
		resl = dc_efi_mkdir(root, L"\\EFI");
		if (resl != ST_OK) break;
		resl = dc_efi_mkdir(root, L"\\EFI\\DCS");
		if (resl != ST_OK) break;

		resl = dc_copy_pkt_files(root, dcs_zip_file, dcs_files, recovery ? dcs_files_count : dcs_re_index);
		if (resl != ST_OK) break;

	} while (0);

	return resl;
}

int dc_make_efi_rec(const wchar_t *root, int format, int shim)
{
	wchar_t               disk[MAX_PATH];
	HANDLE                hdisk = NULL;
	int                   resl, succs;
	u32                   bytes;
	DISK_GEOMETRY         dg;
	PARTITION_INFORMATION pti;
	//STORAGE_DEVICE_NUMBER d_num;
	int                   sb_no_pass;

	sb_no_pass = (dc_efi_is_secureboot() && !dc_efi_dcs_is_signed());
	if (shim == -1) shim = sb_no_pass;

	if (shim && !dc_efi_shim_available())
		return ST_SHIM_MISSING;

	if (root[0] != L'\\')
		_snwprintf(disk, countof(disk), L"\\\\.\\%c:", root[0]);
	else 
		wcsncpy(disk, root, countof(disk));

	do
	{
		hdisk = CreateFile(disk, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (hdisk == INVALID_HANDLE_VALUE) {
			hdisk = NULL;
			resl = ST_ACCESS_DENIED; break;
		}

		succs = DeviceIoControl(hdisk, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &dg, sizeof(dg), &bytes, NULL);
		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		if (dg.MediaType != RemovableMedia) {
			resl = ST_INV_MEDIA_TYPE; break;
		}

		//succs = DeviceIoControl(hdisk, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &d_num, sizeof(d_num), &bytes, NULL);
		//if (succs == 0) {
		//	resl = ST_ERROR; break;
		//}

		if (format == 0) {

			succs = DeviceIoControl(hdisk, IOCTL_DISK_GET_PARTITION_INFO, NULL, 0, &pti, sizeof(pti), &bytes, NULL);
			if (succs == 0) {
				resl = ST_ERROR; break;
			}

			if (pti.PartitionType != PARTITION_FAT32
			 && pti.PartitionType != PARTITION_FAT32_XINT13
			 && pti.PartitionType != PARTITION_XINT13 // FAT
			) {
				resl = ST_FORMAT_NEEDED; break;
			}
		}
		else {

			CloseHandle(hdisk); // close befoer formating
			hdisk = NULL;

			if ((resl = dc_format_fs((wchar_t*)root, L"FAT32")) != ST_OK) {
				break;
			}
		}

		resl = dc_copy_efi_dcs(root, 1);
		if (resl != ST_OK) break;

		resl = dc_efi_mkdir(root, L"\\EFI\\Boot");
		if (resl != ST_OK) break;

		if (shim) {
			resl = dc_copy_efi_shim(root);
			if (resl != ST_OK) break;

			resl = dc_ren_efi_file(root, shim_files[0].target, efi_boot_file);
			if (resl != ST_OK) break;

			resl = dc_ren_efi_file(root, shim_files[shim_ldr_index].target, shim_boot_file); // L"\\EFI\\Boot\\DcsLdr.efi" -> L"\\EFI\\Boot\\grubx64.efi"
		}
		else {
			resl = dc_copy_file(root, root, dcs_files[dcs_re_index].target, efi_boot_file); // L"\\EFI\\DCS\\DcsRe.efi" -> L"\\EFI\\Boot\\BOOTx64.efi"
		}
		if (resl != ST_OK) break;

		ldr_config conf;
		dc_efi_config_init(&conf);
		resl = dc_efi_config_by_partition(root, 1, &conf);
		
	} while (0);

	if (hdisk != NULL) {
		CloseHandle(hdisk);
	}
	return resl;
}

static int dc_load_efi_files(file_entry_t* image_files, size_t* image_file_count, const wchar_t* zip_file, const efi_file_t* files, size_t count)
{
	int     resl = ST_OK;
	char*   data = NULL;
	struct zip_t *zip = NULL;
	TCHAR	source_path[MAX_PATH], *p;
	DWORD	length;
	int 	use_pkg;
	wchar_t src_path[MAX_PATH];

	if (g_inst_dll == NULL || (length = GetModuleFileName(g_inst_dll, source_path, _countof(source_path))) == 0) return ST_NF_FILE;
	if (length >= _countof(source_path) - 1 || (p = wcsrchr(source_path, '\\')) == NULL) return ST_NF_FILE;
	if (wcscpy_s(p + 1, _countof(source_path) - (p - source_path) - 1, zip_file) != 0) return ST_NOMEM;
	use_pkg = dc_efi_file_exists(source_path, L"");
	if (use_pkg) {
		if (wcscat_s(source_path, _countof(source_path), L"\\") != 0) return ST_NOMEM;
	} else {
		if (wcscat_s(source_path, _countof(source_path), L".zip") != 0) return ST_NOMEM;
	}

	do
	{
		if (use_pkg) 
		{
			int size;

			for (size_t i = 0; i < count && resl == ST_OK; i++){

				swprintf_s(src_path, MAX_PATH, L"%s%s", source_path, files[i].source);
				resl = load_file(src_path, &data, &size);
				if (resl != ST_OK) break;

				file_entry_t* iso_file = &image_files[(*image_file_count)++];
				wcscpy(iso_file->path, files[i].target);
				iso_file->size = (size_t)size;
				iso_file->data = data;
			}
		}
		else
		{
			size_t size;

			for (size_t i = 0; i < count && resl == ST_OK; i++) {
				
				resl = dc_zip_load_file(zip, files[i].source, &data, &size);
				if (resl != ST_OK) break;

				file_entry_t* iso_file = &image_files[(*image_file_count)++];
				wcscpy(iso_file->path, files[i].target);
				iso_file->size = size;
				iso_file->data = data;
			}
		}

	} while (0);

	if (zip != NULL) {
		zip_close(zip);
	}
	return resl;
}

int dc_make_efi_iso(wchar_t* file, int shim)
{
	int        resl;
	const int  img_file_max = 32;
	file_entry_t* img_files;
	size_t     img_file_count = 0;
	const int  iso_file_max = 8;
	file_entry_t* iso_files;
	size_t     iso_file_count = 0;
	void*      fat_data = NULL;
	size_t     fat_size = 0;
	void*      iso_data = NULL;
	size_t     iso_size = 0;

	if (shim && !dc_efi_shim_available())
		return ST_SHIM_MISSING;

	// Create an EFI bootable ISO image with FAT file system image inside containing DCS EFI files

	do
	{
		img_files = (file_entry_t*)malloc(sizeof(file_entry_t) * img_file_max); // max 32 files
		if (img_files == NULL) {
			resl = ST_NOMEM; break;
		}
		memset(img_files, 0, sizeof(file_entry_t) * img_file_max);

		iso_files = (file_entry_t*)malloc(sizeof(file_entry_t) * iso_file_max); // max 8 files
		if (iso_files == NULL) {
			resl = ST_NOMEM; break;
		}
		memset(iso_files, 0, sizeof(file_entry_t) * iso_file_max);

		if (shim) 
		{
			resl = dc_load_efi_files(img_files, &img_file_count, shim_zip_file, shim_files, shim_files_count);
			if (resl != ST_OK) break;

			// \\EFI\\Boot\\shimxxx.efi -> \EFI\Boot\BOOTxxx.efi
			wcscpy(img_files[0].path, efi_boot_file);

			// \\EFI\\Boot\\DcsLdr.efi -> \EFI\Boot\GRUBxxx.efi
			wcscpy(img_files[shim_ldr_index].path, shim_boot_file);

			resl = dc_load_efi_files(img_files, &img_file_count, dcs_zip_file, dcs_files, dcs_files_count);
			if (resl != ST_OK) break;
		}
		else 
		{
			// reserver \EFI\Boot\BOOTxxx.efi
			img_file_count = 1;

			resl = dc_load_efi_files(img_files, &img_file_count, dcs_zip_file, dcs_files, dcs_files_count);
			if (resl != ST_OK) break;

			// fill \EFI\Boot\BOOTxxx.efi
			file_entry_t* re_file = &img_files[1 + dcs_re_index];
			wcscpy(img_files->path, efi_boot_file);
			img_files->size = re_file->size;
			img_files->data = malloc(re_file->size);
			if (img_files->data) memcpy(img_files->data, re_file->data, re_file->size);
		}

		// add dummy \EFI\DCS\PlatformInfo
		file_entry_t* info_file = &img_files[img_file_count++];
		wcscpy(info_file->path, dcs_info_file);
		info_file->size = strlen(dcs_efi_dummy_info);
		info_file->data = malloc(info_file->size + 1);
		strcpy(info_file->data, dcs_efi_dummy_info);

		// add \EFI\DCS\DcsProp
		file_entry_t* prop_file = &img_files[img_file_count++];
		wcscpy(prop_file->path, dcs_conf_file);
		prop_file->size = DCS_EMBEDDED_PROP_SIZE;
		prop_file->data = malloc(prop_file->size);
		memset(prop_file->data, '    ', prop_file->size);
		strcpy(prop_file->data, dcs_efi_empty_config);

		assert(img_file_count <= img_file_max);
		
		// create FAT image
		resl = create_fat_image(dc_dcs_img_label, img_files, img_file_count, &fat_data, &fat_size);
		if (resl != ST_OK) {
			break;
		}

		file_entry_t* image_file = &iso_files[iso_file_count++];
		wcscpy(image_file->path, dc_dcs_img_file);
		image_file->data = fat_data;
		image_file->size = fat_size;
		fat_data = NULL;

		assert(iso_file_count <= iso_file_max);

		// create ISO image
		resl = create_iso_image(dc_dcs_iso_label, iso_files, iso_file_count, image_file, &iso_data, &iso_size);
		if (resl != ST_OK) {
			break;
		}

		// save ISO image to file
		resl = save_file(file, iso_data, (int)iso_size);

	} while (0);

	if (img_files) {
		for (size_t i = 0; i < img_file_max; i++) {
			if (img_files[i].data) free(img_files[i].data);
		}
		free(img_files);
	}

	if(iso_files) {
		for (size_t i = 0; i < iso_file_max; i++) {
			if (iso_files[i].data) free(iso_files[i].data);
		}
		free(iso_files);
	}
	
	if (fat_data != NULL) {
		free(fat_data);
	}

	if (iso_data != NULL) {
		free(iso_data);
	}

	return resl;
}

int dc_make_efi_pxe(wchar_t* root, int shim)
{
	int      resl;

	if (!dc_efi_shim_available()) // DcsLdr.efi is required for PXE Boot
		return ST_SHIM_MISSING;

	do
	{
		resl = dc_copy_efi_dcs(root, 1);
		if (resl != ST_OK) break;

		resl = dc_efi_mkdir(root, L"\\EFI\\Boot");
		if (resl != ST_OK) break;

		if (shim) {
			resl = dc_copy_efi_shim(root);
			if (resl != ST_OK) break;

			resl = dc_ren_efi_file(root, shim_files[0].target, efi_boot_file);
			if (resl != ST_OK) break;

			resl = dc_ren_efi_file(root, shim_files[shim_ldr_index].target, shim_boot_file); // L"\\EFI\\Boot\\DcsLdr.efi" -> L"\\EFI\\Boot\\grubx64.efi"
		}
		else {

			resl = dc_copy_pkt_files(root, shim_zip_file, &shim_files[shim_ldr_index], 1);
			if (resl != ST_OK) break;

			resl = dc_ren_efi_file(root, shim_files[shim_ldr_index].target, efi_boot_file); // L"\\EFI\\Boot\\DcsLdr.efi" -> L"\\EFI\\Boot\\BOOTx64.efi"
		}

	} while (0);

	return resl;
}

int dc_replace_msft_boot(const wchar_t *root)
{
	int      resl;
	DWORD    size = 0;
	char*    data = NULL;
	int      is_dcs_file, is_msft_file;

	do
	{
		resl = dc_load_efi_file(root, msft_boot_file, &data, &size);
		if (resl != ST_OK) break;

		is_dcs_file = dc_buffer_contains_wide_string(data, size, L"\\DcsInt.dcs");
		// does the file look like a msft boot manager, or was it already repalced?
		is_msft_file = dc_buffer_contains_string(data, size, "bootmgfw.pdb");

		// rename msft boot manager file
		if (!is_dcs_file && is_msft_file) {
			resl = dc_ren_efi_file(root, msft_boot_file, msft_boot_aux);
			if (resl != ST_OK) break;
		}
		// fail if the renamed boot file does nto exist
		else if (!dc_efi_file_exists(root, msft_boot_aux)) {
			resl = ST_NF_FILE; break;
		}

		// put a copy of the dcs boot file in place of the msft boot file
		resl = dc_copy_efi_file(root, dcs_files[0].target, msft_boot_file);

	} while (0);

	if (data) {
		free(data);
	}
	return ST_OK;
}

int dc_restore_msft_boot(const wchar_t *root)
{
	int      resl;
	DWORD    size = 0;
	char*    data = NULL;
	int      is_dcs_file;

	do
	{
		resl = dc_load_efi_file(root, msft_boot_file, &data, &size);
		if (resl != ST_OK) break;

		// does the boot file look like out bootloader?
		is_dcs_file = dc_buffer_contains_wide_string(data, size, L"\\DcsInt.dcs");

		if (is_dcs_file)
		{
			// fail if the renamed boot file does nto exist
			if (!dc_efi_file_exists(root, msft_boot_aux)) {
				resl = ST_NF_FILE; break;
			}

			// restore the saved boot file
			resl = dc_ren_efi_file(root, msft_boot_aux, msft_boot_file);
		}
		// the boot file already looks like a msft one, just delete the old renamed file
		else {
			dc_delete_efi_file(root, msft_boot_aux);
		}

	} while (0);

	if (data) {
		free(data);
	}
	return ST_OK;
}

int dc_is_msft_boot_replaced(const wchar_t *root)
{
	int      resl;
	DWORD    size = 0;
	char*    data = NULL;
	int      is_dcs_file = 0;

	do
	{
		resl = dc_load_efi_file(root, msft_boot_file, &data, &size);
		if (resl != ST_OK) break;

		// does the boot file look like out bootloader?
		is_dcs_file = dc_buffer_contains_wide_string(data, size, L"\\DcsInt.dcs");

	} while (0);

	if (data) {
		free(data);
	}
	return is_dcs_file;
}

int dc_efi_is_msft_boot_replaced(int dsk_num, int esp_part)
{
	wchar_t  path[MAX_PATH] = { 0 };
	if (dc_efi_get_sys_part(dsk_num, esp_part, path) == ST_OK)
		return dc_is_msft_boot_replaced(path);
	return 0;
}

int dc_efi_replace_msft_boot(int dsk_num, int esp_part)
{
	int      resl;
	wchar_t  root[MAX_PATH] = { 0 };

	do
	{
		resl = dc_efi_get_sys_part(dsk_num, esp_part, root);
		if (resl != ST_OK) break;

		if (!dc_is_dcs_on_partition(root)) {
			resl = ST_BLDR_NOTINST;
			break;
		}

		if (dc_is_msft_boot_replaced(root)) {
			resl = ST_BLDR_INSTALLED;
			break;
		}

		resl = dc_replace_msft_boot(root);

	} while (0);

	return resl;
}

int dc_efi_restore_msft_boot(int dsk_num, int esp_part)
{
	int      resl;
	wchar_t  root[MAX_PATH] = { 0 };

	do
	{
		resl = dc_efi_get_sys_part(dsk_num, esp_part, root);
		if (resl != ST_OK) break;

		if (!dc_is_msft_boot_replaced(root)) {
			resl = ST_BLDR_NOTINST;
			break;
		}

		resl = dc_restore_msft_boot(root);

	} while (0);

	return resl;
}

int dc_set_efi_boot(int dsk_num, int esp_part, int replace_ms, int shim)
{
	int      resl;
	wchar_t  root[MAX_PATH] = { 0 };
	int		 sb_no_pass;

	sb_no_pass = (dc_efi_is_secureboot() && !dc_efi_dcs_is_signed());
	if (shim == -1) shim = sb_no_pass;
	if (sb_no_pass && replace_ms) {
		// when secure boot is enablet don't allow to install DCS if its not signed with a certificate from the current "db" variable
		return ST_SB_NO_PASS;
	}

	if (shim && !dc_efi_shim_available())
		return ST_SHIM_MISSING;

	do
	{
		resl = dc_efi_get_sys_part(dsk_num, esp_part, root);
		if (resl != ST_OK) break;

		// check if the bootloader is already installed
		if (dc_is_dcs_on_partition(root)) {
			resl = ST_BLDR_INSTALLED; break;
		}

		resl = dc_copy_efi_dcs(root, 0);
		if (resl != ST_OK) break;

		if (dc_efi_file_exists(root, efi_boot_file)) { // if there is a original boot file
			if (!dc_efi_file_exists(root, efi_boot_bak)) { // and there is no boot file backup already
				dc_copy_efi_file(root, efi_boot_file, efi_boot_bak); // backup the boot file
			}
		} else { // if there is no boot file, create an empty backup file
			resl = dc_efi_mkdir(root, L"\\EFI\\Boot");
			if (resl != ST_OK) break;
		}

		if (shim) {
			resl = dc_copy_efi_shim(root);
			if (resl != ST_OK) break;
			
			resl = dc_copy_efi_file(root, shim_files[0].target, efi_boot_file); // L"\\EFI\\Boot\\shimx64.efi" -> L"\\EFI\\Boot\\BOOTx64.efi"
			if (resl != ST_OK) break;

			resl = dc_ren_efi_file(root, shim_files[shim_ldr_index].target, shim_boot_file); // L"\\EFI\\Boot\\DcsLdr.efi" -> L"\\EFI\\Boot\\grubx64.efi"

			dc_mok_set_timeout(600); // 10 min, NOTE: this will be auto reset back to 10s after reboot :/

			size_t end = wcslen(root);
			const wchar_t* files[] = {root};
			wcscat_s(root, MAX_PATH, shim_files[shim_mok_index].target);
			dc_mok_enroll_files(files, 1, L"123", 0);
			root[end] = 0;
		}
		else {
			resl = dc_copy_file(root, root, dcs_files[0].target, efi_boot_file); // L"\\EFI\\DCS\\DcsBoot.efi" -> L"\\EFI\\Boot\\BOOTx64.efi"
		}
		if (resl != ST_OK) break;

		ldr_config conf;
		dc_efi_config_init(&conf);
		resl = dc_efi_config_by_partition(root, 1, &conf);
		if (resl != ST_OK) break;

		dc_efi_update_cert(NULL);

		if (replace_ms) {
			resl = dc_replace_msft_boot(root);
		}

	} while (0);

	return resl;
}

int dc_update_efi_boot(int dsk_num, int esp_part)
{
	int      resl;
	wchar_t  root[MAX_PATH] = { 0 };
	int 	 shim;

	do
	{
		resl = dc_efi_get_sys_part(dsk_num, esp_part, root);
		if (resl != ST_OK) break;

		// check if the bootloader is installed
		if (!dc_is_dcs_on_partition(root)) {
			resl = ST_BLDR_NOTINST; break;
		}

		resl = dc_copy_efi_dcs(root, 0);
		if (resl != ST_OK) break;

		shim = dc_is_shim_on_partition(root); // check if shim is installed

		if (shim) {
			resl = dc_copy_efi_shim(root);
			if (resl != ST_OK) break;

			resl = dc_copy_efi_file(root, shim_files[0].target, efi_boot_file);
			if (resl != ST_OK) break;

			resl = dc_ren_efi_file(root, shim_files[shim_ldr_index].target, shim_boot_file); // L"\\EFI\\Boot\\DcsLdr.efi" -> L"\\EFI\\Boot\\grubx64.efi"
		}
		else {
			resl = dc_copy_file(root, root, dcs_files[0].target, efi_boot_file); // L"\\EFI\\DCS\\DcsBoot.efi" -> L"\\EFI\\Boot\\BOOTx64.efi"
		}
		if (resl != ST_OK) break;

		if (dc_is_msft_boot_replaced(root)) {
			resl = dc_replace_msft_boot(root);
		}

	} while (0);

	return resl;
}

int dc_unset_efi_boot(int dsk_num, int esp_part)
{
	int      resl;
	wchar_t  root[MAX_PATH] = { 0 };

	do
	{
		resl = dc_efi_get_sys_part(dsk_num, esp_part, root);
		if (resl != ST_OK) break;

		// check if the bootloader is installed
		if (!dc_is_dcs_on_partition(root)) {
			resl = ST_BLDR_NOTINST; break;
		}

		if (dc_is_msft_boot_replaced(root)) {
			resl = dc_restore_msft_boot(root);
			if (resl != ST_OK) break;
		}

		// delete the entire \\EFI\\DCS directory
		resl = dc_delete_efi_dir(root, L"\\EFI\\DCS", 1, 0);

		// check if shim is installed
		if (dc_is_shim_on_partition(root)) { // remove shim and boot file
			for (int i = 0; i < shim_files_count; i++) {
				dc_delete_efi_file(root, shim_files[i].target);
			}

			dc_delete_efi_file(root, shim_boot_file);
		}
		else { // remove boot file
			dc_delete_efi_file(root, efi_boot_file);
		}

		// restore original boot file
		dc_ren_efi_file(root, efi_boot_bak, efi_boot_file);

		// remove //EFI//Boot and // EFI if thay are empty
		dc_delete_efi_dir(root, L"\\EFI", 0, 1);

	} while (0);

	return resl;
}

int dc_get_platform_info(int dsk_num, char** infoContent, int *size)
{
	int      resl;
	wchar_t  root[MAX_PATH] = { 0 };

	do
	{
		resl = dc_efi_get_sys_part(dsk_num, -1, root);
		if (resl != ST_OK) break;

		// check if the bootloader is installed
		if (!dc_is_dcs_on_partition(root)) {
			resl = ST_BLDR_NOTINST; break;
		}

		resl = dc_load_efi_file(root, dcs_info_file, infoContent, size);

	} while (0);

	return resl;
}

int dc_is_gpt_disk(int dsk_num)
{
	wchar_t               disk[MAX_PATH];
	HANDLE                hdisk = NULL;
	int                   resl, succs;
	u32                   bytes;
	u8                    buff[sizeof(DRIVE_LAYOUT_INFORMATION_EX) + sizeof(PARTITION_INFORMATION_EX) * 127]; // 128 partitions must be enough
	PDRIVE_LAYOUT_INFORMATION_EX dli = pv(buff);

	_snwprintf(disk, countof(disk), L"\\\\.\\PhysicalDrive%d", dsk_num);

	do
	{
		hdisk = CreateFile(disk, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (hdisk == INVALID_HANDLE_VALUE) {
			hdisk = NULL;
			resl = -1; break;
		}

		succs = DeviceIoControl(hdisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, NULL, 0, dli, sizeof(buff), &bytes, NULL);
		if (succs == 0) {
			resl = -1; break;
		}

		resl = dli->PartitionStyle;

	} while (0);

	if (hdisk != NULL) {
		CloseHandle(hdisk);
	}
	return resl;
}

int dc_get_part_info(wchar_t* disk, PARTITION_INFORMATION_EX* ptix)
{
	int      resl, succs;
	u32      bytes;
	HANDLE   hdisk = NULL;

	resl = ST_OK;

	do
	{
		hdisk = CreateFile(disk, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (hdisk == INVALID_HANDLE_VALUE) {
			hdisk = NULL;
			resl = ST_ACCESS_DENIED; break;
		}

		succs = DeviceIoControl(hdisk, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, ptix, sizeof(*ptix), &bytes, NULL);
		if (succs == 0) {
			resl = ST_ERROR; break;
		}

	} while (0);

	if (hdisk != NULL) {
		CloseHandle(hdisk);
	}
	return resl;
}

/*int dc_get_disk_guid(wchar_t* path, char* guid)
{
	int      resl;
	wchar_t  disk[MAX_PATH];

	_snwprintf(disk, countof(disk), L"\\\\?\\GLOBALROOT%s", path);

	do
	{
		resl = dc_get_part_info(disk);
		if(resl != ST_OK) break;

		if (pti.PartitionStyle != PARTITION_STYLE_GPT) {
			resl = ST_INV_FORMAT; break;
		}

		sprintf(guid,"%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX", 
		  pti.Gpt.PartitionId.Data1, pti.Gpt.PartitionId.Data2, pti.Gpt.PartitionId.Data3, 
		  pti.Gpt.PartitionId.Data4[0], pti.Gpt.PartitionId.Data4[1], pti.Gpt.PartitionId.Data4[2], pti.Gpt.PartitionId.Data4[3],
		  pti.Gpt.PartitionId.Data4[4], pti.Gpt.PartitionId.Data4[5], pti.Gpt.PartitionId.Data4[6], pti.Gpt.PartitionId.Data4[7]);

	} while (0);

	return resl;
}

int dc_get_disk_guid_by_id(unsigned long disk_id, char* guid)
{
	int      resl;
	vol_inf  info;

	resl = dc_first_volume(&info);
	if(resl == ST_OK)
	{
		resl = ST_NF_DEVICE;
		do {
			if (info.status.disk_id == disk_id) {	
				resl = dc_get_disk_guid(info.device, guid);
				break;
			}
		} while (dc_next_volume(&info) == ST_OK);
	}

	return resl;
}

int dc_get_disk_id_by_guid(char* guid, unsigned long *disk_id)
{
	int      resl;
	vol_inf  info;
	char disk_guid[36 + 1] = { 0 };

	resl = dc_first_volume(&info);
	if(resl == ST_OK)
	{
		resl = ST_NF_DEVICE;
		do {
			dc_get_disk_guid(info.device, disk_guid);
			if (strcmpi(guid, disk_guid) == 0) {	
				*disk_id = info.status.disk_id;
				resl = ST_OK;
				break;
			}
		} while (dc_next_volume(&info) == ST_OK);
	}

	return resl;
}*/

void dc_efi_config_store(STRING* newConfig, char* configContent, DWORD size, ldr_config* conf, const wchar_t* root)
{
	XmlWriteHeader(newConfig);
	StrAppend(newConfig, "\n\t<configuration>");

// Main:
	// Keyboard Layout
		// QWERTY	0
		// QWERTZ	1
		// AZERTY	2
	WriteConfigInteger(newConfig, configContent, "KeyboardLayout", conf->kbd_layout);

	// Header KDF
	WriteConfigInteger(newConfig, configContent, "HeaderKDF", conf->header_kdf);

	// Keyfile Mixer
	WriteConfigInteger(newConfig, configContent, "KeyfileMixer", conf->keyfile_mixer);

	// Booting Method
		// First disk MBR								// BT_MBR_FIRST    2
		// First partition with appropriate password	// BT_AP_PASSWORD  4
		// Specified partition							// BT_DISK_ID      5
		// (Boot disk MBR)								// BT_MBR_BOOT     1 // default
		// (Active partition)							// BT_ACTIVE       3 // not supported in EFI mode
	WriteConfigInteger(newConfig, configContent, "BootMode", conf->boot_type);
	if (conf->boot_type == LDR_BT_DISK_ID) {
		WriteConfigInteger64(newConfig, configContent, "BootDiskID", conf->disk_id);
	}
	/*char disk_guid[36 + 1] = { 0 };
	resl = dc_get_disk_guid_by_id(conf->disk_id, disk_guid);
	if (resl != ST_OK) break;
	WriteConfigString(newConfig, configContent, "BootPartition", disk_guid); // boot partition guid without brackets*/

// Authentication:
	WriteConfigInteger(newConfig, configContent, "AutoLogin", (conf->logon_type & LDR_LT_GET_PASS) ? 0 : 1);
	
	//WriteConfigString(newConfig, configContent, "AutoPassword", "");

	
	if (is_all_zeros(conf->emb_key, sizeof(conf->emb_key)))
	{
		WriteConfigString(newConfig, configContent, "KeyFilePath", ""); // empty string -> no key file
	}
	else if (root)
	{
		const char keyPath[] = "\\EFI\\DCS\\KeyFile.bin";
		WriteConfigString(newConfig, configContent, "KeyFilePath", keyPath);

		wchar_t fullPath[MAX_PATH];
		swprintf_s(fullPath, MAX_PATH, L"%s%S", root, keyPath);

		save_file(fullPath, conf->emb_key, sizeof(conf->emb_key));
	}

	if (conf->logon_type & LDR_LT_EMBED_KEY)
		WriteConfigInteger(newConfig, configContent, "UseKeyFile", 1);
	else if (conf->logon_type & LDR_LT_USB_KEY)
		WriteConfigInteger(newConfig, configContent, "UseKeyFile", 2);
	else 
		WriteConfigInteger(newConfig, configContent, "UseKeyFile", 0);
	
	// Picture Password
	WriteConfigInteger(newConfig, configContent, "TouchInput", (conf->logon_type & LDR_LT_USE_OSK) ? 1 : 0);
	//WriteConfigString(newConfig, configContent, "PasswordPicture", "\\EFI\\DCS\\login.bmp"); // h1630 v1090
	//WriteConfigString(newConfig, configContent, "PictureChars", ); // leave default
	//WriteConfigInteger(newConfig, configContent, "AuthorizeVisible", 0);		// show chars
	//WriteConfigInteger(newConfig, configContent, "PasswordHideLetters", 1);	// always show letters in touch points
	//WriteConfigInteger(newConfig, configContent, "AuthorizeMarkTouch", 1);	// show touch points

	// Password Prompt Message
	WriteConfigString(newConfig, configContent, "PasswordMsg", (conf->logon_type & LDR_LT_MESSAGE) ? conf->eps_msg  : "");

	// Display Entered Password * or hide completly
	WriteConfigInteger(newConfig, configContent, "AuthorizeProgress", (conf->logon_type & LDR_LT_DSP_PASS) ? 1 : 0);

	// Authentication TimeOut
	WriteConfigInteger(newConfig, configContent, "PasswordTimeout", conf->timeout); // s, 0 -> no timeout
	//																 (conf->options & LDR_OP_EPS_TMO) // timeout enabled
	//																 (conf->options & LDR_OP_TMO_STOP) // DCS always behaves this way
		
	// Trying password message
	WriteConfigString(newConfig, configContent, "AuthStartMsg", (conf->options & LDR_OP_AUTH_MSG) ? conf->ago_msg : "");

	// Success message
	WriteConfigString(newConfig, configContent, "AuthSuccessMsg", (conf->options & LDR_OP_OK_MSG) ? conf->aok_msg : "");

// Invalid Password:
	// use incorrect action if no password entered [ ]
	WriteConfigInteger(newConfig, configContent, "FailOnTimeout", (conf->options & LDR_OP_NOPASS_ERROR) ? 1 : 0);

	// Invalid Password message
	WriteConfigString(newConfig, configContent, "AuthFailedMsg", (conf->error_type & LDR_ET_MESSAGE) ? conf->err_msg : "");

	// Invalid Password action			ConfigReadString("ActionFailed", ...
		// Halt system					"halt"      EFI_DCS_HALT_REQUESTED
		// Reboot system				"reboot"    EFI_DCS_REBOOT_REQUESTED
		// Boot from active partition	"cancel"	EFI_DCS_USER_CANCELED
		// Exit to Firmware				"continue"	
		// Retry authentication			"exit"  &&  gDCryptAuthRetry > 0; else gDCryptAuthRetry == 0;
		// Load Boot Disk MBR			"cancel"	EFI_DCS_USER_CANCELED
		//								"shutdown"  EFI_DCS_SHUTDOWN_REQUESTED

	if (conf->error_type & LDR_ET_REBOOT) 
		WriteConfigString(newConfig, configContent, "ActionFailed", "Reboot");
	else if (conf->error_type & LDR_ET_MBR_BOOT) 
		WriteConfigString(newConfig, configContent, "ActionFailed", "Cancel");
	else if (conf->error_type & LDR_ET_RETRY)
		WriteConfigString(newConfig, configContent, "ActionFailed", "Exit");
	else if (conf->error_type & LDR_ET_EXIT_TO_BIOS)
		WriteConfigString(newConfig, configContent, "ActionFailed", "Exit");
	else if((conf->error_type & 0x3E) == 0)
		WriteConfigString(newConfig, configContent, "ActionFailed", "Halt");

	// Authentication Tries
	WriteConfigInteger(newConfig, configContent, "AuthorizeRetry", (conf->error_type & LDR_ET_RETRY) ? 100 : 0);

// Other

	WriteConfigInteger(newConfig, configContent, "BlockUnencryptedVolumes", (conf->options & LDR_OP_BLOCK_UNENC) ? 1 : 0);

	WriteConfigInteger(newConfig, configContent, "UseHardwareCrypto", (conf->options & LDR_OP_HW_CRYPTO) ? 1 : 0);

	WriteConfigInteger(newConfig, configContent, "VerboseDebug", (conf->options & LDR_OP_DEBUG) ? 1 : 0);

//

	// Write unmodified values
	char* xml = configContent;
	char key[128], value[2048];
	while (xml && (xml = XmlFindElement(xml, "config")))
	{
		XmlGetAttributeText(xml, "key", key, sizeof(key));
		XmlGetNodeText(xml, value, sizeof(value));

		StrAppend(newConfig, "\n\t\t<config key=\"");
		StrAppend(newConfig, key);
		StrAppend(newConfig, "\">");
		StrAppend(newConfig, value);
		StrAppend(newConfig, "</config>");

		xml++;
	}

	StrAppend(newConfig, "\n\t</configuration>");
	XmlWriteFooter(newConfig);
}

int dc_efi_config_write(const wchar_t* root, ldr_config *conf)
{
	int      resl = ST_OK;
	wchar_t  fileName[MAX_PATH];
	wchar_t  tempName[MAX_PATH];
	DWORD    size = 0;
	char*    configContent = NULL;
	STRING   newConfig = {0};

	swprintf_s(fileName, MAX_PATH, L"%s%s", root, dcs_conf_file);
	swprintf_s(tempName, MAX_PATH, L"%s%s.tmp", root, dcs_conf_file);

	do
	{
		load_file(fileName, &configContent, &size);

		dc_efi_config_store(&newConfig, configContent, size, conf, root);

		resl = save_file(tempName, newConfig.str, newConfig.len);

	} while (0);

	if (configContent != NULL){
		free(configContent);
	}

	if (newConfig.str != NULL){
		free(newConfig.str);
	}

	// only commite the file when all changed were writen successfully
	if (resl == ST_OK) { 
		DeleteFile(fileName);
		if (!MoveFile(tempName, fileName)) {
			resl = ST_RW_ERR;
		}
	}

	return resl;
}

void dc_efi_config_load(char* configContent, DWORD size, ldr_config* conf, const wchar_t* root)
{
	char     buffer[1024];

// Main:
	// Keyboard Layout
		// QWERTY	0
		// QWERTZ	1
		// AZERTY	2
	conf->kbd_layout = ReadConfigInteger(configContent, "KeyboardLayout", 0);

	// Header KDF
	conf->header_kdf = ReadConfigInteger(configContent, "HeaderKDF", KDF_DEFAULT);

	// Keyfile Mixer
	conf->keyfile_mixer = ReadConfigInteger(configContent, "KeyfileMixer", KEYFILE_MIX_HASHED);

	// Booting Method
		// First disk MBR								// BT_MBR_FIRST    2
		// First partition with appropriate password	// BT_AP_PASSWORD  4
		// Specified partition							// BT_DISK_ID      5
		// (Boot disk MBR)								// BT_MBR_BOOT     1 // default
		// (Active partition)							// BT_ACTIVE       3 // not supported in EFI mode
	conf->boot_type = ReadConfigInteger(configContent, "BootMode", 1);
	conf->disk_id = (ULONG)ReadConfigInteger64(configContent, "BootDiskID", 0);
	/*char disk_guid[36 + 1] = { 0 };
	ReadConfigString(configContent, "BootPartition", "", disk_guid, sizeof(disk_guid));
	resl = dc_get_disk_id_by_guid(disk_guid, &conf->disk_id);
	if (resl != ST_OK) break;*/

// Authentication:
	if (ReadConfigInteger(configContent, "AutoLogin", 0) == 0) {
		conf->logon_type |= LDR_LT_GET_PASS;
	}

	//ReadConfigString(configContent, "AutoPassword", "", buffer, sizeof(buffer));

	ReadConfigString(configContent, "KeyFilePath", "", buffer, sizeof(buffer));
	if (root && strlen(buffer) > 0) 
	{
		wchar_t fullPath[MAX_PATH];
		swprintf_s(fullPath, MAX_PATH, L"%s%S", root, buffer);

		u8* keyfile;
		u32 keysize;
		if (load_file(fullPath, &keyfile, &keysize) == ST_OK)
		{
			if (keysize == sizeof(conf->emb_key)) {
				memcpy(conf->emb_key, keyfile, sizeof(conf->emb_key));
			}

			burn(keyfile, keysize);
			free(keyfile);
		}
	}

	if (ReadConfigInteger(configContent, "UseKeyFile", 0) == 1) {
		conf->logon_type |= LDR_LT_EMBED_KEY;
	} else if (ReadConfigInteger(configContent, "UseKeyFile", 0) == 2) {
		conf->logon_type |= LDR_LT_USB_KEY;
	}

	// Picture Password
	if (ReadConfigInteger(configContent, "TouchInput", 0)) {
		conf->logon_type |= LDR_LT_USE_OSK;
	}
	//WriteConfigString(configFile, configContent, "PasswordPicture", "\\EFI\\DCS\\login.bmp"); // h1630 v1090
	//WriteConfigString(configFile, configContent, "PictureChars", ); // leave default
	//WriteConfigInteger(configFile, configContent, "AuthorizeVisible", 0);		// show chars
	//WriteConfigInteger(configFile, configContent, "PasswordHideLetters", 0);	// always show letters in touch points
	//WriteConfigInteger(configFile, configContent, "AuthorizeMarkTouch", 0);		// show touch points

	// Password Prompt Message
	ReadConfigString(configContent, "PasswordMsg", "Enter password:", buffer, sizeof(buffer));
	if (strlen(buffer) > 0) {
		strcpy(conf->eps_msg, buffer);
		conf->logon_type |= LDR_LT_MESSAGE;
	}

	// Display Entered Password * or hide completly
	if (ReadConfigInteger(configContent, "AuthorizeProgress", 0)) {
		conf->logon_type |= LDR_LT_DSP_PASS;
	}

	// Authentication TimeOut
	conf->timeout = ReadConfigInteger(configContent, "PasswordTimeout", 180);
	if (conf->timeout != 0) {
		conf->options |= LDR_OP_EPS_TMO; // timeout enabled
		conf->options |= LDR_OP_TMO_STOP; // DCS always behaves this way
	}

	// Trying password message
	ReadConfigString(configContent, "AuthStartMsg", "Authorizing...", buffer, sizeof(buffer));
	if (strlen(buffer) > 0) {
		strcpy(conf->ago_msg, buffer);
		conf->options |= LDR_OP_AUTH_MSG;
	}

	// Success message
	ReadConfigString(configContent, "AuthSuccessMsg", "Password correct", buffer, sizeof(buffer));
	if (strlen(buffer) > 0) {
		strcpy(conf->aok_msg, buffer);
		conf->options |= LDR_OP_OK_MSG;
	}

// Invalid Password:
	// use incorrect action if no password entered [ ]
	if (ReadConfigInteger(configContent, "FailOnTimeout", 0)) {
		conf->options |= LDR_OP_NOPASS_ERROR;
	}

	// Invalid Password message
	ReadConfigString(configContent, "AuthFailedMsg", "Password incorrect", buffer, sizeof(buffer));
	if (strlen(buffer) > 0) {
		strcpy(conf->err_msg, buffer);
		conf->error_type |= LDR_ET_MESSAGE;
	}

	// Invalid Password action			ConfigReadString("ActionFailed", ...
		// Halt system					"halt"      EFI_DCS_HALT_REQUESTED
		// Reboot system				"reboot"    EFI_DCS_REBOOT_REQUESTED
		// Boot from active partition
		// Exit to BIOS
		// Retry authentication			"exit"  &&  gDCryptAuthRetry > 0; else gDCryptAuthRetry == 0;
		// Load Boot Disk				"cancel"	EFI_DCS_USER_CANCELED
		//								"shutdown"  EFI_DCS_SHUTDOWN_REQUESTED
	ReadConfigString(configContent, "ActionFailed", "exit", buffer, sizeof(buffer));
	if (_strcmpi(buffer, "Reboot") == 0)
		conf->error_type |= LDR_ET_REBOOT;
	else if (_strcmpi(buffer, "Cancel") == 0)
		conf->error_type |= LDR_ET_MBR_BOOT;
	else if (_strcmpi(buffer, "Exit") == 0)
		conf->error_type |= LDR_ET_EXIT_TO_BIOS;
	//else if(_strcmpi(buffer, "Exit") == 0)
	//	conf->error_type |= LDR_ET_RETRY;
	//else if(_strcmpi(buffer, "Halt") == 0)
	//	conf->error_type |= 0;

	// Authentication Tries
	if (ReadConfigInteger(configContent, "AuthorizeRetry", 100)) {
		conf->error_type |= LDR_ET_RETRY;
	}

// Other

	if (ReadConfigInteger(configContent, "BlockUnencryptedVolumes", 0)) {
		conf->options |= LDR_OP_BLOCK_UNENC;
	}

	if (ReadConfigInteger(configContent, "UseHardwareCrypto", 1)) {
		conf->options |= LDR_OP_HW_CRYPTO;
	}

	if (ReadConfigInteger(configContent, "VerboseDebug", 0)) {
		conf->options |= LDR_OP_DEBUG;
	}
		
//
}

int dc_efi_config_read(const wchar_t* root, ldr_config *conf)
{
	int      resl = ST_OK;
	wchar_t  fileName[MAX_PATH];
	DWORD    size = 0;
	char*    configContent = NULL;

	memset(conf, 0, sizeof(*conf));

	swprintf_s(fileName, MAX_PATH, L"%s%s", root, dcs_conf_file);

	do
	{
		resl = load_file(fileName, &configContent, &size);
		if (resl != ST_OK) break;

		conf->ldr_ver = dc_get_dcs_version(root);
		
		dc_efi_config_load(configContent, size, conf, root);

	} while (0);

	if (configContent) {
		free(configContent);
	}
	return resl;
}

int dc_efi_config_by_partition(const wchar_t *root, int set_conf, ldr_config *conf)
{
	int      resl;
	wchar_t  path[MAX_PATH] = { 0 };

	if (root[0] != L'\\')
		_snwprintf(path, countof(path), L"\\\\.\\%c:", root[0]);
	else 
		wcsncpy(path, root, countof(path));

	if (set_conf)
		resl = dc_efi_config_write(path, conf);
	else
		resl = dc_efi_config_read(path, conf);

	return resl;
}

typedef struct _ldr_version {
	unsigned long sign1;         // signature to search for bootloader in memory
	unsigned long sign2;         // signature to search for bootloader in memory
	unsigned long ldr_ver;       // bootloader version
} ldr_version;

static ldr_version *dc_find_efi_ver(char *data, int size)
{
	ldr_version *cnf;
	ldr_version *conf = NULL;

	for (; size > sizeof(ldr_version); size--, data++)
	{
		cnf = pv(data);

		if ( (cnf->sign1 == LDR_CFG_SIGN1) && (cnf->sign2 == LDR_CFG_SIGN2) ) {
			conf = cnf;	
			break;
		}
	}

	return conf;
}

static char *dc_find_in_memory(char *data, int size, const void* str, int len)
{
	char* temp;
	char* conf = NULL;

	for (; size > len; size--, data++)
	{
		temp = pv(data);

		if ( memcmp(temp, str, len) == 0 ) {
			conf = temp;
			break;
		}
	}

	return conf;
}

static int dc_get_embedded_config(wchar_t* file, ldr_config* conf)
{
	int      resl;
	int      ver = 0;
	int      size = 0;
	char*    data = NULL;
	size_t   img_size = 0;
	char*    img_data = NULL;
	size_t   prop_size = 0;
	char*    prop_data = NULL;
	ldr_version *cnf = NULL;

	memset(conf, 0, sizeof(*conf));

	do
	{
		resl = load_file(file, &data, &size);
		if (resl != ST_OK) break;

		resl = get_iso_file(data, size, dc_dcs_img_file, &img_data, &img_size);
		if (resl != ST_OK) break;

		if ((cnf = dc_find_efi_ver(img_data, (int)img_size)) != NULL)
			conf->ldr_ver = cnf->ldr_ver;

		resl = get_fat_file(img_data, img_size, dcs_conf_file, &prop_data, &prop_size);
		if (resl != ST_OK) break;

		dc_efi_config_load(prop_data, (DWORD)prop_size, conf, NULL);
	}
	while(0);

	if (data) {
		free(data);
	}

	return resl;
}

static int dc_set_embedded_config(wchar_t* file, ldr_config* conf)
{
	int      resl;
	int      ver = 0;
	int      size = 0;
	char*    data = NULL;
	size_t   img_size = 0;
	char*    img_data = NULL;
	size_t   prop_size = 0;
	char*    prop_data = NULL;
	STRING   newConfig = {0};

	do
	{
		resl = load_file(file, &data, &size);
		if (resl != ST_OK) break;

		resl = get_iso_file(data, size, dc_dcs_img_file, &img_data, &img_size);
		if (resl != ST_OK) break;

		resl = get_fat_file(img_data, img_size, dcs_conf_file, &prop_data, &prop_size);
		if (resl != ST_OK) break;

		dc_efi_config_store(&newConfig, prop_data, (DWORD)prop_size, conf, NULL);

		memset(prop_data, '    ', prop_size);
		strcpy(prop_data, newConfig.str);

		resl = save_file(file, data, size);
	}
	while(0);

	if (data) {
		free(data);
	}

	return resl;
}

int dc_is_dir(wchar_t* path)
{
	DWORD attrs = GetFileAttributes(path);
	BOOL is_directory = (attrs != INVALID_FILE_ATTRIBUTES) && (attrs & FILE_ATTRIBUTE_DIRECTORY);
	return is_directory;
}

int dc_get_efi_config(int dsk_num, wchar_t *file, ldr_config *conf)
{
	int      resl;
	wchar_t  path[MAX_PATH] = { 0 };

	if (file) {
		if(dc_is_dir(file))
			resl = dc_efi_config_read(file, conf);
		else
			resl = dc_get_embedded_config(file, conf);
	}
	else if ((resl = dc_efi_get_sys_part(dsk_num, -1, path)) == ST_OK)
		resl = dc_efi_config_by_partition(path, FALSE, conf);

	return resl;
}

int dc_set_efi_config(int dsk_num, wchar_t* file, ldr_config* conf)
{
	int      resl;
	wchar_t  path[MAX_PATH] = { 0 };

	if (file) {
		if(dc_is_dir(file))
			resl = dc_efi_config_write(file, conf);
		else
			resl = dc_set_embedded_config(file, conf);
	}
	else if ((resl = dc_efi_get_sys_part(dsk_num, -1, path)) == ST_OK)
		resl = dc_efi_config_by_partition(path, TRUE, conf);

	return resl;
}

int dc_get_dcs_version(const wchar_t *root)
{
	int      ver = 0;
	DWORD    size = 0;
	char*    data = NULL;
	ldr_version *cnf = NULL;

	if (dc_load_efi_file(root, dcs_files[1].target, &data, &size) == ST_OK)
	{
		/* find bootloader version */
		if ((cnf = dc_find_efi_ver(data, size)) != NULL)
			ver = cnf->ldr_ver;
		free(data);
	}

	return ver;
}

void dc_efi_config_init(ldr_config *conf)
{
	static ldr_config def_conf = {
		0, 0, // no signature
		DC_UEFI_VER,
		LDR_LT_GET_PASS | LDR_LT_MESSAGE | LDR_LT_DSP_PASS,
		LDR_ET_MESSAGE | LDR_ET_RETRY,
		LDR_BT_MBR_BOOT,
		0,     /* disk id */
		LDR_OP_HW_CRYPTO,  /* options */
		LDR_KB_QWERTY,     /* keyboard layout */
		"Enter password:",
		"Password incorrect",
		{ 0 }, /* original mbr */
		0,     /* timeout */
		{ 0 },  /* embedded key */

		"Authorizing...",
		"Password correct",

		KDF_DEFAULT,
		KEYFILE_MIX_HASHED,

		{ 0 } /*reserved*/
	};

	memcpy(conf, &def_conf, sizeof(ldr_config));
}

int dc_efi_shim_available()
{
	TCHAR	source_path[MAX_PATH], *p;
	DWORD	length;

	DC_FLAGS flags;
	if (dc_device_control(DC_CTL_GET_FLAGS, NULL, 0, &flags, sizeof(flags)) == NO_ERROR && !(flags.load_flags & DST_PRO_ENABLED)) {
		return 0; // pro features are not enabled
	}

	if (g_inst_dll == NULL || (length = GetModuleFileName(g_inst_dll, source_path, _countof(source_path))) == 0) return 0;
	if (length >= _countof(source_path) - 1 || (p = wcsrchr(source_path, '\\')) == NULL) return 0;
	if (wcscpy_s(p + 1, _countof(source_path) - (p - source_path) - 1, shim_zip_file) != 0) return 0;

	if (_waccess(source_path, 0) != -1)
		return 1; // unpacked shim avaialble

	if (wcscat_s(source_path, _countof(source_path), L".zip") != 0) return 0;
	if (_waccess(source_path, 0) != -1)
		return 1; // packed shim avaialble

	return 0;
}

int dc_is_shim_on_partition(const wchar_t *root)
{
	return dc_efi_file_exists(root, shim_files[0].target);
}

int dc_efi_is_shim_set(int dsk_num)
{
	wchar_t  root[MAX_PATH] = { 0 };
	if(dc_efi_get_sys_part(dsk_num, -1, root) == ST_OK)
		return dc_is_shim_on_partition(root);
	return 0;
}

int dc_is_dcs_on_partition(const wchar_t *root)
{
	return dc_efi_file_exists(root, dcs_files[0].target);
}

int dc_is_dcs_on_disk(int dsk_num)
{
	wchar_t  root[MAX_PATH] = { 0 };
	if(dc_efi_get_sys_part(dsk_num, -1, root) == ST_OK)
		return dc_is_dcs_on_partition(root);
	return 0;
}

int dc_efi_is_msft_on_disk(int dsk_num)
{
	wchar_t  root[MAX_PATH] = { 0 };
	if (dc_efi_get_sys_part(dsk_num, -1, root) == ST_OK)
		return dc_efi_file_exists(root, msft_boot_file);
	return 0;
}

int dc_is_dcs_in_file(wchar_t* file)
{
	int      resl;
	DWORD    size = 0;
	char*    data = NULL;
	size_t    lbl_size = 0;
	char*    lbl_data = NULL;

	if (dc_is_dir(file))
	{
		resl = dc_efi_file_exists(file, dcs_files[0].target);
	}
	else
	{
		resl = load_file(file, &data, &size);
		if (resl != ST_OK) return 0;

		resl = get_iso_label(data, size, &lbl_data, &lbl_size);
		if (resl != ST_OK) return 0;

		resl = _memicmp(lbl_data, dc_dcs_iso_label, lbl_size) ? 0 : 1;

		free(data);
	}

	return resl;
}

int dc_efi_set_bme_impl(wchar_t* description, PPARTITION_INFORMATION_EX partInfo, wchar_t* execPath, int setBootEntry, int forceFirstBootEntry, int setBootNext, UINT16 statrtOrderNum, wchar_t* type, UINT32 attr)
{
	if (partInfo != NULL)
	{
		UINT32 varSize = 56;
		varSize += ((UINT32)wcslen(description)) * 2 + 2;
		varSize += ((UINT32)wcslen(execPath)) * 2 + 2;
		byte *startVar = malloc(varSize);
		byte *pVar = startVar;

		// Attributes (1b Active, 1000b - Hidden)
		*(UINT32 *)pVar = attr;
		pVar += sizeof(UINT32);

		// Size Of device path + file path
		*(UINT16 *)pVar = (UINT16)(50 + wcslen(execPath) * 2 + 2);
		pVar += sizeof(UINT16);

		// description
		for (UINT32 i = 0; i < wcslen(description); i++) {
			*(UINT16 *)pVar = description[i];
			pVar += sizeof(UINT16);
		}
		*(UINT16 *)pVar = 0;
		pVar += sizeof(UINT16);

		/* EFI_DEVICE_PATH_PROTOCOL (HARDDRIVE_DEVICE_PATH \ FILE_PATH \ END) */

		// Type
		*(byte *)pVar = 0x04;
		pVar += sizeof(byte);

		// SubType
		*(byte *)pVar = 0x01;
		pVar += sizeof(byte);

		// HDD dev path length
		*(UINT16 *)pVar = 0x2A; // 42
		pVar += sizeof(UINT16);

		// PartitionNumber
		*(UINT32 *)pVar = (UINT32)partInfo->PartitionNumber;
		pVar += sizeof(UINT32);

		// PartitionStart
		*(UINT64 *)pVar = partInfo->StartingOffset.QuadPart >> 9;
		pVar += sizeof(UINT64);

		// PartitiontSize
		*(UINT64 *)pVar = partInfo->PartitionLength.QuadPart >> 9;
		pVar += sizeof(UINT64);

		// GptGuid
		memcpy(pVar, &partInfo->Gpt.PartitionId, 16);
		pVar += 16;

		// MbrType
		*(byte *)pVar = 0x02;
		pVar += sizeof(byte);

		// SigType
		*(byte *)pVar = 0x02;
		pVar += sizeof(byte);

		// Type and sub type 04 04 (file path)
		*(UINT16 *)pVar = 0x0404;
		pVar += sizeof(UINT16);

		// SizeOfFilePath ((CHAR16)FullPath.length + sizeof(EndOfrecord marker) )
		*(UINT16 *)pVar = (UINT16)(wcslen(execPath) * 2 + 2 + sizeof(UINT32));
		pVar += sizeof(UINT16);

		// FilePath
		for (UINT32 i = 0; i < wcslen(execPath); i++) {
			*(UINT16 *)pVar = execPath[i];
			pVar += sizeof(UINT16);
		}
		*(UINT16 *)pVar = 0;
		pVar += sizeof(UINT16);

		// EndOfrecord
		*(UINT32 *)pVar = 0x04ff7f;
		pVar += sizeof(UINT32);

		// Set variable
		wchar_t	varName[256];
		swprintf_s(varName, ARRAYSIZE(varName), L"%s%04X", type == NULL ? L"Boot" : type, statrtOrderNum);

		// only set value if it doesn't already exist
		byte* existingVar = malloc(varSize);
		DWORD existingVarLen = GetFirmwareEnvironmentVariableW(varName, efi_var_guid, existingVar, varSize);
		if ((existingVarLen != varSize) || (0 != memcmp(existingVar, startVar, varSize)))
			SetFirmwareEnvironmentVariableW(varName, efi_var_guid, startVar, varSize);
		free(startVar);
		free(existingVar);
	}

	// Update order
	WCHAR order[64];
	wsprintf(order, L"%sOrder", type == NULL ? L"Boot" : type);
	WCHAR tempBuf[1024];

	UINT32 startOrderLen = GetFirmwareEnvironmentVariableW(order, efi_var_guid, tempBuf, sizeof(tempBuf));
	UINT32 startOrderNumPos = UINT_MAX;
	int	startOrderUpdate = 0;
	UINT16*	startOrder = (UINT16*)tempBuf;
	for (UINT32 i = 0; i < startOrderLen / 2; i++) {
		if (startOrder[i] == statrtOrderNum) {
			startOrderNumPos = i;
			break;
		}
	}

	if (setBootEntry)
	{
		// check if first entry in BootOrder is Windows one
		int bFirstEntryIsWindows = 0;
		if (startOrderNumPos != 0)
		{
			wchar_t	varName[256];
			swprintf_s(varName, ARRAYSIZE(varName), L"%s%04X", type == NULL ? L"Boot" : type, startOrder[0]);

			byte* existingVar = malloc(512);
			DWORD existingVarLen = GetFirmwareEnvironmentVariableW(varName, efi_var_guid, existingVar, 512);
			if (existingVarLen > 0)
			{
				if (dc_buffer_contains_wide_string(existingVar, existingVarLen, msft_boot_file + 1)) // +1 skip first '\' just in case
					bFirstEntryIsWindows = 1;
			}

			free(existingVar);
		}

		// Create new entry if absent
		if (startOrderNumPos == UINT_MAX) {
			if (partInfo != NULL)
			{
				if (forceFirstBootEntry && bFirstEntryIsWindows)
				{
					for (UINT32 i = startOrderLen / 2; i > 0; --i) {
						startOrder[i] = startOrder[i - 1];
					}
					startOrder[0] = statrtOrderNum;
				}
				else
				{
					startOrder[startOrderLen / 2] = statrtOrderNum;
				}
				startOrderLen += 2;
				startOrderUpdate = 1;
			}
		}
		else if ((startOrderNumPos > 0) && forceFirstBootEntry && bFirstEntryIsWindows) {
			for (UINT32 i = startOrderNumPos; i > 0; --i) {
				startOrder[i] = startOrder[i - 1];
			}
			startOrder[0] = statrtOrderNum;
			startOrderUpdate = 1;
		}

		if (startOrderUpdate) {
			SetFirmwareEnvironmentVariableW(order, efi_var_guid, startOrder, startOrderLen);
		}
	}

	if (setBootNext)
	{
		// set BootNext value
		WCHAR next[64];
		wsprintf(next, L"%sNext", type == NULL ? L"Boot" : type);

		SetFirmwareEnvironmentVariableW(next, efi_var_guid, &statrtOrderNum, 2);
	}

	return ST_OK;
}

int dc_efi_del_bme_impl(UINT16 statrtOrderNum, wchar_t* type)
{
	wchar_t	varName[256];
	swprintf_s(varName, ARRAYSIZE(varName), L"%s%04X", type == NULL ? L"Boot" : type, statrtOrderNum);
	SetFirmwareEnvironmentVariableW(varName, efi_var_guid, NULL, 0);

	WCHAR order[64];
	wsprintf(order, L"%sOrder", type == NULL ? L"Boot" : type);
	WCHAR tempBuf[1024];

	UINT32 startOrderLen = GetFirmwareEnvironmentVariableW(order, efi_var_guid, tempBuf, sizeof(tempBuf));
	UINT32 startOrderNumPos = UINT_MAX;
	int	startOrderUpdate = 0;
	UINT16*	startOrder = (UINT16*)tempBuf;
	for (UINT32 i = 0; i < startOrderLen / 2; i++) {
		if (startOrder[i] == statrtOrderNum) {
			startOrderNumPos = i;
			break;
		}
	}

	// delete entry if present
	if (startOrderNumPos != UINT_MAX) {
		for (UINT32 i = startOrderNumPos; i < ((startOrderLen / 2) - 1); ++i) {
			startOrder[i] = startOrder[i + 1];
		}
		startOrderLen -= 2;
		startOrderUpdate = 1;
	}

	if (startOrderUpdate) {
		SetFirmwareEnvironmentVariableW(order, efi_var_guid, startOrder, startOrderLen);

		// remove ourselves from BootNext value
		UINT16 bootNextValue = 0;
		WCHAR next[64];
		wsprintf(next, L"%sNext", type == NULL ? L"Boot" : type);

		if ((GetFirmwareEnvironmentVariableW(next, efi_var_guid, &bootNextValue, 2) == 2)
			&& (bootNextValue == statrtOrderNum)
			)
		{
			SetFirmwareEnvironmentVariableW(next, efi_var_guid, startOrder, 0);
		}
	}

	return ST_OK;
}

int dc_efi_set_bme_ex(wchar_t* description, int dsk_num, int setBootEntry, int forceFirstBootEntry, int setBootNext)
{
	int      resl;
	wchar_t  root[MAX_PATH] = { 0 };
	PARTITION_INFORMATION_EX ptix;
	wchar_t  execPath[MAX_PATH];

	do
	{
		resl = dc_efi_get_sys_part(dsk_num, -1, root);
		if (resl != ST_OK) break;

		if (!dc_is_dcs_on_partition(root)) {
			resl = ST_BLDR_NOTINST;
			break;
		}

		resl = dc_get_part_info(root, &ptix);
		if (resl != ST_OK) break;

		if (dc_is_shim_on_partition(root)) { // if shim is installed point the boot entry to the backup file as the original may get overwriten by windows updates
			wsprintf(execPath, L"%s", shim_files[0].target);
		}
		else { // point the boot entry to "\\EFI\\DCS\\DcsBoot.efi"
			wsprintf(execPath, L"%s", dcs_files[0].target);
		}

		resl = dc_efi_set_bme_impl(description, &ptix, execPath, setBootEntry, forceFirstBootEntry, setBootNext, LDR_DCS_ID, NULL, 1);

	} while (0);

	return resl;
}

int dc_efi_set_bme(wchar_t* description, int dsk_num)
{
	return dc_efi_set_bme_ex(description, dsk_num, 1, 1, 1);
}

int dc_efi_del_bme()
{
	return dc_efi_del_bme_impl(LDR_DCS_ID, NULL);
}

int dc_efi_find_bme(int dsk_num, UINT16 statrtOrderNum, wchar_t* type)
{
	int      resl;
	wchar_t  root[MAX_PATH] = { 0 };
	PARTITION_INFORMATION_EX ptix;

	do
	{
		resl = dc_efi_get_sys_part(dsk_num, -1, root);
		if (resl != ST_OK) break;

		resl = dc_get_part_info(root, &ptix);
		if (resl != ST_OK) break;

		resl = ST_NF_DEVICE;

		wchar_t	varName[256];
		swprintf_s(varName, ARRAYSIZE(varName), L"%s%04X", type == NULL ? L"Boot" : type, statrtOrderNum);

		byte* existingVar = malloc(512);
		DWORD existingVarLen = GetFirmwareEnvironmentVariableW(varName, efi_var_guid, existingVar, 512);
		if (existingVarLen > 0) {
			if (dc_buffer_contains_pattern(existingVar, existingVarLen, (byte*)&ptix.Gpt.PartitionId, 16)) {
				resl = ST_OK;
			}
		}

		free(existingVar);

	} while (0);

	return resl;
}

int dc_efi_is_bme_set(int dsk_num)
{
	return dc_efi_find_bme(dsk_num, LDR_DCS_ID, NULL) == ST_OK;
}

int dc_efi_del_msft_bme()
{
	WCHAR tempBuf[1024];
	UINT32 bootOrderLen;
	UINT16* bootOrder;
	UINT32 i;
	int resl = ST_NF_DEVICE;

	// Read the BootOrder variable
	bootOrderLen = GetFirmwareEnvironmentVariableW(L"BootOrder", efi_var_guid, tempBuf, sizeof(tempBuf));
	if (bootOrderLen == 0) {
		return ST_NF_DEVICE;
	}

	bootOrder = (UINT16*)tempBuf;

	// Iterate through all boot entries to find Windows Boot Manager
	for (i = 0; i < bootOrderLen / 2; i++) {
		wchar_t varName[256];
		byte* entryData;
		DWORD entryLen;

		swprintf_s(varName, ARRAYSIZE(varName), L"Boot%04X", bootOrder[i]);

		entryData = malloc(1024);
		if (entryData == NULL) {
			continue;
		}

		entryLen = GetFirmwareEnvironmentVariableW(varName, efi_var_guid, entryData, 1024);
		if (entryLen > 0) {
			// Check if this entry contains the Windows Boot Manager path
			if (dc_buffer_contains_wide_string(entryData, entryLen, msft_boot_file + 1)) { // +1 skip first '\'
				// Found Windows Boot Manager entry, delete it
				free(entryData);
				resl = dc_efi_del_bme_impl(bootOrder[i], NULL);
				break;
			}
		}
		free(entryData);
	}

	return resl;
}

#include "..\crc32.h"
//#ifdef _M_ARM64
//#include "xts_small.h"
//#include "sha512_pkcs5_2_small.h"
//#else
#include "xts_fast.h"
#include "sha512_pkcs5_2.h"
//#endif
#include "drvinst.h"

int dc_get_dcs_root(wchar_t* root)
{
	int      resl;
	vol_inf  info;

	// first try boot partition
	resl = dc_efi_get_sys_part(-1, -1, root);
	if (resl == ST_OK) {
		if (dc_is_dcs_on_partition(root))
			return ST_OK;
	}

	// if not found try looking on other media
	if (dc_first_volume(&info) == ST_OK)
	{
		do
		{
			swprintf_s(root, MAX_PATH, L"\\\\?%s", &info.device[7]);
			if (dc_is_dcs_on_partition(root))
				return ST_OK;
		} while (dc_next_volume(&info) == ST_OK);
	}
	
	return ST_BLDR_NOTINST;
}

int dc_prep_encrypt(const wchar_t* device, dc_pass* password, crypt_info* crypt, int flags)
{
	int      resl;
	wchar_t  root[MAX_PATH] = { 0 };
	wchar_t  path[MAX_PATH] = { 0 };

	dc_init_crypto();

	if ((resl = dc_get_dcs_root(root)) == ST_OK)
	{
		swprintf_s(path, MAX_PATH, L"%s%s_%s", root, dcs_test_file, &device[8]);

		xts_key*      header_key = NULL;
		//xts_key*      volume_key = NULL;
		dc_header*    header = NULL;
		UCHAR         salt[HEADER_SALT_SIZE], *dk = NULL;

		// allocate required memory
		if ( (header_key = (xts_key*)secure_alloc(sizeof(xts_key))) == NULL ||
			//(volume_key = (xts_key*)secure_alloc(sizeof(xts_key))) == NULL ||
			(dk = (PUCHAR)secure_alloc(DISKKEY_SIZE)) == NULL ||
			(header = (dc_header*)secure_alloc(sizeof(dc_header))) == NULL )
		{
			resl = ERROR_NOT_ENOUGH_MEMORY;
			goto cleanup;
		}

		// create the volume header
		memset((BYTE*)header, 0, sizeof(dc_header));

		if ( (resl = dc_device_control(DC_CTL_GET_RAND, NULL, 0, salt, HEADER_SALT_SIZE)) != NO_ERROR ) goto cleanup;
		if ( (resl = dc_device_control(DC_CTL_GET_RAND, NULL, 0, &header->disk_id, sizeof(header->disk_id))) != NO_ERROR ) goto cleanup;
		if ( (resl = dc_device_control(DC_CTL_GET_RAND, NULL, 0, header->key_1, sizeof(header->key_1))) != NO_ERROR ) goto cleanup;

		header->sign     = DC_VOLUME_SIGN;
		header->version  = DC_HDR_VERSION; // leave at v1 then CRC covers space
		header->flags    = VF_NO_REDIR | flags;
		header->alg_1    = crypt->cipher_id;
		header->data_off = sizeof(dc_header);
		
		header->head_kdf = password->kdf;

		memcpy(header->space, crypt, sizeof(crypt_info));

		header->hdr_crc  = calculate_header_crc_um(header);

		// derive the header key
		if (!dc_derive_key_um(password, password->kdf, salt, dk, NULL)) {
			resl = ST_ERROR;
			goto cleanup;
		}

		// initialize encryption keys
		//if (!xts_set_key(header->key_1, crypt->cipher_id, volume_key)) { resl = ST_INVALID_PARAM; goto cleanup; }
		if (!xts_set_key(dk, crypt->cipher_id, header_key)) { resl = ST_INVALID_PARAM; goto cleanup; }

		// encrypt the volume header
		xts_encrypt((const unsigned char*)header, (unsigned char*)header, sizeof(dc_header), 0, header_key);

		// save salt
		memcpy(header->salt, salt, HEADER_SALT_SIZE);

		// write volume header to output file
		resl = save_file(path, header, sizeof(dc_header));

	cleanup:
		if (header != NULL) secure_free(header);
		if (dk != NULL) secure_free(dk);
		//if (volume_key != NULL) secure_free(volume_key);
		if (header_key != NULL) secure_free(header_key);
	}

	return resl;
}

int dc_has_pending_header(const wchar_t* device)
{
	wchar_t  root[MAX_PATH] = { 0 };
	wchar_t  path[MAX_PATH];

	if (dc_get_dcs_root(root) == ST_OK)
	{
		swprintf_s(path, MAX_PATH, L"%s_%s", dcs_test_file, &device[8]);

		return dc_efi_file_exists(root, path);
	}

	return 0;
}

int dc_clear_pending_header(const wchar_t* device)
{
	int      resl;
	wchar_t  root[MAX_PATH] = { 0 };
	wchar_t  path[MAX_PATH];

	if ((resl = dc_get_dcs_root(root)) == ST_OK)
	{
		swprintf_s(path, MAX_PATH, L"%s_%s", dcs_test_file, &device[8]);

		resl = dc_delete_efi_file(root, path);
	}

	return resl;
}

int dc_get_pending_header_nt(const wchar_t* device, wchar_t* path)
{
	wchar_t  root[MAX_PATH] = { 0 };

	if (dc_get_dcs_root(root) == ST_OK)
	{
		// Convert user-mode path to NT path format: "\\?\" -> "\??\"
		if (wcsncmp(root, L"\\\\?\\", 4) == 0) {
			swprintf_s(path, MAX_PATH, L"\\??\\%s%s_%s", &root[4], dcs_test_file, &device[8]);
		} else {
			swprintf_s(path, MAX_PATH, L"%s%s_%s", root, dcs_test_file, &device[8]);
		}
		return ST_OK;
	}

	return ST_NF_FILE;
}

//
// Note: we only check if the dcs files have the right signer attached, not if the sugnature is actually valid
// we want to check if the files should be trusted according to UEFI Secure Boot DB, not if thay are not corrupted.
//

int dc_init_secureboot_db();
int dc_is_signer_allowed(const BYTE* hash);
int dc_extract_cert_from_file(const wchar_t* filePath, BYTE* thumbprint);
int dc_extract_cert_from_memory(const void* data, size_t size, BYTE* thumbprint);
//int dc_verify_file_signature(const wchar_t* filePath);
//int dc_verify_memory_signature(const void* data, size_t size);

static int dc_is_signable_file(const wchar_t* filename)
{
	const wchar_t* ext = wcsrchr(filename, L'.');
	if (ext == NULL) return 0;
	return (_wcsicmp(ext, L".efi") == 0 || _wcsicmp(ext, L".dcs") == 0);
}

static int dc_pkg_is_signed(const wchar_t *path, const efi_file_t* files, size_t count)
{
	int     resl;
	int     cur, idx = 0;
	wchar_t filePath[MAX_PATH];
	BYTE	thumbprint[20];

	resl = dc_init_secureboot_db();
	if (resl != ST_OK) return 0;

	for (int i = 0; i < count && resl == ST_OK; i++){
		
		if (!dc_is_signable_file(files[i].source)) {
			continue;
		}

		if (swprintf_s(filePath, MAX_PATH, L"%s%s", path, files[i].source) < 0) {
			return ST_NOMEM;
		}

		if (dc_extract_cert_from_file(filePath, thumbprint) == ST_OK) {
			cur = dc_is_signer_allowed(thumbprint);
			if (!cur)
				resl = ST_BL_NOT_PASSED; // Certificate not in UEFI DB
			else if (idx == 0)
				idx = cur; // return first files signer index
		}
		else {
			resl = ST_BL_NOT_PASSED; // Could not extract certificate
		}
		//resl = dc_verify_file_signature(filePath);
		if (resl != ST_OK) {
			break;
		}
	}

	if(resl != ST_OK)
		return 0;
	return idx;
}

static int dc_zip_is_signed(struct zip_t *zip, const efi_file_t* files, size_t count)
{
	int     resl;
	int     cur, idx = 0;
	void*   buffer = NULL;
	size_t  bufsize = 0;
	BYTE	thumbprint[20];

	resl = dc_init_secureboot_db();
	if (resl != ST_OK) return 0;

	for (int i = 0; i < count && resl == ST_OK; i++){

		if (!dc_is_signable_file(files[i].source)) {
			continue;
		}

		dc_zip_load_file(zip, files[i].source, &buffer, &bufsize);
		if (resl != ST_OK) break;

		if (dc_extract_cert_from_memory(buffer, bufsize, thumbprint) == ST_OK) {
			cur = dc_is_signer_allowed(thumbprint);
			if (!cur)
				resl = ST_BL_NOT_PASSED; // Certificate not in UEFI DB
			else if (idx == 0)
				idx = cur; // return first files signer index
		}
		else {
			resl = ST_BL_NOT_PASSED; // Could not extract certificate
		}
		//resl = dc_verify_memory_signature(buffer, bufsize);

		free(buffer);

		if (resl != ST_OK) {
			break;
		}
	}

	if(resl != ST_OK)
		return 0;
	return idx;
}

int dc_efi_dcs_is_signed()
{
	int     resl;
	struct zip_t *zip = NULL;
	TCHAR	source_path[MAX_PATH], *p;
	DWORD	length;
	int 	use_pkg;

	if (g_inst_dll == NULL || (length = GetModuleFileName(g_inst_dll, source_path, _countof(source_path))) == 0) return 0;
	if (length >= _countof(source_path) - 1 || (p = wcsrchr(source_path, '\\')) == NULL) return 0;
	if (wcscpy_s(p + 1, _countof(source_path) - (p - source_path) - 1, dcs_zip_file) != 0) return 0;
	use_pkg = dc_efi_file_exists(source_path, L"");
	if (use_pkg) {
		if (wcscat_s(source_path, _countof(source_path), L"\\") != 0) return 0;
	} else {
		if (wcscat_s(source_path, _countof(source_path), L".zip") != 0) return 0;
	}

	if (use_pkg)
	{
		resl = dc_pkg_is_signed(source_path, dcs_files, dcs_files_count);
	}
	else if (dc_open_zip(source_path, &zip) == ST_OK)
	{
		resl = dc_zip_is_signed(zip, dcs_files, dcs_files_count);

		zip_close(zip);
	}

	return resl;
}

static const wchar_t* dcs_cert_file = L"\\EFI\\DCS\\Certificate.dat";

// Forward declaration for registry certificate loading
int dc_load_certificate(WCHAR* certificate, size_t cert_size);

int dc_efi_update_cert(const wchar_t* cert)
{
	int resl = ST_OK;
	int dsk_num;
	wchar_t root[MAX_PATH];
	wchar_t* cert_buf = NULL;
	const wchar_t* cert_to_use = cert;
	int should_delete = FALSE;

	// Find disk with DCS installed
	dsk_num = dc_efi_get_os_disk();
	if (dsk_num < 0) {
		return ST_NF_DEVICE;
	}

	// Check if DCS is installed on this disk
	if (!dc_is_dcs_on_disk(dsk_num)) {
		return ST_NF_DEVICE;
	}

	// Get the EFI system partition path
	resl = dc_efi_get_sys_part(dsk_num, -1, root);
	if (resl != ST_OK) {
		return resl;
	}

	// Check if \EFI\DCS directory exists
	if (!dc_efi_file_exists(root, L"\\EFI\\DCS")) {
		return ST_NF_DEVICE;
	}

	// If cert is NULL, read from registry
	if (cert == NULL) {
		cert_buf = malloc(4096 * sizeof(WCHAR));
		if (cert_buf == NULL) {
			return ST_NOMEM;
		}

		if (dc_load_certificate(cert_buf, 4096) == ST_OK && cert_buf[0] != L'\0') {
			cert_to_use = cert_buf;
		} else {
			// Registry empty or not found - delete the file
			should_delete = TRUE;
		}
	}
	// If cert is non-NULL but empty, delete the file
	else if (cert[0] == L'\0') {
		should_delete = TRUE;
	}

	if (should_delete) {
		resl = dc_delete_efi_file(root, dcs_cert_file);
	}
	else {
		// Convert wide string to UTF-8
		int utf8_len = WideCharToMultiByte(CP_UTF8, 0, cert_to_use, -1, NULL, 0, NULL, NULL);
		if (utf8_len <= 0) {
			resl = ST_ERROR;
		}
		else {
			char* utf8_cert = malloc(utf8_len);
			if (utf8_cert == NULL) {
				resl = ST_NOMEM;
			}
			else {
				WideCharToMultiByte(CP_UTF8, 0, cert_to_use, -1, utf8_cert, utf8_len, NULL, NULL);

				// Save UTF-8 encoded certificate (without null terminator)
				resl = dc_save_efi_file(root, dcs_cert_file, utf8_cert, utf8_len - 1);

				free(utf8_cert);
			}
		}
	}

	if (cert_buf) {
		free(cert_buf);
	}

	return resl;
}