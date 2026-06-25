/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2019-2026
	* DavidXanatos <info@diskcryptor.org>
	* Copyright (c) 2008-2011
	* ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
    * partial copyright Juergen Schmied and Jon Griffiths

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
#include <aclapi.h>
#pragma warning( disable : 4091 )
#include <ntddscsi.h>
#pragma warning( default : 4091 )
#include <stdio.h>
#include <math.h>

#include "misc.h"
#include "..\crc32.h"
#include "drv_ioctl.h"

typedef int (WINAPI fmt_callback) (int unk1, int unk2, int unk3);

typedef void (WINAPI *PFORMAT) (
	 wchar_t *root_path, u32 unk1, wchar_t *fs_type, wchar_t *label, u32 unk2, fmt_callback callback
	 );

#define KB ((u64)1024)
#define MB (KB*KB)
#define GB (KB*KB*KB)
#define TB (KB*KB*KB*KB)
#define PB (KB*KB*KB*KB*KB)

static struct {
  u64     limit;
  double  divisor; 
  double  normaliser;
  int     decimals;
  wchar_t prefix;
} b_formats[] = {
	{ 10*KB,   10.24,        100.0,  2, 'K' }, /* 10 KB */
    { 100*KB,  102.4,        10.0,   1, 'K' }, /* 100 KB */
    { 1000*KB, 1024.0,       1.0,    0, 'M' }, /* 1000 KB */
    { 10*MB,   10485.76,     100.0,  2, 'M' }, /* 10 MB */
    { 100*MB,  104857.6,     10.0,   1, 'M' }, /* 100 MB */
    { 1000*MB, 1048576.0,    1.0,    0, 'M' }, /* 1000 MB */
    { 10*GB,   10737418.24,  100.0,  2, 'G' }, /* 10 GB */
    { 100*GB,  107374182.4,  10.0,   1, 'G' }, /* 100 GB */
    { 1000*GB, 1073741824.0, 1.0,    0, 'G' }, /* 1000 GB */
    { 10*TB,   10485.76,     100.0,  2, 'T' }, /* 10 TB */
    { 100*TB,  104857.6,     10.0,   1, 'T' }, /* 100 TB */
    { 1000*TB, 1048576.0,    1.0,    0, 'T' }, /* 1000 TB */
    { 10*PB,   10737418.24,  100.00, 2, 'P' }, /* 10 PB */
    { 100*PB,  107374182.4,  10.00,  1, 'P' }, /* 100 PB */
    { 1000*PB, 1073741824.0, 1.00,   0, 'P' }  /* 1000 PB */
};

typedef BOOL (WINAPI *ISWOW64PROCESS)(HANDLE, PBOOL);

int enable_privilege(wchar_t *name)
{
	HANDLE           h_token = NULL;
	TOKEN_PRIVILEGES tp;
	LUID             luid;
	int              resl;

	do
	{
		OpenProcessToken(
			GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &h_token);

		if (h_token == NULL) {
			resl = ST_ACCESS_DENIED; break;
		}

		if (LookupPrivilegeValue(NULL, name, &luid) == FALSE) {
			resl = ST_ACCESS_DENIED; break;
		}

		tp.PrivilegeCount           = 1;
		tp.Privileges[0].Luid       = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (AdjustTokenPrivileges(
			h_token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL) == FALSE)
		{
			resl = ST_ACCESS_DENIED;			
		} else {
			resl = ST_OK;
		}
	} while (0);

	if (h_token != NULL) {
		CloseHandle(h_token);
	}

	return resl;
}

int is_admin()
{
	SID_IDENTIFIER_AUTHORITY autort  = SECURITY_NT_AUTHORITY;
	PSID                     adm_sid = NULL;
	BOOL                     member  = FALSE;
	int                      resl;

	do
	{
		AllocateAndInitializeSid(
			&autort, 2, SECURITY_BUILTIN_DOMAIN_RID, 
			DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adm_sid);

		if (adm_sid == NULL) {
			resl = ST_NOMEM; break;
		}

		if (CheckTokenMembership(NULL, adm_sid, &member) == FALSE) {
			resl = ST_ERROR; break;
		}

		if (member != FALSE) {
			resl = ST_OK;
		} else {
			resl = ST_NO_ADMIN;
		}
	} while (0);

	if (adm_sid != NULL) {
		FreeSid(adm_sid);
	}

	return resl;
}

int save_file(wchar_t *name, void *data, int size)
{
	HANDLE hfile;
	u32    bytes;
	int    resl;

	hfile = CreateFile(
		name, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);

	if (hfile != INVALID_HANDLE_VALUE) 
	{
		WriteFile(hfile, data, size, &bytes, NULL);
		CloseHandle(hfile);
		resl = ST_OK;
	} else {
		resl = ST_ACCESS_DENIED;
	}

	return resl;
}

int load_file(wchar_t *name, void **data, int *size)
{
	HANDLE hfile;
	u32    bytes;
	int    resl;

	do
	{
		hfile = CreateFile(
			name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

		if (hfile == INVALID_HANDLE_VALUE) {
			hfile = NULL; resl = ST_ACCESS_DENIED; break;
		}

		*size = GetFileSize(hfile, NULL);
		*data = malloc(*size);

		if (*data == NULL) {
			resl = ST_NOMEM; break;
		}
		if (ReadFile(hfile, *data, *size, &bytes, NULL) == 0) {
			free(*data); 
			*data = NULL;
			resl = ST_IO_ERROR;
		} else {
			resl = ST_OK;
		}
	} while (0);

	if (hfile != NULL) {
		CloseHandle(hfile);
	}

	return resl;
}

void my_free(PVOID ptr)
{
	free (ptr);
}

PVOID secure_alloc(ULONG length)
{
	DC_LOCK_MEMORY mem;

	// on 32 bit system xts_key must be located in executable memory
	// x64 does not require this
#ifdef _M_IX86
	if ( (mem.ptr = VirtualAlloc(NULL, (mem.length = length), MEM_COMMIT+MEM_RESERVE, PAGE_EXECUTE_READWRITE)) == NULL ) return NULL;
#else
	if ( (mem.ptr = VirtualAlloc(NULL, (mem.length = length), MEM_COMMIT+MEM_RESERVE, PAGE_READWRITE)) == NULL ) return NULL;
#endif
	if (dc_device_control(DC_CTL_LOCK_MEM, &mem, sizeof(mem), NULL, 0) != NO_ERROR) VirtualLock(mem.ptr, length);
	memset(mem.ptr, 0, length);
	return mem.ptr;
}

void secure_free(PVOID ptr)
{
	MEMORY_BASIC_INFORMATION mbi;
	
	if ( (dc_device_control(DC_CTL_UNLOCK_MEM, &ptr, sizeof(ptr), NULL, 0) != NO_ERROR) &&
		 (VirtualQuery(ptr, &mbi, sizeof(mbi)) == sizeof(mbi) && mbi.BaseAddress == ptr && mbi.AllocationBase == ptr) )
	{
		RtlSecureZeroMemory(ptr, mbi.RegionSize);
		VirtualUnlock(ptr, mbi.RegionSize);
	}
	VirtualFree(ptr, 0, MEM_RELEASE);
}

int is_wow64()
{
	ISWOW64PROCESS IsWow64Process;
	BOOL           is_wow = FALSE;

	IsWow64Process = pv(GetProcAddress(
		GetModuleHandleA("kernel32"), "IsWow64Process"));

	if (IsWow64Process == NULL) {
		return 0;
	}

	IsWow64Process(
		GetCurrentProcess(), &is_wow);

	return (is_wow != FALSE);		
}

int is_all_zeros(const char* bytes, size_t size)
{
	for (size_t i = 0; i < size; i++) 
		if (bytes[i] != 0) return 0;
	return 1;
}

int calc_crc32(const char* bytes, size_t size)
{
	return crc32((const unsigned char*)bytes, (u32)size);
}

int dc_fs_type(u8 *buff)
{
	if (memcmp(buff + 3, "NTFS    ", 8) == 0) {
		return FS_NTFS;
	}
	if (memcmp(buff + 54, "FAT12   ", 8) == 0) {
		return FS_FAT12;
	}
	if (memcmp(buff + 54, "FAT16   ", 8) == 0) {
		return FS_FAT16;
	}
	if (memcmp(buff + 82, "FAT32   ", 8) == 0) {
		return FS_FAT32;
	}
	if (memcmp(buff + 3, "EXFAT   ", 8) == 0) {
		return FS_EXFAT;
	}
	return FS_UNK;
}

dc_disk_p *dc_disk_open(int dsk_num, int is_cd)
{
	DISK_GEOMETRY dg;
	wchar_t       device[MAX_PATH];
	int           succs;	
	dc_disk_p    *dp;
	u32           bytes;

	if (is_cd == 0)
	{
		_snwprintf(
			device, countof(device), L"\\\\.\\PhysicalDrive%d", dsk_num);
	} else {
		_snwprintf(
			device, countof(device), L"\\\\.\\CdRom%d", dsk_num);
	}

	succs = 0;
	do
	{
		if ( (dp = malloc(sizeof(dc_disk_p))) == NULL ) {
			break;
		}

		dp->hdisk = CreateFile(
			device, GENERIC_READ | GENERIC_WRITE, 
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		if (dp->hdisk == INVALID_HANDLE_VALUE) {
			dp->hdisk = NULL; break;
		}

		if (is_cd == 0)
		{
			succs = DeviceIoControl(
				dp->hdisk, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &dg, sizeof(dg), &bytes, NULL);

			if (succs != 0) {
				dp->media = dg.MediaType;
				dp->bps   = dg.BytesPerSector;
				dp->spc   = dg.TracksPerCylinder * dg.SectorsPerTrack;
				dp->size  = dg.Cylinders.QuadPart * d64(dp->spc) * d64(dp->bps);			
			}
		} else {
			dp->media = Unknown;
			dp->bps   = CD_SECTOR_SIZE;
			dp->spc   = 0;
			dp->size  = 0; succs = 1;
		}
	} while (0);

	if ( (succs == 0) && (dp != NULL) ) 
	{
		if (dp->hdisk != NULL) {
			CloseHandle(dp->hdisk);
		}
		free(dp); dp = NULL;
	}

	return dp;
}

void dc_disk_close(dc_disk_p *dp)
{
	CloseHandle(dp->hdisk);
	free(dp);
}

int dc_disk_read(dc_disk_p *dp, void *buff, int size, u64 offset)
{
	u64 n_offs;
	u32 n_size, bytes;
	u32 b_offs;
	u8 *p_buff;
	int resl;

	if ( (offset % dp->bps) || (size % dp->bps) ) 
	{
		b_offs = offset % dp->bps;
		n_offs = offset - b_offs;
		n_size = b_offs + size;
		n_size = n_size + (dp->bps - (n_size % dp->bps));
		p_buff = malloc(n_size);		
	} else {
		n_offs = offset, n_size = size, p_buff = buff;
	}
	
	do
	{
		if (p_buff == NULL) {
			resl = ST_NOMEM; break;
		}

		bytes = SetFilePointer(
			dp->hdisk, d32(n_offs), &p32(&n_offs)[1], FILE_BEGIN);

		if (bytes == INVALID_SET_FILE_POINTER) {
			resl = ST_IO_ERROR; break;
		}

		if (ReadFile(dp->hdisk, p_buff, n_size, &bytes, NULL) == 0) {
			resl = ST_IO_ERROR;
		} else {
			resl = ST_OK;
		}
	} while (0);

	if (p_buff != buff)
	{
		if (resl == ST_OK) {
			memcpy(buff, p_buff + b_offs, size);
		}
		free(p_buff);
	}
	
	return resl;
}

int dc_disk_write(dc_disk_p *dp, void *buff, int size, u64 offset)
{
	u64 n_offs;
	u32 n_size, bytes;
	u32 b_offs;
	u8 *p_buff;
	int resl;

	if ( (offset % dp->bps) || (size % dp->bps) ) 
	{
		b_offs = offset % dp->bps;
		n_offs = offset - b_offs;
		n_size = b_offs + size;
		n_size = n_size + (dp->bps - (n_size % dp->bps));
		p_buff = malloc(n_size);		
	} else {
		n_offs = offset, n_size = size, p_buff = buff;
	}
	
	do
	{
		if (p_buff == NULL) {
			resl = ST_NOMEM; break;
		}

		bytes = SetFilePointer(
			dp->hdisk, d32(n_offs), &p32(&n_offs)[1], FILE_BEGIN);

		if (bytes == INVALID_SET_FILE_POINTER) {
			resl = ST_IO_ERROR; break;
		}

		if (p_buff != buff)
		{
			if (ReadFile(dp->hdisk, p_buff, n_size, &bytes, NULL) == 0) {
				resl = ST_IO_ERROR; break;
			}

			memcpy(p_buff + b_offs, buff, size);

			SetFilePointer(
				dp->hdisk, d32(n_offs), &p32(&n_offs)[1], FILE_BEGIN);

			if (WriteFile(dp->hdisk, p_buff, n_size, &bytes, NULL) == 0) {
				resl = ST_IO_ERROR;
			} else { resl = ST_OK; }
		} else 
		{
			if (WriteFile(dp->hdisk, p_buff, n_size, &bytes, NULL) == 0) {
				resl = ST_IO_ERROR;
			} else { resl = ST_OK; }
		}
	} while (0);

	if (p_buff != buff) {		
		free(p_buff);
	}
	
	return resl;	
}


int is_win_vista()
{
	OSVERSIONINFO osv;

	osv.dwOSVersionInfoSize = sizeof(osv);
#pragma warning( disable : 4996 )
	GetVersionEx(&osv);
#pragma warning( default : 4996 )
	return (osv.dwMajorVersion >= 6);
}


/* this function grabbed from ReactOS sources */
void dc_format_byte_size(
	   wchar_t *wc_buf, int wc_size, u64 num_bytes
	   )
{
	double  d_bytes;
	wchar_t format[20];
	int     i;

	if (num_bytes < 1024) 
	{
		_snwprintf(
			wc_buf, wc_size, L"%d bytes", (u32)(num_bytes));
	} else 
	{
		for (i = 0; i < countof(b_formats); i++) 
		{
			if (num_bytes < b_formats[i].limit) {
				break;
			}
		}

		if (i > 8) {
			d_bytes = (double)(num_bytes >> 20) + 0.001; /* Scale down by I MB */
		} else {
			d_bytes = (double)(num_bytes) + 0.00001;
		}

		d_bytes = floor(d_bytes / b_formats[i].divisor) / b_formats[i].normaliser;

		_snwprintf(
			format, countof(format), L"%%-.%df %%cB", b_formats[i].decimals);
		
		_snwprintf(
			wc_buf, wc_size, format, d_bytes, b_formats[i].prefix);		
	}
}

wchar_t *dc_get_cipher_name(int cipher_id)
{
	static wchar_t *cp_names[] = {
		L"AES",
		L"Twofish",
		L"Serpent",
		L"AES-Twofish",
		L"Twofish-Serpent",
		L"Serpent-AES",
		L"AES-Twofish-Serpent"
	};

	return cp_names[cipher_id];
}


static int WINAPI dc_format_callback(int unk1, int unk2, int unk3) {
	return 1;
}

int dc_format_fs(wchar_t *root, wchar_t *fs)
{
	HMODULE fmifs;
	PFORMAT Format;
	int     resl;

	do
	{
		if ( (fmifs = LoadLibrary(L"fmifs")) == NULL ) {
			resl = ST_ERROR; break;
		}

		if ( (Format = pv(GetProcAddress(fmifs, "Format"))) == NULL ) {
			resl = ST_ERROR; break;
		}

		Format(root, 0, fs, L"", 1, dc_format_callback);
		resl = ST_OK;
	} while (0);

	if (fmifs != NULL) {
		FreeLibrary(fmifs);
	}

	return resl;
}

#ifdef _M_IX86
long _stdcall save_fpu_state(unsigned char state[32]) {
	return 0;
}
void _stdcall load_fpu_state(unsigned char state[32]) {
}
#endif

int dc_buffer_contains_pattern(const byte *buffer, size_t bufferSize, const byte *pattern, size_t patternSize)
{
	if (bufferSize < patternSize)
		return 0;

	bufferSize -= patternSize;

	for (size_t i = 0; i < bufferSize; ++i)
	{
		if (memcmp(buffer + i, pattern, patternSize) == 0)
			return 1;
	}

	return 0;
}

int dc_buffer_contains_string(const byte *buffer, size_t bufferSize, const char *str)
{
	return dc_buffer_contains_pattern(buffer, bufferSize, (const byte*)str, strlen(str));
}

int dc_buffer_contains_wide_string(const byte *buffer, size_t bufferSize, const wchar_t *str)
{
	return dc_buffer_contains_pattern(buffer, bufferSize, (const byte*)str, 2 * wcslen(str));
}

wchar_t *dc_get_status_str(int resl)
{
	switch (resl)
	{
	case ST_ERROR:				return L"unknown error";
	case ST_NF_DEVICE:			return L"device not found";
	case ST_RW_ERR:				return L"read/write error";
	case ST_PASS_ERR:			return L"invalid password";
	case ST_ALR_MOUNT:			return L"device is already mounted";
	case ST_NO_MOUNT:			return L"device not mounted";
	case ST_LOCK_ERR:			return L"error on volume locking";
	case ST_UNMOUNTABLE:		return L"device is unmountable";
	case ST_NOMEM:				return L"not enough memory";
	case ST_ERR_THREAD:			return L"error on creating system thread";
	case ST_INV_WIPE_MODE:		return L"invalid data wipe mode";
	case ST_INV_DATA_SIZE:		return L"invalid data size";
	case ST_ACCESS_DENIED:		return L"access denied";
	case ST_NF_FILE:			return L"file not found";
	case ST_IO_ERROR:			return L"disk I/O error";
	case ST_UNK_FS:				return L"unsupported file system";
	case ST_ERR_BOOT:			return L"invalid FS bootsector, please format partition";
	case ST_MBR_ERR:			return L"MBR is corrupted";
	case ST_BLDR_INSTALLED:		return L"bootloader is already installed";
	case ST_NF_SPACE:			return L"not enough space after partitions to install bootloader";
	case ST_BLDR_NOTINST:		return L"bootloader is not installed";
	case ST_INV_BLDR_SIZE:		return L"invalid bootloader size";
	case ST_BLDR_NO_CONF:		return L"bootloader corrupted, config not found";
	case ST_BLDR_OLD_VER:		return L"old bootloader cannot be configured";
	//case ST_AUTORUNNED:			return L"";
	//case ST_NEED_EXIT:			return L"";
	case ST_NO_ADMIN:			return L"user does not have admin privileges";
	case ST_NF_BOOT_DEV:		return L"boot device not found";
	case ST_REG_ERROR:			return L"cannot open registry key";
	case ST_NF_REG_KEY:			return L"registry key not found";
	case ST_SCM_ERROR:			return L"cannot open SCM database";
	case ST_FINISHED:			return L"encryption finished";
	case ST_INV_SECT:			return L"device has unsupported sector size";
	case ST_CLUS_USED:			return L"shrinking error, last clusters are used";
	case ST_NF_PT_SPACE:		return L"not enough free space in partition to continue encrypting";
	case ST_MEDIA_CHANGED:		return L"removable media changed";
	case ST_NO_MEDIA:			return L"no removable media in device";
	case ST_DEVICE_BUSY:		return L"device is busy";
	case ST_INV_MEDIA_TYPE:		return L"media type not supported";
	case ST_FORMAT_NEEDED:		return L"partition must be formatted";
	case ST_CANCEL:				return L"operation canceled";
	case ST_INV_VOL_VER:		return L"invalid volume version";
	case ST_EMPTY_KEYFILES:		return L"keyfiles not found";
	case ST_NOT_BACKUP:			return L"this is not a backup file";
	case ST_NO_OPEN_FILE:		return L"cannot open file";
	case ST_NO_CREATE_FILE:		return L"cannot create file";
	case ST_INV_VOLUME:			return L"invalid volume header";
	//case ST_OLD_VERSION:		return L"";
	//case ST_NEW_VERSION:		return L"";
	//case ST_ENCRYPTED:			return L"";
	//case ST_INCOMPATIBLE:		return L"";
	//case ST_LOADED:				return L"";
	case ST_VOLUME_TOO_NEW:		return L"volume header version is too new";
	case ST_INVALID_PARAM:		return L"an invalid parameter was provided";
	case ST_INV_FORMAT:			return L"disk has incompatible partition format";
	case ST_NO_OPEN_DIR:		return L"cannot open directory";
	case ST_DIR_NOT_EMPTY:		return L"directory is not empty";
	case ST_BL_NOT_PASSED:		return L"bootloader check not passed";
	case ST_SB_NO_PASS:			return L"secureboot enabled and not accepting DCS signature";
	case ST_SHIM_MISSING:		return L"shim package is missing, see https://diskcryptor.org/advanced-boot/ for more information";
	case ST_HEADER_TO_BIG:		return L"volume header is to big";
	case ST_SMALL_BUFF:			return L"buffer too small";
	case ST_BAD_INDEX:		    return L"bad index";
	case ST_SLOT_NOT_OK:		return L"failed to set up keyslot";
	case ST_SHRINK_FAILED:		return L"failed to shrink filesystem";
	case ST_PASS_NOT_FOUND: 	return L"password not found in cache";
	case ST_MORE_DATA:			return L"more data available";
	case ST_NO_TPM:				return L"TPM not available";
	case ST_TPM_ERROR:			return L"TPM command failed";
	case ST_NOT_SUPPORTED:		return L"operation not supported";
	case ST_FORMAT_ERR:			return L"invalid data format";
	case ST_TPM_NV_NOT_FOUND:	return L"NV index not found";
	case ST_TPM_WRONG_PIN:		return L"TPM authentication failed (wrong PIN)";
	case ST_TPM_PCR_MISMATCH:	return L"TPM PCR values don't match (system state changed)";
	case ST_TPM_LOCKOUT:		return L"TPM is locked out (too many failed attempts)";
	case ST_TPM_INTEGRITY:		return L"TPM sealed data integrity check failed";
	case ST_GPT_INVALID:		return L"invalid GPT partition table";
	case ST_NO_FREE_SPACE:		return L"no free space on disk";
	case ST_PART_TOO_SMALL:		return L"partition too small";
	case ST_NOT_PRO:			return L"Not Pro";
	default: return NULL;
	}
}
