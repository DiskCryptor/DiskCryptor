/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2019-2026
	* DavidXanatos <info@diskcryptor.org>
	* Copyright (c) 2008-2013
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
#include "defines.h"
#include "drv_ioctl.h"
#include "misc.h"
#include "dcapi.h"
#include <winternl.h>

int dc_open_device()
{
	HANDLE h_device;

	h_device = CreateFile(DC_WIN32_NAME, 0, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (h_device != INVALID_HANDLE_VALUE) {
		TlsSetValue(g_tls_index, h_device);
		return ST_OK;
	}
    return ST_ERROR;
}

int dc_is_old_runned()
{
	HANDLE h_device;

	h_device = CreateFile(DC_OLD_WIN32_NAME, 0, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (h_device != INVALID_HANDLE_VALUE) {
		CloseHandle(h_device);
		return 1;
	}
	return 0;
}

DWORD dc_device_control(DWORD dwIoControlCode, LPCVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize)
{
	HANDLE h_device;
	DWORD  bytes;

	if ( (h_device = TlsGetValue(g_tls_index)) == NULL )
	{
		if ( (h_device = CreateFile(DC_WIN32_NAME, 0, 0, NULL, OPEN_EXISTING, 0, NULL)) == INVALID_HANDLE_VALUE )
		{
			return ERROR_DC_NOT_FOUND;
		}
		TlsSetValue(g_tls_index, h_device);
	}

	if (DeviceIoControl(h_device, dwIoControlCode, (PVOID)lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, &bytes, NULL) == FALSE)
	{
		return GetLastError();
	} else {
		return NO_ERROR;
	}
}

static int dc_get_vol_info(wchar_t *name, vol_inf *info)
{
	HANDLE   h_device = TlsGetValue(g_tls_index);
	dc_ioctl dctl;
	int      succs;
	u32      bytes;
	int      resl;
	
	do
	{
		wcschr(name, L'}')[1] = 0;
		wcscpy(info->w32_device, name);

		_snwprintf(
			dctl.device, countof(dctl.device), L"\\??\\Volume%s", wcschr(name, '{'));

		succs = DeviceIoControl(
			h_device, DC_CTL_RESOLVE,
			&dctl, sizeof(dctl), &dctl, sizeof(dctl), &bytes, NULL);

		if ( (succs == 0) || (dctl.status != ST_OK) ) {
			resl = ST_ERROR; break;
		}

		wcscpy(info->device, dctl.device);

		succs = DeviceIoControl(
			h_device, DC_CTL_STATUS,
			&dctl, sizeof(dc_ioctl), &info->status, sizeof(dc_status), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		} else 
		{
			if (info->status.mnt_point[0] == 0) {
				wcscpy(info->status.mnt_point, info->w32_device);
			}
			resl = ST_OK;
		}
	} while (0);
	
	return resl;
}

int dc_get_boot_device(wchar_t* bootVolumePath)
{
	ULONG    len;
	NTSTATUS res;
	char tempBuf[1024];
	memset(tempBuf, 0, sizeof(tempBuf));

	// Undocumented NT-API: SysPartitionInformation = 0x62

	res = NtQuerySystemInformation(/*SysPartitionInformation*/ 0x62, tempBuf, sizeof(tempBuf), &len);
	if (res != S_OK)
	{
		//ULONG win32err = RtlNtStatusToDosError(res);
		//if (win32err != ERROR_MR_MID_NOT_FOUND)
		//	res = (NTSTATUS)win32err;
		//SetLastError(res);
		return ST_ERROR;
	}

	PUNICODE_STRING pStr = (PUNICODE_STRING)tempBuf;

	wcscpy_s(bootVolumePath, MAX_PATH, pStr->Buffer);
	//if (path) swprintf_s(path, MAX_PATH, L"\\\\?%s", &pStr->Buffer[7]);

	return ST_OK;
}

/*int dc_get_boot_device(wchar_t *device)
{
	dc_ioctl dctl;
	u32      bytes;
	int      succs;

	// Note: This approach is not reliable!

	wcscpy(dctl.device, L"\\ArcName\\multi(0)disk(0)rdisk(0)partition(1)");

	succs = DeviceIoControl(
		TlsGetValue(g_tls_index), DC_CTL_RESOLVE, 
		&dctl, sizeof(dctl), &dctl, sizeof(dctl), &bytes, NULL);

	if (succs != 0) 
	{
		if (dctl.status == ST_OK) {
			wcscpy(device, dctl.device);
		}
		return dctl.status;
	} else {		
		return ST_ERROR;
	}
}*/

int dc_is_boot_encrypted()
{
	vol_inf info;
	DWORD   flags;
	wchar_t boot_dev[MAX_PATH];
	int     is_enc = 0;

	if (dc_get_boot_device(boot_dev) != ST_OK) {
		boot_dev[0] = 0;
	}

	if (dc_first_volume(&info) == ST_OK)
	{
		do
		{
			flags = info.status.flags;

			if (((flags & F_SYSTEM) ||
				(wcscmp(info.device, boot_dev) == 0)) && (flags & F_ENABLED))
			{
				is_enc = 1;
			}
		} while (dc_next_volume(&info) == ST_OK);
	}

	return is_enc;
}

/* info->find after the enumeration has ended (the handle is closed); never a find handle */
#define DC_VOL_ENUM_DONE ((HANDLE)(LONG_PTR)-2)

/* Does the mount manager know an NT volume device by a volume GUID name? */
static int dc_has_volume_guid_name(const wchar_t *nt_device)
{
	wchar_t name[MAX_PATH];
	wchar_t target[MAX_PATH];
	HANDLE  h_find;
	size_t  len;
	int     found = 0;

	if ( (h_find = FindFirstVolume(name, countof(name))) == INVALID_HANDLE_VALUE ) {
		return 1; /* unknown: do not add anything */
	}
	do
	{
		/* \\?\Volume{GUID}\ -> Volume{GUID} for QueryDosDevice */
		len = wcslen(name);
		if (len < 6 || wcsncmp(name, L"\\\\?\\", 4) != 0) continue;
		if (name[len - 1] == L'\\') name[len - 1] = 0;

		if ( (QueryDosDevice(name + 4, target, countof(target)) != 0) && (_wcsicmp(target, nt_device) == 0) ) {
			found = 1; break;
		}
	} while (FindNextVolume(h_find, name, countof(name)) != 0);

	FindVolumeClose(h_find);
	return found;
}

/*
 * Windows 7 gives an EFI system partition no volume GUID name, so FindFirstVolume never returns
 * it. After the GUID names, dc_next_volume walks \Device and reports every HarddiskVolumeN that
 * is an ESP, has no GUID name and is hooked by the driver, by its device name
 * (\\?\GLOBALROOT\Device\HarddiskVolumeN). On Windows 8 and later nothing is added.
 *
 * Volumes are returned in order of N; info->find keeps the next N to look for, not the directory
 * position (objects created or deleted in \Device between calls would shift it). Values from
 * DC_VOL_EXTRA_BASE down are never a find handle (user-mode handles and pointers are positive).
 */
#define DC_VOL_EXTRA_BASE  ((LONG_PTR)-0x10000)
#define DC_VOL_EXTRA_MAX   0x100000 /* volume numbers up to this */
#define DC_VOL_IS_EXTRA(h) ( ((LONG_PTR)(h) <= DC_VOL_EXTRA_BASE) && ((LONG_PTR)(h) > DC_VOL_EXTRA_BASE - DC_VOL_EXTRA_MAX) )
#define DC_VOL_EXTRA(n)    ((HANDLE)(DC_VOL_EXTRA_BASE - (LONG_PTR)(n)))
#define DC_VOL_EXTRA_NUM(h) ((ULONG)(DC_VOL_EXTRA_BASE - (LONG_PTR)(h)))

#define DC_DIRECTORY_QUERY    0x0001
#define DC_STATUS_MORE_ENTRIES ((NTSTATUS)0x00000105L)
#define DC_DIR_BUFF_SIZE      (64 * 1024)
#define DC_MAX_VOL_NUMS       512

typedef struct _dc_obj_dir_info {
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;
} dc_obj_dir_info;

typedef NTSTATUS (NTAPI *PFN_NtOpenDirectoryObject)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *PFN_NtQueryDirectoryObject)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);

extern const GUID GUID_EFI_SYSTEM_PARTITION; /* gpt_sup.c */

/* \Device\HarddiskVolume<digits> (not HarddiskVolumeShadowCopyN): 1 with *num = N */
static int dc_volume_device_number(const UNICODE_STRING *name, ULONG *num)
{
	static const wchar_t prefix[] = L"HarddiskVolume";
	size_t n = name->Length / sizeof(wchar_t), p = countof(prefix) - 1, i;
	ULONG  v = 0;

	if (name->Buffer == NULL || n <= p || n > p + 6 || _wcsnicmp(name->Buffer, prefix, p) != 0) return 0;
	for (i = p; i < n; i++) {
		if (name->Buffer[i] < L'0' || name->Buffer[i] > L'9') return 0;
		v = v * 10 + (name->Buffer[i] - L'0');
	}
	if (v >= DC_VOL_EXTRA_MAX - 1) return 0;
	*num = v;
	return 1;
}

/* the numbers N of every \Device\HarddiskVolumeN, read in one pass; the count, 0 on failure */
static int dc_list_volume_numbers(ULONG *nums, int max_nums)
{
	PFN_NtOpenDirectoryObject  p_open;
	PFN_NtQueryDirectoryObject p_query;
	HMODULE           ntdll = GetModuleHandleW(L"ntdll.dll");
	UNICODE_STRING    dir_name;
	OBJECT_ATTRIBUTES oa;
	HANDLE            h_dir;
	dc_obj_dir_info  *buff, *entry, *end;
	ULONG             dctx = 0, ret_len, num;
	BOOLEAN           restart = TRUE;
	NTSTATUS          status;
	int               count = 0;

	if (ntdll == NULL) return 0;
	p_open  = (PFN_NtOpenDirectoryObject)GetProcAddress(ntdll, "NtOpenDirectoryObject");
	p_query = (PFN_NtQueryDirectoryObject)GetProcAddress(ntdll, "NtQueryDirectoryObject");
	if (p_open == NULL || p_query == NULL) return 0;

	/* malloc: aligned for the UNICODE_STRINGs' pointers */
	if ( (buff = malloc(DC_DIR_BUFF_SIZE)) == NULL ) return 0;

	RtlInitUnicodeString(&dir_name, L"\\Device");
	InitializeObjectAttributes(&oa, &dir_name, OBJ_CASE_INSENSITIVE, NULL, NULL);
	if (p_open(&h_dir, DC_DIRECTORY_QUERY, &oa) < 0) {
		free(buff); return 0;
	}

	/* as many entries as fit per call (terminated by an empty one), again while more are left */
	for (;;)
	{
		status = p_query(h_dir, buff, DC_DIR_BUFF_SIZE, FALSE, restart, &dctx, &ret_len);
		restart = FALSE;
		if (status < 0) break; /* also STATUS_NO_MORE_ENTRIES */

		end = (dc_obj_dir_info*)((u8*)buff + DC_DIR_BUFF_SIZE);
		for (entry = buff; (entry + 1 <= end) && (entry->Name.Length != 0); entry++)
		{
			if ( (count < max_nums) && dc_volume_device_number(&entry->Name, &num) ) {
				nums[count++] = num;
			}
		}
		if (status != DC_STATUS_MORE_ENTRIES) break;
	}
	CloseHandle(h_dir);
	free(buff);
	return count;
}

/* an EFI system partition (GPT type or MBR type 0xEF) */
static int dc_is_esp_volume(const wchar_t *nt_device)
{
	wchar_t                  path[MAX_PATH];
	PARTITION_INFORMATION_EX ptix;
	HANDLE                   h;
	DWORD                    bytes;
	int                      is_esp = 0;

	_snwprintf(path, countof(path), L"\\\\?\\GLOBALROOT%s", nt_device);
	path[countof(path) - 1] = 0;

	h = CreateFile(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (h == INVALID_HANDLE_VALUE) return 0;

	if (DeviceIoControl(h, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, &ptix, sizeof(ptix), &bytes, NULL) != 0)
	{
		if (ptix.PartitionStyle == PARTITION_STYLE_GPT) {
			is_esp = IsEqualGUID(&ptix.Gpt.PartitionType, &GUID_EFI_SYSTEM_PARTITION);
		} else if (ptix.PartitionStyle == PARTITION_STYLE_MBR) {
			is_esp = (ptix.Mbr.PartitionType == 0xEF);
		}
	}
	CloseHandle(h);
	return is_esp;
}

/* the volume's status from the driver (fails when the driver does not hook it) */
static int dc_get_unnamed_vol_info(const wchar_t *nt_device, vol_inf *info)
{
	HANDLE   h_device = TlsGetValue(g_tls_index);
	dc_ioctl dctl;
	u32      bytes;

	memset(&dctl, 0, sizeof(dctl));
	wcscpy(dctl.device, nt_device);

	if (DeviceIoControl(h_device, DC_CTL_STATUS, &dctl, sizeof(dc_ioctl), &info->status, sizeof(dc_status), &bytes, NULL) == 0) {
		return ST_ERROR;
	}
	wcscpy(info->device, nt_device);
	_snwprintf(info->w32_device, countof(info->w32_device), L"\\\\?\\GLOBALROOT%s", nt_device);
	info->w32_device[countof(info->w32_device) - 1] = 0;

	if (info->status.mnt_point[0] == 0) {
		wcscpy(info->status.mnt_point, info->w32_device);
	}
	return ST_OK;
}

/* Windows 7 or older: from Windows 8 on the mount manager names every ESP, so the \Device walk
   (an open per volume, every second in the GUI) is skipped there. */
static int dc_os_names_no_esp()
{
	typedef LONG (WINAPI *PFN_RtlGetVersion)(PRTL_OSVERSIONINFOW);
	static volatile LONG cached = -1;
	RTL_OSVERSIONINFOW   ver;
	PFN_RtlGetVersion    p_get;
	LONG                 old_os = 0;

	if (cached >= 0) return cached;

	p_get = (PFN_RtlGetVersion)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
	memset(&ver, 0, sizeof(ver));
	ver.dwOSVersionInfoSize = sizeof(ver);
	if (p_get != NULL && p_get(&ver) >= 0) {
		old_os = (ver.dwMajorVersion < 6) || (ver.dwMajorVersion == 6 && ver.dwMinorVersion < 2);
	}
	InterlockedExchange(&cached, old_os);
	return old_os;
}

/* the unnamed ESP with the lowest volume number >= *next_num; ST_OK with *next_num after it */
static int dc_next_unnamed_esp(vol_inf *info, ULONG *next_num)
{
	ULONG   nums[DC_MAX_VOL_NUMS];
	wchar_t nt_device[MAX_DEVICE + 1];
	ULONG   cur = *next_num, best;
	int     count, i, found;

	if (dc_os_names_no_esp() == 0) return ST_ERROR;
	if ( (count = dc_list_volume_numbers(nums, DC_MAX_VOL_NUMS)) == 0 ) return ST_ERROR;

	for (;;)
	{
		/* the lowest number >= cur */
		for (i = 0, found = 0, best = 0; i < count; i++) {
			if ( (nums[i] >= cur) && (found == 0 || nums[i] < best) ) {
				best = nums[i]; found = 1;
			}
		}
		if (found == 0) return ST_ERROR;

		_snwprintf(nt_device, countof(nt_device), L"\\Device\\HarddiskVolume%u", best);
		nt_device[countof(nt_device) - 1] = 0;

		if ( dc_is_esp_volume(nt_device) && (dc_has_volume_guid_name(nt_device) == 0) &&
			 (dc_get_unnamed_vol_info(nt_device, info) == ST_OK) )
		{
			*next_num = best + 1;
			return ST_OK;
		}
		cur = best + 1;
	}
}

int dc_first_volume(vol_inf *info)
{
	wchar_t name[MAX_PATH];

	info->find = FindFirstVolume(name, countof(name));

	if (info->find != INVALID_HANDLE_VALUE)
	{
		if (dc_get_vol_info(name, info) != ST_OK) {
			return dc_next_volume(info);
		} else {
			return ST_OK;
		}
	}
	/* no GUID names at all: still the unnamed ESPs */
	info->find = DC_VOL_EXTRA(0);
	return dc_next_volume(info);
}

int dc_next_volume(vol_inf *info)
{
	wchar_t name[MAX_PATH];
	ULONG   ctx = 0;

	if (info->find == DC_VOL_ENUM_DONE) {
		return ST_ERROR;
	}

	if (DC_VOL_IS_EXTRA(info->find) == 0)
	{
		/* the result, not GetLastError alone: a success does not reset a stale ERROR_NO_MORE_FILES */
		while (FindNextVolume(info->find, name, countof(name)) != 0)
		{
			if (dc_get_vol_info(name, info) == ST_OK) {
				return ST_OK;
			}
		}
		FindVolumeClose(info->find);
	} else {
		ctx = DC_VOL_EXTRA_NUM(info->find);
	}

	/* last: the EFI system partitions the enumeration could not return (Windows 7) */
	if (dc_next_unnamed_esp(info, &ctx) == ST_OK) {
		info->find = DC_VOL_EXTRA(ctx);
		return ST_OK;
	}
	info->find = DC_VOL_ENUM_DONE;
	return ST_ERROR;
}

int dc_get_version()
{
	int version;

	if (dc_device_control(DC_GET_VERSION, NULL, 0, &version, sizeof(version)) != NO_ERROR)
	{
		version = 0;
	}
	return version;
}

int dc_mount_volume(wchar_t *device, dc_pass *password, int flags, volatile LONG *abort)
{
	dc_ioctl *dctl;
	u32       bytes;
	int       resl;
	int       succs;

	do
	{
		if ( (dctl = secure_alloc(sizeof(dc_ioctl))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		wcscpy(dctl->device, device); dctl->flags = flags;

		if (password != NULL) {
			memcpy(&dctl->passw1, password, sizeof(dc_pass));
		}

		dctl->interrupt_cmd = (ULONG*)abort;

		succs = DeviceIoControl(
			TlsGetValue(g_tls_index), DC_CTL_MOUNT,
			dctl, sizeof(dc_ioctl), dctl, sizeof(dc_ioctl), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		resl = dctl->status;
	} while (0);

	if (dctl != NULL) {
		secure_free(dctl);
	}

	return resl;
}

int dc_mount_all(dc_pass *password, int *mounted, int flags, volatile LONG *abort)
{
	dc_ioctl *dctl;
	u32       bytes;
	int       resl;
	int       succs;

	do
	{
		if ( (dctl = secure_alloc(sizeof(dc_ioctl))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		if (password != NULL) {
			memcpy(&dctl->passw1, password, sizeof(dc_pass));
		}

		dctl->flags = flags;
		dctl->interrupt_cmd = (ULONG*)abort;

		succs = DeviceIoControl(
			TlsGetValue(g_tls_index), DC_CTL_MOUNT_ALL,
			dctl, sizeof(dc_ioctl), dctl, sizeof(dc_ioctl), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		resl = dctl->status; 
		mounted[0] = dctl->n_mount;
	} while (0);

	if (dctl != NULL) {
		secure_free(dctl);
	}

	return resl;
}

int dc_unmount_volume(wchar_t *device, int flags)
{
	HANDLE    h_device = TlsGetValue(g_tls_index);
	dc_ioctl  dctl;
	dc_status status;
	u32       bytes;
	int       succs;
	int       resl;
	wchar_t   mnt_p[MAX_PATH];

	wcscpy(dctl.device, device);

	do
	{
		succs = DeviceIoControl(
			h_device, DC_CTL_STATUS, 
			&dctl, sizeof(dc_ioctl), &status, sizeof(dc_status), &bytes, NULL
			);

		if ( (succs == 0) || (IS_UNMOUNTABLE(&status) == 0) ) {
			resl = ST_UNMOUNTABLE; break;
		}

		dctl.flags = flags;

		succs = DeviceIoControl(
			h_device, DC_CTL_UNMOUNT,
			&dctl, sizeof(dc_ioctl), &dctl, sizeof(dc_ioctl), &bytes, NULL
			);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		if ( (resl = dctl.status) != ST_OK ) {
			break;
		}

		if ( (flags & MF_DELMP) || (status.mnt_flags & MF_DELMP) ) 
		{
			_snwprintf(
				mnt_p, countof(mnt_p), L"%s\\", status.mnt_point);

			DeleteVolumeMountPoint(mnt_p);
		}
	} while (0);

	return resl;
}

int dc_unmount_all()
{
	vol_inf info;
	
	if (dc_first_volume(&info) == ST_OK)
	{
		do
		{
			if (info.status.flags & F_ENABLED) {
				dc_unmount_volume(info.device, MF_FORCE);
			}
		} while (dc_next_volume(&info) == ST_OK);
	}
	
	return ST_OK;
}

int dc_add_password(dc_pass *password, volatile LONG *abort)
{
	dc_ioctl *dctl;
	u32       bytes;
	int       resl;
	int       succs;

	do
	{
		if ( (dctl = secure_alloc(sizeof(dc_ioctl))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		memcpy(&dctl->passw1, password, sizeof(dc_pass));
		dctl->interrupt_cmd = (ULONG*)abort;

		succs = DeviceIoControl(
			TlsGetValue(g_tls_index), DC_CTL_ADD_PASS,
			dctl, sizeof(dc_ioctl), dctl, sizeof(dc_ioctl), &bytes, NULL
			);

		if (succs == 0) {
			resl = ST_ERROR;
		} else {
			resl = dctl->status;
		}
	} while (0);

	if (dctl != NULL) {
		secure_free(dctl);
	}
	return resl;
}

int dc_enum_passwords(dc_pass_info *items, int max_count, int *total_count)
{
	dc_pass_enum *penum = NULL;
	u32           size;
	u32           bytes;
	int           resl = ST_ERROR;

	size = DC_PASS_ENUM_SIZE(max_count);
	penum = malloc(size);
	if (penum == NULL) {
		return ST_NOMEM;
	}

	if (DeviceIoControl(TlsGetValue(g_tls_index), DC_CTL_ENUM_PASS,
			NULL, 0, penum, size, &bytes, NULL))
	{
		int i, copy_count = min(penum->count, max_count);
		for (i = 0; i < copy_count; i++) {
			items[i] = penum->items[i];
		}
		*total_count = penum->count;
		resl = (penum->count > max_count) ? ST_MORE_DATA : ST_OK;
	}

	free(penum);
	return resl;
}

int dc_start_encrypt(wchar_t *device, dc_pass *password, crypt_info *crypt, int flags, volatile LONG *abort)
{
	dc_ioctl *dctl;
	u32       bytes;
	int       resl;
	int       succs;

	do
	{
		if ( (dctl = secure_alloc(sizeof(dc_ioctl))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		wcscpy(dctl->device, device);
		memcpy(&dctl->passw1, password, sizeof(dc_pass));

		dctl->flags = flags;
		dctl->crypt = crypt[0];
		dctl->interrupt_cmd = (ULONG*)abort;

		succs = DeviceIoControl(
			TlsGetValue(g_tls_index), DC_CTL_ENCRYPT_START,
			dctl, sizeof(dc_ioctl), dctl, sizeof(dc_ioctl), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		resl = dctl->status;
	} while (0);

	if (dctl != NULL) {
		secure_free(dctl);
	}

	return resl;
}

int dc_api dc_start_encrypt2(wchar_t *device, wchar_t *path)
{
	dc_ioctl *dctl;
	u32       bytes;
	int       resl;
	int       succs;

	do
	{
		if ( (dctl = secure_alloc(sizeof(dc_ioctl))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		wcscpy(dctl->device, device);
		wcscpy(dctl->path, path);

		succs = DeviceIoControl(
			TlsGetValue(g_tls_index), DC_CTL_ENCRYPT_START2,
			dctl, sizeof(dc_ioctl), dctl, sizeof(dc_ioctl), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		resl = dctl->status;
	} while (0);

	if (dctl != NULL) {
		secure_free(dctl);
	}

	return resl;
}

int dc_start_re_encrypt(wchar_t *device, dc_pass *password, crypt_info *crypt, volatile LONG *abort)
{
	dc_ioctl *dctl;
	u32       bytes;
	int       resl;
	int       succs;

	do
	{
		if ( (dctl = secure_alloc(sizeof(dc_ioctl))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		wcscpy(dctl->device, device);
		memcpy(&dctl->passw1, password, sizeof(dc_pass));

		dctl->crypt = crypt[0];
		dctl->interrupt_cmd = (ULONG*)abort;

		succs = DeviceIoControl(
			TlsGetValue(g_tls_index), DC_CTL_RE_ENC_START,
			dctl, sizeof(dc_ioctl), dctl, sizeof(dc_ioctl), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		resl = dctl->status;
	} while (0);

	if (dctl != NULL) {
		secure_free(dctl);
	}

	return resl;
}

int dc_update_layout(wchar_t *device, dc_pass *password, crypt_info *crypt, int flags, volatile LONG *abort)
{
	dc_ioctl *dctl;
	u32       bytes;
	int       resl;
	int       succs;

	do
	{
		if ( (dctl = secure_alloc(sizeof(dc_ioctl))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		wcscpy(dctl->device, device);
		memcpy(&dctl->passw1, password, sizeof(dc_pass));

		dctl->flags = flags;
		dctl->crypt = crypt[0];
		dctl->interrupt_cmd = (ULONG*)abort;

		succs = DeviceIoControl(
			TlsGetValue(g_tls_index), DC_CTL_UPDATE_LAYOUT,
			dctl, sizeof(dc_ioctl), dctl, sizeof(dc_ioctl), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		resl = dctl->status;
	} while (0);

	if (dctl != NULL) {
		secure_free(dctl);
	}

	return resl;
}

int dc_start_decrypt(wchar_t *device, dc_pass *password, crypt_info *crypt, volatile LONG *abort)
{
	dc_ioctl *dctl;
	u32       bytes;
	int       resl;
	int       succs;

	do
	{
		if ( (dctl = secure_alloc(sizeof(dc_ioctl))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		wcscpy(dctl->device, device);
		memcpy(&dctl->passw1, password, sizeof(dc_pass));
		if (crypt != NULL) {
			memcpy(&dctl->crypt, crypt, sizeof(crypt_info));
		} else {
			dctl->crypt.wp_mode = WP_NONE;
		}
		dctl->interrupt_cmd = (ULONG*)abort;

		succs = DeviceIoControl(
			TlsGetValue(g_tls_index), DC_CTL_DECRYPT_START,
			dctl, sizeof(dc_ioctl), dctl, sizeof(dc_ioctl), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		resl = dctl->status;
	} while (0);

	if (dctl != NULL) {
		secure_free(dctl);
	}

	return resl;
}

int dc_change_password(wchar_t *device, dc_pass *old_pass, dc_pass *new_pass, u32 flags, volatile LONG *abort)
{
	dc_ioctl *dctl;
	u32       bytes;
	int       resl;
	int       succs;

	do
	{
		if ( (dctl = secure_alloc(sizeof(dc_ioctl))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		wcscpy(dctl->device, device);
		memcpy(&dctl->passw1, old_pass, sizeof(dc_pass));
		memcpy(&dctl->passw2, new_pass, sizeof(dc_pass));
		dctl->flags = flags;
		dctl->interrupt_cmd = (ULONG*)abort;

		succs = DeviceIoControl(
			TlsGetValue(g_tls_index), DC_CTL_CHANGE_PASS,
			dctl, sizeof(dc_ioctl), dctl, sizeof(dc_ioctl), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		resl = dctl->status;
	} while (0);

	if (dctl != NULL) {
		secure_free(dctl);
	}

	return resl;
}

int dc_enc_step(wchar_t *device, int wp_mode)
{
	dc_ioctl dctl;
	u32      bytes;
	int      succs;

	wcscpy(dctl.device, device);

	dctl.crypt.wp_mode = wp_mode;

	succs = DeviceIoControl(
		TlsGetValue(g_tls_index), DC_CTL_ENCRYPT_STEP,
		&dctl, sizeof(dc_ioctl), &dctl, sizeof(dc_ioctl), &bytes, NULL);

	if (succs == 0) {
		return ST_ERROR;
	} else {
		return dctl.status;
	}
}

int dc_dec_step(wchar_t *device)
{
	dc_ioctl dctl;
	u32      bytes;
	int      succs;

	wcscpy(dctl.device, device);

	succs = DeviceIoControl(
		TlsGetValue(g_tls_index), DC_CTL_DECRYPT_STEP,
		&dctl, sizeof(dc_ioctl), &dctl, sizeof(dc_ioctl), &bytes, NULL);

	if (succs == 0) {
		return ST_ERROR;
	} else {
		return dctl.status;
	}
}

int dc_format_step(wchar_t *device, int wp_mode)
{
	dc_ioctl dctl;
	u32      bytes;
	int      succs;

	wcscpy(dctl.device, device);

	dctl.crypt.wp_mode = wp_mode;

	succs = DeviceIoControl(
		TlsGetValue(g_tls_index), DC_FORMAT_STEP,
		&dctl, sizeof(dc_ioctl), &dctl, sizeof(dc_ioctl), &bytes, NULL);

	if (succs == 0) {
		return ST_ERROR;
	} else {
		return dctl.status;
	}
}

int dc_sync_enc_state(wchar_t *device)
{
	dc_ioctl dctl;
	u32      bytes;
	int      succs;

	wcscpy(dctl.device, device);

	succs = DeviceIoControl(
		TlsGetValue(g_tls_index), DC_CTL_SYNC_STATE,
		&dctl, sizeof(dc_ioctl), &dctl, sizeof(dc_ioctl), &bytes, NULL);

	if (succs == 0) {
		return ST_ERROR;
	} else {
		return dctl.status;
	}
}

int dc_get_device_status(wchar_t *device, dc_status *status)
{
	dc_ioctl dctl;
	u32      bytes;
	int      succs;

	wcscpy(dctl.device, device);

	succs = DeviceIoControl(
		TlsGetValue(g_tls_index), DC_CTL_STATUS,
		&dctl, sizeof(dc_ioctl), status, sizeof(dc_status), &bytes, NULL);

	if (succs == 0) {
		return ST_ERROR;
	} else
	{
		if (status->mnt_point[0] == 0) {
			wcscpy(status->mnt_point, device); /* -- */
		}
		/* the result is in *status (the output buffer); dctl.status is not set */
		return ST_OK;
	}
}

int dc_benchmark(int cipher, dc_bench_info *info)
{
	u32 bytes;
	int succs;

	succs = DeviceIoControl(TlsGetValue(g_tls_index), DC_CTL_BENCHMARK,
		&cipher, sizeof(cipher), info, sizeof(dc_bench_info), &bytes, NULL);

	return succs != 0 ? ST_OK : ST_ERROR;
}

int dc_benchmark_kdf(int kdf, dc_kdf_bench_info *info)
{
	int params[1] = { kdf };
	u32 bytes;
	int succs;

	succs = DeviceIoControl(TlsGetValue(g_tls_index), DC_CTL_BENCHMARK_KDF,
		params, sizeof(params), info, sizeof(dc_kdf_bench_info), &bytes, NULL);

	return succs != 0 ? ST_OK : ST_ERROR;
}

int dc_start_format(wchar_t *device, dc_pass *password, crypt_info *crypt, int flags, volatile LONG *abort)
{
	dc_ioctl *dctl;
	u32       bytes;
	int       resl;
	int       succs;

	do
	{
		if ( (dctl = secure_alloc(sizeof(dc_ioctl))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		wcscpy(dctl->device, device);
		memcpy(&dctl->passw1, password, sizeof(dc_pass));

		dctl->flags = flags;
		dctl->crypt = crypt[0];
		dctl->interrupt_cmd = (ULONG*)abort;

		succs = DeviceIoControl(
			TlsGetValue(g_tls_index), DC_FORMAT_START,
			dctl, sizeof(dc_ioctl), dctl, sizeof(dc_ioctl), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		resl = dctl->status;
	} while (0);

	if (dctl != NULL) {
		secure_free(dctl);
	}

	return resl;
}

int dc_done_format(wchar_t *device)
{
	dc_ioctl dctl;
	u32      bytes;
	int      succs;

	wcscpy(dctl.device, device);

	succs = DeviceIoControl(
		TlsGetValue(g_tls_index), DC_FORMAT_DONE,
		&dctl, sizeof(dc_ioctl), &dctl, sizeof(dc_ioctl), &bytes, NULL);

	if (succs != 0) {
		return dctl.status;
	} else {
		return ST_ERROR;
	}
}

void dc_get_bsod()
{
	u32 bytes;

	DeviceIoControl(
		TlsGetValue(g_tls_index), DC_CTL_BSOD, NULL, 0, NULL, 0, &bytes, NULL);
}

int dc_backup_header(wchar_t *device, dc_pass *password, void *out, int *size, u32 flags, volatile LONG *abort)
{
	dc_backup_ctl *back;
	u32            bytes;
	int            succs;
	int            resl;

	do
	{
		if ( (back = secure_alloc(sizeof(dc_backup_ctl))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		wcscpy(back->device, device);
		memcpy(&back->pass, password, sizeof(dc_pass));
		back->flags = flags;
		back->size = sizeof(back->backup);
		back->interrupt_cmd = (ULONG*)abort;

		succs = DeviceIoControl(
			TlsGetValue(g_tls_index), DC_BACKUP_HEADER,
			back, sizeof(dc_backup_ctl), back, sizeof(dc_backup_ctl), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		if (*size < (int)back->size) {
			resl = ST_SMALL_BUFF; break;
		}

		memcpy(out, back->backup, back->size);
		*size = back->size;
		resl = back->status;
	} while (0);

	if (back != NULL) {
		secure_free(back);
	}

	return resl;
}

int dc_restore_header(wchar_t *device, dc_pass *password, void *in, int size, u32 flags, volatile LONG *abort)
{
	dc_backup_ctl *back;
	u32            bytes;
	int            succs;
	int            resl;

	do
	{
		if ( (back = secure_alloc(sizeof(dc_backup_ctl))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		wcscpy(back->device, device);
		memcpy(&back->pass, password, sizeof(dc_pass));
		memcpy(back->backup, in, size);
		back->flags = flags;
		back->size = size;
		back->interrupt_cmd = (ULONG*)abort;

		succs = DeviceIoControl(
			TlsGetValue(g_tls_index), DC_RESTORE_HEADER,
			back, sizeof(dc_backup_ctl), back, sizeof(dc_backup_ctl), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}
		
		resl = back->status;
	} while (0);

	if (back != NULL) {
		secure_free(back);
	}

	return resl;
}

int dc_update_header(wchar_t *device, dc_pass *password, void *in, int size, u32 flags, volatile LONG *abort)
{
	dc_backup_ctl *back;
	u32            bytes;
	int            succs;
	int            resl;

	do
	{
		if ( (back = secure_alloc(sizeof(dc_backup_ctl))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		wcscpy(back->device, device);
		memcpy(&back->pass, password, sizeof(dc_pass));
		memcpy(back->backup, in, size);
		back->flags = flags;
		back->size = size;
		back->interrupt_cmd = (ULONG*)abort;

		succs = DeviceIoControl(
			TlsGetValue(g_tls_index), DC_UPDATE_HEADER,
			back, sizeof(dc_backup_ctl), back, sizeof(dc_backup_ctl), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		resl = back->status;
	} while (0);

	if (back != NULL) {
		secure_free(back);
	}

	return resl;
}

int dc_is_device_ssd(wchar_t *device)
{
	int						result = 0;
	DWORD					bytesReturned = 0;
	HANDLE					hDevice;
	STORAGE_PROPERTY_QUERY	spqTrim;
	DEVICE_TRIM_DESCRIPTOR	dtd;
	
	hDevice = CreateFile(device, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hDevice != INVALID_HANDLE_VALUE)
	{
		spqTrim.PropertyId = StorageDeviceTrimProperty;
		spqTrim.QueryType = PropertyStandardQuery;
		if (DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY, &spqTrim, sizeof(spqTrim), &dtd, sizeof(dtd), &bytesReturned, NULL) && bytesReturned == sizeof(dtd))
		{
			result = dtd.TrimEnabled;
		}

		CloseHandle(hDevice);
	}

	return result;
}