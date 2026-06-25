/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2026
    * DavidXanatos <info@diskcryptor.org>
	* Copyright (c) 2007-2014
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
#include <tchar.h>
#include <strsafe.h>
#include "drvinst.h"
#include "dcres.h"
#include "misc.h"
#include "drv_ioctl.h"
#include "dcapi.h"
#include "version.h"

static const TCHAR g_dcrypt_service_name[] = _T("dcrypt");
static const TCHAR g_maindriver_filename[] = _T("dcrypt.sys");
static const TCHAR g_service_description[] = _T("DiskCryptor driver");

static const TCHAR g_dcrypt_config_key[] = _T("SYSTEM\\CurrentControlSet\\Services\\dcrypt\\config");
static const TCHAR g_volume_filter_key[] = _T("SYSTEM\\CurrentControlSet\\Control\\Class\\{71A27CDD-812A-11D0-BEC7-08002BE2092F}");
static const TCHAR g_cdrom_filter_key[] = _T("SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E965-E325-11CE-BFC1-08002BE10318}");
static const TCHAR g_crash_filter_key[] = _T("SYSTEM\\CurrentControlSet\\Control\\CrashControl"); 

DWORD dc_load_config(dc_conf_data* conf)
{
	DC_FLAGS flags;
	HKEY     h_key;
	DWORD    status, cb;

	if ( (status = RegOpenKey(HKEY_LOCAL_MACHINE, g_dcrypt_config_key, &h_key)) == NO_ERROR )
	{
		cb = sizeof(conf->conf_flags);

		if (RegQueryValueEx(h_key, _T("Flags"), NULL, NULL, (BYTE *)&conf->conf_flags, &cb) != NO_ERROR) {
			conf->conf_flags = 0;
		}

		cb = sizeof(conf->build);

		if (RegQueryValueEx(h_key, _T("sysBuild"), NULL, NULL, (BYTE *)&conf->build, &cb) != NO_ERROR) {
			conf->build = 0;
		}

		cb = sizeof(conf->hotkeys);

		if (RegQueryValueEx(h_key, _T("Hotkeys"), NULL, NULL, (BYTE *)&conf->hotkeys, &cb) != NO_ERROR) {
			memset(&conf->hotkeys, 0, sizeof(conf->hotkeys));
		}

		if (dc_device_control(DC_CTL_GET_FLAGS, NULL, 0, &flags, sizeof(flags)) == NO_ERROR) {
			conf->load_flags = flags.load_flags;
		} else {
			conf->load_flags = 0;
		}

		RegCloseKey(h_key);
	}
	return status;
}

DWORD dc_save_config(const dc_conf_data* conf)
{
	DC_FLAGS flags = { conf->conf_flags, conf->load_flags, };
	DWORD    status, build = DC_DRIVER_VER;
	HKEY     h_key;

	if ( (status = RegCreateKey(HKEY_LOCAL_MACHINE, g_dcrypt_config_key, &h_key)) == NO_ERROR )
	{
		if ( (status = RegSetValueEx(h_key, _T("Flags"), 0, REG_DWORD, (const BYTE *)&conf->conf_flags, sizeof(conf->conf_flags))) != NO_ERROR ) goto cleanup;
		if ( (status = RegSetValueEx(h_key, _T("Hotkeys"), 0, REG_BINARY, (const BYTE *)&conf->hotkeys, sizeof(conf->hotkeys))) != NO_ERROR ) goto cleanup;
		if ( (status = RegSetValueEx(h_key, _T("sysBuild"), 0, REG_DWORD, (const BYTE *)&build, sizeof(build))) != NO_ERROR ) goto cleanup;
		if ( (status = RegFlushKey(h_key)) != NO_ERROR ) goto cleanup;

		if ( (status = dc_device_control(DC_CTL_SET_FLAGS, &flags, sizeof(flags), NULL, 0)) == ERROR_DC_NOT_FOUND ) status = NO_ERROR;
cleanup:
		RegCloseKey(h_key);
	}
	return status;
}

static DWORD remove_from_reg_multi_sz(PCTSTR key_name, PCTSTR value_name, PCTSTR content)
{
	HKEY  h_key;
	TCHAR buff[1024], *p = buff;
	DWORD cb = sizeof(buff), len, status;
	DWORD type;

	if ( (status = RegOpenKey(HKEY_LOCAL_MACHINE, key_name, &h_key)) != NO_ERROR ) return status;
	if ( (status = RegQueryValueEx(h_key, value_name, NULL, &type, (BYTE *)&buff, &cb)) != NO_ERROR ) goto cleanup;
	
	if (type != REG_MULTI_SZ || cb < sizeof(TCHAR)) {
		status = ERROR_DATATYPE_MISMATCH;
		goto cleanup;
	}

	while ( (len = (DWORD)(_tcslen(p) * sizeof(TCHAR))) != 0 )
	{
		if (_tcscmp(p, content) == 0)
		{
			cb -= len + sizeof(TCHAR);
			memmove(p, (const BYTE*)p + len + sizeof(TCHAR), cb - ((const BYTE*)p - (const BYTE*)buff));

			if (cb == 0 || buff[0] == 0) {
				cb = 0; break;
			}
		} else {
			p += (len / sizeof(TCHAR)) + 1;
		}
	}
	if (cb != 0) {
		if ( (status = RegSetValueEx(h_key, value_name, 0, REG_MULTI_SZ, (const BYTE *)&buff, cb)) != NO_ERROR ) goto cleanup;
	} else {
		if ( (status = RegDeleteValue(h_key, value_name)) != NO_ERROR ) goto cleanup;
	}
	status = RegFlushKey(h_key);
cleanup:
	RegCloseKey(h_key);
	return status;
}

static DWORD add_to_reg_multi_sz(PCTSTR key_name, PCTSTR value_name, PCTSTR content)
{
	HKEY  h_key;
	TCHAR buff[1024], *p;
	DWORD cb, len, status;
	DWORD type;
	
	if ( (status = RegOpenKey(HKEY_LOCAL_MACHINE, key_name, &h_key)) != NO_ERROR ) return status;

	len = (DWORD)((_tcslen(content) + 1) * sizeof(TCHAR));
	cb  = sizeof(buff); p = buff;

	if ( (status = RegQueryValueEx(h_key, value_name, NULL, &type, (BYTE *)&buff, &cb)) != NO_ERROR )
	{
		if (status != ERROR_FILE_NOT_FOUND) goto cleanup;
		buff[0] = 0; cb = sizeof(TCHAR);
	} else
	{
		if (type != REG_MULTI_SZ || cb + len > sizeof(buff)) {
			status = ERROR_DATATYPE_MISMATCH;
			goto cleanup;
		}
	}
	
	for (; *p != 0; p += _tcslen(p) + 1) {
		if (_tcscmp(p, content) == 0) goto cleanup;
	}

	memmove((BYTE *)buff + len, buff, cb);
	memcpy(buff, content, len);
	cb += len;

	if ( (status = RegSetValueEx(h_key, value_name, 0, REG_MULTI_SZ, (const BYTE *)&buff, cb)) == NO_ERROR )
	{
		status = RegFlushKey(h_key);
	}
cleanup:
	RegCloseKey(h_key);
	return status;
}

static DWORD make_driver_path(PTSTR pszPath, size_t cchPath, PCTSTR driver_name)
{
	TCHAR sys_path[MAX_PATH];
	DWORD length;

	if ( (length = GetSystemDirectory(sys_path, _countof(sys_path))) == 0 || length >= _countof(sys_path) )
	{
		return ERROR_INVALID_NAME;
	}
	if ( FAILED(StringCchPrintf(pszPath, cchPath, _T("%s\\drivers\\%s"), sys_path, driver_name)) )
	{
		return ERROR_INSUFFICIENT_BUFFER;
	}
	return NO_ERROR;
}

static DWORD save_dcrypt_driver_file()
{
	TCHAR source_path[MAX_PATH], dest_path[MAX_PATH], temp_path[MAX_PATH], *p;
	DWORD length, status;

	if (g_inst_dll == NULL || (length = GetModuleFileName(g_inst_dll, source_path, _countof(source_path))) == 0) return ERROR_INVALID_NAME;
	if (length >= _countof(source_path) - 1 || (p = _tcsrchr(source_path, '\\')) == NULL) return ERROR_INVALID_NAME;
	if ( FAILED(StringCchCopy(p + 1, _countof(source_path) - (p - source_path) - 1, g_maindriver_filename)) ) return ERROR_INSUFFICIENT_BUFFER;
	
	if ( (status = make_driver_path(dest_path, _countof(dest_path), g_maindriver_filename)) != NO_ERROR ) return status;
	
	if ( (status = make_driver_path(temp_path, _countof(temp_path), _T("dcrypt_old.sys"))) != NO_ERROR ) return status;

	// Note: we cannot overwrite a driver in use we need to rename it and remove it upon reboot

	// rename old driver if present
	if (_waccess(dest_path, 0) != -1) {
		if (MoveFileEx(dest_path, temp_path, MOVEFILE_REPLACE_EXISTING) == FALSE) return GetLastError();
	}

	// copy new driver
	if ( CopyFile(source_path, dest_path, FALSE) == FALSE ) return GetLastError();

	// schedule deleting of old driver
	if (_waccess(temp_path, 0) != -1) {
		if (MoveFileEx(temp_path, NULL, MOVEFILE_DELAY_UNTIL_REBOOT) == FALSE) return GetLastError();
	}
	
	return NO_ERROR;
}

static DWORD install_dcrypt_driver_service()
{
	TCHAR     driver_path[MAX_PATH];
	SC_HANDLE h_scm = NULL;
	SC_HANDLE h_svc = NULL;
	DWORD     status;

	if ( (status = make_driver_path(driver_path, _countof(driver_path), g_maindriver_filename)) != NO_ERROR ) {
		goto cleanup;
	}
	if ( (h_scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS)) == NULL ) {
		status = GetLastError();
		goto cleanup;
	}

	if (h_svc = CreateService(h_scm,                  // hSCManager
		                      g_dcrypt_service_name,  // lpServiceName,
							  g_service_description,  // lpDisplayName
		                      SERVICE_ALL_ACCESS,     // dwDesiredAccess
							  SERVICE_KERNEL_DRIVER,  // dwServiceType
							  SERVICE_BOOT_START,     // dwStartType
							  SERVICE_ERROR_CRITICAL, // dwErrorControl
							  driver_path,            // lpBinaryPathName
							  _T("Filter"),           // lpLoadOrderGroup
							  NULL,                   // lpdwTagId
							  _T("FltMgr"),           // lpDependencies
							  NULL, NULL))            // lpServiceStartName, lpPassword
	{
		status = NO_ERROR;
	} else {
		status = GetLastError();
	}
cleanup:
	if (h_svc != NULL) CloseServiceHandle(h_svc);
	if (h_scm != NULL) CloseServiceHandle(h_scm);
	return status;
}

static DWORD remove_service(PCTSTR service_name)
{
	SC_HANDLE h_scm = NULL;
	SC_HANDLE h_svc = NULL;
	DWORD     status;
	
	if ( (h_scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS)) != NULL &&
		 (h_svc = OpenService(h_scm, service_name, SERVICE_ALL_ACCESS)) != NULL &&
		 (DeleteService(h_svc) != FALSE) )
	{
		status = NO_ERROR;
	} else {
		status = GetLastError();
	}
	if (h_svc != NULL) CloseServiceHandle(h_svc);
	if (h_scm != NULL) CloseServiceHandle(h_scm);
	return status;
}

static DWORD add_altitude_info()
{
	HKEY  hkey_1 = NULL;
	HKEY  hkey_2 = NULL;
	DWORD status, flags = 0;

	if ( (status = RegCreateKey(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Services\\dcrypt\\Instances"), &hkey_1)) != NO_ERROR ) goto cleanup;
	if ( (status = RegSetValueEx(hkey_1, _T("DefaultInstance"), 0, REG_SZ, (const BYTE*)_T("dcrypt"), sizeof(_T("dcrypt")))) != NO_ERROR ) goto cleanup;
	
	if ( (status = RegCreateKey(hkey_1, _T("dcrypt"), &hkey_2)) != NO_ERROR ) goto cleanup;
	if ( (status = RegSetValueEx(hkey_2, _T("Altitude"), 0, REG_SZ, (const BYTE*)_T("87150"), sizeof(_T("87150")))) != NO_ERROR ) goto cleanup;
	if ( (status = RegSetValueEx(hkey_2, _T("Flags"), 0, REG_DWORD, (const BYTE*)&flags, sizeof(flags))) != NO_ERROR ) goto cleanup;

	if ( (status = RegFlushKey(hkey_2)) != NO_ERROR ) goto cleanup;
	if ( (status = RegFlushKey(hkey_1)) != NO_ERROR ) goto cleanup;

cleanup:
	if (hkey_2 != NULL) RegCloseKey(hkey_2);
	if (hkey_1 != NULL) RegCloseKey(hkey_1);
	return status;
}

DWORD dc_install_driver()
{
	dc_conf_data config = { DC_DRIVER_VER, (CONF_HW_CRYPTO | CONF_AUTOMOUNT_BOOT), };
	DWORD        status;

	// copy driver to system directory and install driver service
	if ( (status = save_dcrypt_driver_file()) != NO_ERROR ) goto cleanup;
	if ( (status = install_dcrypt_driver_service()) != NO_ERROR ) goto cleanup;
	
	// add Altitude
	if ( (status = add_altitude_info()) != NO_ERROR ) goto cleanup;

	// add Volume and CD-ROM filters
	if ( (status = add_to_reg_multi_sz(g_volume_filter_key, _T("LowerFilters"), g_dcrypt_service_name)) != NO_ERROR ) goto cleanup;
	if ( (status = add_to_reg_multi_sz(g_cdrom_filter_key, _T("UpperFilters"), g_dcrypt_service_name)) != NO_ERROR ) goto cleanup;

#pragma warning( disable : 4996 )
	if (LOBYTE(LOWORD(GetVersion())) >= 6) {
#pragma warning( default : 4996 )
		// add crashdump filter (Vista+)
		if ( (status = add_to_reg_multi_sz(g_crash_filter_key, _T("DumpFilters"), g_maindriver_filename)) != NO_ERROR ) goto cleanup;
	}

	// setup default config
	if ( (status = dc_save_config(&config)) != NO_ERROR ) goto cleanup;

cleanup:
	if (status != NO_ERROR) dc_remove_driver();
	return status;
}

DWORD dc_remove_driver()
{
	TCHAR path[MAX_PATH];
	DWORD status = NO_ERROR, ret;

	// remove Volume AND CD-ROM filters
	if ( (ret = remove_from_reg_multi_sz(g_cdrom_filter_key, _T("UpperFilters"), g_dcrypt_service_name)) != NO_ERROR ) status = ret;
	if ( (ret = remove_from_reg_multi_sz(g_volume_filter_key, _T("LowerFilters"), g_dcrypt_service_name)) != NO_ERROR ) status = ret;

#pragma warning( disable : 4996 )
	if (LOBYTE(LOWORD(GetVersion())) >= 6) {
#pragma warning( default : 4996 )
		// remove crashdump filters (Vista+)
		if ( (ret = remove_from_reg_multi_sz(g_crash_filter_key, _T("DumpFilters"), g_maindriver_filename)) != NO_ERROR ) status = ret;
	}

	// remove service
	if ( (ret = remove_service(g_dcrypt_service_name)) != NO_ERROR ) status = ret;

	// delete driver file
	if ( (ret = make_driver_path(path, _countof(path), g_maindriver_filename)) == NO_ERROR )
	{
		if (MoveFileEx(path, NULL, MOVEFILE_DELAY_UNTIL_REBOOT) == FALSE) status = GetLastError();
	} else {
		status = ret;
	}
	return status;
}

BOOL dc_is_driver_installed()
{
	TCHAR path[MAX_PATH];

	if (make_driver_path(path, _countof(path), g_maindriver_filename) != NO_ERROR) return FALSE;
	if (GetFileAttributes(path) == INVALID_FILE_ATTRIBUTES) return FALSE;
	return TRUE;
}

BOOL dc_is_driver_works()
{
	HANDLE h_device;

	if ( (dc_is_driver_installed() != FALSE) &&
		 (h_device = CreateFile(DC_WIN32_NAME, 0, 0, NULL, OPEN_EXISTING, 0, NULL)) != INVALID_HANDLE_VALUE )
	{
		CloseHandle(h_device);
		return TRUE;
	}
	return FALSE;
}

DWORD dc_update_driver()
{
	TCHAR        buff[MAX_PATH];
	dc_conf_data config;
	DWORD        status;
	
	if ( (status = save_dcrypt_driver_file()) != NO_ERROR ) goto cleanup;
	if ( (status = dc_load_config(&config)) != NO_ERROR ) goto cleanup;

	if (config.build < 692)
	{
		// remove dc_fsf.sys
		if ( (status = make_driver_path(buff, _countof(buff), _T("dc_fsf.sys"))) != NO_ERROR ) goto cleanup;
		DeleteFile(buff);
		// add Altitude
		if ( (status = add_altitude_info()) != NO_ERROR ) goto cleanup;
	}
	if (config.build < 366)
	{
		// add CD-ROM filter
		if ( (status = add_to_reg_multi_sz(g_cdrom_filter_key, _T("UpperFilters"), g_dcrypt_service_name)) != NO_ERROR ) goto cleanup;
		// set new default flags
		config.conf_flags |= CONF_HW_CRYPTO | CONF_AUTOMOUNT_BOOT;
	}
	//if (config.build < 642) {
	//	config.conf_flags |= CONF_ENABLE_SSD_OPT;
	//}
	// Chunking hurts the performance of modern SSD's, disable it
	if (config.build < 851) {
		config.conf_flags &= ~CONF_ENABLE_SSD_OPT;
	}
	
#pragma warning( disable : 4996 )
	if (config.build < 818 && LOBYTE(LOWORD(GetVersion())) >= 6) {
#pragma warning( default : 4996 )
		// add crashdump filter (Vista+)
		if ( (status = add_to_reg_multi_sz(g_crash_filter_key, _T("DumpFilters"), g_maindriver_filename)) != NO_ERROR ) goto cleanup;
	}
	
	if ( (status = dc_save_config(&config)) == NO_ERROR )
	{
		StringCchPrintf(buff, _countof(buff), _T("DC_UPD_%d"), dc_get_version());
		GlobalAddAtom(buff);
	}
cleanup:
	return status;
}





// File list for offline installation
typedef struct _DC_OFFLINE_FILE {
	const wchar_t* source;  // Source filename (in installation directory)
	const wchar_t* target;  // Target path relative to Windows directory
} DC_OFFLINE_FILE;

static const DC_OFFLINE_FILE g_offline_files[] = {
	{ L"dcrypt.sys",	L"Windows\\System32\\Drivers\\dcrypt.sys" }, // must be first
	{ L"dcrypt.sys",	L"Program Files\\dcrypt\\dcrypt.sys" },
	{ L"dcrypt.exe",	L"Program Files\\dcrypt\\dcrypt.exe" },
	{ L"dccon.exe",		L"Program Files\\dcrypt\\dccon.exe" },
	{ L"dcapi.dll",		L"Program Files\\dcrypt\\dcapi.dll" },
#ifdef _M_IX86
	{ L"DcsPkg_IA32.zip",L"Program Files\\dcrypt\\DcsPkg_IA32.zip" },
	{ L"Shim_IA32.zip",  L"Program Files\\dcrypt\\Shim_IA32.zip" },
#elifdef _M_ARM64
	{ L"DcsPkg_AA64.zip",L"Program Files\\dcrypt\\DcsPkg_AA64.zip" },
	{ L"Shim_AA64.zip",  L"Program Files\\dcrypt\\Shim_AA64.zip" },
#else
	{ L"DcsPkg_X64.zip",L"Program Files\\dcrypt\\DcsPkg_X64.zip" },
	{ L"Shim_X64.zip",  L"Program Files\\dcrypt\\Shim_X64.zip" },
#endif
	{ L"dcinst.exe",	L"Program Files\\dcrypt\\dcinst.exe" },
	{ L"license.txt",	L"Program Files\\dcrypt\\license.txt" }
};

// Helper function to enable a privilege
static BOOL EnablePrivilege(LPCWSTR privilegeName)
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return FALSE;

	if (!LookupPrivilegeValueW(NULL, privilegeName, &luid))
	{
		CloseHandle(hToken);
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		CloseHandle(hToken);
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}

// Helper function to enable required privileges for registry hive operations
static BOOL EnableRegistryPrivileges()
{
	BOOL result = TRUE;
	result = EnablePrivilege(SE_BACKUP_NAME) && result;
	result = EnablePrivilege(SE_RESTORE_NAME) && result;
	return result;
}

// Helper function to remove a string from a REG_MULTI_SZ list
static BOOL RemoveFromMultiSz(wchar_t* buffer, DWORD bufferSize, const wchar_t* value)
{
	wchar_t* src = buffer;
	wchar_t* dst = buffer;
	BOOL found = FALSE;

	while (*src)
	{
		if (_wcsicmp(src, value) == 0)
		{
			found = TRUE;
			src += wcslen(src) + 1;
			continue;
		}

		if (src != dst)
		{
			size_t len = wcslen(src) + 1;
			wmemmove(dst, src, len);
			dst += len;
			src += len;
		}
		else
		{
			size_t len = wcslen(src) + 1;
			dst += len;
			src += len;
		}
	}

	if (found)
	{
		*dst = L'\0'; // Double null terminator
		if (dst > buffer)
			dst[1] = L'\0';
	}

	return found;
}

// Helper function to add a string to a REG_MULTI_SZ list
static BOOL AddToMultiSz(wchar_t* buffer, DWORD bufferSize, const wchar_t* value)
{
	wchar_t* p = buffer;
	DWORD len = (DWORD)wcslen(value);

	// Check if value already exists
	while (*p)
	{
		if (_wcsicmp(p, value) == 0)
			return TRUE; // Already present
		p += wcslen(p) + 1;
	}

	// Calculate current size
	DWORD currentSize = (DWORD)((p - buffer) * sizeof(wchar_t));
	DWORD neededSize = currentSize + (len + 1) * sizeof(wchar_t) + sizeof(wchar_t);

	if (neededSize > bufferSize)
		return FALSE; // Not enough space

	// Add new value at the end
	wcscpy_s(p, bufferSize / sizeof(wchar_t) - (p - buffer), value);
	p[len + 1] = L'\0'; // Double null terminator

	return TRUE;
}

// Helper function to prepend a string to a REG_MULTI_SZ list (adds at the beginning)
static BOOL PrependToMultiSz(wchar_t* buffer, DWORD bufferSize, const wchar_t* value)
{
	wchar_t* p = buffer;
	DWORD len = (DWORD)wcslen(value);
	DWORD currentSize = 0;
	wchar_t* end;

	// Check if value already exists at the beginning
	if (*p && _wcsicmp(p, value) == 0)
		return TRUE; // Already at the beginning

	// Find end of multi-sz and check if value exists elsewhere
	while (*p)
	{
		if (_wcsicmp(p, value) == 0)
		{
			// Value exists but not at the beginning - remove it first
			RemoveFromMultiSz(buffer, bufferSize, value);
			break;
		}
		p += wcslen(p) + 1;
	}

	// Calculate current size (excluding value if it was removed)
	p = buffer;
	while (*p)
		p += wcslen(p) + 1;
	currentSize = (DWORD)((p - buffer) * sizeof(wchar_t));

	// Calculate needed size: new value + existing content + double null
	DWORD neededSize = (len + 1) * sizeof(wchar_t) + currentSize + sizeof(wchar_t);
	if (neededSize > bufferSize)
		return FALSE; // Not enough space

	// Shift existing content to make room at the beginning
	if (currentSize > 0)
		wmemmove(buffer + len + 1, buffer, currentSize / sizeof(wchar_t));

	// Insert new value at the beginning
	wcscpy(buffer, value);

	// Ensure proper double null termination
	end = buffer + len + 1;
	while (*end)
		end += wcslen(end) + 1;
	end[1] = L'\0';

	return TRUE;
}

// Helper function to add a filter value to a registry key (prepends to REG_MULTI_SZ)
static LSTATUS AddFilterToRegistry(const wchar_t* keyPath, const wchar_t* valueName, const wchar_t* filterValue)
{
	LSTATUS lResult;
	HKEY hKey;
	DWORD dwType, dwSize;
	wchar_t multiSzBuffer[4096];

	lResult = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ | KEY_WRITE, &hKey);
	if (lResult != ERROR_SUCCESS)
		return lResult;

	dwSize = sizeof(multiSzBuffer);
	ZeroMemory(multiSzBuffer, sizeof(multiSzBuffer));

	lResult = RegQueryValueExW(hKey, valueName, NULL, &dwType, (BYTE*)multiSzBuffer, &dwSize);
	if (lResult != ERROR_SUCCESS || dwType != REG_MULTI_SZ)
	{
		// Value doesn't exist, create it with just the filter
		wcscpy_s(multiSzBuffer, ARRAYSIZE(multiSzBuffer), filterValue);
		multiSzBuffer[wcslen(filterValue) + 1] = L'\0'; // Double null terminator
		dwSize = (DWORD)((wcslen(filterValue) + 2) * sizeof(wchar_t));
	}
	else
	{
		// Prepend filter to existing value (must be first)
		PrependToMultiSz(multiSzBuffer, sizeof(multiSzBuffer), filterValue);

		// Calculate size of multi-sz
		wchar_t* p = multiSzBuffer;
		while (*p)
			p += wcslen(p) + 1;
		dwSize = (DWORD)((p - multiSzBuffer + 1) * sizeof(wchar_t));
	}

	lResult = RegSetValueExW(hKey, valueName, 0, REG_MULTI_SZ, (BYTE*)multiSzBuffer, dwSize);
	RegCloseKey(hKey);

	return lResult;
}

// Helper function to remove a filter value from a registry key (removes from REG_MULTI_SZ)
static LSTATUS RemoveFilterFromRegistry(const wchar_t* keyPath, const wchar_t* valueName, const wchar_t* filterValue)
{
	LSTATUS lResult;
	HKEY hKey;
	DWORD dwType, dwSize;
	wchar_t multiSzBuffer[4096];

	lResult = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ | KEY_WRITE, &hKey);
	if (lResult != ERROR_SUCCESS)
		return lResult;

	dwSize = sizeof(multiSzBuffer);
	ZeroMemory(multiSzBuffer, sizeof(multiSzBuffer));

	lResult = RegQueryValueExW(hKey, valueName, NULL, &dwType, (BYTE*)multiSzBuffer, &dwSize);
	if (lResult == ERROR_SUCCESS && dwType == REG_MULTI_SZ)
	{
		if (RemoveFromMultiSz(multiSzBuffer, sizeof(multiSzBuffer), filterValue))
		{
			// Calculate size of multi-sz
			wchar_t* p = multiSzBuffer;
			while (*p)
				p += wcslen(p) + 1;
			dwSize = (DWORD)((p - multiSzBuffer + 1) * sizeof(wchar_t));

			// If empty, delete the value
			if (multiSzBuffer[0] == L'\0')
				lResult = RegDeleteValueW(hKey, valueName);
			else
				lResult = RegSetValueExW(hKey, valueName, 0, REG_MULTI_SZ, (BYTE*)multiSzBuffer, dwSize);
		}
	}

	RegCloseKey(hKey);
	return lResult;
}

int install_dc_offline(const wchar_t* windows_path)
{
	wchar_t hivePath[MAX_PATH];
	wchar_t sourcePath[MAX_PATH];
	wchar_t sourceFile[MAX_PATH];
	wchar_t targetFile[MAX_PATH];
	wchar_t* p;
	DWORD uInstallPathLen;
	LSTATUS lResult;
	HKEY hKey;
	DWORD dwValue;

	if (windows_path == NULL)
		return ST_INVALID_PARAM;

	// Enable required privileges for registry operations
	if (!EnableRegistryPrivileges())
		return ST_ACCESS_DENIED;

	// Build path to SYSTEM hive
	StringCchPrintfW(hivePath, ARRAYSIZE(hivePath), L"%s\\Windows\\System32\\Config\\SYSTEM", windows_path);

	// Check if hive exists
	if (_waccess(hivePath, 0) != 0)
		return ST_NF_FILE;

	// Get source path (where dcrypt binaries are located)
	if (g_inst_dll == NULL || (uInstallPathLen = GetModuleFileName(g_inst_dll, sourcePath, _countof(sourcePath))) == 0)
		return ST_NF_FILE;
	if (uInstallPathLen >= _countof(sourcePath) - 1 || (p = wcsrchr(sourcePath, L'\\')) == NULL)
		return ST_NF_FILE;
	*p = L'\0';

	// Check if OFFLINE_SYSTEM hive is already loaded
	lResult = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM", 0, KEY_READ, &hKey);
	if (lResult == ERROR_SUCCESS)
	{
		RegCloseKey(hKey);
		// Try to unload it first
		RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM");
	}

	// Load the offline SYSTEM hive
	lResult = RegLoadKeyW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM", hivePath);
	if (lResult != ERROR_SUCCESS)
		return ST_REG_ERROR;

	// Create dcrypt service key
	lResult = RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM\\ControlSet001\\Services\\dcrypt",
		0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
	if (lResult != ERROR_SUCCESS)
	{
		RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM");
		return ST_REG_ERROR;
	}

	// Set Type = 1 (SERVICE_KERNEL_DRIVER)
	dwValue = 1;
	RegSetValueExW(hKey, L"Type", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(dwValue));

	// Set Start = 0 (SERVICE_BOOT_START)
	dwValue = 0;
	RegSetValueExW(hKey, L"Start", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(dwValue));

	// Set ErrorControl = 3 (SERVICE_ERROR_CRITICAL)
	dwValue = 3;
	RegSetValueExW(hKey, L"ErrorControl", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(dwValue));

	// Set ImagePath
	const wchar_t* imagePath = L"\\SystemRoot\\System32\\drivers\\dcrypt.sys";
	RegSetValueExW(hKey, L"ImagePath", 0, REG_EXPAND_SZ, (BYTE*)imagePath,
		(DWORD)((wcslen(imagePath) + 1) * sizeof(wchar_t)));

	// Set DisplayName
	const wchar_t* displayName = L"DiskCryptor driver";
	RegSetValueExW(hKey, L"DisplayName", 0, REG_SZ, (BYTE*)displayName,
		(DWORD)((wcslen(displayName) + 1) * sizeof(wchar_t)));

	// Set Description
	RegSetValueExW(hKey, L"Description", 0, REG_SZ, (BYTE*)displayName,
		(DWORD)((wcslen(displayName) + 1) * sizeof(wchar_t)));

	// Set Group
	const wchar_t* group = L"Filter";
	RegSetValueExW(hKey, L"Group", 0, REG_SZ, (BYTE*)group,
		(DWORD)((wcslen(group) + 1) * sizeof(wchar_t)));

	// Set DependOnService
	wchar_t depend[] = L"FltMgr\0";
	RegSetValueExW(hKey, L"DependOnService", 0, REG_MULTI_SZ, (BYTE*)depend, sizeof(depend));

	RegCloseKey(hKey);

	// Create Instances subkey
	lResult = RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM\\ControlSet001\\Services\\dcrypt\\Instances",
		0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
	if (lResult == ERROR_SUCCESS)
	{
		const wchar_t* defaultInstance = L"dcrypt";
		RegSetValueExW(hKey, L"DefaultInstance", 0, REG_SZ, (BYTE*)defaultInstance,
			(DWORD)((wcslen(defaultInstance) + 1) * sizeof(wchar_t)));
		RegCloseKey(hKey);
	}

	// Create Instances\dcrypt subkey
	lResult = RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM\\ControlSet001\\Services\\dcrypt\\Instances\\dcrypt",
		0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
	if (lResult == ERROR_SUCCESS)
	{
		const wchar_t* altitude = L"87150";
		RegSetValueExW(hKey, L"Altitude", 0, REG_SZ, (BYTE*)altitude,
			(DWORD)((wcslen(altitude) + 1) * sizeof(wchar_t)));

		dwValue = 0;
		RegSetValueExW(hKey, L"Flags", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(dwValue));

		RegCloseKey(hKey);
	}

	// Create config subkey
	lResult = RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM\\ControlSet001\\Services\\dcrypt\\config",
		0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
	if (lResult == ERROR_SUCCESS)
	{
		dwValue = (CONF_HW_CRYPTO | CONF_AUTOMOUNT_BOOT);
		RegSetValueExW(hKey, L"Flags", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(dwValue));

		BYTE hotkeys[16] = {0};
		RegSetValueExW(hKey, L"Hotkeys", 0, REG_BINARY, hotkeys, sizeof(hotkeys));

		dwValue = DC_DRIVER_VER;
		RegSetValueExW(hKey, L"sysBuild", 0, REG_DWORD, (BYTE*)&dwValue, sizeof(dwValue));

		RegCloseKey(hKey);
	}

	// Add dcrypt to LowerFilters for Volume class
	AddFilterToRegistry(L"OFFLINE_SYSTEM\\ControlSet001\\Control\\Class\\{71A27CDD-812A-11D0-BEC7-08002BE2092F}",
		L"LowerFilters", L"dcrypt");

	// Add dcrypt to UpperFilters for DiskDrive class - for CDROM encryption support - deprecated
	//AddFilterToRegistry(L"OFFLINE_SYSTEM\\ControlSet001\\Control\\Class\\{4D36E965-E325-11CE-BFC1-08002BE10318}",
	//	L"UpperFilters", L"dcrypt");

	// Add dcrypt.sys to DumpFilters for CrashControl
	AddFilterToRegistry(L"OFFLINE_SYSTEM\\ControlSet001\\Control\\CrashControl",
		L"DumpFilters", L"dcrypt.sys");

	// Unload the hive
	RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM");

	// create program directory
	StringCchPrintfW(targetFile, ARRAYSIZE(targetFile), L"%s\\Program Files\\dcrypt", windows_path);
	CreateDirectoryW(targetFile, NULL);

	// Copy files
	for (int i = 0; i < ARRAYSIZE(g_offline_files); i++)
	{
		StringCchPrintfW(sourceFile, ARRAYSIZE(sourceFile), L"%s\\%s", sourcePath, g_offline_files[i].source);
		StringCchPrintfW(targetFile, ARRAYSIZE(targetFile), L"%s\\%s", windows_path, g_offline_files[i].target);
		CopyFileW(sourceFile, targetFile, FALSE);
	}

	// add redirector
	StringCchPrintfW(targetFile, ARRAYSIZE(targetFile), L"%s\\Windows\\dccon.cmd", windows_path);
	const char dccon_cmd[] = 
		"rem @echo off\n"
		"if %1 == -gui goto gui\n"
		"\"\\Program Files\\dcrypt\\dccon.exe\" %*\n"
		"goto end\n"
		":gui\n"
		"start \"\" \"\\Program Files\\dcrypt\\dcrypt.exe\"\n"
		":end\n";
	save_file(targetFile, (void*)dccon_cmd, (int)strlen(dccon_cmd));

	return ST_OK;
}

int remove_dc_offline(const wchar_t* windows_path)
{
	wchar_t hivePath[MAX_PATH];
	wchar_t targetFile[MAX_PATH];
	LSTATUS lResult;
	HKEY hKey;

	if (windows_path == NULL)
		return ST_INVALID_PARAM;

	// Enable required privileges for registry operations
	if (!EnableRegistryPrivileges())
		return ST_ACCESS_DENIED;

	// Build path to SYSTEM hive
	StringCchPrintfW(hivePath, ARRAYSIZE(hivePath), L"%s\\Windows\\System32\\Config\\SYSTEM", windows_path);

	// Check if hive exists
	if (_waccess(hivePath, 0) != 0)
		return ST_NF_FILE;

	// Check if OFFLINE_SYSTEM hive is already loaded
	lResult = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM", 0, KEY_READ, &hKey);
	if (lResult == ERROR_SUCCESS)
	{
		RegCloseKey(hKey);
		// Try to unload it first
		RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM");
	}

	// Load the offline SYSTEM hive
	lResult = RegLoadKeyW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM", hivePath);
	if (lResult != ERROR_SUCCESS)
		return ST_REG_ERROR;

	// Remove dcrypt from LowerFilters for Volume class
	RemoveFilterFromRegistry(L"OFFLINE_SYSTEM\\ControlSet001\\Control\\Class\\{71A27CDD-812A-11D0-BEC7-08002BE2092F}",
		L"LowerFilters", L"dcrypt");

	// Remove dcrypt from UpperFilters for DiskDrive class - for CDROM encryption support
	RemoveFilterFromRegistry(L"OFFLINE_SYSTEM\\ControlSet001\\Control\\Class\\{4D36E965-E325-11CE-BFC1-08002BE10318}",
		L"UpperFilters", L"dcrypt");

	// Remove dcrypt.sys from DumpFilters for CrashControl
	RemoveFilterFromRegistry(L"OFFLINE_SYSTEM\\ControlSet001\\Control\\CrashControl",
		L"DumpFilters", L"dcrypt.sys");

	// Delete dcrypt service key
	RegDeleteTreeW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM\\ControlSet001\\Services\\dcrypt");

	// Unload the hive
	RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"OFFLINE_SYSTEM");

	// Delete files driver
	StringCchPrintfW(targetFile, ARRAYSIZE(targetFile), L"%s\\%s", windows_path, g_offline_files[0].target);
	DeleteFileW(targetFile);

	// remove redirectors
	StringCchPrintfW(targetFile, ARRAYSIZE(targetFile), L"%s\\Windows\\dccon.cmd", windows_path);
	DeleteFileW(targetFile);

	return ST_OK;
}