/*
	*
	* DiskCryptor - open source partition encryption tool
	* Copyright (c) 2019-2026
	* DavidXanatos <info@diskcryptor.org>
	* partial copyright 2013-2017 IDRIX from the VeraCrypt project

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
#include <shlobj.h>
#include <shtypes.h>
#include <KnownFolders.h>
#include <stdio.h>
#include <tchar.h>
#include <strsafe.h>
#include "w10.h"
#include "misc.h"
#include "dcconst.h"

#pragma comment( lib, "Ole32.lib" )

typedef HRESULT(WINAPI *SHGETKNOWNFOLDERPATH) (
	_In_     const GUID*      rfid,
	_In_     DWORD            dwFlags,
	_In_opt_ HANDLE           hToken,
	_Out_    PWSTR            *ppszPath
	);

/*
 * Use RtlGetVersion to get Windows version because GetVersionEx is affected by application manifestation.
 */
typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

static BOOL GetWindowsVersion(LPOSVERSIONINFOW lpVersionInformation)
{
	BOOL bRet = FALSE;
	RtlGetVersionPtr RtlGetVersionFn = (RtlGetVersionPtr)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlGetVersion");
	if (RtlGetVersionFn != NULL)
	{
		if (ERROR_SUCCESS == RtlGetVersionFn(lpVersionInformation))
			bRet = TRUE;
	}

	if (!bRet)
#pragma warning( disable : 4996 )
		bRet = GetVersionExW(lpVersionInformation);
#pragma warning( default : 4996 )

	return bRet;
}

int is_w10_reflect_supported()
{
	OSVERSIONINFOEXW os;
	os.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
	if (GetWindowsVersion((LPOSVERSIONINFOW)&os) == FALSE)
		return 0;
	// starting from Windows 10 1607 (Build 14393), ReflectDrivers in Setupconfig.ini is supported
	return os.dwMajorVersion >= 10 && os.dwBuildNumber >= 14393;
}

BOOL GetSetupconfigLocation(wchar_t* path, DWORD cchSize)
{
	wchar_t szShell32Path[MAX_PATH] = { 0 };
	HMODULE hShell32 = NULL;
	BOOL bResult = FALSE;

	path[0] = 0;

	if (GetSystemDirectory(szShell32Path, MAX_PATH))
		StringCchCatW(szShell32Path, MAX_PATH, L"\\Shell32.dll");
	else
		StringCchCopyW(szShell32Path, MAX_PATH, L"C:\\Windows\\System32\\Shell32.dll");

	hShell32 = LoadLibrary(szShell32Path);
	if (hShell32)
	{
		SHGETKNOWNFOLDERPATH SHGetKnownFolderPathFn = (SHGETKNOWNFOLDERPATH)GetProcAddress(hShell32, "SHGetKnownFolderPath");
		if (SHGetKnownFolderPathFn)
		{
			wchar_t* pszUsersPath = NULL;
			if (S_OK == SHGetKnownFolderPathFn(&FOLDERID_UserProfiles, 0, NULL, &pszUsersPath))
			{
				StringCchPrintfW(path, cchSize, L"%s\\Default\\AppData\\Local\\Microsoft\\Windows\\WSUS\\", pszUsersPath);
				CoTaskMemFree(pszUsersPath);
				bResult = TRUE;
			}
		}
		FreeLibrary(hShell32);
	}

	if (!bResult && is_w10_reflect_supported())
	{
		StringCchPrintfW(path, cchSize, L"%c:\\Users\\Default\\AppData\\Local\\Microsoft\\Windows\\WSUS\\", szShell32Path[0]);
		bResult = TRUE;
	}

	return bResult;
}

int update_w10_reflect_driver()
{
	wchar_t szSetupconfigLocation[MAX_PATH + 20];
	DWORD	uInstallPathLen;
	TCHAR	szInstallPath[MAX_PATH], *p;
	wchar_t wszBuffer[2 * MAX_PATH];

	if (!GetSetupconfigLocation(szSetupconfigLocation, ARRAYSIZE(szSetupconfigLocation)))
		return ST_NF_FILE;
	CreateDirectoryW(szSetupconfigLocation, NULL);
	StringCchCatW(szSetupconfigLocation, ARRAYSIZE(szSetupconfigLocation), L"SetupConfig.ini");

	if (g_inst_dll == NULL || (uInstallPathLen = GetModuleFileName(g_inst_dll, szInstallPath, _countof(szInstallPath))) == 0) return ST_NF_FILE;
	if (uInstallPathLen >= _countof(szInstallPath) - 1 || (p = wcsrchr(szInstallPath, '\\')) == NULL) return ST_NF_FILE;
	*p = L'\0';

	if ( !((0 < GetPrivateProfileStringW(L"SetupConfig", L"ReflectDrivers", L"", wszBuffer, ARRAYSIZE(wszBuffer), szSetupconfigLocation)) && (_wcsicmp(wszBuffer, szInstallPath) == 0)) )
	{
		wsprintf(wszBuffer, L"\"%s\"", szInstallPath);
		WritePrivateProfileStringW(L"SetupConfig", L"ReflectDrivers", wszBuffer, szSetupconfigLocation);

		wsprintf(wszBuffer, L"\"%s\\PostOOBE.cmd\"", szInstallPath);
		WritePrivateProfileStringW(L"SetupConfig", L"PostOOBE", wszBuffer, szSetupconfigLocation);
	}

	return ST_OK;
}

int remove_w10_reflect_driver()
{
	wchar_t szSetupconfigLocation[MAX_PATH + 20];

	if (!GetSetupconfigLocation(szSetupconfigLocation, ARRAYSIZE(szSetupconfigLocation)))
		return ST_NF_FILE;
	StringCchCatW(szSetupconfigLocation, ARRAYSIZE(szSetupconfigLocation), L"SetupConfig.ini");

	if ( _waccess(szSetupconfigLocation,0) != 0 )
	{
		WritePrivateProfileStringW(L"SetupConfig", L"ReflectDrivers", NULL, szSetupconfigLocation);
		WritePrivateProfileStringW(L"SetupConfig", L"PostOOBE", NULL, szSetupconfigLocation);
	}

	return ST_OK;
}