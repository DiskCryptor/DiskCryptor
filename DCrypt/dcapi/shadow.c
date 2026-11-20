/*
	*
	* DiskCryptor - open source partition encryption tool
	* Copyright (c) 2026
	* DavidXanatos <info@diskcryptor.org>

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

/*
 * Shadow copies of a volume: counted with the volsnap query (no COM, no VSS service), deleted
 * with vssadmin ("delete shadows" exists on client and server Windows). See shadow.h.
 */

#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include "shadow.h"
#include "dcconst.h"

/* ntddsnap.h (not in the public SDK): handled by volsnap, an upper filter of every volume */
#define DC_VOLSNAPCONTROLTYPE                     0x00000053 /* 'S' */
#define DC_IOCTL_VOLSNAP_QUERY_NAMES_OF_SNAPSHOTS CTL_CODE(DC_VOLSNAPCONTROLTYPE, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _DC_VOLSNAP_NAMES {
	ULONG MultiSzLength;  /* bytes of Names, including the final empty string */
	WCHAR Names[1];       /* \Device\HarddiskVolumeShadowCopyN\0 ... \0 */
} DC_VOLSNAP_NAMES;

#define DC_VSS_DELETE_TIMEOUT (10 * 60 * 1000) /* many old snapshots can take minutes */

static int dc_volume_path_ok(const wchar_t *w32_device)
{
	return w32_device != NULL && wcsncmp(w32_device, L"\\\\?\\Volume{", 11) == 0 && wcslen(w32_device) < MAX_PATH - 2;
}

int dc_count_shadows(const wchar_t *w32_device, int *count)
{
	DC_VOLSNAP_NAMES  probe;
	DC_VOLSNAP_NAMES *names;
	HANDLE            h;
	DWORD             bytes, len, err;
	int               resl = ST_ERROR, n, attempt;
	const wchar_t    *p, *end;

	*count = 0;
	/* also a volume without a GUID name (the Windows 7 EFI system partition, listed as
	   \\?\GLOBALROOT\Device\HarddiskVolumeN): the volsnap query needs only a handle */
	if (!dc_volume_path_ok(w32_device) &&
		!(w32_device != NULL && wcsncmp(w32_device, L"\\\\?\\GLOBALROOT\\Device\\", 22) == 0 && wcslen(w32_device) < MAX_PATH - 2)) {
		return ST_INVALID_PARAM;
	}

	/* the volume itself (no trailing backslash), no access needed: FILE_ANY_ACCESS */
	h = CreateFileW(w32_device, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
	if (h == INVALID_HANDLE_VALUE) return ST_ERROR;

	/* first the length (ERROR_MORE_DATA), then the names; again if snapshots appear meanwhile */
	for (attempt = 0; attempt < 4; attempt++)
	{
		memset(&probe, 0, sizeof(probe));
		if (DeviceIoControl(h, DC_IOCTL_VOLSNAP_QUERY_NAMES_OF_SNAPSHOTS, NULL, 0, &probe, sizeof(probe), &bytes, NULL) == 0)
		{
			err = GetLastError();
			if (err == ERROR_INVALID_FUNCTION) {
				/* no volsnap on this volume (e.g. some removable media): it can have no shadow copies.
				   Anything else (also ERROR_NOT_SUPPORTED from some other filter) is "not known". */
				resl = ST_OK; break;
			}
			if (err != ERROR_MORE_DATA) break;
		}
		if (probe.MultiSzLength > 16 * 1024 * 1024) break;
		len = FIELD_OFFSET(DC_VOLSNAP_NAMES, Names) + probe.MultiSzLength + 64 * sizeof(WCHAR);
		if ( (names = (DC_VOLSNAP_NAMES*)malloc(len)) == NULL ) {
			resl = ST_NOMEM; break;
		}
		memset(names, 0, len);
		if (DeviceIoControl(h, DC_IOCTL_VOLSNAP_QUERY_NAMES_OF_SNAPSHOTS, NULL, 0, names, len, &bytes, NULL) == 0) {
			err = GetLastError();
			free(names);
			if (err == ERROR_MORE_DATA) continue;
			break;
		}
		/* count the non-empty strings within the returned length */
		p   = names->Names;
		end = (const wchar_t*)((const BYTE*)names->Names + min(names->MultiSzLength, len - FIELD_OFFSET(DC_VOLSNAP_NAMES, Names)));
		for (n = 0; p < end && *p != 0; n++) {
			while (p < end && *p != 0) p++;
			p++;
		}
		free(names);
		*count = n;
		resl = ST_OK;
		break;
	}
	CloseHandle(h);
	return resl;
}

int dc_delete_shadows(const wchar_t *w32_device, int *remaining, volatile LONG *abort)
{
	wchar_t             exe[MAX_PATH], cmd[MAX_PATH * 2];
	STARTUPINFOW        si;
	PROCESS_INFORMATION pi;
	UINT                n;
	ULONGLONG           end;
	int                 left = -1, resl;

	*remaining = -1;
	if (!dc_volume_path_ok(w32_device)) return ST_INVALID_PARAM;

	n = GetSystemDirectoryW(exe, MAX_PATH);
	if (n == 0 || n > MAX_PATH - 16) return ST_ERROR;
	wcscat_s(exe, MAX_PATH, L"\\vssadmin.exe");
	/* /for= takes the volume GUID path with its trailing backslash */
	_snwprintf_s(cmd, countof(cmd), _TRUNCATE, L"\"%s\" delete shadows /for=%s\\ /all /quiet", exe, w32_device);

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	memset(&pi, 0, sizeof(pi));
	if (CreateProcessW(exe, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi) == 0) {
		return ST_ERROR;
	}
	/* the exit code is not trusted (also nonzero when there was nothing to delete): the count
	   afterwards decides. A cancel or the timeout ends vssadmin (a hung VSS service must not
	   block the caller). */
	end = GetTickCount64() + DC_VSS_DELETE_TIMEOUT;
	while (WaitForSingleObject(pi.hProcess, 250) == WAIT_TIMEOUT) {
		if ((abort != NULL && *abort != 0) || GetTickCount64() >= end) {
			TerminateProcess(pi.hProcess, ERROR_CANCELLED);
			WaitForSingleObject(pi.hProcess, 5000);
			break;
		}
	}
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	if ( (resl = dc_count_shadows(w32_device, &left)) != ST_OK ) {
		return resl;
	}
	*remaining = left;
	return left == 0 ? ST_OK : ST_ERROR;
}
