/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2019-2026
	* DavidXanatos <info@diskcryptor.org>
	* Copyright (c) 2007-2010
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

#include "main.h"
#include "subs.h"

#include "threads.h"
#include "ntdll.h"

void __error_s(
		HWND     hwnd,
		wchar_t *pws_format, 
		int      e_code, 
		...
	)
{
	wchar_t msg[MAX_PATH - 20];
	wchar_t est[128];
	va_list args;

	va_start(args, e_code);
	if ( pws_format != NULL )
	{
		_vsnwprintf(
			msg, countof(msg), pws_format, args
			);
	} else {
		msg[0] = 0;
	}

	va_end(args);

	if (e_code < 0) // windows system error code
	{
		wchar_t* lpMsgBuf;
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, -e_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL);
		_snwprintf(est, countof(est), L"\nError: %s", lpMsgBuf);
		wcscat(msg, est);
		LocalFree(lpMsgBuf);
	}
	else if (e_code != ST_OK) 
	{
		wchar_t* status_str = dc_get_status_str(e_code);
		if(status_str)
			_snwprintf( est, countof(est), L"\nError: %s", status_str );
		else
			_snwprintf( est, countof(est), L"\nError code: %d", e_code );
		wcscat(msg, est);
	}
	__msg_e( hwnd, msg );
}


static int _msg_va(
		HWND     hwnd, 
		wchar_t *format, 
		wchar_t *caption, 
		int      type, 
		va_list  args
	)
{
	wchar_t msg[MAX_PATH];
	
	if (format != NULL)
	{
		_vsnwprintf(
			msg, countof(msg), format, args
			);
	} else {
		msg[0] = 0;
	}
	return MessageBox(hwnd, msg, caption, type);
}


int __msg_i( 
		HWND     hwnd, 
		wchar_t *format, 
		... 
	)
{
	va_list args;
	int     resl;

	va_start(args, format);

	resl = _msg_va(
		hwnd, format, L"Information", MB_OK | MB_ICONINFORMATION, args
		);

	va_end(args);
	return resl;
}


int __msg_q(
		HWND     hwnd, 
		wchar_t *format, 
		...
	)
{
	va_list args;
	int     resl;

	va_start(args, format);

	resl = _msg_va(
		hwnd, format, L"Confirm", MB_YESNO | MB_ICONQUESTION, args
		);

	va_end(args);
	return resl == IDYES;
}

int __msg_q3(
	HWND     hwnd, 
	wchar_t *format, 
	...
)
{
	va_list args;
	int     resl;

	va_start(args, format);

	resl = _msg_va(
		hwnd, format, L"Confirm", MB_YESNOCANCEL | MB_ICONQUESTION, args
	);

	va_end(args);
	if (resl == IDYES) return 1;
	if (resl == IDNO) return 0;
	return -1;
}


void _get_status_text(
		_dnode  *node,
		wchar_t *text,
		int      len
	)
{
	wchar_t *act_name = STR_NULL;
	dc_status *st = &node->mnt.info.status;

	*text = L'\0';
	if (st &&st->dsk_size)
	{
		_dact *act = _create_act_thread(node, -1, -1);
		if (DC_IS_LOCKED(st->flags))
		{
			/* keys erased at hibernation, I/O fails until unlocked or unmounted */
			wcscat_s(text, len, L"locked");
		} else if (st->flags & F_ENABLED)
		{
			if (st->mnt_flags & MF_USE_BACKUP) 
				wcscat_s(text, len, L"backup ");
			wcscat_s(text, len, L"mounted");
		}
		if (act && act->status == ACT_RUNNING) 
		{
			int prc = (int)(st->tmp_size/(st->dsk_size/100));
			if (act->act == ACT_DECRYPT) prc = 100 - prc;

			switch (act->act) 
			{
				case ACT_REENCRYPT: act_name = L"reencrypt"; break;
				case ACT_ENCRYPT:   act_name = L"encrypt";   break;

				case ACT_DECRYPT:   act_name = L"decrypt";   break;
				case ACT_FORMAT:    act_name = L"format";    break;
			}
			if (DC_IS_LOCKED(st->flags)) {
				_snwprintf(text, len, L"locked (%s %.02d%%)", act_name, prc);
			} else {
				_snwprintf(text, len, L"%s %.02d%%", act_name, prc);
			}

		}
	}
}

void _reboot( )
{
	int rlt;

	if ( (rlt = enable_privilege(SE_SHUTDOWN_NAME)) == ST_OK )
	{
		ExitWindowsEx(EWX_REBOOT | EWX_FORCE, 0);
		ExitProcess(0);
	} else {
		__error_s( HWND_DESKTOP, NULL, rlt );
	}
}


wchar_t *_mark(
		double   digit,
		wchar_t *text,
		wchar_t  dec
	)
{
	wchar_t  ws_dsp[100];
	wchar_t *result = text;
	wchar_t *pws_dsp = (wchar_t *)&ws_dsp;
	size_t   trim;
	size_t   k;

	_snwprintf( pws_dsp, 50, L"%.2f", digit );

	trim = wcslen(pws_dsp) % 3;
	mincpy( text, ws_dsp, trim );

	for ( pws_dsp += trim, text += trim,
		  k = wcslen(pws_dsp) / 3-1;
		  k; k-- ) 
	{
		if ( trim )
		{
			*text++ = '\x2c'; 
		} else {
			trim = 1;
		}
		mincpy( text, pws_dsp, 3 );
		text += 3; pws_dsp += 3;
	}
	if ( dec )
	{
		mincpy( text, pws_dsp, 3 );
	}
	*text = '\0';
	return result;

}


void _set_trailing_slash( wchar_t *s_path )
{
	int len = (int)(wcslen(s_path));

	if (len && (s_path[len - 1] != L'\\')) 
	{
		s_path[len] = L'\\'; 
		s_path[len + 1] = 0;
	}
}


wchar_t *_extract_name( wchar_t *s_path )
{
	int len = (int)(wcslen(s_path));
	int cnt = len - 1;

	if (len == 0) return NULL;

	while (cnt && s_path[cnt] != '\\') cnt--;
	if (cnt <= 0) 
	{
		return NULL;
	} else {
		return ((wchar_t *)s_path) + cnt + 1;
	}
}


void *_extract_rsrc(
		int     id,
		LPWSTR  type,
		int    *size
	)
{
	void *p_data = NULL;
	
	HGLOBAL h_glb;
	HRSRC   h_res;

	h_res = FindResource(
		__hinst, MAKEINTRESOURCE(id), type
		);
	
	if ( h_res ) 
	{
		*size = SizeofResource(__hinst, h_res);

		h_glb = LoadResource(__hinst, h_res);
		p_data = LockResource(h_glb);
	} 
	return p_data;
}


int _bitcount( DWORD n )
{
	int count = 0;
	while (n) 
	{
		count += n & 0x1u;
		n >>= 1;
	}
	return count;

}

BOOL _array_include(
		int arr[ ], 
		int find
	)
{
	int k = 0;
	for ( ; k < WZR_MAX_STEPS; k++ )
	{
		if ( arr[k] == find )
		{
			return TRUE;
		}
	}
	return FALSE;
}


int _ext_disk_num(
		HWND hwnd
	)
{
	wchar_t vol[MAX_PATH];
	wchar_t *num_offset;
	
	_get_item_text(
		hwnd, ListView_GetSelectionMark(hwnd), 0, vol, countof(vol)
		);

	num_offset = wcschr(vol, ' ');

	return (
		num_offset ? _wtoi(num_offset) : -1
	);
}

void _log(
		wchar_t *pws_message,
		...
	)
{
	PROCESS_BASIC_INFORMATION pbi;
	int                       last_error = GetLastError( );
	wchar_t                   ws_args[MAX_PATH] = { 0 };
	wchar_t                   ws_line[MAX_PATH] = { 0 };
	HANDLE                    h_file;
	DWORD                     bytes;
	va_list                   args;
	static int                count = 0;
	wchar_t                   ws_name[MAX_PATH];
	NTSTATUS                  status;

	status = 
		NtQueryInformationProcess( 
		GetCurrentProcess( ), ProcessBasicInformation, &pbi, sizeof(pbi), NULL 
		);
	{
		_snwprintf( ws_name, countof(ws_name), L"dcrypt_%d.log", status == 0 ? (int)pbi.UniqueProcessId : 0 );
	}

	h_file = CreateFile(
		ws_name, GENERIC_WRITE, FILE_SHARE_READ, NULL, 
		count == 0 ? CREATE_ALWAYS : OPEN_ALWAYS, 0, NULL
		);

	if ( h_file == INVALID_HANDLE_VALUE ) return;	
	if ( SetFilePointer(h_file, 0, 0, FILE_END) != INVALID_SET_FILE_POINTER )
	{
		va_start( args, pws_message );
		if ( pws_message != NULL )
		{
			_vsnwprintf( ws_args, countof(ws_line), pws_message, args );
		}
		va_end( args );

		_snwprintf( ws_line, countof(ws_line), L"line:%0.4X last error:%0.8X message:%s\r\n", count++, last_error, ws_args );

		WriteFile( h_file, _wcsupr(ws_line), d32(wcslen(ws_line) * sizeof(wchar_t)), &bytes, NULL );

		CloseHandle(h_file);
	}
}