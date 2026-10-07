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
#include <stdlib.h>

#include "main.h"
#include "prc_code.h"

#include "dc_header.h"
#include "rand.h"
#include "cd_enc.h"
#include "benchmark.h"
#include "threads.h"

#include "dlg_menu.h"
#include "dlg_drives_list.h"
#include "drives_list.h"
#include "prc_main.h"
#include "unmount_timer.h"

#if (_MSC_VER >= 1300) && _M_IX86
	extern long _ftol(double);
	extern long _ftol2(double dblSource) { return _ftol(dblSource); }
	extern long _ftol2_sse(double dblSource) { return _ftol2(dblSource); }
#endif

INT_PTR CALLBACK
_link_proc(
		HWND   hwnd,
		UINT   message,
		WPARAM wparam,
		LPARAM lparam
	)
{
	WNDPROC old_proc = pv( GetWindowLongPtr(hwnd, GWL_USERDATA) );
	static BOOL over = FALSE;

	switch (message)
	{
		case WM_SETCURSOR : 
		{
			if ( !over )
			{
				TRACKMOUSEEVENT	track = { sizeof(track) };

				track.dwFlags   = TME_LEAVE;
				track.hwndTrack = hwnd;
	
				over = TrackMouseEvent(&track);
				SetCursor( __cur_hand );	
			}
			return 0L;
		}
		break;

		case WM_MOUSELEAVE : 
		{
			over = FALSE;
			SetCursor( __cur_arrow );

			return 0L;
		}
		break;
	}
	return (
		CallWindowProc(
			old_proc, hwnd, message, wparam, lparam
		)
	);
}


/* Benchmark thread data */
typedef struct _bench_result {
	int  type;        /* 0=cipher, 1=kdf_pbkdf2, 2=kdf_argon2 */
	int  index;       /* cipher index or argon2 cost */
	int  row;         /* list row number */
	int  memory_mib;  /* for argon2 */
	int  time_cost;   /* for argon2 */
	int  parallelism; /* for argon2 */
	double value;     /* speed (MB/s) or time (ms) */
} _bench_result;

typedef struct _bench_thread_data {
	HWND   hwnd;
	HANDLE thread;
	volatile BOOL cancel;
	volatile BOOL running;
	BOOL   use_usermode;  /* TRUE = use _um functions, FALSE = use driver */
} _bench_thread_data;

static _bench_thread_data g_bench_data = { NULL, NULL, FALSE, FALSE, FALSE };

/* Storage for cipher benchmark results to enable sorting */
static _bench_result g_cipher_results[CF_CIPHERS_NUM];
static int g_cipher_result_count = 0;

/* Compare function for qsort - sort by speed descending */
static int _bench_result_compare(const void *a, const void *b)
{
	const _bench_result *ra = (const _bench_result *)a;
	const _bench_result *rb = (const _bench_result *)b;
	/* Sort descending: higher speed first */
	if (ra->value > rb->value) return -1;
	if (ra->value < rb->value) return 1;
	return 0;
}

static DWORD WINAPI _benchmark_thread_proc(LPVOID lparam)
{
	_bench_thread_data *data = (_bench_thread_data *)lparam;
	HWND hwnd = data->hwnd;
	_bench_result *result;
	int row;
	BOOL use_um = data->use_usermode;

	dc_open_device();

	/* --- Cipher benchmarks --- */
	{
		dc_bench_info info;
		int i;
		int bench_result;

		for (i = 0; i < CF_CIPHERS_NUM && !data->cancel; i++)
		{
			if (use_um)
				bench_result = dc_benchmark_um(i, &info);
			else
				bench_result = dc_benchmark(i, &info);

			if (bench_result != ST_OK) break;

			result = (_bench_result *)malloc(sizeof(_bench_result));
			if (result)
			{
				result->type = 0;
				result->index = i;
				result->row = i;
				result->value = (double)info.datalen / ((double)info.enctime / (double)info.cpufreq) / 1024 / 1024;

				PostMessage(hwnd, WM_BENCHMARK_RESULT, 0, (LPARAM)result);
			}
		}
	}

	/* Signal cipher benchmarks complete - sort and display before KDF */
	if (!data->cancel)
		PostMessage(hwnd, WM_BENCHMARK_RESULT, 2, 0);

	if (data->cancel) goto cleanup;

	/* --- KDF benchmarks --- */
	{
		dc_kdf_bench_info info;
		int i;
		int bench_result;

		row = 0;

		/* Benchmark only KDFs from kdf_names array */
		for (i = 0; wcslen(kdf_names[i].display) && !data->cancel; i++)
		{
			int kdf = kdf_names[i].val;

			if (use_um)
				bench_result = dc_benchmark_kdf_um(kdf, &info);
			else
				bench_result = dc_benchmark_kdf(kdf, &info);

			result = (_bench_result *)malloc(sizeof(_bench_result));
			if (result)
			{
				memset(result, 0, sizeof(_bench_result));
				result->type = (kdf == 0) ? 1 : 2;
				result->index = kdf;
				result->row = row++;
				result->value = (double)info.elapsed_us / 1000.0;
				result->memory_mib = info.memory_mib;
				result->time_cost = info.time_cost;
				result->parallelism = info.parallelism;
				PostMessage(hwnd, WM_BENCHMARK_RESULT, 0, (LPARAM)result);
			}
		}
	}

cleanup:
	data->running = FALSE;
	PostMessage(hwnd, WM_BENCHMARK_RESULT, 1, 0); /* Signal completion */
	return 0;
}

INT_PTR CALLBACK
_benchmark_dlg_proc(
		HWND	hwnd,
		UINT	message,
		WPARAM	wparam,
		LPARAM	lparam
	)
{
	switch ( message )
	{
		case WM_CLOSE :
		{
			if (g_bench_data.running)
			{
				g_bench_data.cancel = TRUE;
				WaitForSingleObject(g_bench_data.thread, 5000);
				CloseHandle(g_bench_data.thread);
				g_bench_data.thread = NULL;
			}
			__lists[HBENCHMARK] = HWND_NULL;
			__lists[HBENCHMARK_KDF] = HWND_NULL;

			EndDialog( hwnd, 0 );
			return 0L;
		}
		break;

		case WM_BENCHMARK_RESULT :
		{
			if (wparam == 1)
			{
				/* Thread completed */
				if (g_bench_data.thread)
				{
					CloseHandle(g_bench_data.thread);
					g_bench_data.thread = NULL;
				}

				EnableWindow(GetDlgItem(hwnd, IDB_REFRESH_TEST), TRUE);
				EnableWindow(GetDlgItem(hwnd, IDB_CANCEL_TEST), FALSE);
				EnableWindow(GetDlgItem(hwnd, IDOK), TRUE);
				SetCursor(__cur_arrow);
			}
			else if (wparam == 2)
			{
				/* Cipher benchmarks complete - sort and redisplay */
				HWND h_cipher_list = __lists[HBENCHMARK];
				int i;

				/* Sort results array by speed descending */
				qsort(g_cipher_results, g_cipher_result_count, sizeof(_bench_result), _bench_result_compare);

				/* Clear and repopulate with sorted results */
				ListView_DeleteAllItems(h_cipher_list);
				for (i = 0; i < g_cipher_result_count; i++)
				{
					wchar_t s_speed[50];
					_snwprintf(s_speed, countof(s_speed), L"%.2f mb/s", g_cipher_results[i].value);

					_list_insert_item(h_cipher_list, i, 0, dc_get_cipher_name(g_cipher_results[i].index), 0);
					_list_set_item(h_cipher_list, i, 1, IDS_MODE_NAME);
					_list_set_item(h_cipher_list, i, 2, s_speed);
				}
			}
			else
			{
				/* Benchmark result (wparam == 0) */
				_bench_result *result = (_bench_result *)lparam;
				HWND h_cipher_list = __lists[HBENCHMARK];
				HWND h_kdf_list = __lists[HBENCHMARK_KDF];

				if (result->type == 0)
				{
					/* Cipher result - display immediately and store for sorting */
					wchar_t s_speed[50];
					_snwprintf(s_speed, countof(s_speed), L"%.2f mb/s", result->value);

					_list_insert_item(h_cipher_list, result->row, 0, dc_get_cipher_name(result->index), 0);
					_list_set_item(h_cipher_list, result->row, 1, IDS_MODE_NAME);
					_list_set_item(h_cipher_list, result->row, 2, s_speed);

					/* Store in array for later sorting */
					if (g_cipher_result_count < CF_CIPHERS_NUM)
					{
						g_cipher_results[g_cipher_result_count++] = *result;
					}
				}
				else if (result->type == 1)
				{
					/* PBKDF2 result */
					wchar_t s_time[64];
					_snwprintf(s_time, countof(s_time), L"%.2f ms", result->value);

					_list_insert_item(h_kdf_list, result->row, 0, L"PBKDF2-SHA512", 0);
					_list_set_item(h_kdf_list, result->row, 1, L"-");
					_list_set_item(h_kdf_list, result->row, 2, L"1000");
					_list_set_item(h_kdf_list, result->row, 3, s_time);
				}
				else if (result->type == 2)
				{
					/* Argon2id result */
					wchar_t s_name[64], s_mem[32], s_iter[32], s_time[64];
					wchar_t *bracket;

					/* Copy name from kdf_names, strip the [...] */
					wcsncpy(s_name, kdf_names[result->row].display, countof(s_name) - 1);
					if ((bracket = wcschr(s_name, L'[')) != NULL) *bracket = L'\0';

					_snwprintf(s_mem, countof(s_mem), L"%d MB", result->memory_mib);
					_snwprintf(s_iter, countof(s_iter), L"%d", result->time_cost);
					if (result->value > 0.0) {
						_snwprintf(s_time, countof(s_time), L"%.2f ms", result->value);
					} else {
						_snwprintf(s_time, countof(s_time), L"OUT OF MEM");
					}

					_list_insert_item(h_kdf_list, result->row, 0, s_name, 0);
					_list_set_item(h_kdf_list, result->row, 1, s_mem);
					_list_set_item(h_kdf_list, result->row, 2, s_iter);
					_list_set_item(h_kdf_list, result->row, 3, s_time);
				}
				free(result);
			}
			return 0L;
		}
		break;

		case WM_COMMAND :
		/*{
			int code = HIWORD(wparam);			
			int id = LOWORD(wparam);

			if ( ( id == IDOK ) || ( id == IDCANCEL ) )
			{
				EndDialog( hwnd, 0 );
			}
			if ( id == IDB_REFRESH_TEST )
			{
				HWND h_button = GetDlgItem( hwnd, IDB_REFRESH_TEST );

				SetCursor( __cur_wait );
				EnableWindow( h_button, FALSE );
				{
					bench_item bench[CF_CIPHERS_NUM];

					wchar_t s_speed[50];
					int cnt;

					int lvcount = 0;
					int k = 0;

					cnt  = _benchmark(pv(&bench));
					ListView_DeleteAllItems( __lists[HBENCHMARK] );
						
					for ( k = 0; k < cnt; k++ )
					{
						_list_insert_item( __lists[HBENCHMARK], lvcount, 0, bench[k].alg, 0 );
						_list_set_item( __lists[HBENCHMARK], lvcount, 1, STR_EMPTY );

						_snwprintf( s_speed, countof(s_speed), L"%-.2f mb/s", bench[k].speed );
						_list_set_item( __lists[HBENCHMARK], lvcount++, 2, s_speed );
					}
				}
				EnableWindow( h_button, TRUE );
				SetCursor( __cur_arrow );
			}
		} */
		{
			int code = HIWORD(wparam);
			int id = LOWORD(wparam);

			if ( id == IDOK )
			{
				if (!g_bench_data.running)
				{
					EndDialog( hwnd, 0 );
				}
			}
			if ( id == IDCANCEL )
			{
				if (g_bench_data.running)
				{
					g_bench_data.cancel = TRUE;
				}
				else
				{
					EndDialog( hwnd, 0 );
				}
			}
			if ( id == IDB_CANCEL_TEST )
			{
				if (g_bench_data.running)
				{
					g_bench_data.cancel = TRUE;
				}
			}
			if ( id == IDB_REFRESH_TEST )
			{
				HWND h_cipher_list = __lists[HBENCHMARK];
				HWND h_kdf_list = __lists[HBENCHMARK_KDF];
				BOOL ctrl_pressed = (GetKeyState(VK_CONTROL) & 0x8000) != 0;

				SetCursor( __cur_wait );
				EnableWindow( GetDlgItem(hwnd, IDB_REFRESH_TEST), FALSE );
				EnableWindow( GetDlgItem(hwnd, IDB_CANCEL_TEST), TRUE );
				EnableWindow( GetDlgItem(hwnd, IDOK), FALSE );

				/* Clear both lists and reset result counter */
				ListView_DeleteAllItems( h_cipher_list );
				ListView_DeleteAllItems( h_kdf_list );
				g_cipher_result_count = 0;

				/* Start worker thread */
				/* CTRL+click = use user-mode benchmark, normal click = use driver */
				g_bench_data.hwnd = hwnd;
				g_bench_data.cancel = FALSE;
				g_bench_data.running = TRUE;
				g_bench_data.use_usermode = ctrl_pressed;
				g_bench_data.thread = CreateThread(NULL, 0, _benchmark_thread_proc, &g_bench_data, 0, NULL);
			}
		}
		break;

		case WM_INITDIALOG :
		{
			/* Initialize cipher benchmark list */
			__lists[HBENCHMARK] = GetDlgItem( hwnd, IDC_LIST_BENCHMARK );
			_init_list_headers( __lists[HBENCHMARK], _benchmark_headers );

			ListView_SetBkColor( __lists[HBENCHMARK], GetSysColor(COLOR_BTNFACE) );
			ListView_SetTextBkColor( __lists[HBENCHMARK], GetSysColor(COLOR_BTNFACE) );
			ListView_SetExtendedListViewStyle( __lists[HBENCHMARK], LVS_EX_FULLROWSELECT );

			/* Initialize KDF benchmark list */
			__lists[HBENCHMARK_KDF] = GetDlgItem( hwnd, IDC_LIST_BENCHMARK_KDF );
			_init_list_headers( __lists[HBENCHMARK_KDF], _kdf_benchmark_headers );

			ListView_SetBkColor( __lists[HBENCHMARK_KDF], GetSysColor(COLOR_BTNFACE) );
			ListView_SetTextBkColor( __lists[HBENCHMARK_KDF], GetSysColor(COLOR_BTNFACE) );
			ListView_SetExtendedListViewStyle( __lists[HBENCHMARK_KDF], LVS_EX_FULLROWSELECT );

			/* Initialize thread data */
			g_bench_data.hwnd = NULL;
			g_bench_data.thread = NULL;
			g_bench_data.cancel = FALSE;
			g_bench_data.running = FALSE;

			SetForegroundWindow(hwnd);

			_sub_class(GetDlgItem(hwnd, IDC_BUTTON), SUB_STATIC_PROC, HWND_NULL);
			return 1L;
		}
		break;

		case WM_CTLCOLOREDIT :
		{
			return (
				_ctl_color(wparam, _cl(COLOR_BTNFACE, LGHT_CLR))
			);
		}
		break;

		default:
		{
			int rlt = _draw_proc(message, lparam);
			if (rlt != -1)
			{
				return rlt;
			}
		}
	}
	return 0L;

}


INT_PTR CALLBACK
_about_dlg_proc(
		HWND	hwnd,
		UINT	message,
		WPARAM	wparam,
		LPARAM	lparam
	)
{
	_ctl_init ctl_links[ ] = 
	{
		{ DC_HOMEPAGE,  IDC_ABOUT_URL1, 0 },
		{ DC_FORUMPAGE, IDC_ABOUT_URL2, 0 }
	};
	static HICON h_icon;

	switch ( message )
	{
		case WM_DESTROY :
		{
			DestroyIcon(h_icon);
			return 0L;
		}
		break;			

		case WM_CLOSE : 
		{
			EndDialog(hwnd, 0);
			return 0L;
		}
		break;

		case WM_COMMAND : 
		{
			int id   = LOWORD(wparam);
			int code = HIWORD(wparam);
			int k;

			if ( code == EN_SETFOCUS )
			{
				SendMessage( (HWND)lparam, EM_SETSEL, -1, 0 );
			}

			if ( id == IDCANCEL || id == IDOK )
			{
				EndDialog(hwnd, 0);
			}
			for ( k = 0; k < countof(ctl_links); k++ )
			{
				if ( id == ctl_links[k].id )
				{
					__execute(ctl_links[k].display);
				}
			}
		}
		break;

		case WM_SHOWWINDOW :
		{
			SetFocus( GetDlgItem(hwnd, IDC_EDIT_NOTICE) );
			SendMessage( GetDlgItem(hwnd, IDC_EDIT_NOTICE), EM_SETSEL, -1, 0 );
		}
		break;

		case WM_INITDIALOG : 
		{
			HWND    h_notice = GetDlgItem(hwnd, IDC_EDIT_NOTICE);
			wchar_t s_display[MAX_PATH];
			BYTE   *res;
			int     size, id_icon;
			int     k = 0;

			res = _extract_rsrc( IDI_ICON_TRAY, RT_GROUP_ICON, &size );

			id_icon = LookupIconIdFromDirectoryEx( res, TRUE, 48, 48, 0 );
			res = _extract_rsrc( id_icon, RT_ICON, &size );
 
			h_icon = CreateIconFromResourceEx( res, size, TRUE, 0x00030000, 48, 48, 0 );
			SendMessage( GetDlgItem(hwnd, IDC_ICON_MAIN), STM_SETICON, (WPARAM)h_icon, 0 );
			{
				HWND h_title = GetDlgItem( hwnd, IDC_ABOUT1 );

				_snwprintf(
					s_display, countof(s_display), L"%s %s%S", DC_NAME, __config.load_flags & DST_PRO_ENABLED ? L"Pro " : L"", DC_FILE_VER
					);

#ifdef _DEBUG
				int ver = dc_get_version( );
				ldr_config conf = {0};
				size_t len = wcslen(s_display);
				_snwprintf(
					s_display + len, countof(s_display) - len, dc_get_ldr_config( -1, &conf ) == ST_OK ? L"/%d.%d" : L"/%d", ver, (int)conf.ldr_ver
				);
#endif

				SetWindowText( h_title, s_display );
				SetWindowText( h_notice,
					L"This program is free software: you can redistribute "
					L"it under the terms of the GNU General Public License "
					L"version 3 as published by the Free Software Foundation.\r\n\r\n"
					L"Contacts: "
					L"info@diskcryptor.org\r\n\r\n"
					//L"ntldr@diskcryptor.net (PGP key ID 0xC48251EB4F8E4E6E)\r\n\r\n"
					//L"Special thanks to:\r\n"
					//L"Aleksey Bragin and ReactOS Foundation\r\n\r\n"
					L"Portions of this software:\r\n"
					L"Copyright \xa9 1998, 2001, 2002 Brian Palmer\r\n"
					L"Copyright \xa9 2003, Dr Brian Gladman, Worcester, UK\r\n"
					L"Copyright \xa9 2006, Rik Snel <rsnel@cube.dyndns.org>\r\n"
					L"Copyright \xa9 Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>\r\n"
					L"Copyright \xa9 Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>\r\n"
					L"Copyright \xa9 Paulo Barreto <paulo.barreto@terra.com.br>\r\n"
					L"Copyright \xa9 Tom St Denis <tomstdenis@gmail.com>\r\n"
					L"Copyright \xa9 Juergen Schmied and Jon Griffiths\r\n"
					L"Copyright \xa9 Lynn McGuire\r\n"
					L"Copyright \xa9 Matthew Skala <mskala@ansuz.sooke.bc.ca>\r\n"
					L"Copyright \xa9 Werner Koch\r\n"
					L"Copyright \xa9 Dag Arne Osvik <osvik@ii.uib.no>\r\n"
					L"Copyright \xa9 Herbert Valerio Riedel <hvr@gnu.org>\r\n"
					L"Copyright \xa9 Wei Dai\r\n"
					L"Copyright \xa9 Ruben Jesus Garcia Hernandez <ruben@ugr.es>\r\n"
					L"Copyright \xa9 Serge Trusov <serge.trusov@gmail.com>"
				);

				SendMessage( h_title, WM_SETFONT, (WPARAM)__font_bold, 0 );
				for ( k = 0; k < countof(ctl_links); k++ )
				{
					HWND h_ctl = GetDlgItem(hwnd, ctl_links[k].id);

					SetWindowLongPtr( h_ctl, GWL_USERDATA, (LONG_PTR)GetWindowLongPtr( h_ctl, GWL_WNDPROC ) );
					SetWindowLongPtr( h_ctl, GWL_WNDPROC, (LONG_PTR)_link_proc );

					SetWindowText( h_ctl, ctl_links[k].display );
					SendMessage( h_ctl, WM_SETFONT, (WPARAM)__font_link, 0 );
					{
						WINDOWINFO pwi;
						SIZE       size;
						HDC        h_dc = GetDC( h_ctl );

						SelectObject( h_dc, __font_link );
						GetTextExtentPoint32( h_dc, ctl_links[k].display, d32(wcslen(ctl_links[k].display)), &size );

						GetWindowInfo( h_ctl, &pwi );
						ScreenToClient( hwnd, pv(&pwi.rcClient) );

						MoveWindow( h_ctl, pwi.rcClient.left, pwi.rcClient.top, size.cx, size.cy, TRUE );
						ReleaseDC( h_ctl, h_dc );
					}
				}
				{
					DC_FLAGS flags;
					
					if ( dc_device_control(DC_CTL_GET_FLAGS, NULL, 0, &flags, sizeof(flags)) == NO_ERROR )
					{
						wchar_t *s_using = L"Not supported";
						wchar_t *s_inset = L"Not supported";

						if ( flags.load_flags & DST_HW_CRYPTO )
						{
							s_using = (
								flags.conf_flags & CONF_HW_CRYPTO ? L"Enabled" : L"Disabled"
							);
							if ( flags.load_flags & DST_INTEL_NI ) s_inset = L"Intel AES Instructions Set (AES-NI)";
							if ( flags.load_flags & DST_VIA_PADLOCK ) s_inset = L"The VIA PadLock Advanced Cryptography Engine (ACE)";
							if ( flags.load_flags & DST_ARM64_CE ) s_inset = L"ARM64 Crypto Extensions (CE)";
						}
						_snwprintf( s_display, countof(s_display), 
							L"Hardware Cryptography: %s\r\n"
							L"Instruction Set: %s",
							s_using, s_inset
						);
						SetWindowText( GetDlgItem(hwnd, IDC_EDIT_CIPHER_INFO), s_display );
						EnableWindow( GetDlgItem(hwnd, IDC_EDIT_CIPHER_INFO), flags.load_flags & DST_HW_CRYPTO );
					}
				}
			}
			SendMessage( h_notice, EM_SCROLLCARET, 0, 0 );
			SetForegroundWindow( hwnd );

			return 1L;
		}
		break;

		default:
		{
			int rlt = _draw_proc( message, lparam );
			if ( rlt != -1 )
			{
				return rlt;
			}
		}
	}
	return 0L;

}


void _dlg_about(
		HWND hwnd
	)
{
	DialogBoxParam(
			NULL,
			MAKEINTRESOURCE( IDD_DIALOG_ABOUT ),
			hwnd,
			pv( _about_dlg_proc ),
			0
	);
}


void _dlg_benchmark(
		HWND hwnd
	)
{
	DialogBoxParam(
			NULL,
			MAKEINTRESOURCE( IDD_DIALOG_BENCHMARK ),
			hwnd,
			pv( _benchmark_dlg_proc ),
			0
	);
}


static BOOL cd_encryption_callback(ULONGLONG isosize, ULONGLONG encsize, PVOID param)
{
	_dnode *node = (_dnode*)param;
	if ( node != NULL )
	{
		HWND h_iso_info = GetDlgItem( node->dlg.h_page, IDC_ISO_PROGRESS );

		wchar_t s_enc_size[MAX_PATH]  = { 0 };
		wchar_t s_ttl_size[MAX_PATH]  = { 0 };

		wchar_t s_done[MAX_PATH]      = { STR_EMPTY };
		wchar_t s_speed[MAX_PATH]     = { STR_EMPTY };
		wchar_t s_percent[MAX_PATH]   = { STR_EMPTY };

		wchar_t s_elapsed[MAX_PATH]   = { STR_EMPTY };
		wchar_t s_estimated[MAX_PATH] = { STR_EMPTY };

		int speed   = _speed_stat_event( s_speed, countof(s_speed), &node->dlg.iso.speed, encsize, TRUE );
		int new_pos = (int)( encsize / ( isosize / PRG_STEP ) );

		if ( speed != 0 )
		{
			_get_time_period( ( ( isosize - encsize ) / 1024 / 1024 ) / speed, s_estimated, TRUE );					
		}
		dc_format_byte_size( s_enc_size, countof(s_enc_size), encsize );
		dc_format_byte_size( s_ttl_size, countof(s_ttl_size), isosize );

		_snwprintf( s_done, countof(s_done), L"%s / %s", s_enc_size, s_ttl_size );

		_get_time_period( node->dlg.iso.speed.t_begin.QuadPart, s_elapsed, FALSE );

		_list_set_item_text( h_iso_info, 0, 1, _wcslwr( s_done ) );
		_list_set_item_text( h_iso_info, 1, 1, _wcslwr( s_speed ) );
		
		_list_set_item_text( h_iso_info, 3, 1, _wcslwr( s_elapsed ) );
		_list_set_item_text( h_iso_info, 4, 1, _wcslwr( s_estimated ) );

		SendMessage(
			GetDlgItem( node->dlg.h_page, IDC_PROGRESS_ISO ), PBM_SETPOS, (WPARAM)new_pos, 0
			);

		_snwprintf(
			s_percent, countof(s_percent), L"%.2f %%", (double)(encsize) / (double)(isosize) * 100 
			);

		SetWindowText( GetDlgItem(node->dlg.h_page, IDC_STATUS_PROGRESS), s_percent);

		return node->dlg.rlt == ST_OK ? TRUE : FALSE;
	}
	return TRUE;	
}


DWORD 
WINAPI 
_thread_enc_iso_proc(
		LPVOID lparam
	)
{
	_dnode *node;
	dc_open_device( );

	if ( (node = pv(lparam)) != NULL )
	{
		node->dlg.rlt = ST_OK;

		node->dlg.rlt = dc_encrypt_iso_image(node->dlg.iso.s_iso_src,
			                                 node->dlg.iso.s_iso_dst,
											 node->dlg.iso.pass,
											 node->dlg.iso.cipher_id,
											 cd_encryption_callback, lparam) == NO_ERROR ? ST_OK : ST_ERROR;
		{
			secure_free( node->dlg.iso.pass );
			SendMessage( GetParent(GetParent(node->dlg.h_page)), WM_CLOSE_DIALOG, 0, 0 );
		}

	}
	//EnterCriticalSection(&crit_sect);
	//LeaveCriticalSection(&crit_sect);

	return 1L;
}


void _activate_page( )
{
	HWND h_tab  = GetDlgItem( __dlg, IDT_INFO );

	_dnode *node = pv( _get_sel_item( __lists[HMAIN_DRIVES] ) );
	_dact  *act  = _create_act_thread( node, -1, -1 );

	if ( ListView_GetSelectedCount( __lists[HMAIN_DRIVES] ) && node && !node->is_root && act )
	{
		NMHDR mhdr = { 0, 0, TCN_SELCHANGE };

		TabCtrl_SetCurSel( h_tab, 1 );
		SendMessage( __dlg, WM_NOTIFY, IDT_INFO, (LPARAM)&mhdr );
	}
}


void _is_breaking_action( )
{
	list_entry *node;
	list_entry *sub;

	int count = 0;
	int k, flag;

	int action;

	wchar_t s_vol[MAX_PATH] = { 0 };

	BOOLEAN pending_headers = FALSE;
	DC_FLAGS flags;
	if ( dc_device_control(DC_CTL_GET_FLAGS, NULL, 0, &flags, sizeof(flags)) == NO_ERROR ) {
		pending_headers = (flags.boot_flags & BDB_BF_HDR_FOUND);
	}

	for ( k = 0; k < 6; k++ )
	{
		if (k % 2 == 0) // 0, 2, 4
		{
			memset(s_vol, 0, sizeof(s_vol));
			count = 0;
			action = 0;
		}

		for ( node = __drives.flink;
					node != &__drives;
					node = node->flink 
					)
		{
			_dnode *root = contain_record(node, _dnode, list);
			
			for ( sub = root->root.vols.flink;
						sub != &root->root.vols;
						sub = sub->flink 
					)
			{
				_dnode *mnt = contain_record(sub, _dnode, list);

				switch (k)
				{
					case 0:
					case 1:  flag = F_FORMATTING; break;
					case 2:
					case 3:  flag = F_SYNC; break;
					case 4:
					case 5:  flag = F_PENDING; break;
					default: flag = -1; break;
				}

				// get auxiliary data
				// Note: these may be reset during msg box so we need to re get them each time
				if (flag == F_PENDING && pending_headers && (mnt->mnt.info.status.flags & F_ENABLED) == 0)  
				{
					if (dc_has_pending_header(mnt->mnt.info.device))
						mnt->mnt.info.status.flags |= F_PENDING;
				}

				if (mnt->mnt.info.status.flags & flag)
				{
					if (k % 2 == 0) // 0, 2, 4
					{
						if (s_vol[0] != L'\0') wcscat(s_vol, L", ");
						wcscat(s_vol, mnt->mnt.info.status.mnt_point);

						count++;

					} else {
						if (action == 1)
						{
							if (k == 1) _menu_format(mnt);
							if (k == 3) _menu_encrypt(mnt);
							if (k == 5) _menu_encrypt2(mnt);
						}
						else if (action == -1)
						{
							if (k == 5) dc_clear_pending_header(mnt->mnt.info.device);
						}
					}
				}
			}
		}

		if ((k % 2 == 0) && count > 0) // 0, 2, 4
		{
			switch (k)
			{
			case 0:
				action = __msg_q(
					__dlg,
					L"Formatting was suspended for volume%s %s.\n\n"
					L"Continue formatting?",
					count > 1 ? L"s" : STR_NULL,
					s_vol);
				break;
			case 2:
				action = __msg_q(
					__dlg,
					L"Encrypting/decrypting was suspended for volume%s %s.\n\n"
					L"Continue encrypting/decrypting?",
					count > 1 ? L"s" : STR_NULL,
					s_vol);
				break;
			case 4:
				action = __msg_q3(
					__dlg,
					L"There %s volume encryption operation%s pending for volume%s %s.\n\n"
					L"Start encrypting?",
					count > 1 ? L"are" : L"is a",
					count > 1 ? L"s" : STR_NULL,
					count > 1 ? L"s" : STR_NULL,
					s_vol);
				break;
			}
		}
	}
}


void __stdcall 
_timer_handle(
		HWND     hwnd,
		UINT     msg,
		UINT_PTR id,
		DWORD    tickcount
	)
{
	int j = 0;
	switch ( id - IDC_TIMER )
	{
		case PROC_TIMER :
		{		
			_update_info_table( FALSE );
		}
		break;

		case MAIN_TIMER :
		{
			EnterCriticalSection( &crit_sect );

			_load_diskdrives( hwnd, &__drives, _list_volumes(0) );
			_update_info_table( FALSE );
			_unmount_timer_purge_unmounted( );

			_set_timer( PROC_TIMER, IsWindowVisible(__dlg_act_info), FALSE );
			_refresh_menu( );
			_update_status_bar( );

			LeaveCriticalSection( &crit_sect );
		}
		break;

		case RAND_TIMER : 
		{
			rnd_reseed_now( );
			_tray_icon(TRUE);
		}
		break;

		case POST_TIMER :
		{
			_set_timer( POST_TIMER, FALSE, FALSE );
			_is_breaking_action( );
		}
		break;

		case UNMOUNT_TIMER :
		{
			_unmount_timer_check( );
		}
		break;
	}
}



