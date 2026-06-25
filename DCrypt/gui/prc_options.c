/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2026
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
#include "prc_options.h"

#include "hotkeys.h"
#include "prc_common.h"
#include "autorun.h"
#include "cert_utils.h"
#include "drv_ioctl.h"
#include "efiinst.h"
#include "../driver/verify.h"

static const WCHAR* _get_cert_type(SCertInfo cert)
{
	if (cert.type == eCertContributor)
		return L"Contributor";
	else if (CERT_IS_TYPE(cert, eCertEternal))
		return L"Eternal";
	else if (cert.type == eCertDeveloper)
		return L"Developer";
	else if (CERT_IS_TYPE(cert, eCertBusiness))
		return L"Business";
	else if (CERT_IS_TYPE(cert, eCertPersonal))
		return L"Personal";
	else if (cert.type == eCertGreatPatreon)
		return L"Great Patreon";
	else if (CERT_IS_TYPE(cert, eCertPatreon))
		return L"Patreon";
	else if (cert.type == eCertFamily)
		return L"Family";
	else if (CERT_IS_TYPE(cert, eCertHome))
		return L"Home";
	else if (CERT_IS_TYPE(cert, eCertEvaluation))
		return L"Evaluation";
	return L"Unknown";
}

static void _update_cert_info(HWND hwnd)
{
	WCHAR info[512] = {0};
	DC_FLAGS2 flags;

	if (dc_device_control(DC_CTL_GET_FLAGS, NULL, 0, &flags, sizeof(flags)) == NO_ERROR) {
		SCertInfo cert;
		cert.State = flags.verify_flags;

		if (cert.active || cert.expired) {
			const WCHAR* type = _get_cert_type(cert);

			swprintf(info, countof(info), L"Type: %s\r\n", type);

			if (cert.expirers_in_sec > 0) {
				int days = cert.expirers_in_sec / (60*60*24);
				swprintf(info + wcslen(info), countof(info) - wcslen(info), L"Expires in: %d days\r\n", days);
			} else if (cert.expirers_in_sec < 0) {
				int days = -cert.expirers_in_sec / (60*60*24);
				swprintf(info + wcslen(info), countof(info) - wcslen(info), L"Expired: %d days ago\r\n", days);
			}

			if (cert.active) {
				wcscat(info, L"Status: Active");
			} else if (cert.expired) {
				wcscat(info, L"Status: Expired");
			}
			if (cert.outdated) {
				wcscat(info, L" (outdated)");
			}
			if (cert.grace_period) {
				wcscat(info, L" (grace period)");
			}
			if (cert.locked) {
				wcscat(info, L" (locked)");
			}
		} else {
			wcscpy(info, L"No valid certificate");
		}
	}

	SetWindowText(hwnd, info);
}

static BOOL g_cert_changed = FALSE;
static WNDPROC g_cert_edit_orig_proc = NULL;

/* Subclass procedure for certificate edit */
static LRESULT CALLBACK _cert_edit_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	/* Detect text modifications */
	if (msg == WM_CHAR || msg == WM_PASTE || msg == WM_CUT || msg == WM_CLEAR)
	{
		g_cert_changed = TRUE;
	}
	if (msg == WM_KEYDOWN && (wParam == VK_DELETE || wParam == VK_BACK))
	{
		g_cert_changed = TRUE;
	}

	/* Ctrl+A - Select All (not natively supported by edit controls) */
	if (msg == WM_KEYDOWN && wParam == 'A' && (GetKeyState(VK_CONTROL) & 0x8000))
	{
		SendMessage(hwnd, EM_SETSEL, 0, -1);
		return 0;
	}
	if (msg == WM_CHAR && wParam == 1)
	{
		/* Eat Ctrl+A char (0x01) to prevent beep */
		return 0;
	}
	return CallWindowProc(g_cert_edit_orig_proc, hwnd, msg, wParam, lParam);
}

INT_PTR
CALLBACK
_options_dlg_proc(
		HWND	hwnd,
		UINT	message,
		WPARAM	wparam,
		LPARAM	lparam
	)
{
	_ctl_init ctl_chk_general[ ] =
	{
		{ STR_NULL, IDC_AUTO_MOUNT_ON_BOOT,		CONF_AUTOMOUNT_BOOT		},
		{ STR_NULL, IDC_EXPLORER_ON_MOUNT,		CONF_EXPLORER_MOUNT		},
		{ STR_NULL, IDC_CACHE_PASSWORDS,		CONF_CACHE_PASSWORD		},
		{ STR_NULL, IDC_UNMOUNT_LOGOFF,			CONF_DISMOUNT_LOGOFF	},
		{ STR_NULL, IDC_FORCE_UNMOUNT,			CONF_FORCE_DISMOUNT		},
		{ STR_NULL, IDC_WIPE_LOGOFF,			CONF_WIPEPAS_LOGOFF		},
		{ STR_NULL, IDC_AUTO_START,				CONF_AUTO_START			},
		{ STR_NULL, IDC_SECURE_DESKTOP,			CONF_SECURE_DESKTOP		}
	};

	_ctl_init ctl_chk_extended[ ] =
	{
		{ STR_NULL, IDC_HARD_CRYPTO_SUPPORT,	CONF_HW_CRYPTO		},
		{ STR_NULL, IDC_HIDE_FILES,				CONF_HIDE_DCSYS		},
		{ STR_NULL, IDC_DISABLE_TRIM,			CONF_DISABLE_TRIM	},
		{ STR_NULL, IDC_SSD_OPTIMIZATION,		CONF_ENABLE_SSD_OPT	}
	};

	_ctl_init static_head_general[ ] = 
	{
		{ L"# Mount Settings",		IDC_HEAD1, 0 },
		{ L"# Password Caching",	IDC_HEAD2, 0 },
		{ L"# Boot Options",		IDC_HEAD3, 0 }
	};

	_ctl_init static_head_extended[ ] =
	{
		{ L"# Extended Settings",	IDC_HEAD1, 0 }
	};

	_ctl_init static_head_support[ ] =
	{
		{ L"# Support Certificate",	IDC_HEAD_SUPPORT, 0 }
	};

	WORD   code             = LOWORD(wparam);
	WORD   id               = LOWORD(wparam);
	DWORD _flags            = 0;
	DWORD _hotkeys[HOTKEYS] = { 0 };

	_wnd_data *wnd;

	int check = 0; 
	int k     = 0;

	switch ( message )
	{
		case WM_INITDIALOG :
		{
			TCITEM     tab_item = { TCIF_TEXT };
			HWND       h_tab    = GetDlgItem( hwnd, IDT_TAB );
			_tab_data *d_tab    = malloc(sizeof(_tab_data));

			wnd = _sub_class(
				h_tab, SUB_NONE,
				CreateDialog( __hinst, MAKEINTRESOURCE(DLG_CONF_GENERAL), GetDlgItem(hwnd, IDC_TAB), _tab_proc ),
				CreateDialog( __hinst, MAKEINTRESOURCE(DLG_CONF_EXTNDED), GetDlgItem(hwnd, IDC_TAB), _tab_proc ),
				CreateDialog( __hinst, MAKEINTRESOURCE(DLG_CONF_HOTKEYS), GetDlgItem(hwnd, IDC_TAB), _tab_proc ),
				CreateDialog( __hinst, MAKEINTRESOURCE(DLG_CONF_SUPPORT), GetDlgItem(hwnd, IDC_TAB), _tab_proc ),
				HWND_NULL
				);

			memset(d_tab, 0, sizeof(_tab_data));

			d_tab->active = wnd->dlg[0];
			wnd_set_long(hwnd, GWL_USERDATA, d_tab);
			{
				for ( k = 0; k < countof(ctl_chk_general); k++ )
				{
					_sub_class( GetDlgItem( wnd->dlg[0], ctl_chk_general[k].id ), SUB_STATIC_PROC, HWND_NULL );
					_set_check( wnd->dlg[0], ctl_chk_general[k].id, __config.conf_flags & ctl_chk_general[k].val );
				}
				for ( k = 0; k < countof(ctl_chk_extended); k++ )
				{
					_sub_class( GetDlgItem( wnd->dlg[1], ctl_chk_extended[k].id ), SUB_STATIC_PROC, HWND_NULL );
					_set_check( wnd->dlg[1], ctl_chk_extended[k].id, __config.conf_flags & ctl_chk_extended[k].val );
				}
				if ( ! (__config.load_flags & DST_HW_CRYPTO) )
				{
					wchar_t s_ch_label[MAX_PATH] = { 0 };

					HWND h_check = GetDlgItem( wnd->dlg[1], IDC_HARD_CRYPTO_SUPPORT );
					EnableWindow( h_check, FALSE );

					GetWindowText( h_check, s_ch_label, countof(s_ch_label) );
					wcscat( s_ch_label, L" (not supported)" );

					SetWindowText( h_check, s_ch_label );
				}
				for ( k = 0; k < countof(static_head_general); k++ )
				{
					SetWindowText(GetDlgItem(wnd->dlg[0], static_head_general[k].id), static_head_general[k].display);
					SendMessage(GetDlgItem(wnd->dlg[0], static_head_general[k].id), (UINT)WM_SETFONT, (WPARAM)__font_bold, 0);
				}
				for ( k = 0; k < countof(static_head_extended); k++ )
				{
					SetWindowText(GetDlgItem(wnd->dlg[1], static_head_extended[k].id), static_head_extended[k].display);
					SendMessage(GetDlgItem(wnd->dlg[1], static_head_extended[k].id), (UINT)WM_SETFONT, (WPARAM)__font_bold, 0);
				}
				SendMessage(
					wnd->dlg[0], WM_USER_CLICK, (WPARAM)GetDlgItem(wnd->dlg[0], IDC_AUTO_START), 0
					);

				_sub_class(
					GetDlgItem(wnd->dlg[2], IDC_KEY_USEEXT), SUB_STATIC_PROC, HWND_NULL
					);

				k = 0;
				while ( hotks_edit[k].id != -1 )
				{
					wchar_t key[200] = { 0 };

					_sub_class(
						GetDlgItem(wnd->dlg[2], hotks_edit[k].id), SUB_KEY_PROC, HWND_NULL
						);

					_sub_class(
						GetDlgItem(wnd->dlg[2], hotks_chk[k].id), SUB_STATIC_PROC, HWND_NULL
						);

					_set_check( wnd->dlg[2], hotks_chk[k].id, __config.hotkeys[k] );
					SendMessage(
						wnd->dlg[2], WM_USER_CLICK, (WPARAM)GetDlgItem(wnd->dlg[2], hotks_chk[k].id), 0
						);

					_key_name(HIWORD( __config.hotkeys[k]), LOWORD(__config.hotkeys[k]), key );
					SetWindowText(GetDlgItem(wnd->dlg[2], hotks_edit[k].id), key);

					((_wnd_data *)wnd_get_long(
						GetDlgItem(wnd->dlg[2], hotks_edit[k].id), GWL_USERDATA)
						)->vk = __config.hotkeys[k];

					k++;
				}

				/* Initialize Support tab */
				{
					WCHAR cert[4096] = {0};
					HWND hCertEdit = GetDlgItem(wnd->dlg[3], IDE_CERTIFICATE);

					/* Set headers with bold font */
					for ( k = 0; k < countof(static_head_support); k++ )
					{
						SetWindowText(GetDlgItem(wnd->dlg[3], static_head_support[k].id), static_head_support[k].display);
						SendMessage(GetDlgItem(wnd->dlg[3], static_head_support[k].id), (UINT)WM_SETFONT, (WPARAM)__font_bold, 0);
					}

					/* Subclass certificate edit for Ctrl+key handling */
					if (hCertEdit) {
						g_cert_edit_orig_proc = (WNDPROC)SetWindowLongPtr(hCertEdit, GWLP_WNDPROC, (LONG_PTR)_cert_edit_proc);
					}

					/* Load existing certificate */
					if (dc_load_certificate(cert, countof(cert)) == ST_OK) {
						SetWindowText(hCertEdit, cert);
					}
					g_cert_changed = FALSE;

					/* Display certificate info */
					_update_cert_info(GetDlgItem(wnd->dlg[3], IDC_CERT_INFO));
				}
			}
			tab_item.pszText = L"General";
			TabCtrl_InsertItem(h_tab, 0, &tab_item);

			tab_item.pszText = L"Extended";
			TabCtrl_InsertItem(h_tab, 1, &tab_item);

			tab_item.pszText = L"Hot Keys";
			TabCtrl_InsertItem(h_tab, 2, &tab_item);

			tab_item.pszText = L"Support";
			TabCtrl_InsertItem(h_tab, 3, &tab_item);
			{
				k = 1;
				while ( wnd->dlg[k] != 0 )
				{
					ShowWindow( wnd->dlg[k], SW_HIDE );
					k++;
				}
			}
			SetForegroundWindow( hwnd );
			return 1L;
		}
		break;

		case WM_NOTIFY :
		{		
			if ( wparam == IDT_TAB )
			{
				if ( ((NMHDR *)lparam)->code == TCN_SELCHANGE )
				{
					HWND h_tab = GetDlgItem(hwnd, IDT_TAB);

					if ( !_is_curr_in_group(h_tab) )
					{
						_change_page( h_tab, TabCtrl_GetCurSel(h_tab) );
					}
				}
			}
		}
		break;

		case WM_COMMAND :
		{
			/* Handle Get Certificate button */
			if ( id == IDB_GET_CERT )
			{
				wnd = wnd_get_long( GetDlgItem(hwnd, IDT_TAB), GWL_USERDATA );
				if ( wnd && wnd->dlg[3] )
				{
					WCHAR serial[256] = {0};
					GetWindowText(GetDlgItem(wnd->dlg[3], IDE_SERIAL_KEY), serial, countof(serial));

					/* Serial key format: DC20X-XXXXX-XXXXX-XXXXX-XXXXX (29 chars) */
					if (wcslen(serial) < 29) {
						__msg_w(hwnd, L"Please enter a valid serial key (format: DC20X-XXXXX-XXXXX-XXXXX-XXXXX)");
					} else {
						PSTR cert = NULL;
						ULONG cert_len = 0;
						int result;

						SetCursor(LoadCursor(NULL, IDC_WAIT));
						result = dc_download_certificate(serial, &cert, &cert_len);
						SetCursor(LoadCursor(NULL, IDC_ARROW));

						if (result == ST_OK && cert) {
							/* Convert UTF-8 to wide string */
							int wlen = MultiByteToWideChar(CP_UTF8, 0, cert, cert_len, NULL, 0);
							WCHAR* wcert = malloc((wlen + 1) * sizeof(WCHAR));
							if (wcert) {
								MultiByteToWideChar(CP_UTF8, 0, cert, cert_len, wcert, wlen);
								wcert[wlen] = 0;
								SetWindowText(GetDlgItem(wnd->dlg[3], IDE_CERTIFICATE), wcert);
								g_cert_changed = TRUE;
								free(wcert);
							}
							my_free(cert);
						} else {
							__error_s(hwnd, L"Failed to download certificate", result);
						}
					}
				}
				return 1L;
			}

			if ( (id == IDOK) || (id == IDCANCEL) )
			{
				wnd = wnd_get_long( GetDlgItem(hwnd, IDT_TAB), GWL_USERDATA );
				if ( wnd ) 
				{
					for ( k = 0; k < countof(ctl_chk_general); k++ )
					{	
						_flags |= _get_check(wnd->dlg[0], ctl_chk_general[k].id) ? ctl_chk_general[k].val : FALSE;
					}
					for ( k = 0; k < countof(ctl_chk_extended); k++ )
					{	
						_flags |= _get_check(wnd->dlg[1], ctl_chk_extended[k].id) ? ctl_chk_extended[k].val : FALSE;
					}
					k = 0;
					while ( hotks_edit[k].id != -1 )
					{					
						if ( _get_check(wnd->dlg[2], hotks_chk[k].id) )
						{
							_hotkeys[k] = (
								(_wnd_data *)wnd_get_long(GetDlgItem(wnd->dlg[2], hotks_edit[k].id), GWL_USERDATA)
								)->vk;
						}
						k++;
					}
				}
				
				if ( id == IDCANCEL ) check = TRUE;
				if ( id == IDOK ) 
				{
					_unset_hotkeys(__config.hotkeys);	
					check = _check_hotkeys(wnd->dlg[0], _hotkeys);					

					if ( check )
					{
						if ( _hotkeys[3] && !__config.hotkeys[3] ) {
							if (! __msg_w( hwnd, L"Set Hotkey to call BSOD?" ) )
							{
								_hotkeys[3] = 0;
							}
						}
						if ( (_flags & CONF_AUTO_START) != (__config.conf_flags & CONF_AUTO_START) )
						{
							autorun_set(_flags & CONF_AUTO_START);
						}
						__config.conf_flags = _flags;
						memcpy(&__config.hotkeys, &_hotkeys, sizeof(DWORD)*HOTKEYS);

						dc_save_config(&__config);

						/* Save certificate from Support tab only if changed (empty = delete) */
						if (g_cert_changed)
						{
							WCHAR cert[4096] = {0};
							GetWindowText(GetDlgItem(wnd->dlg[3], IDE_CERTIFICATE), cert, countof(cert));
							if (dc_save_certificate(cert) == ST_OK) {
								DC_FLAGS2 flags;
								if (dc_device_control(DC_CTL_GET_FLAGS, NULL, 0, &flags, sizeof(flags)) == NO_ERROR) {
									__config.load_flags = flags.load_flags;

									/* Check if certificate is invalid (not active, not expired, but cert provided) */
									SCertInfo certInfo;
									certInfo.State = flags.verify_flags;
									if (!certInfo.active && !certInfo.expired && cert[0] != 0) {
										__msg_e(hwnd, L"The certificate is invalid");
									}
								}
								/* Also update certificate on EFI partition if DCS bootloader is installed */
								dc_efi_update_cert(cert);
							}
							g_cert_changed = FALSE;
						}
					}
					_set_hotkeys(hwnd, __config.hotkeys, FALSE);

				}
				if ( check )
				{
					EndDialog (hwnd, id);
				}
				return 1L;
			}
		}
		break;

		case WM_DESTROY :
		{
			wnd = wnd_get_long( GetDlgItem(hwnd, IDT_TAB), GWL_USERDATA );
			if ( wnd )
			{
				/* Restore certificate edit original proc */
				if (g_cert_edit_orig_proc && wnd->dlg[3]) {
					HWND hCertEdit = GetDlgItem(wnd->dlg[3], IDE_CERTIFICATE);
					if (hCertEdit) {
						SetWindowLongPtr(hCertEdit, GWLP_WNDPROC, (LONG_PTR)g_cert_edit_orig_proc);
					}
					g_cert_edit_orig_proc = NULL;
				}

				for ( k = 0; k < countof(ctl_chk_general); k++ )
				{
					__unsub_class(GetDlgItem(wnd->dlg[0], ctl_chk_general[k].id));
				}
				for ( k = 0; k < countof(ctl_chk_extended); k++ )
				{
					__unsub_class(GetDlgItem(wnd->dlg[1], ctl_chk_extended[k].id));
				}
				__unsub_class(GetDlgItem(wnd->dlg[1], IDC_KEY_USEEXT));

				k = 0;
				while ( hotks_edit[k].id != -1 )
				{
					__unsub_class(GetDlgItem(wnd->dlg[2], hotks_edit[k].id));
					__unsub_class(GetDlgItem(wnd->dlg[2], hotks_chk[k].id));
					k++;
				}
			}
			__unsub_class(GetDlgItem(hwnd, IDT_TAB));

		}
		break;

		default :
		{
			int rlt = _draw_proc(message, lparam);
			if ( rlt != -1 ) 
			{
				return rlt;
			}
		}
	}
	return 0L;

}


int _dlg_options(
		HWND hwnd
	)
{
	int result =
		(int)DialogBoxParam(
				NULL,
				MAKEINTRESOURCE(IDD_DIALOG_OPTIONS),
				hwnd,
				pv( _options_dlg_proc ),
				(LPARAM)NULL
		);

	return (
		result == IDOK ? ST_OK : ST_CANCEL
	);
}