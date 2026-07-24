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
#include "prc_pass.h"

#include "prc_common.h"
#include "prc_keyfiles.h"
#include "pass.h"
#include "volume_header.h"
#include "secure_desktop.h"
#include "unmount_timer.h"


static const _init_list unmount_timeout_units[] = {
	{ UNMOUNT_TIMEOUT_UNIT_SEC,  L"sec" },
	{ UNMOUNT_TIMEOUT_UNIT_MIN,  L"min" },
	{ UNMOUNT_TIMEOUT_UNIT_HOUR, L"hour" },
	{ 0, STR_NULL }
};

// Per-dialog-instance data for password change dialog
typedef struct _pass_change_dlg_data {
	dlgpass        *info;
	keyfiles_state  kf_current;
	keyfiles_state  kf_new;
} _pass_change_dlg_data;

// Per-dialog-instance data for password dialog
typedef struct _pass_dlg_data {
	dlgpass        *info;
	keyfiles_state  kf_current;
} _pass_dlg_data;


/* Helper to move a control up by delta pixels */
static void
_move_ctl_up(HWND hwnd, int ctl_id, int delta_y)
{
	HWND h_ctl = GetDlgItem(hwnd, ctl_id);
	if (h_ctl) {
		RECT rc;
		GetWindowRect(h_ctl, &rc);
		MapWindowPoints(HWND_DESKTOP, hwnd, (POINT *)&rc, 2);
		SetWindowPos(h_ctl, NULL, rc.left, rc.top - delta_y, 0, 0,
			SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
	}
}

/* Helper to resize a control's height by delta pixels */
static void
_shrink_ctl_height(HWND hwnd, int ctl_id, int delta_y)
{
	HWND h_ctl = GetDlgItem(hwnd, ctl_id);
	if (h_ctl) {
		RECT rc;
		GetWindowRect(h_ctl, &rc);
		MapWindowPoints(HWND_DESKTOP, hwnd, (POINT *)&rc, 2);
		SetWindowPos(h_ctl, NULL, 0, 0,
			rc.right - rc.left,
			(rc.bottom - rc.top) - delta_y,
			SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
	}
}


INT_PTR CALLBACK
_password_change_dlg_proc(
		HWND	hwnd,
		UINT	message,
		WPARAM	wparam,
		LPARAM	lparam
	)
{
	WORD code = HIWORD(wparam);
	WORD id   = LOWORD(wparam);

	wchar_t display[MAX_PATH] = { 0 };
	_pass_change_dlg_data *dlg_data = (_pass_change_dlg_data *)GetWindowLongPtr(hwnd, GWLP_USERDATA);
	dlgpass *info = dlg_data ? dlg_data->info : NULL;
	int     k;

	int check_init[ ] = {
		IDC_CHECK_SHOW_CURRENT, IDC_USE_KEYFILES_CURRENT,
		IDC_CHECK_SHOW_NEW, IDC_USE_KEYFILES_NEW,
		IDC_CLEAR_KEY_SLOTS,
		-1
	};

	_ctl_init static_head[ ] = {
		{ L"# Current Password", IDC_HEAD_PASS_CURRENT, 0 },
		{ L"# New Password",     IDC_HEAD_PASS_NEW,     0 },
		{ L"# Password Rating",  IDC_HEAD_RATING,       0 },
		{ STR_NULL, -1, -1 }
	};

	switch (message)
	{
		case WM_CTLCOLOREDIT : return _ctl_color(wparam, _cl(COLOR_BTNFACE, LGHT_CLR));
			break;

		case WM_CTLCOLORSTATIC :
		{
			HDC dc = (HDC)wparam;
			COLORREF bgcolor, fn = 0;

			SetBkMode(dc, TRANSPARENT);

			k = 0;
			while (pass_gr_ctls[k].id != -1)
			{
				if (pass_gr_ctls[k].hwnd == (HWND)lparam)
					fn = pass_gr_ctls[k].color;

				// pass_pe_ctls has fewer entries, check terminator
				if (pass_pe_ctls[k].id != -1 && pass_pe_ctls[k].hwnd == (HWND)lparam)
					fn = pass_pe_ctls[k].color;

				k++;
			}
			SetTextColor(dc, fn);

			bgcolor = GetSysColor(COLOR_BTNFACE);
			SetDCBrushColor(dc, bgcolor);

			return (INT_PTR)GetStockObject(DC_BRUSH);

		}
		break;
		case WM_INITDIALOG :
		{
			dlgpass *init_info = (dlgpass *)lparam;

			// Allocate per-dialog instance data
			dlg_data = secure_alloc(sizeof(_pass_change_dlg_data));
			if (dlg_data == NULL)
			{
				__error_s(hwnd, L"Can't allocate memory", ST_NOMEM);
				EndDialog(hwnd, IDCANCEL);
				return 0L;
			}

			dlg_data->info = init_info;
			_keyfiles_init(&dlg_data->kf_current);
			_keyfiles_init(&dlg_data->kf_new);

			// Set default mix mode based on volume version
			if (init_info->node && (init_info->node->mnt.info.status.flags & F_ENABLED)
			    && init_info->node->mnt.info.status.crypt.version < DC_HDR_VERSION_2)
			{
				dlg_data->kf_current.mix_mode = KEYFILE_MIX_LEGACY;
				dlg_data->kf_new.mix_mode = KEYFILE_MIX_LEGACY;
			}

			SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)dlg_data);
			info = dlg_data->info;

			SendMessage(GetDlgItem(hwnd, IDE_PASS_NEW_CONFIRM), EM_LIMITTEXT, MAX_PASSWORD, 0);
			SendMessage(GetDlgItem(hwnd, IDE_PASS_CURRENT),     EM_LIMITTEXT, MAX_PASSWORD, 0);
			SendMessage(GetDlgItem(hwnd, IDE_PASS_NEW),         EM_LIMITTEXT, MAX_PASSWORD, 0);

			SendMessage(hwnd, WM_COMMAND,
				MAKELONG(IDE_PASS_NEW, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS_NEW));

			if (info->caption) {
				SetWindowText(hwnd, info->caption);
			} else if (info->node) {
				_snwprintf(display, countof(display), L"[%s] - %s",
					info->node->mnt.info.status.mnt_point, info->node->mnt.info.device);
				SetWindowText(hwnd, display);
			} else {
				SetWindowText(hwnd, L"Change password");
			}

			SendMessage(
				GetDlgItem(hwnd, IDP_BREAKABLE),
				PBM_SETBARCOLOR, 0, _cl(COLOR_BTNSHADOW, DARK_CLR-20)
			);

			SendMessage(
				GetDlgItem(hwnd, IDP_BREAKABLE),
				PBM_SETRANGE, 0, MAKELPARAM(0, 193)
			);

			k = 0;
			while (static_head[k].id != -1) {

				SetWindowText(GetDlgItem(hwnd, static_head[k].id), static_head[k].display);
				SendMessage(GetDlgItem(hwnd, static_head[k].id), (UINT)WM_SETFONT, (WPARAM)__font_bold, 0);
				k++;
			}

			k = 0;
			while (check_init[k] != -1) {

				_sub_class(GetDlgItem(hwnd, check_init[k]), SUB_STATIC_PROC, HWND_NULL);
				_set_check(hwnd, check_init[k], FALSE);
				k++;
			}
			{
				int current_kdf = (info->node && info->node->mnt.info.status.flags & F_ENABLED)
					? info->node->mnt.info.status.crypt.head_kdf : KDF_DEFAULT;
				_init_combo(GetDlgItem(hwnd, IDC_COMBO_KDF_CURRENT), kdf_names_ex, current_kdf, FALSE, -1);
				_init_combo(GetDlgItem(hwnd, IDC_COMBO_KDF_NEW), kdf_names, current_kdf, FALSE, -1);
			}
			if (info->node && _is_boot_device(&info->node->mnt.info) && !__is_efi_boot)
			{
				EnableWindow(GetDlgItem(hwnd, IDC_COMBO_KDF_CURRENT), FALSE);
				EnableWindow(GetDlgItem(hwnd, IDC_COMBO_KDF_NEW), FALSE);
			}

			/* Hide current password section and resize dialog for new_pass_only mode */
			if (info->flags & PF_NEW_PASS_ONLY)
			{
				/* Controls in the "current password" section to hide */
				static const int hide_ids[] = {
					IDC_HEAD_PASS_CURRENT,
					IDC_PASS,
					IDE_PASS_CURRENT,
					IDC_NEW_CONFIRM4,
					IDC_PASS_STATUS_CURRENT,
					IDC_CHECK_SHOW_CURRENT,
					IDC_USE_KEYFILES_CURRENT,
					IDB_USE_KEYFILES_CURRENT,
					IDC_KDF_LABEL_CURRENT,
					IDC_COMBO_KDF_CURRENT,
					IDC_CLEAR_KEY_SLOTS,
					-1
				};

				/* Controls to move up (new password section and rating section) */
				static const int move_ids[] = {
					IDC_HEAD_PASS_NEW,
					IDC_NEW_PASS2,
					IDE_PASS_NEW,
					IDC_NEW_CONFIRM2,
					IDE_PASS_NEW_CONFIRM,
					IDC_NEW_CONFIRM3,
					IDC_PASS_STATUS_NEW,
					IDC_CHECK_SHOW_NEW,
					IDC_USE_KEYFILES_NEW,
					IDB_USE_KEYFILES_NEW,
					IDC_KDF_LABEL,
					IDC_COMBO_KDF_NEW,
					IDC_HEAD_RATING,
					IDP_BREAKABLE,
					IDC_PE_UNCRK,
					IDC_PE_HIGH,
					IDC_PE_MEDIUM,
					IDC_PE_LOW,
					IDC_PE_NONE,
					IDC_GR_ALL,
					IDC_GR_CAPS,
					IDC_GR_SMALL,
					IDC_GR_DIGITS,
					IDC_GR_SPACE,
					IDC_GR_SPEC,
					-1
				};

				RECT rc_current, rc_new, rc_dlg;
				int delta_y;
				int i;

				GetWindowRect(GetDlgItem(hwnd, IDC_HEAD_PASS_CURRENT), &rc_current);
				GetWindowRect(GetDlgItem(hwnd, IDC_HEAD_PASS_NEW), &rc_new);
				MapWindowPoints(HWND_DESKTOP, hwnd, (POINT *)&rc_current, 2);
				MapWindowPoints(HWND_DESKTOP, hwnd, (POINT *)&rc_new, 2);

				delta_y = rc_new.top - rc_current.top;

				for (i = 0; hide_ids[i] != -1; i++) {
					ShowWindow(GetDlgItem(hwnd, hide_ids[i]), SW_HIDE);
				}

				for (i = 0; move_ids[i] != -1; i++) {
					_move_ctl_up(hwnd, move_ids[i], delta_y);
				}

				_shrink_ctl_height(hwnd, IDC_FRAME_RIGHT, delta_y);
				_shrink_ctl_height(hwnd, IDC_FRAME_LEFT, delta_y);

				GetWindowRect(hwnd, &rc_dlg);
				SetWindowPos(hwnd, NULL, 0, 0,
					rc_dlg.right - rc_dlg.left,
					(rc_dlg.bottom - rc_dlg.top) - delta_y,
					SWP_NOMOVE | SWP_NOZORDER);
			}

			if (info->flags & PF_RAW_PASSWORD)
			{
				ShowWindow(GetDlgItem(hwnd, IDC_USE_KEYFILES_NEW), SW_HIDE);
				ShowWindow(GetDlgItem(hwnd, IDB_USE_KEYFILES_NEW), SW_HIDE);

				ShowWindow(GetDlgItem(hwnd, IDC_KDF_LABEL), SW_HIDE);
				ShowWindow(GetDlgItem(hwnd, IDC_COMBO_KDF_NEW), SW_HIDE);
			}

			/* On secure desktop, ensure dialog is visible and properly positioned */
			if (is_secure_desktop_active())
			{
				RECT rc_dlg;
				int x, y, w, h;

				GetWindowRect(hwnd, &rc_dlg);
				w = rc_dlg.right - rc_dlg.left;
				h = rc_dlg.bottom - rc_dlg.top;

				/* Center on primary monitor */
				x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
				y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;

				SetWindowPos(hwnd, HWND_TOPMOST, x, y, 0, 0,
					SWP_NOSIZE | SWP_SHOWWINDOW);
				ShowWindow(hwnd, SW_SHOW);
				SetFocus(GetDlgItem(hwnd, IDE_PASS_NEW));
			}
			else
			{
				SetForegroundWindow(hwnd);
			}
			return 1L;

		}
		break;
		case WM_USER_CLICK :
		{
			if ( (HWND)wparam == GetDlgItem(hwnd, IDC_CHECK_SHOW_CURRENT) )
			{
				SendMessage(GetDlgItem(hwnd, IDE_PASS_CURRENT),
					EM_SETPASSWORDCHAR, _get_check(hwnd, IDC_CHECK_SHOW_CURRENT) ? 0 : '*', 0
					);

				InvalidateRect(GetDlgItem(hwnd, IDE_PASS_CURRENT), NULL, TRUE);
				return 1L;

			}
			if ( (HWND)wparam == GetDlgItem(hwnd, IDC_CHECK_SHOW_NEW) )
			{
				int mask = _get_check(hwnd, IDC_CHECK_SHOW_NEW) ? 0 : '*';

				SendMessage(GetDlgItem(hwnd, IDE_PASS_NEW), EM_SETPASSWORDCHAR,	mask, 0);
				SendMessage(GetDlgItem(hwnd, IDE_PASS_NEW_CONFIRM), EM_SETPASSWORDCHAR,	mask, 0);

				InvalidateRect(GetDlgItem(hwnd, IDE_PASS_NEW), NULL, TRUE);
				InvalidateRect(GetDlgItem(hwnd, IDE_PASS_NEW_CONFIRM), NULL, TRUE);
				return 1L;

			}
			if ( (HWND)wparam == GetDlgItem(hwnd, IDC_USE_KEYFILES_CURRENT) )
			{
				SendMessage(
					hwnd, WM_COMMAND, MAKELONG(IDE_PASS_CURRENT, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS_CURRENT)
					);
				EnableWindow(
					GetDlgItem(hwnd, IDB_USE_KEYFILES_CURRENT), _get_check(hwnd, IDC_USE_KEYFILES_CURRENT)
					);
				return 1L;
			}
			if ( (HWND)wparam == GetDlgItem(hwnd, IDC_USE_KEYFILES_NEW) )
			{
				SendMessage(
					hwnd, WM_COMMAND, MAKELONG(IDE_PASS_NEW, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS_NEW)
					);
				EnableWindow(
					GetDlgItem(hwnd, IDB_USE_KEYFILES_NEW), _get_check(hwnd, IDC_USE_KEYFILES_NEW
					));
				return 1L;
			}
		}
		break;
		case WM_COMMAND :

			if ( id == IDB_USE_KEYFILES_CURRENT )
			{
				_dlg_keyfiles( hwnd, &dlg_data->kf_current, TRUE );

				SendMessage(
					hwnd, WM_COMMAND, MAKELONG(IDE_PASS_CURRENT, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS_CURRENT)
					);
			}
			if ( id == IDB_USE_KEYFILES_NEW )
			{
				// For virtual keyfile mode, disable nested virtual keyfiles
				BOOL allow_virtual = !(info->flags & PF_RAW_PASSWORD);
				_dlg_keyfiles( hwnd, &dlg_data->kf_new, allow_virtual );

				SendMessage(
					hwnd, WM_COMMAND, MAKELONG(IDE_PASS_NEW, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS_NEW)
					);
			}

			if ( code == CBN_SELCHANGE && id == IDC_COMBO_KDF )
			{
				SendMessage(
					hwnd, WM_COMMAND, MAKELONG(IDE_PASS_NEW, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS_NEW)
					);
				return 1L;
			}

			if ( code == EN_CHANGE )
			{
				BOOL correct_current, correct_new;
				int  id_stat_current, id_stat_new;

				dc_pass *pass;
				dc_pass *verify;

				ldr_config conf;

				int kb_layout = -1;
				keyfiles_state *kf_state;

				if ( info->node && _is_boot_device(&info->node->mnt.info) )
				{
					if (dc_get_ldr_config( -1, &conf ) == ST_OK)
					{
						kb_layout = conf.kbd_layout;
					}
				}
				if ( id == IDE_PASS_NEW )
				{
					int entropy;
					int header_kdf;
					dc_pass *pass;
					HWND hProgress;

					header_kdf = _get_combo_val(GetDlgItem(hwnd, IDC_COMBO_KDF), kdf_names);
					pass = _get_pass(hwnd, IDE_PASS_NEW);

					_draw_pass_rating(hwnd, pass, kb_layout, header_kdf, &entropy);
					secure_free(pass);

					hProgress = GetDlgItem(hwnd, IDP_BREAKABLE);
					SendMessage(hProgress, PBM_SETPOS, (WPARAM)entropy, 0);
					update_entropy_tooltip(hwnd, hProgress, entropy);
				}

				/* Skip current password validation in new_pass_only mode */
				if (info->flags & PF_NEW_PASS_ONLY) {
					correct_current = TRUE;
				} else {
					pass = _get_pass(hwnd, IDE_PASS_CURRENT);
					kf_state = _get_check(hwnd, IDC_USE_KEYFILES_CURRENT) ? &dlg_data->kf_current : NULL;

					correct_current =
						_input_verify(pass, NULL, kf_state, -1, &id_stat_current
					);

					secure_free(pass);
				}

				pass    = _get_pass(hwnd, IDE_PASS_NEW);
				verify  = _get_pass(hwnd, IDE_PASS_NEW_CONFIRM);
				kf_state = _get_check(hwnd, IDC_USE_KEYFILES_NEW) ? &dlg_data->kf_new : NULL;

				correct_new =
					_input_verify(pass, verify, kf_state, kb_layout, &id_stat_new
					);

				secure_free(pass);
				secure_free(verify);

				if (!(info->flags & PF_NEW_PASS_ONLY)) {
					SetWindowText(GetDlgItem(hwnd, IDC_PASS_STATUS_CURRENT), _get_text_name(id_stat_current, pass_status));
				}
				SetWindowText(GetDlgItem(hwnd, IDC_PASS_STATUS_NEW), _get_text_name(id_stat_new, pass_status));

				EnableWindow(GetDlgItem(hwnd, IDOK), correct_current && correct_new);

				return 1L;

			}
			if ( (id == IDCANCEL) || (id == IDOK) )
			{
				if ( id == IDOK )
				{
					keyfiles_state *kf_current = _get_check(hwnd, IDC_USE_KEYFILES_CURRENT) ? &dlg_data->kf_current : NULL;
					keyfiles_state *kf_new = _get_check(hwnd, IDC_USE_KEYFILES_NEW) ? &dlg_data->kf_new : NULL;

					info->pass     = __get_pass_keyfiles(GetDlgItem(hwnd, IDE_PASS_CURRENT), kf_current != NULL, kf_current);
					info->new_pass = __get_pass_keyfiles(GetDlgItem(hwnd, IDE_PASS_NEW), kf_new != NULL, kf_new);

					if ( !info->pass || !info->new_pass )
						return 1L;

					info->pass->kdf = _get_combo_val(GetDlgItem(hwnd, IDC_COMBO_KDF_CURRENT), kdf_names);
					info->new_pass->kdf = _get_combo_val(GetDlgItem(hwnd, IDC_COMBO_KDF_NEW), kdf_names);

					info->clear_slots = _get_check(hwnd, IDC_CLEAR_KEY_SLOTS);

					if ( IsWindowEnabled(GetDlgItem(hwnd, IDC_COMBO_MNPOINT)) &&
						 info->mnt_point
						 )
					{
						GetWindowText(
							GetDlgItem(hwnd, IDC_COMBO_MNPOINT),
							(wchar_t *)info->mnt_point,
							MAX_PATH
							);
					}
				}
				EndDialog (hwnd, id);
				return 1L;

			}
		break;
		case WM_DESTROY:
		{
			_wipe_pass_control(hwnd, IDE_PASS_NEW_CONFIRM);
			_wipe_pass_control(hwnd, IDE_PASS_CURRENT);
			_wipe_pass_control(hwnd, IDE_PASS_NEW);

			if (dlg_data)
			{
				_keyfiles_wipe(&dlg_data->kf_current);
				_keyfiles_wipe(&dlg_data->kf_new);
				secure_free(dlg_data);
				SetWindowLongPtr(hwnd, GWLP_USERDATA, 0);
			}

			return 0L;
		}
		break;
		default:
		{
			int rlt = _draw_proc(message, lparam);
			if (rlt != -1) return rlt;
		}
	}
	return 0L;

}


INT_PTR CALLBACK
_password_dlg_proc(
		HWND	hwnd,
		UINT	message,
		WPARAM	wparam,
		LPARAM	lparam
	)
{
	WORD code	= HIWORD(wparam);
	WORD id		= LOWORD(wparam);

	wchar_t display[MAX_PATH] = { 0 };
	_pass_dlg_data *dlg_data = (_pass_dlg_data *)GetWindowLongPtr(hwnd, GWLP_USERDATA);
	dlgpass *info = dlg_data ? dlg_data->info : NULL;

	static RECT rc_left  = { 0, 0, 0, 0 };
	static RECT rc_right = { 0, 0, 0, 0 };

	static cut;
	switch ( message )
	{
		case WM_DRAWITEM :
		{
			DRAWITEMSTRUCT *draw = pv(lparam);

			static RECT left;
			static RECT right;

			switch ( draw->CtlID )
			{
				case IDC_FRAME_LEFT:
				{
					if ( !rc_left.right )
					{
						_relative_rect( draw->hwndItem, &rc_left );
						rc_left.bottom -= cut;
					}
					MoveWindow(
						draw->hwndItem, rc_left.left, rc_left.top, rc_left.right, rc_left.bottom, TRUE
						);
				}
				break;
				case IDC_FRAME_RIGHT:
				{
					if ( !rc_right.right )
					{
						_relative_rect( draw->hwndItem, &rc_right );
						rc_right.bottom -= cut;
					}
					MoveWindow(
						draw->hwndItem, rc_right.left, rc_right.top, rc_right.right, rc_right.bottom, TRUE
						);
				}
				break;
			}
			_draw_static( draw );
			return 1L;
		}
		break;
		case WM_CTLCOLOREDIT :
		{
			return (
				_ctl_color( wparam, _cl(COLOR_BTNFACE, LGHT_CLR) )
			);
		}
		break;
		case WM_INITDIALOG :
		{
			dlgpass *init_info = (dlgpass *)lparam;
			int ctl_resize[ ] = {
				IDC_FRAME_LEFT,
				IDC_FRAME_RIGHT,
				-1
			};

			// Allocate per-dialog instance data
			dlg_data = secure_alloc(sizeof(_pass_dlg_data));
			if (dlg_data == NULL)
			{
				__error_s(hwnd, L"Can't allocate memory", ST_NOMEM);
				EndDialog(hwnd, IDCANCEL);
				return 0L;
			}

			dlg_data->info = init_info;
			_keyfiles_init(&dlg_data->kf_current);

			// Set default mix mode based on volume version
			if (init_info->node && (init_info->node->mnt.info.status.flags & F_ENABLED)
			    && init_info->node->mnt.info.status.crypt.version < DC_HDR_VERSION_2)
			{
				dlg_data->kf_current.mix_mode = KEYFILE_MIX_LEGACY;
			}

			SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)dlg_data);
			info = dlg_data->info;

			_init_mount_points( GetDlgItem(hwnd, IDC_COMBO_MNPOINT) );

			SendMessage( GetDlgItem(hwnd, IDC_COMBO_MNPOINT), CB_SETCURSEL, 1, 0 );
			SendMessage( GetDlgItem(hwnd, IDE_PASS), EM_LIMITTEXT, MAX_PASSWORD, 0 );

			if (info->caption) {
				SetWindowText(hwnd, info->caption);
			} else if ( info->node )
			{
				_snwprintf(
					display, countof(display), L"[%s] - %s",
					info->node->mnt.info.status.mnt_point, info->node->mnt.info.device
					);
				SetWindowText( hwnd, display );
			} else
			{
				SetWindowText( hwnd, L"Enter password" );
			}

			SetWindowText( GetDlgItem(hwnd, IDC_HEAD_PASS), L"# Current Password" );
			SendMessage( GetDlgItem(hwnd, IDC_HEAD_PASS), WM_SETFONT, (WPARAM)__font_bold, 0 );

			SetWindowText( GetDlgItem(hwnd, IDC_HEAD_MOUNT_OPTIONS), L"# Mount Options" );
			SendMessage( GetDlgItem(hwnd, IDC_HEAD_MOUNT_OPTIONS), WM_SETFONT, (WPARAM)__font_bold, 0 );

			_sub_class( GetDlgItem(hwnd, IDC_CHECK_SHOW), SUB_STATIC_PROC, HWND_NULL );
			_set_check( hwnd, IDC_CHECK_SHOW, FALSE );

			_sub_class( GetDlgItem(hwnd, IDC_USE_KEYFILES), SUB_STATIC_PROC, HWND_NULL );
			_set_check( hwnd, IDC_USE_KEYFILES, FALSE );

			{
				int current_kdf = (info->node && info->node->mnt.info.status.flags & F_ENABLED)
					? info->node->mnt.info.status.crypt.head_kdf : KDF_DEFAULT;
				_init_combo(GetDlgItem(hwnd, IDC_COMBO_KDF), kdf_names_ex, current_kdf, FALSE, -1);
			}

			_sub_class( GetDlgItem(hwnd, IDC_USE_KEY_SLOTS), SUB_STATIC_PROC, HWND_NULL );
			_set_check( hwnd, IDC_USE_KEY_SLOTS, FALSE );
			SetDlgItemInt( hwnd, IDE_KEY_SLOT_INDEX, 0, FALSE );
			SendMessage( GetDlgItem(hwnd, IDE_KEY_SLOT_INDEX), EM_LIMITTEXT, 3, 0 );

			/* Disable keyslot controls when requested (header backup/restore/config) */
			if (info->flags & PF_NO_KEY_SLOTS)
			{
				EnableWindow( GetDlgItem(hwnd, IDC_USE_KEY_SLOTS), FALSE );
				EnableWindow( GetDlgItem(hwnd, IDE_KEY_SLOT_INDEX), FALSE );
			}

			_sub_class(GetDlgItem(hwnd, IDC_CHECK_RO_SET), SUB_STATIC_PROC, HWND_NULL);
			_set_check(hwnd, IDC_CHECK_RO_SET, FALSE);

			_sub_class(GetDlgItem(hwnd, IDC_CHECK_SKIP_UNUSED), SUB_STATIC_PROC, HWND_NULL);
			{
				int is_ssd = info->node ? dc_is_device_ssd(info->node->mnt.info.w32_device) : FALSE;
				_set_check(hwnd, IDC_CHECK_SKIP_UNUSED, is_ssd);
			}
			ShowWindow(GetDlgItem(hwnd, IDC_CHECK_SKIP_UNUSED), (info->flags & PF_SHOW_SKIP_UNUSED) ? SW_SHOW : SW_HIDE);

			_sub_class(GetDlgItem(hwnd, IDC_CHECK_USE_BACKUP), SUB_STATIC_PROC, HWND_NULL);
			_set_check(hwnd, IDC_CHECK_USE_BACKUP, FALSE);
			ShowWindow(GetDlgItem(hwnd, IDC_CHECK_USE_BACKUP), (info->flags & (PF_MOUNT_OPTIONS | PF_CAN_USE_BACKUP)) ? SW_SHOW : SW_HIDE);

			/* Cache tag controls - shown only for cache password dialog */
			ShowWindow(GetDlgItem(hwnd, IDC_STATIC_CACHE_TAG), (info->flags & PF_SHOW_CACHE_TAG) ? SW_SHOW : SW_HIDE);
			ShowWindow(GetDlgItem(hwnd, IDE_CACHE_TAG), (info->flags & PF_SHOW_CACHE_TAG) ? SW_SHOW : SW_HIDE);

			if (info->flags & PF_RAW_PASSWORD)
			{
				ShowWindow(GetDlgItem(hwnd, IDC_USE_KEYFILES), SW_HIDE);
				ShowWindow(GetDlgItem(hwnd, IDB_USE_KEYFILES), SW_HIDE);
				ShowWindow(GetDlgItem(hwnd, IDC_KDF_LABEL), SW_HIDE);
				ShowWindow(GetDlgItem(hwnd, IDC_COMBO_KDF), SW_HIDE);
			}
			if (info->flags & (PF_RAW_PASSWORD | PF_NO_KEY_SLOTS))
			{
				ShowWindow(GetDlgItem(hwnd, IDC_USE_KEY_SLOTS), SW_HIDE);
				ShowWindow(GetDlgItem(hwnd, IDE_KEY_SLOT_INDEX), SW_HIDE);	
			}

			{
				HWND mnt_combo = GetDlgItem( hwnd, IDC_COMBO_MNPOINT );
				HWND mnt_check = GetDlgItem( hwnd, IDC_CHECK_MNT_SET );
				HWND mnt_label = GetDlgItem( hwnd, IDC_MNT_POINT );
				HWND mnt_ro = GetDlgItem( hwnd, IDC_CHECK_RO_SET );
				HWND mnt_no_hiber = GetDlgItem( hwnd, IDC_NO_HIBERNATION );
				HWND mnt_header = GetDlgItem( hwnd, IDC_HEAD_MOUNT_OPTIONS );

				BOOL enable;
				RECT rc_main;

				GetWindowRect(hwnd, &rc_main);
				enable = info->node && ( info->node->mnt.info.status.mnt_point[0] == L'\\' );

				EnableWindow( mnt_combo, enable );
				EnableWindow( mnt_check, enable );
				EnableWindow( mnt_label, enable );

				// Hide mount options when dialog is used for decrypt (show_skip mode)
				if (!(info->flags  & PF_MOUNT_OPTIONS))
				{
					ShowWindow( mnt_header, SW_HIDE );
					ShowWindow( mnt_combo, SW_HIDE );
					ShowWindow( mnt_check, SW_HIDE );
					ShowWindow( mnt_label, SW_HIDE );
					ShowWindow( mnt_ro, SW_HIDE );
					ShowWindow( mnt_no_hiber, SW_HIDE );
				}

				_sub_class( mnt_check, SUB_STATIC_PROC, HWND_NULL );
				_set_check( hwnd, IDC_CHECK_MNT_SET, enable );

				_sub_class( mnt_no_hiber, SUB_STATIC_PROC, HWND_NULL );
				_set_check( hwnd, IDC_NO_HIBERNATION, enable );

			}
			{
				int def_val, def_unit;

				_sub_class(GetDlgItem(hwnd, IDC_CHECK_UNMOUNT_TIMEOUT), SUB_STATIC_PROC, HWND_NULL);

				_unmount_timer_load_defaults(&def_val, &def_unit);
				_set_check(hwnd, IDC_CHECK_UNMOUNT_TIMEOUT, (def_val > 0) ? TRUE : FALSE);

				SetDlgItemInt(hwnd, IDE_UNMOUNT_TIMEOUT, (def_val > 0) ? (UINT)def_val : 5, FALSE);
				SendMessage(GetDlgItem(hwnd, IDE_UNMOUNT_TIMEOUT), EM_LIMITTEXT, 5, 0);
				_init_combo(GetDlgItem(hwnd, IDC_COMBO_UNMOUNT_UNIT), unmount_timeout_units, def_unit, FALSE, -1);

				EnableWindow(GetDlgItem(hwnd, IDE_UNMOUNT_TIMEOUT), (def_val > 0));
				EnableWindow(GetDlgItem(hwnd, IDC_COMBO_UNMOUNT_UNIT), (def_val > 0));
			}
			SendMessage(
				hwnd, WM_COMMAND, MAKELONG(IDE_PASS, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS)
				);

			/* On secure desktop, ensure dialog is visible and properly positioned */
			if (is_secure_desktop_active())
			{
				RECT rc_dlg;
				int x, y, w, h;

				GetWindowRect(hwnd, &rc_dlg);
				w = rc_dlg.right - rc_dlg.left;
				h = rc_dlg.bottom - rc_dlg.top;

				/* Center on primary monitor */
				x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
				y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;

				SetWindowPos(hwnd, HWND_TOPMOST, x, y, 0, 0,
					SWP_NOSIZE | SWP_SHOWWINDOW);
				ShowWindow(hwnd, SW_SHOW);
				SetFocus(GetDlgItem(hwnd, IDE_PASS));
			}
			else
			{
				SetForegroundWindow(hwnd);
			}
			return 1L;

		}
		break;
		case WM_USER_CLICK :
		{
			if ( (HWND)wparam == GetDlgItem(hwnd, IDC_CHECK_RO_SET) )
			{
				return 1L;
			}

			if ( (HWND)wparam == GetDlgItem(hwnd, IDC_CHECK_SKIP_UNUSED) )
			{
				return 1L;
			}

			if ( (HWND)wparam == GetDlgItem(hwnd, IDC_CHECK_MNT_SET) )
			{
				EnableWindow(
					GetDlgItem(hwnd, IDC_COMBO_MNPOINT), _get_check(hwnd, IDC_CHECK_MNT_SET)
					);
				EnableWindow(
					GetDlgItem(hwnd, IDC_MNT_POINT), _get_check(hwnd, IDC_CHECK_MNT_SET)
					);
				return 1L;
			}

			if ( (HWND)wparam == GetDlgItem(hwnd, IDC_CHECK_SHOW) )
			{
				int mask = _get_check(hwnd, IDC_CHECK_SHOW) ? 0 : '*';

				SendMessage(GetDlgItem(hwnd, IDE_PASS), EM_SETPASSWORDCHAR, mask, 0 );
				InvalidateRect(GetDlgItem(hwnd, IDE_PASS), NULL, TRUE);

				return 1L;
			}

			if ( (HWND)wparam == GetDlgItem(hwnd, IDC_USE_KEYFILES) )
			{
				SendMessage(
					hwnd, WM_COMMAND,
					MAKELONG(IDE_PASS, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS)
					);

				EnableWindow(GetDlgItem(hwnd, IDB_USE_KEYFILES), _get_check(hwnd, IDC_USE_KEYFILES));
				return 1L;
			}

			if ( (HWND)wparam == GetDlgItem(hwnd, IDC_USE_KEY_SLOTS) )
			{
				EnableWindow(GetDlgItem(hwnd, IDE_KEY_SLOT_INDEX), _get_check(hwnd, IDC_USE_KEY_SLOTS));
				return 1L;
			}

			if ( (HWND)wparam == GetDlgItem(hwnd, IDC_CHECK_UNMOUNT_TIMEOUT) )
			{
				BOOL checked = _get_check(hwnd, IDC_CHECK_UNMOUNT_TIMEOUT);
				EnableWindow(GetDlgItem(hwnd, IDE_UNMOUNT_TIMEOUT), checked);
				EnableWindow(GetDlgItem(hwnd, IDC_COMBO_UNMOUNT_UNIT), checked);
				return 1L;
			}
		}
		break;
		case WM_COMMAND :

			if ( id == IDB_USE_KEYFILES )
			{
				_dlg_keyfiles(hwnd, &dlg_data->kf_current, TRUE);

				SendMessage(
					hwnd, WM_COMMAND, MAKELONG(IDE_PASS, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS)
					);
			}

			if ( code == CBN_SELCHANGE && id == IDC_COMBO_MNPOINT )
			{
				if ( SendMessage((HWND)lparam, CB_GETCURSEL, 0, 0) == 0 )
				{
					HWND h_combo = GetDlgItem(hwnd, IDC_COMBO_MNPOINT);

					int sel_item = 1;
					wchar_t path[MAX_PATH];

					if ( _folder_choice(hwnd, path, L"Choice folder for mount point") )
					{
						sel_item = (int)SendMessage(h_combo, CB_GETCOUNT, 0, 0);
						SendMessage(h_combo, CB_ADDSTRING, 0, (LPARAM)path);
					}
					SendMessage(h_combo, CB_SETCURSEL, sel_item, 0);

				}
			}
			if (code == EN_CHANGE)
			{
				BOOL correct;
				int idx_status;

				dc_pass *pass = _get_pass(hwnd, IDE_PASS);
				keyfiles_state *kf_state = _get_check(hwnd, IDC_USE_KEYFILES) ? &dlg_data->kf_current : NULL;

				correct =
					_input_verify(pass, NULL, kf_state, -1, &idx_status
				);

				secure_free(pass);

				SetWindowText(GetDlgItem(hwnd, IDC_PASS_STATUS), _get_text_name(idx_status, pass_status));
				EnableWindow(GetDlgItem(hwnd, IDOK), correct);

				return 1L;

			}
			if ((id == IDCANCEL) || (id == IDOK))
			{
				if (id == IDOK)
				{
					keyfiles_state *kf_state = _get_check(hwnd, IDC_USE_KEYFILES) ? &dlg_data->kf_current : NULL;

					info->pass = __get_pass_keyfiles(GetDlgItem(hwnd, IDE_PASS), kf_state != NULL, kf_state);
					if ( !info->pass )
						return 1L;

					info->pass->kdf = _get_combo_val(GetDlgItem(hwnd, IDC_COMBO_KDF), kdf_names_ex);

					if (_get_check(hwnd, IDC_USE_KEY_SLOTS)) {
						int slot_idx = GetDlgItemInt(hwnd, IDE_KEY_SLOT_INDEX, NULL, FALSE);
						if (slot_idx < 0 || slot_idx > KEY_SLOT_MAX) {
							__msg_e(hwnd, L"Keyslot index must be between 0 and 100");
							return 1L;
						}
						info->pass->slot = (slot_idx == 0) ? ALL_KEY_SLOTS : slot_idx;
					} else {
						info->pass->slot = 0;
					}

					/* Handle cache tag if shown */
					if (info->flags & PF_SHOW_CACHE_TAG) {
						//wchar_t tag_str[16] = {0};
						//GetDlgItemText(hwnd, IDE_CACHE_TAG, tag_str, countof(tag_str));
						//if (tag_str[0]) {
						//	int len = (int)wcslen(tag_str);
						//	if (len >= 2 && tag_str[0] == L'0' && (tag_str[1] == L'x' || tag_str[1] == L'X')) {
						//		wchar_t *endptr;
						//		if (len > 10) {
						//			__msg_e(hwnd, L"Hex tag too long (max 0x + 8 hex digits)");
						//			return 1L;
						//		}
						//		info->pass->tag = (ULONG)wcstoul(tag_str + 2, &endptr, 16);
						//		if (*endptr != L'\0') {
						//			__msg_e(hwnd, L"Invalid hex tag format");
						//			return 1L;
						//		}
						//	} else {
						//		unsigned char bytes[4] = {0};
						//		int i;
						//		if (len > 4) {
						//			__msg_e(hwnd, L"ASCII tag too long (max 4 characters)");
						//			return 1L;
						//		}
						//		for (i = 0; i < 4 && tag_str[i]; i++) {
						//			if (tag_str[i] > 127) {
						//				__msg_e(hwnd, L"Tag must contain only ASCII characters");
						//				return 1L;
						//			}
						//			bytes[i] = (unsigned char)tag_str[i];
						//		}
						//		info->pass->tag = ((ULONG)bytes[0] << 24) | ((ULONG)bytes[1] << 16) |
						//		                  ((ULONG)bytes[2] << 8) | (ULONG)bytes[3];
						//	}
						//}
						wchar_t label_str[SLOT_LABEL_LEN + 1] = {0};
						GetDlgItemText(hwnd, IDE_CACHE_TAG, label_str, countof(label_str));
						memset(info->pass->label, 0, SLOT_LABEL_LEN);
						WideCharToMultiByte(CP_UTF8, 0, label_str, -1, info->pass->label, SLOT_LABEL_LEN, NULL, NULL);
					}

					info->mnt_ro = _get_check(hwnd, IDC_CHECK_RO_SET);
					info->no_hiber = _get_check(hwnd, IDC_NO_HIBERNATION);
				info->skip_unused = _get_check(hwnd, IDC_CHECK_SKIP_UNUSED);
				info->use_backup = _get_check(hwnd, IDC_CHECK_USE_BACKUP);

				if (_get_check(hwnd, IDC_CHECK_UNMOUNT_TIMEOUT))
				{
					BOOL translated;
					UINT val = GetDlgItemInt(hwnd, IDE_UNMOUNT_TIMEOUT, &translated, FALSE);
					info->unmount_timeout = (translated && val > 0) ? (int)val : 5;
					info->unmount_timeout_unit = _get_combo_val(
						GetDlgItem(hwnd, IDC_COMBO_UNMOUNT_UNIT), unmount_timeout_units);
					if (info->unmount_timeout_unit < 0) info->unmount_timeout_unit = UNMOUNT_TIMEOUT_UNIT_MIN;
					_unmount_timer_save_defaults(info->unmount_timeout, info->unmount_timeout_unit);
				}
				else
				{
					info->unmount_timeout = 0;
					_unmount_timer_save_defaults(info->unmount_timeout, UNMOUNT_TIMEOUT_UNIT_MIN);
				}

					if (IsWindowEnabled(GetDlgItem(hwnd, IDC_COMBO_MNPOINT)) &&
							info->mnt_point)
					{
						GetWindowText(
								GetDlgItem(hwnd, IDC_COMBO_MNPOINT),
								(wchar_t *)info->mnt_point,
								MAX_PATH
						);
					}
				}
				EndDialog (hwnd, id);
				return 1L;

			}
		break;
		case WM_DESTROY:
		{
			_wipe_pass_control(hwnd, IDE_PASS);

			if (dlg_data)
			{
				_keyfiles_wipe(&dlg_data->kf_current);
				secure_free(dlg_data);
				SetWindowLongPtr(hwnd, GWLP_USERDATA, 0);
			}

			memset(&rc_right, 0, sizeof(rc_right));
			memset(&rc_left, 0, sizeof(rc_left));

			cut = 0;
			return 0L;

		}
		break;
		case WM_MEASUREITEM:
		{
			MEASUREITEMSTRUCT *item = pv(lparam);

			if (item->CtlType != ODT_LISTVIEW)
				item->itemHeight -= 3;

		}
		break;
	}
	return 0L;

}


int _dlg_get_pass(
		HWND	 hwnd,
		dlgpass	*pass
	)
{
	int result =
		(int)secure_desktop_dialog_box_param(
				__hinst,
				MAKEINTRESOURCE(IDD_DIALOG_PASS),
				hwnd,
				pv(_password_dlg_proc),
				(LPARAM)pass
		);

	return (
		result == IDOK ? ST_OK : ST_CANCEL
	);
}


int _dlg_change_pass(
		HWND	 hwnd,
		dlgpass	*pass
	)
{
	int result =
		(int)secure_desktop_dialog_box_param(
				__hinst,
				MAKEINTRESOURCE(IDD_DIALOG_CHANGE_PASS),
				hwnd,
				pv(_password_change_dlg_proc),
				(LPARAM)pass
		);

	return (
		result == IDOK ? ST_OK : ST_CANCEL
	);
}
