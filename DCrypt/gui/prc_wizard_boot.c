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
#include <richedit.h>

#include "main.h"
#include "prc_wizard_boot.h"

#include "pass.h"
#include "prc_common.h"
#include "prc_keyfiles.h"
#include "dlg_drives_list.h"
#include "dlg_menu.h"
#include "hotkeys.h"
#include "keyfiles.h"
#include "efiinst.h"
#include "mbrinst.h"

static HWND     h_wizard;
static HHOOK    h_hook;

// Wizard instance data
typedef struct _boot_wizard_data {
	keyfiles_state kf_state;
} _boot_wizard_data;

void _refresh_boot_buttons(
		HWND hwnd,
		HWND h_list,
		int  item
	)
{
	BOOL       remove      = FALSE;
	BOOL	   update      = FALSE;
	BOOL	   enable      = FALSE;
	BOOL       boot_device = FALSE;
	BOOL       force_small = FALSE;
	BOOL       force_shim  = FALSE;
	HWND       h_parent    = GetParent( GetParent( hwnd ) );

	int        sel_disk    = _ext_disk_num(h_list);
	wchar_t	   s_item[MAX_PATH];

	ldr_config conf;
	DC_FLAGS   flags;

	if ( ListView_GetSelectedCount(h_list) )
	{		
		int     boot_disk_1 = -1;
		int     boot_disk_2 = -1;

		if (__is_efi_boot) {
			boot_disk_1 = boot_disk_2 = dc_efi_get_os_disk();
		} else if (dc_get_boot_disk( &boot_disk_1, &boot_disk_2 ) == ST_NF_BOOT_DEV) {
			boot_disk_1 = boot_disk_2 = -1;
		}
		if (boot_disk_1 != -1)
		{
			force_small = (
				( boot_disk_1 == sel_disk || boot_disk_2 == sel_disk ) &&
				( dc_device_control(DC_CTL_GET_FLAGS, NULL, 0, &flags, sizeof(flags)) == NO_ERROR ) && ( flags.load_flags & DST_SMALL_MEM )
			);
		}
		enable = TRUE;

		_get_item_text( h_list, item, 2, s_item, countof(s_item) );
		if ( wcsstr(s_item, L"installed") != NULL )
		{
			remove = TRUE;
			update = dc_get_ldr_config( sel_disk, &conf ) == ST_OK && (int)conf.ldr_ver < (conf.sign1 == 0 ? DC_UEFI_VER : DC_BOOT_VER);
#ifdef _DEBUG
			update = TRUE;
#endif
		}
	}

	force_shim = (dc_efi_is_secureboot() && !dc_efi_dcs_is_signed());

	SetWindowText( GetDlgItem( h_parent, IDC_BTN_INSTALL ), remove ? IDS_BOOTREMOVE : IDS_BOOTINSTALL );
	EnableWindow( GetDlgItem( h_parent, IDC_BTN_INSTALL ), enable );

	EnableWindow( GetDlgItem( h_parent, IDC_BTN_CHANGE_CONF ), remove );
	EnableWindow( GetDlgItem( h_parent, IDC_BTN_UPDATE ), update );

	EnableWindow( GetDlgItem( hwnd, IDC_USE_SMALL_BOOT ), enable && (remove || !force_small) );
	_set_check( hwnd, IDC_USE_SMALL_BOOT, _get_check( hwnd, IDC_USE_SMALL_BOOT ) || force_small );

	EnableWindow( GetDlgItem( hwnd, IDC_USE_SHIM_BOOT ), enable && (remove || !force_shim) );
	_set_check( hwnd, IDC_USE_SHIM_BOOT, _get_check( hwnd, IDC_USE_SHIM_BOOT) || force_shim );
}


int _init_boot_config(
		HWND        hwnd,
		int         type,
		int         dsk_num,
		wchar_t    *vol,
		wchar_t    *path,
		ldr_config *conf
	)
{
	HWND   h_tab    = GetDlgItem(hwnd, IDT_BOOT_TAB);
	TCITEM tab_item = { TCIF_TEXT };

	wchar_t s_title[MAX_PATH];

	_tab_data *d_tab = NULL;
	_wnd_data *wnd;

	// Get wizard data from parent dialog
	HWND h_wizard = GetParent(GetParent(hwnd));
	_boot_wizard_data *wiz_data = wnd_get_long(h_wizard, GWL_USERDATA);
	keyfiles_state *kf_state = wiz_data ? &wiz_data->kf_state : NULL;

	int rlt;
	int isefi = -1;

	switch ( type )
	{
		case CTL_LDR_HDD: 
		{
			isefi = dc_is_dcs_on_disk(dsk_num);
			if (isefi)
				rlt = dc_get_efi_config(dsk_num, NULL, conf);
			else
				rlt = dc_get_mbr_config(dsk_num, NULL, conf);
		}
		break;

		case CTL_LDR_STICK:
		{
			isefi = dc_is_dcs_on_partition(vol);
			if (isefi)
				rlt = dc_efi_config_by_partition(vol, 0, conf);
			else
				rlt = dc_mbr_config_by_partition(vol, FALSE, conf);
		}
		break;

		case CTL_LDR_ISO:
		case CTL_LDR_PXE:   
		{
			isefi = dc_is_dcs_in_file(path);
			if (isefi)
				rlt = dc_get_efi_config(0, path, conf);
			else
				rlt = dc_get_mbr_config(0, path, conf);
		}
		break;
	}

	if ( rlt != ST_OK )
	{
		__error_s( hwnd, L"Error getting %sbootloader configuration", rlt, (isefi == 1 ? L"EFI " : (isefi == 0 ? L"MBR " : L"")) );
		return rlt;
	}

	d_tab = malloc(sizeof(_tab_data));
	memset( d_tab, 0, sizeof(_tab_data) );
	
	wnd_set_long(hwnd, GWL_USERDATA, d_tab);

	wnd = _sub_class(
		h_tab, SUB_NONE,
		CreateDialog( __hinst, MAKEINTRESOURCE(DLG_BOOT_CONF_MAIN),     GetDlgItem(hwnd, IDC_BOOT_TAB), _tab_proc ),
		CreateDialog( __hinst, MAKEINTRESOURCE(DLG_BOOT_CONF_LOGON),    GetDlgItem(hwnd, IDC_BOOT_TAB), _tab_proc ),
		CreateDialog( __hinst, MAKEINTRESOURCE(DLG_BOOT_CONF_GOODPASS), GetDlgItem(hwnd, IDC_BOOT_TAB), _tab_proc ),
		CreateDialog( __hinst, MAKEINTRESOURCE(DLG_BOOT_CONF_BADPASS),  GetDlgItem(hwnd, IDC_BOOT_TAB), _tab_proc ),
		CreateDialog( __hinst, MAKEINTRESOURCE(DLG_BOOT_CONF_OTHER),    GetDlgItem(hwnd, IDC_BOOT_TAB), _tab_proc ),
		HWND_NULL
		);

	d_tab->curr_tab = 1;
	d_tab->active   = wnd->dlg[0];

	__lists[HBOT_PART_LIST_BY_ID] = GetDlgItem( wnd->dlg[2], IDC_PART_LIST_BY_ID );
	///////////////////////////////////////////////////////////////
	/////// MAIN PAGE /////////////////////////////////////////////
	{
	///////////////////////////////////////////////////////////////

		_sub_class(GetDlgItem(wnd->dlg[0], IDC_BT_USE_OSK), SUB_STATIC_PROC, HWND_NULL);
		_set_check(wnd->dlg[0], IDC_BT_USE_OSK, conf->logon_type & LDR_LT_USE_OSK);

		// DX-ToDo: add old real mode OSK support
		EnableWindow( GetDlgItem(wnd->dlg[0], IDC_BT_USE_OSK), isefi == 1 ? TRUE : FALSE );

		_init_combo( GetDlgItem(wnd->dlg[0], IDC_COMBO_KBLAYOUT), kb_layouts, conf->kbd_layout, FALSE, -1 );

		EnableWindow( GetDlgItem(wnd->dlg[0], IDC_COMBO_KDF), isefi == 1 ? TRUE : FALSE );
		_init_combo( GetDlgItem(wnd->dlg[0], IDC_COMBO_KDF), kdf_names_ex, conf->header_kdf, FALSE, -1 );
	}
	///////////////////////////////////////////////////////////////
	/////// AUTHENTICATION PAGE ///////////////////////////////////
	{
	///////////////////////////////////////////////////////////////
		HWND h_auth_combo = GetDlgItem( wnd->dlg[1], IDC_COMBO_AUTH_TYPE );
		HWND h_msg = GetDlgItem( wnd->dlg[1], IDE_RICH_BOOTMSG );

		_init_combo(h_auth_combo, auth_type, conf->logon_type, TRUE, LDR_LT_GET_PASS | LDR_LT_EMBED_KEY);

		if (kf_state)
		{
			_keyfiles_wipe(kf_state);
			_keyfiles_init(kf_state);
			kf_state->mix_mode = conf->keyfile_mixer;
			if (!is_all_zeros(conf->emb_key, sizeof(conf->emb_key))) {
				_list_key_files* new_node = secure_alloc(sizeof(_list_key_files));
				_snwprintf(new_node->path, countof(new_node->path), L"Embedded Keyfile %08X", calc_crc32(conf->emb_key, sizeof(conf->emb_key)));
				new_node->is_virtual = TRUE;
				new_node->virtual_size = sizeof(conf->emb_key);
				new_node->virtual_data = secure_alloc( new_node->virtual_size );
				memcpy(new_node->virtual_data, conf->emb_key, sizeof(conf->emb_key));
				_insert_tail_list(&kf_state->head, &new_node->next);
			}
		}

		_sub_class( GetDlgItem(wnd->dlg[1], IDC_BT_ENTER_PASS_MSG), SUB_STATIC_PROC, HWND_NULL );
		_set_check( wnd->dlg[1], IDC_BT_ENTER_PASS_MSG, conf->logon_type & LDR_LT_MESSAGE );

		EnableWindow( h_msg, conf->logon_type & LDR_LT_MESSAGE );
		_init_combo( GetDlgItem(wnd->dlg[1], IDC_COMBO_SHOW_PASS), show_pass, conf->logon_type, TRUE, -1 );

		SetWindowTextA( h_msg, conf->eps_msg );

		SendMessage( h_msg, EM_SETBKGNDCOLOR, 0, _cl(COLOR_BTNFACE, LGHT_CLR) );
		SendMessage( h_msg, EM_EXLIMITTEXT,	0, sizeof(conf->eps_msg) - 1 );

		_init_combo(
			GetDlgItem(wnd->dlg[1], IDC_COMBO_AUTH_TMOUT), auth_tmount, conf->timeout, FALSE, -1
			);

		_sub_class( GetDlgItem(wnd->dlg[1], IDC_BT_CANCEL_TMOUT), SUB_STATIC_PROC, HWND_NULL );
		_set_check( wnd->dlg[1], IDC_BT_CANCEL_TMOUT, conf->options & LDR_OP_TMO_STOP );

		EnableWindow( GetDlgItem(wnd->dlg[1], IDC_BT_CANCEL_TMOUT), conf->timeout );
		SendMessage( wnd->dlg[1], WM_COMMAND, MAKELONG(IDC_COMBO_AUTH_TYPE, CBN_SELCHANGE), (LPARAM)h_auth_combo );

	}
	///////////////////////////////////////////////////////////////
	/////// CORRECT PASSWORD PAGE /////////////////////////////////
	{
	///////////////////////////////////////////////////////////////

		_sub_class(GetDlgItem(wnd->dlg[2], IDC_BT_GOOD_PASS_MSG), SUB_STATIC_PROC, HWND_NULL);
		_set_check(wnd->dlg[2], IDC_BT_GOOD_PASS_MSG, (conf->options & LDR_OP_OK_MSG) != 0);

		HWND ok_mes = GetDlgItem(wnd->dlg[2], IDE_RICH_OKPASS_MSG);

		EnableWindow(GetDlgItem(wnd->dlg[2], IDE_RICH_OKPASS_MSG), conf->options & LDR_OP_OK_MSG);

		SetWindowTextA(ok_mes, conf->aok_msg);
		SendMessage(ok_mes, EM_EXLIMITTEXT, 0, sizeof(conf->aok_msg) - 1);

		SendMessage(GetDlgItem(wnd->dlg[2], IDE_RICH_OKPASS_MSG), EM_SETBKGNDCOLOR, 0, _cl(COLOR_BTNFACE, LGHT_CLR));

		_init_combo(
			GetDlgItem(wnd->dlg[2], IDC_COMBO_METHOD),
			conf->options & LDR_OP_EXTERNAL ? boot_type_ext : (__is_efi_boot ? boot_type_efi : boot_type_all), conf->boot_type, FALSE, -1
		);

		_list_part_by_disk_id(
			__lists[HBOT_PART_LIST_BY_ID], conf->disk_id
		);

		SendMessage(
			wnd->dlg[2], WM_COMMAND, MAKELONG(IDC_COMBO_METHOD, CBN_SELCHANGE), (LPARAM)GetDlgItem(wnd->dlg[2], IDC_COMBO_METHOD)
		);
	}
	///////////////////////////////////////////////////////////////
	/////// INVALID PASSWORD PAGE /////////////////////////////////
	{
	///////////////////////////////////////////////////////////////
		HWND err_mes = GetDlgItem( wnd->dlg[3], IDE_RICH_ERRPASS_MSG );

		_sub_class( GetDlgItem(wnd->dlg[3], IDC_BT_BAD_PASS_MSG), SUB_STATIC_PROC, HWND_NULL );
		_set_check( wnd->dlg[3], IDC_BT_BAD_PASS_MSG, conf->error_type & LDR_ET_MESSAGE );

		EnableWindow( GetDlgItem(wnd->dlg[3], IDE_RICH_ERRPASS_MSG), conf->error_type & LDR_ET_MESSAGE );

		_sub_class( GetDlgItem(wnd->dlg[3], IDC_BT_ACTION_NOPASS), SUB_STATIC_PROC, HWND_NULL );
		_set_check( wnd->dlg[3], IDC_BT_ACTION_NOPASS, conf->options & LDR_OP_NOPASS_ERROR );

		_init_combo( GetDlgItem(wnd->dlg[3], IDC_COMBO_BAD_PASS_ACT), __is_efi_boot ? bad_pass_act_efi : bad_pass_act, conf->error_type, TRUE, -1 );

		SetWindowTextA( err_mes, conf->err_msg );
		SendMessage( err_mes, EM_EXLIMITTEXT, 0, sizeof(conf->err_msg) - 1 );

		SendMessage( GetDlgItem(wnd->dlg[3], IDE_RICH_ERRPASS_MSG), EM_SETBKGNDCOLOR, 0, _cl(COLOR_BTNFACE, LGHT_CLR) );
	}
	///////////////////////////////////////////////////////////////
	/////// OTHER SETTINGS PAGE ///////////////////////////////////
	{
	///////////////////////////////////////////////////////////////
		_sub_class( GetDlgItem(wnd->dlg[4], IDC_USE_HARD_CRYPTO), SUB_STATIC_PROC, HWND_NULL );
		//EnableWindow(GetDlgItem(wnd->dlg[4], IDC_USE_HARD_CRYPTO), isefi == 1 ? FALSE : TRUE);
		_set_check( wnd->dlg[4], IDC_USE_HARD_CRYPTO, (conf->options & LDR_OP_HW_CRYPTO) != 0 );

		_sub_class(GetDlgItem(wnd->dlg[4], IDC_BT_AUTH_MSG), SUB_STATIC_PROC, HWND_NULL);
		_set_check(wnd->dlg[4], IDC_BT_AUTH_MSG, (conf->options & LDR_OP_AUTH_MSG) != 0);

		HWND go_mes = GetDlgItem(wnd->dlg[4], IDE_RICH_AUTH_MSG);

		EnableWindow(GetDlgItem(wnd->dlg[4], IDE_RICH_AUTH_MSG), conf->options & LDR_OP_OK_MSG);

		SetWindowTextA(go_mes, conf->ago_msg);
		SendMessage(go_mes, EM_EXLIMITTEXT, 0, sizeof(conf->ago_msg) - 1);

		SendMessage(GetDlgItem(wnd->dlg[4], IDE_RICH_AUTH_MSG), EM_SETBKGNDCOLOR, 0, _cl(COLOR_BTNFACE, LGHT_CLR));

		_sub_class( GetDlgItem(wnd->dlg[4], IDC_BT_BLOCK_UNENCRYPTED), SUB_STATIC_PROC, HWND_NULL );
		EnableWindow(GetDlgItem(wnd->dlg[4], IDC_BT_BLOCK_UNENCRYPTED), isefi == 1 ? TRUE : FALSE); 
		_set_check( wnd->dlg[4], IDC_BT_BLOCK_UNENCRYPTED, (conf->options & LDR_OP_BLOCK_UNENC) != 0 );

		_sub_class( GetDlgItem(wnd->dlg[4], IDC_SET_VERBOSE), SUB_STATIC_PROC, HWND_NULL );
		EnableWindow(GetDlgItem(wnd->dlg[4], IDC_SET_VERBOSE), isefi == 1 ? TRUE : FALSE); 
		_set_check( wnd->dlg[4], IDC_SET_VERBOSE, (conf->options & LDR_OP_DEBUG) != 0 );
	}

	tab_item.pszText = L"Main";
	TabCtrl_InsertItem(h_tab, 0, &tab_item);

	tab_item.pszText = L"Authentication";
	TabCtrl_InsertItem(h_tab, 1, &tab_item);

	tab_item.pszText = L"Correct password";
	TabCtrl_InsertItem(h_tab, 2, &tab_item);

	tab_item.pszText = L"Invalid password";
	TabCtrl_InsertItem(h_tab, 3, &tab_item);

	tab_item.pszText = L"Other Settings";
	TabCtrl_InsertItem(h_tab, 4, &tab_item);

	{
		NMHDR mhdr = { 0, 0, TCN_SELCHANGE };
		TabCtrl_SetCurSel(h_tab, 0);

		SendMessage( hwnd, WM_NOTIFY, IDT_BOOT_TAB, (LPARAM)&mhdr );
	}

	_snwprintf( s_title, countof(s_title), L"Bootloader config for [%s]", path[0] ? path : vol );
	SetWindowText( GetParent(GetParent(hwnd)), s_title );

	return rlt;
						
}


int _save_boot_config(
		HWND        hwnd,
		int         type,
		int         dsk_num,
		wchar_t    *vol,
		wchar_t    *path,
		ldr_config *conf
	)
{
	_wnd_data *wnd;
	int rlt = ST_OK;
	int isefi = -1;

	// Get wizard data from parent dialog
	HWND h_wizard = GetParent(GetParent(hwnd));
	_boot_wizard_data *wiz_data = wnd_get_long(h_wizard, GWL_USERDATA);
	keyfiles_state *kf_state = wiz_data ? &wiz_data->kf_state : NULL;

	wnd = wnd_get_long( GetDlgItem(hwnd, IDT_BOOT_TAB), GWL_USERDATA );

	if ( !wnd )
	{
		// Config dialog has already been cleaned up - this shouldn't happen
		return ST_ERROR;
	}

	if ( wnd )
	///////////////////////////////////////////////////////////////
	/////// MAIN PAGE /////////////////////////////////////////////
	{
	///////////////////////////////////////////////////////////////

		BOOL use_osk = _get_check(wnd->dlg[2], IDC_BT_USE_OSK);

		set_flag(conf->logon_type, LDR_LT_USE_OSK, use_osk);

		conf->kbd_layout = _get_combo_val( GetDlgItem( wnd->dlg[0], IDC_COMBO_KBLAYOUT ), kb_layouts );

		conf->header_kdf = _get_combo_val(GetDlgItem(wnd->dlg[0], IDC_COMBO_KDF), kdf_names_ex);
	}
	///////////////////////////////////////////////////////////////
	/////// AUTHENTICATION PAGE ///////////////////////////////////
	{
	///////////////////////////////////////////////////////////////
		HWND auth_combo = GetDlgItem( wnd->dlg[1], IDC_COMBO_AUTH_TYPE );
		HWND show_combo = GetDlgItem( wnd->dlg[1], IDC_COMBO_SHOW_PASS );

		BOOL dsp_pass;
		int timeout = _get_combo_val( GetDlgItem(wnd->dlg[1], IDC_COMBO_AUTH_TMOUT), auth_tmount );

		BOOL show_text = _get_check( wnd->dlg[1], IDC_BT_ENTER_PASS_MSG );
		//BOOL embed_key = _get_combo_val( auth_combo, auth_type) & LDR_LT_EMBED_KEY;

		conf->logon_type &= ~(LDR_LT_GET_PASS | LDR_LT_EMBED_KEY);
		conf->logon_type |= _get_combo_val( auth_combo, auth_type );

		if ( show_text )
		{
			GetWindowTextA( GetDlgItem(wnd->dlg[1], IDE_RICH_BOOTMSG), conf->eps_msg, sizeof(conf->eps_msg) );
		}
		set_flag( conf->logon_type, LDR_LT_MESSAGE, show_text );

		dsp_pass = _get_combo_val( show_combo, show_pass ) == LDR_LT_DSP_PASS;
		set_flag( conf->logon_type, LDR_LT_DSP_PASS, dsp_pass );

		conf->timeout = timeout;

		set_flag( conf->options, LDR_OP_EPS_TMO, timeout != 0 );
		set_flag( conf->options, LDR_OP_TMO_STOP, _get_check(wnd->dlg[1], IDC_BT_CANCEL_TMOUT) );

		//if ( embed_key )
		//{
		//if ( _keyfiles_count(KEYLIST_EMBEDDED) )
		int kf_count = kf_state ? _keyfiles_count(kf_state) : 0;
		if ( kf_count > 0)
		{
			conf->keyfile_mixer = kf_state->mix_mode;

			int is_efi = IsWindowEnabled( GetDlgItem(wnd->dlg[0], IDC_COMBO_KDF) ); // MBR loader supports only Pkcs5.2 SHA-512
			if (!is_efi && conf->keyfile_mixer != KEYFILE_MIX_LEGACY) {
				__msg_e(hwnd, L"MBR bootloader supporty only Additive (Legacy) key file mixing");
				return ST_ERROR;
			}

			memset( conf->emb_key, 0, sizeof(conf->emb_key) );
			//set_flag( conf->logon_type, LDR_LT_EMBED_KEY, 0 );

			_list_key_files *first_kf = _first_keyfile(kf_state);
			if (kf_count == 1 && first_kf->is_virtual && first_kf->virtual_size == 64) // == SHA512_DIGEST_SIZE
			{
				memcpy( &conf->emb_key, first_kf->virtual_data, sizeof(conf->emb_key) );
			}
			else
			{
				BOOLEAN kf_is_raw = FALSE;

				if (kf_count == 1)
				{
					HANDLE h_file = CreateFile(first_kf->path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
					if (h_file != INVALID_HANDLE_VALUE)
					{
						if (GetFileSize(h_file, NULL) == 64) // == sizeof(conf->emb_key) // == SHA512_DIGEST_SIZE
						{
							kf_is_raw = TRUE;

							if (!ReadFile(h_file, conf->emb_key, sizeof(conf->emb_key), NULL, NULL))
							{
								__msg_e( hwnd, L"Keyfile not loaded\n" );
								rlt = ST_ERROR;
							}
						}
						CloseHandle(h_file);
					}
				}

				//if (kf_count == 1 && !kf_is_raw && conf->keyfile_mixer == KEYFILE_MIX_LEGACY)
				//{
				//	__msg_e( hwnd, L"Embedded keyfile must be 64 byte size\n" );
				//	rlt = ST_ERROR;
				//}
				//else

				if ( !kf_is_raw )
				{
					dc_pass pass;
					memset(&pass, 0, sizeof(pass));

					rlt = __mix_keyfiles_pass(&pass, kf_state);

					if (rlt != ST_OK)
					{
						__msg_e(hwnd, L"Keyfiles not loaded\n");
					}
					else
					{
						memcpy( &conf->emb_key, pass.pass, sizeof(conf->emb_key) );
					}
					burn(&pass, sizeof(pass));
				}
			}
		}
		//}
		else {
			memset(conf->emb_key, 0, sizeof(conf->emb_key));
		}
	}
	///////////////////////////////////////////////////////////////
	/////// CORRECT PASSWORD PAGE /////////////////////////////////
	{
	///////////////////////////////////////////////////////////////
		BOOL show_good = _get_check(wnd->dlg[2], IDC_BT_GOOD_PASS_MSG);

		set_flag(conf->options, LDR_OP_OK_MSG, show_good);

		if (show_good)
		{
			GetWindowTextA(
				GetDlgItem(wnd->dlg[2], IDE_RICH_OKPASS_MSG), conf->aok_msg, sizeof(conf->aok_msg)
			);
		}

		conf->boot_type = _get_combo_val(GetDlgItem(wnd->dlg[2], IDC_COMBO_METHOD), boot_type_all);

		if (conf->boot_type == LDR_BT_DISK_ID)
		{
			wchar_t text[MAX_PATH];

			_get_item_text(
				__lists[HBOT_PART_LIST_BY_ID], ListView_GetSelectionMark(__lists[HBOT_PART_LIST_BY_ID]), 2, text, countof(text)
			);

			if (wcslen(text) && ListView_GetSelectedCount(__lists[HBOT_PART_LIST_BY_ID]))
			{
				conf->disk_id = wcstoul(text, L'\0', 16);
			}
			else {
				__msg_e(hwnd, L"You must select a partition by ID");
				return ST_ERROR;
			}
		}
	}
	///////////////////////////////////////////////////////////////
	/////// INVALID PASSWORD PAGE /////////////////////////////////
	{
	///////////////////////////////////////////////////////////////
		BOOL show_err    = _get_check( wnd->dlg[3], IDC_BT_BAD_PASS_MSG );
		BOOL act_no_pass = _get_check( wnd->dlg[3], IDC_BT_ACTION_NOPASS );

		conf->error_type = _get_combo_val( GetDlgItem(wnd->dlg[3], IDC_COMBO_BAD_PASS_ACT), __is_efi_boot ? bad_pass_act_efi : bad_pass_act );

		set_flag( conf->error_type, LDR_ET_MESSAGE, show_err );
		set_flag( conf->options, LDR_OP_NOPASS_ERROR, act_no_pass );

		if ( show_err )
		{
			GetWindowTextA(
				GetDlgItem( wnd->dlg[3], IDE_RICH_ERRPASS_MSG), conf->err_msg, sizeof(conf->err_msg) 
				);
		}						
	}
	///////////////////////////////////////////////////////////////
	/////// OTHER SETTINGS PAGE ///////////////////////////////////
	{
	///////////////////////////////////////////////////////////////
		set_flag( 
			conf->options, LDR_OP_HW_CRYPTO, _get_check(wnd->dlg[4], IDC_USE_HARD_CRYPTO) 
			);

		BOOL show_good = _get_check(wnd->dlg[4], IDC_BT_AUTH_MSG);

		set_flag(conf->options, LDR_OP_AUTH_MSG, show_good);

		if (show_good)
		{
			GetWindowTextA(
				GetDlgItem(wnd->dlg[4], IDE_RICH_AUTH_MSG), conf->ago_msg, sizeof(conf->ago_msg)
			);
		}

		set_flag( 
			conf->options, LDR_OP_BLOCK_UNENC, _get_check(wnd->dlg[4], IDC_BT_BLOCK_UNENCRYPTED)
			);

		set_flag( 
			conf->options, LDR_OP_DEBUG, _get_check(wnd->dlg[4], IDC_SET_VERBOSE)
			);
	}

	if ( rlt != ST_OK )
	{
		return rlt;
	}
	switch ( type )
	{
		case CTL_LDR_HDD: 
		{
			isefi = dc_is_dcs_on_disk(dsk_num);
			if (isefi)
				rlt = dc_set_efi_config(dsk_num, NULL, conf);
			else
				rlt = dc_set_mbr_config(dsk_num, NULL, conf);
		}
		break;
		case CTL_LDR_STICK:
		{
			isefi = dc_is_dcs_on_partition(vol);
			if (isefi)
				rlt = dc_efi_config_by_partition(vol, TRUE, conf);
			else
				rlt = dc_mbr_config_by_partition(vol, TRUE, conf); 
		}
		break;

		case CTL_LDR_ISO:
		case CTL_LDR_PXE:
		{
			isefi = dc_is_dcs_in_file(path);
			if (isefi)
				rlt = dc_set_efi_config(0, path, conf);
			else
				rlt = dc_set_mbr_config(0, path, conf);
		}
		break;
	}
	if ( rlt != ST_OK )
	{
		__error_s( hwnd, L"Error set %sbootloader configuration", rlt, (isefi == 1 ? L"EFI " : (isefi == 0 ? L"MBR " : L"")) );
		return rlt;
	}
	// EndDialog removed - caller now handles window flow (return to overview instead of closing)
	// EndDialog( GetParent(GetParent(hwnd)), IDOK );

	return rlt;

}


static
LRESULT
CALLBACK
_get_msg_proc(
		int    code,
		WPARAM wparam,
		LPARAM lparam
	)
{
	if ( code >= 0 )
	{
		MSG *p_msg = pv(lparam);

		if ( p_msg->message >= WM_KEYFIRST && p_msg->message <= WM_KEYLAST )
		{
			if ( TranslateAccelerator( h_wizard, __hacc, p_msg ) )
			{
				p_msg->message = WM_NULL;
			}
		}
	}
	return (
		CallNextHookEx( h_hook, code, wparam, lparam )
	);
}


void _cleanup_and_restore_config_state(
		HWND            hwnd,
		_wz_sheets     *bt_sheets,
		int             saved_type,
		int             saved_item_idx,
		const wchar_t  *saved_path
	)
{
	// Cleanup config page resources
	HWND h_tab = GetDlgItem(bt_sheets[1].hwnd, IDT_BOOT_TAB);
	_wnd_data *wnd = wnd_get_long(h_tab, GWL_USERDATA);
	_tab_data *d_tab = wnd_get_long(bt_sheets[1].hwnd, GWL_USERDATA);

	if (wnd) {
		// Destroy all tab child dialogs
		for (int i = 0; i < 20 && wnd->dlg[i] != NULL; i++) {
			DestroyWindow(wnd->dlg[i]);
		}
		free(wnd);
		wnd_set_long(h_tab, GWL_USERDATA, NULL);
	}

	if (d_tab) {
		free(d_tab);
		wnd_set_long(bt_sheets[1].hwnd, GWL_USERDATA, NULL);
	}

	// Remove all tabs from the tab control
	TabCtrl_DeleteAllItems(h_tab);

	// Switch back to overview page
	ShowWindow( bt_sheets[1].hwnd, SW_HIDE );
	ShowWindow( bt_sheets[0].hwnd, SW_SHOW );

	ShowWindow( GetDlgItem(hwnd, IDC_BTN_CHANGE_CONF), TRUE );
	ShowWindow( GetDlgItem(hwnd, IDC_BTN_UPDATE), TRUE );

	// Restore state based on loader type
	if (saved_type == CTL_LDR_HDD || saved_type == CTL_LDR_STICK) {
		// For HDD/USB: refresh device list and restore selection
		_list_devices( __lists[HBOT_WIZARD_BOOT_DEVS], saved_type == CTL_LDR_HDD, -1 );

		// Restore selected item
		if (saved_item_idx >= 0 && saved_item_idx < ListView_GetItemCount(__lists[HBOT_WIZARD_BOOT_DEVS])) {
			ListView_SetItemState(__lists[HBOT_WIZARD_BOOT_DEVS], saved_item_idx,
				LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
			ListView_EnsureVisible(__lists[HBOT_WIZARD_BOOT_DEVS], saved_item_idx, FALSE);
		}

		_refresh_boot_buttons( bt_sheets[0].hwnd, __lists[HBOT_WIZARD_BOOT_DEVS], saved_item_idx );
	} else {
		// For ISO/PXE: reset button state first, then restore path
		// Trigger combo change to reset button text to "Create" (this clears the path field)
		SendMessage( bt_sheets[0].hwnd, WM_COMMAND,
			MAKELONG(IDC_COMBO_LOADER_TYPE, CBN_SELCHANGE),
			(LPARAM)GetDlgItem(bt_sheets[0].hwnd, IDC_COMBO_LOADER_TYPE) );

		// Now restore the saved path (after the combo change that clears it)
		if (saved_path[0] != 0) {
			SetWindowText( GetDlgItem(bt_sheets[0].hwnd, IDE_BOOT_PATH), saved_path );
		}

		// Trigger path change to update button enable state
		SendMessage( bt_sheets[0].hwnd, WM_COMMAND,
			MAKELONG(IDE_BOOT_PATH, EN_CHANGE),
			(LPARAM)GetDlgItem(bt_sheets[0].hwnd, IDE_BOOT_PATH) );
	}
}


INT_PTR
CALLBACK
_wizard_boot_dlg_proc(
		HWND	hwnd,
		UINT	message,
		WPARAM	wparam,
		LPARAM	lparam
	)
{

	WORD   code             = HIWORD(wparam);
    WORD   id               = LOWORD(wparam);
	DWORD _flags            = 0;
	DWORD _hotkeys[HOTKEYS] = { 0 };

	static _wz_sheets
	bt_sheets[ ] =
	{
		{ DLG_BOOT_SET,  0, TRUE, IDC_COMBO_LOADER_TYPE, 0 },
		{ DLG_BOOT_CONF, 0, TRUE, IDT_BOOT_TAB,          0 },
		{ -1 }
	};
	static ldr_config *ldr;
	static int saved_type = -1;          // Store the loader type when opening config
	static int saved_item_idx = -1;      // Store the selected list item index
	static wchar_t saved_path[MAX_PATH]; // Store the ISO/PXE path

	int check = 0; 
	int count = 0;
	
	switch ( message )
	{
		case WM_CLOSE:
			EndDialog( hwnd, IDCANCEL );
		case WM_DESTROY:
		{
			_boot_wizard_data *wiz_data = wnd_get_long(hwnd, GWL_USERDATA);

			if (wiz_data)
			{
				_keyfiles_wipe(&wiz_data->kf_state);
				free(wiz_data);
				wnd_set_long(hwnd, GWL_USERDATA, NULL);
			}

			__lists[HBOT_WIZARD_BOOT_DEVS] = HWND_NULL;
			__lists[HBOT_PART_LIST_BY_ID]  = HWND_NULL;
		}
		break;

		case WM_INITDIALOG:
		{
			_boot_wizard_data *wiz_data;

			// Initialize saved state
			saved_type = -1;
			saved_item_idx = -1;
			saved_path[0] = 0;

			// Allocate and initialize wizard instance data
			wiz_data = malloc(sizeof(_boot_wizard_data));
			if (wiz_data == NULL)
			{
				EndDialog(hwnd, IDCANCEL);
				return 0L;
			}
			_keyfiles_init(&wiz_data->kf_state);
			wnd_set_long(hwnd, GWL_USERDATA, wiz_data);

			h_wizard = hwnd;
			h_hook   = SetWindowsHookEx( WH_GETMESSAGE, (HOOKPROC)_get_msg_proc, NULL, GetCurrentThreadId( ) );

			while ( bt_sheets[count].id != -1 )
			{
				bt_sheets[count].hwnd = CreateDialog(
					__hinst, MAKEINTRESOURCE( bt_sheets[count].id ), GetDlgItem( hwnd, IDC_TAB ), _tab_proc
					);

				//EnumChildWindows( bt_sheets[count].hwnd, __sub_enum, (LPARAM)NULL );

				bt_sheets[count].first_tab_hwnd = 
				(
					( bt_sheets[count].first_tab_id != -1 ) ? 
					GetDlgItem( bt_sheets[count].hwnd, bt_sheets[count].first_tab_id ) : HWND_NULL
				);
				count++;
			}

			hwnd = bt_sheets[0].hwnd;
			{
				_set_check( hwnd, __is_efi_boot ? IDC_EFI_BOOT : IDC_MBR_BOOT, TRUE );

				__lists[HBOT_WIZARD_BOOT_DEVS] = GetDlgItem( hwnd, IDC_WZD_BOOT_DEVS );

				_init_combo(
					GetDlgItem(hwnd, IDC_COMBO_LOADER_TYPE), __is_efi_boot ? loader_type_efi : loader_type_mbr, lparam ? CTL_LDR_ISO : CTL_LDR_HDD, FALSE, -1
					);

				_list_devices( __lists[HBOT_WIZARD_BOOT_DEVS], TRUE, -1 );
				SendMessage( hwnd, WM_COMMAND, MAKELONG(IDC_COMBO_LOADER_TYPE, CBN_SELCHANGE), 0 );

				_sub_class( GetDlgItem(hwnd, IDC_CHECK_CONFIG), SUB_STATIC_PROC, HWND_NULL );
				_set_check( hwnd, IDC_CHECK_CONFIG, FALSE );	

				_sub_class( GetDlgItem(hwnd, IDC_USE_SMALL_BOOT), SUB_STATIC_PROC, HWND_NULL );
				_set_check( hwnd, IDC_USE_SMALL_BOOT, FALSE );
				ShowWindow(GetDlgItem(hwnd, IDC_USE_SMALL_BOOT), __is_efi_boot ? SW_HIDE : SW_SHOW);

				_sub_class( GetDlgItem(hwnd, IDC_USE_SHIM_BOOT), SUB_STATIC_PROC, HWND_NULL );
				_set_check( hwnd, IDC_USE_SHIM_BOOT, FALSE );
				ShowWindow(GetDlgItem(hwnd, IDC_USE_SHIM_BOOT), __is_efi_boot ? SW_SHOW : SW_HIDE);
			}
			ShowWindow(bt_sheets[0].hwnd, SW_SHOW);

		}
		break;

		case WM_COMMAND: 
		{
			int  is_efi   = _get_check(bt_sheets[0].hwnd, IDC_EFI_BOOT);
			int  type     = _get_combo_val( GetDlgItem(bt_sheets[0].hwnd, IDC_COMBO_LOADER_TYPE), is_efi ? loader_type_efi : loader_type_mbr );
			int  is_small = _get_check( bt_sheets[0].hwnd, IDC_USE_SMALL_BOOT );			
			int  is_shim  = _get_check(bt_sheets[0].hwnd, IDC_USE_SHIM_BOOT);
			int  dsk_num  = _ext_disk_num( __lists[HBOT_WIZARD_BOOT_DEVS] );

			int rlt;

			wchar_t vol[MAX_PATH]  = { 0 };
			wchar_t path[MAX_PATH] = { 0 };

			static ldr_config conf = { 0 };

			_get_item_text( __lists[HBOT_WIZARD_BOOT_DEVS], ListView_GetSelectionMark(__lists[HBOT_WIZARD_BOOT_DEVS]), 0, vol, countof(vol) );
			GetWindowText( GetDlgItem(bt_sheets[0].hwnd, IDE_BOOT_PATH), path, countof(path) );

			switch ( id )
			{
				case ID_SHIFT_TAB :
				case ID_TAB :
				{
					int index = IsWindowVisible( bt_sheets[0].hwnd ) ? 0 : 1;

					_focus_tab( 
						IDC_BTN_INSTALL, hwnd, 
						bt_sheets[index].hwnd, 
						bt_sheets[index].first_tab_hwnd, id == ID_TAB 
						);
				}
				break;

				case IDC_BTN_INSTALL:
				{
					wchar_t btn_text[MAX_PATH];				
					GetWindowText( (HWND)lparam, btn_text, countof(btn_text) );

					if ( wcscmp(btn_text, IDS_BOOTINSTALL) == 0 )
					{
						if (is_efi)
							_menu_set_loader_efi( hwnd, vol, dsk_num, type, is_shim );
						else
							_menu_set_loader_mbr( hwnd, vol, dsk_num, type, is_small );
					}
					if ( wcscmp(btn_text, IDS_BOOTREMOVE) == 0 )
					{
						_menu_unset_loader(hwnd, vol, dsk_num, type);
					}
					if ( wcscmp(btn_text, IDS_BOOTCREATE) == 0 )
					{
						if (is_efi)
							_menu_set_loader_file_efi( hwnd, path, type == CTL_LDR_ISO, is_shim );
						else
							_menu_set_loader_file_mbr( hwnd, path, type == CTL_LDR_ISO, is_small );

						SendMessage(
							bt_sheets[0].hwnd, WM_COMMAND, MAKELONG(IDE_BOOT_PATH, EN_CHANGE), (LPARAM)GetDlgItem(bt_sheets[0].hwnd, IDE_BOOT_PATH)
							);

						return 0L;
					}
					if ( wcscmp(btn_text, IDS_SAVECHANGES) == 0 )
					{
						// We're in config mode - save and return to overview
						_save_boot_config(bt_sheets[1].hwnd, saved_type, dsk_num, vol, path, &conf);
						_cleanup_and_restore_config_state(hwnd, bt_sheets, saved_type, saved_item_idx, saved_path);
						return 0L;
					}
					_list_devices( __lists[HBOT_WIZARD_BOOT_DEVS], type == CTL_LDR_HDD, -1 );
					_refresh_boot_buttons( bt_sheets[0].hwnd, __lists[HBOT_WIZARD_BOOT_DEVS], -1 );

				} 
				break;

				case IDC_BTN_UPDATE:
				{
					_menu_update_loader( hwnd, vol, dsk_num );
				}
				break;

				case IDC_BTN_CHANGE_CONF:
				{
					// Save current state before opening config
					saved_type = type;
					saved_item_idx = (type == CTL_LDR_HDD || type == CTL_LDR_STICK) ?
						ListView_GetSelectionMark(__lists[HBOT_WIZARD_BOOT_DEVS]) : -1;
					wcscpy_s(saved_path, countof(saved_path), path);

					rlt = _init_boot_config( bt_sheets[1].hwnd, type, dsk_num, vol, path, &conf );
					if ( rlt == ST_OK )
					{
						SetWindowText( GetDlgItem(hwnd, IDC_BTN_INSTALL), IDS_SAVECHANGES );
						EnableWindow( GetDlgItem(hwnd, IDC_BTN_INSTALL), TRUE );

						ShowWindow( GetDlgItem(hwnd, IDC_BTN_CHANGE_CONF), FALSE );
						ShowWindow( GetDlgItem(hwnd, IDC_BTN_UPDATE), FALSE );

						ShowWindow( bt_sheets[0].hwnd, SW_HIDE );
						ShowWindow( bt_sheets[1].hwnd, SW_SHOW );
					}
				}
				break;

				case IDCANCEL:
				{
					// Check if we're on the config page
					if ( IsWindowVisible(bt_sheets[1].hwnd) )
					{
						// Return to overview without saving
						_cleanup_and_restore_config_state(hwnd, bt_sheets, saved_type, saved_item_idx, saved_path);
					}
					else
					{
						// We're on the overview page, close the dialog
						EndDialog( hwnd, IDCANCEL );
					}
				}
				break;
			}
		}
		break;

		default:
		{
			int rlt = _draw_proc(message, lparam);
			if ( rlt != -1 )
			{
				return rlt;
			}
		}
		break;
	}
	return 0L;

}


int _dlg_config_loader(
		HWND hwnd,
		BOOL external
	)
{
	int result =
		(int)DialogBoxParam(
				NULL, 
				MAKEINTRESOURCE(IDD_WIZARD_BOOT),
				hwnd,
				pv(_wizard_boot_dlg_proc),
				(LPARAM)external
		);

	return (
		result == IDOK ? ST_OK : ST_CANCEL
	);
}