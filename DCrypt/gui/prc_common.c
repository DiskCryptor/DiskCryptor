/*  *
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
#include <shlwapi.h>

#include "main.h"
#include "prc_common.h"

#include "prc_keyfiles.h"

// Helper to get keyfiles_state from a tab page's parent wizard dialog
// Tab pages are children of IDC_TAB which is a child of the wizard dialog
// For nested tabs (boot config), we need to go up 4 levels instead of 2
static keyfiles_state *_get_wizard_keyfiles(HWND hwnd)
{
	HWND h_parent = hwnd;

	// Walk up parent chain looking for wizard dialog with keyfiles_state
	// Standard wizard tabs: page -> IDC_TAB -> wizard (2 levels)
	// Boot config nested tabs: page -> IDC_BOOT_TAB -> DLG_BOOT_CONF -> IDC_TAB -> wizard (4 levels)
	for (int i = 0; i < 5 && h_parent; i++)
	{
		h_parent = GetParent(h_parent);
		if (h_parent && i >= 1)  // Start checking from 2nd parent
		{
			void *wiz_data = wnd_get_long(h_parent, GWL_USERDATA);
			if (wiz_data)
			{
				// Verify this looks like wizard data by checking the window class
				// The wizard dialogs have IDC_TAB as direct child
				if (GetDlgItem(h_parent, IDC_TAB) != NULL)
				{
					return (keyfiles_state *)wiz_data;
				}
			}
		}
	}
	return NULL;
}
#include "prc_wizard_boot.h"
#include "dlg_menu.h"
#include "pass.h"
#include "threads.h"
#include "dlg_drives_list.h"
#include "volume_header.h"
#include "secure_desktop.h"


void update_entropy_tooltip(HWND hwnd, HWND hCtrl, int entropy)
{
	static HWND hTooltip = NULL;
	wchar_t tip_text[64];

	/* Skip tooltip operations on secure desktop - the static hTooltip handle
	   may point to a window on the default desktop, causing cross-desktop
	   message deadlocks */
	if (is_secure_desktop_active())
		return;

	_snwprintf(tip_text, countof(tip_text), L"Entropy: %d bits", entropy);

	if (!hTooltip || !IsWindow(hTooltip))
	{
		TOOLINFO ti = { sizeof(TOOLINFO) };

		hTooltip = CreateWindowEx(0, TOOLTIPS_CLASS, NULL,
			WS_POPUP | TTS_ALWAYSTIP | TTS_NOPREFIX,
			CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
			hwnd, NULL, __hinst, NULL);

		if (hTooltip)
		{
			ti.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
			ti.hwnd = hwnd;
			ti.uId = (UINT_PTR)hCtrl;
			ti.lpszText = tip_text;
			SendMessage(hTooltip, TTM_ADDTOOL, 0, (LPARAM)&ti);
		}
	}
	else
	{
		TOOLINFO ti = { sizeof(TOOLINFO) };
		ti.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
		ti.hwnd = hwnd;
		ti.uId = (UINT_PTR)hCtrl;
		ti.lpszText = tip_text;
		SendMessage(hTooltip, TTM_UPDATETIPTEXT, 0, (LPARAM)&ti);
	}
}

INT_PTR
CALLBACK
_tab_proc(
		HWND   hwnd,
		UINT   message,
		WPARAM wparam,
		LPARAM lparam
	)
{
	WORD code = HIWORD(wparam);
	WORD id   = LOWORD(wparam);
	HDC dc;

	wchar_t tmpb[MAX_PATH];
	int k;

	/*if (id == IDE_RICH_BOOTMSG)
	{
		TCHAR temp_str[100];
		wsprintf(temp_str, L"%d %d\r\n", message, code);
		OutputDebugString(temp_str);
	}*/

	switch ( message )
	{
		case WM_NOTIFY:
		{
			if ( wparam == IDT_BOOT_TAB )
			{
				if ( ((NMHDR *)lparam)->code == TCN_SELCHANGE )
				{
					HWND h_tab = GetDlgItem(hwnd, IDT_BOOT_TAB);

					if ( !_is_curr_in_group(h_tab) )
					{
						_change_page(h_tab, TabCtrl_GetCurSel(h_tab));
					}
				}
			}
			if ( wparam == IDC_WZD_BOOT_DEVS )
			{
				NM_LISTVIEW	*msg_info = pv(lparam);
				NMHDR		*msg_hdr  = pv(lparam);

				if ( msg_hdr->code == LVN_ITEMACTIVATE )
				{
					_get_item_text( __lists[HBOT_WIZARD_BOOT_DEVS], msg_info->iItem, 2, tmpb, countof(tmpb) );

					if ( wcsstr(tmpb, L"installed") != NULL )
					{
						SendMessage( GetParent(GetParent(hwnd)), WM_COMMAND, MAKELONG(IDC_BTN_CHANGE_CONF, 0), 0 );
					} else 
					{
						wchar_t vol[MAX_PATH];

						int dsk_num;

						int is_efi = _get_check(hwnd, IDC_EFI_BOOT);
						int type = _get_combo_val( GetDlgItem(hwnd, IDC_COMBO_LOADER_TYPE), is_efi ? loader_type_efi : loader_type_mbr );
						int is_small = _get_check( hwnd, IDC_USE_SMALL_BOOT );
						int is_shim  = _get_check( hwnd, IDC_USE_SHIM_BOOT );

						_get_item_text( __lists[HBOT_WIZARD_BOOT_DEVS], msg_info->iItem, 0, vol, countof(vol) );
						dsk_num = _ext_disk_num( __lists[HBOT_WIZARD_BOOT_DEVS] );

						if(is_efi)
							_menu_set_loader_efi( hwnd, vol, dsk_num, type, is_shim );
						else
							_menu_set_loader_mbr( hwnd, vol, dsk_num, type, is_small );

						_list_devices( __lists[HBOT_WIZARD_BOOT_DEVS], type == CTL_LDR_HDD, -1 );
						_refresh_boot_buttons( hwnd, msg_hdr->hwndFrom, msg_info->iItem );

					}
				}
				if ( ( msg_hdr->code == LVN_ITEMCHANGED ) && ( msg_info->uNewState & LVIS_FOCUSED ) )
				{
					_refresh_boot_buttons( hwnd, msg_hdr->hwndFrom, msg_info->iItem );
					return 1L;
				}
				if ( msg_hdr->code == NM_CLICK )
				{
					_refresh_boot_buttons( hwnd, msg_hdr->hwndFrom, msg_info->iItem );
					return 1L;
				}					
				if ( msg_hdr->code == NM_RCLICK )
				{
					HMENU popup       = CreatePopupMenu( );
					BOOL  item_update = FALSE;

					int is_efi   = _get_check(hwnd, IDC_EFI_BOOT);
					int type     = _get_combo_val( GetDlgItem(hwnd, IDC_COMBO_LOADER_TYPE), is_efi ? loader_type_efi : loader_type_mbr );
					int is_small = _get_check( hwnd, IDC_USE_SMALL_BOOT );
					int is_shim  = _get_check( hwnd, IDC_USE_SHIM_BOOT );

					ldr_config conf;

					int dsk_num = -1;
					int item;					

					wchar_t vol[MAX_PATH];					

					_get_item_text( __lists[HBOT_WIZARD_BOOT_DEVS], msg_info->iItem, 0, vol, countof(vol) );
					dsk_num = _ext_disk_num( __lists[HBOT_WIZARD_BOOT_DEVS] );

					if ( ListView_GetSelectedCount( __lists[HBOT_WIZARD_BOOT_DEVS] ) )
					{
						_get_item_text( __lists[HBOT_WIZARD_BOOT_DEVS], msg_info->iItem, 2, tmpb, countof(tmpb) );

						if ( wcsstr(tmpb, L"installed") != NULL )
						{
							AppendMenu(popup, MF_STRING, ID_BOOT_REMOVE, IDS_BOOTREMOVE);

							if ( type == CTL_LDR_HDD )
							{
								item_update =
									dc_get_ldr_config( dsk_num, &conf ) == ST_OK &&
									(int)conf.ldr_ver < (conf.sign1 == 0 ? DC_UEFI_VER : DC_BOOT_VER);
								
								if ( item_update )
								{
									AppendMenu(popup, MF_STRING, ID_BOOT_UPDATE, IDS_BOOTUPDATE);
								}
							}

							if ( wcsstr(tmpb, L"EFI") != NULL || wcsstr(tmpb, L"ESP") != NULL )
							{
								AppendMenu(popup, MF_SEPARATOR, 0, NULL);

								if ( wcsstr(tmpb, L", bme") != NULL )
									AppendMenu(popup, MF_STRING, ID_BOOT_DEL_BME, IDS_BOOTDELBME);
								else
									AppendMenu(popup, MF_STRING, ID_BOOT_ADD_BME, IDS_BOOTADDBME);

								if (wcsstr(tmpb, L"ESP") == NULL) 
								{
									if (wcsstr(tmpb, L", ms") != NULL)
										AppendMenu(popup, MF_STRING, ID_BOOT_RESTORE_MS, IDS_BOOTRESTOREMS);
									else
										AppendMenu(popup, MF_STRING, ID_BOOT_REPLACE_MS, IDS_BOOTREPLACEMS);
								}
							}

							AppendMenu(popup, MF_SEPARATOR, 0, NULL);
							AppendMenu(popup, MF_STRING, ID_BOOT_CHANGE_CONFIG, IDS_BOOTCHANGECGF);

						} else {
							AppendMenu(popup, MF_STRING, ID_BOOT_INSTALL, IDS_BOOTINSTALL);
						}
					}
					item = TrackPopupMenu(
							popup,
							TPM_RETURNCMD | TPM_LEFTBUTTON,
							LOWORD(GetMessagePos( )),
							HIWORD(GetMessagePos( )),
							0,
							hwnd,
							NULL
						);

					DestroyMenu( popup );
					switch ( item )
					{
						case ID_BOOT_INSTALL:
							if(is_efi)				_menu_set_loader_efi( hwnd, vol, dsk_num, type, is_shim );
							else					_menu_set_loader_mbr( hwnd, vol, dsk_num, type, is_small ); 
							break;

						case ID_BOOT_REMOVE:		_menu_unset_loader(hwnd, vol, dsk_num, type ); break;

						case ID_BOOT_UPDATE:		_menu_update_loader( hwnd, vol, dsk_num ); break;

						case ID_BOOT_ADD_BME:		_menu_add_bme( hwnd, vol, dsk_num ); break;
						case ID_BOOT_DEL_BME:		_menu_del_bme( hwnd, vol, dsk_num ); break;
						case ID_BOOT_REPLACE_MS:	_menu_repalce_msldr( hwnd, vol, dsk_num ); break;
						case ID_BOOT_RESTORE_MS:	_menu_restore_msldr( hwnd, vol, dsk_num ); break;

						case ID_BOOT_CHANGE_CONFIG: 
							SendMessage(GetParent(GetParent(hwnd)), WM_COMMAND, MAKELONG(IDC_BTN_CHANGE_CONF, 0), 0);
							break;
					}

					if ( ( item == ID_BOOT_INSTALL ) || ( item == ID_BOOT_REMOVE )
					  || ( item == ID_BOOT_ADD_BME ) || ( item == ID_BOOT_DEL_BME ) 
					  || ( item == ID_BOOT_REPLACE_MS ) || ( item == ID_BOOT_RESTORE_MS ) )
					{
						_list_devices( __lists[HBOT_WIZARD_BOOT_DEVS], type == CTL_LDR_HDD, -1 );
						_refresh_boot_buttons( hwnd, msg_hdr->hwndFrom, msg_info->iItem );
					}
				}
			}
		}
		break;
		case WM_USER_CLICK : 
		{
			HWND ctl_wnd = (HWND)wparam;
			if ( ctl_wnd == GetDlgItem(hwnd, IDC_AUTO_START) )
			{
				BOOL enable = _get_check(hwnd, IDC_AUTO_START);
				EnableWindow(GetDlgItem(hwnd, IDC_WIPE_LOGOFF), enable);
				EnableWindow(GetDlgItem(hwnd, IDC_UNMOUNT_LOGOFF), enable);

				InvalidateRect(GetDlgItem(hwnd, IDC_WIPE_LOGOFF), NULL, TRUE);
				InvalidateRect(GetDlgItem(hwnd, IDC_UNMOUNT_LOGOFF), NULL, TRUE);

				if ( !enable )
				{
					_set_check(hwnd, IDC_WIPE_LOGOFF, enable);
					_set_check(hwnd, IDC_UNMOUNT_LOGOFF, enable);
				}
				return 1L;
			}
			if ( ctl_wnd == GetDlgItem(hwnd, IDC_BT_ENTER_PASS_MSG) )
			{
				EnableWindow(GetDlgItem(hwnd, IDE_RICH_BOOTMSG), _get_check(hwnd, IDC_BT_ENTER_PASS_MSG));
				return 1L;
			}
			if (ctl_wnd == GetDlgItem(hwnd, IDC_BT_AUTH_MSG))
			{
				EnableWindow(GetDlgItem(hwnd, IDE_RICH_AUTH_MSG), _get_check(hwnd, IDC_BT_AUTH_MSG));
				return 1L;
			}
			if (ctl_wnd == GetDlgItem(hwnd, IDC_BT_GOOD_PASS_MSG))
			{
				EnableWindow(GetDlgItem(hwnd, IDE_RICH_OKPASS_MSG), _get_check(hwnd, IDC_BT_GOOD_PASS_MSG));
				return 1L;
			}
			if ( ctl_wnd == GetDlgItem(hwnd, IDC_BT_BAD_PASS_MSG) )
			{
				EnableWindow(GetDlgItem(hwnd, IDE_RICH_ERRPASS_MSG), _get_check(hwnd, IDC_BT_BAD_PASS_MSG));
				return 1L;
			}
			if ( ctl_wnd == GetDlgItem(hwnd, IDC_CHECK_SHOW) )
			{
				int mask = _get_check(hwnd, IDC_CHECK_SHOW) ? 0 : '*';

				SendMessage(
					GetDlgItem(hwnd, IDE_PASS), EM_SETPASSWORDCHAR,	mask, 0
				);
				SendMessage(
					GetDlgItem(hwnd, IDE_CONFIRM), EM_SETPASSWORDCHAR,	mask, 0
				);
				InvalidateRect(GetDlgItem(hwnd, IDE_PASS), NULL, TRUE);
				InvalidateRect(GetDlgItem(hwnd, IDE_CONFIRM), NULL, TRUE);
				return 1L;
			}
			if ( ctl_wnd == GetDlgItem(hwnd, IDC_USE_KEYFILES) )
			{
				keyfiles_state *kf_state = _get_wizard_keyfiles(hwnd);

				SendMessage(
					hwnd, WM_COMMAND, MAKELONG(IDE_PASS, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS)
					);

				EnableWindow(GetDlgItem(hwnd, IDB_USE_KEYFILES), _get_check(hwnd, IDC_USE_KEYFILES));
				if (kf_state && _keyfiles_count(kf_state) == 0) {
					if (IsDlgButtonChecked(hwnd, IDC_RADIO_HDR_V2) == BST_CHECKED)
						kf_state->mix_mode = KEYFILE_MIX_HASHED;
					else
						kf_state->mix_mode = KEYFILE_MIX_LEGACY;
				}
				return 1L;
			}
			if ( ctl_wnd == GetDlgItem(hwnd, IDC_CHECK_SKIP_UNUSED) )
			{
				BOOL skip_enabled = _get_check(hwnd, IDC_CHECK_SKIP_UNUSED);
				EnableWindow(GetDlgItem(hwnd, IDC_COMBO_PASSES), !skip_enabled);
				EnableWindow(GetDlgItem(hwnd, IDC_STATIC_PASSES_LIST), !skip_enabled);
				return 1L;
			}
			{
				_wnd_data *data = wnd_get_long(ctl_wnd, GWL_USERDATA);

				k = 0;
				while ( hotks_chk[k].id != -1 )
				{
					if( ctl_wnd == GetDlgItem(hwnd, hotks_chk[k].id) )
					{
						EnableWindow(GetDlgItem(hwnd, hotks_edit[k].id), data->state);
						EnableWindow(GetDlgItem(hwnd, hotks_static[k].id), data->state);
						SetFocus(GetDlgItem(hwnd, hotks_edit[k].id));

						return 1L;												
					}
					k++;
				}
			}
		}
		break;

		case WM_COMMAND : 
		{
			_dnode	*node = pv( _get_sel_item( __lists[HMAIN_DRIVES] ) );
			_dact	*act  = _create_act_thread( node, -1, -1 );

			switch (id)
			{
				case IDB_USE_KEYFILES : // encrypt dialog
				{
					keyfiles_state *kf_state = _get_wizard_keyfiles(hwnd);
					if (kf_state)
					{
						_dlg_keyfiles( hwnd, kf_state, TRUE );
					}

					SendMessage( hwnd, WM_COMMAND, MAKELONG(IDE_PASS, EN_CHANGE), (LPARAM)GetDlgItem(hwnd, IDE_PASS) );

				}
				break;

				case IDB_SECURE_PASS_ENTRY : // secure password entry on wizard password page
				{
					// Forward to parent wizard dialog
					SendMessage( GetParent(GetParent(hwnd)), WM_COMMAND, MAKELONG(IDB_SECURE_PASS_ENTRY, 0), 0 );
				}
				break;

				case IDB_GET_CERT : // Get certificate button on Support tab
				{
					// Forward to parent options dialog
					SendMessage( GetParent(GetParent(hwnd)), WM_COMMAND, MAKELONG(IDB_GET_CERT, 0), 0 );
				}
				break;

				case IDB_BOOT_PREF :
				{
					_dlg_config_loader( hwnd, TRUE );
				}
				break;

				case IDB_BT_CONF_EMB_KEY : // bootloader config dialog
				{
					keyfiles_state *kf_state = _get_wizard_keyfiles(hwnd);
					if (kf_state)
					{
						_dlg_keyfiles( hwnd, kf_state, TRUE );
					}
				}
				break;

				case IDB_EXPORT_EMB_KEY : // export embedded keyfile
				{
					keyfiles_state *kf_state = _get_wizard_keyfiles(hwnd);
					_list_key_files *keyfile = kf_state ? _first_keyfile( kf_state ) : NULL;
					if ( keyfile && keyfile->is_virtual && keyfile->virtual_size == 64 ) // == SHA512_DIGEST_SIZE
					{
						wchar_t s_file[MAX_PATH] = { L"keyfile.key" };
						if ( _save_file_dialog( hwnd, s_file, countof(s_file), L"Export embedded keyfile" ) )
						{
							int rlt = save_file( s_file, keyfile->virtual_data, keyfile->virtual_size );
							if ( rlt == ST_OK )
							{
								__msg_i( hwnd, L"Embedded keyfile exported successfully to:\n%s", s_file );
							}
							else
							{
								__error_s( hwnd, L"Error exporting keyfile", rlt );
							}
						}
					}
					else
					{
						__msg_w( hwnd, L"No embedded keyfile configured.\n\nUse 'Config embedded keyfile' to set up a 64-byte keyfile first." );
					}
				}
				break;

				case IDB_ACT_PAUSE :
				{
					if ( node )
					{	
						if (act->status == ACT_RUNNING) 
						{
							act->status	= act->act != ACT_FORMAT ? ACT_PAUSED : ACT_STOPPED;
							act->act	= ACT_ENCRYPT;
						}
					}
					_refresh(TRUE);
				}
				break;

				case IDB_BOOT_PATH :
				{
					int is_efi = _get_check(hwnd, IDC_EFI_BOOT);
					int boot_type = _get_combo_val( GetDlgItem(hwnd, IDC_COMBO_LOADER_TYPE), is_efi ? loader_type_efi : loader_type_mbr );

					wchar_t s_path[MAX_PATH] = { 0 };

					// PXE in EFI mode uses a folder, not a file
					if (boot_type == CTL_LDR_PXE && is_efi)
					{
						if ( _folder_choice(hwnd, s_path, L"Select empty folder for PXE bootloader files") )
						{
							// Check if folder is empty
							wchar_t search_path[MAX_PATH];
							WIN32_FIND_DATA find_data;
							HANDLE h_find;
							BOOL is_empty = TRUE;

							_snwprintf(search_path, countof(search_path), L"%s\\*", s_path);
							h_find = FindFirstFile(search_path, &find_data);

							if (h_find != INVALID_HANDLE_VALUE)
							{
								do {
									// Skip "." and ".." entries
									if (wcscmp(find_data.cFileName, L".") != 0 && wcscmp(find_data.cFileName, L"..") != 0)
									{
										is_empty = FALSE;
										break;
									}
								} while (FindNextFile(h_find, &find_data));
								FindClose(h_find);
							}

							if (!is_empty)
							{
								if (MessageBox(hwnd,
									L"The selected folder is not empty. Files may be overwritten.\nContinue anyway?",
									L"Folder Not Empty",
									MB_YESNO | MB_ICONWARNING) != IDYES)
								{
									break; // User cancelled
								}
							}

							SetWindowText( GetDlgItem(hwnd, IDE_BOOT_PATH), s_path );
						}
					}
					else
					{
						// ISO or PXE in MBR mode uses a file
						wcscpy( s_path, boot_type == CTL_LDR_ISO ? L"loader.iso" : L"loader.img" );

						if ( _save_file_dialog(hwnd, s_path, countof(s_path), L"Save Bootloader File As") )
						{
							SetWindowText( GetDlgItem(hwnd, IDE_BOOT_PATH), s_path );
						}
					}
				}
				break;

				case IDB_ISO_OPEN_SRC :
				{
					wchar_t s_file[MAX_PATH] = { 0 };

					if ( _open_file_dialog(hwnd, s_file, countof(s_file), L"Open ISO file to encrypt") ) 
					{
						SetWindowText(GetDlgItem(hwnd, IDE_ISO_SRC_PATH), s_file);
					}
				}
				break;

				case IDB_ISO_OPEN_DST :
				{
					wchar_t  s_dst_file[MAX_PATH] = { L"encrypted." };
					wchar_t  s_src_file[MAX_PATH] = { 0 };

					wchar_t *s_name;

					GetWindowText( GetDlgItem(hwnd, IDE_ISO_SRC_PATH), s_src_file, countof(s_src_file ));

					s_name = _extract_name(s_src_file);
					wcsncat(s_dst_file, (s_name != NULL) ? s_name : L"iso", countof(s_dst_file) - wcslen(s_src_file));

					if ( _save_file_dialog(hwnd, s_dst_file, countof(s_dst_file), L"Save encrypted ISO file to...") ) 
					{						
						SetWindowText(GetDlgItem(hwnd, IDE_ISO_DST_PATH), s_dst_file);
					}
				}
				break;

				case IDC_EFI_BOOT:
				case IDC_MBR_BOOT:
				{
					int is_efi = _get_check(hwnd, IDC_EFI_BOOT);

					if (is_efi != __is_efi_boot)
					{
						wchar_t message[1024];
						swprintf_s(message, _countof(message),
							L"This windows installation is setup for %s boot, it won't be able to boot with a different bootloader type.\n"
							L"Do you want to select the correct bootloader type?"
							, __is_efi_boot ? L"EFI" : L"MBR");

						if(__msg_w(hwnd,message)) {
							_set_check(hwnd, IDC_EFI_BOOT, __is_efi_boot ? TRUE : FALSE);
							_set_check(hwnd, IDC_MBR_BOOT, __is_efi_boot ? FALSE : TRUE);
							break;
						}
					}

					SendMessage( GetDlgItem(hwnd, IDC_COMBO_LOADER_TYPE), CB_RESETCONTENT, 0, 0 );
					_init_combo( GetDlgItem(hwnd, IDC_COMBO_LOADER_TYPE), is_efi ? loader_type_efi : loader_type_mbr, CTL_LDR_HDD, FALSE, -1 );

					ShowWindow(GetDlgItem(hwnd, IDC_USE_SMALL_BOOT), is_efi ? SW_HIDE : SW_SHOW);
					ShowWindow(GetDlgItem(hwnd, IDC_USE_SHIM_BOOT), is_efi ? SW_SHOW : SW_HIDE);
				}
				break;

				case IDC_RADIO_HDR_V1:
				case IDC_RADIO_HDR_V2:
				{
					BOOL is_v2 = IsDlgButtonChecked(hwnd, IDC_RADIO_HDR_V2) == BST_CHECKED;
					EnableWindow(GetDlgItem(hwnd, IDC_STATIC_HDR_SLOTS), is_v2);
					EnableWindow(GetDlgItem(hwnd, IDC_EDIT_HDR_SLOTS), is_v2);

					/* Update KDF combo in password dialog only if user hasn't changed it */
					{
						HWND h_tab = GetParent(hwnd);
						HWND h_child = GetWindow(h_tab, GW_CHILD);
						while (h_child) {
							HWND h_kdf = GetDlgItem(h_child, IDC_COMBO_KDF);
							if (h_kdf) {
								int cur_kdf = _get_combo_val(h_kdf, kdf_names);
								/* Only change if KDF is at its default value for the other header type */
								if ((is_v2 && cur_kdf == 0) || (!is_v2 && cur_kdf == KDF_ARGON_DEFAULT)) {
									SendMessage(h_kdf, CB_RESETCONTENT, 0, 0);
									_init_combo(h_kdf, kdf_names, is_v2 ? KDF_ARGON_DEFAULT : 0, FALSE, -1);
								}
								break;
							}
							h_child = GetWindow(h_child, GW_HWNDNEXT);
						}
					}

					if (!(__config.load_flags & DST_PRO_ENABLED)) {
						is_v2 = FALSE;
					}

					EnableWindow(GetDlgItem(hwnd, IDC_COMBO_HDR_SIZE), is_v2);
					EnableWindow(GetDlgItem(hwnd, IDC_CHECK_BAK_HEADER), is_v2);
					if (!is_v2) {
						/* Select default header size (2 KiB) in combo box */
						SendMessage(GetDlgItem(hwnd, IDC_COMBO_HDR_SIZE), CB_SETCURSEL, 0, 0);
					} else {
						/* Trigger recalculation of header size */
						SendMessage(hwnd, WM_COMMAND, MAKELONG(IDC_EDIT_HDR_SLOTS, EN_CHANGE),
							(LPARAM)GetDlgItem(hwnd, IDC_EDIT_HDR_SLOTS));
					}
				}
				break;
			}

			switch (code) 
			{
				case CBN_SELCHANGE :
				{
					switch ( id )
					{
						case IDC_COMBO_AUTH_TYPE :
						{
							BOOL b_pass   = _get_combo_val( (HWND)lparam, auth_type ) & LDR_LT_GET_PASS;
							//BOOL b_keyfie = _get_combo_val( (HWND)lparam, auth_type ) & LDR_LT_EMBED_KEY;

							_enb_but_this( hwnd, IDC_COMBO_AUTH_TYPE, b_pass );

							EnableWindow( GetDlgItem(hwnd, IDC_STATIC_AUTH_TYPE), TRUE );
							EnableWindow( GetDlgItem(hwnd, IDC_CNT_BOOTMSG), FALSE );

							//EnableWindow( GetDlgItem(hwnd, IDB_BT_CONF_EMB_KEY), b_keyfie );
							EnableWindow( GetDlgItem(hwnd, IDB_BT_CONF_EMB_KEY), TRUE );
							EnableWindow( GetDlgItem(hwnd, IDB_EXPORT_EMB_KEY), TRUE );

							if ( b_pass )
							{
								EnableWindow(
									GetDlgItem(hwnd, IDE_RICH_BOOTMSG), _get_check(hwnd, IDC_BT_ENTER_PASS_MSG)
									);
								EnableWindow(
									GetDlgItem(hwnd, IDC_BT_CANCEL_TMOUT), (BOOL)SendMessage(GetDlgItem(hwnd, IDC_COMBO_AUTH_TMOUT), CB_GETCURSEL, 0, 0)
									);
							}
						}
						break;

						case IDC_COMBO_AUTH_TMOUT :
						{						
							EnableWindow(
								GetDlgItem(hwnd, IDC_BT_CANCEL_TMOUT), (BOOL)SendMessage((HWND)lparam, CB_GETCURSEL, 0, 0)
								);

							InvalidateRect( GetDlgItem(hwnd, IDC_BT_CANCEL_TMOUT), NULL, TRUE );

						}
						break;

						case IDC_COMBO_METHOD :
						{
							wchar_t text[MAX_PATH];
							BOOL enable;

							_get_item_text( __lists[HBOT_PART_LIST_BY_ID], 0, 0, text, countof(text) );
							enable = _get_combo_val((HWND)lparam, boot_type_ext) == LDR_BT_DISK_ID && !wcsstr(text, L"not found");

							EnableWindow( GetDlgItem(hwnd, IDC_STATIC_SELECT_PART), enable );
							EnableWindow( __lists[HBOT_PART_LIST_BY_ID], enable );

						}
						break;

						case IDC_COMBO_LOADER_TYPE : 
						{
							int k;
							int ctl_enb[ ] =
							{
								IDC_HEAD_BOOT_DEV, IDC_WZD_BOOT_DEVS,
								IDC_HEAD_BOOT_FILE, IDE_BOOT_PATH, IDB_BOOT_PATH
							};

							int type = (int)SendMessage( GetDlgItem(hwnd, IDC_COMBO_LOADER_TYPE), CB_GETCURSEL, 0, 0 );
							for ( k = 0; k < countof(ctl_enb); k++ )
							{
								EnableWindow(
									GetDlgItem( hwnd, ctl_enb[k] ), ( type < 2 && k < 2 ) || ( type > 1 && k > 1 )
									);
							}
							if ( type < 2 ) 
							{
								_list_devices( __lists[HBOT_WIZARD_BOOT_DEVS], !type, -1 );
							}
							SetWindowText(
								GetDlgItem(GetParent(GetParent(hwnd)), IDC_BTN_INSTALL), type > 1 ? IDS_BOOTCREATE : IDS_BOOTINSTALL
								);

							EnableWindow( GetDlgItem(GetParent(GetParent(hwnd)), IDC_BTN_INSTALL), FALSE );

							SetWindowText( GetDlgItem(hwnd, IDE_BOOT_PATH), STR_NULL );
							SetFocus( GetDlgItem(hwnd, IDE_BOOT_PATH) );

						}
						break;

						case IDC_COMBO_BOOT_INST :
						{
							BOOL ext_loader = SendMessage((HWND)lparam, CB_GETCURSEL, 0, 0) == 0;

							EnableWindow( GetDlgItem(hwnd, IDC_USE_SMALL_BOOT), !ext_loader );
							EnableWindow( GetDlgItem(hwnd, IDB_BOOT_PREF), ext_loader );

							/* Enable/disable EFI checkboxes based on selection */
							EnableWindow( GetDlgItem(hwnd, IDC_CHECK_CREATE_ESP), !ext_loader );
							EnableWindow( GetDlgItem(hwnd, IDC_CHECK_CREATE_BME), !ext_loader );
						}
						break;

						case IDC_COMBO_KBLAYOUT :
						{
							SendMessage( hwnd, WM_COMMAND, MAKELONG(IDE_PASS, EN_CHANGE), lparam );
						}
						break;

						case IDC_COMBO_KDF :
						{
							SendMessage( hwnd, WM_COMMAND, MAKELONG(IDE_PASS, EN_CHANGE), lparam );
						}
						break;

						case IDC_COMBO_PASSES : 
						{
							_dact *act = _create_act_thread(node, -1, -1);
							if ( act )
							{
								act->wp_mode = (int)(SendMessage((HWND)lparam, CB_GETCURSEL, 0, 0));
							}
						}
						break;
					}
				}
				break;

				case EN_UPDATE:
				{
					char s_msg[MAX_PATH];
					char s_count[MAX_PATH];

					GetWindowTextA((HWND)lparam, s_msg, sizeof(s_msg));

					_snprintf(s_count, sizeof(s_count), "%zd / %d", strlen(s_msg), 120);

					switch (id)
					{
						case IDE_RICH_BOOTMSG :
						{
							SetWindowTextA( GetDlgItem(hwnd, IDC_CNT_BOOTMSG), s_count );
						}
						break;

						case IDE_RICH_AUTH_MSG:
						{
							SetWindowTextA(GetDlgItem(hwnd, IDC_CNT_AUTOMSG), s_count);
						}
						break;

						case IDE_RICH_OKPASS_MSG:
						{
							SetWindowTextA(GetDlgItem(hwnd, IDC_CNT_GOODMSG), s_count);
						}
						break;

						case IDE_RICH_ERRPASS_MSG:
						{
							SetWindowTextA(GetDlgItem(hwnd, IDC_CNT_ERRMSG), s_count);
						}
						break;
					}
				}
				break;

				case EN_CHANGE : 
				{
					switch (id)
					{
						case IDE_ISO_SRC_PATH :
						case IDE_ISO_DST_PATH :
						{
							HWND h_wiz_parent = GetParent(GetParent(hwnd));
							HWND h_ctl_parent = GetParent((HWND)lparam);
							
							wchar_t s_src_path[MAX_PATH] = { 0 };
							wchar_t s_dst_path[MAX_PATH] = { 0 };

							if ( h_wiz_parent != NULL && h_ctl_parent != NULL )
							{
								GetWindowText( GetDlgItem(h_ctl_parent, IDE_ISO_SRC_PATH), s_src_path, countof(s_src_path) );
								GetWindowText( GetDlgItem(h_ctl_parent, IDE_ISO_DST_PATH), s_dst_path, countof(s_dst_path) );

								EnableWindow(
									GetDlgItem(h_wiz_parent, IDOK), ( PathFileExists(s_src_path) && (s_dst_path[0] != 0) )
									);
							}					
						}
						break;

						case IDE_BOOT_PATH :
						{
							wchar_t s_path[MAX_PATH] = { 0 };
							GetWindowText( (HWND)lparam, s_path, countof(s_path) );

							BOOL path_valid = FALSE;

							// Check if PXE in EFI mode (requires folder) or file-based bootloader
							int is_efi = _get_check(hwnd, IDC_EFI_BOOT);
							int boot_type = _get_combo_val( GetDlgItem(hwnd, IDC_COMBO_LOADER_TYPE), is_efi ? loader_type_efi : loader_type_mbr );

							if (s_path[0] != 0)
							{
								if (boot_type == CTL_LDR_PXE && is_efi)
								{
									// PXE in EFI mode: validate it's a directory
									DWORD attrs = GetFileAttributes(s_path);
									path_valid = (attrs != INVALID_FILE_ATTRIBUTES) && (attrs & FILE_ATTRIBUTE_DIRECTORY);
								}
								else
								{
									// ISO or PXE in MBR mode: validate file exists
									path_valid = PathFileExists(s_path);
								}
							}

							EnableWindow( GetDlgItem(GetParent(GetParent(hwnd)), IDC_BTN_INSTALL), s_path[0] != 0 );
							EnableWindow( GetDlgItem(GetParent(GetParent(hwnd)), IDC_BTN_CHANGE_CONF), path_valid );
						}
						break;

						case IDC_EDIT_HDR_SLOTS :
						{
							if (IsDlgButtonChecked(hwnd, IDC_RADIO_HDR_V2) == BST_CHECKED && (__config.load_flags & DST_PRO_ENABLED)) {
								int slot_count = GetDlgItemInt(hwnd, IDC_EDIT_HDR_SLOTS, NULL, FALSE);
								u32 head_len;
								int i;

								if (slot_count < 1) slot_count = 1;
								if (slot_count > KEY_SLOT_MAX) slot_count = KEY_SLOT_MAX;

								head_len = DC_BASE_SIZE + slot_count * (PKCS_DERIVE_MAX + sizeof(dc_slot_info));
								if (head_len < DC_AREA_SIZE)
									head_len = DC_AREA_SIZE;
								else {
									unsigned long index;
									if (_BitScanReverse(&index, head_len - 1))
										head_len = 1ul << (index + 1);
								}

								/* Find and select the matching size in combo box, but only if larger than current */
								{
									HWND h_combo = GetDlgItem(hwnd, IDC_COMBO_HDR_SIZE);
									int count = (int)SendMessage(h_combo, CB_GETCOUNT, 0, 0);
									int cur_sel = (int)SendMessage(h_combo, CB_GETCURSEL, 0, 0);
									u32 cur_val = (cur_sel >= 0) ? (u32)SendMessage(h_combo, CB_GETITEMDATA, cur_sel, 0) : 0;

									/* Only change selection if current size is too small */
									if (cur_val < head_len) {
										for (i = 0; i < count; i++) {
											u32 val = (u32)SendMessage(h_combo, CB_GETITEMDATA, i, 0);
											if (val >= head_len) {
												SendMessage(h_combo, CB_SETCURSEL, i, 0);
												break;
											}
										}
									}
								}
							}
						}
						break;

						case IDE_PASS :
						case IDE_CONFIRM :
						{
							BOOL correct;

							int kb_layout = -1;
							int idx_status;
							int entropy;
							int header_kdf;

							dc_pass *pass;
							HWND hProgress;

							if (IsWindowEnabled(GetDlgItem(hwnd, IDC_COMBO_KBLAYOUT)))
							{
								kb_layout = _get_combo_val(GetDlgItem(hwnd, IDC_COMBO_KBLAYOUT), kb_layouts);
							}
							header_kdf = _get_combo_val(GetDlgItem(hwnd, IDC_COMBO_KDF), kdf_names);
							pass = _get_pass(hwnd, IDE_PASS);

							_draw_pass_rating(hwnd, pass, kb_layout, header_kdf, &entropy);
							secure_free(pass);

							hProgress = GetDlgItem(hwnd, IDP_BREAKABLE);
							SendMessage(hProgress, PBM_SETPOS, (WPARAM)entropy, 0);
							update_entropy_tooltip(hwnd, hProgress, entropy);

							if ( IsWindowVisible(GetDlgItem(hwnd, IDE_PASS)) )
							{
								dc_pass *pass   = _get_pass(hwnd, IDE_PASS);
								dc_pass *verify = NULL;
								BOOL confirm_visible = IsWindowVisible(GetDlgItem(hwnd, IDE_CONFIRM));

								/* Only get confirm password if the field is visible */
								if (confirm_visible)
									verify = _get_pass(hwnd, IDE_CONFIRM);

								keyfiles_state *kf_state = _get_check( hwnd, IDC_USE_KEYFILES ) ? _get_wizard_keyfiles(hwnd) : NULL;

								correct = _input_verify( pass, verify, kf_state, kb_layout, &idx_status );

								secure_free( pass );
								if (verify)
									secure_free( verify );

								/* Only update status if visible */
								if (IsWindowVisible(GetDlgItem(hwnd, IDC_PASS_STATUS)))
									SetWindowText( GetDlgItem(hwnd, IDC_PASS_STATUS), _get_text_name(idx_status, pass_status) );

								EnableWindow( GetDlgItem(GetParent(GetParent(hwnd)), IDOK), correct );
							}
							return 1L;	
						}
						break;
					} // switch id
				} // case en_change
				break;
			}
		}
		break;

		case WM_CTLCOLOREDIT :
		case WM_CTLCOLORSTATIC :
		case WM_CTLCOLORLISTBOX :
		{
			COLORREF bgcolor, fn = 0;

			dc = (HDC)wparam;

			/* Multiline edit controls need OPAQUE mode to properly redraw */
			if ((message == WM_CTLCOLOREDIT) && (GetWindowLong((HWND)lparam, GWL_STYLE) & ES_MULTILINE))
				SetBkMode(dc, OPAQUE);
			else
				SetBkMode(dc, TRANSPARENT);

			if ( WM_CTLCOLORSTATIC == message )
			{
				k = 0;
				while ( pass_gr_ctls[k].id != -1 )
				{
					if ( pass_gr_ctls[k].hwnd == (HWND)lparam )
					{
						fn = pass_gr_ctls[k].color;
					}
					// pass_pe_ctls has fewer entries, check terminator
					if ( pass_pe_ctls[k].id != -1 && pass_pe_ctls[k].hwnd == (HWND)lparam )
					{
						fn = pass_pe_ctls[k].color;
					}
					k++;
				}
				SetTextColor(dc, fn);
				bgcolor = GetSysColor(COLOR_BTNFACE);

			} else bgcolor = _cl(COLOR_BTNFACE, LGHT_CLR);

			SetDCBrushColor(dc, bgcolor);
			return (INT_PTR)GetStockObject(DC_BRUSH);
		
		}
		break;
		/*
		case WM_KEYDOWN: 
		{
			if (wparam == VK_TAB) 
			{
				HWND edit = GetDlgItem(hwnd, IDE_PASS);
				if (edit && (GetFocus( ) == edit)) 
				{
					SetFocus(GetDlgItem(hwnd, IDE_NEW_PASS));
				}
			}
		}
		break;
		*/
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

