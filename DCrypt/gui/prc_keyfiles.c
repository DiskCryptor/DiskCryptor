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
#include "prc_keyfiles.h"
#include "prc_pass.h"
#include "tpm_sup.h"

_colinfo _keyfiles_headers[ ] =
{
	{ L"File / Folder Path", 375, LVCFMT_LEFT, FALSE },
	{ STR_NULL }
};


void _keyfiles_init(keyfiles_state *state)
{
	_init_list_head(&state->head);
	state->mix_mode = KEYFILE_MIX_HASHED;
}


_list_key_files *_first_keyfile(keyfiles_state *state)
{
	_list_key_files *keyfile;

	if ( state == NULL || _is_list_empty(&state->head) )
	{
		keyfile = NULL;
	}
	else
	{
		keyfile = contain_record(state->head.flink, _list_key_files, next);
	}
	return keyfile;
}


_list_key_files *_next_keyfile(
		_list_key_files	*keyfile,
		keyfiles_state  *state
	)
{
	_list_key_files *next;

	if ( state == NULL || keyfile->next.flink == &state->head )
	{
		next = NULL;
	}
	else
	{
		next = contain_record( keyfile->next.flink, _list_key_files, next );
	}
	return next;
}


void _keyfiles_wipe(keyfiles_state *state)
{
	_list_key_files *node, *next_node;

	if ( state == NULL )
		return;

	for ( next_node = _first_keyfile(state); next_node != NULL; )
	{
		node = next_node;
		next_node = _next_keyfile( node, state );

		_remove_entry_list( &node->next );

		// Free virtual keyfile data if present
		if ( node->is_virtual && node->virtual_data != NULL )
		{
			burn( node->virtual_data, node->virtual_size );
			secure_free( node->virtual_data );
		}
		secure_free( node );
	}

	state->mix_mode = KEYFILE_MIX_HASHED;
}


int _keyfiles_count(keyfiles_state *state)
{
	_list_key_files *node;
	int              count = 0;

	if ( state == NULL )
	{
		return count;
	}
	for ( node = _first_keyfile(state); node != NULL; node = _next_keyfile(node, state) )
	{
		count++;
	}
	return count;
}


int _keyfiles_has_virtual(keyfiles_state *state)
{
	_list_key_files *node;

	if ( state == NULL )
	{
		return FALSE;
	}
	for ( node = _first_keyfile(state); node != NULL; node = _next_keyfile(node, state) )
	{
		if ( node->is_virtual )
		{
			return TRUE;
		}
	}
	return FALSE;
}


static
void _ui_keys_list_refresh(HWND hwnd)
{
	HWND h_list = GetDlgItem( hwnd, IDC_LIST_KEYFILES );

	if ( !IsWindowEnabled(h_list) )
	{
		ListView_DeleteAllItems( h_list );

		EnableWindow( h_list, TRUE );
		EnableWindow( GetDlgItem(hwnd, IDB_REMOVE_ITEMS), TRUE );

	}
	else
	{
		if ( !ListView_GetItemCount( h_list ) )
		{
			EnableWindow( h_list, FALSE );
			_list_insert_item( h_list, 0, 0, IDS_EMPTY_LIST, 0 );

			EnableWindow( GetDlgItem(hwnd, IDB_REMOVE_ITEM), FALSE );
			EnableWindow( GetDlgItem(hwnd, IDB_REMOVE_ITEMS), FALSE );
		}
	}
}


// Structure to hold virtual keyfile data during dialog session
typedef struct _virtual_keyfile_node {
	struct _virtual_keyfile_node *next;
	wchar_t  display_name[MAX_PATH + 16];
	u32      size;
	u8       data[0];
} _virtual_keyfile_node;

// Parameters for keyfiles dialog (input)
typedef struct _keyfiles_dlg_params {
	keyfiles_state *state;
	BOOL            allow_virtual;
} _keyfiles_dlg_params;

// Per-dialog-instance data for keyfiles dialog
typedef struct _keyfiles_dlg_data {
	keyfiles_state        *state;
	BOOL                   allow_virtual;
	_virtual_keyfile_node *vk_list_head;
} _keyfiles_dlg_data;

// Add a virtual keyfile node to the session list
static _virtual_keyfile_node *_vk_list_add(_virtual_keyfile_node **head, const wchar_t *display_name, u8 *data, u32 size)
{
	_virtual_keyfile_node *node = secure_alloc( sizeof(_virtual_keyfile_node) + size );
	if ( node == NULL ) return NULL;

	wcsncpy( node->display_name, display_name, countof(node->display_name) - 1 );
	node->display_name[countof(node->display_name) - 1] = 0;
	node->size = size;
	memcpy(node->data, data, size);
	node->next = *head;
	*head = node;
	return node;
}

// Find virtual keyfile data by display name
static _virtual_keyfile_node *_vk_list_find(_virtual_keyfile_node *head, const wchar_t *display_name)
{
	_virtual_keyfile_node *node = head;
	while ( node != NULL )
	{
		if ( wcscmp(node->display_name, display_name) == 0 )
			return node;
		node = node->next;
	}
	return NULL;
}

// Remove a node from the virtual keyfile list (does not free the node)
static void _vk_list_remove(_virtual_keyfile_node **head, _virtual_keyfile_node *target)
{
	_virtual_keyfile_node **pp = head;
	while ( *pp != NULL )
	{
		if ( *pp == target )
		{
			*pp = target->next;
			return;
		}
		pp = &(*pp)->next;
	}
}

// Free all virtual keyfile data in the session list
static void _vk_list_free_all(_virtual_keyfile_node **head)
{
	_virtual_keyfile_node *node = *head;
	while ( node != NULL )
	{
		_virtual_keyfile_node *next = node->next;
		burn( node->data, node->size );
		secure_free( node );
		node = next;
	}
	*head = NULL;
}


// Forward declarations for TPM backup loading
static void _add_tpm_file_backup(HWND hwnd, _keyfiles_dlg_data *dlg_data);
static void _add_tpm_backup(HWND hwnd, _keyfiles_dlg_data *dlg_data, int srk);
static void _add_virtual_keyfile(HWND hwnd, _keyfiles_dlg_data *dlg_data);

// Show popup menu for Add Hardware button and handle selection
// Returns TRUE if an action was taken, FALSE if menu was cancelled
static BOOL _show_add_hardware_menu(HWND hwnd, _keyfiles_dlg_data *dlg_data)
{
	if (!(__config.load_flags & DST_PRO_ENABLED)) {
		void _menu_no_pro(HWND hwnd, int no_shim);
		_menu_no_pro( hwnd, 0 );
		return FALSE;
	}

	HMENU hMenu = LoadMenu(NULL, MAKEINTRESOURCE(IDR_MENU_ADD_HARDWARE));
	if (hMenu == NULL) return FALSE;

	HMENU hPopup = GetSubMenu(hMenu, 0);
	if (hPopup == NULL) {
		DestroyMenu(hMenu);
		return FALSE;
	}

	/* Disable TPM-dependent options if no TPM is present */
	if ( dc_tpm_get_version() <= 0 )
	{
		EnableMenuItem(hPopup, IDM_TPM_NV_BACKUP, MF_BYCOMMAND | MF_GRAYED);
		EnableMenuItem(hPopup, IDM_TPM_SRK_BACKUP, MF_BYCOMMAND | MF_GRAYED);
	}

	// Position menu below the button
	HWND hButton = GetDlgItem(hwnd, IDB_ADD_HARDWARE);
	RECT rc;
	GetWindowRect(hButton, &rc);

	UINT cmd = TrackPopupMenu(hPopup,
		TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RETURNCMD | TPM_LEFTBUTTON,
		rc.left, rc.bottom, 0, hwnd, NULL);

	DestroyMenu(hMenu);

	if (cmd == 0) return FALSE;

	switch (cmd)
	{
		case IDM_TPM_NV_BACKUP:
			_add_tpm_backup(hwnd, dlg_data, 0);
			break;
		case IDM_TPM_SRK_BACKUP:
			_add_tpm_backup(hwnd, dlg_data, 1);
			break;
		case IDM_TPM_FILE_BACKUP:
			_add_tpm_file_backup(hwnd, dlg_data);
			break;
	}
	return TRUE;
}

// Add a virtual keyfile (original Add Virtual functionality)
static void _add_virtual_keyfile(HWND hwnd, _keyfiles_dlg_data *dlg_data)
{
	HWND h_list = GetDlgItem(hwnd, IDC_LIST_KEYFILES);
	dlgpass dlg_info = { L"Create Virtual Keyfile", NULL, PF_NEW_PASS_ONLY };

	if (_dlg_change_pass(hwnd, &dlg_info) == ST_OK && dlg_info.new_pass && dlg_info.new_pass->size > 0 && dlg_data)
	{
		wchar_t display_name[MAX_PATH + 16];

		_snwprintf(display_name, countof(display_name), L"Virtual Keyfile %08X", calc_crc32((char*)dlg_info.new_pass->pass, dlg_info.new_pass->size));

		if (_vk_list_add(&dlg_data->vk_list_head, display_name, (u8*)dlg_info.new_pass->pass, dlg_info.new_pass->size) == NULL)
		{
			__error_s(hwnd, L"Cannot allocate memory", ST_NOMEM);
		}
		else
		{
			_ui_keys_list_refresh(hwnd);
			_list_insert_item(h_list, ListView_GetItemCount(h_list), 0, display_name, 0);
		}
	}

	if (dlg_info.new_pass) secure_free(dlg_info.new_pass);
}


static
void _add_item(
		HWND     h_list,
		wchar_t *s_file
	)
{
	if (_is_duplicated_item(h_list, s_file))
	{
		__msg_i(
			GetParent(h_list),
			L"%s \"%s\" already exists in keyfiles list",
			s_file[wcslen(s_file) - 1] == L'\\' ? L"Folder" : L"File", s_file
			);
	} else {
		_list_insert_item(h_list, ListView_GetItemCount(h_list), 0, s_file, 0);
	}
}


static
INT_PTR CALLBACK
_keyfiles_dlg_proc(
		HWND	hwnd,
		UINT	message,
		WPARAM	wparam,
		LPARAM	lparam
	)
{
	_keyfiles_dlg_data *dlg_data = (_keyfiles_dlg_data *)GetWindowLongPtr(hwnd, GWLP_USERDATA);

	switch ( message )
	{
		case WM_CLOSE :
		{
			if ( dlg_data )
			{
				_vk_list_free_all(&dlg_data->vk_list_head);
			}
			EndDialog( hwnd, 0 );
			return 0L;
		}
		break;

		case WM_NOTIFY :
		{
			if( wparam == IDC_LIST_KEYFILES )
			{
				if ( ((NMHDR *)lparam)->code == LVN_ITEMCHANGED &&
					 (((NMLISTVIEW *)lparam)->uNewState & LVIS_FOCUSED ) )
				{
					HWND h_list = GetDlgItem( hwnd, IDC_LIST_KEYFILES );

					EnableWindow(GetDlgItem( hwnd, IDB_REMOVE_ITEM), ListView_GetSelectedCount( h_list ) );

					return 1L;
				}
				if ( ((NM_LISTVIEW *)lparam)->hdr.code == NM_CLICK )
				{
					HWND h_list = GetDlgItem( hwnd, IDC_LIST_KEYFILES );

					EnableWindow( GetDlgItem( hwnd, IDB_REMOVE_ITEM), ListView_GetSelectedCount( h_list ) );
				}
			}
		}
		case WM_COMMAND :
		{
			HWND h_list = GetDlgItem( hwnd, IDC_LIST_KEYFILES );

			int code = HIWORD(wparam);
			int id   = LOWORD(wparam);

			switch ( id )
			{
				case IDB_GENERATE_KEYFILE :
				{
					wchar_t s_file[MAX_PATH] = { L"KeyFile.bin" };

					byte keyfile[64];
					int rlt;

					if ( _save_file_dialog(
							hwnd, s_file, countof(s_file), L"Save 64 bytes random keyfile as.."
						) )
					{
						rlt = dc_device_control(DC_CTL_GET_RAND, NULL, 0, keyfile, sizeof(keyfile)) == NO_ERROR ? ST_OK : ST_ERROR;

						if ( rlt == ST_OK )
						{
							rlt = save_file(s_file, keyfile, sizeof(keyfile));
							burn(keyfile, sizeof(keyfile));
						}
						if ( rlt == ST_OK )
						{
							if ( __msg_q(hwnd,
								L"Keyfile \"%s\" successfully created\n\n"
								L"Add this file to the keyfiles list?",
								s_file
								)	)
							{
								_ui_keys_list_refresh(hwnd);
								_add_item( h_list, s_file );
							}
						} else {
							__error_s( hwnd, L"Error creating Keyfile", rlt );
						}
					}
				}
				break;
				case IDB_REMOVE_ITEM :
				{
					int sel_idx = ListView_GetSelectionMark(h_list);
					if ( sel_idx >= 0 && dlg_data )
					{
						wchar_t item_text[MAX_PATH + 16];
						_virtual_keyfile_node *vk_node;

						_get_item_text( h_list, sel_idx, 0, item_text, countof(item_text) );

						vk_node = _vk_list_find( dlg_data->vk_list_head, item_text );
						if ( vk_node != NULL )
						{
							_vk_list_remove( &dlg_data->vk_list_head, vk_node );
							burn( vk_node->data, vk_node->size );
							secure_free( vk_node );
						}

						ListView_DeleteItem( h_list, sel_idx );
					}

					_ui_keys_list_refresh( hwnd );
				}
				break;
				case IDB_REMOVE_ITEMS :
				{
					if ( dlg_data )
					{
						_vk_list_free_all(&dlg_data->vk_list_head);
					}
					ListView_DeleteAllItems( h_list );

					_ui_keys_list_refresh( hwnd );
				}
				break;
				case IDB_ADD_FOLDER :
				{
					wchar_t path[MAX_PATH];
					if ( _folder_choice(hwnd, path, L"Choice folder..") )
					{
						_ui_keys_list_refresh( hwnd );

						_set_trailing_slash( path );
						_add_item( h_list, path );
					}
				}
				break;
				case IDB_ADD_FILE :
				{
					wchar_t s_path[MAX_PATH] = { 0 };
					if ( _open_file_dialog(hwnd, s_path, countof(s_path), L"Select File..") )
					{
						_ui_keys_list_refresh( hwnd );
						_add_item( h_list, s_path );
					}
				}
				break;
				case IDB_ADD_VIRTUAL :
				{
					if (dlg_data && dlg_data->allow_virtual) {
						_add_virtual_keyfile(hwnd, dlg_data);
					}
				}
				break;
				case IDB_ADD_HARDWARE :
				{
					if (dlg_data) {
						_show_add_hardware_menu(hwnd, dlg_data);
					}
				}
				break;
			}
			if ( id == IDCANCEL )
			{
				if ( dlg_data )
				{
					_vk_list_free_all(&dlg_data->vk_list_head);
				}
				EndDialog(hwnd, 0);
			}
			if ( id == IDOK && dlg_data )
			{
				int k = 0;
				keyfiles_state *state = dlg_data->state;

				_keyfiles_wipe(state);

				// Save keyfile mixing mode selection
				state->mix_mode = _get_combo_val( GetDlgItem(hwnd, IDC_COMBO_KEYFILE_MIX), keyfile_mix_modes );

				for ( ; k < ListView_GetItemCount( h_list ); k++ )
				{
					wchar_t item[MAX_PATH + 16];
					_virtual_keyfile_node *vk_node;

					_get_item_text( h_list, k, 0, item, countof(item) );

					if ( wcscmp(item, IDS_EMPTY_LIST) != 0 )
					{
						_list_key_files *new_node;

						if ( (new_node = secure_alloc(sizeof(_list_key_files))) == NULL )
						{
							__error_s( hwnd, L"Can't allocate memory", ST_NOMEM );
							_keyfiles_wipe(state);
							break;
						}

						vk_node = _vk_list_find( dlg_data->vk_list_head, item );
						if ( vk_node != NULL )
						{
							new_node->is_virtual = TRUE;
							new_node->virtual_size = vk_node->size;
							new_node->virtual_data = secure_alloc( vk_node->size );
							if ( new_node->virtual_data == NULL )
							{
								secure_free( new_node );
								__error_s( hwnd, L"Can't allocate memory", ST_NOMEM );
								_keyfiles_wipe(state);
								break;
							}
							memcpy( new_node->virtual_data, vk_node->data, vk_node->size );
						}
						else
						{
							new_node->is_virtual = FALSE;
							new_node->virtual_data = NULL;
							new_node->virtual_size = 0;
						}

						wcsncpy(new_node->path, item, countof(new_node->path));
						_insert_tail_list(&state->head, &new_node->next);
					}
				}

				_vk_list_free_all(&dlg_data->vk_list_head);

				EndDialog(hwnd, 0);

			}
		}
		break;
		case WM_INITDIALOG :
		{
			HWND h_list = GetDlgItem(hwnd, IDC_LIST_KEYFILES);
			HWND h_mix_combo = GetDlgItem(hwnd, IDC_COMBO_KEYFILE_MIX);
			_keyfiles_dlg_params *params = (_keyfiles_dlg_params *)lparam;
			_list_key_files *key_file;

			dlg_data = secure_alloc(sizeof(_keyfiles_dlg_data));
			if ( dlg_data == NULL )
			{
				__error_s( hwnd, L"Can't allocate memory", ST_NOMEM );
				EndDialog(hwnd, 0);
				return 0L;
			}

			dlg_data->state = params->state;
			dlg_data->allow_virtual = params->allow_virtual;
			dlg_data->vk_list_head = NULL;

			SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)dlg_data);

			if ( !dlg_data->allow_virtual )
			{
				EnableWindow( GetDlgItem(hwnd, IDB_ADD_VIRTUAL), FALSE );
			}

			_init_list_headers( h_list, _keyfiles_headers );

			for ( key_file = _first_keyfile(dlg_data->state); key_file != NULL; key_file = _next_keyfile(key_file, dlg_data->state) )
			{
				EnableWindow( GetDlgItem(hwnd, IDB_REMOVE_ITEMS), TRUE );

				if ( key_file->is_virtual && key_file->virtual_data != NULL )
				{
					_vk_list_add(&dlg_data->vk_list_head, key_file->path, key_file->virtual_data, key_file->virtual_size);
				}
				_list_insert_item( h_list, ListView_GetItemCount(h_list), 0, key_file->path, 0 );
			}

			_ui_keys_list_refresh( hwnd );

			_init_combo( h_mix_combo, keyfile_mix_modes, dlg_data->state->mix_mode, FALSE, -1 );

			ListView_SetBkColor( h_list, GetSysColor(COLOR_BTNFACE) );
			ListView_SetTextBkColor( h_list, GetSysColor(COLOR_BTNFACE) );
			ListView_SetExtendedListViewStyle( h_list, LVS_EX_FLATSB | LVS_EX_FULLROWSELECT );

			SetForegroundWindow(hwnd);
			return 1L;
		}
		break;
		case WM_CTLCOLOREDIT :
		{
			return _ctl_color(wparam, _cl(COLOR_BTNFACE, LGHT_CLR));
		}
		break;
		case WM_DESTROY :
		{
			if ( dlg_data )
			{
				_vk_list_free_all(&dlg_data->vk_list_head);
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


// Load secret from password-encrypted backup file on EFI partition
static void _add_tpm_file_backup(HWND hwnd, _keyfiles_dlg_data *dlg_data)
{
	HWND h_list = GetDlgItem(hwnd, IDC_LIST_KEYFILES);
	dlgpass dlg_info = { L"Enter Backup File Password", NULL, PF_NO_KEY_SLOTS };
	dc_pass pass;
	wchar_t display_name[MAX_PATH + 16];
	int resl;

	// Check if backup file exists
	if (!dc_tpm_backup_file_exists()) {
		__msg_e(hwnd, L"No TPM backup file found on EFI partition.\n\n"
			L"Expected file: \\EFI\\DCS\\tpm_backup.dat");
		return;
	}

	// Prompt for backup password (existing password, no confirmation needed)
	if (_dlg_get_pass(hwnd, &dlg_info) != ST_OK || !dlg_info.pass || dlg_info.pass->size == 0) {
		if (dlg_info.pass) {
			burn(dlg_info.pass, sizeof(dc_pass));
			secure_free(dlg_info.pass);
		}
		return;
	}

	// Try to restore the backup
	resl = dc_tpm_unseal_backup_file(dlg_info.pass, &pass);

	// Clean up password
	burn(dlg_info.pass, sizeof(dc_pass));
	secure_free(dlg_info.pass);

	if (resl != ST_OK) {
		if (resl == ST_PASS_ERR) {
			__msg_e(hwnd, L"Incorrect backup password or corrupted backup file.");
		} else if (resl == ST_INCOMPATIBLE) {
			__msg_e(hwnd, L"Backup file version is not supported.");
		} else {
			__error_s(hwnd, L"Failed to restore TPM backup", resl);
		}
		burn(&pass, sizeof(pass));
		return;
	}

	// Generate display name with CRC of the secret
	_snwprintf(display_name, countof(display_name),
		L"TPM Backup Secret %08X",
		calc_crc32((char*)pass.pass, pass.size));

	// Add as virtual keyfile
	if (_vk_list_add(&dlg_data->vk_list_head, display_name,
		(u8*)pass.pass, pass.size) == NULL)
	{
		__error_s(hwnd, L"Cannot allocate memory", ST_NOMEM);
	}
	else
	{
		_ui_keys_list_refresh(hwnd);
		_list_insert_item(h_list, ListView_GetItemCount(h_list), 0, display_name, 0);
		__msg_i(hwnd, L"TPM backup secret loaded successfully.");
	}

	// Securely clean up backup data
	burn(&pass, sizeof(pass));
}


// Load secret from PIN-protected TPM backup entry
static void _add_tpm_backup(HWND hwnd, _keyfiles_dlg_data *dlg_data, int srk)
{
	HWND h_list = GetDlgItem(hwnd, IDC_LIST_KEYFILES);
	dlgpass dlg_info = { L"Enter TPM PIN", NULL, PF_RAW_PASSWORD };
	dc_pass pass;
	wchar_t display_name[MAX_PATH + 16];
	int resl;

	// Prompt for PIN (existing password, no confirmation needed)
	if (_dlg_get_pass(hwnd, &dlg_info) != ST_OK || !dlg_info.pass) {
		if (dlg_info.pass) {
			burn(dlg_info.pass, sizeof(dc_pass));
			secure_free(dlg_info.pass);
		}
		return;
	}

	if (srk) {
		// Try to unseal the password from TPM SRK backup entry
		resl = dc_tpm_srk_unseal_file(
			DC_TPM_SRK_FILE_RECOVERY,
			dlg_info.pass->pass,
			&pass);
	}
	else {
		// Try to unseal the password from TPM NV backup index
		resl = dc_tpm_unseal_nv_entry(
			DC_TPM_NV_INDEX_RECOVERY,
			dlg_info.pass->pass,
			&pass);
	}

	// Clean up PIN
	burn(dlg_info.pass, sizeof(dc_pass));
	secure_free(dlg_info.pass);

	if (resl != ST_OK) {
		if (resl == ST_PASS_ERR) {
			__msg_e(hwnd, L"Incorrect PIN or TPM backup entry not found.");
		} else if (resl == ST_NOT_SUPPORTED) {
			__msg_e(hwnd, L"PCR+PIN combined policy is not yet supported.\n\n"
				L"Only PIN-only backups (PcrMask=0) are currently supported.");
		} else if (resl == ST_FORMAT_ERR) {
			__msg_e(hwnd, L"TPM backup entry is corrupted or has invalid format.");
		} else {
			__error_s(hwnd, L"Failed to read TPM backup", resl);
		}
		burn(&pass, sizeof(pass));
		return;
	}

	// Generate display name with CRC of the secret
	_snwprintf(display_name, countof(display_name),
		L"TPM %s Secret %08X",
		srk ? L"SRK" : L"NV",
		calc_crc32((char*)pass.pass, pass.size));

	// Add as virtual keyfile
	if (_vk_list_add(&dlg_data->vk_list_head, display_name,
		(u8*)pass.pass, pass.size) == NULL)
	{
		__error_s(hwnd, L"Cannot allocate memory", ST_NOMEM);
	}
	else
	{
		_ui_keys_list_refresh(hwnd);
		_list_insert_item(h_list, ListView_GetItemCount(h_list), 0, display_name, 0);
		__msg_i(hwnd, L"TPM recovery secret loaded successfully.");
	}

	// Securely clean up password data
	burn(&pass, sizeof(pass));
}


void _dlg_keyfiles(
		HWND hwnd,
		keyfiles_state *state,
		BOOL allow_virtual
	)
{
	_keyfiles_dlg_params params;
	params.state = state;
	params.allow_virtual = allow_virtual;

	DialogBoxParam(
			NULL,
			MAKEINTRESOURCE(IDD_DIALOG_KEYFILES),
			hwnd,
			pv(_keyfiles_dlg_proc),
			(LPARAM)&params
	);
}
