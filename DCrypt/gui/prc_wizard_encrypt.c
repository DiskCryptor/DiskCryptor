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
#include "w10.h"
#include "prc_wizard_encrypt.h"

#include "prc_keyfiles.h"
#include "pass.h"
#include "prc_common.h"
#ifdef _M_ARM64
#include "xts_small.h"
#else
#include "xts_fast.h"
#endif
#include "dlg_drives_list.h"
#include "prc_pass.h"
#include "prc_wait.h"
#include "volume_header.h"
#include "prc_header.h"
#include "efiinst.h"
#include "mbrinst.h"
#include "secure_desktop.h"
#include "dcconst.h"

wchar_t *fs_names[ ] =
{
	L"RAW", L"FAT", L"FAT32", L"NTFS" //, L"exFAT"
};

// Helper to get display name from _init_list array by value
static wchar_t *_get_combo_name(const _init_list *list, int val)
{
	int i;
	for (i = 0; list[i].display && wcslen(list[i].display) > 0; i++)
	{
		if (list[i].val == val)
			return list[i].display;
	}
	return NULL;
}

static HWND     h_wizard;
static HHOOK    h_hook;

// Wizard instance data
typedef struct _encrypt_wizard_data {
	keyfiles_state kf_state;
	dc_pass       *secure_pass;      // Password entered on secure desktop (NULL if not used)
	BOOL           secure_pass_set;  // TRUE if password was set via secure desktop
} _encrypt_wizard_data;

// Update wizard password page UI based on secure password state
static void _update_secure_pass_ui(HWND hwnd_page, BOOL secure_pass_set)
{
	HWND hSecureBtn = GetDlgItem(hwnd_page, IDB_SECURE_PASS_ENTRY);

	// Disable/enable password fields
	EnableWindow(GetDlgItem(hwnd_page, IDE_PASS), !secure_pass_set);
	EnableWindow(GetDlgItem(hwnd_page, IDE_CONFIRM), !secure_pass_set);
	EnableWindow(GetDlgItem(hwnd_page, IDC_CHECK_SHOW), !secure_pass_set);

	// Disable/enable keyfiles controls - keyfiles are handled in the secure password dialog
	EnableWindow(GetDlgItem(hwnd_page, IDC_USE_KEYFILES), !secure_pass_set);
	EnableWindow(GetDlgItem(hwnd_page, IDB_USE_KEYFILES), !secure_pass_set);

	// Set button toggle state (checked = pressed appearance)
	if (hSecureBtn)
	{
		SendMessage(hSecureBtn, BM_SETCHECK, secure_pass_set ? BST_CHECKED : BST_UNCHECKED, 0);
		InvalidateRect(hSecureBtn, NULL, TRUE);
	}

	if (secure_pass_set)
	{
		// Show placeholder asterisks
		SetWindowTextW(GetDlgItem(hwnd_page, IDE_PASS), L"****************");
		SetWindowTextW(GetDlgItem(hwnd_page, IDE_CONFIRM), L"****************");
		// Ensure password mode
		SendMessage(GetDlgItem(hwnd_page, IDE_PASS), EM_SETPASSWORDCHAR, '*', 0);
		SendMessage(GetDlgItem(hwnd_page, IDE_CONFIRM), EM_SETPASSWORDCHAR, '*', 0);
		InvalidateRect(GetDlgItem(hwnd_page, IDE_PASS), NULL, TRUE);
		InvalidateRect(GetDlgItem(hwnd_page, IDE_CONFIRM), NULL, TRUE);
	}
	else
	{
		// Clear fields
		SetWindowTextW(GetDlgItem(hwnd_page, IDE_PASS), L"");
		SetWindowTextW(GetDlgItem(hwnd_page, IDE_CONFIRM), L"");
	}
}

int combo_sel[ ] =
{
	IDC_COMBO_ALGORT, IDC_COMBO_HASH,
	IDC_COMBO_MODE, IDC_COMBO_PASSES
};

int _update_layout(
		_dnode *node,
		int     new_layout,  /* -1 - init */
		int    *old_layout,
		int	   *header_kdf
	)
{
	BOOL boot_dev = _is_boot_device( &node->mnt.info );
	ldr_config conf;

	int kbd_layout = LDR_KB_QWERTY;
	int rlt = ST_OK;

	if ( new_layout != -1 )
	{
		if ( boot_dev )
		{
			if ( (rlt = dc_get_ldr_config( -1, &conf )) != ST_OK )
			{
				return rlt;
			}
			conf.kbd_layout = new_layout;
			conf.header_kdf = header_kdf ? *header_kdf : KDF_SHA512_PKCS5_2;
			if(conf.header_kdf == KDF_SHA512_PKCS5_2 || conf.header_kdf == KDF_ARGON_DEFAULT) conf.header_kdf = KDF_DEFAULT;

			if ( (rlt = dc_set_ldr_config( -1, &conf )) != ST_OK )
			{
				return rlt;
			}
		}
		return rlt;
	} 
	else 
	{
		BOOL result = dc_get_ldr_config( -1, &conf ) == ST_OK;

		if ( old_layout )
		{
			*old_layout = result ? conf.kbd_layout : LDR_KB_QWERTY;
		}

		if ( header_kdf )
		{
			*header_kdf = result ? conf.header_kdf : KDF_SHA512_PKCS5_2;
		}
		return result;
	}
}


// Helper to get password - uses secure_pass if set, otherwise reads from edit control
static dc_pass *_get_wizard_pass(_encrypt_wizard_data *wiz_data, HWND hwnd_pass_page, keyfiles_state *kf_state)
{
	// If secure password was entered via secure desktop, use it
	// Note: keyfiles were already mixed in the secure password dialog, so just copy
	if (wiz_data && wiz_data->secure_pass_set && wiz_data->secure_pass)
	{
		dc_pass *pass = secure_alloc(sizeof(dc_pass));
		if (pass)
		{
			memcpy(pass, wiz_data->secure_pass, sizeof(dc_pass));
		}
		return pass;
	}

	// Otherwise get from edit control
	return __get_pass_keyfiles(
		GetDlgItem(hwnd_pass_page, IDE_PASS),
		_get_check(hwnd_pass_page, IDC_USE_KEYFILES),
		kf_state
	);
}

void _run_wizard_action(
		HWND        hwnd,
		_wz_sheets *sheets,
		_dnode     *node

	)
{
	_encrypt_wizard_data *wiz_data = wnd_get_long(hwnd, GWL_USERDATA);
	keyfiles_state *kf_state = wiz_data ? &wiz_data->kf_state : NULL;

	BOOL set_loader = (BOOL)
		SendMessage(
			GetDlgItem(sheets[WPAGE_ENC_BOOT].hwnd, IDC_COMBO_BOOT_INST), CB_GETCURSEL, 0, 0
			);

	wchar_t *fs_name = 
		fs_names[SendMessage(
			GetDlgItem(sheets[WPAGE_ENC_FRMT].hwnd, IDC_COMBO_FS_LIST), CB_GETCURSEL, 0, 0
			)];

	int  kb_layout = _get_combo_val( GetDlgItem(sheets[WPAGE_ENC_PASS].hwnd, IDC_COMBO_KBLAYOUT), kb_layouts );
	BOOL q_format  = _get_check( sheets[WPAGE_ENC_FRMT].hwnd, IDC_CHECK_QUICK_FORMAT );

	int is_small = (
		IsWindowEnabled( GetDlgItem( sheets[WPAGE_ENC_CONF].hwnd, IDC_COMBO_ALGORT ) ) ? FALSE : TRUE
	);

	int is_shim = __is_efi_boot ? (dc_efi_is_secureboot() && !dc_efi_dcs_is_signed()) : 0;

	crypt_info  crypt = { 0 };
	dc_pass    *pass = NULL;
	int enc_flags = 0;

	crypt.cipher_id  = _get_combo_val( GetDlgItem(sheets[WPAGE_ENC_CONF].hwnd, IDC_COMBO_ALGORT), cipher_names );
	crypt.wp_mode    = _get_combo_val( GetDlgItem(sheets[WPAGE_ENC_CONF].hwnd, IDC_COMBO_PASSES), wipe_modes );

	/* Read header options */
	{
		HWND h_conf = sheets[WPAGE_ENC_CONF].hwnd;
		BOOL is_v2 = IsDlgButtonChecked(h_conf, IDC_RADIO_HDR_V2) == BST_CHECKED;

		if (is_v2) {
			u32 min_head_len;

			crypt.version = DC_HDR_VERSION_2;
			crypt.slot_count = (u8)GetDlgItemInt(h_conf, IDC_EDIT_HDR_SLOTS, NULL, FALSE);
			if (crypt.slot_count < 0) crypt.slot_count = 0;
			if (crypt.slot_count > KEY_SLOT_MAX) crypt.slot_count = KEY_SLOT_MAX;

			/* Calculate minimum header size for slot count */
			min_head_len = DC_BASE_SIZE + crypt.slot_count * (PKCS_DERIVE_MAX + sizeof(dc_slot_info));
			if (min_head_len < DC_AREA_SIZE)
				min_head_len = DC_AREA_SIZE;

			/* Read header size from combo box */
			{
				HWND h_combo = GetDlgItem(h_conf, IDC_COMBO_HDR_SIZE);
				int sel = (int)SendMessage(h_combo, CB_GETCURSEL, 0, 0);
				crypt.head_len = (u32)SendMessage(h_combo, CB_GETITEMDATA, sel, 0);
			}

			if (crypt.head_len < min_head_len) {
				wchar_t msg[256];
				_snwprintf(msg, countof(msg), L"Header size must be at least %u bytes for %d key slots", min_head_len, crypt.slot_count);
				__msg_e(hwnd, msg);
				return;
			}

			/* Build flags for encryption functions */
			if ( _get_check( sheets[WPAGE_ENC_CONF].hwnd, IDC_CHECK_BAK_HEADER ) )
			{
				enc_flags |= VF_BACKUP_HEADER;
			}

		} else {
			crypt.version = DC_HDR_VERSION;
			crypt.head_len = DC_AREA_SIZE;
			crypt.slot_count = 0;
		}
	}

	/* Skip unused sectors optimization - overrides wipe mode */
	if ( _get_check( sheets[WPAGE_ENC_CONF].hwnd, IDC_CHECK_SKIP_UNUSED ) )
	{
		crypt.wp_mode = WP_SKIP_UNUSED;
	}

	node->dlg.rlt = ST_ERROR;

	int header_kdf = _get_combo_val(GetDlgItem(sheets[WPAGE_ENC_PASS].hwnd, IDC_COMBO_KDF), kdf_names);

	switch ( node->dlg.act_type )
	{
	///////////////////////////////////////////////////////////////
	case ACT_REENCRYPT :
	///////////////////////////////////////////////////////////////
	/////// REENCRYPT VOLUME //////////////////////////////////////
	{
		pass = _get_wizard_pass(wiz_data, sheets[WPAGE_ENC_PASS].hwnd, kf_state);

		if ( pass )
		{
			/* Use current volume KDF for password verification, or auto-detect */
			pass->kdf = (node->mnt.info.status.flags & F_ENABLED)
				? node->mnt.info.status.crypt.head_kdf : KDF_DEFAULT;

			node->mnt.info.status.crypt.wp_mode = crypt.wp_mode;
			node->dlg.rlt = _wait_dc_start_re_encrypt( __dlg, node->mnt.info.device, pass, &crypt, L"Starting re-encryption..." );

			secure_free( pass );
		} else {
			node->dlg.rlt = ST_CANCEL;
		}
	}
	break;
	///////////////////////////////////////////////////////////////
	case ACT_ENCRYPT_CD :
	///////////////////////////////////////////////////////////////
	/////// ENCRYPT CD ////////////////////////////////////////////
	{
		_init_speed_stat( &node->dlg.iso.speed );
		pass = _get_wizard_pass(wiz_data, sheets[WPAGE_ENC_PASS].hwnd, kf_state);

		if ( pass )
		{
			pass->kdf = header_kdf;

			DWORD resume;
			{
				wchar_t s_src_path[MAX_PATH] = { 0 };
				wchar_t s_dst_path[MAX_PATH] = { 0 };

				GetWindowText( GetDlgItem(sheets[WPAGE_ENC_ISO].hwnd, IDE_ISO_SRC_PATH), s_src_path, countof(s_src_path) );
				GetWindowText( GetDlgItem(sheets[WPAGE_ENC_ISO].hwnd, IDE_ISO_DST_PATH), s_dst_path, countof(s_dst_path) );

				wcscpy( node->dlg.iso.s_iso_src, s_src_path );
				wcscpy( node->dlg.iso.s_iso_dst, s_dst_path );

				node->dlg.iso.cipher_id = crypt.cipher_id;
				node->dlg.iso.pass      = pass;
			}

			node->dlg.iso.h_thread = 
				CreateThread(
					NULL, 0, _thread_enc_iso_proc, pv(node), CREATE_SUSPENDED, NULL
					);

			SetThreadPriority( node->dlg.iso.h_thread, THREAD_PRIORITY_LOWEST );
			resume = ResumeThread( node->dlg.iso.h_thread );

			if ( !node->dlg.iso.h_thread || resume == (DWORD) -1 )
			{
				int rlt = GetLastError();
				__error_s( hwnd, L"Error create thread", -rlt );
				secure_free(pass);
			}
		}		
	}
	break;
	///////////////////////////////////////////////////////////////
	default :
	///////////////////////////////////////////////////////////////
	{
		node->mnt.info.status.crypt.wp_mode = crypt.wp_mode;
		node->dlg.rlt = ST_OK;

		if ( sheets[WPAGE_ENC_BOOT].show )
		{
			if ( set_loader )
			{
				if ( __is_efi_boot ) // add boot menu entry and replace windows loader
				{
					/* Read checkbox values: 0 = unchecked (no), 1 = checked (yes) */
					int add_esp = _get_check(sheets[WPAGE_ENC_BOOT].hwnd, IDC_CHECK_CREATE_ESP) ? 1 : 0;
					int add_bme = _get_check(sheets[WPAGE_ENC_BOOT].hwnd, IDC_CHECK_CREATE_BME) ? 1 : 0;

					/* If encrypting the Windows EFI Partition, force dedicated DCS ESP */
					wchar_t s_boot_dev[MAX_PATH];
					if ((dc_get_boot_device(s_boot_dev) == ST_OK) && (wcscmp(node->mnt.info.device, s_boot_dev) == 0)) {
						add_esp = 1;  /* Must use dedicated ESP when encrypting Windows ESP */
					}

					node->dlg.rlt = _set_boot_loader_efi( hwnd, -1, is_shim, add_esp, add_bme);
				}
				else
					node->dlg.rlt = _set_boot_loader_mbr( hwnd, -1, is_small );
			}

			// prepare reflect driver
			if ( is_w10_reflect_supported() )
			{
				update_w10_reflect_driver();
			}
		}
		if ( ( node->dlg.rlt == ST_OK ) && 
			 ( IsWindowEnabled( GetDlgItem( sheets[WPAGE_ENC_PASS].hwnd, IDC_LAYOUTS_LIST ) ) ) 
		   )
		{
			node->dlg.rlt = _update_layout( node, kb_layout, NULL, &header_kdf);
		}
		if ( node->dlg.rlt == ST_OK )
		{
			switch ( node->dlg.act_type )
			{
		///////////////////////////////////////////////////////////////
			case ACT_ENCRYPT :
		///////////////////////////////////////////////////////////////
		/////// ENCRYPT VOLUME ////////////////////////////////////////
			{
				pass = _get_wizard_pass(wiz_data, sheets[WPAGE_ENC_PASS].hwnd, kf_state);

				if ( pass )
				{
					DC_FLAGS enc_flags_check;
					BOOL needs_reboot = FALSE;

					pass->kdf = header_kdf;

					/* Check if reboot is required: boot device + EFI + bootloader not yet active */
					if (_is_boot_device(&node->mnt.info) && __is_efi_boot)
					{
						if (dc_device_control(DC_CTL_GET_FLAGS, NULL, 0, &enc_flags_check, sizeof(enc_flags_check)) != NO_ERROR ||
						    !(enc_flags_check.load_flags & DST_BOOTLOADER))
						{
							needs_reboot = TRUE;
						}
					}

					if ( needs_reboot )
					{
						node->dlg.rlt = dc_prep_encrypt(node->mnt.info.device, pass, &crypt, enc_flags);

						if (node->dlg.rlt == ST_OK)
						{
							if (__msg_q(HWND_DESKTOP,
								L"The bootloader has been configured, after the reboot it should show you a password prompt.\n"
								L"You can abort by pressing escape instead of entering a password.\n"
								L"Do you want to restart your computer now?"))
							{
								_reboot();
							}
							node->dlg.rlt = ST_CANCEL; // not cancel after reboot it will be resumed
						}
					}
					else
					{
						node->dlg.rlt = _wait_dc_start_encrypt(__dlg, node->mnt.info.device, pass, &crypt, enc_flags, L"Starting encryption...");
					}
					secure_free(pass);
				}
			}
			break;
		///////////////////////////////////////////////////////////////
			case ACT_FORMAT :
		///////////////////////////////////////////////////////////////
		/////// FORMAT VOLUME /////////////////////////////////////////
			{
				pass = _get_wizard_pass(wiz_data, sheets[WPAGE_ENC_PASS].hwnd, kf_state);

				if ( pass )
				{
					pass->kdf = header_kdf;

					node->dlg.rlt = _wait_dc_start_format(__dlg, node->mnt.info.device, pass, &crypt, enc_flags, L"Starting format...");
					secure_free(pass);
				}
			}
			break;
			}
		}
	}
	}
	node->dlg.q_format = q_format;
	node->dlg.fs_name  = fs_name;

	if ( !node->dlg.iso.h_thread )
	{
		EndDialog( hwnd, 0 );
	}
}


int _get_info_install_boot_page(
		vol_inf    *vol,
		_wz_sheets *sheets,
		int        *dsk_num	
	)
{				
	ldr_config conf;
	drive_inf  drv;

	int boot_disk_1;
	int boot_disk_2;

	int rlt = ST_ERROR;

	sheets[WPAGE_ENC_BOOT].show = FALSE;
	sheets[WPAGE_ENC_STOP].show = TRUE;  /* Summary page always shown */
	if ( _is_boot_device(vol) )
	{
		sheets[WPAGE_ENC_BOOT].show = TRUE;
	}

	rlt = dc_get_drive_info( vol->w32_device, &drv );
	if ( ( rlt && dsk_num ) == ST_OK )
	{
		*dsk_num = drv.disks[0].number;
	}

	if (__is_efi_boot) {
		boot_disk_1 = boot_disk_2 = dc_efi_get_os_disk();
		rlt = (boot_disk_1 >= 0) ? ST_OK : ST_NF_BOOT_DEV;
	} else {
		rlt = dc_get_boot_disk( &boot_disk_1, &boot_disk_2 );
	}
	if ( rlt == ST_OK )
	{
		// check if bootloader is present and if so skip the bootloader installation page
		if ( dc_get_ldr_config( boot_disk_1, &conf ) == ST_OK )
			sheets[WPAGE_ENC_BOOT].show = FALSE;
	}
	return rlt;

}


int _init_wizard_encrypt_pages(
		HWND        parent,
		_wz_sheets *sheets,
		_dnode     *node
	)
{
	wchar_t *static_head[ ] =
	{
		L"# Choose ISO file",
		L"# Format Options",
		L"# Encryption Settings",
		L"# Boot Settings",
		L"# Volume Password",
		L"# Encryption Progress",
		L"# Summary"
	};

	HWND     hwnd;
	DC_FLAGS flags;
	int      k, count = 0;

	BOOL    boot_device = (
		_is_boot_device( &node->mnt.info )
	);
	BOOL    force_small = (
		boot_device && ( dc_device_control(DC_CTL_GET_FLAGS, NULL, 0, &flags, sizeof(flags)) == NO_ERROR ) && ( flags.load_flags & DST_SMALL_MEM )
	);

	while ( sheets[count].id != -1 )
	{
		HWND hwnd;

		sheets[count].hwnd = 
			CreateDialog(
				__hinst, MAKEINTRESOURCE(sheets[count].id), GetDlgItem(parent, IDC_TAB), _tab_proc
				);

		hwnd = sheets[count].hwnd;

		EnumChildWindows( hwnd, __sub_enum, (LPARAM)NULL );

		SetWindowText( GetDlgItem( hwnd, IDC_HEAD ), static_head[count] );
		SendMessage( GetDlgItem( hwnd, IDC_HEAD ), (UINT)WM_SETFONT, (WPARAM)__font_bold, 0 );

		sheets[count].first_tab_hwnd = 
			(
				( sheets[count].first_tab_id != -1 ) ? GetDlgItem( hwnd, sheets[count].first_tab_id ) : HWND_NULL
			);

		count++;
	}
	///////////////////////////////////////////////////////////////
	hwnd = sheets[WPAGE_ENC_FRMT].hwnd;
	///////////////////////////////////////////////////////////////
	/////// FORMAT OPTIONS PAGE ///////////////////////////////////
	{
		HWND h_fs = GetDlgItem(hwnd, IDC_COMBO_FS_LIST);

		_sub_class( GetDlgItem(hwnd, IDC_CHECK_QUICK_FORMAT), SUB_STATIC_PROC, HWND_NULL );
		_set_check( hwnd, IDC_CHECK_QUICK_FORMAT, FALSE );

		for ( k = 0; k < countof(fs_names); k++ )
		{
			SendMessage( h_fs, (UINT)CB_ADDSTRING, 0, (LPARAM)fs_names[k] );
		}
		SendMessage( h_fs, CB_SETCURSEL, 2, 0 );			
	}
	///////////////////////////////////////////////////////////////
	hwnd = sheets[WPAGE_ENC_CONF].hwnd;
	///////////////////////////////////////////////////////////////
	/////// ENCRYPTION SETTINGS PAGE //////////////////////////////
	{
		HWND h_combo_wipe = GetDlgItem(hwnd, IDC_COMBO_PASSES);
		int is_ssd = dc_is_device_ssd(node->mnt.info.w32_device);
		BOOLEAN use_v2 = TRUE;

		_init_combo( h_combo_wipe, wipe_modes, WP_NONE, FALSE, -1 );

		EnableWindow( h_combo_wipe, node->dlg.act_type != ACT_ENCRYPT_CD && !is_ssd);
		EnableWindow( GetDlgItem(hwnd, IDC_STATIC_PASSES_LIST), node->dlg.act_type != ACT_ENCRYPT_CD && !is_ssd);

		/* Skip unused sectors checkbox - auto-enable for SSDs */
		_sub_class( GetDlgItem(hwnd, IDC_CHECK_SKIP_UNUSED), SUB_STATIC_PROC, HWND_NULL );
		_set_check( hwnd, IDC_CHECK_SKIP_UNUSED, is_ssd );
		EnableWindow( GetDlgItem(hwnd, IDC_CHECK_SKIP_UNUSED), node->dlg.act_type != ACT_ENCRYPT_CD );

		/* Header options section */
		SetWindowText( GetDlgItem(hwnd, IDC_HEAD_HDR_OPTIONS), L"# Header Options" );
		SendMessage( GetDlgItem(hwnd, IDC_HEAD_HDR_OPTIONS), WM_SETFONT, (WPARAM)__font_bold, 0 );

		/* Default header */
		CheckRadioButton( hwnd, IDC_RADIO_HDR_V1, IDC_RADIO_HDR_V2, use_v2 ? IDC_RADIO_HDR_V2 : IDC_RADIO_HDR_V1 );

		/* Disable V2 header for MBR boot system volumes - V2/Argon2 not supported by MBR bootloader */
		if (boot_device && !__is_efi_boot)
		{
			EnableWindow( GetDlgItem(hwnd, IDC_RADIO_HDR_V2), FALSE );
		}

		/* Set default slot count and header size */
		SendMessage( GetDlgItem(hwnd, IDC_EDIT_HDR_SLOTS), EM_LIMITTEXT, 3, 0 );
		SetDlgItemInt( hwnd, IDC_EDIT_HDR_SLOTS, use_v2 ? 4 : 0, FALSE );
		EnableWindow( GetDlgItem(hwnd, IDC_EDIT_HDR_SLOTS), use_v2 );

		if (!(__config.load_flags & DST_PRO_ENABLED)) {
			use_v2 = FALSE;
		}

		/* Initialize header size combo box with predefined sizes (2 KiB to 32 MiB, doubling) */
		{
			HWND h_combo = GetDlgItem(hwnd, IDC_COMBO_HDR_SIZE);
			u32 size;
			for (size = DC_AREA_SIZE; size <= DC_AREA_MAX_SIZE_UI; size *= 2) {
				wchar_t buf[32];
				int idx;
				_format_hdr_size(size, buf, countof(buf), FALSE);
				idx = (int)SendMessage(h_combo, CB_ADDSTRING, 0, (LPARAM)buf);
				SendMessage(h_combo, CB_SETITEMDATA, idx, (LPARAM)size);
			}
			SendMessage(h_combo, CB_SETCURSEL, use_v2 ? 5 : 0, 0);
		}
		EnableWindow( GetDlgItem(hwnd, IDC_COMBO_HDR_SIZE), use_v2 );

		/* Backup header checkbox - only available for V2 headers */
		_sub_class( GetDlgItem(hwnd, IDC_CHECK_BAK_HEADER), SUB_STATIC_PROC, HWND_NULL );
		_set_check( hwnd, IDC_CHECK_BAK_HEADER, use_v2 );
		EnableWindow( GetDlgItem(hwnd, IDC_CHECK_BAK_HEADER), use_v2 );

		/* Hide header options for reencrypt and encrypt CD operations */
		if ( node->dlg.act_type == ACT_REENCRYPT || node->dlg.act_type == ACT_ENCRYPT_CD )
		{
			ShowWindow( GetDlgItem(hwnd, IDC_HEAD_HDR_OPTIONS), SW_HIDE );
			ShowWindow( GetDlgItem(hwnd, IDC_RADIO_HDR_V1), SW_HIDE );
			ShowWindow( GetDlgItem(hwnd, IDC_RADIO_HDR_V2), SW_HIDE );
			ShowWindow( GetDlgItem(hwnd, IDC_STATIC_HDR_SLOTS), SW_HIDE );
			ShowWindow( GetDlgItem(hwnd, IDC_EDIT_HDR_SLOTS), SW_HIDE );
			ShowWindow( GetDlgItem(hwnd, IDC_STATIC_HDR_SIZE), SW_HIDE );
			ShowWindow( GetDlgItem(hwnd, IDC_COMBO_HDR_SIZE), SW_HIDE );
			ShowWindow( GetDlgItem(hwnd, IDC_STATIC_HDR_LABEL), SW_HIDE );
			ShowWindow( GetDlgItem(hwnd, IDC_CHECK_BAK_HEADER), SW_HIDE );
		}

		_init_combo(
			GetDlgItem(hwnd, IDC_COMBO_ALGORT), cipher_names, CF_AES, FALSE, -1
			);

		if( __is_efi_boot )
		{
			if (boot_device && dc_efi_is_secureboot() && !dc_efi_dcs_is_signed())
			{
				SendMessage(GetDlgItem(hwnd, IDC_WIZ_CONF_WARNING), (UINT)WM_SETFONT, (WPARAM)__font_bold, 0);

				if (dc_efi_shim_available()) {
					SetWindowText(GetDlgItem(hwnd, IDC_WIZ_CONF_WARNING),
						L"Your EFI firmware is configured for secure boot. "
						L"You will need to use a shim loader, otherwise THE SYSTEM WILL NOT BOOT!!!");
				} 
				else {
					SetWindowText(GetDlgItem(hwnd, IDC_WIZ_CONF_WARNING),
						L"Your EFI firmware is configured for secure boot. "
						L"The DCS EFI bootloader is not signed with a certificate trusted by your firmware. "
						L"The required shim package is available for project supporters.\nVisit our website to get a Supporter Certificate.");

					EnableWindow(GetDlgItem(parent, IDOK), FALSE);
				}
			}
		}
		else
		{
			if ( force_small )
			{
				EnableWindow( GetDlgItem(hwnd, IDC_COMBO_ALGORT), FALSE );

				SendMessage( GetDlgItem(hwnd, IDC_WIZ_CONF_WARNING), (UINT)WM_SETFONT, (WPARAM)__font_bold, 0 );
				SetWindowText( 
					GetDlgItem(hwnd, IDC_WIZ_CONF_WARNING),
					L"Your BIOS does not provide enough base memory,\n"
					L"you can only use AES to encrypt the boot partition!"
				);
			}
		}

		for ( k = 0; k < countof(combo_sel); k++ )
		{
			SendMessage( GetDlgItem(hwnd, combo_sel[k]), CB_SETCURSEL, 0, 0 );
		}	
	}
	///////////////////////////////////////////////////////////////
	hwnd = sheets[WPAGE_ENC_BOOT].hwnd;
	///////////////////////////////////////////////////////////////
	/////// BOOT SETTINGS PAGE ////////////////////////////////////
	{
		int dsk_num = -1;
		int rlt = _get_info_install_boot_page( &node->mnt.info, sheets, &dsk_num );

		__lists[HENC_WIZARD_BOOT_DEVS] = GetDlgItem(hwnd, IDC_BOOT_DEVS);

		_list_devices( __lists[HENC_WIZARD_BOOT_DEVS], TRUE, dsk_num );
		SendMessage( GetDlgItem(hwnd, IDC_COMBO_BOOT_INST), (UINT)CB_ADDSTRING, 0, (LPARAM)L"Use external bootloader" );

		/* Initialize EFI boot checkboxes */
		_sub_class( GetDlgItem(hwnd, IDC_CHECK_CREATE_ESP), SUB_STATIC_PROC, HWND_NULL );
		_sub_class( GetDlgItem(hwnd, IDC_CHECK_CREATE_BME), SUB_STATIC_PROC, HWND_NULL );
		_set_check( hwnd, IDC_CHECK_CREATE_ESP, TRUE );
		_set_check( hwnd, IDC_CHECK_CREATE_BME, TRUE );

		/* Show checkboxes in EFI boot mode */
		if ( __is_efi_boot )
		{
			ShowWindow( GetDlgItem(hwnd, IDC_CHECK_CREATE_ESP), SW_SHOW );
			ShowWindow( GetDlgItem(hwnd, IDC_CHECK_CREATE_BME), SW_SHOW );
		}

		if ( rlt != ST_OK )
		{
			SetWindowText( GetDlgItem(hwnd, IDC_WARNING), L"Bootable HDD not found!" );
			SendMessage( GetDlgItem(hwnd, IDC_COMBO_BOOT_INST), CB_SETCURSEL, 0, 0 );

			SendMessage( GetDlgItem(hwnd, IDC_WARNING), (UINT)WM_SETFONT, (WPARAM)__font_bold, 0 );
			EnableWindow( GetDlgItem(hwnd, IDB_BOOT_PREF), TRUE );

			/* Disable checkboxes when using external bootloader */
			EnableWindow( GetDlgItem(hwnd, IDC_CHECK_CREATE_ESP), FALSE );
			EnableWindow( GetDlgItem(hwnd, IDC_CHECK_CREATE_BME), FALSE );
		} else {
			SendMessage( GetDlgItem(hwnd, IDC_COMBO_BOOT_INST), (UINT)CB_ADDSTRING, 0, (LPARAM)L"Install to HDD" );
			SendMessage( GetDlgItem(hwnd, IDC_COMBO_BOOT_INST), CB_SETCURSEL, 1, 0 );

			/* Enable checkboxes when "Install to HDD" is selected */
			wchar_t s_boot_dev[MAX_PATH];
			EnableWindow( GetDlgItem(hwnd, IDC_CHECK_CREATE_ESP), __is_efi_boot && !((dc_get_boot_device(s_boot_dev) == ST_OK) && (wcscmp(node->mnt.info.device, s_boot_dev) == 0)));
			EnableWindow( GetDlgItem(hwnd, IDC_CHECK_CREATE_BME), __is_efi_boot );
		}
	}
	///////////////////////////////////////////////////////////////
	hwnd = sheets[WPAGE_ENC_PASS].hwnd;
	///////////////////////////////////////////////////////////////
	/////// VOLUME PASSWORD PAGE //////////////////////////////////
	{
		int kbd_layout = 0;
		_update_layout( node, -1, &kbd_layout, NULL);

		_init_combo( GetDlgItem(hwnd, IDC_COMBO_KBLAYOUT), kb_layouts, kbd_layout, FALSE, -1 );
		SetWindowText( GetDlgItem( hwnd, IDC_USE_KEYFILES), boot_device ? IDS_USE_KEYFILE : IDS_USE_KEYFILES );
		EnableWindow( GetDlgItem( hwnd, IDC_USE_KEYFILES), boot_device ? FALSE : TRUE );

		_sub_class( GetDlgItem(hwnd, IDC_CHECK_SHOW), SUB_STATIC_PROC, HWND_NULL );
		_set_check( hwnd, IDC_CHECK_SHOW, FALSE );

		_sub_class( GetDlgItem(hwnd, IDC_USE_KEYFILES), SUB_STATIC_PROC, HWND_NULL );
		_set_check( hwnd, IDC_USE_KEYFILES, FALSE );

		_init_combo(GetDlgItem(hwnd, IDC_COMBO_KDF), kdf_names, KDF_ARGON_DEFAULT, FALSE, -1);
		if (boot_device && !__is_efi_boot)
			EnableWindow( GetDlgItem(hwnd, IDC_COMBO_KDF), FALSE );

		SendMessage(
			GetDlgItem( hwnd, IDP_BREAKABLE ),
			PBM_SETBARCOLOR, 0, _cl( COLOR_BTNSHADOW, DARK_CLR-20 )
		);	
		SendMessage(
			GetDlgItem(hwnd, IDP_BREAKABLE),
			PBM_SETRANGE, 0, MAKELPARAM(0, 193)
		);
		SetWindowText( GetDlgItem(hwnd, IDC_HEAD2), L"# Password Rating" );
		SendMessage( GetDlgItem(hwnd, IDC_HEAD2), (UINT)WM_SETFONT, (WPARAM)__font_bold, 0 );

		SendMessage( GetDlgItem(hwnd, IDE_PASS), EM_LIMITTEXT, MAX_PASSWORD, 0 );
		SendMessage( GetDlgItem(hwnd, IDE_CONFIRM), EM_LIMITTEXT, MAX_PASSWORD, 0 );

		/* Hide secure entry button if secure desktop is disabled */
		if (!(__config.conf_flags & CONF_SECURE_DESKTOP))
		{
			ShowWindow(GetDlgItem(hwnd, IDB_SECURE_PASS_ENTRY), SW_HIDE);
		}
	}
	///////////////////////////////////////////////////////////////
	hwnd = sheets[WPAGE_ENC_PROGRESS].hwnd;
	///////////////////////////////////////////////////////////////
	/////// ENCRYPTION PROGRESS PAGE //////////////////////////////
	{
		_colinfo _progress_iso_crypt_headers[ ] = 
		{
			{ STR_HEAD_NO_ICONS, 100, LVCFMT_LEFT, FALSE },
			{ STR_HEAD_NO_ICONS, 120, LVCFMT_LEFT, FALSE },
			{ STR_NULL }
		};

		HWND h_list = GetDlgItem( hwnd, IDC_ISO_PROGRESS );
		int  rlt    = ST_OK;
		int  j      = 0;

		ListView_SetBkColor( h_list, GetSysColor(COLOR_BTNFACE) );
		_init_list_headers( h_list, _progress_iso_crypt_headers );

		while ( wcslen(_act_table_items[j]) > 0 )
		{
			_list_insert_item( h_list, j, 0, _act_table_items[j], 0 );
			if ( j != 2 ) ListView_SetItemText( h_list, j, 1, STR_EMPTY );

			j++;
		}
		SendMessage(
			GetDlgItem( hwnd, IDC_PROGRESS_ISO ),
			PBM_SETBARCOLOR, 0, _cl(COLOR_BTNSHADOW, DARK_CLR-20)
		);

		SendMessage(
			GetDlgItem( hwnd, IDC_PROGRESS_ISO ),
			PBM_SETRANGE, 0, MAKELPARAM(0, PRG_STEP)
		);
	}

	return count;

}


BOOL _wizard_step(
		_dnode     *node,
		_wz_sheets *sheets,
		int        *index,
		int         id_back,
		int         id_next,
		int         id
	)
{
	HWND h_parent = GetParent( GetParent(sheets[WPAGE_ENC_CONF].hwnd) );
	BOOL enb_back = FALSE;

	int next = 0;
	int back = 0;
	int k    = 0;

	ShowWindow( sheets[*index].hwnd, SW_HIDE );

	if ( id == id_next )
	{
		while ( sheets[++*index].show == 0 );
	} else {
		while ( sheets[--*index].show == 0 );
	}

	next = *index;
	while ( sheets[++next].show == 0 );

	back = *index - 1;
	while ( ( back >= 0 ) && ( sheets[back].show == 0 ) )
	{
		back--;
	}

	EnableWindow( GetDlgItem(h_parent, id_back), !(back < 0 && node->dlg.act_type != -1) );

	if ( ( sheets[*index].id == -1 ) || ( sheets[next].id == -1 ) )
	{
		SetWindowText( GetDlgItem(h_parent, id_next), L"OK" );
		EnableWindow( GetDlgItem(h_parent, id_next), FALSE );
	} else {
		SetWindowText( GetDlgItem(h_parent, id_next), L"&Next" );
		EnableWindow( GetDlgItem(h_parent, id_next), TRUE );
	}

	ShowWindow( sheets[*index].hwnd, SW_SHOW );
	if ( (*index) < 0 )
	{
		while ( sheets[k].id != -1 )
		{
			sheets[k++].show = TRUE;
		}
		_get_info_install_boot_page( &node->mnt.info, sheets, NULL );
	}

	return (
		sheets[*index].id == -1
	);
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


INT_PTR 
CALLBACK
_wizard_encrypt_dlg_proc(
		HWND	hwnd,
		UINT	message,
		WPARAM	wparam,
		LPARAM	lparam
	)
{
	WORD code = LOWORD(wparam);
	WORD id   = LOWORD(wparam);

	static _wz_sheets 
	sheets[ ] = 
	{
		{ DLG_WIZ_ISO,      0, TRUE,	IDE_ISO_SRC_PATH,    0 },	// WPAGE_ENC_ISO
		{ DLG_WIZ_FORMAT,   0, TRUE,	IDC_COMBO_FS_LIST,   0 },	// WPAGE_ENC_FRMT
		{ DLG_WIZ_CONF,     0, TRUE,	IDC_COMBO_ALGORT,    0 },	// WPAGE_ENC_CONF
		{ DLG_WIZ_LOADER,   0, TRUE,	IDC_COMBO_BOOT_INST, 0 },	// WPAGE_ENC_BOOT
		{ DLG_WIZ_PASS,     0, TRUE,	IDE_PASS,            0 },	// WPAGE_ENC_PASS
		{ DLG_WIZ_PROGRESS, 0, TRUE,	-1,                  0 },	// WPAGE_ENC_PROGRESS
		{ DLG_WIZ_STOP,     0, TRUE,	-1,                  0 },	// WPAGE_ENC_STOP
		{ -1, 0, TRUE }
	};

	static int enc_sheets[ ][WZR_MAX_STEPS + 1] =
	{
		{ 2,  3,  4,  6, -1 }, // ACT_ENCRYPT (summary page 6 always shown)
		{ 2,  4,  6, -1, -1 }, // ACT_DECRYPT (added summary page)
		{ 2,  4,  6, -1, -1 }, // ACT_REENCRYPT (conf, pass, summary)
		{ 1,  2,  4,  6, -1 }, // ACT_FORMAT (added summary page)
		{ 0,  2,  4,  6,  5 }  // ACT_ENCRYPT_CD (summary before progress)
	};

	static vol_inf *vol;
	static _dnode  *node;

	static index = 0;
	static count = 0;

    int    k     = 0;
	int    cr    = 0;
	int    check = 0; 	

	switch ( message )
	{
		case WM_INITDIALOG :
		{
			_encrypt_wizard_data *wiz_data;

			{
				node = (_dnode *)lparam;
				if ( node == NULL )
				{
					EndDialog(hwnd, 0);
					return 0L;
				}
				vol = &((_dnode *)lparam)->mnt.info;
			}
			h_wizard = hwnd;
			h_hook   = SetWindowsHookEx( WH_GETMESSAGE, (HOOKPROC)_get_msg_proc, NULL, GetCurrentThreadId( ) );

			// Allocate and initialize wizard instance data
			wiz_data = malloc(sizeof(_encrypt_wizard_data));
			if (wiz_data == NULL)
			{
				EndDialog(hwnd, 0);
				return 0L;
			}
			_keyfiles_init(&wiz_data->kf_state);
			wiz_data->secure_pass = NULL;
			wiz_data->secure_pass_set = FALSE;
			wnd_set_long(hwnd, GWL_USERDATA, wiz_data);

			SetWindowText(hwnd, vol->device);

			count = _init_wizard_encrypt_pages( hwnd, pv(&sheets), node );
			sheets[count].hwnd = (HWND)lparam;

			node->dlg.h_page = sheets[WPAGE_ENC_PROGRESS].hwnd;

			k = 0;
			while ( sheets[k].id != -1 )
			{
				if ( ! _array_include(enc_sheets[node->dlg.act_type], k) )
				{
					sheets[k].show = FALSE;
				}
				k++;
			}

			index = enc_sheets[node->dlg.act_type][0];
			ShowWindow( sheets[index].hwnd, SW_SHOW );

			if ( node->dlg.act_type == ACT_ENCRYPT_CD )
			{
				EnableWindow( GetDlgItem(hwnd, IDOK), FALSE );
			}

			SetForegroundWindow(hwnd);
			return 1L;
		}
		break;

		case WM_COMMAND:
		{
			switch ( id )
			{
			case ID_SHIFT_TAB :
			case ID_TAB :
			{
				_focus_tab(
					IDC_BACK, hwnd, sheets[index].hwnd, sheets[index].first_tab_hwnd, id == ID_TAB
					);
			}
			break;

			case IDOK :
			case IDC_BACK :
			{
				BOOL set_loader = (BOOL) (
						( sheets[WPAGE_ENC_BOOT].show && SendMessage(GetDlgItem(sheets[WPAGE_ENC_BOOT].hwnd, IDC_COMBO_BOOT_INST), CB_GETCURSEL, 0, 0) ) ||
						( _is_boot_device(vol) && _update_layout(node, -1, NULL, NULL) )
					);

				if ( node->dlg.act_type == ACT_REENCRYPT )
				{
					k = 0;
					while ( combo_sel[k] != -1 )
					{
						SendMessage( GetDlgItem(hwnd, combo_sel[k++]), CB_RESETCONTENT, 0, 0 );
					}
					_init_combo(
						GetDlgItem(hwnd, IDC_COMBO_ALGORT), cipher_names, node->mnt.info.status.crypt.cipher_id, FALSE, -1
						);
					_init_combo(
						GetDlgItem(hwnd, IDC_COMBO_PASSES), wipe_modes, node->mnt.info.status.crypt.wp_mode, FALSE, -1
						);
				}

				EnableWindow( GetDlgItem(sheets[WPAGE_ENC_PASS].hwnd, IDC_LAYOUTS_LIST), set_loader );
				EnableWindow( GetDlgItem(sheets[WPAGE_ENC_PASS].hwnd, IDC_COMBO_KBLAYOUT), set_loader );

				if ( _wizard_step(node, pv(&sheets), &index, IDC_BACK, IDOK, id) )
				{
					_run_wizard_action( hwnd, pv(&sheets), node );
					/* If we're still here (action failed validation), step back to summary page */
					_wizard_step(node, pv(&sheets), &index, IDC_BACK, IDOK, IDC_BACK);
				} else
				{
					if ( sheets[index].id == DLG_WIZ_PROGRESS && node->dlg.act_type == ACT_ENCRYPT_CD )
					{
						_run_wizard_action(hwnd, pv(&sheets), node);
					}
				}

				/* Gray out wipe mode controls when quick format is selected */
				if ( sheets[index].id == DLG_WIZ_CONF && node->dlg.act_type == ACT_FORMAT )
				{
					BOOL q_format = _get_check( sheets[WPAGE_ENC_FRMT].hwnd, IDC_CHECK_QUICK_FORMAT );
					HWND h_conf = sheets[WPAGE_ENC_CONF].hwnd;

					EnableWindow( GetDlgItem(h_conf, IDC_COMBO_PASSES), !q_format );
					EnableWindow( GetDlgItem(h_conf, IDC_STATIC_PASSES_LIST), !q_format );
					EnableWindow( GetDlgItem(h_conf, IDC_CHECK_SKIP_UNUSED), !q_format );
				}
				/* Enable OK button on summary page for all action types */
				if ( node->dlg.act_type == ACT_REENCRYPT || sheets[index].id == DLG_WIZ_STOP )
				{
					EnableWindow(GetDlgItem(hwnd, IDOK), TRUE);
				}

				/* Configure password page for re-encrypt mode (verify existing password) */
				if ( sheets[index].id == DLG_WIZ_PASS && node->dlg.act_type == ACT_REENCRYPT )
				{
					HWND h_pass = sheets[WPAGE_ENC_PASS].hwnd;

					/* Change header text to indicate password verification */
					SetWindowText(GetDlgItem(h_pass, IDC_HEAD), L"# Current Password");

					/* Hide confirm field and label */
					ShowWindow(GetDlgItem(h_pass, IDE_CONFIRM), SW_HIDE);
					ShowWindow(GetDlgItem(h_pass, IDC_NEW_CONFIRM), SW_HIDE);

					/* Hide KDF selection (already set on volume) */
					ShowWindow(GetDlgItem(h_pass, IDC_COMBO_KDF), SW_HIDE);
					ShowWindow(GetDlgItem(h_pass, IDC_KDF_LABEL), SW_HIDE);

					/* Hide keyboard layout (not changing boot settings) */
					ShowWindow(GetDlgItem(h_pass, IDC_COMBO_KBLAYOUT), SW_HIDE);
					ShowWindow(GetDlgItem(h_pass, IDC_LAYOUTS_LIST), SW_HIDE);

					/* Hide password status field */
					ShowWindow(GetDlgItem(h_pass, IDC_PASS_STATUS), SW_HIDE);
					ShowWindow(GetDlgItem(h_pass, IDC_NEW_CONFIRM2), SW_HIDE);

					/* Hide password rating section */
					ShowWindow(GetDlgItem(h_pass, IDC_HEAD2), SW_HIDE);
					ShowWindow(GetDlgItem(h_pass, IDP_BREAKABLE), SW_HIDE);
					ShowWindow(GetDlgItem(h_pass, IDC_PE_UNCRK), SW_HIDE);
					ShowWindow(GetDlgItem(h_pass, IDC_PE_HIGH), SW_HIDE);
					ShowWindow(GetDlgItem(h_pass, IDC_PE_MEDIUM), SW_HIDE);
					ShowWindow(GetDlgItem(h_pass, IDC_PE_LOW), SW_HIDE);
					ShowWindow(GetDlgItem(h_pass, IDC_PE_NONE), SW_HIDE);
					ShowWindow(GetDlgItem(h_pass, IDC_GR_ALL), SW_HIDE);
					ShowWindow(GetDlgItem(h_pass, IDC_GR_CAPS), SW_HIDE);
					ShowWindow(GetDlgItem(h_pass, IDC_GR_SMALL), SW_HIDE);
					ShowWindow(GetDlgItem(h_pass, IDC_GR_DIGITS), SW_HIDE);
					ShowWindow(GetDlgItem(h_pass, IDC_GR_SPACE), SW_HIDE);
					ShowWindow(GetDlgItem(h_pass, IDC_GR_SPEC), SW_HIDE);
				}

				/* Populate summary page when navigating to it */
				if ( sheets[index].id == DLG_WIZ_STOP )
				{
					HWND h_stop = sheets[WPAGE_ENC_STOP].hwnd;
					HWND h_conf = sheets[WPAGE_ENC_CONF].hwnd;
					HWND h_pass = sheets[WPAGE_ENC_PASS].hwnd;
					wchar_t summary_buf[256];

					/* Cipher algorithm */
					{
						int cipher_id = _get_combo_val(GetDlgItem(h_conf, IDC_COMBO_ALGORT), cipher_names);
						wchar_t *cipher_name = _get_combo_name(cipher_names, cipher_id);
						SetDlgItemTextW(h_stop, IDC_SUMMARY_CIPHER, cipher_name ? cipher_name : L"Unknown");
					}

					/* KDF algorithm */
					{
						if (node->dlg.act_type == ACT_REENCRYPT) {
							/* Re-encrypt doesn't change KDF */
							SetDlgItemTextW(h_stop, IDC_SUMMARY_KDF, L"Unchanged");
						} else {
							int kdf_id = _get_combo_val(GetDlgItem(h_pass, IDC_COMBO_KDF), kdf_names);
							wchar_t *kdf_name = _get_combo_name(kdf_names, kdf_id);
							SetDlgItemTextW(h_stop, IDC_SUMMARY_KDF, kdf_name ? kdf_name : L"Unknown");
						}
					}

					/* Wipe mode */
					{
						int wp_mode = _get_combo_val(GetDlgItem(h_conf, IDC_COMBO_PASSES), wipe_modes);
						wchar_t *wipe_name = _get_combo_name(wipe_modes, wp_mode);
						BOOL skip_unused = _get_check(h_conf, IDC_CHECK_SKIP_UNUSED);

						if (skip_unused) {
							SetDlgItemTextW(h_stop, IDC_SUMMARY_WIPE, L"Skip unused sectors");
						} else {
							SetDlgItemTextW(h_stop, IDC_SUMMARY_WIPE, wipe_name ? wipe_name : L"None");
						}
					}

					/* Header format */
					{
						if (node->dlg.act_type == ACT_REENCRYPT) {
							/* Re-encrypt doesn't change header format */
							SetDlgItemTextW(h_stop, IDC_SUMMARY_HEADER, L"Unchanged");
						} else {
							BOOL is_v2 = IsDlgButtonChecked(h_conf, IDC_RADIO_HDR_V2) == BST_CHECKED;
							if (is_v2) {
								int slots = GetDlgItemInt(h_conf, IDC_EDIT_HDR_SLOTS, NULL, FALSE);
								HWND h_combo = GetDlgItem(h_conf, IDC_COMBO_HDR_SIZE);
								int sel = (int)SendMessage(h_combo, CB_GETCURSEL, 0, 0);
								u32 hdr_size = (u32)SendMessage(h_combo, CB_GETITEMDATA, sel, 0);
								BOOL backup = _get_check(h_conf, IDC_CHECK_BAK_HEADER);
								wchar_t size_buf[32];

								_format_hdr_size(hdr_size, size_buf, countof(size_buf), FALSE);
								_snwprintf(summary_buf, countof(summary_buf), L"V2 (%s, %d slots%s)",
									size_buf, slots, backup ? L", backup" : L"");
							} else {
								_snwprintf(summary_buf, countof(summary_buf), L"V1 (2 KiB, legacy)");
							}
							SetDlgItemTextW(h_stop, IDC_SUMMARY_HEADER, summary_buf);
						}
					}

					/* Notice text - show reboot warning when boot device + EFI + bootloader not active */
					{
						BOOL needs_reboot = FALSE;
						DC_FLAGS chk_flags;

						if (_is_boot_device(vol) && __is_efi_boot)
						{
							if (dc_device_control(DC_CTL_GET_FLAGS, NULL, 0, &chk_flags, sizeof(chk_flags)) != NO_ERROR ||
							    !(chk_flags.load_flags & DST_BOOTLOADER))
							{
								needs_reboot = TRUE;
							}
						}

						if (needs_reboot)
						{
							SetDlgItemTextW(h_stop, IDC_SUMMARY_NOTICE,
								L"Note: After clicking OK, the bootloader will be configured. "
								L"Your computer will need to restart to begin encryption. "
								L"You will see a password prompt at boot - enter your password to continue.");
						}
						else
						{
							SetDlgItemTextW(h_stop, IDC_SUMMARY_NOTICE, L"");
						}
					}
				}
				SetFocus(GetDlgItem(sheets[index].hwnd, IDE_PASS));

				SendMessage(
					sheets[index].hwnd, WM_COMMAND, MAKELONG(IDE_PASS, EN_CHANGE), (LPARAM)GetDlgItem(sheets[index].hwnd, IDE_PASS)
					);
			}
			break;

			case IDCANCEL:
			{
				BOOL b_close = TRUE;
				if ( node->dlg.iso.h_thread != NULL )
				{
					SuspendThread( node->dlg.iso.h_thread );
					if ( __msg_w( hwnd, L"Do you really want to interrupt the encryption\nof an ISO file?" ) == 0 )
					{
						b_close = FALSE;
					}
					ResumeThread( node->dlg.iso.h_thread );
				}
				if ( b_close )
				{
					node->dlg.rlt = ST_CANCEL;
					SendMessage( hwnd, WM_CLOSE_DIALOG, 0, 0 );
				}
				return 0L;
			}
			break;

			case IDB_SECURE_PASS_ENTRY:
			{
				_encrypt_wizard_data *wiz_data = wnd_get_long(hwnd, GWL_USERDATA);
				if (wiz_data && (__config.conf_flags & CONF_SECURE_DESKTOP))
				{
					// Toggle behavior: if already set, clear and re-enable local UI
					if (wiz_data->secure_pass_set)
					{
						// Clear secure password
						if (wiz_data->secure_pass)
						{
							secure_free(wiz_data->secure_pass);
							wiz_data->secure_pass = NULL;
						}
						wiz_data->secure_pass_set = FALSE;

						// Re-enable local UI
						_update_secure_pass_ui(sheets[WPAGE_ENC_PASS].hwnd, FALSE);
					}
					else
					{
						// Show secure password dialog - use different dialog for re-encrypt
						if (node->dlg.act_type == ACT_REENCRYPT)
						{
							// Re-encrypt: verify existing password
							dlgpass dlg_info = { L"Enter Current Password", node, PF_NO_KEY_SLOTS };

							if (_dlg_get_pass(hwnd, &dlg_info) == ST_OK && dlg_info.pass && dlg_info.pass->size > 0)
							{
								// Store the password
								if (wiz_data->secure_pass)
								{
									secure_free(wiz_data->secure_pass);
								}
								wiz_data->secure_pass = dlg_info.pass;
								wiz_data->secure_pass_set = TRUE;

								// Update UI to show password was entered securely
								_update_secure_pass_ui(sheets[WPAGE_ENC_PASS].hwnd, TRUE);
							}
							else if (dlg_info.pass)
							{
								// User cancelled, free any allocated password
								secure_free(dlg_info.pass);
							}
						}
						else
						{
							// New encryption: create new password
							dlgpass dlg_info = { L"Secure Password Entry", NULL, PF_NEW_PASS_ONLY };

							if (_dlg_change_pass(hwnd, &dlg_info) == ST_OK && dlg_info.new_pass && dlg_info.new_pass->size > 0)
							{
								// Store the password
								if (wiz_data->secure_pass)
								{
									secure_free(wiz_data->secure_pass);
								}
								wiz_data->secure_pass = dlg_info.new_pass;
								wiz_data->secure_pass_set = TRUE;

								// Update UI to show password was entered securely
								_update_secure_pass_ui(sheets[WPAGE_ENC_PASS].hwnd, TRUE);
							}
							else if (dlg_info.new_pass)
							{
								// User cancelled, free any allocated password
								secure_free(dlg_info.new_pass);
							}
						}
					}
				}
				return 0L;
			}
			break;
			}
		}
		break;

		case WM_CLOSE_DIALOG :
		{
			if ( node->dlg.iso.h_thread != NULL )
			{
				CloseHandle( node->dlg.iso.h_thread );
			}
			EndDialog(hwnd, 0);
		}
		break;

		case WM_ACTIVATE :
		{
			/* Ensure proper focus handling when dialog is activated/deactivated */
			if ( LOWORD(wparam) != WA_INACTIVE )
			{
				/* Dialog is being activated - let default handling proceed */
				return 0L;
			}
		}
		break;

		case WM_DESTROY :
		{
			_encrypt_wizard_data *wiz_data = wnd_get_long(hwnd, GWL_USERDATA);

			node = NULL;
			vol  = NULL;

			_wipe_pass_control( sheets[WPAGE_ENC_PASS].hwnd, IDE_PASS );
			_wipe_pass_control( sheets[WPAGE_ENC_PASS].hwnd, IDE_CONFIRM );

			if (wiz_data)
			{
				_keyfiles_wipe(&wiz_data->kf_state);
				if (wiz_data->secure_pass)
				{
					secure_free(wiz_data->secure_pass);
					wiz_data->secure_pass = NULL;
				}
				free(wiz_data);
				wnd_set_long(hwnd, GWL_USERDATA, NULL);
			}

			count = 0;
			while ( sheets[count].id != -1 )
			{
				sheets[count].show = TRUE;
				DestroyWindow(sheets[count++].hwnd);
			}
			__lists[HENC_WIZARD_BOOT_DEVS] = HWND_NULL;

			if (h_hook) UnhookWindowsHookEx(h_hook);
			count = index = 0;

			return 0L;
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
	}
	return 0L;

}

