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
#include "dlg_menu.h"
#include "dcconst.h"

#include "xts_fast.h"
#include "threads.h"
#include "prc_pass.h"
#include "prc_wait.h"
#include "prc_wizard_encrypt.h"
#include "prc_header.h"
#include "gpt_sup.h"
#include "efiinst.h"
#include "secure_desktop.h"
#include "shadow.h"

void _state_menu(
		HMENU	menu,
		UINT	state
	)
{
	int count = GetMenuItemCount(menu);
	char k = 0;

	for ( ; k < count; k++ ) 
	{
		EnableMenuItem( menu, GetMenuItemID(menu, k), state );
	}
}


/*
   TRUE (with a message) if the volume is locked (keys erased at hibernation, see F_LOCKED):
   the driver rejects every operation except unlock (mount) and unmount on it
*/
static
BOOL _locked_volume_msg(
		_dnode *node
	)
{
	if ( node && !node->is_root && DC_IS_LOCKED(node->mnt.info.status.flags) )
	{
		__msg_i(
			__dlg,
			L"Volume [%s] is locked, its keys were erased at hibernation.\n"
			L"Unlock it with its password first, or unmount it.", node->mnt.info.status.mnt_point
			);
		return TRUE;
	}
	return FALSE;
}


void _refresh_menu( )
{
	HMENU   h_menu       = GetMenu( __dlg );
	_dnode *node         = pv(_get_sel_item( __lists[HMAIN_DRIVES] ));
	_dact  *act          = _create_act_thread( node, -1, -1 );
	wchar_t ws_display[MAX_PATH];
	wchar_t ws_new_display[MAX_PATH];

	BOOL    unmount      = FALSE, mount		= FALSE;
	BOOL    decrypt      = FALSE, encrypt	= FALSE;
	BOOL    backup       = FALSE, restore	= FALSE;
	BOOL    format       = FALSE, reencrypt	= FALSE;
	BOOL    del_mntpoint = FALSE, ch_pass	= FALSE;
	BOOL    locked       = FALSE, force_unmount = FALSE;

	if ( node && ListView_GetSelectedCount( __lists[HMAIN_DRIVES] ) &&
		 !_is_root_item( (LPARAM)node ) &&
	 	  _is_active_item( (LPARAM)node )
		 )
	{
		int flags = node->mnt.info.status.flags;

		del_mntpoint =
			wcsstr( node->mnt.info.status.mnt_point, L"\\\\?\\" ) == 0 &&
			IS_UNMOUNTABLE( &node->mnt.info.status );

		if ( DC_IS_LOCKED(flags) )
		{
			/*
			   locked volume (keys erased at hibernation): only unlock (= mount with
			   password) or (force) unmount make sense, the driver rejects the rest
			*/
			locked = TRUE;
			mount  = TRUE;

			if ( IS_UNMOUNTABLE( &node->mnt.info.status ) )
			{
				unmount = force_unmount = TRUE;
			}
		} else if ( flags & F_CDROM )
		{
			if ( flags & F_ENABLED )
			{
				unmount = TRUE;
			} else 
			{
				if ( *node->mnt.fs == '\0' )
				{
					mount = TRUE;
				}
			}
		} else 
		{
			backup = !( flags & F_SYNC );
	
			if ( flags & F_ENABLED )
			{
				if ( flags & F_FORMATTING )
				{
					format = TRUE;
				} else 
				{
					if ( IS_UNMOUNTABLE( &node->mnt.info.status ) ) 
					{
						unmount = TRUE;
					}
					if (! (act && act->status == ACT_RUNNING) )
					{
						if (! (flags & F_REENCRYPT) ) decrypt = TRUE;
						if (! (flags & F_SYNC) ) ch_pass = TRUE;

						if ( flags & F_SYNC )
						{
							encrypt = TRUE;
						} else {
							reencrypt = TRUE;
						}
					}
				}
			} else 
			{
				restore = TRUE;
				if ( IS_UNMOUNTABLE( &node->mnt.info.status ) ) 
				{
					format = TRUE;
				}	
				if ( *node->mnt.fs == '\0' )
				{
					mount = TRUE;
				}	else {
					encrypt = TRUE;
				}
			}
		}
	}
	{
		HWND h_mount = GetDlgItem(__dlg, IDC_BTN_MOUNT_);

		GetWindowText( h_mount, ws_display, countof(ws_display) );
		wcscpy( ws_new_display, locked ? IDS_UNLOCK : ( unmount ? IDS_UNMOUNT : IDS_MOUNT ) );

		if ( ( wcscmp( ws_display, ws_new_display ) != 0 ) || ( IsWindowEnabled(h_mount) != ( unmount || mount ) ) )
		{
			SetWindowText( h_mount, ws_new_display );
			EnableWindow( h_mount, unmount || mount );
#ifdef LOG_FILE
			_log( 
				L"func:menu refresh; mount button from \"%s\" %d to \"%s\" %d", 
				ws_display, IsWindowEnabled( h_mount ), ws_new_display, unmount || mount 
				);
#endif
		}
	}
	EnableWindow( GetDlgItem(__dlg, IDC_BTN_ENCRYPT_), encrypt );
	EnableWindow( GetDlgItem(__dlg, IDC_BTN_DECRYPT_), decrypt );

	{
		/* "Mount Volume" unlocks a locked volume, name it accordingly */
		wchar_t *s_mount = locked ? L"Unlock Volume" : L"Mount Volume";

		if ( GetMenuString( h_menu, ID_VOLUMES_MOUNT, ws_display, countof(ws_display), MF_BYCOMMAND ) &&
			 wcscmp( ws_display, s_mount ) != 0
			 )
		{
			ModifyMenu( h_menu, ID_VOLUMES_MOUNT, MF_BYCOMMAND | MF_STRING, ID_VOLUMES_MOUNT, s_mount );
		}
	}
	EnableMenuItem( h_menu, ID_VOLUMES_MOUNT, _menu_onoff(mount) );
	EnableMenuItem( h_menu, ID_VOLUMES_FORCE_DISMOUNT, _menu_onoff(force_unmount) );
	EnableMenuItem( h_menu, ID_VOLUMES_ENCRYPT, _menu_onoff(encrypt) );

	EnableMenuItem( h_menu, ID_VOLUMES_DISMOUNT, _menu_onoff(unmount) );
	EnableMenuItem( h_menu, ID_VOLUMES_DECRYPT, _menu_onoff(decrypt) );

	EnableMenuItem( h_menu, ID_VOLUMES_BACKUPHEADER, _menu_onoff(backup) );
	EnableMenuItem( h_menu, ID_VOLUMES_RESTOREHEADER, _menu_onoff(restore) );
	EnableMenuItem( h_menu, ID_TOOLS_HEADER_CONFIG, _menu_onoff(backup) );

	EnableMenuItem( h_menu, ID_VOLUMES_CHANGEPASS, _menu_onoff(ch_pass) );
	EnableMenuItem( h_menu, ID_VOLUMES_DELETE_MNTPOINT, _menu_onoff(del_mntpoint) );

	EnableMenuItem( h_menu, ID_VOLUMES_FORMAT, _menu_onoff(format) );
	EnableMenuItem( h_menu, ID_VOLUMES_REENCRYPT, _menu_onoff(reencrypt) );

}


int _finish_formatting(
		_dnode *node
	)
{
	int rlt = ST_OK; /* RAW: nothing to format */

	if ( wcscmp(node->dlg.fs_name, L"RAW") != 0 )
	{
		rlt = dc_format_fs( node->mnt.info.w32_device, node->dlg.fs_name );
	}
	if (rlt != ST_OK) 
	{
		__error_s(
			__dlg, L"Error formatting volume [%s]", rlt, node->mnt.info.status.mnt_point
			);
	}
	return rlt;
}


static 
int _bench_cmp(
		const bench_item *arg1, 
		const bench_item *arg2
	)
{
	if ( arg1->speed > arg2->speed )
	{
		return -1;
	} else {
		return ( arg1->speed < arg2->speed );
	}
}


int _benchmark(
		bench_item *bench	
	)
{
	dc_bench_info info;
	int           i;

	for ( i = 0; i < CF_CIPHERS_NUM; i++ )
	{
		if ( dc_benchmark(i, &info) != ST_OK ) break;
		bench[i].alg   = dc_get_cipher_name(i);
		bench[i].speed = (double)info.datalen / ( (double)info.enctime / (double)info.cpufreq) / 1024 / 1024;
	}
	qsort( bench, CF_CIPHERS_NUM, sizeof(bench[0]), _bench_cmp );
	return CF_CIPHERS_NUM;
}


int _menu_update_loader(
		HWND     hwnd,
		wchar_t *vol,
		int      dsk_num,
		int      type
	)
{
	int rlt = ST_ERROR;
	int is_dcs;

	if ( type == CTL_LDR_STICK )
	{
		is_dcs = dc_is_dcs_on_partition(vol);
		if (is_dcs)
			rlt = dc_update_efi_boot_on_partition(vol);
	}
	else
	{
		is_dcs = dc_is_dcs_on_disk(dsk_num);
		if (is_dcs)
			rlt = dc_update_efi_boot(dsk_num, -1);
		else
			rlt = dc_update_boot(dsk_num);
	}

	if ( rlt == ST_OK )
	{
		__msg_i( hwnd, L"%s Bootloader on [%s] successfully updated\n", is_dcs ? L"EFI" : L"MBR", vol );
	} else {
		__error_s( hwnd, L"Error update %s bootloader\n", rlt, is_dcs ? L"EFI" : L"MBR");
	}

	return rlt;
}


int _menu_unset_loader(
		HWND     hwnd,
		wchar_t *vol,
		int      dsk_num,
		int      type
	)
{
	int rlt = ST_ERROR;
	int is_dcs;

	if ( type == CTL_LDR_STICK )
	{
		wchar_t dev[MAX_PATH];
		drive_inf inf;

		_snwprintf( dev, countof(dev), L"\\\\.\\%s", vol );
		rlt = dc_get_drive_info(dev, &inf);

		if ( rlt == ST_OK )
		{
			if ( inf.dsk_num == 1 )
			{
				dsk_num = inf.disks[0].number;
			} else {
				__msg_w( hwnd, L"One volume on two disks\nIt's very strange..." );
				return rlt;
			}								
		}
	}

	if ( __msg_q(
			hwnd, 
			L"Are you sure you want to remove bootloader\n"
			L"from [%s]?", vol)
			)
	{
		is_dcs = dc_is_dcs_on_disk(dsk_num);
		if ( is_dcs ) {
			rlt = dc_unset_efi_boot(dsk_num, -1);

			if ( rlt == ST_OK && dc_efi_is_bme_set(dsk_num) ) {
				dc_efi_del_bme();
			}
		}
		else
			rlt = dc_unset_mbr(dsk_num);

		if ( rlt == ST_OK )
		{
			__msg_i( hwnd, L"%s Bootloader successfully removed from [%s]\n", is_dcs ? L"EFI" : L"MBR", vol );
		} else {
			__error_s( hwnd, L"Error removing %s bootloader\n", rlt, is_dcs ? L"EFI" : L"MBR" );
		}
		return rlt;
	} else {
		return ST_CANCEL;
	}
}


int _menu_set_loader_mbr(
		HWND     hwnd,
		wchar_t *vol,
		int      dsk_num,
		int      type,
		int      is_small
	)
{
	ldr_config conf;
	int rlt = ST_ERROR;

	if ( type == CTL_LDR_STICK )
	{
		if ( (rlt = dc_set_boot( vol, FALSE, is_small )) == ST_FORMAT_NEEDED )
		{
			if ( __msg_q(
					hwnd,
					L"Removable media not correctly formatted\n"
					L"Format media?\n")
					)
			{
				rlt = dc_set_boot( vol, TRUE, is_small );
			}
		}
		if ( rlt == ST_OK )
		{
			if ( (rlt = dc_mbr_config_by_partition(vol, FALSE, &conf)) == ST_OK )
			{				
				conf.options  |= LDR_OP_EXTERNAL;
				conf.boot_type = LDR_BT_AP_PASSWORD;

				rlt = dc_mbr_config_by_partition(vol, TRUE, &conf);
			}
		}
	} else {							
		rlt = _set_boot_loader_mbr( hwnd, dsk_num, is_small );
	}

	if ( rlt == ST_OK )
	{
		__msg_i( hwnd, L"MBR Bootloader successfully installed to [%s]", vol );
	} else {
		__error_s( hwnd, L"Error installing MBR bootloader", rlt );
	}
	return rlt;

}

int _menu_set_loader_efi(
		HWND     hwnd,
		wchar_t *vol,
		int      dsk_num,
		int      type,
		int      is_shim
	)
{
	ldr_config conf;
	int rlt = ST_ERROR;

	if (type == CTL_LDR_STICK)
	{
		if ( (rlt = dc_make_efi_rec( vol, FALSE, is_shim )) == ST_FORMAT_NEEDED )
		{
			if ( __msg_q(
					hwnd,
					L"Removable media not correctly formatted\n"
					L"Format media?\n")
					)
			{
				rlt = dc_make_efi_rec( vol, TRUE, is_shim);
			}
		}
		if (rlt == ST_OK)
		{
			if ((rlt = dc_efi_config_by_partition(vol, FALSE, &conf)) == ST_OK)
			{
				conf.options |= LDR_OP_EXTERNAL;
				conf.boot_type = LDR_BT_AP_PASSWORD;

				rlt = dc_efi_config_by_partition(vol, TRUE, &conf);
			}
		}
	}
	else {
		/* esp_part = -1 (ask user), add_bme = -1 (ask user) */
		rlt = _set_boot_loader_efi( hwnd, dsk_num, is_shim, -1, -1 );
	}

	if ( rlt == ST_OK )
	{
		__msg_i( hwnd, L"EFI Bootloader successfully installed to [%s]", vol );
	} else if ( rlt == ST_SHIM_MISSING ) {
		void _menu_no_pro(HWND hwnd, int no_shim);
		_menu_no_pro( hwnd, 1);
	} else {
		__error_s( hwnd, L"Error install EFI bootloader", rlt );
	}
	return rlt;

}


int _menu_set_loader_file_mbr(
		HWND     hwnd,
		wchar_t *path,
		BOOL     iso,
		int      is_small
	)
{
	ldr_config conf;

	int rlt = ST_ERROR;
	wchar_t *s_img = iso ? L"ISO" : L"PXE";

	rlt = iso ? dc_make_iso( path, is_small ) : dc_make_pxe( path, is_small );
	if ( rlt == ST_OK )
	{
		if ( (rlt = dc_get_mbr_config( 0, path, &conf )) == ST_OK )
		{
			conf.options   |= LDR_OP_EXTERNAL;
			conf.boot_type  = LDR_BT_MBR_FIRST;

			rlt = dc_set_mbr_config( 0, path, &conf );
		}			
	}
	if ( rlt == ST_OK )
	{
		__msg_i( hwnd, L"Bootloader %s image file \"%s\" successfully created", s_img, path );
	} else {
		__error_s( hwnd, L"Error creating %s image", rlt, s_img );
	}
	return rlt;

}


int _menu_set_loader_file_efi(
		HWND     hwnd,
		wchar_t *path,
		BOOL     iso,
		int      is_shim
	)
{
	ldr_config conf;

	int rlt = ST_ERROR;
	wchar_t *s_img = iso ? L"ISO" : L"PXE";

	rlt = iso ? dc_make_efi_iso( path, is_shim ) : dc_make_efi_pxe( path, is_shim );
	if ( rlt == ST_OK )
	{
		dc_efi_config_init(&conf);
		conf.options   |= LDR_OP_EXTERNAL;
		conf.boot_type  = LDR_BT_MBR_FIRST;

		rlt = dc_set_efi_config( 0, path, &conf );		
	}

	if ( rlt == ST_OK )
	{
		__msg_i( hwnd, L"DCS Bootloader %s image file \"%s\" successfully created", s_img, path );
	} else if ( rlt == ST_SHIM_MISSING ) {
		void _menu_no_pro(HWND hwnd, int no_shim);
		_menu_no_pro( hwnd, iso ? 1 : 2 );
	} else {
		__error_s( hwnd, L"Error creating %s image", rlt, s_img );
	}
	return rlt;
}


/*
   skip-unused (WP_SKIP_UNUSED) and shadow copies, asked before a skip-unused session takes its
   first step in this driver session (after the start, a mount / reboot / unlock); see dcapi
   shadow.h. Yes deletes every shadow copy of the volume, No keeps them, Cancel stops. A failed
   deletion is reported and the operation goes on.
*/
int _check_shadow_copies(
		HWND     hwnd,
		vol_inf *vol,
		int      wp_mode
	)
{
	wchar_t msg[1024];
	int     count = 0, left = -1, rlt, q;

	if ( wp_mode != WP_SKIP_UNUSED ) return ST_OK;

	/* not __msg_q3: it formats into MAX_PATH characters, too short for this text */
	if ( (rlt = dc_count_shadows( vol->w32_device, &count )) == ST_OK )
	{
		if ( count == 0 ) return ST_OK;
		_snwprintf( msg, countof(msg),
			L"Volume %s has %d shadow copies (System Restore points, Previous Versions or backup snapshots).\n\n"
			L"\"Skip unused sectors\" does not process sectors that are unused now, but older shadow copies "
			L"may still keep data in them. Those shadow copies would become corrupt.\n\n"
			L"Yes:\tdelete all shadow copies of this volume (recommended)\n"
			L"No:\tkeep them (they may become unusable)\n"
			L"Cancel:\tdo not continue now (a started operation stays paused)",
			vol->status.mnt_point, count );
	} else {
		_snwprintf( msg, countof(msg),
			L"The shadow copies of volume %s could not be checked (error %d).\n\n"
			L"\"Skip unused sectors\" corrupts shadow copies (System Restore points, Previous Versions or "
			L"backup snapshots) that exist when it starts.\n\n"
			L"Yes:\tdelete all shadow copies of this volume\n"
			L"No:\tcontinue without deleting\n"
			L"Cancel:\tdo not continue now (a started operation stays paused)",
			vol->status.mnt_point, rlt );
	}
	msg[countof(msg) - 1] = 0;
	q = MessageBox( hwnd, msg, L"Shadow copies", MB_YESNOCANCEL | MB_ICONWARNING );
	if ( q == IDCANCEL ) return ST_CANCEL;
	if ( q != IDYES ) return ST_OK;

	/* the wait dialog is modeless - no menu action on the volume while vssadmin runs */
	EnableWindow( hwnd, FALSE );
	rlt = _wait_dc_delete_shadows( hwnd, vol->w32_device, &left, L"Deleting shadow copies..." );
	EnableWindow( hwnd, TRUE );
	SetForegroundWindow( hwnd );
	if ( rlt != ST_OK )
	{
		if ( left > 0 ) {
			_snwprintf( msg, countof(msg),
				L"%d shadow copies of volume %s could not be deleted.\n\n"
				L"The operation continues; these shadow copies may become unusable.", left, vol->status.mnt_point );
		} else {
			_snwprintf( msg, countof(msg),
				L"The shadow copies of volume %s could not be deleted (error %d).\n\n"
				L"The operation continues; existing shadow copies may become unusable.", vol->status.mnt_point, rlt );
		}
		msg[countof(msg) - 1] = 0;
		MessageBox( hwnd, msg, L"Warning", MB_OK | MB_ICONWARNING );
	}
	return ST_OK;
}

/* before the act of a started or resumed session runs. Not asked when the act runs or has
   stepped in this driver session already (a pause keeps the bitmap; a lock clears act->stepped,
   a remount makes a new act). The session's own mode counts; an unknown status asks. */
static int _session_check_shadows(
		_dnode *node
	)
{
	_dact    *act = _create_act_thread( node, -1, -1 );
	dc_status st;
	int       wp_mode = WP_SKIP_UNUSED;

	if ( act != NULL && (act->status == ACT_RUNNING || act->stepped) ) return ST_OK;
	if ( dc_get_device_status( node->mnt.info.device, &st ) == ST_OK )
	{
		if ( !(st.flags & F_SYNC) ) return ST_OK; /* no session (e.g. prepared for the reboot) */
		wp_mode = st.crypt.wp_mode;
	}
	return _check_shadow_copies( __dlg, &node->mnt.info, wp_mode );
}

/* the act runs - or, cancelled at the shadow copy question, stays paused */
static void _run_act_checked(
		_dnode *node,
		int     act_type
	)
{
	if ( _session_check_shadows( node ) == ST_OK ) {
		_create_act_thread( node, act_type, ACT_RUNNING );
	} else {
		_create_act_thread( node, act_type, ACT_PAUSED );
	}
	_activate_page( );
}


/* the decryption start: what it will do (the encryption wizard has its summary page); TRUE = go */
static BOOL _confirm_decrypt(
		_dnode  *node,
		dlgpass *info
	)
{
	wchar_t        msg[512];
	const wchar_t *prot = _get_text_name(info->safe_mode, safe_modes);

	/* the list is greyed for a v1 header (the driver ignores the protection there) */
	if ( info->safe_mode == SAFE_MODE_NONE && node->mnt.info.status.crypt.version < DC_HDR_VERSION_2 ) {
		prot = L"None (needs a version 2 header)";
	}
	_snwprintf(
		msg, countof(msg),
		L"Decrypt volume %s?\n\n"
		L"Power-loss protection:\t%s\n"
		L"Unused sectors:\t\t%s\n\n"
		L"Decryption can be paused and resumed at any time.",
		node->mnt.info.status.mnt_point,
		prot != NULL ? prot : L"None",
		info->skip_unused ? L"skipped" : L"decrypted"
	);
	msg[countof(msg) - 1] = 0;

	return MessageBox( __dlg, msg, L"Decrypt", MB_OKCANCEL | MB_ICONQUESTION | MB_DEFBUTTON1 ) == IDOK;
}

void _menu_decrypt(
		_dnode *node
	)
{
	dlgpass dlg_info = { NULL, node, PF_SHOW_SKIP_UNUSED };

	int rlt;
	if ( _locked_volume_msg(node) ) return;

	if ( !_create_act_thread(node, -1, -1) )
	{
		rlt = _dlg_get_pass( __dlg, &dlg_info );
		if ( rlt == ST_OK )
		{
			crypt_info crypt = { 0 };
			crypt.wp_mode = dlg_info.skip_unused ? WP_SKIP_UNUSED : WP_NONE;
			crypt.flags |= SAFE_MODE_FLAGS( dlg_info.safe_mode ); // power-loss protection

			if ( !_confirm_decrypt(node, &dlg_info) )
			{
				secure_free( dlg_info.pass );
				return; /* nothing started */
			}

			rlt = _wait_dc_start_decrypt( __dlg, node->mnt.info.device, dlg_info.pass, &crypt, L"Starting decryption..." );
			secure_free( dlg_info.pass );

			if ( rlt != ST_OK )
			{
				__error_s(
					__dlg, L"Error start decrypt volume [%s]", rlt, node->mnt.info.status.mnt_point
					);
			}
		}
	} else
	{
		rlt = ST_OK;
	}
	if ( rlt == ST_OK )
	{
		_run_act_checked( node, ACT_DECRYPT );
	}
}


int _set_boot_loader_mbr(
		HWND hwnd,
		int  dsk_num,
		int  is_small
	)
{
	int boot_disk_1 = dsk_num;
	ldr_config conf;

	int rlt;

	if ( (rlt = dc_set_mbr( boot_disk_1, 0, is_small ) ) == ST_NF_SPACE )
	{
		if (__msg_w( hwnd,
				L"Not enough space after partitions to install bootloader.\n\n"
				L"Install bootloader to the first HDD track?\n"
				L"(incompatible with third-party boot managers, like GRUB)"
				)
			) 
		{
			if ( (( rlt = dc_set_mbr( boot_disk_1, 1, is_small ) ) == ST_OK ) && 
				  ( dc_get_mbr_config( boot_disk_1, NULL, &conf ) == ST_OK )
				) 
			{
				conf.boot_type = LDR_BT_ACTIVE;						
				if ( (rlt = dc_set_mbr_config( boot_disk_1, NULL, &conf )) != ST_OK )
				{
					dc_unset_mbr( boot_disk_1 );
				}
			}
		}
	}
	return rlt;

}

int _set_boot_loader_efi(
		HWND hwnd,
		int  dsk_num,
		int  is_shim,
		int  add_esp,   /* -1 = ask user, 0 = no (use Windows ESP), 1 = yes (use dedicated DCS ESP) */
		int  add_bme    /* -1 = ask user, 0 = no, 1 = yes */
	)
{
	int sb_no_pass = (dc_efi_is_secureboot() && !dc_efi_dcs_is_signed());
	int rlt;
	int esp_part = -1;  /* -1 = use default Windows ESP */
	wchar_t esp_path[MAX_PATH];

	if (sb_no_pass && !dc_efi_shim_available()) {
		void _menu_no_pro(HWND hwnd, int no_shim);
		_menu_no_pro( hwnd, 1 );
		return ST_CANCEL;
	}

	if (!is_shim && sb_no_pass) {
		if (__msg_w(hwnd, L"This machine's EFI firmware is configured for secure boot.\n"
			L"Without the shim loader, or YOU manually signing the bootloader files, it won't be able to boot.\n"
			L"Do you want to install the shim loader?")
			) {
			is_shim = 1;
		}
	}

	if (is_shim && !__msg_w(hwnd,
		L"For Secure Boot compatibility, the Shim loader will be installed.\n"
		L"On the first boot, you will be presented with the Shim MOK enrollment prompt.\n"
		L"Press any key to continue, then select 'Enroll MOK' from the menu. You will be given the option to view the key or continue; "
		L"select 'Continue', then confirm by selecting 'Yes'.\n"
		L"You will then be asked for a temporary password. The password is always '123' and is discarded after the enrollment process completes.\n"
		L"The final screen offers the option to reboot. If everything was successful, the DiskCryptor bootloader password prompt will appear after the restart.\n"
		L"If enrollment fails, you may encounter the error message 'Verification failed: (0x1A) Security Violation'. "
		L"To resolve this, start 'MOK Manager' and manually enroll the certificate located at \\EFI\\Boot\\CustomSigner.der.\n"
		L"After another reboot, the DiskCryptor bootloader should start normally and display the password prompt.\n"
		L"Do you want to continue?"
		)) {
		return ST_CANCEL;
	}

	/* Determine whether to use dedicated ESP partition */
	if (add_esp == -1) {
		/* Check if a dedicated but empty DCS ESP partition already exists */
		int existing_esp = dc_find_dcs_esp(dsk_num);
		if (existing_esp > 0) {
			/* Found a DCS ESP partition - check if it's empty (no DCS installed yet) */
			wchar_t check_path[MAX_PATH];
			swprintf_s(check_path, MAX_PATH,
				L"\\\\?\\GLOBALROOT\\Device\\Harddisk%d\\Partition%d", dsk_num, existing_esp);
			if (!dc_is_dcs_on_partition(check_path)) {
				/* Empty DCS ESP exists - use it automatically */
				add_esp = 1;
			}
		}
	}
	if (add_esp == -1) {
		/* Ask user */
		add_esp = __msg_q3(hwnd,
			L"Do you want to use a dedicated EFI System Partition for the DCS loader?\n\n"
			L"Yes: Create or use existing DCS EFI partition (allows encrypting Windows EFI Partition)\n"
			L"No: Install to Windows existing EFI Partition\n"
			L"Cancel: Abort installation");

		if (add_esp == -1) {
			return ST_CANCEL;  /* User cancelled */
		}
	}

	if (add_esp == 1) {
		/* User wants dedicated DCS ESP - find or create it (0 = default 128MB) */
		rlt = dc_get_or_create_dcs_esp(&dsk_num, esp_path, &esp_part, 0);
		if (rlt != ST_OK) {
			__error_s(hwnd, L"Failed to create DCS ESP partition", rlt);
			return rlt;
		}
	}

	/* Determine whether to add boot menu entry */
	if (add_bme == -1) {
		/* Ask user */
		if (__msg_w(hwnd, L"Do you want to add a DCS loader boot menu entry (recommended).")) {
			add_bme = 1;

#ifndef _M_ARM64
			if (!add_esp && !sb_no_pass && dc_efi_is_msft_on_disk(dsk_num))
			{
				if (__msg_w(hwnd, L"Note: Some EFI implementations are not adhering to the standard and always start the windows bootloader.\n"
					L"Do you want to replace the windows bootloader file (BOOTMGFW.EFI) with a redirection to the DCS loader as a workaround?")) {
					add_bme = 2;
				}
			}
#endif
		} else {
			add_bme = 0;
		}
	}

	rlt = dc_set_efi_boot(dsk_num, esp_part, add_bme == 2, is_shim);

	if (rlt == ST_OK && add_bme != 0) {
		rlt = dc_efi_set_bme(L"DiskCrypto (DCS) loader", dsk_num);
	}

	return rlt;

}


int _menu_add_shim(
	HWND     hwnd,
	wchar_t *vol,
	int      dsk_num,
	int      type
)
{
	int rlt = ST_ERROR;

	if ( type == CTL_LDR_STICK )
	{
		rlt = dc_efi_set_shim_on_partition(vol);
	}
	else
	{
		rlt = dc_efi_set_shim(dsk_num, -1);

		if ( rlt == ST_OK )
		{
			if (dc_efi_is_bme_set(dsk_num) && !dc_efi_is_bme_shim(dsk_num)) {
				dc_efi_set_bme(L"DiskCrypto (DCS) loader", dsk_num);
			}
		}
	}

	if ( rlt == ST_OK )
	{
		__msg_i( hwnd, L"Secure Boot shim successfully installed\n");
	} else {
		__error_s( hwnd, L"Error installing Secure Boot shim\n", rlt );
	}
	return rlt;
}

int _menu_del_shim(
	HWND     hwnd,
	wchar_t *vol,
	int      dsk_num,
	int      type
)
{
	int rlt = ST_ERROR;

	if ( type == CTL_LDR_STICK )
	{
		rlt = dc_efi_unset_shim_on_partition(vol);
	}
	else
	{
		rlt = dc_efi_unset_shim(dsk_num, -1);

		if ( rlt == ST_OK )
		{
			if (dc_efi_is_bme_set(dsk_num) && dc_efi_is_bme_shim(dsk_num)) {
				dc_efi_set_bme_to_dcsboot(L"DiskCrypto (DCS) loader", dsk_num);
			}
		}
	}

	if ( rlt == ST_OK )
	{
		__msg_i( hwnd, L"Secure Boot shim successfully removed\n");
	} else {
		__error_s( hwnd, L"Error removing Secure Boot shim\n", rlt );
	}
	return rlt;
}

int _menu_add_bme(
	HWND     hwnd,
	wchar_t *vol,
	int      dsk_num
)
{
	int rlt = ST_ERROR;

	rlt = dc_efi_set_bme(L"DiskCrypto (DCS) loader", dsk_num);

	if ( rlt == ST_OK )
	{
		__msg_i( hwnd, L"DCS Boot Menu Entry successfully added\n");
	} else {
		__error_s( hwnd, L"Error adding DCS Boot Menu Entry\n", rlt );
	}
	return rlt;

}

int _menu_del_bme(
	HWND     hwnd,
	wchar_t *vol,
	int      dsk_num
)
{
	int rlt = ST_ERROR;

	rlt = dc_efi_del_bme();

	if ( rlt == ST_OK )
	{
		__msg_i( hwnd, L"DCS Boot Menu Entry successfully removed\n");
	} else {
		__error_s( hwnd, L"Error removing DCS Boot Menu Entry\n", rlt );
	}
	return rlt;

}

int _menu_repalce_msldr(
	HWND     hwnd,
	wchar_t *vol,
	int      dsk_num
)
{
	int rlt = ST_ERROR;

	rlt = dc_efi_replace_msft_boot(dsk_num, -1);

	if ( rlt == ST_OK )
	{
		__msg_i( hwnd, L"Microsoft Boot Manager successfully replaced on [%s]\n", vol );
	} else {
		__error_s( hwnd, L"Error replacing Microsoft Boot Manager on [%s]\n", rlt, vol );
	}
	return rlt;

}

int _menu_restore_msldr(
	HWND     hwnd,
	wchar_t *vol,
	int      dsk_num
)
{
	int rlt = ST_ERROR;

	rlt = dc_efi_restore_msft_boot(dsk_num, -1);

	if ( rlt == ST_OK )
	{
		__msg_i( hwnd, L"Microsoft Boot Manager successfully restored on [%s]\n", vol );
	} else {
		__error_s( hwnd, L"Error restoring Microsoft Boot Manager on [%s]\n", rlt, vol );
	}
	return rlt;

}


void _menu_encrypt_cd(  )
{
	_dnode *node = pv( malloc(sizeof(_dnode)) );		
	memset( node, 0, sizeof(_dnode) );
	
	wcscpy( node->mnt.info.device, L"Encrypt ISO file" );
	node->dlg.act_type = ACT_ENCRYPT_CD;

	/* Note: Wizard uses regular dialog - password entry within wizard pages
	   is protected by _dlg_get_pass which uses secure desktop */
	DialogBoxParam(
		__hinst, MAKEINTRESOURCE(IDD_WIZARD_ENCRYPT), __dlg, pv(_wizard_encrypt_dlg_proc), (LPARAM)node
		);

	if ( node->dlg.rlt == ST_CANCEL ) 
	{
		return;
	}
	if ( node->dlg.rlt == ST_OK )
	{
		__msg_i( 
			__dlg, L"ISO image \"%s\" successfully encrypted to \"%s\"", 
			_extract_name(node->dlg.iso.s_iso_src), 
			_extract_name(node->dlg.iso.s_iso_dst)
			);		
	} else 
	{
		__error_s(
			__dlg, 
			L"Error encrypting ISO image \"%s\"", node->dlg.rlt, _extract_name(node->dlg.iso.s_iso_src) 
			);
	}
	free(node);
}


void _menu_encrypt(
		_dnode *node
	)
{
	int rlt;

	if ( _locked_volume_msg(node) ) return;

	/* Check if this partition contains DCS bootloader files - cannot encrypt it */
	if ( __is_efi_boot )
	{
		wchar_t vol_root[MAX_PATH];
		/* Build volume root path from w32_device (e.g., \\?\Volume{...}\) */
		_snwprintf(vol_root, MAX_PATH, L"%s\\", node->mnt.info.w32_device);

		if ( dc_is_dcs_on_partition(vol_root) )
		{
			wchar_t s_boot_dev[MAX_PATH];
			if ((dc_get_boot_device(s_boot_dev) == ST_OK) && (wcscmp(node->mnt.info.device, s_boot_dev) == 0)) {
				__msg_e(__dlg,
					L"This partition contains the DCS bootloader and cannot be encrypted.\n"
					L"The UEFI firmware needs to read the bootloader files before Windows starts.\n\n"
					L"If you want to encrypt the Windows EFI partition, first install the DCS loader\n"
					L"to a dedicated DCS EFI partition, then remove it from this partition.");
			} else {
				__msg_e(__dlg,
					L"This partition contains the DCS bootloader and cannot be encrypted.\n"
					L"The UEFI firmware needs to read the bootloader files before Windows starts.");
				
			}
			return;
		}
	}

	if ( _create_act_thread(node, -1, -1) == 0 )
	{
		node->dlg.act_type = ACT_ENCRYPT;

		DialogBoxParam(
			__hinst, MAKEINTRESOURCE(IDD_WIZARD_ENCRYPT), __dlg, pv(_wizard_encrypt_dlg_proc), (LPARAM)node
			);

		rlt = node->dlg.rlt;
	} else {
		rlt = ST_OK;
	}

	if ( rlt == ST_CANCEL ) return;
	if ( rlt != ST_OK )
	{
		__error_s(
			__dlg, L"Error start encrypt volume [%s]", rlt, node->mnt.info.status.mnt_point
			);
	} else {
		_run_act_checked( node, ACT_ENCRYPT );

	}
}

void _menu_encrypt2(
	_dnode *node
)
{
	int rlt = ST_OK;
	wchar_t path[MAX_PATH];

	rlt = dc_get_pending_header_nt(node->mnt.info.device, path);
	if ( rlt == ST_OK )
	{
		rlt = dc_start_encrypt2(node->mnt.info.device, path);
	}

	if ( rlt != ST_OK ) 
	{
		__error_s(
			__dlg, L"Error start pending encrypt volume [%s]", rlt, node->mnt.info.status.mnt_point
		);
	} else {
		_run_act_checked( node, ACT_ENCRYPT );

	}
}

//void _menu_wizard(
//		_dnode *node
//	)
//{
//	wchar_t *s_act;
//	int      rlt;
//
//	if ( _create_act_thread(node, -1, -1) == 0 )
//	{
//		node->dlg.act_type = -1;
//
//		DialogBoxParam(__hinst, 
//			MAKEINTRESOURCE(IDD_WIZARD_ENCRYPT), __dlg, pv(_wizard_encrypt_dlg_proc), (LPARAM)node);
//
//		rlt = node->dlg.rlt;
//
//	} else {
//		rlt = ST_OK;
//	}
//	
//	if (rlt == ST_CANCEL) return;
//	if (rlt != ST_OK) 
//	{
//		switch (node->dlg.act_type) 
//		{
//			case ACT_REENCRYPT: s_act = L"reencrypt"; break;
//			case ACT_ENCRYPT:   s_act = L"encrypt";   break;
//			case ACT_FORMAT:    s_act = L"format";    break;
//		};
//		__error_s(
//			__dlg, L"Error start %s volume [%s]", rlt, s_act, node->mnt.info.status.mnt_point
//			);
//	} else {
//		_create_act_thread(node, node->dlg.act_type, ACT_RUNNING);
//		_activate_page( );
//
//	}
//}


void _menu_reencrypt(
		_dnode *node
	)
{
	int rlt;
	if ( _locked_volume_msg(node) ) return;

	node->dlg.act_type = ACT_REENCRYPT;

	if ( _create_act_thread(node, -1, -1) == 0 &&
		 !(node->mnt.info.status.flags & F_REENCRYPT)
		)
	{
		DialogBoxParam(
			__hinst, MAKEINTRESOURCE(IDD_WIZARD_ENCRYPT), __dlg, pv(_wizard_encrypt_dlg_proc), (LPARAM)node
			);

		rlt = node->dlg.rlt;
	} else {
		rlt = ST_OK;
	}

	if ( rlt == ST_CANCEL ) return;
	if ( rlt != ST_OK )
	{
		__error_s(
			__dlg, L"Error start reencrypt volume [%s]", rlt, node->mnt.info.status.mnt_point
			);
	} else {
		_run_act_checked( node, ACT_REENCRYPT );

	}
}


void _menu_format(
		_dnode *node
	)
{
	int rlt;

	if ( _locked_volume_msg(node) ) return;

	node->dlg.act_type = ACT_FORMAT;
	node->dlg.q_format = FALSE;

	node->dlg.fs_name  = L"FAT32";

	if ( _create_act_thread(node, -1, -1) == 0 &&
		 !(node->mnt.info.status.flags & F_FORMATTING)
		)
	{
		DialogBoxParam(
			__hinst, MAKEINTRESOURCE(IDD_WIZARD_ENCRYPT), __dlg, pv(_wizard_encrypt_dlg_proc), (LPARAM)node
			);

		rlt = node->dlg.rlt;
	} else {
		rlt = ST_OK;
	}

	if ( rlt == ST_CANCEL ) return;
	if ( rlt != ST_OK )
	{
		__error_s(
			__dlg, L"Error start format volume [%s]", rlt, node->mnt.info.status.mnt_point
			);
	} else 
	{
		if ( node->dlg.q_format )
		{
			rlt = dc_done_format( node->mnt.info.device );
			if ( rlt == ST_OK )
			{
				_finish_formatting(node);
			}
		} else {
			_create_act_thread(node, ACT_FORMAT, ACT_RUNNING);
			_activate_page( );
		}
	}
}


static
void _menu_unmount_ex(
		_dnode *node,
		BOOL    force
	)
{
	int  resl   = ST_ERROR;
	int  flags  = ( force || (__config.conf_flags & CONF_FORCE_DISMOUNT) ) ? MF_FORCE : 0;
	BOOL locked = DC_IS_LOCKED( node->mnt.info.status.flags );
	int  confirm;

	if ( force )
	{
		confirm = __msg_q(
			__dlg,
			L"Force unmount volume [%s]?\n\n"
			L"Open files are closed, data not yet written to the volume is lost.", node->mnt.info.status.mnt_point
			);
	} else if ( locked )
	{
		/* the FS cannot flush its cache to a locked volume, its writes fail */
		confirm = __msg_q(
			__dlg,
			L"Unmount locked volume [%s]?\n\n"
			L"Its keys were erased at hibernation, data not yet written to the volume is lost.", node->mnt.info.status.mnt_point
			);
	} else
	{
		confirm = __msg_q( __dlg, L"Unmount volume [%s]?", node->mnt.info.status.mnt_point );
	}

	if ( confirm )
	{
		resl = dc_unmount_volume( node->mnt.info.device, flags );

		if ( resl == ST_LOCK_ERR )
		{
			if ( __msg_w( __dlg, locked ?
					L"The file system of this locked volume cannot be flushed.\n"
					L"Would you like to force an unmount on this volume?\n"
					L"Data not yet written to the volume is lost." :
					L"This volume contains opened files.\n"
					L"Would you like to force an unmount on this volume?" )
				)
			{
				resl = dc_unmount_volume( node->mnt.info.device, MF_FORCE );
			} else {
				resl = ST_OK;
			}
		}

		if ( resl != ST_OK )
		{
			__error_s(
				__dlg, L"Error unmount volume [%s]", resl, node->mnt.info.status.mnt_point
				);
		} else {
			_dact *act;

			EnterCriticalSection(&crit_sect);
			if ( act = _create_act_thread(node, -1, -1) ) 
			{
				act->status = ACT_STOPPED;
			}
			LeaveCriticalSection(&crit_sect);
		}
	}
}


void _menu_unmount(
		_dnode *node
	)
{
	_menu_unmount_ex( node, FALSE );
}


void _menu_force_unmount(
		_dnode *node
	)
{
	_menu_unmount_ex( node, TRUE );
}


static
void _unlock_error(
		_dnode *node,
		int     rlt
	)
{
	wchar_t msg[MAX_PATH * 2];

	switch ( rlt )
	{
		case ST_CANCEL:
		{
			/* the driver refuses mounts / unlocks while the system hibernates */
			_snwprintf(
				msg, countof(msg),
				L"Volume [%s] cannot be unlocked while the system is entering hibernation.\n"
				L"Try again after the resume.", node->mnt.info.status.mnt_point
				);
			msg[countof(msg) - 1] = 0;
			__msg_e( __dlg, msg );
		}
		break;
		case ST_MEDIA_CHANGED:
		{
			_snwprintf(
				msg, countof(msg),
				L"The volume header found on [%s] does not match the locked volume.\n"
				L"The volume stays locked, unmount it instead.", node->mnt.info.status.mnt_point
				);
			msg[countof(msg) - 1] = 0;
			__msg_e( __dlg, msg );
		}
		break;
		case ST_ERROR:
		{
			_snwprintf(
				msg, countof(msg),
				L"Volume [%s] cannot be unlocked in its current state\n"
				L"(e.g. its decryption has just finished), unmount it instead.", node->mnt.info.status.mnt_point
				);
			msg[countof(msg) - 1] = 0;
			__msg_e( __dlg, msg );
		}
		break;
		default:
		{
			__error_s(
				__dlg, L"Error unlock volume [%s]", rlt, node->mnt.info.status.mnt_point
				);
		}
		break;
	}
}


/*
   Unlock a locked volume (keys erased at hibernation, see F_LOCKED) in place: DC_CTL_MOUNT
   with the password. The driver also tries the cached passwords, keeps the original mount
   flags (only MF_USE_BACKUP applies) and continues a paused or running transcryption.
*/
static
void _menu_unlock(
		_dnode *node
	)
{
	wchar_t caption[MAX_PATH];
	dlgpass dlg_info = { NULL, node, PF_CAN_USE_BACKUP };
	int     rlt;
	int     flags;
	int     aborted = 0;
	/* a volume mounted from its backup header is unlocked from it as well (the driver also
	   ORs MF_USE_BACKUP in itself): the first attempt uses it, the dialog shows it fixed */
	int     bk_flags = node->mnt.info.status.mnt_flags & MF_USE_BACKUP;

	_snwprintf(
		caption, countof(caption), L"Unlock [%s] - %s", node->mnt.info.status.mnt_point, node->mnt.info.device
		);
	caption[countof(caption) - 1] = 0;
	dlg_info.caption    = caption;
	dlg_info.use_backup = bk_flags != 0;
	if ( bk_flags != 0 )
	{
		dlg_info.flags |= PF_BACKUP_FORCED;
	}

	/* cached passwords / boot keys first; ST_DEVICE_BUSY: the volume was locked again (or
	   another volume mounted on it) while its header was probed - probe once more */
	rlt = _wait_dc_mount_volume_ex( __dlg, node->mnt.info.device, NULL, bk_flags, L"Unlocking volume...", &aborted );
	if ( rlt == ST_DEVICE_BUSY && !aborted )
	{
		rlt = _wait_dc_mount_volume_ex( __dlg, node->mnt.info.device, NULL, bk_flags, L"Unlocking volume...", &aborted );
	}
	if ( aborted )
	{
		return; /* the user cancelled the wait (the driver reports it as ST_CANCEL) */
	}

	/* ST_NO_MOUNT: dismounted meanwhile - no password prompt (it would mount it afresh,
	   without its original options); reported below */
	if ( (rlt != ST_OK) && (rlt != ST_ALR_MOUNT) && (rlt != ST_ERROR) && (rlt != ST_CANCEL) && (rlt != ST_NO_MOUNT) )
	{
		if ( _dlg_get_pass(__dlg, &dlg_info) != ST_OK )
		{
			return; /* cancelled by the user */
		}
		flags = (dlg_info.use_backup || bk_flags) ? MF_USE_BACKUP : 0;

		rlt = _wait_dc_mount_volume_ex( __dlg, node->mnt.info.device, dlg_info.pass, flags, L"Unlocking volume...", &aborted );
		if ( rlt == ST_DEVICE_BUSY && !aborted )
		{
			rlt = _wait_dc_mount_volume_ex( __dlg, node->mnt.info.device, dlg_info.pass, flags, L"Unlocking volume...", &aborted );
		}
		secure_free( dlg_info.pass );
		if ( aborted )
		{
			return;
		}
	}

	/* ST_ALR_MOUNT: mounted and no longer locked, e.g. unlocked on resume meanwhile */
	if ( (rlt != ST_OK) && (rlt != ST_ALR_MOUNT) )
	{
		_unlock_error( node, rlt );
	}
}


void _menu_mount(
		_dnode *node
	)
{
	wchar_t mnt_point[MAX_PATH] = { 0 };
	wchar_t vol[MAX_PATH];
	int flags = 0;

	dlgpass dlg_info = { NULL, node, PF_MOUNT_OPTIONS, NULL, NULL, mnt_point};

	int rlt;

	if ( DC_IS_LOCKED(node->mnt.info.status.flags) )
	{
		_menu_unlock( node );
		return;
	}

	rlt = _wait_dc_mount_volume(
			__dlg, node->mnt.info.device, NULL, (mnt_point[0] != 0) ? MF_DELMP : 0, L"Mounting volume..."
		);

	if ( rlt != ST_OK )
	{
		if ( _dlg_get_pass(__dlg, &dlg_info) == ST_OK )
		{
			if (mnt_point[0] != 0)   flags |= MF_DELMP;
			if (dlg_info.mnt_ro)     flags |= MF_READ_ONLY;
			if (dlg_info.no_hiber)   flags |= MF_NO_HIBER;
			if (dlg_info.use_backup) flags |= MF_USE_BACKUP;
			rlt = _wait_dc_mount_volume( __dlg, node->mnt.info.device, dlg_info.pass, flags, L"Mounting volume..." );
			secure_free( dlg_info.pass );

			if ( rlt == ST_OK )
			{						
				if ( mnt_point[0] != 0 )
				{
					_snwprintf( vol, countof(vol), L"%s\\", node->mnt.info.w32_device );
					_set_trailing_slash(mnt_point);

					if ( SetVolumeMountPoint(mnt_point, vol) == 0 )
					{
						__error_s( __dlg, L"Error when adding mount point", rlt );
					}
				}
			} else 
			{
				__error_s(
					__dlg, L"Error mount volume [%s]", rlt, node->mnt.info.status.mnt_point
					);
			}
		}
	}
	if ( (rlt == ST_OK) && (__config.conf_flags & CONF_EXPLORER_MOUNT) )
	{
		__execute(node->mnt.info.status.mnt_point);
	}
}


void _menu_mountall( )
{
	dlgpass dlg_info  = { NULL, NULL, PF_MOUNT_OPTIONS };
	int     mount_cnt = 0;
	int     flags = 0;	

	_wait_dc_mount_all(__dlg, NULL, &mount_cnt, 0, L"Mounting volumes...");
	if ( mount_cnt == 0 )
	{
		if ( _dlg_get_pass(__dlg, &dlg_info) == ST_OK )
		{
			if (dlg_info.mnt_ro)     flags |= MF_READ_ONLY;
			if (dlg_info.no_hiber)   flags |= MF_NO_HIBER;
			if (dlg_info.use_backup) flags |= MF_USE_BACKUP;
			_wait_dc_mount_all( __dlg, dlg_info.pass, &mount_cnt, flags, L"Mounting volumes..." );
			secure_free( dlg_info.pass );

			__msg_i( __dlg, L"Mounted or unlocked devices: %d", mount_cnt );
		}
	}
}


void _menu_unmountall( )
{
	list_entry *node = __action.flink;

	if ( __msg_q( __dlg, L"Unmount all volumes?" ) )
	{
		dc_unmount_all( );
		for ( ;node != &__action; node = node->flink ) 
		{
			((_dact *)node)->status = ACT_STOPPED;
		}
	}
}


void _menu_change_pass(
		_dnode *node
	)
{
	dlgpass dlg_info = { NULL, node, PF_NO_KEY_SLOTS };
	int     resl     = ST_ERROR;
	int     flags = 0;

	if ( _locked_volume_msg(node) ) return;

	if ( _dlg_change_pass( __dlg, &dlg_info ) == ST_OK )
	{
		if (dlg_info.clear_slots)
			flags |= HF_CLEAR_SLOTS;

		resl = _wait_dc_change_password(__dlg, node->mnt.info.device, dlg_info.pass, dlg_info.new_pass, flags, L"Changing password...");

		secure_free( dlg_info.pass );
		secure_free( dlg_info.new_pass );

		if ( resl == ST_NOT_BACKUP )
		{
			__msg_i( __dlg, L"Primary header password changed for [%s],\nFAILED to change backup header password.", node->mnt.info.status.mnt_point );
		}
		else if ( resl != ST_OK )
		{
			__error_s( __dlg, L"Error change password", resl );
		} else {
			__msg_i( __dlg, L"Password successfully changed for [%s]", node->mnt.info.status.mnt_point );
		}
	}
}


void _menu_clear_cache( )
{
	if ( __msg_q( __dlg, L"Wipe All Passwords?" ) )
	{
		dc_device_control(DC_CTL_CLEAR_PASS, NULL, 0, NULL, 0);
	}
}


void _menu_cache_password( )
{
	dlgpass dlg_info = { NULL, NULL, PF_SHOW_CACHE_TAG };
	int rlt;

	rlt = _dlg_get_pass(__dlg, &dlg_info);
	if (rlt == ST_OK)
	{
		rlt = _wait_dc_add_password(__dlg, dlg_info.pass, L"Caching password...");
		secure_free(dlg_info.pass);

		if (rlt != ST_OK)
		{
			__error_s(__dlg, L"Error caching password", rlt);
		}
	}
}


void _menu_backup_header(
		_dnode *node
	)
{
	dlgpass dlg_info = { NULL, node, PF_NO_KEY_SLOTS | PF_CAN_USE_BACKUP };

	wchar_t s_path[MAX_PATH];
	int     rlt;
	int     flags = 0;

	if ( _locked_volume_msg(node) ) return;

	rlt = _dlg_get_pass( __dlg, &dlg_info );
	if ( rlt == ST_OK )
	{
		int bytes = DC_AREA_MAX_SIZE;
		u8 *backup = malloc(bytes);

		if (dlg_info.use_backup)
			flags |= HF_BACKUP_HEADER;

		rlt = _wait_dc_backup_header( __dlg, node->mnt.info.device, dlg_info.pass, backup, &bytes, flags, L"Backing up header..." );
		secure_free( dlg_info.pass );

		if ( rlt == ST_OK )
		{
			_snwprintf( s_path, countof(s_path), L"%s.bin", wcsrchr(node->mnt.info.device, '\\') + 1 );
			if ( _save_file_dialog( __dlg, s_path, countof(s_path), L"Save backup volume header to file" ) )
			{
				rlt = save_file( s_path, backup, bytes );
			} else rlt = ST_CANCEL;
		}

		secure_free(backup);
	}

	if ( rlt == ST_OK )
	{
		__msg_i( __dlg, L"Volume header backup successfully saved to\n\"%s\"", s_path );
	} else if ( rlt != ST_CANCEL ) {
		__error_s( __dlg, L"Error save volume header backup", rlt );
	}
}


void _menu_restore_header(
		_dnode *node
	)
{
	dlgpass dlg_info = { NULL, node, PF_NO_KEY_SLOTS | PF_CAN_USE_BACKUP };

	wchar_t s_path[MAX_PATH] = { 0 };
	int     rlt = ST_ERROR;
	u8     *backup;
	u32     bytes;
	int     flags = 0;

	if ( _locked_volume_msg(node) ) return;

	if ( _open_file_dialog( __dlg, s_path, countof(s_path), L"Open backup volume header" ) )
	{		
		if ( (rlt = load_file(s_path, &backup, &bytes)) == ST_OK)
		{
			rlt = _dlg_get_pass(__dlg, &dlg_info); 
			if (rlt == ST_OK )
			{
				if (dlg_info.use_backup)
					flags |= HF_BACKUP_HEADER;

				rlt = _wait_dc_restore_header( __dlg, node->mnt.info.device, dlg_info.pass, backup, bytes, flags, L"Restoring header..." );
				secure_free( dlg_info.pass );
			}
			my_free(backup);
		}
	} else rlt = ST_CANCEL;

	if ( rlt == ST_OK )
	{
		__msg_i( __dlg, L"Volume header successfully restored from\n\"%s\"", s_path );
	} else if ( rlt != ST_CANCEL ) {
		__error_s( __dlg, L"Error restore volume header from backup", rlt );
	}
}


void _menu_header_config(
		_dnode *node
	)
{
	if (!node || node->is_root) {
		__msg_e(__dlg, L"Please select a volume");
		return;
	}
	if ( _locked_volume_msg(node) ) return;

	_dlg_header_config_volume(__dlg, node);
}


void _menu_header_file( )
{
	wchar_t s_path[MAX_PATH] = { 0 };

	if (_open_file_dialog(__dlg, s_path, countof(s_path), L"Open header backup file"))
	{
		_dlg_header_config_file(__dlg, s_path);
	}
}
