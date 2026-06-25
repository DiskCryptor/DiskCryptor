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
#include "dlg_drives_list.h"
#include "efiinst.h"
#include "gpt_sup.h"

static
void _set_device_item(
		HWND     h_list,
		int      lvcount,
		int      num,
		wchar_t *mnt_point,
		_dnode  *root,
		BOOL     fixed,
		BOOL     is_gpt,
		BOOL     mbr_ldr,
		BOOL     efi_ldr,
		BOOL     boot
	)
{
	LVITEM lvitem;

	int lvsub = 0;
	__int64 size;	
	int  has_bme, replaced_ms, has_shim;

	wchar_t s_size[MAX_PATH];
	wchar_t s_hdd[MAX_PATH];
	wchar_t s_ldr[128];
	wchar_t s_type[128];

	lvitem.mask		= LVIF_TEXT | LVIF_PARAM;
	lvitem.iItem	= lvcount;
	lvitem.iSubItem	= 0;			
			
	lvitem.lParam	= (LPARAM)root;
	lvitem.pszText	= STR_NULL;
	ListView_InsertItem( h_list, &lvitem );
			
	size = dc_dsk_get_size( num, 0 );
	dc_format_byte_size( s_size, countof(s_size), size );

	_snwprintf( s_hdd, countof(s_hdd), L"HardDisk %d", num );

	/* Check if DCS is installed to a dedicated ESP */
	int has_dcs_esp = efi_ldr ? (dc_find_dcs_esp(num) > 0) : 0;

	if (mbr_ldr && efi_ldr) wcscpy(s_ldr, has_dcs_esp ? L"MBR + ESP installed" : L"MBR + EFI installed");
	else if (mbr_ldr)		wcscpy(s_ldr, L"MBR installed");
	else if (efi_ldr)		wcscpy(s_ldr, has_dcs_esp ? L"ESP installed" : L"EFI installed");
	else					wcscpy(s_ldr, L"none");

	if (efi_ldr)
	{
		has_bme = dc_efi_is_bme_set(num);
		has_shim = dc_efi_is_shim_set(num);
		replaced_ms = dc_efi_is_msft_boot_replaced(num, -1);
		if (has_shim)
			wcscat(s_ldr, L", shim");
		if (has_bme)
			wcscat(s_ldr, L", bme");
		if (replaced_ms)
			wcscat(s_ldr, L", ms");
	}

	_snwprintf(s_type, countof(s_type), L"%s%s", is_gpt ? L"GPT" : L"MBR", boot ? L", boot" : L"");

	ListView_SetItemText( h_list, lvcount, lvsub++, fixed ? s_hdd : mnt_point );
	ListView_SetItemText( h_list, lvcount, lvsub++, s_size );

	ListView_SetItemText( h_list, lvcount, lvsub++, s_ldr);
	ListView_SetItemText( h_list, lvcount, lvsub++, s_type);

}


void _load_diskdrives(
		HWND        hwnd,
		list_entry *volumes,
		char        vcount
	)
{ 
	LVITEM lvitem;

	list_entry *node;
	list_entry *sub;

	BOOL boot_enc = TRUE;
	BOOL run_enc  = TRUE;
	BOOL vol_enb  = FALSE;

	int count;

	wchar_t s_display[MAX_PATH] = { L"{ ERR_NAME }" };
	wchar_t s_boot_dev[MAX_PATH];

	int k       = 0;
	int col     = 0;
	int item    = 0;
	int subitem = 1;

	SendMessage( __lists[HMAIN_DRIVES], WM_SETREDRAW, FALSE, 0 );
	count = ListView_GetItemCount( __lists[HMAIN_DRIVES] );

	_init_list_headers( __lists[HMAIN_DRIVES], _main_headers );
	if ( count != vcount )
	{
		ListView_DeleteAllItems( __lists[HMAIN_DRIVES] );
		count = 0;
	}
	lvitem.mask      = LVIF_TEXT | LVIF_IMAGE | LVIF_STATE | LVIF_PARAM; 
	lvitem.state     = 0; 
	lvitem.stateMask = 0;

	for ( node  = __drives.flink;
		  node != &__drives;
		  node  = node->flink, subitem = 1 
		  )
	{
		_dnode *root = contain_record( node, _dnode, list );

		lvitem.iItem    = item;
		lvitem.iSubItem = 0;
		lvitem.lParam   = (LPARAM)root;

		if (! count )
		{
			lvitem.iImage  = 0;
			lvitem.pszText = root->root.dsk_name;
			ListView_InsertItem( __lists[HMAIN_DRIVES], &lvitem );
		} else {
			lvitem.mask = LVIF_PARAM; 
			ListView_SetItem( __lists[HMAIN_DRIVES], &lvitem );
		}

		for ( sub  = root->root.vols.flink, item++;
			  sub != &root->root.vols;
			  sub  = sub->flink, item++, subitem = 1 
			  )
		{
			_dnode *mnt = contain_record( sub, _dnode, list );
			mnt->exists = FALSE;

			lvitem.iItem = item;
			lvitem.lParam = (LPARAM)mnt;
			lvitem.iSubItem = 0;

			if ( wcsstr( mnt->mnt.info.status.mnt_point, L"\\\\?\\" ) == 0 )
			{
				_snwprintf(
					s_display, countof(s_display), L"&%s", mnt->mnt.info.status.mnt_point
					);
			} else 
			{
				wchar_t *vol_name = wcsrchr( mnt->mnt.info.device, L'V' );

				if (! vol_name ) vol_name = wcsrchr( mnt->mnt.info.device, L'\\' ) + 1;

				if ( vol_name )
				{
					_snwprintf( s_display, countof(s_display), L"&%s", vol_name );
				}
			}
			if (! count )
			{
				lvitem.iImage  = 1; 
				lvitem.pszText = s_display;
				ListView_InsertItem( __lists[HMAIN_DRIVES], &lvitem );
			} else {
				lvitem.mask = LVIF_PARAM;
				ListView_SetItem( __lists[HMAIN_DRIVES], &lvitem );
			}
			_list_set_item_text( __lists[HMAIN_DRIVES], item, 0, s_display );

			dc_format_byte_size( s_display, countof(s_display), mnt->mnt.info.status.dsk_size );
			_list_set_item_text( __lists[HMAIN_DRIVES], item, subitem++, s_display );

			_list_set_item_text( __lists[HMAIN_DRIVES], item, subitem++, mnt->mnt.label );
			if (mnt->mnt.info.status.flags & F_FS_RAW) 
				_list_set_item_text(__lists[HMAIN_DRIVES], item, subitem++, L"RAW");
			else 
				_list_set_item_text(__lists[HMAIN_DRIVES], item, subitem++, mnt->mnt.fs);


			_get_status_text( mnt, s_display, countof(s_display) );
			_list_set_item_text( __lists[HMAIN_DRIVES], item, subitem++, s_display );

			if ( mnt->mnt.info.status.flags & F_SYNC ) 
			{
				run_enc = FALSE;
			}
			if ( mnt->mnt.info.status.flags & F_ENABLED && !_is_boot_device(&mnt->mnt.info) ) 
			{
				vol_enb = TRUE;
			}
			if ( dc_get_boot_device(s_boot_dev) == ST_OK )
			{
				wchar_t s_boot[MAX_PATH] = { 0 };

				if ( wcscmp(mnt->mnt.info.device, s_boot_dev) == 0 )
				{
					if(__is_efi_boot)
						wcscat( s_boot, L"efi" );
					else
						wcscat( s_boot, L"boot" );
				}
				if ( mnt->mnt.info.status.flags & F_SYSTEM )
				{
					if ( wcslen(s_boot) )
					{
						wcscat(s_boot, L", ");
					}
					wcscat( s_boot, L"sys" );
				}
				/* Check if volume contains DCS bootloader files */
				if ( __is_efi_boot )
				{
					wchar_t vol_root[MAX_PATH];
					_snwprintf(vol_root, MAX_PATH, L"%s\\", mnt->mnt.info.w32_device);
					if ( dc_is_dcs_on_partition(vol_root) )
					{
						if ( wcslen(s_boot) )
						{
							wcscat(s_boot, L", ");
						}
						wcscat( s_boot, L"dcs" );
					}
				}
				if ( wcslen(s_boot) && mnt->mnt.info.status.flags & F_ENABLED )
				{
					boot_enc = FALSE;
				}
				_list_set_item_text( __lists[HMAIN_DRIVES], item, subitem++, s_boot );
			}
		}
	}	
	EnableMenuItem( GetMenu(__dlg), ID_TOOLS_DRIVER, _menu_onoff(boot_enc) );
	EnableMenuItem( GetMenu(__dlg), ID_TOOLS_BSOD, _menu_onoff(run_enc) );
	EnableWindow( GetDlgItem(hwnd, IDC_BTN_UNMOUNTALL_), vol_enb );

	SendMessage( __lists[HMAIN_DRIVES], WM_SETREDRAW, TRUE, 0 );

} 


void _list_devices(
		HWND h_list,
		BOOL fixed,
		int  sel
	)
{
	list_entry *node, *sub;

	int k   = 0;
	int col = 0;

	int lvcount     = 0;
	int boot_disk_1 = -1;
	int boot_disk_2 = -1;
	int is_gpt;
	int mbr_ldr, efi_ldr;

	//ldr_config conf;
	_dnode *root = malloc(sizeof(_dnode));

	memset( root, 0, sizeof(_dnode) );
	root->is_root = TRUE;

	_init_list_headers( h_list, _boot_headers );
	ListView_DeleteAllItems( h_list );

	if (__is_efi_boot) {
		boot_disk_1 = boot_disk_2 = dc_efi_get_os_disk();
	} else {
		dc_get_boot_disk( &boot_disk_1, &boot_disk_2 );
	}
	if ( !fixed )
	{
		for ( node = __drives.flink;
			  node != &__drives;
			  node = node->flink ) 
		{						
			_dnode *drv = contain_record( node, _dnode, list );

			for ( sub = drv->root.vols.flink;
				  sub != &drv->root.vols;
				  sub = sub->flink ) 
			{
				dc_status *st = &contain_record(sub, _dnode, list)->mnt.info.status;

				if ( _is_removable_media(drv->root.dsk_num) )
				{
					is_gpt = (dc_is_gpt_disk(drv->root.dsk_num) == 1);
					//mbr_ldr = (dc_get_mbr_config(drv->root.dsk_num, NULL, &conf) == ST_OK);
					mbr_ldr = (dc_has_dc_mbr(drv->root.dsk_num) == ST_OK);
					//efi_ldr = (dc_get_efi_config(drv->root.dsk_num, NULL, &conf) == ST_OK);
					efi_ldr = (dc_is_dcs_on_disk(drv->root.dsk_num) == 1);

					_set_device_item(
							h_list, lvcount++, drv->root.dsk_num, st->mnt_point, 
							drv->root.dsk_num == sel ? root : NULL, FALSE, 
							is_gpt, mbr_ldr, efi_ldr, 
							drv->root.dsk_num == boot_disk_1
						);
				}
			}
		}
	} 
	else 
	{
		for ( ; k < 100; k++ ) 
		{
			if ( dc_dsk_get_size(k, 0) )
			{
				if (! _is_removable_media(k) )
				{
					is_gpt = (dc_is_gpt_disk(k) == 1);
					//mbr_ldr = (dc_get_mbr_config(k, NULL, &conf) == ST_OK);
					mbr_ldr = (dc_has_dc_mbr(k) == ST_OK);
					//efi_ldr = (dc_get_efi_config(k, NULL, &conf) == ST_OK);
					efi_ldr = (dc_is_dcs_on_disk(k) == 1);

					_set_device_item(
							h_list, lvcount++, k, NULL, k == sel ? root : NULL, TRUE, 
						    is_gpt, mbr_ldr, efi_ldr,
						    k == boot_disk_1
						);
				}
			}
		}
	}
	ListView_SetBkColor( h_list, GetSysColor(COLOR_BTNFACE) );
	ListView_SetTextBkColor( h_list, GetSysColor(COLOR_BTNFACE) );
	ListView_SetExtendedListViewStyle( h_list, LVS_EX_FLATSB | LVS_EX_FULLROWSELECT );

	if ( ListView_GetItemCount(h_list) == 0 )
	{
		_list_insert_item( h_list, 0, 0, L"Volumes not found", 0 );
		EnableWindow( h_list, FALSE );
	}

}


BOOL _list_part_by_disk_id(
		HWND hwnd,
		int  disk_id
	)
{
	list_entry *node;
	list_entry *sub;

	wchar_t s_id[MAX_PATH];
	wchar_t s_size[MAX_PATH];

	int count = 0;
	int item = 0;

	_init_list_headers( hwnd, _part_by_id_headers );
	ListView_DeleteAllItems(hwnd);

	for ( node = __drives.flink;
				node != &__drives;
				node = node->flink
			) 
	{
		list_entry *vols = 
		&contain_record(node, _dnode, list)->root.vols;

		for ( sub = vols->flink;
					sub != vols;
					sub = sub->flink
				)
		{
			dc_status *status = &contain_record(sub, _dnode, list)->mnt.info.status;
			if ( (status->flags & F_ENABLED) && (status->disk_id) )
			{							
				dc_format_byte_size(
					s_size, countof(s_size), status->dsk_size
					);

				_snwprintf( s_id, countof(s_id), L"%.08X", status->disk_id );

				_list_insert_item(
					hwnd, count, 0, status->mnt_point, status->disk_id == disk_id ? LVIS_SELECTED : FALSE
					);

				_list_set_item(hwnd, count, 1, s_size);
				_list_set_item(hwnd, count, 2, s_id);

				if (status->disk_id == disk_id) item = count;
				count++;				

			}
		}
	}
	if ( !count ) 
	{
		_list_insert_item( hwnd, count, 0, L"Partitions not found", 0 );
	}
	
	ListView_SetBkColor( hwnd, GetSysColor(COLOR_BTNFACE) );
	ListView_SetTextBkColor( hwnd, GetSysColor(COLOR_BTNFACE) );

	ListView_SetExtendedListViewStyle( hwnd, LVS_EX_FLATSB | LVS_EX_FULLROWSELECT );
	ListView_SetSelectionMark( hwnd, item );

	return count;

}

