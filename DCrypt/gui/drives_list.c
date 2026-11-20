/*
    *
    * DiskCryptor - open source partition encryption tool
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
#include "drives_list.h"

#include "threads.h"
#include "disk_name.h"

void 
_add_drive_node(
		_dnode    *exist_node,
		drive_inf *new_drv,
		vol_inf   *vol, 
		int        disk_number
	)
{
	wchar_t drvname[MAX_PATH];

	wchar_t fs[MAX_PATH]    = { 0 };
	wchar_t label[MAX_PATH] = { 0 };

	wchar_t path[MAX_PATH];

	list_entry *node;
	BOOL root_exists = FALSE;

	_dnode *root;
	_dnode *mnt;

	mnt = exist_node;
	if ( mnt == NULL )
	{
		mnt = malloc( sizeof(_dnode) );
		memset( mnt, 0, sizeof(_dnode) );
	}
	mnt->exists = TRUE;
	memcpy( &mnt->mnt.info, vol, sizeof(vol_inf) );

	/* a locked volume fails every read/write (keys erased at hibernation): do not make
	   the file system touch it, keep the last known label / file system name */
	if (! DC_IS_LOCKED(vol->status.flags) )
	{
		_snwprintf( path, countof(path), L"%s\\", vol->status.mnt_point );
		GetVolumeInformation( path, label, countof(label), 0, 0, 0, fs, countof(fs) );

		wcscpy( mnt->mnt.label, label );
		wcscpy( mnt->mnt.fs, fs );
	}

	if (! exist_node )
	{
		dc_get_hw_name(
			disk_number, vol->status.flags & F_CDROM, drvname, countof(drvname)
			);

		if (! ( vol->status.flags & F_CDROM ) )
		{
			for ( node  = __drives.flink;
				  node != &__drives;
				  node  = node->flink ) 
			{
				root = contain_record(node, _dnode, list);
				if ( root->root.dsk_num == disk_number )
				{
					root_exists = TRUE;
					break;
				}
			}
		}
		mnt->is_root = FALSE;
		memcpy( &mnt->root.info, new_drv, sizeof(drive_inf) );

		if (! root_exists )
		{
			root = malloc(sizeof(_dnode));	
			root->is_root = TRUE;

			memcpy(&root->mnt.info, vol, sizeof(vol_inf));
			memcpy(&root->root.info, new_drv, sizeof(drive_inf));

			wcscpy(root->root.dsk_name, drvname);
			root->root.dsk_num = disk_number;	

			_init_list_head(&root->root.vols);
			_insert_tail_list(&__drives, &root->list);

		} 
		_insert_tail_list(&root->root.vols, &mnt->list);

	} 		
	if ( vol->status.flags & F_SYNC && _create_act_thread(mnt, -1, -1) == NULL )
	{
		_create_act_thread(mnt, ACT_ENCRYPT, ACT_PAUSED);
	}
}


_dnode *_scan_vols_tree(
		vol_inf *vol,
		int     *count
	)
{
	list_entry *del;
	list_entry *node;
	list_entry *sub;	

	for ( node = __drives.flink;
		  node != &__drives
		  ;
		) 
	{
		_dnode *root = contain_record(node, _dnode, list);
		if ( count )
		{
			*count += 1;
		}
		for ( sub = root->root.vols.flink;
			  sub != &root->root.vols
			  ; 
			) 
		{
			_dnode *mnt = contain_record(sub, _dnode, list);
			if ( count ) 
			{
				*count += 1;
			}				
			if (! vol )
			{
				if (! mnt->exists )
				{
					del = sub;
					sub = sub->flink;

					_remove_entry_list(del);
					free(del);

					continue;
				}
			} else {
				if ( ( wcscmp(mnt->mnt.info.device, vol->device) == 0 ) && (! mnt->exists) ) 
				{
					return mnt;
				}
			}
			sub = sub->flink;
		}
		if (_is_list_empty(sub)) 
		{
			del = node;
			node = node->flink;

			_remove_entry_list(del);
			free(del);

			continue;
		}
		node = node->flink;
	}
	return NULL;

}


int _list_volumes(
		list_entry *volumes
	)
{
	DWORD drives = 0;

	u32 k     = 2;
	int count = 0;

	vol_inf   volinfo;
	drive_inf drvinfo;

	if ( dc_first_volume( &volinfo ) == ST_OK )
	{
		do 
		{
			_dnode *mnt = _scan_vols_tree( &volinfo, NULL );
			if (! mnt )
			{
				if ( volinfo.status.flags & F_CDROM )
				{
					_add_drive_node( NULL, &drvinfo, &volinfo, 0 );
					continue;
				}
				if ( dc_get_drive_info( volinfo.w32_device, &drvinfo ) != ST_OK ) 
				{
					continue;
				}
				for ( k = 0; k < drvinfo.dsk_num; k++ ) 
				{
					_add_drive_node( NULL, &drvinfo, &volinfo, drvinfo.disks[k].number );
				}
			} else 
			{
				do {
					_add_drive_node( mnt, NULL, &volinfo, 0 );
				} while ( (mnt = _scan_vols_tree(&volinfo, NULL)) != NULL );
			}

		} while ( dc_next_volume(&volinfo) == ST_OK );
	}
	_scan_vols_tree(NULL, &count);
	return count;

}


