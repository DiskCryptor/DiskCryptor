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
#include <shlobj.h>

#include "main.h"
#include "ui_utils.h"
#include "efiinst.h"

#include "hotkeys.h"

void *wnd_get_long(
		HWND h_wnd, 
		int  index
	)
{
	#pragma warning(disable:4312)
		return (void*)GetWindowLongPtr( h_wnd, index );
	#pragma warning(default:4312)
}


void *wnd_set_long(
		HWND  h_wnd, 
		int   index, 
		void *ptr
	)
{
	#pragma warning(disable:4312 4244)
		return (void*)SetWindowLongPtr( h_wnd, index, (LONG_PTR)ptr );
	#pragma warning(default:4312 4244)
}


DWORD _cl(
		int  index,
		char prc
	)
{
	DWORD color = GetSysColor(index);

	BYTE r = (BYTE)color;	
	BYTE g = (BYTE)(color >> 8);
	BYTE b = (BYTE)(color >> 16);

	r += ((255 - r) * prc) / 100;
	g += ((255 - g) * prc) / 100;
	b += ((255 - b) * prc) / 100;

	return (r | (g << 8) | (b << 16));

}


BOOL _ui_init(
		HINSTANCE h_inst
	)
{
	HBITMAP undisk      = LoadBitmap( h_inst, MAKEINTRESOURCE( IDB_UNDISK ) );
	HBITMAP undisk_mask = LoadBitmap( h_inst, MAKEINTRESOURCE( IDB_UNDISK_MASK ) );

	HBITMAP disk        = LoadBitmap( h_inst, MAKEINTRESOURCE( IDB_DISK ) );
	HBITMAP disk_mask   = LoadBitmap( h_inst, MAKEINTRESOURCE( IDB_DISK_MASK ) );

	HBITMAP cdrom       = LoadBitmap( h_inst, MAKEINTRESOURCE( IDB_CDROM ) );
	HBITMAP cdrom_mask  = LoadBitmap( h_inst, MAKEINTRESOURCE( IDB_CDROM_MASK ) );

	HBITMAP disk_enb    = LoadBitmap( h_inst, MAKEINTRESOURCE( IDB_ENABLED ) );

	HBITMAP check       = LoadBitmap( h_inst, MAKEINTRESOURCE( IDB_CHECK ) );
	HBITMAP check_mask  = LoadBitmap( h_inst, MAKEINTRESOURCE( IDB_CHECK_MASK ) );

	NONCLIENTMETRICS metric = { sizeof(metric) };

	InitCommonControls( );
	if ( LoadLibrary(L"riched20.dll") == 0 ) return FALSE;

	__hinst = h_inst;
	__dlg = HWND_DESKTOP;

	// x-todo: fix font dpi
	metric.lfMessageFont.lfWeight = FW_BOLD;
	metric.lfMessageFont.lfHeight = -11;
	__font_bold = CreateFontIndirect( &metric.lfMessageFont );

	metric.lfMessageFont.lfWeight = FW_DONTCARE;
	metric.lfMessageFont.lfUnderline = TRUE;
	__font_link = CreateFontIndirect( &metric.lfMessageFont );

	metric.lfMessageFont.lfHeight = -9;
	metric.lfMessageFont.lfUnderline = FALSE;
	__font_small = CreateFontIndirect( &metric.lfMessageFont );

	__img = ImageList_Create( 9, 9, ILC_MASK, 2, 2 );
	__dsk_img = ImageList_Create( 15, 11, ILC_MASK | ILC_COLOR24, 5, 5 );
	
	ImageList_Add( __img, check, check_mask );

	ImageList_Add( __dsk_img, disk, disk_mask );
	ImageList_Add( __dsk_img, undisk, undisk_mask );
	ImageList_Add( __dsk_img, disk_enb, disk_mask );
	ImageList_Add( __dsk_img, cdrom, cdrom_mask );

	__cur_arrow = LoadCursor( NULL, IDC_ARROW );
	__cur_hand  = LoadCursor( NULL, IDC_HAND );
	__cur_wait  = LoadCursor( NULL, IDC_WAIT );

	return TRUE;

}


_wnd_data *_sub_class(
		HWND hwnd,
		int  proc_idx,
		HWND dlg,
		...
	)
{
	_wnd_data *data = NULL;
	void *proc = NULL;

	if ( hwnd ) 
	{
		data = malloc(sizeof(_wnd_data));
		memset( data, 0, sizeof(_wnd_data) );
	}
	if ( data ) 
	{
		if ( proc_idx != SUB_NONE )
		{
			if ( proc_idx == SUB_KEY_PROC )    proc = _key_proc; 
			if ( proc_idx == SUB_STATIC_PROC ) proc = _static_proc; 

			if ( proc != NULL )
			{
				data->old_proc = wnd_set_long( hwnd, GWL_WNDPROC, proc );
			}
		}
		{
			int     k   = 0;
			HWND    val = dlg;
			va_list va;

			va_start( va, dlg );
			while ( val != HWND_NULL )
			{
				data->dlg[k] = val;
				val = va_arg( va, HWND );				
				k++;
			}
			va_end(va);
		}
		wnd_set_long( hwnd, GWL_USERDATA, data );
		return data;

	} else return NULL;

}


void __unsub_class(
		HWND hwnd
	)
{
	_wnd_data *data = wnd_get_long( hwnd, GWL_USERDATA );
	int k = 0;

	if ( data )
	{		
		while ( data->dlg[k] && ( data->dlg[k] != HWND_NULL ) )
		{
			DestroyWindow( data->dlg[k] );
			k++;
		}
		free( data );
		SetWindowLongPtr( hwnd, GWL_USERDATA, 0 );
	}
}


LRESULT 
CALLBACK 
_key_proc(
		HWND   hwnd,
		UINT   msg,
		WPARAM wparam,
		LPARAM lparam
	)
{
	char resolve;
	wchar_t text[500] = { 0 };

	int shift = 0;
	_wnd_data *data = wnd_get_long( hwnd, GWL_USERDATA );

	if ( !data ) return 1L;

	if ( _keyup(msg) || _keydown(msg) ) 
	{
		wchar_t key[100] = { 0 };

		if ( GetKeyState(VK_CONTROL) < 0 )	shift |= MOD_CONTROL;
		if ( GetKeyState(VK_SHIFT) < 0 )	shift |= MOD_SHIFT;
		if ( GetKeyState(VK_MENU) < 0 )		shift |= MOD_ALT;

		resolve = _key_name( wparam, shift, key );
		if ( _keyup(msg) && !resolve ) 
		{
			GetWindowText( hwnd, text, countof(text) );				
			if ( text[wcslen(text) - 2] == L'+' )
			{
				SetWindowText(hwnd, STR_NULL);
			}
			return 0L;
		}
		if ( !_keyup(msg) && resolve )
		{
			data->vk = MAKELONG(shift, wparam);
		}
		SetWindowText( hwnd, key );
		return 0L;

	}
	CallWindowProc( data->old_proc, hwnd, msg, wparam, lparam );
	return 1L;	

}


LRESULT 
CALLBACK 
_static_proc(
		HWND   hwnd,
		UINT   msg,
		WPARAM wparam,
		LPARAM lparam
	)
{
	int code = HIWORD(wparam);
	int rlt  = 1;

	_wnd_data *data = wnd_get_long(hwnd, GWL_USERDATA);
	if ( !data ) return 1L;

	switch ( msg ) 
	{
		case BM_GETCHECK :
		{
			rlt = (data->state) ? BST_CHECKED : BST_UNCHECKED;
		}
		break;

		case BM_SETCHECK :
		{
			data->state = wparam ? BST_CHECKED : BST_UNCHECKED;
			rlt = 0; 
		}
		break;

		case WM_KEYUP: 
		{
			if (wparam != VK_SPACE) break;
		}

		case WM_LBUTTONDBLCLK :
		case WM_LBUTTONDOWN :

			_change_page(hwnd, 0);
			rlt = 0;
			break;

	}
	CallWindowProc( data->old_proc, hwnd, msg, wparam, lparam );
	return rlt;	

}


BOOL 
CALLBACK 
__sub_enum(
		HWND   hwnd,
		LPARAM lParam
	)
{
	wchar_t name[MAX_PATH];

	if ( !GetClassName(hwnd, name, MAX_PATH) ) return 1L;
	if ( (wcscmp(name, L"SysListView32") == 0 )	|| 
		 (wcscmp(name, L"ComboBox") == 0 )		||
		 (wcscmp(name, L"Button") == 0) 
		 
	) return 1L;

	if ( GetWindowLong(hwnd, GWL_STYLE) & BS_OWNERDRAW )
	{
		_sub_class( hwnd, SUB_STATIC_PROC, HWND_NULL );
	}
	return 1L;

}


BOOL 
CALLBACK 
__enable_enum(
		HWND   hwnd,
		LPARAM lparam
	)
{
	EnableWindow( hwnd, (BOOL)(lparam) );
	InvalidateRect( hwnd, NULL, TRUE );

	return 1L;

}

void _enb_but_this(
		HWND parent,
		int  skip_id,
		BOOL enable
	)
{
	EnumChildWindows(parent, __enable_enum, enable);
	EnableWindow(GetDlgItem(parent, skip_id), TRUE);

}


int _find_list_item(
		HWND     h_list,
		wchar_t *text,
		int      column
	)
{
	int item = 0;
	wchar_t tmpb[MAX_PATH];
	int count = ListView_GetItemCount( h_list );

	if ( count )
	{
		for ( ;item < count; item++ ) 
		{
			ListView_GetItemText( h_list, item, column, tmpb, MAX_PATH );
			if ( !wcscmp(text, tmpb) )
			{
				return item;
			}
		}
	}
	return -1;
}


void _tray_icon(
		char install
	)
{
	if ( install )
	{
		NOTIFYICONDATA ni = 
		{	
			sizeof(ni), 
			__dlg, IDI_ICON_TRAY, NIF_MESSAGE | NIF_ICON | NIF_TIP, WM_APP + WM_APP_TRAY,
			LoadIcon(__hinst, MAKEINTRESOURCE(IDI_ICON_TRAY)),
			DC_NAME
		};
		Shell_NotifyIcon( NIM_ADD, &ni );
	} else 
	{
		NOTIFYICONDATA ni = { sizeof(ni), __dlg, IDI_ICON_TRAY };
		Shell_NotifyIcon( NIM_DELETE, &ni );
	}
}


BOOL 
CALLBACK 
_enum_proc(
		HWND   hwnd,
		LPARAM lparam
	)
{
	wchar_t caption[200];
	void *data;

	if ( *(HWND *)lparam == hwnd )
	{
		return 1L;
	}
	data = wnd_get_long( hwnd, GWL_USERDATA );
	if ( data )
	{
		GetWindowText( hwnd, caption, countof(caption) );
		if ( wcscmp(caption, DC_NAME) == 0 )
		{
			*(HWND *)lparam = hwnd;
		}
	}
	return 1L;
}


int _init_combo(
		HWND        hwnd, 
		const _init_list *list,
		DWORD       val,
		BOOL        or,
		int         bits
	)
{
	int count = 0;
	int item = 0;

	while ( wcslen(list[count].display) )
	{
		SendMessage( hwnd, (UINT)CB_ADDSTRING, 0, (LPARAM)list[count].display );
		if (!or )
		{
			if (list[count].val == val)
			{
				item = count;
			}
		} 
		else if(bits == -1) {
			if (val & list[count].val)
			{
				item = count;
			}
		} 
		else {
			if ((val & bits) == list[count].val)
			{
				item = count;
			}
		}		
		count++;
	}
	SendMessage( hwnd, CB_SETCURSEL, item, 0 );
	return item;
}


int _get_combo_val(
		HWND        hwnd, 
		const _init_list *list
	)
{
	int count = 0;
	wchar_t text[MAX_PATH];

	GetWindowText( hwnd, text, countof(text) );
	while ( wcslen(list[count].display) )
	{
		if ( !wcscmp(list[count].display, text) )
		{
			return list[count].val;
		}
		count++;
	}
	return -1;
}


wchar_t *_get_text_name(
		int         val, 
		const _init_list *list
	)
{
	int count = 0;
	while (wcslen(list[count].display)) 
	{
		if (list[count].val == val) 
			return list[count].display;

		count++;
	}
	return NULL;

}


int 
CALLBACK 
_browse_callback(
		HWND   hwnd,
		UINT   msg,
		LPARAM lparam,
		LPARAM data
	)
{
	WIN32_FIND_DATA file_data;
	HANDLE h_find;

	int count = -1;
	wchar_t path[MAX_PATH];

	if ( msg == BFFM_SELCHANGED )
	{
		if ( SHGetPathFromIDList((PIDLIST_ABSOLUTE)lparam, path) )
		{
			_set_trailing_slash(path);
			wcscat(path, L"*.*");

			h_find = FindFirstFile( path, &file_data );
			if ( h_find != INVALID_HANDLE_VALUE )
			{
				while ( FindNextFile(h_find, &file_data) != 0 )
				{
					count++;
				}
				FindClose( h_find );
			}
		}
	}
	return 1L;
}


BOOL _folder_choice(
		HWND     hwnd, 
		wchar_t *path, 
		wchar_t *title
	)
{
	PIDLIST_ABSOLUTE pid;
	BROWSEINFO binfo = { hwnd };

	binfo.pszDisplayName = path;
	//binfo.lpfn           = _browse_callback; 
	binfo.ulFlags        = BIF_NEWDIALOGSTYLE;
	binfo.lpszTitle      = title;

	pid = SHBrowseForFolder( &binfo );
	if ( pid )
	{
		if ( SHGetPathFromIDList(pid, path) )
		{
			return TRUE;
		}
	}
	return FALSE;
}


void _init_list_headers(
		HWND      hwnd,
		_colinfo *cols
	)
{
	LVCOLUMN lvcol = { 0 };
	int k = 0;

	if ( !ListView_GetItemCount(hwnd) )
	{	
		lvcol.mask  = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		if ( cols[k].row_images )
		{
			lvcol.fmt |= LVCFMT_BITMAP_ON_RIGHT;
		}
		while ( wcslen(cols[k].name) != 0 ) 
		{ 
			lvcol.iSubItem  = k;
			lvcol.pszText   = cols[k].name;
			lvcol.cx        = cols[k].width;
			lvcol.fmt      |= cols[k].align;

			ListView_InsertColumn( hwnd, k, &lvcol );
			k++;
		}
	}
}


BOOL _open_file_dialog(
		HWND     h_parent,
		wchar_t *s_path,
		int      size,
		wchar_t *s_title
	)
{
	OPENFILENAME ofn = { sizeof(ofn), h_parent };

	ofn.lpstrFile  = s_path;
	ofn.nMaxFile   = size;

	ofn.lpstrTitle = s_title;
	ofn.FlagsEx    = OFN_EX_NOPLACESBAR;

	if (GetOpenFileName(&ofn))
	{
		return TRUE;
	} else {
		return FALSE;
	}	
}


BOOL _save_file_dialog(
		HWND     h_parent,
		wchar_t *s_path,
		int      size,
		wchar_t *s_title
	)
{
	OPENFILENAME ofn = { sizeof(ofn), h_parent };
	ofn.lpstrFile = s_path;

	ofn.lpstrTitle = s_title;	
	ofn.nMaxFile  = size;	

	ofn.Flags = OFN_FORCESHOWHIDDEN | OFN_HIDEREADONLY;
	ofn.FlagsEx = OFN_EX_NOPLACESBAR;

	if ( GetSaveFileName(&ofn) )
	{
		return TRUE;
	} else {
		return FALSE;
	}
}



BOOL _is_warning_item(
		LPARAM lparam 
	) 
{
	_dnode *info = pv(lparam);

	if (info && (info->mnt.info.status.flags & F_FORMATTING))
	return TRUE;	
	return FALSE;

}


BOOL _is_active_item(
		LPARAM lparam 
	)
{
	_dnode *info = pv(lparam);

	if (info &&
		!info->is_root && 
		info->mnt.info.status.flags & F_UNSUPRT
		)
	return FALSE;
	return TRUE;

}


BOOL _is_root_item( 
		LPARAM lparam 
	)
{
	_dnode *info = pv(lparam);
	return (
		info ? info->is_root : FALSE
	);
}


BOOL_is_enabled_item(
		LPARAM lparam 
	)
{
	_dnode *info = pv(lparam);
	return (
		info ? info->mnt.info.status.flags & F_ENABLED : FALSE
	);
}


BOOL _is_marked_item(
		LPARAM lparam 
	)
{
	_dnode *info = pv(lparam);
	return (
		info ? info->is_root && (info->root.dsk_name[0] == '\0') : FALSE
	);
}


BOOL _is_splited_item(
		LPARAM lparam 
	)
{
	_dnode *info = pv(lparam);
	return (
		info ? info->root.info.dsk_num > 1 : FALSE
	);
}


BOOL _is_cdrom_item( 
		LPARAM lparam 
	)
{
	_dnode *info = pv(lparam);
	return (
		info ? info->mnt.info.status.flags & F_CDROM : FALSE
	);
}


BOOL _is_curr_in_group( 
		HWND h_tab 
	)
{
	_tab_data *tab;

	tab = wnd_get_long(GetParent(h_tab), GWL_USERDATA);
	return (
		tab && (tab->curr_tab == TabCtrl_GetCurSel(h_tab))
	);

}


BOOL _is_icon_show( 
		HWND   h_list,
		int    idx
	)
{
	WINDOWINFO winfo = { 0 };
	wchar_t    s_header[200] = { STR_HEAD_NO_ICONS };

	winfo.cbSize = sizeof( winfo );
	GetWindowInfo( h_list, &winfo );

	if (idx != -1)
	{
		_get_header_text( 
			h_list, idx, s_header, countof(s_header) 
			);
	}

	return (
		s_header[wcslen(s_header) - 1] == L' '
	);
}


BOOL _is_boot_device(
		vol_inf *vol
	)
{
	wchar_t boot_dev[MAX_PATH];
	dc_get_boot_device( boot_dev );

	if ( vol == NULL ) return FALSE;

	return (
		( vol->status.flags & F_SYSTEM ) || (! wcscmp(vol->device, boot_dev) )
	);
}


BOOL _is_removable_media(
		int dsk_num
	)
{
	dc_disk_p *d_info;
	BOOL       rem_media = FALSE;

	d_info = dc_disk_open( dsk_num, FALSE );
	if ( d_info != NULL )
	{
		rem_media = d_info->media == RemovableMedia;
		dc_disk_close( d_info );
	} 
	else {
		__error_s( __dlg, L"Error get volume information", ST_ACCESS_DENIED );
	}
	return rem_media;

}


HWND _get_next_enabled_item(
		HWND h_dialog,
		HWND h_first,
		BOOL b_next
	)
{
	HWND h_last_item = h_first;
	HWND h_find_item;

	do 
	{
		h_find_item = GetNextDlgTabItem( h_dialog, h_last_item, ! b_next );
		if ( h_find_item == h_first )
		{
			break;
		}
		if ( IsWindowEnabled( h_find_item ) ) 
		{
			return h_find_item;
		}
		h_last_item = h_find_item;

	} while ( 1 );

	return h_first;
}


HWND _get_next_enabled_tab_item(
		HWND h_dialog,
		HWND h_first_item,
		BOOL b_next
	)
{
	return 
	(
		IsWindowEnabled( h_first_item ) ? 
		h_first_item : GetNextDlgTabItem( h_dialog, h_first_item, ! b_next )
	);
}


HWND _get_last_tab_item(
		HWND h_dialog,
		HWND h_first_item
	)
{
	HWND h_last = h_first_item;
	HWND h_find;

	if ( h_first_item == HWND_NULL ) return HWND_NULL;
	while (	( h_find = GetNextDlgTabItem( h_dialog, h_last, FALSE ) ) != h_first_item )
	{
		h_last = h_find;
	}
	return h_last;
}


_focus_tab(
		int  h_parent_first_tab_id,
		HWND h_parent,
		HWND h_page,
		HWND h_page_first_tab,
		BOOL b_next
	)
{
	HWND h_current_tab   = GetFocus( );
	HWND h_next_tab      = GetNextDlgTabItem( GetParent( h_current_tab ), h_current_tab, ! b_next );

	HWND h_wiz_first_tab = _get_next_enabled_tab_item( h_parent, GetDlgItem( h_parent, h_parent_first_tab_id ), b_next );
	HWND h_wiz_last_tab  = _get_last_tab_item( h_parent, h_wiz_first_tab );

	HWND h_page_last_tab = _get_last_tab_item( h_page, h_page_first_tab );

	if ( b_next )
	{
		if ( ( h_current_tab == h_wiz_last_tab ) && ( h_page_first_tab != HWND_NULL ) )
		{
			h_next_tab = h_page_first_tab;
		}
		if ( h_current_tab == h_page_last_tab )
		{
			h_next_tab = h_wiz_first_tab;
		}
	} else {
		if ( ( h_current_tab == h_wiz_first_tab ) && ( h_page_first_tab != HWND_NULL ) )
		{
			h_next_tab = h_page_last_tab;
		}
		if ( h_current_tab == h_page_first_tab )
		{
			h_next_tab = h_wiz_last_tab;
		}
	}
	SetFocus( h_next_tab );

}