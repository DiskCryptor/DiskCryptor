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
#include "dlg_code.h"

#ifdef _M_ARM64
#include "xts_small.h"
#else
#include "xts_fast.h"
#endif
#include "pass.h"

_colinfo _main_headers[ ] =
{
	{ STR_SPACE,	120,	LVCFMT_LEFT,	TRUE	},
	{ L"Size",		74,		LVCFMT_RIGHT,	FALSE	},
	{ L"Label",		94,		LVCFMT_RIGHT,	FALSE	},
	{ L"Type",		43,		LVCFMT_RIGHT,	FALSE	},
	{ L"Status",	88,		LVCFMT_RIGHT,	FALSE	},
	{ STR_SPACE,	65,		LVCFMT_RIGHT,	FALSE	},
	{ STR_NULL }
};

_colinfo _boot_headers[ ] =
{
	{ L"Device ",		115,	LVCFMT_LEFT,	TRUE	},
	{ L"Size",			60,		LVCFMT_RIGHT,	FALSE	},
	{ L"Bootloader",	125,	LVCFMT_RIGHT,	FALSE	},
	{ L"Disk type",		70,		LVCFMT_RIGHT,	FALSE	},
	{ STR_NULL }
};

_colinfo _part_by_id_headers[ ] =
{
	{ L"Volume ",	115,	LVCFMT_LEFT,	TRUE	},
	{ L"Size",		60,		LVCFMT_RIGHT,	FALSE	},
	{ L"Disk ID",	90,		LVCFMT_RIGHT,	FALSE	},
	{ STR_SPACE,	110,	LVCFMT_RIGHT,	FALSE	},
	{ STR_NULL }
};

_colinfo _benchmark_headers[ ] =
{
	{ L"Cipher",	160,	LVCFMT_LEFT,	FALSE	},
	{ L"Mode",		60,		LVCFMT_RIGHT,	FALSE	},
	{ L"Speed",		90,		LVCFMT_RIGHT,	FALSE	},
	{ STR_NULL }
};

_colinfo _kdf_benchmark_headers[ ] =
{
	{ L"KDF",		160,	LVCFMT_LEFT,	FALSE	},
	{ L"Memory",	60,		LVCFMT_RIGHT,	FALSE	},
	{ L"Iter",		40,		LVCFMT_RIGHT,	FALSE	},
	{ L"Time",		80,		LVCFMT_RIGHT,	FALSE	},
	{ STR_NULL }
};

wchar_t *_info_table_items[ ] =
{
	L"Symbolic Link",
	L"Device",
	STR_SPACE,
	L"Cipher",
	//L"Encryption mode",
	L"Header KDF",
	L"Header Format",
	STR_NULL
};

wchar_t *_act_table_items[ ] =
{
	L"Done:",
	L"Speed:",
	STR_SPACE,
	L"Estimated:",
	L"Elapsed:",
	STR_NULL
};

_static_view pass_gr_ctls[ ] =
{
	{ IDC_GR_SMALL,	 0, 0 }, { IDC_GR_CAPS,	 0, 0 },
	{ IDC_GR_DIGITS, 0, 0 }, { IDC_GR_SPACE, 0, 0 },
	{ IDC_GR_SPEC,	 0, 0 }, { IDC_GR_ALL,	 0, 0 },
	{ -1, 0, 0 }
};

_static_view pass_pe_ctls[ ] =
{
	{ IDC_PE_NONE,   0, 0 }, { IDC_PE_LOW,  0, 0 },
	{ IDC_PE_MEDIUM, 0, 0 }, { IDC_PE_HIGH, 0, 0 },
	{ IDC_PE_UNCRK,  0, 0 }, 
	{ -1, 0, 0 }
};

const _init_list cipher_names[ ] =
{
	{ CF_AES,					L"AES (XTS Mode)"					},
	{ CF_TWOFISH,				L"Twofish (XTS Mode)"				},
	{ CF_SERPENT,				L"Serpent (XTS Mode)"				},
	{ CF_AES_TWOFISH,			L"AES-Twofish (XTS Mode)"			},
	{ CF_TWOFISH_SERPENT,		L"Twofish-Serpent (XTS Mode)"		},
	{ CF_SERPENT_AES,			L"Serpent-AES (XTS Mode)"			},
	{ CF_AES_TWOFISH_SERPENT,	L"AES-Twofish-Serpent (XTS Mode)"	},
	{ 0, STR_NULL }
};

const _init_list kdf_names_ex[] =
{
    { KDF_DEFAULT, L"Standard Pkcs5.2 & Default Argon2id" },
    { KDF_ALL, L"Try all KDF's    >>> Very Slow <<<"      },

    {  0, L"Pkcs5.2 SHA-512 (0 - Legacy)"				  }, //    2ms

    {  1, L"Argon2id (1 - Minimum) [64 MiB]"			  }, //   33ms
    {  2, L"Argon2id (2 - Low) [128 MiB]"				  }, //   62ms
    {  3, L"Argon2id (3 - Moderate) [192 MiB]"			  }, //  115ms
    {  4, L"Argon2id (4 - Standard) [256 MiB]"			  }, //  154ms
    {  5, L"Argon2id (5 - Recommended) [384 MiB]"		  }, //  281ms
    {  6, L"Argon2id (6 - Enhanced) [512 MiB]"			  }, //  379ms
    {  7, L"Argon2id (7 - Hardened) [768 MiB]"			  }, //  579ms
    {  8, L"Argon2id (8 - High Cost) [1024 MiB]"		  }, //  943ms
    {  9, L"Argon2id (9 - Very High Cost) [1536 MiB]"	  }, // 1506ms
    { 10, L"Argon2id (10 - Extreme Cost) [2048 MiB]"	  }, // 2185ms

    {  0, STR_NULL }
};

/* kdf_names points to kdf_names_ex[2], skipping the "Automatic" entries */
const _init_list *kdf_names = &kdf_names_ex[2];

const _init_list keyfile_mix_modes[ ] =
{
	{ KEYFILE_MIX_LEGACY,		L"Additive (Legacy)"			},
	{ KEYFILE_MIX_HASHED,		L"Canonical (Recommended)"		},
	{ 0, STR_NULL }
};

const _init_list wipe_modes[ ] =
{
	{ WP_NONE,		L"None"										},
	{ WP_DOD_E,		L"US DoD 5220.22-M (8-306. / E)"			},
	{ WP_DOD,		L"US DoD 5220.22-M (8-306. / E, C and E)"	},
	{ WP_GUTMANN,	L"Gutmann mode"								},
	{ 0, STR_NULL }
};

const _init_list kb_layouts[ ] =
{
	{ LDR_KB_QWERTY, L"QWERTY" },
	{ LDR_KB_QWERTZ, L"QWERTZ" },
	{ LDR_KB_AZERTY, L"AZERTY" },
	{ 0, STR_NULL }
};

const _init_list auth_type[ ] =
{
	{ LDR_LT_GET_PASS,										L"Password request"						},
	{ LDR_LT_GET_PASS | LDR_LT_USB_KEY,						L"Password and USB keyfile"				},
	{ LDR_LT_USB_KEY,										L"USB keyfile only"		                },
	{ LDR_LT_GET_PASS | LDR_LT_EMBED_KEY,					L"Password and Embedded keyfile"		},
	{ LDR_LT_EMBED_KEY,										L"Embedded keyfile only"		        },
	{ 0, STR_NULL }
};

const _init_list show_pass[ ] =
{
	{ TRUE,			L"Hide entered password"				},
	{ LDR_LT_DSP_PASS,	L"Display entered password as \"*\""	},
	{ 0, STR_NULL }
};

const _init_list auth_tmount[ ] =
{
	{ 0,	L"Disabled"		},
	{ 3,	L"3 sec"		},
	{ 5,	L"5 sec"		},
	{ 7,	L"7 sec"		},
	{ 10,	L"10 sec"		},
	{ 20,	L"20 sec"		},
	{ 30,	L"30 sec"		},
	{ 50,	L"50 sec"		},
	{ 120,	L"2 minutes"	},
	{ 180,	L"3 minutes"	},
	{ 300,	L"5 minutes"	},
	{ 0,STR_NULL }
};

const _init_list boot_type_ext[ ] = // external
{
	{ LDR_BT_MBR_FIRST,		L"First disk"									},
	{ LDR_BT_AP_PASSWORD,	L"First partition with appropriate password"	},
	{ LDR_BT_DISK_ID,		L"Specified partition"							},
	{ 0, STR_NULL }
};

const _init_list boot_type_efi[ ] =
{
	{ LDR_BT_MBR_FIRST,		L"First disk"									},
	{ LDR_BT_AP_PASSWORD,	L"First partition with appropriate password"	},
	{ LDR_BT_DISK_ID,		L"Specified partition"							},
	{ LDR_BT_MBR_BOOT,		L"Boot disk"									},
	{ 0, STR_NULL }
};

const _init_list boot_type_all[ ] =
{
	{ LDR_BT_MBR_FIRST,		L"First disk"									},
	{ LDR_BT_AP_PASSWORD,	L"First partition with appropriate password"	},
	{ LDR_BT_DISK_ID,		L"Specified partition"							},
	{ LDR_BT_MBR_BOOT,		L"Boot disk"									},
	{ LDR_BT_ACTIVE,		L"Active partition"								},
	{ 0, STR_NULL }
};

const _init_list bad_pass_act_efi[ ] =
{
	{ FALSE,				L"Halt system"					},
	{ LDR_ET_REBOOT,		L"Reboot system"				},
	{ LDR_ET_EXIT_TO_BIOS,	L"Exit to Firmware"				},
	{ LDR_ET_RETRY,			L"Retry authentication"			},
	{ LDR_ET_MBR_BOOT,		L"Load Boot Disk"				},
	{ 0, STR_NULL }
};

const _init_list bad_pass_act[ ] =
{
	{ FALSE,				L"Halt system"					},
	{ LDR_ET_REBOOT,		L"Reboot system"				},
	{ LDR_ET_BOOT_ACTIVE,	L"Boot from active partition"	},
	{ LDR_ET_EXIT_TO_BIOS,	L"Exit to BIOS"					},
	{ LDR_ET_RETRY,			L"Retry authentication"			},
	{ LDR_ET_MBR_BOOT,		L"Load Boot Disk"				},
	{ 0, STR_NULL }
};

const _init_list loader_type_mbr[ ] =
{
	{ CTL_LDR_HDD,		L"HDD master boot record"					},
	{ CTL_LDR_STICK,	L"Bootable partition (USB-Stick, etc)"		},
	{ CTL_LDR_ISO,		L"ISO bootloader image"						},
	{ CTL_LDR_PXE,		L"Bootloader image for PXE network booting"	},
	{ 0, STR_NULL }
};

const _init_list loader_type_efi[ ] =
{
	{ CTL_LDR_HDD,		L"EFI partition on HDD"						},
	{ CTL_LDR_STICK,	L"Removable media (USB-Stick, etc)"			},
	{ CTL_LDR_ISO,		L"ISO bootloader image"						},
	{ CTL_LDR_PXE,		L"Boot files for PXE network booting"		},
	{ 0, STR_NULL }
};

const _init_list pass_status[ ] =
{
	{ ST_PASS_SPRS_SYMBOLS,		L" Used suppressed symbols on this layout"		},
	{ ST_PASS_EMPTY,			L" Pass is empty"								},
	{ ST_PASS_NOT_CONFIRMED,	L" The password was not correctly confirmed"	},
	{ ST_PASS_EMPTY_CONFIRM,	L" Confirm is empty"							},
	{ ST_PASS_EMPTY_KEYLIST,	L" Keyfiles list is empty"						},
	{ ST_PASS_CORRECT,			L" Ready"										},
	{ 0, STR_NULL }
};

const _ctl_init hotks_chk[ ] =
{
	{ STR_NULL, IDC_KEY_MOUNTALL	},
	{ STR_NULL, IDC_KEY_UNMOUNTALL	},
	{ STR_NULL, IDC_KEY_WIPE		},
	{ STR_NULL, IDC_KEY_BSOD		},
	{ STR_NULL, -1, -1 }
};

const _ctl_init hotks_edit[ ] =
{
	{ STR_NULL, IDC_EDIT_KEY_MOUNTALL,		0 },
	{ STR_NULL, IDC_EDIT_KEY_UNMOUNTALL,	0 },
	{ STR_NULL, IDC_EDIT_KEY_WIPE,			0 },
	{ STR_NULL, IDC_EDIT_KEY_BSOD,			0 },
	{ STR_NULL, -1, -1 }
};

const _ctl_init hotks_static[ ] =
{
	{ STR_NULL, IDC_STATIC_KEY_MOUNTALL,	0 },
	{ STR_NULL, IDC_STATIC_KEY_UNMOUNTALL,	0 },
	{ STR_NULL, IDC_STATIC_KEY_WIPE,		0 },
	{ STR_NULL, IDC_STATIC_KEY_BSOD,		0 },
	{ STR_NULL, -1, -1 }
};

HIMAGELIST	__dsk_img;
HIMAGELIST	__img;

HINSTANCE	__hinst;

HCURSOR		__cur_arrow;
HCURSOR		__cur_hand;
HCURSOR		__cur_wait;

HFONT		__font_small;
HFONT		__font_bold;
HFONT		__font_link;

HACCEL		__hacc;

HWND		__dlg;
HWND		__dlg_act_info;
HWND		__lists[10];


BOOL _list_set_item(
		HWND     h_list,
		DWORD    item,
		DWORD    subitem,
		wchar_t *text
	)
{
	LVITEM lvitem	= { LVIF_TEXT, 0, 0 };
	lvitem.pszText	= text;
	
	lvitem.iItem	= item; 
	lvitem.iSubItem	= subitem;

	return ListView_SetItem( h_list, &lvitem );

}


void _list_set_item_text(
		HWND     h_list,
		DWORD    item,
		DWORD    subitem,
		wchar_t *text
	)
{
	wchar_t curr[MAX_PATH];

	LVITEM lvitem = { 
		LVIF_TEXT, item, subitem, 0, 0, curr, countof(curr) 
	};

	ListView_GetItem( h_list, &lvitem );
	if ( wcscmp(curr, text) )
	{
		ListView_SetItemText( h_list, item, subitem, text );
	}
}



int _list_insert_col(
		HWND h_list,
		int  cx
	)
{
	LVCOLUMN lvcol = { LVCF_WIDTH, 0 };			
	lvcol.cx = cx;

	if ( ListView_InsertColumn( h_list, 0, &lvcol ) )
	{
		return ST_OK;
	} else {
		return ST_ERROR;
	}
}


LPARAM _get_item_index(
		HWND h_list,
		int  item
	)
{
	LVITEM lvi;
	memset( &lvi, 0, sizeof(LVITEM) );

	lvi.mask  = LVIF_PARAM;
	lvi.iItem = item;

	if ( ListView_GetItem( h_list, &lvi ) ) 
	{
		return lvi.lParam;
	} else {
		return (LPARAM)NULL;
	}
}


void _get_item_text(
		HWND     h_list,
		int      item,
		int      subitem,
		wchar_t *text,
		int      chars
	)
{
	LVITEM lvitem = { 
		LVIF_TEXT, item, subitem, 0, 0, text, chars 
	};

	ListView_GetItem( h_list, &lvitem );
	if ( item == -1 )
	{
		text[0] = 0;
	}

}


BOOL _is_duplicated_item(
		HWND     h_list,
		wchar_t *s_item
	)
{
	wchar_t item[MAX_PATH];
	int k = 0;

	for ( ; k < ListView_GetItemCount(h_list) ; k++ )
	{
		_get_item_text( h_list, k, 0, item, countof(item) );
		if ( wcscmp(item, s_item) == 0 )
		{
			return TRUE;
		}
	}
	return FALSE;

}


LPARAM _get_sel_item( HWND h_list )
{
	return _get_item_index(
		h_list, ListView_GetSelectionMark( h_list )
		);
}


BOOL _get_header_text(
		HWND     h_list,
		int      idx,
		wchar_t *s_header,
		int      size
	)
{
	HDITEM hd_item = { HDI_TEXT };

	hd_item.pszText    = s_header;
	hd_item.cchTextMax = size;

	return Header_GetItem(
		ListView_GetHeader( h_list ), idx, &hd_item
		);
}


BOOL _set_header_text(
		HWND     h_list,
		int      idx,
		wchar_t *s_header,
		int      size
	)
{
	HDITEM hd_item = { HDI_TEXT };

	hd_item.pszText    = s_header;
	hd_item.cchTextMax = size;

	return Header_SetItem(
		ListView_GetHeader( h_list ), idx, &hd_item
		);
}

BOOL _list_insert_item(
		HWND     h_list,
		DWORD    item,
		DWORD    subitem,
		wchar_t *text,
		int      state
	)
{
	LVITEM lvitem	= { LVIF_TEXT | LVIF_STATE, 0, 0 };
	lvitem.pszText	= text;

	lvitem.iItem	= item; 
	lvitem.iSubItem	= subitem;

	lvitem.state	= state;

	if ( wcslen(text) == 0 )
	{
		return FALSE;
	}
	return (
		ListView_InsertItem( h_list, &lvitem ) != -1
	);
}


void _middle_ctl(
		HWND h_anchor,
		HWND h_child,
		BOOL border_correct
	)
{
	RECT ch_size, pr_rect, pr_size;

	GetClientRect(h_child, &ch_size);
	GetClientRect(h_anchor, &pr_size);

	GetWindowRect(h_anchor, &pr_rect);
	ScreenToClient(GetParent(h_anchor), pv(&pr_rect));

	MoveWindow(
		h_child, 
		pr_rect.left   + ( pr_size.right  / 2 ) - ( ch_size.right  / 2 ),
		pr_rect.top    + ( pr_size.bottom / 2 ) - ( ch_size.bottom / 2 ),
		ch_size.right  + ( border_correct ? GetSystemMetrics(SM_CXEDGE) : 0 ),
		ch_size.bottom + ( border_correct ? GetSystemMetrics(SM_CYEDGE) : 0 ),
		TRUE

	);
}





void _resize_ctl(
		HWND h_ctl,
		int  dy,
		int  dx,
		BOOL border_correct
	)
{	
	RECT rc_ctl, cr_ctl;

	GetWindowRect(h_ctl, &cr_ctl);
	GetClientRect(h_ctl, &rc_ctl);

	ScreenToClient(GetParent(h_ctl), pv(&cr_ctl.right));
	ScreenToClient(GetParent(h_ctl), pv(&cr_ctl.left));
	
	MoveWindow(
		h_ctl, 
		cr_ctl.left,
		cr_ctl.top,
		rc_ctl.right + dx + 
				( border_correct ? GetSystemMetrics(SM_CXEDGE) : 0 ) + 
				( GetWindowLong(h_ctl, GWL_STYLE) & WS_VSCROLL ? GetSystemMetrics(SM_CYVSCROLL) : 0 ),
		rc_ctl.bottom + dy + 
				( border_correct ? GetSystemMetrics(SM_CYEDGE) : 0 ) + 
				( GetWindowLong(h_ctl, GWL_STYLE) & WS_HSCROLL ? GetSystemMetrics(SM_CYHSCROLL) : 0 ),
		TRUE

	);
}


void _relative_move(
		HWND h_anchor,
		HWND h_child,
		int  dt,
		BOOL dy,
		BOOL border_correct
	)
{
	RECT rc_child, cr_child;
	RECT rc_anchor;

	HWND h_parent = GetParent(h_anchor);
	if (GetParent(h_anchor) != GetParent(h_child)) return;

	GetClientRect(h_child,  &rc_child);
	GetWindowRect(h_child,  &cr_child);

	ScreenToClient(h_parent, pv(&cr_child.left));
	GetWindowRect(h_anchor, &rc_anchor);

	ScreenToClient(h_parent, pv(&rc_anchor.right));
	ScreenToClient(h_parent, pv(&rc_anchor.left));

	MoveWindow(
		h_child, 
		( !dy ? rc_anchor.left   + dt : cr_child.left ),
		(  dy ? rc_anchor.bottom + dt : cr_child.top  ),
		rc_child.right   + ( border_correct ? GetSystemMetrics(SM_CXEDGE) : 0 ),
		rc_child.bottom  + ( border_correct ? GetSystemMetrics(SM_CYEDGE) : 0 ),
		TRUE

	);
}


void _relative_rect(
		HWND  hwnd,
		RECT *rc
	)
{
	RECT rc_parent;
	RECT rc_size;

	WINDOWINFO winfo;

	GetWindowInfo( GetParent(hwnd), &winfo );
	GetWindowRect( GetParent(hwnd), &rc_parent );

	GetWindowRect( hwnd, rc );
	GetClientRect( hwnd, &rc_size );

	rc->top		-= ( rc_parent.top  + winfo.cyWindowBorders + GetSystemMetrics(SM_CYCAPTION) );
	rc->left	-= ( rc_parent.left + winfo.cxWindowBorders );

	rc->right	= rc_size.right  + winfo.cxWindowBorders - 1;
	rc->bottom	= rc_size.bottom + winfo.cyWindowBorders - 1;

}


INT_PTR _ctl_color(
		WPARAM   wparam,
		COLORREF color
	)
{
	HDC dc = (HDC)wparam;
	SetDCBrushColor(dc, color);
	SetBkMode(dc, TRANSPARENT);

	return (INT_PTR)GetStockObject(DC_BRUSH);

}


void _init_mount_points(
		HWND hwnd
	)
{
	wchar_t item[MAX_PATH];

	int drives = GetLogicalDrives( );
	int k = 2;

	SendMessage( hwnd, CB_ADDSTRING, 0, (LPARAM)L"Select Folder.." );
	for ( ; k < 26; k++ ) 
	{
		if ( !(drives & (1 << k)) )
		{
			_snwprintf( item, countof(item), L"%c:", 'A' + k );
			SendMessage( hwnd, CB_ADDSTRING, 0, (LPARAM)item );
		}
	}
}


void _change_page(
		HWND hwnd,
		int  wnd_idx
	)
{
	_wnd_data *data = wnd_get_long( hwnd, GWL_USERDATA );
	if (! data ) 
	{
		return;
	}
	data->state = ! data->state;
	if ( data->dlg[0] )
	{
		_tab_data *tab = wnd_get_long( GetParent(hwnd), GWL_USERDATA );
		if ( ! tab ) 
		{
			return;
		}
		tab->h_curr   = hwnd;
		tab->curr_tab = wnd_idx;

		if ( data->dlg[wnd_idx] != HWND_NULL )
		{				
			ShowWindow( tab->active, SW_HIDE );
			tab->active = data->dlg[wnd_idx];

			ShowWindow( tab->active, SW_SHOW );
			SetWindowPos( tab->active, HWND_TOP, 0, 0, 0, 0, SWP_NOSIZE );
		}
		InvalidateRect( GetParent(hwnd), NULL, FALSE );
	} else {
		InvalidateRect( hwnd, NULL, FALSE );
	}

	SendMessage( 
		GetParent(hwnd), WM_USER_CLICK, (WPARAM)hwnd, 0 
		);

}

