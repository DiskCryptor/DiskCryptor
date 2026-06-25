#ifndef _DLGCODE_
#define _DLGCODE_

typedef struct __colinfo 
{
	wchar_t *name;
	int      width;
	int      align;
	BOOL     row_images;

} _colinfo;

typedef struct __tblinfo 
{
	int       id;
	wchar_t  *items[5];
	_colinfo  cols[2];	

} _tblinfo;

typedef struct __wnd_data 
{
	WNDPROC old_proc;
	BOOL    state;
	UINT    vk;
	UINT    id;
	HWND    dlg[20];
	void   *data;

} _wnd_data, *_pwnd_data;

typedef struct __tab_data 
{
	HWND h_curr;
	HWND active;
	int  curr_tab;

} _tab_data;

typedef struct __static_view 
{
	int      id;
	HWND     hwnd;
	COLORREF color;

} _static_view;

typedef struct __init_list 
{
	int      val;
	wchar_t *display;

} _init_list;

typedef struct __ctl_init 
{
	wchar_t *display;
	int      id;
	int      val;

} _ctl_init;

typedef struct __size_move_ctls 
{
	int anchor;
	int id;
	int val;
	int dx;
	int dy;

} _size_move_ctls;

#define CTL_LDR_HDD           0
#define CTL_LDR_STICK         1
#define CTL_LDR_ISO           2
#define CTL_LDR_PXE           3

typedef struct __dlg_templateex 
{
	WORD  dlgVer;
	WORD  signature;
	DWORD helpID;
	DWORD exStyle;
	DWORD style;
	WORD  cDlgItems;
	short x;
	short y;
	short cx;
	short cy;

} _dlg_templateex;

extern _colinfo _main_headers[ ];
extern _colinfo _boot_headers[ ];

extern _colinfo _part_by_id_headers[ ];
extern _colinfo _benchmark_headers[ ];
extern _colinfo _kdf_benchmark_headers[ ];

const extern _init_list wipe_modes[ ];
const extern _init_list kb_layouts[ ];

const extern _init_list boot_type_ext[ ];
const extern _init_list boot_type_efi[ ];
const extern _init_list boot_type_all[ ];

const extern _init_list show_pass[ ];
const extern _init_list auth_tmount[ ];

const extern _init_list bad_pass_act_efi[ ];
const extern _init_list bad_pass_act[ ];
const extern _init_list auth_type[ ];

const extern _init_list cipher_names[ ];

const extern _init_list kdf_names_ex[ ];
const extern _init_list *kdf_names;

const extern _init_list keyfile_mix_modes[ ];

const extern _init_list loader_type_mbr[ ];
const extern _init_list loader_type_efi[ ];

const extern _init_list pass_status[ ];

extern wchar_t *_info_table_items[ ];
extern wchar_t *_act_table_items[ ];

const extern _ctl_init hotks_edit[ ];
const extern _ctl_init hotks_chk[ ];
const extern _ctl_init hotks_static[ ];

extern _static_view pass_gr_ctls[ ];
extern _static_view pass_pe_ctls[ ];

extern HWND		__lists[10];
extern HACCEL	__hacc;

void _draw_static(
		LPDRAWITEMSTRUCT itst
	);

void _change_page(
		HWND hwnd,
		int  wnd_idx
	);

void _get_item_text(
		HWND     h_list,
		int      item,
		int      subitem,
		wchar_t *text,
		int      chars
	);


#endif