#ifndef _UIUTILS_
#define _UIUTILS_

#include <commctrl.h>

#define IDS_MOUNT			L"&Mount"
#define IDS_UNMOUNT			L"&Unmount"
#define IDS_ENCRYPT			L"&Encrypt"
#define IDS_DECRYPT			L"&Decrypt"

#define IDS_FORMAT			L"&Format"
#define IDS_REENCRYPT		L"&Reencrypt"

#define IDS_CHPASS			L"&Change Password"
#define IDS_HEADCFG         L"&Edit Header"

#define IDS_BOOTINSTALL		L"&Install Loader"
#define IDS_BOOTREMOVE		L"&Remove Loader"
#define IDS_BOOTCREATE		L"&Create Loader"
#define IDS_SAVECHANGES		L"&Save Changes"

#define IDS_BOOTUPDATE		L"&Update Loader"
#define IDS_BOOTCHANGECGF	L"C&hange Config"

#define IDS_BOOTADDBME		L"&Add to EFI Boot Menu"
#define IDS_BOOTDELBME		L"&Delete from EFI Boot Menu"

#define IDS_BOOTREPLACEMS	L"Re&place bootmgfw.efi"
#define IDS_BOOTRESTOREMS	L"R&estore bootmgfw.efi"

#define IDS_MOUNTALL		L"Mount &All"
#define IDS_UNMOUNTALL		L"U&nmount All"

#define IDS_SETTINGS		L"&Settings"
#define IDS_ABOUT			L"&About"
#define IDS_EXIT			L"E&xit"

#define IDS_EMPTY_LIST		L"< .. list is empty .. >"

#define IDS_USE_KEYFILES	L"Use Keyfiles"
#define IDS_USE_KEYFILE		L"Use Keyfile"

#define IDS_MODE_NAME		L"XTS"
#define IDS_PRF_NAME		L"Pkcs5.2 SHA-512"
#define IDS_ARGON_NAME		L"Argon2id v1.3"

#define DC_HOMEPAGE			L"https://diskcryptor.org/"
#define DC_FORUMPAGE		L"https://diskcryptor.org/go.php?to=dc-forum"
#define DC_NAME				L"DiskCryptor"

#define DC_MUTEX			L"DC_UI_MUTEX"
#define DC_CLASS			L"DC_UI_DLG_CLASS"

#define STR_HEAD_NO_ICONS	L"[NO_ICONS]"
#define STR_EMPTY			L"--"

#define STR_SPACE			L" "
#define STR_NULL			L""

#define COL_SIZE			1
#define COL_LABEL			2
#define COL_TYPE			3
#define COL_STATUS			4
#define COL_MOUNTED			5

#define LGHT_CLR			50
#define DARK_CLR			45

#define WM_APP_TRAY			1
#define WM_APP_SHOW			2
#define WM_APP_FILE			3

#define WM_THEMECHANGED		794
#define WM_USER_CLICK		WM_USER + 01
#define WM_CLOSE_DIALOG		WM_USER + 02

#define CL_WHITE			RGB(255,255,255)
#define CL_BLUE				RGB(0,0,255)
#define CL_GREEN			RGB(0,255,0)
#define CL_RED				RGB(255,0,0)

#define CL_WARNING			RGB(218,18,18)
#define CL_WARNING_BG		RGB(255,170,160)
#define CL_WARNING_BG_LT	RGB(255,215,215)

#define PRG_STEP			9000
#define MAIN_DLG_MIN_HEIGHT	380

#define SUB_NONE			0
#define SUB_KEY_PROC		1
#define SUB_STATIC_PROC		2

#define ALG_RIGHT			0
#define ALG_LEFT			1

#define IC_NONE				-3
#define IC_CONTEXT			-2
#define IC_BASE				-1

#define HMAIN_DRIVES			0	// IDC_DISKDRIVES
#define HMAIN_INFO				1	// IDC_INF_TABLE
#define HMAIN_ACT				2	// IDC_ACT_TABLE
#define HBOT_WIZARD_BOOT_DEVS	3	// IDC_WZD_BOOT_DEVS
#define HBOT_PART_LIST_BY_ID	4	// IDC_PART_LIST_BY_ID
#define HENC_WIZARD_BOOT_DEVS	5	// IDC_BOOT_DEVS
#define HBENCHMARK				6	// IDC_LIST_BENCHMARK
#define HBENCHMARK_KDF			7	// IDC_LIST_BENCHMARK_KDF

#define _set_check( hwnd, id, state ) ( \
		SendMessage( GetDlgItem( hwnd, id ), BM_SETCHECK, state, 0 ) \
	)
#define _get_check( hwnd, id ) ( \
		SendMessage( GetDlgItem( hwnd, id ), BM_GETCHECK, 0, 0 ) == BST_CHECKED \
	)
#define _menu_onoff( enable ) ( \
		enable ? MF_ENABLED : MF_GRAYED \
	)

#define _keyup( message ) ( \
		( message == WM_KEYUP ) || ( message == WM_SYSKEYUP ) \
	)

#define _keydown( message ) ( \
		( message == WM_KEYDOWN ) || ( message == WM_SYSKEYDOWN ) \
	)

BOOL _list_set_item(
		HWND     h_list,
		DWORD    item,
		DWORD    subitem,
		wchar_t *text
	);

BOOL _list_insert_item(
		HWND     h_list,
		DWORD    item,
		DWORD    subitem,
		wchar_t *text,
		int      state
	);

void _list_set_item_text(
		HWND     h_list,
		DWORD    item,
		DWORD    subitem,
		wchar_t *text
	);

BOOL _set_header_text(
		HWND     h_list,
		int      idx,
		wchar_t *s_header,
		int      size
	);

int _list_insert_col(
		HWND h_list,
		int  cx
	);   // ret ST_OK || ST_ERROR

void _init_mount_points(
		HWND hwnd
	);

LPARAM _get_item_index(
		HWND h_list,
		int  index
	);

LPARAM _get_sel_item(
		HWND h_list
	);

void _tray_icon( 
		char install
	);

BOOL _ui_init( 
		HINSTANCE h_inst
	);

void __unsub_class(
		HWND hwnd
	);

BOOL _folder_choice(
		HWND     hwnd, 
		wchar_t *path, 
		wchar_t *title
	);

char *_get_item (
		HWND  h_list,
		DWORD item,
		DWORD subitem
	);

void _relative_move(
		HWND h_anchor,
		HWND h_child,
		int  dt,
		BOOL dy,
		BOOL border_correct
	);

void _resize_ctl(
		HWND h_ctl,
		int  dy,
		int  dx,
		BOOL border_correct
	);

void _relative_rect(
		HWND  hwnd,
		RECT *rc
	);

void _middle_ctl(
		HWND h_anchor,
		HWND h_child,
		BOOL border_correct
	);

INT_PTR _ctl_color(
		WPARAM   wparam,
		COLORREF color
	);

DWORD _cl(
		int  index,
		char prc
	);

_wnd_data *_sub_class(
		HWND hwnd,
		int  proc_idx,
		HWND dlg,
		...
	);

LRESULT 
CALLBACK 
_key_proc(
		HWND   hwnd,
		UINT   msg,
		WPARAM wparam,
		LPARAM lparam
	);

LRESULT 
CALLBACK 
_static_proc(
		HWND   hwnd,
		UINT   msg,
		WPARAM wparam,
		LPARAM lparam
	);

BOOL 
CALLBACK 
__sub_enum(
		HWND   hwnd,
		LPARAM lParam
	);

int _find_list_item(
		HWND     h_list,
		wchar_t *text,
		int      column
	);

void *wnd_get_long(
		HWND wnd, 
		int  index
	);

void *wnd_set_long(
		HWND  wnd, 
		int   index, 
		void *ptr
	);

BOOL 
CALLBACK 
_enum_proc(
		HWND   hwnd,
		LPARAM lparam
	);

void _show_pass_group(
		HWND hwnd,
		int  flags,
		int  layout
	);

void _get_item_text(
		HWND     h_list,
		int      item,
		int      subitem,
		wchar_t *text,
		int      chars
	);

int _init_combo(
		HWND        hwnd, 
		const _init_list *list,
		DWORD       val,
		BOOL        or,
		int         bits
	);

void _enb_but_this(
		HWND parent,
		int  skip,
		BOOL enable
	);

void _init_list_headers(
		HWND      hwnd,
		_colinfo *cols
	);

BOOL _get_header_text(
		HWND     h_list,
		int      idx,
		wchar_t *s_header,
		int      size
	);

int _draw_proc(
		int     message,
		LPARAM lparam
	);

BOOL _is_duplicated_item(
		HWND     h_list,
		wchar_t *s_item
	);

void _change_page(
		HWND hwnd,
		int  wnd_idx
	);

int _get_combo_val(
		HWND hwnd, 
		const _init_list *list
	);

wchar_t *_get_text_name(
		int val, 
		const _init_list *list
	);

HANDLE _get_hwnd_info_list( );

BOOL _is_active_item( 
		LPARAM lparam 
	);

BOOL _is_root_item( 
		LPARAM lparam 
	);

BOOL _is_enabled_item(
		LPARAM lparam
	);

BOOL _is_splited_item(
		LPARAM lparam
	);

BOOL _is_marked_item(
		LPARAM lparam
	);

BOOL _is_curr_in_group(
		HWND hwnd
	);

BOOL _is_cdrom_item(
		LPARAM lparam
	);

BOOL _is_icon_show(
		HWND   hwnd, 
		int    idx
	);

BOOL _is_warning_item(
		LPARAM lparam
	);

BOOL _open_file_dialog(
		HWND     h_parent,
		wchar_t *s_path,
		int      size,
		wchar_t *s_title
	);

BOOL _save_file_dialog(
		HWND     h_parent,
		wchar_t *s_path,
		int      size,
		wchar_t *s_title
	);

_focus_tab(
		int  h_parent_first_tab_id,
		HWND h_parent,
		HWND h_page,
		HWND h_page_first_tab,
		BOOL b_next
	);

HWND _get_next_enabled_item(
		HWND h_dialog,
		HWND h_first,
		BOOL b_next
	);

extern HINSTANCE __hinst;

extern HFONT __font_bold;
extern HFONT __font_link;
extern HFONT __font_small;

extern HCURSOR __cur_hand;
extern HCURSOR __cur_arrow;
extern HCURSOR __cur_wait;

extern HIMAGELIST __img;
extern HIMAGELIST __dsk_img;

extern HWND __dlg;
extern HWND __dlg_act_info;

#ifdef _WIN64
 #define GWL_USERDATA GWLP_USERDATA
 #define GWL_WNDPROC  GWLP_WNDPROC
#endif


#endif
