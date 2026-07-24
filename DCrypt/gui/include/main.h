#ifndef _MAIN_
#define _MAIN_

#include "linklist.h"
#include "dlg_code.h"
#include "prc_code.h"
#include "misc.h"
#include "ui_utils.h"
#include "defines.h"
#include "main.h"
#include "subs.h"
#include "resource.h"
#include "drvinst.h"
#include "stat.h"

extern list_entry __drives;
extern list_entry __volumes;
extern list_entry __action;

extern CRITICAL_SECTION crit_sect;
extern int _tmr_elapse[ ];

typedef struct _timer_info 
{
	int id;
	int elapse;

} timer_info;

extern int          __status;
extern dc_conf_data __config;
extern int          __is_efi_boot;

//extern CRITICAL_SECTION CritSection;

static wchar_t drv_msk[ ] = L"%s\\drivers\\%s.sys";

#define __execute( path ) (  \
		ShellExecuteW( NULL, L"open", path, NULL, NULL, SW_SHOWNORMAL ) \
	)

void _refresh(
		char main
	);

int _benchmark( 
		bench_item *bench
	);

int dc_get_ldr_config(
		int			dsk_num, 
		ldr_config	*conf
	);

int dc_set_ldr_config(
		int			dsk_num,
		ldr_config	*conf
	);

int _set_boot_loader_mbr(
		HWND  hwnd,
		int   dsk_num,
		int   is_small
	);

int _set_boot_loader_efi(
		HWND  hwnd,
		int   dsk_num,
		int   is_shim,
		int   add_esp,  /* -1 = ask user, 0 = no (use Windows ESP), 1 = yes (use dedicated DCS ESP) */
		int   add_bme    /* -1 = ask user, 0 = no, 1 = yes */
	);

BOOL _is_boot_device(
		vol_inf *vol
	);

BOOL _is_removable_media(
		int dsk_num
	);

void _lock_unmount_add(
		const wchar_t *device
	);

void _lock_unmount_remove(
		const wchar_t *device
	);

void _lock_unmount_remove_all(void);

void _activate_page( );

void _set_timer(
		int  index,
		BOOL set,
		BOOL refresh
	);

void _check_driver(
		HWND   hwnd,
		size_t buff_size,
		char   set
	);

void _get_driver_path(
		wchar_t *name, 
		wchar_t *path
	);


#endif
