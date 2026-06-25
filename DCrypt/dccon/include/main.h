#ifndef _MAIN_
#define _MAIN_

#include "drv_ioctl.h"

int dc_set_boot_interactive(int d_num, int small_boot);
int dc_set_efi_boot_interactive(int d_num, int add_bme, int shim, int esp);
int is_param(wchar_t *name);

#define on_off(a) ( (a) != 0 ? L"ON":L"OFF" )
#define set_flag(var,flag,value) if ((value) == 0) { (var) &= ~(flag); } else { (var) |= (flag); }

#define MAX_VOLUMES 128

extern vol_inf   volumes[MAX_VOLUMES];
extern u32       vol_cnt;
extern int       g_argc;
extern wchar_t **g_argv;

#endif