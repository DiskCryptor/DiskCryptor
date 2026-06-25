#ifndef _DRVINST_H_
#define _DRVINST_H_

#include "dcapi.h"
#include "drv_ioctl.h"

#define HOT_MAX 4 /* maximum number of hotkeys */

typedef struct dc_conf_data {
	DWORD build;
	DWORD conf_flags;
	DWORD load_flags;
	DWORD hotkeys[HOT_MAX];

} dc_conf_data;

DWORD dc_api dc_load_config(dc_conf_data* conf);
DWORD dc_api dc_save_config(const dc_conf_data* conf);

BOOL dc_api dc_is_driver_installed();
BOOL dc_api dc_is_driver_works();

DWORD dc_api dc_install_driver();
DWORD dc_api dc_remove_driver();
DWORD dc_api dc_update_driver();

int dc_api install_dc_offline(const wchar_t* windows_path);
int dc_api remove_dc_offline(const wchar_t* windows_path);

#endif
