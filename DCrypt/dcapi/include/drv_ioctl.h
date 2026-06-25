#ifndef _DRV_IOCTL_
#define _DRV_IOCTL_

#include "dcapi.h"
#include "..\driver\include\driver.h"
#include "dcconst.h"

typedef struct _vol_info {
	HANDLE    find;
	wchar_t   device[MAX_PATH];
	wchar_t   w32_device[MAX_PATH];
	dc_status status;

} vol_inf;

int dc_api dc_first_volume(vol_inf *info);
int dc_api dc_next_volume(vol_inf *info);

int  dc_api dc_is_old_runned();
int  dc_api dc_open_device();
int  dc_api dc_get_version();

int dc_api dc_get_boot_device(wchar_t *device);

int dc_api dc_is_boot_encrypted();

int dc_api dc_add_password(dc_pass *password, volatile LONG *abort);
int dc_api dc_enum_passwords(dc_pass_info *items, int max_count, int *total_count);
int dc_api dc_mount_volume(wchar_t *device, dc_pass *password, int flags, volatile LONG *abort);
int dc_api dc_start_encrypt(wchar_t *device, dc_pass *password, crypt_info *crypt, int flags, volatile LONG *abort);
int dc_api dc_start_encrypt2(wchar_t *device, wchar_t *path);
int dc_api dc_start_decrypt(wchar_t *device, dc_pass *password, crypt_info *crypt, volatile LONG *abort);
int dc_api dc_start_re_encrypt(wchar_t *device, dc_pass *password, crypt_info *crypt, volatile LONG *abort);
int dc_api dc_update_layout(wchar_t *device, dc_pass *password, crypt_info *crypt, int flags, volatile LONG *abort);
int dc_api dc_mount_all(dc_pass *password, int *mounted, int flags, volatile LONG *abort);

int dc_api dc_start_format(wchar_t *device, dc_pass *password, crypt_info *crypt, int flags, volatile LONG *abort);
int dc_api dc_format_step(wchar_t *device, int wp_mode);
int dc_api dc_done_format(wchar_t *device);

int dc_api dc_change_password(wchar_t *device, dc_pass *old_pass, dc_pass *new_pass, u32 flags, volatile LONG *abort);

int dc_api dc_unmount_volume(wchar_t *device, int flags);
int dc_api dc_unmount_all();

int dc_api dc_enc_step(wchar_t *device, int wp_mode);
int dc_api dc_dec_step(wchar_t *device);
int dc_api dc_sync_enc_state(wchar_t *device);

int dc_api dc_get_device_status(wchar_t *device, dc_status *status);

int dc_api dc_benchmark(int cipher, dc_bench_info *info);
int dc_api dc_benchmark_kdf(int kdf, dc_kdf_bench_info *info);

DWORD dc_api dc_device_control(DWORD dwIoControlCode, LPCVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize);

void dc_api dc_get_bsod();

int dc_api dc_backup_header(wchar_t *device, dc_pass *password, void *out, int *size, u32 flags, volatile LONG *abort);
int dc_api dc_restore_header(wchar_t *device, dc_pass *password, void *in, int size, u32 flags, volatile LONG *abort);
int dc_api dc_update_header(wchar_t *device, dc_pass *password, void *in, int size, u32 flags, volatile LONG *abort);

int dc_api dc_is_device_ssd(wchar_t *device);

#endif