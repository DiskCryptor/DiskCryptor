#ifndef _EFIINST_
#define _EFIINST_

#include "dcapi.h"
#include "bootloader.h"

extern dc_api const wchar_t* efi_var_guid;
extern dc_api const wchar_t* sb_var_guid;

void dc_api dc_efi_init();
int dc_api dc_efi_check();
int dc_api dc_efi_is_secureboot();
int dc_api dc_efi_is_sb_setupmode();

int dc_api dc_efi_file_exists(const wchar_t *root, const wchar_t* name);
int dc_api dc_efi_get_volume_guid_path(int dsk_num, int part_num, wchar_t *path, int max_len);
int dc_api dc_efi_get_os_disk(void);

int dc_api dc_make_efi_rec(const wchar_t *root, int format, int shim);
int dc_api dc_make_efi_iso(wchar_t *file, int shim);
int dc_api dc_make_efi_pxe(wchar_t *root, int shim);
int dc_api dc_set_efi_boot(int dsk_num, int esp_part, int replace_ms, int shim);

int dc_api dc_efi_get_sys_part(int dsk_num, int esp_part, wchar_t* path);

int dc_api dc_efi_is_msft_boot_replaced(int dsk_num, int esp_part);
int dc_api dc_efi_replace_msft_boot(int dsk_num, int esp_part);
int dc_api dc_efi_restore_msft_boot(int dsk_num, int esp_part);

int dc_api dc_update_efi_boot(int dsk_num, int esp_part);
int dc_api dc_unset_efi_boot(int dsk_num, int esp_part);

int dc_api dc_get_platform_info(int dsk_num, char** infoContent, int *size);

int dc_api dc_is_gpt_disk(int dsk_num);

int dc_api dc_get_efi_config(
	int dsk_num, wchar_t *file, ldr_config *conf);

int dc_api dc_set_efi_config(
	int dsk_num, wchar_t *file, ldr_config *conf);

int dc_api dc_efi_config_by_partition(
	const wchar_t *root, int set_conf, ldr_config *conf);

int dc_api dc_get_dcs_version(const wchar_t *root);

void dc_api dc_efi_config_init(ldr_config *conf);

int dc_api dc_efi_shim_available();
int dc_api dc_is_shim_on_partition(const wchar_t *root);
int dc_api dc_efi_is_shim_set(int dsk_num);

int dc_api dc_is_dcs_on_partition(const wchar_t *root);
int dc_api dc_is_dcs_on_disk(int dsk_num);
int dc_api dc_efi_is_msft_on_disk(int dsk_num);
int dc_api dc_is_dcs_in_file(wchar_t *file);

int dc_api dc_efi_set_bme(wchar_t* description, int dsk_num);
int dc_api dc_efi_del_bme();
int dc_api dc_efi_is_bme_set(int dsk_num);
int dc_api dc_efi_del_msft_bme();

int dc_api dc_prep_encrypt(const wchar_t *device, struct _dc_pass *password, struct _crypt_info *crypt, int flags);
int dc_api dc_has_pending_header(const wchar_t* device);
int dc_api dc_clear_pending_header(const wchar_t* device);
int dc_api dc_get_pending_header_nt(const wchar_t* device, wchar_t* path);

int dc_api dc_efi_dcs_is_signed();
int dc_api dc_efi_enum_allowed_signers(int(*cb)(const BYTE* hash, const char* name, PVOID param), PVOID param);
int dc_api dc_efi_enum_var(const wchar_t* name, const wchar_t* guid, int(*cb)(const BYTE* hash, const char* name, PVOID param), PVOID param);

// Update certificate file on EFI partition (\EFI\DCS\Certificate.dat)
// If cert is NULL: reads from registry, saves if found, deletes file if not found
// If cert is empty string: deletes the certificate file
// Otherwise: saves cert as UTF-8 encoded text
int dc_api dc_efi_update_cert(const wchar_t* cert);

#endif
