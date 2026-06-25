#ifndef _PRCWAIT_
#define _PRCWAIT_

#include <windows.h>
#include "drv_ioctl.h"
#include "dc_header.h"

/* Wait dialog wrapper functions for cancellable KDF operations */

int _wait_dc_mount_volume(
	HWND parent,
	wchar_t *device,
	dc_pass *password,
	int flags,
	const wchar_t *description
);

int _wait_dc_mount_all(
	HWND parent,
	dc_pass *password,
	int *mounted,
	int flags,
	const wchar_t *description
);

int _wait_dc_add_password(
	HWND parent,
	dc_pass *password,
	const wchar_t *description
);

int _wait_dc_change_password(
	HWND parent,
	wchar_t *device,
	dc_pass *old_pass,
	dc_pass *new_pass,
	u32 flags,
	const wchar_t *description
);

int _wait_dc_start_encrypt(
	HWND parent,
	wchar_t *device,
	dc_pass *password,
	crypt_info *crypt,
	int flags,
	const wchar_t *description
);

int _wait_dc_start_decrypt(
	HWND parent,
	wchar_t *device,
	dc_pass *password,
	crypt_info *crypt,
	const wchar_t *description
);

int _wait_dc_start_re_encrypt(
	HWND parent,
	wchar_t *device,
	dc_pass *password,
	crypt_info *crypt,
	const wchar_t *description
);

int _wait_dc_start_format(
	HWND parent,
	wchar_t *device,
	dc_pass *password,
	crypt_info *crypt,
	int flags,
	const wchar_t *description
);

int _wait_dc_update_layout(
	HWND parent,
	wchar_t *device,
	dc_pass *password,
	crypt_info *crypt,
	int flags,
	const wchar_t *description
);

int _wait_dc_backup_header(
	HWND parent,
	wchar_t *device,
	dc_pass *password,
	void *out,
	int *size,
	u32 flags,
	const wchar_t *description
);

int _wait_dc_restore_header(
	HWND parent,
	wchar_t *device,
	dc_pass *password,
	void *in,
	int size,
	u32 flags,
	const wchar_t *description
);

int _wait_dc_update_header(
	HWND parent,
	wchar_t *device,
	dc_pass *password,
	void *in,
	int size,
	u32 flags,
	const wchar_t *description
);

/* User-mode wrapper functions for cancellable KDF operations */

int _wait_dc_decrypt_header(
	HWND parent,
	u8 *enc_header,
	int enc_len,
	dc_pass *password,
	dc_header **out_header,
	xts_key **out_key,
	int *out_len,
	int *out_kdf,
	u8 *out_dk,
	const wchar_t *description
);

int _wait_dc_load_header_file(
	HWND parent,
	wchar_t *file_path,
	dc_pass *password,
	dc_header **out_header,
	xts_key **out_key,
	int *out_len,
	u8 *out_dk,
	const wchar_t *description
);

int _wait_dc_derive_key_um(
	HWND parent,
	dc_pass *password,
	int kdf,
	u8 *salt,
	u8 *dk,
	const wchar_t *description
);

#endif
