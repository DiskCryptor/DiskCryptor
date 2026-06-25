/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2026
    * DavidXanatos <info@diskcryptor.org>
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
#include "prc_wait.h"
#include "dc_header.h"

/* Timer IDs */
#define TIMER_SHOW_DELAY    1  /* 500ms delay before showing dialog */
#define TIMER_CLOSE_DELAY   2  /* 2 second delay before closing dialog */

/* Timing constants */
#define SHOW_DELAY_MS       500   /* Don't show dialog until 500ms elapsed */
#define CLOSE_DELAY_MS      500   /* Keep dialog visible for 500ms after operation completes */

/* Custom message for worker completion */
#define WM_WORKER_DONE      (WM_USER + 100)

/* Context for passing operation info to _run_wait_dialog */
typedef struct _wait_op_ctx {
	void          *params;        /* Operation-specific parameters */
	DWORD        (*worker)(void*);/* Worker function to execute */
	volatile LONG  abort;         /* Receives abort flag after completion */
} wait_op_ctx;

/* Persistent wait dialog state */
typedef struct _wait_dialog_state {
	HWND           hwnd;              /* Dialog window handle (NULL if not created) */
	HWND           parent;            /* Parent window for current dialog */
	BOOL           is_visible;        /* Dialog is currently visible */
	volatile LONG  abort;             /* Abort flag for current operation */
	int            result;            /* Result of current operation */
	BOOL           operation_pending; /* TRUE while operation is running */
	void          *params;            /* Current operation params */
	DWORD        (*worker)(void*);    /* Current worker function */
	const wchar_t *description;       /* Current description */
} wait_dialog_state;

/* Global persistent dialog state */
static wait_dialog_state g_wait = {0};

/* Mount volume operation params */
typedef struct _mount_params {
	wchar_t    *device;
	dc_pass    *password;
	int         flags;
} mount_params;

/* Mount all operation params */
typedef struct _mount_all_params {
	dc_pass    *password;
	int        *mounted;
	int         flags;
} mount_all_params;

/* Add password operation params */
typedef struct _add_pass_params {
	dc_pass    *password;
} add_pass_params;

/* Change password operation params */
typedef struct _change_pass_params {
	wchar_t    *device;
	dc_pass    *old_pass;
	dc_pass    *new_pass;
	u32         flags;
} change_pass_params;

/* Start encrypt operation params */
typedef struct _start_encrypt_params {
	wchar_t    *device;
	dc_pass    *password;
	crypt_info *crypt;
	int         flags;
} start_encrypt_params;

/* Start decrypt operation params */
typedef struct _start_decrypt_params {
	wchar_t    *device;
	dc_pass    *password;
	crypt_info *crypt;
} start_decrypt_params;

/* Start re-encrypt operation params */
typedef struct _start_re_encrypt_params {
	wchar_t    *device;
	dc_pass    *password;
	crypt_info *crypt;
} start_re_encrypt_params;

/* Start format operation params */
typedef struct _start_format_params {
	wchar_t    *device;
	dc_pass    *password;
	crypt_info *crypt;
	int         flags;
} start_format_params;

/* Update layout operation params */
typedef struct _update_layout_params {
	wchar_t    *device;
	dc_pass    *password;
	crypt_info *crypt;
	int         flags;
} update_layout_params;

/* Backup header operation params */
typedef struct _backup_header_params {
	wchar_t    *device;
	dc_pass    *password;
	void       *out;
	int        *size;
	u32         flags;
} backup_header_params;

/* Restore header operation params */
typedef struct _restore_header_params {
	wchar_t    *device;
	dc_pass    *password;
	void       *in;
	int         size;
	u32         flags;
} restore_header_params;

/* Update header operation params */
typedef struct _update_header_params {
	wchar_t    *device;
	dc_pass    *password;
	void       *in;
	int         size;
	u32         flags;
} update_header_params;

/* User-mode decrypt header operation params */
typedef struct _um_decrypt_header_params {
	u8         *enc_header;
	int         enc_len;
	dc_pass    *password;
	dc_header **out_header;
	xts_key   **out_key;
	int        *out_len;
	int        *out_kdf;
	u8         *out_dk;
} um_decrypt_header_params;

/* User-mode load header file operation params */
typedef struct _um_load_header_file_params {
	wchar_t    *file_path;
	dc_pass    *password;
	dc_header **out_header;
	xts_key   **out_key;
	int        *out_len;
	u8         *out_dk;
} um_load_header_file_params;

/* User-mode derive key operation params */
typedef struct _um_derive_key_params {
	dc_pass    *password;
	int         kdf;
	u8         *salt;
	u8         *dk;
} um_derive_key_params;

/* Worker thread functions - return result directly, wrapper handles posting */
static DWORD WINAPI _worker_mount_volume(LPVOID param)
{
	mount_params *p = (mount_params*)param;
	return (DWORD)dc_mount_volume(p->device, p->password, p->flags, &g_wait.abort);
}

static DWORD WINAPI _worker_mount_all(LPVOID param)
{
	mount_all_params *p = (mount_all_params*)param;
	return (DWORD)dc_mount_all(p->password, p->mounted, p->flags, &g_wait.abort);
}

static DWORD WINAPI _worker_add_password(LPVOID param)
{
	add_pass_params *p = (add_pass_params*)param;
	return (DWORD)dc_add_password(p->password, &g_wait.abort);
}

static DWORD WINAPI _worker_change_password(LPVOID param)
{
	change_pass_params *p = (change_pass_params*)param;
	return (DWORD)dc_change_password(p->device, p->old_pass, p->new_pass, p->flags, &g_wait.abort);
}

static DWORD WINAPI _worker_start_encrypt(LPVOID param)
{
	start_encrypt_params *p = (start_encrypt_params*)param;
	return (DWORD)dc_start_encrypt(p->device, p->password, p->crypt, p->flags, &g_wait.abort);
}

static DWORD WINAPI _worker_start_decrypt(LPVOID param)
{
	start_decrypt_params *p = (start_decrypt_params*)param;
	return (DWORD)dc_start_decrypt(p->device, p->password, p->crypt, &g_wait.abort);
}

static DWORD WINAPI _worker_start_re_encrypt(LPVOID param)
{
	start_re_encrypt_params *p = (start_re_encrypt_params*)param;
	return (DWORD)dc_start_re_encrypt(p->device, p->password, p->crypt, &g_wait.abort);
}

static DWORD WINAPI _worker_start_format(LPVOID param)
{
	start_format_params *p = (start_format_params*)param;
	return (DWORD)dc_start_format(p->device, p->password, p->crypt, p->flags, &g_wait.abort);
}

static DWORD WINAPI _worker_update_layout(LPVOID param)
{
	update_layout_params *p = (update_layout_params*)param;
	return (DWORD)dc_update_layout(p->device, p->password, p->crypt, p->flags, &g_wait.abort);
}

static DWORD WINAPI _worker_backup_header(LPVOID param)
{
	backup_header_params *p = (backup_header_params*)param;
	return (DWORD)dc_backup_header(p->device, p->password, p->out, p->size, p->flags, &g_wait.abort);
}

static DWORD WINAPI _worker_restore_header(LPVOID param)
{
	restore_header_params *p = (restore_header_params*)param;
	return (DWORD)dc_restore_header(p->device, p->password, p->in, p->size, p->flags, &g_wait.abort);
}

static DWORD WINAPI _worker_update_header(LPVOID param)
{
	update_header_params *p = (update_header_params*)param;
	return (DWORD)dc_update_header(p->device, p->password, p->in, p->size, p->flags, &g_wait.abort);
}

/* User-mode worker functions */
static DWORD WINAPI _worker_um_decrypt_header(LPVOID param)
{
	um_decrypt_header_params *p = (um_decrypt_header_params*)param;
	return (DWORD)dc_decrypt_header(p->enc_header, p->enc_len, p->password,
		p->out_header, p->out_key, p->out_len, p->out_kdf, p->out_dk, &g_wait.abort);
}

static DWORD WINAPI _worker_um_load_header_file(LPVOID param)
{
	um_load_header_file_params *p = (um_load_header_file_params*)param;
	return (DWORD)dc_load_header_file(p->file_path, p->password,
		p->out_header, p->out_key, p->out_len, p->out_dk, &g_wait.abort);
}

static DWORD WINAPI _worker_um_derive_key(LPVOID param)
{
	um_derive_key_params *p = (um_derive_key_params*)param;
	return (DWORD)dc_derive_key_um(p->password, p->kdf, p->salt, p->dk, &g_wait.abort);
}

/* Worker thread wrapper - posts completion message */
static DWORD WINAPI _wait_worker_wrapper(LPVOID param)
{
	/* Run the actual worker */
	g_wait.result = g_wait.worker(g_wait.params);

	/* Signal completion */
	g_wait.operation_pending = FALSE;

	/* Post message to dialog if it exists */
	if (g_wait.hwnd) {
		PostMessage(g_wait.hwnd, WM_WORKER_DONE, 0, 0);
	}
	return 0;
}

/* Close the persistent wait dialog */
static void _close_wait_dialog(void)
{
	if (g_wait.hwnd) {
		KillTimer(g_wait.hwnd, TIMER_SHOW_DELAY);
		KillTimer(g_wait.hwnd, TIMER_CLOSE_DELAY);
		DestroyWindow(g_wait.hwnd);
		g_wait.hwnd = NULL;
	}
	g_wait.parent = NULL;
	g_wait.is_visible = FALSE;
	g_wait.operation_pending = FALSE;
}

/* Persistent wait dialog procedure */
static INT_PTR CALLBACK _wait_dlg_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
	switch (msg)
	{
		case WM_INITDIALOG:
		{
			g_wait.hwnd = hwnd;
			g_wait.is_visible = FALSE;

			/* Set description text */
			if (g_wait.description != NULL) {
				SetDlgItemTextW(hwnd, IDC_WAIT_TEXT, g_wait.description);
			}

			/* Enable cancel button */
			EnableWindow(GetDlgItem(hwnd, IDC_WAIT_CANCEL), TRUE);

			/* Set timer to show dialog after delay */
			SetTimer(hwnd, TIMER_SHOW_DELAY, SHOW_DELAY_MS, NULL);
			return TRUE;
		}

		case WM_TIMER:
		{
			if (wparam == TIMER_SHOW_DELAY)
			{
				KillTimer(hwnd, TIMER_SHOW_DELAY);

				/* If operation still running, show the dialog now */
				if (g_wait.operation_pending)
				{
					g_wait.is_visible = TRUE;
					ShowWindow(hwnd, SW_SHOW);
				}
				return TRUE;
			}

			if (wparam == TIMER_CLOSE_DELAY)
			{
				/* Close delay elapsed - close the dialog */
				KillTimer(hwnd, TIMER_CLOSE_DELAY);
				_close_wait_dialog();
				return TRUE;
			}
			break;
		}

		case WM_WORKER_DONE:
		{
			/* Worker thread completed */
			KillTimer(hwnd, TIMER_SHOW_DELAY);

			if (!g_wait.is_visible)
			{
				/* Dialog was never shown, close immediately */
				_close_wait_dialog();
			}
			else
			{
				/* Dialog is visible - keep it open for 500ms to avoid gaps */
				SetTimer(hwnd, TIMER_CLOSE_DELAY, CLOSE_DELAY_MS, NULL);
			}
			return TRUE;
		}

		case WM_COMMAND:
		{
			if (LOWORD(wparam) == IDC_WAIT_CANCEL)
			{
				/* Signal abort and disable cancel button */
				InterlockedExchange(&g_wait.abort, 1);
				EnableWindow(GetDlgItem(hwnd, IDC_WAIT_CANCEL), FALSE);
				SetDlgItemTextW(hwnd, IDC_WAIT_TEXT, L"Cancelling, please wait...");
				return TRUE;
			}
			break;
		}

		case WM_CLOSE:
			/* Prevent closing with X button while operation is pending */
			if (g_wait.operation_pending) {
				InterlockedExchange(&g_wait.abort, 1);
				EnableWindow(GetDlgItem(hwnd, IDC_WAIT_CANCEL), FALSE);
				SetDlgItemTextW(hwnd, IDC_WAIT_TEXT, L"Cancelling, please wait...");
			} else {
				_close_wait_dialog();
			}
			return TRUE;

		case WM_DESTROY:
			g_wait.hwnd = NULL;
			return TRUE;

		case WM_CTLCOLORDLG:
			return _ctl_color(wparam, _cl(COLOR_BTNFACE, LGHT_CLR));

		case WM_CTLCOLORSTATIC:
			return _ctl_color(wparam, _cl(COLOR_BTNFACE, LGHT_CLR));

		case WM_DRAWITEM:
		{
			DRAWITEMSTRUCT *draw = (DRAWITEMSTRUCT*)lparam;
			_draw_static(draw);
			return TRUE;
		}
	}
	return FALSE;
}

/* Prepare dialog for a new operation */
static void _prepare_wait_dialog(HWND parent, const wchar_t *description)
{
	/* Check if we need to close existing dialog (different parent) */
	if (g_wait.hwnd && g_wait.parent != parent) {
		_close_wait_dialog();
	}

	/* Reset state for new operation */
	g_wait.abort = 0;
	g_wait.result = ST_ERROR;
	g_wait.operation_pending = TRUE;
	g_wait.description = description;
	g_wait.parent = parent;

	/* Kill any pending close timer */
	if (g_wait.hwnd) {
		KillTimer(g_wait.hwnd, TIMER_CLOSE_DELAY);
	}

	/* If dialog exists, reuse it */
	if (g_wait.hwnd) {
		/* Update description */
		SetDlgItemTextW(g_wait.hwnd, IDC_WAIT_TEXT, description);
		/* Re-enable cancel button */
		EnableWindow(GetDlgItem(g_wait.hwnd, IDC_WAIT_CANCEL), TRUE);

		/* If dialog is already visible, keep it visible */
		if (!g_wait.is_visible) {
			/* Reset show delay timer */
			SetTimer(g_wait.hwnd, TIMER_SHOW_DELAY, SHOW_DELAY_MS, NULL);
		}
	} else {
		/* Create new modeless dialog (starts hidden due to no WS_VISIBLE) */
		g_wait.is_visible = FALSE;
		CreateDialogParamW(
			GetModuleHandle(NULL),
			MAKEINTRESOURCEW(IDD_DIALOG_WAIT),
			parent,
			_wait_dlg_proc,
			0
		);
	}
}

/* Generic helper to run wait dialog */
static int _run_wait_dialog(HWND parent, const wchar_t *description, wait_op_ctx *ctx)
{
	MSG msg;

	/* Store params in global state for worker wrapper */
	g_wait.params = ctx->params;
	g_wait.worker = ctx->worker;

	/* Prepare or reuse dialog */
	_prepare_wait_dialog(parent, description);

	/* Start worker thread */
	CreateThread(NULL, 0, _wait_worker_wrapper, NULL, 0, NULL);

	/* Pump messages until operation completes */
	while (g_wait.operation_pending) {
		if (GetMessage(&msg, NULL, 0, 0)) {
			/* Check if this is a message for the wait dialog */
			if (!g_wait.hwnd || !IsDialogMessage(g_wait.hwnd, &msg)) {
				TranslateMessage(&msg);
				DispatchMessage(&msg);
			}
		}
	}

	/* Copy abort flag back to context for caller to check */
	ctx->abort = g_wait.abort;

	/* Return result immediately - dialog may still be visible with close timer */
	return g_wait.result;
}

/* Public wrapper functions */

int _wait_dc_mount_volume(
	HWND parent,
	wchar_t *device,
	dc_pass *password,
	int flags,
	const wchar_t *description
)
{
	wait_op_ctx ctx = { 0 };
	mount_params params = { device, password, flags };
	ctx.params = &params;
	ctx.worker = _worker_mount_volume;
	return _run_wait_dialog(parent, description, &ctx);
}

int _wait_dc_mount_all(
	HWND parent,
	dc_pass *password,
	int *mounted,
	int flags,
	const wchar_t *description
)
{
	wait_op_ctx ctx = { 0 };
	mount_all_params params = { password, mounted, flags };
	ctx.params = &params;
	ctx.worker = _worker_mount_all;
	return _run_wait_dialog(parent, description, &ctx);
}

int _wait_dc_add_password(
	HWND parent,
	dc_pass *password,
	const wchar_t *description
)
{
	wait_op_ctx ctx = { 0 };
	add_pass_params params = { password };
	ctx.params = &params;
	ctx.worker = _worker_add_password;
	return _run_wait_dialog(parent, description, &ctx);
}

int _wait_dc_change_password(
	HWND parent,
	wchar_t *device,
	dc_pass *old_pass,
	dc_pass *new_pass,
	u32 flags,
	const wchar_t *description
)
{
	wait_op_ctx ctx = { 0 };
	change_pass_params params = { device, old_pass, new_pass, flags };
	ctx.params = &params;
	ctx.worker = _worker_change_password;
	return _run_wait_dialog(parent, description, &ctx);
}

int _wait_dc_start_encrypt(
	HWND parent,
	wchar_t *device,
	dc_pass *password,
	crypt_info *crypt,
	int flags,
	const wchar_t *description
)
{
	wait_op_ctx ctx = { 0 };
	start_encrypt_params params = { device, password, crypt, flags };
	ctx.params = &params;
	ctx.worker = _worker_start_encrypt;
	return _run_wait_dialog(parent, description, &ctx);
}

int _wait_dc_start_decrypt(
	HWND parent,
	wchar_t *device,
	dc_pass *password,
	crypt_info *crypt,
	const wchar_t *description
)
{
	wait_op_ctx ctx = { 0 };
	start_decrypt_params params = { device, password, crypt };
	ctx.params = &params;
	ctx.worker = _worker_start_decrypt;
	return _run_wait_dialog(parent, description, &ctx);
}

int _wait_dc_start_re_encrypt(
	HWND parent,
	wchar_t *device,
	dc_pass *password,
	crypt_info *crypt,
	const wchar_t *description
)
{
	wait_op_ctx ctx = { 0 };
	start_re_encrypt_params params = { device, password, crypt };
	ctx.params = &params;
	ctx.worker = _worker_start_re_encrypt;
	return _run_wait_dialog(parent, description, &ctx);
}

int _wait_dc_start_format(
	HWND parent,
	wchar_t *device,
	dc_pass *password,
	crypt_info *crypt,
	int flags,
	const wchar_t *description
)
{
	wait_op_ctx ctx = { 0 };
	start_format_params params = { device, password, crypt, flags };
	ctx.params = &params;
	ctx.worker = _worker_start_format;
	return _run_wait_dialog(parent, description, &ctx);
}

int _wait_dc_update_layout(
	HWND parent,
	wchar_t *device,
	dc_pass *password,
	crypt_info *crypt,
	int flags,
	const wchar_t *description
)
{
	wait_op_ctx ctx = { 0 };
	update_layout_params params = { device, password, crypt, flags };
	ctx.params = &params;
	ctx.worker = _worker_update_layout;
	return _run_wait_dialog(parent, description, &ctx);
}

int _wait_dc_backup_header(
	HWND parent,
	wchar_t *device,
	dc_pass *password,
	void *out,
	int *size,
	u32 flags,
	const wchar_t *description
)
{
	wait_op_ctx ctx = { 0 };
	backup_header_params params = { device, password, out, size, flags };
	ctx.params = &params;
	ctx.worker = _worker_backup_header;
	return _run_wait_dialog(parent, description, &ctx);
}

int _wait_dc_restore_header(
	HWND parent,
	wchar_t *device,
	dc_pass *password,
	void *in,
	int size,
	u32 flags,
	const wchar_t *description
)
{
	wait_op_ctx ctx = { 0 };
	restore_header_params params = { device, password, in, size, flags };
	ctx.params = &params;
	ctx.worker = _worker_restore_header;
	return _run_wait_dialog(parent, description, &ctx);
}

int _wait_dc_update_header(
	HWND parent,
	wchar_t *device,
	dc_pass *password,
	void *in,
	int size,
	u32 flags,
	const wchar_t *description
)
{
	wait_op_ctx ctx = { 0 };
	update_header_params params = { device, password, in, size, flags };
	ctx.params = &params;
	ctx.worker = _worker_update_header;
	return _run_wait_dialog(parent, description, &ctx);
}

/* User-mode wrapper functions */

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
)
{
	wait_op_ctx ctx = { 0 };
	um_decrypt_header_params params = { enc_header, enc_len, password,
		out_header, out_key, out_len, out_kdf, out_dk };
	ctx.params = &params;
	ctx.worker = _worker_um_decrypt_header;
	return _run_wait_dialog(parent, description, &ctx);
}

int _wait_dc_load_header_file(
	HWND parent,
	wchar_t *file_path,
	dc_pass *password,
	dc_header **out_header,
	xts_key **out_key,
	int *out_len,
	u8 *out_dk,
	const wchar_t *description
)
{
	wait_op_ctx ctx = { 0 };
	um_load_header_file_params params = { file_path, password,
		out_header, out_key, out_len, out_dk };
	ctx.params = &params;
	ctx.worker = _worker_um_load_header_file;
	return _run_wait_dialog(parent, description, &ctx);
}

int _wait_dc_derive_key_um(
	HWND parent,
	dc_pass *password,
	int kdf,
	u8 *salt,
	u8 *dk,
	const wchar_t *description
)
{
	wait_op_ctx ctx = { 0 };
	um_derive_key_params params = { password, kdf, salt, dk };
	ctx.params = &params;
	ctx.worker = _worker_um_derive_key;
	return _run_wait_dialog(parent, description, &ctx);
}
