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
#include <objbase.h>
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>

#include "main.h"
#include "prc_header.h"
#include "prc_common.h"
#include "prc_pass.h"
#include "prc_wait.h"
#include "pass.h"
#include "drv_ioctl.h"
#include "dc_header.h"


/* Operation modes */
#define MODE_VOLUME     0
#define MODE_FILE       1

/* Backup sync status flags */
#define SYNC_OK             0x00
#define SYNC_BASE_MISMATCH  0x01  /* Header base fields mismatch */
#define SYNC_SLOTS_MISMATCH 0x02  /* Slot layout mismatch */
#define SYNC_EXT_MISMATCH   0x04  /* Extended header mismatch */

/* Dialog state structure */
typedef struct _keys_dlg_state {
    _tab_data       tab;                /* Must be first for tab system compatibility */

    int             mode;               /* MODE_VOLUME or MODE_FILE */
    wchar_t         device[MAX_PATH];   /* Device path (for volumes) */
    wchar_t         file_path[MAX_PATH];/* File path (for backup files) */

    dc_header      *header;             /* Decrypted primary header */
    int             header_len;         /* Header length in bytes */
    xts_key        *hdr_key;            /* Primary header encryption key */
    dc_pass        *password;           /* User password */

    dc_header      *backup_header;      /* Decrypted backup header (if present) */
    int             backup_header_len;  /* Backup header length */
    xts_key        *backup_hdr_key;     /* Backup header encryption key */

    /* Backup sync status */
    u32             backup_sync_status; /* SYNC_* flags indicating what's out of sync */
    u32             slots_out_of_sync;  /* Bitmask of slots that differ between primary and backup */

    BOOL            initializing;       /* TRUE during control initialization */
    u32             modified;           /* HF_UPDATE_* flags for pending changes */
    u32             orig_disk_id;       /* For change detection */

    int             selected_slot;      /* Currently selected slot index (-1 if none) */
    BOOL            slot_edit_mode;     /* TRUE if in slot editor view */
    int             editing_slot;       /* Slot being edited */

    /* Layout change state */
    BOOL            layout_modified;    /* TRUE if layout change is pending */
    u32             orig_head_len;      /* Original header size */
    BOOL            orig_has_backup;    /* Original backup header state */
    BOOL            orig_storage_file;  /* Original storage location (file vs partition end) */

    /* Cached derived key for primary header password */
    u8              cached_primary_hdk[PKCS_DERIVE_MAX];
    BOOL            cached_primary_hdk_valid;

    /* Cached derived key for backup header password */
    u8              cached_backup_hdk[PKCS_DERIVE_MAX];
    BOOL            cached_backup_hdk_valid;

} keys_dlg_state;

/* Forward declarations */
static INT_PTR CALLBACK _wizard_keys_dlg_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam);
static INT_PTR CALLBACK _keys_slots_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam);
static INT_PTR CALLBACK _keys_props_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam);
static int  _load_header_from_volume(HWND hwnd, keys_dlg_state *state, wchar_t *device, dc_pass *password);
static int  _load_header_from_file(HWND hwnd, keys_dlg_state *state, wchar_t *file_path, dc_pass *password);
static int  _save_header_to_volume(HWND hwnd, keys_dlg_state *state, dc_header* upd_header, int head_size);
static int  _save_header_to_file(keys_dlg_state *state, dc_header* upd_header, int head_size);

static void _populate_slot_list(HWND h_list, keys_dlg_state *state);
static void _update_slot_buttons(HWND hwnd, keys_dlg_state *state);
static int  _set_slot_password(HWND hwnd, keys_dlg_state *state, int slot_idx);
static int  _set_boot_password(HWND hwnd, keys_dlg_state *state, int slot_idx);
static int  _clear_slot(HWND hwnd, keys_dlg_state *state, int slot_idx);
static int  _toggle_slot(HWND hwnd, keys_dlg_state *state, int slot_idx);
static int  _test_slot_password(HWND hwnd, keys_dlg_state *state, int slot_idx);

static void _show_slot_editor(HWND hwnd, keys_dlg_state *state, int slot_idx);

static void _update_props_controls(HWND hwnd, keys_dlg_state *state);
static void _check_layout_modified(HWND hwnd, keys_dlg_state *state);
static int  _apply_layout_changes(HWND hwnd, keys_dlg_state *state);
static int  _apply_header_changes(HWND hwnd, keys_dlg_state *state, dc_header** out_header, int* out_size);
static void _verify_backup_sync(keys_dlg_state *state);
static void _sync_backup_from_primary(keys_dlg_state *state);


/*
 * Format a ULONG tag as a display string.
 * If the tag contains only printable ASCII (0x20-0x7E) and NUL (0x00),
 * display it as a quoted string. Otherwise display as uppercase hex.
 */
//static void _format_tag_display(ULONG tag, wchar_t *out, int out_size)
//{
//    unsigned char bytes[4];
//    int i, j;
//    wchar_t str[5] = {0};
//    BOOL is_printable = TRUE;
//
//    /* Extract bytes */
//    bytes[3] = (unsigned char)(tag & 0xFF);
//    bytes[2] = (unsigned char)((tag >> 8) & 0xFF);
//    bytes[1] = (unsigned char)((tag >> 16) & 0xFF);
//    bytes[0] = (unsigned char)((tag >> 24) & 0xFF);
//
//    /* Check if all bytes are printable ASCII or NUL */
//    for (i = 0; i < 4; i++) {
//        if (bytes[i] != 0 && (bytes[i] < 0x20 || bytes[i] > 0x7E)) {
//            is_printable = FALSE;
//            break;
//        }
//    }
//
//    if (is_printable && tag != 0) {
//        /* Format as quoted ASCII string */
//        for (i = 0, j = 0; i < 4; i++) {
//			if (j > 0 || bytes[i]) { /* Skip leading spaces */
//                str[j++] = bytes[i] ? (wchar_t)bytes[i] : L' ';
//            }
//        }
//        /* Trim trailing spaces */
//        for (i = j; i > 0 && str[i-1] == L' '; i--) {
//            str[i] = 0;
//        }
//        //_snwprintf(out, out_size, L"'%s'", str);
//		wcscpy_s(out, out_size, str);
//    } else {
//        /* Format as hex */
//        _snwprintf(out, out_size, L"0x%08X", tag);
//        //_snwprintf(out, out_size, L"%X", tag);
//    }
//}

/*
 * Tag selection dialog state
 */
typedef struct _tag_select_state {
    dc_pass_info *items;
    int           item_count;
    char          selected_label[SLOT_LABEL_LEN];
    int           selected_kdf;
} tag_select_state;

/*
 * Set KDF combo selection by value (without re-populating).
 */
static void _set_kdf_combo_sel(HWND h_combo, int kdf)
{
    int i, count;
    if (kdf < -1)
        kdf = KDF_SHA512_PKCS5_2;
    count = (int)SendMessage(h_combo, CB_GETCOUNT, 0, 0);
    for (i = 0; i < count; i++) {
        /* kdf_names index matches combo index since _init_combo adds in order */
        if (kdf_names[i].val == kdf) {
            SendMessage(h_combo, CB_SETCURSEL, i, 0);
            return;
        }
    }
    /* Fallback to first item */
    SendMessage(h_combo, CB_SETCURSEL, 0, 0);
}

/*
 * Tag selection dialog procedure
 */
static INT_PTR CALLBACK _select_tag_dlg_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam)
{
    tag_select_state *state = (tag_select_state*)wnd_get_long(hwnd, GWL_USERDATA);

    switch (message)
    {
        case WM_INITDIALOG:
        {
            HWND h_combo_tag = GetDlgItem(hwnd, IDC_COMBO_SELECT_TAG);
            HWND h_combo_kdf = GetDlgItem(hwnd, IDC_COMBO_SELECT_KDF);
            int i;

            state = (tag_select_state*)lparam;
            wnd_set_long(hwnd, GWL_USERDATA, state);

            /* Populate combo box with lebels */
            for (i = 0; i < state->item_count; i++) {
                wchar_t display[64];
                int idx;
                if (!*state->items[i].label) continue;  /* Skip unlabeled passwords */
                //_format_tag_display(state->items[i].tag, display, countof(display));
                MultiByteToWideChar(CP_UTF8, 0, state->items[i].label, SLOT_LABEL_LEN, display, countof(display) - 1);
                display[countof(display) - 1] = 0;
                idx = (int)SendMessage(h_combo_tag, CB_ADDSTRING, 0, (LPARAM)display);
                SendMessage(h_combo_tag, CB_SETITEMDATA, idx, (LPARAM)i);  /* Store index for kdf lookup */
            }

            /* Select first item and get its KDF */
            if (SendMessage(h_combo_tag, CB_GETCOUNT, 0, 0) > 0) {
                int item_idx;
                SendMessage(h_combo_tag, CB_SETCURSEL, 0, 0);
                item_idx = (int)SendMessage(h_combo_tag, CB_GETITEMDATA, 0, 0);
                memcpy(state->selected_label, state->items[item_idx].label, SLOT_LABEL_LEN);
                state->selected_kdf = state->items[item_idx].kdf == KDF_DEFAULT ? KDF_SHA512_PKCS5_2 : state->items[item_idx].kdf;
            }

            /* Initialize KDF combo once with the initial KDF value */
            _init_combo(h_combo_kdf, kdf_names, state->selected_kdf, FALSE, -1);

            return TRUE;
        }

        case WM_COMMAND:
        {
            int id = LOWORD(wparam);
            int code = HIWORD(wparam);

            if (id == IDC_COMBO_SELECT_TAG && code == CBN_SELCHANGE)
            {
                HWND h_combo_tag = GetDlgItem(hwnd, IDC_COMBO_SELECT_TAG);
                HWND h_combo_kdf = GetDlgItem(hwnd, IDC_COMBO_SELECT_KDF);
                int sel = (int)SendMessage(h_combo_tag, CB_GETCURSEL, 0, 0);
                if (sel != CB_ERR) {
                    int item_idx = (int)SendMessage(h_combo_tag, CB_GETITEMDATA, sel, 0);
                    memcpy(state->selected_label, state->items[item_idx].label, SLOT_LABEL_LEN);
                    state->selected_kdf = state->items[item_idx].kdf == KDF_DEFAULT ? KDF_SHA512_PKCS5_2 : state->items[item_idx].kdf;
                    /* Update KDF combo selection */
                    _set_kdf_combo_sel(h_combo_kdf, state->selected_kdf);
                }
                return TRUE;
            }

            if (id == IDC_COMBO_SELECT_KDF && code == CBN_SELCHANGE)
            {
                HWND h_combo_kdf = GetDlgItem(hwnd, IDC_COMBO_SELECT_KDF);
                state->selected_kdf = _get_combo_val(h_combo_kdf, kdf_names);
                return TRUE;
            }

            if (id == IDOK)
            {
                EndDialog(hwnd, IDOK);
                return TRUE;
            }

            if (id == IDCANCEL)
            {
                EndDialog(hwnd, IDCANCEL);
                return TRUE;
            }
            break;
        }

        case WM_CLOSE:
            EndDialog(hwnd, IDCANCEL);
            return TRUE;
    }

    return FALSE;
}

/*
 * Show tag selection dialog and return selected tag.
 * Returns ST_OK if a tag was selected, ST_CANCEL if cancelled,
 * or ST_ERROR if no cached passwords available.
 */
static int _select_cached_password_tag(HWND hwnd, char *out_label, int *out_kdf)
{
    dc_pass_info items[64];
    int total_count = 0;
    int tagged_count = 0;
    int resl, i;
    tag_select_state state = {0};

    /* Get list of cached password info */
    resl = dc_enum_passwords(items, countof(items), &total_count);
    if (resl != ST_OK && resl != ST_MORE_DATA) {
        return ST_ERROR;
    }

    if (total_count == 0) {
        __msg_e(hwnd, L"No cached passwords available.\n\n"
            L"Passwords are cached by the bootloader during boot or when you mount a volume.");
        return ST_ERROR;
    }

    /* Count non-zero tags */
    for (i = 0; i < min(total_count, (int)countof(items)); i++) {
        if (*items[i].label) tagged_count++;
    }

    if (tagged_count == 0) {
        __msg_e(hwnd, L"No labeled passwords available.");
        return ST_ERROR;
    }

    state.items = items;
    state.item_count = min(total_count, (int)countof(items));
	memset(state.selected_label, 0, SLOT_LABEL_LEN);
    state.selected_kdf = KDF_SHA512_PKCS5_2;

    if (DialogBoxParam(__hinst, MAKEINTRESOURCE(DLG_SELECT_TAG), hwnd,
            _select_tag_dlg_proc, (LPARAM)&state) != IDOK)
    {
        return ST_CANCEL;
    }

	memcpy(out_label, state.selected_label, SLOT_LABEL_LEN);
    if (out_kdf) *out_kdf = state.selected_kdf;
    return ST_OK;
}


/*
 * Public API: Open header configuration dialog for a volume
 */
int _dlg_header_config_volume(HWND hwnd, _dnode *node)
{
    keys_dlg_state *state = NULL;
    dlgpass         dlg_info = { NULL, node, PF_NO_KEY_SLOTS };
    int             resl = ST_ERROR;

    if (!node || node->is_root) {
        __msg_e(hwnd, L"Please select a volume");
        return ST_ERROR;
    }

    /* Allocate state */
    state = (keys_dlg_state*)secure_alloc(sizeof(keys_dlg_state));
    if (!state) {
        __msg_e(hwnd, L"Memory allocation failed");
        return ST_NOMEM;
    }
    memset(state, 0, sizeof(keys_dlg_state));

    state->mode = MODE_VOLUME;
    wcscpy(state->device, node->mnt.info.device);
    state->selected_slot = -1;

    /* Get password from user */
    resl = _dlg_get_pass(hwnd, &dlg_info);
    if (resl != ST_OK) {
        goto cleanup;
    }

    /* Load header from volume */
    resl = _load_header_from_volume(hwnd, state, state->device, dlg_info.pass);
    secure_free(dlg_info.pass);

    if (resl != ST_OK) {
        __error_s(hwnd, L"Failed to load volume header", resl);
        goto cleanup;
    }

    /* Warn if backup header is out of sync */
    if (state->backup_header && state->backup_sync_status != SYNC_OK)
    {
        wchar_t msg[512];
        wchar_t details[256] = { 0 };

        if (state->backup_sync_status & SYNC_BASE_MISMATCH) {
            wcscat(details, L"- Header base fields\n");
        }
        if (state->backup_sync_status & SYNC_SLOTS_MISMATCH) {
            wcscat(details, L"- Keyslot configuration\n");
        }
        if (state->backup_sync_status & SYNC_EXT_MISMATCH) {
            wcscat(details, L"- Extended header data\n");
        }

        _snwprintf(msg, countof(msg),
            L"The backup header is out of sync with the primary header.\n\n"
            L"Mismatched areas:\n%s\n"
            L"Applying changes will synchronize the backup header with the primary header "
            L"(except for salt and keyslot passwords which are independent).",
            details);

        MessageBox(hwnd, msg, L"Backup Header Out of Sync", MB_OK | MB_ICONWARNING);
    }

    /* Show configuration dialog */
    resl = (int)DialogBoxParam(
        __hinst,
        MAKEINTRESOURCE(IDD_DIALOG_HEADER),
        hwnd,
        _wizard_keys_dlg_proc,
        (LPARAM)state
    );

cleanup:
    if (state) {
        if (state->header) {
            burn(state->header, state->header_len);
            secure_free(state->header);
        }
        if (state->hdr_key) {
            burn(state->hdr_key, sizeof(xts_key));
            secure_free(state->hdr_key);
        }
        if (state->backup_header) {
            burn(state->backup_header, state->backup_header_len);
            secure_free(state->backup_header);
        }
        if (state->backup_hdr_key) {
            burn(state->backup_hdr_key, sizeof(xts_key));
            secure_free(state->backup_hdr_key);
        }
        if (state->password) {
            burn(state->password, sizeof(dc_pass));
            secure_free(state->password);
        }
        /* Clear cached derived keys */
        burn(state->cached_primary_hdk, sizeof(state->cached_primary_hdk));
        state->cached_primary_hdk_valid = FALSE;
        burn(state->cached_backup_hdk, sizeof(state->cached_backup_hdk));
        state->cached_backup_hdk_valid = FALSE;
        secure_free(state);
    }
    return resl;
}

/*
 * Public API: Open header configuration dialog for a backup file
 */
int _dlg_header_config_file(HWND hwnd, wchar_t *file_path)
{
    keys_dlg_state *state = NULL;
    dlgpass         dlg_info = { NULL, NULL, PF_NO_KEY_SLOTS };
    int             resl = ST_ERROR;

    if (!file_path || !file_path[0]) {
        __msg_e(hwnd, L"Please specify a header backup file");
        return ST_ERROR;
    }

    /* Allocate state */
    state = (keys_dlg_state*)secure_alloc(sizeof(keys_dlg_state));
    if (!state) {
        __msg_e(hwnd, L"Memory allocation failed");
        return ST_NOMEM;
    }
    memset(state, 0, sizeof(keys_dlg_state));

    state->mode = MODE_FILE;
    wcscpy(state->file_path, file_path);
    state->selected_slot = -1;

    /* Get password from user */
    resl = _dlg_get_pass(hwnd, &dlg_info);
    if (resl != ST_OK) {
        goto cleanup;
    }

    /* Load header from file */
    resl = _load_header_from_file(hwnd, state, file_path, dlg_info.pass);
    secure_free(dlg_info.pass);

    if (resl != ST_OK) {
        __error_s(hwnd, L"Failed to load header from file", resl);
        goto cleanup;
    }

    /* Show configuration dialog */
    resl = (int)DialogBoxParam(
        __hinst,
        MAKEINTRESOURCE(IDD_DIALOG_HEADER),
        hwnd,
        _wizard_keys_dlg_proc,
        (LPARAM)state
    );

cleanup:
    if (state) {
        if (state->header) {
            burn(state->header, state->header_len);
            secure_free(state->header);
        }
        if (state->hdr_key) {
            burn(state->hdr_key, sizeof(xts_key));
            secure_free(state->hdr_key);
        }
        if (state->backup_header) {
            burn(state->backup_header, state->backup_header_len);
            secure_free(state->backup_header);
        }
        if (state->backup_hdr_key) {
            burn(state->backup_hdr_key, sizeof(xts_key));
            secure_free(state->backup_hdr_key);
        }
        if (state->password) {
            burn(state->password, sizeof(dc_pass));
            secure_free(state->password);
        }
        /* Clear cached derived keys */
        burn(state->cached_primary_hdk, sizeof(state->cached_primary_hdk));
        state->cached_primary_hdk_valid = FALSE;
        burn(state->cached_backup_hdk, sizeof(state->cached_backup_hdk));
        state->cached_backup_hdk_valid = FALSE;
        secure_free(state);
    }
    return resl;
}

/*
 * Main wizard dialog procedure
 */
static INT_PTR CALLBACK _wizard_keys_dlg_proc(
    HWND   hwnd,
    UINT   message,
    WPARAM wparam,
    LPARAM lparam
)
{
    keys_dlg_state *state = (keys_dlg_state*)wnd_get_long(hwnd, GWL_USERDATA);

    switch (message)
    {
        case WM_INITDIALOG:
        {
            HWND       h_tab = GetDlgItem(hwnd, IDT_KEYS_TAB);
            TCITEM     tab_item = { TCIF_TEXT };
            _wnd_data *wnd;

            state = (keys_dlg_state*)lparam;
            wnd_set_long(hwnd, GWL_USERDATA, state);

            /* Create tab pages */
            wnd = _sub_class(
                h_tab, SUB_NONE,
                CreateDialog(__hinst, MAKEINTRESOURCE(DLG_KEYS_SLOTS), GetDlgItem(hwnd, IDC_KEYS_TAB), _keys_slots_proc),
                CreateDialog(__hinst, MAKEINTRESOURCE(DLG_HEADER_PROPS), GetDlgItem(hwnd, IDC_KEYS_TAB), _keys_props_proc),
                HWND_NULL
            );

            /* Initialize tab_data for proper tab switching */
            state->tab.curr_tab = 1;
            state->tab.active = wnd->dlg[0];

            /* Store state in tab pages */
            wnd_set_long(wnd->dlg[0], GWL_USERDATA, state);
            wnd_set_long(wnd->dlg[1], GWL_USERDATA, state);

            /* Insert tabs */
            tab_item.pszText = L"Key Slots";
            TabCtrl_InsertItem(h_tab, 0, &tab_item);

            tab_item.pszText = L"Properties";
            TabCtrl_InsertItem(h_tab, 1, &tab_item);

            /* Select first tab */
            TabCtrl_SetCurSel(h_tab, 0);
            _change_page(h_tab, 0);

            /* Initialize controls (set flag to prevent false modification detection) */
            state->initializing = TRUE;
            _populate_slot_list(GetDlgItem(wnd->dlg[0], IDC_KEYS_SLOT_LIST), state);
            _update_props_controls(wnd->dlg[1], state);
            state->initializing = FALSE;

            /* Disable Key Slots tab if not v2 header */
            if (!dc_has_key_slots(state->header)) {
                EnableWindow(wnd->dlg[0], FALSE);
                /* Disable slot buttons when no key slots available */
                EnableWindow(GetDlgItem(hwnd, IDC_BTN_SET_SLOT_PASS), FALSE);
                EnableWindow(GetDlgItem(hwnd, IDC_BTN_TEST_SLOT_PASS), FALSE);
                EnableWindow(GetDlgItem(hwnd, IDC_BTN_EDIT_SLOT), FALSE);
                EnableWindow(GetDlgItem(hwnd, IDC_BTN_TOGGLE_SLOT), FALSE);
                EnableWindow(GetDlgItem(hwnd, IDC_BTN_CLEAR_SLOT), FALSE);
                EnableWindow(GetDlgItem(hwnd, IDC_BTN_SET_BOOT_PASS), FALSE);
            } else {
                /* Start with slot buttons disabled until a slot is selected */
                EnableWindow(GetDlgItem(hwnd, IDC_BTN_SET_SLOT_PASS), FALSE);
                EnableWindow(GetDlgItem(hwnd, IDC_BTN_TEST_SLOT_PASS), FALSE);
                EnableWindow(GetDlgItem(hwnd, IDC_BTN_EDIT_SLOT), FALSE);
                EnableWindow(GetDlgItem(hwnd, IDC_BTN_TOGGLE_SLOT), FALSE);
                EnableWindow(GetDlgItem(hwnd, IDC_BTN_CLEAR_SLOT), FALSE);
                EnableWindow(GetDlgItem(hwnd, IDC_BTN_SET_BOOT_PASS), FALSE);
            }

            return TRUE;
        }

        case WM_NOTIFY:
        {
            if (wparam == IDT_KEYS_TAB)
            {
                NMHDR *mhdr = (NMHDR*)lparam;
                if (mhdr->code == TCN_SELCHANGE)
                {
                    HWND h_tab = GetDlgItem(hwnd, IDT_KEYS_TAB);
                    int  k_sel = TabCtrl_GetCurSel(h_tab);

                    if (!_is_curr_in_group(h_tab)) {
                        _change_page(h_tab, k_sel);
                    }

                    /* Enable/disable slot buttons based on active tab */
                    if (k_sel == 0 && dc_has_key_slots(state->header)) {
                        /* Key Slots tab - enable buttons based on selection */
                        _wnd_data *wnd = wnd_get_long(h_tab, GWL_USERDATA);
                        _update_slot_buttons(wnd->dlg[0], state);
                    } else {
                        /* Not on Key Slots tab - disable all slot buttons */
                        EnableWindow(GetDlgItem(hwnd, IDC_BTN_SET_SLOT_PASS), FALSE);
                        EnableWindow(GetDlgItem(hwnd, IDC_BTN_TEST_SLOT_PASS), FALSE);
                        EnableWindow(GetDlgItem(hwnd, IDC_BTN_EDIT_SLOT), FALSE);
                        EnableWindow(GetDlgItem(hwnd, IDC_BTN_TOGGLE_SLOT), FALSE);
                        EnableWindow(GetDlgItem(hwnd, IDC_BTN_CLEAR_SLOT), FALSE);
                        EnableWindow(GetDlgItem(hwnd, IDC_BTN_SET_BOOT_PASS), FALSE);
                    }
                    return TRUE;
                }
            }
            break;
        }

        case WM_COMMAND:
        {
            int id = LOWORD(wparam);
            int code = HIWORD(wparam);

            switch (id)
            {
                case IDOK:
                case IDC_BTN_APPLY:
                {
                    int resl;
                    dc_header* upd_header = NULL;
                    int head_size = 0;

                    if (!state->modified) {
                        if (id == IDOK) EndDialog(hwnd, ST_OK);
                        return TRUE;
                    }

                    /* Apply UI changes to header structure */
                    resl = _apply_header_changes(hwnd, state, &upd_header, &head_size);
                    if (resl != ST_OK) {
                        return TRUE;
                    }

                    /* Save changes to volume or file */
                    if (state->mode == MODE_VOLUME) {
                        resl = _save_header_to_volume(hwnd, state, upd_header, head_size);
                    } else {
                        resl = _save_header_to_file(state, upd_header, head_size);
                    }

					if (upd_header) secure_free(upd_header);

                    if (resl != ST_OK) {
                        __error_s(hwnd, L"Failed to save header changes", resl);
                        return TRUE;
                    }

                    /* Reload header from driver/file to verify round-trip */
                    {
                        dc_header *old_header = state->header;
                        xts_key *old_key = state->hdr_key;
                        int old_len = state->header_len;
                        dc_header *old_backup = state->backup_header;
                        xts_key *old_backup_key = state->backup_hdr_key;
                        int old_backup_len = state->backup_header_len;

                        state->header = NULL;
                        state->hdr_key = NULL;
                        state->header_len = 0;
                        state->backup_header = NULL;
                        state->backup_hdr_key = NULL;
                        state->backup_header_len = 0;
                        state->cached_backup_hdk_valid = FALSE;

                        if (state->mode == MODE_VOLUME) {
                            resl = _load_header_from_volume(hwnd, state, state->device, state->password);
                        } else {
                            resl = _load_header_from_file(hwnd, state, state->file_path, state->password);
                        }

                        if (resl != ST_OK) {
                            /* Reload failed - restore old state and warn user */
                            state->header = old_header;
                            state->hdr_key = old_key;
                            state->header_len = old_len;
                            state->backup_header = old_backup;
                            state->backup_hdr_key = old_backup_key;
                            state->backup_header_len = old_backup_len;
                            __error_s(hwnd, L"Save succeeded but failed to reload header", resl);
                        } else {
                            /* Reload succeeded - free old data */
                            if (old_header) {
                                burn(old_header, old_len);
                                secure_free(old_header);
                            }
                            if (old_key) {
                                burn(old_key, sizeof(xts_key));
                                secure_free(old_key);
                            }
                            if (old_backup) {
                                burn(old_backup, old_backup_len);
                                secure_free(old_backup);
                            }
                            if (old_backup_key) {
                                burn(old_backup_key, sizeof(xts_key));
                                secure_free(old_backup_key);
                            }
                        }
                    }

                    /* Refresh UI to reflect reloaded state */
                    state->initializing = TRUE;
                    {
                        HWND h_tab = GetDlgItem(hwnd, IDT_KEYS_TAB);
                        _wnd_data *wnd = wnd_get_long(h_tab, GWL_USERDATA);
                        _populate_slot_list(GetDlgItem(wnd->dlg[0], IDC_KEYS_SLOT_LIST), state);
                        _update_props_controls(wnd->dlg[1], state);

                        /* Update slot buttons based on current state */
                        if (dc_has_key_slots(state->header)) {
                            EnableWindow(wnd->dlg[0], TRUE);
                            _update_slot_buttons(wnd->dlg[0], state);
                        } else {
                            EnableWindow(wnd->dlg[0], FALSE);
                            EnableWindow(GetDlgItem(hwnd, IDC_BTN_SET_SLOT_PASS), FALSE);
                            EnableWindow(GetDlgItem(hwnd, IDC_BTN_TEST_SLOT_PASS), FALSE);
                            EnableWindow(GetDlgItem(hwnd, IDC_BTN_EDIT_SLOT), FALSE);
                            EnableWindow(GetDlgItem(hwnd, IDC_BTN_TOGGLE_SLOT), FALSE);
                            EnableWindow(GetDlgItem(hwnd, IDC_BTN_CLEAR_SLOT), FALSE);
                            EnableWindow(GetDlgItem(hwnd, IDC_BTN_SET_BOOT_PASS), FALSE);
                        }
                    }
                    state->initializing = FALSE;

                    state->modified = 0;
                    EnableWindow(GetDlgItem(hwnd, IDC_BTN_APPLY), FALSE);

                    if (id == IDOK) {
                        EndDialog(hwnd, ST_OK);
                    }
                    return TRUE;
                }

                case IDCANCEL:
                {
                    EndDialog(hwnd, ST_CANCEL);
                    return TRUE;
                }

                case IDC_BTN_SET_SLOT_PASS:
                {
                    if (state && state->selected_slot >= 0) {
                        HWND h_tab = GetDlgItem(hwnd, IDT_KEYS_TAB);
                        _wnd_data *wnd = wnd_get_long(h_tab, GWL_USERDATA);
                        _set_slot_password(wnd->dlg[0], state, state->selected_slot);
                    }
                    return TRUE;
                }

                case IDC_BTN_EDIT_SLOT:
                {
                    if (state && state->selected_slot >= 0) {
                        HWND h_tab = GetDlgItem(hwnd, IDT_KEYS_TAB);
                        _wnd_data *wnd = wnd_get_long(h_tab, GWL_USERDATA);
                        _show_slot_editor(wnd->dlg[0], state, state->selected_slot);
                    }
                    return TRUE;
                }

                case IDC_BTN_TOGGLE_SLOT:
                {
                    if (state && state->selected_slot >= 0) {
                        HWND h_tab = GetDlgItem(hwnd, IDT_KEYS_TAB);
                        _wnd_data *wnd = wnd_get_long(h_tab, GWL_USERDATA);
                        _toggle_slot(wnd->dlg[0], state, state->selected_slot);
                    }
                    return TRUE;
                }

                case IDC_BTN_CLEAR_SLOT:
                {
                    if (state && state->selected_slot >= 0) {
                        HWND h_tab = GetDlgItem(hwnd, IDT_KEYS_TAB);
                        _wnd_data *wnd = wnd_get_long(h_tab, GWL_USERDATA);
                        _clear_slot(wnd->dlg[0], state, state->selected_slot);
                    }
                    return TRUE;
                }

                case IDC_BTN_SET_BOOT_PASS:
                {
                    if (state && state->selected_slot >= 0 && state->mode == MODE_VOLUME) {
                        HWND h_tab = GetDlgItem(hwnd, IDT_KEYS_TAB);
                        _wnd_data *wnd = wnd_get_long(h_tab, GWL_USERDATA);
                        _set_boot_password(wnd->dlg[0], state, state->selected_slot);
                    }
                    return TRUE;
                }

                case IDC_BTN_TEST_SLOT_PASS:
                {
                    if (state && state->selected_slot >= 0) {
                        HWND h_tab = GetDlgItem(hwnd, IDT_KEYS_TAB);
                        _wnd_data *wnd = wnd_get_long(h_tab, GWL_USERDATA);
                        _test_slot_password(wnd->dlg[0], state, state->selected_slot);
                    }
                    return TRUE;
                }

                case IDC_BTN_CHANGE_LAYOUT:
                {
                    if (state && state->layout_modified) {
                        _apply_layout_changes(hwnd, state);
                    }
                    return TRUE;
                }
            }
            break;
        }

        case WM_CLOSE:
        {
            if (state && state->modified) {
                int ret = MessageBox(hwnd,
                    L"You have unsaved changes. Do you want to save them?",
                    L"Header Editor",
                    MB_YESNOCANCEL | MB_ICONQUESTION);

                if (ret == IDYES) {
                    /* Save and close */
                    dc_header* upd_header = NULL;
                    int head_size = 0;
                    int resl = _apply_header_changes(hwnd, state, &upd_header, &head_size);
                    if (resl != ST_OK) {
                        return TRUE;  /* Apply failed, stay open */
                    }

                    if (state->mode == MODE_VOLUME) {
                        resl = _save_header_to_volume(hwnd, state, upd_header, head_size);
                    } else {
                        resl = _save_header_to_file(state, upd_header, head_size);
                    }

					if (upd_header) secure_free(upd_header);

                    if (resl != ST_OK) {
                        __error_s(hwnd, L"Failed to save header changes", resl);
                        return TRUE;  /* Save failed, stay open */
                    }
                    EndDialog(hwnd, ST_OK);
                } else if (ret == IDNO) {
                    /* Just close without saving */
                    EndDialog(hwnd, ST_CANCEL);
                }
                /* IDCANCEL - don't close, stay in dialog */
                return TRUE;
            }
            EndDialog(hwnd, ST_CANCEL);
            return TRUE;
        }

        default:
        {
            int rlt = _draw_proc(message, lparam);
            if (rlt != -1) {
                return rlt;
            }
        }
    }

    return FALSE;
}

/*
 * Key Slots tab dialog procedure
 */
static INT_PTR CALLBACK _keys_slots_proc(
    HWND   hwnd,
    UINT   message,
    WPARAM wparam,
    LPARAM lparam
)
{
    keys_dlg_state *state = (keys_dlg_state*)wnd_get_long(hwnd, GWL_USERDATA);

    switch (message)
    {
        case WM_INITDIALOG:
        {
            HWND h_list = GetDlgItem(hwnd, IDC_KEYS_SLOT_LIST);
            LVCOLUMN col = { LVCF_TEXT | LVCF_WIDTH };

            /* Setup list columns */
            col.pszText = L"#";
            col.cx = 30;
            ListView_InsertColumn(h_list, 0, &col);

            col.pszText = L"Name";
            col.cx = 100;
            ListView_InsertColumn(h_list, 1, &col);

            col.pszText = L"Status";
            col.cx = 70;
            ListView_InsertColumn(h_list, 2, &col);

            col.pszText = L"KDF";
            col.cx = 180;
            ListView_InsertColumn(h_list, 3, &col);

            ListView_SetExtendedListViewStyle(h_list,
                LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

            return TRUE;
        }

        case WM_NOTIFY:
        {
            NMHDR *nmhdr = (NMHDR*)lparam;

            if (nmhdr->idFrom == IDC_KEYS_SLOT_LIST)
            {
                if (nmhdr->code == LVN_ITEMCHANGED)
                {
                    NMLISTVIEW *nmlv = (NMLISTVIEW*)lparam;
                    if (nmlv->uChanged & LVIF_STATE)
                    {
                        if (nmlv->uNewState & LVIS_SELECTED) {
                            state->selected_slot = nmlv->iItem;
                        } else if (!(nmlv->uNewState & LVIS_SELECTED) &&
                                   (nmlv->uOldState & LVIS_SELECTED)) {
                            state->selected_slot = -1;
                        }
                        _update_slot_buttons(hwnd, state);
                    }
                }
                else if (nmhdr->code == NM_DBLCLK)
                {
                    /* Double-click opens the slot editor */
                    if (state && state->selected_slot >= 0) {
                        _show_slot_editor(hwnd, state, state->selected_slot);
                    }
                }
            }
            break;
        }

    }

    return _tab_proc(hwnd, message, wparam, lparam);
}

/*
 * Properties tab dialog procedure
 */
static INT_PTR CALLBACK _keys_props_proc(
    HWND   hwnd,
    UINT   message,
    WPARAM wparam,
    LPARAM lparam
)
{
    keys_dlg_state *state = (keys_dlg_state*)wnd_get_long(hwnd, GWL_USERDATA);

    switch (message)
    {
        case WM_INITDIALOG:
        {
            /* Setup controls */
            _sub_class(GetDlgItem(hwnd, IDC_CHECK_EXT_HEADER), SUB_STATIC_PROC, HWND_NULL);
            _sub_class(GetDlgItem(hwnd, IDC_CHECK_HDR_BACKUP), SUB_STATIC_PROC, HWND_NULL);

            /* Set header text */
            SetWindowText(GetDlgItem(hwnd, IDC_HEAD_VERSION), L"# Header Format");
            SendMessage(GetDlgItem(hwnd, IDC_HEAD_VERSION), WM_SETFONT, (WPARAM)__font_bold, 0);

            SetWindowText(GetDlgItem(hwnd, IDC_HEAD_PROPS), L"# Volume Properties");
            SendMessage(GetDlgItem(hwnd, IDC_HEAD_PROPS), WM_SETFONT, (WPARAM)__font_bold, 0);

            /* Limit disk ID input */
            SendMessage(GetDlgItem(hwnd, IDC_EDIT_DISK_ID), EM_LIMITTEXT, 8, 0);

            /* Limit slot count input */
            SendMessage(GetDlgItem(hwnd, IDC_EDIT_SLOT_COUNT), EM_LIMITTEXT, 2, 0);

            /* Limit volume comment input (UTF-8) */
            SendMessage(GetDlgItem(hwnd, IDC_EDIT_VOLUME_NOTE), EM_LIMITTEXT, 40, 0);

            return TRUE;
        }

        case WM_COMMAND:
        {
            int id = LOWORD(wparam);
            int code = HIWORD(wparam);

            switch (id)
            {
                case IDC_RADIO_V1:
                case IDC_RADIO_V2:
                {
                    if (code == BN_CLICKED && state && !state->initializing)
                    {
                        BOOL want_v2 = (id == IDC_RADIO_V2);
                        BOOL want_ext = _get_check(hwnd, IDC_CHECK_EXT_HEADER);

                        /* Warn if downgrading from v2 to v1 and there are active slots */
                        if (!want_v2 && (state->header->feature_flags & FF_KEY_SLOTS))
                        {
                            want_v2 = FALSE;
                            dc_slot_info slot;
                            for (int i = 0; i < state->header->key_slot_count; i++) {
                                if (dc_get_slot_info(state->header, i, &slot) == ST_OK && (slot.flags & SF_ACTIVE)) {
                                    want_v2 = TRUE;
                                    break;
                                }
                            }

                            if (want_v2) 
                            {
                                int ret = MessageBox(hwnd,
                                    L"Downgrading to v1 header will clear all key slots. Continue?",
                                    L"Warning",
                                    MB_YESNO | MB_ICONWARNING);
                                if (ret != IDYES) {
                                    CheckRadioButton(hwnd, IDC_RADIO_V1, IDC_RADIO_V2, IDC_RADIO_V2);
                                    return TRUE;
                                }

                                for (int i = 0; i < state->header->key_slot_count; i++) {
									dc_set_slot(state->header, i, (dc_slot_info*)-1, (u8*)-1, 0);
                                }

                                if (state->backup_header && dc_has_key_slots(state->backup_header)) {
                                    for (int i = 0; i < state->backup_header->key_slot_count; i++) {
                                        dc_set_slot(state->backup_header, i, (dc_slot_info*)-1, (u8*)-1, 0);
                                        /* Clear out-of-sync flag for this slot since both headers now match */
                                        state->slots_out_of_sync &= ~(1 << i);
                                    }
                                }
                            }
                        }

                        /* Enable/disable controls based on selected version */
                        EnableWindow(GetDlgItem(hwnd, IDC_EDIT_SLOT_COUNT), want_v2);
                        EnableWindow(GetDlgItem(hwnd, IDC_CHECK_EXT_HEADER), want_v2);

                        /* GUID only editable if v2 AND extended header checked */
                        EnableWindow(GetDlgItem(hwnd, IDC_EDIT_VOLUME_NOTE), want_v2 && want_ext);

                        /* Layout controls only enabled for v2 on actual volumes */
                        if (state->mode == MODE_VOLUME) {
                            EnableWindow(GetDlgItem(hwnd, IDC_COMBO_HDR_SIZE_PROPS), want_v2);
                            EnableWindow(GetDlgItem(hwnd, IDC_CHECK_HDR_BACKUP), want_v2);
                        }

                        /* Mark as modified - version change affects all parts */
                        state->modified = HF_UPDATE_ALL;
                        EnableWindow(GetDlgItem(GetParent(GetParent(hwnd)), IDC_BTN_APPLY), TRUE);
                    }
                    return TRUE;
                }

                //case IDC_EDIT_VOLUME_GUID:
                //{
                //    if (code == EN_CHANGE && state && !state->initializing)
                //    {
                //        state->modified |= HF_UPDATE_BASE;
                //        EnableWindow(GetDlgItem(GetParent(GetParent(hwnd)), IDC_BTN_APPLY), TRUE);
                //    }
                //    return TRUE;
                //}

                //case IDC_BTN_GEN_GUID:
                //{
                //    /* Button is only enabled when v2 and extended header are selected */
                //    if (state)
                //    {
                //        GUID new_guid;
                //        wchar_t guid_str[64];

                //        CoCreateGuid(&new_guid);
                //        StringFromGUID2(&new_guid, guid_str, countof(guid_str));
                //        SetDlgItemText(hwnd, IDC_EDIT_VOLUME_GUID, guid_str);

                //        state->modified |= HF_UPDATE_EXT;
                //        EnableWindow(GetDlgItem(GetParent(GetParent(hwnd)), IDC_BTN_APPLY), TRUE);
                //    }
                //    return TRUE;
                //}

                case IDC_EDIT_DISK_ID:
                {
                    if (code == EN_CHANGE && state && !state->initializing)
                    {
                        state->modified |= HF_UPDATE_BASE;
                        EnableWindow(GetDlgItem(GetParent(GetParent(hwnd)), IDC_BTN_APPLY), TRUE);
                    }
                    return TRUE;
                }

                case IDC_EDIT_SLOT_COUNT:
                {
                    if (code == EN_CHANGE && state && !state->initializing)
                    {
                        state->modified |= HF_UPDATE_BASE | HF_UPDATE_SLOTS;
                        EnableWindow(GetDlgItem(GetParent(GetParent(hwnd)), IDC_BTN_APPLY), TRUE);
                    }
                    return TRUE;
                }

                case IDC_EDIT_VOLUME_NOTE:
                {
                    if (code == EN_CHANGE && state && !state->initializing)
                    {
                        state->modified |= HF_UPDATE_EXT;
                        EnableWindow(GetDlgItem(GetParent(GetParent(hwnd)), IDC_BTN_APPLY), TRUE);
                    }
                    return TRUE;
                }

                case IDC_CHECK_EXT_HEADER:
                {
                    if (state && !state->initializing)
                    {
                        BOOL checked = _get_check(hwnd, IDC_CHECK_EXT_HEADER);

                        /* Enable/disable GUID and label controls based on extended header setting */
                        EnableWindow(GetDlgItem(hwnd, IDC_EDIT_VOLUME_NOTE), checked);
                        //EnableWindow(GetDlgItem(hwnd, IDC_EDIT_VOLUME_GUID), checked);
                        //EnableWindow(GetDlgItem(hwnd, IDC_BTN_GEN_GUID), checked);

                        /* Extended header toggle affects base (ext_hdr_off field) and ext */
                        state->modified |= HF_UPDATE_BASE | HF_UPDATE_EXT;
                        EnableWindow(GetDlgItem(GetParent(GetParent(hwnd)), IDC_BTN_APPLY), TRUE);
                    }
                    return TRUE;
                }

                case IDC_CHECK_HDR_BACKUP:
                case IDC_RADIO_STORAGE_FILE:
                case IDC_RADIO_STORAGE_END:
                {
                    if (state && !state->initializing)
                    {
                        _check_layout_modified(hwnd, state);
                    }
                    return TRUE;
                }
            }

            /* Handle combo box selection changes */
            if (code == CBN_SELCHANGE)
            {
                switch (id)
                {
                    case IDC_COMBO_HDR_SIZE_PROPS:
                    {
                        if (state && !state->initializing)
                        {
                            _check_layout_modified(hwnd, state);
                        }
                        return TRUE;
                    }
                }
            }
            break;
        }
    }

    return _tab_proc(hwnd, message, wparam, lparam);
}

/*
 * Populate the slot list view
 */
static void _populate_slot_list(HWND h_list, keys_dlg_state *state)
{
    int i;
    wchar_t buf[32];
    int prev_selection = state->selected_slot;

    ListView_DeleteAllItems(h_list);

    if (!dc_has_key_slots(state->header)) {
        state->selected_slot = -1;
        return;
    }

    for (i = 0; i < state->header->key_slot_count; i++)
    {
        LVITEM item = { LVIF_TEXT };
        dc_slot_info slot;

        /* Index column */
        _snwprintf(buf, countof(buf), L"%d", i + 1);
        item.iItem = i;
        item.iSubItem = 0;
        item.pszText = buf;
        ListView_InsertItem(h_list, &item);

        if (dc_get_slot_info(state->header, i, &slot) != ST_OK) {
            ListView_SetItemText(h_list, i, 1, L"");
            ListView_SetItemText(h_list, i, 2, L"Invalid");
            continue;
        }

        /* Name column - show name for active or corrupt slots (empty slots may have garbage) */
        if (slot.slot_name[0]) {
            wchar_t name_wide[32] = {0};
            MultiByteToWideChar(CP_UTF8, 0, slot.slot_name, sizeof(slot.slot_name), name_wide, countof(name_wide) - 1);
            name_wide[sizeof(slot.slot_name)] = 0;
            ListView_SetItemText(h_list, i, 1, name_wide);
        }

        /* Status column - include out-of-sync indicator if backup differs */
        {
            wchar_t status[32];
            BOOL out_of_sync = (state->backup_header && (state->slots_out_of_sync & (1 << i)));

            if (!(slot.flags & SF_ACTIVE)) {
                wcscpy(status, out_of_sync ? L"Empty *" : L"Empty");
            } else if (slot.flags & SF_CORRUPT) {
                wcscpy(status, out_of_sync ? L"Corrupt *" : L"Corrupt");
            } else if (slot.flags & SF_DISABLED) {
                wcscpy(status, out_of_sync ? L"Disabled *" : L"Disabled");
            } else {
                wcscpy(status, out_of_sync ? L"Active *" :  L"Active");
            }
            
            ListView_SetItemText(h_list, i, 2, status);
        }

        /* KDF column - show KDF name for active slots */
        {
            wchar_t *kdf_name = NULL;
            if (slot.flags & SF_ACTIVE) {
                kdf_name = _get_text_name(slot.data_0.slot_kdf, kdf_names_ex);
            }
            ListView_SetItemText(h_list, i, 3, kdf_name ? kdf_name : L"");
        }
    }

    /* Restore previous selection if valid */
    if (prev_selection >= 0 && prev_selection < state->header->key_slot_count) {
        ListView_SetItemState(h_list, prev_selection, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        state->selected_slot = prev_selection;
    } else {
        state->selected_slot = -1;
    }
}

/*
 * Update slot button states based on selection
 * Buttons are in the main dialog, not the slots tab dialog
 */
static void _update_slot_buttons(HWND hwnd, keys_dlg_state *state)
{
    HWND h_main;
    BOOL has_selection;

    /* Find main dialog window (parent of parent of slots tab) */
    h_main = GetParent(GetParent(hwnd));
    if (!h_main) h_main = hwnd;  /* Fallback */

    has_selection = (state && state->selected_slot >= 0 && dc_has_key_slots(state->header));

    /* Set Password - enabled when a slot is selected */
    EnableWindow(GetDlgItem(h_main, IDC_BTN_SET_SLOT_PASS), has_selection);
    /* Test Password - enabled when a slot is selected and active */
    {
        BOOL test_enabled = FALSE;
        if (has_selection) {
            dc_slot_info slot;
            if (dc_get_slot_info(state->header, state->selected_slot, &slot) == ST_OK) {
                /* Only enable for active slots (that have a password set) */
                if (slot.flags & SF_ACTIVE) {
                    test_enabled = TRUE;
                }
            }
        }
        EnableWindow(GetDlgItem(h_main, IDC_BTN_TEST_SLOT_PASS), test_enabled);
    }
    /* Edit Slot - enabled when a slot is selected (for name editing) */
    EnableWindow(GetDlgItem(h_main, IDC_BTN_EDIT_SLOT), has_selection);
    /* Toggle Slot - enabled when a non-empty slot is selected, text changes based on state */
    {
        BOOL toggle_enabled = FALSE;
        if (has_selection) {
            dc_slot_info slot;
            if (dc_get_slot_info(state->header, state->selected_slot, &slot) == ST_OK) {
                /* Only enable for non-empty slots (active or disabled) */
                if (slot.flags & (SF_ACTIVE | SF_DISABLED)) {
                    toggle_enabled = TRUE;
                    SetDlgItemText(h_main, IDC_BTN_TOGGLE_SLOT,
                        (slot.flags & SF_DISABLED) ? L"Enable Slot" : L"Disable Slot");
                }
            }
        }
        EnableWindow(GetDlgItem(h_main, IDC_BTN_TOGGLE_SLOT), toggle_enabled);
    }
    /* Clear Slot - only enabled for active slots */
    EnableWindow(GetDlgItem(h_main, IDC_BTN_CLEAR_SLOT), has_selection);

    /* Set Boot Password - enabled when:
     * - A slot is selected
     * - We're in volume mode (not file mode)
     * - System was booted via DC bootloader (DST_BOOTLOADER flag set)
     */
    {
        BOOL boot_pass_enabled = FALSE;
        if (has_selection && state->mode == MODE_VOLUME) {
            DC_FLAGS flags;
            if (dc_device_control(DC_CTL_GET_FLAGS, NULL, 0, &flags, sizeof(flags)) == NO_ERROR) {
                boot_pass_enabled = (flags.load_flags & DST_BOOTLOADER) ? TRUE : FALSE;
            }
        }
        EnableWindow(GetDlgItem(h_main, IDC_BTN_SET_BOOT_PASS), 1 | boot_pass_enabled);
    }
}

/*
 * Set password for a keyslot
 *
 * The slot ciphertext stores: header_derived_key XOR slot_derived_key
 * This allows recovering the header key using the slot password.
 */
static int _set_slot_password(HWND hwnd, keys_dlg_state *state, int slot_idx)
{
    dc_slot_info slot;
    u8 payload[PKCS_DERIVE_MAX];
    u8 backup_payload[PKCS_DERIVE_MAX];
    dlgpass dlg_info = { L"Enter Slot Password", NULL, PF_NEW_PASS_ONLY };
    int resl;
    HWND h_main;
    u8 header_dk[PKCS_DERIVE_MAX];
    u8 slot_dk[PKCS_DERIVE_MAX];
    u8 backup_header_dk[PKCS_DERIVE_MAX];
    u8 backup_slot_dk[PKCS_DERIVE_MAX];

    if ((resl = dc_get_slot_info(state->header, slot_idx, &slot)) != ST_OK) return resl;

    h_main = GetParent(GetParent(hwnd));

    /* Get header key - use cached value if available */
    if (!state->password) {
        __msg_e(hwnd, L"Password not available");
        return ST_ERROR;
    }
    if (state->cached_primary_hdk_valid) {
        memcpy(header_dk, state->cached_primary_hdk, PKCS_DERIVE_MAX);
    } else {
        int derive_result = _wait_dc_derive_key_um(hwnd, state->password, state->password->kdf,
            state->header->salt, header_dk, L"Deriving key...");
        if (derive_result != 1) {
            if (derive_result == -1) {
                resl = ST_CANCEL;
            } else {
                __msg_e(hwnd, L"Failed to derive header key");
                resl = ST_ERROR;
            }
            return resl;
        }
        /* Cache for future use */
        memcpy(state->cached_primary_hdk, header_dk, PKCS_DERIVE_MAX);
        state->cached_primary_hdk_valid = TRUE;
    }

    /* Get slot password from user with confirmation */
    resl = _dlg_change_pass(hwnd, &dlg_info);
    if (resl != ST_OK) {
        goto cleanup;
    }

    /* Derive slot key from slot password using primary header's salt */
    {
        int derive_result = _wait_dc_derive_key_um(hwnd, dlg_info.new_pass, dlg_info.new_pass->kdf,
            state->header->salt, slot_dk, L"Deriving slot key...");
        if (derive_result != 1) {
            if (derive_result == -1) {
                resl = ST_CANCEL;
            } else {
                __msg_e(hwnd, L"Failed to derive slot key");
                resl = ST_ERROR;
            }
            goto cleanup;
        }
    }

    slot.type = DC_SLOT_TYPE_0;
    slot.data_0.slot_kdf = (u8)dlg_info.new_pass->kdf;
    if (!dc_wrap_header_key(payload, slot_dk, header_dk, slot.type)) {
        __msg_e(hwnd, L"Failed to wrap header key with slot key");
        resl = ST_ERROR;
        goto cleanup;
    }

    /* Update slot on primary header */
    slot.flags |= SF_ACTIVE;
    slot.flags &= ~SF_CORRUPT;
    resl = dc_set_slot(state->header, slot_idx, &slot, payload, PKCS_DERIVE_MAX);
    if (resl != ST_OK) {
        goto cleanup;
    }

    /* Update backup header slot if backup exists */
    if (state->backup_header && state->backup_hdr_key)
    {
        int backup_ok = 1;
        /* Derive keys using backup header's salt (different from primary, so need wait dialog) */
        int derive_result = _wait_dc_derive_key_um(hwnd, state->password, state->password->kdf,
            state->backup_header->salt, backup_header_dk, L"Deriving backup key...");
        if (derive_result != 1) {
            __msg_e(hwnd, L"Failed to derive backup header key");
            backup_ok = 0;
        }
        if (backup_ok) {
            derive_result = _wait_dc_derive_key_um(hwnd, dlg_info.new_pass, dlg_info.new_pass->kdf,
                state->backup_header->salt, backup_slot_dk, L"Deriving backup slot key...");
            if (derive_result != 1) {
                __msg_e(hwnd, L"Failed to derive backup slot key");
                backup_ok = 0;
            }
        }
        if (backup_ok && !dc_wrap_header_key(backup_payload, backup_slot_dk, backup_header_dk, slot.type)) {
            __msg_e(hwnd, L"Failed to wrap backup header key");
            backup_ok = 0;
        }
        if (backup_ok) {
            /* Update slot on backup header */
            dc_set_slot(state->backup_header, slot_idx, &slot, backup_payload, PKCS_DERIVE_MAX);
            /* Clear out-of-sync flag for this slot since both headers now match */
            state->slots_out_of_sync &= ~(1 << slot_idx);
        }
        /* Continue even if backup failed - primary was updated */
    }

    /* Mark modified and refresh */
    state->modified |= HF_UPDATE_SLOTS;
    EnableWindow(GetDlgItem(h_main, IDC_BTN_APPLY), TRUE);
    _populate_slot_list(GetDlgItem(hwnd, IDC_KEYS_SLOT_LIST), state);
    _update_slot_buttons(hwnd, state);

cleanup:
    if (dlg_info.new_pass) secure_free(dlg_info.new_pass);
    burn(payload, PKCS_DERIVE_MAX);
    burn(backup_payload, PKCS_DERIVE_MAX);
    burn(header_dk, sizeof(header_dk));
    burn(slot_dk, sizeof(slot_dk));
    burn(backup_header_dk, sizeof(backup_header_dk));
    burn(backup_slot_dk, sizeof(backup_slot_dk));

    return resl;
}

/*
 * Set boot password for a keyslot
 *
 * This function uses dc_change_password to have the driver set a slot password
 * using a cached password selected by the user from a dialog.
 * Unlike _set_slot_password, this operates on the live volume through the driver.
 */
static int _set_boot_password(HWND hwnd, keys_dlg_state *state, int slot_idx)
{
    dc_slot_info slot;
    HWND h_main;
    int resl;
    dc_pass new_pass;
    BOOL slot_was_empty = FALSE;
    BOOL need_save = FALSE;
    char selected_label[SLOT_LABEL_LEN] = {0};
    int selected_kdf = 0;
    wchar_t display[64];

    if (!dc_has_key_slots(state->header)) return ST_ERROR;
    if (state->mode != MODE_VOLUME) {
        __msg_e(hwnd, L"Set Cached Password is only available for mounted volumes");
        return ST_ERROR;
    }

    if ((resl = dc_get_slot_info(state->header, slot_idx, &slot)) != ST_OK) return resl;

    h_main = GetParent(GetParent(hwnd));

    /* Show tag selection dialog */
    resl = _select_cached_password_tag(hwnd, selected_label, &selected_kdf);
    if (resl != ST_OK) {
        return resl;
    }

    /* Format the selected tag for display */
    //_format_tag_display(selected_tag, display, countof(display));
    MultiByteToWideChar(CP_UTF8, 0, selected_label, SLOT_LABEL_LEN, display, countof(display) - 1);
    display[countof(display) - 1] = 0;

    /* Check for unsaved changes first */
    if (state->modified)
    {
        int ret = MessageBox(hwnd,
            L"There are unsaved changes. Do you want to save them before setting the cached password?\n\n"
            L"Note: Setting a cached password operates on the live volume and requires the header to be saved first.",
            L"Unsaved Changes",
            MB_YESNOCANCEL | MB_ICONQUESTION);

        if (ret == IDCANCEL) {
            return ST_CANCEL;
        }

        if (ret == IDYES) {
            /* Apply and save changes */
            dc_header* upd_header = NULL;
            int head_size = 0;

            resl = _apply_header_changes(h_main, state, &upd_header, &head_size);
            if (resl != ST_OK) {
                return resl;
            }

            resl = _save_header_to_volume(hwnd, state, upd_header, head_size);
            if (upd_header) secure_free(upd_header);

            if (resl != ST_OK) {
                __error_s(hwnd, L"Failed to save header changes", resl);
                return resl;
            }

            state->modified = 0;
            EnableWindow(GetDlgItem(h_main, IDC_BTN_APPLY), FALSE);
        }
    }

    /* Confirm with user */
    {
        wchar_t msg[512];
        wchar_t slot_name[64];

        if (slot.slot_name[0]) {
            wchar_t name_wide[32] = {0};
            MultiByteToWideChar(CP_UTF8, 0, slot.slot_name, sizeof(slot.slot_name), name_wide, countof(name_wide) - 1);
            _snwprintf(slot_name, countof(slot_name), L"slot %d (%s)", slot_idx + 1, name_wide);
        } else {
            _snwprintf(slot_name, countof(slot_name), L"slot %d", slot_idx + 1);
        }

        _snwprintf(msg, countof(msg),
            L"This will set %s to use the cached password %s.\n\n"
            L"The driver will look up the password in the cache and use it to "
            L"derive the new slot key.\n\n"
            L"Do you want to continue?",
            slot_name, display);

        if (MessageBox(hwnd, msg, L"Set Cached Password", MB_YESNO | MB_ICONQUESTION) != IDYES) {
            return ST_CANCEL;
        }
    }

    /* Check if slot is unlabeled and needs to be labeled first */
    slot_was_empty = !(slot.flags & SF_ACTIVE);
    if (!slot.slot_name[0])
    {
        /* Label the slot with the tag */
		memcpy(slot.slot_name, selected_label, SLOT_LABEL_LEN);

        /* Update slot info on primary header */
        dc_set_slot(state->header, slot_idx, &slot, NULL, 0);

        /* Update slot info on backup header if it exists */
        if (state->backup_header && dc_has_key_slots(state->backup_header)) {
            dc_set_slot(state->backup_header, slot_idx, &slot, NULL, 0);
        }

        need_save = TRUE;
    }

    /* Save header changes if we modified the slot label */
    if (need_save)
    {
        dc_header* upd_header = NULL;
        int head_size = 0;

        state->modified |= HF_UPDATE_SLOTS;

        resl = _apply_header_changes(h_main, state, &upd_header, &head_size);
        if (resl != ST_OK) {
            return resl;
        }

        resl = _save_header_to_volume(hwnd, state, upd_header, head_size);
        if (upd_header) secure_free(upd_header);

        if (resl != ST_OK) {
            __error_s(hwnd, L"Failed to save slot label", resl);
            return resl;
        }

        state->modified = 0;
        EnableWindow(GetDlgItem(h_main, IDC_BTN_APPLY), FALSE);
    }

    /* Prepare old password (cached header password) */
    if (!state->password) {
        __msg_e(hwnd, L"Password not available");
        return ST_ERROR;
    }

    /* Prepare new password - special format to lookup password from cache by tag */
    memset(&new_pass, 0, sizeof(dc_pass));
    new_pass.size = 0;              /* Size 0 indicates lookup from cache */
    new_pass.kdf = selected_kdf;    /* Use selected KDF */
    new_pass.slot = slot_idx + 1;   /* 1-based slot index */
	memcpy(new_pass.label, selected_label, SLOT_LABEL_LEN);  /* Label to lookup the cached password */

    /* Call driver to change the slot password */
    resl = _wait_dc_change_password(hwnd, state->device, state->password, &new_pass, 0, L"Setting cached password...");

    burn(&new_pass, sizeof(new_pass));

    if (resl != ST_OK) {
        if (resl == ST_PASS_NOT_FOUND) {
                wchar_t err_msg[256];
                _snwprintf(err_msg, countof(err_msg),
                    L"Cached password %s not found.\n\n"
                    L"The password may have been cleared from the cache.", display);
            __msg_e(hwnd, err_msg);
        } else {
            __error_s(hwnd, L"Failed to set cached password", resl);
        }
        return resl;
    }

    /* Reload header to reflect changes */
    {
        dc_header *old_header = state->header;
        xts_key *old_key = state->hdr_key;
        int old_len = state->header_len;
        dc_header *old_backup = state->backup_header;
        xts_key *old_backup_key = state->backup_hdr_key;
        int old_backup_len = state->backup_header_len;

        state->header = NULL;
        state->hdr_key = NULL;
        state->header_len = 0;
        state->backup_header = NULL;
        state->backup_hdr_key = NULL;
        state->backup_header_len = 0;
        state->cached_backup_hdk_valid = FALSE;

        resl = _load_header_from_volume(hwnd, state, state->device, state->password);

        if (resl != ST_OK) {
            /* Reload failed - restore old state and warn user */
            state->header = old_header;
            state->hdr_key = old_key;
            state->header_len = old_len;
            state->backup_header = old_backup;
            state->backup_hdr_key = old_backup_key;
            state->backup_header_len = old_backup_len;
            __error_s(hwnd, L"Cached password set but failed to reload header", resl);
        } else {
            /* Reload succeeded - free old data */
            if (old_header) {
                burn(old_header, old_len);
                secure_free(old_header);
            }
            if (old_key) {
                burn(old_key, sizeof(xts_key));
                secure_free(old_key);
            }
            if (old_backup) {
                burn(old_backup, old_backup_len);
                secure_free(old_backup);
            }
            if (old_backup_key) {
                burn(old_backup_key, sizeof(xts_key));
                secure_free(old_backup_key);
            }

            MessageBox(hwnd, L"Cached password has been successfully set for this slot.",
                L"Success", MB_OK | MB_ICONINFORMATION);
        }
    }

    /* Refresh UI to reflect reloaded state */
    state->initializing = TRUE;
    _populate_slot_list(GetDlgItem(hwnd, IDC_KEYS_SLOT_LIST), state);
    _update_slot_buttons(hwnd, state);
    state->initializing = FALSE;

    return ST_OK;
}

/*
 * Clear a keyslot
 */
static int _clear_slot(HWND hwnd, keys_dlg_state *state, int slot_idx)
{
    HWND h_main;
    int resl;

    if (!dc_has_key_slots(state->header)) return ST_ERROR;

    /* Find main dialog */
    h_main = GetParent(GetParent(hwnd));

    /* Confirm */
    if (MessageBox(hwnd,
        L"Are you sure you want to clear this keyslot?",
        L"Clear Keyslot",
        MB_YESNO | MB_ICONQUESTION) != IDYES)
    {
        return ST_CANCEL;
    }

    /* Clear slot on primary header */
    resl = dc_set_slot(state->header, slot_idx, ((dc_slot_info*)-1), (u8*)-1, 0);

    /* Clear slot on backup header if it exists */
    if (state->backup_header && dc_has_key_slots(state->backup_header)) {
        dc_set_slot(state->backup_header, slot_idx, ((dc_slot_info*)-1), (u8*)-1, 0);
        /* Clear out-of-sync flag for this slot since both headers now match */
        state->slots_out_of_sync &= ~(1 << slot_idx);
    }

    /* Mark modified and refresh */
    state->modified |= HF_UPDATE_SLOTS;
    EnableWindow(GetDlgItem(h_main, IDC_BTN_APPLY), TRUE);
    _populate_slot_list(GetDlgItem(hwnd, IDC_KEYS_SLOT_LIST), state);
    _update_slot_buttons(hwnd, state);

    return resl;
}

/*
 * Toggle the SF_DISABLED flag on a keyslot
 */
static int _toggle_slot(HWND hwnd, keys_dlg_state *state, int slot_idx)
{
    HWND h_main;
    dc_slot_info slot;
    int resl;

    if (!dc_has_key_slots(state->header)) return ST_ERROR;

    /* Find main dialog */
    h_main = GetParent(GetParent(hwnd));

    /* Get current slot info */
    resl = dc_get_slot_info(state->header, slot_idx, &slot);
    if (resl != ST_OK) return resl;

    /* Toggle the disabled flag */
    if (slot.flags & SF_DISABLED) {
        slot.flags &= ~SF_DISABLED;
    } else {
        slot.flags |= SF_DISABLED;
    }

    /* Update slot on primary header (passing NULL for payload keeps existing ciphertext) */
    resl = dc_set_slot(state->header, slot_idx, &slot, NULL, 0);
    if (resl != ST_OK) return resl;

    /* Update slot on backup header if it exists */
    if (state->backup_header && dc_has_key_slots(state->backup_header)) {
        dc_slot_info backup_slot;
        if (dc_get_slot_info(state->backup_header, slot_idx, &backup_slot) == ST_OK) {
            /* Apply same flag change to backup */
            if (slot.flags & SF_DISABLED) {
                backup_slot.flags |= SF_DISABLED;
            } else {
                backup_slot.flags &= ~SF_DISABLED;
            }
            dc_set_slot(state->backup_header, slot_idx, &backup_slot, NULL, 0);
        }
    }

    /* Mark modified and refresh */
    state->modified |= HF_UPDATE_SLOTS;
    EnableWindow(GetDlgItem(h_main, IDC_BTN_APPLY), TRUE);
    _populate_slot_list(GetDlgItem(hwnd, IDC_KEYS_SLOT_LIST), state);
    _update_slot_buttons(hwnd, state);

    return ST_OK;
}

/*
 * Test a password against a keyslot
 * Verifies if the entered password can unlock the slot by:
 * 1. Getting the slot payload (header_dk XOR slot_dk)
 * 2. Deriving the test key from the entered password
 * 3. XORing to recover potential header_dk
 * 4. Comparing with actual header_dk
 */
static int _test_slot_password(HWND hwnd, keys_dlg_state *state, int slot_idx)
{
    dc_slot_info slot;
    dlgpass dlg_info = { L"Test Slot Password", NULL, 0 };
    int resl;
    u8 slot_payload[PKCS_DERIVE_MAX];
    u8 header_dk[PKCS_DERIVE_MAX];
    u8 backup_header_dk[PKCS_DERIVE_MAX];
    u8 test_slot_dk[PKCS_DERIVE_MAX];
    u8 recovered_dk[PKCS_DERIVE_MAX];
    BOOL has_backup;
    BOOL primary_match = FALSE;
    BOOL backup_match = FALSE;
    int i;

    if (!dc_has_key_slots(state->header)) return ST_ERROR;

    /* Get slot info */
    resl = dc_get_slot_info(state->header, slot_idx, &slot);
    if (resl != ST_OK) return resl;

    /* Check if slot is active */
    if (!(slot.flags & SF_ACTIVE)) {
        __msg_e(hwnd, L"Cannot test password on an empty or inactive slot.");
        return ST_ERROR;
    }

    /* Check if backup header is available */
    has_backup = (state->mode == MODE_VOLUME && state->backup_header && dc_has_key_slots(state->backup_header));

    /* Get password from user */
    resl = _dlg_get_pass(hwnd, &dlg_info);
    if (resl != ST_OK) {
        return resl;
    }

    /* Derive header key from stored password - use cache for primary */
    if (!state->password) {
        __msg_e(hwnd, L"Original password not available");
        resl = ST_ERROR;
        goto cleanup;
    }
    if (state->cached_primary_hdk_valid) {
        memcpy(header_dk, state->cached_primary_hdk, PKCS_DERIVE_MAX);
    } else {
        int derive_result = _wait_dc_derive_key_um(hwnd, state->password, state->password->kdf,
            state->header->salt, header_dk, L"Deriving key...");
        if (derive_result != 1) {
            if (derive_result == -1) {
                resl = ST_CANCEL;
            } else {
                __msg_e(hwnd, L"Failed to derive header key");
                resl = ST_ERROR;
            }
            goto cleanup;
        }
        memcpy(state->cached_primary_hdk, header_dk, PKCS_DERIVE_MAX);
        state->cached_primary_hdk_valid = TRUE;
    }

    /* Derive backup header key if needed (always derive fresh, don't cache) */
    if (has_backup) {
        int derive_result = _wait_dc_derive_key_um(hwnd, state->password, state->password->kdf,
            state->backup_header->salt, backup_header_dk, L"Deriving backup key...");
        if (derive_result != 1) {
            if (derive_result == -1) {
                resl = ST_CANCEL;
            } else {
                __msg_e(hwnd, L"Failed to derive backup header key");
                resl = ST_ERROR;
            }
            goto cleanup;
        }
    }

    /* Test against primary header */
    resl = dc_get_slot_payload(state->header, slot_idx, slot_payload, PKCS_DERIVE_MAX);
    if (resl != ST_OK) {
        __msg_e(hwnd, L"Failed to get slot payload");
        goto cleanup;
    }

    resl = dc_get_slot_info(state->header, slot_idx, &slot);
    if (resl != ST_OK) {
        goto cleanup;
    }

    /* Derive test key from entered password using primary header's salt */
    {
        int derive_result = _wait_dc_derive_key_um(hwnd, dlg_info.pass,
            dlg_info.pass->kdf != KDF_DEFAULT ? dlg_info.pass->kdf : slot.data_0.slot_kdf,
            state->header->salt, test_slot_dk, L"Testing password...");
        if (derive_result != 1) {
            if (derive_result == -1) {
                resl = ST_CANCEL;
            } else {
                __msg_e(hwnd, L"Failed to derive test key");
                resl = ST_ERROR;
            }
            goto cleanup;
        }
    }

    /* Recover header_dk by XORing payload with test slot key */
    for (i = 0; i < PKCS_DERIVE_MAX; i += 8) {
        *(__int64*)(recovered_dk + i) = *(__int64*)(slot_payload + i) ^ *(__int64*)(test_slot_dk + i);
    }

    /* Check primary match */
    primary_match = (memcmp(recovered_dk, header_dk, PKCS_DERIVE_MAX) == 0);

    /* Test against backup header if present */
    if (has_backup) {
        dc_slot_info backup_slot;

        resl = dc_get_slot_payload(state->backup_header, slot_idx, slot_payload, PKCS_DERIVE_MAX);
        if (resl != ST_OK) {
            __msg_e(hwnd, L"Failed to get backup slot payload");
            goto cleanup;
        }

        resl = dc_get_slot_info(state->backup_header, slot_idx, &backup_slot);
        if (resl != ST_OK) {
            goto cleanup;
        }

        /* Derive test key using backup header's salt */
        {
            int derive_result = _wait_dc_derive_key_um(hwnd, dlg_info.pass,
                dlg_info.pass->kdf != KDF_DEFAULT ? dlg_info.pass->kdf : backup_slot.data_0.slot_kdf,
                state->backup_header->salt, test_slot_dk, L"Testing backup password...");
            if (derive_result != 1) {
                if (derive_result == -1) {
                    resl = ST_CANCEL;
                } else {
                    __msg_e(hwnd, L"Failed to derive backup test key");
                    resl = ST_ERROR;
                }
                goto cleanup;
            }
        }

        /* Recover backup header_dk */
        for (i = 0; i < PKCS_DERIVE_MAX; i += 8) {
            *(__int64*)(recovered_dk + i) = *(__int64*)(slot_payload + i) ^ *(__int64*)(test_slot_dk + i);
        }

        backup_match = (memcmp(recovered_dk, backup_header_dk, PKCS_DERIVE_MAX) == 0);
    }

    /* Report results */
    if (has_backup) {
        if (primary_match && backup_match) {
            __msg_i(hwnd, L"Password is correct for both primary and backup header slots.");
            resl = ST_OK;
        } else if (primary_match && !backup_match) {
            __msg_w(hwnd, L"Password is correct for the primary header slot, but does NOT match the backup header slot.");
            resl = ST_OK;
        } else if (!primary_match && backup_match) {
            __msg_w(hwnd, L"Password is correct for the backup header slot, but does NOT match the primary header slot.");
            resl = ST_OK;
        } else {
            __msg_e(hwnd, L"Password is incorrect for both primary and backup header slots.");
            resl = ST_PASS_ERR;
        }
    } else {
        if (primary_match) {
            __msg_i(hwnd, L"Password is correct for the slot.");
            resl = ST_OK;
        } else {
            __msg_e(hwnd, L"Password is incorrect for the slot.");
            resl = ST_PASS_ERR;
        }
    }

cleanup:
    if (dlg_info.pass) {
        burn(dlg_info.pass, sizeof(dc_pass));
        secure_free(dlg_info.pass);
    }
    burn(slot_payload, sizeof(slot_payload));
    burn(header_dk, sizeof(header_dk));
    burn(backup_header_dk, sizeof(backup_header_dk));
    burn(test_slot_dk, sizeof(test_slot_dk));
    burn(recovered_dk, sizeof(recovered_dk));

    return resl;
}

/* Data passed to slot editor dialog */
typedef struct _slot_edit_data {
    keys_dlg_state *state;
    int             slot_idx;
    wchar_t         name[32];
} slot_edit_data;

/* Slot editor dialog procedure */
static INT_PTR CALLBACK _slot_edit_dlg_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam)
{
    slot_edit_data *data = (slot_edit_data*)GetWindowLongPtr(hwnd, GWLP_USERDATA);

    switch (message)
    {
        case WM_INITDIALOG:
        {
            data = (slot_edit_data*)lparam;
            SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)data);

            /* Set current slot name */
            SetDlgItemText(hwnd, IDC_EDIT_SLOT_NAME, data->name);

            /* Limit name length */
            SendDlgItemMessage(hwnd, IDC_EDIT_SLOT_NAME, EM_LIMITTEXT, SLOT_LABEL_LEN, 0);

            /* Update caption with slot number */
            {
                wchar_t caption[64];
                _snwprintf(caption, countof(caption), L"Edit Keyslot %d", data->slot_idx + 1);
                SetWindowText(hwnd, caption);
            }

            return TRUE;
        }

        case WM_COMMAND:
        {
            switch (LOWORD(wparam))
            {
                case IDOK:
                {
                    /* Get the edited name */
                    GetDlgItemText(hwnd, IDC_EDIT_SLOT_NAME, data->name, countof(data->name));
                    EndDialog(hwnd, IDOK);
                    return TRUE;
                }

                case IDCANCEL:
                {
                    EndDialog(hwnd, IDCANCEL);
                    return TRUE;
                }
            }
            break;
        }
    }

    return FALSE;
}

/*
 * Show the slot editor dialog to edit slot name
 */
static void _show_slot_editor(HWND hwnd, keys_dlg_state *state, int slot_idx)
{
    dc_slot_info slot;
    slot_edit_data data;
    HWND h_main;
    INT_PTR result;
    int len;

    if (!dc_has_key_slots(state->header)) return;

    if (dc_get_slot_info(state->header, slot_idx, &slot) != ST_OK) return;

    h_main = GetParent(GetParent(hwnd));

    /* Initialize edit data */
    memset(&data, 0, sizeof(data));
    data.state = state;
    data.slot_idx = slot_idx;
	data.name[0] = 0;

    /* Get current name - use existing name for active or corrupt slots (empty slots may have garbage) */
    if (slot.slot_name[0]) {
        len = MultiByteToWideChar(CP_UTF8, 0, slot.slot_name, sizeof(slot.slot_name), data.name, countof(data.name));
        data.name[len] = 0;
    }

    /* Show dialog */
    result = DialogBoxParam(__hinst, MAKEINTRESOURCE(DLG_KEYS_SLOT_EDIT), hwnd, _slot_edit_dlg_proc, (LPARAM)&data);

    if (result == IDOK) {
        /* Save the new name - clear first to avoid trailing garbage */
        memset(slot.slot_name, 0, sizeof(slot.slot_name));
        len = WideCharToMultiByte(CP_UTF8, 0, data.name, -1, slot.slot_name, sizeof(slot.slot_name), NULL, NULL);
        if(len < sizeof(slot.slot_name))
            memset(slot.slot_name + len, 0, sizeof(slot.slot_name) - len);

        /* Update slot info on primary header */
        dc_set_slot(state->header, slot_idx, &slot, NULL, 0);

        /* Update slot info on backup header if it exists */
        if (state->backup_header && dc_has_key_slots(state->backup_header)) {
            dc_set_slot(state->backup_header, slot_idx, &slot, NULL, 0);
            /* Clear out-of-sync flag for this slot since both headers now match */
            state->slots_out_of_sync &= ~(1 << slot_idx);
        }

        /* Mark modified and refresh */
        state->modified |= HF_UPDATE_SLOTS;
        EnableWindow(GetDlgItem(h_main, IDC_BTN_APPLY), TRUE);
        _populate_slot_list(GetDlgItem(hwnd, IDC_KEYS_SLOT_LIST), state);
    }
}

/*
 * Update properties tab controls based on header state
 */
static void _update_props_controls(HWND hwnd, keys_dlg_state* state)
{
    wchar_t buf[64];
    HWND h_combo;
    BOOL is_v2;
    BOOL has_slots;
    BOOL has_ext = FALSE;
    BOOL has_backup;
    BOOL storage_file;
    BOOL can_change_version;
    BOOL can_change_layout;
    u32 head_len;
    int idx, sel_idx;
    u32 size;

    if (!state || !state->header) return;

    is_v2 = (state->header->version >= DC_HDR_VERSION_2);
    has_slots = is_v2 ? (state->header->feature_flags & FF_KEY_SLOTS) : FALSE;
    head_len = is_v2 ? state->header->head_len : DC_AREA_SIZE;
    has_backup = (state->header->flags & VF_BACKUP_HEADER) ? TRUE : FALSE;
    storage_file = (state->header->flags & VF_STORAGE_FILE) ? TRUE : FALSE;

    /* Store original values for layout change detection */
    state->orig_head_len = head_len;
    state->orig_has_backup = has_backup;
    state->orig_storage_file = storage_file;
    state->layout_modified = FALSE;

    /* Header version radio buttons */
    CheckRadioButton(hwnd, IDC_RADIO_V1, IDC_RADIO_V2, is_v2 ? IDC_RADIO_V2 : IDC_RADIO_V1);

    /* Version switching is only allowed if header size and storage area is standard (DC_AREA_SIZE) */
    /* For v2 headers with non-standard size, downgrade would require a layout change */
    can_change_version = !is_v2 || (state->header->head_len == DC_AREA_SIZE &&
                         (state->header->stor_len == DC_AREA_SIZE || (state->header->flags & VF_STORAGE_FILE)));
    EnableWindow(GetDlgItem(hwnd, IDC_RADIO_V1), can_change_version);
    EnableWindow(GetDlgItem(hwnd, IDC_RADIO_V2), can_change_version);

    /* Layout changes only allowed for actual volumes (not backup files) */
    can_change_layout = (state->mode == MODE_VOLUME);

    /* Header size combo box */
    h_combo = GetDlgItem(hwnd, IDC_COMBO_HDR_SIZE_PROPS);
    SendMessage(h_combo, CB_RESETCONTENT, 0, 0);
    sel_idx = 0;
    for (size = DC_AREA_SIZE; size <= DC_AREA_MAX_SIZE_UI; size *= 2) {
        _format_hdr_size(size, buf, countof(buf), FALSE);
        idx = (int)SendMessage(h_combo, CB_ADDSTRING, 0, (LPARAM)buf);
        SendMessage(h_combo, CB_SETITEMDATA, idx, (LPARAM)size);
        if (size == head_len) {
            sel_idx = idx;
        }
    }
    /* If current size doesn't match any predefined size, add it as custom */
    if (head_len != DC_AREA_SIZE) {
        BOOL found = FALSE;
        for (size = DC_AREA_SIZE; size <= DC_AREA_MAX_SIZE_UI; size *= 2) {
            if (size == head_len) { found = TRUE; break; }
        }
        if (!found) {
            _format_hdr_size(head_len, buf, countof(buf), TRUE);
            wcscat(buf, L" (custom)");
            idx = (int)SendMessage(h_combo, CB_ADDSTRING, 0, (LPARAM)buf);
            SendMessage(h_combo, CB_SETITEMDATA, idx, (LPARAM)head_len);
            sel_idx = idx;
        }
    }
    SendMessage(h_combo, CB_SETCURSEL, sel_idx, 0);
    /* Header size only changeable for v2 volumes */
    EnableWindow(h_combo, can_change_layout && is_v2);

    /* Backup header checkbox */
    _set_check(hwnd, IDC_CHECK_HDR_BACKUP, has_backup);
    /* Backup only changeable for v2 volumes */
    EnableWindow(GetDlgItem(hwnd, IDC_CHECK_HDR_BACKUP), can_change_layout && is_v2);

    /* Storage size display (read-only) */
    size = is_v2 ? state->header->stor_len : DC_AREA_SIZE;
    _format_hdr_size(size, buf, countof(buf), FALSE);
    SetDlgItemText(hwnd, IDC_EDIT_STORAGE_SIZE, buf);

    /* Storage location radio buttons */
    CheckRadioButton(hwnd, IDC_RADIO_STORAGE_FILE, IDC_RADIO_STORAGE_END,
                     storage_file ? IDC_RADIO_STORAGE_FILE : IDC_RADIO_STORAGE_END);
    /* Storage location only changeable for v2 volumes */
    EnableWindow(GetDlgItem(hwnd, IDC_RADIO_STORAGE_FILE), can_change_layout);
    EnableWindow(GetDlgItem(hwnd, IDC_RADIO_STORAGE_END), can_change_layout);

    /* Slot count - editable for v2 */
    _snwprintf(buf, countof(buf), L"%d", has_slots ? state->header->key_slot_count : 0);
    SetDlgItemText(hwnd, IDC_EDIT_SLOT_COUNT, buf);
    EnableWindow(GetDlgItem(hwnd, IDC_EDIT_SLOT_COUNT), is_v2);

    /* Extended header checkbox */
    _set_check(hwnd, IDC_CHECK_EXT_HEADER, is_v2 && state->header->ext_hdr_off > 0);
    EnableWindow(GetDlgItem(hwnd, IDC_CHECK_EXT_HEADER), is_v2);

    /* Volume label - editable for v2 with extended header */
    buf[0] = 0;
    if (is_v2 && state->header->ext_hdr_off > 0) {
        dc_ext_header *ext = (dc_ext_header*)(((u8*)state->header) + state->header->ext_hdr_off);
        if (ext->version != DC_EXT_VERSION) {
            __msg_e(hwnd, L"Unsupported extended header version");
        } else {
            dc_ext_data ext_data;
            if (read_ext_header(ext->data, ext->size - MIN_EXT_HDR_SIZE, &ext_data) != ST_OK) {
                __msg_e(hwnd, L"Failed to read extended header data");
            } else {
                if (ext_data.volume_comment[0]) {
                    MultiByteToWideChar(CP_UTF8, 0, ext_data.volume_comment, sizeof(ext_data.volume_comment), buf, countof(buf) - 1);
                    buf[sizeof(ext_data.volume_comment)] = 0;
                }
                has_ext = TRUE;
            }
        }
    }
    SetDlgItemText(hwnd, IDC_EDIT_VOLUME_NOTE, buf);
    EnableWindow(GetDlgItem(hwnd, IDC_EDIT_VOLUME_NOTE), has_ext);

    /* Disk ID (always editable) */
    _snwprintf(buf, countof(buf), L"%08X", state->header->disk_id);
    SetDlgItemText(hwnd, IDC_EDIT_DISK_ID, buf);
    state->orig_disk_id = state->header->disk_id;
}

/*
 * Check if layout has been modified and update button states
 */
static void _check_layout_modified(HWND hwnd, keys_dlg_state *state)
{
    HWND h_main;
    HWND h_combo;
    u32 new_head_len;
    BOOL new_has_backup;
    BOOL new_storage_file;
    int sel;

    if (!state || !state->header) return;
    if (state->mode == MODE_FILE) return;  /* No layout changes for backup files */

    h_main = GetParent(GetParent(hwnd));

    /* Get current values from controls */
    h_combo = GetDlgItem(hwnd, IDC_COMBO_HDR_SIZE_PROPS);
    sel = (int)SendMessage(h_combo, CB_GETCURSEL, 0, 0);
    new_head_len = (u32)SendMessage(h_combo, CB_GETITEMDATA, sel, 0);

    new_has_backup = _get_check(hwnd, IDC_CHECK_HDR_BACKUP);

    new_storage_file = (IsDlgButtonChecked(hwnd, IDC_RADIO_STORAGE_FILE) == BST_CHECKED);

    /* Check if any layout value has changed */
    state->layout_modified = (new_head_len != state->orig_head_len ||
                              new_has_backup != state->orig_has_backup ||
                              new_storage_file != state->orig_storage_file);

    /* Update button states */
    EnableWindow(GetDlgItem(h_main, IDC_BTN_CHANGE_LAYOUT), state->layout_modified);

    /* When layout is modified, disable OK/Apply buttons */
    if (state->layout_modified) {
        EnableWindow(GetDlgItem(h_main, IDOK), FALSE);
        EnableWindow(GetDlgItem(h_main, IDC_BTN_APPLY), FALSE);
    } else {
        EnableWindow(GetDlgItem(h_main, IDOK), TRUE);
        EnableWindow(GetDlgItem(h_main, IDC_BTN_APPLY), state->modified ? TRUE : FALSE);
    }
}

/*
 * Apply layout changes to volume
 */
static int _apply_layout_changes(HWND hwnd, keys_dlg_state *state)
{
    HWND h_tab = GetDlgItem(hwnd, IDT_KEYS_TAB);
    _wnd_data *wnd = wnd_get_long(h_tab, GWL_USERDATA);
    HWND h_props = wnd->dlg[1];
    HWND h_combo;
    crypt_info crypt = { 0 };
    u32 flags = 0;
    int sel;
    u32 new_head_len;
    BOOL new_has_backup;
    BOOL new_storage_file;
    int resl;

    if (!state || !state->header || !state->password) {
        return ST_ERROR;
    }

    if (state->mode != MODE_VOLUME) {
        __msg_e(hwnd, L"Layout changes are only supported for actual volumes");
        return ST_ERROR;
    }

    if (!(__config.load_flags & DST_PRO_ENABLED)) {
        void _menu_no_pro(HWND hwnd, int no_shim);
        _menu_no_pro(hwnd, -1);
        return ST_NOT_PRO;
    }

    /* Check if volume is mounted */
    {
        dc_status vol_status;
        dc_get_device_status(state->device, &vol_status);
        if (!(vol_status.flags & F_ENABLED))
        {
            __msg_e(hwnd, L"The volume must be mounted to change its layout");
            return ST_ERROR;
        }
    }

	crypt.version = (IsDlgButtonChecked(h_props, IDC_RADIO_V2) == BST_CHECKED) ? DC_HDR_VERSION_2 : DC_HDR_VERSION;

    /* Get current values from controls */
    h_combo = GetDlgItem(h_props, IDC_COMBO_HDR_SIZE_PROPS);
    sel = (int)SendMessage(h_combo, CB_GETCURSEL, 0, 0);
    new_head_len = (u32)SendMessage(h_combo, CB_GETITEMDATA, sel, 0);

    new_has_backup = _get_check(h_props, IDC_CHECK_HDR_BACKUP);

    new_storage_file = (IsDlgButtonChecked(h_props, IDC_RADIO_STORAGE_FILE) == BST_CHECKED);

    /* Determine what operations are needed */
    if (new_head_len != state->orig_head_len) {
        flags |= S_RESIZE_HEADER;
        crypt.head_len = new_head_len;
    }

    if (new_has_backup != state->orig_has_backup) {
        if (new_has_backup) {
            flags |= S_BACKUP_HEADER;
        } else {
            flags |= S_REMOVE_BACKUP;
        }
    }

    if (new_storage_file != state->orig_storage_file) {
        if (new_storage_file) {
            flags |= S_STORAGE_TO_FILE;
        } else {
            flags |= S_STORAGE_TO_END;
        }
    }

    if (flags == 0) {
        /* No changes needed */
        return ST_OK;
    }

    /* Confirm the operation */
    {
        wchar_t msg[512];
        wchar_t ops[256] = { 0 };

        if (flags & S_RESIZE_HEADER) {
            wchar_t size_str[32];
            _format_hdr_size(new_head_len, size_str, countof(size_str), FALSE);
            _snwprintf(ops + wcslen(ops), countof(ops) - wcslen(ops), L"- Resize header to %s\n", size_str);
        }
        if (flags & S_BACKUP_HEADER) {
            wcscat(ops, L"- Enable backup header\n");
        }
        if (flags & S_REMOVE_BACKUP) {
            wcscat(ops, L"- Remove backup header\n");
        }
        if (flags & S_STORAGE_TO_FILE) {
            wcscat(ops, L"- Move storage to file\n");
        }
        if (flags & S_STORAGE_TO_END) {
            wcscat(ops, L"- Move storage to partition end\n");
        }

        _snwprintf(msg, countof(msg),
            L"The following layout changes will be applied:\n\n%s\n"
            L"This operation may take some time and should not be interrupted.\n\n"
            L"Changing the volume layout will invalidate any previously created "
            L"header backup files.\n\n"
            L"Do you want to continue?",
            ops);

        if (MessageBox(hwnd, msg, L"Confirm Layout Change", MB_YESNO | MB_ICONWARNING) != IDYES) {
            return ST_CANCEL;
        }
    }

    /* Call dc_update_layout */
    resl = _wait_dc_update_layout(hwnd, state->device, state->password, &crypt, flags, L"Updating layout...");

    if (resl != ST_OK) {
        __error_s(hwnd, L"Layout change failed", resl);
        return resl;
    }

    /* Reload header to reflect changes */
    {
        dc_header *old_header = state->header;
        xts_key *old_key = state->hdr_key;
        int old_len = state->header_len;
        dc_header *old_backup = state->backup_header;
        xts_key *old_backup_key = state->backup_hdr_key;
        int old_backup_len = state->backup_header_len;

        state->header = NULL;
        state->hdr_key = NULL;
        state->header_len = 0;
        state->backup_header = NULL;
        state->backup_hdr_key = NULL;
        state->backup_header_len = 0;
        state->cached_backup_hdk_valid = FALSE;

        resl = _load_header_from_volume(hwnd, state, state->device, state->password);

        if (resl != ST_OK) {
            /* Reload failed - restore old state and warn user */
            state->header = old_header;
            state->hdr_key = old_key;
            state->header_len = old_len;
            state->backup_header = old_backup;
            state->backup_hdr_key = old_backup_key;
            state->backup_header_len = old_backup_len;
            __error_s(hwnd, L"Layout change succeeded but failed to reload header", resl);
        } else {
            /* Reload succeeded - free old data */
            if (old_header) {
                burn(old_header, old_len);
                secure_free(old_header);
            }
            if (old_key) {
                burn(old_key, sizeof(xts_key));
                secure_free(old_key);
            }
            if (old_backup) {
                burn(old_backup, old_backup_len);
                secure_free(old_backup);
            }
            if (old_backup_key) {
                burn(old_backup_key, sizeof(xts_key));
                secure_free(old_backup_key);
            }
        }
    }

    /* Refresh UI to reflect reloaded state */
    state->initializing = TRUE;
    {
        _populate_slot_list(GetDlgItem(wnd->dlg[0], IDC_KEYS_SLOT_LIST), state);
        _update_props_controls(wnd->dlg[1], state);

        /* Update slot buttons based on current state */
        if (dc_has_key_slots(state->header)) {
            EnableWindow(wnd->dlg[0], TRUE);
            _update_slot_buttons(wnd->dlg[0], state);
        } else {
            EnableWindow(wnd->dlg[0], FALSE);
            EnableWindow(GetDlgItem(hwnd, IDC_BTN_SET_SLOT_PASS), FALSE);
            EnableWindow(GetDlgItem(hwnd, IDC_BTN_TEST_SLOT_PASS), FALSE);
            EnableWindow(GetDlgItem(hwnd, IDC_BTN_EDIT_SLOT), FALSE);
            EnableWindow(GetDlgItem(hwnd, IDC_BTN_TOGGLE_SLOT), FALSE);
            EnableWindow(GetDlgItem(hwnd, IDC_BTN_CLEAR_SLOT), FALSE);
            EnableWindow(GetDlgItem(hwnd, IDC_BTN_SET_BOOT_PASS), FALSE);
        }
    }
    state->initializing = FALSE;

    /* Reset modified states */
    state->modified = 0;
    state->layout_modified = FALSE;
    EnableWindow(GetDlgItem(hwnd, IDC_BTN_APPLY), FALSE);
    EnableWindow(GetDlgItem(hwnd, IDC_BTN_CHANGE_LAYOUT), FALSE);
    EnableWindow(GetDlgItem(hwnd, IDOK), TRUE);

    __msg_i(hwnd, L"Layout change completed successfully");

    return ST_OK;
}

/*
 * Apply UI changes to header
 */
static int _apply_header_changes(HWND hwnd, keys_dlg_state *state, dc_header** out_header, int* out_size)
{
    HWND h_tab = GetDlgItem(hwnd, IDT_KEYS_TAB);
    _wnd_data *wnd = wnd_get_long(h_tab, GWL_USERDATA);
    HWND h_props = wnd->dlg[1];
    HWND h_slots = wnd->dlg[0];

	if (!state || !state->header || !out_header || !out_size) return ST_ERROR;
    *out_header = NULL;
    *out_size = 0;

    wchar_t buf[256];

	int slot_type = 0; // Only one slot type for now, but keep flexible for future types

    /* collect old layout info */
    BOOL old_v2 = (state->header->version >= DC_HDR_VERSION_2);
    
    BOOL old_has_slots = FALSE;
    int old_slot_area_len = 0;
    int old_slot_count = 0;
    int old_info_size = 0;
    
    BOOL old_has_ext = FALSE;
	int old_ext_offset = 0;
    int old_ext_size = 0;
    u16 old_ext_ver = 0;

    if (old_v2) 
    {
        old_has_slots = (state->header->feature_flags & FF_KEY_SLOTS);
        if (old_has_slots) {
            old_slot_area_len = state->header->slot_area_len;
            old_slot_count = state->header->key_slot_count;

            old_info_size = state->header->slot_info_size;
        }

        if (state->header->ext_hdr_off > 0) {
            old_has_ext = TRUE;
            old_ext_offset = state->header->ext_hdr_off;

            dc_ext_header* ext_hdr = (dc_ext_header*)(((u8*)state->header) + state->header->ext_hdr_off);
            if (state->header->ext_hdr_off > state->header->head_len || state->header->head_len - state->header->ext_hdr_off < ext_hdr->size) {
                old_has_ext = FALSE;
            } else {
                old_ext_size = ext_hdr->size;
                old_ext_ver = ext_hdr->version;
            }
        }
    }

    /* prepare new layout info */
    BOOL new_v2 = (IsDlgButtonChecked(h_props, IDC_RADIO_V2) == BST_CHECKED);

    BOOL new_has_slots = FALSE;
    int new_slot_area_len = 0; //
    int new_slot_count = 0;
    int new_info_size = 0;

    BOOL new_has_ext = FALSE;
    int new_ext_offset = 0; //
    int new_ext_size = 0;
    u8 ext_hdr_data[1024];

    if (new_v2) 
    {
        GetDlgItemText(h_props, IDC_EDIT_SLOT_COUNT, buf, countof(buf));
        new_slot_count = _wtoi(buf);

        new_has_slots = new_slot_count > 0;
        if (new_has_slots) {
            // keep slot descriptor size and version if set, otherwise use defaults
            if (old_slot_count > 0 || new_slot_count == 0) {
                new_info_size = old_info_size;
            }
            else {
                new_info_size = sizeof(dc_slot_info);
            }
        }

        new_has_ext = _get_check(h_props, IDC_CHECK_EXT_HEADER);
        if (new_has_ext && (state->modified & HF_UPDATE_EXT))
        {
            dc_ext_data ext_data;

            // Try to parse GUID from UI
            //GetDlgItemText(h_props, IDC_EDIT_VOLUME_GUID, buf, countof(buf));
            //if (buf[0]) {
            //    CLSIDFromString(buf, (GUID*)ext_data.volume_guid);
            //} else {
			//	memset(ext_data.volume_guid, 0, sizeof(ext_data.volume_guid));
            //}

            // Get volume label from UI
            memset(ext_data.volume_comment, 0, sizeof(ext_data.volume_comment));
            GetDlgItemText(h_props, IDC_EDIT_VOLUME_NOTE, buf, countof(buf));
            if (buf[0]) {
                WideCharToMultiByte(CP_UTF8, 0, buf, -1, ext_data.volume_comment, sizeof(ext_data.volume_comment) - 1, NULL, NULL);
            }

            const int bytes_lef = state->header->head_len - (DC_BASE_SIZE + new_slot_count * (PKCS_DERIVE_MAX + new_info_size));

            new_ext_size = write_ext_header(&ext_data, ext_hdr_data, min(bytes_lef, sizeof(ext_hdr_data)));
            if (new_ext_size > 0) {
                new_ext_size += MIN_EXT_HDR_SIZE;
            } else {
                state->modified &= ~HF_UPDATE_EXT;
				__msg_e(hwnd, L"Failed to prepare extended header data. Changes to extended header will be discarded.");
            }
        }
        
        // keep old extended header blob when not changed
        if(new_ext_size == 0) {
            new_ext_size = old_ext_size;
        }
    }
    
	// check layout changes
    if (new_slot_count != old_slot_count || (new_slot_count && (new_info_size != old_info_size)) || 
           new_has_ext != old_has_ext || (new_has_ext && (new_ext_size != old_ext_size)) )
    {
		// check if reducing slot count would remove active slots
        for (int i = new_slot_count; i < old_slot_count; i++) {
            dc_slot_info slot;
            if (dc_get_slot_info(state->header, i, &slot) == ST_OK && (slot.flags & SF_ACTIVE)) {
                wchar_t msg[128];
                _snwprintf(msg, countof(msg), L"Slot %d is in use and would be removed. Cannot reduce slot count.", i + 1);
                __msg_e(hwnd, msg);
                return ST_ERROR;
            }
        }

        // calculate new layout
        if (new_v2) 
        {
			new_slot_area_len = new_slot_count * dc_get_key_slot_size(slot_type);

            new_ext_offset = DC_BASE_SIZE + new_slot_area_len + (new_slot_count * new_info_size);

            // check if new layout fits in current header size
            if (new_ext_offset + new_ext_size > state->header_len) {
                __msg_e(hwnd, L"Header configuration exceeds current header size.");
                return ST_ERROR;
            }

            if (!new_has_ext) new_ext_offset = 0;
        }

        state->modified |= HF_UPDATE_BASE;
    }
	else // No layout changes
    {
        new_slot_area_len = old_slot_area_len;
        new_info_size = old_info_size;

		new_ext_offset = old_ext_offset;
        new_ext_size = old_ext_size;
    }


    // preapre update header
    dc_header *update_header = (dc_header*)secure_alloc(state->header_len);
    if (!update_header) return ST_NOMEM;
    memset(update_header, 0, state->header_len);
    // copy base
    memcpy(update_header, state->header, DC_BASE_SIZE);

    // version switching
    if (old_v2 != new_v2) {
        if (new_v2) 
        {
            update_header->version = DC_HDR_VERSION_2;
            
            update_header->head_len = state->header_len; // use existing size
            update_header->stor_len = update_header->head_len;

            update_header->head_kdf = (u8)state->password->kdf;
        } 
        else 
        {
            update_header->version = DC_HDR_VERSION;

            update_header->head_len = 0; // v1 has fixed header size
            update_header->stor_len = 0;
		}
        state->modified |= HF_UPDATE_BASE;
    }

	// set layout fields for v2 (or clear if switching to v1)
    if (new_v2) {
        update_header->ext_hdr_off = new_ext_offset;

        if (new_has_slots) {
            update_header->feature_flags |= FF_KEY_SLOTS;
        } else {
            update_header->feature_flags &= ~FF_KEY_SLOTS;
		}

        update_header->slot_area_len = new_slot_area_len;
        update_header->key_slot_count = new_slot_count;
        update_header->slot_info_size = new_info_size;
    } else {
        memset(&update_header->footer_cnt, 0, sizeof(dc_header) - offsetof(dc_header, footer_cnt));
    }

    // set updatable base fields
    if (state->modified & HF_UPDATE_BASE)  {
        GetDlgItemText(h_props, IDC_EDIT_DISK_ID, buf, countof(buf));
        update_header->disk_id = (u32)wcstoul(buf, NULL, 16);
        if (!update_header->disk_id)// if parsing failed or zero, keep original disk ID
			update_header->disk_id = state->orig_disk_id;
    }

    update_header->hdr_crc = calculate_header_crc_um(update_header);


    // prepare new key slots
    if (new_slot_count > 0) 
    {
        // copy slot payload and info for unchanged slots
        if (old_slot_area_len) {
            int slot_area_to_copy = min(old_slot_area_len, new_slot_area_len);
            memcpy(((u8*)update_header) + DC_BASE_SIZE, ((u8*)state->header) + DC_BASE_SIZE, slot_area_to_copy);
            int info_area_to_copy = min(old_slot_count * old_info_size, new_slot_count * new_info_size);
            memcpy(((u8*)update_header) + DC_BASE_SIZE + new_slot_area_len, ((u8*)state->header) + DC_BASE_SIZE + old_slot_area_len, info_area_to_copy);
        }
            
        // if increasing slot area, initialize new slots with random data
        if(new_slot_area_len > old_slot_area_len) {
            dc_device_control(DC_CTL_GET_RAND, NULL, 0, ((u8*)update_header) + DC_BASE_SIZE + old_slot_area_len, new_slot_area_len - old_slot_area_len);
		}
    }

	// prepare extended header
    if (new_has_ext)
    {
        dc_ext_header* ext_hdr = (dc_ext_header*)(((u8*)update_header) + new_ext_offset);
        if (state->modified & HF_UPDATE_EXT) {
			ext_hdr->size = new_ext_size;
            ext_hdr->version = DC_EXT_VERSION;
			memcpy(ext_hdr->data, ext_hdr_data, new_ext_size - MIN_EXT_HDR_SIZE);
            ext_hdr->crc = calculate_ext_header_crc_um(ext_hdr);
        } else {
			memcpy(ext_hdr, ((u8*)state->header) + old_ext_offset, old_ext_size);
        }
    }


    *out_header = update_header;
	*out_size = state->header_len;

    return ST_OK;
}

/*
 * Verify backup header is in sync with primary header
 * Sets state->backup_sync_status and state->slots_out_of_sync
 */
static void _verify_backup_sync(keys_dlg_state *state)
{
    dc_header *pri = state->header;
    dc_header *bak = state->backup_header;
    int i;

    state->backup_sync_status = SYNC_OK;
    state->slots_out_of_sync = 0;

    if (!pri || !bak) return;

    /* Compare header base fields (excluding salt which is expected to differ) */
    if (pri->version != bak->version ||
        pri->flags != bak->flags ||
        pri->disk_id != bak->disk_id ||
        pri->alg_1 != bak->alg_1 ||
        memcmp(pri->key_1, bak->key_1, DISKKEY_SIZE) != 0 ||
        pri->stor_off != bak->stor_off ||
        pri->stor_len != bak->stor_len ||
        pri->head_len != bak->head_len ||
        pri->tmp_size != bak->tmp_size)
    {
        state->backup_sync_status |= SYNC_BASE_MISMATCH;
    }

    /* Compare v2 specific fields */
    if (pri->version >= DC_HDR_VERSION_2)
    {
        if (pri->feature_flags != bak->feature_flags ||
            pri->head_kdf != bak->head_kdf)
        {
            state->backup_sync_status |= SYNC_BASE_MISMATCH;
        }

        /* Compare slot layout */
        if ((pri->feature_flags & FF_KEY_SLOTS) != (bak->feature_flags & FF_KEY_SLOTS) ||
            pri->slot_area_len != bak->slot_area_len ||
            pri->key_slot_count != bak->key_slot_count ||
            pri->slot_info_size != bak->slot_info_size)
        {
            state->backup_sync_status |= SYNC_SLOTS_MISMATCH;
        }
        else if (pri->feature_flags & FF_KEY_SLOTS)
        {
            /* Compare individual slot info (flags, name, kdf - not CRC which depends on salt) */
            for (i = 0; i < pri->key_slot_count && i < 32; i++)
            {
                dc_slot_info pri_slot, bak_slot;
                if (dc_get_slot_info(pri, i, &pri_slot) == ST_OK &&
                    dc_get_slot_info(bak, i, &bak_slot) == ST_OK)
                {
                    /* Compare slot info fields that should match */
                    if (pri_slot.flags != bak_slot.flags ||
                        pri_slot.type != bak_slot.type ||
                        memcmp(pri_slot.slot_name, bak_slot.slot_name, SLOT_LABEL_LEN) != 0 ||
                        pri_slot.data_0.slot_kdf != bak_slot.data_0.slot_kdf)
                    {
                        state->slots_out_of_sync |= (1 << i);
                    }
                }
            }
            if (state->slots_out_of_sync) {
                state->backup_sync_status |= SYNC_SLOTS_MISMATCH;
            }
        }

        /* Compare extended header */
        if (pri->ext_hdr_off != bak->ext_hdr_off)
        {
            state->backup_sync_status |= SYNC_EXT_MISMATCH;
        }
        else if (pri->ext_hdr_off > 0 && pri->ext_hdr_off < pri->head_len)
        {
            dc_ext_header *pri_ext = (dc_ext_header*)(((u8*)pri) + pri->ext_hdr_off);
            dc_ext_header *bak_ext = (dc_ext_header*)(((u8*)bak) + bak->ext_hdr_off);
            if (pri_ext->size != bak_ext->size ||
                pri_ext->version != bak_ext->version ||
                memcmp(pri_ext->data, bak_ext->data, pri_ext->size - MIN_EXT_HDR_SIZE) != 0)
            {
                state->backup_sync_status |= SYNC_EXT_MISMATCH;
            }
        }
    }
}

/*
 * Sync backup header from primary (copies everything except salt and keyslot payloads)
 */
static void _sync_backup_from_primary(keys_dlg_state *state)
{
    dc_header *pri = state->header;
    dc_header *bak = state->backup_header;
    int slots_len = 0;

    if (!pri || !bak) return;

    /* Calculate slot area length to preserve */
    if (pri->version >= DC_HDR_VERSION_2 && (pri->feature_flags & FF_KEY_SLOTS) && pri->slot_area_len > 0) {
        slots_len = pri->slot_area_len;
    }

    /* Copy header base (after salt) */
    memcpy(((u8*)bak) + HEADER_SALT_SIZE, ((u8*)pri) + HEADER_SALT_SIZE, DC_BASE_SIZE - HEADER_SALT_SIZE);

    /* Copy data after keyslot payload area (slot info, ext header, etc.) */
    if (DC_BASE_SIZE + slots_len < state->header_len) {
        memcpy(((u8*)bak) + DC_BASE_SIZE + slots_len, ((u8*)pri) + DC_BASE_SIZE + slots_len,
               state->header_len - DC_BASE_SIZE - slots_len);
    }

    /* Re-verify sync status */
    _verify_backup_sync(state);
}

/*
 * Load header from volume using driver
 */
static int _load_header_from_volume(HWND hwnd, keys_dlg_state *state, wchar_t *device, dc_pass *password)
{
    u8  *backup = NULL;
    int  bytes = DC_AREA_MAX_SIZE;
    int  resl;
    dc_pass empty_pass = {0};  /* Empty password for raw read optimization */

    //BOOL use_fast_path;
    //dc_status status;
    //dc_get_device_status(device, &status);
    //use_fast_path = (status.flags & F_ENABLED);

    do {
        /* Allocate buffer for encrypted header */
        backup = (u8*)secure_alloc(bytes);
        if (!backup) { resl = ST_NOMEM; break; }

        /* Get raw encrypted primary header from driver (no KDF in driver) */
        resl = _wait_dc_backup_header(hwnd, device, &empty_pass, backup, &bytes, HF_KEEP_SALT, L"Loading header...");
        if (resl != ST_OK) break;

        /* Decrypt header in user-mode (single KDF operation)
         * Also capture derived key for caching */
        state->cached_primary_hdk_valid = FALSE;
        resl = _wait_dc_decrypt_header(hwnd, backup, bytes, password,
            &state->header, &state->hdr_key, &state->header_len, &password->kdf,
            state->cached_primary_hdk, L"Decrypting header...");
        if (resl != ST_OK) break;
        state->cached_primary_hdk_valid = TRUE;

        /* If primary header indicates a backup header exists, load it too */
        if (state->header->flags & VF_BACKUP_HEADER)
        {
            int backup_bytes = DC_AREA_MAX_SIZE;

            /* Get raw encrypted backup header from driver */
            resl = _wait_dc_backup_header(hwnd, device, &empty_pass, backup, &backup_bytes, HF_KEEP_SALT | HF_BACKUP_HEADER, L"Loading backup header...");
            if (resl == ST_OK) {
                u8 *backup_start = backup;
                int backup_len = backup_bytes;

                /* Adjust offset: backup header is at the END of the read buffer.
                 * The driver reads head_len bytes but actual backup header size
                 * matches the primary header size. */
                if (backup_bytes > state->header_len) {
                    backup_start = backup + (backup_bytes - state->header_len);
                    backup_len = state->header_len;
                }

                /* Decrypt backup header in user-mode and cache derived key */
                state->cached_backup_hdk_valid = FALSE;
                resl = _wait_dc_decrypt_header(hwnd, backup_start, backup_len, password,
                    &state->backup_header, &state->backup_hdr_key, &state->backup_header_len, NULL,
                    state->cached_backup_hdk, L"Decrypting backup header...");
                if (resl == ST_OK) {
                    state->cached_backup_hdk_valid = TRUE;
                } else {
                    /* Backup header failed to load - warn but continue with primary only */
                    state->backup_header = NULL;
                    state->backup_hdr_key = NULL;
                    state->backup_header_len = 0;
                    resl = ST_OK; /* Don't fail the whole operation */
                }
            } else {
                /* Backup header not found - warn but continue with primary only */
                resl = ST_OK;
            }
        }

    } while (0);

    if (backup) secure_free(backup);

    if (resl == ST_OK) {
        /* Save password for later use */
        state->password = (dc_pass*)secure_alloc(sizeof(dc_pass));
        if (state->password) {
            memcpy(state->password, password, sizeof(dc_pass));
        }

        /* Verify backup header sync status */
        if (state->backup_header) {
            _verify_backup_sync(state);
        }
    }

    return resl;
}

/*
 * Load header from file (user-mode decryption)
 */
static int _load_header_from_file(HWND hwnd, keys_dlg_state *state, wchar_t *file_path, dc_pass *password)
{
    int resl;

    /* Load and decrypt header using dcapi function
     * Also capture derived key for caching */
    state->cached_primary_hdk_valid = FALSE;
    resl = _wait_dc_load_header_file(hwnd, file_path, password,
        &state->header, &state->hdr_key, &state->header_len,
        state->cached_primary_hdk, L"Loading header file...");

    if (resl == ST_OK) {
        state->cached_primary_hdk_valid = TRUE;
        /* Save password for later use */
        state->password = (dc_pass*)secure_alloc(sizeof(dc_pass));
        if (state->password) {
            memcpy(state->password, password, sizeof(dc_pass));
        }
    }

    return resl;
}

/*
 * Save header to volume using driver
 */
static int _save_header_to_volume(HWND hwnd, keys_dlg_state *state, dc_header* upd_header, int head_size)
{
    u8  *enc_header = NULL;
    int  resl;
    dc_pass *update_pass;
    dc_pass raw_key_pass = {0};

    if (!upd_header || !state->hdr_key || !state->password) {
        return ST_ERROR;
    }

    /* Use cached derived key if available to skip KDF in driver */
    if (state->cached_primary_hdk_valid) {
        raw_key_pass.kdf = KDF_NONE;
        raw_key_pass.size = DISKKEY_SIZE;
        memcpy(raw_key_pass.pass, state->cached_primary_hdk, PKCS_DERIVE_MAX);
        update_pass = &raw_key_pass;
    } else {
        update_pass = state->password;
    }

    /* Encrypt header using dcapi function */
    resl = dc_encrypt_header(upd_header, head_size, state->hdr_key, &enc_header);
    if (resl != ST_OK) {
        return resl;
    }

    /* Update primary header on volume */
    resl = _wait_dc_update_header(hwnd, state->device, update_pass, enc_header, head_size, state->modified, L"Saving header...");

    /* Burn raw key if used */
    if (update_pass == &raw_key_pass) {
        burn(&raw_key_pass, sizeof(raw_key_pass));
    }

    secure_free(enc_header);
    enc_header = NULL;

    if (resl != ST_OK) {
        return resl;
    }

    /* If backup header exists, sync and update it too */
    if ((state->header->flags & VF_BACKUP_HEADER) && state->backup_header && state->backup_hdr_key)
    {
        dc_header *bak_upd = NULL;
        int slots_len = 0;

        /* Create backup update header - copy from upd_header but preserve backup's salt and key slots */
        bak_upd = (dc_header*)secure_alloc(head_size);
        if (!bak_upd) {
            return ST_NOT_BACKUP;
        }

        /* Start with backup header (to preserve salt and keyslot payloads) */
        memcpy(bak_upd, state->backup_header, head_size);

        /* Calculate keyslot area length to preserve */
        if (upd_header->version >= DC_HDR_VERSION_2 && (upd_header->feature_flags & FF_KEY_SLOTS) && upd_header->slot_area_len > 0) {
            slots_len = upd_header->slot_area_len + upd_header->key_slot_count * upd_header->slot_info_size;
        }

        /* Copy header base (after salt) from updated primary */
        memcpy(((u8*)bak_upd) + HEADER_SALT_SIZE, ((u8*)upd_header) + HEADER_SALT_SIZE, DC_BASE_SIZE - HEADER_SALT_SIZE);

        /* Copy data after keyslot payload area (slot info, ext header, etc.) from updated primary */
        if (DC_BASE_SIZE + slots_len < head_size) {
            memcpy(((u8*)bak_upd) + DC_BASE_SIZE + slots_len, ((u8*)upd_header) + DC_BASE_SIZE + slots_len, head_size - DC_BASE_SIZE - slots_len);
        }

        /* Encrypt with backup header key */
        resl = dc_encrypt_header(bak_upd, head_size, state->backup_hdr_key, &enc_header);
        secure_free(bak_upd);

        if (resl == ST_OK) {
            dc_pass *bak_update_pass;
            dc_pass bak_raw_key_pass = {0};

            /* Use cached derived key if available to skip KDF in driver */
            if (state->cached_backup_hdk_valid) {
                bak_raw_key_pass.kdf = KDF_NONE;
                bak_raw_key_pass.size = DISKKEY_SIZE;
                memcpy(bak_raw_key_pass.pass, state->cached_backup_hdk, PKCS_DERIVE_MAX);
                bak_update_pass = &bak_raw_key_pass;
            } else {
                bak_update_pass = state->password;
            }

            /* Update backup header on volume */
            int bak_resl = _wait_dc_update_header(hwnd, state->device, bak_update_pass, enc_header, head_size,
                                            state->modified | HF_BACKUP_HEADER, L"Saving backup header...");

            /* Burn raw key if used */
            if (bak_update_pass == &bak_raw_key_pass) {
                burn(&bak_raw_key_pass, sizeof(bak_raw_key_pass));
            }

            secure_free(enc_header);

            if (bak_resl != ST_OK) {
                /* Backup update failed - return specific error but primary was saved */
                return ST_NOT_BACKUP;
            }
        } else {
            /* Encryption failed for backup - primary was saved */
            return ST_NOT_BACKUP;
        }
    }

    return resl;
}

/*
 * Save header to file (user-mode encryption)
 */
static int _save_header_to_file(keys_dlg_state *state, dc_header* upd_header, int head_size)
{
    if (!upd_header || !state->hdr_key) {
        return ST_ERROR;
    }

    /* Save encrypted header using dcapi function */
    return dc_save_header_file(state->file_path, upd_header, head_size, state->hdr_key);
}

void _format_hdr_size(u32 size, wchar_t *buf, int buf_len, BOOLEAN no_hint)
{
    if (size == DC_AREA_SIZE && !no_hint)
        _snwprintf(buf, buf_len, L"2 KiB (legacy)");
    else if (size == 64*1024 && !no_hint)
        _snwprintf(buf, buf_len, L"64 KiB (recommended)");
    else if (size < 1024 * 1024)
        _snwprintf(buf, buf_len, L"%u KiB", size / 1024);
    else
        _snwprintf(buf, buf_len, L"%u MiB", size / (1024 * 1024));
}