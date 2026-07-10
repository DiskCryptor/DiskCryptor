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
#include <commctrl.h>

#include "main.h"
#include "prc_tpm.h"
#include "prc_pass.h"
#include "prc_wait.h"
#include "tpm_sup.h"

// Entry types
#define TPM_ENTRY_PRIMARY_NV      0
#define TPM_ENTRY_PRIMARY_FILE    1
#define TPM_ENTRY_RECOVERY_NV     2
#define TPM_ENTRY_RECOVERY_FILE   3
#define TPM_ENTRY_BACKUP_FILE     4

// Entry info structure
typedef struct _tpm_entry_info {
    int     type;
    BOOL    exists;
    BOOL    valid;
    wchar_t type_str[32];
    wchar_t location_str[32];
    wchar_t protection_str[64];
} tpm_entry_info;

// Tab indices
#define TAB_ENTRIES     0
#define TAB_INFO        1
#define TAB_PCRS        2
#define TAB_NV          3

// Dialog state
typedef struct _tpm_dlg_state {
    HWND    h_tab;
    HWND    h_entries_dlg;
    HWND    h_info_dlg;
    HWND    h_pcrs_dlg;
    HWND    h_nv_dlg;
    HWND    h_list;
    HWND    h_pcr_list;
    HWND    h_nv_list;
    int     current_tab;
    tpm_entry_info entries[5];
    int     entry_count;
    int     selected_entry;
    int     selected_nv_entry;
    int     tpm_version;            // 12 or 20
    wchar_t owner_pwd[MAX_PASSWORD]; // TPM 1.2 owner password (cached)
    int     owner_pwd_set;          // 1 if owner password has been entered
} tpm_dlg_state;

static tpm_dlg_state *g_tpm_state = NULL;

// Forward declarations
static void _tpm_refresh_entries(HWND hwnd);
static void _tpm_refresh_info(HWND hwnd);
static void _tpm_refresh_pcrs(HWND hwnd);
static void _tpm_refresh_nv(HWND hwnd);
static void _tpm_add_recovery_nv(HWND hwnd);
static void _tpm_add_recovery_file(HWND hwnd);
static void _tpm_add_backup_file(HWND hwnd);
static void _tpm_remove_entry(HWND hwnd);
static void _tpm_load_to_cache(HWND hwnd);
static void _tpm_update_buttons(HWND hwnd);
static void _tpm_update_tab_states(HWND hwnd);

// Get owner password for TPM 1.2 operations
// Returns pointer to cached password or NULL for TPM 2.0
// If TPM 1.2 and password not cached, prompts user
static const wchar_t* _tpm_get_owner_pwd(HWND hwnd)
{
    tpm_dlg_state *state = g_tpm_state;
    if (!state) return NULL;

    // TPM 2.0 doesn't need owner password for these operations
    if (state->tpm_version != 12) {
        return NULL;
    }

    // Already have password cached
    if (state->owner_pwd_set) {
        return state->owner_pwd;
    }

    // Prompt for owner password
    dlgpass dlg_info = { L"Enter TPM Owner Password", NULL, PF_RAW_PASSWORD };
    if (_dlg_get_pass(hwnd, &dlg_info) != ST_OK || !dlg_info.pass) {
        if (dlg_info.pass) {
            burn(dlg_info.pass, sizeof(dc_pass));
            secure_free(dlg_info.pass);
        }
        return NULL;
    }

    // Cache the password
    wcsncpy(state->owner_pwd, dlg_info.pass->pass, MAX_PASSWORD - 1);
    state->owner_pwd[MAX_PASSWORD - 1] = L'\0';
    state->owner_pwd_set = 1;

    burn(dlg_info.pass, sizeof(dc_pass));
    secure_free(dlg_info.pass);

    return state->owner_pwd;
}

// Clear cached owner password (call on wrong password error)
static void _tpm_clear_owner_pwd(void)
{
    tpm_dlg_state *state = g_tpm_state;
    if (state && state->owner_pwd_set) {
        burn(state->owner_pwd, sizeof(state->owner_pwd));
        state->owner_pwd_set = 0;
    }
}


static void _tpm_init_list(HWND h_list)
{
    LVCOLUMN lvc = {0};

    ListView_SetExtendedListViewStyle(h_list,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

    // Type column
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lvc.pszText = L"Type";
    lvc.cx = 80;
    lvc.iSubItem = 0;
    ListView_InsertColumn(h_list, 0, &lvc);

    // Location column
    lvc.pszText = L"Location";
    lvc.cx = 100;
    lvc.iSubItem = 1;
    ListView_InsertColumn(h_list, 1, &lvc);

    // Protection column
    lvc.pszText = L"Protection";
    lvc.cx = 90;
    lvc.iSubItem = 2;
    ListView_InsertColumn(h_list, 2, &lvc);
}


static void _tpm_build_protection_str(wchar_t *buf, size_t buf_size, u32 pcr_mask, u32 flags)
{
    int has_pcr = (pcr_mask != 0);
    int pin_required = (flags & DC_TPM_FLAG_PIN_REQUIRED) != 0;
    if (has_pcr) {
        _snwprintf(buf, buf_size,
            L"%sPCR (0x%X)",
            pin_required ? L"PIN + " : L"",
            pcr_mask);
    } else if (pin_required) {
        wcscpy(buf, L"PIN");
    } else {
        wcscpy(buf, L"None");
    }
}

static void _tpm_populate_entry(tpm_entry_info *entry, int type)
{
    u32 pcr_mask = 0;
    u32 flags = 0;

    entry->type = type;
    entry->exists = FALSE;
    entry->valid = FALSE;
    wcscpy(entry->protection_str, L"-");

    switch (type) {
        case TPM_ENTRY_PRIMARY_NV:
            wcscpy(entry->type_str, L"Primary");
            wcscpy(entry->location_str, L"TPM NV");
            if (dc_tpm_nv_entry_exists(DC_TPM_NV_INDEX_PRIMARY)) {
                entry->exists = TRUE;
                if (dc_tpm_nv_get_info(DC_TPM_NV_INDEX_PRIMARY, &pcr_mask, &flags, NULL, NULL) == ST_OK) {
                    entry->valid = TRUE;
                    _tpm_build_protection_str(entry->protection_str, countof(entry->protection_str), pcr_mask, flags);
                }
            }
            break;

        case TPM_ENTRY_PRIMARY_FILE:
            wcscpy(entry->type_str, L"Primary");
            wcscpy(entry->location_str, L"EFI File");
            if (dc_tpm_srk_file_exists(DC_TPM_SRK_FILE_PRIMARY)) {
                entry->exists = TRUE;
                if (dc_tpm_srk_get_file_info(DC_TPM_SRK_FILE_PRIMARY, &pcr_mask, &flags, NULL, NULL) == ST_OK) {
                    entry->valid = TRUE;
                    _tpm_build_protection_str(entry->protection_str, countof(entry->protection_str), pcr_mask, flags);
                }
            }
            break;

        case TPM_ENTRY_RECOVERY_NV:
            wcscpy(entry->type_str, L"Recovery");
            wcscpy(entry->location_str, L"TPM NV");
            if (dc_tpm_nv_entry_exists(DC_TPM_NV_INDEX_RECOVERY)) {
                entry->exists = TRUE;
                if (dc_tpm_nv_get_info(DC_TPM_NV_INDEX_RECOVERY, &pcr_mask, &flags, NULL, NULL) == ST_OK) {
                    entry->valid = TRUE;
                    _tpm_build_protection_str(entry->protection_str, countof(entry->protection_str), pcr_mask, flags);
                }
            }
            break;

        case TPM_ENTRY_RECOVERY_FILE:
            wcscpy(entry->type_str, L"Recovery");
            wcscpy(entry->location_str, L"EFI File");
            if (dc_tpm_srk_file_exists(DC_TPM_SRK_FILE_RECOVERY)) {
                entry->exists = TRUE;
                if (dc_tpm_srk_get_file_info(DC_TPM_SRK_FILE_RECOVERY, &pcr_mask, &flags, NULL, NULL) == ST_OK) {
                    entry->valid = TRUE;
                    _tpm_build_protection_str(entry->protection_str, countof(entry->protection_str), pcr_mask, flags);
                }
            }
            break;

        case TPM_ENTRY_BACKUP_FILE:
            wcscpy(entry->type_str, L"Backup");
            wcscpy(entry->location_str, L"EFI File");
            if (dc_tpm_backup_file_exists()) {
                entry->exists = TRUE;
                entry->valid = TRUE;
                wcscpy(entry->protection_str, L"Password");
            }
            break;
    }
}


static void _tpm_refresh_entries(HWND hwnd)
{
    tpm_dlg_state *state = g_tpm_state;
    if (!state || !state->h_list) return;

    // Clear the list
    ListView_DeleteAllItems(state->h_list);
    state->entry_count = 0;
    state->selected_entry = -1;

    // Populate entries
    for (int i = 0; i < 5; i++) {
        _tpm_populate_entry(&state->entries[i], i);

        // Only show existing entries
        if (state->entries[i].exists) {
            LVITEM lvi = {0};
            lvi.mask = LVIF_TEXT | LVIF_PARAM;
            lvi.iItem = state->entry_count;
            lvi.lParam = i;  // Store entry type as param
            lvi.pszText = state->entries[i].type_str;
            int idx = ListView_InsertItem(state->h_list, &lvi);

            ListView_SetItemText(state->h_list, idx, 1, state->entries[i].location_str);
            ListView_SetItemText(state->h_list, idx, 2, state->entries[i].protection_str);

            state->entry_count++;
        }
    }

    // Update button states
    EnableWindow(GetDlgItem(hwnd, IDB_TPM_REMOVE_ENTRY), FALSE);
}


static void _tpm_refresh_info(HWND hwnd)
{
    tpm_dlg_state *state = g_tpm_state;
    if (!state || !state->h_info_dlg) return;

    DC_TPM_INFO tpm_info = {0};
    wchar_t buf[256];
    int resl;

    // Get TPM info
    resl = dc_tpm_get_info(&tpm_info);

    // Save TPM version to state (12 for TPM 1.2, 20 for TPM 2.0)
    if (resl == ST_OK && tpm_info.version > 0) {
        state->tpm_version = (tpm_info.version == 1) ? 12 : 20;
    }

    // Display TPM version
    if (resl == ST_OK && tpm_info.version > 0) {
        _snwprintf(buf, countof(buf), L"TPM %.1f", tpm_info.version == 1 ? 1.2 : tpm_info.version);
    } else if (resl == ST_NO_TPM) {
        wcscpy(buf, L"Not available");
    } else {
        wcscpy(buf, L"Not detected");
    }
    SetDlgItemTextW(state->h_info_dlg, IDC_TPM_VERSION, buf);

    // Display vendor info
    if (resl == ST_OK && tpm_info.vendor_id != 0) {
        _snwprintf(buf, countof(buf), L"%hs (FW: %u.%u.%u.%u)",
            tpm_info.vendor_str,
            (tpm_info.firmware_v1 >> 16) & 0xFFFF,
            tpm_info.firmware_v1 & 0xFFFF,
            (tpm_info.firmware_v2 >> 16) & 0xFFFF,
            tpm_info.firmware_v2 & 0xFFFF);
    } else {
        wcscpy(buf, L"Unknown");
    }
    SetDlgItemTextW(state->h_info_dlg, IDC_TPM_VENDOR, buf);

    // Display lockout status
    if (resl == ST_OK && tpm_info.version == 2) {
        if (tpm_info.is_locked_out) {
            _snwprintf(buf, countof(buf), L"Locked (%u sec remaining)",
                tpm_info.lockout_recovery);
        } else {
            _snwprintf(buf, countof(buf), L"OK (%u/%u attempts)",
                tpm_info.lockout_counter, tpm_info.lockout_max);
        }
    } else {
        wcscpy(buf, L"N/A");
    }
    SetDlgItemTextW(state->h_info_dlg, IDC_TPM_LOCKOUT, buf);
}


// PCR descriptions for common PCRs
static const wchar_t *_pcr_descriptions[] = {
	L"BIOS/UEFI firmware",
	L"BIOS/UEFI configuration",
	L"Option ROMs/Drivers (DcsInt, etc...)",
	L"Option ROM configuration",
	L"Boot Manager (DcsBoot)",
	L"Boot Manager configuration/GPT",
	L"Platform state (vendor-specific)",
	L"Secure Boot (state, PK, KEK, db, dbx)",
	L"DiskCryptor DCS Config & Lock",
    L"OS-specific measurements",
    L"OS-specific measurements",
    L"OS-specific measurements",
    L"OS-specific measurements",
    L"OS-specific measurements",
    L"shim, MOK, MokList, MokListX, shim policy",
    L"OS/runtime-specific measurements",
};

static void _tpm_init_pcr_list(HWND h_list)
{
    LVCOLUMN lvc = {0};

    ListView_SetExtendedListViewStyle(h_list,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

    // PCR Number column
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lvc.pszText = L"PCR";
    lvc.cx = 30;
    lvc.iSubItem = 0;
    ListView_InsertColumn(h_list, 0, &lvc);

    // Description column
    lvc.pszText = L"Description";
    lvc.cx = 95;
    lvc.iSubItem = 1;
    ListView_InsertColumn(h_list, 1, &lvc);

    // Value column
    lvc.pszText = L"Hash Value";
    lvc.cx = 145;
    lvc.iSubItem = 2;
    ListView_InsertColumn(h_list, 2, &lvc);
}

static void _tpm_refresh_pcrs(HWND hwnd)
{
    tpm_dlg_state *state = g_tpm_state;
    if (!state || !state->h_pcr_list) return;

    u8 pcr_value[32];
    u32 pcr_size;
    wchar_t buf_num[8];
    wchar_t buf_value[128];
    int resl;
    int i, j;

    // Clear the list
    ListView_DeleteAllItems(state->h_pcr_list);

    // Read and display PCRs 0-15
    for (i = 0; i <= 15; i++) {
        pcr_size = sizeof(pcr_value);
        memset(pcr_value, 0, sizeof(pcr_value));

        resl = dc_tpm_read_pcr(i, pcr_value, &pcr_size);

        // PCR number
        _snwprintf(buf_num, countof(buf_num), L"%d", i);

        LVITEM lvi = {0};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = i;
        lvi.pszText = buf_num;
        int idx = ListView_InsertItem(state->h_pcr_list, &lvi);

        // Description
        ListView_SetItemText(state->h_pcr_list, idx, 1, (LPWSTR)_pcr_descriptions[i]);

        // Value as full hex string
        if (resl == ST_OK && pcr_size > 0) {
            wchar_t *p = buf_value;
            for (j = 0; j < (int)pcr_size && j < 32; j++) {
                p += _snwprintf(p, 3, L"%02X", pcr_value[j]);
            }
            *p = L'\0';
        } else {
            wcscpy(buf_value, L"(read error)");
        }
        ListView_SetItemText(state->h_pcr_list, idx, 2, buf_value);
    }
}


static void _tpm_format_nv_attrs(u32 attrs, u32 pcr_mask, wchar_t *buf, int buf_size)
{
    wchar_t flags[8];
    int pos = 0;

    // W/- = Written
    flags[pos++] = (attrs & TPMA_NV_WRITTEN) ? L'W' : L'-';

    // Write access: A=AuthWrite, O=OwnerWrite, P=PPWrite, Y=PolicyWrite, -=none
    if (attrs & TPMA_NV_AUTHWRITE) {
        flags[pos++] = L'A';
    } else if (attrs & TPMA_NV_OWNERWRITE) {
        flags[pos++] = L'O';
    } else if (attrs & TPMA_NV_PPWRITE) {
        flags[pos++] = L'P';
    } else if (attrs & TPMA_NV_POLICYWRITE) {
        flags[pos++] = L'Y';
    } else {
        flags[pos++] = L'-';
    }

    // Read access: a=AuthRead, o=OwnerRead, p=PPRead, y=PolicyRead, -=none
    if (attrs & TPMA_NV_AUTHREAD) {
        flags[pos++] = L'a';
    } else if (attrs & TPMA_NV_OWNERREAD) {
        flags[pos++] = L'o';
    } else if (attrs & TPMA_NV_PPREAD) {
        flags[pos++] = L'p';
    } else if (attrs & TPMA_NV_POLICYREAD) {
        flags[pos++] = L'y';
    } else {
        flags[pos++] = L'-';
    }

    // L/- = WriteLock
    flags[pos++] = (attrs & TPMA_NV_WRITELOCK) ? L'L' : L'-';
    flags[pos] = L'\0';

    // Format: 0x******** (----) or with PCR mask for TPM 1.2
    if (pcr_mask != 0) {
        _snwprintf(buf, buf_size, L"0x%08X (%s) PCR:0x%03X", attrs, flags, pcr_mask);
    } else {
        _snwprintf(buf, buf_size, L"0x%08X (%s)", attrs, flags);
    }
}

static void _tpm_init_nv_list(HWND h_list)
{
    LVCOLUMN lvc = {0};

    ListView_SetExtendedListViewStyle(h_list,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

    // Index column
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lvc.pszText = L"Index";
    lvc.cx = 75;
    lvc.iSubItem = 0;
    ListView_InsertColumn(h_list, 0, &lvc);

    // Description column
    lvc.pszText = L"Description";
    lvc.cx = 80;
    lvc.iSubItem = 1;
    ListView_InsertColumn(h_list, 1, &lvc);

    // Attributes column (hex + flags + PCR mask)
    lvc.pszText = L"Attributes";
    lvc.cx = 175;
    lvc.iSubItem = 2;
    ListView_InsertColumn(h_list, 2, &lvc);

    // Size column
    lvc.pszText = L"Size";
    lvc.cx = 35;
    lvc.iSubItem = 3;
    ListView_InsertColumn(h_list, 3, &lvc);
}

static void _tpm_refresh_nv(HWND hwnd)
{
    tpm_dlg_state *state = g_tpm_state;
    if (!state || !state->h_nv_list) return;

    DC_TPM_NV_ENTRY nv_entries[DC_TPM_NV_MAX_ENTRIES];
    u32 count = DC_TPM_NV_MAX_ENTRIES;
    wchar_t buf_index[16];
    wchar_t buf_attrs[48];
    wchar_t buf_size[16];
    int resl;

    // Clear the list
    ListView_DeleteAllItems(state->h_nv_list);
    state->selected_nv_entry = -1;

    // Enumerate NV entries
    resl = dc_tpm_enum_nv(nv_entries, &count);
    if (resl != ST_OK || count == 0) {
        return;
    }

    for (u32 i = 0; i < count; i++) {
        // Index as hex
        _snwprintf(buf_index, countof(buf_index), L"0x%08X", nv_entries[i].nv_index);

        LVITEM lvi = {0};
        lvi.mask = LVIF_TEXT | LVIF_PARAM;
        lvi.iItem = i;
        lvi.pszText = buf_index;
        lvi.lParam = nv_entries[i].nv_index;  // Store handle for later use
        int idx = ListView_InsertItem(state->h_nv_list, &lvi);

        // Description
        if (nv_entries[i].description[0] != L'\0') {
            ListView_SetItemText(state->h_nv_list, idx, 1, nv_entries[i].description);
        } else {
            ListView_SetItemText(state->h_nv_list, idx, 1, L"-");
        }

        // Attributes (hex + readable format + PCR mask)
        _tpm_format_nv_attrs(nv_entries[i].attributes, nv_entries[i].pcr_mask, buf_attrs, countof(buf_attrs));
        ListView_SetItemText(state->h_nv_list, idx, 2, buf_attrs);

        // Size
        _snwprintf(buf_size, countof(buf_size), L"%u", nv_entries[i].data_size);
        ListView_SetItemText(state->h_nv_list, idx, 3, buf_size);
    }
}


static void _tpm_update_buttons(HWND hwnd)
{
    tpm_dlg_state *state = g_tpm_state;
    if (!state) return;

    int tab = state->current_tab;
    BOOL enable_add = FALSE;
    BOOL enable_remove = FALSE;
    BOOL enable_load = FALSE;

    switch (tab) {
        case TAB_ENTRIES:
            enable_add = TRUE;
            enable_remove = (state->selected_entry >= 0);
            enable_load = (state->selected_entry >= 0);
            break;
        case TAB_INFO:
        case TAB_PCRS:
            // No buttons enabled
            break;
        case TAB_NV:
#ifdef _DEBUG
            enable_remove = (state->selected_nv_entry >= 0);
#endif
            break;
    }

    EnableWindow(GetDlgItem(hwnd, IDB_TPM_ADD_ENTRY), enable_add);
    EnableWindow(GetDlgItem(hwnd, IDB_TPM_REMOVE_ENTRY), enable_remove);
    EnableWindow(GetDlgItem(hwnd, IDB_TPM_LOAD_TO_CACHE), enable_load);
}


static void _tpm_add_recovery_nv(HWND hwnd)
{
    dlgpass dlg_info = { L"Enter Secret to Store", NULL, PF_NEW_PASS_ONLY };
    int resl;

    DC_TPM_INFO tpm_info = {0};
    if (dc_tpm_get_info(&tpm_info) != ST_OK || tpm_info.version == 0) {
        __msg_e(hwnd, L"A TPM is required for NV storage.");
        return;
    }

    // Check if already exists
    if (dc_tpm_nv_entry_exists(DC_TPM_NV_INDEX_RECOVERY)) {
        if (!__msg_q(hwnd, L"Recovery NV entry already exists.\n\nDo you want to overwrite it?")) {
            return;
        }
    }

    // Prompt for secret
    if (_dlg_change_pass(hwnd, &dlg_info) != ST_OK || !dlg_info.new_pass) {
        if (dlg_info.new_pass) {
            burn(dlg_info.new_pass, sizeof(dc_pass));
            secure_free(dlg_info.new_pass);
        }
        return;
    }

    dc_pass *secret = dlg_info.new_pass;
    dlg_info.new_pass = NULL;
    dlg_info.caption = L"Enter TPM PIN";
    dlg_info.flags |= PF_RAW_PASSWORD;

    // Prompt for PIN
    if (_dlg_change_pass(hwnd, &dlg_info) != ST_OK || !dlg_info.new_pass) {
        burn(secret, sizeof(dc_pass));
        secure_free(secret);
        if (dlg_info.new_pass) {
            burn(dlg_info.new_pass, sizeof(dc_pass));
            secure_free(dlg_info.new_pass);
        }
        return;
    }

    dc_pass *pin = dlg_info.new_pass;

    // Get owner password for TPM 1.2
    const wchar_t *owner_pwd = _tpm_get_owner_pwd(hwnd);
    if (g_tpm_state->tpm_version == 12 && !owner_pwd) {
        burn(secret, sizeof(dc_pass));
        secure_free(secret);
        burn(pin, sizeof(dc_pass));
        secure_free(pin);
        return;
    }

    // Create the NV entry
    resl = dc_tpm_create_nv_entry(DC_TPM_NV_INDEX_RECOVERY, pin->pass, 0, secret, NULL, 0, owner_pwd);

    burn(secret, sizeof(dc_pass));
    secure_free(secret);
    burn(pin, sizeof(dc_pass));
    secure_free(pin);

    if (resl == ST_TPM_WRONG_PIN) {
        _tpm_clear_owner_pwd();
    }

    if (resl == ST_OK) {
        __msg_i(hwnd, L"Recovery NV entry created successfully.");
        _tpm_refresh_entries(hwnd);
    } else {
        __error_s(hwnd, L"Failed to create Recovery NV entry", resl);
    }
}


static void _tpm_add_recovery_file(HWND hwnd)
{
    dlgpass dlg_info = { L"Enter Secret to Store", NULL, PF_NEW_PASS_ONLY };
    int resl;

    DC_TPM_INFO tpm_info = {0};
    if (dc_tpm_get_info(&tpm_info) != ST_OK || tpm_info.version == 0) {
        __msg_e(hwnd, L"A TPM is required for SRK sealing.");
        return;
    }

    // Check if already exists
    if (dc_tpm_srk_file_exists(DC_TPM_SRK_FILE_RECOVERY)) {
        if (!__msg_q(hwnd, L"Recovery file already exists.\n\nDo you want to overwrite it?")) {
            return;
        }
    }

    // Prompt for secret
    if (_dlg_change_pass(hwnd, &dlg_info) != ST_OK || !dlg_info.new_pass) {
        if (dlg_info.new_pass) {
            burn(dlg_info.new_pass, sizeof(dc_pass));
            secure_free(dlg_info.new_pass);
        }
        return;
    }

    dc_pass *secret = dlg_info.new_pass;
    dlg_info.new_pass = NULL;
    dlg_info.caption = L"Enter TPM PIN";
    dlg_info.flags |= PF_RAW_PASSWORD;

    // Prompt for PIN (optional)
    if (_dlg_change_pass(hwnd, &dlg_info) != ST_OK || !dlg_info.new_pass) {
        if (dlg_info.new_pass) {
            burn(dlg_info.new_pass, sizeof(dc_pass));
            secure_free(dlg_info.new_pass);
        }
        burn(secret, sizeof(dc_pass));
        secure_free(secret);
        return;
    }
    wchar_t *pin = _wcsdup(dlg_info.new_pass->pass);

    // Create the SRK sealed file
    resl = dc_tpm_srk_create_file(DC_TPM_SRK_FILE_RECOVERY, secret, 0, pin, NULL, 0);

    burn(secret, sizeof(dc_pass));
    secure_free(secret);
    if (pin) {
        burn(pin, wcslen(pin) * sizeof(wchar_t));
        free(pin);
    }

    if (resl == ST_OK) {
        __msg_i(hwnd, L"Recovery file created successfully.");
        _tpm_refresh_entries(hwnd);
    } else {
        __error_s(hwnd, L"Failed to create recovery file", resl);
    }
}


static void _tpm_add_backup_file(HWND hwnd)
{
    dlgpass dlg_info = { L"Enter Secret to Store", NULL, PF_NEW_PASS_ONLY };
    int resl;

    // Check if already exists
    if (dc_tpm_backup_file_exists()) {
        if (!__msg_q(hwnd, L"Backup file already exists.\n\nDo you want to overwrite it?")) {
            return;
        }
    }

    // Prompt for secret
    if (_dlg_change_pass(hwnd, &dlg_info) != ST_OK || !dlg_info.new_pass) {
        if (dlg_info.new_pass) {
            burn(dlg_info.new_pass, sizeof(dc_pass));
            secure_free(dlg_info.new_pass);
        }
        return;
    }

    dc_pass *secret = dlg_info.new_pass;
    dlg_info.new_pass = NULL;
    dlg_info.caption = L"Enter Backup File Password";

    // Prompt for backup password
    if (_dlg_change_pass(hwnd, &dlg_info) != ST_OK || !dlg_info.new_pass) {
        burn(secret, sizeof(dc_pass));
        secure_free(secret);
        if (dlg_info.new_pass) {
            burn(dlg_info.new_pass, sizeof(dc_pass));
            secure_free(dlg_info.new_pass);
        }
        return;
    }

    dc_pass *backup_pass = dlg_info.new_pass;

    // Create the backup file (kdf=0 for PKCS5.2, cipher=0 for AES)
    resl = dc_tpm_backup_file_create(backup_pass, secret, 0, 0);

    burn(secret, sizeof(dc_pass));
    secure_free(secret);
    burn(backup_pass, sizeof(dc_pass));
    secure_free(backup_pass);

    if (resl == ST_OK) {
        __msg_i(hwnd, L"Backup file created successfully.");
        _tpm_refresh_entries(hwnd);
    } else {
        __error_s(hwnd, L"Failed to create backup file", resl);
    }
}


static void _tpm_remove_entry(HWND hwnd)
{
    tpm_dlg_state *state = g_tpm_state;
    if (!state) return;

    int resl = ST_ERROR;

    // Handle NV tab removal (debug only)
#ifdef _DEBUG
    if (state->current_tab == TAB_NV && state->selected_nv_entry >= 0) {
        LVITEM lvi = {0};
        lvi.mask = LVIF_PARAM;
        lvi.iItem = state->selected_nv_entry;
        if (!ListView_GetItem(state->h_nv_list, &lvi)) return;

        u32 nv_index = (u32)lvi.lParam;
        wchar_t msg[128];
        _snwprintf(msg, countof(msg), L"Delete NV entry 0x%08X?\n\nThis action cannot be undone.", nv_index);
        if (!__msg_q(hwnd, msg))
            return;

        // Get owner password for TPM 1.2
        const wchar_t *owner_pwd = _tpm_get_owner_pwd(hwnd);
        if (state->tpm_version == 12 && !owner_pwd) {
            return;
        }

        resl = dc_tpm_delete_nv(nv_index, owner_pwd);

        if (resl == ST_TPM_WRONG_PIN) {
            _tpm_clear_owner_pwd();
        }

        if (resl == ST_OK) {
            __msg_i(hwnd, L"NV entry deleted successfully.");
            _tpm_refresh_nv(hwnd);
            _tpm_refresh_entries(hwnd);
            _tpm_update_buttons(hwnd);
        } else {
            __error_s(hwnd, L"Failed to delete NV entry", resl);
        }
        return;
    }
#endif

    // Handle Sealed Entries tab removal
    if (state->current_tab != TAB_ENTRIES || state->selected_entry < 0) return;

    // Get the selected item's entry type
    LVITEM lvi = {0};
    lvi.mask = LVIF_PARAM;
    lvi.iItem = state->selected_entry;
    if (!ListView_GetItem(state->h_list, &lvi)) return;

    int entry_type = (int)lvi.lParam;

    switch (entry_type) {
        case TPM_ENTRY_PRIMARY_NV:
            if (!__msg_q(hwnd, L"Remove Primary NV entry?\n\nThis will delete the sealed secret from TPM NV storage."))
                return;
            {
                const wchar_t *owner_pwd = _tpm_get_owner_pwd(hwnd);
                if (state->tpm_version == 12 && !owner_pwd) return;
                resl = dc_tpm_delete_nv_entry(DC_TPM_NV_INDEX_PRIMARY, owner_pwd);
                if (resl == ST_TPM_WRONG_PIN) _tpm_clear_owner_pwd();
            }
            break;

        case TPM_ENTRY_PRIMARY_FILE:
            if (!__msg_q(hwnd, L"Remove Primary sealed file?\n\nThis will delete the file from the EFI partition."))
                return;
            resl = dc_tpm_srk_delete_file(DC_TPM_SRK_FILE_PRIMARY);
            break;

        case TPM_ENTRY_RECOVERY_NV:
            if (!__msg_q(hwnd, L"Remove Recovery NV entry?\n\nThis will delete the sealed secret from TPM NV storage."))
                return;
            {
                const wchar_t *owner_pwd = _tpm_get_owner_pwd(hwnd);
                if (state->tpm_version == 12 && !owner_pwd) return;
                resl = dc_tpm_delete_nv_entry(DC_TPM_NV_INDEX_RECOVERY, owner_pwd);
                if (resl == ST_TPM_WRONG_PIN) _tpm_clear_owner_pwd();
            }
            break;

        case TPM_ENTRY_RECOVERY_FILE:
            if (!__msg_q(hwnd, L"Remove Recovery sealed file?\n\nThis will delete the file from the EFI partition."))
                return;
            resl = dc_tpm_srk_delete_file(DC_TPM_SRK_FILE_RECOVERY);
            break;

        case TPM_ENTRY_BACKUP_FILE:
            if (!__msg_q(hwnd, L"Remove Backup file?\n\nThis will delete the file from the EFI partition."))
                return;
            resl = dc_tpm_backup_file_delete();
            break;
    }

    if (resl == ST_OK) {
        __msg_i(hwnd, L"Entry removed successfully.");
        _tpm_refresh_entries(hwnd);
        _tpm_update_buttons(hwnd);
    } else {
        __error_s(hwnd, L"Failed to remove entry", resl);
    }
}


static void _tpm_load_to_cache(HWND hwnd)
{
    tpm_dlg_state *state = g_tpm_state;
    if (!state || state->current_tab != TAB_ENTRIES || state->selected_entry < 0) return;

    // Get the selected item's entry type
    LVITEM lvi = {0};
    lvi.mask = LVIF_PARAM;
    lvi.iItem = state->selected_entry;
    if (!ListView_GetItem(state->h_list, &lvi)) return;

    int entry_type = (int)lvi.lParam;
    dlgpass dlg_info;
    dc_pass pass;
    int resl = ST_ERROR;

    memset(&pass, 0, sizeof(pass));

    switch (entry_type) {
        case TPM_ENTRY_PRIMARY_NV:
        case TPM_ENTRY_RECOVERY_NV:
        {
            // Prompt for TPM PIN
            dlg_info.caption = L"Enter TPM PIN";
            dlg_info.node = NULL;
            dlg_info.flags = PF_RAW_PASSWORD;
            dlg_info.pass = NULL;

            if (_dlg_get_pass(hwnd, &dlg_info) != ST_OK || !dlg_info.pass) {
                if (dlg_info.pass) {
                    burn(dlg_info.pass, sizeof(dc_pass));
                    secure_free(dlg_info.pass);
                }
                return;
            }

            // Unseal from NV entry
            u32 nv_index = (entry_type == TPM_ENTRY_PRIMARY_NV) ?
                DC_TPM_NV_INDEX_PRIMARY : DC_TPM_NV_INDEX_RECOVERY;
            resl = dc_tpm_unseal_nv_entry(nv_index, dlg_info.pass->pass, &pass);

            burn(dlg_info.pass, sizeof(dc_pass));
            secure_free(dlg_info.pass);
        }
        break;

        case TPM_ENTRY_PRIMARY_FILE:
        case TPM_ENTRY_RECOVERY_FILE:
        {
            // Prompt for TPM PIN
            dlg_info.caption = L"Enter TPM PIN";
            dlg_info.node = NULL;
            dlg_info.flags = PF_RAW_PASSWORD;
            dlg_info.pass = NULL;

            if (_dlg_get_pass(hwnd, &dlg_info) != ST_OK || !dlg_info.pass) {
                if (dlg_info.pass) {
                    burn(dlg_info.pass, sizeof(dc_pass));
                    secure_free(dlg_info.pass);
                }
                return;
            }

            // Unseal from SRK file
            const wchar_t* path = (entry_type == TPM_ENTRY_PRIMARY_FILE) ?
                DC_TPM_SRK_FILE_PRIMARY : DC_TPM_SRK_FILE_RECOVERY;
            resl = dc_tpm_srk_unseal_file(path, dlg_info.pass->pass, &pass);

            burn(dlg_info.pass, sizeof(dc_pass));
            secure_free(dlg_info.pass);
        }
        break;

        case TPM_ENTRY_BACKUP_FILE:
        {
            // Prompt for backup password
            dlg_info.caption = L"Enter Backup File Password";
            dlg_info.node = NULL;
            dlg_info.flags = PF_NO_KEY_SLOTS;
            dlg_info.pass = NULL;

            if (_dlg_get_pass(hwnd, &dlg_info) != ST_OK || !dlg_info.pass) {
                if (dlg_info.pass) {
                    burn(dlg_info.pass, sizeof(dc_pass));
                    secure_free(dlg_info.pass);
                }
                return;
            }

            resl = dc_tpm_unseal_backup_file(dlg_info.pass, &pass);

            burn(dlg_info.pass, sizeof(dc_pass));
            secure_free(dlg_info.pass);
        }
        break;

        default:
            return;
    }

    if (resl != ST_OK) {
        if (resl == ST_PASS_ERR) {
            __msg_e(hwnd, L"Incorrect PIN or password.");
        } else if (resl == ST_NOT_SUPPORTED) {
            __msg_e(hwnd, L"PCR+PIN combined policy is not yet supported.\n\n"
                L"Only PIN-only entries (PcrMask=0) are currently supported.");
        } else if (resl == ST_FORMAT_ERR) {
            __msg_e(hwnd, L"TPM entry is corrupted or has invalid format.");
        } else {
            __error_s(hwnd, L"Failed to unseal TPM secret", resl);
        }
        burn(&pass, sizeof(pass));
        return;
    }

    // Set the tag to 'TPM' and add to password cache
    strcpy(pass.label, "TPM Secret");
    resl = _wait_dc_add_password(hwnd, &pass, L"Adding TPM password to cache...");

    burn(&pass, sizeof(pass));

    if (resl != ST_OK) {
        __error_s(hwnd, L"Failed to add password to cache", resl);
    } else {
        __msg_i(hwnd, L"TPM secret loaded to password cache with tag 'TPM'.");
    }
}


static void _tpm_show_add_menu(HWND hwnd)
{
    tpm_dlg_state *state = g_tpm_state;
    HMENU hMenu = LoadMenu(NULL, MAKEINTRESOURCE(IDR_MENU_TPM_ADD));
    if (!hMenu) return;

    HMENU hPopup = GetSubMenu(hMenu, 0);
    if (!hPopup) {
        DestroyMenu(hMenu);
        return;
    }

    // Disable TPM-dependent options when no TPM is available
    if (!state || state->tpm_version == 0) {
        EnableMenuItem(hPopup, IDM_TPM_ADD_RECOVERY_NV, MF_BYCOMMAND | MF_GRAYED);
        EnableMenuItem(hPopup, IDM_TPM_ADD_RECOVERY_FILE, MF_BYCOMMAND | MF_GRAYED);
    }

    // Get button position
    RECT rc;
    GetWindowRect(GetDlgItem(hwnd, IDB_TPM_ADD_ENTRY), &rc);

    // Show the menu
    int cmd = TrackPopupMenu(hPopup,
        TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RETURNCMD | TPM_NONOTIFY,
        rc.left, rc.bottom, 0, hwnd, NULL);

    DestroyMenu(hMenu);

    // Handle menu selection
    switch (cmd) {
        case IDM_TPM_ADD_RECOVERY_NV:
            _tpm_add_recovery_nv(hwnd);
            break;
        case IDM_TPM_ADD_RECOVERY_FILE:
            _tpm_add_recovery_file(hwnd);
            break;
        case IDM_TPM_ADD_BACKUP_FILE:
            _tpm_add_backup_file(hwnd);
            break;
    }
}


static void _tpm_on_list_select(HWND hwnd)
{
    tpm_dlg_state *state = g_tpm_state;
    if (!state || !state->h_list) return;

    int sel = ListView_GetNextItem(state->h_list, -1, LVNI_SELECTED);
    state->selected_entry = sel;

    _tpm_update_buttons(hwnd);
}


static void _tpm_on_nv_list_select(HWND hwnd)
{
    tpm_dlg_state *state = g_tpm_state;
    if (!state || !state->h_nv_list) return;

    int sel = ListView_GetNextItem(state->h_nv_list, -1, LVNI_SELECTED);
    state->selected_nv_entry = sel;

    _tpm_update_buttons(hwnd);
}


static void _tpm_switch_tab(HWND hwnd, int tab_idx)
{
    tpm_dlg_state *state = g_tpm_state;
    if (!state) return;

    state->current_tab = tab_idx;

    ShowWindow(state->h_entries_dlg, tab_idx == TAB_ENTRIES ? SW_SHOW : SW_HIDE);
    ShowWindow(state->h_info_dlg, tab_idx == TAB_INFO ? SW_SHOW : SW_HIDE);
    ShowWindow(state->h_pcrs_dlg, tab_idx == TAB_PCRS ? SW_SHOW : SW_HIDE);
    ShowWindow(state->h_nv_dlg, tab_idx == TAB_NV ? SW_SHOW : SW_HIDE);

    _tpm_update_buttons(hwnd);
}


static void _tpm_update_tab_states(HWND hwnd)
{
    tpm_dlg_state *state = g_tpm_state;
    if (!state || !state->h_tab) return;

    TCITEM tci = {0};
    tci.mask = TCIF_TEXT;

    // Update PCR tab text based on TPM availability
    if (state->tpm_version == 0) {
        tci.pszText = L"PCRs (N/A)";
    } else {
        tci.pszText = L"PCRs";
    }
    TabCtrl_SetItem(state->h_tab, TAB_PCRS, &tci);

    // Update NV tab text based on TPM availability
    if (state->tpm_version == 0) {
        tci.pszText = L"NV Entries (N/A)";
    } else {
        tci.pszText = L"NV Entries";
    }
    TabCtrl_SetItem(state->h_tab, TAB_NV, &tci);
}


static
INT_PTR CALLBACK
_tpm_entries_dlg_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam)
{
    switch (message) {
        case WM_INITDIALOG:
            return TRUE;

        case WM_NOTIFY:
        {
            NMHDR *nmhdr = (NMHDR*)lparam;
            if (nmhdr->idFrom == IDC_TPM_ENTRY_LIST) {
                if (nmhdr->code == LVN_ITEMCHANGED) {
                    _tpm_on_list_select(GetParent(hwnd));
                }
            }
        }
        break;
    }
    return FALSE;
}


static
INT_PTR CALLBACK
_tpm_info_dlg_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam)
{
    switch (message) {
        case WM_INITDIALOG:
            return TRUE;

        case WM_NOTIFY:
        {
            NMHDR *nmhdr = (NMHDR*)lparam;
            // Handle NV list selection - forward to main dialog
            if (nmhdr->idFrom == IDC_TPM_NV_LIST && nmhdr->code == LVN_ITEMCHANGED) {
                HWND hwnd_parent = GetParent(hwnd);
                _tpm_on_nv_list_select(hwnd_parent);
            }
        }
        break;
    }
    return FALSE;
}


static
INT_PTR CALLBACK
_tpm_dlg_proc(
    HWND    hwnd,
    UINT    message,
    WPARAM  wparam,
    LPARAM  lparam
)
{
    switch (message)
    {
        case WM_CLOSE:
        {
            dc_tpm_close();
            if (g_tpm_state) {
                free(g_tpm_state);
                g_tpm_state = NULL;
            }
            EndDialog(hwnd, 0);
            return 0L;
        }
        break;

        case WM_COMMAND:
        {
            int id = LOWORD(wparam);

            switch (id)
            {
                case IDB_REFRESH_TEST:
                    _tpm_refresh_info(hwnd);
                    _tpm_refresh_entries(hwnd);
                    if (g_tpm_state && g_tpm_state->tpm_version != 0) {
                        _tpm_refresh_pcrs(hwnd);
                        _tpm_refresh_nv(hwnd);
                    }
                    _tpm_update_tab_states(hwnd);
                    _tpm_update_buttons(hwnd);
                    break;

                case IDB_TPM_ADD_ENTRY:
                    _tpm_show_add_menu(hwnd);
                    break;

                case IDB_TPM_REMOVE_ENTRY:
                    _tpm_remove_entry(hwnd);
                    break;

                case IDB_TPM_LOAD_TO_CACHE:
                    _tpm_load_to_cache(hwnd);
                    break;

                case IDOK:
                case IDCANCEL:
                    dc_tpm_close();
                    if (g_tpm_state) {
                        // Clear any cached owner password
                        _tpm_clear_owner_pwd();
                        free(g_tpm_state);
                        g_tpm_state = NULL;
                    }
                    EndDialog(hwnd, 0);
                    break;
            }
        }
        break;

        case WM_NOTIFY:
        {
            NMHDR *nmhdr = (NMHDR*)lparam;
            if (nmhdr->idFrom == IDT_TPM_TAB) {
                if (nmhdr->code == TCN_SELCHANGING) {
                    // Prevent switching to PCR or NV tabs when no TPM is available
                    tpm_dlg_state *state = g_tpm_state;
                    if (state && state->tpm_version == 0) {
                        int new_tab = TabCtrl_GetCurSel(nmhdr->hwndFrom);
                        // GetCurSel returns current tab during SELCHANGING,
                        // we need to check where user is trying to go
                        TCHITTESTINFO hti;
                        POINT pt;
                        GetCursorPos(&pt);
                        ScreenToClient(nmhdr->hwndFrom, &pt);
                        hti.pt = pt;
                        int clicked_tab = TabCtrl_HitTest(nmhdr->hwndFrom, &hti);
                        if (clicked_tab == TAB_PCRS || clicked_tab == TAB_NV) {
                            SetWindowLongPtr(hwnd, DWLP_MSGRESULT, TRUE);
                            return TRUE;  // Prevent tab change
                        }
                    }
                }
                else if (nmhdr->code == TCN_SELCHANGE) {
                    int tab_idx = TabCtrl_GetCurSel(nmhdr->hwndFrom);
                    _tpm_switch_tab(hwnd, tab_idx);
                }
            }
            // Handle NV list selection changes
            if (nmhdr->idFrom == IDC_TPM_NV_LIST && nmhdr->code == LVN_ITEMCHANGED) {
                _tpm_on_nv_list_select(hwnd);
            }
        }
        break;

        case WM_INITDIALOG:
        {
            // Allocate state
            g_tpm_state = (tpm_dlg_state*)malloc(sizeof(tpm_dlg_state));
            if (!g_tpm_state) {
                EndDialog(hwnd, 0);
                return 0L;
            }
            memset(g_tpm_state, 0, sizeof(tpm_dlg_state));
            g_tpm_state->selected_entry = -1;
            g_tpm_state->selected_nv_entry = -1;

            // Setup tabs
            g_tpm_state->h_tab = GetDlgItem(hwnd, IDT_TPM_TAB);

            // Add owner-draw style for custom tab rendering
            LONG_PTR style = GetWindowLongPtr(g_tpm_state->h_tab, GWL_STYLE);
            SetWindowLongPtr(g_tpm_state->h_tab, GWL_STYLE, style | TCS_OWNERDRAWFIXED);

            TCITEM tci = {0};
            tci.mask = TCIF_TEXT;
            tci.pszText = L"Sealed Entries";
            TabCtrl_InsertItem(g_tpm_state->h_tab, TAB_ENTRIES, &tci);
            tci.pszText = L"TPM Info";
            TabCtrl_InsertItem(g_tpm_state->h_tab, TAB_INFO, &tci);
            tci.pszText = L"PCRs";
            TabCtrl_InsertItem(g_tpm_state->h_tab, TAB_PCRS, &tci);
            tci.pszText = L"NV Entries";
            TabCtrl_InsertItem(g_tpm_state->h_tab, TAB_NV, &tci);

            // Get tab content area
            RECT rc_tab;
            GetWindowRect(GetDlgItem(hwnd, IDC_TPM_TAB), &rc_tab);
            MapWindowPoints(NULL, hwnd, (POINT*)&rc_tab, 2);

            // Create child dialogs
            g_tpm_state->h_entries_dlg = CreateDialog(NULL,
                MAKEINTRESOURCE(DLG_TPM_ENTRIES), hwnd, _tpm_entries_dlg_proc);
            SetWindowPos(g_tpm_state->h_entries_dlg, NULL,
                rc_tab.left + 2, rc_tab.top + 2,
                rc_tab.right - rc_tab.left - 4, rc_tab.bottom - rc_tab.top - 4,
                SWP_NOZORDER);

            g_tpm_state->h_info_dlg = CreateDialog(NULL,
                MAKEINTRESOURCE(DLG_TPM_INFO), hwnd, _tpm_info_dlg_proc);
            SetWindowPos(g_tpm_state->h_info_dlg, NULL,
                rc_tab.left + 2, rc_tab.top + 2,
                rc_tab.right - rc_tab.left - 4, rc_tab.bottom - rc_tab.top - 4,
                SWP_NOZORDER);

            g_tpm_state->h_pcrs_dlg = CreateDialog(NULL,
                MAKEINTRESOURCE(DLG_TPM_PCRS), hwnd, _tpm_info_dlg_proc);
            SetWindowPos(g_tpm_state->h_pcrs_dlg, NULL,
                rc_tab.left + 2, rc_tab.top + 2,
                rc_tab.right - rc_tab.left - 4, rc_tab.bottom - rc_tab.top - 4,
                SWP_NOZORDER);

            g_tpm_state->h_nv_dlg = CreateDialog(NULL,
                MAKEINTRESOURCE(DLG_TPM_NV), hwnd, _tpm_info_dlg_proc);
            SetWindowPos(g_tpm_state->h_nv_dlg, NULL,
                rc_tab.left + 2, rc_tab.top + 2,
                rc_tab.right - rc_tab.left - 4, rc_tab.bottom - rc_tab.top - 4,
                SWP_NOZORDER);

            // Initialize lists
            g_tpm_state->h_list = GetDlgItem(g_tpm_state->h_entries_dlg, IDC_TPM_ENTRY_LIST);
            _tpm_init_list(g_tpm_state->h_list);

            g_tpm_state->h_pcr_list = GetDlgItem(g_tpm_state->h_pcrs_dlg, IDC_TPM_PCR_LIST);
            _tpm_init_pcr_list(g_tpm_state->h_pcr_list);

            g_tpm_state->h_nv_list = GetDlgItem(g_tpm_state->h_nv_dlg, IDC_TPM_NV_LIST);
            _tpm_init_nv_list(g_tpm_state->h_nv_list);

            // Show first tab
            ShowWindow(g_tpm_state->h_entries_dlg, SW_SHOW);
            ShowWindow(g_tpm_state->h_info_dlg, SW_HIDE);
            ShowWindow(g_tpm_state->h_pcrs_dlg, SW_HIDE);
            ShowWindow(g_tpm_state->h_nv_dlg, SW_HIDE);

            // Refresh content (info first to set tpm_version)
            _tpm_refresh_info(hwnd);
            _tpm_refresh_entries(hwnd);

            // Only refresh PCR/NV if TPM is available
            if (g_tpm_state->tpm_version != 0) {
                _tpm_refresh_pcrs(hwnd);
                _tpm_refresh_nv(hwnd);
            }

            // Update tab states based on TPM availability
            _tpm_update_tab_states(hwnd);

            // Set initial button states
            _tpm_update_buttons(hwnd);

            SetForegroundWindow(hwnd);
            return 1L;
        }
        break;

        case WM_CTLCOLOREDIT:
        {
            return _ctl_color(wparam, _cl(COLOR_BTNFACE, LGHT_CLR));
        }
        break;

        case WM_DRAWITEM:
        {
            DRAWITEMSTRUCT *dis = (DRAWITEMSTRUCT*)lparam;
            if (dis->CtlType == ODT_TAB && dis->CtlID == IDT_TPM_TAB) {
                tpm_dlg_state *state = g_tpm_state;
                BOOL is_disabled = FALSE;
                BOOL is_selected = (dis->itemState & ODS_SELECTED) != 0;

                // Check if this tab should be disabled (PCR or NV tab when no TPM)
                if (state && state->tpm_version == 0) {
                    if (dis->itemID == TAB_PCRS || dis->itemID == TAB_NV) {
                        is_disabled = TRUE;
                    }
                }

                // Get tab text
                wchar_t text[64] = {0};
                TCITEM tci = {0};
                tci.mask = TCIF_TEXT;
                tci.pszText = text;
                tci.cchTextMax = countof(text);
                TabCtrl_GetItem(dis->hwndItem, dis->itemID, &tci);

                // Fill background
                HBRUSH hBrush = GetSysColorBrush(COLOR_BTNFACE);
                FillRect(dis->hDC, &dis->rcItem, hBrush);

                // Adjust rect for selected tab
                RECT rc = dis->rcItem;
                if (is_selected) {
                    rc.top -= 2;
                }

                // Set text color (gray for disabled, normal for enabled)
                SetBkMode(dis->hDC, TRANSPARENT);
                if (is_disabled) {
                    SetTextColor(dis->hDC, GetSysColor(COLOR_GRAYTEXT));
                } else {
                    SetTextColor(dis->hDC, GetSysColor(COLOR_BTNTEXT));
                }

                // Draw text centered
                DrawTextW(dis->hDC, text, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

                return TRUE;
            }
            // Let other controls (buttons, etc.) be handled by default/draw_proc
            int rlt = _draw_proc(WM_DRAWITEM, lparam);
            if (rlt != -1) return rlt;
        }
        break;

        default:
        {
            int rlt = _draw_proc(message, lparam);
            if (rlt != -1) return rlt;
        }
    }
    return 0L;
}

void _menu_no_pro(
    HWND     hwnd,
    int      no_shim
)
{
    wchar_t message[1000];
    if (no_shim > 0) {
        _snwprintf(message, countof(message),
            L"Bootloader creation failed: The shim package is not available.\n\n" L"%s\n\nThe shim package is available for project supporters.", 
            no_shim == 2 ? L"For PXE boot, DcsLdr.efi is required, which is part of the shim package." : L"The shim package is required for secure boot compatibility.");
    }
    else if (no_shim == -1) {
        wcscpy_s(message, countof(message), L"Volume layout editing is available for project supporters.");
    }
    else {
        wcscpy_s(message, countof(message), L"TPM and Hardware Key support is available for project supporters.");
    }
    wcscat_s(message, countof(message), L"\nWould you like to open our website to obtain a Supporter Certificate?");

    if ( __msg_w( hwnd, message ) )
    {
        __execute( L"https://diskcryptor.org/go.php?to=dc-get-cert" );
    }
}

void _dlg_tpm(HWND hwnd)
{
    if (!(__config.load_flags & DST_PRO_ENABLED)) {
        _menu_no_pro(hwnd, 0);
        return;
    }

    DialogBoxParam(
        NULL,
        MAKEINTRESOURCE(IDD_DIALOG_TPM),
        hwnd,
        pv(_tpm_dlg_proc),
        0
    );
}
