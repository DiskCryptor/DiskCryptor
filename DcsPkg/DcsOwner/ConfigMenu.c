/** @file
DcsOwner configuration menu

Interactive console menu for editing DcsOwner-managed settings.
Uses the protocol's own GetVariable/SetVariable for all reads and writes.

Copyright (c) 2026. DiskCryptor, David Xanatos

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include "DcsOwner.h"
#include "TpmKill.h"

#include <Library/CommonLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseCryptLib.h>
#include <Protocol/DcsOwnerProto.h>
#include <DcsConfig.h>
#include "common/Xml.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#define CFG_VALUE_COL   24
#define CFG_VALUE_WIDTH 30

typedef struct _CFG_VALUE_NAME {
    INT32    Value;
    CHAR16  *Name;
} CFG_VALUE_NAME;

typedef struct _CFG_MENU_ITEM {
    CONST CHAR16  *VarName;      // EFI variable name (EFI-variable-backed items)
    CONST CHAR8   *ConfigKey;    // DcsProp key (config-file-backed items); NULL otherwise
    CHAR16        *Label;
    CFG_VALUE_NAME *Values;
    INT32          ValueCount;
    INT32          CurrentIndex;
    INT32          OrigIndex;
    BOOLEAN        DirectVar;
    BOOLEAN        Action;       // action item (not a value selector; e.g. clearable key)
    CHAR16         ValueText[24];// value column text for Action/info items (Values == NULL)
} CFG_MENU_ITEM;

STATIC CFG_VALUE_NAME gSecureBootModValues[] = {
    { DCSOWNER_SB_DISABLED,   L"Disabled" },
    { DCSOWNER_SB_REPORT_OFF, L"Report Off" },
    { DCSOWNER_SB_REPORT_ON,  L"Report On" },
};

STATIC CFG_VALUE_NAME gTpmKillValues[] = {
    { TPM_KILL_MODE_DISABLED,     L"No" },
    { TPM_KILL_MODE_FULL,         L"Fully" },
    { TPM_KILL_MODE_CONSERVATIVE, L"Conservative (keep UID EK variable)" },
};

static CFG_VALUE_NAME gBoolValues[] = {
    { 0, L"False" },
    { 1, L"True" }
};

STATIC
INT32
CfgFindValueIndex (
    IN CFG_VALUE_NAME  *Values,
    IN INT32           Count,
    IN INT32           Value
    )
{
    INT32 i;
    for (i = 0; i < Count; i++) {
        if (Values[i].Value == Value)
            return i;
    }
    return -1;
}

STATIC
INT32
CfgGetValue (
    IN CFG_MENU_ITEM  *Item
    )
{
    if (Item->Values != NULL && Item->CurrentIndex >= 0 && Item->CurrentIndex < Item->ValueCount)
        return Item->Values[Item->CurrentIndex].Value;
    return Item->CurrentIndex;
}

STATIC
VOID
CfgDrawItem (
    IN CFG_MENU_ITEM  *Item,
    IN INT32          Row,
    IN BOOLEAN        Selected
    )
{
    INT32  i, len;
    CHAR16 valBuf[CFG_VALUE_WIDTH + 1];

    gST->ConOut->SetCursorPosition(gST->ConOut, 0, Row);

    if (Selected)
        OUT_PRINT(L"%V> ");
    else
        OUT_PRINT(L"  ");

    OUT_PRINT(L"%s", Item->Label);

    gST->ConOut->SetCursorPosition(gST->ConOut, CFG_VALUE_COL, Row);

    {
        CHAR16 *src = NULL;
        if (Item->Values != NULL && Item->CurrentIndex >= 0 && Item->CurrentIndex < Item->ValueCount)
            src = Item->Values[Item->CurrentIndex].Name;      // value selector
        else if (Item->ValueText[0] != L'\0')
            src = Item->ValueText;                            // action/info item text

        len = (src != NULL) ? (INT32)StrLen(src) : 0;
        for (i = 0; i < CFG_VALUE_WIDTH; i++)
            valBuf[i] = (i < len) ? src[i] : L' ';
        valBuf[CFG_VALUE_WIDTH] = L'\0';
    }

    OUT_PRINT(L"< %s >", valBuf);

    if (Selected)
        OUT_PRINT(L"%N");
}

//
// Some DcsOwner settings live in the DcsProp config file (DcsBoot reads them
// from there) rather than in EFI variables. Such menu items carry a ConfigKey;
// they are loaded with ConfigReadInt() and saved together in one file rewrite,
// the way DiskCryptorLib's menu does it. Config file access happens only here,
// at boot-services time. To add another DcsProp parameter, declare a menu item
// with a ConfigKey - no other change is needed.
//
#define DCSOWNER_BOOTMENULOCK_KEY  "BootMenuLock"


/**
  Persist every ConfigKey-backed menu item to the DcsProp file in a single
  rewrite, preserving all other keys untouched. Mirrors DiskCryptorLib's
  DcAuthStoreConfig: write the managed keys (which marks them in the loaded
  copy), then copy every remaining key verbatim.
**/
STATIC
EFI_STATUS
DcsOwnerSaveConfigItems (
    IN CFG_MENU_ITEM  *Items,
    IN INT32           Count
    )
{
    EFI_STATUS  Status;
    CFG_STRING  NewConfig;
    CHAR8      *ConfigContent = NULL;
    CHAR8      *Xml;
    CHAR8       Key[128];
    CHAR8       Val[2048];
    INT32       i;

    if (gConfigFileName == NULL) {
        return EFI_NOT_READY;               // config never loaded - nothing to save into
    }

    Status = CfgStrInit(&NewConfig, 4096);
    if (EFI_ERROR(Status)) {
        return Status;
    }

    // Work on a copy of the current file so CfgMarkUpdated can flag our keys.
    if (gConfigBuffer != NULL) {
        ConfigContent = MEM_ALLOC(gConfigBufferSize + 1);
        if (ConfigContent != NULL) {
            CopyMem(ConfigContent, gConfigBuffer, gConfigBufferSize);
            ConfigContent[gConfigBufferSize] = '\0';
        }
    }

    Status = CfgWriteHeader(&NewConfig);
    if (EFI_ERROR(Status)) goto cleanup;

    // Write each managed key (also marks it in ConfigContent so it isn't copied twice).
    for (i = 0; i < Count; i++) {
        if (Items[i].ConfigKey != NULL) {
            Status = CfgWriteInteger(&NewConfig, ConfigContent, Items[i].ConfigKey, CfgGetValue(&Items[i]));
            if (EFI_ERROR(Status)) goto cleanup;
        }
    }

    // Copy every remaining (unmarked) key verbatim.
    if (ConfigContent != NULL) {
        Xml = ConfigContent;
        while (Xml != NULL && (Xml = XmlFindElement(Xml, "config")) != NULL) {
            XmlGetAttributeText(Xml, "key", Key, sizeof(Key));
            XmlGetNodeText(Xml, Val, sizeof(Val));

            Status = CfgStrAppend(&NewConfig, "\n\t\t<config key=\"");
            if (EFI_ERROR(Status)) goto cleanup;
            Status = CfgStrAppend(&NewConfig, Key);
            if (EFI_ERROR(Status)) goto cleanup;
            Status = CfgStrAppend(&NewConfig, "\">");
            if (EFI_ERROR(Status)) goto cleanup;
            Status = CfgStrAppend(&NewConfig, Val);
            if (EFI_ERROR(Status)) goto cleanup;
            Status = CfgStrAppend(&NewConfig, "</config>");
            if (EFI_ERROR(Status)) goto cleanup;

            Xml++;
        }
    }

    Status = CfgWriteFooter(&NewConfig);
    if (EFI_ERROR(Status)) goto cleanup;

    Status = ConfigSave(&NewConfig);

cleanup:
    if (ConfigContent != NULL) {
        MEM_FREE(ConfigContent);
    }
    CfgStrFree(&NewConfig);
    return Status;
}

//
// User Public Key (MajorPrivacy) - stored raw in the DcsOwner variable store.
// The menu shows the SHA-256 of the raw payload and lets the operator clear it.
//
#define DCSOWNER_USERKEY_NAME     L"UserPubKey"       // gVarMap Name (protocol clears BS+RT+runtime)
#define DCSOWNER_USERKEY_STORE    L"UserPubKey_BS"    // committed payload

/**
  Read the committed User Public Key and SHA-256 the raw payload.
  @retval TRUE   a key is present; Hash[0..31] filled.
  @retval FALSE  no key set.
**/
STATIC
BOOLEAN
DcsOwnerUserKeyHash (
    OUT UINT8  Hash[32]
    )
{
    UINTN  Size = 0;
    VOID  *Data = CfgGetBytes(DCSOWNER_USERKEY_STORE, &Size);

    if (Data == NULL || Size == 0) {
        if (Data != NULL) MEM_FREE(Data);
        return FALSE;
    }
    Sha256HashAll(Data, Size, Hash);
    MEM_FREE(Data);
    return TRUE;
}

/**
  Draw the detail line under the menu: the full SHA-256 when the User Public Key
  item is selected, or a cleared line otherwise.
**/
STATIC
VOID
DcsOwnerDrawKeyDetail (
    IN INT32    Row,
    IN BOOLEAN  Show,
    IN BOOLEAN  Present,
    IN UINT8    *Hash
    )
{
    INT32 i;

    gST->ConOut->SetCursorPosition(gST->ConOut, 0, Row);
    for (i = 0; i < 78; i++) OUT_PRINT(L" ");        // clear the line
    gST->ConOut->SetCursorPosition(gST->ConOut, 0, Row);

    if (!Show) return;

    if (!Present) {
        OUT_PRINT(L"  SHA-256: (none)");
        return;
    }
    // Prefix kept short so "  SHA-256: " (11) + 64 hex = 75 fits an 80-col line.
    OUT_PRINT(L"  SHA-256: ");
    for (i = 0; i < 32; i++) OUT_PRINT(L"%02x", Hash[i]);
}

EFI_STATUS
EFIAPI
DcsOwnerShowConfigMenu (
    IN  EFI_DCSOWNER_PROTOCOL  *This
    )
{
    EFI_INPUT_KEY  key;
    INT32          selected = 0;
    INT32          prev;
    INT32          baseRow;
    INT32          i;
    INT32          count = 0;
    INT32          detailRow;
    INT32          keyIdx = -1;
    BOOLEAN        keyPresent;
    UINT8          keyHash[32];
    CFG_MENU_ITEM  items[8];

    ZeroMem(items, sizeof(items));
    keyPresent = DcsOwnerUserKeyHash(keyHash);

    // Boot Menu Lock (stored in DcsProp, not an EFI variable)
    {
        INT32 lockVal = ConfigReadInt(DCSOWNER_BOOTMENULOCK_KEY, 1);

        items[count].ConfigKey    = DCSOWNER_BOOTMENULOCK_KEY;   // DcsProp-backed
        items[count].Label        = L"Boot Menu Lock";
        items[count].Values       = gBoolValues;
        items[count].ValueCount   = ARRAY_SIZE(gBoolValues);
        items[count].DirectVar    = FALSE;
        items[count].CurrentIndex = CfgFindValueIndex(gBoolValues, ARRAY_SIZE(gBoolValues), lockVal);
        if (items[count].CurrentIndex < 0) items[count].CurrentIndex = 0;
        count++;
    }

    // Block TPM after Boot (EFI variable or DcsProp, per DCSOWNER_VAR_TPMKILL)
    {
        UINT8 tpmMode = DcsOwnerGetTpmKillMode();

        items[count].Label        = L"Block TPM after Boot";
        items[count].Values       = gTpmKillValues;
        items[count].ValueCount   = ARRAY_SIZE(gTpmKillValues);
        items[count].CurrentIndex = CfgFindValueIndex(gTpmKillValues, items[count].ValueCount, tpmMode);
        if (gUseConfigFile) {
            items[count].ConfigKey = DCSOWNER_CFG_TPMKILL;
        } else {
            items[count].VarName   = DCSOWNER_VAR_TPMKILL;
            items[count].DirectVar = TRUE;
        }
        if (items[count].CurrentIndex < 0) items[count].CurrentIndex = 0;
        count++;
    }

    // Secure Boot Override
    {
        UINT8 sbMod = DCSOWNER_SB_DISABLED;
        UINTN Size = sizeof(sbMod);
        if (EFI_ERROR(This->GetVariable(This, DCSOWNER_VAR_SB, &Size, &sbMod, NULL))) {
            sbMod = DCSOWNER_SB_DISABLED;
        }

        items[count].VarName      = DCSOWNER_VAR_SB;
        items[count].Label        = L"Secure Boot Override";
        items[count].Values       = gSecureBootModValues;
        items[count].ValueCount   = ARRAY_SIZE(gSecureBootModValues);
        items[count].CurrentIndex = CfgFindValueIndex(gSecureBootModValues, items[count].ValueCount, sbMod);
        items[count].DirectVar    = FALSE;
        if (items[count].CurrentIndex < 0) items[count].CurrentIndex = 0;
        count++;
    }

    // Suspend Isoaltor
    {
        UINT8 Value = 0;
        UINTN Size = sizeof(Value);
        if (EFI_ERROR(This->GetVariable(This, L"SuspendIsolator", &Size, &Value, NULL))) {
            Value = 0;
        }

        items[count].VarName      = L"SuspendIsolator";
        items[count].Label        = L"Suspend Isolator";
        items[count].Values       = gBoolValues;
        items[count].ValueCount   = ARRAY_SIZE(gBoolValues);
        items[count].DirectVar    = FALSE;
        items[count].CurrentIndex = CfgFindValueIndex(gBoolValues, ARRAY_SIZE(gBoolValues), Value);
        if (items[count].CurrentIndex < 0) items[count].CurrentIndex = 0;
        count++;
    }

    // User Public Key (raw MajorPrivacy key) - view SHA-256 / clear (Del)
    {
        items[count].Label     = L"User Public Key";
        items[count].VarName   = DCSOWNER_USERKEY_NAME;   // clear target (via protocol)
        items[count].Action    = TRUE;                    // not a value selector
        StrCpyS(items[count].ValueText, ARRAY_SIZE(items[count].ValueText),
                keyPresent ? L"Present (Del: clear)" : L"None");
        keyIdx = count;
        count++;
    }

    // Debug Output (EFI variable or DcsProp, per DCSOWNER_VAR_DEBUG)
    {
        UINT8 dbgVal = (UINT8)(DcsOwnerGetVerboseDebug() ? 1 : 0);

        items[count].Label        = L"Debug Output";
        items[count].Values       = gBoolValues;
        items[count].ValueCount   = ARRAY_SIZE(gBoolValues);
        items[count].CurrentIndex = CfgFindValueIndex(gBoolValues, ARRAY_SIZE(gBoolValues), dbgVal);
        if (gUseConfigFile) {
            items[count].ConfigKey = DCSOWNER_CFG_DEBUG;
        } else {
            items[count].VarName   = DCSOWNER_VAR_DEBUG;
            items[count].DirectVar = TRUE;
        }
        if (items[count].CurrentIndex < 0) items[count].CurrentIndex = 0;
        count++;
    }

    // Snapshot original indices for dirty tracking
    for (i = 0; i < count; i++)
        items[i].OrigIndex = items[i].CurrentIndex;

    // --- Initial draw ---
    gST->ConOut->ClearScreen(gST->ConOut);
    OUT_PRINT(L"--- DcsOwner Configuration ---\r\n");

    {
        UINTN col, row;
        gST->ConOut->QueryMode(gST->ConOut, gST->ConOut->Mode->Mode, &col, &row);
        baseRow = (INT32)gST->ConOut->Mode->CursorRow;
    }

    for (i = 0; i < count; i++) {
        CfgDrawItem(&items[i], baseRow + i, (i == selected));
        OUT_PRINT(L"\r\n");
    }

    OUT_PRINT(L"------------------------------\r\n");
    OUT_PRINT(L"Up/Down:select  Left/Right:change  Del:clear  Enter:apply  Esc:cancel\r\n");

    detailRow = baseRow + count + 2;
    DcsOwnerDrawKeyDetail(detailRow, (selected == keyIdx), keyPresent, keyHash);

    gST->ConOut->EnableCursor(gST->ConOut, FALSE);

    // --- Input loop ---
    for (;;) {
        EFI_STATUS  Status;
        UINTN       EventIndex;

        Status = gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &EventIndex);
        if (EFI_ERROR(Status))
            continue;

        Status = gST->ConIn->ReadKeyStroke(gST->ConIn, &key);
        if (EFI_ERROR(Status))
            continue;

        if (key.ScanCode == SCAN_ESC) {
            gST->ConOut->EnableCursor(gST->ConOut, TRUE);
            gST->ConOut->ClearScreen(gST->ConOut);
            return EFI_ABORTED;
        }

        if (key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
            for (i = 0; i < count; i++) {
                if (items[i].VarName != NULL && !items[i].Action &&
                    items[i].CurrentIndex != items[i].OrigIndex) {
                    UINT8 val = (UINT8)CfgGetValue(&items[i]);
                    if (items[i].DirectVar) {
                        gST->RuntimeServices->SetVariable(
                            (CHAR16 *)items[i].VarName, &gEfiDcsOwnerGuid,
                            EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
                            sizeof(val), &val);
                    } else {
                        This->SetVariable(This, items[i].VarName, sizeof(val), &val);
                    }
                }
            }

            // DcsProp-backed items are persisted together in one file rewrite.
            {
                BOOLEAN cfgDirty = FALSE;
                for (i = 0; i < count; i++) {
                    if (items[i].ConfigKey != NULL &&
                        items[i].CurrentIndex != items[i].OrigIndex) {
                        cfgDirty = TRUE;
                        break;
                    }
                }
                if (cfgDirty) {
                    DcsOwnerSaveConfigItems(items, count);
                }
            }

            gST->ConOut->EnableCursor(gST->ConOut, TRUE);
            gST->ConOut->ClearScreen(gST->ConOut);
            OUT_PRINT(L"DcsOwner: configuration saved.\n");
            return EFI_SUCCESS;
        }

        if (key.ScanCode == SCAN_UP) {
            if (selected > 0) {
                prev = selected;
                selected--;
                CfgDrawItem(&items[prev], baseRow + prev, FALSE);
                CfgDrawItem(&items[selected], baseRow + selected, TRUE);
                DcsOwnerDrawKeyDetail(detailRow, (selected == keyIdx), keyPresent, keyHash);
            }
        }

        if (key.ScanCode == SCAN_DOWN) {
            if (selected < count - 1) {
                prev = selected;
                selected++;
                CfgDrawItem(&items[prev], baseRow + prev, FALSE);
                CfgDrawItem(&items[selected], baseRow + selected, TRUE);
                DcsOwnerDrawKeyDetail(detailRow, (selected == keyIdx), keyPresent, keyHash);
            }
        }

        if (key.ScanCode == SCAN_RIGHT) {
            if (items[selected].Values != NULL &&
                items[selected].CurrentIndex < items[selected].ValueCount - 1) {
                items[selected].CurrentIndex++;
                CfgDrawItem(&items[selected], baseRow + selected, TRUE);
            }
        }

        if (key.ScanCode == SCAN_LEFT) {
            if (items[selected].Values != NULL &&
                items[selected].CurrentIndex > 0) {
                items[selected].CurrentIndex--;
                CfgDrawItem(&items[selected], baseRow + selected, TRUE);
            }
        }

        // Delete clears the selected action item (currently the User Public Key).
        if (key.ScanCode == SCAN_DELETE &&
            items[selected].Action && items[selected].VarName != NULL && keyPresent) {

            gST->ConOut->SetCursorPosition(gST->ConOut, 0, detailRow);
            OUT_PRINT(L"  Clear the User Public Key? (y/n) ");
            for (;;) {
                UINTN EvIdx;
                gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &EvIdx);
                if (EFI_ERROR(gST->ConIn->ReadKeyStroke(gST->ConIn, &key)))
                    continue;
                if (key.UnicodeChar == L'y' || key.UnicodeChar == L'Y' ||
                    key.UnicodeChar == L'n' || key.UnicodeChar == L'N' ||
                    key.ScanCode == SCAN_ESC)
                    break;
            }

            if (key.UnicodeChar == L'y' || key.UnicodeChar == L'Y') {
                // Protocol clears the committed store, the RT mirror and runtime state.
                This->SetVariable(This, items[selected].VarName, 0, NULL);
                keyPresent = FALSE;
                StrCpyS(items[selected].ValueText, ARRAY_SIZE(items[selected].ValueText), L"None");
                CfgDrawItem(&items[selected], baseRow + selected, TRUE);
            }
            DcsOwnerDrawKeyDetail(detailRow, (selected == keyIdx), keyPresent, keyHash);
        }
    }
}
