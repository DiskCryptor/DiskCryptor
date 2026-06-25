/** @file
DiskCryptor configuration menu

Copyright (c) 2026. DiskCryptor, David Xanatos

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Uefi.h>
#include <Library/CommonLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include <DcsConfig.h>
#include "DcsConfigMenu.h"
#include "DcsDiskCryptor.h"
#include "common/Xml.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#define CFG_VALUE_COL   22  // column where "< value >" starts
#define CFG_VALUE_WIDTH 45  // fixed width for the value text between < >

// Menu item IDs - used to identify items regardless of their position in the array
typedef enum {
	CFG_ID_NONE = 0,
	CFG_ID_KEYBOARD_LAYOUT,
	CFG_ID_HEADER_KDF,
	CFG_ID_KEYFILE_MIXER,
	CFG_ID_TPM_MODE,
	CFG_ID_TPM_STORAGE,
	CFG_ID_TPM_PCR_MASK,
	CFG_ID_HW_CRYPTO,
	CFG_ID_DEBUG_OUTPUT,
	CFG_ID_BOOT_MODE,
	CFG_ID_BLOCK_UNENCRYPTED,
	CFG_ID_HANDOFF_MODE,
	CFG_ID_SECURE_BOOT,
} CFG_MENU_ID;

typedef struct _CFG_VALUE_NAME {
	INT32    Value;
	CHAR16  *Name;
} CFG_VALUE_NAME;

// Function pointer types for custom picker items
typedef EFI_STATUS (*CFG_PICKER_FUNC)(INT32 *Value);      // Custom picker function
typedef VOID (*CFG_DISPLAY_FUNC)(INT32 Value, CHAR16 *Buffer, INT32 BufLen); // Custom display function

typedef struct _CFG_MENU_ITEM {
	CFG_MENU_ID       Id;           // Unique identifier for this menu item
	CHAR16           *Label;
	CFG_VALUE_NAME   *Values;       // Array of value-name pairs (NULL for numeric Min/Max or custom)
	INT32             ValueCount;   // Number of entries in Values array
	INT32             CurrentIndex; // Current index into Values array (or raw value for custom)
	INT32             Min;          // For numeric-only items (when Values is NULL)
	INT32             Max;          // For numeric-only items (when Values is NULL)
	CFG_PICKER_FUNC   PickerFunc;   // Custom picker function (NULL for standard behavior)
	CFG_DISPLAY_FUNC  DisplayFunc;  // Custom display function (NULL for standard behavior)
} CFG_MENU_ITEM;

static CFG_VALUE_NAME gKbLayoutValues[] = {
	{ 0, L"QWERTY" },
	{ 1, L"QWERTZ" }
};

static CFG_VALUE_NAME gBoolValues[] = {
	{ 0, L"False" },
	{ 1, L"True" }
};

static CFG_VALUE_NAME gKdfValues[] = {
	{ -3, L"Try all KDF's    >>> Very Slow <<<" },
	{ -2, L"Standard Pkcs5.2 & Default Argon2id" },
	{  0, L"Pkcs5.2 SHA-512 (0 - Legacy)" },
	{  1, L"Argon2id (1 - Minimum) [64 MiB]" },
	{  2, L"Argon2id (2 - Low) [128 MiB]" },
	{  3, L"Argon2id (3 - Moderate) [192 MiB]" },
	{  4, L"Argon2id (4 - Standard) [256 MiB]" },
	{  5, L"Argon2id (5 - Recommended) [384 MiB]" },
	{  6, L"Argon2id (6 - Enhanced) [512 MiB]" },
	{  7, L"Argon2id (7 - Hardened) [768 MiB]" },
	{  8, L"Argon2id (8 - High Cost) [1024 MiB]" },
	{  9, L"Argon2id (9 - Very High Cost) [1536 MiB]" },
	{ 10, L"Argon2id (10 - Extreme Cost) [2048 MiB]" },
};

static CFG_VALUE_NAME gKfMixerValues[] = {
	{ 0, L"Additive (Legacy)" },
	{ 1, L"Canonical (Recommended)" },
};

static CFG_VALUE_NAME gTpmModeValues[] = {
	{ 0, L"Unattended Unlock (PCR only)" },
	{ 1, L"Require Password (mix after unseal)" },
	{ 2, L"Require PIN (TPM-validated)" },
	{ 3, L"Require Password + PIN (both)" },
};

static CFG_VALUE_NAME gTpmStorageValues[] = {
	{ 0, L"Auto Selection" },
	{ 1, L"Sealed File" },
	{ 2, L"NV Storage" },
};

static CFG_VALUE_NAME gBootModeValues[] = {
	{ 1, L"Boot Disk (default)" },
	{ 2, L"First Disk" },
	{ 4, L"First Partition with Password" },
	{ 5, L"Partition by Disk ID" },
	{ 6, L"Boot Menu" },
};

#ifdef _M_ARM64
static CFG_VALUE_NAME gHandoffModeValues[] = {
	{ 0, L"Default" },
	{ 2, L"Full" },
	{ 3, L"Keys Only" },
};
#else
static CFG_VALUE_NAME gHandoffModeValues[] = {
	{ 0, L"Default" },
	{ 1, L"Legacy" },
	{ 2, L"Full" },
	{ 3, L"Keys Only" },
};
#endif

// TPM PCR Mask display function - shows value as 0xHHH
static VOID
CfgDisplayPcrMask(
	INT32   Value,
	CHAR16 *Buffer,
	INT32   BufLen
)
{
	if (Buffer == NULL || BufLen < 6)
		return;
	// Format as 0xHHH (3 hex digits)
	Buffer[0] = L'0';
	Buffer[1] = L'x';
	Buffer[2] = L"0123456789ABCDEF"[(Value >> 8) & 0xF];
	Buffer[3] = L"0123456789ABCDEF"[(Value >> 4) & 0xF];
	Buffer[4] = L"0123456789ABCDEF"[Value & 0xF];
	Buffer[5] = L'\0';
}

// TPM PCR Mask picker wrapper - calls DcTpmAskPcrMask
static EFI_STATUS
CfgPickerPcrMask(
	INT32 *Value
)
{
	UINT32 mask = (UINT32)*Value;
	EFI_STATUS status;

	gST->ConOut->ClearScreen(gST->ConOut);

	status = DcTpmAskPcrMask(&mask, mask);
	if (!EFI_ERROR(status)) {
		*Value = (INT32)mask;
	}
	return status;
}

// Find index in Values array for a given value, returns -1 if not found
static INT32
CfgFindValueIndex(
	CFG_VALUE_NAME *Values,
	INT32           ValueCount,
	INT32           Value
)
{
	INT32 i;
	for (i = 0; i < ValueCount; i++) {
		if (Values[i].Value == Value)
			return i;
	}
	return -1;
}

// Get the actual value from current index
static INT32
CfgGetValue(
	CFG_MENU_ITEM *Item
)
{
	if (Item->Values != NULL && Item->CurrentIndex >= 0 && Item->CurrentIndex < Item->ValueCount)
		return Item->Values[Item->CurrentIndex].Value;
	return Item->CurrentIndex; // For numeric-only items, CurrentIndex holds the value
}

// Find a menu item by its ID, returns NULL if not found
static CFG_MENU_ITEM*
CfgFindItemById(
	CFG_MENU_ITEM *Items,
	INT32          Count,
	CFG_MENU_ID    Id
)
{
	INT32 i;
	for (i = 0; i < Count; i++) {
		if (Items[i].Id == Id)
			return &Items[i];
	}
	return NULL;
}

// Draw a single menu item line at the given screen row.
static VOID
CfgMenuDrawItem(
	CFG_MENU_ITEM *Item,
	INT32          Row,
	BOOLEAN        Selected
)
{
	INT32 i;
	CHAR16 valBuf[CFG_VALUE_WIDTH + 1];
	INT32 len;

	gST->ConOut->SetCursorPosition(gST->ConOut, 0, Row);

	if (Selected)
		OUT_PRINT(L"%V> ");
	else
		OUT_PRINT(L"  ");

	OUT_PRINT(L"%-20s", Item->Label);

	// Format value into fixed-width buffer, left-justified, space-padded
	if (Item->DisplayFunc != NULL) {
		// Use custom display function
		Item->DisplayFunc(Item->CurrentIndex, valBuf, CFG_VALUE_WIDTH + 1);
		// Ensure padding to full width
		len = (INT32)StrLen(valBuf);
		for (i = len; i < CFG_VALUE_WIDTH; i++)
			valBuf[i] = L' ';
		valBuf[CFG_VALUE_WIDTH] = L'\0';
	} else if (Item->Values != NULL && Item->CurrentIndex >= 0 && Item->CurrentIndex < Item->ValueCount) {
		len = (INT32)StrLen(Item->Values[Item->CurrentIndex].Name);
		for (i = 0; i < CFG_VALUE_WIDTH; i++)
			valBuf[i] = (i < len) ? Item->Values[Item->CurrentIndex].Name[i] : L' ';
		valBuf[CFG_VALUE_WIDTH] = L'\0';
	} else {
		// Format the integer manually into the buffer (for numeric-only items)
		CHAR16 numBuf[12];
		INT32 val = CfgGetValue(Item);
		INT32 pos = 0;
		BOOLEAN neg = FALSE;
		if (val < 0) {
			neg = TRUE;
			val = -val;
		}
		if (val == 0) {
			numBuf[pos++] = L'0';
		} else {
			// Build digits in reverse
			CHAR16 tmp[12];
			INT32 tpos = 0;
			while (val > 0) {
				tmp[tpos++] = L'0' + (CHAR16)(val % 10);
				val /= 10;
			}
			// Reverse into numBuf
			if (neg)
				numBuf[pos++] = L'-';
			while (tpos > 0)
				numBuf[pos++] = tmp[--tpos];
		}
		len = pos;
		for (i = 0; i < CFG_VALUE_WIDTH; i++)
			valBuf[i] = (i < len) ? numBuf[i] : L' ';
		valBuf[CFG_VALUE_WIDTH] = L'\0';
	}

	OUT_PRINT(L"< %s >", valBuf);

	if (Selected)
		OUT_PRINT(L"%N");
}

// Redraw only the value portion of a single item.
static VOID
CfgMenuDrawValue(
	CFG_MENU_ITEM *Item,
	INT32          Row,
	BOOLEAN        Selected
)
{
	// Reposition to value column and redraw from there
	// Redrawing the full line is simplest to keep highlight consistent
	CfgMenuDrawItem(Item, Row, Selected);
}

VOID
DcsShowHelp(
	VOID
)
{
	gST->ConOut->ClearScreen(gST->ConOut);
	OUT_PRINT(L"=== DiskCryptor Boot Loader Help ===\r\n");
	OUT_PRINT(L"\r\n");
	OUT_PRINT(L"Password Entry:                        Editing:\r\n");
	OUT_PRINT(L"  Enter      Submit password             Left/Right  Move cursor\r\n");
	OUT_PRINT(L"  Esc        Cancel / Exit               Home/End    Jump to start/end\r\n");
	OUT_PRINT(L"  Backspace  Delete previous char        Delete      Delete at cursor\r\n");
	OUT_PRINT(L"                                         Insert      Insert space\r\n");
	OUT_PRINT(L"\r\n");
	OUT_PRINT(L"Function Keys:\r\n");
	OUT_PRINT(L"  F1   Help                              F6   Configuration menu\r\n");
	OUT_PRINT(L"                                         F7   Toggle keyfile\r\n");
	OUT_PRINT(L"  F3   Force boot (skip decryption)      F8   Toggle hardware key\r\n");
	OUT_PRINT(L"  F4   Add password                                                   \r\n");
	OUT_PRINT(L"  F5   Toggle password visibility        F10  Save secret to TPM\r\n");
	OUT_PRINT(L"\r\n");
	OUT_PRINT(L"====================================\r\n");
	OUT_PRINT(L"Press any key to return...\r\n");

	GetKey();
	FlushInputDelay(100000);
	gST->ConOut->ClearScreen(gST->ConOut);
}

BOOLEAN
DcsConfigMenuShow(
	VOID
)
{
	EFI_INPUT_KEY key;
	INT32         selected = 0;
	INT32         prev;
	INT32         baseRow;
	INT32         i;
	INT32         count = 0;
	CFG_MENU_ITEM items[12];
	//UINT8         sbState;

	// Zero-initialize all items to ensure PickerFunc/DisplayFunc are NULL
	ZeroMem(items, sizeof(items));

	// Keyboard Layout
	items[count].Id           = CFG_ID_KEYBOARD_LAYOUT;
	items[count].Label        = L"Keyboard Layout";
	items[count].Values       = gKbLayoutValues;
	items[count].ValueCount   = ARRAY_SIZE(gKbLayoutValues);
	items[count].CurrentIndex = CfgFindValueIndex(gKbLayoutValues, items[count].ValueCount, gKeyboardLayout);
	if (items[count].CurrentIndex < 0) items[count].CurrentIndex = 0;
	items[count].Min          = 0;
	items[count].Max          = 0;
	count++;

	// Header KDF
	items[count].Id           = CFG_ID_HEADER_KDF;
	items[count].Label        = L"Header Kdf";
	items[count].Values       = gKdfValues;
	items[count].ValueCount   = ARRAY_SIZE(gKdfValues);
	items[count].CurrentIndex = CfgFindValueIndex(gKdfValues, items[count].ValueCount, gDCryptHeaderKdf);
	if (items[count].CurrentIndex < 0) items[count].CurrentIndex = 0;
	items[count].Min          = 0;
	items[count].Max          = 0;
	count++;

	// Keyfile Mixer
	items[count].Id           = CFG_ID_KEYFILE_MIXER;
	items[count].Label        = L"Keyfile Mixer";
	items[count].Values       = gKfMixerValues;
	items[count].ValueCount   = ARRAY_SIZE(gKfMixerValues);
	items[count].CurrentIndex = CfgFindValueIndex(gKfMixerValues, items[count].ValueCount, gDCryptKfMixer);
	if (items[count].CurrentIndex < 0) items[count].CurrentIndex = 0;
	items[count].Min          = 0;
	items[count].Max          = 0;
	count++;

	// TPM Mode
	items[count].Id           = CFG_ID_TPM_MODE;
	items[count].Label        = L"TPM Mode";
	items[count].Values       = gTpmModeValues;
	items[count].ValueCount   = ARRAY_SIZE(gTpmModeValues);
	items[count].CurrentIndex = CfgFindValueIndex(gTpmModeValues, items[count].ValueCount, gDCryptTpmMode);
	if (items[count].CurrentIndex < 0) items[count].CurrentIndex = 0;
	items[count].Min          = 0;
	items[count].Max          = 0;
	count++;

	// TPM Storage
	items[count].Id           = CFG_ID_TPM_STORAGE;
	items[count].Label        = L"TPM Storage";
	items[count].Values       = gTpmStorageValues;
	items[count].ValueCount   = ARRAY_SIZE(gTpmStorageValues);
	items[count].CurrentIndex = CfgFindValueIndex(gTpmStorageValues, items[count].ValueCount, gDCryptTpmStorage);
	if (items[count].CurrentIndex < 0) items[count].CurrentIndex = 0;
	items[count].Min          = 0;
	items[count].Max          = 0;
	count++;

	// TPM PCR Mask (custom picker)
	items[count].Id           = CFG_ID_TPM_PCR_MASK;
	items[count].Label        = L"TPM PCR Mask";
	items[count].Values       = NULL;
	items[count].ValueCount   = 0;
	items[count].CurrentIndex = gDCryptTpmPcrMask;  // Raw value, not index
	items[count].Min          = 0;
	items[count].Max          = 0;
	items[count].PickerFunc   = CfgPickerPcrMask;
	items[count].DisplayFunc  = CfgDisplayPcrMask;
	count++;

	// Boot Mode
	items[count].Id           = CFG_ID_BOOT_MODE;
	items[count].Label        = L"Boot Mode";
	items[count].Values       = gBootModeValues;
	items[count].ValueCount   = ARRAY_SIZE(gBootModeValues);
	items[count].CurrentIndex = CfgFindValueIndex(gBootModeValues, items[count].ValueCount, gDCryptBootMode);
	if (items[count].CurrentIndex < 0) items[count].CurrentIndex = 0;
	items[count].Min          = 0;
	items[count].Max          = 0;
	count++;

	// Block Unencrypted Volumes
	items[count].Id           = CFG_ID_BLOCK_UNENCRYPTED;
	items[count].Label        = L"Block Unencrypted";
	items[count].Values       = gBoolValues;
	items[count].ValueCount   = ARRAY_SIZE(gBoolValues);
	items[count].CurrentIndex = CfgFindValueIndex(gBoolValues, items[count].ValueCount, gBlockUnencryptedVolumes ? 1 : 0);
	if (items[count].CurrentIndex < 0) items[count].CurrentIndex = 0;
	items[count].Min          = 0;
	items[count].Max          = 0;
	count++;

	// Handoff Mode
	items[count].Id           = CFG_ID_HANDOFF_MODE;
	items[count].Label        = L"Handoff Mode";
	items[count].Values       = gHandoffModeValues;
	items[count].ValueCount   = ARRAY_SIZE(gHandoffModeValues);
	items[count].CurrentIndex = CfgFindValueIndex(gHandoffModeValues, items[count].ValueCount, gDCryptHandoffMode);
	if (items[count].CurrentIndex < 0) items[count].CurrentIndex = 0;
	items[count].Min          = 0;
	items[count].Max          = 0;
	count++;

	// Secure Boot (conditionally added)
	//if (!EFI_ERROR(DcsLdrGetMokSBState(&sbState))) {
	//	items[count].Id           = CFG_ID_SECURE_BOOT;
	//	items[count].Label        = L"Secure Boot";
	//	items[count].Values       = gBoolValues;
	//	items[count].ValueCount   = ARRAY_SIZE(gBoolValues);
	//	items[count].CurrentIndex = CfgFindValueIndex(gBoolValues, items[count].ValueCount, sbState ? 0 : 1);
	//	if (items[count].CurrentIndex < 0) items[count].CurrentIndex = 0;
	//	items[count].Min          = 0;
	//	items[count].Max          = 0;
	//	count++;
	//}

	// Hardware Crypto
	items[count].Id           = CFG_ID_HW_CRYPTO;
	items[count].Label        = L"Hardware Crypto";
	items[count].Values       = gBoolValues;
	items[count].ValueCount   = ARRAY_SIZE(gBoolValues);
	items[count].CurrentIndex = CfgFindValueIndex(gBoolValues, items[count].ValueCount, gDCryptHwCrypto ? 1 : 0);
	if (items[count].CurrentIndex < 0) items[count].CurrentIndex = 0;
	items[count].Min          = 0;
	items[count].Max          = 0;
	count++;

	// Debug Mode
	items[count].Id           = CFG_ID_DEBUG_OUTPUT;
	items[count].Label        = L"Debug Output";
	items[count].Values       = gBoolValues;
	items[count].ValueCount   = ARRAY_SIZE(gBoolValues);
	items[count].CurrentIndex = CfgFindValueIndex(gBoolValues, items[count].ValueCount, gConfigDebug ? 1 : 0);
	if (items[count].CurrentIndex < 0) items[count].CurrentIndex = 0;
	items[count].Min          = 0;
	items[count].Max          = 0;
	count++;

	// --- Initial full draw ---
	gST->ConOut->ClearScreen(gST->ConOut);
	OUT_PRINT(L"--- Configuration ---\r\n");

	baseRow = gST->ConOut->Mode->CursorRow;

	for (i = 0; i < count; i++) {
		CfgMenuDrawItem(&items[i], baseRow + i, (i == selected));
		OUT_PRINT(L"\r\n");
	}

	OUT_PRINT(L"---------------------\r\n");
	OUT_PRINT(L"Up/Down:select  Left/Right:change  Enter:apply  Esc:cancel\r\n");

	gST->ConOut->EnableCursor(gST->ConOut, FALSE);

	// --- Input loop: only redraw what changed ---
	for (;;) {
		key = GetKey();
		FlushInputDelay(100000);

		if (key.ScanCode == SCAN_ESC) {
			gST->ConOut->EnableCursor(gST->ConOut, TRUE);
			gST->ConOut->ClearScreen(gST->ConOut);
			return FALSE;
		}

		if (key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
			// Apply values by ID - order doesn't matter, only apply if item exists
			CFG_MENU_ITEM *item;
			if ((item = CfgFindItemById(items, count, CFG_ID_KEYBOARD_LAYOUT)) != NULL)
				gKeyboardLayout = CfgGetValue(item);
			if ((item = CfgFindItemById(items, count, CFG_ID_HEADER_KDF)) != NULL)
				gDCryptHeaderKdf = CfgGetValue(item);
			if ((item = CfgFindItemById(items, count, CFG_ID_KEYFILE_MIXER)) != NULL)
				gDCryptKfMixer = CfgGetValue(item);
			if ((item = CfgFindItemById(items, count, CFG_ID_TPM_MODE)) != NULL)
				gDCryptTpmMode = CfgGetValue(item);
			if ((item = CfgFindItemById(items, count, CFG_ID_TPM_STORAGE)) != NULL)
				gDCryptTpmStorage = CfgGetValue(item);
			if ((item = CfgFindItemById(items, count, CFG_ID_TPM_PCR_MASK)) != NULL)
				gDCryptTpmPcrMask = item->CurrentIndex;  // Raw value stored in CurrentIndex
			if ((item = CfgFindItemById(items, count, CFG_ID_HW_CRYPTO)) != NULL)
				gDCryptHwCrypto = CfgGetValue(item);
			if ((item = CfgFindItemById(items, count, CFG_ID_DEBUG_OUTPUT)) != NULL)
				gConfigDebug = CfgGetValue(item) ? TRUE : FALSE;
			if ((item = CfgFindItemById(items, count, CFG_ID_BOOT_MODE)) != NULL)
				gDCryptBootMode = (UINT8)CfgGetValue(item);
			if ((item = CfgFindItemById(items, count, CFG_ID_BLOCK_UNENCRYPTED)) != NULL)
				gBlockUnencryptedVolumes = (UINT8)CfgGetValue(item);
			if ((item = CfgFindItemById(items, count, CFG_ID_HANDOFF_MODE)) != NULL)
				gDCryptHandoffMode = (UINT8)CfgGetValue(item);
			//if ((item = CfgFindItemById(items, count, CFG_ID_SECURE_BOOT)) != NULL)
			//	DcsLdrSetMokSBState(CfgGetValue(item) ? 0 : 1);

			gST->ConOut->EnableCursor(gST->ConOut, TRUE);
			gST->ConOut->ClearScreen(gST->ConOut);

			if (gDcsTpm != NULL && gDCryptTpmVersion > 0) {
				OUT_PRINT(L"\n%HWarning: Saving the config file will modify PCR8 used for TPM sealing.%N\n");
			}
			if (AskYesNo(L"\n%HSave changes permanently to config file?%N [y/N]: ", FALSE)) {
				DCAuthStoreConfig();
			}
			OUT_PRINT(L"\n");

			return TRUE;
		}

		if (key.ScanCode == SCAN_UP) {
			if (selected > 0) {
				prev = selected;
				selected--;
				CfgMenuDrawItem(&items[prev], baseRow + prev, FALSE);
				CfgMenuDrawItem(&items[selected], baseRow + selected, TRUE);
			}
		}

		if (key.ScanCode == SCAN_DOWN) {
			if (selected < count - 1) {
				prev = selected;
				selected++;
				CfgMenuDrawItem(&items[prev], baseRow + prev, FALSE);
				CfgMenuDrawItem(&items[selected], baseRow + selected, TRUE);
			}
		}

		if (key.ScanCode == SCAN_RIGHT || key.ScanCode == SCAN_LEFT) {
			if (items[selected].PickerFunc != NULL) {
				// Custom picker: invoke and redraw menu on success
				INT32 newValue = items[selected].CurrentIndex;
				if (!EFI_ERROR(items[selected].PickerFunc(&newValue))) {
					items[selected].CurrentIndex = newValue;
				}
				// Redraw entire menu after picker returns (even on cancel)
				gST->ConOut->ClearScreen(gST->ConOut);
				OUT_PRINT(L"--- Configuration ---\r\n");
				baseRow = gST->ConOut->Mode->CursorRow;
				for (i = 0; i < count; i++) {
					CfgMenuDrawItem(&items[i], baseRow + i, (i == selected));
					OUT_PRINT(L"\r\n");
				}
				OUT_PRINT(L"---------------------\r\n");
				OUT_PRINT(L"Up/Down:select  Left/Right:change  Enter:apply  Esc:cancel\r\n");
				gST->ConOut->EnableCursor(gST->ConOut, FALSE);
			} else if (key.ScanCode == SCAN_RIGHT) {
				if (items[selected].Values != NULL) {
					// Named values: cycle through array
					if (items[selected].CurrentIndex < items[selected].ValueCount - 1) {
						items[selected].CurrentIndex++;
						CfgMenuDrawValue(&items[selected], baseRow + selected, TRUE);
					}
				} else {
					// Numeric-only: use Min/Max
					if (items[selected].CurrentIndex < items[selected].Max) {
						items[selected].CurrentIndex++;
						CfgMenuDrawValue(&items[selected], baseRow + selected, TRUE);
					}
				}
			} else { // SCAN_LEFT
				if (items[selected].Values != NULL) {
					// Named values: cycle through array
					if (items[selected].CurrentIndex > 0) {
						items[selected].CurrentIndex--;
						CfgMenuDrawValue(&items[selected], baseRow + selected, TRUE);
					}
				} else {
					// Numeric-only: use Min/Max
					if (items[selected].CurrentIndex > items[selected].Min) {
						items[selected].CurrentIndex--;
						CfgMenuDrawValue(&items[selected], baseRow + selected, TRUE);
					}
				}
			}
		}
	}
}

//////////////////////////////////////////////////////////////////////////
// Save configuration to file
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
DCAuthStoreConfig(
	VOID
)
{
	EFI_STATUS   Status;
	CFG_STRING   NewConfig;
	CHAR8       *ConfigContent = NULL;
	CHAR8       *Xml;
	CHAR8        Key[128];
	CHAR8        Value[2048];

	// Check if config was initialized
	if (gConfigFileName == NULL) {
		ERR_PRINT(L"Config not initialized, cannot save.\n");
		return EFI_NOT_READY;
	}

	// Initialize string builder
	Status = CfgStrInit(&NewConfig, 4096);
	if (EFI_ERROR(Status))
		return Status;

	// Load existing config content if available
	if (gConfigBuffer != NULL) {
		ConfigContent = MEM_ALLOC(gConfigBufferSize + 1);
		if (ConfigContent != NULL) {
			CopyMem(ConfigContent, gConfigBuffer, gConfigBufferSize);
			ConfigContent[gConfigBufferSize] = '\0';
		}
	}

	// Write XML header
	Status = CfgWriteHeader(&NewConfig);
	if (EFI_ERROR(Status)) goto cleanup;

	// Set the DCS Module in case we use a build that supports multiple methods
	Status = CfgWriteString(&NewConfig, ConfigContent, "DcsModule", "DiskCryptor");
	if (EFI_ERROR(Status)) goto cleanup;

	// Main settings
	Status = CfgWriteInteger(&NewConfig, ConfigContent, "KeyboardLayout", gKeyboardLayout);
	if (EFI_ERROR(Status)) goto cleanup;

	Status = CfgWriteInteger(&NewConfig, ConfigContent, "HeaderKDF", gDCryptHeaderKdf);
	if (EFI_ERROR(Status)) goto cleanup;

	Status = CfgWriteInteger(&NewConfig, ConfigContent, "KeyfileMixer", gDCryptKfMixer);
	if (EFI_ERROR(Status)) goto cleanup;

	// TPM settings
	Status = CfgWriteInteger(&NewConfig, ConfigContent, "TpmMode", gDCryptTpmMode);
	if (EFI_ERROR(Status)) goto cleanup;

	Status = CfgWriteInteger(&NewConfig, ConfigContent, "TpmStorage", gDCryptTpmStorage);
	if (EFI_ERROR(Status)) goto cleanup;

	Status = CfgWriteInteger(&NewConfig, ConfigContent, "TpmPcrMask", gDCryptTpmPcrMask);
	if (EFI_ERROR(Status)) goto cleanup;

	// Other settings
	Status = CfgWriteInteger(&NewConfig, ConfigContent, "UseHardwareCrypto", gDCryptHwCrypto ? 1 : 0);
	if (EFI_ERROR(Status)) goto cleanup;

	Status = CfgWriteInteger(&NewConfig, ConfigContent, "VerboseDebug", gConfigDebug ? 1 : 0);
	if (EFI_ERROR(Status)) goto cleanup;

	Status = CfgWriteInteger(&NewConfig, ConfigContent, "BootMode", gDCryptBootMode);
	if (EFI_ERROR(Status)) goto cleanup;

	Status = CfgWriteInteger(&NewConfig, ConfigContent, "BlockUnencryptedVolumes", gBlockUnencryptedVolumes ? 1 : 0);
	if (EFI_ERROR(Status)) goto cleanup;

	Status = CfgWriteInteger(&NewConfig, ConfigContent, "HandoffMode", gDCryptHandoffMode);
	if (EFI_ERROR(Status)) goto cleanup;

	// Copy all unmodified values from original config
	if (ConfigContent != NULL) {
		Xml = ConfigContent;
		while (Xml != NULL && (Xml = XmlFindElement(Xml, "config")) != NULL) {
			XmlGetAttributeText(Xml, "key", Key, sizeof(Key));
			XmlGetNodeText(Xml, Value, sizeof(Value));

			Status = CfgStrAppend(&NewConfig, "\n\t\t<config key=\"");
			if (EFI_ERROR(Status)) goto cleanup;

			Status = CfgStrAppend(&NewConfig, Key);
			if (EFI_ERROR(Status)) goto cleanup;

			Status = CfgStrAppend(&NewConfig, "\">");
			if (EFI_ERROR(Status)) goto cleanup;

			Status = CfgStrAppend(&NewConfig, Value);
			if (EFI_ERROR(Status)) goto cleanup;

			Status = CfgStrAppend(&NewConfig, "</config>");
			if (EFI_ERROR(Status)) goto cleanup;

			Xml++;
		}
	}

	// Write XML footer
	Status = CfgWriteFooter(&NewConfig);
	if (EFI_ERROR(Status)) goto cleanup;

	// Save config file (handles PXE and local file system)
	Status = ConfigSave(&NewConfig);
	if (EFI_ERROR(Status)) goto cleanup;

	if (gConfigDebug) {
		OUT_PRINT(L"Configuration saved successfully.\n");
	}

cleanup:
	if (ConfigContent != NULL)
		MEM_FREE(ConfigContent);
	CfgStrFree(&NewConfig);

	return Status;
}
