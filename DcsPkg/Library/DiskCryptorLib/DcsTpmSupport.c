/** @file
TPM Support for DiskCryptor EFI module

Copyright (c) 2026. DiskCryptor, David Xanatos

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Uefi.h>
#include "DcsDiskCryptor.h"
#include "include/dc_header.h"
#include "crypto_fast/crc32.h"
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/DevicePathLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>

#include <Library/CommonLib.h>
#include <Library/BaseLib.h>
#include <Library/GraphLib.h>
#include <DcsConfig.h>

#include "../DcsTpm/DcsTpmProto.h"
#include "../MiscUtilsLib/MiscUtilsLib.h"

EFI_DCS_TPM_PROTOCOL* gDcsTpm = NULL;

CHAR16* sDcsTpmEfi = L"EFI\\" DCS_DIRECTORY L"\\DcsTpm.dcs";

EFI_STATUS
InitDcsTpm() {
	EFI_STATUS res;

	res = gBS->LocateProtocol(&gEfiDcsTpmProtocolGuid, NULL, (VOID**)&gDcsTpm);
	if (EFI_ERROR(res)) {
		if (IsPxeBoot()) {
			PxeExec(sDcsTpmEfi);
		} else {
			EfiExec(NULL, sDcsTpmEfi);
		}
		res = gBS->LocateProtocol(&gEfiDcsTpmProtocolGuid, NULL, (VOID**)&gDcsTpm);
	}

	return res;
}

#define DC_TPM_SECRET_TYPE_PLAIN    0   // Plain password
#define DC_TPM_SECRET_TYPE_1		1
#define DC_TPM_SECRET_TYPE_RECOVERY	((UINT32)(-1))  // Recovery data (includes PCR mask and PIN for re-seal)

#define DC_TPM_FLAG_NONE            0x00000000
#define DC_TPM_FLAG_REQ_PASS		0x00000001

#define DC_TPM_BACKUP_PROVISIONING	0x00000001

#define DC_TPM_NV_INDEX_PRIMARY		0x0DC5C
#define DC_TPM_NV_INDEX_RECOVERY	0x0DC5E

#define DC_TPM_SRK_FILE_PRIMARY      L"\\EFI\\DCS\\tpm_sealed.dat"
#define DC_TPM_SRK_FILE_RECOVERY     L"\\EFI\\DCS\\tpm_recovery.dat"

#pragma pack(push, 1)

// Full structure (for loading - must match what dc_pass fields are used)
// Note: TPM 1.2's limit is ~200 byte only
typedef struct _tpm_secret {
	UINT32    Flags;
	int       Kdf;
	int       Slot;
	UINT16	  SecretSize;
	UINT8 	  SecretData[0];
} tpm_secret;

// Backup data structure - stores secret plus original PCR mask and PIN for re-seal
typedef struct _tpm_backup {
	UINT32    PcrMask;
	UINT32    Flags;
	UINT16    PinSize;
	UINT32    SecretType;
	UINT16    SecretSize;
	UINT8     SecretData[0];
} tpm_backup;

#pragma pack(pop)

// Simplified function key handler for password confirmation (F5 show/hide only)
static INT32 HandleFuncKeysSimple(EFI_INPUT_KEY key, VOID *Param)
{
	if (key.ScanCode == SCAN_F5) {
		return AskPwdRetShow;
	}
	return AskPwdRetNone;
}

/**
Check if an EFI error is likely an authorization failure that
could be resolved by providing owner password.

Based on EDK2 Tpm2NVStorage.c error mapping:
- EFI_SECURITY_VIOLATION <- TPM_RC_NV_AUTHORIZATION
- EFI_INVALID_PARAMETER  <- TPM_RC_AUTH_FAIL, TPM_RC_BAD_AUTH
- EFI_DEVICE_ERROR       <- Catch-all (may include auth errors)

@param[in] Status  The EFI status to check
@return TRUE if retry with password might help
**/
STATIC
BOOLEAN
IsAuthError(
	IN EFI_STATUS Status
)
{
	// These errors indicate auth failure - retry with password might help
	if (Status == EFI_SECURITY_VIOLATION ||
		Status == EFI_INVALID_PARAMETER ||
		Status == EFI_DEVICE_ERROR) {
		return TRUE;
	}

	// These errors won't be fixed by providing password:
	// EFI_NOT_FOUND       - NV index doesn't exist
	// EFI_ALREADY_STARTED - NV index already exists
	// EFI_OUT_OF_RESOURCES - TPM NV storage full
	// EFI_UNSUPPORTED     - Attribute issues
	// EFI_BAD_BUFFER_SIZE - Size/range errors
	// EFI_ACCESS_DENIED   - PCR policy failure
	return FALSE;
}


/**
Ask user for TPM owner password interactively.

@param[in]  This           A pointer to the EFI_DCS_TPM_PROTOCOL instance.
@param[out] OwnerPassword  Buffer to receive owner password (size DCS_TPM_OWNER_PWD_MAX).

@retval EFI_SUCCESS           Password entered successfully.
@retval EFI_ABORTED           User cancelled.
@retval EFI_INVALID_PARAMETER OwnerPassword is NULL.

**/
EFI_STATUS
EFIAPI
AskOwnerPassword (
	OUT CHAR16                *OwnerPassword
)
{
	UINTN maxLen = DCS_TPM_OWNER_PWD_MAX;
	UINT32 len = 0;
	INT32 pwdCode;

	if (OwnerPassword == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	OUT_PRINT(L"TIP: For TPM 2.0 Windows leaves owner auth EMPTY.\n");

	ZeroMem(OwnerPassword, maxLen * sizeof(CHAR16));
	AskConsolePwdEx("Enter TPM owner password: ", &len, OwnerPassword, &pwdCode, maxLen - 1, FALSE, TRUE, HandleFuncKeysSimple, NULL, NULL);
	if (pwdCode == AskPwdRetCancel) {
		OUT_PRINT(L"Cancelled.\n");
		return EFI_ABORTED;
	}

	return EFI_SUCCESS;
}

// PCR descriptions for the interactive menu
static CHAR16 *gPcrDescriptions[] = {
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

#define PCR_MENU_COUNT  16  // PCRs 0-15

// Draw a single PCR item with cursor inside brackets for selected item
STATIC
VOID
PcrMenuDrawItem(
	IN INT32    PcrIndex,
	IN INT32    Row,
	IN BOOLEAN  Selected,
	IN BOOLEAN  Enabled
)
{
	gST->ConOut->SetCursorPosition(gST->ConOut, 0, Row);

	// Show > marker and highlight inside brackets for selected item
	if (Selected) {
		OUT_PRINT(L"> %V[%s]%N PCR %d: %-25s",
			Enabled ? L"X" : L" ",
			PcrIndex,
			gPcrDescriptions[PcrIndex]);
	} else {
		OUT_PRINT(L"  [%s] PCR %d: %-25s",
			Enabled ? L"X" : L" ",
			PcrIndex,
			gPcrDescriptions[PcrIndex]);
	}

	// Clear rest of line
	OUT_PRINT(L"          ");
}

/**
Ask user for PCR mask with interactive selection.

@param[out] PcrMask      Pointer to receive PCR mask.
@param[in]  DefaultMask  Default PCR mask (pre-selected PCRs).

@retval EFI_SUCCESS  PCR mask entered successfully.
@retval EFI_ABORTED  User cancelled.
**/
EFI_STATUS
DcTpmAskPcrMask(
	OUT UINT32  *PcrMask,
	IN  UINT32  DefaultMask
)
{
	EFI_INPUT_KEY key;
	INT32         selected = 0;
	INT32         prev;
	INT32         baseRow;
	INT32         i;
	UINT32        mask;
	UINTN         screenRows = 25;
	UINTN         screenCols = 80;
	INT32         totalNeeded;
	INT32         currentRow;
	INT32         availableRows;

	if (PcrMask == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	// Initialize mask from default
	mask = DefaultMask;

	// Get screen dimensions
	if (gST->ConOut->Mode != NULL) {
		gST->ConOut->QueryMode(gST->ConOut, gST->ConOut->Mode->Mode, &screenCols, &screenRows);
	}

	// Header
	OUT_PRINT(L"\n--- Select PCRs for TPM Sealing ---\n");
	OUT_PRINT(L"Pre-selected PCRs are required for security!\n\n");

	// Calculate space needed: items + 2 footer lines
	totalNeeded = PCR_MENU_COUNT + 2;
	currentRow = (INT32)gST->ConOut->Mode->CursorRow;
	availableRows = (INT32)screenRows - currentRow;

	// If not enough room, scroll to make space
	if (availableRows < totalNeeded) {
		INT32 scrollNeeded = totalNeeded - availableRows;
		// Move to bottom row so newlines will actually scroll the screen
		gST->ConOut->SetCursorPosition(gST->ConOut, 0, screenRows - 1);
		for (i = 0; i < scrollNeeded; i++) {
			OUT_PRINT(L"\n");
		}
		// After scrolling, menu fits at bottom of screen
		baseRow = (INT32)screenRows - totalNeeded;
	} else {
		baseRow = currentRow;
	}

	// Initial draw of all items
	for (i = 0; i < PCR_MENU_COUNT; i++) {
		PcrMenuDrawItem(i, baseRow + i, (i == selected), (mask & (1 << i)) != 0);
	}

	// Footer - position and print without trailing newline to avoid scroll
	gST->ConOut->SetCursorPosition(gST->ConOut, 0, baseRow + PCR_MENU_COUNT);
	OUT_PRINT(L"\nUp/Down: select   Space: toggle   Enter: confirm   Esc: cancel");

	gST->ConOut->EnableCursor(gST->ConOut, FALSE);

	// Input loop
	for (;;) {
		key = GetKey();

		if (key.ScanCode == SCAN_ESC) {
			gST->ConOut->EnableCursor(gST->ConOut, TRUE);
			// Position cursor below footer before printing
			gST->ConOut->SetCursorPosition(gST->ConOut, 0, baseRow + PCR_MENU_COUNT + 1);
			OUT_PRINT(L"\nCancelled.\n");
			return EFI_ABORTED;
		}

		if (key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
			// Confirm selection
			gST->ConOut->EnableCursor(gST->ConOut, TRUE);
			// Position cursor below footer before printing
			gST->ConOut->SetCursorPosition(gST->ConOut, 0, baseRow + PCR_MENU_COUNT + 1);

			*PcrMask = mask;
			OUT_PRINT(L"\nPCR mask: 0x%03x\n", mask);
			return EFI_SUCCESS;
		}

		if (key.ScanCode == SCAN_UP) {
			if (selected > 0) {
				prev = selected;
				selected--;
				PcrMenuDrawItem(prev, baseRow + prev, FALSE, (mask & (1 << prev)) != 0);
				PcrMenuDrawItem(selected, baseRow + selected, TRUE, (mask & (1 << selected)) != 0);
			}
		}

		if (key.ScanCode == SCAN_DOWN) {
			if (selected < PCR_MENU_COUNT - 1) {
				prev = selected;
				selected++;
				PcrMenuDrawItem(prev, baseRow + prev, FALSE, (mask & (1 << prev)) != 0);
				PcrMenuDrawItem(selected, baseRow + selected, TRUE, (mask & (1 << selected)) != 0);
			}
		}

		// Toggle with space
		if (key.UnicodeChar == L' ') {
			mask ^= (1 << selected);
			PcrMenuDrawItem(selected, baseRow + selected, TRUE, (mask & (1 << selected)) != 0);
		}
	}
}

/**
Ask user for optional TPM PIN with confirmation.

@param[out] TpmPin    Buffer to receive TPM PIN.
@param[in]  MaxLen    Maximum PIN length (in characters).
@param[out] PinSet    TRUE if PIN was entered, FALSE if skipped.

@retval EFI_SUCCESS  PIN entered or skipped successfully.
@retval EFI_ABORTED  User cancelled (PIN mismatch).
**/
EFI_STATUS
DcTpmAskTpmPin(
	OUT CHAR16   *TpmPin,
	IN  UINTN    MaxLen,
	OUT BOOLEAN  *PinSet
)
{
	UINT32 pinLen = 0;
	CHAR16 confirmPin[DCS_TPM_OWNER_PWD_MAX];
	UINT32 confirmLen = 0;
	INT32  pwdCode;

	if (TpmPin == NULL || MaxLen == 0 || PinSet == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	*PinSet = FALSE;

retry:
	// Get PIN
	ZeroMem(TpmPin, MaxLen * sizeof(CHAR16));
	AskConsolePwdEx("Enter TPM PIN: ", &pinLen, TpmPin, &pwdCode, MaxLen - 1, FALSE, TRUE, HandleFuncKeysSimple, NULL, NULL);
	if (pwdCode == AskPwdRetCancel)
		return EFI_ABORTED;

	if (pinLen > 0) {
		// Confirm PIN
		ZeroMem(confirmPin, sizeof(confirmPin));
		AskConsolePwdEx("Confirm TPM PIN: ", &confirmLen, confirmPin, &pwdCode, DCS_TPM_OWNER_PWD_MAX - 1, FALSE, TRUE, HandleFuncKeysSimple, NULL, NULL);
		if (pwdCode == AskPwdRetCancel)
			return EFI_ABORTED;

		if (StrCmp(TpmPin, confirmPin) != 0) {
			ERR_PRINT(L"PINs do not match. retry.\n");
			ZeroMem(TpmPin, MaxLen * sizeof(CHAR16));
			ZeroMem(confirmPin, sizeof(confirmPin));
			goto retry;
		}

		ZeroMem(confirmPin, sizeof(confirmPin));
	}

	*PinSet = TRUE;

	return EFI_SUCCESS;
}

/**
Get TPM seal options interactively from user.

@param[in]  This     A pointer to the EFI_DCS_TPM_PROTOCOL instance.
@param[out] Options  Pointer to options structure to fill.

@retval EFI_SUCCESS        Options gathered successfully.
@retval EFI_ABORTED        User cancelled.
@retval EFI_NOT_READY      TPM not available.

**/
EFI_STATUS
EFIAPI
GetSealOptions (
	OUT DCS_TPM_SEAL_OPTIONS   *Options,
	IN  BOOLEAN                SkipOwnerPassword
)
{
	EFI_STATUS res;
	BOOLEAN    pinSet = FALSE;
	UINT8      sbState;

	if (Options == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	// Initialize structure
	ZeroMem(Options, sizeof(DCS_TPM_SEAL_OPTIONS));
	Options->Size = sizeof(DCS_TPM_SEAL_OPTIONS);

	// Get owner password (unless skipped)
	if (!SkipOwnerPassword) {
		res = AskOwnerPassword(Options->OwnerPassword);
		if (EFI_ERROR(res)) {
			ZeroMem(Options, sizeof(DCS_TPM_SEAL_OPTIONS));
			return res;
		}
	}
	// else: leave OwnerPassword empty (already zeroed)

	// Get PCR mask
	//res = DcTpmAskPcrMask(&Options->PcrMask, DCS_TPM_DEFAULT_PCR_MASK);
	//if (EFI_ERROR(res)) {
	//	ZeroMem(Options, sizeof(DCS_TPM_SEAL_OPTIONS));
	//	return res;
	//}
	Options->PcrMask = gDCryptTpmPcrMask;

	if (!(gDCryptTpmMode & DCryptTpmPin)) {
		goto check_sb;
	}

	OUT_PRINT(L"\n%HTPM PIN (optional - validated by TPM hardware):%N\n");
	OUT_PRINT(L"  If set, TPM will require this PIN to unseal the secret.\n");
	OUT_PRINT(L"  This is NOT limited to digits - any passphrase is allowed.\n");
	OUT_PRINT(L"  Leave empty for PCR-only protection.\n\n");

retry:
	// Get optional TPM PIN
	res = DcTpmAskTpmPin(Options->TpmPin, DCS_TPM_OWNER_PWD_MAX, &pinSet);
	if (EFI_ERROR(res)) {
		ZeroMem(Options, sizeof(DCS_TPM_SEAL_OPTIONS));
		return res;
	}

check_sb:
	if (!pinSet || Options->TpmPin[0] == '\0') {

		if (!gBlockUnencryptedVolumes && (EFI_ERROR(DcsLdrGetMokSBState(&sbState)) || !sbState)) {
			// If Secure Boot is disabled, warn about PIN-less protection and confirm                         |
			OUT_PRINT(L"\n%OWARNING:%N %HSecure Boot is disabled.%N TPM-only unattended unlock is not recommended.\n");
			OUT_PRINT(L"This configuration may allow an attacker to modify the boot chain and gain access to the stored secret.\n");
			if (!AskYesNo(L"\nDo you want to continue anyways? [y/N]?", FALSE))
				goto retry;
		}

		//OUT_PRINT(L"No PIN entered, continuing without PIN.\n");
	} 
	else {
		OUT_PRINT(L"TPM PIN will be required for unsealing.\n");
		Options->Flags |= DCS_TPM_OPT_FLAG_USE_PIN;
	}

	OUT_PRINT(L"\n");

	return EFI_SUCCESS;
}


/**
Delete a TPM sealed file at the given path.

@param[in] FilePath  Path to the sealed file

@return EFI_SUCCESS or error status
**/
STATIC
EFI_STATUS
DcFileDeletePath(
	IN CONST CHAR16 *FilePath
)
{
	if (IsPxeBoot()) {
		// TFTP doesn't support file deletion - just return success
		return EFI_UNSUPPORTED;
	}
	return FileDelete(NULL, (CHAR16*)FilePath);
}


/**
Check if a TPM sealed file exists at the given path.

@param[in] FilePath  Path to the sealed file

@return TRUE if file exists
**/
STATIC
BOOLEAN
DcFileExistsPath(
	IN CONST CHAR16 *FilePath
)
{
	if (IsPxeBoot()) {
		return !EFI_ERROR(PxeFileExist((CHAR16*)FilePath));
	}
	return !EFI_ERROR(FileExist(NULL, (CHAR16*)FilePath));
}


/**
Read a TPM sealed file from the given path.

@param[in]     FilePath    Path to the sealed file
@param[out]    Buffer      Buffer to receive file contents
@param[in,out] BufferSize  On input: buffer size; On output: bytes read

@return EFI_SUCCESS or error status
**/
STATIC
EFI_STATUS
DcFileReadPath(
	IN     CONST CHAR16 *FilePath,
	OUT    UINT8        **Buffer,
	IN OUT UINT32       *BufferSize
)
{
	EFI_STATUS ret;
	VOID       *fileData = NULL;
	UINTN      fileSize = 0;

	if (IsPxeBoot()) {
		ret = PxeDownloadFile((CHAR16*)FilePath, &fileData, &fileSize);
	} else {
		ret = FileLoad(NULL, (CHAR16*)FilePath, &fileData, &fileSize);
	}

	if (EFI_ERROR(ret)) {
		return ret;
	}

	if (fileData == NULL || fileSize == 0) {
		if (fileData) MEM_FREE(fileData);
		return EFI_NOT_FOUND;
	}

	*Buffer = (UINT8*)fileData;
	*BufferSize = (UINT32)fileSize;

	return EFI_SUCCESS;
}

/**
Write a TPM sealed file to the given path.

@param[in] FilePath    Path to the sealed file
@param[in] Buffer      Buffer containing sealed data
@param[in] BufferSize  Size of buffer in bytes

@return EFI_SUCCESS or error status
**/
STATIC
EFI_STATUS
DcFileWritePath(
	IN CONST CHAR16 *FilePath,
	IN UINT8        *Buffer,
	IN UINT32       BufferSize
)
{
	EFI_STATUS ret;

	if (IsPxeBoot()) {
		ret = PxeUploadFile((CHAR16*)FilePath, Buffer, BufferSize);
	} else {
		// Ensure directory exists
		DirectoryCreate(gFileRoot, L"\\EFI\\DCS");
		ret = FileSave(gFileRoot, (CHAR16*)FilePath, Buffer, BufferSize);
	}

	return ret;
}

/**
Determine if we should use SRK-based sealing (file-based storage) or NV index sealing.

@return TRUE if SRK-based sealing (file-based) should be used, FALSE for NV index sealing
**/

STATIC 
BOOLEAN
DcTpmStorageUseSrkMode()
{
	if (gDCryptTpmStorage == DCryptTpmDefault) {
		if(gDCryptTpmVersion >= 0x200)
			return FALSE;
		return TRUE;
	}

	if (gDCryptTpmStorage == DCryptTpmNV)
		return FALSE;
	return TRUE;
}

STATIC
EFI_STATUS
DcGetRecOptions(
	IN  DCS_TPM_SEAL_OPTIONS   *PrimaryOpts,
	OUT DCS_TPM_SEAL_OPTIONS   *backupOptions
)
{
	EFI_STATUS ret;
	BOOLEAN    pinSet = FALSE;

	// Prepare backup seal options
	ZeroMem(backupOptions, sizeof(DCS_TPM_SEAL_OPTIONS));
	backupOptions->Size = sizeof(DCS_TPM_SEAL_OPTIONS);
	backupOptions->PcrMask = 0;  // No PCRs for backup - PIN only
	CopyMem(backupOptions->OwnerPassword, PrimaryOpts->OwnerPassword, sizeof(backupOptions->OwnerPassword));
	backupOptions->Flags = DCS_TPM_OPT_FLAG_USE_PIN;

	OUT_PRINT(L"\n--- Create TPM Recovery ---\n\n");
	OUT_PRINT(L"The recovery allows you to unlock your disk if PCR values change\n");
	OUT_PRINT(L"(e.g., BIOS update, Secure Boot change).\n\n");

retry:
	ret = DcTpmAskTpmPin(backupOptions->TpmPin, DCS_TPM_OWNER_PWD_MAX, &pinSet);
	if (EFI_ERROR(ret)) {
		return ret;
	}

	if (!pinSet) {
		OUT_PRINT(L"Recovery PIN is required for backup. Aborting.\n");
		goto retry;
	}

	return EFI_SUCCESS;
}

STATIC
EFI_STATUS
DcPrepBackup(
	IN  VOID                   *Data,
	IN  UINT32                 DataSize,
	IN  UINT32                 DataType,
	IN  DCS_TPM_SEAL_OPTIONS   *PrimaryOpts,
	OUT UINT8                  *backupBuffer,
	OUT UINT32                 *backupSize,
	OUT UINT32                 *backupType,
	OUT DCS_TPM_SEAL_OPTIONS   *backupOptions,
	IN  BOOLEAN                RawBackup
)
{
	EFI_STATUS ret;
	tpm_backup           *backup = (tpm_backup*)backupBuffer;

	if (backupOptions) {
		ret = DcGetRecOptions(PrimaryOpts, backupOptions);
		if (EFI_ERROR(ret)) {
			return ret;
		}
	}

	if (RawBackup) {
		CopyMem(backupBuffer, Data, DataSize);

		*backupSize = DataSize;
		*backupType = DataType;

		return EFI_SUCCESS;
	}

	// Prepare backup data structure (same format as NV backup)
	backup->SecretSize = (UINT16)DataSize;
	backup->SecretType = DataType;
	backup->PcrMask = PrimaryOpts->PcrMask;  // Store original PCR mask for re-seal
	backup->PinSize = 0;
	backup->Flags = 0;

	CopyMem(backup->SecretData, Data, DataSize);

	// Store original PIN if used (for re-seal convenience)
	if (PrimaryOpts->Flags & DCS_TPM_OPT_FLAG_USE_PIN) {
		UINTN origPinBytes = (StrLen(PrimaryOpts->TpmPin) + 1) * sizeof(CHAR16);
		backup->PinSize = (UINT16)origPinBytes;
		CopyMem(backup->SecretData + DataSize, PrimaryOpts->TpmPin, origPinBytes);
	}

	*backupSize = sizeof(tpm_backup) + backup->SecretSize + backup->PinSize;
	*backupType = DC_TPM_SECRET_TYPE_RECOVERY;

	return EFI_SUCCESS;
}

/**
Seal data to TPM and write to file.
Common helper for sealing operations in file-based storage mode.

@param[in] Data      Data to seal
@param[in] DataSize  Size of data
@param[in] DataType  Type identifier for data
@param[in] PcrMask   PCR mask for sealing (0 for PIN-only)
@param[in] Pin       Optional PIN for sealing (NULL if not used)
@param[in] FilePath  Path to write sealed data

@return EFI_SUCCESS or error status
**/
STATIC
EFI_STATUS
DcTpmSealToFile(
	IN CONST CHAR16	          *FilePath,
	IN VOID                   *Data,
	IN UINT32                 DataSize,
	IN UINT32                 DataType,
	IN  DCS_TPM_SEAL_OPTIONS  *Options
)
{
	EFI_STATUS ret;
	UINT8      sealedBuffer[2048];
	UINT32     sealedSize = sizeof(sealedBuffer);

	ret = gDcsTpm->SrkSealPassword(
		gDcsTpm,
		Data, DataSize, DataType,
		Options,
		NULL, 0,
		sealedBuffer, &sealedSize
	);

	if (EFI_ERROR(ret)) {
		MEM_BURN(sealedBuffer, sizeof(sealedBuffer));
		return ret;
	}

	ret = DcFileWritePath(FilePath, sealedBuffer, sealedSize);
	MEM_BURN(sealedBuffer, sizeof(sealedBuffer));

	return ret;
}

STATIC
EFI_STATUS
DcApplyBackup(
	IN UINT8*   BackupBuffer, 
	IN UINT32   BackupSize, 
	IN UINT32   BackupType, 
	OUT UINT8   *Data,
	IN UINT32   DataBufferSize,
	OUT UINT32  *DataSize,
	OUT UINT32  *DataType)
{
	EFI_STATUS ret;
	UINT32 backupFlags = 0;

	if (BackupType == DC_TPM_SECRET_TYPE_RECOVERY)
	{
		tpm_backup *backup = (tpm_backup *)BackupBuffer;

		if (DataBufferSize < backup->SecretSize) {
			ret = EFI_BUFFER_TOO_SMALL;
		} 
		else  {
			*DataSize = backup->SecretSize;
			*DataType = backup->SecretType;
			memcpy(Data, backup->SecretData, backup->SecretSize);
			backupFlags = backup->Flags;

			ret = EFI_SUCCESS;
		}
	}
	else { // raw backup without metadata
		*DataSize = BackupSize;
		*DataType = BackupType;
		memcpy(Data, BackupBuffer, BackupSize);
		backupFlags = DC_TPM_BACKUP_PROVISIONING;

		ret = EFI_SUCCESS;
	}

	if(EFI_ERROR(ret)) {
		ERR_PRINT(L" Failed: %r\n", ret);
		return ret;
	} else {
		OUT_PRINT(L"%VSuccess!%N\n");
	}

	// Offer to re-seal with current PCRs (only if TPM is available)
	if (gDcsTpm == NULL) {
		ERR_PRINT(L"TPM not available, cannot re-seal secret values.\n");
		return EFI_SUCCESS;
	}

	if (AskYesNo(L"\n%HRe-seal to TPM with current PCR values?%N [y/N]: ", FALSE)) {

		DCS_TPM_SEAL_OPTIONS options;

		if (DcTpmStorageUseSrkMode()) {
			OUT_PRINT(L"\n--- TPM Re-seal to File ---\n\n");
		} else {
			OUT_PRINT(L"\n--- TPM Re-seal to NV ---\n\n");
		}

		if (BackupType != DC_TPM_SECRET_TYPE_RECOVERY || (backupFlags & DC_TPM_BACKUP_PROVISIONING)) {
			ret = GetSealOptions(&options, TRUE);
			if(EFI_ERROR(ret)) {
				ERR_PRINT(L"Failed to get seal options: %r\n", ret);
				return EFI_SUCCESS;
			}
		}
		else {
			tpm_backup *backup = (tpm_backup *)BackupBuffer;

			OUT_PRINT(L"Using stored PCR mask: 0x%x\n", backup->PcrMask);

			// Initialize options with stored values from backup
			ZeroMem(&options, sizeof(DCS_TPM_SEAL_OPTIONS));
			options.Size = sizeof(DCS_TPM_SEAL_OPTIONS);
			options.PcrMask = backup->PcrMask;  // Use original PCR mask
			options.Flags = DCS_TPM_OPT_FLAG_NONE;

			// Restore original PIN if stored in backup
			if (backup->PinSize > 0) {
				CHAR16* origPin = (CHAR16*)(backup->SecretData + backup->SecretSize);
				UINTN origPinLen = backup->PinSize / sizeof(CHAR16);
				if (origPinLen > 0 && origPinLen < DCS_TPM_OWNER_PWD_MAX) {
					CopyMem(options.TpmPin, origPin, backup->PinSize);
					options.TpmPin[origPinLen] = L'\0';
					options.Flags |= DCS_TPM_OPT_FLAG_USE_PIN;
					OUT_PRINT(L"Using stored original PIN.\n");
				}
			}
		}

		// Save to file or TPM based on storage mode
		if (DcTpmStorageUseSrkMode())  {
			OUT_PRINT(L"Sealing and saving to File... ");
			ret = DcTpmSealToFile(
				DC_TPM_SRK_FILE_PRIMARY,
				Data, *DataSize, 
				*DataType,
				&options);
		} 
		else {
			if (gDCryptTpmAskOwnerPw == 0) {
				// Try without owner password first (TPM 2.0 with default empty owner auth)
				OUT_PRINT(L"Sealing secret to TPM NV Memory... ");
				ret = gDcsTpm->SealSecret(gDcsTpm, DC_TPM_NV_INDEX_PRIMARY, Data, *DataSize, *DataType, &options, NULL, 0);
				if (IsAuthError(ret)) {
					// Auth failure - ask for owner password and retry
					OUT_PRINT(L"\n");
					OUT_PRINT(L"Owner authorization required.\n");
					gDCryptTpmAskOwnerPw = 2;
				}
			}

			if (gDCryptTpmAskOwnerPw != 0) {
				// Always ask for owner password (TPM 1.2 or setting enabled)
				ret = AskOwnerPassword(options.OwnerPassword);
				if (EFI_ERROR(ret)) {
					if (ret != EFI_ABORTED) {
						ERR_PRINT(L"Failed to get owner password: %r\n", ret);
					}
					MEM_BURN(&options, sizeof(options));
					return EFI_SUCCESS;
				}

				OUT_PRINT(L"Sealing secret to TPM... ");
				ret = gDcsTpm->SealSecret(gDcsTpm, DC_TPM_NV_INDEX_PRIMARY, Data, *DataSize, *DataType, &options, NULL, 0);
			}
		}

		MEM_BURN(&options, sizeof(options));

		if (EFI_ERROR(ret)) {
			ERR_PRINT(L"Failed: %r\n", ret);
		} else {
			OUT_PRINT(L"%VDone.%N\n");
			OUT_PRINT(L"Secret re-sealed with current PCR values.\n");
		}
	}

	return EFI_SUCCESS;
}

/**
Create a recovery backup of the sealed secret.
The backup is sealed with PIN-only (no PCRs) so it can be used for recovery
when PCR values change.

@param[in] Data         The secret data to backup
@param[in] DataSize     Size of the data
@param[in] DataType     Type of the data
@param[in] PrimaryOpts  Primary seal options (contains original PIN if any)
**/
STATIC
VOID
DcTpmCreateBackup(
	IN VOID                   *Data,
	IN UINT32                 DataSize,
	IN UINT32                 DataType,
	IN DCS_TPM_SEAL_OPTIONS   *PrimaryOpts,
	IN BOOLEAN                RawBackup
)
{
	EFI_STATUS           ret;
	UINT8                backupBuffer[DCS_SECRET_DATA_MAX];
	UINT32               backupSize = sizeof(backupBuffer);
	UINT32               backupType = 0;
	DCS_TPM_SEAL_OPTIONS backupOptions;

	ZeroMem(backupBuffer, backupSize);

	ret = DcPrepBackup(Data, DataSize, DataType, PrimaryOpts, backupBuffer, &backupSize, &backupType, &backupOptions, RawBackup);
	if (EFI_ERROR(ret)) {
		ERR_PRINT(L"Failed to prepare backup data: %r\n", ret);
		return;
	}

	if (DcTpmStorageUseSrkMode()) {
		// Seal with PIN only (no PCRs) and write to file
		OUT_PRINT(L"Sealing and saving recovery to File... ");
		ret = DcTpmSealToFile(
			DC_TPM_SRK_FILE_RECOVERY,
			backupBuffer, backupSize, 
			backupType,
			&backupOptions);
	} 
	else {
		// Seal backup to recovery entry
		OUT_PRINT(L"Sealing recovery to TPM... ");
		ret = gDcsTpm->SealSecret(gDcsTpm, 
			DC_TPM_NV_INDEX_RECOVERY, 
			backupBuffer, backupSize, 
			DC_TPM_SECRET_TYPE_RECOVERY, 
			&backupOptions, NULL, 0);
	}

	MEM_BURN(backupBuffer, sizeof(backupBuffer));
	MEM_BURN(&backupOptions, sizeof(backupOptions));

	if (EFI_ERROR(ret)) {
		ERR_PRINT(L"Failed: %r\n", ret);
	} else {
		OUT_PRINT(L"%VDone.%N\n");
		OUT_PRINT(L"Recovery backup created. Use recovery PIN if PCRs change.\n");
	}
}

//////////////////////////////////////////////////////////////////////////
// TPM Operations (File-based storage mode)
//////////////////////////////////////////////////////////////////////////

/**
Restore secret from TPM-sealed recovery file (PIN-only).

@param[out] password       Buffer to receive password (if plain password type)
@param[out] password_size  Receives password size
@return EFI_SUCCESS on successful restore, EFI_ABORTED if user cancelled
**/
STATIC
EFI_STATUS
DcTpmRestoreFromSrkBackup(
	OUT UINT8   *Data,
	IN UINT32   DataBufferSize,
	OUT UINT32  *DataSize,
	OUT UINT32  *DataType
)
{
	EFI_STATUS       ret;
	UINT8            *sealedBuffer = NULL;
	UINT32           sealedSize = 0;
	UINT8            backupBuffer[DCS_SECRET_DATA_MAX];
	UINT32           backupSize = sizeof(backupBuffer);
	UINT32           dataType = 0;
	CHAR16           recoveryPin[DCS_TPM_OWNER_PWD_MAX];
	UINT32           recoveryPinLen = 0;
	INT32            pwdCode;

	// Read recovery file
	ret = DcFileReadPath(DC_TPM_SRK_FILE_RECOVERY, &sealedBuffer, &sealedSize);
	if (EFI_ERROR(ret)) {
		ERR_PRINT(L"Failed to read TPM sealed backup file: %r\n", ret);
		return ret;
	}

retry:
	OUT_PRINT(L"\n%HTPM recovery file available.%N\n");
	ZeroMem(recoveryPin, sizeof(recoveryPin));
	AskConsolePwdEx("Enter recovery PIN: ", &recoveryPinLen, recoveryPin, &pwdCode, DCS_TPM_OWNER_PWD_MAX - 1, FALSE, TRUE, HandleFuncKeysSimple, NULL, NULL);

	if (pwdCode == AskPwdRetCancel || recoveryPinLen == 0) {
		MEM_BURN(recoveryPin, sizeof(recoveryPin));
		MEM_BURN(sealedBuffer, sealedSize);
		MEM_FREE(sealedBuffer);
		return EFI_ABORTED;
	}

	gDCryptTpmPinUsed = TRUE;  // User interaction - skip countdown

	// Unseal recovery data
	OUT_PRINT(L"Loading secret from recovery file... ");
	backupSize = sizeof(backupBuffer);
	ret = gDcsTpm->SrkUnsealPassword(
		gDcsTpm,
		sealedBuffer, sealedSize,
		backupBuffer, &backupSize, 
		&dataType,
		recoveryPin
	);
	MEM_BURN(recoveryPin, sizeof(recoveryPin));

	if (EFI_ERROR(ret)) {
		ERR_PRINT(L"Failed: %r\n", ret);
		OUT_PRINT(L"Check that recovery PIN is correct.\n");
		goto retry;
	}

	MEM_BURN(sealedBuffer, sealedSize);
	MEM_FREE(sealedBuffer);

	ret = DcApplyBackup(backupBuffer, backupSize, dataType, Data, DataBufferSize, DataSize, DataType);

	MEM_BURN(backupBuffer, sizeof(backupBuffer));
	return ret;
}

///////////////////////////////////////
// Main SRK file-based sealing and loading functions

/**
Helper: Store secret to TPM using SRK (file-based storage).
Seals data to file and offers recovery/backup creation.

@param[in] Data       Secret data to seal
@param[in] DataSize   Size of secret data
@param[in] DataType   Type of secret data
@param[in] Options    Seal options (PCR mask, PIN, etc.)

@retval EFI_SUCCESS   Secret sealed and saved successfully
@retval Other         Error from seal or file operations
**/
STATIC
EFI_STATUS
DcTpmStoreSrk(
	IN UINT8                *Data,
	IN UINT32               DataSize,
	IN UINT32               DataType,
	IN DCS_TPM_SEAL_OPTIONS *Options
)
{
	EFI_STATUS  ret;
	CHAR16     *pinToUse = NULL;

	// Use PIN if configured
	if (Options->Flags & DCS_TPM_OPT_FLAG_USE_PIN) {
		pinToUse = Options->TpmPin;
	}

	OUT_PRINT(L"Sealing and saving to File... ");
	ret = DcTpmSealToFile(
		DC_TPM_SRK_FILE_PRIMARY,
		Data, DataSize, 
		DataType,
		Options);

	if (EFI_ERROR(ret)) {
		ERR_PRINT(L"Failed: %r\n", ret);
		return ret;
	}

	OUT_PRINT(L"%VDone.%N\n");
	OUT_PRINT(L"Sealed data saved to %s\n", DC_TPM_SRK_FILE_PRIMARY);

	AsciiStrCpyS(gDCryptPassword.label, sizeof(gDCryptPassword.label), "TPM Secret");

	return EFI_SUCCESS;
}

/**
Helper: Load secret from TPM using SRK (file-based storage).
Handles file existence check, PCR mismatch recovery, and PIN retry loop.

@param[out] Data          Buffer to receive unsealed data
@param[in] DataBufferSize Size of Data buffer
@param[out] DataSize      Actual size of unsealed data
@param[out] DataType      Type of unsealed data
@param[in] password       Password buffer for recovery fallback
@param[in] password_size  Password size for recovery fallback

@retval EFI_SUCCESS           Secret unsealed successfully
@retval EFI_NOT_FOUND         No sealed file and no backup exists
@retval EFI_DCS_INPUT_REQUIRED Success via recovery, password returned
@retval Other                 Error from TPM operations
**/
STATIC
EFI_STATUS
DcTpmLoadSrk(
	OUT UINT8   *Data,
	IN UINT32   DataBufferSize,
	OUT UINT32  *DataSize,
	OUT UINT32  *DataType
)
{
	EFI_STATUS  ret;
	UINT8       *sealedBuffer = NULL;
	UINT32      sealedSize = 0;
	UINT32      pcrMask = 0;
	UINT32      srkStatus = 0;
	UINT32      flags = 0;
	BOOLEAN     pinRequired = FALSE;
	CHAR16      tpmPin[DCS_TPM_OWNER_PWD_MAX];
	CHAR16     *pinToUse = NULL;
	UINT32      pinLen = 0;
	INT32       pwdCode;

	// Check if sealed file exists
	if (!DcFileExistsPath(DC_TPM_SRK_FILE_PRIMARY)) {
		// No primary file - check if recovery file exists
		if (DcFileExistsPath(DC_TPM_SRK_FILE_RECOVERY)) {
			OUT_PRINT(L"No primary TPM secret file, but recovery file available.\n");
			if (AskYesNo(L"%HRestore from recovery file?%N [Y/n]: ", TRUE)) {
				return DcTpmRestoreFromSrkBackup(Data, DataBufferSize, DataSize, DataType);
			}
		}
		if (gConfigDebug) {
			OUT_PRINT(L"No TPM secret file present.\n");
		}
		return EFI_NOT_FOUND;
	}

	// Read sealed file
	ret = DcFileReadPath(DC_TPM_SRK_FILE_PRIMARY, &sealedBuffer, &sealedSize);
	if (EFI_ERROR(ret)) {
		ERR_PRINT(L"Failed to read TPM sealed file: %r\n", ret);
		return ret;
	}

	// Check PCR mask and status
	ret = gDcsTpm->SrkGetStatus(gDcsTpm, sealedBuffer, sealedSize, &srkStatus, &pcrMask, &flags, NULL, NULL);
	if (EFI_ERROR(ret)) {
		MEM_BURN(sealedBuffer, sealedSize);
		MEM_FREE(sealedBuffer);
		return ret;
	}

	pinRequired = (flags & DC_TPM_FLAG_PIN_REQUIRED) != 0;

	// Handle PCR mismatch (locked state)
	if (srkStatus & DCS_TPM_STATUS_LOCKED) {
		BOOLEAN recoveryFileExists = DcFileExistsPath(DC_TPM_SRK_FILE_RECOVERY);

		ERR_PRINT(L"TPM sealed file locked (PCR mismatch)\n");
		MEM_BURN(sealedBuffer, sealedSize);
		MEM_FREE(sealedBuffer);

		// Try TPM recovery file first (PIN-only, no PCRs)
		if (recoveryFileExists) {
			ret = DcTpmRestoreFromSrkBackup(Data, DataBufferSize, DataSize, DataType);
			if (!EFI_ERROR(ret)) {
				return ret;
			}
		}

		return EFI_ACCESS_DENIED;
	}

retry:
	// PIN retry loop
	ZeroMem(tpmPin, sizeof(tpmPin));
	// Prompt for PIN if required
	if (pinRequired && pinToUse == NULL) {
		AskConsolePwdEx("Enter TPM PIN: ", &pinLen, tpmPin, &pwdCode, DCS_TPM_OWNER_PWD_MAX - 1, FALSE, TRUE, HandleFuncKeysSimple, NULL, NULL);
		if (pwdCode == AskPwdRetCancel) {
			MEM_BURN(sealedBuffer, sealedSize);
			MEM_FREE(sealedBuffer);
			return EFI_ABORTED;
		}
		if (pinLen > 0) {
			pinToUse = tpmPin;
			gDCryptTpmPinUsed = TRUE;
		} else {
			ERR_PRINT(L"PIN is required but not provided.\n");
			MEM_BURN(sealedBuffer, sealedSize);
			MEM_FREE(sealedBuffer);
			return EFI_ACCESS_DENIED;
		}
	}

	// Unseal from buffer
	OUT_PRINT(L"Loading secret from TPM (file mode)... ");
	*DataSize = DataBufferSize;
	ret = gDcsTpm->SrkUnsealPassword(
		gDcsTpm,
		sealedBuffer, sealedSize,
		Data, DataSize, DataType,
		pinToUse
	);

	if (!EFI_ERROR(ret)) {
		OUT_PRINT(L"%VSuccess!%N\n");
		goto cleanup;
	}

	ERR_PRINT(L"Failed: %r\n", ret);

	// Retry on wrong PIN
	if (pinToUse != NULL && ret == EFI_ACCESS_DENIED) {
		OUT_PRINT(L"Check that TPM PIN is correct.\n");
		ZeroMem(tpmPin, sizeof(tpmPin));
		pinToUse = NULL;
		goto retry;
	}

cleanup:
	MEM_BURN(sealedBuffer, sealedSize);
	MEM_FREE(sealedBuffer);
	MEM_BURN(tpmPin, sizeof(tpmPin));
	return ret;
}


//////////////////////////////////////////////////////////////////////////
// TPM Operations (NV-based storage mode)
//////////////////////////////////////////////////////////////////////////

/**
Restore secret from NV-based TPM backup (recovery PIN).

@param[out] password       Buffer to receive password (if plain password type)
@param[out] password_size  Receives password size
@return EFI_SUCCESS on successful restore, EFI_ABORTED if user cancelled
**/
STATIC
EFI_STATUS
DcTpmRestoreFromNvBackup(
	OUT UINT8   *Data,
	IN UINT32   DataBufferSize,
	OUT UINT32  *DataSize,
	OUT UINT32  *DataType
)
{
	EFI_STATUS ret;
	CHAR16 recoveryPin[DCS_TPM_OWNER_PWD_MAX];
	UINT32 recoveryPinLen = 0;
	INT32 pwdCode;
	UINT8 backupBuffer[DCS_SECRET_DATA_MAX];
	UINT32 backupSize = sizeof(backupBuffer);
	UINT32 dataType = 0;

retry:
	OUT_PRINT(L"\n%HRecovery entry available.%N\n");
	ZeroMem(recoveryPin, sizeof(recoveryPin));
	AskConsolePwdEx("Enter recovery PIN: ", &recoveryPinLen, recoveryPin, &pwdCode, DCS_TPM_OWNER_PWD_MAX - 1, FALSE, TRUE, HandleFuncKeysSimple, NULL, NULL);

	if (pwdCode == AskPwdRetCancel || recoveryPinLen == 0) {
		MEM_BURN(recoveryPin, sizeof(recoveryPin));
		return EFI_ABORTED;
	}

	gDCryptTpmPinUsed = TRUE;  // User interaction - skip countdown

	// Try to unseal from backup (NvIndex 1)
	OUT_PRINT(L"Loading secret from backup... ");
	backupSize = sizeof(backupBuffer);
	ret = gDcsTpm->UnsealSecret(gDcsTpm, 
		DC_TPM_NV_INDEX_RECOVERY, 
		backupBuffer, &backupSize, 
		&dataType, 
		recoveryPin);
	MEM_BURN(recoveryPin, sizeof(recoveryPin));

	if (EFI_ERROR(ret)) {
		ERR_PRINT(L" Failed: %r\n", ret);
		OUT_PRINT(L"Check that recovery PIN is correct.\n");
		goto retry;
	}

	ret = DcApplyBackup(backupBuffer, backupSize, dataType, Data, DataBufferSize, DataSize, DataType);

	MEM_BURN(backupBuffer, sizeof(backupBuffer));
	return ret;
}

///////////////////////////////////////
// Main NV-based sealing and loading functions

/**
Helper: Store secret to TPM NV storage.
Seals data to NV and offers recovery/backup creation.

@param[in] Data       Secret data to seal
@param[in] DataSize   Size of secret data
@param[in] DataType   Type of secret data
@param[in] Options    Seal options (PCR mask, owner password, etc.)

@retval EFI_SUCCESS   Secret sealed successfully
@retval Other         Error from seal operations
**/
STATIC
EFI_STATUS
DcTpmStoreNv(
	IN UINT8                *Data,
	IN UINT32               DataSize,
	IN UINT32               DataType,
	IN DCS_TPM_SEAL_OPTIONS *Options
)
{
	EFI_STATUS ret;

	if (gDCryptTpmAskOwnerPw == 0) {
		// Try sealing without owner password
		OUT_PRINT(L"Sealing secret to TPM... ");
		ret = gDcsTpm->SealSecret(gDcsTpm, DC_TPM_NV_INDEX_PRIMARY, Data, DataSize, DataType, Options, NULL, 0);
		if (IsAuthError(ret)) {
			// Auth failure - ask for owner password and retry
			OUT_PRINT(L"\n");
			OUT_PRINT(L"Owner authorization required.\n");
			ret = AskOwnerPassword(Options->OwnerPassword);
			if (EFI_ERROR(ret)) {
				return ret;
			}
			OUT_PRINT(L"Sealing secret to TPM... ");
			ret = gDcsTpm->SealSecret(gDcsTpm, DC_TPM_NV_INDEX_PRIMARY, Data, DataSize, DataType, Options, NULL, 0);
		}
	} else {
		// Always ask for owner password (TPM 1.2 or setting enabled)
		OUT_PRINT(L"Sealing secret to TPM... ");
		ret = gDcsTpm->SealSecret(gDcsTpm, DC_TPM_NV_INDEX_PRIMARY, Data, DataSize, DataType, Options, NULL, 0);
	}

	if (EFI_ERROR(ret)) {
		ERR_PRINT(L"Failed: %r\n", ret);
		return ret;
	}

	AsciiStrCpyS(gDCryptPassword.label, sizeof(gDCryptPassword.label), "TPM Secret");
	OUT_PRINT(L"%VDone.%V\n");

	return EFI_SUCCESS;
}

/**
Helper: Load secret from TPM NV storage.
Handles configuration check, PCR mismatch recovery, and PIN retry loop.

@param[out] Data          Buffer to receive unsealed data
@param[in] DataBufferSize Size of Data buffer
@param[out] DataSize      Actual size of unsealed data
@param[out] DataType      Type of unsealed data
@param[in] password       Password buffer for recovery fallback
@param[in] password_size  Password size for recovery fallback

@retval EFI_SUCCESS           Secret unsealed successfully
@retval EFI_NOT_FOUND         No secret configured and no backup exists
@retval EFI_DCS_INPUT_REQUIRED Success via recovery, password returned
@retval Other                 Error from TPM operations
**/
STATIC
EFI_STATUS
DcTpmLoadNv(
	OUT UINT8   *Data,
	IN UINT32   DataBufferSize,
	OUT UINT32  *DataSize,
	OUT UINT32  *DataType
)
{
	EFI_STATUS  ret;
	UINT32      status = 0;
	BOOLEAN     pinRequired = FALSE;
	CHAR16      tpmPin[DCS_TPM_OWNER_PWD_MAX];
	CHAR16     *pinToUse = NULL;
	UINT32      pinLen = 0;
	INT32       pwdCode;

	gDcsTpm->GetStatus(gDcsTpm, DC_TPM_NV_INDEX_PRIMARY, &status, NULL, NULL, NULL, NULL);

	// Check if configured
	if (!(status & DCS_TPM_STATUS_CONFIGURED)) {
		// No primary entry - check if backup entry exists
		UINT32 backupStatus = 0;
		gDcsTpm->GetStatus(gDcsTpm, DC_TPM_NV_INDEX_RECOVERY, &backupStatus, NULL, NULL, NULL, NULL);

		if (backupStatus & DCS_TPM_STATUS_CONFIGURED) {
			OUT_PRINT(L"No primary TPM secret entry, but recovery entry available.\n");
			if (AskYesNo(L"%HRestore from recovery entry?%N [Y/n]: ", TRUE)) {
				return DcTpmRestoreFromNvBackup(Data, DataBufferSize, DataSize, DataType);
			}
		}
		if (gConfigDebug) {
			OUT_PRINT(L"No TPM secret NV entry configured.\n");
		}
		return EFI_NOT_FOUND;
	}

	// Handle PCR mismatch (locked state)
	if (status & DCS_TPM_STATUS_LOCKED) {
		UINT32 backupStatus = 0;

		ERR_PRINT(L"TPM sealed secret found but locked (PCR mismatch)\n");
		gDcsTpm->GetStatus(gDcsTpm, DC_TPM_NV_INDEX_RECOVERY, &backupStatus, NULL, NULL, NULL, NULL);

		// Try NV backup first if configured
		if (backupStatus & DCS_TPM_STATUS_CONFIGURED) {
			ret = DcTpmRestoreFromNvBackup(Data, DataBufferSize, DataSize, DataType);
			if (!EFI_ERROR(ret)) {
				return ret;
			}
		}

		return EFI_ACCESS_DENIED;
	}

	pinRequired = (status & DCS_TPM_STATUS_PIN_REQUIRED) != 0;

retry:
	// PIN retry loop
	ZeroMem(tpmPin, sizeof(tpmPin));
	// Prompt for PIN if required
	if (pinRequired && pinToUse == NULL) {
		AskConsolePwdEx("Enter TPM PIN: ", &pinLen, tpmPin, &pwdCode, DCS_TPM_OWNER_PWD_MAX - 1, FALSE, TRUE, HandleFuncKeysSimple, NULL, NULL);
		if (pwdCode == AskPwdRetCancel) {
			return EFI_ABORTED;
		}
		if (pinLen > 0) {
			pinToUse = tpmPin;
			gDCryptTpmPinUsed = TRUE;
		} else {
			ERR_PRINT(L"PIN is required but not provided.\n");
			return EFI_ACCESS_DENIED;
		}
	}

	// Load password from NV
	OUT_PRINT(L"Loading secret from TPM... ");
	*DataSize = DataBufferSize;
	ret = gDcsTpm->UnsealSecret(gDcsTpm, DC_TPM_NV_INDEX_PRIMARY, Data, DataSize, DataType, pinToUse);

	if (!EFI_ERROR(ret)) {
		OUT_PRINT(L"%VSuccess!%N\n");
		goto cleanup;
	}

	ERR_PRINT(L" Failed, error: %r\n", ret);

	// Retry on wrong PIN
	if (pinToUse != NULL && ret == EFI_ACCESS_DENIED) {
		OUT_PRINT(L"Check that TPM PIN is correct.\n");
		ZeroMem(tpmPin, sizeof(tpmPin));
		pinToUse = NULL;
		goto retry;
	}

cleanup:
	MEM_BURN(tpmPin, sizeof(tpmPin));
	return ret;
}


//////////////////////////////////////////////////////////////////////////
// Password-Encrypted File Backup
//////////////////////////////////////////////////////////////////////////

// Backup file constants
#define DC_TPM_BACKUP_MAGIC          0x4B424344  // "DCBK"
#define DC_TPM_BACKUP_VERSION        1
#define DC_TPM_BACKUP_FILE_SIZE      1024
#define DC_TPM_BACKUP_ENCRYPTED_OFF  HEADER_SALT_SIZE  // 64
#define DC_TPM_BACKUP_ENCRYPTED_SIZE (DC_TPM_BACKUP_FILE_SIZE - HEADER_SALT_SIZE)  // 960
#define DC_TPM_BACKUP_DATA_SPACE     896         // Space for tpm_backup_data in union
#define DC_TPM_BACKUP_FILE_PATH      L"\\EFI\\DCS\\tpm_backup.dat"

// CRC area: from Version field to end (excluding Magic and Crc itself)
#define DC_TPM_BACKUP_CRC_OFF        8  // Offset within encrypted area (after Magic+Crc)
#define DC_TPM_BACKUP_CRC_SIZE       (DC_TPM_BACKUP_ENCRYPTED_SIZE - DC_TPM_BACKUP_CRC_OFF)  // 952

// Backup file structure (1024 bytes)
// Layout: 64-byte salt (plaintext), 960 bytes XTS-encrypted
#pragma pack(1)
typedef struct _DC_TPM_BACKUP_FILE {
	// Plaintext (64 bytes)
	UINT8    Salt[HEADER_SALT_SIZE];     // 64-byte salt for KDF

	// Everything below is XTS-encrypted (960 bytes)
	UINT32   Magic;                      // DC_TPM_BACKUP_MAGIC - validates decryption
	UINT32   Crc;                        // CRC32 of data from Version onward
	UINT16   Version;                    // DC_TPM_BACKUP_VERSION
	UINT16   BackupSize;
	UINT32   BackupType;
	UINT8    Reserved[48];
	UINT8    Backup[DC_TPM_BACKUP_DATA_SPACE];  // Padding to fixed size (950 bytes)
} DC_TPM_BACKUP_FILE;
#pragma pack()

// Verify structure size at compile time
static_assert(sizeof(DC_TPM_BACKUP_FILE) == DC_TPM_BACKUP_FILE_SIZE, "Invalid DC_TPM_BACKUP_FILE size");

/**
Create a password-encrypted file backup of the sealed secret.
This backup is independent of TPM and can be restored on any machine.
Uses tpm_backup format (same as NV backup) for consistency.

@param[in] Data         The secret data to backup
@param[in] DataSize     Size of the data
@param[in] DataType     Type of the data
@param[in] PrimaryOpts  Primary seal options (contains PCR mask)
**/
STATIC
VOID
DcTpmCreateFileBackup(
	IN VOID                   *Data,
	IN UINT32                 DataSize,
	IN UINT32                 DataType,
	IN DCS_TPM_SEAL_OPTIONS   *PrimaryOpts,
	IN BOOLEAN                RawBackup
)
{
	EFI_STATUS			ret;
	CHAR16				backupPwd[MAX_PASSWORD];
	CHAR16				confirmPwd[MAX_PASSWORD];
	UINT32				bpLen = 0, cpLen = 0;
	INT32				pwdCode = 0;
	DCRYPT_PW_PROMPT	Params = { DCryptPwPromptBackup };
	dc_pass				pass;
	UINT8               dk[PKCS_DERIVE_MAX];
	xts_key             xtsk;
	UINT8               savedSalt[HEADER_SALT_SIZE];
	DC_TPM_BACKUP_FILE  backupFile;
	UINT32              backupSize = sizeof(backupFile.Backup);

	OUT_PRINT(L"\n--- Create Encrypted File Backup ---\n\n");
	OUT_PRINT(L"This backup is protected by a password and stored as a file.\n");
	OUT_PRINT(L"It can be used to recover your secret on any machine.\n\n");

retry:
	// Ask for backup password
	ZeroMem(backupPwd, sizeof(backupPwd));
	AskConsolePwdEx("Enter backup password: ", &bpLen, backupPwd, &pwdCode, MAX_PASSWORD, FALSE, TRUE, HandleFuncKeys, FormatStatus, &Params);

	if (pwdCode == AskPwdRetCancel) {
		OUT_PRINT(L"Backup cancelled.\n");
		MEM_BURN(backupPwd, sizeof(backupPwd));
		return;
	}

	if (bpLen == 0) {
		ERR_PRINT(L"Password cannot be empty. Backup cancelled.\n");
		MEM_BURN(backupPwd, sizeof(backupPwd));
		return;
	}

	// Confirm backup password
	ZeroMem(confirmPwd, sizeof(confirmPwd));
	AskConsolePwdEx("Confirm backup password: ", &cpLen, confirmPwd, &pwdCode, MAX_PASSWORD, FALSE, TRUE, HandleFuncKeysSimple, NULL, NULL);

	if (pwdCode == AskPwdRetCancel) {
		OUT_PRINT(L"Backup cancelled.\n");
		MEM_BURN(backupPwd, sizeof(backupPwd));
		MEM_BURN(confirmPwd, sizeof(confirmPwd));
		return;
	}

	if (bpLen != cpLen || StrCmp(backupPwd, confirmPwd) != 0) {
		ERR_PRINT(L"Passwords do not match. Please try again.\n");
		goto retry;
	}
	MEM_BURN(confirmPwd, sizeof(confirmPwd));

	ret = DCFinalizePassword(&pass, backupPwd, bpLen, Params.KeyFile, 0, NULL, 0);
	MEM_BURN(backupPwd, sizeof(backupPwd));

	if (EFI_ERROR(ret)) {
		ERR_PRINT(L"Failed to finalize backup password: %r\n", ret);
		return;
	}

	OUT_PRINT(L"Creating encrypted backup... ");

	// Initialize backup structure
	ZeroMem(&backupFile, sizeof(backupFile));

	// Generate random salt using TPM or RNG
	if (gDcsTpm != NULL && gDcsTpm->GetRandom != NULL) {
		ret = gDcsTpm->GetRandom(gDcsTpm, HEADER_SALT_SIZE, backupFile.Salt);
	} else {
		ret = EFI_UNSUPPORTED;
	}
	if (EFI_ERROR(ret)) {
		// Fallback: use system RNG if available
		ERR_PRINT(L"Warning: Could not get TPM random (%r), using fallback.\n", ret);
		for (UINTN i = 0; i < HEADER_SALT_SIZE; i++) {
			backupFile.Salt[i] = (UINT8)(i ^ 0xAA);  // Weak fallback
		}
	}

	// Save salt before encryption (will be restored after XTS encryption)
	CopyMem(savedSalt, backupFile.Salt, HEADER_SALT_SIZE);

	// Derive encryption key using configured KDF
	if (!dc_derive_key(&pass, gDCryptHeaderKdf < 0 ? KDF_ARGON_DEFAULT : gDCryptHeaderKdf, backupFile.Salt, dk)) {
		ERR_PRINT(L"Key derivation failed.\n");
		ret = EFI_DEVICE_ERROR;
		goto finish;
	}

	// Fill backup structure using tpm_backup format (same as NV backup)
	backupFile.Version = DC_TPM_BACKUP_VERSION;
	ret = DcPrepBackup(Data, DataSize, DataType, PrimaryOpts, backupFile.Backup, &backupSize, &backupFile.BackupType, NULL, RawBackup);
	backupFile.BackupSize = (UINT16)backupSize;

	// Calculate CRC of data from Version onward (excluding Magic and Crc fields)
	backupFile.Crc = crc32((const unsigned char *)&backupFile.Version, DC_TPM_BACKUP_CRC_SIZE);

	// Set magic (validates successful decryption)
	backupFile.Magic = DC_TPM_BACKUP_MAGIC;

	// Initialize XTS and encrypt entire buffer from offset 0 (like dc_header)
	xts_set_key(dk, CF_AES, &xtsk);
	xts_encrypt((UINT8 *)&backupFile, (UINT8 *)&backupFile, DC_TPM_BACKUP_FILE_SIZE, 0, &xtsk);

	// Restore salt (must remain in plaintext)
	CopyMem(backupFile.Salt, savedSalt, HEADER_SALT_SIZE);

	// Secure cleanup of key material
	MEM_BURN(dk, sizeof(dk));
	MEM_BURN(&xtsk, sizeof(xtsk));
	MEM_BURN(savedSalt, sizeof(savedSalt));

	// Write backup file
	DcFileWritePath(DC_TPM_BACKUP_FILE_PATH, (UINT8*)&backupFile, DC_TPM_BACKUP_FILE_SIZE);
	
finish:
	MEM_BURN(&pass, sizeof(pass));
	MEM_BURN(&backupFile, sizeof(backupFile));

	if (!EFI_ERROR(ret)) {
		OUT_PRINT(L"%VDone.%N\n");
		OUT_PRINT(L"Backup saved to %s\n", DC_TPM_BACKUP_FILE_PATH);
	} else {
		ERR_PRINT(L"Failed: %r\n", ret);
	}
}

/**
Restore secret from encrypted file backup.
Uses zero-knowledge decryption: tries all KDF/cipher combinations.
Handles tpm_backup format (same as NV backup).

@param[out] password       Buffer to receive password (if plain password type)
@param[out] password_size  Receives password size
@return EFI_SUCCESS on successful restore, EFI_ABORTED if user cancelled
**/
STATIC
EFI_STATUS
DcTpmRestoreFromFileBackup(
	OUT UINT8   *Data,
	IN UINT32   DataBufferSize,
	OUT UINT32  *DataSize,
	OUT UINT32  *DataType
)
{
	EFI_STATUS			ret;
	CHAR16				backupPwd[MAX_PASSWORD];
	UINT32				bpLen = 0;
	INT32				bpCode = 0;
	DCRYPT_PW_PROMPT	Params = { DCryptPwPromptBackup };
	dc_pass				pass;
	DC_TPM_BACKUP_FILE	backupFile;
	UINT8               dk[PKCS_DERIVE_MAX];
	xts_key             xtsk;
	INT32               kdf;
	INT32               cipher;
	UINT32              calculatedCrc;
	UINT8*				fileData = NULL;
	UINT32              fileSize = 0;
	int					*kdfs;
	int                 oneKdf[] = { 0, -1 };

	if (gDCryptHeaderKdf == KDF_ALL) {
		kdfs = (int*)dc_all_kdfs;
	}
	else if (gDCryptHeaderKdf == KDF_DEFAULT) {
		kdfs = (int*)dc_default_kdfs;
	}
	else {
		oneKdf[0] = gDCryptHeaderKdf;
		kdfs = oneKdf;
	}

	OUT_PRINT(L"\n%HEncrypted file backup available.%N\n");
	ZeroMem(backupPwd, sizeof(backupPwd));
retry:
	AskConsolePwdEx("Backup password: ", &bpLen, backupPwd, &bpCode, MAX_PASSWORD, FALSE, TRUE, HandleFuncKeys, FormatStatus, &Params);

	if (bpCode == AskPwdRetCancel || bpLen == 0) {
		ret = EFI_ABORTED;
		goto finish;
	}

	ret = DCFinalizePassword(&pass, backupPwd, bpLen, Params.KeyFile, 0, NULL, 0);

	if (EFI_ERROR(ret)) {
		ERR_PRINT(L"Failed to finalize backup password: %r\n", ret);
		goto finish;
	}

	// Read backup file
	ret = DcFileReadPath(DC_TPM_BACKUP_FILE_PATH, &fileData, &fileSize);
	if (EFI_ERROR(ret)) {
		ERR_PRINT(L"Failed to read backup file: %r\n", ret);
		goto finish;
	}
	if (fileSize < DC_TPM_BACKUP_FILE_SIZE || fileData == NULL) {
		if (fileData) MEM_FREE(fileData);
		ERR_PRINT(L"Invalid backup file size: expected %d, got %d\n", DC_TPM_BACKUP_FILE_SIZE, fileSize);
		ret = EFI_COMPROMISED_DATA;
		goto finish;
	}

	OUT_PRINT(L"Decrypting backup... ");
	ret = EFI_ACCESS_DENIED;

	// Try all KDF/cipher combinations
	for (INT32 kdfIdx = 0; kdfs[kdfIdx] != -1; kdfIdx++) {
		kdf = kdfs[kdfIdx];

		// Derive key with this KDF (using plaintext salt from backup)
		if (!dc_derive_key(&pass, kdf, fileData, dk)) {
			continue;  // KDF failed, try next
		}

		// Only use CF_AES - that's what we encrypt with
		cipher = CF_AES;

		// Setup XTS with AES cipher
		xts_set_key(dk, cipher, &xtsk);

		// Decrypt entire buffer from offset 0 (like dc_header), salt area becomes garbage
		xts_decrypt((UINT8*)fileData, (UINT8*)&backupFile, DC_TPM_BACKUP_FILE_SIZE, 0, &xtsk);

		// Check magic
		if (backupFile.Magic != DC_TPM_BACKUP_MAGIC) {
			continue;  // Wrong key, try next KDF
		}

		// Check CRC
		calculatedCrc = crc32((const unsigned char*)&backupFile.Version, DC_TPM_BACKUP_CRC_SIZE);
		if (calculatedCrc != backupFile.Crc) {
			continue;  // CRC mismatch, try next KDF
		}

		// Success
		ret = EFI_SUCCESS;
		break;
	}

	if (EFI_ERROR(ret)) {
		ERR_PRINT(L"Wrong Wassword.\n");
		OUT_PRINT(L"Check that backup password is correct.\n");
		goto retry;
	}
	
	// Success! Validate data size
	if (backupFile.BackupSize > DC_TPM_BACKUP_DATA_SPACE) {
		ERR_PRINT(L"Invalid backup data size: %d\n", backupFile.BackupSize);
		ret = EFI_COMPROMISED_DATA;
		goto finish;
	}

	ret = DcApplyBackup(backupFile.Backup, backupFile.BackupSize, backupFile.BackupType, Data, DataBufferSize, DataSize, DataType);

finish:
	MEM_BURN(backupPwd, sizeof(backupPwd));

	MEM_BURN(&pass, sizeof(pass));
	MEM_BURN(dk, PKCS_DERIVE_MAX);
	MEM_BURN(&xtsk, sizeof(xtsk));

	MEM_BURN(&backupFile, sizeof(backupFile));
	return ret;
}


//////////////////////////////////////////////////////////////////////////
// TPM Main Flow
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
DcTpmStore(VOID)
{
	EFI_STATUS               ret;
	UINT8                    data[DCS_SECRET_DATA_MAX];
	UINT32                   dataSize = sizeof(data);
	UINT32                   dataType = 0;
	DCS_TPM_SEAL_OPTIONS     options;
	tpm_secret*              secret = (tpm_secret*)data;
	CHAR16                   password[MAX_PASSWORD];
	UINT32                   password_size = 0;
	INT32                    pwdCode = 0;
	CHAR16                   confirmPassword[MAX_PASSWORD];
	UINT32                   confirmSize = 0;
	INT32                    confirmCode = 0;
	BOOLEAN                  useRandomSecret;
	DCRYPT_PW_PROMPT         Params = { DCryptPwPromptTpmSecret };

	Params.KeyFile = DCryptPlatform;

	if (!gDcsTpm) {
		return EFI_UNSUPPORTED;
	}

	RED_PRINT(L"--- Seal Secret to TPM ---\n\n");

	// Ask user whether to generate random secret or enter manually
	OUT_PRINT(L"A random secret provides maximum security and is recommended.\n");
	OUT_PRINT(L"Manual entry allows using an existing password/keyfile combination.\n\n");
	useRandomSecret = AskYesNo(L"%HGenerate random secret?%N [Y/n]: ", TRUE);

	memset(data, 0, sizeof(data));

	if (useRandomSecret) {

		dataType = DC_TPM_SECRET_TYPE_1;

		// Generate random secret
		OUT_PRINT(L"\nGenerating random secret... ");

		ret = gDcsTpm->GetRandom(gDcsTpm, DC_KF_HASH_SIZE, secret->SecretData);
		if (EFI_ERROR(ret)) {
			ERR_PRINT(L"Failed to generate random data: %r\n", ret);
			return ret;
		}
		OUT_PRINT(L"%VDone.%N\n");

		secret->Flags = 0;
		secret->SecretSize = DC_KF_HASH_SIZE;
		secret->Kdf = gDCryptHeaderKdf;
		secret->Slot = -KEY_SLOT_COUNT;

		// Check if password should also be required
		if (gDCryptTpmMode & DCryptTpmPass) {
			secret->Flags |= DC_TPM_FLAG_REQ_PASS;
			OUT_PRINT(L"Password will be required in addition to the TPM secret.\n");
		}

		// Copy to global TPM secret
		memcpy(gDCryptTpmSecret, secret->SecretData, DC_KF_HASH_SIZE);
		gDCryptTpmSecretValid = TRUE;

		dataSize = sizeof(tpm_secret) + secret->SecretSize;

		OUT_PRINT(L"\nThis random secret will be sealed to TPM and used as a virtual key file.\n");
	} 
	else {

		// Manual password entry
		OUT_PRINT(L"\n");

		// Prompt for password
		ZeroMem(password, sizeof(password));
		AskConsolePwdEx("Enter secret: ", &password_size, password, &pwdCode, MAX_PASSWORD, gPasswordVisible, TRUE, HandleFuncKeys, FormatStatus, &Params);

		if (pwdCode == AskPwdRetCancel) {
			MEM_BURN(password, sizeof(password));
			return EFI_ABORTED;
		}

		if (password_size == 0) {
			ERR_PRINT(L"Secret cannot be empty.\n");
			MEM_BURN(password, sizeof(password));
			return EFI_INVALID_PARAMETER;
		}

		// Password confirmation
		ZeroMem(confirmPassword, sizeof(confirmPassword));
		AskConsolePwdEx("Confirm secret: ", &confirmSize, confirmPassword, &confirmCode, MAX_PASSWORD, gPasswordVisible, TRUE, HandleFuncKeysSimple, NULL, NULL);

		if (confirmCode == AskPwdRetCancel) {
			MEM_BURN(password, sizeof(password));
			MEM_BURN(confirmPassword, sizeof(confirmPassword));
			return EFI_ABORTED;
		}

		if (confirmSize != password_size || CompareMem(password, confirmPassword, password_size) != 0) {
			ERR_PRINT(L"Secrets do not match.\n");
			MEM_BURN(password, sizeof(password));
			MEM_BURN(confirmPassword, sizeof(confirmPassword));
			return EFI_INVALID_PARAMETER;
		}

		MEM_BURN(confirmPassword, sizeof(confirmPassword));

		if (Params.KeyFile != DCryptNo) {

			dc_pass tempPass;

			dataType = DC_TPM_SECRET_TYPE_1;

			if (gDCryptTpmMode & DCryptTpmPass) {
				secret->Flags |= DC_TPM_FLAG_REQ_PASS;
				OUT_PRINT(L"Password will be required in addition to the TPM secret.\n");
			}

			// Finalize password into temp structure
			memset(&tempPass, 0, sizeof(tempPass));
			ret = DCFinalizePassword(&tempPass, password, password_size, Params.KeyFile, 0, NULL, 0);
			if (EFI_ERROR(ret)) {
				ERR_PRINT(L"Failed to finalize password, error: %r\n", ret);
				MEM_BURN(password, sizeof(password));
				return ret;
			}

			if (tempPass.size != DC_KF_HASH_SIZE) {
				ERR_PRINT(L"Finalized password size is invalid\n");
				MEM_BURN(password, sizeof(password));
				MEM_BURN(&tempPass, sizeof(tempPass));
				return EFI_INVALID_PARAMETER;
			}

			secret->SecretSize = (UINT16)tempPass.size;
			memcpy(secret->SecretData, tempPass.pass, tempPass.size);
			secret->Kdf = gDCryptHeaderKdf;
			secret->Slot = -KEY_SLOT_COUNT;

			// Also set global TPM secret
			memcpy(gDCryptTpmSecret, tempPass.pass, DC_KF_HASH_SIZE);
			gDCryptTpmSecretValid = TRUE;

			MEM_BURN(&tempPass, sizeof(tempPass));

			dataSize = sizeof(tpm_secret) + secret->SecretSize;

			OUT_PRINT(L"This will store your disk decryption secret in TPM.\n");
			OUT_PRINT(L"The key file will be combined with the password as a second virtual key file.\n");
		} 
		else {

			// Plain password
			memcpy(data, password, password_size);
			dataSize = password_size;

			OUT_PRINT(L"This will store your disk decryption password in the TPM.\n"
				L"%HNot recommended%N - combine the password with a key file (salt) instead.\n");
		}

		MEM_BURN(password, sizeof(password));
	}

	OUT_PRINT(L"\nThe secret can only be retrieved if boot chain is unchanged.\n");

	// Get TPM seal options (PCR mask and optional PIN)
	ret = GetSealOptions(&options, gDCryptTpmAskOwnerPw == 0 ? TRUE : DcTpmStorageUseSrkMode());

	if (EFI_ERROR(ret)) {
		MEM_BURN(data, sizeof(data));
		return ret;
	}

	// Store to appropriate storage mode
	if (DcTpmStorageUseSrkMode()) {
		ret = DcTpmStoreSrk(data, dataSize, dataType, &options);
	} else {
		ret = DcTpmStoreNv(data, dataSize, dataType, &options);
	}

	// Offer to create TPM recovery entry/file only if PCRs are bound
	if (!EFI_ERROR(ret) && options.PcrMask != 0) {
		if (AskYesNo(L"\n%HSetup TPM recovery?%N [y/N]: ", FALSE)) {
			DcTpmCreateBackup(data, dataSize, dataType, &options, FALSE);
		}
	}

	// Offer encrypted file backup (no TPM involvement)
	if (!EFI_ERROR(ret)) {
		if (AskYesNo(L"\n%HCreate encrypted file backup?%N [Y/n]: ", TRUE)) {
			DcTpmCreateFileBackup(data, dataSize, dataType, &options, FALSE);
		}
	}

	// Cleanup
	MEM_BURN(data, sizeof(data));
	MEM_BURN(&options, sizeof(options));

	if (!EFI_ERROR(ret) && (gDCryptTpmMode & DCryptTpmPass)) {
		return EFI_DCS_INPUT_REQUIRED;
	}

	return ret;
}


EFI_STATUS
DcTpmLoad(CHAR16 *password, UINT32 *password_size)
{
	EFI_STATUS     ret;
	UINT8          data[DCS_SECRET_DATA_MAX];
	UINT32         dataSize;
	UINT32         dataType = 0;
	tpm_secret*    secret = (tpm_secret*)data;

	// Check TPM availability
	if (gDcsTpm == NULL) {
		ret = EFI_UNSUPPORTED;
	}
	// Load from appropriate storage mode
	else if (DcTpmStorageUseSrkMode()) {
		ret = DcTpmLoadSrk(data, sizeof(data), &dataSize, &dataType);
	} else {
		ret = DcTpmLoadNv(data, sizeof(data), &dataSize, &dataType);
	}

	// On missing entry or PCR lockout, offer recovery from file backup if available
	if (ret == EFI_UNSUPPORTED || ret == EFI_NOT_FOUND || ret == EFI_ACCESS_DENIED) {
		if (DcFileExistsPath(DC_TPM_BACKUP_FILE_PATH)) {
			gDCryptTpmPinUsed = TRUE;  // User interaction - skip countdown
			ret =  DcTpmRestoreFromFileBackup(data, sizeof(data), &dataSize, &dataType);
		}
	}

	// failure to load from TPM and no backup available or backup failed - return error
	if (EFI_ERROR(ret)) {
		MEM_BURN(data, sizeof(data));
		return ret;
	}

	// Process unsealed data
	if (dataType == 0) {
		// Plain password
		if (dataSize > MAX_PASSWORD * sizeof(CHAR16)) {
			ERR_PRINT(L"Loaded password size is invalid  %d\n", dataSize);
			MEM_BURN(data, sizeof(data));
			return EFI_INVALID_PARAMETER;
		}

		*password_size = dataSize;
		memcpy(password, data, dataSize);

		gDCryptPassword.kdf = gDCryptHeaderKdf;
		gDCryptPassword.slot = -KEY_SLOT_COUNT;
	}
	else if (dataType == DC_TPM_SECRET_TYPE_1) {
		if (secret->SecretSize > DC_KF_HASH_SIZE) {
			ERR_PRINT(L"Loaded secret size is invalid  %d\n", secret->SecretSize);
			MEM_BURN(data, sizeof(data));
			return EFI_INVALID_PARAMETER;
		}

		memcpy(gDCryptTpmSecret, secret->SecretData, DC_KF_HASH_SIZE);
		gDCryptTpmSecretValid = TRUE;

		if (secret->Flags & DC_TPM_FLAG_REQ_PASS)
			ret = EFI_DCS_INPUT_REQUIRED;

		gDCryptPassword.kdf = secret->Kdf;
		gDCryptPassword.slot = secret->Slot;
	}
	else {
		ERR_PRINT(L"Failed, unknown secret type\n");
		MEM_BURN(data, sizeof(data));
		return EFI_INVALID_PARAMETER;
	}

	MEM_BURN(data, sizeof(data));
	return ret;
}


//////////////////////////////////////////////////////////////////////////
// TPM Secret Management Menu
//////////////////////////////////////////////////////////////////////////

// Menu item types (not indices - actual items are built dynamically)
#define TPM_MENU_SAVE           0
#define TPM_MENU_DELETE         1
#define TPM_MENU_LOAD_RECOVERY  2
#define TPM_MENU_LOAD_BACKUP    3
#define TPM_MENU_DELETE_BACKUP  4
#define TPM_MENU_SHOW_PCRS      5
#define TPM_MENU_SHOW_NV        6
#define TPM_MENU_EXIT           7
#define TPM_MENU_TYPE_COUNT     8

static CHAR16 *gTpmMenuLabels[] = {
	L"Save secret to TPM",
	L"Delete TPM secret",
	L"Load from recovery entry",
	L"Load from backup file",
	L"Delete backup file",
	L"Show PCR values",
	L"Show NV indices",
	L"Exit"
};

// Dynamic menu state
static INT32 gTpmMenuItems[TPM_MENU_TYPE_COUNT];  // Maps display index to menu type
static INT32 gTpmMenuCount = 0;

/**
Check if TPM recovery entry is available.
**/
STATIC
BOOLEAN
DcTpmIsRecoveryAvailable(VOID)
{
	if (gDcsTpm == NULL) {
		return FALSE;
	}

	if (DcTpmStorageUseSrkMode()) {
		// File-based mode: check for recovery file
		return DcFileExistsPath(DC_TPM_SRK_FILE_RECOVERY);
	} else {
		// NV-based mode: check NV backup status
		UINT32 backupStatus = 0;
		gDcsTpm->GetStatus(gDcsTpm, DC_TPM_NV_INDEX_RECOVERY, &backupStatus, NULL, NULL, NULL, NULL);
		return (backupStatus & DCS_TPM_STATUS_CONFIGURED) != 0;
	}
}

/**
Check if encrypted file backup is available.
**/
STATIC
BOOLEAN
DcTpmIsBackupAvailable(VOID)
{
	return DcFileExistsPath(DC_TPM_BACKUP_FILE_PATH);
}

/**
Build the dynamic menu based on what's available.
**/
STATIC
VOID
DcTpmBuildMenu(VOID)
{
	gTpmMenuCount = 0;

	// Always available items
	gTpmMenuItems[gTpmMenuCount++] = TPM_MENU_SAVE;
	gTpmMenuItems[gTpmMenuCount++] = TPM_MENU_DELETE;

	// Conditional items - only show if available
	if (DcTpmIsRecoveryAvailable()) {
		gTpmMenuItems[gTpmMenuCount++] = TPM_MENU_LOAD_RECOVERY;
	}
	if (DcTpmIsBackupAvailable()) {
		gTpmMenuItems[gTpmMenuCount++] = TPM_MENU_LOAD_BACKUP;
		gTpmMenuItems[gTpmMenuCount++] = TPM_MENU_DELETE_BACKUP;
	}

	// Always available items
	gTpmMenuItems[gTpmMenuCount++] = TPM_MENU_SHOW_PCRS;
	gTpmMenuItems[gTpmMenuCount++] = TPM_MENU_SHOW_NV;
	gTpmMenuItems[gTpmMenuCount++] = TPM_MENU_EXIT;
}

STATIC
VOID
DcTpmMenuDrawItem(
	INT32   Index,
	INT32   Row,
	BOOLEAN Selected
)
{
	INT32 menuType = gTpmMenuItems[Index];
	gST->ConOut->SetCursorPosition(gST->ConOut, 0, Row);
	if (Selected)
		OUT_PRINT(L"%V> %-30s%N", gTpmMenuLabels[menuType]);
	else
		OUT_PRINT(L"  %-30s", gTpmMenuLabels[menuType]);
}

STATIC
VOID
DcTpmPrintStatus(VOID)
{
	UINT32       status = 0;
	DCS_TPM_INFO info;
	UINT32       pcrMask = 0;

	if (gDcsTpm == NULL) {
		ERR_PRINT(L"TPM: not available\n");
		return;
	}

	// Get TPM info
	if (!EFI_ERROR(gDcsTpm->GetInfo(gDcsTpm, &info))) {
		OUT_PRINT(L"TPM Version: ");
		if (info.TpmVersion >= 0x200) {
			OUT_PRINT(L"%V2.0%N");
			// Show manufacturer if available
			if (info.Manufacturer[0] != '\0') {
				OUT_PRINT(L" (%a)", info.Manufacturer);
			}
			// Show firmware version
			if (info.FirmwareVersion1 != 0 || info.FirmwareVersion2 != 0) {
				OUT_PRINT(L" FW: %d.%d.%d.%d",
					(info.FirmwareVersion1 >> 16) & 0xFFFF, info.FirmwareVersion1 & 0xFFFF,
					(info.FirmwareVersion2 >> 16) & 0xFFFF, info.FirmwareVersion2 & 0xFFFF);
			}
			OUT_PRINT(L"\n");
		} else {
			OUT_PRINT(L"%V1.2%N\n");
		}
	}

	// Show storage mode
	OUT_PRINT(L"Storage: %V%s%N\n",
		DcTpmStorageUseSrkMode()
		? L"EFI Partition (TPM-Sealed)"
		: L"TPM NV Memory");

	// File-based storage mode
	if (DcTpmStorageUseSrkMode()) {
		UINT8   *sealedBuffer = NULL;
		UINT32  sealedSize = 0;
		BOOLEAN isOpen;

		OUT_PRINT(L"Secret: ");
		if (DcFileExistsPath(DC_TPM_SRK_FILE_PRIMARY)) {
			// Read sealed file to check status
			if (!EFI_ERROR(DcFileReadPath(DC_TPM_SRK_FILE_PRIMARY, &sealedBuffer, &sealedSize))) {
				OUT_PRINT(L"%Vconfigured%N, ");

				// Check status and PCR mask
				{
					UINT32 srkStatus = 0;
					UINT32 flags = 0;
					if (!EFI_ERROR(gDcsTpm->SrkGetStatus(gDcsTpm, sealedBuffer, sealedSize, &srkStatus, &pcrMask, &flags, NULL, NULL))) {
						// Check if PCRs match
						isOpen = !(srkStatus & DCS_TPM_STATUS_LOCKED);
						if (isOpen) {
							OUT_PRINT(L"%Vopen%N\n");
						} else {
							ERR_PRINT(L"locked (PCR mismatch)\n");
						}

						OUT_PRINT(L"PCR Mask: 0x%03x\n", pcrMask);
						if (flags & DC_TPM_FLAG_PIN_REQUIRED) {
							OUT_PRINT(L"TPM PIN: %Vrequired%N\n");
						}
					} else {
						ERR_PRINT(L"status error\n");
					}
				}

				MEM_BURN(sealedBuffer, sealedSize);
				MEM_FREE(sealedBuffer);

				// Show recovery file status
				if (DcFileExistsPath(DC_TPM_SRK_FILE_RECOVERY)) {
					OUT_PRINT(L"Recovery: %Vavailable%N\n");
				}
			} else {
				ERR_PRINT(L"file read error\n");
				OUT_PRINT(L"PCR Mask: 0x%03x\n", gDCryptTpmPcrMask);
			}
		} else {
			ERR_PRINT(L"not configured\n");
			OUT_PRINT(L"PCR Mask: 0x%03x\n", gDCryptTpmPcrMask);
		}
	}
	// NV-based storage mode
	else {
		// Get secret status from NV (also get pcrMask in one call)
		if (EFI_ERROR(gDcsTpm->GetStatus(gDcsTpm, DC_TPM_NV_INDEX_PRIMARY, &status, &pcrMask, NULL, NULL, NULL))) {
			ERR_PRINT(L"TPM: error getting status\n");
			return;
		}

		OUT_PRINT(L"Secret: ");
		if (status & DCS_TPM_STATUS_CONFIGURED) {
			UINT32 backupStatus = 0;

			OUT_PRINT(L"%Vconfigured%N, ");
			if (status & DCS_TPM_STATUS_LOCKED) {
				ERR_PRINT(L"locked (PCR mismatch)\n");
			} else {
				OUT_PRINT(L"%Vopen%N\n");
			}

			// Show PCR mask
			OUT_PRINT(L"PCR Mask: 0x%03x\n", pcrMask);

			// Show PIN required status
			if (status & DCS_TPM_STATUS_PIN_REQUIRED) {
				OUT_PRINT(L"TPM PIN: %Vrequired%N\n");
			}

			// Show backup status by querying index 1
			gDcsTpm->GetStatus(gDcsTpm, DC_TPM_NV_INDEX_RECOVERY, &backupStatus, NULL, NULL, NULL, NULL);
			if (backupStatus & DCS_TPM_STATUS_CONFIGURED) {
				OUT_PRINT(L"Recovery: %Vavailable%N\n");
			}
		} else {
			ERR_PRINT(L"not configured\n");
			OUT_PRINT(L"PCR Mask: 0x%03x\n", gDCryptTpmPcrMask);
		}
	}

	// Show file backup status (common to both modes)
	if (DcFileExistsPath(DC_TPM_BACKUP_FILE_PATH)) {
		OUT_PRINT(L"File Backup: %Vavailable%N\n");
	}

	// Show lockout info for TPM 2.0
	if (info.TpmVersion >= 0x200) {
		OUT_PRINT(L"Lockout: ");
		if (info.LockoutCounter > 0) {
			ERR_PRINT(L"%d failed attempts", info.LockoutCounter);
			if (info.LockoutInterval > 0) {
				OUT_PRINT(L" (recovery: %d sec)", info.LockoutInterval);
			}
			OUT_PRINT(L"\n");
		} else {
			OUT_PRINT(L"%Vnone%N\n");
		}
	}
}

/**
Delete TPM secret and all associated backups.
**/
STATIC
VOID
DcTpmMenuDoDelete(VOID)
{
	EFI_STATUS ret;
	UINT32 status = 0;

	// Check for existing secret based on storage mode
	if (DcTpmStorageUseSrkMode()) {
		// File-based mode: check for sealed file
		if (!DcFileExistsPath(DC_TPM_SRK_FILE_PRIMARY)) {
			OUT_PRINT(L"No sealed secret file found.\n");
			return;
		}
	} else {
		// NV-based mode: check TPM status
		ret = gDcsTpm->GetStatus(gDcsTpm, DC_TPM_NV_INDEX_PRIMARY, &status, NULL, NULL, NULL, NULL);
		if (EFI_ERROR(ret) || !(status & DCS_TPM_STATUS_CONFIGURED)) {
			OUT_PRINT(L"No sealed secret found.\n");
			return;
		}
	}

	if (!AskYesNo(L"\n%ORemove sealed Secret from TPM?%N [Y/n]: ", TRUE)) {
		return;
	}

	CHAR16 ownerPwd[DCS_TPM_OWNER_PWD_MAX];
	ZeroMem(ownerPwd, sizeof(ownerPwd));

	// Handle file-based storage mode
	if (DcTpmStorageUseSrkMode()) {
		OUT_PRINT(L"Deleting sealed file... ");
		ret = DcFileDeletePath(DC_TPM_SRK_FILE_PRIMARY);
		if (!EFI_ERROR(ret)) {
			OUT_PRINT(L"%VDone.%N\n");
			gDCryptTpmSecretValid = FALSE;
			MEM_BURN(gDCryptTpmSecret, sizeof(gDCryptTpmSecret));
		} else {
			ERR_PRINT(L"Failed: %r\n", ret);
		}

		// Delete recovery file if it exists
		if (DcFileExistsPath(DC_TPM_SRK_FILE_RECOVERY)) {
			OUT_PRINT(L"Deleting recovery file... ");
			ret = DcFileDeletePath(DC_TPM_SRK_FILE_RECOVERY);
			if (!EFI_ERROR(ret)) {
				OUT_PRINT(L"%VDone.%N\n");
			} else {
				ERR_PRINT(L"Failed: %r\n", ret);
			}
		}
	}
	// Handle NV-based storage mode
	else {
		if (gDCryptTpmAskOwnerPw == 0) {
			// Try without owner password first
			OUT_PRINT(L"Deleting secret from TPM... ");
			ret = gDcsTpm->ClearSecret(gDcsTpm, DC_TPM_NV_INDEX_PRIMARY, ownerPwd);
			if (IsAuthError(ret)) {
				// Auth failure - ask for owner password and retry
				OUT_PRINT(L"\n");
				OUT_PRINT(L"Owner authorization required.\n");
				gDCryptTpmAskOwnerPw = 2;
			}
		}

		if (gDCryptTpmAskOwnerPw != 0) {
			// Always ask for owner password
			ret = AskOwnerPassword(ownerPwd);
			if (EFI_ERROR(ret)) {
				MEM_BURN(ownerPwd, sizeof(ownerPwd));
				return;
			}
			OUT_PRINT(L"Deleting secret from TPM... ");
			ret = gDcsTpm->ClearSecret(gDcsTpm, DC_TPM_NV_INDEX_PRIMARY, ownerPwd);
		}

		if (!EFI_ERROR(ret)) {
			OUT_PRINT(L"%VDone.%N\n");
			gDCryptTpmSecretValid = FALSE;
			MEM_BURN(gDCryptTpmSecret, sizeof(gDCryptTpmSecret));
		} else {
			ERR_PRINT(L"Failed: %r\n", ret);
		}

		// Clear NV Backup
		UINT32 backupStatus = 0;
		gDcsTpm->GetStatus(gDcsTpm, DC_TPM_NV_INDEX_RECOVERY, &backupStatus, NULL, NULL, NULL, NULL);
		if (backupStatus & DCS_TPM_STATUS_CONFIGURED) {
			OUT_PRINT(L"Deleting NV backup... ");
			ret = gDcsTpm->ClearSecret(gDcsTpm, DC_TPM_NV_INDEX_RECOVERY, ownerPwd);
			if (!EFI_ERROR(ret)) {
				OUT_PRINT(L"%VDone.%N\n");
			} else {
				ERR_PRINT(L"Failed: %r\n", ret);
			}
		}
	}

	MEM_BURN(ownerPwd, sizeof(ownerPwd));
}

/**
Delete encrypted backup file (non-TPM).
**/
STATIC
VOID
DcTpmMenuDoDeleteBackup(VOID)
{
	EFI_STATUS ret;

	if (!DcFileExistsPath(DC_TPM_BACKUP_FILE_PATH)) {
		OUT_PRINT(L"No backup file found.\n");
		return;
	}

	if (!AskYesNo(L"\n%ODelete encrypted backup file?%N [Y/n]: ", TRUE)) {
		return;
	}

	OUT_PRINT(L"Deleting backup file... ");
	ret = DcFileDeletePath(DC_TPM_BACKUP_FILE_PATH);
	if (!EFI_ERROR(ret)) {
		OUT_PRINT(L"%VDone.%N\n");
	} else {
		ERR_PRINT(L"Failed: %r\n", ret);
	}
}

/**
Load secret from recovery entry or backup file.

@param[in] IsBackup  TRUE to load from backup file, FALSE to load from recovery entry
**/
STATIC
VOID
DcTpmMenuDoLoadBackup(
	IN BOOLEAN IsBackup
)
{
	EFI_STATUS ret;
	UINT8      data[DCS_SECRET_DATA_MAX];
	UINT32     dataSize = sizeof(data);
	UINT32     dataType = 0;

	OUT_PRINT(L"--- Load from %s ---\n\n", IsBackup ? L"Backup File" : L"Recovery Entry");

	if (IsBackup) {
		ret = DcTpmRestoreFromFileBackup(data, sizeof(data), &dataSize, &dataType);
	} 
	else if (DcTpmStorageUseSrkMode()) {
		ret = DcTpmRestoreFromSrkBackup(data, sizeof(data), &dataSize, &dataType);
	} else {
		ret = DcTpmRestoreFromNvBackup(data, sizeof(data), &dataSize, &dataType);
	}

	if (!EFI_ERROR(ret)) {
		// Process the recovered secret (same as DcTpmLoad)
		if (dataType == 0) {
			OUT_PRINT(L"Plain password recovered - reboot to load.\n");
		} 
		else if (dataType == DC_TPM_SECRET_TYPE_1) {
			tpm_secret *secret = (tpm_secret *)data;
			if (secret->SecretSize <= DC_KF_HASH_SIZE) {
				memcpy(gDCryptTpmSecret, secret->SecretData, DC_KF_HASH_SIZE);
				gDCryptTpmSecretValid = TRUE;
				gDCryptPassword.kdf = secret->Kdf;
				gDCryptPassword.slot = secret->Slot;
				OUT_PRINT(L"TPM secret recovered and activated.\n");
			}
		}
	} else if (ret != EFI_ABORTED) {
		ERR_PRINT(L"%s failed %r\n", ret);
	}

	MEM_BURN(data, sizeof(data));
}

// Returns TRUE to exit menu, FALSE to stay
STATIC
BOOLEAN
DcTpmMenuExecute(
	INT32 Selection
)
{
	EFI_STATUS ret;
	INT32 menuType = gTpmMenuItems[Selection];
	// Clear Screen
	gST->ConOut->ClearScreen(gST->ConOut);

	switch (menuType) {
	case TPM_MENU_SAVE:
		ret = DcTpmStore();
		if (ret == EFI_ABORTED) {
			return FALSE; // User cancelled
		}
		if (EFI_ERROR(ret)) {
			ERR_PRINT(L"An error occured: %r\n", ret);
		}
		OUT_PRINT(L"\nPress any key to continue...\n");
		GetKey();
		return FALSE;

	case TPM_MENU_DELETE:
		DcTpmMenuDoDelete();
		OUT_PRINT(L"\nPress any key to continue...\n");
		GetKey();
		return FALSE;

	case TPM_MENU_LOAD_RECOVERY:
		DcTpmMenuDoLoadBackup(FALSE);
		OUT_PRINT(L"\nPress any key to continue...\n");
		GetKey();
		return FALSE;

	case TPM_MENU_LOAD_BACKUP:
		DcTpmMenuDoLoadBackup(TRUE);
		OUT_PRINT(L"\nPress any key to continue...\n");
		GetKey();
		return FALSE;

	case TPM_MENU_DELETE_BACKUP:
		DcTpmMenuDoDeleteBackup();
		OUT_PRINT(L"\nPress any key to continue...\n");
		GetKey();
		return FALSE;

	case TPM_MENU_SHOW_PCRS:
		gDcsTpm->ShowPcrs(gDcsTpm);
		return FALSE;

	case TPM_MENU_SHOW_NV:
		gDcsTpm->ShowNvIndices(gDcsTpm);
		return FALSE;

	case TPM_MENU_EXIT:
	default:
		return TRUE;
	}
}

EFI_STATUS
DcTpmMenu()
{
	EFI_INPUT_KEY key;
	INT32         selected = 0;
	INT32         prev;
	INT32         baseRow;
	INT32         i;

	// Check TPM availability early
	if (gDcsTpm == NULL || gDCryptTpmVersion == 0) {
		gST->ConOut->ClearScreen(gST->ConOut);
		ERR_PRINT(L"TPM not available.\n");
		OUT_PRINT(L"\nPress any key to continue...\n");
		GetKey();
		gST->ConOut->ClearScreen(gST->ConOut);
		return EFI_NOT_READY;
	}

	for (;;) {
		// Build dynamic menu based on current availability
		DcTpmBuildMenu();

		// Reset selection if it's now out of bounds
		if (selected >= gTpmMenuCount) {
			selected = 0;
		}

		// Full screen draw
		gST->ConOut->ClearScreen(gST->ConOut);
		OUT_PRINT(L"--- TPM Secret Management ---\n\n");

		// Show TPM status
		DcTpmPrintStatus();
		OUT_PRINT(L"\n");

		baseRow = gST->ConOut->Mode->CursorRow;

		// Draw menu items
		for (i = 0; i < gTpmMenuCount; i++) {
			DcTpmMenuDrawItem(i, baseRow + i, (i == selected));
		}

		// Footer
		gST->ConOut->SetCursorPosition(gST->ConOut, 0, baseRow + gTpmMenuCount + 1);
		OUT_PRINT(L"Up/Down: select   Enter: execute   Esc: cancel\n");

		gST->ConOut->EnableCursor(gST->ConOut, FALSE);

		// Input loop - only redraws changed items
		for (;;) {
			key = GetKey();
			FlushInputDelay(100000);

			if (key.ScanCode == SCAN_ESC) {
				gST->ConOut->EnableCursor(gST->ConOut, TRUE);
				gST->ConOut->ClearScreen(gST->ConOut);
				return EFI_SUCCESS;
			}

			if (key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
				gST->ConOut->EnableCursor(gST->ConOut, TRUE);
				if (DcTpmMenuExecute(selected)) {
					gST->ConOut->ClearScreen(gST->ConOut);
					return EFI_SUCCESS;
				}
				break;  // Redraw full screen
			}

			if (key.ScanCode == SCAN_UP && selected > 0) {
				prev = selected;
				selected--;
				DcTpmMenuDrawItem(prev, baseRow + prev, FALSE);
				DcTpmMenuDrawItem(selected, baseRow + selected, TRUE);
			}

			if (key.ScanCode == SCAN_DOWN && selected < gTpmMenuCount - 1) {
				prev = selected;
				selected++;
				DcTpmMenuDrawItem(prev, baseRow + prev, FALSE);
				DcTpmMenuDrawItem(selected, baseRow + selected, TRUE);
			}
		}
	}
}
