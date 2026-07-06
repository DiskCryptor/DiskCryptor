/** @file
  DCS TPM Driver - TPM interface for DiskCryptor

  Copyright (c) 2026 David Xanatos. All rights reserved.

**/

#include "../MiscUtilsLib/MiscUtilsLib.h"
#include <Library/BaseLib.h>
#include <Library/UefiLib.h>
#include <Library/MemoryAllocationLib.h>
#include "TpmLib.h"
#include "DcsTpm.h"


//////////////////////////////////////////////////////////////////////////
// TPM Interface Functions
//////////////////////////////////////////////////////////////////////////

/**
  Get the current TPM status.

  @param[in]  This    A pointer to the EFI_DCS_TPM_PROTOCOL instance.
  @param[out] Status  Pointer to receive the TPM status.

  @retval EFI_UNSUPPORTED  Function not yet implemented.

**/
EFI_STATUS
EFIAPI
DcsGetStatus (
  IN      EFI_DCS_TPM_PROTOCOL  *This,
  IN      UINT32                NvIndex,
  OUT     UINT32                *Status,
  OUT     UINT32                *PcrMask OPTIONAL,
  OUT     UINT32                *Flags OPTIONAL,
  OUT     VOID                  *Info OPTIONAL,
  IN OUT  UINT32                *InfoSize OPTIONAL
  )
{
	EFI_STATUS     res;
	UINT32         localFlags = 0;

	if (!Status) {
		return EFI_INVALID_PARAMETER;
	}

	// Check if TPM is ready
	res = GetTpm();
	if (EFI_ERROR(res) || gTpm == NULL) {
		return EFI_NOT_READY;
	}

	*Status = 0;

	if (gTpm->NvIsConfigured(NvIndex)) {
		*Status |= DCS_TPM_STATUS_CONFIGURED;

		if (!gTpm->NvIsOpen(NvIndex)) {
			*Status |= DCS_TPM_STATUS_LOCKED;
		}

		// Get info (PcrMask, Flags, InfoData)
		if (gTpm->NvGetInfo != NULL) {
			res = gTpm->NvGetInfo(NvIndex, PcrMask, &localFlags, Info, InfoSize);
			if (!EFI_ERROR(res) && (localFlags & DC_TPM_FLAG_PIN_REQUIRED)) {
				*Status |= DCS_TPM_STATUS_PIN_REQUIRED;
			}
			if (Flags != NULL) {
				*Flags = localFlags;
			}
		}
	} else {
		// Not configured - no info data
		if (InfoSize != NULL) {
			*InfoSize = 0;
		}
	}

	return EFI_SUCCESS;
}

/**
  Unseal a key from TPM storage.

  @param[in]  This            A pointer to the EFI_DCS_TPM_PROTOCOL instance.
  @param[out] Data            Pointer to buffer to receive the unsealed key.
  @param[out] DataSize        Pointer to receive the size of the unsealed key.
  @param[out] DataType        Pointer to receive the data type.
  @param[in]  TpmPin          Optional TPM-validated PIN (NULL if not used).

  @retval EFI_SUCCESS        Secret unsealed successfully.
  @retval EFI_NOT_READY      TPM not available.
  @retval EFI_ACCESS_DENIED  PIN required but not provided or incorrect.

**/
EFI_STATUS
EFIAPI
DcsUnsealSecret (
  IN  EFI_DCS_TPM_PROTOCOL  *This,
  IN  UINT32                NvIndex,
  OUT VOID                  *Data,
  OUT UINT32                *DataSize,
  OUT UINT32                *DataType,
  IN  CHAR16                *TpmPin OPTIONAL
  )
{
	EFI_STATUS     res;

	// Check if TPM is ready
	res = GetTpm();
	if (EFI_ERROR(res) || gTpm == NULL) {
		return EFI_NOT_READY;
	}

#ifdef _M_ARM64
	/* On ARM64, the first attempt to unseal may fail due to a known issue with TPM PIN handling. 
	   If the first attempt fails and a PIN is provided, retry once. */
	static BOOLEAN first_atempt = TRUE;
retry:
	res = gTpm->NvUnsealPassword(NvIndex, Data, DataSize, DataType, TpmPin);
	if (res == EFI_DEVICE_ERROR && first_atempt && TpmPin) {
		first_atempt = FALSE;
		goto retry;
	}
#else
	res = gTpm->NvUnsealPassword(NvIndex, Data, DataSize, DataType, TpmPin);
#endif

	return res;
}

/**
  Seal a key to TPM storage.

  @param[in] This            A pointer to the EFI_DCS_TPM_PROTOCOL instance.
  @param[in] Data            Pointer to the key to seal.
  @param[in] DataSize        Size of the key in bytes.
  @param[in] Options         Seal options (PCR mask, owner password).
  @param[in] Info            Optional plaintext info data to store (NULL = none).
  @param[in] InfoSize        Size of info data (0 = none, max 512 bytes).

  @retval EFI_SUCCESS        Secret sealed successfully.
  @retval EFI_NOT_READY      TPM not available.
  @retval EFI_UNSUPPORTED    Extended sealing not supported.
  @retval EFI_BAD_BUFFER_SIZE InfoSize exceeds maximum.

**/
EFI_STATUS
EFIAPI
DcsSealSecret (
  IN  EFI_DCS_TPM_PROTOCOL  *This,
  IN  UINT32                NvIndex,
  IN  VOID                  *Data,
  IN  UINT32                DataSize,
  IN  UINT32                DataType,
  IN  DCS_TPM_SEAL_OPTIONS  *Options,
  IN  VOID                  *Info OPTIONAL,
  IN  UINT32                InfoSize
  )
{
	EFI_STATUS     res;
	UINT32         PcrMask;
	CHAR16         *OwnerPassword;
	CHAR16         *TpmPin;

	if (Options == NULL) {
		return EFI_INVALID_PARAMETER;
	}
	if (InfoSize > DCS_TPM_INFO_MAX_SIZE) {
		return EFI_BAD_BUFFER_SIZE;
	}

	PcrMask = Options->PcrMask;
	OwnerPassword = Options->OwnerPassword[0] != L'\0' ? Options->OwnerPassword : NULL;
	TpmPin = (Options->Flags & DCS_TPM_OPT_FLAG_USE_PIN) && Options->TpmPin[0] != L'\0'
	         ? Options->TpmPin : NULL;

	// Check if TPM is ready
	res = GetTpm();
	if (EFI_ERROR(res) || gTpm == NULL) {
		return EFI_NOT_READY;
	}

	return gTpm->NvSealPassword(NvIndex, Data, DataSize, DataType, PcrMask, OwnerPassword, TpmPin, Info, InfoSize);
}

/**
  Clear a sealed secret from TPM storage.

  @param[in] This           A pointer to the EFI_DCS_TPM_PROTOCOL instance.
  @param[in] NvIndex        TPM NV index to clear.
  @param[in] OwnerPassword  TPM owner password for authorization.

  @retval EFI_SUCCESS       Secret cleared successfully.
  @retval EFI_NOT_READY     TPM not available.
  @retval EFI_ACCESS_DENIED Authorization failed.

**/
EFI_STATUS
EFIAPI
DcsClearSecret (
  IN  EFI_DCS_TPM_PROTOCOL  *This,
  IN  UINT32                NvIndex,
  IN  CHAR16                *OwnerPassword
  )
{
	EFI_STATUS res;

	// Check if TPM is ready
	res = GetTpm();
	if (EFI_ERROR(res) || gTpm == NULL) {
		return EFI_NOT_READY;
	}

	if (gTpm->NvClearSecret == NULL) {
		return EFI_UNSUPPORTED;
	}

	return gTpm->NvClearSecret(NvIndex, OwnerPassword);
}

/**
  Extend PCR 8 with the given data.

  @param[in] This  A pointer to the EFI_DCS_TPM_PROTOCOL instance.
  @param[in] size  Size of the data to extend
  @param[in] data  Pointer to the data

  @retval EFI_UNSUPPORTED  Function not yet implemented.

**/
EFI_STATUS
EFIAPI
DcsUpdatePcr8 (
  IN  EFI_DCS_TPM_PROTOCOL  *This,
  IN  UINTN                 size,
  IN  VOID*                 data
  )
{
	EFI_STATUS res;
	res = GetTpm();
	if (EFI_ERROR(res) || gTpm == NULL) {
		return EFI_NOT_READY;
	}

	if (gTpm->Measure != NULL) {
		return gTpm->Measure(gTpm, 8, size, data);
	}

	return EFI_UNSUPPORTED;
}

/**
  Get random bytes from TPM hardware RNG.

  @param[in]  This        A pointer to the EFI_DCS_TPM_PROTOCOL instance.
  @param[in]  RandomSize  Number of random bytes to generate.
  @param[out] RandomData  Pointer to buffer to receive random data.

  @retval EFI_SUCCESS           Random data generated successfully.
  @retval EFI_NOT_READY         TPM not available.
  @retval EFI_INVALID_PARAMETER RandomData is NULL.

**/
EFI_STATUS
EFIAPI
DcsGetRandom (
  IN  EFI_DCS_TPM_PROTOCOL  *This,
  IN  UINTN                 RandomSize,
  OUT UINT8                 *RandomData
  )
{
  EFI_STATUS res;

  if (RandomData == NULL || RandomSize == 0) {
    return EFI_INVALID_PARAMETER;
  }

  // Check if TPM is ready
  res = GetTpm();
  if (EFI_ERROR(res) || gTpm == NULL) {
    return EFI_NOT_READY;
  }

  return gTpm->GetRandom(gTpm, (UINT32)RandomSize, RandomData);
}

/**
  Get TPM information including version, manufacturer, firmware, lockout.

  @param[in]  This  A pointer to the EFI_DCS_TPM_PROTOCOL instance.
  @param[out] Info  Pointer to DCS_TPM_INFO structure to fill.

  @retval EFI_SUCCESS           Info retrieved successfully.
  @retval EFI_NOT_READY         TPM not available.
  @retval EFI_INVALID_PARAMETER Info is NULL.

**/
EFI_STATUS
EFIAPI
DcsGetInfo (
  IN  EFI_DCS_TPM_PROTOCOL  *This,
  OUT DCS_TPM_INFO          *Info
  )
{
  EFI_STATUS res;

  if (Info == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  // Check if TPM is ready
  res = GetTpm();
  if (EFI_ERROR(res) || gTpm == NULL) {
    return EFI_NOT_READY;
  }

  // Initialize structure
  ZeroMem(Info, sizeof(DCS_TPM_INFO));
  Info->TpmVersion = (UINT32)gTpm->TpmVersion;

  // Get TPM 2.0 specific info
  if (gTpm->TpmVersion >= 0x200) {
    UINT32 mfrId = 0;

    if (gTpm->GetManufacturer != NULL) {
      gTpm->GetManufacturer(&mfrId, Info->Manufacturer);
    }

    if (gTpm->GetFirmwareVersion != NULL) {
      gTpm->GetFirmwareVersion(&Info->FirmwareVersion1, &Info->FirmwareVersion2);
    }

    if (gTpm->GetLockoutInfo != NULL) {
      gTpm->GetLockoutInfo(&Info->LockoutCounter, &Info->LockoutInterval, NULL);
    }
  } else {
    // TPM 1.2
  }

  return EFI_SUCCESS;
}

/**
  Show PCR values used by sealed secret.

  @param[in] This  A pointer to the EFI_DCS_TPM_PROTOCOL instance.

  @retval EFI_SUCCESS     PCRs displayed successfully.
  @retval EFI_NOT_READY   TPM not available.

**/
EFI_STATUS
EFIAPI
DcsShowPcrs (
  IN  EFI_DCS_TPM_PROTOCOL  *This
  )
{
	EFI_STATUS res;
	UINT32     pcrMask = 0;
	UINTN      i;
	UINT8      pcrValue[64];  // Max PCR size (SHA-512)
	UINT32     pcrSize;

	res = GetTpm();
	if (EFI_ERROR(res) || gTpm == NULL) {
		return EFI_NOT_READY;
	}

	gST->ConOut->ClearScreen(gST->ConOut);
	OUT_PRINT(L"--- PCR Values ---\n\n");

	// Try to get PCR mask and show relevant PCRs
	if (!EFI_ERROR(gTpm->NvGetInfo(0, &pcrMask, NULL, NULL, NULL))) {
		OUT_PRINT(L"PCRs used by sealed secret (mask 0x%03x):\n\n", pcrMask);
	} else {
		OUT_PRINT(L"PCRs 0-15 (no secret configured):\n\n");
	}

	for (i = 0; i <= 15; ++i) {
		OUT_PRINT((pcrMask & (1 << i)) ? L"%HPCR%02d%N " : L"PCR%02d ", i);
		res = gTpm->ReadPcr((UINT32)i, pcrValue, &pcrSize);
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"Error: %r\n", res);
		} else {
			UefiPrintBytes(pcrValue, pcrSize);
			OUT_PRINT(L"\n");
		}
	}

	OUT_PRINT(L"\nPress any key to continue...\n");
	UefiGetKey();
	return EFI_SUCCESS;
}

// NV Index entry for display
typedef struct {
	UINT32     Index;
	UINT32     DataSize;
	UINT32     Attributes;
	UINT32     PcrRead;
	UINT32     PcrWrite;
	BOOLEAN    HasInfo;
	EFI_STATUS InfoError;
	CHAR16     *Label;
} NV_INDEX_ENTRY;

STATIC
VOID
DcTpmPrintNvEntry(
	IN NV_INDEX_ENTRY *Entry,
	IN BOOLEAN        IsTpm20
)
{
	OUT_PRINT(L"  0x%08x", Entry->Index);

	if (Entry->HasInfo) {
		OUT_PRINT(L"  Size: %4d  ", Entry->DataSize);

		UINT32 attrs = Entry->Attributes;
		OUT_PRINT(L"Attr: ");
		// Written
		OUT_PRINT((attrs & 0x00020000) ? L"W" : L"-");
		// Write access
		if (attrs & 0x00000004) OUT_PRINT(L"A");       // AUTHWRITE
		else if (attrs & 0x00000002) OUT_PRINT(L"O");  // OWNERWRITE
		else if (attrs & 0x00000001) OUT_PRINT(L"P");  // PPWRITE
		else if (attrs & 0x00000040) OUT_PRINT(L"Y");  // POLICYWRITE
		else OUT_PRINT(L"-");
		// Read access
		if (attrs & 0x00040000) OUT_PRINT(L"a");       // AUTHREAD
		else if (attrs & 0x00000100) OUT_PRINT(L"o");  // OWNERREAD
		else if (attrs & 0x00010000) OUT_PRINT(L"p");  // PPREAD
		else if (attrs & 0x00080000) OUT_PRINT(L"y");  // POLICYREAD
		else OUT_PRINT(L"-");
		// Lock
		OUT_PRINT((attrs & 0x02000000) ? L"L" : L"-");

		if (IsTpm20) {
			// TPM 2.0
		} else {
			// TPM 1.2
			if (Entry->PcrRead != 0) OUT_PRINT(L" PCR-R:0x%03x ", Entry->PcrRead);
			if (Entry->PcrWrite != 0) OUT_PRINT(L" PCR-W:0x%03x", Entry->PcrWrite);
		}
	} else {
		OUT_PRINT(L"  (error: %r)", Entry->InfoError);
	}

	if (Entry->Label != NULL) {
		OUT_PRINT(L"  %V%s%N", Entry->Label);
	}
	OUT_PRINT(L"\n");
}

STATIC
CHAR16*
DcTpmGetNvIndexLabel(
	IN UINT32 NvIndex
)
{
	UINT32 baseIndex = NvIndex & 0x00FFFFFF;

	// Known DCS/VeraCrypt/DiskCryptor indices
	if ((baseIndex & 0xFFFF0) == 0x0DC50 && (baseIndex & DC_TPM_NV_PCRS_BIT) == 0) return L"DCS Entry";
	if ((baseIndex & 0xFFFF0) == 0x0DC50 && (baseIndex & DC_TPM_NV_PCRS_BIT) != 0) return L"DCS Entry (Info)";

	// TCG defined indices (PC Client spec)
	if (NvIndex == 0x01C00002) return L"TCG Boot Service";
	if (NvIndex == 0x01C00003) return L"TCG Owner Policy";
	if (NvIndex == 0x01C00004) return L"TCG Auth Policy";
	if (NvIndex == 0x01C10102) return L"Windows BitLocker";
	if (NvIndex == 0x01C10103) return L"Windows BitLocker (alt)";
	if (NvIndex == 0x01C10104) return L"Windows Resume Key";

	// Platform indices
	if ((NvIndex & 0xFF000000) == 0x01000000) return L"Owner Defined";
	if ((NvIndex & 0xFF000000) == 0x01400000) return L"Platform Defined";
	if ((NvIndex & 0xFF000000) == 0x01800000) return L"Endorsement Defined";
	if ((NvIndex & 0xFF000000) == 0x01C00000) return L"TCG Defined";

	return NULL;
}

/**
  Show NV indices list.

  @param[in] This  A pointer to the EFI_DCS_TPM_PROTOCOL instance.

  @retval EFI_SUCCESS     NV indices displayed successfully.
  @retval EFI_NOT_READY   TPM not available.

**/
EFI_STATUS
EFIAPI
DcsShowNvIndices (
  IN  EFI_DCS_TPM_PROTOCOL  *This
  )
{
	EFI_STATUS      res;
	UINT32          rawIndices[128];
	NV_INDEX_ENTRY  entries[128];
	UINT32          rawCount = 128;
	UINT32          validCount = 0;
	UINT32          i;
	BOOLEAN         isTpm20;
	UINTN           screenRows = 25;
	UINTN           screenCols = 80;
	UINT32          entriesPerPage;
	UINT32          currentPage = 0;
	UINT32          totalPages;
	EFI_INPUT_KEY   key;

	res = GetTpm();
	if (EFI_ERROR(res) || gTpm == NULL) {
		return EFI_NOT_READY;
	}

	// Get console size
	if (gST->ConOut->Mode != NULL) {
		gST->ConOut->QueryMode(gST->ConOut, gST->ConOut->Mode->Mode, &screenCols, &screenRows);
	}
	// Reserve lines for header (3) + footer (4) + margin (1)
	entriesPerPage = (UINT32)(screenRows > 10 ? screenRows - 8 : 10);

	isTpm20 = (gTpm->TpmVersion >= 0x200);

	// Enumerate and gather NV index info
	res = gTpm->EnumNvIndices(rawIndices, &rawCount);
	if (EFI_ERROR(res)) {
		gST->ConOut->ClearScreen(gST->ConOut);
		ERR_PRINT(L"Failed to enumerate NV indices: %r\n", res);
		OUT_PRINT(L"\nPress any key to continue...\n");
		UefiGetKey();
		return res;
	}

	for (i = 0; i < rawCount && validCount < 128; i++) {
		if (rawIndices[i] == 0) continue;

		entries[validCount].Index = rawIndices[i];
		entries[validCount].Label = DcTpmGetNvIndexLabel(rawIndices[i]);
		entries[validCount].PcrRead = 0;
		entries[validCount].PcrWrite = 0;

		res = gTpm->GetNvIndexInfo(rawIndices[i],
			&entries[validCount].Attributes,
			&entries[validCount].DataSize,
			&entries[validCount].PcrRead,
			&entries[validCount].PcrWrite);
		entries[validCount].HasInfo = !EFI_ERROR(res);
		entries[validCount].InfoError = res;
		validCount++;
	}

	if (validCount == 0) {
		gST->ConOut->ClearScreen(gST->ConOut);
		OUT_PRINT(L"--- TPM NV Indices ---\n\n");
		OUT_PRINT(L"No NV indices defined.\n");
		OUT_PRINT(L"\nPress any key to continue...\n");
		UefiGetKey();
		return EFI_SUCCESS;
	}

	// Calculate total pages
	totalPages = (validCount + entriesPerPage - 1) / entriesPerPage;

	// Display loop with pagination
	while (TRUE) {
		UINT32 startIdx = currentPage * entriesPerPage;
		UINT32 endIdx = startIdx + entriesPerPage;
		if (endIdx > validCount) endIdx = validCount;

		gST->ConOut->ClearScreen(gST->ConOut);
		OUT_PRINT(L"--- TPM NV Indices (%d total) ---\n\n", validCount);

		// Print entries for current page
		for (i = startIdx; i < endIdx; i++) {
			DcTpmPrintNvEntry(&entries[i], isTpm20);
		}

		// Footer
		OUT_PRINT(L"\n");
		if (isTpm20) {
			OUT_PRINT(L"Attr: W=Written O/o=Owner A/a=Auth P/p=PP Y/y=Policy L=Locked\n");
		}
		OUT_PRINT(L"Page %d/%d  ", currentPage + 1, totalPages);
		if (totalPages > 1) {
			OUT_PRINT(L"[PgUp/PgDn] Navigate  ");
		}
		OUT_PRINT(L"[Esc/x/e] Back\n");

		key = UefiGetKey();

		if (key.ScanCode == SCAN_PAGE_UP || key.ScanCode == SCAN_UP) {
			if (currentPage > 0) currentPage--;
		} else if (key.ScanCode == SCAN_PAGE_DOWN || key.ScanCode == SCAN_DOWN) {
			if (currentPage < totalPages - 1) currentPage++;
		} else if (key.ScanCode == SCAN_HOME) {
			currentPage = 0;
		} else if (key.ScanCode == SCAN_END) {
			currentPage = totalPages - 1;
		} else if (key.ScanCode == SCAN_ESC ||
			key.UnicodeChar == L'x' || key.UnicodeChar == L'X' ||
			key.UnicodeChar == L'e' || key.UnicodeChar == L'E' ||
			key.UnicodeChar == L'q' || key.UnicodeChar == L'Q') {
			break;
		}
	}

	return EFI_SUCCESS;
}

/**
  Shutdown TPM.

  TPM 2.0: Executes TPM2_Shutdown(TPM_SU_CLEAR) to prepare for power off.
  TPM 1.2: Returns EFI_UNSUPPORTED (no explicit shutdown command).

  @param[in] This  A pointer to the EFI_DCS_TPM_PROTOCOL instance.

  @retval EFI_SUCCESS      TPM shutdown successful (TPM 2.0).
  @retval EFI_NOT_READY    TPM not available.
  @retval EFI_UNSUPPORTED  TPM 1.2 does not support explicit shutdown.

**/
EFI_STATUS
EFIAPI
DcsShutdown (
  IN  EFI_DCS_TPM_PROTOCOL  *This
  )
{
  EFI_STATUS res;

  // Check if TPM is ready
  res = GetTpm();
  if (EFI_ERROR(res) || gTpm == NULL) {
    return EFI_NOT_READY;
  }

  // TPM 1.2 does not have an explicit shutdown command
  if (gTpm->Shutdown == NULL) {
    return EFI_UNSUPPORTED;
  }

  return gTpm->Shutdown();
}

//////////////////////////////////////////////////////////////////////////
// Buffer-based SRK API (caller handles file I/O)
//////////////////////////////////////////////////////////////////////////

/**
  Get status from sealed buffer.

  @param[in]     This        A pointer to the EFI_DCS_TPM_PROTOCOL instance.
  @param[in]     Buffer      Buffer containing sealed data.
  @param[in]     BufferSize  Size of buffer.
  @param[out]    Status      Receives DCS_TPM_STATUS_* flags.
  @param[out]    PcrMask     Receives PCR mask (optional).
  @param[out]    Flags       Receives DC_TPM_FLAG_* flags (optional).
  @param[out]    Info        Output buffer for info data (optional).
  @param[in,out] InfoSize    In = buffer size, Out = actual size (optional).

  @retval EFI_SUCCESS     Status retrieved successfully.
  @retval EFI_NOT_FOUND   Invalid or unrecognized sealed data.
  @retval EFI_NOT_READY   TPM not available.
  @retval EFI_UNSUPPORTED Function not supported.

**/
EFI_STATUS
EFIAPI
DcsSrkGetStatus (
  IN     EFI_DCS_TPM_PROTOCOL  *This,
  IN     UINT8                 *Buffer,
  IN     UINT32                BufferSize,
  OUT    UINT32                *Status,
  OUT    UINT32                *PcrMask OPTIONAL,
  OUT    UINT32                *Flags OPTIONAL,
  OUT    VOID                  *Info OPTIONAL,
  IN OUT UINT32                *InfoSize OPTIONAL
  )
{
  EFI_STATUS res;
  UINT32     localFlags = 0;

  if (Buffer == NULL || BufferSize == 0 || Status == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  res = GetTpm();
  if (EFI_ERROR(res) || gTpm == NULL) {
    return EFI_NOT_READY;
  }

  *Status = DCS_TPM_STATUS_CONFIGURED;  // If we can parse it, it's configured

  // Check if open (PCRs match)
  if (gTpm->SrkIsOpen != NULL && !gTpm->SrkIsOpen(Buffer, BufferSize)) {
    *Status |= DCS_TPM_STATUS_LOCKED;
  }

  // Get info (PcrMask, Flags, InfoData)
  if (gTpm->SrkGetInfo != NULL) {
    res = gTpm->SrkGetInfo(Buffer, BufferSize, PcrMask, &localFlags, Info, InfoSize);
    if (EFI_ERROR(res)) {
      return res;
    }
    if (localFlags & DC_TPM_FLAG_PIN_REQUIRED) {
      *Status |= DCS_TPM_STATUS_PIN_REQUIRED;
    }
    if (Flags != NULL) {
      *Flags = localFlags;
    }
  }

  return EFI_SUCCESS;
}

/**
  Seal password to buffer using SRK with envelope encryption.

  @param[in]     This          A pointer to the EFI_DCS_TPM_PROTOCOL instance.
  @param[in]     Password      Password data to seal.
  @param[in]     PasswordSize  Size of password.
  @param[in]     PasswordType  Application-specific password type.
  @param[in]     PcrMask       PCR mask for sealing policy.
  @param[in]     TpmPin        Optional TPM-validated PIN.
  @param[in]     Info          Optional plaintext info data.
  @param[in]     InfoSize      Size of info data (0 = none).
  @param[out]    Buffer        Output buffer for sealed data.
  @param[in,out] BufferSize    In = buffer size, Out = actual/required size.

  @retval EFI_SUCCESS           Password sealed successfully.
  @retval EFI_BUFFER_TOO_SMALL  Buffer too small, BufferSize set to required.
  @retval EFI_NOT_READY         TPM not available.
  @retval EFI_UNSUPPORTED       SRK sealing not supported.

**/
EFI_STATUS
EFIAPI
DcsSrkSealPassword (
  IN     EFI_DCS_TPM_PROTOCOL  *This,
  IN     VOID                  *Password,
  IN     UINT32                PasswordSize,
  IN     UINT32                PasswordType,
  IN     DCS_TPM_SEAL_OPTIONS  *Options,
  IN     VOID                  *Info OPTIONAL,
  IN     UINT32                InfoSize,
  OUT    UINT8                 *Buffer,
  IN OUT UINT32                *BufferSize
  )
{
  EFI_STATUS res;

  if (Password == NULL || PasswordSize == 0 || Buffer == NULL || BufferSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  if (InfoSize > DCS_TPM_INFO_MAX_SIZE) {
    return EFI_BAD_BUFFER_SIZE;
  }

  res = GetTpm();
  if (EFI_ERROR(res) || gTpm == NULL) {
    return EFI_NOT_READY;
  }

  if (gTpm->SrkSealPassword == NULL) {
    return EFI_UNSUPPORTED;
  }

  return gTpm->SrkSealPassword(Password, PasswordSize, PasswordType, Options->PcrMask,
                                Options->TpmPin, Info, InfoSize, Buffer, BufferSize);
}

/**
  Unseal password from buffer.

  @param[in]  This          A pointer to the EFI_DCS_TPM_PROTOCOL instance.
  @param[in]  Buffer        Buffer containing sealed data.
  @param[in]  BufferSize    Size of buffer.
  @param[out] Password      Output buffer for decrypted password.
  @param[out] PasswordSize  Receives actual password size.
  @param[out] PasswordType  Receives password type.
  @param[in]  TpmPin        Optional TPM-validated PIN.

  @retval EFI_SUCCESS       Password unsealed successfully.
  @retval EFI_ACCESS_DENIED PCRs don't match or wrong PIN.
  @retval EFI_NOT_READY     TPM not available.
  @retval EFI_UNSUPPORTED   SRK unsealing not supported.

**/
EFI_STATUS
EFIAPI
DcsSrkUnsealPassword (
  IN  EFI_DCS_TPM_PROTOCOL  *This,
  IN  UINT8                 *Buffer,
  IN  UINT32                BufferSize,
  OUT VOID                  *Password,
  OUT UINT32                *PasswordSize,
  OUT UINT32                *PasswordType,
  IN  CHAR16                *TpmPin OPTIONAL
  )
{
  EFI_STATUS res;

  if (Buffer == NULL || BufferSize == 0 || Password == NULL ||
      PasswordSize == NULL || PasswordType == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  res = GetTpm();
  if (EFI_ERROR(res) || gTpm == NULL) {
    return EFI_NOT_READY;
  }

  if (gTpm->SrkUnsealPassword == NULL) {
    return EFI_UNSUPPORTED;
  }

#ifdef _M_ARM64
  /* On ARM64, the first attempt to unseal may fail due to a known issue with TPM PIN handling. 
  If the first attempt fails and a PIN is provided, retry once. */
  static BOOLEAN first_atempt = TRUE;
retry:
  res = gTpm->SrkUnsealPassword(Buffer, BufferSize, Password, PasswordSize, PasswordType, TpmPin);
  if (res == EFI_DEVICE_ERROR && first_atempt && TpmPin) {
	  first_atempt = FALSE;
	  goto retry;
  }
#else
  res = gTpm->SrkUnsealPassword(Buffer, BufferSize, Password, PasswordSize, PasswordType, TpmPin);
#endif

  return res;
}

//////////////////////////////////////////////////////////////////////////
// Protocol Instance
//////////////////////////////////////////////////////////////////////////

EFI_GUID gEfiDcsTpmProtocolGuid = EFI_DCS_TPM_INTERFACE_PROTOCOL_GUID;

EFI_DCS_TPM_PROTOCOL gEfiDcsTpmProtocol = {
  // NV-based API
  DcsGetStatus,
  DcsUnsealSecret,
  DcsSealSecret,
  DcsClearSecret,
  // Other API
  DcsUpdatePcr8,
  DcsGetRandom,
  DcsGetInfo,
  DcsShowPcrs,
  DcsShowNvIndices,
  DcsShutdown,
  // Buffer-based SRK API
  DcsSrkGetStatus,
  DcsSrkSealPassword,
  DcsSrkUnsealPassword
};

//////////////////////////////////////////////////////////////////////////
// Driver Entry and Unload
//////////////////////////////////////////////////////////////////////////

/**
  Unloads an image.

  @param[in] ImageHandle  Handle that identifies the image to be unloaded.

  @retval EFI_SUCCESS           The image has been unloaded.
  @retval EFI_INVALID_PARAMETER ImageHandle is not a valid image handle.

**/
EFI_STATUS
EFIAPI
DcsTpmUnload (
  IN EFI_HANDLE  ImageHandle
  )
{
  EFI_STATUS  Status;

  //
  // Uninstall DCS TPM Protocol from ImageHandle
  //
  Status = gBS->UninstallMultipleProtocolInterfaces (
                  ImageHandle,
                  &gEfiDcsTpmProtocolGuid, &gEfiDcsTpmProtocol,
                  NULL
                  );

  if (EFI_ERROR (Status)) {
    return Status;
  }

  return EFI_SUCCESS;
}

/**
  This is the entry point for the DCS TPM driver.

  @param[in] ImageHandle  The firmware allocated handle for the EFI image.
  @param[in] SystemTable  A pointer to the EFI System Table.

  @retval EFI_SUCCESS     The operation completed successfully.
  @retval Others          An unexpected error occurred.

**/
EFI_STATUS
EFIAPI
DcsTpmMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;
  EFI_DCS_TPM_PROTOCOL   *DcsTpm;

  Status = gBS->LocateProtocol(
				  &gEfiDcsTpmProtocolGuid,
				  NULL,
				  (VOID **)&DcsTpm
					);

  // Check multiple execution of DcsTpm
  if (!EFI_ERROR(Status)) {
	  return EFI_ACCESS_DENIED;
  }

  //
  // Install DCS TPM Protocol onto ImageHandle
  //
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &ImageHandle,
                  &gEfiDcsTpmProtocolGuid, &gEfiDcsTpmProtocol,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  return Status;
}
