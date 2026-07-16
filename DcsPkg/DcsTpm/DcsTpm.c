/** @file
  DCS TPM Driver - TPM interface for DiskCryptor

  Copyright (c) 2026 David Xanatos. All rights reserved.

**/

#include "../Library/MiscUtilsLib/MiscUtilsLib.h"
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
  Read a single PCR value from the TPM.

  @param[in]  This      A pointer to the EFI_DCS_TPM_PROTOCOL instance.
  @param[in]  PcrIndex  PCR index (0-23).
  @param[out] PcrValue  Buffer for PCR value (must be at least 64 bytes).
  @param[out] PcrSize   Receives actual PCR size.

  @retval EFI_SUCCESS           PCR read successfully.
  @retval EFI_NOT_READY         TPM not available.
  @retval EFI_INVALID_PARAMETER Invalid parameters.

**/
EFI_STATUS
EFIAPI
DcsReadPcr (
  IN  EFI_DCS_TPM_PROTOCOL  *This,
  IN  UINT32                PcrIndex,
  OUT UINT8                 *PcrValue,
  OUT UINT32                *PcrSize
  )
{
	EFI_STATUS res;

	if (PcrValue == NULL || PcrSize == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	res = GetTpm();
	if (EFI_ERROR(res) || gTpm == NULL) {
		return EFI_NOT_READY;
	}

	if (gTpm->ReadPcr == NULL) {
		return EFI_UNSUPPORTED;
	}

	return gTpm->ReadPcr(PcrIndex, PcrValue, PcrSize);
}

/**
  Enumerate NV indices.

  @param[in]     This       A pointer to the EFI_DCS_TPM_PROTOCOL instance.
  @param[out]    IndexList  Array to receive NV indices.
  @param[in,out] IndexCount In = array size, Out = actual count.

  @retval EFI_SUCCESS           Indices enumerated successfully.
  @retval EFI_NOT_READY         TPM not available.
  @retval EFI_BUFFER_TOO_SMALL  IndexList too small.

**/
EFI_STATUS
EFIAPI
DcsEnumNvIndices (
  IN     EFI_DCS_TPM_PROTOCOL  *This,
  OUT    UINT32                *IndexList,
  IN OUT UINT32                *IndexCount
  )
{
	EFI_STATUS res;

	if (IndexList == NULL || IndexCount == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	res = GetTpm();
	if (EFI_ERROR(res) || gTpm == NULL) {
		return EFI_NOT_READY;
	}

	if (gTpm->EnumNvIndices == NULL) {
		return EFI_UNSUPPORTED;
	}

	return gTpm->EnumNvIndices(IndexList, IndexCount);
}

/**
  Get NV index information.

  @param[in]  This       A pointer to the EFI_DCS_TPM_PROTOCOL instance.
  @param[in]  NvIndex    NV index to query.
  @param[out] Attributes Receives NV attributes.
  @param[out] DataSize   Receives data size.
  @param[out] PcrRead    Receives PCR read mask (TPM 1.2 only, optional).
  @param[out] PcrWrite   Receives PCR write mask (TPM 1.2 only, optional).

  @retval EFI_SUCCESS           Info retrieved successfully.
  @retval EFI_NOT_READY         TPM not available.
  @retval EFI_NOT_FOUND         Index not found.

**/
EFI_STATUS
EFIAPI
DcsGetNvIndexInfo (
  IN  EFI_DCS_TPM_PROTOCOL  *This,
  IN  UINT32                NvIndex,
  OUT UINT32                *Attributes,
  OUT UINT32                *DataSize,
  OUT UINT32                *PcrRead OPTIONAL,
  OUT UINT32                *PcrWrite OPTIONAL
  )
{
	EFI_STATUS res;

	if (Attributes == NULL || DataSize == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	res = GetTpm();
	if (EFI_ERROR(res) || gTpm == NULL) {
		return EFI_NOT_READY;
	}

	if (gTpm->GetNvIndexInfo == NULL) {
		return EFI_UNSUPPORTED;
	}

	return gTpm->GetNvIndexInfo(NvIndex, Attributes, DataSize, PcrRead, PcrWrite);
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
  DcsReadPcr,
  DcsEnumNvIndices,
  DcsGetNvIndexInfo,
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
