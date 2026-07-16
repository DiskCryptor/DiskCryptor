/** @file
  TPM Library

  Copyright (c) 2026 David Xanatos. All rights reserved.

**/

#include "../Library/MiscUtilsLib/MiscUtilsLib.h"
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/PrintLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/BaseLib.h>

#include <IndustryStandard/Tpm12.h>
#include <IndustryStandard/TcpaAcpi.h>
#include <Library/Tpm12DeviceLib.h>
#include <Protocol/TcgService.h>

#include "TpmLib.h"


EFI_STATUS
GetTpm() {
	EFI_STATUS res;
	if (gTpm != NULL) return EFI_SUCCESS;
	res = InitTpm12();
	if (!EFI_ERROR(res)) {
		gTpm = (TPM_LIB_PROTOCOL*)MEM_ALLOC(sizeof(TPM_LIB_PROTOCOL));
		if (gTpm == NULL) return EFI_BUFFER_TOO_SMALL;
		InitTpmLib12(gTpm);
		return EFI_SUCCESS;
	}
	res = InitTpm20();
	if (!EFI_ERROR(res)) {
		gTpm = (TPM_LIB_PROTOCOL*)MEM_ALLOC(sizeof(TPM_LIB_PROTOCOL));
		if (gTpm == NULL) return EFI_BUFFER_TOO_SMALL;
		InitTpmLib20(gTpm);
		return EFI_SUCCESS;
	}
	return res;
}

EFI_STATUS
Sha1Hash(
	IN  VOID    *data,
	IN  UINTN   dataSize,
	OUT UINT8   *hash
)
{
	if (!Sha1HashAll(data, dataSize, hash)) {
		return EFI_DEVICE_ERROR;
	}
	return EFI_SUCCESS;
}

EFI_STATUS
Sha256Hash(
	IN  VOID    *data,
	IN  UINTN   dataSize,
	OUT UINT8   *hash
)
{
	UINTN ctxSize;
	VOID  *ctx;
	ctxSize = Sha256GetContextSize();
	ctx = MEM_ALLOC(ctxSize);
	if (ctx == NULL) return EFI_BUFFER_TOO_SMALL;
	Sha256Init(ctx);
	Sha256Update(ctx, data, dataSize);
	if (!Sha256Final(ctx, hash)) {
		MEM_FREE(ctx);
		return EFI_DEVICE_ERROR;
	}
	MEM_FREE(ctx);
	return EFI_SUCCESS;
}


// AES-256-CBC encrypt (in-place, data must be multiple of 16 bytes) 
EFI_STATUS
TpmAes256CbcEncrypt(
	IN     UINT8    *Key,       // 32 bytes
	IN     UINT8    *Iv,        // 16 bytes
	IN OUT UINT8    *Data,
	IN     UINT32   DataSize
)
{
	VOID    *AesContext;
	UINTN   CtxSize;
	UINT8   Output[512];
	BOOLEAN Success;

	if (DataSize > sizeof(Output)) {
		return EFI_BAD_BUFFER_SIZE;
	}

	CtxSize = AesGetContextSize();
	if (CtxSize == 0) {
		return EFI_UNSUPPORTED;
	}

	AesContext = AllocatePool(CtxSize);
	if (AesContext == NULL) {
		return EFI_OUT_OF_RESOURCES;
	}

	Success = AesInit(AesContext, Key, 256);
	if (!Success) {
		FreePool(AesContext);
		return EFI_DEVICE_ERROR;
	}

	Success = AesCbcEncrypt(AesContext, Data, DataSize, Iv, Output);
	SetMem(AesContext, CtxSize, 0);
	FreePool(AesContext);

	if (!Success) {
		return EFI_DEVICE_ERROR;
	}

	CopyMem(Data, Output, DataSize);
	SetMem(Output, sizeof(Output), 0);
	return EFI_SUCCESS;
}

// AES-256-CBC decrypt (in-place, data must be multiple of 16 bytes)
EFI_STATUS
TpmAes256CbcDecrypt(
	IN     UINT8    *Key,       // 32 bytes
	IN     UINT8    *Iv,        // 16 bytes
	IN OUT UINT8    *Data,
	IN     UINT32   DataSize
)
{
	VOID    *AesContext;
	UINTN   CtxSize;
	UINT8   Output[512];
	BOOLEAN Success;

	if (DataSize > sizeof(Output)) {
		return EFI_BAD_BUFFER_SIZE;
	}

	CtxSize = AesGetContextSize();
	if (CtxSize == 0) {
		return EFI_UNSUPPORTED;
	}

	AesContext = AllocatePool(CtxSize);
	if (AesContext == NULL) {
		return EFI_OUT_OF_RESOURCES;
	}

	Success = AesInit(AesContext, Key, 256);
	if (!Success) {
		FreePool(AesContext);
		return EFI_DEVICE_ERROR;
	}

	Success = AesCbcDecrypt(AesContext, Data, DataSize, Iv, Output);
	SetMem(AesContext, CtxSize, 0);
	FreePool(AesContext);

	if (!Success) {
		return EFI_DEVICE_ERROR;
	}

	CopyMem(Data, Output, DataSize);
	SetMem(Output, sizeof(Output), 0);
	return EFI_SUCCESS;
}