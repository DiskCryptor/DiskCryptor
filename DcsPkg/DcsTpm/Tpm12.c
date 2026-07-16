/** @file
  TPM 1.2 Library

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


//
// HMAC-SHA1 implementation using SHA1 primitives
// HMAC-SHA1 was deprecated in BaseCryptLib but is required for TPM 1.2
//
#define HMAC_SHA1_BLOCK_SIZE  64
#define HMAC_SHA1_DIGEST_SIZE 20

typedef struct {
  UINT8  Key[HMAC_SHA1_BLOCK_SIZE];
  VOID   *Sha1Context;
} HMAC_SHA1_CTX;

STATIC
UINTN
HmacSha1GetContextSize (
  VOID
  )
{
  return sizeof(HMAC_SHA1_CTX) + Sha1GetContextSize();
}

STATIC
BOOLEAN
HmacSha1Init (
  OUT VOID        *HmacContext,
  IN  CONST UINT8 *Key,
  IN  UINTN       KeySize
  )
{
  HMAC_SHA1_CTX *Ctx;
  UINT8         KeyHash[HMAC_SHA1_DIGEST_SIZE];
  UINT8         iPad[HMAC_SHA1_BLOCK_SIZE];
  UINTN         Index;

  if (HmacContext == NULL) {
    return FALSE;
  }

  Ctx = (HMAC_SHA1_CTX *)HmacContext;
  Ctx->Sha1Context = (VOID *)((UINT8 *)HmacContext + sizeof(HMAC_SHA1_CTX));

  // If key is longer than block size, hash it first
  ZeroMem(Ctx->Key, HMAC_SHA1_BLOCK_SIZE);
  if (KeySize > HMAC_SHA1_BLOCK_SIZE) {
    if (!Sha1HashAll(Key, KeySize, KeyHash)) {
      return FALSE;
    }
    CopyMem(Ctx->Key, KeyHash, HMAC_SHA1_DIGEST_SIZE);
  } else {
    CopyMem(Ctx->Key, Key, KeySize);
  }

  // Prepare inner padding (key XOR 0x36)
  for (Index = 0; Index < HMAC_SHA1_BLOCK_SIZE; Index++) {
    iPad[Index] = Ctx->Key[Index] ^ 0x36;
  }

  // Start inner hash: SHA1(key XOR iPad || message)
  if (!Sha1Init(Ctx->Sha1Context)) {
    return FALSE;
  }

  if (!Sha1Update(Ctx->Sha1Context, iPad, HMAC_SHA1_BLOCK_SIZE)) {
    return FALSE;
  }

  return TRUE;
}

STATIC
BOOLEAN
HmacSha1Update (
  IN OUT VOID       *HmacContext,
  IN     CONST VOID *Data,
  IN     UINTN      DataSize
  )
{
  HMAC_SHA1_CTX *Ctx;

  if (HmacContext == NULL) {
    return FALSE;
  }

  Ctx = (HMAC_SHA1_CTX *)HmacContext;
  return Sha1Update(Ctx->Sha1Context, Data, DataSize);
}

STATIC
BOOLEAN
HmacSha1Final (
  IN OUT VOID  *HmacContext,
  OUT    UINT8 *HmacValue
  )
{
  HMAC_SHA1_CTX *Ctx;
  UINT8         InnerHash[HMAC_SHA1_DIGEST_SIZE];
  UINT8         oPad[HMAC_SHA1_BLOCK_SIZE];
  UINTN         Index;

  if ((HmacContext == NULL) || (HmacValue == NULL)) {
    return FALSE;
  }

  Ctx = (HMAC_SHA1_CTX *)HmacContext;

  // Complete inner hash
  if (!Sha1Final(Ctx->Sha1Context, InnerHash)) {
    return FALSE;
  }

  // Prepare outer padding (key XOR 0x5c)
  for (Index = 0; Index < HMAC_SHA1_BLOCK_SIZE; Index++) {
    oPad[Index] = Ctx->Key[Index] ^ 0x5c;
  }

  // Compute outer hash: SHA1(key XOR oPad || inner_hash)
  if (!Sha1Init(Ctx->Sha1Context)) {
    return FALSE;
  }

  if (!Sha1Update(Ctx->Sha1Context, oPad, HMAC_SHA1_BLOCK_SIZE)) {
    return FALSE;
  }

  if (!Sha1Update(Ctx->Sha1Context, InnerHash, HMAC_SHA1_DIGEST_SIZE)) {
    return FALSE;
  }

  if (!Sha1Final(Ctx->Sha1Context, HmacValue)) {
    return FALSE;
  }

  return TRUE;
}

//#pragma warning(disable: 4706)

extern EFI_TCG_PROTOCOL  *mTcgProtocol;

EFI_STATUS
InitTpm12() {
	EFI_STATUS res = EFI_SUCCESS;
	if (mTcgProtocol == NULL) {
		return Tpm12RequestUseTpm();
	}
	return res;
}

typedef struct  {
	UINT8      *Cmd;
	UINTN      CmdPos;
	UINTN      CmdSize;
	UINT8      *Resp;
	UINTN      RespPos;
	UINTN      RespSize;
	UINT8      *Hash;
} TPM12IO;

//////////////////////////////////////////////////////////////////////////
// TPM IO Create/ Free
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
Tpm12IOCreate(
	TPM12IO **tpmio,
	UINTN cmdSize,
	UINTN respSize) 
{
	TPM12IO *io;
	if (tpmio == NULL) return EFI_INVALID_PARAMETER;
	io = *tpmio;
	if (io == NULL) {
		io = MEM_ALLOC(sizeof(*io));
		if (io == NULL) return EFI_BUFFER_TOO_SMALL;
	}
	if (io->CmdSize < cmdSize) {
		MEM_FREE(io->Cmd);
		io->Cmd = MEM_ALLOC(cmdSize);
		if (io->Cmd == NULL) goto err;
	}
	io->CmdPos = 0;
	io->CmdSize = cmdSize;
	if (io->RespSize < respSize) {
		MEM_FREE(io->Resp);
		io->Resp = MEM_ALLOC(respSize);
		if (io->Resp == NULL) goto err;
	}
	io->RespPos = 0;
	io->RespSize = respSize;
	if (io->Hash == NULL) {
		UINTN sha1ctxsize;
		sha1ctxsize = Sha1GetContextSize();
		io->Hash = MEM_ALLOC(sha1ctxsize);
		if (io->Hash == NULL) goto err;
	}
	if(!Sha1Init(io->Hash)) goto err;
	*tpmio = io;
	return EFI_SUCCESS;
err:
	MEM_FREE(io->Cmd);
	MEM_FREE(io->Resp);
	MEM_FREE(io->Hash);
	MEM_FREE(io);
	*tpmio = NULL;
	return EFI_BUFFER_TOO_SMALL;
}

VOID
Tpm12IOFree(
	TPM12IO **tpmio)
{
	TPM12IO *io;
	if (tpmio == NULL) return;
	io = *tpmio;
	if (io == NULL) return;
	MEM_FREE(io->Cmd);
	MEM_FREE(io->Resp);
	MEM_FREE(io->Hash);
	MEM_FREE(io);
	*tpmio = NULL;
}

//////////////////////////////////////////////////////////////////////////
// Cmd init and write
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
Tpm12IOUpdateCmdSize(
	TPM12IO *tpmio) 
{
	UINT32      *data;
	if (tpmio == NULL) return EFI_INVALID_PARAMETER;
	data = (UINT32*)&tpmio->Cmd[2];
	*data = SwapBytes32((UINT32)tpmio->CmdPos);
	return EFI_SUCCESS;
}

EFI_STATUS
Tpm12IOWrite16(
	TPM12IO *tpmio,
	UINT16      prm,
	BOOLEAN     hashIt)
{
	UINT16      *data;
	if (tpmio == NULL) return EFI_INVALID_PARAMETER;
	if (tpmio->CmdPos + 2 >= tpmio->CmdSize) {
		tpmio->CmdPos = tpmio->CmdSize;
		return EFI_BUFFER_TOO_SMALL;
	}
	data = (UINT16*)&tpmio->Cmd[tpmio->CmdPos];
	*data = SwapBytes16(prm);
	if(hashIt) {
		Sha1Update(tpmio->Hash, data, 2);
	}
	tpmio->CmdPos += 2;
	return Tpm12IOUpdateCmdSize(tpmio);
}

EFI_STATUS
Tpm12IOWrite32(
	TPM12IO *tpmio,
	UINT32      prm,
	BOOLEAN     hashIt)
{
	UINT32      *data;
	if (tpmio == NULL) return EFI_INVALID_PARAMETER;
	if (tpmio->CmdPos + 4 >= tpmio->CmdSize){
		tpmio->CmdPos = tpmio->CmdSize;
		return EFI_BUFFER_TOO_SMALL;
	}
	data = (UINT32*)&tpmio->Cmd[tpmio->CmdPos];
	*data = SwapBytes32(prm);
	if (hashIt) {
		Sha1Update(tpmio->Hash, data, 4);
	}
	tpmio->CmdPos += 4;
	return Tpm12IOUpdateCmdSize(tpmio);
}

EFI_STATUS
Tpm12IOWriteBytes(
	TPM12IO *tpmio,
	VOID       *prm,
	UINTN       prmSize,
	BOOLEAN     hashIt)
{
	UINT8      *data;
	if (tpmio == NULL) return EFI_INVALID_PARAMETER;
	if (tpmio->CmdPos + prmSize >= tpmio->CmdSize) {
		tpmio->CmdPos = tpmio->CmdSize;
		return EFI_BUFFER_TOO_SMALL;
	}
	data = &tpmio->Cmd[tpmio->CmdPos];
	CopyMem(data, prm, prmSize);
	if (hashIt) {
		Sha1Update(tpmio->Hash, data, prmSize);
	}
	tpmio->CmdPos += prmSize;
	return Tpm12IOUpdateCmdSize(tpmio);
}

EFI_STATUS
Tpm12IOWrite8(
	TPM12IO *tpmio,
	UINT8       prm,
	BOOLEAN     hashIt) 
{
	return Tpm12IOWriteBytes(tpmio, &prm, 1, hashIt);
}

EFI_STATUS
Tpm12IOInit(
	TPM12IO *tpmio,
	UINT16       tag,
	UINT32       ord)
{
	if (tpmio == NULL) return EFI_INVALID_PARAMETER;
	tpmio->CmdPos = 0;
	ZeroMem(tpmio->Cmd, tpmio->CmdSize);
	tpmio->RespPos = 0;
	ZeroMem(tpmio->Resp, tpmio->RespSize);
	Sha1Init(tpmio->Hash);
	Tpm12IOWrite16(tpmio, tag, FALSE);
	Tpm12IOWrite32(tpmio, 0, FALSE);
	return Tpm12IOWrite32(tpmio, ord, TRUE);
}


//////////////////////////////////////////////////////////////////////////
// Read / Parse responses
//////////////////////////////////////////////////////////////////////////
UINT16
Tpm12RespTag(
	TPM12IO          *tpmio)
{
	UINT16 *tag;
	if (tpmio == NULL) return 0;
	tag = (UINT16*)tpmio->Resp;
	return SwapBytes16(*tag);
}

UINT32
Tpm12RespCode(
	IN  TPM12IO          *tpmio
	)
{
	UINT32 *code;
	if (tpmio == NULL) return 0;
	code = (UINT32*)&tpmio->Resp[6];
	return SwapBytes32(*code);
}

UINT32
Tpm12RespSize(
	IN  TPM12IO          *tpmio
	)
{
	UINT32 *size;
	if (tpmio == NULL) return 0;
	size = (UINT32*)&tpmio->Resp[2];
	return SwapBytes32(*size);
}

UINT8*
Tpm12RespData(
	IN  TPM12IO          *tpmio
	)
{
	if (tpmio == NULL) return NULL;
	return &tpmio->Resp[10];
}

EFI_STATUS
Tpm12RespRead16(
	IN  TPM12IO          *tpmio,
	OUT UINT16               *data,
	IN  BOOLEAN              hashIt
	)
{
	UINT16 *tmp;
	if (tpmio == NULL) return EFI_INVALID_PARAMETER;
	if(tpmio->RespPos + 2 > tpmio->RespSize) return EFI_BUFFER_TOO_SMALL;
	tmp = (UINT16 *)&tpmio->Resp[tpmio->RespPos];
	if (data != NULL) {
		*data = SwapBytes16(*tmp);
	}
	if (hashIt) {
		Sha1Update(tpmio->Hash, tmp, 2);
	}
	tpmio->RespPos += 2;
	return EFI_SUCCESS;
}

EFI_STATUS
Tpm12RespRead32(
	IN  TPM12IO          *tpmio,
	OUT UINT32               *data,
	IN  BOOLEAN              hashIt
	)
{
	UINT32 *tmp;
	if (tpmio == NULL) return EFI_INVALID_PARAMETER;
	if (tpmio->RespPos + 4 > tpmio->RespSize) return EFI_BUFFER_TOO_SMALL;
	tmp = (UINT32 *)&tpmio->Resp[tpmio->RespPos];
	if (data != NULL) {
		*data = SwapBytes32(*tmp);
	}
	if (hashIt) {
		Sha1Update(tpmio->Hash, tmp, 4);
	}
	tpmio->RespPos += 4;
	return EFI_SUCCESS;
}

EFI_STATUS
Tpm12RespReadBytes(
	IN  TPM12IO          *tpmio,
	OUT VOID                 *data,
	IN  UINT32               dataSize,
	IN  BOOLEAN              hashIt
	)
{
	UINT8 *tmp;
	if (tpmio == NULL) return EFI_INVALID_PARAMETER;
	if (tpmio->RespPos + dataSize > tpmio->RespSize) return EFI_BUFFER_TOO_SMALL;
	tmp = &tpmio->Resp[tpmio->RespPos];
	if (data != NULL) {
		CopyMem(data, tmp, dataSize);
	}
	if (hashIt) {
		Sha1Update(tpmio->Hash, tmp, dataSize);
	}
	tpmio->RespPos += dataSize;
	return EFI_SUCCESS;
}

VOID
Tpm12Parse16(UINT8** pos, UINT16 *data) {
	if (data == NULL) {
		data = (UINT16*)(*pos);
	}
	*data = SwapBytes16(*((UINT16*)(*pos)));
	(*pos) += 2;
}

VOID
Tpm12Parse32(UINT8** pos, UINT32 *data) {
	if (data == NULL) {
		data = (UINT32*)(*pos);
	}
	*data = SwapBytes32(*((UINT32*)(*pos)));
	(*pos) += 4;
}

VOID
Tpm12ParsePcrInfoShort(UINT8** pos, TPM_PCR_INFO_SHORT*data) {
	if (data == NULL) {
		data = (TPM_PCR_INFO_SHORT*)(*pos);
	}
	data->pcrSelection.sizeOfSelect = SwapBytes16(*((UINT16*)(*pos)));
	(*pos) += data->pcrSelection.sizeOfSelect + 2 + 1 + 20;
}

//////////////////////////////////////////////////////////////////////////
// Transmit command
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
Tpm12Transmit(
	TPM12IO          *tpmio) 
{
	UINT32               TpmRecvSize;
	EFI_STATUS           res;
	if (tpmio == NULL) return EFI_INVALID_PARAMETER;
	if (tpmio->CmdPos >= tpmio->CmdSize) return EFI_BUFFER_TOO_SMALL;
	TpmRecvSize = (UINT32)tpmio->RespSize;
	res = Tpm12SubmitCommand((UINT32)tpmio->CmdPos, tpmio->Cmd, &TpmRecvSize, tpmio->Resp);
	if (EFI_ERROR(res)) {
		return res;
	}
	if (Tpm12RespCode(tpmio) != TPM_SUCCESS) {
		return EFI_DEVICE_ERROR;
	}
	Sha1Init(tpmio->Hash); // Init hash
	tpmio->RespPos = 6;    // Skip tag and size
	Tpm12RespRead32(tpmio, NULL, TRUE);         // Hash return code
	Sha1Update(tpmio->Hash, tpmio->Cmd + 6, 4); // Hash ordinal
	return res;
}

//////////////////////////////////////////////////////////////////////////
// Global TPM12 I/O
//////////////////////////////////////////////////////////////////////////
TPM12IO *gTpm12Io = NULL;
EFI_STATUS
GetTpm12Io()
{
	EFI_STATUS res = EFI_SUCCESS;
	if (gTpm12Io == NULL) {
		res = Tpm12IOCreate(&gTpm12Io, 1024, 1024);
	}
	if (mTcgProtocol == NULL) {
		return EFI_NOT_READY;
	}
	return res;
}

//////////////////////////////////////////////////////////////////////////
// PCRs
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
Tpm12Cmd_PcrRead(
	TPM12IO *tpmio,
	IN UINT32   PcrIndex
	)
{
	Tpm12IOInit(tpmio, TPM_TAG_RQU_COMMAND, TPM_ORD_PcrRead);
	return Tpm12IOWrite32(tpmio, PcrIndex, TRUE);
}

/**
Send PCR Read command to TPM1.2.

@param PcrIndex          The index of the PCR to read.
@param PcrValue          The PCR value.

@retval EFI_SUCCESS      Operation completed successfully.
@retval EFI_DEVICE_ERROR Unexpected device behavior.
**/
EFI_STATUS
Tpm12PcrRead(
	IN UINT32   PcrIndex,
	OUT void    *PcrValue
	)
{
	EFI_STATUS res;
	res = GetTpm12Io();
	if (EFI_ERROR(res)) return res;
	res = Tpm12Cmd_PcrRead(gTpm12Io, PcrIndex);
	if (EFI_ERROR(res)) return res;
	res = Tpm12Transmit(gTpm12Io);
	if (EFI_ERROR(res)) {
		return res;
	}
	Tpm12RespReadBytes(gTpm12Io, PcrValue, sizeof(TPM_PCRVALUE), TRUE);
	return res;
}

EFI_STATUS
Tpm12Cmd_PcrExtend(
	TPM12IO  *tpmio,
	IN  UINT32   PcrIndex,
	IN  UINTN    dataSz,
	IN  VOID     *data
	)
{
	TPM_DIGEST digest;
	Tpm12IOInit(tpmio, TPM_TAG_RQU_COMMAND, TPM_ORD_Extend);
	Sha1Hash(data, dataSz, (UINT8*)&digest);
	Tpm12IOWrite32(tpmio, PcrIndex, TRUE);
	return Tpm12IOWriteBytes(tpmio, &digest, sizeof(digest), TRUE);
}

/**
Send PCR Extend command to TPM1.2.

@param PcrIndex          The index of the PCR to read.
@param dataSz             size of data
@param data               data. Extend PCR with Sha1(data)

@retval EFI_SUCCESS      Operation completed successfully.
@retval EFI_DEVICE_ERROR Unexpected device behavior.
**/
EFI_STATUS
Tpm12PcrExtend(
	IN  UINT32   PcrIndex,
	IN  UINTN    dataSz,
	IN  VOID     *data
	)
{
	EFI_STATUS res;
	res = GetTpm12Io();
	if (EFI_ERROR(res)) return res;
	res = Tpm12Cmd_PcrExtend(gTpm12Io, PcrIndex, dataSz, data);
	if (EFI_ERROR(res)) return res;
	res = Tpm12Transmit(gTpm12Io);
	if (EFI_ERROR(res)) {
		return res;
	}
	return res;
}

EFI_STATUS
Tpm12PcrsSave(
	IN UINTN sPcr,
	IN UINTN ePcr,
	TPM_DIGEST *Pcrs
	) {
	UINT32       i;
	EFI_STATUS   Status = EFI_SUCCESS;
	for (i = (UINT32)sPcr; i <= (UINT32)ePcr; ++i) {
		Status = Tpm12PcrRead(i, &Pcrs[i].digest);
		if (EFI_ERROR(Status)) {
			return Status;
		}
	}
	return Status;
}

EFI_STATUS
Tpm12ReadPcr(
	IN  UINT32    PcrIndex,
	OUT UINT8     *PcrValue,
	OUT UINT32    *PcrSize
	)
{
	TPM_PCRVALUE Value;
	EFI_STATUS   Status;

	if (PcrValue == NULL || PcrSize == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	Status = Tpm12PcrRead(PcrIndex, &Value);
	if (EFI_ERROR(Status)) {
		return Status;
	}

	CopyMem(PcrValue, Value.digest, sizeof(Value.digest));
	*PcrSize = sizeof(Value.digest);
	return EFI_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
// Get Capability
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
Tpm12Cmd_GetCapability(
	TPM12IO *tpmio,
	IN  UINT32    capArea,
	IN  UINT32    subCapSize,
	IN  UINT8     *subCap
	)
{
	EFI_STATUS res;
	Tpm12IOInit(tpmio, TPM_TAG_RQU_COMMAND, TPM_ORD_GetCapability);
	Tpm12IOWrite32(tpmio, capArea, TRUE);
	res = Tpm12IOWrite32(tpmio, subCapSize, TRUE);
	if (subCapSize > 0) {
		res = Tpm12IOWriteBytes(tpmio, subCap, subCapSize, TRUE);
	}
	return res;
}

/**
Send GetCapability command to TPM1.2.

@param capArea           The index of the Capability
@param subCapSize        The size of details.
@param subCap            Details

@retval EFI_SUCCESS      Operation completed successfully.
@retval EFI_DEVICE_ERROR Unexpected device behavior.
**/
EFI_STATUS
EFIAPI
Tpm12GetCapability(
	IN  UINT32    capArea,
	IN  UINT32    subCapSize,
	IN  UINT8     *subCap,
	OUT UINT32    *respSize,
	OUT UINT8     *resp
	)
{
	EFI_STATUS res;
	res = GetTpm12Io();
	if (EFI_ERROR(res)) return res;
	res = Tpm12Cmd_GetCapability(gTpm12Io, capArea, subCapSize, subCap);
	if (EFI_ERROR(res)) return res;
	res = Tpm12Transmit(gTpm12Io);
	if (EFI_ERROR(res)) {
		return res;
	}
	res = Tpm12RespRead32(gTpm12Io, respSize, TRUE);
	if (!EFI_ERROR(res)) {
		res = Tpm12RespReadBytes(gTpm12Io, resp, *respSize, TRUE);
	}
	return res;
}

//////////////////////////////////////////////////////////////////////////
// NV
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
Tpm12GetNvList(
	OUT UINT32    *IndexList,
	IN OUT UINT32 *IndexCount
	) {
	EFI_STATUS  res;
	UINT32      byteCount;
	UINT32      i;
	UINT32      count;

	res = Tpm12GetCapability(TPM_CAP_NV_LIST, 0, NULL, &byteCount, (UINT8*)IndexList);
	if (EFI_ERROR(res)) {
		*IndexCount = 0;
		return res;
	}

	// TPM returns byte count, convert to index count
	count = byteCount / sizeof(UINT32);

	// Indices are returned in big-endian, swap to native
	for (i = 0; i < count; i++) {
		IndexList[i] = SwapBytes32(IndexList[i]);
	}

	*IndexCount = count;
	return EFI_SUCCESS;
}

EFI_STATUS
Tpm12PcrsDigest(
	IN  UINT16     sizeOfSelect,
	IN  UINT8      *pcrSelect,
	IN  TPM_DIGEST *Pcrs,
	OUT TPM_DIGEST *digest
	)
{
	UINTN Sha1CtxSize;
	UINTN i;
	UINTN j;
	UINTN k;
	VOID* Sha1Ctx;
	UINT16 tmp16;
	UINT32 tmp32;

	k = 0;
	for (i = 0; i < sizeOfSelect; ++i) {
		UINT8 tmp = pcrSelect[i];
		for (j = 0; j < 8; ++j) {
			if ((tmp & 1) == 1) {
				k++;
			}
			tmp >>= 1;
		}
	}
	if (k == 0) return EFI_SUCCESS;

	Sha1CtxSize = Sha1GetContextSize();
	Sha1Ctx = MEM_ALLOC(Sha1CtxSize);
	if (Sha1Ctx == NULL) return EFI_BUFFER_TOO_SMALL;
	Sha1Init(Sha1Ctx);
	// Use big-endian (standard TPM wire format)
	tmp16 = SwapBytes16(sizeOfSelect);
	Sha1Update(Sha1Ctx, &tmp16, sizeof(tmp16));
	Sha1Update(Sha1Ctx, pcrSelect, sizeOfSelect);

	tmp32 = SwapBytes32((UINT32)(k * sizeof(TPM_DIGEST)));
	Sha1Update(Sha1Ctx, &tmp32, sizeof(tmp32));

	k = 0;
	for (i = 0; i < sizeOfSelect; ++i) {
		UINT8 tmp = pcrSelect[i];
		for (j = 0; j < 8; ++j) {
			if ((tmp & 1) == 1) {
				Sha1Update(Sha1Ctx, &Pcrs[k], sizeof(TPM_DIGEST));
			}
			tmp >>= 1;
			k++;
		}
	}
	if (Sha1Final(Sha1Ctx, digest->digest)) {
		MEM_FREE(Sha1Ctx);
		return EFI_SUCCESS;
	}
	MEM_FREE(Sha1Ctx);
	return EFI_DEVICE_ERROR;
}

EFI_STATUS
Tpm12NvDetails(
	IN  UINT32    index,
	OUT UINT32    *attr,
	OUT UINT32    *dataSz,
	OUT UINT32    *pcrR,
	OUT UINT32    *pcrW
	) 
{
	EFI_STATUS res;
	TPM_PCR_INFO_SHORT* pcrRead;
	TPM_PCR_INFO_SHORT* pcrWrite;
	UINT8 nvdata[sizeof(TPM_NV_DATA_PUBLIC) + 256];
	UINT8* pos = nvdata;
	UINT32 sz = sizeof(nvdata);
	UINT32 swapindex = SwapBytes32(index);
	res = Tpm12GetCapability(TPM_CAP_NV_INDEX, 4, (UINT8*)&swapindex, &sz, nvdata);
	if(EFI_ERROR(res)) return res;
	Tpm12Parse16(&pos, NULL);
	Tpm12Parse32(&pos, &index);
	pcrRead = (TPM_PCR_INFO_SHORT*)pos;
	Tpm12ParsePcrInfoShort(&pos, NULL);
	pcrWrite = (TPM_PCR_INFO_SHORT*)pos;
	Tpm12ParsePcrInfoShort(&pos, NULL);
	Tpm12Parse16(&pos, NULL);
	Tpm12Parse32(&pos, attr);
	pos += 3;
	Tpm12Parse32(&pos, dataSz);
	if (pcrR != NULL) {
		*pcrR = pcrRead->pcrSelection.pcrSelect[0];
		*pcrR |= pcrRead->pcrSelection.sizeOfSelect > 1 ? pcrRead->pcrSelection.pcrSelect[1] << 8 : 0;
		*pcrR |= pcrRead->pcrSelection.sizeOfSelect > 2 ? pcrRead->pcrSelection.pcrSelect[2] << 16 : 0;
		*pcrR |= pcrRead->pcrSelection.sizeOfSelect > 3 ? pcrRead->pcrSelection.pcrSelect[3] << 24 : 0;
	}
	if (pcrW != NULL) {
		*pcrW =  pcrWrite->pcrSelection.pcrSelect[0];
		*pcrW |= pcrWrite->pcrSelection.sizeOfSelect > 1 ? pcrWrite->pcrSelection.pcrSelect[1] << 8 : 0;
		*pcrW |= pcrWrite->pcrSelection.sizeOfSelect > 2 ? pcrWrite->pcrSelection.pcrSelect[2] << 16 : 0;
		*pcrW |= pcrWrite->pcrSelection.sizeOfSelect > 3 ? pcrWrite->pcrSelection.pcrSelect[3] << 24 : 0;
	}
	return res;
}

//////////////////////////////////////////////////////////////////////////
// OSAP
//////////////////////////////////////////////////////////////////////////

#pragma pack(1)
typedef struct {
	TPM_NONCE nonceOdd;
	TPM_NONCE nonceOddOSAP;
	TPM_NONCE nonceEven;
	TPM_NONCE nonceEvenOSAP;
	TPM_DIGEST SharedSecret;
	TPM_AUTHHANDLE authHandle;
} TPM12_OSAP;
#pragma pack()

EFI_STATUS
Tpm12Cmd_OSAP(
	IN TPM12IO *tpmio,
	IN TPM12_OSAP *osap,
	IN UINT16  entityType,
	IN UINT32  entityValue
	)
{
	EFI_STATUS res;
	Tpm12IOInit(tpmio, TPM_TAG_RQU_COMMAND, TPM_ORD_OSAP);
	res = Tpm12IOWrite16(tpmio, entityType, TRUE);
	res = Tpm12IOWrite32(tpmio, entityValue, TRUE);
	res = Tpm12IOWriteBytes(tpmio, &osap->nonceOddOSAP, sizeof(osap->nonceOddOSAP), TRUE);
	return res;
}

TPM12_OSAP *gTpm12Osap;

// Forward declaration for Tpm12GetRandom (defined later in file)
EFI_STATUS
Tpm12GetRandom(
	IN OUT UINT32     *DataSize,
	OUT    UINT8      *Data
	);

// Forward declaration for Tpm12Seal (defined later in file)
EFI_STATUS
Tpm12Seal(
	IN  TPM_DIGEST *srkAuth,
	IN  TPM_DIGEST *dataAuth,
	IN  UINT32     pcrMask,
	IN  UINT8      *data,
	IN  UINT32     dataSize,
	OUT UINT8      *sealedBlob,
	OUT UINT32     *sealedBlobSize
	);

// Counter for generating unique nonces when random isn't available
STATIC UINT32 gNonceCounter = 0x12345678;

// Initialize OSAP nonces with random or pseudo-random values
STATIC
VOID
Tpm12InitOsapNonces(
	IN OUT TPM12_OSAP *osap
	)
{
	UINT32  rndSize = sizeof(TPM_NONCE);
	UINT32  i;

	// Try to get random from TPM
	if (EFI_ERROR(Tpm12GetRandom(&rndSize, (UINT8*)&osap->nonceOddOSAP)) || rndSize < sizeof(TPM_NONCE)) {
		// Fallback: use counter-based pseudo-random
		for (i = 0; i < sizeof(TPM_NONCE); i++) {
			osap->nonceOddOSAP.nonce[i] = (UINT8)(gNonceCounter >> ((i % 4) * 8));
			gNonceCounter = gNonceCounter * 1103515245 + 12345;  // LCG
		}
	}

	rndSize = sizeof(TPM_NONCE);
	if (EFI_ERROR(Tpm12GetRandom(&rndSize, (UINT8*)&osap->nonceOdd)) || rndSize < sizeof(TPM_NONCE)) {
		// Fallback: use counter-based pseudo-random
		for (i = 0; i < sizeof(TPM_NONCE); i++) {
			osap->nonceOdd.nonce[i] = (UINT8)(gNonceCounter >> ((i % 4) * 8));
			gNonceCounter = gNonceCounter * 1103515245 + 12345;
		}
	}
}

//////////////////////////////////////////////////////////////////////////
// TPM owner auth handling (supports base64-encoded Windows TPM auth)
//////////////////////////////////////////////////////////////////////////

/**
  Get owner auth from password string.
  If the string is base64-encoded (ends with '='), decode it using EDK2 Base64Decode.
  Otherwise, hash the password as UTF-16.

  Windows ConvertTo-TpmOwnerAuth produces base64-encoded SHA-1 hashes like:
  "AAAAAAAAAAAAAAAAAAAAAAAAAAA="

  @param[in]  OwnerPass   Password string (CHAR16)
  @param[out] OwnerAuth   Receives the 20-byte auth value
**/
STATIC
VOID
GetOwnerAuthFromPassword(
	IN  CHAR16     *OwnerPass,
	OUT TPM_DIGEST *OwnerAuth
	)
{
	UINTN         len;
	UINTN         i;
	CHAR8         asciiStr[64];
	UINTN         decodedSize;
	RETURN_STATUS status;

	if (OwnerPass == NULL || OwnerAuth == NULL) {
		return;
	}

	len = StrLen(OwnerPass);

	// Check if this looks like a base64-encoded TPM auth
	// Base64-encoded 20 bytes = 28 characters (with padding ending in '=')
	if (len == 28 && OwnerPass[len - 1] == L'=') {
		//OUT_PRINT(L"SHA1 hash: %s ", OwnerPass);

		// Convert CHAR16 to CHAR8 (base64 is ASCII-only)
		for (i = 0; i < len && i < sizeof(asciiStr) - 1; i++) {
			if (OwnerPass[i] > 127) {
				goto hash_password;  // Non-ASCII, not valid base64
			}
			asciiStr[i] = (CHAR8)OwnerPass[i];
		}
		asciiStr[i] = '\0';

		// Try to decode using EDK2 Base64Decode
		decodedSize = sizeof(TPM_DIGEST);
		status = Base64Decode(asciiStr, len, (UINT8*)OwnerAuth, &decodedSize);
		if (!RETURN_ERROR(status) && decodedSize == sizeof(TPM_DIGEST)) {
			//OUT_PRINT(L"decoded\n");
			return;  // Successfully decoded base64 auth (exactly 20 bytes)
		}
		//OUT_PRINT(L"invalid\n");
	}

hash_password:
	// Not base64 or decode failed - hash as UTF-16 password
	Sha1Hash(OwnerPass, len * 2, (UINT8*)OwnerAuth);
}

EFI_STATUS
Tpm12OSAPStart(
	IN UINT16  entityType,
	IN UINT32  entityValue,
	IN CHAR16    *ownerPass
	)
{
	EFI_STATUS   res;
	TPM_DIGEST   ownerKey;
	UINTN        CtxSize;
	VOID*        HmacCtx;
	res = GetTpm12Io();
	if (EFI_ERROR(res)) return res;
	if (gTpm12Osap == NULL) {
		gTpm12Osap = MEM_ALLOC(sizeof(TPM12_OSAP));
	}
	// Initialize nonces with random values
	Tpm12InitOsapNonces(gTpm12Osap);
	res = Tpm12Cmd_OSAP(gTpm12Io, gTpm12Osap, entityType, entityValue);
	if (EFI_ERROR(res)) return res;
	res = Tpm12Transmit(gTpm12Io);
	if (EFI_ERROR(res)) {
		return res;
	}
	Tpm12RespRead32(gTpm12Io, &gTpm12Osap->authHandle, FALSE);
	Tpm12RespReadBytes(gTpm12Io, &gTpm12Osap->nonceEven, sizeof(TPM_NONCE), FALSE);
	res = Tpm12RespReadBytes(gTpm12Io, &gTpm12Osap->nonceEvenOSAP, sizeof(TPM_NONCE), FALSE);
	if (EFI_ERROR(res)) return res;
	// Get auth - either from base64 or by hashing password
	GetOwnerAuthFromPassword(ownerPass, &ownerKey);
	CtxSize = HmacSha1GetContextSize();
	HmacCtx = MEM_ALLOC(CtxSize);
	HmacSha1Init(HmacCtx, (UINT8*)&ownerKey, sizeof(ownerKey));
	HmacSha1Update(HmacCtx, &gTpm12Osap->nonceEvenOSAP, sizeof(gTpm12Osap->nonceEvenOSAP));
	HmacSha1Update(HmacCtx, &gTpm12Osap->nonceOddOSAP, sizeof(gTpm12Osap->nonceOddOSAP));
	HmacSha1Final(HmacCtx, (UINT8*)&gTpm12Osap->SharedSecret);
	MEM_FREE(HmacCtx);
	return res;
}

// OSAP start with raw auth value (for well-known SRK auth)
EFI_STATUS
Tpm12OSAPStartRaw(
	IN UINT16     entityType,
	IN UINT32     entityValue,
	IN TPM_DIGEST *authValue
	)
{
	EFI_STATUS   res;
	UINTN        CtxSize;
	VOID*        HmacCtx;
	res = GetTpm12Io();
	if (EFI_ERROR(res)) return res;
	if (gTpm12Osap == NULL) {
		gTpm12Osap = MEM_ALLOC(sizeof(TPM12_OSAP));
	}
	// Initialize nonces with random values
	Tpm12InitOsapNonces(gTpm12Osap);
	res = Tpm12Cmd_OSAP(gTpm12Io, gTpm12Osap, entityType, entityValue);
	if (EFI_ERROR(res)) return res;
	res = Tpm12Transmit(gTpm12Io);
	if (EFI_ERROR(res)) {
		return res;
	}
	Tpm12RespRead32(gTpm12Io, &gTpm12Osap->authHandle, FALSE);
	Tpm12RespReadBytes(gTpm12Io, &gTpm12Osap->nonceEven, sizeof(TPM_NONCE), FALSE);
	res = Tpm12RespReadBytes(gTpm12Io, &gTpm12Osap->nonceEvenOSAP, sizeof(TPM_NONCE), FALSE);
	if (EFI_ERROR(res)) return res;
	// Use raw auth value directly
	CtxSize = HmacSha1GetContextSize();
	HmacCtx = MEM_ALLOC(CtxSize);
	HmacSha1Init(HmacCtx, (UINT8*)authValue, sizeof(TPM_DIGEST));
	HmacSha1Update(HmacCtx, &gTpm12Osap->nonceEvenOSAP, sizeof(gTpm12Osap->nonceEvenOSAP));
	HmacSha1Update(HmacCtx, &gTpm12Osap->nonceOddOSAP, sizeof(gTpm12Osap->nonceOddOSAP));
	HmacSha1Final(HmacCtx, (UINT8*)&gTpm12Osap->SharedSecret);
	MEM_FREE(HmacCtx);
	return res;
}

EFI_STATUS
Tpm12OSAPAppend(
	IN  UINT8 continueSession
	)
{
	EFI_STATUS res;
	UINTN        CtxSize;
	VOID*        HmacCtx;
	TPM_DIGEST   hashCmd;
	TPM_DIGEST   auth;

	Tpm12IOWrite32(gTpm12Io, gTpm12Osap->authHandle, FALSE);
	Tpm12IOWriteBytes(gTpm12Io, &gTpm12Osap->nonceOdd, sizeof(gTpm12Osap->nonceOdd), FALSE);
	res = Tpm12IOWrite8(gTpm12Io, continueSession, FALSE);
	*((UINT16*)gTpm12Io->Cmd) = SwapBytes16(TPM_TAG_RQU_AUTH1_COMMAND); // Update Tag
	Sha1Final(gTpm12Io->Hash, (UINT8*)&hashCmd);
	CtxSize = HmacSha1GetContextSize();
	HmacCtx = MEM_ALLOC(CtxSize);
	if (HmacCtx == NULL) return EFI_BUFFER_TOO_SMALL;
	HmacSha1Init(HmacCtx, (UINT8*)&gTpm12Osap->SharedSecret, sizeof(gTpm12Osap->SharedSecret));
	HmacSha1Update(HmacCtx, &hashCmd, sizeof(hashCmd));
	HmacSha1Update(HmacCtx, &gTpm12Osap->nonceEven, sizeof(gTpm12Osap->nonceEven));
	HmacSha1Update(HmacCtx, &gTpm12Osap->nonceOdd, sizeof(gTpm12Osap->nonceOdd));
	HmacSha1Update(HmacCtx, &continueSession, sizeof(continueSession));
	HmacSha1Final(HmacCtx, (UINT8*)&auth);
	MEM_FREE(HmacCtx);
	res = Tpm12IOWriteBytes(gTpm12Io, &auth, sizeof(auth), FALSE);
	return res;
}

//////////////////////////////////////////////////////////////////////////
// OIAP - Object Independent Authorization Protocol
// Needed for TPM_Unseal (doesn't require knowledge of object auth beforehand)
//////////////////////////////////////////////////////////////////////////
#pragma pack(1)
typedef struct {
	TPM_NONCE      nonceOdd;
	TPM_NONCE      nonceEven;
	TPM_AUTHHANDLE authHandle;
} TPM12_OIAP;
#pragma pack()

TPM12_OIAP *gTpm12Oiap = NULL;

EFI_STATUS
Tpm12OIAPStart(VOID)
{
	EFI_STATUS   res;
	res = GetTpm12Io();
	if (EFI_ERROR(res)) return res;
	if (gTpm12Oiap == NULL) {
		gTpm12Oiap = MEM_ALLOC(sizeof(TPM12_OIAP));
		if (gTpm12Oiap == NULL) return EFI_OUT_OF_RESOURCES;
	}

	Tpm12IOInit(gTpm12Io, TPM_TAG_RQU_COMMAND, TPM_ORD_OIAP);
	res = Tpm12Transmit(gTpm12Io);
	if (EFI_ERROR(res)) {
		return res;
	}
	Tpm12RespRead32(gTpm12Io, &gTpm12Oiap->authHandle, FALSE);
	res = Tpm12RespReadBytes(gTpm12Io, &gTpm12Oiap->nonceEven, sizeof(TPM_NONCE), FALSE);
	return res;
}

// Append OIAP authorization with specified auth value
EFI_STATUS
Tpm12OIAPAppend(
	IN  TPM_DIGEST *authValue,
	IN  UINT8      continueSession
	)
{
	EFI_STATUS res;
	UINTN      CtxSize;
	VOID       *HmacCtx;
	TPM_DIGEST hashCmd;
	TPM_DIGEST auth;

	Tpm12IOWrite32(gTpm12Io, gTpm12Oiap->authHandle, FALSE);
	Tpm12IOWriteBytes(gTpm12Io, &gTpm12Oiap->nonceOdd, sizeof(gTpm12Oiap->nonceOdd), FALSE);
	res = Tpm12IOWrite8(gTpm12Io, continueSession, FALSE);
	*((UINT16*)gTpm12Io->Cmd) = SwapBytes16(TPM_TAG_RQU_AUTH1_COMMAND); // Update Tag

	// Calculate command hash
	Sha1Final(gTpm12Io->Hash, (UINT8*)&hashCmd);

	// HMAC = HMAC-SHA1(authValue, hashCmd || nonceEven || nonceOdd || continueSession)
	CtxSize = HmacSha1GetContextSize();
	HmacCtx = MEM_ALLOC(CtxSize);
	if (HmacCtx == NULL) return EFI_BUFFER_TOO_SMALL;
	HmacSha1Init(HmacCtx, (UINT8*)authValue, sizeof(TPM_DIGEST));
	HmacSha1Update(HmacCtx, &hashCmd, sizeof(hashCmd));
	HmacSha1Update(HmacCtx, &gTpm12Oiap->nonceEven, sizeof(gTpm12Oiap->nonceEven));
	HmacSha1Update(HmacCtx, &gTpm12Oiap->nonceOdd, sizeof(gTpm12Oiap->nonceOdd));
	HmacSha1Update(HmacCtx, &continueSession, sizeof(continueSession));
	HmacSha1Final(HmacCtx, (UINT8*)&auth);
	MEM_FREE(HmacCtx);
	res = Tpm12IOWriteBytes(gTpm12Io, &auth, sizeof(auth), FALSE);
	return res;
}

// Parse OIAP response and verify auth
EFI_STATUS
Tpm12OIAPVerifyResponse(
	IN  TPM_DIGEST *authValue,
	IN  UINT8      continueSession
	)
{
	EFI_STATUS res;
	UINTN      CtxSize;
	VOID       *HmacCtx;
	TPM_DIGEST hashResp;
	TPM_DIGEST expectedAuth;
	TPM_NONCE  newNonceEven;
	TPM_DIGEST respAuth;
	UINT8      respContinue;

	// Finalize the response hash BEFORE reading auth data
	// Hash = SHA1(returnCode || ordinal || outParams)
	// Note: returnCode is hashed by Tpm12Transmit, outParams by caller
	Sha1Final(gTpm12Io->Hash, (UINT8*)&hashResp);

	// Read response auth data (at end of response)
	// nonceEven (20) + continueSession (1) + authData (20)
	// These are NOT part of outParams hash, just used for HMAC
	res = Tpm12RespReadBytes(gTpm12Io, &newNonceEven, sizeof(TPM_NONCE), FALSE);
	if (EFI_ERROR(res)) return res;
	res = Tpm12RespReadBytes(gTpm12Io, &respContinue, 1, FALSE);
	if (EFI_ERROR(res)) return res;
	res = Tpm12RespReadBytes(gTpm12Io, &respAuth, sizeof(TPM_DIGEST), FALSE);
	if (EFI_ERROR(res)) return res;

	// Calculate expected response auth
	// HMAC = HMAC-SHA1(authValue, SHA1(returnCode || ordinal || outParams) || nonceEven || nonceOdd || continueSession)

	CtxSize = HmacSha1GetContextSize();
	HmacCtx = MEM_ALLOC(CtxSize);
	if (HmacCtx == NULL) return EFI_BUFFER_TOO_SMALL;
	HmacSha1Init(HmacCtx, (UINT8*)authValue, sizeof(TPM_DIGEST));
	HmacSha1Update(HmacCtx, &hashResp, sizeof(hashResp));
	HmacSha1Update(HmacCtx, &newNonceEven, sizeof(newNonceEven));
	HmacSha1Update(HmacCtx, &gTpm12Oiap->nonceOdd, sizeof(gTpm12Oiap->nonceOdd));
	HmacSha1Update(HmacCtx, &respContinue, sizeof(respContinue));
	HmacSha1Final(HmacCtx, (UINT8*)&expectedAuth);
	MEM_FREE(HmacCtx);

	if (CompareMem(&respAuth, &expectedAuth, sizeof(TPM_DIGEST)) != 0) {
		return EFI_SECURITY_VIOLATION;
	}

	// Update nonceEven for next command
	CopyMem(&gTpm12Oiap->nonceEven, &newNonceEven, sizeof(TPM_NONCE));
	return EFI_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
// NV
//////////////////////////////////////////////////////////////////////////

// Forward declaration (defined later in SRK sealing section)
STATIC VOID Tpm12InitOiapNonce(IN OUT TPM_NONCE *nonce);

EFI_STATUS
Tpm12WritePcrInfo(
	IN TPM12IO  *tpmio,
	IN UINT16       sizeOfSelect,
	IN UINT8        *pcrSelect,
	IN UINT8        localityAtRelease,
	IN TPM_DIGEST*  pcrs)
{
	TPM_DIGEST   digestAtRelease;
	ZeroMem(&digestAtRelease, sizeof(digestAtRelease));
	Tpm12IOWrite16   (tpmio, sizeOfSelect, TRUE);
	Tpm12IOWriteBytes(tpmio, pcrSelect, sizeOfSelect, TRUE);
	Tpm12IOWrite8(tpmio, localityAtRelease, TRUE);
	Tpm12PcrsDigest(sizeOfSelect, pcrSelect, pcrs, &digestAtRelease);
	return Tpm12IOWriteBytes(tpmio, &digestAtRelease, sizeof(TPM_DIGEST), TRUE);
}

TPM_DIGEST gTpm12Pcrs[24];
TPM_DIGEST gTpm12OwnerPass;

VOID
PcrUpdateMask(
	UINT32 mask,
	UINT8  *pcr) 
{
	pcr[0] = (UINT8)(mask & 0xFF);
	pcr[1] = (UINT8)((mask >> 8) & 0xFF);
	pcr[2] = (UINT8)((mask >> 16) & 0xFF);
}

EFI_STATUS
Tpm12NvSpaceWithAuth(
	IN UINT32      index,
	IN UINT32      size,
	IN CHAR16      *ownerPass,
	TPM_DIGEST     *pcrs,
	IN UINT32      pcrReadMask,
	IN UINT32      pcrWriteMask,
	IN UINT32      Attributes,
	IN UINT8       bReadSTClear,
	IN UINT8       bWriteSTClear,
	IN UINT8       bWriteDefine,
	IN TPM_DIGEST  *nvAuth OPTIONAL
	) {
	EFI_STATUS   res;
	TPM_DIGEST   encAuth;
	UINT8        pcrRead[3];
	UINT8        pcrWrite[3];

	PcrUpdateMask(pcrReadMask, pcrRead);
	PcrUpdateMask(pcrWriteMask, pcrWrite);

	res = Tpm12OSAPStart(TPM_ET_OWNER, TPM_KH_OWNER, ownerPass);
	if (EFI_ERROR(res)) {
		return res;
	}

	// Encrypt nvAuth using ADIP protocol if provided
	if (nvAuth != NULL) {
		UINTN      Sha1CtxSize;
		VOID       *Sha1Ctx;
		TPM_DIGEST encKey;
		UINTN      i;

		// ADIP encryption: encAuth = SHA1(sharedSecret || nonceEven) XOR nvAuth
		Sha1CtxSize = Sha1GetContextSize();
		Sha1Ctx = MEM_ALLOC(Sha1CtxSize);
		if (Sha1Ctx == NULL) {
			return EFI_OUT_OF_RESOURCES;
		}
		Sha1Init(Sha1Ctx);
		Sha1Update(Sha1Ctx, &gTpm12Osap->SharedSecret, sizeof(gTpm12Osap->SharedSecret));
		Sha1Update(Sha1Ctx, &gTpm12Osap->nonceEven, sizeof(gTpm12Osap->nonceEven));
		Sha1Final(Sha1Ctx, (UINT8*)&encKey);
		MEM_FREE(Sha1Ctx);

		// XOR to get encrypted auth
		for (i = 0; i < sizeof(TPM_DIGEST); i++) {
			encAuth.digest[i] = encKey.digest[i] ^ nvAuth->digest[i];
		}
		SetMem(&encKey, sizeof(encKey), 0);
	} else {
		// No auth - use dummy value
		SetMem(&encAuth, sizeof(encAuth), 0xEA);
	}

	Tpm12IOInit(gTpm12Io, TPM_TAG_RQU_AUTH1_COMMAND, TPM_ORD_NV_DefineSpace);
	// NV_DATA_PUBLIC
	Tpm12IOWrite16(gTpm12Io, TPM_TAG_NV_DATA_PUBLIC, TRUE);
	Tpm12IOWrite32(gTpm12Io, index, TRUE);
	Tpm12WritePcrInfo(gTpm12Io, sizeof(pcrRead) , pcrRead,  0x1F, pcrs);
	Tpm12WritePcrInfo(gTpm12Io, sizeof(pcrWrite), pcrWrite, 0x1F, pcrs);
	Tpm12IOWrite16(gTpm12Io, TPM_TAG_NV_ATTRIBUTES, TRUE);
	Tpm12IOWrite32(gTpm12Io, Attributes, TRUE);
	Tpm12IOWrite8(gTpm12Io, bReadSTClear, TRUE);
	Tpm12IOWrite8(gTpm12Io, bWriteSTClear, TRUE);
	Tpm12IOWrite8(gTpm12Io, bWriteDefine, TRUE);
	Tpm12IOWrite32(gTpm12Io, size, TRUE);
	//
	Tpm12IOWriteBytes(gTpm12Io, &encAuth, sizeof(encAuth), TRUE);
	// OSAP
	Tpm12OSAPAppend(0);

	SetMem(&encAuth, sizeof(encAuth), 0);
	res = Tpm12Transmit(gTpm12Io);
	if (EFI_ERROR(res)) {
		return res;
	}
	return res;
}

EFI_STATUS
Tpm12NvSpace(
	IN UINT32    index,
	IN UINT32    size,
	IN CHAR16    *ownerPass,
	TPM_DIGEST   *pcrs,
	IN UINT32    pcrReadMask,
	IN UINT32    pcrWriteMask,
	IN UINT32    Attributes,
	IN UINT8     bReadSTClear,
	IN UINT8     bWriteSTClear,
	IN UINT8     bWriteDefine
	) {
	// Wrapper for backward compatibility - no NV auth
	return Tpm12NvSpaceWithAuth(index, size, ownerPass, pcrs, pcrReadMask, pcrWriteMask,
	                            Attributes, bReadSTClear, bWriteSTClear, bWriteDefine, NULL);
}

EFI_STATUS
Tpm12Cmd_NvRead(
	IN TPM12IO    *tpmio,
	IN TPM_NV_INDEX   NvIndex,
	IN UINT32         Offset,
	IN UINT32         DataSize
	)
{
	EFI_STATUS res;
	CE(Tpm12IOInit(tpmio, TPM_TAG_RQU_COMMAND, TPM_ORD_NV_ReadValue));
	CE(Tpm12IOWrite32(tpmio, NvIndex, TRUE));
	CE(Tpm12IOWrite32(tpmio, Offset, TRUE));
	CE(Tpm12IOWrite32(tpmio, DataSize, TRUE));
err:
	return res;
}

/**
Send NV ReadValue command to TPM1.2.

@param NvIndex           The index of the area to set.
@param Offset            The offset into the area.
@param DataSize          The size of the data area.
@param Data              The data to set the area to.

@retval EFI_SUCCESS      Operation completed successfully.
@retval EFI_DEVICE_ERROR Unexpected device behavior.
**/
EFI_STATUS
Tpm12NvRead(
	IN TPM_NV_INDEX   NvIndex,
	IN UINT32         Offset,
	IN OUT UINT32     *DataSize,
	OUT UINT8         *Data
	)
{
	EFI_STATUS res;
	res = GetTpm12Io();
	if (EFI_ERROR(res)) return res;
	res = Tpm12Cmd_NvRead(gTpm12Io, NvIndex,Offset,*DataSize);
	if (EFI_ERROR(res)) return res;
	res = Tpm12Transmit(gTpm12Io);
	if (EFI_ERROR(res)) {
		return res;
	}
	res = Tpm12RespRead32(gTpm12Io, DataSize, TRUE);
	if (!EFI_ERROR(res)) {
		res = Tpm12RespReadBytes(gTpm12Io, Data, *DataSize, TRUE);
	}
	return res;
}

/**
Send NV ReadValueAuth command to TPM1.2 with OIAP authorization.

@param NvIndex           The index of the area to read.
@param Offset            The offset into the area.
@param DataSize          On input, the size of the data buffer.
                         On output, the size of the data read.
@param Data              Buffer to receive the data.
@param nvAuth            The authorization value for the NV index.

@retval EFI_SUCCESS      Operation completed successfully.
@retval EFI_DEVICE_ERROR Unexpected device behavior.
**/
EFI_STATUS
Tpm12NvReadAuth(
	IN TPM_NV_INDEX   NvIndex,
	IN UINT32         Offset,
	IN OUT UINT32     *DataSize,
	OUT UINT8         *Data,
	IN TPM_DIGEST     *nvAuth
	)
{
	EFI_STATUS res;

	res = GetTpm12Io();
	if (EFI_ERROR(res)) return res;

	// Start OIAP session
	CE(Tpm12OIAPStart());

	// Initialize nonceOdd with random value
	Tpm12InitOiapNonce(&gTpm12Oiap->nonceOdd);

	// Build TPM_NV_ReadValueAuth command
	// inParamDigest = SHA1(ordinal || nvIndex || offset || dataSize)
	CE(Tpm12IOInit(gTpm12Io, TPM_TAG_RQU_AUTH1_COMMAND, TPM_ORD_NV_ReadValueAuth));
	CE(Tpm12IOWrite32(gTpm12Io, NvIndex, TRUE));
	CE(Tpm12IOWrite32(gTpm12Io, Offset, TRUE));
	CE(Tpm12IOWrite32(gTpm12Io, *DataSize, TRUE));

	// Append OIAP authorization
	CE(Tpm12OIAPAppend(nvAuth, 0));

	res = Tpm12Transmit(gTpm12Io);
	if (EFI_ERROR(res)) {
		goto err;
	}

	// Read response data size and data (before verifying auth)
	res = Tpm12RespRead32(gTpm12Io, DataSize, TRUE);
	if (EFI_ERROR(res)) goto err;
	res = Tpm12RespReadBytes(gTpm12Io, Data, *DataSize, TRUE);
	if (EFI_ERROR(res)) goto err;

	// Verify response authorization
	res = Tpm12OIAPVerifyResponse(nvAuth, 0);

err:
	return res;
}

EFI_STATUS
Tpm12Cmd_NvWrite(
	IN TPM12IO    *tpmio,
	IN TPM_NV_INDEX   NvIndex,
	IN UINT32         Offset,
	IN UINT32         DataSize,
	IN UINT8          *Data
	)
{
	EFI_STATUS res;
	CE(Tpm12IOInit(tpmio, TPM_TAG_RQU_COMMAND, TPM_ORD_NV_WriteValue));
	CE(Tpm12IOWrite32(tpmio, NvIndex, TRUE));
	CE(Tpm12IOWrite32(tpmio, Offset, TRUE));
	CE(Tpm12IOWrite32(tpmio, DataSize, TRUE));
	CE(Tpm12IOWriteBytes(tpmio, Data, DataSize, TRUE));
err:
	return res;
}

/**
Send NV WriteValue command to TPM1.2.

@param NvIndex           The index of the area to set.
@param Offset            The offset into the NV Area.
@param DataSize          The size of the data parameter.
@param Data              The data to set the area to.

@retval EFI_SUCCESS      Operation completed successfully.
@retval EFI_DEVICE_ERROR Unexpected device behavior.
**/
EFI_STATUS
EFIAPI
Tpm12NvWrite(
	IN TPM_NV_INDEX   NvIndex,
	IN UINT32         Offset,
	IN UINT32         DataSize,
	IN UINT8          *Data,
	CHAR16            *ownerPass
	)
{
	EFI_STATUS res;
	res = GetTpm12Io();
	if (EFI_ERROR(res)) return res;
	res = Tpm12OSAPStart(TPM_ET_OWNER, TPM_KH_OWNER, ownerPass);
	if (EFI_ERROR(res)) {
		return res;
	}
	res = Tpm12Cmd_NvWrite(gTpm12Io, NvIndex, Offset, DataSize, Data);
	if (EFI_ERROR(res)) return res;
	// OSAP
	Tpm12OSAPAppend(0);
	res = Tpm12Transmit(gTpm12Io);
	if (EFI_ERROR(res)) {
		return res;
	}
	return res;
}

//////////////////////////////////////////////////////////////////////////
// Random
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
Tpm12GetRandom(
	IN OUT UINT32     *DataSize,
	OUT    UINT8      *Data
	)
{
	EFI_STATUS res;
	res = GetTpm12Io();
	if (EFI_ERROR(res)) return res;
	CE(Tpm12IOInit(gTpm12Io, TPM_TAG_RQU_COMMAND, TPM_ORD_GetRandom));
	CE(Tpm12IOWrite32(gTpm12Io, *DataSize, TRUE));
	if (EFI_ERROR(res)) return res;
	res = Tpm12Transmit(gTpm12Io);
	if (EFI_ERROR(res)) {
		return res;
	}
	res = Tpm12RespRead32(gTpm12Io, DataSize, TRUE);
	if (!EFI_ERROR(res)) {
		res = Tpm12RespReadBytes(gTpm12Io, Data, *DataSize, TRUE);
	}
err:
	return res;
}

//////////////////////////////////////////////////////////////////////////
// Protocol
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
Tpm12LibGetRandom(
	IN   TPM_LIB_PROTOCOL*  tpm,
	IN   UINT32             DataSize,
	OUT  UINT8              *Data
	)
{
	UINT32             remains = DataSize;
	UINT32             gotBytes = 0;
	UINT8              *rnd = Data;
	EFI_STATUS         res = EFI_SUCCESS;
	while (remains > 0)
	{
		gotBytes = remains;
		res = Tpm12GetRandom(&gotBytes, rnd);
		if (EFI_ERROR(res)) return res;
		rnd += gotBytes;
		remains -= gotBytes;
	}
	return res;
}

EFI_STATUS
Tpm12LibMeasure(
	TPM_LIB_PROTOCOL* tpm,
	IN UINTN          index,
	IN UINTN          dataSz,
	IN VOID*          data
	) 
{
	EFI_STATUS res;
	TPM_DIGEST hash;
	
	CE(Sha1Hash(data, dataSz, (UINT8*)&hash));
	CE(Tpm12PcrExtend((UINT32)index, sizeof(hash), &hash));

err:
	return res;
}

TPM_LIB_PROTOCOL* gTpm = (TPM_LIB_PROTOCOL*)NULL;

STATIC
UINT32
Tpm12ResolveNvIndex(
	IN UINT32 NvIndex
	)
{
	return NvIndex;
}

BOOLEAN
Tpm12IsConfigured(
	IN UINT32 NvIndex
	)
{
	EFI_STATUS   res;
	UINT32       DataNvIndex;
	UINT32       dataSz;
	UINT32       attr;
	UINT32       pcrR;
	UINT32       pcrW;

	if (EFI_ERROR(InitTpm12())) {
		return FALSE;
	}

	DataNvIndex = Tpm12ResolveNvIndex(NvIndex);

	res = Tpm12NvDetails(DataNvIndex, &attr, &dataSz, &pcrR, &pcrW);
	if (EFI_ERROR(res)) return FALSE;
	if (dataSz < DC_TPM_SEALED_MIN_SIZE) return FALSE;
	return TRUE;
}

BOOLEAN
Tpm12IsOpen(
	IN UINT32 NvIndex
	)
{
	EFI_STATUS   res;
	UINT32       DataNvIndex;
	UINT32       PcrInfoNvIndex;
	UINT32       sz = 64;  // Just read a small amount to test
	UINT8        data[64];
	UINT8        pcrInfoBuf[DC_TPM_PCRINFO_BASE_SIZE];
	DC_TPM_PCRINFO_DATA *pcrInfo = (DC_TPM_PCRINFO_DATA*)pcrInfoBuf;
	UINT32       pcrInfoSz;
	UINT32       nvDataSz;
	UINT32       attr;

	if (!Tpm12IsConfigured(NvIndex)) {
		return FALSE;
	}

	DataNvIndex = Tpm12ResolveNvIndex(NvIndex);
	PcrInfoNvIndex = DC_TPM_NV_INDEX_TO_PCRS(DataNvIndex);

	// Check if PIN is required or PCR binding exists by reading PcrInfo NV
	BOOLEAN pinRequired = FALSE;
	BOOLEAN pcrBinding = FALSE;
	res = Tpm12NvDetails(PcrInfoNvIndex, &attr, &nvDataSz, NULL, NULL);
	if (!EFI_ERROR(res) && nvDataSz >= DC_TPM_PCRINFO_BASE_SIZE) {
		pcrInfoSz = DC_TPM_PCRINFO_BASE_SIZE;
		res = Tpm12NvRead(PcrInfoNvIndex, 0, &pcrInfoSz, pcrInfoBuf);
		if (!EFI_ERROR(res) && pcrInfo->Magic == DC_TPM_PCRINFO_MAGIC) {
			pinRequired = (pcrInfo->Flags & DC_TPM_FLAG_PIN_REQUIRED) != 0;
			pcrBinding = (pcrInfo->PcrMask != 0);
		}
	}

	if (pinRequired) {
		// PIN required - we can't test PCR state without PIN
		// Return TRUE to avoid false "PCR mismatch" error
		// The PIN_REQUIRED flag is returned via DcGetInfo
		return TRUE;
	}

	// Test if NV can be read (checks PCR state)
	// If PCR binding exists, we must use authenticated read with zeros auth
	// because AUTHREAD is set and unauthenticated read would fail
	if (pcrBinding) {
		TPM_DIGEST nvAuth;
		SetMem(&nvAuth, sizeof(nvAuth), 0);
		res = Tpm12NvReadAuth(DataNvIndex, 0, &sz, data, &nvAuth);
	} else {
		res = Tpm12NvRead(DataNvIndex, 0, &sz, data);
	}
	SetMem(data, sizeof(data), 0);
	return !EFI_ERROR(res);
}

EFI_STATUS
Tpm12SealPassword(
	IN  UINT32    NvIndex,
	IN  VOID      *password,
	IN  UINT32    passwordSize,
	IN  UINT32    passwordType,
	IN  UINT32    pcrMask,
	IN  CHAR16    *ownerPwd,
	IN  CHAR16    *tpmPin OPTIONAL,
	IN  VOID      *info OPTIONAL,
	IN  UINT32    infoSize
	)
{
	EFI_STATUS         res;
	UINT32             DataNvIndex;
	UINT32             PcrInfoNvIndex;
	UINT8              sealedBuffer[DC_TPM_SEALED_MAX_SIZE];
	DC_TPM_SEALED_DATA *sealedData = (DC_TPM_SEALED_DATA *)sealedBuffer;
	UINT32             sealedSize;
	UINT8              pcrInfoBuf[DC_TPM_PCRINFO_BASE_SIZE + DC_TPM_INFO_MAX_SIZE];
	DC_TPM_PCRINFO_DATA *pcrInfo = (DC_TPM_PCRINFO_DATA*)pcrInfoBuf;
	UINT32             pcrInfoSize;
	BOOLEAN            usePin = FALSE;
	TPM_DIGEST         nvAuth;
	TPM_DIGEST         *pNvAuth = NULL;
	UINT32             nvAttributes;

	if (password == NULL || passwordSize == 0 || ownerPwd == NULL) {
		return EFI_INVALID_PARAMETER;
	}
	if (passwordSize > DC_TPM_SEALED_MAX_SIZE - DC_TPM_SEALED_BASE_SIZE) {
		return EFI_BAD_BUFFER_SIZE;
	}
	if (infoSize > DC_TPM_INFO_MAX_SIZE) {
		return EFI_BAD_BUFFER_SIZE;
	}

	CE(InitTpm12());

	// Derive nvAuth from PIN if provided
	if (tpmPin != NULL && tpmPin[0] != L'\0') {
		Sha1Hash(tpmPin, StrLen(tpmPin) * sizeof(CHAR16), (UINT8*)&nvAuth);
		usePin = TRUE;
		pNvAuth = &nvAuth;
	}

	DataNvIndex = Tpm12ResolveNvIndex(NvIndex);
	PcrInfoNvIndex = DC_TPM_NV_INDEX_TO_PCRS(DataNvIndex);

	CE(Tpm12PcrsSave(0, 23, gTpm12Pcrs));

	// Delete existing NV spaces (ignore errors)
	Tpm12NvSpace(DataNvIndex, 0, ownerPwd, gTpm12Pcrs, 0, 0, TPM_NV_PER_OWNERWRITE, 0, 0, 0);
	Tpm12NvSpace(PcrInfoNvIndex, 0, ownerPwd, gTpm12Pcrs, 0, 0, TPM_NV_PER_OWNERWRITE, 0, 0, 0);

	// Set NV attributes based on PIN usage and PCR binding
	// TPM_NV_PER_OWNERWRITE = owner can write
	// TPM_NV_PER_AUTHREAD = requires auth to read
	//
	// IMPORTANT: For PCR binding to be enforced, AUTHREAD must be set.
	// TPM_NV_ReadValue (unauthenticated) does NOT check pcrInfoRead.
	// Only TPM_NV_ReadValueAuth checks PCRs.
	// So if pcrMask is set, we MUST use AUTHREAD even without a PIN.
	nvAttributes = TPM_NV_PER_OWNERWRITE;
	if (usePin || pcrMask != 0) {
		nvAttributes |= TPM_NV_PER_AUTHREAD;
		// If no PIN but PCR binding requested, use well-known (zeros) auth
		if (!usePin) {
			SetMem(&nvAuth, sizeof(nvAuth), 0);
			pNvAuth = &nvAuth;
		}
	}

	// Calculate sealed data size (padded to 16 bytes, min 96)
	sealedSize = DC_TPM_SEALED_DATA_SIZE(passwordSize);

	// Create NV space with PCR protection and optional auth
	CE(Tpm12NvSpaceWithAuth(DataNvIndex, sealedSize, ownerPwd,
	                        gTpm12Pcrs, pcrMask, 0, nvAttributes, 0, 0, 0, pNvAuth));

	// Prepare sealed data structure
	SetMem(sealedBuffer, sizeof(sealedBuffer), 0);
	sealedData->Magic = DC_TPM_SEALED_MAGIC;
	sealedData->Version = DC_TPM_SEALED_VERSION;
	sealedData->PasswordSize = (UINT16)passwordSize;
	sealedData->PasswordType = passwordType;
	CopyMem(sealedData->Password, password, passwordSize);

	// Calculate checksum
	gBS->CalculateCrc32(password, passwordSize, &sealedData->Checksum);

	// Write sealed data
	CE(Tpm12NvWrite(DataNvIndex, 0, sealedSize,
	                sealedBuffer, ownerPwd));

	// Create and write PCR info NV (no PCR binding - just for storage)
	pcrInfoSize = DC_TPM_PCRINFO_BASE_SIZE + infoSize;
	SetMem(pcrInfoBuf, sizeof(pcrInfoBuf), 0);
	pcrInfo->Magic = DC_TPM_PCRINFO_MAGIC;
	pcrInfo->Version = DC_TPM_PCRINFO_VERSION;
	pcrInfo->PcrMask = pcrMask;
	pcrInfo->Flags = 0;
	if (usePin) {
		pcrInfo->Flags |= DC_TPM_FLAG_PIN_REQUIRED;
	}
	pcrInfo->InfoSize = (UINT16)infoSize;
	if (info != NULL && infoSize > 0) {
		CopyMem(pcrInfo->InfoData, info, infoSize);
	}

	CE(Tpm12NvSpace(PcrInfoNvIndex, pcrInfoSize, ownerPwd,
	                gTpm12Pcrs, 0, 0, TPM_NV_PER_OWNERWRITE, 0, 0, 0));
	CE(Tpm12NvWrite(PcrInfoNvIndex, 0, pcrInfoSize,
	                pcrInfoBuf, ownerPwd));

err:
	SetMem(sealedBuffer, sizeof(sealedBuffer), 0);
	SetMem(pcrInfoBuf, sizeof(pcrInfoBuf), 0);
	SetMem(&nvAuth, sizeof(nvAuth), 0);
	return res;
}

EFI_STATUS
Tpm12UnsealPassword(
	IN  UINT32    NvIndex,
	OUT VOID      *password,
	OUT UINT32    *passwordSize,
	OUT UINT32    *passwordType,
	IN  CHAR16    *tpmPin OPTIONAL
	)
{
	EFI_STATUS         res;
	UINT32             DataNvIndex;
	UINT32             PcrInfoNvIndex;
	UINT8              sealedBuffer[DC_TPM_SEALED_MAX_SIZE];
	DC_TPM_SEALED_DATA *sealedData = (DC_TPM_SEALED_DATA *)sealedBuffer;
	UINT32             nvSize = 0;
	UINT32             crc = 0;
	BOOLEAN            pinRequired = FALSE;
	TPM_DIGEST         nvAuth;
	UINT8              pcrInfoBuf[DC_TPM_PCRINFO_BASE_SIZE];
	DC_TPM_PCRINFO_DATA *pcrInfo = (DC_TPM_PCRINFO_DATA*)pcrInfoBuf;
	UINT32             pcrInfoSz;
	UINT32             nvDataSz;
	UINT32             attr;

	if (password == NULL || passwordSize == NULL || passwordType == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	CE(InitTpm12());

	DataNvIndex = Tpm12ResolveNvIndex(NvIndex);
	PcrInfoNvIndex = DC_TPM_NV_INDEX_TO_PCRS(DataNvIndex);

	// Query NV size first to know how much to read
	res = Tpm12NvDetails(DataNvIndex, &attr, &nvDataSz, NULL, NULL);
	if (EFI_ERROR(res)) {
		return res;
	}
	nvSize = nvDataSz;
	if (nvSize > sizeof(sealedBuffer)) {
		nvSize = sizeof(sealedBuffer);
	}
	if (nvSize < DC_TPM_SEALED_MIN_SIZE) {
		return EFI_COMPROMISED_DATA;
	}

	// Check if PIN is required and if PCR binding exists by reading PcrInfo NV
	BOOLEAN pcrBinding = FALSE;
	res = Tpm12NvDetails(PcrInfoNvIndex, &attr, &nvDataSz, NULL, NULL);
	if (!EFI_ERROR(res) && nvDataSz >= DC_TPM_PCRINFO_BASE_SIZE) {
		pcrInfoSz = DC_TPM_PCRINFO_BASE_SIZE;
		res = Tpm12NvRead(PcrInfoNvIndex, 0, &pcrInfoSz, pcrInfoBuf);
		if (!EFI_ERROR(res) && pcrInfo->Magic == DC_TPM_PCRINFO_MAGIC) {
			pinRequired = (pcrInfo->Flags & DC_TPM_FLAG_PIN_REQUIRED) != 0;
			pcrBinding = (pcrInfo->PcrMask != 0);
		}
	}

	// Read sealed data
	// IMPORTANT: If PCR binding exists, we MUST use authenticated read
	// because TPM_NV_ReadValue doesn't check PCRs, only TPM_NV_ReadValueAuth does.
	if (pinRequired) {
		if (tpmPin == NULL || tpmPin[0] == L'\0') {
			// PIN required but not provided
			return EFI_ACCESS_DENIED;
		}
		Sha1Hash(tpmPin, StrLen(tpmPin) * sizeof(CHAR16), (UINT8*)&nvAuth);
		CE(Tpm12NvReadAuth(DataNvIndex, 0, &nvSize, sealedBuffer, &nvAuth));
	} else if (pcrBinding) {
		// PCR binding without PIN - use well-known (zeros) auth
		SetMem(&nvAuth, sizeof(nvAuth), 0);
		CE(Tpm12NvReadAuth(DataNvIndex, 0, &nvSize, sealedBuffer, &nvAuth));
	} else {
		// No PIN and no PCR binding - use unauthenticated read
		CE(Tpm12NvRead(DataNvIndex, 0, &nvSize, sealedBuffer));
	}

	// Validate
	if (sealedData->Magic != DC_TPM_SEALED_MAGIC) {
		res = EFI_COMPROMISED_DATA;
		goto err;
	}
	if (sealedData->Version != DC_TPM_SEALED_VERSION) {
		res = EFI_UNSUPPORTED;
		goto err;
	}
	// Validate password size fits within NV data
	if (sealedData->PasswordSize > nvSize - DC_TPM_SEALED_BASE_SIZE) {
		res = EFI_COMPROMISED_DATA;
		goto err;
	}

	// Verify checksum
	gBS->CalculateCrc32(sealedData->Password, sealedData->PasswordSize, &crc);
	if (crc != sealedData->Checksum) {
		res = EFI_CRC_ERROR;
		goto err;
	}

	CopyMem(password, sealedData->Password, sealedData->PasswordSize);
	*passwordSize = sealedData->PasswordSize;
	*passwordType = sealedData->PasswordType;
	res = EFI_SUCCESS;

err:
	SetMem(sealedBuffer, sizeof(sealedBuffer), 0);
	SetMem(&nvAuth, sizeof(nvAuth), 0);
	return res;
}

EFI_STATUS
Tpm12ClearSecret(
	IN  UINT32    NvIndex,
	IN  CHAR16    *ownerPwd
	)
{
	EFI_STATUS res;
	UINT32     DataNvIndex;
	UINT32     PcrInfoNvIndex;

	if (ownerPwd == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	CE(InitTpm12());

	DataNvIndex = Tpm12ResolveNvIndex(NvIndex);
	PcrInfoNvIndex = DC_TPM_NV_INDEX_TO_PCRS(DataNvIndex);

	CE(Tpm12PcrsSave(0, 23, gTpm12Pcrs));

	// Delete PCR info NV space first (ignore error if not present)
	Tpm12NvSpace(PcrInfoNvIndex, 0, ownerPwd, gTpm12Pcrs, 0, 0, 0x2, 0, 0, 0);

	// Delete main NV space (size=0 deletes)
	CE(Tpm12NvSpace(DataNvIndex, 0, ownerPwd, gTpm12Pcrs, 0, 0, 0x2, 0, 0, 0));

err:
	return res;
}

EFI_STATUS
Tpm12GetInfo(
	IN      UINT32    NvIndex,
	OUT     UINT32    *PcrMask OPTIONAL,
	OUT     UINT32    *Flags OPTIONAL,
	OUT     VOID      *Info OPTIONAL,
	IN OUT  UINT32    *InfoSize OPTIONAL
	)
{
	EFI_STATUS res;
	UINT32     DataNvIndex;
	UINT32     PcrInfoNvIndex;
	UINT8      pcrInfoBuf[DC_TPM_PCRINFO_BASE_SIZE + DC_TPM_INFO_MAX_SIZE];
	DC_TPM_PCRINFO_DATA *pcrInfo = (DC_TPM_PCRINFO_DATA*)pcrInfoBuf;
	UINT32     sz;
	UINT32     attr;
	UINT32     nvDataSz;
	BOOLEAN    havePcrInfo = FALSE;

	CE(InitTpm12());

	DataNvIndex = Tpm12ResolveNvIndex(NvIndex);
	PcrInfoNvIndex = DC_TPM_NV_INDEX_TO_PCRS(DataNvIndex);

	// Try to read from PcrInfo NV
	res = Tpm12NvDetails(PcrInfoNvIndex, &attr, &nvDataSz, NULL, NULL);
	if (!EFI_ERROR(res) && nvDataSz >= DC_TPM_PCRINFO_BASE_SIZE) {
		sz = sizeof(pcrInfoBuf);
		if (sz > nvDataSz) sz = nvDataSz;
		res = Tpm12NvRead(PcrInfoNvIndex, 0, &sz, pcrInfoBuf);
		if (!EFI_ERROR(res) && pcrInfo->Magic == DC_TPM_PCRINFO_MAGIC) {
			havePcrInfo = TRUE;
		}
	}

	if (havePcrInfo) {
		// Return PcrMask from pcrInfo
		if (PcrMask != NULL) {
			*PcrMask = pcrInfo->PcrMask;
		}
		// Return Flags from pcrInfo
		if (Flags != NULL) {
			*Flags = pcrInfo->Flags;
		}
		// Return Info data if requested
		if (InfoSize != NULL) {
			if (Info != NULL && pcrInfo->InfoSize > 0) {
				if (*InfoSize < pcrInfo->InfoSize) {
					*InfoSize = pcrInfo->InfoSize;
					res = EFI_BUFFER_TOO_SMALL;
					goto err;
				}
				CopyMem(Info, pcrInfo->InfoData, pcrInfo->InfoSize);
			}
			*InfoSize = pcrInfo->InfoSize;
		}
	} else {
		// Fallback: read PcrMask from NV attributes (no flags or info available)
		if (PcrMask != NULL) {
			CE(Tpm12NvDetails(DataNvIndex, &attr, &nvDataSz, PcrMask, NULL));
		}
		if (Flags != NULL) {
			*Flags = 0;
		}
		if (InfoSize != NULL) {
			*InfoSize = 0;
		}
	}

	res = EFI_SUCCESS;

err:
	SetMem(pcrInfoBuf, sizeof(pcrInfoBuf), 0);
	return res;
}

// TPM 1.2 ordinals not in EDK2 headers
#ifndef TPM_ORD_ForceClear
#define TPM_ORD_ForceClear       0x0000005D
#endif
#ifndef TPM_ORD_ChangeAuthOwner
#define TPM_ORD_ChangeAuthOwner  0x00000010
#endif
#ifndef TPM_ORD_Seal
#define TPM_ORD_Seal             0x00000017
#endif
#ifndef TPM_ORD_Unseal
#define TPM_ORD_Unseal           0x00000018
#endif
#ifndef TPM_ORD_OIAP
#define TPM_ORD_OIAP             0x0000000A
#endif
#ifndef TPM_PID_OWNER
#define TPM_PID_OWNER            0x0005
#endif
#ifndef TPM_PID_ADCP
#define TPM_PID_ADCP             0x0004  // Authorization Data Change Protocol
#endif
#ifndef TPM_ET_KEYHANDLE
#define TPM_ET_KEYHANDLE         0x0001  // Key handle entity type (for OSAP with keys)
#endif
#ifndef TPM_ET_OWNER
#define TPM_ET_OWNER             0x0002
#endif
#ifndef TPM_ET_SRK
#define TPM_ET_SRK               0x0004  // SRK entity type (for ChangeAuthOwner)
#endif
#ifndef TPM_KH_SRK
#define TPM_KH_SRK               0x40000000  // Well-known SRK handle
#endif
#ifndef TPM_AUTHFAIL
#define TPM_AUTHFAIL             0x00000001  // Authentication failed
#endif
#ifndef TPM_AUTH2FAIL
#define TPM_AUTH2FAIL            0x0000001D  // Second auth session failed
#endif
#ifndef TPM_WRONGPCRVAL
#define TPM_WRONGPCRVAL          0x00000018  // PCR values don't match
#endif
#ifndef TPM_TAG_RQU_AUTH2_COMMAND
#define TPM_TAG_RQU_AUTH2_COMMAND 0x00C3    // Two auth sessions
#endif

//////////////////////////////////////////////////////////////////////////
// TPM management functions
//////////////////////////////////////////////////////////////////////////

// TPM 1.2 ForceClear - clears the TPM
// Requires owner authorization via OSAP
EFI_STATUS
Tpm12ClearTpm(
	IN  CHAR16    *ownerPwd OPTIONAL,
	OUT BOOLEAN   *NeedsReboot
	)
{
	EFI_STATUS res;
	CHAR16     emptyPwd[] = L"";

	if (NeedsReboot != NULL) {
		*NeedsReboot = FALSE;
	}

	CE(InitTpm12());
	CE(GetTpm12Io());

	// ForceClear requires owner authorization
	if (ownerPwd == NULL) {
		ownerPwd = emptyPwd;
	}

	CE(Tpm12OSAPStart(TPM_ET_OWNER, TPM_KH_OWNER, ownerPwd));
	Tpm12IOInit(gTpm12Io, TPM_TAG_RQU_AUTH1_COMMAND, TPM_ORD_ForceClear);
	Tpm12OSAPAppend(0);

	res = Tpm12Transmit(gTpm12Io);

err:
	return res;
}

// TPM 1.2 ResetLockValue - clears dictionary attack lockout
// Requires owner authorization
#ifndef TPM_ORD_ResetLockValue
#define TPM_ORD_ResetLockValue   0x00000040
#endif

EFI_STATUS
Tpm12ResetLockValue(
	IN  CHAR16    *ownerPwd
	)
{
	EFI_STATUS   res;

	CE(InitTpm12());
	CE(GetTpm12Io());
	CE(Tpm12OSAPStart(TPM_ET_OWNER, TPM_KH_OWNER, ownerPwd));

	Tpm12IOInit(gTpm12Io, TPM_TAG_RQU_AUTH1_COMMAND, TPM_ORD_ResetLockValue);
	Tpm12OSAPAppend(0);

	res = Tpm12Transmit(gTpm12Io);

err:
	return res;
}

// TPM 1.2 ChangeAuthOwner - changes the owner password
// Requires OSAP with current owner auth, encrypts new auth using ADIP
EFI_STATUS
Tpm12ChangeOwnerPassword(
	IN  CHAR16    *oldOwnerPwd,
	IN  CHAR16    *newOwnerPwd
	)
{
	EFI_STATUS   res;
	TPM_DIGEST   newAuthData;
	TPM_DIGEST   encKey;
	TPM_DIGEST   encAuth;
	UINTN        i;
	UINTN        Sha1CtxSize;
	VOID         *Sha1Ctx;

	if (oldOwnerPwd == NULL) {
		return EFI_INVALID_PARAMETER;
	}
	if (newOwnerPwd == NULL) {
		newOwnerPwd = L"";  // Allow setting empty password
	}

	CE(InitTpm12());
	CE(GetTpm12Io());

	// Get auth value for new password (handles both base64 and regular passwords)
	GetOwnerAuthFromPassword(newOwnerPwd, &newAuthData);

	// Start OSAP session with old owner auth
	CE(Tpm12OSAPStart(TPM_ET_OWNER, TPM_KH_OWNER, oldOwnerPwd));

	// ADIP encryption: encAuth = SHA1(sharedSecret || nonceEven) XOR newAuthData
	Sha1CtxSize = Sha1GetContextSize();
	Sha1Ctx = MEM_ALLOC(Sha1CtxSize);
	if (Sha1Ctx == NULL) {
		res = EFI_OUT_OF_RESOURCES;
		goto err;
	}

	Sha1Init(Sha1Ctx);
	Sha1Update(Sha1Ctx, &gTpm12Osap->SharedSecret, sizeof(TPM_DIGEST));
	Sha1Update(Sha1Ctx, &gTpm12Osap->nonceEven, sizeof(TPM_NONCE));
	Sha1Final(Sha1Ctx, (UINT8*)&encKey);
	MEM_FREE(Sha1Ctx);

	// XOR to get encrypted auth
	for (i = 0; i < sizeof(TPM_DIGEST); i++) {
		encAuth.digest[i] = encKey.digest[i] ^ newAuthData.digest[i];
	}

	// Build ChangeAuthOwner command
	// Format: tag, size, ordinal, protocolID, encNewAuth, entityType, [OSAP auth]
	Tpm12IOInit(gTpm12Io, TPM_TAG_RQU_AUTH1_COMMAND, TPM_ORD_ChangeAuthOwner);
	Tpm12IOWrite16(gTpm12Io, TPM_PID_ADCP, TRUE);              // protocolID: Auth Data Change Protocol
	Tpm12IOWriteBytes(gTpm12Io, &encAuth, sizeof(encAuth), TRUE);  // encrypted new auth
	Tpm12IOWrite16(gTpm12Io, TPM_ET_OWNER, TRUE);              // entityType: owner

	// Append OSAP authorization
	Tpm12OSAPAppend(0);

	res = Tpm12Transmit(gTpm12Io);

	// Clear sensitive data
	SetMem(&newAuthData, sizeof(newAuthData), 0);
	SetMem(&encKey, sizeof(encKey), 0);
	SetMem(&encAuth, sizeof(encAuth), 0);

err:
	return res;
}

// Note: TPM 1.2 TakeOwnership requires RSA encryption with the endorsement key
// This is significantly more complex than OSAP - it needs:
// 1. Read TPM's endorsement key public portion
// 2. RSA-encrypt both owner auth and SRK auth with EK
// 3. Use OIAP (not OSAP) for the command authorization
// For now, recommend using OS tools or BIOS setup for initial ownership.
EFI_STATUS
Tpm12TakeOwnership(
	IN  CHAR16    *newOwnerPwd
	)
{
	// TPM 1.2 ownership requires RSA encryption with endorsement key
	// This is more complex than OSAP and requires RSA crypto library
	return EFI_UNSUPPORTED;
}

//////////////////////////////////////////////////////////////////////////
// SRK-based Password Sealing for TPM 1.2
//
// Uses TPM_Seal/TPM_Unseal with SRK instead of NV storage.
// PCR binding is enforced by TPM hardware during unseal operation.
// SRK auth is expected to be well-known (all zeros).
//////////////////////////////////////////////////////////////////////////

// SRK well-known auth secret (20 bytes of 0x00)
STATIC TPM_DIGEST gSrkWellKnownAuth = { { 0 } };

// Reset SRK auth to well-known (all zeros) using owner password
// Uses TPM_ChangeAuthOwner with entityType = TPM_ET_SRK
/*EFI_STATUS
Tpm12ResetSrkAuth(
	IN  CHAR16    *ownerPwd
	)
{
	EFI_STATUS   res;
	TPM_DIGEST   encKey;
	TPM_DIGEST   encAuth;
	UINTN        i;
	UINTN        Sha1CtxSize;
	VOID         *Sha1Ctx;

	if (ownerPwd == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	CE(InitTpm12());
	CE(GetTpm12Io());

	// New SRK auth = well-known (all zeros) - already in gSrkWellKnownAuth

	// Start OSAP session with owner auth
	CE(Tpm12OSAPStart(TPM_ET_OWNER, TPM_KH_OWNER, ownerPwd));

	// ADIP encryption: encAuth = SHA1(sharedSecret || nonceEven) XOR newAuthData
	Sha1CtxSize = Sha1GetContextSize();
	Sha1Ctx = MEM_ALLOC(Sha1CtxSize);
	if (Sha1Ctx == NULL) {
		res = EFI_OUT_OF_RESOURCES;
		goto err;
	}

	Sha1Init(Sha1Ctx);
	Sha1Update(Sha1Ctx, &gTpm12Osap->SharedSecret, sizeof(TPM_DIGEST));
	Sha1Update(Sha1Ctx, &gTpm12Osap->nonceEven, sizeof(TPM_NONCE));
	Sha1Final(Sha1Ctx, (UINT8*)&encKey);
	MEM_FREE(Sha1Ctx);

	// XOR to get encrypted auth (well-known auth XOR encKey)
	for (i = 0; i < sizeof(TPM_DIGEST); i++) {
		encAuth.digest[i] = encKey.digest[i] ^ gSrkWellKnownAuth.digest[i];
	}

	// Build ChangeAuthOwner command with entityType = SRK
	Tpm12IOInit(gTpm12Io, TPM_TAG_RQU_AUTH1_COMMAND, TPM_ORD_ChangeAuthOwner);
	Tpm12IOWrite16(gTpm12Io, TPM_PID_ADCP, TRUE);              // protocolID: Auth Data Change Protocol
	Tpm12IOWriteBytes(gTpm12Io, &encAuth, sizeof(encAuth), TRUE);  // encrypted new auth (well-known)
	Tpm12IOWrite16(gTpm12Io, TPM_ET_SRK, TRUE);                // entityType: SRK

	// Append OSAP authorization
	Tpm12OSAPAppend(0);

	res = Tpm12Transmit(gTpm12Io);

	// Clear sensitive data
	SetMem(&encKey, sizeof(encKey), 0);
	SetMem(&encAuth, sizeof(encAuth), 0);

err:
	return res;
}*/

// Check if SRK uses well-known auth by attempting a test seal operation
// Note: OSAP alone doesn't validate auth - we need to attempt an actual command
/*BOOLEAN
Tpm12IsSrkWellKnown(VOID)
{
	EFI_STATUS   res;
	TPM_DIGEST   dataAuth;
	UINT8        testData[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
	UINT8        sealedBlob[512];
	UINT32       sealedBlobSize = sizeof(sealedBlob);

	res = InitTpm12();
	if (EFI_ERROR(res)) return FALSE;

	// Save current PCR values
	res = Tpm12PcrsSave(0, 23, gTpm12Pcrs);
	if (EFI_ERROR(res)) return FALSE;

	// Use well-known auth for sealed data
	SetMem(&dataAuth, sizeof(dataAuth), 0);

	// Try to seal a small test blob with well-known SRK auth
	// If this succeeds, SRK auth is well-known
	res = Tpm12Seal(&gSrkWellKnownAuth, &dataAuth, 0,  // No PCR binding for test
	                testData, sizeof(testData),
	                sealedBlob, &sealedBlobSize);

	// Clear test data
	SetMem(sealedBlob, sizeof(sealedBlob), 0);

	if (EFI_ERROR(res)) {
		UINT32 tpmErr = Tpm12RespCode(gTpm12Io);
		if (tpmErr == TPM_AUTHFAIL || tpmErr == 0x01) {
			return FALSE;  // SRK auth is not well-known
		}
		// Other error - assume SRK auth issue
		return FALSE;
	}

	return TRUE;  // Seal succeeded - SRK auth is well-known
}*/

// TPM_Seal: Seal data to PCRs using SRK
// Returns sealed blob that can only be unsealed when PCRs match
EFI_STATUS
Tpm12Seal(
	IN  TPM_DIGEST *srkAuth,      // SRK authorization (well-known = zeros)
	IN  TPM_DIGEST *dataAuth,     // Authorization for sealed data
	IN  UINT32     pcrMask,       // PCRs to bind to
	IN  UINT8      *data,         // Data to seal
	IN  UINT32     dataSize,      // Size of data
	OUT UINT8      *sealedBlob,   // Output sealed blob
	OUT UINT32     *sealedBlobSize // Size of sealed blob
	)
{
	EFI_STATUS   res;
	UINTN        Sha1CtxSize;
	VOID         *Sha1Ctx;
	TPM_DIGEST   encKey;
	TPM_DIGEST   encAuth;
	UINT8        pcrSelect[3];
	UINT8        i;
	UINT32       sealedSize;
	TPM_DIGEST   currentPcrs[24];

	//if (dataSize > 256) {
	//	return EFI_BAD_BUFFER_SIZE;  // TPM_Seal has size limits (max ~256 bytes due to RSA)
	//}

	CE(GetTpm12Io());

	// Read current PCR values for the composite hash
	res = Tpm12PcrsSave(0, 23, currentPcrs);
	if (EFI_ERROR(res)) {
		goto err;
	}

	// Start OSAP session with SRK using raw auth value (well-known = zeros)
	// Use TPM_ET_KEYHANDLE for key operations, not TPM_ET_SRK
	res = Tpm12OSAPStartRaw(TPM_ET_KEYHANDLE, TPM_KH_SRK, srkAuth);
	if (EFI_ERROR(res)) {
		goto err;
	}

	// ADIP encryption: encAuth = SHA1(sharedSecret || nonceEven) XOR dataAuth
	Sha1CtxSize = Sha1GetContextSize();
	Sha1Ctx = MEM_ALLOC(Sha1CtxSize);
	if (Sha1Ctx == NULL) {
		res = EFI_OUT_OF_RESOURCES;
		goto err;
	}

	Sha1Init(Sha1Ctx);
	Sha1Update(Sha1Ctx, &gTpm12Osap->SharedSecret, sizeof(TPM_DIGEST));
	Sha1Update(Sha1Ctx, &gTpm12Osap->nonceEven, sizeof(TPM_NONCE));
	Sha1Final(Sha1Ctx, (UINT8*)&encKey);
	MEM_FREE(Sha1Ctx);

	for (i = 0; i < sizeof(TPM_DIGEST); i++) {
		encAuth.digest[i] = encKey.digest[i] ^ dataAuth->digest[i];
	}

	// Limit to PCRs 0-15 (sizeOfSelect=2) - some TPMs don't support 24 PCRs
	pcrMask &= 0xFFFF;

	// Build TPM_Seal command
	// Format: keyHandle, encAuth, pcrInfoSize, pcrInfo, inDataSize, inData
	// inParamDigest = SHA1(ordinal || encAuth || pcrInfoSize || pcrInfo || inDataSize || inData)
	// Note: keyHandle is NOT part of inParamDigest per TPM 1.2 spec
	Tpm12IOInit(gTpm12Io, TPM_TAG_RQU_AUTH1_COMMAND, TPM_ORD_Seal);
	Tpm12IOWrite32(gTpm12Io, TPM_KH_SRK, FALSE);                   // keyHandle = SRK (not hashed)
	Tpm12IOWriteBytes(gTpm12Io, &encAuth, sizeof(encAuth), TRUE);  // encAuth

	// PCR_INFO structure (for sealing)
	if (pcrMask == 0) {
		// No PCR binding - pcrInfoSize = 0
		Tpm12IOWrite32(gTpm12Io, 0, TRUE);  // pcrInfoSize = 0
	} else {
		// Build PCR select and PCR_INFO structure
		// Use sizeOfSelect=2 (16 PCRs) - this TPM requires 2
		TPM_DIGEST digestAtRelease;
		TPM_DIGEST digestAtCreation;
		UINT16 sizeOfSelect = 2;
		UINT32 pcrInfoSize = 2 + sizeOfSelect + 2 * sizeof(TPM_DIGEST);

		PcrUpdateMask(pcrMask, pcrSelect);

		// Calculate PCR composite hash
		SetMem(&digestAtRelease, sizeof(digestAtRelease), 0);
		SetMem(&digestAtCreation, sizeof(digestAtCreation), 0);
		Tpm12PcrsDigest(sizeOfSelect, pcrSelect, currentPcrs, &digestAtRelease);
		CopyMem(&digestAtCreation, &digestAtRelease, sizeof(digestAtCreation));

		Tpm12IOWrite32(gTpm12Io, pcrInfoSize, TRUE);               // pcrInfoSize
		Tpm12IOWrite16(gTpm12Io, sizeOfSelect, TRUE);              // sizeOfSelect
		Tpm12IOWriteBytes(gTpm12Io, pcrSelect, sizeOfSelect, TRUE);
		Tpm12IOWriteBytes(gTpm12Io, &digestAtRelease, sizeof(digestAtRelease), TRUE);
		Tpm12IOWriteBytes(gTpm12Io, &digestAtCreation, sizeof(digestAtCreation), TRUE);
	}

	Tpm12IOWrite32(gTpm12Io, dataSize, TRUE);                      // inDataSize
	Tpm12IOWriteBytes(gTpm12Io, data, dataSize, TRUE);             // inData

	// Append OSAP authorization
	Tpm12OSAPAppend(0);

	res = Tpm12Transmit(gTpm12Io);
	if (EFI_ERROR(res)) {
		goto err;
	}

	// Read sealed data from response
	// TPM_STORED_DATA structure (no size prefix!):
	//   ver (4 bytes) + sealInfoSize (4) + sealInfo (var) + encDataSize (4) + encData (var)
	{
		UINT32 ver, sealInfoSize, encDataSize;
		UINT32 pos = 0;

		// Read version
		res = Tpm12RespRead32(gTpm12Io, &ver, FALSE);
		if (EFI_ERROR(res)) goto err;
		CopyMem(sealedBlob + pos, &gTpm12Io->Resp[gTpm12Io->RespPos - 4], 4);
		pos += 4;

		// Read sealInfoSize
		res = Tpm12RespRead32(gTpm12Io, &sealInfoSize, FALSE);
		if (EFI_ERROR(res)) goto err;
		CopyMem(sealedBlob + pos, &gTpm12Io->Resp[gTpm12Io->RespPos - 4], 4);
		pos += 4;

		// Read sealInfo
		if (sealInfoSize > 0) {
			if (pos + sealInfoSize > *sealedBlobSize) {
				res = EFI_BUFFER_TOO_SMALL;
				goto err;
			}
			res = Tpm12RespReadBytes(gTpm12Io, sealedBlob + pos, sealInfoSize, FALSE);
			if (EFI_ERROR(res)) goto err;
			pos += sealInfoSize;
		}

		// Read encDataSize
		res = Tpm12RespRead32(gTpm12Io, &encDataSize, FALSE);
		if (EFI_ERROR(res)) goto err;
		CopyMem(sealedBlob + pos, &gTpm12Io->Resp[gTpm12Io->RespPos - 4], 4);
		pos += 4;

		// Read encData
		if (pos + encDataSize > *sealedBlobSize) {
			res = EFI_BUFFER_TOO_SMALL;
			goto err;
		}
		res = Tpm12RespReadBytes(gTpm12Io, sealedBlob + pos, encDataSize, FALSE);
		if (EFI_ERROR(res)) goto err;
		pos += encDataSize;

		sealedSize = pos;
	}
	*sealedBlobSize = sealedSize;

	// Clear sensitive data
	SetMem(&encKey, sizeof(encKey), 0);
	SetMem(&encAuth, sizeof(encAuth), 0);

err:
	return res;
}

// Note: TPM_Unseal requires two authorization sessions (SRK + sealed blob).
// Use Tpm12UnsealSimple() which uses two OIAP sessions with well-known auth.

// Initialize OIAP nonce with random or pseudo-random value
STATIC
VOID
Tpm12InitOiapNonce(
	IN OUT TPM_NONCE *nonce
	)
{
	UINT32  rndSize = sizeof(TPM_NONCE);
	UINT32  i;

	if (EFI_ERROR(Tpm12GetRandom(&rndSize, (UINT8*)nonce)) || rndSize < sizeof(TPM_NONCE)) {
		// Fallback: use counter-based pseudo-random
		for (i = 0; i < sizeof(TPM_NONCE); i++) {
			nonce->nonce[i] = (UINT8)(gNonceCounter >> ((i % 4) * 8));
			gNonceCounter = gNonceCounter * 1103515245 + 12345;
		}
	}
}

// Simplified Unseal using dual OIAP auth (when both auths are well-known)
EFI_STATUS
Tpm12UnsealSimple(
	IN  UINT8      *sealedBlob,   // Sealed blob from TPM_Seal
	IN  UINT32     sealedBlobSize,
	OUT UINT8      *data,         // Output unsealed data
	OUT UINT32     *dataSize      // Size of unsealed data
	)
{
	EFI_STATUS   res;
	UINT32       outSize;
	TPM12_OIAP   oiap1, oiap2;
	UINTN        CtxSize;
	VOID         *HmacCtx;
	TPM_DIGEST   hashCmd;
	TPM_DIGEST   auth1, auth2;

	CE(GetTpm12Io());

	// Initialize nonces with random values
	Tpm12InitOiapNonce(&oiap1.nonceOdd);
	Tpm12InitOiapNonce(&oiap2.nonceOdd);

	// Start two OIAP sessions
	// First OIAP (for SRK)
	Tpm12IOInit(gTpm12Io, TPM_TAG_RQU_COMMAND, TPM_ORD_OIAP);
	CE(Tpm12Transmit(gTpm12Io));
	Tpm12RespRead32(gTpm12Io, &oiap1.authHandle, FALSE);
	Tpm12RespReadBytes(gTpm12Io, &oiap1.nonceEven, sizeof(TPM_NONCE), FALSE);

	// Second OIAP (for sealed data)
	Tpm12IOInit(gTpm12Io, TPM_TAG_RQU_COMMAND, TPM_ORD_OIAP);
	CE(Tpm12Transmit(gTpm12Io));
	Tpm12RespRead32(gTpm12Io, &oiap2.authHandle, FALSE);
	Tpm12RespReadBytes(gTpm12Io, &oiap2.nonceEven, sizeof(TPM_NONCE), FALSE);

	// Build TPM_Unseal command with AUTH2
	// TPM_Unseal input: parentHandle + inData (TPM_STORED_DATA directly, NO size prefix)
	// TPM_STORED_DATA is self-describing (contains internal sealInfoSize and encDataSize)
	// inParamDigest = SHA1(ordinal || inData) - parentHandle NOT part of hash
	Tpm12IOInit(gTpm12Io, TPM_TAG_RQU_AUTH2_COMMAND, TPM_ORD_Unseal);
	Tpm12IOWrite32(gTpm12Io, TPM_KH_SRK, FALSE);                   // parentHandle = SRK (not hashed)
	// NOTE: NO size prefix - TPM_STORED_DATA is self-describing
	Tpm12IOWriteBytes(gTpm12Io, sealedBlob, sealedBlobSize, TRUE); // inData (TPM_STORED_DATA directly)

	// Calculate command hash up to here
	Sha1Final(gTpm12Io->Hash, (UINT8*)&hashCmd);

	// First auth block (SRK - using well-known auth)
	Tpm12IOWrite32(gTpm12Io, oiap1.authHandle, FALSE);
	Tpm12IOWriteBytes(gTpm12Io, &oiap1.nonceOdd, sizeof(TPM_NONCE), FALSE);
	Tpm12IOWrite8(gTpm12Io, 0, FALSE);  // continueSession = FALSE

	// Compute auth1 HMAC (with well-known SRK auth = zeros)
	CtxSize = HmacSha1GetContextSize();
	HmacCtx = MEM_ALLOC(CtxSize);
	if (HmacCtx == NULL) return EFI_OUT_OF_RESOURCES;
	HmacSha1Init(HmacCtx, (UINT8*)&gSrkWellKnownAuth, sizeof(TPM_DIGEST));
	HmacSha1Update(HmacCtx, &hashCmd, sizeof(hashCmd));
	HmacSha1Update(HmacCtx, &oiap1.nonceEven, sizeof(oiap1.nonceEven));
	HmacSha1Update(HmacCtx, &oiap1.nonceOdd, sizeof(oiap1.nonceOdd));
	{
		UINT8 cont = 0;
		HmacSha1Update(HmacCtx, &cont, 1);
	}
	HmacSha1Final(HmacCtx, (UINT8*)&auth1);
	MEM_FREE(HmacCtx);
	Tpm12IOWriteBytes(gTpm12Io, &auth1, sizeof(auth1), FALSE);

	// Second auth block (data blob - also using well-known auth)
	Tpm12IOWrite32(gTpm12Io, oiap2.authHandle, FALSE);
	Tpm12IOWriteBytes(gTpm12Io, &oiap2.nonceOdd, sizeof(TPM_NONCE), FALSE);
	Tpm12IOWrite8(gTpm12Io, 0, FALSE);  // continueSession = FALSE

	HmacCtx = MEM_ALLOC(CtxSize);
	if (HmacCtx == NULL) return EFI_OUT_OF_RESOURCES;
	HmacSha1Init(HmacCtx, (UINT8*)&gSrkWellKnownAuth, sizeof(TPM_DIGEST));  // data auth also well-known
	HmacSha1Update(HmacCtx, &hashCmd, sizeof(hashCmd));
	HmacSha1Update(HmacCtx, &oiap2.nonceEven, sizeof(oiap2.nonceEven));
	HmacSha1Update(HmacCtx, &oiap2.nonceOdd, sizeof(oiap2.nonceOdd));
	{
		UINT8 cont = 0;
		HmacSha1Update(HmacCtx, &cont, 1);
	}
	HmacSha1Final(HmacCtx, (UINT8*)&auth2);
	MEM_FREE(HmacCtx);
	Tpm12IOWriteBytes(gTpm12Io, &auth2, sizeof(auth2), FALSE);

	res = Tpm12Transmit(gTpm12Io);
	if (EFI_ERROR(res)) {
		goto err;
	}

	// Read unsealed data
	res = Tpm12RespRead32(gTpm12Io, &outSize, TRUE);
	if (EFI_ERROR(res)) goto err;

	if (outSize > *dataSize) {
		res = EFI_BUFFER_TOO_SMALL;
		goto err;
	}

	res = Tpm12RespReadBytes(gTpm12Io, data, outSize, TRUE);
	*dataSize = outSize;

err:
	return res;
}

/**
  Unseal a blob with custom dataAuth (PIN support).
  This variant allows specifying the sealed data authorization value.

  @param[in]  sealedBlob      Sealed blob from TPM_Seal
  @param[in]  sealedBlobSize  Size of sealed blob
  @param[in]  dataAuth        Authorization value for sealed data (NULL = well-known zeros)
  @param[out] data            Output unsealed data
  @param[out] dataSize        Size of unsealed data

  @return EFI_SUCCESS or error
**/
EFI_STATUS
Tpm12UnsealWithAuth(
	IN  UINT8      *sealedBlob,
	IN  UINT32     sealedBlobSize,
	IN  TPM_DIGEST *dataAuth OPTIONAL,
	OUT UINT8      *data,
	OUT UINT32     *dataSize
	)
{
	EFI_STATUS   res;
	UINT32       outSize;
	TPM12_OIAP   oiap1, oiap2;
	UINTN        CtxSize;
	VOID         *HmacCtx;
	TPM_DIGEST   hashCmd;
	TPM_DIGEST   auth1, auth2;
	TPM_DIGEST   *blobAuth;

	// Use provided dataAuth or fall back to well-known (zeros)
	if (dataAuth != NULL) {
		blobAuth = dataAuth;
	} else {
		blobAuth = &gSrkWellKnownAuth;
	}

	CE(GetTpm12Io());

	// Initialize nonces with random values
	Tpm12InitOiapNonce(&oiap1.nonceOdd);
	Tpm12InitOiapNonce(&oiap2.nonceOdd);

	// Start two OIAP sessions
	// First OIAP (for SRK)
	Tpm12IOInit(gTpm12Io, TPM_TAG_RQU_COMMAND, TPM_ORD_OIAP);
	CE(Tpm12Transmit(gTpm12Io));
	Tpm12RespRead32(gTpm12Io, &oiap1.authHandle, FALSE);
	Tpm12RespReadBytes(gTpm12Io, &oiap1.nonceEven, sizeof(TPM_NONCE), FALSE);

	// Second OIAP (for sealed data)
	Tpm12IOInit(gTpm12Io, TPM_TAG_RQU_COMMAND, TPM_ORD_OIAP);
	CE(Tpm12Transmit(gTpm12Io));
	Tpm12RespRead32(gTpm12Io, &oiap2.authHandle, FALSE);
	Tpm12RespReadBytes(gTpm12Io, &oiap2.nonceEven, sizeof(TPM_NONCE), FALSE);

	// Build TPM_Unseal command with AUTH2
	Tpm12IOInit(gTpm12Io, TPM_TAG_RQU_AUTH2_COMMAND, TPM_ORD_Unseal);
	Tpm12IOWrite32(gTpm12Io, TPM_KH_SRK, FALSE);
	Tpm12IOWriteBytes(gTpm12Io, sealedBlob, sealedBlobSize, TRUE);

	// Calculate command hash up to here
	Sha1Final(gTpm12Io->Hash, (UINT8*)&hashCmd);

	// First auth block (SRK - using well-known auth)
	Tpm12IOWrite32(gTpm12Io, oiap1.authHandle, FALSE);
	Tpm12IOWriteBytes(gTpm12Io, &oiap1.nonceOdd, sizeof(TPM_NONCE), FALSE);
	Tpm12IOWrite8(gTpm12Io, 0, FALSE);

	CtxSize = HmacSha1GetContextSize();
	HmacCtx = MEM_ALLOC(CtxSize);
	if (HmacCtx == NULL) return EFI_OUT_OF_RESOURCES;
	HmacSha1Init(HmacCtx, (UINT8*)&gSrkWellKnownAuth, sizeof(TPM_DIGEST));
	HmacSha1Update(HmacCtx, &hashCmd, sizeof(hashCmd));
	HmacSha1Update(HmacCtx, &oiap1.nonceEven, sizeof(oiap1.nonceEven));
	HmacSha1Update(HmacCtx, &oiap1.nonceOdd, sizeof(oiap1.nonceOdd));
	{
		UINT8 cont = 0;
		HmacSha1Update(HmacCtx, &cont, 1);
	}
	HmacSha1Final(HmacCtx, (UINT8*)&auth1);
	MEM_FREE(HmacCtx);
	Tpm12IOWriteBytes(gTpm12Io, &auth1, sizeof(auth1), FALSE);

	// Second auth block (data blob - use provided auth or well-known)
	Tpm12IOWrite32(gTpm12Io, oiap2.authHandle, FALSE);
	Tpm12IOWriteBytes(gTpm12Io, &oiap2.nonceOdd, sizeof(TPM_NONCE), FALSE);
	Tpm12IOWrite8(gTpm12Io, 0, FALSE);

	HmacCtx = MEM_ALLOC(CtxSize);
	if (HmacCtx == NULL) return EFI_OUT_OF_RESOURCES;
	HmacSha1Init(HmacCtx, (UINT8*)blobAuth, sizeof(TPM_DIGEST));  // Use PIN-derived auth
	HmacSha1Update(HmacCtx, &hashCmd, sizeof(hashCmd));
	HmacSha1Update(HmacCtx, &oiap2.nonceEven, sizeof(oiap2.nonceEven));
	HmacSha1Update(HmacCtx, &oiap2.nonceOdd, sizeof(oiap2.nonceOdd));
	{
		UINT8 cont = 0;
		HmacSha1Update(HmacCtx, &cont, 1);
	}
	HmacSha1Final(HmacCtx, (UINT8*)&auth2);
	MEM_FREE(HmacCtx);
	Tpm12IOWriteBytes(gTpm12Io, &auth2, sizeof(auth2), FALSE);

	res = Tpm12Transmit(gTpm12Io);
	if (EFI_ERROR(res)) {
		goto err;
	}

	// Read unsealed data
	res = Tpm12RespRead32(gTpm12Io, &outSize, TRUE);
	if (EFI_ERROR(res)) goto err;

	if (outSize > *dataSize) {
		res = EFI_BUFFER_TOO_SMALL;
		goto err;
	}

	res = Tpm12RespReadBytes(gTpm12Io, data, outSize, TRUE);
	*dataSize = outSize;

err:
	return res;
}

//////////////////////////////////////////////////////////////////////////
// Buffer-based SRK functions (caller handles file I/O)
// Buffer format: [DC_TPM_SRK_FILE_HEADER][SealedKEK][Encrypted DC_TPM_SEALED_DATA][InfoData]
//////////////////////////////////////////////////////////////////////////

// Check if buffer contains valid sealed data that can be unsealed
BOOLEAN
Tpm12SrkIsOpenBuf(
	IN  UINT8     *buffer,
	IN  UINT32    bufferSize
	)
{
	DC_TPM_SRK_FILE_HEADER *Header;
	UINT8                  *DataBlob;
	UINT8                  testData[480];
	UINT32                 testSize = sizeof(testData);
	EFI_STATUS             res;

	if (buffer == NULL || bufferSize < sizeof(DC_TPM_SRK_FILE_HEADER)) {
		return FALSE;
	}

	if (EFI_ERROR(InitTpm12())) {
		return FALSE;
	}

	Header = (DC_TPM_SRK_FILE_HEADER*)buffer;

	if (Header->Magic != DC_TPM_SRK_FILE_MAGIC) {
		return FALSE;
	}

	// If PIN is required, we can't test unseal - just return TRUE
	if (Header->Flags & DC_TPM_FLAG_PIN_REQUIRED) {
		return TRUE;
	}

	// Get pointer to sealed blob
	DataBlob = buffer + sizeof(DC_TPM_SRK_FILE_HEADER);
	if (sizeof(DC_TPM_SRK_FILE_HEADER) + Header->SealedBlobSize > bufferSize) {
		return FALSE;
	}


	res = Tpm12UnsealSimple(DataBlob, Header->SealedBlobSize, testData, &testSize);
	SetMem(testData, sizeof(testData), 0);

	return !EFI_ERROR(res);
}

// Seal password to buffer using SRK with envelope encryption
EFI_STATUS
Tpm12SrkSealPasswordBuf(
	IN  VOID      *password,
	IN  UINT32    passwordSize,
	IN  UINT32    passwordType,
	IN  UINT32    pcrMask,
	IN  CHAR16    *tpmPin OPTIONAL,
	IN  VOID      *info OPTIONAL,
	IN  UINT32    infoSize,
	OUT UINT8     *buffer,
	IN OUT UINT32 *bufferSize
	)
{
	EFI_STATUS             res = EFI_SUCCESS;
	DC_TPM_SRK_FILE_HEADER *Header;
	UINT8                  kek[32];
	UINT8                  iv[16];
	UINT8                  sealedBuffer[DC_TPM_SEALED_MAX_SIZE];
	DC_TPM_SEALED_DATA     *sealedData = (DC_TPM_SEALED_DATA *)sealedBuffer;
	UINT8                  encryptedData[DC_TPM_SEALED_MAX_SIZE];
	UINT32                 encryptedSize;
	UINT8                  sealedKek[512];
	UINT32                 sealedKekSize = sizeof(sealedKek);
	TPM_DIGEST             dataAuth;
	BOOLEAN                usePin = FALSE;
	UINT32                 requiredSize;
	UINT8                  *writePtr;
	UINT32                 rndSize;

	if (password == NULL || passwordSize == 0 || buffer == NULL || bufferSize == NULL) {
		return EFI_INVALID_PARAMETER;
	}
	if (passwordSize > DC_TPM_SEALED_MAX_SIZE - DC_TPM_SEALED_BASE_SIZE) {
		return EFI_BAD_BUFFER_SIZE;
	}
	if (infoSize > DC_TPM_INFO_MAX_SIZE) {
		return EFI_BAD_BUFFER_SIZE;
	}

	CE(InitTpm12());
	CE(Tpm12PcrsSave(0, 23, gTpm12Pcrs));

	// Derive dataAuth from PIN if provided
	if (tpmPin != NULL && tpmPin[0] != L'\0') {
		Sha1Hash(tpmPin, StrLen(tpmPin) * sizeof(CHAR16), (UINT8*)&dataAuth);
		usePin = TRUE;
	} else {
		SetMem(&dataAuth, sizeof(dataAuth), 0);
	}

	// Generate random KEK using TPM
	rndSize = sizeof(kek);
	CE(Tpm12GetRandom(&rndSize, kek));
	if (rndSize < sizeof(kek)) {
		res = EFI_DEVICE_ERROR;
		goto err;
	}

	// Generate random IV
	rndSize = sizeof(iv);
	CE(Tpm12GetRandom(&rndSize, iv));
	if (rndSize < sizeof(iv)) {
		res = EFI_DEVICE_ERROR;
		goto err;
	}

	// Seal KEK with SRK
	res = Tpm12Seal(&gSrkWellKnownAuth, &dataAuth, pcrMask,
	                kek, sizeof(kek), sealedKek, &sealedKekSize);
	if (EFI_ERROR(res)) {
		goto err;
	}

	// Build DC_TPM_SEALED_DATA structure (variable size, padded to 16 bytes, min 96)
	encryptedSize = DC_TPM_SEALED_DATA_SIZE(passwordSize);
	SetMem(sealedBuffer, sizeof(sealedBuffer), 0);
	sealedData->Magic = DC_TPM_SEALED_MAGIC;
	sealedData->Version = DC_TPM_SEALED_VERSION;
	sealedData->PasswordSize = (UINT16)passwordSize;
	sealedData->PasswordType = passwordType;
	CopyMem(sealedData->Password, password, passwordSize);
	gBS->CalculateCrc32(&sealedData->Password[0], passwordSize, &sealedData->Checksum);

	// Encrypt DC_TPM_SEALED_DATA with AES-256-CBC (already block-aligned)
	CopyMem(encryptedData, sealedBuffer, encryptedSize);
	CE(TpmAes256CbcEncrypt(kek, iv, encryptedData, encryptedSize));

	// Calculate required buffer size
	requiredSize = sizeof(DC_TPM_SRK_FILE_HEADER) + sealedKekSize + encryptedSize + infoSize;
	if (*bufferSize < requiredSize) {
		*bufferSize = requiredSize;
		res = EFI_BUFFER_TOO_SMALL;
		goto err;
	}

	// Prepare header
	Header = (DC_TPM_SRK_FILE_HEADER*)buffer;
	SetMem(Header, sizeof(DC_TPM_SRK_FILE_HEADER), 0);
	Header->Magic = DC_TPM_SRK_FILE_MAGIC;
	Header->Version = DC_TPM_SRK_VERSION;
	Header->Flags = usePin ? DC_TPM_FLAG_PIN_REQUIRED : DC_TPM_FLAG_NONE;
	Header->PcrMask = pcrMask;
	Header->SealedBlobSize = (UINT16)sealedKekSize;
	Header->EncryptedSize = (UINT16)encryptedSize;
	Header->InfoSize = (UINT16)infoSize;
	CopyMem(Header->Iv, iv, sizeof(iv));

	// Write data to buffer
	writePtr = buffer + sizeof(DC_TPM_SRK_FILE_HEADER);
	CopyMem(writePtr, sealedKek, sealedKekSize);
	writePtr += sealedKekSize;
	CopyMem(writePtr, encryptedData, encryptedSize);
	writePtr += encryptedSize;
	if (info != NULL && infoSize > 0) {
		CopyMem(writePtr, info, infoSize);
	}

	*bufferSize = requiredSize;

err:
	SetMem(kek, sizeof(kek), 0);
	SetMem(iv, sizeof(iv), 0);
	SetMem(sealedBuffer, sizeof(sealedBuffer), 0);
	SetMem(encryptedData, sizeof(encryptedData), 0);
	SetMem(sealedKek, sizeof(sealedKek), 0);
	SetMem(&dataAuth, sizeof(dataAuth), 0);
	return res;
}

// Unseal password from buffer
EFI_STATUS
Tpm12SrkUnsealPasswordBuf(
	IN  UINT8     *buffer,
	IN  UINT32    bufferSize,
	OUT VOID      *password,
	OUT UINT32    *passwordSize,
	OUT UINT32    *passwordType,
	IN  CHAR16    *tpmPin OPTIONAL
	)
{
	EFI_STATUS             res = EFI_SUCCESS;
	DC_TPM_SRK_FILE_HEADER *Header;
	UINT8                  *DataBlob;
	UINT8                  kek[32];
	UINT32                 kekSize = sizeof(kek);
	UINT8                  sealedBuffer[DC_TPM_SEALED_MAX_SIZE];
	DC_TPM_SEALED_DATA     *sealedData = (DC_TPM_SEALED_DATA *)sealedBuffer;
	TPM_DIGEST             dataAuth;
	TPM_DIGEST             *pDataAuth = NULL;
	UINT32                 crc;

	if (buffer == NULL || password == NULL || passwordSize == NULL || passwordType == NULL) {
		return EFI_INVALID_PARAMETER;
	}
	if (bufferSize < sizeof(DC_TPM_SRK_FILE_HEADER)) {
		return EFI_INVALID_PARAMETER;
	}

	CE(InitTpm12());

	Header = (DC_TPM_SRK_FILE_HEADER*)buffer;

	if (Header->Magic != DC_TPM_SRK_FILE_MAGIC) {
		return EFI_COMPROMISED_DATA;
	}

	// Validate encrypted size (must be 16-byte aligned, within valid range)
	if (Header->EncryptedSize < DC_TPM_SEALED_MIN_SIZE ||
	    Header->EncryptedSize > DC_TPM_SEALED_MAX_SIZE ||
	    (Header->EncryptedSize % 16) != 0) {
		return EFI_COMPROMISED_DATA;
	}

	// Validate buffer size
	if (bufferSize < sizeof(DC_TPM_SRK_FILE_HEADER) + Header->SealedBlobSize + Header->EncryptedSize) {
		return EFI_COMPROMISED_DATA;
	}

	// Derive dataAuth from PIN if provided
	if (tpmPin != NULL && tpmPin[0] != L'\0') {
		Sha1Hash(tpmPin, StrLen(tpmPin) * sizeof(CHAR16), (UINT8*)&dataAuth);
		pDataAuth = &dataAuth;
	}

	// Get pointer to sealed blob
	DataBlob = buffer + sizeof(DC_TPM_SRK_FILE_HEADER);

	// Unseal KEK
	res = Tpm12UnsealWithAuth(DataBlob, Header->SealedBlobSize, pDataAuth, kek, &kekSize);
	if (EFI_ERROR(res)) {
		goto err;
	}

	// Decrypt DC_TPM_SEALED_DATA
	CopyMem(sealedBuffer, DataBlob + Header->SealedBlobSize, Header->EncryptedSize);
	CE(TpmAes256CbcDecrypt(kek, Header->Iv, sealedBuffer, Header->EncryptedSize));

	// Validate sealed data structure
	if (sealedData->Magic != DC_TPM_SEALED_MAGIC) {
		res = EFI_COMPROMISED_DATA;
		goto err;
	}
	// Validate password size fits within encrypted data
	if (sealedData->PasswordSize > Header->EncryptedSize - DC_TPM_SEALED_BASE_SIZE) {
		res = EFI_COMPROMISED_DATA;
		goto err;
	}

	// Verify checksum
	gBS->CalculateCrc32(&sealedData->Password[0], sealedData->PasswordSize, &crc);
	if (crc != sealedData->Checksum) {
		res = EFI_COMPROMISED_DATA;
		goto err;
	}

	// Copy decrypted password
	*passwordSize = sealedData->PasswordSize;
	CopyMem(password, sealedData->Password, sealedData->PasswordSize);
	*passwordType = sealedData->PasswordType;

err:
	SetMem(kek, sizeof(kek), 0);
	SetMem(sealedBuffer, sizeof(sealedBuffer), 0);
	SetMem(&dataAuth, sizeof(dataAuth), 0);
	return res;
}

// Get PCR mask, flags, and info data from buffer
EFI_STATUS
Tpm12SrkGetInfoBuf(
	IN     UINT8     *buffer,
	IN     UINT32    bufferSize,
	OUT    UINT32    *PcrMask OPTIONAL,
	OUT    UINT32    *Flags OPTIONAL,
	OUT    VOID      *Info OPTIONAL,
	IN OUT UINT32    *InfoSize OPTIONAL
	)
{
	DC_TPM_SRK_FILE_HEADER *Header;
	UINT8                  *InfoPtr;
	UINT32                 DataOffset;

	if (buffer == NULL) {
		return EFI_INVALID_PARAMETER;
	}
	if (bufferSize < sizeof(DC_TPM_SRK_FILE_HEADER)) {
		return EFI_INVALID_PARAMETER;
	}

	Header = (DC_TPM_SRK_FILE_HEADER*)buffer;

	if (Header->Magic != DC_TPM_SRK_FILE_MAGIC) {
		return EFI_NOT_FOUND;
	}

	// Return PcrMask
	if (PcrMask != NULL) {
		*PcrMask = Header->PcrMask;
	}

	// Return Flags
	if (Flags != NULL) {
		*Flags = 0;
		if (Header->Flags & DC_TPM_FLAG_PIN_REQUIRED) {
			*Flags |= DC_TPM_FLAG_PIN_REQUIRED;
		}
	}

	// Return Info data
	if (InfoSize != NULL) {
		DataOffset = sizeof(DC_TPM_SRK_FILE_HEADER) + Header->SealedBlobSize + Header->EncryptedSize;

		if (Info != NULL && Header->InfoSize > 0) {
			if (*InfoSize < Header->InfoSize) {
				*InfoSize = Header->InfoSize;
				return EFI_BUFFER_TOO_SMALL;
			}
			if (DataOffset + Header->InfoSize > bufferSize) {
				return EFI_COMPROMISED_DATA;
			}
			InfoPtr = buffer + DataOffset;
			CopyMem(Info, InfoPtr, Header->InfoSize);
		}
		*InfoSize = Header->InfoSize;
	}

	return EFI_SUCCESS;
}

VOID
InitTpmLib12(
	IN OUT TPM_LIB_PROTOCOL* Tpm)
{
	Tpm->TpmVersion = 0x102;
	Tpm->Measure = Tpm12LibMeasure;
	Tpm->GetRandom = Tpm12LibGetRandom;
	// NV-based: PCR binding on NV space
	Tpm->NvIsConfigured = Tpm12IsConfigured;
	Tpm->NvIsOpen = Tpm12IsOpen;
	Tpm->NvSealPassword = Tpm12SealPassword;
	Tpm->NvUnsealPassword = Tpm12UnsealPassword;
	Tpm->NvClearSecret = Tpm12ClearSecret;
	Tpm->NvGetInfo = Tpm12GetInfo;
	// Buffer-based SRK functions (always available, caller handles file I/O)
	Tpm->SrkIsOpen = Tpm12SrkIsOpenBuf;
	Tpm->SrkGetInfo = Tpm12SrkGetInfoBuf;
	Tpm->SrkSealPassword = Tpm12SrkSealPasswordBuf;
	Tpm->SrkUnsealPassword = Tpm12SrkUnsealPasswordBuf;

	// TPM management
	Tpm->ClearTpm = Tpm12ClearTpm;
	Tpm->TakeOwnership = Tpm12TakeOwnership;
	Tpm->ChangeOwnerPwd = Tpm12ChangeOwnerPassword;
	// PCR read
	Tpm->ReadPcr = Tpm12ReadPcr;
	// TPM 2.0 info (not available for TPM 1.2)
	Tpm->GetManufacturer = NULL;
	Tpm->GetFirmwareVersion = NULL;
	Tpm->GetLockoutInfo = NULL;
	// NV enumeration
	Tpm->EnumNvIndices = Tpm12GetNvList;
	Tpm->GetNvIndexInfo = Tpm12NvDetails;
	// Shutdown (not supported for TPM 1.2)
	Tpm->Shutdown = NULL;
}