/** @file
  TPM 2.0 Library

  Copyright (c) 2026 David Xanatos. All rights reserved.

**/

#include "../Library/MiscUtilsLib/MiscUtilsLib.h"
#include <Library/BaseLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/PrintLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseCryptLib.h>

#include <IndustryStandard/Tpm20.h>
#include <IndustryStandard/TcpaAcpi.h>
#include <IndustryStandard/TcgPhysicalPresence.h>
#include <Library/Tpm2DeviceLib.h>
#include <Library/Tpm2CommandLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Protocol/Tcg2Protocol.h>
#include <Guid/Tcg2PhysicalPresenceData.h>
#include <Library/BaseCryptLib.h>

#include "TpmLib.h"


//STATIC BOOLEAN Tpm2NvIndexExists(IN UINT32 NvIndex);


EFI_STATUS
InitTpm20() 
{
	STATIC EFI_STATUS Tpm2Ready = EFI_NOT_READY;
	
	if (EFI_ERROR(Tpm2Ready)) {
		Tpm2Ready = Tpm2RequestUseTpm();
	}
	
	return Tpm2Ready;
}

//////////////////////////////////////////////////////////////////////////
// Auth Helper
//////////////////////////////////////////////////////////////////////////

/**
  Convert password to TPM auth bytes (raw CHAR16 bytes).

  @param[in]   Password    Password string
  @param[out]  AuthData    Buffer for auth bytes
  @param[out]  AuthSize    Size of auth data in bytes

  @return EFI_SUCCESS on success
**/
STATIC
EFI_STATUS
TpmPrepareAuth(
	IN  CONST CHAR16  *Password,
	OUT UINT8         *AuthData,
	OUT UINT16        *AuthSize
	)
{
	UINTN  pwdLen;

	if (AuthData == NULL || AuthSize == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	if (Password == NULL || Password[0] == L'\0') {
		*AuthSize = 0;
		return EFI_SUCCESS;
	}

	pwdLen = StrLen(Password);
	*AuthSize = (UINT16)(pwdLen * sizeof(CHAR16));
	CopyMem(AuthData, Password, *AuthSize);

	return EFI_SUCCESS;
}

/**
  Check if TPM is in lockout state due to dictionary attack protection.

  @param[out] IsLocked      TRUE if TPM is locked out
  @param[out] LockoutCount  Current lockout counter value

  @return EFI_SUCCESS on success
**/
STATIC
EFI_STATUS
Tpm2CheckLockout(
	OUT BOOLEAN  *IsLocked,
	OUT UINT32   *LockoutCount OPTIONAL
	)
{
	EFI_STATUS  res;
	UINT32      Counter = 0;

	if (IsLocked == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	*IsLocked = FALSE;

	res = Tpm2GetCapabilityLockoutCounter(&Counter);
	if (EFI_ERROR(res)) {
		// Can't determine - assume not locked
		return res;
	}

	if (LockoutCount != NULL) {
		*LockoutCount = Counter;
	}

	// If counter > 0, TPM has recorded failed auth attempts
	// Actual lockout threshold depends on TPM configuration
	// We can't easily know the threshold, so just report the counter
	return EFI_SUCCESS;
}

/**
  Print user-friendly error message for TPM NV read failures.

  @param[in] Status      EFI_STATUS from Tpm2NvRead
  @param[in] PinRequired TRUE if PIN was required for this operation
**/
STATIC
VOID
Tpm2PrintAuthError(
	IN EFI_STATUS  Status,
	IN BOOLEAN     PinRequired
	)
{
	BOOLEAN  IsLocked = FALSE;
	UINT32   LockoutCount = 0;

	// Check lockout status first
	if (!EFI_ERROR(Tpm2CheckLockout(&IsLocked, &LockoutCount))) {
		if (LockoutCount > 0) {
			OUT_PRINT(L"TPM lockout counter: %d failed attempts\n", LockoutCount);
		}
	}

	switch (Status) {
	case EFI_SECURITY_VIOLATION:
		// TPM_RC_NV_AUTHORIZATION - Policy not satisfied
		if (PinRequired) {
			OUT_PRINT(L"Authorization failed - wrong PIN or PCR mismatch\n");
		} else {
			OUT_PRINT(L"Authorization failed - PCR values don't match\n");
		}
		break;

	case EFI_ACCESS_DENIED:
		// TPM_RC_NV_LOCKED or similar
		OUT_PRINT(L"Access denied - NV index is locked\n");
		break;

	case EFI_DEVICE_ERROR:
		// Could be TPM_RC_AUTH_FAIL (wrong PIN) or TPM_RC_LOCKOUT
		if (LockoutCount > 0) {
			OUT_PRINT(L"TPM error - possibly locked out due to too many failed PIN attempts\n");
			OUT_PRINT(L"Try rebooting or wait for lockout recovery\n");
		} else if (PinRequired) {
			OUT_PRINT(L"TPM error - likely wrong PIN\n");
		} else {
			OUT_PRINT(L"TPM device error\n");
		}
		break;

	case EFI_NOT_READY:
		OUT_PRINT(L"NV index not initialized\n");
		break;

	default:
		OUT_PRINT(L"TPM error: %r\n", Status);
		break;
	}
}

//////////////////////////////////////////////////////////////////////////
// TPM 2.0 Helpers
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
Tpm2LibPcrRead(
	IN UINT32   PcrIndex,
	OUT void    *PcrValue
	)
{
	TPML_PCR_SELECTION        PcrSelectionIn = { 0 };
	UINT32                    PcrUpdateCounter;
	TPML_PCR_SELECTION        PcrSelectionOut;
	
	PcrSelectionIn.count = 1;
	PcrSelectionIn.pcrSelections[0].hash = TPM_ALG_SHA256;
	PcrSelectionIn.pcrSelections[0].sizeofSelect = 3;
	PcrSelectionIn.pcrSelections[0].pcrSelect[0] = (PcrIndex < 8) ? 1 << PcrIndex : 0;
	PcrSelectionIn.pcrSelections[0].pcrSelect[1] = (PcrIndex > 7) && (PcrIndex < 16) ? 1 << (PcrIndex - 8) : 0;
	PcrSelectionIn.pcrSelections[0].pcrSelect[2] = (PcrIndex > 15) ? 1 << (PcrIndex - 16) : 0;

	return Tpm2PcrRead(&PcrSelectionIn, &PcrUpdateCounter, &PcrSelectionOut, PcrValue);
}

#pragma pack(1)
typedef struct {
	UINT32         cmd;
	UINT32         count;
	TPM_ALG_ID     hashType;
	UINT8          pcrCount;
	UINT8          pcrSelection[3];
	UINT8          hash[SHA256_DIGEST_SIZE];
} TPM_CC_POLICYPCR;
#pragma pack()

EFI_STATUS
Tpm2MakePolicyPcr(
	IN  UINT32                pcrMask,
	OUT UINT8                 *hash
	)
{
	EFI_STATUS                res = EFI_SUCCESS;
	TPML_DIGEST               PcrValue;
	UINTN                     ctxSize;
	VOID                      *ctx;
	UINT32                    tmp;
	UINTN                     i;
	TPM_CC_POLICYPCR          polycyPcr;
	
	polycyPcr.cmd = SwapBytes32(TPM_CC_PolicyPCR);
	polycyPcr.count = SwapBytes32(1);
	polycyPcr.hashType = SwapBytes16(TPM_ALG_SHA256);
	polycyPcr.pcrCount = 3;
	polycyPcr.pcrSelection[0] = pcrMask & 0xFF;
	polycyPcr.pcrSelection[1] = (pcrMask >> 8) & 0xFF;
	polycyPcr.pcrSelection[2] = (pcrMask >> 16) & 0xFF;

	ctxSize = Sha256GetContextSize();
	ctx = MEM_ALLOC(ctxSize);
	if (ctx == NULL) return EFI_BUFFER_TOO_SMALL;
	Sha256Init(ctx);
	tmp = pcrMask;
	for (i = 0; i < 32; ++i) {
		if ((tmp & 1) == 1) {
			CE(Tpm2LibPcrRead((UINT32)i, &PcrValue));
			Sha256Update(ctx, PcrValue.digests[0].buffer, SHA256_DIGEST_SIZE);
		}
		tmp >>= 1;
	}
	CE(Sha256Final(ctx, &polycyPcr.hash[0]) ? EFI_SUCCESS: EFI_DEVICE_ERROR);
	Sha256Init(ctx);
	SetMem(hash, SHA256_DIGEST_SIZE, 0);
	Sha256Update(ctx, hash, SHA256_DIGEST_SIZE);
	Sha256Update(ctx, &polycyPcr, sizeof(polycyPcr));
	CE(Sha256Final(ctx, &hash[0]) ? EFI_SUCCESS : EFI_DEVICE_ERROR);

err:
	MEM_FREE(ctx);
	return res;
}

//
// TPM_CC_PolicyAuthValue command code for policy chaining
// This adds an authValue check to the policy
// Note: TPM_CC_PolicyAuthValue (0x16B) is defined in IndustryStandard/Tpm20.h
//

/**
  Create policy digest for PCR + AuthValue (PIN) policy.
  This chains PolicyAuthValue after PolicyPCR.

  The policy digest is: SHA256(SHA256(PolicyPCR) || TPM_CC_PolicyAuthValue)

  @param[in]  pcrMask   Mask of PCRs to include in policy
  @param[out] hash      Buffer for 32-byte policy digest

  @return EFI_SUCCESS or error
**/
EFI_STATUS
Tpm2MakePolicyPcrAuth(
	IN  UINT32   pcrMask,
	OUT UINT8    *hash
	)
{
	EFI_STATUS   res = EFI_SUCCESS;
	UINTN        ctxSize;
	VOID         *ctx;
	UINT8        pcrPolicyDigest[SHA256_DIGEST_SIZE];
	UINT32       cmdCode;

	// First compute the PolicyPCR digest
	CE(Tpm2MakePolicyPcr(pcrMask, pcrPolicyDigest));

	// Now extend with PolicyAuthValue
	// newDigest = SHA256(pcrPolicyDigest || TPM_CC_PolicyAuthValue)
	cmdCode = SwapBytes32(TPM_CC_PolicyAuthValue);

	ctxSize = Sha256GetContextSize();
	ctx = MEM_ALLOC(ctxSize);
	if (ctx == NULL) return EFI_BUFFER_TOO_SMALL;

	Sha256Init(ctx);
	Sha256Update(ctx, pcrPolicyDigest, SHA256_DIGEST_SIZE);
	Sha256Update(ctx, &cmdCode, sizeof(cmdCode));
	CE(Sha256Final(ctx, hash) ? EFI_SUCCESS : EFI_DEVICE_ERROR);

err:
	MEM_FREE(ctx);
	return res;
}

/**
  Create policy digest for PCR + Password policy.
  This chains PolicyPassword after PolicyPCR.

  PolicyPassword allows the authValue to be provided in clear text.

  IMPORTANT: Per TPM 2.0 spec Part 3, section 23.16, PolicyPassword updates
  the policy digest using TPM_CC_PolicyAuthValue (0x16B), NOT TPM_CC_PolicyPassword.
  Both commands use the same digest computation; the difference is only in how
  the authValue is provided during authorization.

  The policy digest is: SHA256(SHA256(PolicyPCR) || TPM_CC_PolicyAuthValue)

  @param[in]  pcrMask   Mask of PCRs to include in policy
  @param[out] hash      Buffer for 32-byte policy digest

  @return EFI_SUCCESS or error
**/
EFI_STATUS
Tpm2MakePolicyPcrPassword(
	IN  UINT32   pcrMask,
	OUT UINT8    *hash
	)
{
	EFI_STATUS   res = EFI_SUCCESS;
	UINTN        ctxSize;
	VOID         *ctx;
	UINT8        pcrPolicyDigest[SHA256_DIGEST_SIZE];
	UINT32       cmdCode;

	// First compute the PolicyPCR digest
	CE(Tpm2MakePolicyPcr(pcrMask, pcrPolicyDigest));

	// Now extend with PolicyPassword/PolicyAuthValue
	// Per TPM spec, PolicyPassword uses TPM_CC_PolicyAuthValue in digest computation
	// newDigest = SHA256(pcrPolicyDigest || TPM_CC_PolicyAuthValue)
	cmdCode = SwapBytes32(TPM_CC_PolicyAuthValue);

	ctxSize = Sha256GetContextSize();
	ctx = MEM_ALLOC(ctxSize);
	if (ctx == NULL) return EFI_BUFFER_TOO_SMALL;

	Sha256Init(ctx);
	Sha256Update(ctx, pcrPolicyDigest, SHA256_DIGEST_SIZE);
	Sha256Update(ctx, &cmdCode, sizeof(cmdCode));
	CE(Sha256Final(ctx, hash) ? EFI_SUCCESS : EFI_DEVICE_ERROR);

err:
	MEM_FREE(ctx);
	return res;
}

#pragma pack(1)
typedef struct {
	TPM2_COMMAND_HEADER       Header;
	UINT16                    Size;
} TPM2_GET_RANDOM_COMMAND;

typedef struct {
	TPM2_RESPONSE_HEADER       Header;
	TPM2B_MAX_BUFFER           Data;
} TPM2_GET_RANDOM_RESPONSE;
#pragma pack()

EFI_STATUS
Tpm2GetRandom(
	IN  UINTN  size,
	OUT VOID*  data
	) 
{
	EFI_STATUS                        res = EFI_SUCCESS;
	UINTN                             remains = size;
	UINTN                             request;
	UINTN                             gotBytes;
	UINT8                             *rnd = data;
	TPM2_GET_RANDOM_COMMAND           SendBuffer;
	TPM2_GET_RANDOM_RESPONSE          RecvBuffer;
	UINT32                            SendBufferSize;
	UINT32                            RecvBufferSize;
	TPM_RC                            ResponseCode;

	SendBufferSize = (UINT32) sizeof(SendBuffer);
	SendBuffer.Header.tag = SwapBytes16(TPM_ST_NO_SESSIONS);
	SendBuffer.Header.commandCode = SwapBytes32(TPM_CC_GetRandom);
	SendBuffer.Header.paramSize = SwapBytes32(SendBufferSize);

	while (remains > 0) {
		request = (remains < sizeof(RecvBuffer.Data.buffer)) ? remains : sizeof(RecvBuffer.Data.buffer);
		SendBuffer.Size = SwapBytes16((UINT16)request);
		RecvBufferSize = (UINT32) sizeof(RecvBuffer);

		res = Tpm2SubmitCommand(SendBufferSize, (UINT8 *)&SendBuffer, &RecvBufferSize, (UINT8 *)&RecvBuffer);
		if (EFI_ERROR(res)) {
			return res;
		}

		if (RecvBufferSize < sizeof(TPM2_RESPONSE_HEADER)) {
			return EFI_DEVICE_ERROR;
		}
		ResponseCode = SwapBytes32(RecvBuffer.Header.responseCode);
		if (ResponseCode != TPM_RC_SUCCESS) {
			return EFI_DEVICE_ERROR;
		}
		gotBytes = SwapBytes16(RecvBuffer.Data.size);
		CopyMem(rnd, &RecvBuffer.Data.buffer[0], gotBytes);
		remains -= gotBytes;
		rnd += gotBytes;
	}
	return res;
}

EFI_STATUS
Tpm2Measure(
	IN UINT32    index,
	IN UINTN     size,
	IN VOID*     data
	) 
{
	EFI_STATUS                res = EFI_SUCCESS;
	TPMI_DH_PCR               PcrHandle = index;
	TPML_DIGEST_VALUES        Digests;

	Digests.count = 2;
	Digests.digests[0].hashAlg = TPM_ALG_SHA256;
	Digests.digests[1].hashAlg = TPM_ALG_SHA1;
	CE(Sha256Hash(data, size, &Digests.digests[0].digest.sha256[0]));
	CE(Sha1Hash(data, size, &Digests.digests[1].digest.sha1[0]));

	CE(Tpm2PcrExtend(PcrHandle,&Digests));

err:
	return res;
}

VOID
Tpm2AuthSessionOwnerPrepare(
	IN  UINT8                 *OwnerPwd,
	IN  UINT16                OwnerPwdSize,
	OUT TPMS_AUTH_COMMAND     *AuthSession
	) 
{
	SetMem(AuthSession, sizeof(*AuthSession), 0);
	AuthSession->sessionHandle = TPM_RS_PW;
	AuthSession->nonce.size = 0;
 	AuthSession->hmac.size = (UINT16)OwnerPwdSize;
 	CopyMem(&AuthSession->hmac.buffer[0], OwnerPwd, OwnerPwdSize);
//	AuthSession->hmac.size = (UINT16)AsciiStrLen("tpmoPwd");
//	AsciiStrCpy(AuthSession->hmac.buffer, "tpmoPwd");

}

#pragma pack(1)
typedef struct {
	TPM2_COMMAND_HEADER       Header;
	UINT32                    Handle;
	UINT16                    auth;
	UINT32                    count;
	TPM_ALG_ID                hashType;
	UINT8                     pcrCount;
	UINT8                     pcrSelection[3];
} TPM2_POLICYPCR_COMMAND;

typedef struct {
	TPM2_RESPONSE_HEADER       Header;
} TPM2_POLICYPCR_RESPONSE;

typedef struct {
	TPM2_COMMAND_HEADER       Header;
	UINT32                    PolicySession;
} TPM2_POLICYAUTHVALUE_COMMAND;

typedef struct {
	TPM2_RESPONSE_HEADER       Header;
} TPM2_POLICYAUTHVALUE_RESPONSE;
#pragma pack()

/**
  Execute TPM2_PolicyAuthValue command to add authValue to policy session.
  This makes the policy require the NV index's authValue (PIN) in addition
  to any other policy assertions already made (like PolicyPCR).

  @param[in] SessionHandle  The policy session handle

  @return EFI_SUCCESS or TPM error
**/
STATIC
EFI_STATUS
Tpm2PolicyAuthValue(
	IN TPMI_SH_AUTH_SESSION SessionHandle
	)
{
	TPM2_POLICYAUTHVALUE_COMMAND    SendBuffer;
	TPM2_POLICYAUTHVALUE_RESPONSE   RecvBuffer;
	UINT32                          SendBufferSize;
	UINT32                          RecvBufferSize;
	TPM_RC                          ResponseCode;
	EFI_STATUS                      res;

	SetMem(&SendBuffer, sizeof(SendBuffer), 0);
	SetMem(&RecvBuffer, sizeof(RecvBuffer), 0);
	SendBufferSize = (UINT32)sizeof(SendBuffer);
	RecvBufferSize = (UINT32)sizeof(RecvBuffer);

	SendBuffer.Header.tag = SwapBytes16(TPM_ST_NO_SESSIONS);
	SendBuffer.Header.commandCode = SwapBytes32(TPM_CC_PolicyAuthValue);
	SendBuffer.Header.paramSize = SwapBytes32(SendBufferSize);
	SendBuffer.PolicySession = SwapBytes32(SessionHandle);

	res = Tpm2SubmitCommand(SendBufferSize, (UINT8 *)&SendBuffer, &RecvBufferSize, (UINT8 *)&RecvBuffer);
	if (EFI_ERROR(res)) {
		return res;
	}

	if (RecvBufferSize < sizeof(TPM2_RESPONSE_HEADER)) {
		return EFI_DEVICE_ERROR;
	}
	ResponseCode = SwapBytes32(RecvBuffer.Header.responseCode);
	if (ResponseCode != TPM_RC_SUCCESS) {
		return EFI_DEVICE_ERROR;
	}

	return EFI_SUCCESS;
}

/**
  Execute TPM2_PolicyPassword command to require password in clear text.
  This makes the policy require the NV index's authValue (PIN) to be
  provided in clear text in the hmac field of the auth session.

  @param[in] SessionHandle  The policy session handle

  @return EFI_SUCCESS or TPM error
**/
STATIC
EFI_STATUS
Tpm2PolicyPassword(
	IN TPMI_SH_AUTH_SESSION SessionHandle
	)
{
	TPM2_POLICYAUTHVALUE_COMMAND    SendBuffer;  // Same structure as PolicyAuthValue
	TPM2_POLICYAUTHVALUE_RESPONSE   RecvBuffer;
	UINT32                          SendBufferSize;
	UINT32                          RecvBufferSize;
	TPM_RC                          ResponseCode;
	EFI_STATUS                      res;

	SetMem(&SendBuffer, sizeof(SendBuffer), 0);
	SetMem(&RecvBuffer, sizeof(RecvBuffer), 0);
	SendBufferSize = (UINT32)sizeof(SendBuffer);
	RecvBufferSize = (UINT32)sizeof(RecvBuffer);

	SendBuffer.Header.tag = SwapBytes16(TPM_ST_NO_SESSIONS);
	SendBuffer.Header.commandCode = SwapBytes32(TPM_CC_PolicyPassword);
	SendBuffer.Header.paramSize = SwapBytes32(SendBufferSize);
	SendBuffer.PolicySession = SwapBytes32(SessionHandle);

	res = Tpm2SubmitCommand(SendBufferSize, (UINT8 *)&SendBuffer, &RecvBufferSize, (UINT8 *)&RecvBuffer);
	if (EFI_ERROR(res)) {
		return res;
	}

	if (RecvBufferSize < sizeof(TPM2_RESPONSE_HEADER)) {
		return EFI_DEVICE_ERROR;
	}
	ResponseCode = SwapBytes32(RecvBuffer.Header.responseCode);
	if (ResponseCode != TPM_RC_SUCCESS) {
		return EFI_DEVICE_ERROR;
	}

	return EFI_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
// PCRs
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
Tpm2ReadPcr(
	IN  UINT32    PcrIndex,
	OUT UINT8     *PcrValue,
	OUT UINT32    *PcrSize
	)
{
	TPML_DIGEST  Value;
	EFI_STATUS   Status;

	if (PcrValue == NULL || PcrSize == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	Status = Tpm2LibPcrRead(PcrIndex, &Value);
	if (EFI_ERROR(Status)) {
		return Status;
	}

	CopyMem(PcrValue, Value.digests[0].buffer, Value.digests[0].size);
	*PcrSize = Value.digests[0].size;
	return EFI_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
// TPM 2.0 Protocol
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
Tpm2LibGetRandom(
	IN   TPM_LIB_PROTOCOL*  tpm,
	IN   UINT32             DataSize,
	OUT  UINT8              *Data
	)
{
	return Tpm2GetRandom(DataSize, Data);
}

EFI_STATUS
Tpm2LibMeasure(
	TPM_LIB_PROTOCOL* tpm,
	IN UINTN          index,
	IN UINTN          dataSz,
	IN VOID*          data
	)
{
	return Tpm2Measure((UINT32)index, dataSz, data);
}

STATIC
UINT32
Tpm2ResolveNvIndex(
	IN UINT32 NvIndex
	)
{
	return 0x01000000 | NvIndex; // TPM 2.0 owner-defined range
}

// Check if an NV index exists using Tpm2NvReadPublic
STATIC
BOOLEAN
Tpm2NvIndexExists(
	IN UINT32 NvIndex
	)
{
	EFI_STATUS       res;
	TPM2B_NV_PUBLIC  NvPublic;
	TPM2B_NAME       NvName;

	res = Tpm2NvReadPublic(NvIndex, &NvPublic, &NvName);
	return !EFI_ERROR(res);
}

// Check if an NV index exists using TPM capability enumeration.
//STATIC
//BOOLEAN
//Tpm2NvIndexExists(
//	IN UINT32 NvIndex
//	)
//{
//	EFI_STATUS            res;
//	TPMI_YES_NO           MoreData;
//	TPMS_CAPABILITY_DATA  CapData;
//	UINT32                i;
//	UINT32                ReturnedCount;
//
//	// Query capability for this specific handle
//	// By starting at NvIndex and requesting 1, we can check if it exists
//	SetMem(&CapData, sizeof(CapData), 0);
//
//	res = Tpm2GetCapability(
//		TPM_CAP_HANDLES,
//		NvIndex,
//		1,  // Request just one handle starting at NvIndex
//		&MoreData,
//		&CapData
//		);
//
//	if (EFI_ERROR(res)) {
//		return FALSE;
//	}
//
//	// Get count of returned handles
//	ReturnedCount = CapData.data.handles.count;
//
//	// Handle potential byte order issues
//	if (ReturnedCount > MAX_CAP_HANDLES) {
//		ReturnedCount = SwapBytes32(ReturnedCount);
//		if (ReturnedCount > MAX_CAP_HANDLES) {
//			return FALSE;
//		}
//	}
//
//	// Check if the returned handle matches our target
//	for (i = 0; i < ReturnedCount; i++) {
//		UINT32 rawHandle = CapData.data.handles.handle[i];
//		UINT32 handle;
//
//		if (rawHandle == 0) {
//			continue;
//		}
//
//		// Determine byte order
//		if ((rawHandle & 0xFF000000) == (TPM_HT_NV_INDEX << 24)) {
//			handle = rawHandle;
//		} else if ((rawHandle & 0x000000FF) == TPM_HT_NV_INDEX) {
//			handle = SwapBytes32(rawHandle);
//		} else {
//			continue;
//		}
//
//		// Check if this is our target index
//		if (handle == NvIndex) {
//			return TRUE;
//		}
//	}
//
//	return FALSE;
//}

// Read PCR mask, flags, and optional info data from PCR info NV entry
STATIC
EFI_STATUS
Tpm2NVReadPcrInfo(
	IN  UINT32    DataNvIndex,
	OUT UINT32    *PcrMask,
	OUT UINT32    *Flags OPTIONAL,
	OUT VOID      *Info OPTIONAL,
	IN OUT UINT32 *InfoSize OPTIONAL
	)
{
	EFI_STATUS                res = EFI_SUCCESS;
	UINT32                    PcrNvIndex = DC_TPM_NV_INDEX_TO_PCRS(DataNvIndex);
	TPMS_AUTH_COMMAND         AuthSession;
	TPM2B_NV_PUBLIC           NvPublic;
	TPM2B_NAME                NvName;
	UINT16                    nvSize;
	TPM2B_MAX_BUFFER          OutData;
	DC_TPM_PCRINFO_DATA       *pcrInfo;

	SetMem(&AuthSession, sizeof(AuthSession), 0);
	AuthSession.sessionHandle = TPM_RS_PW;

	// Get NV public to determine size
	CE(Tpm2NvReadPublic(PcrNvIndex, &NvPublic, &NvName));
	nvSize = NvPublic.nvPublic.dataSize;

	// Read all data from NV
	CE(Tpm2NvRead(PcrNvIndex, PcrNvIndex, &AuthSession, nvSize, 0, &OutData));

	// Parse as DC_TPM_PCRINFO_DATA structure
	if (nvSize < DC_TPM_PCRINFO_BASE_SIZE) {
		res = EFI_COMPROMISED_DATA;
		goto err;
	}

	pcrInfo = (DC_TPM_PCRINFO_DATA *)OutData.buffer;

	// Verify magic
	if (pcrInfo->Magic != DC_TPM_PCRINFO_MAGIC) {
		res = EFI_COMPROMISED_DATA;
		goto err;
	}

	// Return PcrMask and Flags separately
	*PcrMask = pcrInfo->PcrMask;
	if (Flags != NULL) {
		*Flags = pcrInfo->Flags;
	}

	// Return info data if requested
	if (InfoSize != NULL) {
		UINT32 storedInfoSize = pcrInfo->InfoSize;
		if (Info != NULL && storedInfoSize > 0 && *InfoSize >= storedInfoSize) {
			CopyMem(Info, pcrInfo->InfoData, storedInfoSize);
		}
		*InfoSize = storedInfoSize;
	}

err:
	return res;
}

STATIC
EFI_STATUS
Tpm2NVReadPcrMaskAndFlags(
	IN  UINT32 DataNvIndex,
	OUT UINT32 *PcrMask,
	OUT UINT32 *Flags OPTIONAL
	)
{
	return Tpm2NVReadPcrInfo(DataNvIndex, PcrMask, Flags, NULL, NULL);
}

BOOLEAN
Tpm2IsConfigured(
	IN UINT32 NvIndex
	)
{
	EFI_STATUS                res = EFI_SUCCESS;
	UINT32                    DataNvIndex;
//	UINT32                    PcrNvIndex;
	TPM2B_NV_PUBLIC           NvPublic;
	TPM2B_NAME                NvName;
	UINT32                    PcrMask;

	if (EFI_ERROR(InitTpm20())) {
		return FALSE;
	}

	DataNvIndex = Tpm2ResolveNvIndex(NvIndex);
//	PcrNvIndex = DC_TPM_NV_INDEX_TO_PCRS(DataNvIndex);

//	if (!Tpm2NvIndexExists(PcrNvIndex) || !Tpm2NvIndexExists(DataNvIndex)) {
//		return FALSE;
//	}

	if (EFI_ERROR(res = Tpm2NVReadPcrMaskAndFlags(DataNvIndex, &PcrMask, NULL)) ||
		EFI_ERROR(res = Tpm2NvReadPublic(DataNvIndex, &NvPublic, &NvName)) ||
		(NvPublic.nvPublic.dataSize < DC_TPM_SEALED_MIN_SIZE) ||
		(NvPublic.nvPublic.attributes.TPMA_NV_WRITTEN == 0)
		) {
		return FALSE;
	}

	return TRUE;
}

BOOLEAN
Tpm2IsOpen(
	IN UINT32 NvIndex
	)
{
	EFI_STATUS                res = EFI_SUCCESS;
	UINT32                    DataNvIndex;
	UINT32                    PcrMask;
	UINT32                    Flags;
	BOOLEAN                   PinRequired;
	TPM2B_NV_PUBLIC           NvPublic;
	TPM2B_NAME                NvName;
	UINT8                     computedPolicy[SHA256_DIGEST_SIZE];

	if (EFI_ERROR(InitTpm20())) {
		return FALSE;
	}

	DataNvIndex = Tpm2ResolveNvIndex(NvIndex);

	if (!Tpm2IsConfigured(NvIndex)) {
		return FALSE;
	}

	// Read NV public to get stored authPolicy
	CE(Tpm2NvReadPublic(DataNvIndex, &NvPublic, &NvName));

	// Read PCR mask and flags
	CE(Tpm2NVReadPcrMaskAndFlags(DataNvIndex, &PcrMask, &Flags));
	PinRequired = (Flags & DC_TPM_FLAG_PIN_REQUIRED) != 0;

	// If PIN-only (backup entry with no PCRs), always return TRUE
	// Let unseal handle PIN validation
	if (PinRequired && PcrMask == 0) {
		return TRUE;
	}

	// If no policy (AUTHREAD mode - old format), return TRUE
	if (NvPublic.nvPublic.authPolicy.size == 0) {
		return TRUE;
	}

	// Verify stored policy digest size matches SHA256
	if (NvPublic.nvPublic.authPolicy.size != SHA256_DIGEST_SIZE) {
		return FALSE;
	}

	// Compute expected policy digest using current PCR values
	// This uses the same software computation as during sealing
	// (More reliable than trial sessions which may behave differently on some TPMs)
	if (PinRequired) {
		// PCR + PIN: Combined policy (PolicyPCR + PolicyAuthValue)
		CE(Tpm2MakePolicyPcrPassword(PcrMask, computedPolicy));
	} else {
		// PCR only: Just PolicyPCR
		CE(Tpm2MakePolicyPcr(PcrMask, computedPolicy));
	}

	// Compare computed digest with stored authPolicy
	if (CompareMem(computedPolicy, NvPublic.nvPublic.authPolicy.buffer, SHA256_DIGEST_SIZE) != 0) {
		// Digests don't match - PCRs have changed
		res = EFI_ACCESS_DENIED;
		goto err;
	}

	// Digests match - PCRs are OK (PIN will be validated during unseal)
	res = EFI_SUCCESS;

err:
	return !EFI_ERROR(res);
}

EFI_STATUS
Tpm2Clean(
	IN UINT32   DataNvIndex,
	IN UINT8    *OwnerPwd,
	IN UINT16   OwnerPwdSize
	)
{
	EFI_STATUS                res = EFI_SUCCESS;
	TPMS_AUTH_COMMAND         AuthSession;
	UINT32                    PcrNvIndex = DC_TPM_NV_INDEX_TO_PCRS(DataNvIndex);

	Tpm2AuthSessionOwnerPrepare(OwnerPwd, OwnerPwdSize, &AuthSession);

	// Try to delete PCR mask NV - ignore error if not present
	Tpm2NvUndefineSpace(
		TPM_RH_OWNER,
		PcrNvIndex,
		&AuthSession
		);

	// Delete main NV
	CE(Tpm2NvUndefineSpace(
		TPM_RH_OWNER,
		DataNvIndex,
		&AuthSession
		));

err:
	return res;
}

EFI_STATUS
Tpm2SealPassword(
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
	EFI_STATUS                res = EFI_SUCCESS;
	TPMS_AUTH_COMMAND         AuthSession;
	TPM2B_AUTH                Auth;
	TPM2B_NV_PUBLIC           NvPublic;
	TPM2B_MAX_BUFFER          InData;
	UINT8                     SealedBuffer[DC_TPM_SEALED_MAX_SIZE];
	DC_TPM_SEALED_DATA        *SealedData = (DC_TPM_SEALED_DATA *)SealedBuffer;
	UINT32                    SealedSize;
	UINT8                     OwnerAuthData[64];
	UINT16                    OwnerAuthSize;
	UINT8                     PinAuthData[128];
	UINT16                    PinAuthSize = 0;
	BOOLEAN                   usePin = FALSE;
	UINT32                    DataNvIndex;
	UINT32                    PcrNvIndex;
	UINT32                    PcrInfoNvSize;

	if (password == NULL || passwordSize == 0) {
		return EFI_INVALID_PARAMETER;
	}
	if (passwordSize > DC_TPM_SEALED_MAX_SIZE - DC_TPM_SEALED_BASE_SIZE) {
		return EFI_BAD_BUFFER_SIZE;
	}
	if (infoSize > DC_TPM_INFO_MAX_SIZE) {
		return EFI_BAD_BUFFER_SIZE;
	}

	CE(InitTpm20());

	// Resolve NV indices
	DataNvIndex = Tpm2ResolveNvIndex(NvIndex);
	PcrNvIndex = DC_TPM_NV_INDEX_TO_PCRS(DataNvIndex);

	// Calculate PCR info NV size
	PcrInfoNvSize = DC_TPM_PCRINFO_BASE_SIZE + infoSize;

	// Prepare owner auth
	// Note: Windows provisioning leaves owner auth EMPTY - use empty password in that case
	if (ownerPwd == NULL || ownerPwd[0] == L'\0') {
		OwnerAuthSize = 0;
	} else {
		CE(TpmPrepareAuth(ownerPwd, OwnerAuthData, &OwnerAuthSize));
	}

	// Prepare PIN auth if provided
	if (tpmPin != NULL && tpmPin[0] != L'\0') {
		CE(TpmPrepareAuth(tpmPin, PinAuthData, &PinAuthSize));
		usePin = TRUE;
	}

	// Clean up any existing NV spaces
	Tpm2Clean(DataNvIndex, OwnerAuthData, OwnerAuthSize);

	Tpm2AuthSessionOwnerPrepare(OwnerAuthData, OwnerAuthSize, &AuthSession);

	// Define NV space for the sealed password
	SetMem(&NvPublic, sizeof(NvPublic), 0);
	SetMem(&Auth, sizeof(Auth), 0);

	// Set NV index authValue from PIN (if provided)
	if (usePin) {
		Auth.size = PinAuthSize;
		CopyMem(Auth.buffer, PinAuthData, PinAuthSize);
	} else {
		Auth.size = 0;
	}

	NvPublic.nvPublic.nvIndex = DataNvIndex;
	NvPublic.nvPublic.nameAlg = TPM_ALG_SHA256;
	NvPublic.nvPublic.attributes.TPMA_NV_OWNERWRITE = 1;
	NvPublic.nvPublic.attributes.TPMA_NV_POLICYWRITE = 1;

	// For backup (pcrMask == 0): PIN-only, no PCR policy
	// For PIN with PCRs: Combined policy (PolicyPCR + PolicyAuthValue) - both TPM-enforced
	// For no-PIN with PCRs: use POLICYREAD (PCR-bound policy)
	if (pcrMask == 0) {
		// Backup entry: PIN-only protection, no PCR binding
		// PIN is required for backup entries
		if (!usePin) {
			res = EFI_INVALID_PARAMETER;  // Backup requires PIN
			goto err;
		}
		// CRITICAL: Do NOT set OWNERREAD for backup - owner must not bypass PIN!
		NvPublic.nvPublic.attributes.TPMA_NV_OWNERREAD = 0;  // Owner cannot read
		NvPublic.nvPublic.attributes.TPMA_NV_AUTHREAD = 1;   // Read requires PIN auth
		NvPublic.nvPublic.attributes.TPMA_NV_POLICYREAD = 0;
		NvPublic.nvPublic.attributes.TPMA_NV_NO_DA = 0;      // ENABLE dictionary attack protection!
		NvPublic.nvPublic.authPolicy.size = 0;  // No policy for backup
		NvPublic.size = 4 + 2 + 4 + 2 + 0 + 2;  // No policy hash
	} else if (usePin) {
		// PCR + PIN: Combined policy using PolicyPCR + PolicyPassword
		// Both PCRs and PIN are TPM-enforced via policy
		NvPublic.nvPublic.attributes.TPMA_NV_OWNERREAD = 1;  // Owner can read (but needs policy)
		NvPublic.nvPublic.attributes.TPMA_NV_AUTHREAD = 0;   // Not using direct auth
		NvPublic.nvPublic.attributes.TPMA_NV_POLICYREAD = 1; // Read requires policy
		NvPublic.nvPublic.attributes.TPMA_NV_NO_DA = 0;      // ENABLE dictionary attack protection!
		NvPublic.nvPublic.authPolicy.size = SHA256_DIGEST_SIZE;
		// Policy hash: H(H(PolicyPCR) || TPM_CC_PolicyAuthValue) - PolicyPassword uses same digest
		CE(Tpm2MakePolicyPcrPassword(pcrMask, &NvPublic.nvPublic.authPolicy.buffer[0]));
		NvPublic.size = 4 + 2 + 4 + 2 + SHA256_DIGEST_SIZE + 2;
	} else {
		// PCR only: Use policy for read - no PIN to brute force
		NvPublic.nvPublic.attributes.TPMA_NV_OWNERREAD = 1;  // Owner can read (but needs policy)
		NvPublic.nvPublic.attributes.TPMA_NV_AUTHREAD = 0;
		NvPublic.nvPublic.attributes.TPMA_NV_POLICYREAD = 1; // Read requires policy
		NvPublic.nvPublic.attributes.TPMA_NV_NO_DA = 1;      // No PIN, DA protection not needed
		NvPublic.nvPublic.authPolicy.size = SHA256_DIGEST_SIZE;
		CE(Tpm2MakePolicyPcr(pcrMask, &NvPublic.nvPublic.authPolicy.buffer[0]));
		NvPublic.size = 4 + 2 + 4 + 2 + SHA256_DIGEST_SIZE + 2;
	}

	// Calculate sealed data size (padded to 16 bytes, min 96)
	SealedSize = DC_TPM_SEALED_DATA_SIZE(passwordSize);
	NvPublic.nvPublic.dataSize = (UINT16)SealedSize;

	CE(Tpm2NvDefineSpace(
		TPM_RH_OWNER,
		&AuthSession,
		&Auth,
		&NvPublic
		));

	// Define NV space for PCR info (mask + flags + info data)
	SetMem(&NvPublic, sizeof(NvPublic), 0);
	SetMem(&Auth, sizeof(Auth), 0);
	Auth.size = 0;
	NvPublic.size = 4 + 2 + 4 + 2 + 2;
	NvPublic.nvPublic.nvIndex = PcrNvIndex;
	NvPublic.nvPublic.nameAlg = TPM_ALG_SHA256;
	NvPublic.nvPublic.attributes.TPMA_NV_OWNERREAD = 1;
	NvPublic.nvPublic.attributes.TPMA_NV_OWNERWRITE = 1;
	NvPublic.nvPublic.attributes.TPMA_NV_AUTHREAD = 1;
	NvPublic.nvPublic.attributes.TPMA_NV_NO_DA = 1;
	NvPublic.nvPublic.authPolicy.size = 0;
	NvPublic.nvPublic.dataSize = (UINT16)PcrInfoNvSize;

	CE(Tpm2NvDefineSpace(
		TPM_RH_OWNER,
		&AuthSession,
		&Auth,
		&NvPublic
		));

	// Prepare sealed data structure
	SetMem(SealedBuffer, sizeof(SealedBuffer), 0);
	SealedData->Magic = DC_TPM_SEALED_MAGIC;
	SealedData->Version = DC_TPM_SEALED_VERSION;
	SealedData->PasswordSize = (UINT16)passwordSize;
	SealedData->PasswordType = passwordType;

	CopyMem(SealedData->Password, password, passwordSize);
	// Calculate checksum
	gBS->CalculateCrc32(password, passwordSize, &SealedData->Checksum);

	// Write sealed data
	InData.size = (UINT16)SealedSize;
	CopyMem(InData.buffer, SealedBuffer, SealedSize);

	CE(Tpm2NvWrite(
		TPM_RH_OWNER,
		DataNvIndex,
		&AuthSession,
		&InData,
		0
		));

	// Write PCR info with mask, PIN flag, and optional info data
	{
		UINT8 pcrInfoBuffer[DC_TPM_PCRINFO_BASE_SIZE + DC_TPM_INFO_MAX_SIZE];
		DC_TPM_PCRINFO_DATA *pcrInfoData = (DC_TPM_PCRINFO_DATA *)pcrInfoBuffer;
		UINT32 flags = 0;

		SetMem(pcrInfoBuffer, sizeof(pcrInfoBuffer), 0);

		if (usePin) {
			flags |= DC_TPM_FLAG_PIN_REQUIRED;
		}

		pcrInfoData->Magic = DC_TPM_PCRINFO_MAGIC;
		pcrInfoData->Version = DC_TPM_PCRINFO_VERSION;
		pcrInfoData->PcrMask = pcrMask;
		pcrInfoData->Flags = flags;
		pcrInfoData->InfoSize = (UINT16)infoSize;

		if (info != NULL && infoSize > 0) {
			CopyMem(pcrInfoData->InfoData, info, infoSize);
		}

		InData.size = (UINT16)PcrInfoNvSize;
		CopyMem(InData.buffer, pcrInfoBuffer, PcrInfoNvSize);

		CE(Tpm2NvWrite(
			TPM_RH_OWNER,
			PcrNvIndex,
			&AuthSession,
			&InData,
			0
			));
	}

err:
	// Clear sensitive data
	SetMem(SealedBuffer, sizeof(SealedBuffer), 0);
	SetMem(PinAuthData, sizeof(PinAuthData), 0);
	return res;
}

EFI_STATUS
Tpm2UnsealPassword(
	IN  UINT32    NvIndex,
	OUT VOID      *password,
	OUT UINT32    *passwordSize,
	OUT UINT32    *passwordType,
	IN  CHAR16    *tpmPin OPTIONAL
	)
{
	EFI_STATUS                res = EFI_SUCCESS;
	TPMI_SH_AUTH_SESSION      SessionHandle = 0;
	UINT32                    DataNvIndex;
	UINT32                    PcrMask;
	UINT32                    Flags;
	UINT8                     SealedBuffer[DC_TPM_SEALED_MAX_SIZE];
	DC_TPM_SEALED_DATA        *SealedData = (DC_TPM_SEALED_DATA *)SealedBuffer;
	UINT32                    NvSize = 0;
	UINT32                    crc = 0;
	UINT8                     PinAuthData[128];
	UINT16                    PinAuthSize = 0;
	BOOLEAN                   pinRequired = FALSE;

	if (password == NULL || passwordSize == NULL || passwordType == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	CE(InitTpm20());

	// Resolve NV index
	DataNvIndex = Tpm2ResolveNvIndex(NvIndex);

	// Read PCR mask and flags to determine if PIN is required
	CE(Tpm2NVReadPcrMaskAndFlags(DataNvIndex, &PcrMask, &Flags));
	pinRequired = (Flags & DC_TPM_FLAG_PIN_REQUIRED) != 0;

	// Prepare PIN auth if provided
	if (tpmPin != NULL && tpmPin[0] != L'\0') {
		res = TpmPrepareAuth(tpmPin, PinAuthData, &PinAuthSize);
		if (EFI_ERROR(res)) {
			return res;
		}
	} else if (pinRequired) {
		// PIN is required but not provided
		return EFI_ACCESS_DENIED;
	}

	// Check NV index attributes to determine auth method
	// Old sealing used AUTHREAD=1, new combined policy uses POLICYREAD=1
	{
		TPM2B_NV_PUBLIC  NvPublic;
		TPM2B_NAME       NvName;
		BOOLEAN          usePolicyRead = FALSE;

		res = Tpm2NvReadPublic(DataNvIndex, &NvPublic, &NvName);
		if (!EFI_ERROR(res)) {
			usePolicyRead = NvPublic.nvPublic.attributes.TPMA_NV_POLICYREAD != 0;
			NvSize = NvPublic.nvPublic.dataSize;
			if (NvSize > sizeof(SealedBuffer)) {
				NvSize = sizeof(SealedBuffer);
			}
		}
		if (NvSize < DC_TPM_SEALED_MIN_SIZE) {
			return EFI_COMPROMISED_DATA;
		}

		// Use password auth if:
		// 1. PIN-only (backup entry with PcrMask == 0), OR
		// 2. Old format with AUTHREAD (POLICYREAD == 0)
		if ((pinRequired && PcrMask == 0) || (pinRequired && !usePolicyRead)) {
			// PIN case with password auth: Use TPM_RS_PW directly
			TPMS_AUTH_COMMAND         AuthSession;
			TPM2B_MAX_BUFFER          OutData;

			SetMem(&AuthSession, sizeof(AuthSession), 0);
			AuthSession.sessionHandle = TPM_RS_PW;  // Password session
			AuthSession.nonce.size = 0;
			AuthSession.sessionAttributes.continueSession = 0;
			AuthSession.hmac.size = PinAuthSize;
			CopyMem(AuthSession.hmac.buffer, PinAuthData, PinAuthSize);

			res = Tpm2NvRead(
				DataNvIndex,
				DataNvIndex,
				&AuthSession,
				(UINT16)NvSize,
				0,
				&OutData
				);

			if (EFI_ERROR(res)) {
				//Tpm2PrintAuthError(res, TRUE);
				goto err;
			}

			CopyMem(SealedBuffer, &OutData.buffer[0], OutData.size);
		} else {
			// Policy-based read: PCR only or PCR + PIN (combined policy)
			// Start policy session and execute required policy commands
			TPMI_DH_OBJECT            TpmKey = TPM_RH_NULL;
			TPMI_DH_ENTITY            Bind = TPM_RH_NULL;
			TPM2B_NONCE               NonceCaller;
			TPM2B_ENCRYPTED_SECRET    Salt;
			TPM_SE                    SessionType = TPM_SE_POLICY;
		TPMT_SYM_DEF              Symmetric;
		TPMI_ALG_HASH             AuthHash = TPM_ALG_SHA256;
		TPM2B_NONCE               NonceTPM;

		SetMem(&NonceCaller, sizeof(NonceCaller), 0);
		NonceCaller.size = 0x20;
		Salt.size = 0;
		Symmetric.algorithm = TPM_ALG_XOR;
		Symmetric.keyBits.xor_ = TPM_ALG_SHA256;

		res = Tpm2StartAuthSession(
			TpmKey, Bind, &NonceCaller, &Salt,
			SessionType, &Symmetric, AuthHash,
			&SessionHandle, &NonceTPM
			);
		if (EFI_ERROR(res)) {
			//OUT_PRINT(L"DEBUG: StartAuthSession failed: %r\n", res);
			goto err;
		}
		//OUT_PRINT(L"DEBUG: StartAuthSession OK, handle=0x%x\n", SessionHandle);

		{
			TPM2_POLICYPCR_COMMAND    SendBuffer;
			TPM2_POLICYPCR_RESPONSE   RecvBuffer;
			UINT32                    SendBufferSize;
			UINT32                    RecvBufferSize;
			TPM_RC                    ResponseCode;
			TPMS_AUTH_COMMAND         AuthSession;
			TPM2B_MAX_BUFFER          OutData;

			// Step 1: Execute PolicyPCR
			//OUT_PRINT(L"DEBUG: Executing PolicyPCR, PcrMask=0x%x\n", PcrMask);
			SetMem(&SendBuffer, sizeof(SendBuffer), 0);
			SetMem(&RecvBuffer, sizeof(RecvBuffer), 0);
			RecvBufferSize = (UINT32)sizeof(RecvBuffer);
			SendBufferSize = (UINT32)sizeof(SendBuffer);

			SendBuffer.Header.tag = SwapBytes16(TPM_ST_NO_SESSIONS);
			SendBuffer.Header.commandCode = SwapBytes32(TPM_CC_PolicyPCR);
			SendBuffer.Header.paramSize = SwapBytes32(SendBufferSize);
			SendBuffer.Handle = SwapBytes32(SessionHandle);
			SendBuffer.auth = 0;
			SendBuffer.hashType = SwapBytes16(TPM_ALG_SHA256);
			SendBuffer.count = SwapBytes32(1);
			SendBuffer.pcrCount = 3;
			SendBuffer.pcrSelection[0] = (PcrMask) & 0xFF;
			SendBuffer.pcrSelection[1] = ((PcrMask) >> 8) & 0xFF;
			SendBuffer.pcrSelection[2] = ((PcrMask) >> 16) & 0xFF;

			res = Tpm2SubmitCommand(SendBufferSize, (UINT8 *)&SendBuffer, &RecvBufferSize, (UINT8 *)&RecvBuffer);
			if (EFI_ERROR(res)) {
				//OUT_PRINT(L"DEBUG: PolicyPCR submit failed: %r\n", res);
				goto err;
			}

			if (RecvBufferSize < sizeof(TPM2_RESPONSE_HEADER)) {
				//OUT_PRINT(L"DEBUG: PolicyPCR response too small\n");
				res = EFI_DEVICE_ERROR;
				goto err;
			}
			ResponseCode = SwapBytes32(RecvBuffer.Header.responseCode);
			if (ResponseCode != TPM_RC_SUCCESS) {
				//OUT_PRINT(L"DEBUG: PolicyPCR failed, TPM RC=0x%x\n", ResponseCode);
				res = EFI_DEVICE_ERROR;
				goto err;
			}
			//OUT_PRINT(L"DEBUG: PolicyPCR OK\n");

			// Step 2: If PIN required, execute PolicyPassword
			if (pinRequired) {
				//OUT_PRINT(L"DEBUG: Executing PolicyPassword\n");
				res = Tpm2PolicyPassword(SessionHandle);
				if (EFI_ERROR(res)) {
					//OUT_PRINT(L"DEBUG: PolicyPassword failed: %r\n", res);
					goto err;
				}
				//OUT_PRINT(L"DEBUG: PolicyPassword OK\n");
			}

			// Step 3: Read NV using policy session
			//OUT_PRINT(L"DEBUG: Reading NV index 0x%x, pinRequired=%d, PinAuthSize=%d\n", DataNvIndex, pinRequired, PinAuthSize);
			SetMem(&AuthSession, sizeof(AuthSession), 0);
			AuthSession.sessionHandle = SessionHandle;
			AuthSession.nonce.size = 0;
			if (pinRequired) {
				AuthSession.hmac.size = PinAuthSize;
				CopyMem(AuthSession.hmac.buffer, PinAuthData, PinAuthSize);
			} else {
				AuthSession.hmac.size = 0;
			}

			res = Tpm2NvRead(
				DataNvIndex,
				DataNvIndex,
				&AuthSession,
				(UINT16)NvSize,
				0,
				&OutData
				);
			if (EFI_ERROR(res)) {
				//OUT_PRINT(L"DEBUG: NvRead failed: %r\n", res);
				//Tpm2PrintAuthError(res, pinRequired);
				goto err;
			}
			//OUT_PRINT(L"DEBUG: NvRead OK, size=%d\n", OutData.size);

			CopyMem(SealedBuffer, &OutData.buffer[0], OutData.size);
		}
	}
	}  // End of NV public check block

	// Validate sealed data
	if (SealedData->Magic != DC_TPM_SEALED_MAGIC) {
		res = EFI_COMPROMISED_DATA;
		goto err;
	}
	// Accept version
	if (SealedData->Version != DC_TPM_SEALED_VERSION) {
		res = EFI_UNSUPPORTED;
		goto err;
	}
	// Validate password size fits within NV data
	if (SealedData->PasswordSize > NvSize - DC_TPM_SEALED_BASE_SIZE) {
		res = EFI_COMPROMISED_DATA;
		goto err;
	}

	// Verify checksum
	gBS->CalculateCrc32(SealedData->Password, SealedData->PasswordSize, &crc);
	if (crc != SealedData->Checksum) {
		res = EFI_CRC_ERROR;
		goto err;
	}

	// Copy password out
	CopyMem(password, SealedData->Password, SealedData->PasswordSize);
	*passwordSize = SealedData->PasswordSize;
	*passwordType = SealedData->PasswordType;

err:
	if (SessionHandle != 0) {
		Tpm2FlushContext(SessionHandle);
	}
	// Clear sensitive data
	SetMem(SealedBuffer, sizeof(SealedBuffer), 0);
	SetMem(PinAuthData, sizeof(PinAuthData), 0);
	return res;
}

EFI_STATUS
Tpm2ClearSecret(
	IN  UINT32    NvIndex,
	IN  CHAR16    *ownerPwd
	)
{
	EFI_STATUS res;
	UINT32     DataNvIndex;
	UINT8      OwnerAuthData[64];
	UINT16     OwnerAuthSize;

	if (ownerPwd == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	CE(InitTpm20());

	// Resolve NV index
	DataNvIndex = Tpm2ResolveNvIndex(NvIndex);

	// Prepare owner auth (handles both plaintext password and Windows base64 blob)
	CE(TpmPrepareAuth(ownerPwd, OwnerAuthData, &OwnerAuthSize));
	res = Tpm2Clean(DataNvIndex, OwnerAuthData, OwnerAuthSize);

err:
	SetMem(OwnerAuthData, sizeof(OwnerAuthData), 0);
	return res;
}

EFI_STATUS
Tpm2TakeOwnership(
	IN  CHAR16    *newOwnerPwd
	)
{
	EFI_STATUS                res = EFI_SUCCESS;
	TPM2B_AUTH                NewAuth;
	TPMS_AUTH_COMMAND         AuthSession;
	UINT8                     NewAuthData[64];
	UINT16                    NewAuthSize;

	if (newOwnerPwd == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	CE(InitTpm20());

	// Prepare new auth (handles both plaintext password and Windows base64 blob)
	CE(TpmPrepareAuth(newOwnerPwd, NewAuthData, &NewAuthSize));
	if (NewAuthSize > sizeof(NewAuth.buffer)) {
		return EFI_BUFFER_TOO_SMALL;
	}

	// Prepare empty auth for current (unowned) state
	SetMem(&AuthSession, sizeof(AuthSession), 0);
	AuthSession.sessionHandle = TPM_RS_PW;
	AuthSession.nonce.size = 0;
	AuthSession.hmac.size = 0;

	// Set new owner password
	NewAuth.size = NewAuthSize;
	CopyMem(NewAuth.buffer, NewAuthData, NewAuthSize);

	CE(Tpm2HierarchyChangeAuth(TPM_RH_OWNER, &AuthSession, &NewAuth));

err:
	SetMem(NewAuthData, sizeof(NewAuthData), 0);
	SetMem(&NewAuth, sizeof(NewAuth), 0);
	return res;
}

EFI_STATUS
Tpm2ChangeOwnerPassword(
	IN  CHAR16    *oldOwnerPwd,
	IN  CHAR16    *newOwnerPwd
	)
{
	EFI_STATUS                res = EFI_SUCCESS;
	TPM2B_AUTH                NewAuth;
	TPMS_AUTH_COMMAND         AuthSession;
	UINT8                     OldAuthData[64];
	UINT16                    OldAuthSize;
	UINT8                     NewAuthData[64];
	UINT16                    NewAuthSize;

	if (newOwnerPwd == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	CE(InitTpm20());

	// Prepare old auth
	CE(TpmPrepareAuth(oldOwnerPwd, OldAuthData, &OldAuthSize));

	// Prepare new auth
	CE(TpmPrepareAuth(newOwnerPwd, NewAuthData, &NewAuthSize));
	if (NewAuthSize > sizeof(NewAuth.buffer)) {
		res = EFI_BUFFER_TOO_SMALL;
		goto err;
	}

	// Prepare auth session with current owner password
	SetMem(&AuthSession, sizeof(AuthSession), 0);
	AuthSession.sessionHandle = TPM_RS_PW;
	AuthSession.nonce.size = 0;
	AuthSession.hmac.size = OldAuthSize;
	CopyMem(AuthSession.hmac.buffer, OldAuthData, OldAuthSize);

	// Set new owner password
	NewAuth.size = NewAuthSize;
	CopyMem(NewAuth.buffer, NewAuthData, NewAuthSize);

	CE(Tpm2HierarchyChangeAuth(TPM_RH_OWNER, &AuthSession, &NewAuth));

err:
	SetMem(OldAuthData, sizeof(OldAuthData), 0);
	SetMem(NewAuthData, sizeof(NewAuthData), 0);
	SetMem(&AuthSession, sizeof(AuthSession), 0);
	SetMem(&NewAuth, sizeof(NewAuth), 0);
	return res;
}

EFI_STATUS
Tpm2GetInfo(
	IN      UINT32    NvIndex,
	OUT     UINT32    *PcrMask OPTIONAL,
	OUT     UINT32    *Flags OPTIONAL,
	OUT     VOID      *Info OPTIONAL,
	IN OUT  UINT32    *InfoSize OPTIONAL
	)
{
	UINT32 DataNvIndex;
	UINT32 localPcrMask;

	if (EFI_ERROR(InitTpm20())) {
		return EFI_NOT_READY;
	}

	// Resolve NV index
	DataNvIndex = Tpm2ResolveNvIndex(NvIndex);

	return Tpm2NVReadPcrInfo(DataNvIndex,
		PcrMask ? PcrMask : &localPcrMask,
		Flags, Info, InfoSize);
}

//////////////////////////////////////////////////////////////////////////
// Buffer-based SRK functions (caller handles file I/O)
// Buffer format: [DC_TPM_SRK_FILE_HEADER][SealedBlob][Encrypted DC_TPM_SEALED_DATA][InfoData]
//////////////////////////////////////////////////////////////////////////

// Maximum size for sealed blob (private + public parts)
#define DC_TPM2_MAX_SEALED_BLOB_SIZE  512

// Structure to hold sealed object blobs for file storage
#pragma pack(1)
typedef struct _DC_TPM2_SEALED_BLOB {
	UINT16  PrivateSize;    // Size of private blob
	UINT16  PublicSize;     // Size of public blob
	UINT8   Data[1];        // Private blob followed by public blob
} DC_TPM2_SEALED_BLOB;
#pragma pack()

/**
  Create the Storage Root Key (SRK) using TPM2_CreatePrimary.
  Uses standard RSA-2048 SRK template from TPM 2.0 spec.

  @param[out] SrkHandle     Handle to the created SRK

  @return EFI_SUCCESS or error
**/
STATIC
EFI_STATUS
Tpm2CreateSrk(
	OUT TPMI_DH_OBJECT  *SrkHandle
	)
{
	EFI_STATUS         res;
	UINT8              SendBuffer[512];
	UINT8              RecvBuffer[1024];
	UINT32             SendBufferSize;
	UINT32             RecvBufferSize;
	UINT8              *Buffer;
	TPM2_COMMAND_HEADER *CmdHdr;
	TPM2_RESPONSE_HEADER *RspHdr;
	UINT32             AuthSize;

	// Build TPM2_CreatePrimary command manually
	SetMem(SendBuffer, sizeof(SendBuffer), 0);
	Buffer = SendBuffer;
	CmdHdr = (TPM2_COMMAND_HEADER *)Buffer;

	// Header
	CmdHdr->tag = SwapBytes16(TPM_ST_SESSIONS);
	CmdHdr->commandCode = SwapBytes32(TPM_CC_CreatePrimary);
	Buffer += sizeof(TPM2_COMMAND_HEADER);

	// primaryHandle = TPM_RH_OWNER (storage hierarchy)
	*(UINT32*)Buffer = SwapBytes32(TPM_RH_OWNER);
	Buffer += 4;

	// Authorization area (empty password session)
	AuthSize = 4 + 2 + 1 + 2;  // sessionHandle + nonceSize + attributes + hmacSize
	*(UINT32*)Buffer = SwapBytes32(AuthSize);
	Buffer += 4;
	*(UINT32*)Buffer = SwapBytes32(TPM_RS_PW);  // sessionHandle
	Buffer += 4;
	*(UINT16*)Buffer = 0;  // nonce size
	Buffer += 2;
	*Buffer = 0;  // session attributes
	Buffer += 1;
	*(UINT16*)Buffer = 0;  // hmac size (empty owner auth)
	Buffer += 2;

	// inSensitive (TPM2B_SENSITIVE_CREATE) - empty auth, no data
	*(UINT16*)Buffer = SwapBytes16(4);  // size of TPMS_SENSITIVE_CREATE
	Buffer += 2;
	*(UINT16*)Buffer = 0;  // userAuth size
	Buffer += 2;
	*(UINT16*)Buffer = 0;  // data size
	Buffer += 2;

	// inPublic (TPM2B_PUBLIC) - RSA-2048 SRK template
	{
		UINT8 *PublicStart = Buffer;
		UINT8 *PublicSizePtr = Buffer;
		Buffer += 2;  // Skip size field, fill later

		// TPMT_PUBLIC
		*(UINT16*)Buffer = SwapBytes16(TPM_ALG_RSA);  // type
		Buffer += 2;
		*(UINT16*)Buffer = SwapBytes16(TPM_ALG_SHA256);  // nameAlg
		Buffer += 2;

		// objectAttributes - restricted, decrypt, fixedTPM, fixedParent, sensitiveDataOrigin, userWithAuth
		{
			UINT32 attrs = 0x00030472;  // Standard SRK attributes
			*(UINT32*)Buffer = SwapBytes32(attrs);
			Buffer += 4;
		}

		*(UINT16*)Buffer = 0;  // authPolicy size (empty)
		Buffer += 2;

		// TPMS_RSA_PARMS
		*(UINT16*)Buffer = SwapBytes16(TPM_ALG_AES);  // symmetric.algorithm
		Buffer += 2;
		*(UINT16*)Buffer = SwapBytes16(128);  // symmetric.keyBits
		Buffer += 2;
		*(UINT16*)Buffer = SwapBytes16(TPM_ALG_CFB);  // symmetric.mode
		Buffer += 2;
		*(UINT16*)Buffer = SwapBytes16(TPM_ALG_NULL);  // scheme
		Buffer += 2;
		*(UINT16*)Buffer = SwapBytes16(2048);  // keyBits
		Buffer += 2;
		*(UINT32*)Buffer = 0;  // exponent (default)
		Buffer += 4;

		// unique (TPM2B_PUBLIC_KEY_RSA) - empty for CreatePrimary
		*(UINT16*)Buffer = 0;
		Buffer += 2;

		// Fill in public size
		*(UINT16*)PublicSizePtr = SwapBytes16((UINT16)(Buffer - PublicStart - 2));
	}

	// outsideInfo (TPM2B_DATA) - empty
	*(UINT16*)Buffer = 0;
	Buffer += 2;

	// creationPCR (TPML_PCR_SELECTION) - empty
	*(UINT32*)Buffer = 0;  // count = 0
	Buffer += 4;

	SendBufferSize = (UINT32)(Buffer - SendBuffer);
	CmdHdr->paramSize = SwapBytes32(SendBufferSize);

	RecvBufferSize = sizeof(RecvBuffer);
	res = Tpm2SubmitCommand(SendBufferSize, SendBuffer, &RecvBufferSize, RecvBuffer);
	if (EFI_ERROR(res)) {
		return res;
	}

	RspHdr = (TPM2_RESPONSE_HEADER *)RecvBuffer;
	if (SwapBytes32(RspHdr->responseCode) != TPM_RC_SUCCESS) {
		return EFI_DEVICE_ERROR;
	}

	// Parse response: skip header, get objectHandle
	Buffer = RecvBuffer + sizeof(TPM2_RESPONSE_HEADER);
	*SrkHandle = SwapBytes32(*(UINT32*)Buffer);

	return EFI_SUCCESS;
}

/**
  Create a sealed data object under the SRK using TPM2_Create.

  @param[in]  SrkHandle     Handle to the SRK
  @param[in]  Data          Data to seal (KEK)
  @param[in]  DataSize      Size of data
  @param[in]  AuthPolicy    Auth policy digest (for PCR binding)
  @param[in]  PolicySize    Size of auth policy (0 or SHA256_DIGEST_SIZE)
  @param[in]  Auth          Optional auth value (PIN)
  @param[in]  AuthSize      Size of auth value
  @param[out] OutPrivate    Output private blob
  @param[out] PrivateSize   Size of private blob
  @param[out] OutPublic     Output public blob
  @param[out] PublicSize    Size of public blob

  @return EFI_SUCCESS or error
**/
STATIC
EFI_STATUS
Tpm2CreateSealed(
	IN  TPMI_DH_OBJECT  SrkHandle,
	IN  UINT8           *Data,
	IN  UINT16          DataSize,
	IN  UINT8           *AuthPolicy,
	IN  UINT16          PolicySize,
	IN  UINT8           *Auth,
	IN  UINT16          AuthSize,
	OUT UINT8           *OutPrivate,
	OUT UINT16          *PrivateSize,
	OUT UINT8           *OutPublic,
	OUT UINT16          *PublicSize
	)
{
	EFI_STATUS         res;
	UINT8              SendBuffer[512];
	UINT8              RecvBuffer[1024];
	UINT32             SendBufferSize;
	UINT32             RecvBufferSize;
	UINT8              *Buffer;
	TPM2_COMMAND_HEADER *CmdHdr;
	TPM2_RESPONSE_HEADER *RspHdr;
	UINT32             AuthAreaSize;
	UINT16             SensitiveSize;

	SetMem(SendBuffer, sizeof(SendBuffer), 0);
	Buffer = SendBuffer;
	CmdHdr = (TPM2_COMMAND_HEADER *)Buffer;

	// Header
	CmdHdr->tag = SwapBytes16(TPM_ST_SESSIONS);
	CmdHdr->commandCode = SwapBytes32(TPM_CC_Create);
	Buffer += sizeof(TPM2_COMMAND_HEADER);

	// parentHandle
	*(UINT32*)Buffer = SwapBytes32(SrkHandle);
	Buffer += 4;

	// Authorization area (password session for SRK - empty auth)
	AuthAreaSize = 4 + 2 + 1 + 2;
	*(UINT32*)Buffer = SwapBytes32(AuthAreaSize);
	Buffer += 4;
	*(UINT32*)Buffer = SwapBytes32(TPM_RS_PW);
	Buffer += 4;
	*(UINT16*)Buffer = 0;  // nonce
	Buffer += 2;
	*Buffer = 0;  // attributes
	Buffer += 1;
	*(UINT16*)Buffer = 0;  // hmac (empty SRK auth)
	Buffer += 2;

	// inSensitive (TPM2B_SENSITIVE_CREATE)
	SensitiveSize = 2 + AuthSize + 2 + DataSize;
	*(UINT16*)Buffer = SwapBytes16(SensitiveSize);
	Buffer += 2;
	*(UINT16*)Buffer = SwapBytes16(AuthSize);  // userAuth size
	Buffer += 2;
	if (AuthSize > 0) {
		CopyMem(Buffer, Auth, AuthSize);
		Buffer += AuthSize;
	}
	*(UINT16*)Buffer = SwapBytes16(DataSize);  // data size
	Buffer += 2;
	CopyMem(Buffer, Data, DataSize);
	Buffer += DataSize;

	// inPublic (TPM2B_PUBLIC) - keyedHash sealed data object
	{
		UINT8 *PublicStart = Buffer;
		UINT8 *PublicSizePtr = Buffer;
		Buffer += 2;

		*(UINT16*)Buffer = SwapBytes16(TPM_ALG_KEYEDHASH);  // type
		Buffer += 2;
		*(UINT16*)Buffer = SwapBytes16(TPM_ALG_SHA256);  // nameAlg
		Buffer += 2;

		// objectAttributes - fixedTPM, fixedParent
		{
			UINT32 attrs = 0x00000052;  // fixedTPM | fixedParent | userWithAuth
			if (PolicySize > 0) {
				attrs &= ~0x00000040;  // Clear userWithAuth if policy-based
			}
			*(UINT32*)Buffer = SwapBytes32(attrs);
			Buffer += 4;
		}

		// authPolicy
		*(UINT16*)Buffer = SwapBytes16(PolicySize);
		Buffer += 2;
		if (PolicySize > 0) {
			CopyMem(Buffer, AuthPolicy, PolicySize);
			Buffer += PolicySize;
		}

		// TPMT_KEYEDHASH_SCHEME - NULL scheme for sealed data
		*(UINT16*)Buffer = SwapBytes16(TPM_ALG_NULL);
		Buffer += 2;

		// unique (TPM2B_DIGEST) - empty for Create
		*(UINT16*)Buffer = 0;
		Buffer += 2;

		*(UINT16*)PublicSizePtr = SwapBytes16((UINT16)(Buffer - PublicStart - 2));
	}

	// outsideInfo
	*(UINT16*)Buffer = 0;
	Buffer += 2;

	// creationPCR
	*(UINT32*)Buffer = 0;
	Buffer += 4;

	SendBufferSize = (UINT32)(Buffer - SendBuffer);
	CmdHdr->paramSize = SwapBytes32(SendBufferSize);

	RecvBufferSize = sizeof(RecvBuffer);
	res = Tpm2SubmitCommand(SendBufferSize, SendBuffer, &RecvBufferSize, RecvBuffer);
	if (EFI_ERROR(res)) {
		return res;
	}

	RspHdr = (TPM2_RESPONSE_HEADER *)RecvBuffer;
	if (SwapBytes32(RspHdr->responseCode) != TPM_RC_SUCCESS) {
		OUT_PRINT(L"TPM2_Create failed: 0x%x\n", SwapBytes32(RspHdr->responseCode));
		return EFI_DEVICE_ERROR;
	}

	// Parse response: skip header + parameterSize
	Buffer = RecvBuffer + sizeof(TPM2_RESPONSE_HEADER);
	Buffer += 4;  // Skip parameterSize

	// outPrivate (TPM2B_PRIVATE)
	*PrivateSize = SwapBytes16(*(UINT16*)Buffer);
	Buffer += 2;
	CopyMem(OutPrivate, Buffer, *PrivateSize);
	Buffer += *PrivateSize;

	// outPublic (TPM2B_PUBLIC)
	*PublicSize = SwapBytes16(*(UINT16*)Buffer);
	Buffer += 2;
	CopyMem(OutPublic, Buffer, *PublicSize);

	return EFI_SUCCESS;
}

/**
  Load a sealed data object under the SRK using TPM2_Load.

  @param[in]  SrkHandle     Handle to the SRK
  @param[in]  InPrivate     Private blob
  @param[in]  PrivateSize   Size of private blob
  @param[in]  InPublic      Public blob
  @param[in]  PublicSize    Size of public blob
  @param[out] ObjectHandle  Handle to loaded object

  @return EFI_SUCCESS or error
**/
STATIC
EFI_STATUS
Tpm2LoadSealed(
	IN  TPMI_DH_OBJECT  SrkHandle,
	IN  UINT8           *InPrivate,
	IN  UINT16          PrivateSize,
	IN  UINT8           *InPublic,
	IN  UINT16          PublicSize,
	OUT TPMI_DH_OBJECT  *ObjectHandle
	)
{
	EFI_STATUS         res;
	UINT8              SendBuffer[512];
	UINT8              RecvBuffer[256];
	UINT32             SendBufferSize;
	UINT32             RecvBufferSize;
	UINT8              *Buffer;
	TPM2_COMMAND_HEADER *CmdHdr;
	TPM2_RESPONSE_HEADER *RspHdr;
	UINT32             AuthAreaSize;

	SetMem(SendBuffer, sizeof(SendBuffer), 0);
	Buffer = SendBuffer;
	CmdHdr = (TPM2_COMMAND_HEADER *)Buffer;

	CmdHdr->tag = SwapBytes16(TPM_ST_SESSIONS);
	CmdHdr->commandCode = SwapBytes32(TPM_CC_Load);
	Buffer += sizeof(TPM2_COMMAND_HEADER);

	// parentHandle
	*(UINT32*)Buffer = SwapBytes32(SrkHandle);
	Buffer += 4;

	// Authorization area
	AuthAreaSize = 4 + 2 + 1 + 2;
	*(UINT32*)Buffer = SwapBytes32(AuthAreaSize);
	Buffer += 4;
	*(UINT32*)Buffer = SwapBytes32(TPM_RS_PW);
	Buffer += 4;
	*(UINT16*)Buffer = 0;
	Buffer += 2;
	*Buffer = 0;
	Buffer += 1;
	*(UINT16*)Buffer = 0;
	Buffer += 2;

	// inPrivate (TPM2B_PRIVATE)
	*(UINT16*)Buffer = SwapBytes16(PrivateSize);
	Buffer += 2;
	CopyMem(Buffer, InPrivate, PrivateSize);
	Buffer += PrivateSize;

	// inPublic (TPM2B_PUBLIC)
	*(UINT16*)Buffer = SwapBytes16(PublicSize);
	Buffer += 2;
	CopyMem(Buffer, InPublic, PublicSize);
	Buffer += PublicSize;

	SendBufferSize = (UINT32)(Buffer - SendBuffer);
	CmdHdr->paramSize = SwapBytes32(SendBufferSize);

	RecvBufferSize = sizeof(RecvBuffer);
	res = Tpm2SubmitCommand(SendBufferSize, SendBuffer, &RecvBufferSize, RecvBuffer);
	if (EFI_ERROR(res)) {
		return res;
	}

	RspHdr = (TPM2_RESPONSE_HEADER *)RecvBuffer;
	if (SwapBytes32(RspHdr->responseCode) != TPM_RC_SUCCESS) {
		OUT_PRINT(L"TPM2_Load failed: 0x%x\n", SwapBytes32(RspHdr->responseCode));
		return EFI_DEVICE_ERROR;
	}

	// Parse response
	Buffer = RecvBuffer + sizeof(TPM2_RESPONSE_HEADER);
	*ObjectHandle = SwapBytes32(*(UINT32*)Buffer);

	return EFI_SUCCESS;
}

/**
  Unseal data from a sealed object using TPM2_Unseal.

  @param[in]  ObjectHandle    Handle to sealed object
  @param[in]  SessionHandle   Policy session handle (0 for password auth)
  @param[in]  Auth            Optional auth value
  @param[in]  AuthSize        Size of auth value
  @param[out] OutData         Unsealed data
  @param[out] DataSize        Size of unsealed data

  @return EFI_SUCCESS or error
**/
STATIC
EFI_STATUS
Tpm2Unseal(
	IN  TPMI_DH_OBJECT        ObjectHandle,
	IN  TPMI_SH_AUTH_SESSION  SessionHandle,
	IN  UINT8                 *Auth,
	IN  UINT16                AuthSize,
	OUT UINT8                 *OutData,
	OUT UINT16                *DataSize
	)
{
	EFI_STATUS         res;
	UINT8              SendBuffer[256];
	UINT8              RecvBuffer[256];
	UINT32             SendBufferSize;
	UINT32             RecvBufferSize;
	UINT8              *Buffer;
	TPM2_COMMAND_HEADER *CmdHdr;
	TPM2_RESPONSE_HEADER *RspHdr;
	UINT32             AuthAreaSize;

	SetMem(SendBuffer, sizeof(SendBuffer), 0);
	Buffer = SendBuffer;
	CmdHdr = (TPM2_COMMAND_HEADER *)Buffer;

	CmdHdr->tag = SwapBytes16(TPM_ST_SESSIONS);
	CmdHdr->commandCode = SwapBytes32(TPM_CC_Unseal);
	Buffer += sizeof(TPM2_COMMAND_HEADER);

	// itemHandle
	*(UINT32*)Buffer = SwapBytes32(ObjectHandle);
	Buffer += 4;

	// Authorization area
	AuthAreaSize = 4 + 2 + 1 + 2 + AuthSize;
	*(UINT32*)Buffer = SwapBytes32(AuthAreaSize);
	Buffer += 4;
	*(UINT32*)Buffer = SwapBytes32(SessionHandle != 0 ? SessionHandle : TPM_RS_PW);
	Buffer += 4;
	*(UINT16*)Buffer = 0;  // nonce
	Buffer += 2;
	*Buffer = (SessionHandle != 0) ? 1 : 0;  // continueSession for policy
	Buffer += 1;
	*(UINT16*)Buffer = SwapBytes16(AuthSize);
	Buffer += 2;
	if (AuthSize > 0) {
		CopyMem(Buffer, Auth, AuthSize);
		Buffer += AuthSize;
	}

	SendBufferSize = (UINT32)(Buffer - SendBuffer);
	CmdHdr->paramSize = SwapBytes32(SendBufferSize);

	RecvBufferSize = sizeof(RecvBuffer);
	res = Tpm2SubmitCommand(SendBufferSize, SendBuffer, &RecvBufferSize, RecvBuffer);
	if (EFI_ERROR(res)) {
		return res;
	}

	RspHdr = (TPM2_RESPONSE_HEADER *)RecvBuffer;
	{
		TPM_RC ResponseCode = SwapBytes32(RspHdr->responseCode);
		if (ResponseCode != TPM_RC_SUCCESS) {
			// Decode common error codes for better user feedback
			// TPM_RC values: AUTH_FAIL=0x08E, LOCKOUT=0x921, POLICY_FAIL=0x099
			UINT32 RcBase = ResponseCode & 0xFF;  // Base error code
			//BOOLEAN IsLocked = FALSE;
			//UINT32 LockoutCount = 0;
			
			//OUT_PRINT(L"TPM2_Unseal failed: 0x%x\n", ResponseCode);
			
			// Check lockout status
			//if (!EFI_ERROR(Tpm2CheckLockout(&IsLocked, &LockoutCount)) && LockoutCount > 0) {
			//	OUT_PRINT(L"TPM lockout counter: %d failed attempts\n", LockoutCount);
			//}
			
			if (ResponseCode == TPM_RC_LOCKOUT) {
				//OUT_PRINT(L"TPM is locked out - too many failed PIN attempts\n");
				//OUT_PRINT(L"Reboot or wait for lockout recovery period\n");
				return EFI_ACCESS_DENIED;
			} else if (RcBase == TPM_RC_AUTH_FAIL) {
				//OUT_PRINT(L"Authorization failed - wrong PIN\n");
				return EFI_ACCESS_DENIED;
			} else if (RcBase == TPM_RC_BAD_AUTH) { // this always happens on my 2 ARM64 laptops on first atempt, then it works on second attempt
				//OUT_PRINT(L"Authorization failed - wrong PIN\n");
			} else if (RcBase == TPM_RC_POLICY_FAIL || RcBase == TPM_RC_PCR_CHANGED) {
				//OUT_PRINT(L"Policy failed - PCR values don't match\n");
				return EFI_ACCESS_DENIED;
			}

			return EFI_DEVICE_ERROR;
		}
	}

	// Parse response: skip header + parameterSize
	Buffer = RecvBuffer + sizeof(TPM2_RESPONSE_HEADER);
	Buffer += 4;  // parameterSize

	// outData (TPM2B_SENSITIVE_DATA)
	*DataSize = SwapBytes16(*(UINT16*)Buffer);
	Buffer += 2;
	CopyMem(OutData, Buffer, *DataSize);

	return EFI_SUCCESS;
}

/**
  Seal a Key Encryption Key (KEK) using SRK with optional PCR policy.
  Returns the sealed blob that can be stored and later unsealed.

  @param[in]  Kek             KEK to seal (32 bytes for AES-256)
  @param[in]  KekSize         Size of KEK
  @param[in]  PcrMask         PCR mask for policy (0 = PIN-only)
  @param[in]  PinAuth         PIN auth data (NULL if no PIN)
  @param[in]  PinAuthSize     Size of PIN auth data
  @param[out] SealedBlob      Output buffer for sealed blob
  @param[in,out] SealedBlobSize  In: buffer size, Out: actual size

  @return EFI_SUCCESS or error
**/
STATIC
EFI_STATUS
Tpm2SrkSealKek(
	IN  UINT8              *Kek,
	IN  UINT32             KekSize,
	IN  UINT32             PcrMask,
	IN  UINT8              *PinAuth OPTIONAL,
	IN  UINT16             PinAuthSize,
	OUT UINT8              *SealedBlob,
	IN OUT UINT32          *SealedBlobSize
	)
{
	EFI_STATUS          res = EFI_SUCCESS;
	UINT8               privateBlob[256];
	UINT8               publicBlob[256];
	UINT16              privateSize = 0;
	UINT16              publicSize = 0;
	UINT8               authPolicy[SHA256_DIGEST_SIZE];
	UINT16              policySize = 0;
	TPMI_DH_OBJECT      SrkHandle = 0;
	DC_TPM2_SEALED_BLOB *BlobHeader;
	UINT32              totalSize;
	BOOLEAN             usePin = (PinAuth != NULL && PinAuthSize > 0);

	if (Kek == NULL || KekSize == 0 || SealedBlob == NULL || SealedBlobSize == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	CE(InitTpm20());

	// Compute auth policy
	SetMem(authPolicy, sizeof(authPolicy), 0);
	if (PcrMask == 0) {
		// PIN-only (no PCR policy)
		if (!usePin) {
			return EFI_INVALID_PARAMETER;  // Need at least PCR or PIN
		}
		policySize = 0;  // No policy, use userWithAuth
	} else if (usePin) {
		// PCR + PIN
		CE(Tpm2MakePolicyPcrPassword(PcrMask, authPolicy));
		policySize = SHA256_DIGEST_SIZE;
	} else {
		// PCR only
		CE(Tpm2MakePolicyPcr(PcrMask, authPolicy));
		policySize = SHA256_DIGEST_SIZE;
	}

	// Create SRK
	CE(Tpm2CreateSrk(&SrkHandle));

	// Create sealed object with KEK
	res = Tpm2CreateSealed(
		SrkHandle,
		Kek, (UINT16)KekSize,
		authPolicy, policySize,
		usePin ? PinAuth : NULL,
		usePin ? PinAuthSize : 0,
		privateBlob, &privateSize,
		publicBlob, &publicSize
	);

	// Flush SRK handle
	Tpm2FlushContext(SrkHandle);
	SrkHandle = 0;

	if (EFI_ERROR(res)) {
		goto err;
	}

	// Calculate total size and check buffer
	totalSize = sizeof(DC_TPM2_SEALED_BLOB) - 1 + privateSize + publicSize;
	if (*SealedBlobSize < totalSize) {
		*SealedBlobSize = totalSize;
		res = EFI_BUFFER_TOO_SMALL;
		goto err;
	}

	// Build sealed blob structure
	BlobHeader = (DC_TPM2_SEALED_BLOB*)SealedBlob;
	BlobHeader->PrivateSize = privateSize;
	BlobHeader->PublicSize = publicSize;
	CopyMem(BlobHeader->Data, privateBlob, privateSize);
	CopyMem(BlobHeader->Data + privateSize, publicBlob, publicSize);

	*SealedBlobSize = totalSize;

err:
	SetMem(privateBlob, sizeof(privateBlob), 0);
	SetMem(publicBlob, sizeof(publicBlob), 0);
	return res;
}

/**
  Unseal a Key Encryption Key (KEK) from a sealed blob.
  Requires PCR values to match the policy used during sealing.

  @param[in]  SealedBlob      Sealed blob from Tpm2SrkSealKek
  @param[in]  SealedBlobSize  Size of sealed blob
  @param[in]  PcrMask         PCR mask used during sealing
  @param[in]  PinAuth         PIN auth data (NULL if no PIN)
  @param[out] Kek             Output buffer for KEK
  @param[in,out] KekSize      In: buffer size, Out: actual size

  @return EFI_SUCCESS or error
**/
STATIC
EFI_STATUS
Tpm2SrkUnsealKek(
	IN  UINT8              *SealedBlob,
	IN  UINT32             SealedBlobSize,
	IN  UINT32             PcrMask,
	IN  UINT8              *PinAuth OPTIONAL,
	IN  UINT16             PinAuthSize,
	OUT UINT8              *Kek,
	IN OUT UINT32          *KekSize
	)
{
	EFI_STATUS           res = EFI_SUCCESS;
	DC_TPM2_SEALED_BLOB  *BlobHeader;
	UINT8                *PrivateBlob;
	UINT8                *PublicBlob;
	TPMI_DH_OBJECT       SrkHandle = 0;
	TPMI_DH_OBJECT       SealedHandle = 0;
	TPMI_SH_AUTH_SESSION SessionHandle = 0;
	UINT16               OutSize;
	BOOLEAN              usePin = (PinAuth != NULL && PinAuthSize > 0);

	if (SealedBlob == NULL || Kek == NULL || KekSize == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	CE(InitTpm20());

	// Parse sealed blob
	BlobHeader = (DC_TPM2_SEALED_BLOB*)SealedBlob;
	if (SealedBlobSize < sizeof(DC_TPM2_SEALED_BLOB) - 1 + BlobHeader->PrivateSize + BlobHeader->PublicSize) {
		return EFI_COMPROMISED_DATA;
	}
	PrivateBlob = BlobHeader->Data;
	PublicBlob = BlobHeader->Data + BlobHeader->PrivateSize;

	// Create SRK
	CE(Tpm2CreateSrk(&SrkHandle));

	// Load sealed object
	CE(Tpm2LoadSealed(
		SrkHandle,
		PrivateBlob, BlobHeader->PrivateSize,
		PublicBlob, BlobHeader->PublicSize,
		&SealedHandle
	));

	// Setup policy session if needed
	if (PcrMask != 0) {
		// PCR-based policy
		TPMI_DH_OBJECT    TpmKey = TPM_RH_NULL;
		TPMI_DH_ENTITY    Bind = TPM_RH_NULL;
		TPM2B_NONCE       NonceCaller;
		TPM2B_ENCRYPTED_SECRET Salt;
		TPM_SE            SessionType = TPM_SE_POLICY;
		TPMT_SYM_DEF      Symmetric;
		TPMI_ALG_HASH     AuthHash = TPM_ALG_SHA256;
		TPM2B_NONCE       NonceTPM;

		SetMem(&NonceCaller, sizeof(NonceCaller), 0);
		NonceCaller.size = 0x20;
		Salt.size = 0;
		Symmetric.algorithm = TPM_ALG_XOR;
		Symmetric.keyBits.xor_ = TPM_ALG_SHA256;

		res = Tpm2StartAuthSession(TpmKey, Bind, &NonceCaller, &Salt,
		                           SessionType, &Symmetric, AuthHash,
		                           &SessionHandle, &NonceTPM);
		if (EFI_ERROR(res)) {
			goto err;
		}

		// Execute PolicyPCR
		{
			TPM2_POLICYPCR_COMMAND  SendBuffer;
			TPM2_POLICYPCR_RESPONSE RecvBuffer;
			UINT32 SendBufferSize = sizeof(SendBuffer);
			UINT32 RecvBufferSize = sizeof(RecvBuffer);

			SetMem(&SendBuffer, sizeof(SendBuffer), 0);
			SendBuffer.Header.tag = SwapBytes16(TPM_ST_NO_SESSIONS);
			SendBuffer.Header.commandCode = SwapBytes32(TPM_CC_PolicyPCR);
			SendBuffer.Header.paramSize = SwapBytes32(SendBufferSize);
			SendBuffer.Handle = SwapBytes32(SessionHandle);
			SendBuffer.auth = 0;
			SendBuffer.hashType = SwapBytes16(TPM_ALG_SHA256);
			SendBuffer.count = SwapBytes32(1);
			SendBuffer.pcrCount = 3;
			SendBuffer.pcrSelection[0] = (PcrMask) & 0xFF;
			SendBuffer.pcrSelection[1] = ((PcrMask) >> 8) & 0xFF;
			SendBuffer.pcrSelection[2] = ((PcrMask) >> 16) & 0xFF;

			res = Tpm2SubmitCommand(SendBufferSize, (UINT8*)&SendBuffer,
			                        &RecvBufferSize, (UINT8*)&RecvBuffer);
			if (EFI_ERROR(res)) {
				goto err;
			}
		}

		// Execute PolicyPassword if PIN required
		// Note: PolicyPassword (not PolicyAuthValue) because we send auth in plaintext
		// Both update policy digest the same way (using TPM_CC_PolicyAuthValue per spec)
		if (usePin) {
			res = Tpm2PolicyPassword(SessionHandle);
			if (EFI_ERROR(res)) {
				goto err;
			}
		}
	}

	// Unseal the KEK
	OutSize = (UINT16)*KekSize;
	res = Tpm2Unseal(
		SealedHandle,
		SessionHandle,  // 0 for PIN-only (password auth), policy session otherwise
		usePin ? PinAuth : NULL,
		usePin ? PinAuthSize : 0,
		Kek, &OutSize
	);
	*KekSize = OutSize;

err:
	if (SessionHandle != 0) {
		Tpm2FlushContext(SessionHandle);
	}
	if (SealedHandle != 0) {
		Tpm2FlushContext(SealedHandle);
	}
	if (SrkHandle != 0) {
		Tpm2FlushContext(SrkHandle);
	}
	return res;
}

// Check if buffer contains valid sealed data that can be unsealed
BOOLEAN
Tpm2SrkIsOpenBuf(
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

	if (EFI_ERROR(InitTpm20())) {
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

	// Try to unseal the KEK to verify PCRs match
	res = Tpm2SrkUnsealKek(DataBlob, Header->SealedBlobSize, Header->PcrMask,
	                          NULL, 0, testData, &testSize);
	SetMem(testData, sizeof(testData), 0);

	return !EFI_ERROR(res);
}

// Seal password to buffer using SRK with envelope encryption
EFI_STATUS
Tpm2SrkSealPasswordBuf(
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
	UINT8                  sealedBlob[DC_TPM2_MAX_SEALED_BLOB_SIZE];
	UINT32                 sealedBlobSize = sizeof(sealedBlob);
	UINT8                  PinAuthData[128];
	UINT16                 PinAuthSize = 0;
	BOOLEAN                usePin = FALSE;
	UINT32                 requiredSize;
	UINT8                  *writePtr;

	if (password == NULL || passwordSize == 0 || buffer == NULL || bufferSize == NULL) {
		return EFI_INVALID_PARAMETER;
	}
	if (passwordSize > DC_TPM_SEALED_MAX_SIZE - DC_TPM_SEALED_BASE_SIZE) {
		return EFI_BAD_BUFFER_SIZE;
	}
	if (infoSize > DC_TPM_INFO_MAX_SIZE) {
		return EFI_BAD_BUFFER_SIZE;
	}

	CE(InitTpm20());

	// Prepare PIN auth if provided
	if (tpmPin != NULL && tpmPin[0] != L'\0') {
		CE(TpmPrepareAuth(tpmPin, PinAuthData, &PinAuthSize));
		usePin = TRUE;
	}

	// Generate random KEK and IV
	CE(Tpm2GetRandom(sizeof(kek), kek));
	CE(Tpm2GetRandom(sizeof(iv), iv));

	// Seal KEK with SRK
	CE(Tpm2SrkSealKek(kek, sizeof(kek), pcrMask,
	                     usePin ? PinAuthData : NULL, usePin ? PinAuthSize : 0,
	                     sealedBlob, &sealedBlobSize));

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
	requiredSize = sizeof(DC_TPM_SRK_FILE_HEADER) + sealedBlobSize + encryptedSize + infoSize;
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
	Header->SealedBlobSize = (UINT16)sealedBlobSize;
	Header->EncryptedSize = (UINT16)encryptedSize;
	Header->InfoSize = (UINT16)infoSize;
	CopyMem(Header->Iv, iv, sizeof(iv));

	// Write data to buffer
	writePtr = buffer + sizeof(DC_TPM_SRK_FILE_HEADER);
	CopyMem(writePtr, sealedBlob, sealedBlobSize);
	writePtr += sealedBlobSize;
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
	SetMem(sealedBlob, sizeof(sealedBlob), 0);
	SetMem(PinAuthData, sizeof(PinAuthData), 0);
	return res;
}

// Unseal password from buffer
EFI_STATUS
Tpm2SrkUnsealPasswordBuf(
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
	UINT8                  PinAuthData[128];
	UINT16                 PinAuthSize = 0;
	UINT32                 crc;

	if (buffer == NULL || password == NULL || passwordSize == NULL || passwordType == NULL) {
		return EFI_INVALID_PARAMETER;
	}
	if (bufferSize < sizeof(DC_TPM_SRK_FILE_HEADER)) {
		return EFI_INVALID_PARAMETER;
	}

	CE(InitTpm20());

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

	// Prepare PIN auth if provided
	if (tpmPin != NULL && tpmPin[0] != L'\0') {
		CE(TpmPrepareAuth(tpmPin, PinAuthData, &PinAuthSize));
	}

	// Get pointer to sealed blob
	DataBlob = buffer + sizeof(DC_TPM_SRK_FILE_HEADER);

	// Unseal KEK
	res = Tpm2SrkUnsealKek(DataBlob, Header->SealedBlobSize, Header->PcrMask,
	                          (PinAuthSize > 0) ? PinAuthData : NULL, PinAuthSize, kek, &kekSize);
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
	SetMem(PinAuthData, sizeof(PinAuthData), 0);
	return res;
}

// Get PCR mask, flags, and info data from buffer
EFI_STATUS
Tpm2SrkGetInfoBuf(
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

	// Return PcrMask if requested
	if (PcrMask != NULL) {
		*PcrMask = Header->PcrMask;
	}

	// Return Flags if requested
	if (Flags != NULL) {
		*Flags = 0;
		if (Header->Flags & DC_TPM_FLAG_PIN_REQUIRED) {
			*Flags |= DC_TPM_FLAG_PIN_REQUIRED;
		}
	}

	// Return Info data if requested
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

/**
  Request TPM clear via Physical Presence mechanism.
  This sets the PP variable which firmware processes on next boot.
  Similar to how Windows Clear-Tpm works.
**/
STATIC
EFI_STATUS
Tpm2RequestClearPP(VOID)
{
	EFI_STATUS                    Status;
	EFI_TCG2_PHYSICAL_PRESENCE    PpData;
	UINTN                         DataSize;

	// Read current PP data
	DataSize = sizeof(PpData);
	Status = gRT->GetVariable(
		TCG2_PHYSICAL_PRESENCE_VARIABLE,
		&gEfiTcg2PhysicalPresenceGuid,
		NULL,
		&DataSize,
		&PpData
		);

	if (EFI_ERROR(Status)) {
		// Variable doesn't exist, initialize it
		SetMem(&PpData, sizeof(PpData), 0);
	}

	// Set clear request
	PpData.PPRequest = TCG2_PHYSICAL_PRESENCE_CLEAR;
	PpData.PPRequestParameter = 0;

	// Write PP request variable
	Status = gRT->SetVariable(
		TCG2_PHYSICAL_PRESENCE_VARIABLE,
		&gEfiTcg2PhysicalPresenceGuid,
		EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
		sizeof(PpData),
		&PpData
		);

	return Status;
}

/**
  Clear TPM 2.0.
  First tries direct clear with platform auth, then lockout auth,
  then falls back to Physical Presence request (processed on next boot).

  @param[in]  LockoutAuth   Optional lockout auth password (can be NULL)
  @param[out] NeedsReboot   TRUE if clear will happen on next reboot

  @return EFI_SUCCESS if clear succeeded or PP request was set
**/
EFI_STATUS
Tpm2ClearTpm(
	IN  CHAR16    *LockoutAuth OPTIONAL,
	OUT BOOLEAN   *NeedsReboot
	)
{
	EFI_STATUS            Status;
	TPMS_AUTH_COMMAND     AuthSession;
	UINT8                 AuthData[64];
	UINT16                AuthSize;

	if (NeedsReboot != NULL) {
		*NeedsReboot = FALSE;
	}

	Status = InitTpm20();
	if (EFI_ERROR(Status)) {
		return Status;
	}

	// Prepare empty auth session (reused for multiple attempts)
	SetMem(&AuthSession, sizeof(AuthSession), 0);
	AuthSession.sessionHandle = TPM_RS_PW;
	AuthSession.nonce.size = 0;
	AuthSession.hmac.size = 0;

	// Try 1: Clear with platform auth (empty) - works if platform hierarchy is open
	Status = Tpm2Clear(TPM_RH_PLATFORM, &AuthSession);
	if (!EFI_ERROR(Status)) {
		return EFI_SUCCESS;
	}

	// Try 2: Clear with lockout auth (empty) - this is how Windows typically clears
	// Windows provisioning often leaves lockout auth empty
	Status = Tpm2Clear(TPM_RH_LOCKOUT, &AuthSession);
	if (!EFI_ERROR(Status)) {
		return EFI_SUCCESS;
	}

	// Try 3: Clear with provided lockout auth if given
	if (LockoutAuth != NULL && LockoutAuth[0] != L'\0') {
		Status = TpmPrepareAuth(LockoutAuth, AuthData, &AuthSize);
		if (!EFI_ERROR(Status)) {
			SetMem(&AuthSession, sizeof(AuthSession), 0);
			AuthSession.sessionHandle = TPM_RS_PW;
			AuthSession.nonce.size = 0;
			AuthSession.hmac.size = AuthSize;
			CopyMem(AuthSession.hmac.buffer, AuthData, AuthSize);

			Status = Tpm2Clear(TPM_RH_LOCKOUT, &AuthSession);
			SetMem(AuthData, sizeof(AuthData), 0);
			SetMem(&AuthSession, sizeof(AuthSession), 0);

			if (!EFI_ERROR(Status)) {
				return EFI_SUCCESS;
			}
		}
	}

	// Try 4: Request clear via Physical Presence (fallback)
	Status = Tpm2RequestClearPP();
	if (!EFI_ERROR(Status) && NeedsReboot != NULL) {
		*NeedsReboot = TRUE;
	}

	return Status;
}

//////////////////////////////////////////////////////////////////////////
// TPM 2.0 Info Functions
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
Tpm2GetManufacturer(
	OUT UINT32    *ManufacturerId,
	OUT CHAR8     *ManufacturerStr  // At least 5 bytes
	)
{
	EFI_STATUS res;

	if (ManufacturerId == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	CE(InitTpm20());
	CE(Tpm2GetCapabilityManufactureID(ManufacturerId));

	// Convert manufacturer ID to string (4 ASCII chars)
	// TPM returns big-endian, EDK2 swaps to host order (little-endian on x86)
	// Swap back to big-endian to extract ASCII string in correct order
	if (ManufacturerStr != NULL) {
		UINT32 id = SwapBytes32(*ManufacturerId);
		ManufacturerStr[0] = (CHAR8)((id >> 24) & 0xFF);
		ManufacturerStr[1] = (CHAR8)((id >> 16) & 0xFF);
		ManufacturerStr[2] = (CHAR8)((id >> 8) & 0xFF);
		ManufacturerStr[3] = (CHAR8)(id & 0xFF);
		ManufacturerStr[4] = '\0';
	}

err:
	return res;
}

EFI_STATUS
Tpm2GetFirmwareVersion(
	OUT UINT32    *FirmwareVersion1,
	OUT UINT32    *FirmwareVersion2
	)
{
	EFI_STATUS res;

	if (FirmwareVersion1 == NULL || FirmwareVersion2 == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	CE(InitTpm20());
	CE(Tpm2GetCapabilityFirmwareVersion(FirmwareVersion1, FirmwareVersion2));

err:
	return res;
}

EFI_STATUS
Tpm2GetLockoutInfo(
	OUT UINT32    *LockoutCounter,
	OUT UINT32    *LockoutInterval,
	OUT UINT32    *LockoutRecovery
	)
{
	EFI_STATUS res;

	CE(InitTpm20());

	if (LockoutCounter != NULL) {
		res = Tpm2GetCapabilityLockoutCounter(LockoutCounter);
		if (EFI_ERROR(res)) *LockoutCounter = 0;
	}
	if (LockoutInterval != NULL) {
		res = Tpm2GetCapabilityLockoutInterval(LockoutInterval);
		if (EFI_ERROR(res)) *LockoutInterval = 0;
	}
	if (LockoutRecovery != NULL) {
		// LockoutRecovery is retrieved similarly
		*LockoutRecovery = 0;  // Default
	}

	res = EFI_SUCCESS;
err:
	return res;
}

EFI_STATUS
Tpm2EnumerateNvIndices(
	OUT UINT32    *IndexList,    // Array to receive indices
	IN OUT UINT32 *IndexCount    // In: max entries, Out: actual count
	)
{
	EFI_STATUS            res;
	TPMI_YES_NO           MoreData;
	TPMS_CAPABILITY_DATA  CapData;
	UINT32                i;
	UINT32                MaxCount;
	UINT32                TotalCount = 0;
	UINT32                NextHandle;
	UINT32                ReturnedCount;

	if (IndexList == NULL || IndexCount == NULL || *IndexCount == 0) {
		return EFI_INVALID_PARAMETER;
	}

	MaxCount = *IndexCount;
	*IndexCount = 0;
	NextHandle = TPM_HT_NV_INDEX << 24;  // Start at first NV handle

	CE(InitTpm20());

	// Get NV handles (may need multiple calls if MoreData is set)
	do {
		SetMem(&CapData, sizeof(CapData), 0);

		res = Tpm2GetCapability(
			TPM_CAP_HANDLES,
			NextHandle,
			MaxCount - TotalCount,  // Request remaining capacity
			&MoreData,
			&CapData
			);

		if (EFI_ERROR(res)) {
			goto err;
		}

		// Get count of returned handles
		ReturnedCount = CapData.data.handles.count;

		// If count looks like big-endian (very large), it may need swapping
		if (ReturnedCount > MAX_CAP_HANDLES) {
			ReturnedCount = SwapBytes32(ReturnedCount);
			if (ReturnedCount > MAX_CAP_HANDLES) {
				ReturnedCount = 0;  // Still invalid, stop
			}
		}

		// Copy handles to output
		for (i = 0; i < ReturnedCount && TotalCount < MaxCount; i++) {
			UINT32 rawHandle = CapData.data.handles.handle[i];
			UINT32 handle;

			// Skip zero handles
			if (rawHandle == 0) {
				continue;
			}

			// Try to determine byte order and get correct handle value
			// If high byte is 0x01, it's already in correct order
			// If low byte is 0x01, it needs swapping
			if ((rawHandle & 0xFF000000) == (TPM_HT_NV_INDEX << 24)) {
				// Already correct byte order
				handle = rawHandle;
			} else if ((rawHandle & 0x000000FF) == TPM_HT_NV_INDEX) {
				// Big-endian, need to swap
				handle = SwapBytes32(rawHandle);
			} else {
				// Not a valid NV handle in either byte order
				continue;
			}

			IndexList[TotalCount] = handle;
			TotalCount++;

			// Set next handle for continuation query
			NextHandle = handle + 1;
		}

		// If no handles returned, we're done
		if (ReturnedCount == 0) {
			break;
		}

	} while (MoreData && TotalCount < MaxCount);

	*IndexCount = TotalCount;

err:
	return res;
}

EFI_STATUS
Tpm2GetNvIndexInfo(
	IN  UINT32    NvIndex,
	OUT UINT32    *Attributes,
	OUT UINT32    *DataSize,
	OUT UINT32    *PcrRead OPTIONAL,
	OUT UINT32    *PcrWrite OPTIONAL
	)
{
	EFI_STATUS       res;
	TPM2B_NV_PUBLIC  NvPublic;
	TPM2B_NAME       NvName;

	// Unused for TPM 2.0 - PCR info is not returned in NvReadPublic
	(VOID)PcrRead;
	(VOID)PcrWrite;

	if (DataSize == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	CE(InitTpm20());

	SetMem(&NvPublic, sizeof(NvPublic), 0);
	SetMem(&NvName, sizeof(NvName), 0);

	res = Tpm2NvReadPublic(NvIndex, &NvPublic, &NvName);
	if (EFI_ERROR(res)) {
		goto err;
	}

	*DataSize = NvPublic.nvPublic.dataSize;
	if (Attributes != NULL) {
		*Attributes = *(UINT32*)&NvPublic.nvPublic.attributes;
	}

err:
	return res;
}

/**
  Shutdown TPM 2.0 with TPM_SU_CLEAR.

  Prepares TPM for system power off, discarding volatile state.
  Should be called before system shutdown/reboot.

  @retval EFI_SUCCESS     TPM shutdown successful.
  @retval EFI_NOT_READY   TPM not initialized.
  @retval Others          TPM command failed.

**/
EFI_STATUS
Tpm2LibShutdown()
{
	EFI_STATUS  res;
	UINT32      SendBufferSize;
	UINT32      RecvBufferSize;

	#pragma pack(push, 1)
	typedef struct {
		TPM2_COMMAND_HEADER  Header;
		TPM_SU               ShutdownType;
	} TPM2_SHUTDOWN_COMMAND;

	typedef struct {
		TPM2_RESPONSE_HEADER Header;
	} TPM2_SHUTDOWN_RESPONSE;
	#pragma pack(pop)

	TPM2_SHUTDOWN_COMMAND   SendBuffer;
	TPM2_SHUTDOWN_RESPONSE  RecvBuffer;

	CE(InitTpm20());

	// Build shutdown command with TPM_SU_CLEAR
	SendBufferSize = sizeof(SendBuffer);
	RecvBufferSize = sizeof(RecvBuffer);

	SendBuffer.Header.tag = SwapBytes16(TPM_ST_NO_SESSIONS);
	SendBuffer.Header.commandCode = SwapBytes32(TPM_CC_Shutdown);
	SendBuffer.Header.paramSize = SwapBytes32(SendBufferSize);
	SendBuffer.ShutdownType = SwapBytes16(TPM_SU_CLEAR);

	res = Tpm2SubmitCommand(SendBufferSize, (UINT8 *)&SendBuffer, &RecvBufferSize, (UINT8 *)&RecvBuffer);
	if (EFI_ERROR(res)) {
		return res;
	}

	if (RecvBufferSize < sizeof(TPM2_RESPONSE_HEADER)) {
		return EFI_DEVICE_ERROR;
	}

	if (SwapBytes32(RecvBuffer.Header.responseCode) != TPM_RC_SUCCESS) {
		return EFI_DEVICE_ERROR;
	}

	return EFI_SUCCESS;

err:
	return res;
}

VOID
InitTpmLib20(
	IN OUT TPM_LIB_PROTOCOL* Tpm)
{
	Tpm->TpmVersion = 0x200;
	Tpm->Measure = Tpm2LibMeasure;
	Tpm->GetRandom = Tpm2LibGetRandom;
	// password sealing (NV-based)
	Tpm->NvIsConfigured = Tpm2IsConfigured;
	Tpm->NvIsOpen = Tpm2IsOpen;
	Tpm->NvSealPassword = Tpm2SealPassword;
	Tpm->NvUnsealPassword = Tpm2UnsealPassword;
	Tpm->NvClearSecret = Tpm2ClearSecret;
	Tpm->NvGetInfo = Tpm2GetInfo;
	// Buffer-based SRK functions (always available)
	Tpm->SrkIsOpen = Tpm2SrkIsOpenBuf;
	Tpm->SrkGetInfo = Tpm2SrkGetInfoBuf;
	Tpm->SrkSealPassword = Tpm2SrkSealPasswordBuf;
	Tpm->SrkUnsealPassword = Tpm2SrkUnsealPasswordBuf;
	// TPM management
	Tpm->ClearTpm = Tpm2ClearTpm;
	Tpm->TakeOwnership = Tpm2TakeOwnership;
	Tpm->ChangeOwnerPwd = Tpm2ChangeOwnerPassword;
	// PCR read
	Tpm->ReadPcr = Tpm2ReadPcr;
	// TPM 2.0 info
	Tpm->GetManufacturer = Tpm2GetManufacturer;
	Tpm->GetFirmwareVersion = Tpm2GetFirmwareVersion;
	Tpm->GetLockoutInfo = Tpm2GetLockoutInfo;
	// NV enumeration
	Tpm->EnumNvIndices = Tpm2EnumerateNvIndices;
	Tpm->GetNvIndexInfo = Tpm2GetNvIndexInfo;
	// Shutdown
	Tpm->Shutdown = Tpm2LibShutdown;
}