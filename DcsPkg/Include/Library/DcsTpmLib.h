/** @file
Dcs TPM library

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 

This program and the accompanying materials are licensed and made available 
under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#ifndef __DCSTPMLIB_H__
#define __DCSTPMLIB_H__

#include <Uefi.h>

#define DCS_TPM_NV_INDEX  0x0DC5B
#define DCS_TPM_NV_SIZE   128
#define DCS_TPM_PCR_LOCK  8
#define TPM_OWNER_PWD_MAX 64

typedef struct _DCS_TPM_PROTOCOL DCS_TPM_PROTOCOL;
extern DCS_TPM_PROTOCOL* gTpm;

EFI_STATUS
GetTpm();

UINT32
AskPcrsMask(
	IN UINT32 def
	);

VOID
AskTpmOwnerPwd(
	OUT CHAR16*  ownerPass
	);

EFI_STATUS
Sha1Hash(
	IN  VOID    *data,
	IN  UINTN   dataSize,
	OUT UINT8   *hash
	);

EFI_STATUS
Sha256Hash(
	IN  VOID    *data,
	IN  UINTN   dataSize,
	OUT UINT8   *hash
	);

//////////////////////////////////////////////////////////////////////////
// TPM 1.2
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
InitTpm12();

EFI_STATUS
Tpm12PcrRead(
	IN UINT32   PcrIndex,
	OUT void    *PcrValue
	);

EFI_STATUS
Tpm12DumpPcrs(
	IN UINT32 sPcr,
	IN UINT32 ePcr);

EFI_STATUS
Tpm12GetNvList(
	OUT UINT32    *respSize,
	OUT UINT32    *resp
	);

EFI_STATUS
Tpm12NvDetails(
	IN  UINT32    index,
	OUT UINT32    *attr,
	OUT UINT32    *dataSz,
	OUT UINT32    *pcrR,
	OUT UINT32    *pcrW
	);

VOID
DcsInitTpm12(
	IN OUT DCS_TPM_PROTOCOL* Tpm);

//////////////////////////////////////////////////////////////////////////
// TPM 2.0
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
InitTpm20();

EFI_STATUS
DcsTpm2DumpPcrs(
	IN UINT32 sPcr,
	IN UINT32 ePcr);

EFI_STATUS
Tpm20Tests();

VOID
DcsInitTpm20(
	IN OUT DCS_TPM_PROTOCOL* Tpm);

//////////////////////////////////////////////////////////////////////////
// DCS TPM protocol
//////////////////////////////////////////////////////////////////////////

typedef EFI_STATUS(*DCS_TPM_LOCK)(
	IN  DCS_TPM_PROTOCOL   *tpm
	);

typedef EFI_STATUS(*DCS_TPM_APPLY)(
	IN  DCS_TPM_PROTOCOL   *tpm,
	OUT VOID*              pwd
	);

typedef EFI_STATUS(*DCS_TPM_CONFIGURE)(
	IN  DCS_TPM_PROTOCOL  *tpm
	);

typedef BOOLEAN(*DCS_TPM_IS_OPEN)(
	IN  DCS_TPM_PROTOCOL   *tpm
	);

typedef BOOLEAN(*DCS_TPM_IS_CONFIGURED)(
	IN  DCS_TPM_PROTOCOL  *tpm
	);

typedef EFI_STATUS(*DCS_TPM_GETRANDOM)(
	IN  DCS_TPM_PROTOCOL   *tpm,
	IN  UINT32              size,
	OUT VOID*              rnd
	);

typedef EFI_STATUS(*DCS_TPM_MEASURE)(
	IN  DCS_TPM_PROTOCOL   *tpm,
	IN  UINTN              index,
	IN  UINTN              size,
	OUT VOID*              data
	);

/*
Lock         - Try lock TPM secret
Apply        - Apply secret to password
Configure    - Create TPM secret and configure PCRs
IsConfigured - TPM secret is set?
IsOpen       - Can apply secret?
*/
typedef struct _DCS_TPM_PROTOCOL {
	UINTN                  TpmVersion;
	DCS_TPM_LOCK           Lock;
	DCS_TPM_APPLY          Apply;
	DCS_TPM_CONFIGURE      Configure;
	DCS_TPM_IS_OPEN        IsOpen;
	DCS_TPM_IS_CONFIGURED  IsConfigured;
	DCS_TPM_GETRANDOM      GetRandom;
	DCS_TPM_MEASURE        Measure;
} DCS_TPM_PROTOCOL;



#endif