/** @file
DCS Owner - protected Secure Boot / PK virtualization driver

Presents overridden SecureBoot / SetupMode / variable values to the OS at runtime,
driven by runtime-inaccessible EFI variables that can only be changed through an
RT-mirror + boot-time physical-presence confirmation flow, and measures the
committed presets into PCR 7.

Copyright (c) 2026. DiskCryptor, David Xanatos

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#ifndef __EFI_DCSOWNER_H__
#define __EFI_DCSOWNER_H__

#include <Uefi.h>

#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>
#include <Library/UefiLib.h>
#include <Library/PrintLib.h>

//
// Config variable GUID (defined in DcsPkg.dec, provided via AutoGen)
//
extern EFI_GUID gEfiDcsOwnerGuid;

//
// MySecureBoot control variable - special: drives SecureBoot + SetupMode reporting.
// Kept as a named macro because its logic is not a simple 1:1 proxy.
//
#define DCSOWNER_VAR_SB          L"SecureBootOverride_BS"
#define DCSOWNER_VAR_SB_RT       L"SecureBootOverride_RT"

//
// MySecureBoot value bits: bit0 = override active, bit1 = reported value.
//
#define DCSOWNER_SB_DISABLED     0x00    // disabled
#define DCSOWNER_SB_REPORT_OFF   0x01    // override active, report SecureBoot = 0
#define DCSOWNER_SB_REPORT_ON    0x03    // override active, report SecureBoot = 1
#define DCSOWNER_SB_ACTIVE(v)    (((v) & 0x01) != 0 ? 1 : 0)
#define DCSOWNER_SB_VALUE(v)     (((v) & 0x02) != 0 ? 1 : 0)

//
// Generic variable override entry.
//   Name   - real UEFI variable name to intercept (e.g. L"PK")
//   NameRT - RT-accessible mirror for OS proposals (e.g. L"MyPKRT")
//   NameBS - BS-only private store for committed value (e.g. L"MyPK")
//   Guid   - GUID of the real variable being overridden
//   Attr   - attributes to report for the overridden variable
//
typedef VOID (*DCSOWNER_VAR_DESCRIBE)(IN VOID *Data, IN UINTN Size, OUT CHAR16 *Buf, IN UINTN BufChars);

typedef struct _DCSOWNER_VAR_MAP {
    CONST CHAR16          *Name;
    CONST CHAR16          *NameRT;
    CONST CHAR16          *NameBS;
    EFI_GUID              *Guid;
    UINT32                Attr;
    DCSOWNER_VAR_DESCRIBE Describe;
} DCSOWNER_VAR_MAP;

//
// Variable attribute sets.
//
#define DCSOWNER_ATTR_PRIVATE    (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS)
#define DCSOWNER_ATTR_MIRROR     (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS)
#define DCSOWNER_ATTR_VIRTUAL    0x80000000

//
// TpmKill and verbose-debug settings can come from either the DcsProp config
// file or EFI variables. The source is decided at runtime in DcsOwnerMain:
// gUseConfigFile is TRUE when the DcsProp file loaded, FALSE otherwise (then the
// EFI variables are used). Both name sets are always defined.
//
#define DCSOWNER_VAR_TPMKILL     L"DcsTpmKill"      // EFI variable (no config file)
#define DCSOWNER_VAR_DEBUG       L"DcsVerboseDebug"
#define DCSOWNER_CFG_TPMKILL     "TpmKill"          // DcsProp key (config file present)
#define DCSOWNER_CFG_DEBUG       "VerboseDebug"

extern BOOLEAN gUseConfigFile;

//
// PCR used to measure the committed presets.
//
#define DCSOWNER_PCR_INDEX       7

extern BOOLEAN          gDcsVerboseDebug;
extern DCSOWNER_VAR_MAP gVarMap[];
extern CONST UINTN      gVarMapCount;

UINT8
CfgGetU8 (
    IN  CHAR16    *Name,
    OUT BOOLEAN   *Present
    );

VOID *
CfgGetBytes (
    IN  CHAR16    *Name,
    OUT UINTN     *Size
    );

VOID
CfgSetU8 (
    IN CHAR16    *Name,
    IN UINT8     Value,
    IN UINT32    Attr
    );

VOID
CfgSetBytes (
    IN CHAR16    *Name,
    IN VOID      *Data,
    IN UINTN     Size,
    IN UINT32    Attr
    );

BOOLEAN
BytesEqual (
    IN VOID   *A,
    IN UINTN  ASize,
    IN VOID   *B,
    IN UINTN  BSize
    );

VOID
DescribeCertFingerprint (
    IN  VOID    *Data,
    IN  UINTN  Size,
    OUT CHAR16  *Buf,
    IN  UINTN  BufChars
    );

EFI_STATUS
DcsOwnerConfirmChanges (
    IN BOOLEAN  SbChanged,
    IN UINT8    OldSb,
    IN UINT8    NewSb,
    OUT BOOLEAN *SbAccepted,
    OUT BOOLEAN *VarAccepted
    );

// Read verbose-debug / TpmKill mode from the EFI variable or the DcsProp file,
// depending on whether DCSOWNER_VAR_DEBUG / DCSOWNER_VAR_TPMKILL is defined.
BOOLEAN
DcsOwnerGetVerboseDebug (
    VOID
    );

UINT8
DcsOwnerGetTpmKillMode (
    VOID
    );

EFI_STATUS
EFIAPI
DcsOwnerMain (
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE  *SystemTable
    );

EFI_STATUS
EFIAPI
DcsOwnerUnload (
    IN EFI_HANDLE  ImageHandle
    );

#endif // __EFI_DCSOWNER_H__
