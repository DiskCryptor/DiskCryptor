/** @file
  TPM Kill - Disable TPM before Windows handoff

  Implements multi-layer TPM disabling to prevent Windows from using TPM
  for BitLocker, attestation, or other privacy-invasive features.

  Layer 1: TPM2_Shutdown(TPM_SU_CLEAR) - TPM 2.0 only
  Layer 2: Uninstall EFI_TCG/TCG2 protocols
  Layer 3: Patch TPM2/TCPA ACPI tables

  Copyright (c) 2026 David Xanatos. All rights reserved.

  This program and the accompanying materials are licensed and made available
  under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

  The full text of the license may be found at
  https://opensource.org/licenses/LGPL-3.0
**/

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseLib.h>

#include <Protocol/Tcg2Protocol.h>
#include <Protocol/TcgService.h>
#include <IndustryStandard/Tpm20.h>
#include <IndustryStandard/Acpi.h>
#include <Guid/Acpi.h>

#include "TpmKill.h"

//
// ACPI table parsing helpers
//

// RSDP signature "RSD PTR "
#define ACPI_RSDP_SIGNATURE  SIGNATURE_64('R', 'S', 'D', ' ', 'P', 'T', 'R', ' ')

#pragma pack(push, 1)

// ACPI 2.0+ RSDP structure
typedef struct {
    UINT64    Signature;
    UINT8     Checksum;
    UINT8     OemId[6];
    UINT8     Revision;
    UINT32    RsdtAddress;
    UINT32    Length;
    UINT64    XsdtAddress;
    UINT8     ExtendedChecksum;
    UINT8     Reserved[3];
} ACPI_RSDP_2_0;

#pragma pack(pop)

//////////////////////////////////////////////////////////////////////////
// Layer 1: TPM2 Shutdown
//////////////////////////////////////////////////////////////////////////

/**
  Send TPM2_Shutdown(TPM_SU_CLEAR) command via TCG2 protocol.

  @param[in,out] Context  TPM Kill context to update.

  @retval EFI_SUCCESS     Shutdown command sent successfully.
  @retval EFI_NOT_FOUND   TCG2 protocol not found.
  @retval Others          TPM command failed.
**/
STATIC
EFI_STATUS
TpmKillShutdown(
    IN OUT TPM_KILL_CONTEXT *Context
)
{
    EFI_STATUS         res;
    EFI_TCG2_PROTOCOL  *Tcg2 = NULL;

    #pragma pack(push, 1)
    typedef struct {
        TPM2_COMMAND_HEADER  Header;
        TPM_SU               ShutdownType;
    } TPM2_SHUTDOWN_CMD;

    typedef struct {
        TPM2_RESPONSE_HEADER Header;
    } TPM2_SHUTDOWN_RSP;
    #pragma pack(pop)

    TPM2_SHUTDOWN_CMD  Cmd;
    TPM2_SHUTDOWN_RSP  Rsp;
    UINT32             RspSize;

    // Locate TCG2 protocol (TPM 2.0)
    res = gBS->LocateProtocol(&gEfiTcg2ProtocolGuid, NULL, (VOID**)&Tcg2);
    if (EFI_ERROR(res) || Tcg2 == NULL) {
        // No TPM 2.0 - not an error, TPM 1.2 doesn't have shutdown
        return EFI_NOT_FOUND;
    }

    // Build TPM2_Shutdown command with TPM_SU_CLEAR
    ZeroMem(&Cmd, sizeof(Cmd));
    ZeroMem(&Rsp, sizeof(Rsp));

    Cmd.Header.tag = SwapBytes16(TPM_ST_NO_SESSIONS);
    Cmd.Header.commandCode = SwapBytes32(TPM_CC_Shutdown);
    Cmd.Header.paramSize = SwapBytes32(sizeof(Cmd));
    Cmd.ShutdownType = SwapBytes16(TPM_SU_CLEAR);

    RspSize = sizeof(Rsp);
    res = Tcg2->SubmitCommand(
        Tcg2,
        sizeof(Cmd),
        (UINT8*)&Cmd,
        RspSize,
        (UINT8*)&Rsp
    );

    if (!EFI_ERROR(res)) {
        Context->Tpm2Shutdown = TRUE;
    }

    return res;
}

//////////////////////////////////////////////////////////////////////////
// Layer 2: Protocol Uninstallation
//////////////////////////////////////////////////////////////////////////

/**
  Uninstall all handles for a given protocol GUID.

  @param[in] ProtocolGuid  Protocol GUID to uninstall.

  @return Number of handles uninstalled.
**/
STATIC
UINTN
TpmKillUninstallProtocol(
    IN EFI_GUID *ProtocolGuid
)
{
    EFI_STATUS  res;
    EFI_HANDLE  *Handles = NULL;
    UINTN       HandleCount = 0;
    UINTN       Index;
    UINTN       KillCount = 0;
    VOID        *Protocol;

    res = gBS->LocateHandleBuffer(
        ByProtocol,
        ProtocolGuid,
        NULL,
        &HandleCount,
        &Handles
    );

    if (EFI_ERROR(res) || HandleCount == 0) {
        return 0;
    }

    for (Index = 0; Index < HandleCount; Index++) {
        res = gBS->HandleProtocol(
            Handles[Index],
            ProtocolGuid,
            &Protocol
        );

        if (!EFI_ERROR(res) && Protocol != NULL) {
            res = gBS->UninstallProtocolInterface(
                Handles[Index],
                ProtocolGuid,
                Protocol
            );

            if (!EFI_ERROR(res)) {
                KillCount++;
            }
        }
    }

    if (Handles != NULL) {
        FreePool(Handles);
    }

    return KillCount;
}

/**
  Uninstall TCG and TCG2 protocol handles.

  @param[in,out] Context  TPM Kill context to update.

  @retval EFI_SUCCESS  At least one protocol handle uninstalled.
  @retval EFI_NOT_FOUND  No protocol handles found.
**/
STATIC
EFI_STATUS
TpmKillUninstallProtocols(
    IN OUT TPM_KILL_CONTEXT *Context
)
{
    UINTN KillCount = 0;

    // Uninstall TCG2 (TPM 2.0)
    KillCount += TpmKillUninstallProtocol(&gEfiTcg2ProtocolGuid);

    // Uninstall TCG (TPM 1.2)
    KillCount += TpmKillUninstallProtocol(&gEfiTcgProtocolGuid);

    Context->ProtocolKilled = (KillCount > 0);

    return (KillCount > 0) ? EFI_SUCCESS : EFI_NOT_FOUND;
}

//////////////////////////////////////////////////////////////////////////
// Layer 3: ACPI Table Patching
//////////////////////////////////////////////////////////////////////////

/**
  Find and corrupt TPM-related ACPI tables.

  Searches XSDT/RSDT for TPM2 and TCPA tables and corrupts their signatures.

  @param[in,out] Context  TPM Kill context to update.

  @retval EFI_SUCCESS    At least one table corrupted.
  @retval EFI_NOT_FOUND  No TPM tables found.
**/
STATIC
EFI_STATUS
TpmKillPatchAcpi(
    IN OUT TPM_KILL_CONTEXT *Context
)
{
    UINTN                          Index;
    ACPI_RSDP_2_0                   *Rsdp = NULL;
    EFI_ACPI_DESCRIPTION_HEADER    *Xsdt = NULL;
    EFI_ACPI_DESCRIPTION_HEADER    *Rsdt = NULL;
    UINT64                         *XsdtEntries;
    UINT32                         *RsdtEntries;
    UINTN                          EntryCount;
    UINTN                          i;
    EFI_ACPI_DESCRIPTION_HEADER    *Table;
    BOOLEAN                        Found = FALSE;

    // Find ACPI tables in EFI configuration table
    for (Index = 0; Index < gST->NumberOfTableEntries; Index++) {
        // ACPI 2.0+ (preferred - has XSDT)
        if (CompareGuid(&gST->ConfigurationTable[Index].VendorGuid, &gEfiAcpi20TableGuid)) {
            Rsdp = (ACPI_RSDP_2_0*)gST->ConfigurationTable[Index].VendorTable;
            break;
        }
        // ACPI 1.0 fallback
        if (CompareGuid(&gST->ConfigurationTable[Index].VendorGuid, &gEfiAcpi10TableGuid)) {
            Rsdp = (ACPI_RSDP_2_0*)gST->ConfigurationTable[Index].VendorTable;
            // Don't break - prefer ACPI 2.0 if available
        }
    }

    if (Rsdp == NULL) {
        return EFI_NOT_FOUND;
    }

    // Try XSDT first (64-bit pointers, ACPI 2.0+)
    if (Rsdp->Revision >= 2 && Rsdp->XsdtAddress != 0) {
        Xsdt = (EFI_ACPI_DESCRIPTION_HEADER*)(UINTN)Rsdp->XsdtAddress;

        if (Xsdt != NULL && Xsdt->Signature == SIGNATURE_32('X', 'S', 'D', 'T')) {
            EntryCount = (Xsdt->Length - sizeof(EFI_ACPI_DESCRIPTION_HEADER)) / sizeof(UINT64);
            XsdtEntries = (UINT64*)((UINT8*)Xsdt + sizeof(EFI_ACPI_DESCRIPTION_HEADER));

            for (i = 0; i < EntryCount; i++) {
                Table = (EFI_ACPI_DESCRIPTION_HEADER*)(UINTN)XsdtEntries[i];
                if (Table == NULL) continue;

                // Corrupt TPM2 table (TPM 2.0)
                if (Table->Signature == EFI_ACPI_TPM2_SIGNATURE) {
                    Table->Signature = SIGNATURE_32('X', 'X', 'X', 'X');
                    Table->Checksum = 0xFF;
                    Found = TRUE;
                }

                // Corrupt TCPA table (TPM 1.2)
                if (Table->Signature == EFI_ACPI_TCPA_SIGNATURE) {
                    Table->Signature = SIGNATURE_32('X', 'X', 'X', 'X');
                    Table->Checksum = 0xFF;
                    Found = TRUE;
                }
            }
        }
    }

    // Also try RSDT (32-bit pointers, for older systems or if XSDT empty)
    if (Rsdp->RsdtAddress != 0) {
        Rsdt = (EFI_ACPI_DESCRIPTION_HEADER*)(UINTN)Rsdp->RsdtAddress;

        if (Rsdt != NULL && Rsdt->Signature == SIGNATURE_32('R', 'S', 'D', 'T')) {
            EntryCount = (Rsdt->Length - sizeof(EFI_ACPI_DESCRIPTION_HEADER)) / sizeof(UINT32);
            RsdtEntries = (UINT32*)((UINT8*)Rsdt + sizeof(EFI_ACPI_DESCRIPTION_HEADER));

            for (i = 0; i < EntryCount; i++) {
                Table = (EFI_ACPI_DESCRIPTION_HEADER*)(UINTN)RsdtEntries[i];
                if (Table == NULL) continue;

                // Corrupt TPM2 table (TPM 2.0)
                if (Table->Signature == EFI_ACPI_TPM2_SIGNATURE) {
                    Table->Signature = SIGNATURE_32('X', 'X', 'X', 'X');
                    Table->Checksum = 0xFF;
                    Found = TRUE;
                }

                // Corrupt TCPA table (TPM 1.2)
                if (Table->Signature == EFI_ACPI_TCPA_SIGNATURE) {
                    Table->Signature = SIGNATURE_32('X', 'X', 'X', 'X');
                    Table->Checksum = 0xFF;
                    Found = TRUE;
                }
            }
        }
    }

    Context->AcpiPatched = Found;
    return Found ? EFI_SUCCESS : EFI_NOT_FOUND;
}

//////////////////////////////////////////////////////////////////////////
// Layer 4: Delete TPM EFI Variables
//////////////////////////////////////////////////////////////////////////

//
// Windows TPM Offline Unique ID GUID
// {eaec226f-c9a3-477a-a826-ddc716cdc0e3}
//
// These variables store a unique device identifier derived from the TPM's
// Endorsement Key (EK). This ID is persistent and survives TPM clears -
// only physically replacing the TPM chip will change it. Windows uses
// this for device attestation and tracking purposes.
//
// To protect user privacy and hide all TPM-related information from
// Windows, we delete these variables before handoff. Windows will
// recreate them identically on next boot if TPM is accessible, but
// since we also disable TPM access, they won't be recreated.
//
STATIC EFI_GUID gTpmOfflineIdGuid = {
    0xeaec226f, 0xc9a3, 0x477a, { 0xa8, 0x26, 0xdd, 0xc7, 0x16, 0xcd, 0xc0, 0xe3 }
};

/**
  Delete TPM-related EFI variables used by Windows.

  Deletes OfflineUniqueIDEKPub and OfflineUniqueIDEKPubCRC variables
  which store endorsement key information derived from the TPM's EK.
  These provide a persistent device fingerprint used for attestation.

  @param[in,out] Context  TPM Kill context to update.

  @retval EFI_SUCCESS    At least one variable deleted.
  @retval EFI_NOT_FOUND  No variables found to delete.
**/
STATIC
EFI_STATUS
TpmKillDeleteVariables(
    IN OUT TPM_KILL_CONTEXT *Context
)
{
    EFI_STATUS  res1, res2;
    BOOLEAN     Deleted = FALSE;

    // Delete OfflineUniqueIDEKPub
    res1 = gRT->SetVariable(
        L"OfflineUniqueIDEKPub",
        &gTpmOfflineIdGuid,
        0,      // Attributes = 0 to delete
        0,      // DataSize = 0 to delete
        NULL    // Data = NULL to delete
    );
    if (!EFI_ERROR(res1) || res1 == EFI_NOT_FOUND) {
        // EFI_NOT_FOUND means variable didn't exist, which is fine
        if (!EFI_ERROR(res1)) {
            Deleted = TRUE;
        }
    }

    // Delete OfflineUniqueIDEKPubCRC
    res2 = gRT->SetVariable(
        L"OfflineUniqueIDEKPubCRC",
        &gTpmOfflineIdGuid,
        0,      // Attributes = 0 to delete
        0,      // DataSize = 0 to delete
        NULL    // Data = NULL to delete
    );
    if (!EFI_ERROR(res2) || res2 == EFI_NOT_FOUND) {
        if (!EFI_ERROR(res2)) {
            Deleted = TRUE;
        }
    }

    Context->VariablesDeleted = Deleted;
    return Deleted ? EFI_SUCCESS : EFI_NOT_FOUND;
}

//////////////////////////////////////////////////////////////////////////
// Public API
//////////////////////////////////////////////////////////////////////////

/**
  Execute TPM Kill - disable TPM before Windows handoff.

  @param[in,out] Context  Initialized context, updated with results.

  @retval EFI_SUCCESS     At least one layer succeeded.
  @retval EFI_NOT_FOUND   No TPM found or all layers failed.
  @retval EFI_ABORTED     Feature is disabled.
**/
EFI_STATUS
TpmKillExecute(
    IN OUT TPM_KILL_CONTEXT *Context
)
{
    UINTN SuccessCount = 0;

    if (Context == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    if (!Context->Mode) {
        return EFI_ABORTED;
    }

    // Layer 1: TPM2_Shutdown (TPM 2.0 only)
    if (!EFI_ERROR(TpmKillShutdown(Context))) {
        SuccessCount++;
    }

    // Layer 2: Protocol uninstallation
    if (!EFI_ERROR(TpmKillUninstallProtocols(Context))) {
        SuccessCount++;
    }

    // Layer 3: ACPI table patching
    if (!EFI_ERROR(TpmKillPatchAcpi(Context))) {
        SuccessCount++;
    }

    // Layer 4: Delete TPM EFI variables
    if (Context->Mode == TPM_KILL_MODE_FULL && !EFI_ERROR(TpmKillDeleteVariables(Context))) {
        SuccessCount++;
    }

    return (SuccessCount > 0) ? EFI_SUCCESS : EFI_NOT_FOUND;
}
