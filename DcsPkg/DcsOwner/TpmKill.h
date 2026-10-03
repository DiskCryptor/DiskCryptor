/** @file
  TPM Kill - Disable TPM before Windows handoff

  Copyright (c) 2026 David Xanatos. All rights reserved.

  This program and the accompanying materials are licensed and made available
  under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

  The full text of the license may be found at
  https://opensource.org/licenses/LGPL-3.0
**/

#ifndef __TPM_KILL_H__
#define __TPM_KILL_H__

#include <Uefi.h>

//
// TPM Kill configuration modes
//
#define TPM_KILL_MODE_DISABLED      0   // Feature disabled
#define TPM_KILL_MODE_FULL          1
#define TPM_KILL_MODE_CONSERVATIVE  2

//
// ACPI table signatures
//
#define EFI_ACPI_TPM2_SIGNATURE   SIGNATURE_32('T', 'P', 'M', '2')  // TPM 2.0
#define EFI_ACPI_TCPA_SIGNATURE   SIGNATURE_32('T', 'C', 'P', 'A')  // TPM 1.2

//
// TPM Kill context - tracks which layers succeeded
//
typedef struct _TPM_KILL_CONTEXT {
    UINT8       Mode;
    BOOLEAN     Tpm2Shutdown;     // Layer 1: TPM2_Shutdown succeeded
    BOOLEAN     ProtocolKilled;   // Layer 2: Protocol uninstall succeeded
    BOOLEAN     AcpiPatched;      // Layer 3: ACPI patching succeeded
    BOOLEAN     VariablesDeleted; // Layer 4: EFI variables deleted
} TPM_KILL_CONTEXT;

/**
  Execute TPM Kill - disable TPM before Windows handoff.

  Executes enabled layers based on mode

  @param[in,out] Context  Initialized context, updated with results.

  @retval EFI_SUCCESS     At least one layer succeeded.
  @retval EFI_NOT_FOUND   No TPM found or all layers failed.
  @retval EFI_ABORTED     Feature is disabled.
**/
EFI_STATUS
TpmKillExecute(
    IN OUT TPM_KILL_CONTEXT *Context
);

#endif // __TPM_KILL_H__
