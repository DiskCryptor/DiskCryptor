/** @file
Keep this runtime driver's own code executable at OS runtime on firmware that
enforces the EFI Memory Attributes Table (MAT).

Background: a DXE_RUNTIME_DRIVER loaded from the ESP after EndOfDxe is accepted
onto the runtime image list (it gets relocated at SetVirtualAddressMap), but
firmware that publishes and enforces a MAT typically maps its code no-execute -
either leaving it out of the table or marking it XP - so the OS faults the first
time it calls into it. This module makes the image's executable sections
read-only/executable in the MAT, re-asserts that after every LoadImage (firmware
re-derives the table on image loads and drops the flip), and exposes a probe the
caller uses at ExitBootServices to decide whether the flip survived.

Nothing here is specific to DcsOwner's variable-override policy; it only concerns
keeping the containing image's code executable. The caller owns its own hooks and
is responsible for un-hooking if MatExecAddrExecutable() reports the flip was lost.

Copyright (c) 2026. DiskCryptor, David Xanatos
Licensed under the GNU Lesser General Public License, version 3.0 (LGPL-3.0).
**/

#ifndef _DCS_MAT_EXEC_H_
#define _DCS_MAT_EXEC_H_

#include <Uefi.h>

/**
  Confirm the DXE core loaded this image as a runtime image (its code and data
  are EfiRuntimeServicesCode/Data). Hooks only survive the handoff if so.
**/
BOOLEAN
MatExecImageIsRuntime (
  VOID
  );

/**
  Report whether the given code address is mapped executable per the live MAT.

  @param[in]  Addr        A code address inside this image.
  @param[out] MatPresent  TRUE if the firmware publishes a MAT at all.
  @param[in]  Quiet       Suppress debug output (use at ExitBootServices).

  @retval TRUE   Addr is executable, or no MAT exists (memory map governs).
  @retval FALSE  The OS will map Addr non-executable.
**/
BOOLEAN
MatExecAddrExecutable (
  IN  EFI_PHYSICAL_ADDRESS  Addr,
  OUT BOOLEAN               *MatPresent,
  IN  BOOLEAN               Quiet
  );

/**
  Make this image's executable sections read-only/executable in the MAT and arm
  a LoadImage hook that re-asserts the flip after each subsequent image load.

  @param[in] GuardAddr  A code address inside this image, used for the
                        post-install re-check and by the LoadImage re-assert.

  @retval TRUE   A flip was installed and GuardAddr is now executable.
  @retval FALSE  Nothing changed; the caller must not rely on runtime execution.
**/
BOOLEAN
MatExecMakeExecutable (
  IN EFI_PHYSICAL_ADDRESS  GuardAddr
  );

/**
  Stop re-asserting the flip: restore gBS->LoadImage and its table CRC. Safe to
  call more than once. Does NOT free the installed MAT copy (still live).
**/
VOID
MatExecDisarm (
  VOID
  );

/**
  Release the MAT copy this module installed. Teardown only - after this the
  live configuration table pointer is stale, so only call when unloading.
**/
VOID
MatExecFreeTable (
  VOID
  );

/**
  Recompute a service table's header CRC after its entries were modified.
  UEFI 2.10 4.2: CRC32 is computed over HeaderSize bytes with the field zeroed.
**/
VOID
MatExecRecomputeTableCrc (
  IN OUT EFI_TABLE_HEADER  *Hdr
  );

#endif // _DCS_MAT_EXEC_H_
