/** @file
DCS Owner protocol - allows other DCS components to:
  - Read/write virtualized variables by primary name (e.g. "PK", "MySecureBoot")
  - Lock Boot* variables against modification
  - Manage the DCS boot order entry

Copyright (c) 2026. DiskCryptor, David Xanatos

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#ifndef _EFI_DCSOWNERPROTO_H
#define _EFI_DCSOWNERPROTO_H

#include <Uefi.h>

// {4E8B2F1A-D6C3-47A5-9B0E-3F1C8A5D7E20}
#define EFI_DCSOWNER_PROTOCOL_GUID \
  { \
    0x4e8b2f1a, 0xd6c3, 0x47a5, { 0x9b, 0x0e, 0x3f, 0x1c, 0x8a, 0x5d, 0x7e, 0x20 } \
  }

typedef struct _EFI_DCSOWNER_PROTOCOL EFI_DCSOWNER_PROTOCOL;

//
// BootMenuLock flags (same values as the old DcsBml protocol for compatibility)
//
#define DCSOWNER_LOCK_BOOT_VARS     0x01   // Block SetVariable writes to Boot* variables
#define DCSOWNER_UPDATE_BOOTORDER   0x02   // Create/fix DCS boot entry and put it first
#define DCSOWNER_SET_BOOTNEXT       0x04   // Set BootNext to DCS boot entry

/**
  Read a virtualized variable by primary name.

  For mapped variables (e.g. "PK"), returns the committed override data.
  For "MySecureBoot", returns the effective SB byte.
  Returns EFI_NOT_FOUND if the name is not managed by DcsOwner.

  @param[in]      This          Protocol instance.
  @param[in]      Name          Primary variable name (e.g. L"PK", L"MySecureBoot").
  @param[in,out]  DataSize      On input, buffer size; on output, actual data size.
  @param[out]     Data          Buffer to receive the data (NULL for size query).
  @param[out]     Attributes    Optional: reported attributes for the variable.

  @retval EFI_SUCCESS           Data returned.
  @retval EFI_BUFFER_TOO_SMALL  DataSize updated with required size.
  @retval EFI_NOT_FOUND         Name not managed by this driver.
**/
typedef
EFI_STATUS
(EFIAPI *EFI_DCSOWNER_GET_VARIABLE) (
    IN     EFI_DCSOWNER_PROTOCOL  *This,
    IN     CONST CHAR16           *Name,
    IN OUT UINTN                  *DataSize,
    OUT    VOID                   *Data OPTIONAL,
    OUT    UINT32                 *Attributes OPTIONAL
    );

/**
  Write a virtualized variable by primary name.

  Writes to both the BS private store and RT mirror, and updates
  the in-memory runtime state immediately.

  @param[in]  This          Protocol instance.
  @param[in]  Name          Primary variable name (e.g. L"PK", L"MySecureBoot").
  @param[in]  DataSize      Size of Data buffer (0 to delete/clear).
  @param[in]  Data          Data to write (NULL with DataSize=0 to clear).

  @retval EFI_SUCCESS       Written and committed.
  @retval EFI_NOT_FOUND     Name not managed by this driver.
  @retval other             Failure.
**/
typedef
EFI_STATUS
(EFIAPI *EFI_DCSOWNER_SET_VARIABLE) (
    IN  EFI_DCSOWNER_PROTOCOL  *This,
    IN  CONST CHAR16           *Name,
    IN  UINTN                  DataSize,
    IN  VOID                   *Data OPTIONAL
    );

/**
  Activate runtime hooks (GetVariable, SetVariable, GetNextVariableName).

  Until this is called, DcsOwner only provides protocol access to its
  config variables but does not intercept firmware runtime services.
  Call once when the boot flow is ready to hand off to the OS.

  @param[in]  This          Protocol instance.

  @retval EFI_SUCCESS       Hooks installed.
  @retval EFI_ALREADY_STARTED  Hooks were already active.
**/
typedef
EFI_STATUS
(EFIAPI *EFI_DCSOWNER_TAKE_OWNERSHIP) (
    IN  EFI_DCSOWNER_PROTOCOL  *This
    );

/**
  Lock boot menu and/or manage DCS boot entry.

  @param[in]  This          Protocol instance.
  @param[in]  LockFlags     Combination of DCSOWNER_LOCK_* / DCSOWNER_UPDATE_* flags.

  @retval EFI_SUCCESS       Requested actions performed.
**/
typedef
EFI_STATUS
(EFIAPI *EFI_DCSOWNER_BOOT_MENU_LOCK) (
    IN  EFI_DCSOWNER_PROTOCOL  *This,
    IN  UINT32                 LockFlags
    );

/**
  Show the DcsOwner interactive configuration menu.

  Displays a console-based menu for editing DcsOwner-managed settings
  (Secure Boot override, etc.). Uses the protocol's own GetVariable/SetVariable
  to read and write values.

  @param[in]  This          Protocol instance.

  @retval EFI_SUCCESS       User applied changes.
  @retval EFI_ABORTED       User cancelled.
**/
typedef
EFI_STATUS
(EFIAPI *EFI_DCSOWNER_SHOW_CONFIG_MENU) (
    IN  EFI_DCSOWNER_PROTOCOL  *This
    );

/**
  Show the DcsOwner boot prompt.

  Displays a countdown and informations.

  @param[in]  This          Protocol instance.

  @retval EFI_SUCCESS       User applied changes.
  @retval EFI_ABORTED       User cancelled.
**/
typedef
EFI_STATUS
(EFIAPI *EFI_DCSOWNER_SHOW_BOOT_PROMPT) (
    IN  EFI_DCSOWNER_PROTOCOL  *This
    );

struct _EFI_DCSOWNER_PROTOCOL {
    EFI_DCSOWNER_GET_VARIABLE        GetVariable;
    EFI_DCSOWNER_SET_VARIABLE        SetVariable;
    EFI_DCSOWNER_TAKE_OWNERSHIP      TakeOwnership;
    EFI_DCSOWNER_BOOT_MENU_LOCK      BootMenuLock;
    EFI_DCSOWNER_SHOW_CONFIG_MENU    ShowConfigMenu;
    EFI_DCSOWNER_SHOW_BOOT_PROMPT    ShowBootPrompt;
};

extern EFI_GUID gEfiDcsOwnerProtocolGuid;

#endif
