/** @file
  DCS Security Protocol Interface

  This protocol provides an interface to the DcsLdr security services,
  including MOK-extended Secure Boot verification and MokSBState control.

  Copyright (c) 2026 David Xanatos. All rights reserved.

**/

#ifndef _EFI_DCSSECURITYPROTO_H
#define _EFI_DCSSECURITYPROTO_H

#include <Uefi.h>

//
// Global Id for DcsSecurity Interface
// {3C8A7E5D-9F12-4B6A-A831-7D4E2C1F0B9A}
//
#define EFI_DCS_LDR_PROTOCOL_GUID \
  { \
    0x3c8a7e5d, 0x9f12, 0x4b6a, { 0xa8, 0x31, 0x7d, 0x4e, 0x2c, 0x1f, 0x0b, 0x9a } \
  }

typedef struct _EFI_DCS_LDR_PROTOCOL EFI_DCS_LDR_PROTOCOL;

//
// MokSBState values
//
#define DCS_MOK_SB_STATE_ENABLED   0x00  // Secure Boot verification active
#define DCS_MOK_SB_STATE_DISABLED  0x01  // Secure Boot verification bypassed

/**
  Get the current MokSBState value.

  MokSBState controls whether Secure Boot verification is enforced:
  - DCS_MOK_SB_STATE_ENABLED (0): Verification is active
  - DCS_MOK_SB_STATE_DISABLED (1): Verification is bypassed

  @param[in]  This          Pointer to the protocol instance.
  @param[out] MokSBState    Pointer to receive the current MokSBState value.
  @param[out] IsValid       Pointer to receive validity flag. TRUE if MokSBState
                            variable exists and was loaded, FALSE otherwise.

  @retval EFI_SUCCESS           MokSBState retrieved successfully.
  @retval EFI_INVALID_PARAMETER This, MokSBState, or IsValid is NULL.

**/
typedef
EFI_STATUS
(EFIAPI *EFI_DCS_SECURITY_GET_MOK_SB_STATE) (
  IN  EFI_DCS_LDR_PROTOCOL  *This,
  OUT UINT8                 *MokSBState
  );

/**
  Set the MokSBState value.

  This function updates both the in-memory state used by the security hooks
  and the persistent UEFI variable. The change takes effect immediately for
  all subsequent image loads.

  Note: The MokSBState variable is stored with Boot Services access only
  (no Runtime access) for security, matching shim's behavior.

  @param[in]  This          Pointer to the protocol instance.
  @param[in]  MokSBState    The new MokSBState value to set.
                            Use DCS_MOK_SB_STATE_ENABLED or DCS_MOK_SB_STATE_DISABLED.

  Turning verification off (DCS_MOK_SB_STATE_DISABLED) needs the user to have
  entered credentials in this boot (EFI_DCS_LDR_AUTH_PROTOCOL ConfirmUser, called by DCS after
  an interactive unlock), and is measured into PCR 7 first, so a TPM seal to PCR 7 does not
  unseal in a boot where it happened. Turning it back on is always allowed.

  @retval EFI_SUCCESS           MokSBState set successfully.
  @retval EFI_INVALID_PARAMETER This is NULL or MokSBState is invalid.
  @retval EFI_ACCESS_DENIED     Off requested without an interactive unlock in this boot.
  @retval EFI_SECURITY_VIOLATION Off requested, but a TPM is present and the measurement failed.

**/
typedef
EFI_STATUS
(EFIAPI *EFI_DCS_SECURITY_SET_MOK_SB_STATE) (
  IN  EFI_DCS_LDR_PROTOCOL  *This,
  IN  UINT8                 MokSBState
  );

typedef
EFI_STATUS
(EFIAPI *EFI_DCS_SECURITY_GET_CERT_STATE) (
    IN  EFI_DCS_LDR_PROTOCOL  *This,
    IN  UINT64*               State
    );

//
// Protocol definition
//
struct _EFI_DCS_LDR_PROTOCOL {
  EFI_DCS_SECURITY_GET_MOK_SB_STATE  GetMokSBState;
  EFI_DCS_SECURITY_SET_MOK_SB_STATE  SetMokSBState;

  EFI_DCS_SECURITY_GET_CERT_STATE    GetCertState;
};

extern EFI_GUID gEfiDcsLdrProtocolGuid;

//
// DCS tells DcsLdr that the user entered credentials in this boot (DCS_BOOT_CONFIG.UnlockInteractive);
// until then SetMokSBState refuses to turn verification off. A separate protocol, so DCS can tell
// whether its DcsLdr has it (with an older one the toggle stays off).
// {9B2F4C71-3D85-4E6A-B19C-5A7E20D4C836}
//
#define EFI_DCS_LDR_AUTH_PROTOCOL_GUID \
  { \
    0x9b2f4c71, 0x3d85, 0x4e6a, { 0xb1, 0x9c, 0x5a, 0x7e, 0x20, 0xd4, 0xc8, 0x36 } \
  }

typedef struct _EFI_DCS_LDR_AUTH_PROTOCOL EFI_DCS_LDR_AUTH_PROTOCOL;

typedef
EFI_STATUS
(EFIAPI *EFI_DCS_LDR_CONFIRM_USER) (
  IN  EFI_DCS_LDR_AUTH_PROTOCOL  *This
  );

struct _EFI_DCS_LDR_AUTH_PROTOCOL {
  EFI_DCS_LDR_CONFIRM_USER           ConfirmUser;
};

extern EFI_GUID gEfiDcsLdrAuthProtocolGuid;

#endif // _EFI_DCSSECURITYPROTO_H
