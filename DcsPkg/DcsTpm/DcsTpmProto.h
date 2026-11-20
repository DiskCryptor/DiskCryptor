/** @file
  DCS TPM Interface Protocol

  Copyright (c) 2026 David Xanatos. All rights reserved.

**/

#ifndef _EFI_DCS_TPM_PROTO_H
#define _EFI_DCS_TPM_PROTO_H

#include <Uefi.h>

//
// Global Id for DCS TPM Interface
//
// {A5D3E8C2-7B4F-4D1A-9E6C-8F2B5A1D0C3E}
#define EFI_DCS_TPM_INTERFACE_PROTOCOL_GUID \
  { \
    0xa5d3e8c2, 0x7b4f, 0x4d1a, { 0x9e, 0x6c, 0x8f, 0x2b, 0x5a, 0x1d, 0x0c, 0x3e } \
  }

typedef struct _EFI_DCS_TPM_PROTOCOL EFI_DCS_TPM_PROTOCOL;

//
// Get TPM Status
// NvIndex: TPM NV index to check status for (0 = default index 0x0DC5C)
// Status: Returns DCS_TPM_STATUS_* flags
// PcrMask: Returns PCR mask used for sealing (NULL = don't retrieve)
// Flags: Returns DC_TPM_FLAG_* flags (NULL = don't retrieve)
// Info: Optional output buffer to receive plaintext info data (NULL = don't retrieve)
// InfoSize: In = buffer size, Out = actual size of info data (NULL = don't retrieve)
//
typedef
EFI_STATUS
(EFIAPI *EFI_DCS_TPM_GET_STATUS) (
  IN      EFI_DCS_TPM_PROTOCOL  *This,
  IN      UINT32                NvIndex,
  OUT     UINT32                *Status,
  OUT     UINT32                *PcrMask OPTIONAL,
  OUT     UINT32                *Flags OPTIONAL,
  OUT     VOID                  *Info OPTIONAL,
  IN OUT  UINT32                *InfoSize OPTIONAL
  );

#define DCS_TPM_STATUS_NONE         0x00
#define DCS_TPM_STATUS_CONFIGURED   0x01
#define DCS_TPM_STATUS_LOCKED       0x02
#define DCS_TPM_STATUS_PIN_REQUIRED 0x04
#define DCS_TPM_STATUS_OWNER_READ   0x08 // sealed by an older build, readable with owner auth alone - reseal

#define DCS_SECRET_DATA_MAX       480 // see DC_TPM_SEALED_DATA Password
#define DCS_TPM_INFO_MAX_SIZE     512 // Maximum size of plaintext info data

//
// TPM owner password maximum length
//
#define DCS_TPM_OWNER_PWD_MAX     64

//
// TPM Seal Options structure
// Contains parameters gathered from user for sealing operations
//
#pragma pack(push, 1)
typedef struct _DCS_TPM_SEAL_OPTIONS {
  UINT32    Size;                              // Size of this structure (for versioning)
  UINT32    PcrMask;                           // PCR mask for sealing policy
  CHAR16    OwnerPassword[DCS_TPM_OWNER_PWD_MAX]; // TPM owner password (may be empty)
  CHAR16    TpmPin[DCS_TPM_OWNER_PWD_MAX];     // TPM-validated PIN (hardware auth, optional)
  UINT32    Flags;                             // DCS_TPM_OPT_FLAG_* flags
} DCS_TPM_SEAL_OPTIONS;
#pragma pack(pop)

//
// TPM Seal Options flags
//
#define DCS_TPM_OPT_FLAG_NONE       0x00000000
#define DCS_TPM_OPT_FLAG_USE_PIN    0x00000001  // Use TPM-validated PIN

//
// Default PCR mask: PCR 0 firmware, 2 drivers, 4 bootloader, 7 secure boot, 8 custom, 14 shim
//
#define DCS_TPM_DEFAULT_PCR_MASK  0x4195

//
// Flags
//

#define DC_TPM_FLAG_PIN_REQUIRED  0x00000001  // TPM-validated PIN is required to unseal

//
// Unseal Key from TPM
// NvIndex: TPM NV index containing the sealed data
// Returns the secret key and optionally a descriptor blob (opaque to TPM module)
// TpmPin is optional - if NULL, unseal without hardware PIN validation
// If sealed with PIN but TpmPin is NULL or wrong, returns EFI_ACCESS_DENIED
//
typedef
EFI_STATUS
(EFIAPI *EFI_DCS_TPM_UNSEAL_KEY) (
  IN  EFI_DCS_TPM_PROTOCOL  *This,
  IN  UINT32                NvIndex,
  OUT VOID                  *Data,
  OUT UINT32                *DataSize,
  OUT UINT32                *DataType,
  IN  CHAR16                *TpmPin OPTIONAL
  );

//
// Seal Key to TPM
// NvIndex: TPM NV index to store the sealed data
// Stores the secret key and optionally a descriptor blob (opaque to TPM module)
// The descriptor blob is application-specific data stored alongside the key
// Options struct contains PCR mask and owner password (use GetSealOptions to gather interactively)
// Info: Optional plaintext data to store alongside the sealed data (readable without unseal)
// InfoSize: Size of info data (0 = no info, max 512 bytes)
//
typedef
EFI_STATUS
(EFIAPI *EFI_DCS_TPM_SEAL_KEY) (
  IN  EFI_DCS_TPM_PROTOCOL  *This,
  IN  UINT32                NvIndex,
  IN  VOID                  *Data,
  IN  UINT32                DataSize,
  IN  UINT32                DataType,
  IN  DCS_TPM_SEAL_OPTIONS  *Options,
  IN  VOID                  *Info OPTIONAL,
  IN  UINT32                InfoSize
  );

//
// Clear Secret from TPM
// NvIndex: TPM NV index to clear (removes both data and associated PCR mask entry)
// OwnerPassword: TPM owner password for authorization
//
typedef
EFI_STATUS
(EFIAPI *EFI_DCS_TPM_CLEAR_SECRET) (
  IN  EFI_DCS_TPM_PROTOCOL  *This,
  IN  UINT32                NvIndex,
  IN  CHAR16                *OwnerPassword
  );

//
// Measure to PCR8
//
typedef
EFI_STATUS
(EFIAPI *EFI_DCS_TPM_UPDATE_PCR) (
  IN  EFI_DCS_TPM_PROTOCOL  *This,
  IN  UINTN                 size,
  IN  VOID*                 data
  );

//
// Get Random bytes from TPM
// Uses TPM hardware RNG to generate random data
//
typedef
EFI_STATUS
(EFIAPI *EFI_DCS_TPM_GET_RANDOM) (
  IN  EFI_DCS_TPM_PROTOCOL  *This,
  IN  UINTN                 RandomSize,
  OUT UINT8                 *RandomData
  );

//
// TPM Info structure returned by GetInfo
//
#pragma pack(push, 1)
typedef struct _DCS_TPM_INFO {
  UINT32    TpmVersion;           // 0x100 for 1.2, 0x200 for 2.0
  CHAR8     Manufacturer[8];      // Manufacturer string (TPM 2.0 only, empty for 1.2)
  UINT32    FirmwareVersion1;     // Firmware version part 1 (TPM 2.0 only)
  UINT32    FirmwareVersion2;     // Firmware version part 2 (TPM 2.0 only)
  UINT32    LockoutCounter;       // Failed auth attempts (TPM 2.0 only)
  UINT32    LockoutInterval;      // Recovery interval in seconds (TPM 2.0 only)
} DCS_TPM_INFO;
#pragma pack(pop)

//
// Get TPM Info
// Returns TPM version, manufacturer, firmware version, lockout info
//
typedef
EFI_STATUS
(EFIAPI *EFI_DCS_TPM_GET_INFO) (
  IN  EFI_DCS_TPM_PROTOCOL  *This,
  OUT DCS_TPM_INFO          *Info
  );


//
// Read PCR Value
// Reads a single PCR value from the TPM
// PcrIndex: PCR index (0-23)
// PcrValue: Output buffer for PCR value (must be at least 64 bytes for SHA-512)
// PcrSize: Out = actual PCR size
//
typedef
EFI_STATUS
(EFIAPI *EFI_DCS_TPM_READ_PCR) (
  IN  EFI_DCS_TPM_PROTOCOL  *This,
  IN  UINT32                PcrIndex,
  OUT UINT8                 *PcrValue,
  OUT UINT32                *PcrSize
  );

//
// Enumerate NV Indices
// Lists all TPM NV indices
// IndexList: Output array for NV indices
// IndexCount: In = array size, Out = actual count
//
typedef
EFI_STATUS
(EFIAPI *EFI_DCS_TPM_ENUM_NV_INDICES) (
  IN     EFI_DCS_TPM_PROTOCOL  *This,
  OUT    UINT32                *IndexList,
  IN OUT UINT32                *IndexCount
  );

//
// Get NV Index Info
// Returns attributes and size of an NV index
// NvIndex: NV index to query
// Attributes: Output for TPM NV attributes
// DataSize: Output for data size
// PcrRead: Output for PCR read mask (TPM 1.2 only, NULL ok)
// PcrWrite: Output for PCR write mask (TPM 1.2 only, NULL ok)
//
typedef
EFI_STATUS
(EFIAPI *EFI_DCS_TPM_GET_NV_INDEX_INFO) (
  IN  EFI_DCS_TPM_PROTOCOL  *This,
  IN  UINT32                NvIndex,
  OUT UINT32                *Attributes,
  OUT UINT32                *DataSize,
  OUT UINT32                *PcrRead OPTIONAL,
  OUT UINT32                *PcrWrite OPTIONAL
  );

//
// Shutdown TPM
// Prepares TPM for system power off using TPM_SU_CLEAR (volatile state discarded)
// TPM 2.0: Executes TPM2_Shutdown(TPM_SU_CLEAR)
// TPM 1.2: Returns EFI_UNSUPPORTED (no explicit shutdown command)
//
typedef
EFI_STATUS
(EFIAPI *EFI_DCS_TPM_SHUTDOWN) (
  IN  EFI_DCS_TPM_PROTOCOL  *This
  );

//////////////////////////////////////////////////////////////////////////
// Buffer-based SRK API (caller handles file I/O)
// These functions work with sealed data buffers directly, no NV storage
// Buffer format: [DC_TPM_SRK_FILE_HEADER][SealedBlob][EncryptedDC_TPM_SEALED_DATA][InfoData]
//////////////////////////////////////////////////////////////////////////

//
// Get status from sealed buffer
// Status: Returns DCS_TPM_STATUS_* flags
// PcrMask: Returns PCR mask used for sealing (NULL = don't retrieve)
// Flags: Returns DC_TPM_FLAG_* flags (NULL = don't retrieve)
// Info: Optional output buffer to receive plaintext info data (NULL = don't retrieve)
// InfoSize: In = buffer size, Out = actual size of info data (NULL = don't retrieve)
//
typedef
EFI_STATUS
(EFIAPI *EFI_DCS_TPM_SRK_GET_STATUS) (
  IN     EFI_DCS_TPM_PROTOCOL  *This,
  IN     UINT8                 *Buffer,
  IN     UINT32                BufferSize,
  OUT    UINT32                *Status,
  OUT    UINT32                *PcrMask OPTIONAL,
  OUT    UINT32                *Flags OPTIONAL,
  OUT    VOID                  *Info OPTIONAL,
  IN OUT UINT32                *InfoSize OPTIONAL
  );

//
// Seal password to buffer using SRK with envelope encryption
// Buffer: Output buffer to receive sealed data
// BufferSize: In = buffer size, Out = actual size needed/used
// Returns EFI_BUFFER_TOO_SMALL if buffer too small (BufferSize set to required)
//
typedef
EFI_STATUS
(EFIAPI *EFI_DCS_TPM_SRK_SEAL_PASSWORD) (
  IN     EFI_DCS_TPM_PROTOCOL  *This,
  IN     VOID                  *Password,
  IN     UINT32                PasswordSize,
  IN     UINT32                PasswordType,
  IN     DCS_TPM_SEAL_OPTIONS  *Options,
  IN     VOID                  *Info OPTIONAL,
  IN     UINT32                InfoSize,
  OUT    UINT8                 *Buffer,
  IN OUT UINT32                *BufferSize
  );

//
// Unseal password from buffer
// Password: Output buffer to receive decrypted password
// PasswordSize: Out = actual password size
// PasswordType: Out = password type stored during seal
//
typedef
EFI_STATUS
(EFIAPI *EFI_DCS_TPM_SRK_UNSEAL_PASSWORD) (
  IN  EFI_DCS_TPM_PROTOCOL  *This,
  IN  UINT8                 *Buffer,
  IN  UINT32                BufferSize,
  OUT VOID                  *Password,
  OUT UINT32                *PasswordSize,
  OUT UINT32                *PasswordType,
  IN  CHAR16                *TpmPin OPTIONAL
  );


//
// Protocol definition
//
struct _EFI_DCS_TPM_PROTOCOL {
  // NV-based API
  EFI_DCS_TPM_GET_STATUS            GetStatus;
  EFI_DCS_TPM_UNSEAL_KEY            UnsealSecret;
  EFI_DCS_TPM_SEAL_KEY              SealSecret;
  EFI_DCS_TPM_CLEAR_SECRET          ClearSecret;

  // Other API
  EFI_DCS_TPM_UPDATE_PCR            UpdatePcr8;
  EFI_DCS_TPM_GET_RANDOM            GetRandom;
  EFI_DCS_TPM_GET_INFO              GetInfo;
  EFI_DCS_TPM_READ_PCR              ReadPcr;
  EFI_DCS_TPM_ENUM_NV_INDICES       EnumNvIndices;
  EFI_DCS_TPM_GET_NV_INDEX_INFO     GetNvIndexInfo;
  EFI_DCS_TPM_SHUTDOWN              Shutdown;

  // Buffer-based SRK API (caller handles file I/O)
  EFI_DCS_TPM_SRK_GET_STATUS        SrkGetStatus;
  EFI_DCS_TPM_SRK_SEAL_PASSWORD     SrkSealSecret;
  EFI_DCS_TPM_SRK_UNSEAL_PASSWORD   SrkUnsealSecret;
};

extern EFI_GUID gEfiDcsTpmProtocolGuid;

#endif
