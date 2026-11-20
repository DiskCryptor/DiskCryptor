/** @file
  TPM Library

  Copyright (c) 2026 David Xanatos. All rights reserved.

**/

#ifndef __TPMLIB_H__
#define __TPMLIB_H__

#include <Uefi.h>

extern UINTN gCELine;
#define CE(ex) gCELine = __LINE__; if(EFI_ERROR(res = ex)) goto err

typedef struct _TPM_LIB_PROTOCOL TPM_LIB_PROTOCOL;
extern TPM_LIB_PROTOCOL* gTpm;

EFI_STATUS
GetTpm();

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

EFI_STATUS
TpmAes256CbcDecrypt(
	IN     UINT8    *Key,       // 32 bytes
	IN     UINT8    *Iv,        // 16 bytes
	IN OUT UINT8    *Data,
	IN     UINT32   DataSize
	);

EFI_STATUS
TpmAes256CbcEncrypt(
	IN     UINT8    *Key,       // 32 bytes
	IN     UINT8    *Iv,        // 16 bytes
	IN OUT UINT8    *Data,
	IN     UINT32   DataSize
	);

//////////////////////////////////////////////////////////////////////////
// TPM 1.2
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
InitTpm12();

VOID
InitTpmLib12(
	IN OUT TPM_LIB_PROTOCOL* Tpm);

//////////////////////////////////////////////////////////////////////////
// TPM 2.0
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
InitTpm20();

VOID
InitTpmLib20(
	IN OUT TPM_LIB_PROTOCOL* Tpm);

//////////////////////////////////////////////////////////////////////////
// TPM LIB protocol
//////////////////////////////////////////////////////////////////////////

typedef EFI_STATUS(*TPM_LIB_GETRANDOM)(
	IN  TPM_LIB_PROTOCOL   *tpm,
	IN  UINT32              size,
	OUT VOID*              rnd
	);

typedef EFI_STATUS(*TPM_LIB_MEASURE)(
	IN  TPM_LIB_PROTOCOL   *tpm,
	IN  UINTN              index,
	IN  UINTN              size,
	IN  VOID*              data
	);

// NvIndex: TPM NV index for sealed data (0 = use default DC_TPM2_NV_INDEX_DEFAULT)
// PCR mask index is derived automatically using DC_TPM_NV_INDEX_TO_PCRS()
typedef EFI_STATUS(*TPM_LIB_SEAL_PASSWORD)(
	IN  UINT32    NvIndex,             // NV index (0 = default)
	IN  VOID      *password,
	IN  UINT32    passwordSize,
	IN  UINT32    passwordType,
	IN  UINT32    pcrMask,
	IN  CHAR16    *ownerPwd,
	IN  CHAR16    *tpmPin OPTIONAL,    // TPM-validated PIN (hardware auth)
	IN  VOID      *info OPTIONAL,      // Plaintext info data to store
	IN  UINT32    infoSize             // Size of info data (0 = none)
	);

typedef EFI_STATUS(*TPM_LIB_UNSEAL_PASSWORD)(
	IN  UINT32    NvIndex,             // NV index (0 = default)
	OUT VOID      *password,
	OUT UINT32    *passwordSize,
	OUT UINT32    *passwordType,
	IN  CHAR16    *tpmPin OPTIONAL     // TPM-validated PIN (hardware auth)
	);

typedef EFI_STATUS(*TPM_LIB_CLEAR_SECRET)(
	IN  UINT32    NvIndex,             // NV index (0 = default)
	IN  CHAR16    *ownerPwd
	);

typedef EFI_STATUS(*TPM_LIB_GET_INFO)(
	IN      UINT32    NvIndex,         // NV index (0 = default)
	OUT     UINT32    *PcrMask OPTIONAL, // PCR mask (bits 0-23)
	OUT     UINT32    *Flags OPTIONAL, // DC_TPM_FLAG_* flags
	OUT     VOID      *Info OPTIONAL,  // Buffer to receive info data
	IN OUT  UINT32    *InfoSize OPTIONAL // In = buffer size, Out = actual size
	);

typedef EFI_STATUS(*TPM_LIB_CLEAR_TPM)(
	IN  CHAR16    *authPwd OPTIONAL,
	OUT BOOLEAN   *NeedsReboot
	);

typedef EFI_STATUS(*TPM_LIB_TAKE_OWNERSHIP)(
	IN  CHAR16    *newOwnerPwd
	);

typedef EFI_STATUS(*TPM_LIB_CHANGE_OWNER_PWD)(
	IN  CHAR16    *oldOwnerPwd,
	IN  CHAR16    *newOwnerPwd
	);

typedef BOOLEAN(*TPM_LIB_IS_CONFIGURED)(
	IN  UINT32    NvIndex              // NV index (0 = default)
	);

typedef BOOLEAN(*TPM_LIB_IS_OPEN)(
	IN  UINT32    NvIndex              // NV index (0 = default)
	);

// The data index can be read with owner authorization alone (TPM 2.0 indices
// sealed by older builds with TPMA_NV_OWNERREAD) - it has to be resealed. NULL for TPM 1.2.
typedef BOOLEAN(*TPM_LIB_IS_OWNER_READABLE)(
	IN  UINT32    NvIndex              // NV index (0 = default)
	);

//
// SRK buffer-based sealing functions (caller handles file I/O)
// These work with a buffer containing DC_TPM_SRK_FILE_HEADER + sealed data + info
// Buffer format: [Header][SealedBlob][EncryptedDC_TPM_SEALED_DATA][InfoData]
//
typedef BOOLEAN(*TPM_LIB_SRK_IS_OPEN)(
	IN  UINT8     *buffer,             // Buffer containing sealed data
	IN  UINT32    bufferSize           // Size of buffer
	);

typedef EFI_STATUS(*TPM_LIB_SRK_GET_INFO)(
	IN     UINT8     *buffer,          // Buffer containing sealed data
	IN     UINT32    bufferSize,       // Size of buffer
	OUT    UINT32    *PcrMask OPTIONAL, // PCR mask (bits 0-23)
	OUT    UINT32    *Flags OPTIONAL,  // DC_TPM_FLAG_* flags
	OUT    VOID      *Info OPTIONAL,   // Buffer to receive info data
	IN OUT UINT32    *InfoSize OPTIONAL // In = buffer size, Out = actual size
	);

typedef EFI_STATUS(*TPM_LIB_SRK_SEAL_PASSWORD)(
	IN  VOID      *password,
	IN  UINT32    passwordSize,
	IN  UINT32    passwordType,
	IN  UINT32    pcrMask,
	IN  CHAR16    *tpmPin OPTIONAL,    // TPM-validated PIN (hardware auth)
	IN  VOID      *info OPTIONAL,      // Plaintext info data to store
	IN  UINT32    infoSize,            // Size of info data (0 = none)
	OUT UINT8     *buffer,             // Output buffer for sealed data
	IN OUT UINT32 *bufferSize          // In = buffer capacity, Out = actual size
	);

typedef EFI_STATUS(*TPM_LIB_SRK_UNSEAL_PASSWORD)(
	IN  UINT8     *buffer,             // Buffer containing sealed data
	IN  UINT32    bufferSize,          // Size of buffer
	OUT VOID      *password,
	OUT UINT32    *passwordSize,
	OUT UINT32    *passwordType,
	IN  CHAR16    *tpmPin OPTIONAL     // TPM-validated PIN (hardware auth)
	);


typedef EFI_STATUS(*TPM_LIB_READ_PCR)(
	IN  UINT32    PcrIndex,
	OUT UINT8     *PcrValue,
	OUT UINT32    *PcrSize
	);

// TPM 2.0 info functions (NULL for TPM 1.2)
typedef EFI_STATUS(*TPM_LIB_GET_MANUFACTURER)(
	OUT UINT32    *ManufacturerId,
	OUT CHAR8     *ManufacturerStr
	);

typedef EFI_STATUS(*TPM_LIB_GET_FW_VERSION)(
	OUT UINT32    *FirmwareVersion1,
	OUT UINT32    *FirmwareVersion2
	);

typedef EFI_STATUS(*TPM_LIB_GET_LOCKOUT_INFO)(
	OUT UINT32    *LockoutCounter,
	OUT UINT32    *LockoutInterval,
	OUT UINT32    *LockoutRecovery
	);

typedef EFI_STATUS(*TPM_LIB_ENUM_NV_INDICES)(
	OUT UINT32    *IndexList,
	IN OUT UINT32 *IndexCount
	);

typedef EFI_STATUS(*TPM_LIB_GET_NV_INDEX_INFO)(
	IN  UINT32    NvIndex,
	OUT UINT32    *Attributes,
	OUT UINT32    *DataSize,
	OUT UINT32    *PcrRead OPTIONAL,
	OUT UINT32    *PcrWrite OPTIONAL
	);

// Shutdown TPM (TPM 2.0 only, returns EFI_UNSUPPORTED for TPM 1.2)
typedef EFI_STATUS (*TPM_LIB_SHUTDOWN)();

typedef struct _TPM_LIB_PROTOCOL {
	UINTN                       TpmVersion;
	TPM_LIB_GETRANDOM           GetRandom;
	TPM_LIB_MEASURE             Measure;
	// password sealing
	TPM_LIB_IS_CONFIGURED		NvIsConfigured;
	TPM_LIB_IS_OPEN				NvIsOpen;
	TPM_LIB_IS_OWNER_READABLE   NvIsOwnerReadable;
	TPM_LIB_SEAL_PASSWORD       NvSealPassword;
	TPM_LIB_UNSEAL_PASSWORD     NvUnsealPassword;
	TPM_LIB_CLEAR_SECRET        NvClearSecret;
	TPM_LIB_GET_INFO			NvGetInfo;
	// TPM management
	TPM_LIB_CLEAR_TPM           ClearTpm;
	TPM_LIB_TAKE_OWNERSHIP      TakeOwnership;
	TPM_LIB_CHANGE_OWNER_PWD    ChangeOwnerPwd;
	// PCR read
	TPM_LIB_READ_PCR            ReadPcr;
	// TPM 2.0 info (NULL for TPM 1.2)
	TPM_LIB_GET_MANUFACTURER    GetManufacturer;
	TPM_LIB_GET_FW_VERSION      GetFirmwareVersion;
	TPM_LIB_GET_LOCKOUT_INFO    GetLockoutInfo;
	// NV enumeration
	TPM_LIB_ENUM_NV_INDICES     EnumNvIndices;
	TPM_LIB_GET_NV_INDEX_INFO   GetNvIndexInfo;
	// SRK buffer-based sealing (caller handles file I/O)
	TPM_LIB_SRK_IS_OPEN         SrkIsOpen;
	TPM_LIB_SRK_GET_INFO        SrkGetInfo;
	TPM_LIB_SRK_SEAL_PASSWORD   SrkSealPassword;
	TPM_LIB_SRK_UNSEAL_PASSWORD SrkUnsealPassword;
	// Shutdown (TPM 2.0 only)
	TPM_LIB_SHUTDOWN            Shutdown;
} TPM_LIB_PROTOCOL;

//////////////////////////////////////////////////////////////////////////
// TPM Support (direct password sealing)
//////////////////////////////////////////////////////////////////////////

// NV index derivation: PCR mask index is derived from data index using bit 21
// Bit 21 (0x200000) is the highest freely usable bit within TPM NV ranges
// Data index must have bit 21 clear; PCR index has bit 21 set
#define DC_TPM_NV_PCRS_BIT              0x200000
#define DC_TPM_NV_INDEX_TO_PCRS(idx)    ((idx) | DC_TPM_NV_PCRS_BIT)
#define DC_TPM_NV_IS_VALID_INDEX(idx)   (((idx) & DC_TPM_NV_PCRS_BIT) == 0)


// Sealed password data structure (variable length)
#pragma pack(push, 1)
typedef struct _DC_TPM_SEALED_DATA {
	UINT32   Magic;           // DC_TPM_SEALED_MAGIC
	UINT16   Version;         // Structure version
	UINT16   PasswordSize;    // Password size in bytes
	UINT32   PasswordType;    // Password type
	UINT32   Checksum;        // CRC32 of password data
	UINT8    Reserved[16];    // Reserved for future use
	UINT8    Password[0];     // Variable-length password data
} DC_TPM_SEALED_DATA;
#pragma pack(pop)

#define DC_TPM_SEALED_MAGIC       0x50544344  // "DCTP" - NV-based sealing
#define DC_TPM_SEALED_VERSION     1

#define DC_TPM_SEALED_BASE_SIZE   32   // Size of header without Password
#define DC_TPM_SEALED_MIN_SIZE    96   // Minimum blob size for security
#define DC_TPM_SEALED_MAX_SIZE    512  // Maximum blob size (legacy compatibility)

// Calculate required blob size for a given password size (16-byte aligned, min 96 bytes)
#define DC_TPM_SEALED_DATA_SIZE(pwdSize) \
	((((DC_TPM_SEALED_BASE_SIZE + (pwdSize)) + 15) & ~15) < DC_TPM_SEALED_MIN_SIZE ? \
	 DC_TPM_SEALED_MIN_SIZE : (((DC_TPM_SEALED_BASE_SIZE + (pwdSize)) + 15) & ~15))

#define DC_TPM_NV_SIZE            512  // Legacy/max NV size

// Sealed data flags
#define DC_TPM_FLAG_NONE          0x00000000
#define DC_TPM_FLAG_PIN_REQUIRED  0x00000001  // TPM-validated PIN is required to unseal

// PCR Info data structure for NV-based plaintext storage
#pragma pack(push, 1)
typedef struct _DC_TPM_PCRINFO_DATA {
	UINT32   Magic;             // DC_TPM_PCRINFO_MAGIC
	UINT16   Version;           // Structure version (currently 1)
	UINT16   InfoSize;          // Size of InfoData (0 = none, max DC_TPM_INFO_MAX_SIZE)
	UINT32   PcrMask;           // PCR mask used for sealing
	UINT32   Flags;             // Flags (DC_TPM_FLAG_*)
	UINT8    InfoData[0];       // Variable-length payload
} DC_TPM_PCRINFO_DATA;
#pragma pack(pop)

#define DC_TPM_PCRINFO_MAGIC      0x49524350  // "PCRI" - PCR info structure
#define DC_TPM_PCRINFO_VERSION    1

#define DC_TPM_PCRINFO_BASE_SIZE  16  // Size of header without InfoData

// Maximum size of plaintext info data
#define DC_TPM_INFO_MAX_SIZE      512

//////////////////////////////////////////////////////////////////////////
// File header for SRK-sealed blob storage (shared by TPM 1.2 and 2.0)
//////////////////////////////////////////////////////////////////////////

// SRK Envelope encryption (KEK sealed, DC_TPM_SEALED_DATA encrypted with AES-256-CBC)
#pragma pack(1)
typedef struct _DC_TPM_SRK_FILE_HEADER {
	UINT32   Magic;           // DC_TPM_SRK_FILE_MAGIC
	UINT16   Version;         // Version
	UINT16   Reserved1;       // Reserved for alignment
	UINT32   Flags;           // DC_TPM_FLAG_PIN_REQUIRED, etc.
	UINT32   PcrMask;         // PCR mask used for sealing
	UINT16   SealedBlobSize;  // Size of sealed KEK blob
	UINT16   EncryptedSize;   // Size of encrypted DC_TPM_SEALED_DATA (with padding)
	UINT8    Iv[16];          // AES IV for envelope encryption
	UINT16   InfoSize;        // Size of plaintext info data (0 = none, max DC_TPM_INFO_MAX_SIZE)
	// Followed by: sealed KEK blob + encrypted DC_TPM_SEALED_DATA + InfoData
} DC_TPM_SRK_FILE_HEADER;
#pragma pack()

#define DC_TPM_SRK_FILE_MAGIC     0x4B525344  // "DSRK"
#define DC_TPM_SRK_VERSION        1


#endif
