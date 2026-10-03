/** @file
  MiscUtilsLib - Miscellaneous utility functions for DiskCryptor UEFI

  SPDX-License-Identifier: MIT

  Copyright (c) 2024-2026 DiskCryptor contributors

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.

**/

#ifndef _MISC_UTILS_LIB_H_
#define _MISC_UTILS_LIB_H_

#include <Uefi.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/PxeBaseCode.h>

#ifndef MEM_ALLOC
#define MEM_ALLOC(size)         AllocateZeroPool(size)
#define MEM_FREE(ptr)           if ((ptr) != NULL) FreePool(ptr);
#endif

#include "FsUtils.h"
#include "CliUtils.h"

#ifndef OUT_PRINT
#define OUT_PRINT(format, ...)  Print(format, ##__VA_ARGS__)
#define ERR_PRINT(format, ...)  Print(L"ERROR: " format, ##__VA_ARGS__)

extern UINTN gCELine;
#define CE(ex) gCELine = __LINE__; if(EFI_ERROR(res = ex)) goto err
#endif

//////////////////////////////////////////////////////////////////////////
// String Utilities
//////////////////////////////////////////////////////////////////////////

/**
  Case-insensitive comparison of two Unicode strings.

  @param[in]  Str1  First null-terminated Unicode string.
  @param[in]  Str2  Second null-terminated Unicode string.

  @return  < 0 if Str1 < Str2, = 0 if equal, > 0 if Str1 > Str2.

**/
INTN
EFIAPI
StrCmpI (
    IN CONST CHAR16  *Str1,
    IN CONST CHAR16  *Str2
    );

//////////////////////////////////////////////////////////////////////////
// EFI Variable Helpers
//////////////////////////////////////////////////////////////////////////

/**
  Get an EFI variable value.

  Allocates memory for the variable data. Caller must free with FreePool.

  @param[in]   VarName   Name of the variable.
  @param[in]   VarGuid   GUID of the variable.
  @param[out]  VarValue  Receives allocated buffer with variable data.
  @param[out]  VarSize   Receives size of variable data.
  @param[out]  VarAttr   Receives variable attributes. Optional, may be NULL.

  @retval EFI_SUCCESS           Variable retrieved successfully.
  @retval EFI_NOT_FOUND         Variable does not exist.
  @retval EFI_OUT_OF_RESOURCES  Memory allocation failed.
  @retval Other                 Error from GetVariable.

**/
EFI_STATUS
EFIAPI
GetEfiVar (
    IN  CONST CHAR16  *VarName,
    IN  EFI_GUID      *VarGuid   OPTIONAL,
    OUT VOID          **VarValue,
    OUT UINTN         *VarSize,
    OUT UINT32        *VarAttr   OPTIONAL
    );

/**
  Set an EFI variable value.

  @param[in]  VarName   Name of the variable.
  @param[in]  VarGuid   GUID of the variable.
  @param[in]  VarValue  Variable data to set.
  @param[in]  VarSize   Size of variable data.
  @param[in]  VarAttr   Variable attributes.

  @retval EFI_SUCCESS  Variable set successfully.
  @retval Other        Error from SetVariable.

**/
EFI_STATUS
EFIAPI
SetEfiVar (
    IN CONST CHAR16  *VarName,
    IN EFI_GUID      *VarGuid   OPTIONAL,
    IN VOID          *VarValue,
    IN UINTN         VarSize,
    IN UINT32        VarAttr
    );

/**
  Get the device handle from which the current image was loaded.

  @param[out]  handle  Receives the boot device handle.

  @retval EFI_SUCCESS  Device handle retrieved.
  @retval Other        Error from HandleProtocol.

**/
EFI_STATUS
UefiGetStartDevice(
    OUT EFI_HANDLE  *handle
    );

//////////////////////////////////////////////////////////////////////////
// File System & Exec Dispatch (FS / PXE)
//////////////////////////////////////////////////////////////////////////

/**
  Delete a file by path, dispatching to FS or PXE.

  @param[in]  FilePath  Null-terminated file path.

  @retval EFI_SUCCESS      File deleted.
  @retval EFI_UNSUPPORTED  PXE boot (deletion not supported).
  @retval Other            Error from FS delete.

**/
EFI_STATUS
UefiFileDeletePath(
    IN CONST CHAR16 *FilePath
    );

/**
  Check if a file exists, dispatching to FS or PXE.

  @param[in]  FilePath  Null-terminated file path.

  @retval TRUE   File exists.
  @retval FALSE  File not found or error.

**/
BOOLEAN
UefiFileExistsPath(
    IN CONST CHAR16 *FilePath
    );

/**
  Read a file by path, dispatching to FS or PXE.

  Allocates buffer for the file data. Caller must free with MEM_FREE.

  @param[in]      FilePath    Null-terminated file path.
  @param[out]     Buffer      Receives allocated buffer with file data.
  @param[in,out]  BufferSize  Receives size of data read.

  @retval EFI_SUCCESS   File read successfully.
  @retval Other         Error from FS or PXE.

**/
EFI_STATUS
UefiFileReadPath(
    IN     CONST CHAR16 *FilePath,
    OUT    UINT8        **Buffer,
    IN OUT UINT32       *BufferSize
    );

/**
  Write data to a file by path, dispatching to FS or PXE.

  Creates the \\EFI\\DCS directory if writing to local FS.

  @param[in]  FilePath    Null-terminated file path.
  @param[in]  Buffer      Data to write.
  @param[in]  BufferSize  Size of data in bytes.

  @retval EFI_SUCCESS  File written successfully.
  @retval Other        Error from FS or PXE.

**/
EFI_STATUS
UefiFileWritePath(
    IN CONST CHAR16 *FilePath,
    IN UINT8        *Buffer,
    IN UINT32       BufferSize
    );

/**
  Execute an EFI application, dispatching to FS or PXE.

  @param[in]  path  Path to EFI application.

  @retval EFI_SUCCESS  Application executed successfully.
  @retval Other        Error loading/starting application.

**/
EFI_STATUS
UefiExec(
    IN CHAR16  *path
    );

/**
  Execute an EFI application with LoadOptions, dispatching to FS or PXE.

  @param[in]  path             Path to EFI application.
  @param[in]  LoadOptions      Data to pass via LoadOptions.
  @param[in]  LoadOptionsSize  Size of LoadOptions data.

  @retval EFI_SUCCESS  Application executed successfully.
  @retval Other        Error loading/starting application.

**/
EFI_STATUS
UefiExecEx(
    IN CHAR16  *path,
    IN VOID    *LoadOptions      OPTIONAL,
    IN UINTN   LoadOptionsSize
    );

//////////////////////////////////////////////////////////////////////////
// SMBIOS / UUID
//////////////////////////////////////////////////////////////////////////

#define UUID_STRING_LENGTH  37

/**
  Get the system UUID from SMBIOS and format it as a string.

  Retrieves the UUID from SMBIOS Type 1 (System Information) structure
  and formats it as: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX

  @param[out]  UuidString  Buffer to receive the UUID string.
                           Must be at least UUID_STRING_LENGTH characters.
  @param[in]   BufferSize  Size of UuidString buffer in bytes.

  @retval EFI_SUCCESS           UUID retrieved and formatted.
  @retval EFI_NOT_FOUND         SMBIOS table or Type 1 not found.
  @retval EFI_BUFFER_TOO_SMALL  Buffer too small.
  @retval EFI_INVALID_PARAMETER UuidString is NULL.

**/
EFI_STATUS
EFIAPI
GetSystemUuid (
    OUT CHAR16  *UuidString,
    IN  UINTN   BufferSize
    );

//////////////////////////////////////////////////////////////////////////
// PXE Boot Functions
//////////////////////////////////////////////////////////////////////////

//
// PXE global state (read-only from external modules)
//
extern BOOLEAN         gPxeBoot;      // TRUE if booted via PXE
extern BOOLEAN         gPxeUseIPv6;   // TRUE if using IPv6
extern EFI_IP_ADDRESS  gPxeServerIp;  // TFTP server IP address

/**
  Initialize PXE boot support.

  Auto-detects if the system was booted via PXE and configures
  the TFTP server address.

  @retval EFI_SUCCESS      PXE initialized successfully.
  @retval EFI_UNSUPPORTED  Not a PXE boot.
  @retval Other            Error during initialization.

**/
EFI_STATUS
EFIAPI
InitPxe (
    VOID
    );

/**
  Initialize PXE from inherited state.

  Called by child modules to inherit PXE state from parent via variable.
  This is used when a PXE-booted loader launches another EFI application.

  @retval EFI_SUCCESS      PXE state inherited
  @retval EFI_UNSUPPORTED  No PXE state to inherit
  @retval EFI_NOT_READY    PXE protocol not found
**/
EFI_STATUS
InitPxe2(
  VOID
  );

/**
  Check if currently booted via PXE.

  @retval TRUE   System was booted via PXE.
  @retval FALSE  Not a PXE boot.

**/
BOOLEAN
EFIAPI
IsPxeBoot (
    VOID
    );

/**
  Get the PXE server IP address.

  @param[out]  ServerIp  Receives the TFTP server IP address.

  @retval EFI_SUCCESS    Server IP retrieved.
  @retval EFI_NOT_READY  PXE not initialized.

**/
EFI_STATUS
EFIAPI
PxeGetServerIp (
    OUT EFI_IP_ADDRESS  *ServerIp
    );

/**
  Download a file from TFTP server using PXE.

  @param[in]   FilePath    Path to the file on TFTP server.
  @param[out]  Buffer      Receives allocated buffer with file data.
                           Caller must free with FreePool.
  @param[out]  BufferSize  Receives size of downloaded data.

  @retval EFI_SUCCESS           File downloaded successfully.
  @retval EFI_NOT_READY         PXE not initialized.
  @retval EFI_OUT_OF_RESOURCES  Memory allocation failed.
  @retval Other                 TFTP error.

**/
EFI_STATUS
EFIAPI
PxeDownloadFile (
    IN  CHAR16  *FilePath,
    OUT VOID    **Buffer,
    OUT UINTN   *BufferSize
    );

/**
  Upload a file to TFTP server using PXE.

  @param[in]  FilePath    Path for the file on TFTP server.
  @param[in]  Buffer      Data to upload.
  @param[in]  BufferSize  Size of data in bytes.

  @retval EFI_SUCCESS           File uploaded successfully.
  @retval EFI_NOT_READY         PXE not initialized.
  @retval EFI_INVALID_PARAMETER Invalid parameters.
  @retval Other                 TFTP error.

**/
EFI_STATUS
EFIAPI
PxeUploadFile (
    IN CHAR16  *FilePath,
    IN VOID    *Buffer,
    IN UINTN   BufferSize
    );

/**
  Check if a file exists on TFTP server.

  @param[in]  FilePath  Path to check on TFTP server.

  @retval EFI_SUCCESS    File exists.
  @retval EFI_NOT_FOUND  File does not exist.
  @retval EFI_NOT_READY  PXE not initialized.
  @retval Other          TFTP error.

**/
EFI_STATUS
EFIAPI
PxeFileExist (
    IN CHAR16  *FilePath
    );

/**
  Download and execute an EFI application from TFTP server.

  @param[in]  Path  Path to the EFI application on TFTP server.

  @retval EFI_SUCCESS    Application executed (may have returned).
  @retval EFI_NOT_READY  PXE not initialized.
  @retval Other          Download or load error.

**/
EFI_STATUS
EFIAPI
PxeExec (
    IN CHAR16  *Path
    );

/**
  Download and execute an EFI application from TFTP server with LoadOptions.

  @param[in]  Path             Path to the EFI application on TFTP server.
  @param[in]  LoadOptions      Data to pass to the loaded image via LoadOptions.
  @param[in]  LoadOptionsSize  Size of LoadOptions data.

  @retval EFI_SUCCESS    Application executed (may have returned).
  @retval EFI_NOT_READY  PXE not initialized.
  @retval Other          Download or load error.

**/
EFI_STATUS
EFIAPI
PxeExecEx (
    IN CHAR16  *Path,
    IN VOID    *LoadOptions      OPTIONAL,
    IN UINTN   LoadOptionsSize
    );

/**
  Download file from TFTP and save to local filesystem.

  @param[in]  SrcPath   Source path on TFTP server.
  @param[in]  DstRoot   Destination filesystem root.
  @param[in]  DstPath   Destination file path.

  @retval EFI_SUCCESS           File copied successfully.
  @retval EFI_NOT_READY         PXE not initialized.
  @retval EFI_INVALID_PARAMETER Invalid parameters.
  @retval Other                 Download or save error.

**/
EFI_STATUS
EFIAPI
PxeFileCopy (
    IN CHAR16    *SrcPath,
    IN EFI_FILE  *DstRoot,
    IN CHAR16    *DstPath
    );


//////////////////////////////////////////////////////////////////////////
// Base64 Decoding
//////////////////////////////////////////////////////////////////////////

/**
  Calculate the decoded size of a Base64 encoded Unicode string.

  @param[in]  Input  Null-terminated Base64 encoded Unicode string.

  @return  Number of bytes needed for decoded data, or 0 if Input is NULL.

**/
UINTN
EFIAPI
DcsBase64DecodedSize (
    IN CONST CHAR16  *Input
    );

/**
  Decode a Base64 encoded Unicode string to binary data.

  @param[in]   Input       Null-terminated Base64 encoded Unicode string.
  @param[out]  Output      Buffer to receive decoded data.
  @param[in]   OutputSize  Size of the output buffer in bytes.

  @retval TRUE   Decoding successful.
  @retval FALSE  Invalid input, null pointer, or buffer too small.

**/
BOOLEAN
EFIAPI
DcsBase64Decode (
    IN  CONST CHAR16  *Input,
    OUT UINT8         *Output,
    IN  UINTN         OutputSize
    );

//////////////////////////////////////////////////////////////////////////
// DCS Ldr
//////////////////////////////////////////////////////////////////////////

extern EFI_GUID gEfiDcsLdrProtocolGuid;
extern struct _EFI_DCS_LDR_PROTOCOL* gDcsLdr;

EFI_STATUS
InitDcsLdr(
    VOID
    );

EFI_STATUS
DcsLdrGetMokSBState(
    OUT UINT8* MokSBState
    );

EFI_STATUS
DcsLdrSetMokSBState(
    IN UINT8 MokSBState
    );

EFI_STATUS
DcsLdrGetCertState(
    OUT UINT64* State
    );

BOOLEAN
IsSecureBootEnabled(
    VOID
    );

#endif // _MISC_UTILS_LIB_H_
