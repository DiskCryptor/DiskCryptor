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

#ifndef OUT_PRINT
#define OUT_PRINT(format, ...)  Print(format, ##__VA_ARGS__)
#define ERR_PRINT(format, ...)  Print(L"ERROR: " format, ##__VA_ARGS__)

extern UINTN gCELine;
#define CE(ex) gCELine = __LINE__; if(EFI_ERROR(res = ex)) goto err
#endif

//=============================================================================
// String Utility Functions
//=============================================================================

/**
  Case-insensitive comparison of two Unicode strings.

  @param[in]  Str1  First null-terminated Unicode string.
  @param[in]  Str2  Second null-terminated Unicode string.

  @return  < 0 if Str1 < Str2 (case-insensitive)
           = 0 if Str1 == Str2 (case-insensitive)
           > 0 if Str1 > Str2 (case-insensitive)

**/
INTN
EFIAPI
StrCmpI (
    IN CONST CHAR16  *Str1,
    IN CONST CHAR16  *Str2
    );

//=============================================================================
// EFI Helper Functions
//=============================================================================

/**
  Wait for and return a single key press.

  @return  The key that was pressed.
**/
EFI_INPUT_KEY
EFIAPI
UefiGetKey (
    VOID
    );

/**
  Flush pending keyboard input with a delay.

  Discards any pending keystrokes in the input buffer.

  @param[in]  Delay  Delay in 100-nanosecond units (e.g., 1000000 = 100ms).

**/
VOID
EFIAPI
UefiFlushInputDelay (
    IN UINTN  Delay
    );

/**
  Flush pending keyboard input.

  Discards any pending keystrokes in the input buffer using a 100ms delay.

**/
VOID
EFIAPI
UefiFlushInput (
    VOID
    );

/**
  Wait for a key press with a countdown timer.

  Displays a countdown prompt and waits for either a key press or timeout.
  The prompt should contain a %d or %2d format specifier for the countdown.

  @param[in]  Prompt       Format string for countdown display (e.g., L"Wait %2d...").
  @param[in]  Seconds      Number of seconds to wait.
  @param[in]  DefaultScan  Default scan code to return on timeout.
  @param[in]  DefaultChar  Default unicode char to return on timeout.

  @return  The key that was pressed, or default values if timeout occurred.

**/
EFI_INPUT_KEY
EFIAPI
UefiKeyWait (
    IN CHAR16  *Prompt,
    IN UINTN   Seconds,
    IN UINT16  DefaultScan,
    IN UINT16  DefaultChar
    );

/**
  Print bytes in hexadecimal format.

  @param[in] Data  Pointer to the data buffer.
  @param[in] Size  Number of bytes to print.
**/
VOID
EFIAPI
UefiPrintBytes (
    IN UINT8  *Data,
    IN UINTN  Size
    );

/**
  Get an EFI variable value.

  Allocates memory for the variable data. Caller must free with FreePool.

  @param[in]   VarName   Name of the variable.
  @param[in]   VarGuid   GUID of the variable. If NULL, uses gEfiGlobalVariableGuid.
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
  @param[in]  VarGuid   GUID of the variable. If NULL, uses gEfiGlobalVariableGuid.
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


//////////////////////////////////////////////////////////////////////////
// Block I/O
//////////////////////////////////////////////////////////////////////////

// Global block I/O handles
extern EFI_HANDLE  *gBIOHandles;
extern UINTN       gBIOCount;

/**
  Initialize block I/O device handles.

  @retval EFI_SUCCESS  Block I/O handles retrieved
  @retval Other        Error enumerating handles
**/
EFI_STATUS
UefiInitBio(
  VOID
  );

/**
  Get the device handle from which the current image was loaded.
**/
EFI_STATUS
UefiGetStartDevice(
    OUT EFI_HANDLE  *handle
);

//////////////////////////////////////////////////////////////////////////
// File system operations
//////////////////////////////////////////////////////////////////////////

// Global file system root handle
extern EFI_FILE   *gFileRoot;
extern EFI_HANDLE gFileRootHandle;

// Global file system handles
extern EFI_HANDLE  *gFSHandles;
extern UINTN       gFSCount;

/**
  Initialize the file system from the boot device.

  @retval EFI_SUCCESS       File system initialized
  @retval EFI_NOT_FOUND     No file system found
**/
EFI_STATUS
UefiInitFS(
  VOID
  );

/**
  Open the root directory of a file system.

  @param[in]  rootHandle  Handle with SimpleFileSystem protocol
  @param[out] rootFile    Pointer to receive root file handle

  @retval EFI_SUCCESS  Root directory opened
  @retval Other        Error opening root
**/
EFI_STATUS
EfiFileOpenRoot(
  IN  EFI_HANDLE  rootHandle,
  OUT EFI_FILE    **rootFile
  );

/**
  Check if a file exists.

  @param[in] root  File root handle (NULL = use gFileRoot)
  @param[in] name  File path

  @retval EFI_SUCCESS    File exists
  @retval EFI_NOT_FOUND  File not found
**/
EFI_STATUS
UefiFileExist(
  IN EFI_FILE  *root,
  IN CHAR16    *name
  );

/**
Save data to a file.

Creates or overwrites the file with the specified data.

@param[in]  Root  Root directory handle.
@param[in]  Name  File name/path.
@param[in]  Data  Data to write.
@param[in]  Size  Size of data in bytes.

@retval EFI_SUCCESS           File saved successfully.
@retval EFI_INVALID_PARAMETER Invalid parameters.
@retval Other                 Error from file operations.

**/
EFI_STATUS
EFIAPI
SimpleFileSave (
    IN EFI_FILE  *Root,
    IN CHAR16    *Name,
    IN VOID      *Data,
    IN UINTN     Size
);

/**
  Load data from a file.

  Allocates buffer and reads the entire file contents.
  Caller must free the buffer with FreePool.

  @param[in]   Root    Root directory handle.
  @param[in]   Name    File name/path.
  @param[out]  Data    Receives allocated buffer with file data.
  @param[out]  Size    Receives size of data in bytes.

  @retval EFI_SUCCESS           File loaded successfully.
  @retval EFI_INVALID_PARAMETER Invalid parameters.
  @retval EFI_NOT_FOUND         File not found or empty.
  @retval EFI_OUT_OF_RESOURCES  Memory allocation failed.
  @retval Other                 Error from file operations.

**/
EFI_STATUS
EFIAPI
SimpleFileLoad (
    IN  EFI_FILE  *Root,
    IN  CHAR16    *Name,
    OUT VOID      **Data,
    OUT UINTN     *Size
);

/**
  Execute an EFI application from the file system.

  @param[in] deviceHandle  Device handle (NULL = use boot device)
  @param[in] path          Path to EFI application

  @retval EFI_SUCCESS       Application executed successfully
  @retval Other             Error loading/starting application
**/
EFI_STATUS
UefiExec(
  IN EFI_HANDLE  deviceHandle,
  IN CHAR16      *path
  );



//=============================================================================
// SMBIOS / UUID Functions
//=============================================================================

//
// UUID string buffer size (includes null terminator)
// Format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX (36 chars + null)
//
#define UUID_STRING_LENGTH  37

/**
Get the system UUID from SMBIOS and format it as a string.

Retrieves the UUID from SMBIOS Type 1 (System Information) structure
and formats it as a standard UUID string: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX

@param[out]  UuidString   Buffer to receive the UUID string.
Must be at least UUID_STRING_LENGTH characters.
@param[in]   BufferSize   Size of UuidString buffer in bytes.

@retval EFI_SUCCESS           UUID retrieved and formatted successfully.
@retval EFI_NOT_FOUND         SMBIOS table or Type 1 structure not found.
@retval EFI_BUFFER_TOO_SMALL  UuidString buffer is too small.
@retval EFI_INVALID_PARAMETER UuidString is NULL.

**/
EFI_STATUS
EFIAPI
GetSystemUuid (
    OUT CHAR16  *UuidString,
    IN  UINTN   BufferSize
);


//=============================================================================
// PXE Boot Functions
//=============================================================================

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


//=============================================================================
// Base64 Decoding Functions
//=============================================================================

/**
Calculate the decoded size of a Base64 encoded Unicode string.

@param[in]  Input  Null-terminated Base64 encoded Unicode string.

@return  The number of bytes needed to store the decoded data,
or 0 if Input is NULL.

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


//=============================================================================
// DCS Ldr
//=============================================================================

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

#endif // _MISC_UTILS_LIB_H_
