/** @file
  FsUtils - EFI File System utility functions for DiskCryptor UEFI

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

#ifndef _FS_UTILS_H_
#define _FS_UTILS_H_

#include <Uefi.h>
#include <Protocol/SimpleFileSystem.h>
#include <Guid/FileInfo.h>

//////////////////////////////////////////////////////////////////////////
// Global File System State
//////////////////////////////////////////////////////////////////////////

extern EFI_FILE    *gFileRoot;
extern EFI_HANDLE  gFileRootHandle;
extern EFI_HANDLE  *gFSHandles;
extern UINTN       gFSCount;

//////////////////////////////////////////////////////////////////////////
// Core File Operations
//////////////////////////////////////////////////////////////////////////

/**
Initialize the file system from the boot device.

Enumerates all SimpleFileSystem handles and opens the root directory
of the boot device.

@retval EFI_SUCCESS   File system initialized.
@retval Other         Error during initialization.

**/
EFI_STATUS
InitFs(
    VOID
);

/**
  Open the root directory of a file system volume.

  Locates the SimpleFileSystem protocol on the given handle and opens
  its root directory.

  @param[in]   RootHandle  Handle with SimpleFileSystem protocol installed.
  @param[out]  RootFile    Receives the opened root directory file handle.

  @retval EFI_SUCCESS           Root directory opened successfully.
  @retval EFI_INVALID_PARAMETER RootFile is NULL or protocol not found.
  @retval Other                 Error from HandleProtocol or OpenVolume.

**/
EFI_STATUS
FsFileOpenRoot(
    IN  EFI_HANDLE  RootHandle,
    OUT EFI_FILE    **RootFile
    );

/**
  Open a file or directory relative to a root directory.

  If Root is NULL, uses gFileRoot. If Mode is 0, defaults to
  EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE.

  @param[in]   Root        Root directory handle, or NULL for gFileRoot.
  @param[in]   Name        Null-terminated path to the file or directory.
  @param[out]  File        Receives the opened file handle.
  @param[in]   Mode        Open mode flags (EFI_FILE_MODE_*).
  @param[in]   Attributes  File attributes for creation (EFI_FILE_*).

  @retval EFI_SUCCESS           File opened successfully.
  @retval EFI_INVALID_PARAMETER Name or File is NULL, or no root available.
  @retval Other                 Error from EFI_FILE Open.

**/
EFI_STATUS
FsFileOpen(
    IN  EFI_FILE   *Root,
    IN  CHAR16     *Name,
    OUT EFI_FILE   **File,
    IN  UINT64     Mode,
    IN  UINT64     Attributes
    );

/**
  Close an open file handle.

  @param[in]  File  File handle to close.

  @retval EFI_SUCCESS           File closed successfully.
  @retval EFI_INVALID_PARAMETER File is NULL.

**/
EFI_STATUS
FsFileClose(
    IN EFI_FILE  *File
    );

/**
  Read data from a file at an optional position.

  If Position is non-NULL, seeks to *Position before reading and
  updates *Position to the new file position after the read.

  @param[in]      File      Open file handle.
  @param[out]     Data      Buffer to receive the read data.
  @param[in,out]  Bytes     On input, number of bytes to read.
                            On output, number of bytes actually read.
  @param[in,out]  Position  Optional file position. If NULL, reads from
                            the current position.

  @retval EFI_SUCCESS           Data read successfully.
  @retval EFI_INVALID_PARAMETER File, Data, or Bytes is NULL.
  @retval Other                 Error from SetPosition or Read.

**/
EFI_STATUS
FsFileRead(
    IN     EFI_FILE  *File,
    OUT    VOID      *Data,
    IN OUT UINTN     *Bytes,
    IN OUT UINT64    *Position  OPTIONAL
    );

/**
  Write data to a file at an optional position.

  Handles partial writes by retrying until all bytes are written or an
  error occurs. If Position is non-NULL, seeks to *Position before writing
  and updates *Position to the new file position after the write.

  @param[in]      File      Open file handle.
  @param[in]      Data      Buffer containing data to write.
  @param[in]      Bytes     Number of bytes to write.
  @param[in,out]  Position  Optional file position. If NULL, writes at
                            the current position.

  @retval EFI_SUCCESS           All data written successfully.
  @retval EFI_INVALID_PARAMETER File or Data is NULL.
  @retval Other                 Error from SetPosition or Write.

**/
EFI_STATUS
FsFileWrite(
    IN     EFI_FILE  *File,
    IN     VOID      *Data,
    IN     UINTN     Bytes,
    IN OUT UINT64    *Position  OPTIONAL
    );

/**
  Retrieve the EFI_FILE_INFO for an open file.

  Allocates memory for the info structure. Caller must free with MEM_FREE.

  @param[in]   File  Open file handle.
  @param[out]  Info  Receives allocated EFI_FILE_INFO structure.
  @param[out]  Size  Optional. Receives the size of the info structure.

  @retval EFI_SUCCESS           Info retrieved successfully.
  @retval EFI_INVALID_PARAMETER File or Info is NULL.
  @retval EFI_OUT_OF_RESOURCES  Memory allocation failed.
  @retval Other                 Error from GetInfo.

**/
EFI_STATUS
FsFileGetInfo(
    IN  EFI_FILE       *File,
    OUT EFI_FILE_INFO  **Info,
    OUT UINTN          *Size  OPTIONAL
    );

/**
  Get the size of an open file in bytes.

  @param[in]   File  Open file handle.
  @param[out]  Size  Receives the file size.

  @retval EFI_SUCCESS           Size retrieved successfully.
  @retval EFI_INVALID_PARAMETER File or Size is NULL.
  @retval Other                 Error from GetInfo.

**/
EFI_STATUS
FsFileGetSize(
    IN  EFI_FILE  *File,
    OUT UINTN     *Size
    );

//////////////////////////////////////////////////////////////////////////
// Directory Operations
//////////////////////////////////////////////////////////////////////////

/**
  Create a directory, opening and closing it immediately.

  Creates the directory if it does not exist. If Root is NULL, uses gFileRoot.

  @param[in]  Root  Root directory handle, or NULL for gFileRoot.
  @param[in]  Name  Null-terminated path of the directory to create.

  @retval EFI_SUCCESS           Directory created or already exists.
  @retval EFI_INVALID_PARAMETER Name is NULL.
  @retval Other                 Error from file open.

**/
EFI_STATUS
FsDirectoryCreate(
    IN EFI_FILE  *Root,
    IN CHAR16    *Name
    );

/**
  Check if a directory exists.

  Attempts to open the path as a directory in read mode.

  @param[in]  Root  Root directory handle, or NULL for gFileRoot.
  @param[in]  Name  Null-terminated path to check.

  @retval EFI_SUCCESS    Directory exists.
  @retval EFI_NOT_FOUND  Directory does not exist.
  @retval Other          Error from file open.

**/
EFI_STATUS
FsDirectoryExists(
    IN EFI_FILE  *Root,
    IN CHAR16    *Name
    );

//////////////////////////////////////////////////////////////////////////
// File-Level Operations
//////////////////////////////////////////////////////////////////////////

/**
  Check if a file exists.

  Attempts to open the file in read mode and closes it immediately.

  @param[in]  Root  Root directory handle, or NULL for gFileRoot.
  @param[in]  Name  Null-terminated file path to check.

  @retval EFI_SUCCESS    File exists.
  @retval EFI_NOT_FOUND  File does not exist.
  @retval Other          Error from file open.

**/
EFI_STATUS
FsFileExist(
    IN EFI_FILE  *Root,
    IN CHAR16    *Name
    );

/**
  Delete a file by name.

  Opens the file and calls EFI_FILE Delete on it. The file handle is
  consumed by Delete regardless of success.

  @param[in]  Root  Root directory handle, or NULL for gFileRoot.
  @param[in]  Name  Null-terminated file path to delete.

  @retval EFI_SUCCESS           File deleted successfully.
  @retval EFI_INVALID_PARAMETER Name is NULL.
  @retval Other                 Error from open or delete.

**/
EFI_STATUS
FsFileDelete(
    IN EFI_FILE  *Root,
    IN CHAR16    *Name
    );

/**
  Load an entire file into an allocated buffer.

  Allocates memory for the file contents. Caller must free with MEM_FREE.

  @param[in]   Root  Root directory handle, or NULL for gFileRoot.
  @param[in]   Name  Null-terminated file path to load.
  @param[out]  Data  Receives allocated buffer with file contents.
  @param[out]  Size  Receives file size in bytes.

  @retval EFI_SUCCESS           File loaded successfully.
  @retval EFI_NOT_FOUND         File not found or empty.
  @retval EFI_OUT_OF_RESOURCES  Memory allocation failed.
  @retval Other                 Error from file operations.

**/
EFI_STATUS
EFIAPI
FsFileLoad(
    IN  EFI_FILE  *Root,
    IN  CHAR16    *Name,
    OUT VOID      **Data,
    OUT UINTN     *Size
    );

/**
  Save data to a file, creating or overwriting it.

  Deletes the existing file first, then creates a new one and writes
  the data.

  @param[in]  Root  Root directory handle, or NULL for gFileRoot.
  @param[in]  Name  Null-terminated file path.
  @param[in]  Data  Data to write.
  @param[in]  Size  Size of data in bytes.

  @retval EFI_SUCCESS           File saved successfully.
  @retval EFI_INVALID_PARAMETER Data or Name is NULL.
  @retval Other                 Error from file operations.

**/
EFI_STATUS
EFIAPI
FsFileSave(
    IN EFI_FILE  *Root,
    IN CHAR16    *Name,
    IN VOID      *Data,
    IN UINTN     Size
    );

/**
  Rename a file.

  Opens the source file, retrieves its info, and sets new info with
  the destination filename.

  @param[in]  Root  Root directory handle, or NULL for gFileRoot.
  @param[in]  Src   Current file path.
  @param[in]  Dst   New file name (not a full path, just the filename).

  @retval EFI_SUCCESS           File renamed successfully.
  @retval EFI_INVALID_PARAMETER Src or Dst is NULL.
  @retval EFI_OUT_OF_RESOURCES  Memory allocation failed.
  @retval Other                 Error from file operations.

**/
EFI_STATUS
FsFileRename(
    IN EFI_FILE  *Root,
    IN CHAR16    *Src,
    IN CHAR16    *Dst
    );

/**
  Copy a file between directories using a buffered transfer.

  Reads the source file in chunks and writes them to the destination.
  Deletes the destination file first if it exists.

  @param[in]  SrcRoot   Source root directory handle.
  @param[in]  Src       Source file path.
  @param[in]  DstRoot   Destination root directory handle.
  @param[in]  Dst       Destination file path.
  @param[in]  BufSize   Size of the copy buffer in bytes.

  @retval EFI_SUCCESS           File copied successfully.
  @retval EFI_OUT_OF_RESOURCES  Buffer allocation failed.
  @retval Other                 Error from file operations.

**/
EFI_STATUS
FsFileCopy(
    IN EFI_FILE  *SrcRoot,
    IN CHAR16    *Src,
    IN EFI_FILE  *DstRoot,
    IN CHAR16    *Dst,
    IN UINTN     BufSize
    );

/**
  Print a formatted ASCII string to a file.

  Uses a static 1024-byte buffer for formatting.

  @param[in]  File    Open file handle to write to.
  @param[in]  Format  ASCII format string (printf-style).
  @param[in]  ...     Variable arguments for the format string.

  @return  Number of bytes written, or 0 if File is NULL.

**/
UINTN
FsFileAsciiPrint(
    IN EFI_FILE     *File,
    IN CONST CHAR8  *Format,
    ...
    );

#endif // _FS_UTILS_H_
