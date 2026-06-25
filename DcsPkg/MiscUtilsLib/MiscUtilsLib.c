/** @file
  MiscUtilsLib - Miscellaneous utility functions for DiskCryptor UEFI

  SPDX-License-Identifier: MIT

  Copyright (c) 2024-2026 David Xanatos

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

#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>
#include <Library/DevicePathLib.h>
#include <Library/DebugLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/BlockIo.h>
#include <Guid/FileInfo.h>
#include <IndustryStandard/SmBios.h>
#include <Guid/SmBios.h>

#include "../DcsLdr/DcsLdrProto.h"
#include "MiscUtilsLib.h"

//////////////////////////////////////////////////////////////////////////
// Global Variables
//////////////////////////////////////////////////////////////////////////

// Block I/O handles
EFI_HANDLE  *gBIOHandles = NULL;
UINTN       gBIOCount = 0;

// File system handles
EFI_FILE    *gFileRoot = NULL;
EFI_HANDLE  gFileRootHandle = NULL;
EFI_HANDLE  *gFSHandles = NULL;
UINTN       gFSCount = 0;

UINTN       gCELine = 0;

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
)
{
    CHAR16  C1;
    CHAR16  C2;

    if (Str1 == NULL || Str2 == NULL) {
        return (Str1 == Str2) ? 0 : (Str1 == NULL ? -1 : 1);
    }

    while (*Str1 != L'\0') {
        C1 = *Str1;
        C2 = *Str2;

        // Convert to uppercase for comparison
        if (C1 >= L'a' && C1 <= L'z') {
            C1 -= (L'a' - L'A');
        }
        if (C2 >= L'a' && C2 <= L'z') {
            C2 -= (L'a' - L'A');
        }

        if (C1 != C2) {
            return C1 - C2;
        }

        Str1++;
        Str2++;
    }

    return *Str1 - *Str2;
}

//=============================================================================
// EFI Variable Helper Functions
//=============================================================================

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
)
{
    EFI_STATUS  Status;
    VOID        *Data;
    UINTN       DataSize;
    UINT32      Attributes;

    if (VarGuid == NULL || VarName == NULL || VarValue == NULL || VarSize == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    *VarValue = NULL;
    *VarSize = 0;

    // First call to get the size
    DataSize = 0;
    Status = gRT->GetVariable(
        (CHAR16 *)VarName,
        VarGuid,
        &Attributes,
        &DataSize,
        NULL
    );

    if (Status != EFI_BUFFER_TOO_SMALL) {
        return Status;
    }

    // Allocate buffer
    Data = AllocateZeroPool(DataSize);
    if (Data == NULL) {
        return EFI_OUT_OF_RESOURCES;
    }

    // Get the variable
    Status = gRT->GetVariable(
        (CHAR16 *)VarName,
        VarGuid,
        &Attributes,
        &DataSize,
        Data
    );

    if (EFI_ERROR(Status)) {
        FreePool(Data);
        return Status;
    }

    *VarValue = Data;
    *VarSize = DataSize;
    if (VarAttr != NULL) {
        *VarAttr = Attributes;
    }

    return EFI_SUCCESS;
}

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
)
{
    if (VarGuid == NULL || VarName == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    return gRT->SetVariable(
        (CHAR16 *)VarName,
        VarGuid,
        VarAttr,
        VarSize,
        VarValue
    );
}


/**
Wait for and return a single key press.

@return  The key that was pressed.
**/
EFI_INPUT_KEY
EFIAPI
UefiGetKey (
    VOID
)
{
    EFI_INPUT_KEY  Key;
    UINTN          EventIndex;

    ZeroMem(&Key, sizeof(Key));

    // Wait for key event
    gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &EventIndex);

    // Read the key
    gST->ConIn->ReadKeyStroke(gST->ConIn, &Key);

    return Key;
}

/**
Flush pending keyboard input with a delay.

Discards any pending keystrokes in the input buffer.

@param[in]  Delay  Delay in 100-nanosecond units (e.g., 1000000 = 100ms).

**/
VOID
EFIAPI
UefiFlushInputDelay (
    IN UINTN  Delay
)
{
    EFI_INPUT_KEY  Key;
    EFI_EVENT      InputEvents[2];
    UINTN          EventIndex = 0;

    InputEvents[0] = gST->ConIn->WaitForKey;
    gBS->CreateEvent(EVT_TIMER, 0, (EFI_EVENT_NOTIFY)NULL, NULL, &InputEvents[1]);
    gBS->SetTimer(InputEvents[1], TimerPeriodic, Delay);

    while (EventIndex == 0) {
        gBS->WaitForEvent(2, InputEvents, &EventIndex);
        if (EventIndex == 0) {
            gST->ConIn->ReadKeyStroke(gST->ConIn, &Key);
        }
    }

    gBS->CloseEvent(InputEvents[1]);
}

/**
Flush pending keyboard input.

Discards any pending keystrokes in the input buffer using a 100ms delay.

**/
VOID
EFIAPI
UefiFlushInput (
    VOID
)
{
    UefiFlushInputDelay(1000000);  // 100ms in 100ns units
}

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
)
{
    EFI_INPUT_KEY  Key;
    EFI_EVENT      InputEvents[2];
    UINTN          EventIndex;

    // Flush any pending input first
    UefiFlushInput();

    // Set default return values
    Key.ScanCode = DefaultScan;
    Key.UnicodeChar = DefaultChar;

    InputEvents[0] = gST->ConIn->WaitForKey;

    // Create a 1-second periodic timer
    gBS->CreateEvent(EVT_TIMER, 0, (EFI_EVENT_NOTIFY)NULL, NULL, &InputEvents[1]);
    gBS->SetTimer(InputEvents[1], TimerPeriodic, 10000000);  // 1 second in 100ns units

    while (Seconds > 0) {
        // Display countdown
        Print(Prompt, Seconds);

        // Wait for either key press or timer
        gBS->WaitForEvent(2, InputEvents, &EventIndex);

        if (EventIndex == 0) {
            // Key was pressed
            if (!EFI_ERROR(gST->ConIn->ReadKeyStroke(gST->ConIn, &Key))) {
                break;
            }
            // ReadKeyStroke failed, continue waiting
            continue;
        } else {
            // Timer fired, decrement countdown
            Seconds--;
        }
    }

    // Final display update
    Print(Prompt, Seconds);

    gBS->CloseEvent(InputEvents[1]);
    return Key;
}

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
)
{
    UINTN  Index;

    if (Data == NULL || Size == 0) {
        return;
    }

    for (Index = 0; Index < Size; Index++) {
        Print(L"%02x", Data[Index]);
    }
}

//////////////////////////////////////////////////////////////////////////
// Block I/O
//////////////////////////////////////////////////////////////////////////

/**
Initialize block I/O device handles.
**/
EFI_STATUS
UefiInitBio(
    VOID
)
{
    EFI_STATUS  Status;
    UINTN       BufferSize;

    if (gBIOHandles != NULL) {
        FreePool(gBIOHandles);
        gBIOHandles = NULL;
    }
    gBIOCount = 0;

    BufferSize = 0;
    Status = gBS->LocateHandle(
        ByProtocol,
        &gEfiBlockIoProtocolGuid,
        NULL,
        &BufferSize,
        NULL
    );

    if (Status != EFI_BUFFER_TOO_SMALL) {
        return Status;
    }

    gBIOHandles = AllocateZeroPool(BufferSize);
    if (gBIOHandles == NULL) {
        return EFI_OUT_OF_RESOURCES;
    }

    Status = gBS->LocateHandle(
        ByProtocol,
        &gEfiBlockIoProtocolGuid,
        NULL,
        &BufferSize,
        gBIOHandles
    );

    if (EFI_ERROR(Status)) {
        FreePool(gBIOHandles);
        gBIOHandles = NULL;
        return Status;
    }

    gBIOCount = BufferSize / sizeof(EFI_HANDLE);
    return EFI_SUCCESS;
}

/**
Get the device handle from which the current image was loaded.
**/
EFI_STATUS
UefiGetStartDevice(
    OUT EFI_HANDLE  *handle
)
{
    EFI_STATUS                 Status;
    EFI_LOADED_IMAGE_PROTOCOL  *LoadedImage;

    Status = gBS->HandleProtocol(
        gImageHandle,
        &gEfiLoadedImageProtocolGuid,
        (VOID **)&LoadedImage
    );
    if (EFI_ERROR(Status)) {
        return Status;
    }

    *handle = LoadedImage->DeviceHandle;
    return EFI_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
// File System
//////////////////////////////////////////////////////////////////////////

/**
Open the root directory of a file system.
**/
EFI_STATUS
EfiFileOpenRoot(
    IN  EFI_HANDLE  rootHandle,
    OUT EFI_FILE    **rootFile
)
{
    EFI_STATUS                       Status;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *SimpleFileSystem;

    Status = gBS->HandleProtocol(
        rootHandle,
        &gEfiSimpleFileSystemProtocolGuid,
        (VOID **)&SimpleFileSystem
    );
    if (EFI_ERROR(Status)) {
        return Status;
    }

    return SimpleFileSystem->OpenVolume(SimpleFileSystem, rootFile);
}

/**
Initialize the file system from the boot device.
**/
EFI_STATUS
UefiInitFS(
    VOID
)
{
    EFI_STATUS  Status;
    UINTN       BufferSize;

    // Get all file system handles
    if (gFSHandles != NULL) {
        FreePool(gFSHandles);
        gFSHandles = NULL;
    }
    gFSCount = 0;

    BufferSize = 0;
    Status = gBS->LocateHandle(
        ByProtocol,
        &gEfiSimpleFileSystemProtocolGuid,
        NULL,
        &BufferSize,
        NULL
    );

    if (Status == EFI_BUFFER_TOO_SMALL) {
        gFSHandles = AllocateZeroPool(BufferSize);
        if (gFSHandles != NULL) {
            Status = gBS->LocateHandle(
                ByProtocol,
                &gEfiSimpleFileSystemProtocolGuid,
                NULL,
                &BufferSize,
                gFSHandles
            );
            if (!EFI_ERROR(Status)) {
                gFSCount = BufferSize / sizeof(EFI_HANDLE);
            }
        }
    }

    // Get root file system from boot device
    Status = UefiGetStartDevice(&gFileRootHandle);
    if (!EFI_ERROR(Status)) {
        Status = EfiFileOpenRoot(gFileRootHandle, &gFileRoot);
    }

    return Status;
}

/**
Check if a file exists.
**/
EFI_STATUS
UefiFileExist(
    IN EFI_FILE  *root,
    IN CHAR16    *name
)
{
    EFI_STATUS  Status;
    EFI_FILE    *File;
    EFI_FILE    *Root;

    Root = (root != NULL) ? root : gFileRoot;
    if (Root == NULL) {
        return EFI_NOT_READY;
    }

    Status = Root->Open(
        Root,
        &File,
        name,
        EFI_FILE_MODE_READ,
        0
    );

    if (!EFI_ERROR(Status)) {
        File->Close(File);
        return EFI_SUCCESS;
    }

    return EFI_NOT_FOUND;
}

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
    )
{
    EFI_STATUS  Status;
    EFI_FILE    *File;
    UINTN       WriteSize;

    if (Root == NULL) {
		Root = gFileRoot;
    }

    if (Name == NULL || Data == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    // Try to delete existing file first (ignore errors)
    Status = Root->Open(
        Root,
        &File,
        Name,
        EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE,
        0
        );
    if (!EFI_ERROR(Status)) {
        File->Delete(File);
    }

    // Create new file
    Status = Root->Open(
        Root,
        &File,
        Name,
        EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
        0
        );
    if (EFI_ERROR(Status)) {
        return Status;
    }

    // Write data
    WriteSize = Size;
    Status = File->Write(File, &WriteSize, Data);

    File->Close(File);

    return Status;
}

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
    )
{
    EFI_STATUS     Status;
    EFI_FILE       *File;
    EFI_FILE_INFO  *FileInfo;
    UINTN          FileInfoSize;
    VOID           *Buffer;
    UINTN          FileSize;

    if (Root == NULL) {
        Root = gFileRoot;
    }

    if (Name == NULL || Data == NULL || Size == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    *Data = NULL;
    *Size = 0;

    // Open the file
    Status = Root->Open(
        Root,
        &File,
        Name,
        EFI_FILE_MODE_READ,
        0
        );
    if (EFI_ERROR(Status)) {
        return Status;
    }

    // Get file size
    FileInfoSize = 0;
    Status = File->GetInfo(File, &gEfiFileInfoGuid, &FileInfoSize, NULL);
    if (Status != EFI_BUFFER_TOO_SMALL) {
        File->Close(File);
        return EFI_DEVICE_ERROR;
    }

    FileInfo = AllocatePool(FileInfoSize);
    if (FileInfo == NULL) {
        File->Close(File);
        return EFI_OUT_OF_RESOURCES;
    }

    Status = File->GetInfo(File, &gEfiFileInfoGuid, &FileInfoSize, FileInfo);
    if (EFI_ERROR(Status)) {
        FreePool(FileInfo);
        File->Close(File);
        return Status;
    }

    FileSize = (UINTN)FileInfo->FileSize;
    FreePool(FileInfo);

    if (FileSize == 0) {
        File->Close(File);
        return EFI_NOT_FOUND;
    }

    // Allocate buffer and read file
    Buffer = AllocatePool(FileSize);
    if (Buffer == NULL) {
        File->Close(File);
        return EFI_OUT_OF_RESOURCES;
    }

    Status = File->Read(File, &FileSize, Buffer);
    if (EFI_ERROR(Status)) {
        FreePool(Buffer);
        File->Close(File);
        return Status;
    }

    File->Close(File);

    *Data = Buffer;
    *Size = FileSize;
    return EFI_SUCCESS;
}

/**
Execute an EFI application from the file system.
**/
EFI_STATUS
UefiExec(
    IN EFI_HANDLE  deviceHandle,
    IN CHAR16      *path
)
{
    EFI_STATUS                 Status;
    EFI_HANDLE                 ImageHandle;
    EFI_DEVICE_PATH_PROTOCOL   *FilePath;
    EFI_HANDLE                 Device;

    Device = (deviceHandle != NULL) ? deviceHandle : gFileRootHandle;
    if (Device == NULL) {
        return EFI_NOT_READY;
    }

    FilePath = FileDevicePath(Device, path);
    if (FilePath == NULL) {
        return EFI_OUT_OF_RESOURCES;
    }

    Status = gBS->LoadImage(
        FALSE,
        gImageHandle,
        FilePath,
        NULL,
        0,
        &ImageHandle
    );
    FreePool(FilePath);

    if (EFI_ERROR(Status)) {
        return Status;
    }

    Status = gBS->StartImage(ImageHandle, NULL, NULL);

    return Status;
}

//=============================================================================
// SMBIOS / UUID Functions
//=============================================================================

/**
Get the next SMBIOS structure in the table.

@param[in]  Current  Current SMBIOS structure pointer.

@return  Pointer to the next SMBIOS structure.

**/
STATIC
SMBIOS_STRUCTURE_POINTER
SmbiosGetNextStructure (
    IN SMBIOS_STRUCTURE_POINTER  Current
)
{
    SMBIOS_STRUCTURE_POINTER  Next;
    UINT8                     *Ptr;

    // Skip to the end of the formatted area
    Ptr = (UINT8 *)Current.Raw + Current.Hdr->Length;

    // Skip past the string table (double null terminated)
    while (Ptr[0] != 0 || Ptr[1] != 0) {
        Ptr++;
    }

    // Skip the double null terminator
    Next.Raw = Ptr + 2;
    return Next;
}

/**
Find an SMBIOS structure by type.

@param[in]  TableBase    Base address of SMBIOS table.
@param[in]  TableLength  Length of SMBIOS table.
@param[in]  Type         SMBIOS structure type to find.

@return  Pointer to the found structure, or NULL if not found.

**/
STATIC
SMBIOS_STRUCTURE_POINTER
SmbiosFindStructure (
    IN UINT8  *TableBase,
    IN UINTN  TableLength,
    IN UINT8  Type
)
{
    SMBIOS_STRUCTURE_POINTER  Current;
    UINT8                     *TableEnd;

    Current.Raw = TableBase;
    TableEnd = TableBase + TableLength;

    while (Current.Raw < TableEnd && Current.Hdr->Type != 127) {
        if (Current.Hdr->Type == Type) {
            return Current;
        }
        Current = SmbiosGetNextStructure(Current);
    }

    Current.Raw = NULL;
    return Current;
}

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
)
{
    UINTN                         Index;
    SMBIOS_TABLE_ENTRY_POINT      *SmbiosEntry;
    SMBIOS_TABLE_3_0_ENTRY_POINT  *Smbios3Entry;
    UINT8                         *TableBase;
    UINTN                         TableLength;
    SMBIOS_STRUCTURE_POINTER      SysInfo;
    SMBIOS_TABLE_TYPE1            *Type1;

    if (UuidString == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    if (BufferSize < UUID_STRING_LENGTH * sizeof(CHAR16)) {
        return EFI_BUFFER_TOO_SMALL;
    }

    SmbiosEntry = NULL;
    Smbios3Entry = NULL;
    TableBase = NULL;
    TableLength = 0;

    //
    // Search for SMBIOS table in EFI configuration table
    //
    for (Index = 0; Index < gST->NumberOfTableEntries; Index++) {
        if (CompareGuid(&gST->ConfigurationTable[Index].VendorGuid, &gEfiSmbios3TableGuid)) {
            Smbios3Entry = (SMBIOS_TABLE_3_0_ENTRY_POINT *)gST->ConfigurationTable[Index].VendorTable;
            if (Smbios3Entry != NULL) {
                TableBase = (UINT8 *)(UINTN)Smbios3Entry->TableAddress;
                TableLength = Smbios3Entry->TableMaximumSize;
                DEBUG((DEBUG_INFO, "MiscUtilsLib: Found SMBIOS 3.0 table\n"));
            }
            break;
        }
        if (CompareGuid(&gST->ConfigurationTable[Index].VendorGuid, &gEfiSmbiosTableGuid)) {
            SmbiosEntry = (SMBIOS_TABLE_ENTRY_POINT *)gST->ConfigurationTable[Index].VendorTable;
            if (SmbiosEntry != NULL) {
                TableBase = (UINT8 *)(UINTN)SmbiosEntry->TableAddress;
                TableLength = SmbiosEntry->TableLength;
                DEBUG((DEBUG_INFO, "MiscUtilsLib: Found SMBIOS 2.x table\n"));
            }
            // Continue looking for SMBIOS 3.0
        }
    }

    if (TableBase == NULL || TableLength == 0) {
        StrCpyS(UuidString, BufferSize / sizeof(CHAR16), L"00000000-0000-0000-0000-000000000000");
        DEBUG((DEBUG_WARN, "MiscUtilsLib: SMBIOS table not found\n"));
        return EFI_NOT_FOUND;
    }

    //
    // Find System Information (Type 1) structure
    //
    SysInfo = SmbiosFindStructure(TableBase, TableLength, SMBIOS_TYPE_SYSTEM_INFORMATION);
    if (SysInfo.Raw == NULL) {
        StrCpyS(UuidString, BufferSize / sizeof(CHAR16), L"00000000-0000-0000-0000-000000000000");
        DEBUG((DEBUG_WARN, "MiscUtilsLib: SMBIOS Type 1 not found\n"));
        return EFI_NOT_FOUND;
    }

    Type1 = SysInfo.Type1;

    //
    // Check if UUID field is present (structure must be at least 25 bytes for UUID)
    //
    if (Type1->Hdr.Length < 25) {
        StrCpyS(UuidString, BufferSize / sizeof(CHAR16), L"00000000-0000-0000-0000-000000000000");
        DEBUG((DEBUG_WARN, "MiscUtilsLib: SMBIOS Type 1 too short for UUID\n"));
        return EFI_NOT_FOUND;
    }

    //
    // Format UUID as string: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
    // SMBIOS 2.6+ specifies UUID in RFC4122 format (mixed endian)
    //
    UnicodeSPrint(
        UuidString,
        BufferSize,
        L"%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        Type1->Uuid.Data1,
        Type1->Uuid.Data2,
        Type1->Uuid.Data3,
        Type1->Uuid.Data4[0],
        Type1->Uuid.Data4[1],
        Type1->Uuid.Data4[2],
        Type1->Uuid.Data4[3],
        Type1->Uuid.Data4[4],
        Type1->Uuid.Data4[5],
        Type1->Uuid.Data4[6],
        Type1->Uuid.Data4[7]
    );

    DEBUG((DEBUG_INFO, "MiscUtilsLib: System UUID: %s\n", UuidString));
    return EFI_SUCCESS;
}


//=============================================================================
// DCS Ldr
//=============================================================================

EFI_GUID gEfiDcsLdrProtocolGuid = EFI_DCS_LDR_PROTOCOL_GUID;
EFI_DCS_LDR_PROTOCOL* gDcsLdr = NULL;

EFI_STATUS
InitDcsLdr(
    VOID
)
{
    EFI_STATUS res;
    res = gBS->LocateProtocol(&gEfiDcsLdrProtocolGuid, NULL, (VOID**)&gDcsLdr);
    return res;
}

EFI_STATUS
DcsLdrGetMokSBState(
    OUT UINT8* MokSBState
)
{
    EFI_STATUS res;
    if (gDcsLdr == NULL) {
        res = InitDcsLdr();
        if (EFI_ERROR(res)) {
            return EFI_NOT_READY;
        }
    }

    return gDcsLdr->GetMokSBState(gDcsLdr, MokSBState);
}

EFI_STATUS
DcsLdrSetMokSBState(
    IN UINT8 MokSBState
)
{
    EFI_STATUS res;
    if (gDcsLdr == NULL) {
        res = InitDcsLdr();
        if (EFI_ERROR(res)) {
            return EFI_NOT_READY;
        }
    }

    return gDcsLdr->SetMokSBState(gDcsLdr, MokSBState);
}

EFI_STATUS
DcsLdrGetCertState(
    OUT UINT64* State
)
{
    EFI_STATUS res;
    if (gDcsLdr == NULL) {
        res = InitDcsLdr();
        if (EFI_ERROR(res)) {
            return EFI_NOT_READY;
        }
    }

    return gDcsLdr->GetCertState(gDcsLdr, State);
}