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

UINTN       gCELine = 0;

//////////////////////////////////////////////////////////////////////////
// String Utilities
//////////////////////////////////////////////////////////////////////////

/* StrCmpI */
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

//////////////////////////////////////////////////////////////////////////
// EFI Variable Helpers
//////////////////////////////////////////////////////////////////////////

/* GetEfiVar */
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

    Data = AllocateZeroPool(DataSize);
    if (Data == NULL) {
        return EFI_OUT_OF_RESOURCES;
    }

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

/* SetEfiVar */
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

/* UefiGetStartDevice */
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
// File System Initialization & Dispatch
//////////////////////////////////////////////////////////////////////////

/* UefiFileDeletePath */
EFI_STATUS
UefiFileDeletePath(
    IN CONST CHAR16 *FilePath
    )
{
    if (IsPxeBoot()) {
        return EFI_UNSUPPORTED;
    }
    return FsFileDelete(NULL, (CHAR16*)FilePath);
}

/* UefiFileExistsPath */
BOOLEAN
UefiFileExistsPath(
    IN CONST CHAR16 *FilePath
    )
{
    if (IsPxeBoot()) {
        return !EFI_ERROR(PxeFileExist((CHAR16*)FilePath));
    }
    return !EFI_ERROR(FsFileExist(NULL, (CHAR16*)FilePath));
}

/* UefiFileReadPath */
EFI_STATUS
UefiFileReadPath(
    IN     CONST CHAR16 *FilePath,
    OUT    UINT8        **Buffer,
    IN OUT UINT32       *BufferSize
    )
{
    EFI_STATUS ret;
    VOID       *fileData = NULL;
    UINTN      fileSize = 0;

    if (IsPxeBoot()) {
        ret = PxeDownloadFile((CHAR16*)FilePath, &fileData, &fileSize);
    } else {
        ret = FsFileLoad(NULL, (CHAR16*)FilePath, &fileData, &fileSize);
    }

    if (EFI_ERROR(ret)) {
        return ret;
    }

    if (fileData == NULL || fileSize == 0) {
        if (fileData) MEM_FREE(fileData);
        return EFI_NOT_FOUND;
    }

    *Buffer = (UINT8*)fileData;
    *BufferSize = (UINT32)fileSize;

    return EFI_SUCCESS;
}

/* UefiFileWritePath */
EFI_STATUS
UefiFileWritePath(
    IN CONST CHAR16 *FilePath,
    IN UINT8        *Buffer,
    IN UINT32       BufferSize
    )
{
    EFI_STATUS ret;

    if (IsPxeBoot()) {
        ret = PxeUploadFile((CHAR16*)FilePath, Buffer, BufferSize);
    } else {
        FsDirectoryCreate(gFileRoot, L"\\EFI\\DCS");
        ret = FsFileSave(gFileRoot, (CHAR16*)FilePath, Buffer, BufferSize);
    }

    return ret;
}

/* EfiExecEx */
STATIC
EFI_STATUS
EfiExecEx(
   IN    EFI_HANDLE  deviceHandle,
   IN    CHAR16*     path,
   IN    VOID*       LoadOptions,
   IN    UINTN       LoadOptionsSize
   )
{
   EFI_STATUS                  Status;
   EFI_DEVICE_PATH*            DevicePath;
   EFI_HANDLE                  ImageHandle;
   EFI_LOADED_IMAGE_PROTOCOL   *LoadedImage;
   UINTN                       ExitDataSize;
   CHAR16                      *ExitData;

   if (deviceHandle == NULL) {
      deviceHandle = gFileRootHandle;
   }
   if (!path || !deviceHandle) return EFI_INVALID_PARAMETER;
   DevicePath = FileDevicePath(deviceHandle, path);

   Status = gBS->LoadImage(FALSE, gImageHandle, DevicePath, NULL, 0, &ImageHandle);
   if (EFI_ERROR(Status)) {
      return Status;
   }

   // Pass LoadOptions to the loaded image
   if (LoadOptions != NULL && LoadOptionsSize > 0) {
       Status = gBS->HandleProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID**)&LoadedImage);
      if (!EFI_ERROR(Status) && LoadedImage != NULL) {
         LoadedImage->LoadOptions = LoadOptions;
         LoadedImage->LoadOptionsSize = (UINT32)LoadOptionsSize;
      }
   }

   Status = gBS->StartImage(ImageHandle, &ExitDataSize, &ExitData);

   return Status;
}

/* UefiExecEx */
EFI_STATUS
UefiExecEx(
    IN    CHAR16*     path,
    IN    VOID*       LoadOptions      OPTIONAL,
    IN    UINTN       LoadOptionsSize
    )
{
    if (IsPxeBoot()) {
        return PxeExecEx(path, LoadOptions, LoadOptionsSize);
    } else {
        return EfiExecEx(NULL, path, LoadOptions, LoadOptionsSize);
    }
}

/* UefiExec */
EFI_STATUS
UefiExec(
    IN CHAR16  *path
    )
{
    return UefiExecEx(path, NULL, 0);
}

//////////////////////////////////////////////////////////////////////////
// SMBIOS / UUID
//////////////////////////////////////////////////////////////////////////

/* SmbiosGetNextStructure */
STATIC
SMBIOS_STRUCTURE_POINTER
SmbiosGetNextStructure (
    IN SMBIOS_STRUCTURE_POINTER  Current
    )
{
    SMBIOS_STRUCTURE_POINTER  Next;
    UINT8                     *Ptr;

    Ptr = (UINT8 *)Current.Raw + Current.Hdr->Length;

    while (Ptr[0] != 0 || Ptr[1] != 0) {
        Ptr++;
    }

    Next.Raw = Ptr + 2;
    return Next;
}

/* SmbiosFindStructure */
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

/* GetSystemUuid */
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

//////////////////////////////////////////////////////////////////////////
// DCS Ldr
//////////////////////////////////////////////////////////////////////////

EFI_GUID gEfiDcsLdrProtocolGuid = EFI_DCS_LDR_PROTOCOL_GUID;
EFI_DCS_LDR_PROTOCOL* gDcsLdr = NULL;

/* InitDcsLdr */
EFI_STATUS
InitDcsLdr(
    VOID
    )
{
    EFI_STATUS res;
    res = gBS->LocateProtocol(&gEfiDcsLdrProtocolGuid, NULL, (VOID**)&gDcsLdr);
    return res;
}

/* DcsLdrGetMokSBState */
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

/* DcsLdrSetMokSBState */
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

/* DcsLdrGetCertState */
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

/* IsSecureBootEnabled */
BOOLEAN
IsSecureBootEnabled(
    VOID
    )
{
    EFI_STATUS  Status;
    UINT8       *SecureBoot = NULL;
    UINTN       Size = 0;
    UINT32      Attr = 0;
    BOOLEAN     Enabled = FALSE;

    Status = GetEfiVar(L"SecureBoot", &gEfiGlobalVariableGuid, (VOID**)&SecureBoot, &Size, &Attr);
    if (!EFI_ERROR(Status) && SecureBoot != NULL && Size == sizeof(UINT8)) {
        Enabled = (*SecureBoot == 1);
        MEM_FREE(SecureBoot);
    }

    // check if shim has disabled all verification
    UINT8 sbState = 0;
    if (!EFI_ERROR(DcsLdrGetMokSBState(&sbState)) && sbState == 1) {
        return FALSE;
    }

    return Enabled;
}