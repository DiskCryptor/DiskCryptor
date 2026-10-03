/** @file
  FsUtils - EFI File System utility functions for DiskCryptor UEFI

  SPDX-License-Identifier: MIT

  Copyright (c) 2024-2026 DiskCryptor contributors

**/

#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>
#include <Library/PrintLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Guid/FileInfo.h>

#include "MiscUtilsLib.h"

//////////////////////////////////////////////////////////////////////////
// Global Variables
//////////////////////////////////////////////////////////////////////////

EFI_FILE    *gFileRoot = NULL;
EFI_HANDLE  gFileRootHandle = NULL;
EFI_HANDLE  *gFSHandles = NULL;
UINTN       gFSCount = 0;

//////////////////////////////////////////////////////////////////////////
// Core File Operations
//////////////////////////////////////////////////////////////////////////

/* InitFs */
EFI_STATUS
InitFs(
    VOID
)
{
    EFI_STATUS  Status;
    UINTN       BufferSize;

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

    Status = UefiGetStartDevice(&gFileRootHandle);
    if (!EFI_ERROR(Status)) {
        Status = FsFileOpenRoot(gFileRootHandle, &gFileRoot);
    }

    return Status;
}

/* FsFileOpenRoot */
EFI_STATUS
FsFileOpenRoot(
    IN  EFI_HANDLE  RootHandle,
    OUT EFI_FILE    **RootFile
    )
{
    EFI_STATUS                       Status;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *SimpleFileSystem;

    Status = gBS->HandleProtocol(
        RootHandle,
        &gEfiSimpleFileSystemProtocolGuid,
        (VOID **)&SimpleFileSystem
        );
    if (EFI_ERROR(Status)) {
        return Status;
    }

    return SimpleFileSystem->OpenVolume(SimpleFileSystem, RootFile);
}

/* FsFileOpen */
EFI_STATUS
FsFileOpen(
    IN  EFI_FILE   *Root,
    IN  CHAR16     *Name,
    OUT EFI_FILE   **File,
    IN  UINT64     Mode,
    IN  UINT64     Attributes
    )
{
    if (!Name || !File) {
        return EFI_INVALID_PARAMETER;
    }
    if (!Root) Root = gFileRoot;
    if (!Root) {
        return EFI_INVALID_PARAMETER;
    }
    if (Mode == 0) {
        Mode = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE;
    }

    return Root->Open(Root, File, Name, Mode, Attributes);
}

/* FsFileClose */
EFI_STATUS
FsFileClose(
    IN EFI_FILE  *File
    )
{
    if (!File) {
        return EFI_INVALID_PARAMETER;
    }
    return File->Close(File);
}

/* FsFileRead */
EFI_STATUS
FsFileRead(
    IN     EFI_FILE  *File,
    OUT    VOID      *Data,
    IN OUT UINTN     *Bytes,
    IN OUT UINT64    *Position  OPTIONAL
    )
{
    EFI_STATUS  Status;

    if (!File || !Data || !Bytes) {
        return EFI_INVALID_PARAMETER;
    }

    if (Position != NULL) {
        Status = File->SetPosition(File, *Position);
        if (EFI_ERROR(Status)) {
            return Status;
        }
    }

    Status = File->Read(File, Bytes, Data);

    if (Position != NULL) {
        File->GetPosition(File, Position);
    }

    return Status;
}

/* FsFileWrite */
EFI_STATUS
FsFileWrite(
    IN     EFI_FILE  *File,
    IN     VOID      *Data,
    IN     UINTN     Bytes,
    IN OUT UINT64    *Position  OPTIONAL
    )
{
    EFI_STATUS  Status;
    UINTN       Remaining;
    UINTN       WriteSize;
    UINT8       *Ptr;

    if (!File || !Data) {
        return EFI_INVALID_PARAMETER;
    }

    if (Position != NULL) {
        Status = File->SetPosition(File, *Position);
        if (EFI_ERROR(Status)) {
            return Status;
        }
    }

    Ptr = (UINT8 *)Data;
    Remaining = Bytes;
    WriteSize = Remaining;

    Status = File->Write(File, &WriteSize, Ptr);
    if (!EFI_ERROR(Status)) {
        Remaining -= WriteSize;
        Ptr += WriteSize;
        WriteSize = Remaining;
        while (Remaining > 0 && !EFI_ERROR(Status)) {
            Status = File->Write(File, &WriteSize, Ptr);
            Remaining -= WriteSize;
            Ptr += WriteSize;
            WriteSize = Remaining;
        }
    }

    if (Position != NULL) {
        File->GetPosition(File, Position);
    }

    return Status;
}

/* FsFileGetInfo */
EFI_STATUS
FsFileGetInfo(
    IN  EFI_FILE       *File,
    OUT EFI_FILE_INFO  **Info,
    OUT UINTN          *Size  OPTIONAL
    )
{
    EFI_STATUS  Status;
    UINTN       InfoSize;

    if (!File || !Info) {
        return EFI_INVALID_PARAMETER;
    }

    InfoSize = 0;
    Status = File->GetInfo(File, &gEfiFileInfoGuid, &InfoSize, NULL);
    if (Status != EFI_BUFFER_TOO_SMALL) {
        return Status;
    }

    *Info = (EFI_FILE_INFO *)MEM_ALLOC(InfoSize);
    if (*Info == NULL) {
        return EFI_OUT_OF_RESOURCES;
    }

    Status = File->GetInfo(File, &gEfiFileInfoGuid, &InfoSize, *Info);
    if (EFI_ERROR(Status)) {
        MEM_FREE(*Info);
        *Info = NULL;
        InfoSize = 0;
    }

    if (Size != NULL) {
        *Size = InfoSize;
    }

    return Status;
}

/* FsFileGetSize */
EFI_STATUS
FsFileGetSize(
    IN  EFI_FILE  *File,
    OUT UINTN     *Size
    )
{
    EFI_STATUS     Status;
    EFI_FILE_INFO  *Info;

    if (!File || !Size) {
        return EFI_INVALID_PARAMETER;
    }

    Info = NULL;
    Status = FsFileGetInfo(File, &Info, NULL);
    if (!EFI_ERROR(Status)) {
        *Size = (UINTN)Info->FileSize;
        MEM_FREE(Info);
    }

    return Status;
}

//////////////////////////////////////////////////////////////////////////
// Directory Operations
//////////////////////////////////////////////////////////////////////////

/* FsDirectoryCreate */
EFI_STATUS
FsDirectoryCreate(
    IN EFI_FILE  *Root,
    IN CHAR16    *Name
    )
{
    EFI_FILE    *File;
    EFI_STATUS  Status;

    if (!Name) {
        return EFI_INVALID_PARAMETER;
    }

    Status = FsFileOpen(Root, Name, &File,
        EFI_FILE_MODE_READ | EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE,
        EFI_FILE_DIRECTORY);
    if (EFI_ERROR(Status)) {
        return Status;
    }

    FsFileClose(File);
    return Status;
}

/* FsDirectoryExists */
EFI_STATUS
FsDirectoryExists(
    IN EFI_FILE  *Root,
    IN CHAR16    *Name
    )
{
    EFI_FILE    *File;
    EFI_STATUS  Status;

    if (!Name) {
        return EFI_INVALID_PARAMETER;
    }

    Status = FsFileOpen(Root, Name, &File, EFI_FILE_MODE_READ, EFI_FILE_DIRECTORY);
    if (EFI_ERROR(Status)) {
        return Status;
    }

    FsFileClose(File);
    return EFI_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
// File-Level Operations
//////////////////////////////////////////////////////////////////////////

/* FsFileExist */
EFI_STATUS
FsFileExist(
    IN EFI_FILE  *Root,
    IN CHAR16    *Name
    )
{
    EFI_STATUS  Status;
    EFI_FILE    *File;

    Status = FsFileOpen(Root, Name, &File, EFI_FILE_MODE_READ, 0);
    if (!EFI_ERROR(Status)) {
        FsFileClose(File);
        return EFI_SUCCESS;
    }

    return EFI_NOT_FOUND;
}

/* FsFileDelete */
EFI_STATUS
FsFileDelete(
    IN EFI_FILE  *Root,
    IN CHAR16    *Name
    )
{
    EFI_FILE    *File;
    EFI_STATUS  Status;

    if (!Name) {
        return EFI_INVALID_PARAMETER;
    }

    Status = FsFileOpen(Root, Name, &File, 0, 0);
    if (EFI_ERROR(Status)) {
        return Status;
    }

    return File->Delete(File);
}

/* FsFileLoad */
EFI_STATUS
EFIAPI
FsFileLoad(
    IN  EFI_FILE  *Root,
    IN  CHAR16    *Name,
    OUT VOID      **Data,
    OUT UINTN     *Size
    )
{
    EFI_STATUS  Status;
    EFI_FILE    *File;
    UINTN       FileSize;
    VOID        *Buffer;

    if (!Data) {
        return EFI_INVALID_PARAMETER;
    }

    *Data = NULL;
    if (Size != NULL) {
        *Size = 0;
    }

    Status = FsFileOpen(Root, Name, &File, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(Status)) {
        return Status;
    }

    Status = FsFileGetSize(File, &FileSize);
    if (EFI_ERROR(Status)) {
        FsFileClose(File);
        return Status;
    }

    if (FileSize == 0) {
        FsFileClose(File);
        return EFI_NOT_FOUND;
    }

    Buffer = MEM_ALLOC(FileSize);
    if (Buffer == NULL) {
        FsFileClose(File);
        return EFI_OUT_OF_RESOURCES;
    }

    Status = FsFileRead(File, Buffer, &FileSize, NULL);
    if (EFI_ERROR(Status)) {
        MEM_FREE(Buffer);
        FsFileClose(File);
        return Status;
    }

    FsFileClose(File);

    *Data = Buffer;
    if (Size != NULL) {
        *Size = FileSize;
    }

    return EFI_SUCCESS;
}

/* FsFileSave */
EFI_STATUS
EFIAPI
FsFileSave(
    IN EFI_FILE  *Root,
    IN CHAR16    *Name,
    IN VOID      *Data,
    IN UINTN     Size
    )
{
    EFI_STATUS  Status;
    EFI_FILE    *File;

    if (!Data || !Name) {
        return EFI_INVALID_PARAMETER;
    }

    FsFileDelete(Root, Name);

    Status = FsFileOpen(Root, Name, &File,
        EFI_FILE_MODE_READ | EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE, 0);
    if (EFI_ERROR(Status)) {
        return Status;
    }

    Status = FsFileWrite(File, Data, Size, NULL);
    FsFileClose(File);

    return Status;
}

/* FsFileRename */
EFI_STATUS
FsFileRename(
    IN EFI_FILE  *Root,
    IN CHAR16    *Src,
    IN CHAR16    *Dst
    )
{
    EFI_STATUS     Status;
    EFI_FILE       *File;
    EFI_FILE_INFO  *Info;
    EFI_FILE_INFO  *DstInfo;
    UINTN          DstNameSize;
    UINTN          DstInfoSize;

    if (!Src || !Dst) {
        return EFI_INVALID_PARAMETER;
    }

    Status = FsFileOpen(Root, Src, &File, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(Status)) {
        return Status;
    }

    Info = NULL;
    Status = FsFileGetInfo(File, &Info, NULL);
    if (EFI_ERROR(Status)) {
        FsFileClose(File);
        return Status;
    }

    DstNameSize = StrSize(Dst);
    DstInfoSize = SIZE_OF_EFI_FILE_INFO + DstNameSize;
    DstInfo = (EFI_FILE_INFO *)MEM_ALLOC(DstInfoSize);
    if (DstInfo == NULL) {
        MEM_FREE(Info);
        FsFileClose(File);
        return EFI_OUT_OF_RESOURCES;
    }

    CopyMem(DstInfo, Info, SIZE_OF_EFI_FILE_INFO);
    DstInfo->FileName[0] = 0;
    StrCatS(DstInfo->FileName, DstNameSize / sizeof(CHAR16), Dst);

    Status = File->SetInfo(File, &gEfiFileInfoGuid, DstInfoSize, DstInfo);

    MEM_FREE(Info);
    MEM_FREE(DstInfo);
    FsFileClose(File);

    return Status;
}

/* FsFileCopy */
EFI_STATUS
FsFileCopy(
    IN EFI_FILE  *SrcRoot,
    IN CHAR16    *Src,
    IN EFI_FILE  *DstRoot,
    IN CHAR16    *Dst,
    IN UINTN     BufSize
    )
{
    EFI_STATUS  Status;
    EFI_FILE    *SrcFile;
    EFI_FILE    *DstFile;
    UINTN       Remaining;
    UINTN       ChunkSize;
    CHAR8       *Buffer;

    SrcFile = NULL;
    DstFile = NULL;
    Buffer = NULL;

    Status = FsFileOpen(SrcRoot, Src, &SrcFile, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(Status)) {
        return Status;
    }

    Status = FsFileGetSize(SrcFile, &Remaining);
    if (EFI_ERROR(Status)) {
        goto Done;
    }

    Buffer = (CHAR8 *)MEM_ALLOC(BufSize);
    if (Buffer == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        goto Done;
    }

    FsFileDelete(DstRoot, Dst);
    Status = FsFileOpen(DstRoot, Dst, &DstFile,
        EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(Status)) {
        goto Done;
    }

    while (Remaining > 0) {
        ChunkSize = (Remaining > BufSize) ? BufSize : Remaining;
        Status = FsFileRead(SrcFile, Buffer, &ChunkSize, NULL);
        if (EFI_ERROR(Status)) {
            goto Done;
        }
        Status = FsFileWrite(DstFile, Buffer, ChunkSize, NULL);
        if (EFI_ERROR(Status)) {
            goto Done;
        }
        Remaining -= ChunkSize;
    }

Done:
    MEM_FREE(Buffer);
    if (SrcFile != NULL) FsFileClose(SrcFile);
    if (DstFile != NULL) FsFileClose(DstFile);

    return Status;
}

/* FsFileAsciiPrint */
STATIC CHAR8 mFsAsciiPrintBuffer[1024];

UINTN
FsFileAsciiPrint(
    IN EFI_FILE     *File,
    IN CONST CHAR8  *Format,
    ...
    )
{
    VA_LIST  Marker;
    UINTN   Len;

    if (File == NULL) {
        return 0;
    }

    VA_START(Marker, Format);
    Len = AsciiVSPrint(mFsAsciiPrintBuffer, sizeof(mFsAsciiPrintBuffer), Format, Marker);
    VA_END(Marker);

    File->Write(File, &Len, mFsAsciiPrintBuffer);
    return Len;
}
