/** @file
EFI file system helpers

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 

This program and the accompanying materials are licensed and made available
under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Uefi.h>
#include <Library/CommonLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Guid/FileInfo.h>
#include <Guid/FileSystemInfo.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>

//////////////////////////////////////////////////////////////////////////
// EFI file 
//////////////////////////////////////////////////////////////////////////

EFI_FILE*      gFileRoot = NULL;
EFI_HANDLE     gFileRootHandle = NULL;

EFI_HANDLE* gFSHandles = NULL;
UINTN       gFSCount = 0;

EFI_STATUS
InitFS() {
   EFI_STATUS  res;
   EfiGetHandles(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, 0, &gFSHandles, &gFSCount);
   res = EfiGetStartDevice(&gFileRootHandle);
   if (!EFI_ERROR(res)) {
      res = FileOpenRoot(gFileRootHandle, &gFileRoot);
   }
   return res;
}

EFI_STATUS
DirectoryCreate(
   IN    EFI_FILE*   root,
   IN    CHAR16*     name
   )
{
   EFI_FILE*      file;
   EFI_STATUS     res;
   if (!name) { return EFI_INVALID_PARAMETER; }

   res = FileOpen(root, name, &file, EFI_FILE_MODE_READ | EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE, EFI_FILE_DIRECTORY);
   if (EFI_ERROR(res)) return res;
   FileClose(file);
   return res;
}

EFI_STATUS
DirectoryExists(
   IN    EFI_FILE*   root,
   IN    CHAR16*     name
   )
{
   EFI_FILE*      file;
   EFI_STATUS     res;
   if (!name) { return EFI_INVALID_PARAMETER; }

   res = FileOpen(root, name, &file, EFI_FILE_MODE_READ, EFI_FILE_DIRECTORY);
   if (EFI_ERROR(res)) return res;
   FileClose(file);
   return EFI_SUCCESS;
}

EFI_STATUS
FileOpenRoot(
   IN    EFI_HANDLE rootHandle,
   OUT   EFI_FILE** rootFile)
{
   EFI_STATUS res = 0;
   EFI_FILE_IO_INTERFACE* fSysProtocol = NULL;
   res = gBS->HandleProtocol(rootHandle, &gEfiSimpleFileSystemProtocolGuid, (VOID**)&fSysProtocol);
   if (res == RETURN_SUCCESS && fSysProtocol != NULL) {
      res = fSysProtocol->OpenVolume(fSysProtocol, rootFile);
   }
   return res;
}

EFI_STATUS 
FileOpen(
   IN    EFI_FILE*   root, 
   IN    CHAR16*     name,
   OUT   EFI_FILE**  file,
   IN    UINT64      mode,
   IN    UINT64      attributes
   )
{
   EFI_STATUS res;

   if (!name || !file) { return EFI_INVALID_PARAMETER; }
   if (!root) root = gFileRoot;
   if (!root) { return EFI_INVALID_PARAMETER; }
   if (mode == 0) {
      mode = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE;
   }
   res = root->Open(root, file, name, mode , attributes);
   return res;
}

EFI_STATUS 
FileClose(
   IN EFI_FILE* f) 
{
   if (!f) { return EFI_INVALID_PARAMETER; }
   return f->Close(f);
}

EFI_STATUS 
FileDelete(
   IN    EFI_FILE*   root,
   IN    CHAR16*     name
   )
{
   EFI_FILE*      f;
   EFI_STATUS res;
   if (!name) { return EFI_INVALID_PARAMETER; }
   res = FileOpen(root, name, &f, 0, 0);
   if (EFI_ERROR(res)) {
      return res;
   }
   res = f->Delete(f);
//   f->Close(f);
   return res;
}

EFI_STATUS 
FileRead(
   IN       EFI_FILE*   f, 
   OUT      VOID*       data, 
   IN OUT   UINTN*      bytes,
   IN OUT   UINT64*     position)
{
   EFI_STATUS res;

   if (!f || !data || !bytes) { 
      return EFI_INVALID_PARAMETER; 
   }
   if (position != NULL) {
      res = f->SetPosition(f, *position);
      if (EFI_ERROR(res)) { 
         return res; 
      }
   }
   res = f->Read(f, bytes, data);
   if (position != NULL) {
      f->GetPosition(f, position);
   }
   return res;
}

EFI_STATUS 
FileWrite(
   IN       EFI_FILE*   f, 
   IN       VOID*       data,
   IN OUT   UINTN      bytes, 
   IN OUT   UINT64*     position) 
{
   EFI_STATUS res;
   UINTN remaining;
   UINT8* pbData = (UINT8*) data;

   if (!f || !data) { 
      return EFI_INVALID_PARAMETER; 
   }
   if (position != NULL) {
      res = f->SetPosition(f, *position);
      if (EFI_ERROR(res)) {
         return res;
      }
   }
   remaining = bytes;
   res = f->Write(f, &bytes, pbData);
   if (!EFI_ERROR(res)) {
	   remaining -= bytes;
	   pbData += bytes;
	   bytes = remaining;
	   while ((remaining > 0) && !EFI_ERROR(res))
	   {
		   res = f->Write(f, &bytes, pbData);
		   remaining -= bytes;
		   pbData += bytes;
		   bytes = remaining;
 	   }
   }
   if (position != NULL) {
      f->GetPosition(f, position);
   }
   return res;
}

CHAR8 gFileAsciiPrintBuffer[1024];

UINTN
FileAsciiPrint(
	IN EFI_FILE            *f,
	IN CONST CHAR8         *format,
	...
	) {
	VA_LIST  marker;
	UINTN    len;
	if (f == NULL) return 0;
	VA_START(marker, format);
	len = AsciiVSPrint((CHAR8*)gFileAsciiPrintBuffer, sizeof(gFileAsciiPrintBuffer), format, marker);
	VA_END(marker);
	f->Write(f, &len, gFileAsciiPrintBuffer);
	return len;
}

EFI_STATUS
FileGetInfo(
   IN    EFI_FILE*         f,
   OUT   EFI_FILE_INFO**   info,
   OUT   UINTN*            size
   )
{
   EFI_STATUS     res;
   UINTN          sz = 0;
   if (!f || !info) { return EFI_INVALID_PARAMETER; }
   res = f->GetInfo(f, &gEfiFileInfoGuid, &sz, NULL);
   if (res == RETURN_BUFFER_TOO_SMALL) {
      *info = (EFI_FILE_INFO*)MEM_ALLOC(sz);
      if (!(*info)) {
         return res;
      }
      res = f->GetInfo(f, &gEfiFileInfoGuid, &sz, *info);
      if (EFI_ERROR(res)) {
         MEM_FREE(*info);
         *info = NULL;
         sz = 0;
      }
   }
   if (size) {
      *size = sz;
   }
   return res;
}

EFI_STATUS 
FileGetSize(
   IN    EFI_FILE*   f,
   OUT   UINTN*     size
   ) 
{
   EFI_STATUS  res;
   EFI_FILE_INFO* info = NULL;
   if (!f || !size) { return EFI_INVALID_PARAMETER; }
   res = FileGetInfo(f, &info, NULL);
   if (!EFI_ERROR(res)) {
      *size = (UINTN)info->FileSize;
      MEM_FREE(info);
   }
   return res;
}

EFI_STATUS 
FileLoad(
   IN    EFI_FILE*   root,
   IN    CHAR16*     name,
   OUT   VOID**      data,
   OUT   UINTN*      size
   )
{
   EFI_FILE*      file;
   EFI_STATUS     res;
   UINTN          sz;
   UINTN          allocSz;
   if (!data) { 
      return EFI_INVALID_PARAMETER; 
   }
   res = FileOpen(root, name, &file, EFI_FILE_MODE_READ, 0);
   if (EFI_ERROR(res)) return res;
   res = FileGetSize(file, &sz);
   if (EFI_ERROR(res)) {
      FileClose(file);
      return res;
   }
   if (sz > MAX_UINTN - sizeof(CHAR16)) {
      FileClose(file);
      return EFI_BAD_BUFFER_SIZE;
   }
   // Zeroed extra bytes keep text callers (config XML) NUL-terminated; *size stays the file size
   allocSz = sz + sizeof(CHAR16);
   *data = MEM_ALLOC(allocSz);
   if (*data == NULL) {
      FileClose(file);
      return EFI_BUFFER_TOO_SMALL;
   }
   res = FileRead(file, *data, &sz, NULL);
   if (EFI_ERROR(res)) {
      FileClose(file);
      MEM_BURN(*data, allocSz);
      MEM_FREE(*data);
      *data = NULL;
      return res;
   }
   FileClose(file);
   if (size != NULL) { 
      *size = sz; 
   }
   return res;
}

EFI_STATUS
FileSave(
   IN    EFI_FILE*   root,
   IN    CHAR16*     name,
   IN    VOID*       data,
   IN    UINTN      size
   )
{
   EFI_FILE*      file;
   EFI_STATUS     res;
   if (!data || !name) { return EFI_INVALID_PARAMETER; }
   FileDelete(root, name);
   res = FileOpen(root, name, &file, EFI_FILE_MODE_READ | EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE, 0);
   if (EFI_ERROR(res)) return res;
   res = FileWrite(file, data, size, NULL);
   FileClose(file);
   return res;
}

EFI_STATUS
FileExist(
	IN    EFI_FILE*   root,
	IN    CHAR16*     name)
{
	EFI_FILE*      file;
	EFI_STATUS     res;
	res = FileOpen(root, name, &file, EFI_FILE_MODE_READ, 0);
	if (EFI_ERROR(res)) return res;
	FileClose(file);
	return EFI_SUCCESS;
}

EFI_STATUS
FileRename(
	IN    EFI_FILE*   root,
	IN    CHAR16*     src,
	IN    CHAR16*     dst)
{
	EFI_STATUS     res;
	EFI_FILE*      file;
	EFI_FILE_INFO* info = NULL;
	UINTN          sz;
	EFI_FILE_INFO* dstinfo = NULL;
	UINTN          dstinfosz;

	res = FileOpen(root, src, &file, EFI_FILE_MODE_READ, 0);
	if (EFI_ERROR(res)) return res;
	res = FileGetInfo(file, &info, &sz);
	if (EFI_ERROR(res)) return res;
	sz = StrSize(dst);
	dstinfosz = SIZE_OF_EFI_FILE_INFO + sz;
	dstinfo = (EFI_FILE_INFO*)MEM_ALLOC(dstinfosz);
	if (dstinfo != NULL) {
		CopyMem(dstinfo, info, SIZE_OF_EFI_FILE_INFO);
		dstinfo->FileName[0] = 0;
		StrCatS(dstinfo->FileName, sz, dst);
		res = file->SetInfo(file, &gEfiFileInfoGuid, dstinfosz, dstinfo);
	}	else {
		res = EFI_BUFFER_TOO_SMALL;
	}

	MEM_FREE(info);
	MEM_FREE(dstinfo);
	FileClose(file);
	return res;
}

EFI_STATUS
FileCopy(
	IN    EFI_FILE*   srcroot,
	IN    CHAR16*     src,
	IN    EFI_FILE*   dstroot,
	IN    CHAR16*     dst,
	IN    UINTN       bufSz
	)
{
	EFI_STATUS     res;
	EFI_FILE*      srcfile = NULL;
	EFI_FILE*      dstfile = NULL;
	UINTN          remains;
	CHAR8*         data = NULL;
	UINTN          datasz = bufSz;

	res = FileOpen(srcroot, src, &srcfile, EFI_FILE_MODE_READ, 0);
	if (EFI_ERROR(res)) return res;
	res = FileGetSize(srcfile, &remains);
	if (EFI_ERROR(res)) return res;

	data = (CHAR8*)MEM_ALLOC(bufSz);
	if (data == NULL) {
		res = EFI_BUFFER_TOO_SMALL;
		goto copyerr;
	}
	
	FileDelete (dstroot, dst);
	res = FileOpen(dstroot, dst, &dstfile, EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ, 0);
	if (EFI_ERROR(res)) goto copyerr;

	do {
		datasz = remains > bufSz ? bufSz : remains;
		res =FileRead(srcfile, data, &datasz, NULL);
		if (EFI_ERROR(res)) goto copyerr;
		res = FileWrite(dstfile, data, datasz, NULL);
		if (EFI_ERROR(res)) goto copyerr;
		remains -= datasz;
	} while (remains > 0);

copyerr:
	MEM_FREE(data);
	FileClose(srcfile);
	FileClose(dstfile);
	return res;
}
