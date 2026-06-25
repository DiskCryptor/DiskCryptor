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

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Protocol/PxeBaseCode.h>
#include <Protocol/LoadedImage.h>

#include "MiscUtilsLib.h"

//#define DEBUG_BUILD

typedef struct {
	EFI_IP_ADDRESS ServerIp;
	BOOLEAN UseIPv6;
} DCS_PXE_STATE;


BOOLEAN gPxeBoot = FALSE;
BOOLEAN gPxeUseIPv6 = FALSE;
//struct _EFI_PXE_BASE_CODE_PROTOCOL* gPxeProtocol = NULL;
static EFI_PXE_BASE_CODE_PROTOCOL* gPxeProtocol = NULL;
EFI_IP_ADDRESS gPxeServerIp;


/**
* Validate IPv4 address
*/
BOOLEAN
IsValidIPv4(
	IN	UINT8* ip
)
{
	if (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0) {
		return FALSE;
	}
	return TRUE;
}

/**
* Check if we should use auto-server detection
*/
BOOLEAN
ShouldUseAutoServer(VOID)
{
	if (gPxeUseIPv6) {
		return TRUE;
	} else {
		return !IsValidIPv4(gPxeServerIp.v4.Addr);
	}
}

/**
Download a file from TFTP server using PXE
*/
EFI_STATUS
PxeDownloadFile(
	IN  CHAR16*  FilePath,
	OUT VOID**   Buffer,
	OUT UINTN*   BufferSize
	)
{
	EFI_STATUS res;
	UINT64 size64;
	CHAR8 *asciiPath;
	UINTN pathLen;

	if (!gPxeBoot || !gPxeProtocol) {
		return EFI_NOT_READY;
	}

	// Convert CHAR16 path to CHAR8 and convert backslashes to forward slashes for TFTP
	pathLen = StrLen(FilePath);
	asciiPath = MEM_ALLOC(pathLen + 1);
	if (!asciiPath) {
		return EFI_OUT_OF_RESOURCES;
	}

	for (UINTN i = 0; i <= pathLen; i++) {
		if (FilePath[i] == L'\\') {
			asciiPath[i] = '/';  // Convert backslash to forward slash for TFTP
		} else {
			asciiPath[i] = (CHAR8)FilePath[i];
		}
	}

	// First get file size
	size64 = 0;
	res = gPxeProtocol->Mtftp(
		gPxeProtocol,
		EFI_PXE_BASE_CODE_TFTP_GET_FILE_SIZE,
		NULL,
		gPxeUseIPv6,
		&size64,
		NULL,
		ShouldUseAutoServer() ? NULL : &gPxeServerIp,
		(UINT8*)asciiPath,
		NULL,
		FALSE
		);

	if (EFI_ERROR(res)) {
		MEM_FREE(asciiPath);
		return res;
	}

	// Allocate buffer
	*BufferSize = (UINTN)size64;
	*Buffer = MEM_ALLOC(*BufferSize);
	if (!*Buffer) {
		MEM_FREE(asciiPath);
		return EFI_OUT_OF_RESOURCES;
	}

	// Download file
#ifdef DEBUG_BUILD
	OUT_PRINT(L"Downloading %s (%d KB)...\n", FilePath, (*BufferSize + 1023) / 1024);
#endif
	res = gPxeProtocol->Mtftp(
		gPxeProtocol,
		EFI_PXE_BASE_CODE_TFTP_READ_FILE,
		*Buffer,
		gPxeUseIPv6,
		&size64,
		NULL,
		ShouldUseAutoServer() ? NULL : &gPxeServerIp,
		(UINT8*)asciiPath,
		NULL,
		FALSE
		);

	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Failed to download %s: %r\n", FilePath, res);
		MEM_FREE(*Buffer);
		*Buffer = NULL;
		*BufferSize = 0;
	}

	MEM_FREE(asciiPath);
	return res;
}

/**
Upload a file to TFTP server using PXE
*/
EFI_STATUS
PxeUploadFile(
	IN CHAR16*  FilePath,
	IN VOID*    Buffer,
	IN UINTN    BufferSize
	)
{
	EFI_STATUS res;
	UINT64 size64;
	CHAR8 *asciiPath;
	UINTN pathLen;

	if (!gPxeBoot || !gPxeProtocol) {
		return EFI_NOT_READY;
	}

	if (!Buffer || BufferSize == 0) {
		return EFI_INVALID_PARAMETER;
	}

	// Convert CHAR16 path to CHAR8 and convert backslashes to forward slashes for TFTP
	pathLen = StrLen(FilePath);
	asciiPath = MEM_ALLOC(pathLen + 1);
	if (!asciiPath) {
		return EFI_OUT_OF_RESOURCES;
	}

	for (UINTN i = 0; i <= pathLen; i++) {
		if (FilePath[i] == L'\\') {
			asciiPath[i] = '/';  // Convert backslash to forward slash for TFTP
		} else {
			asciiPath[i] = (CHAR8)FilePath[i];
		}
	}

	size64 = BufferSize;

	// Upload file
#ifdef DEBUG_BUILD
	OUT_PRINT(L"Uploading %s (%d KB)...\n", FilePath, (BufferSize + 1023) / 1024);
#endif
	res = gPxeProtocol->Mtftp(
		gPxeProtocol,
		EFI_PXE_BASE_CODE_TFTP_WRITE_FILE,
		Buffer,
		gPxeUseIPv6,
		&size64,
		NULL,
		ShouldUseAutoServer() ? NULL : &gPxeServerIp,
		(UINT8*)asciiPath,
		NULL,
		FALSE
		);

	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Failed to upload %s: %r\n", FilePath, res);
	}

	MEM_FREE(asciiPath);
	return res;
}

/**
Check if a file exists via TFTP
*/
EFI_STATUS
PxeFileExist(
	IN CHAR16* FilePath
	)
{
	EFI_STATUS res;
	UINT64 size64 = 0;
	CHAR8 *asciiPath;
	UINTN pathLen;

	if (!gPxeBoot || !gPxeProtocol) {
		return EFI_NOT_READY;
	}

	// Convert CHAR16 path to CHAR8 and convert backslashes to forward slashes for TFTP
	pathLen = StrLen(FilePath);
	asciiPath = MEM_ALLOC(pathLen + 1);
	if (!asciiPath) {
		return EFI_OUT_OF_RESOURCES;
	}

	for (UINTN i = 0; i <= pathLen; i++) {
		if (FilePath[i] == L'\\') {
			asciiPath[i] = '/';  // Convert backslash to forward slash for TFTP
		} else {
			asciiPath[i] = (CHAR8)FilePath[i];
		}
	}

	// Try to get file size
	res = gPxeProtocol->Mtftp(
		gPxeProtocol,
		EFI_PXE_BASE_CODE_TFTP_GET_FILE_SIZE,
		NULL,
		gPxeUseIPv6,
		&size64,
		NULL,
		ShouldUseAutoServer() ? NULL : &gPxeServerIp,
		(UINT8*)asciiPath,
		NULL,
		FALSE
		);

	MEM_FREE(asciiPath);
	return res;
}

/**
Downloades and EFI from TFTP server and executes it
*/
EFI_STATUS
PxeExec(
	IN CHAR16* path
	)
{
	EFI_STATUS res;
	VOID* fileBuffer = NULL;
	UINTN fileSize = 0;
	EFI_HANDLE imageHandle = NULL;

  if (!gPxeBoot) {
    return EFI_NOT_READY;
  }


	// Download file from TFTP server
	res = PxeDownloadFile(path, &fileBuffer, &fileSize);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Failed to download %s via TFTP: %r\n", path, res);
		return res;
	}

	// Load image from memory
	res = gBS->LoadImage(
		FALSE,
		gImageHandle,
		NULL,
		fileBuffer,
		fileSize,
		&imageHandle
		);

	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Failed to load image: %r\n", res);
		MEM_FREE(fileBuffer);
		return res;
	}

	// Start the image
	res = gBS->StartImage(imageHandle, NULL, NULL);

	MEM_FREE(fileBuffer);
	return res;
}

/**
PXE-aware FileCopy - copies from TFTP if in PXE mode, otherwise from local disk
*/
EFI_STATUS
PxeFileCopy(
	IN CHAR16* src,
	IN EFI_FILE* dstroot,
	IN CHAR16* dst
	)
{
	EFI_STATUS res;

  if (!gPxeBoot) {
    return EFI_NOT_READY;
  }

	// Download from TFTP and save to destination
	VOID* fileBuffer = NULL;
	UINTN fileSize = 0;
	res = PxeDownloadFile(src, &fileBuffer, &fileSize);
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Failed to download %s: %r\n", src, res);
		return res;
	}
	res = SimpleFileSave(dstroot, dst, fileBuffer, fileSize);
	MEM_FREE(fileBuffer);
	return res;
}

/**
PXE-initialization 2nd stage - inherit PXE state from caller via variable
*/
EFI_STATUS
InitPxe2(VOID)
{
	EFI_STATUS  res;
	UINTN       len;
	UINT32      attr;
	CHAR16*     tmp = NULL;

	res = GetEfiVar(L"DcsPxeServerIp", &gEfiDcsLdrProtocolGuid, &tmp, &len, &attr);
#ifdef DEBUG_BUILD
	OUT_PRINT(L"InitPxe2: GetEfiVar(DcsPxeServerIp) returned %r, len=%d\n", res, len);
#endif
	if (!EFI_ERROR(res)) {
		// Retrieve both IP and IPv6 flag from the structure
		DCS_PXE_STATE *pxeState = (DCS_PXE_STATE*)tmp;

		CopyMem(&gPxeServerIp, &pxeState->ServerIp, sizeof(EFI_IP_ADDRESS));
		gPxeUseIPv6 = pxeState->UseIPv6;

		// Parent was in PXE mode, inherit the state, search for PXE protocol on available handles
		EFI_HANDLE* handles = NULL;
		UINTN handleCount = 0;
		res = gBS->LocateHandleBuffer(
			ByProtocol,
			&gEfiPxeBaseCodeProtocolGuid,
			NULL,
			&handleCount,
			&handles
		);

		if (!EFI_ERROR(res) && handleCount > 0) {
			// Use the first PXE handle found
			res = gBS->HandleProtocol(handles[0], &gEfiPxeBaseCodeProtocolGuid, (VOID**)&gPxeProtocol);
			if (!EFI_ERROR(res) && gPxeProtocol != NULL) {
				gPxeBoot = TRUE;
#ifdef DEBUG_BUILD
				if (gPxeUseIPv6) {
					OUT_PRINT(L"PXE Boot (inherited, IPv6) - TFTP Server: auto-detect\n");
				} else {
					OUT_PRINT(L"PXE Boot (inherited, IPv4) - TFTP Server: %d.%d.%d.%d\n",
						gPxeServerIp.v4.Addr[0], gPxeServerIp.v4.Addr[1],
						gPxeServerIp.v4.Addr[2], gPxeServerIp.v4.Addr[3]);
				}
#endif
			}
		}

		if (handles != NULL) {
			FreePool(handles);
		}

		if(gPxeBoot)
			return EFI_SUCCESS;
		return EFI_NOT_READY;
	}

	return EFI_UNSUPPORTED;
}

/**
Check if currently booted via PXE
*/
BOOLEAN
IsPxeBoot(
	VOID
	)
{
	return gPxeBoot;
}

/**
Get the PXE server IP address
*/
EFI_STATUS
PxeGetServerIp(
	OUT EFI_IP_ADDRESS* ServerIp
	)
{
	if (!gPxeBoot) {
		return EFI_NOT_READY;
	}
	if (ServerIp != NULL) {
		CopyMem(ServerIp, &gPxeServerIp, sizeof(EFI_IP_ADDRESS));
	}
	return EFI_SUCCESS;
}
