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
PXE-initialization
*/
EFI_STATUS
InitPxe(VOID)
{
	EFI_STATUS  res;
	EFI_HANDLE  deviceHandle;
	BOOLEAN fallback = FALSE;

	// First check if parent module set PXE state via variable
	res = InitPxe2();
	if(res != EFI_UNSUPPORTED) {
		return res;
	}

	// If not inherited, try to detect if we're booting from PXE
	res = UefiGetStartDevice(&deviceHandle);
	if (!EFI_ERROR(res)) {
		res = gBS->HandleProtocol(deviceHandle, &gEfiPxeBaseCodeProtocolGuid, (VOID**)&gPxeProtocol);
	}
	if (!EFI_ERROR(res) && gPxeProtocol != NULL && gPxeProtocol->Mode != NULL && gPxeProtocol->Mode->Started) {
		gPxeBoot = TRUE;
		gPxeUseIPv6 = gPxeProtocol->Mode->UsingIpv6;
	}
	else {
		return EFI_UNSUPPORTED;
	}

	// Get TFTP server IP from PXE mode - try multiple sources
	if (gPxeUseIPv6) {
		ZeroMem(&gPxeServerIp, sizeof(EFI_IP_ADDRESS));
		res = EFI_SUCCESS; // IPv6 auto-detection is normal
	} 
	else if (IsValidIPv4(gPxeProtocol->Mode->DhcpAck.Dhcpv4.BootpSiAddr)) { // when dhcp option 66 is set, as it shoudl be the ip is here
		CopyMem(&gPxeServerIp, gPxeProtocol->Mode->DhcpAck.Dhcpv4.BootpSiAddr, 4);
	}
	else if (IsValidIPv4(gPxeProtocol->Mode->ProxyOffer.Dhcpv4.BootpSiAddr)) {
		CopyMem(&gPxeServerIp, gPxeProtocol->Mode->ProxyOffer.Dhcpv4.BootpSiAddr, 4);
	}
	else if (IsValidIPv4(gPxeProtocol->Mode->PxeReply.Dhcpv4.BootpSiAddr)) {
		CopyMem(&gPxeServerIp, gPxeProtocol->Mode->PxeReply.Dhcpv4.BootpSiAddr, 4);
	}
	else { // fallback parse DHCP options to find option 54 (Server Identifier)
		res = EFI_INVALID_PARAMETER;
		UINT8* dhcpOptions = gPxeProtocol->Mode->DhcpAck.Dhcpv4.DhcpOptions;
		for (UINTN i = 0; i < sizeof(gPxeProtocol->Mode->DhcpAck.Dhcpv4.DhcpOptions) - 6; i++) {
			if (dhcpOptions[i] == 54 && dhcpOptions[i + 1] == 4 && IsValidIPv4(&dhcpOptions[i + 2])) {
				CopyMem(&gPxeServerIp, &dhcpOptions[i + 2], 4);
				fallback = TRUE;
				res = EFI_SUCCESS;
				break;
			}
			if (dhcpOptions[i] == 255) break; // End option
			if (dhcpOptions[i] == 0) continue; // Pad option
			if (i + 1 < sizeof(gPxeProtocol->Mode->DhcpAck.Dhcpv4.DhcpOptions)) {
				i += dhcpOptions[i + 1] + 1; // Skip option data
			}
		}
	}

	// Display PXE boot information
	if (gPxeUseIPv6) {
		// IPv6 display - typically uses auto-detection
		OUT_PRINT(L"PXE Boot (IPv6) - Client: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x, TFTP Server: auto-detect\n",
			gPxeProtocol->Mode->StationIp.v6.Addr[0], gPxeProtocol->Mode->StationIp.v6.Addr[1], gPxeProtocol->Mode->StationIp.v6.Addr[2], gPxeProtocol->Mode->StationIp.v6.Addr[3],
			gPxeProtocol->Mode->StationIp.v6.Addr[4], gPxeProtocol->Mode->StationIp.v6.Addr[5], gPxeProtocol->Mode->StationIp.v6.Addr[6], gPxeProtocol->Mode->StationIp.v6.Addr[7],
			gPxeProtocol->Mode->StationIp.v6.Addr[8], gPxeProtocol->Mode->StationIp.v6.Addr[9], gPxeProtocol->Mode->StationIp.v6.Addr[10], gPxeProtocol->Mode->StationIp.v6.Addr[11],
			gPxeProtocol->Mode->StationIp.v6.Addr[12], gPxeProtocol->Mode->StationIp.v6.Addr[13], gPxeProtocol->Mode->StationIp.v6.Addr[14], gPxeProtocol->Mode->StationIp.v6.Addr[15]);
	} else if (!EFI_ERROR(res)) {
		// IPv4 display
		OUT_PRINT(L"PXE Boot (IPv4) - Client: %d.%d.%d.%d, %s Server: %d.%d.%d.%d\n",
			gPxeProtocol->Mode->StationIp.v4.Addr[0], gPxeProtocol->Mode->StationIp.v4.Addr[1],
			gPxeProtocol->Mode->StationIp.v4.Addr[2], gPxeProtocol->Mode->StationIp.v4.Addr[3],
			fallback ? L"DHCP" : L"TFTP",
			gPxeServerIp.v4.Addr[0], gPxeServerIp.v4.Addr[1],
			gPxeServerIp.v4.Addr[2], gPxeServerIp.v4.Addr[3]);
	}
	else { // Server IP not found in DHCP options (IPv4 only)
		OUT_PRINT(L"PXE Boot (IPv4) - Client: %d.%d.%d.%d, TFTP Server: auto-detect\n",
			gPxeProtocol->Mode->StationIp.v4.Addr[0], gPxeProtocol->Mode->StationIp.v4.Addr[1],
			gPxeProtocol->Mode->StationIp.v4.Addr[2], gPxeProtocol->Mode->StationIp.v4.Addr[3]);
	}

	// Set PXE state variable so child modules can detect PXE boot
	// Store both IP and IPv6 flag in a structure
	DCS_PXE_STATE pxeState;

	CopyMem(&pxeState.ServerIp, &gPxeServerIp, sizeof(EFI_IP_ADDRESS));
	pxeState.UseIPv6 = gPxeUseIPv6;

	res = SetEfiVar(L"DcsPxeServerIp", &gEfiDcsLdrProtocolGuid, &pxeState, sizeof(DCS_PXE_STATE), EFI_VARIABLE_BOOTSERVICE_ACCESS);
#ifdef DEBUG_BUILD
	OUT_PRINT(L"InitPxe: SetEfiVar(DcsPxeServerIp) returned %r\n", res);
#endif
	return EFI_SUCCESS;
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
