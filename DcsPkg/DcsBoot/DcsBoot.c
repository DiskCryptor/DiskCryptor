/** @file
  This is DCS boot loader application

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI
Copyright (c) 2019-2026. DiskCryptor, David Xanatos

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Uefi.h>
#include <Library/CommonLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>
#include "../DcsTpm/DcsTpmProto.h"
#include <Protocol/DcsOwnerProto.h>
#include <DcsConfig.h>
#include <Guid/Gpt.h>
#include <Guid/GlobalVariable.h>
#include "../Library/MiscUtilsLib/MiscUtilsLib.h"
#include "../DcsOwner/DcsOwner.h"

EFI_GUID          ImagePartGuid;
EFI_GUID          *gEfiExecPartGuid = &ImagePartGuid;
CHAR16            *gEfiExecCmdDefault = L"\\EFI\\Microsoft\\Boot\\Bootmgfw_ms.vc";
CHAR16            *gEfiExecCmdMS = L"\\EFI\\Microsoft\\Boot\\Bootmgfw.efi";
CHAR16            *gEfiExecCmd = NULL;
CHAR8             gDoExecCmdMsg[256];
CONST CHAR8*      g_szMsBootString = "bootmgfw.pdb";

//////////////////////////////////////////////////////////////////////////
// EFI boot
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
DoExecCmd()
{
	EFI_STATUS          res;
	gDoExecCmdMsg[0] = 0;
	res = EfiFindPartByGUID(gEfiExecPartGuid, &gFileRootHandle);
	if (!EFI_ERROR(res)) {
		res = FileOpenRoot(gFileRootHandle, &gFileRoot);
		if (!EFI_ERROR(res)) {
			res = EfiExec(NULL, gEfiExecCmd);
			if (EFI_ERROR(res))
				AsciiSPrint(gDoExecCmdMsg, sizeof(gDoExecCmdMsg), "\nCannot execute %s start partition %g\n", gEfiExecCmd, gEfiExecPartGuid);
			else
				AsciiSPrint(gDoExecCmdMsg, sizeof(gDoExecCmdMsg), "\nDone executing %s start partition %g\n", gEfiExecCmd, gEfiExecPartGuid);
		}	else {
			AsciiSPrint(gDoExecCmdMsg, sizeof(gDoExecCmdMsg), "\nCannot open start partition %g\n", gEfiExecPartGuid);
		}
	}	else {
		AsciiSPrint(gDoExecCmdMsg, sizeof(gDoExecCmdMsg), "\nCannot find start partition %g\n", gEfiExecPartGuid);
	}
	return res;
}

/**
 * Try to execute the Windows bootloader from a specific partition handle.
 * Returns EFI_SUCCESS if executed, error otherwise.
 */
STATIC EFI_STATUS
TryWindowsLoaderOnPartition(
	IN EFI_HANDLE  PartHandle
	)
{
	EFI_STATUS  res;
	EFI_FILE    *root = NULL;
	EFI_FILE    *savedRoot = gFileRoot;
	EFI_HANDLE  savedHandle = gFileRootHandle;

	res = FileOpenRoot(PartHandle, &root);
	if (EFI_ERROR(res))
		return res;

	gFileRoot = root;
	gFileRootHandle = PartHandle;

	if (!EFI_ERROR(FileExist(NULL, gEfiExecCmdDefault))) {
		res = EfiExec(NULL, gEfiExecCmdDefault);
		if (!EFI_ERROR(res))
			return res;
	}

	if (!EFI_ERROR(FileExist(NULL, gEfiExecCmdMS))) {
		UINT8*  fileData = NULL;
		UINTN   fileSize = 0;
		BOOLEAN bFound = FALSE;
		if (!EFI_ERROR(FileLoad(NULL, gEfiExecCmdMS, &fileData, &fileSize))) {
			if ((fileSize > 32768) && !EFI_ERROR(MemoryHasPattern(fileData, fileSize, g_szMsBootString, AsciiStrLen(g_szMsBootString)))) {
				bFound = TRUE;
			}
		}
		MEM_FREE(fileData);
		if (bFound) {
			res = EfiExec(NULL, gEfiExecCmdMS);
			if (!EFI_ERROR(res))
				return res;
		}
	}

	gFileRoot = savedRoot;
	gFileRootHandle = savedHandle;
	return EFI_NOT_FOUND;
}

/**
 * Search ESP partitions on a given disk for the Windows bootloader.
 */
STATIC EFI_STATUS
SearchWindowsLoaderOnDisk(
	IN EFI_HANDLE  DiskHandle
	)
{
	EFI_STATUS                  res;
	EFI_BLOCK_IO_PROTOCOL       *bio;
	EFI_PARTITION_TABLE_HEADER  *gptHdr = NULL;
	EFI_PARTITION_ENTRY         *gptEntry = NULL;
	UINT32                      i;

	bio = EfiGetBlockIO(DiskHandle);
	if (bio == NULL)
		return EFI_NOT_FOUND;

	res = GptReadHeader(bio, 1, &gptHdr);
	if (EFI_ERROR(res))
		return res;

	res = GptReadEntryArray(bio, gptHdr, &gptEntry);
	if (EFI_ERROR(res)) {
		MEM_FREE(gptHdr);
		return res;
	}

	for (i = 0; i < gptHdr->NumberOfPartitionEntries; ++i) {
		if (CompareGuid(&gptEntry[i].PartitionTypeGUID, &gEfiPartTypeSystemPartGuid)) {
			EFI_HANDLE espHandle = NULL;
			if (!EFI_ERROR(EfiFindPartByGUID(&gptEntry[i].UniquePartitionGUID, &espHandle))) {
				res = TryWindowsLoaderOnPartition(espHandle);
				if (!EFI_ERROR(res)) {
					MEM_FREE(gptEntry);
					MEM_FREE(gptHdr);
					return EFI_SUCCESS;
				}
			}
		}
	}

	MEM_FREE(gptEntry);
	MEM_FREE(gptHdr);
	return EFI_NOT_FOUND;
}

EFI_STATUS
ExecMSWindowsLoader()
{
	EFI_STATUS          res;
	HARDDRIVE_DEVICE_PATH hdp;
	EFI_HANDLE          disk = NULL;
	UINTN               i;
	INTN                searchAllDisks;

	if (gFileRootHandle) {
		/* First try the current partition (original behavior) */
		res = TryWindowsLoaderOnPartition(gFileRootHandle);
		if (!EFI_ERROR(res))
			return res;

		/* Search other ESP partitions on the disk DCS was started from */
		if (!EFI_ERROR(EfiGetPartDetails(gFileRootHandle, &hdp, &disk))) {
			res = SearchWindowsLoaderOnDisk(disk);
			if (!EFI_ERROR(res))
				return res;
		}
	}

	/* Optionally search ESP partitions on all other disks */
	searchAllDisks = ConfigReadInt("SearchAllDisksForLoader", 0);
	if (searchAllDisks || !gFileRootHandle) {
		for (i = 0; i < gBIOCount; ++i) {
			EFI_BLOCK_IO_PROTOCOL *bio = EfiGetBlockIO(gBIOHandles[i]);
			if (bio == NULL || bio->Media->LogicalPartition)
				continue;
			if (gBIOHandles[i] == disk)
				continue;
			res = SearchWindowsLoaderOnDisk(gBIOHandles[i]);
			if (!EFI_ERROR(res))
				return res;
		}
	}

	ERR_PRINT(L"Could not find the original Windows loader\r\n");
	return EFI_NOT_READY;
}

//////////////////////////////////////////////////////////////////////////
// Boot Menu - Boot from File (using CommonLib File Picker)
//////////////////////////////////////////////////////////////////////////

/**
 * Main boot menu entry point - uses generalized file picker from CommonLib
 */
STATIC EFI_STATUS
BootMenuShow(
	VOID
)
{
	EFI_STATUS      res;
	EFI_HANDLE      volumeHandle;
	CHAR16          *selectedPath = NULL;
	CONST CHAR16    *efiExtensions[] = { L".efi", NULL };

	for (;;) {
		res = FilePickerSelectFile(efiExtensions, L"Select Boot File", &volumeHandle, &selectedPath);
		if (EFI_ERROR(res)) {
			if (res == EFI_DCS_USER_CANCELED) {
				gST->ConOut->ClearScreen(gST->ConOut);
				return EFI_ABORTED;
			}
			if (res == EFI_NOT_FOUND) {
				ERR_PRINT(L"No bootable volumes found\n");
				KeyWait(L"Press any key to continue...", 5, 0, 0);
			}
			return res;
		}

		// Execute selected .efi file
		gST->ConOut->ClearScreen(gST->ConOut);
		OUT_PRINT(L"Booting %s...\n", selectedPath);
		gBS->Stall(1000000);

		res = EfiExec(volumeHandle, selectedPath);

		MEM_FREE(selectedPath);
		selectedPath = NULL;

		if (EFI_ERROR(res)) {
			ERR_PRINT(L"Failed to boot: %r\n", res);
			KeyWait(L"Press any key to continue...", 5, 0, 0);
			// Loop back to allow another selection
		} else {
			return EFI_SUCCESS;
		}
	}
}

//////////////////////////////////////////////////////////////////////////
// DcsOwner protocol helper
//////////////////////////////////////////////////////////////////////////

/**
The actual entry point for the application.

@param[in] ImageHandle    The firmware allocated handle for the EFI image.
@param[in] SystemTable    A pointer to the EFI System Table.

@retval EFI_SUCCESS       The entry point executed successfully.
@retval other             Some error occurred when executing this entry point.

**/
EFI_STATUS
EFIAPI
DcsBootMain(
   IN EFI_HANDLE        ImageHandle,
   IN EFI_SYSTEM_TABLE  *SystemTable
   )
{
	EFI_STATUS			res;
	BOOLEAN             searchOnESP = FALSE;
	BOOLEAN             searchMsOnESP = FALSE;
	EFI_GUID			*pEfiExecPartBackup = NULL;
	DCS_BOOT_CONFIG     bootConfig;
	UINT32              bmeEnabled;
	UINT32              lockFlags;
	EFI_DCSOWNER_PROTOCOL *Owner = NULL;

#ifdef DEBUG_BUILD
	OUT_PRINT(L"DcsBoot - DEBUG Build %s %s\n", _T(__DATE__), _T(__TIME__));
#endif

	InitBio();		// Initialize Block IO
	res = InitFS();	// Initialize FileSystem
	if (EFI_ERROR(res)) {
		res = InitPxe2(); // check and Initialize PXE boot
	}
	InitConfig(CONFIG_FILE_PATH); // Initialize Config
	InitParams();

	if (gConfigDebug && !IsPxeBoot()) {
		OUT_PRINT(L"Root Device: ");
		EfiPrintDevicePath(gFileRootHandle);
		OUT_PRINT(L"\n");
	}

	// Dump platform info
	if (ConfigReadInt("CollectPlatformInfo", 0) && !IsPxeBoot() &&
		EFI_ERROR(FileExist(NULL, L"\\EFI\\" DCS_DIRECTORY L"\\PlatformInfo")) &&
		!EFI_ERROR(FileExist(NULL, L"\\EFI\\" DCS_DIRECTORY L"\\DcsInfo.dcs"))) {
		OUT_PRINT(L"Collecting Platform information...\n");
		res = EfiExec(NULL, L"\\EFI\\" DCS_DIRECTORY L"\\DcsInfo.dcs");
		if (!EFI_ERROR(res) &&
			!EFI_ERROR(FileExist(NULL, L"\\EFI\\" DCS_DIRECTORY L"\\PlatformInfo"))) {
			KeyWait(L"PlatformInfo generated, rebooting in %02d s\r", 10, 0, 0);
			gST->RuntimeServices->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
		}
	}

#ifndef _M_ARM64
	// Load all drivers
	UefiExec(L"\\EFI\\" DCS_DIRECTORY L"\\LegacySpeaker.dcs"); // driver for ordinary speaker (beep)
#endif

	// Load DcsOwner
	UefiExec(L"\\EFI\\" DCS_DIRECTORY L"\\DcsOwner.dcs");
	EFI_GUID LocDcsOwnerProtocolGuid = EFI_DCSOWNER_PROTOCOL_GUID;
	gBS->LocateProtocol(&LocDcsOwnerProtocolGuid, NULL, (VOID **)&Owner);

	// Get boot partition GUID - not valid for PXE or ISO boot
	if (!IsPxeBoot()) {
		res = EfiGetPartGUID(gFileRootHandle, &ImagePartGuid);
		if (EFI_ERROR(res)) {
			if (gConfigDebug) {
				OUT_PRINT(L"No partition GUID available (ISO boot?)\n");
			}
		}
	}

	// Initialize boot config to pass to DcsInt via LoadOptions
	ZeroMem(&bootConfig, sizeof(bootConfig));
	bootConfig.Size = sizeof(DCS_BOOT_CONFIG);
	bootConfig.ConfigFileName = gConfigFileName;
	bootConfig.ConfigBuffer = gConfigBuffer;
	bootConfig.ConfigBufferSize = gConfigBufferSize;
	CopyGuid(&bootConfig.ExecPartGuid, &ImagePartGuid);
	bootConfig.ExternMode = gExternMode;
	if (!EFI_ERROR(FileExist(NULL, gEfiExecCmdDefault))) {
		StrCpyS(bootConfig.ExecCmd, ARRAY_SIZE(bootConfig.ExecCmd), gEfiExecCmdDefault);
	} else {
		StrCpyS(bootConfig.ExecCmd, ARRAY_SIZE(bootConfig.ExecCmd), gEfiExecCmdMS);
	}

	if (UefiFileExistsPath(L"\\EFI\\" DCS_DIRECTORY L"\\DcsInt.dcs")) {
		gBS->SetWatchdogTimer(0, 0, 0, NULL); // disable 5-min UEFI watchdog so password prompt can wait indefinitely
		// Authorize - pass boot config to DcsInt via LoadOptions
		res = UefiExecEx(L"\\EFI\\" DCS_DIRECTORY L"\\DcsInt.dcs", &bootConfig, sizeof(bootConfig));

		if (gConfigDebug) {
			ERR_PRINT(L"DcsInt %r\n", res);
			gBS->Stall(100000);
		}
	}
	else {
		if (Owner) {
			Owner->ShowBootPrompt(Owner);
		} 
		else {
			ERR_PRINT(L"DCS files are missing.\n");
			KeyWait(L"Boot in %2d sec\r", 30, 0, 0);
		}
		res = EFI_DCS_USER_CANCELED;
	}

	// Activate DcsOwner runtime hooks (variable override, SetVariable blocking)
	if (Owner != NULL) {
		Owner->TakeOwnership(Owner);
	}

	if (EFI_ERROR(res)) {

		if (gExternMode)
			return EFI_SUCCESS; // in recovery mode return to DcsRe.efi

		if (res == EFI_DCS_USER_CANCELED)
		{
			if (gConfigDebug) {
				KeyWait(L"Attempting to boot Windows in %02d s\r", 30, 0, 0);
				OUT_PRINT(L"\n");
			}

			/* If user cancels password prompt, call original Windows loader */
			res = ExecMSWindowsLoader();
			if (EFI_ERROR(res)) {
				ERR_PRINT(L"Failed to execute Windows loader: %r\n", res);
				res = EFI_DCS_SHUTDOWN_REQUESTED;
			}
		}

		if (res == EFI_DCS_SHUTDOWN_REQUESTED)
		{
			res = EFI_SUCCESS;
			KeyWait(L"Shutdown in %02d s\r", 10, 0, 0);
			gST->RuntimeServices->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);
		}
		else if (res == EFI_DCS_REBOOT_REQUESTED)
		{
			res = EFI_SUCCESS;
			KeyWait(L"Reboot in %02d s\r", 10, 0, 0);
			gST->RuntimeServices->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
		}
		else if (res == EFI_DCS_HALT_REQUESTED)
		{
			KeyWait(L"Halting Cpu in %02d s\r", 10, 0, 0);
			EfiCpuHalt();
		}
		return res;
	}

	// Find new start partition
	ConnectAllEfi(); // this applies the installed IO hook
	InitBio();
	InitFS();

	// Boot menu lock via DcsOwner protocol (skip in extern/PXE mode)
	bmeEnabled = ConfigReadInt("BootMenuLock", 1);
	if (bmeEnabled && !(gExternMode || IsPxeBoot())) {
		if (Owner != NULL) {
			lockFlags = (UINT32)ConfigReadInt("BootMenuLockFlags", DCSOWNER_LOCK_BOOT_VARS | DCSOWNER_SET_BOOTNEXT | DCSOWNER_UPDATE_BOOTORDER);
			Owner->BootMenuLock(Owner, lockFlags);
		} else if (gConfigDebug) {
			ERR_PRINT(L"DcsOwner protocol not found, boot menu lock skipped\n");
		}
	}

	if (res == EFI_DCS_INPUT_REQUIRED) {
		res = BootMenuShow();
		if(EFI_ERROR(res))
			return EFI_ABORTED;
		return EFI_SUCCESS;
	}

	// Get boot partition and command from bootConfig (updated by DcsInt)
	gEfiExecPartGuid = &bootConfig.ExecPartGuid;
	gEfiExecCmd = bootConfig.ExecCmd[0] ? bootConfig.ExecCmd : NULL;

	if (!gEfiExecCmd) {
		if (!EFI_ERROR(FileExist(NULL, gEfiExecCmdDefault))) {
			gEfiExecCmd = gEfiExecCmdDefault;
		} else {
			gEfiExecCmd = gEfiExecCmdMS;
		}
	}

	if (gConfigDebug) {
		OUT_PRINT(L"DcsExecPartGuid %g\n", gEfiExecPartGuid);
		OUT_PRINT(L"DcsExecCmd %s\n", gEfiExecCmd);
		KeyWait(L"Attempting to boot Windows in %02d s\r", 30, 0, 0);
		OUT_PRINT(L"\n");
	}

	pEfiExecPartBackup = gEfiExecPartGuid;

	searchOnESP = CompareGuid(gEfiExecPartGuid, &ImagePartGuid) && EFI_ERROR(FileExist(NULL, gEfiExecCmd));
	searchMsOnESP = CompareGuid(gEfiExecPartGuid, &ImagePartGuid) && EFI_ERROR(FileExist(NULL, gEfiExecCmdMS));

	while (1)
	{
		// Default load of bootmgfw?
		if (searchOnESP) {
			// gEfiExecCmd is not found on start partition. Try from ESP
			EFI_BLOCK_IO_PROTOCOL *bio = NULL;
			EFI_PARTITION_TABLE_HEADER *gptHdr = NULL;
			EFI_PARTITION_ENTRY        *gptEntry = NULL;
			HARDDRIVE_DEVICE_PATH hdp;
			EFI_HANDLE disk;
			if (!EFI_ERROR(res = EfiGetPartDetails(gFileRootHandle, &hdp, &disk))) {
				if ((bio = EfiGetBlockIO(disk)) != NULL) {
					if (!EFI_ERROR(res = GptReadHeader(bio, 1, &gptHdr)) &&
						!EFI_ERROR(res = GptReadEntryArray(bio, gptHdr, &gptEntry))) {
						UINT32 i;
						for (i = 0; i < gptHdr->NumberOfPartitionEntries; ++i) {
							if (CompareGuid(&gptEntry[i].PartitionTypeGUID, &gEfiPartTypeSystemPartGuid)) {
								// select ESP GUID
								CopyGuid(gEfiExecPartGuid, &gptEntry[i].UniquePartitionGUID);
								res = DoExecCmd();
								if(EFI_ERROR(res)) continue;
							}
						}
					}
				}
			}
		}	else {
			res = DoExecCmd();
		}

		if(EFI_ERROR(res))
		{
			if (0 == StrCmp(gEfiExecCmd, gEfiExecCmdDefault))
			{
				gEfiExecCmd = gEfiExecCmdMS;
				searchOnESP = searchMsOnESP;
				gEfiExecPartGuid = pEfiExecPartBackup;
			}
			else
				break;
		}
		else
			break;
	}

	ERR_PRINT(L"%a\nStatus -  %r", gDoExecCmdMsg, res);
	KeyWait(L"Shutdown in %02d s\r", 10, 0, 0);
	gST->RuntimeServices->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);
	return EFI_INVALID_PARAMETER;
}
