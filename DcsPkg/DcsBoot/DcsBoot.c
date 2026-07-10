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
#ifndef NO_BML
#include <Protocol/DcsBmlProto.h>
#endif
#include <DcsConfig.h>
#include <Guid/Gpt.h>
#include <Guid/GlobalVariable.h>
#include "../MiscUtilsLib/MiscUtilsLib.h"
#include "TpmKill.h"

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
#ifndef NO_BML
			UINT32 lockFlags = 0;
			// Lock EFI boot variables
			InitBml();
			lockFlags = ConfigReadInt("DcsBmlLockFlags", BML_LOCK_SETVARIABLE | BML_SET_BOOTNEXT | BML_UPDATE_BOOTORDER);
			BmlLock(lockFlags);
#endif
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

EFI_STATUS
ExecMSWindowsLoader() 
{
	if (!EFI_ERROR(FileExist(NULL, gEfiExecCmdDefault)))
		return EfiExec(NULL, gEfiExecCmdDefault);
	else
	{
		if (!EFI_ERROR(FileExist(NULL, gEfiExecCmdMS)))
		{
			/* check if it is Microsoft one */
			UINT8*      fileData = NULL;
			UINTN       fileSize = 0;
			BOOLEAN		bFound = FALSE;
			if (!EFI_ERROR(FileLoad(NULL, gEfiExecCmdMS, &fileData, &fileSize)))
			{
				if ((fileSize > 32768) && !EFI_ERROR(MemoryHasPattern(fileData, fileSize, g_szMsBootString, AsciiStrLen(g_szMsBootString))))
				{
					bFound = TRUE;
				}
			}
			
			MEM_FREE(fileData);
			
			if (bFound)
				return EfiExec(NULL, gEfiExecCmdMS);
		}

		ERR_PRINT(L"Could not find the original Windows loader\r\n");

		return EFI_NOT_READY;
	}
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
// BML - Boot Menu Lock
//////////////////////////////////////////////////////////////////////////
#ifndef NO_BML
CHAR16* sDcsBmlEfi = L"EFI\\" DCS_DIRECTORY L"\\DcsBml.dcs";
CHAR16* sDcsBmlEfiDesc = _T(DCS_CAPTION) L"(DcsBml) driver";
CHAR16* sDcsBmlDriverVar = L"DriverDC5B";
UINT16  DcsBmlDriverNum = 0x0DC5B;

VOID
UpdateDriverBmlStart() {
    EFI_STATUS          res;
    UINTN               len;
    UINT32              attr;
    int                 drvInst;
    CHAR16*             tmp = NULL;

    // Driver load selected?
    drvInst = ConfigReadInt("DcsBmlDriver", 0);
    if (drvInst) {
        res = EfiGetVar(sDcsBmlDriverVar, &gEfiGlobalVariableGuid, &tmp, &len, &attr);
        // Driver installed?
        if (EFI_ERROR(res)) {
            // No -> install
            res = BootMenuItemCreate(sDcsBmlDriverVar, sDcsBmlEfiDesc, gFileRootHandle, sDcsBmlEfi, FALSE);
//            ERR_PRINT(L"Drv %s %r\n", sDcsBmlDriverVar, res);
            if (!EFI_ERROR(res)) {
                len = 0;
                res = EfiGetVar(L"DriverOrder", &gEfiGlobalVariableGuid, &tmp, &len, &attr);
                if (!EFI_ERROR(res)) len = len / 2;
                res = BootOrderInsert(L"DriverOrder", len, DcsBmlDriverNum);
            }
//            ERR_PRINT(L"Drv order %d %r\n", len, res);
        }
        MEM_FREE(tmp);
    }
    else {
        // uninstall driver
        res = EfiGetVar(sDcsBmlDriverVar, &gEfiGlobalVariableGuid, &tmp, &len, &attr);
        if (!EFI_ERROR(res)) {
            BootMenuItemRemove(sDcsBmlDriverVar);
            BootOrderRemove(L"DriverOrder", DcsBmlDriverNum);
        }
    }
    MEM_FREE(tmp);
}
#endif

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
//	EFI_INPUT_KEY       key;

#ifdef DEBUG_BUILD
	OUT_PRINT(L"DcsBoot - DEBUG Build %s %s\n", _T(__DATE__), _T(__TIME__));
#endif

	InitBio();		// Initialize Block IO
	res = InitFS();	// Initialize FileSystem
	if (EFI_ERROR(res)) {
		res = InitPxe2(); // check and Initialize PXE boot
	}
	InitConfig(CONFIG_FILE_PATH); // Initialize Config

	if (gConfigDebug && !IsPxeBoot()) {
		OUT_PRINT(L"Root Device: ");
		EfiPrintDevicePath(gFileRootHandle);
		OUT_PRINT(L"\n");
	}

#ifndef NO_BML
	// BML installed?
	if (EFI_ERROR(InitBml())) { // if not
		// Install the Boot Menu Lock
		if (IsPxeBoot()) {
			PxeExec(sDcsBmlEfi);
		} else {
			EfiExec(NULL, sDcsBmlEfi);
		}
	}

	UpdateDriverBmlStart();
#endif

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

	// Load all drivers
	if (IsPxeBoot()) {
		PxeExec(L"\\EFI\\" DCS_DIRECTORY L"\\LegacySpeaker.dcs"); // driver for ordinary speaker (beep)
	} else {
		EfiExec(NULL, L"\\EFI\\" DCS_DIRECTORY L"\\LegacySpeaker.dcs"); // driver for ordinary speaker (beep)
	}

	// Get boot partition GUID - not valid for PXE or ISO boot
	if (!IsPxeBoot()) {
		res = EfiGetPartGUID(gFileRootHandle, &ImagePartGuid);
		if (EFI_ERROR(res)) {
			// No partition GUID found (e.g., booting from ISO with FAT image only)
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
	if (!EFI_ERROR(FileExist(NULL, gEfiExecCmdDefault))) {
		StrCpyS(bootConfig.ExecCmd, ARRAY_SIZE(bootConfig.ExecCmd), gEfiExecCmdDefault);
	} else {
		StrCpyS(bootConfig.ExecCmd, ARRAY_SIZE(bootConfig.ExecCmd), gEfiExecCmdMS);
	}
	bootConfig.TpmKill = (UINT8)ConfigReadInt("TpmKill", TPM_KILL_MODE_DISABLED);

	// Authorize - pass boot config to DcsInt via LoadOptions
	gBS->SetWatchdogTimer(0, 0, 0, NULL);
	if (IsPxeBoot()) {
		res = PxeExecEx(L"\\EFI\\" DCS_DIRECTORY L"\\DcsInt.dcs", &bootConfig, sizeof(bootConfig));
	} else {
		res = EfiExecEx(NULL, L"\\EFI\\" DCS_DIRECTORY L"\\DcsInt.dcs", &bootConfig, sizeof(bootConfig));
	}

	if (gConfigDebug) {
		ERR_PRINT(L"\nDcsInt.efi %r\n",res);
		gBS->Stall(100000);
	}

	// TPM Kill - disable TPM before handing off to Windows
	// Use value from bootConfig (may have been updated by DcsInt config menu)
	if (bootConfig.TpmKill) {
		TPM_KILL_CONTEXT tpmKillCtx = {bootConfig.TpmKill};
		EFI_STATUS tpmRes = TpmKillExecute(&tpmKillCtx);
		if (EFI_ERROR(tpmRes)) {
			ERR_PRINT(L"TpmKill failed: %r\n", tpmRes);
		}
		else if (gConfigDebug) {
			OUT_PRINT(L"TpmKill success: Shutdown=%d Protocol=%d Acpi=%d Vars=%d\n", tpmKillCtx.Tpm2Shutdown, tpmKillCtx.ProtocolKilled, tpmKillCtx.AcpiPatched, tpmKillCtx.VariablesDeleted);
		}
	}

	// Get boot partition and command from bootConfig (updated by DcsInt)
	gEfiExecPartGuid = &bootConfig.ExecPartGuid;
	gEfiExecCmd = bootConfig.ExecCmd[0] ? bootConfig.ExecCmd : NULL;

	if (EFI_ERROR(res)) {

		if (res == EFI_DCS_SHUTDOWN_REQUESTED)
		{
			res = EFI_SUCCESS;
			gST->RuntimeServices->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);
		}
		else if (res == EFI_DCS_REBOOT_REQUESTED)
		{
			res = EFI_SUCCESS;
			gST->RuntimeServices->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
		}
		else if (res == EFI_DCS_HALT_REQUESTED)
		{
			KeyWait(L"Halting Cpu in %02d s\r", 10, 0, 0);
			EfiCpuHalt();
		}
		else if (res == EFI_DCS_USER_CANCELED)
		{
			/* If user cancels password prompt, call original Windows loader */
			res = ExecMSWindowsLoader();
		}
		return res;
	}

	// Find new start partition
	ConnectAllEfi(); // this applies the installed IO hook
	InitBio();
	InitFS();

	if (res == EFI_DCS_INPUT_REQUIRED) {
		res = BootMenuShow();
		if(EFI_ERROR(res))
			return EFI_ABORTED;
		return EFI_SUCCESS;
	}

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
			if (0 == StrCmp (gEfiExecCmd, gEfiExecCmdDefault))
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
	KeyWait(L"Halting Cpu in %02d s\r", 10, 0, 0);
	EfiCpuHalt();
	return EFI_INVALID_PARAMETER;
}
