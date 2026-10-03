/** @file
  This is DCS recovery loader application

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
#include <Guid/GlobalVariable.h>
#include <DcsConfig.h>
#include "../Library/MiscUtilsLib/MiscUtilsLib.h"

#if defined(_M_X64)
#define ARCHdot L"x64."
#define ARCHdotEFI L"x64.efi"
#elif defined(_M_ARM64)
#define ARCHdot L"aa64."
#define ARCHdotEFI L"aa64.efi"
#else
#define ARCHdot L"IA32."
#define ARCHdotEFI L"IA32.efi"
#endif

CHAR8* g_szMsBootString = "bootmgfw.pdb";
CHAR16* g_szVcBootString = _T(DCS_CAPTION);
CHAR16* g_szMsBootPath = L"EFI\\Microsoft\\Boot\\bootmgfw.efi";
CHAR16* g_szVcBootPath = L"EFI\\Microsoft\\Boot\\bootmgfw_ms.vc";

CHAR16* sDcsBootEfi = L"EFI\\" DCS_DIRECTORY L"\\DcsBoot.efi";
CHAR16* sDcsBootEfiDesc = _T(DCS_CAPTION) L"(DCS) loader";

CHAR16* sShimEfi = L"EFI\\Boot\\shim" ARCHdotEFI;
CHAR16* sShimEfiDesc = _T(DCS_CAPTION) L"(DCS) loader (SHIM)";


//////////////////////////////////////////////////////////////////////////
// Menu
//////////////////////////////////////////////////////////////////////////

BOOLEAN    gContinue = TRUE;
PMENU_ITEM gMenu = NULL;


//////////////////////////////////////////////////////////////////////////
// EFI volume
//////////////////////////////////////////////////////////////////////////

UINTN        EfiBootVolumeIndex = 0;
EFI_FILE     *EfiBootVolume = NULL;

VOID
SelectEfiVolume(UINTN *efiBootVolumeIndex, EFI_FILE **efiBootVolume, BOOLEAN win_only)
{
	UINTN        i;
	EFI_STATUS   res;
	EFI_FILE     *file;
	EFI_FILE     **efiVolumes;
	UINTN        efiVolumesCount = 0;
	BOOLEAN      fallback = FALSE;

	efiVolumes = MEM_ALLOC(sizeof(EFI_FILE*) * gFSCount);

retry:
	for (i = 0; i < gFSCount; ++i) {
		if (gFSHandles[i] == gFileRootHandle)
			continue;
		res = FileOpenRoot(gFSHandles[i], &file);
		if(EFI_ERROR(res)) { ERR_PRINT(L"FileOpenRoot %r\n", res); continue;}

		if (    (!EFI_ERROR(FileExist(file, L"EFI\\Boot\\boot" ARCHdotEFI))	&& fallback && !win_only)
			||	(!EFI_ERROR(FileExist(file, g_szMsBootPath))				&& (fallback || win_only))
			||	(!EFI_ERROR(FileExist(file, g_szVcBootPath))				&& (fallback || win_only))
			
			||  (!EFI_ERROR(FileExist(file, sDcsBootEfi)))					&& !fallback && !win_only)
		{
			efiVolumesCount++;
			efiVolumes[i] = file;
			*efiBootVolumeIndex = i;
			*efiBootVolume = file;
		} else {
			FileClose(file);
		}
	}

	if (efiVolumesCount == 0 && !fallback && !win_only) {
		fallback = TRUE;
		goto retry;
	}

	if (efiVolumesCount > 1)
	{
		for (i = 0; i < gFSCount; ++i) {
			OUT_PRINT(L"%H%d)%N ", i);
			if (efiVolumes[i] != NULL) {
				OUT_PRINT(L"%V [Boot] %N");
			}
			EfiPrintDevicePath(gFSHandles[i]);
			OUT_PRINT(L"\n");
		}

		do {
			*efiBootVolumeIndex = AskUINTN("Select EFI boot volume:", *efiBootVolumeIndex);
			if (*efiBootVolumeIndex >= gFSCount) continue;
			*efiBootVolume = efiVolumes[*efiBootVolumeIndex];
		} while (*efiBootVolume == NULL);
		
		/* free unused descriptors */
		for (i = 0; i < gFSCount; ++i) {
			if (efiVolumes[i] != NULL && efiVolumes[i] != *efiBootVolume) {
				FileClose(efiVolumes[i]);
			}
		}

		OUT_PRINT (L"\n");
	}

	MEM_FREE(efiVolumes);
}

//////////////////////////////////////////////////////////////////////////
// Actions
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
ActionBootWinPE(IN VOID* ctx) {
  return UefiExec(L"EFI\\Boot\\WinPE_boot" ARCHdotEFI);
}

EFI_STATUS
ActionToggleSB(IN VOID* ctx) {
	EFI_STATUS res;
	UINT8 sbState;
	res = DcsLdrGetMokSBState(&sbState);
	if (!EFI_ERROR(res)) {
		sbState = sbState ? 0 : 1;
		res = DcsLdrSetMokSBState(sbState);
		if (!EFI_ERROR(res)) {
			OUT_PRINT(L"Secure Boot enforcement is %S\n", sbState ? L"Disabled" : L"Enabled");
		}
	}
	return res;
}

EFI_STATUS
ActionShell(IN VOID* ctx) {
  return UefiExec(L"EFI\\Shell\\Shell.efi");
}

CHAR16* sRecoveryKey = OPT_EXTERN_KEY;

EFI_STATUS
ActionDcsRecoveryBoot(IN VOID* ctx) {
	EfiSetVar(L"DcsExecMode", NULL, sRecoveryKey, StrSize(sRecoveryKey), EFI_VARIABLE_BOOTSERVICE_ACCESS);
  return UefiExec(sDcsBootEfi);
}

EFI_STATUS
ActionDcsBoot(IN VOID* ctx) {
	if (EfiBootVolume == NULL) return EFI_NOT_READY;
	return EfiExec(gFSHandles[EfiBootVolumeIndex], sDcsBootEfi);
}

EFI_STATUS
ActionWindowsBoot(IN VOID* ctx) 
{
	if (!AskConfirm("If Windows is encrypted, Windows original loader will fail to start.\r\nDo you want to continue? [N]", 1))
		return EFI_SUCCESS;
	
	UINTN    efiBootVolumeIndex = 0;
	EFI_FILE *efiBootVolume = NULL;

	SelectEfiVolume(&efiBootVolumeIndex, &efiBootVolume, TRUE);

	if (efiBootVolume == NULL) return EFI_NOT_READY;

	if (!EFI_ERROR(FileExist(efiBootVolume, g_szVcBootPath)))
		return EfiExec(gFSHandles[efiBootVolumeIndex], g_szVcBootPath);
	
	if (!EFI_ERROR(FileExist(efiBootVolume, g_szMsBootPath)))
	{
		/* check if it is Microsoft one */
		UINT8*      fileData = NULL;
		UINTN       fileSize = 0;
		BOOLEAN		bFound = FALSE;
		if (!EFI_ERROR(FileLoad(efiBootVolume, g_szMsBootPath, &fileData, &fileSize)))
		{
			if ((fileSize > 32768) && !EFI_ERROR(MemoryHasPattern(fileData, fileSize, g_szMsBootString, AsciiStrLen(g_szMsBootString))))
			{
				bFound = TRUE;
			}
		}
				
		MEM_FREE(fileData);
				
		if (bFound)
			return EfiExec(gFSHandles[efiBootVolumeIndex], g_szMsBootPath);
	}

	ERR_PRINT(L"Could not find the original Windows loader\r\n");
			
	return EFI_NOT_READY;
}

CHAR16* DcsBootBins[] = {
	L"EFI\\" DCS_DIRECTORY L"\\DcsBoot.efi",
	L"EFI\\" DCS_DIRECTORY L"\\DcsInt.dcs",
	L"EFI\\" DCS_DIRECTORY L"\\DcsTpm.dcs",
	L"EFI\\" DCS_DIRECTORY L"\\DcsOwner.dcs",
	L"EFI\\" DCS_DIRECTORY L"\\DcsInfo.dcs",
	//L"EFI\\" DCS_DIRECTORY L"\\DcsCfg.dcs",
#ifndef _M_ARM64
	L"EFI\\" DCS_DIRECTORY L"\\LegacySpeaker.dcs",
#endif
};

/**
Copy DCS binaries from rescue disk to EFI boot volume
*/
EFI_STATUS
ActionRestoreDcsLoader(IN VOID* ctx) {
	EFI_STATUS res = EFI_NOT_READY;
	UINTN i, errors = 0;
	if (EfiBootVolume == NULL) return EFI_NOT_READY;

	DirectoryCreate(EfiBootVolume, L"EFI\\" DCS_DIRECTORY);

	for (i = 0; i < sizeof(DcsBootBins) / sizeof(CHAR16*); ++i) {
		if (IsPxeBoot()) {
			res = PxeFileCopy(DcsBootBins[i], EfiBootVolume, DcsBootBins[i]);
		} else {
			res = FileCopy(NULL, DcsBootBins[i], EfiBootVolume, DcsBootBins[i], 1024 * 1024);
		}
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"Failed to copy %s: %r\n", DcsBootBins[i], res);
			errors++;
		}
	}

	if (errors > 0) {
		ERR_PRINT(L"\n" _T(DCS_CAPTION) L" Loader restore completed with %d errors\n\n", errors);
	}
	else {
		OUT_PRINT(L"\n" _T(DCS_CAPTION) L" Loader restored to disk successfully\n\n");
	}

	return EFI_SUCCESS;
}

/**
Update boot menu
*/

EFI_STATUS
ActionRestoreDcsBootMenu(IN VOID* ctx)
{
	EFI_STATUS res = EFI_NOT_READY;
	CHAR16* bootPath;
	CHAR16* descr;

	if (EfiBootVolume == NULL) return EFI_NOT_READY;

	if (!EFI_ERROR(FileExist(EfiBootVolume, sShimEfi))) {
		bootPath = sShimEfi;
		descr = sShimEfiDesc;
	} else {
		bootPath = sDcsBootEfi;
		descr = sDcsBootEfiDesc;
	}

	res = BootMenuItemCreate(L"BootDC5B", descr, gFSHandles[EfiBootVolumeIndex], bootPath, TRUE);
	if (EFI_ERROR(res)) return res;
	res = BootOrderInsert(L"BootOrder", 0, 0x0DC5B);
	return res;
}

EFI_STATUS
ActionRemoveDcsBootMenu(IN VOID* ctx)
{
	EFI_STATUS res = EFI_NOT_READY;
	BootMenuItemRemove(L"BootDC5B");
	res = BootOrderRemove(L"BootOrder", 0x0DC5B);
	return res;
}

/**
Copy DcsProp from rescue disk to EFI boot volume
*/
EFI_STATUS
ActionRestoreDcsProp(IN VOID* ctx) {
	if (EfiBootVolume == NULL) return EFI_NOT_READY;
  if (IsPxeBoot()) {
    return PxeFileCopy(L"EFI\\" DCS_DIRECTORY L"\\DcsProp", EfiBootVolume, L"EFI\\" DCS_DIRECTORY L"\\DcsProp");
  } else {
    return FileCopy(NULL, L"EFI\\" DCS_DIRECTORY L"\\DcsProp", EfiBootVolume, L"EFI\\" DCS_DIRECTORY L"\\DcsProp", 1024*1024);
  }
}

/**
Copy shim binaries from rescue disk to EFI boot volume
*/

CHAR16* DcsShimBins[] = {
	L"EFI\\Boot\\shim" ARCHdotEFI,
	L"EFI\\Boot\\mm" ARCHdotEFI,
	L"EFI\\Boot\\grub" ARCHdotEFI, // DcsLdr.efi
	L"EFI\\Boot\\CustomSigner.der",
};

EFI_STATUS
ActionRestoreShim(IN VOID* ctx) {
	EFI_STATUS res = EFI_NOT_READY;
	UINTN i, errors = 0;
	if (EfiBootVolume == NULL) return EFI_NOT_READY;

	DirectoryCreate(EfiBootVolume, L"EFI\\Boot");

	for (i = 0; i < sizeof(DcsShimBins) / sizeof(CHAR16*); ++i) {
		if (IsPxeBoot()) {
			res = PxeFileCopy(DcsShimBins[i], EfiBootVolume, DcsShimBins[i]);
		} else {
			res = FileCopy(NULL, DcsShimBins[i], EfiBootVolume, DcsShimBins[i], 1024 * 1024);
		}
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"Failed to copy %s: %r\n", DcsShimBins[i], res);
			errors++;
		}
	}

	if (errors > 0) {
		ERR_PRINT(L"\nSecure Boot shim restore completed with %d errors\n\n", errors);
	}
	else {
		OUT_PRINT(L"\nSecure Boot shim restored to system disk successfully\n\n");
	}

	return EFI_SUCCESS;
}

EFI_STATUS
ActionExit(IN VOID* ctx) {
	gContinue = FALSE;
	return EFI_SUCCESS;
}

EFI_STATUS
ActionHelp(IN VOID* ctx) {
	OUT_PRINT(L"\r\n\
	%HRescue disk for " _T(DCS_CAPTION) L" OS encryption%N\r\n\
	visit https://diskcryptor.org for documentation.\r\n\
	");
	return EFI_SUCCESS;
}

/**
* boot menu
*/
EFI_STATUS
ActionBootMenu(IN VOID* ctx)
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

/**
The actual entry point for the application.

@param[in] ImageHandle    The firmware allocated handle for the EFI image.
@param[in] SystemTable    A pointer to the EFI System Table.

@retval EFI_SUCCESS       The entry point executed successfully.
@retval other             Some error occurred when executing this entry point.

**/
EFI_STATUS
EFIAPI
DcsReMain(
   IN EFI_HANDLE        ImageHandle,
   IN EFI_SYSTEM_TABLE  *SystemTable
   )
{
	EFI_STATUS          res;
	EFI_INPUT_KEY       key;
	PMENU_ITEM          item = gMenu;
	BOOLEAN             dcsDirectoryExists = FALSE;

#ifdef DEBUG_BUILD
	OUT_PRINT(L"DcsRe - DEBUG Build %s %s\n", _T(__DATE__), _T(__TIME__));
#endif

	InitBio();		// Initialize Block IO
	res = InitFS();	// Initialize FileSystem
	if (EFI_ERROR(res)) {
		res = InitPxe2(); // check and Initialize PXE boot
	}

	// Check if DCS directory exists (either local or via TFTP)
	if (IsPxeBoot()) {
		res = PxeFileExist(sDcsBootEfi);
		dcsDirectoryExists = !EFI_ERROR(res);
	} else {
		res = DirectoryExists(NULL, L"EFI\\" DCS_DIRECTORY);
		dcsDirectoryExists = !EFI_ERROR(res);
	}

	if (dcsDirectoryExists)
	{
		item = DcsMenuAppend(NULL, L"Help", 'h', ActionHelp, NULL);
		gMenu = item;

		if (UefiFileExistsPath(sDcsBootEfi)) {
			item = DcsMenuAppend(item, L"Start " _T(DCS_CAPTION) L" loader", 'd', ActionDcsRecoveryBoot, NULL);
		}
		item = DcsMenuAppend(item, L"Start " _T(DCS_CAPTION) L" loader from system disk", 'b', ActionDcsBoot, NULL);

		if (UefiFileExistsPath(L"EFI\\" DCS_DIRECTORY L"\\DcsProp")) {
			item = DcsMenuAppend(item, L"Restore " _T(DCS_CAPTION) L" loader configuration to system disk", 'c', ActionRestoreDcsProp, NULL);
		}

		if (UefiFileExistsPath(sDcsBootEfi)) {
			item = DcsMenuAppend(item, L"Restore " _T(DCS_CAPTION) L" loader binaries to system disk", 'r', ActionRestoreDcsLoader, NULL);
		}
		if (UefiFileExistsPath(sShimEfi)) {
			item = DcsMenuAppend(item, L"Restore Secure Boot Shim to system disk", 'i', ActionRestoreShim, NULL);
		}

		item = DcsMenuAppend(item, L"Restore " _T(DCS_CAPTION) L" loader to boot menu", 'm', ActionRestoreDcsBootMenu, NULL);
		item = DcsMenuAppend(item, L"Remove " _T(DCS_CAPTION) L" loader from boot menu", 'z', ActionRemoveDcsBootMenu, NULL);

		item = DcsMenuAppend(item, L"Boot Original Windows Loader", 'o', ActionWindowsBoot, NULL);

		if (!IsPxeBoot() && !EFI_ERROR(FileExist(NULL, L"EFI\\Boot\\WinPE_boot" ARCHdotEFI))) {
			item = DcsMenuAppend(item, L"Boot Windows PE from rescue disk", 'w', ActionBootWinPE, NULL);
		}

		if (IsSecureBootEnabled) {
			item = DcsMenuAppend(item, L"Toggle Secure Boot Enforcement", 't', ActionToggleSB, NULL);
		}
		if (UefiFileExistsPath(L"EFI\\Shell\\Shell.efi")) {
			item = DcsMenuAppend(item, L"Start EFI Shell", 's', ActionShell, NULL);
		}
		item = DcsMenuAppend(item, L"Boot from file...", 'f', ActionBootMenu, NULL);

		item = DcsMenuAppend(item, L"Exit", 'e', ActionExit, NULL);


		gBS->SetWatchdogTimer(0, 0, 0, NULL);
		OUT_PRINT(L"%V" _T(DCS_CAPTION) L" rescue disk %d.%02d%N\r\n", DCS_VERSION / 100, DCS_VERSION % 100);

		SelectEfiVolume(&EfiBootVolumeIndex, &EfiBootVolume, FALSE);
		if (EfiBootVolume) {
			OUT_PRINT(L"Selected EFI volume: ");
			EfiPrintDevicePath(gFSHandles[EfiBootVolumeIndex]);
			OUT_PRINT(L"\n");
		}

		do {
			OUT_PRINT(L"Select an action:\r\n");

			DcsMenuPrint(gMenu);
			item = NULL;
			key.UnicodeChar = 0;
			while (item == NULL) {
				item = gMenu;
				key = GetKey();
				while (item != NULL) {
					if (item->Select == key.UnicodeChar) break;
					item = item->Next;
				}
			}
			OUT_PRINT(L"%c\n",key.UnicodeChar);
			res = item->Action(item->Context);
			if (EFI_ERROR(res)) {
				ERR_PRINT(L"Command returned an ERROR: %r\n", res);
			}

			OUT_PRINT(L"\r\n");
		} while (gContinue);
	}
	else
	{
		/* No DCS folder. Boot directly from the hard drive */
		res = ActionDcsBoot (NULL);
		if (EFI_ERROR(res)) {
			ERR_PRINT(L"%r\n", res);
		}
	}
	return EFI_INVALID_PARAMETER;
}
