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
#include "../MiscUtilsLib/MiscUtilsLib.h"

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

#define NO_CONF_UTIL

CONST CHAR8* g_szMsBootString = "bootmgfw.pdb";
CONST CHAR16* g_szVcBootString = _T(DCS_CAPTION);

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
SelectEfiVolume() 
{
	UINTN        i;
	EFI_STATUS   res;
	EFI_FILE     *file;
	EFI_FILE     **efiVolumes;
	UINTN        efiVolumesCount = 0;
	if (EfiBootVolume != NULL) return;

	efiVolumes = MEM_ALLOC(sizeof(EFI_FILE*) * gFSCount);
	for (i = 0; i < gFSCount; ++i) {
		if (gFSHandles[i] == gFileRootHandle)
			continue;
		res = FileOpenRoot(gFSHandles[i], &file);
		if(EFI_ERROR(res)) { ERR_PRINT(L"FileOpenRoot %r\n", res); continue;}
		if (	!EFI_ERROR(FileExist(file, L"EFI\\Boot\\boot" ARCHdotEFI))
			||	!EFI_ERROR(FileExist(file, L"EFI\\Microsoft\\Boot\\bootmgfw.efi"))
			||	!EFI_ERROR(FileExist(file, L"EFI\\Microsoft\\Boot\\bootmgfw_ms.vc"))
			) 
		{
			efiVolumesCount++;
			efiVolumes[i] = file;
			EfiBootVolumeIndex = i;
			EfiBootVolume = file;
		}	else {
			FileClose(file);
		}
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
			EfiBootVolumeIndex = AskUINTN("Select EFI boot volume:", EfiBootVolumeIndex);
			if (EfiBootVolumeIndex >= gFSCount) continue;
			EfiBootVolume = efiVolumes[EfiBootVolumeIndex];
		} while (EfiBootVolume == NULL);
		
		/* free unused descriptors */
		for (i = 0; i < gFSCount; ++i) {
			if (efiVolumes[i] != NULL && efiVolumes[i] != EfiBootVolume) {
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
  if (IsPxeBoot()) {
    return PxeExec(L"EFI\\Boot\\WinPE_boot" ARCHdotEFI);
  } else {
    return EfiExec(NULL, L"EFI\\Boot\\WinPE_boot" ARCHdotEFI);
  }
}

EFI_STATUS
ActionShell(IN VOID* ctx) {
  if (IsPxeBoot()) {
    return PxeExec(L"EFI\\Shell\\Shell.efi");
  } else {
	  return EfiExec(NULL, L"EFI\\Shell\\Shell.efi");
  }
}

CHAR16* sRecoveryKey = OPT_EXTERN_KEY;
CHAR16* sDcsBoot = L"EFI\\" DCS_DIRECTORY L"\\DcsBoot.efi";

EFI_STATUS
ActionDcsRecoveryBoot(IN VOID* ctx) {
	EfiSetVar(L"DcsExecMode", NULL, sRecoveryKey, StrSize(sRecoveryKey), EFI_VARIABLE_BOOTSERVICE_ACCESS);
  if (IsPxeBoot()) {
    return PxeExec(sDcsBoot);
  } else {
	  return EfiExec(NULL, sDcsBoot);
  }
}

EFI_STATUS
ActionDcsBoot(IN VOID* ctx) {
	SelectEfiVolume();
	if (EfiBootVolume == NULL) return EFI_NOT_READY;
	return EfiExec(gFSHandles[EfiBootVolumeIndex], sDcsBoot);
}

EFI_STATUS
ActionWindowsBoot(IN VOID* ctx) {
	if (AskConfirm("If Windows is encrypted, Windows original loader will fail to start.\r\nDo you want to continue? [N]", 1))
	{
		SelectEfiVolume();
		if (EfiBootVolume == NULL) return EFI_NOT_READY;
		if (!EFI_ERROR(FileExist(EfiBootVolume, L"EFI\\Microsoft\\Boot\\bootmgfw_ms.vc")))
			return EfiExec(gFSHandles[EfiBootVolumeIndex], L"EFI\\Microsoft\\Boot\\bootmgfw_ms.vc");
		else
		{
			if (!EFI_ERROR(FileExist(EfiBootVolume, L"EFI\\Microsoft\\Boot\\bootmgfw.efi")))
			{
				/* check if it is Microsoft one */
				UINT8*      fileData = NULL;
				UINTN       fileSize = 0;
				BOOLEAN		bFound = FALSE;
				if (!EFI_ERROR(FileLoad(EfiBootVolume, L"EFI\\Microsoft\\Boot\\bootmgfw.efi", &fileData, &fileSize)))
				{
					if ((fileSize > 32768) && !EFI_ERROR(MemoryHasPattern(fileData, fileSize, g_szMsBootString, AsciiStrLen(g_szMsBootString))))
					{
						bFound = TRUE;
					}
				}
				
				MEM_FREE(fileData);
				
				if (bFound)
					return EfiExec(gFSHandles[EfiBootVolumeIndex], L"EFI\\Microsoft\\Boot\\bootmgfw.efi");
			}

			ERR_PRINT(L"Could not find the original Windows loader\r\n");
			
			return EFI_NOT_READY;
		}
	}
	else
		return EFI_SUCCESS;
}

CHAR16* DcsBootBins[] = {
	L"EFI\\" DCS_DIRECTORY L"\\DcsBoot.efi",
	L"EFI\\" DCS_DIRECTORY L"\\DcsInt.dcs",
	L"EFI\\" DCS_DIRECTORY L"\\DcsBml.dcs",
	L"EFI\\" DCS_DIRECTORY L"\\DcsCfg.dcs",
	L"EFI\\" DCS_DIRECTORY L"\\LegacySpeaker.dcs"
};

/**
Copy DCS binaries from rescue disk to EFI boot volume
*/
EFI_STATUS
ActionRestoreDcsLoader(IN VOID* ctx) {
	EFI_STATUS res = EFI_NOT_READY;
	UINTN i;
	SelectEfiVolume();
	if (EfiBootVolume == NULL) return EFI_NOT_READY;

	DirectoryCreate (EfiBootVolume, L"EFI\\" DCS_DIRECTORY);

	for (i = 0; i < sizeof(DcsBootBins) / sizeof(CHAR16*); ++i) {
    if (IsPxeBoot()) {
      res = PxeFileCopy(DcsBootBins[i], EfiBootVolume, DcsBootBins[i]);
    } else {
		  res = FileCopy(NULL, DcsBootBins[i], EfiBootVolume, DcsBootBins[i], 1024 * 1024);
    }
		if (EFI_ERROR(res)) return res;
	}

	if (!AskConfirm("Do you want to replace the default windows loader with the " DCS_CAPTION " one? [N]", 1)) goto done;

	/* restore standard boot file */
	if (!EFI_ERROR(FileExist(EfiBootVolume, L"EFI\\Boot\\boot" ARCHdotEFI)))
	{
		/* check if it is Microsoft one or ours */
		UINT8*      fileData = NULL;
		UINTN       fileSize = 0;
		res = EFI_SUCCESS;
		if (!EFI_ERROR(FileLoad(EfiBootVolume, L"EFI\\Boot\\boot" ARCHdotEFI, &fileData, &fileSize)))
		{
			if ((fileSize > 32768) && !EFI_ERROR(MemoryHasPattern(fileData, fileSize, g_szMsBootString, AsciiStrLen(g_szMsBootString))))
			{
				res = FileCopy(EfiBootVolume, L"EFI\\Boot\\boot" ARCHdotEFI, EfiBootVolume, L"\\EFI\\Boot\\original_boot" ARCHdot L"vc_backup", 1024 * 1024);
				if (!EFI_ERROR(res))
          if (IsPxeBoot()) {
            res = PxeFileCopy(L"EFI\\" DCS_DIRECTORY L"\\DcsBoot.efi", EfiBootVolume, L"EFI\\Boot\\boot" ARCHdotEFI);
          } else {
					  res = FileCopy(NULL, L"EFI\\" DCS_DIRECTORY L"\\DcsBoot.efi", EfiBootVolume, L"EFI\\Boot\\boot" ARCHdotEFI, 1024 * 1024);
          }
			}
			else if ((fileSize <= 32768) && !EFI_ERROR(MemoryHasPattern(fileData, fileSize, g_szVcBootString, StrLen (g_szVcBootString) * 2)))
			{
        if (IsPxeBoot()) {
          res = PxeFileCopy(L"EFI\\" DCS_DIRECTORY L"\\DcsBoot.efi", EfiBootVolume, L"EFI\\Boot\\boot" ARCHdotEFI);
        } else {
          res = FileCopy(NULL, L"EFI\\" DCS_DIRECTORY L"\\DcsBoot.efi", EfiBootVolume, L"EFI\\Boot\\boot" ARCHdotEFI, 1024 * 1024);
        }
			}
			MEM_FREE(fileData);
			
			if (EFI_ERROR(res)) return res;
		}		
	}
	else if (!EFI_ERROR(FileExist(EfiBootVolume, L"\\EFI\\Boot\\original_boot" ARCHdot L"vc_backup")))
	{
    if (IsPxeBoot()) {
      res = PxeFileCopy(L"EFI\\" DCS_DIRECTORY L"\\DcsBoot.efi", EfiBootVolume, L"EFI\\Boot\\boot" ARCHdotEFI);
    } else {
      res = FileCopy(NULL, L"EFI\\" DCS_DIRECTORY L"\\DcsBoot.efi", EfiBootVolume, L"EFI\\Boot\\boot" ARCHdotEFI, 1024 * 1024);
    }
		if (EFI_ERROR(res)) return res;
	}

	if (!EFI_ERROR(FileExist(EfiBootVolume, L"EFI\\Microsoft\\Boot\\bootmgfw.efi")))
	{
		/* check if it is Microsoft one */
		UINT8*      fileData = NULL;
		UINTN       fileSize = 0;
		res = EFI_SUCCESS;
		if (!EFI_ERROR(FileLoad(EfiBootVolume, L"EFI\\Microsoft\\Boot\\bootmgfw.efi", &fileData, &fileSize)))
		{
			if ((fileSize > 32768) && !EFI_ERROR(MemoryHasPattern(fileData, fileSize, g_szMsBootString, AsciiStrLen(g_szMsBootString))))
			{
				res = FileCopy(EfiBootVolume, L"EFI\\Microsoft\\Boot\\bootmgfw.efi", EfiBootVolume, L"\\EFI\\Microsoft\\Boot\\bootmgfw_ms.vc", 1024 * 1024);
			}

			MEM_FREE(fileData);

			if (EFI_ERROR(res)) return res;
		}

    if (IsPxeBoot()) {
      res = PxeFileCopy(L"EFI\\" DCS_DIRECTORY L"\\DcsBoot.efi", EfiBootVolume, L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi");
    } else {
      res = FileCopy(NULL, L"EFI\\" DCS_DIRECTORY L"\\DcsBoot.efi", EfiBootVolume, L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi", 1024 * 1024);
    }
		if (EFI_ERROR(res)) return res;
	}
	else if (!EFI_ERROR(FileExist(EfiBootVolume, L"\\EFI\\Microsoft\\Boot\\bootmgfw_ms.vc")))
	{
    if (IsPxeBoot()) {
      res = PxeFileCopy(L"EFI\\" DCS_DIRECTORY L"\\DcsBoot.efi", EfiBootVolume, L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi");
    } else {
      res = FileCopy(NULL, L"EFI\\" DCS_DIRECTORY L"\\DcsBoot.efi", EfiBootVolume, L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi", 1024 * 1024);
    }
		if (EFI_ERROR(res)) return res;
	}

done:
	OUT_PRINT (L"\n" _T(DCS_CAPTION) L" Loader restored to disk successfully\n\n");
	
	return EFI_SUCCESS;
}

CHAR16* sDcsBootEfi = L"EFI\\" DCS_DIRECTORY L"\\DcsBoot.efi";
CHAR16* sDcsBootEfiDesc = _T(DCS_CAPTION) L"(DCS) loader";
/**
Update boot menu
*/
EFI_STATUS
ActionRestoreDcsBootMenu(IN VOID* ctx)
{
	EFI_STATUS res = EFI_NOT_READY;
	SelectEfiVolume();
	if (EfiBootVolume == NULL) return EFI_NOT_READY;
	// Prepare BootDC5B
	res = BootMenuItemCreate(L"BootDC5B", sDcsBootEfiDesc, gFSHandles[EfiBootVolumeIndex], sDcsBootEfi, TRUE);
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
	SelectEfiVolume();
	if (EfiBootVolume == NULL) return EFI_NOT_READY;
  if (IsPxeBoot()) {
    return PxeFileCopy(L"EFI\\" DCS_DIRECTORY L"\\DcsProp", EfiBootVolume, L"EFI\\" DCS_DIRECTORY L"\\DcsProp");
  } else {
    return FileCopy(NULL, L"EFI\\" DCS_DIRECTORY L"\\DcsProp", EfiBootVolume, L"EFI\\" DCS_DIRECTORY L"\\DcsProp", 1024*1024);
  }
}

#ifndef NO_CONF_UTIL

#define OPT_OS_DECRYPT L"-osdecrypt"
#define OPT_OS_RESTORE_KEY L"-osrestorekey"

CHAR16* sOSDecrypt = OPT_OS_DECRYPT;
CHAR16* sOSRestoreKey = OPT_OS_RESTORE_KEY;
CHAR16* sDcsCfg = L"EFI\\" DCS_DIRECTORY L"\\DcsCfg.dcs";

EFI_STATUS
ActionRestoreHeader(IN VOID* ctx) {
	EfiSetVar(L"dcscfgcmd", NULL, sOSRestoreKey, StrSize(sOSRestoreKey), EFI_VARIABLE_BOOTSERVICE_ACCESS);
  if (IsPxeBoot()) {
    return PxeExec(sDcsCfg);
  } else {
    return EfiExec(NULL, sDcsCfg);
  }
}

EFI_STATUS
ActionDecryptOS(IN VOID* ctx) {
	EfiSetVar(L"dcscfgcmd", NULL, sOSDecrypt, StrSize(sOSDecrypt), EFI_VARIABLE_BOOTSERVICE_ACCESS);
  if (IsPxeBoot()) {
    return PxeExec(sDcsCfg);
  } else {
    return EfiExec(NULL, sDcsCfg);
  }
}

#endif

EFI_STATUS
ActionExit(IN VOID* ctx) {
	gContinue = FALSE;
	return EFI_SUCCESS;
}

EFI_STATUS
ActionHelp(IN VOID* ctx) {
OUT_PRINT(L"\
%HRescue disk for " _T(DCS_CAPTION) L" OS encryption%N\n\r\
Help message to be defined\n\r\
");
	return EFI_SUCCESS;
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
		res = PxeFileExist(L"EFI\\" DCS_DIRECTORY L"\\DcsBoot.efi");
		dcsDirectoryExists = !EFI_ERROR(res);
	} else {
		res = DirectoryExists(NULL, L"EFI\\" DCS_DIRECTORY);
		dcsDirectoryExists = !EFI_ERROR(res);
	}

	if (dcsDirectoryExists)
	{
		item = DcsMenuAppend(NULL, L"Boot " _T(DCS_CAPTION) L" loader from system disk", 'b', ActionDcsBoot, NULL);
		gMenu = item;

#ifndef NO_CONF_UTIL
		item = DcsMenuAppend(item, L"Decrypt OS", 'd', ActionDecryptOS, NULL);
#endif
		item = DcsMenuAppend(item, L"Restore " _T(DCS_CAPTION) L" loader to boot menu", 'm', ActionRestoreDcsBootMenu, NULL);
		item = DcsMenuAppend(item, L"Remove " _T(DCS_CAPTION) L" loader from boot menu", 'z' , ActionRemoveDcsBootMenu, NULL);

		if (IsPxeBoot()) {
			if (!EFI_ERROR(PxeFileExist(L"EFI\\" DCS_DIRECTORY L"\\DcsProp"))) {
				item = DcsMenuAppend(item, L"Restore " _T(DCS_CAPTION) L" loader configuration to system disk", 'c', ActionRestoreDcsProp, NULL);
			}
		} else {
			if (!EFI_ERROR(FileExist(NULL, L"EFI\\" DCS_DIRECTORY L"\\DcsProp"))) {
				item = DcsMenuAppend(item, L"Restore " _T(DCS_CAPTION) L" loader configuration to system disk", 'c', ActionRestoreDcsProp, NULL);
			}
		}

#ifndef NO_CONF_UTIL
		if (!IsPxeBoot()) {
			if (!EFI_ERROR(FileExist(NULL, L"EFI\\" DCS_DIRECTORY L"\\svh_bak"))) {
				item = DcsMenuAppend(item, L"Restore OS header keys", 'k', ActionRestoreHeader, NULL);
			}
		}
#endif

		if (IsPxeBoot()) {
			if (!EFI_ERROR(PxeFileExist(L"EFI\\" DCS_DIRECTORY L"\\DcsBoot.efi"))) {
				item = DcsMenuAppend(item, L"Restore " _T(DCS_CAPTION) L" loader binaries to system disk", 'r', ActionRestoreDcsLoader, NULL);
				item = DcsMenuAppend(item, L"Boot " _T(DCS_CAPTION) L" loader from PXE server", 'v', ActionDcsRecoveryBoot, NULL);
			}
		} else {
			if (!EFI_ERROR(FileExist(NULL, L"EFI\\" DCS_DIRECTORY L"\\DcsBoot.efi"))) {
				item = DcsMenuAppend(item, L"Restore " _T(DCS_CAPTION) L" loader binaries to system disk", 'r', ActionRestoreDcsLoader, NULL);
				item = DcsMenuAppend(item, L"Boot " _T(DCS_CAPTION) L" loader from rescue disk", 'v', ActionDcsRecoveryBoot, NULL);
			}
		}

		if (!IsPxeBoot()) {
			item = DcsMenuAppend(item, L"Boot Original Windows Loader", 'o', ActionWindowsBoot, NULL);

			if (!EFI_ERROR(FileExist(NULL, L"EFI\\Boot\\WinPE_boot" ARCHdotEFI))) {
				item = DcsMenuAppend(item, L"Boot Windows PE from rescue disk", 'w', ActionBootWinPE, NULL);
			}
		}

		if (IsPxeBoot()) {
			if (!EFI_ERROR(PxeFileExist(L"EFI\\Shell\\Shell.efi"))) {
				item = DcsMenuAppend(item, L"Boot Shell.efi from PXE server", 's', ActionShell, NULL);
			}
		} else {
			if (!EFI_ERROR(FileExist(NULL, L"EFI\\Shell\\Shell.efi"))) {
				item = DcsMenuAppend(item, L"Boot Shell.efi from rescue disk", 's', ActionShell, NULL);
			}
		}

		item = DcsMenuAppend(item, L"Help", 'h', ActionHelp, NULL);
		item = DcsMenuAppend(item, L"Exit", 'e', ActionExit, NULL);
		OUT_PRINT(L"%V" _T(DCS_CAPTION) L" rescue disk %d.%02d%N\n", DCS_VERSION / 100, DCS_VERSION % 100);
		gBS->SetWatchdogTimer(0, 0, 0, NULL);
		do {
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
				ERR_PRINT(L"%r\n", res);
			}
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
