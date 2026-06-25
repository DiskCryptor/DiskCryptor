/** @file
EFI File Picker - Generalized file selection UI

Copyright (c) 2026. DiskCryptor, David Xanatos

This program and the accompanying materials are licensed and made available
under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Library/CommonLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>

//////////////////////////////////////////////////////////////////////////
// Constants
//////////////////////////////////////////////////////////////////////////

#define FILE_PICKER_PAGE_SIZE 18

//////////////////////////////////////////////////////////////////////////
// Internal structures
//////////////////////////////////////////////////////////////////////////

typedef enum {
	FILE_PICKER_ENTRY_PARENT_DIR,
	FILE_PICKER_ENTRY_DIRECTORY,
	FILE_PICKER_ENTRY_FILE
} FILE_PICKER_ENTRY_TYPE;

typedef struct {
	CHAR16                  Name[256];
	FILE_PICKER_ENTRY_TYPE  Type;
} FILE_PICKER_FILE_ENTRY;

typedef struct {
	EFI_HANDLE  Handle;
	UINTN       DiskNum;
	UINT32      PartNum;
	EFI_GUID    PartGuid;
	CHAR16      *DisplayName;   // Points to config or auto-generated string
	BOOLEAN     OwnsName;       // TRUE if DisplayName was auto-allocated
	BOOLEAN     HasFS;
} FILE_PICKER_VOLUME_ENTRY;

//////////////////////////////////////////////////////////////////////////
// Static helper functions
//////////////////////////////////////////////////////////////////////////

/**
 * Get 1-based disk number for a disk handle
 */
STATIC UINTN
FilePickerGetDiskNumber(
	IN EFI_HANDLE diskHandle
)
{
	UINTN diskNum = 0;
	UINTN j;
	for (j = 0; j < gBIOCount; j++) {
		if (!EfiIsPartition(gBIOHandles[j])) {
			diskNum++;
			if (gBIOHandles[j] == diskHandle) {
				return diskNum;
			}
		}
	}
	return 0;
}

/**
 * Sort volumes by disk number, then by partition number
 */
STATIC VOID
FilePickerSortVolumes(
	IN OUT FILE_PICKER_VOLUME_ENTRY *List,
	IN     UINTN                    Count
)
{
	UINTN                    i, j;
	FILE_PICKER_VOLUME_ENTRY temp;

	// Simple bubble sort - list is small
	for (i = 0; i < Count; i++) {
		for (j = i + 1; j < Count; j++) {
			// Compare: first by disk, then by partition
			if (List[j].DiskNum < List[i].DiskNum ||
				(List[j].DiskNum == List[i].DiskNum &&
				 List[j].PartNum < List[i].PartNum)) {
				// Swap
				CopyMem(&temp, &List[i], sizeof(FILE_PICKER_VOLUME_ENTRY));
				CopyMem(&List[i], &List[j], sizeof(FILE_PICKER_VOLUME_ENTRY));
				CopyMem(&List[j], &temp, sizeof(FILE_PICKER_VOLUME_ENTRY));
			}
		}
	}
}

/**
 * Test if a volume's root directory can be enumerated
 */
STATIC BOOLEAN
FilePickerCanEnumerateVolume(
	IN EFI_HANDLE Handle
)
{
	EFI_STATUS  status;
	EFI_FILE    *root;
	UINTN       bufSize;
	UINT8       buf[sizeof(EFI_FILE_INFO) + 256];

	// Try to open root
	status = FileOpenRoot(Handle, &root);
	if (EFI_ERROR(status)) {
		return FALSE;
	}

	// Try to read first directory entry
	bufSize = sizeof(buf);
	status = root->Read(root, &bufSize, buf);
	FileClose(root);

	// If read succeeded (even with 0 bytes for empty dir), volume is accessible
	return !EFI_ERROR(status);
}

/**
 * Case-insensitive string comparison
 */
STATIC INTN
FilePickerStriCmp(
	IN CONST CHAR16 *s1,
	IN CONST CHAR16 *s2
)
{
	CHAR16 c1, c2;
	while (*s1 && *s2) {
		c1 = (*s1 >= L'A' && *s1 <= L'Z') ? (*s1 + 32) : *s1;
		c2 = (*s2 >= L'A' && *s2 <= L'Z') ? (*s2 + 32) : *s2;
		if (c1 != c2) return c1 - c2;
		s1++;
		s2++;
	}
	c1 = (*s1 >= L'A' && *s1 <= L'Z') ? (*s1 + 32) : *s1;
	c2 = (*s2 >= L'A' && *s2 <= L'Z') ? (*s2 + 32) : *s2;
	return c1 - c2;
}

/**
 * Check if filename matches any extension in the filter list
 */
STATIC BOOLEAN
FilePickerMatchesExtension(
	IN CONST CHAR16  *FileName,
	IN CONST CHAR16  **Extensions  // NULL = match all
)
{
	UINTN len;
	UINTN extLen;
	UINTN i;

	// No filter = match all files
	if (Extensions == NULL) {
		return TRUE;
	}

	len = StrLen(FileName);

	for (i = 0; Extensions[i] != NULL; i++) {
		extLen = StrLen(Extensions[i]);
		if (len >= extLen) {
			if (FilePickerStriCmp(FileName + len - extLen, Extensions[i]) == 0) {
				return TRUE;
			}
		}
	}
	return FALSE;
}

/**
 * Build list of available volumes
 */
STATIC EFI_STATUS
FilePickerBuildVolumeList(
	IN  CONST FILE_PICKER_CONFIG     *Config,
	OUT FILE_PICKER_VOLUME_ENTRY     **Entries,
	OUT UINTN                        *EntryCount
)
{
	UINTN                    i, count = 0;
	FILE_PICKER_VOLUME_ENTRY *list;
	HARDDRIVE_DEVICE_PATH    hdp;
	EFI_HANDLE               disk;
	EFI_GUID                 guid;
	CHAR16                   *autoName;

	// If custom volume list provided, use it
	if (Config != NULL && Config->Volumes != NULL && Config->VolumeCount > 0) {
		list = MEM_ALLOC(Config->VolumeCount * sizeof(FILE_PICKER_VOLUME_ENTRY));
		if (list == NULL) {
			return EFI_OUT_OF_RESOURCES;
		}

		for (i = 0; i < Config->VolumeCount; i++) {
			list[i].Handle = Config->Volumes[i].Handle;
			list[i].DisplayName = Config->Volumes[i].DisplayName;
			list[i].OwnsName = FALSE;
			list[i].HasFS = FilePickerCanEnumerateVolume(Config->Volumes[i].Handle);

			// Get disk/partition info for sorting
			if (!EFI_ERROR(EfiGetPartDetails(Config->Volumes[i].Handle, &hdp, &disk))) {
				list[i].DiskNum = FilePickerGetDiskNumber(disk);
				list[i].PartNum = hdp.PartitionNumber;
			} else {
				list[i].DiskNum = 0;
				list[i].PartNum = 0;
			}

			if (!EFI_ERROR(EfiGetPartGUID(Config->Volumes[i].Handle, &guid))) {
				CopyGuid(&list[i].PartGuid, &guid);
			} else {
				ZeroMem(&list[i].PartGuid, sizeof(EFI_GUID));
			}
		}

		*Entries = list;
		*EntryCount = Config->VolumeCount;
		return EFI_SUCCESS;
	}

	// Auto-discover: Count partitions with accessible file systems
	for (i = 0; i < gFSCount; i++) {
		if (EfiIsPartition(gFSHandles[i]) && FilePickerCanEnumerateVolume(gFSHandles[i])) {
			count++;
		}
	}

	if (count == 0) {
		*Entries = NULL;
		*EntryCount = 0;
		return EFI_NOT_FOUND;
	}

	list = MEM_ALLOC(count * sizeof(FILE_PICKER_VOLUME_ENTRY));
	if (list == NULL) {
		return EFI_OUT_OF_RESOURCES;
	}

	count = 0;
	for (i = 0; i < gFSCount; i++) {
		if (!EfiIsPartition(gFSHandles[i])) {
			continue;
		}

		// Skip volumes that can't be enumerated
		if (!FilePickerCanEnumerateVolume(gFSHandles[i])) {
			continue;
		}

		list[count].Handle = gFSHandles[i];

		// Get disk number and partition number
		if (!EFI_ERROR(EfiGetPartDetails(gFSHandles[i], &hdp, &disk))) {
			list[count].DiskNum = FilePickerGetDiskNumber(disk);
			list[count].PartNum = hdp.PartitionNumber;
		} else {
			list[count].DiskNum = 0;
			list[count].PartNum = 0;
		}

		// Get partition GUID
		if (!EFI_ERROR(EfiGetPartGUID(gFSHandles[i], &guid))) {
			CopyGuid(&list[count].PartGuid, &guid);
		} else {
			ZeroMem(&list[count].PartGuid, sizeof(EFI_GUID));
		}

		// Auto-generate display name
		autoName = MEM_ALLOC(128 * sizeof(CHAR16));
		if (autoName != NULL) {
			UnicodeSPrint(autoName, 128 * sizeof(CHAR16), L"Disk %d Partition %d",
				list[count].DiskNum, list[count].PartNum);
			list[count].DisplayName = autoName;
			list[count].OwnsName = TRUE;
		} else {
			list[count].DisplayName = NULL;
			list[count].OwnsName = FALSE;
		}

		list[count].HasFS = TRUE;
		count++;
	}

	if (count == 0) {
		MEM_FREE(list);
		*Entries = NULL;
		*EntryCount = 0;
		return EFI_NOT_FOUND;
	}

	// Sort by disk number, then partition number
	FilePickerSortVolumes(list, count);

	*Entries = list;
	*EntryCount = count;
	return EFI_SUCCESS;
}

/**
 * Free volume list and any auto-allocated names
 */
STATIC VOID
FilePickerFreeVolumeList(
	IN FILE_PICKER_VOLUME_ENTRY *List,
	IN UINTN                    Count
)
{
	UINTN i;
	if (List != NULL) {
		for (i = 0; i < Count; i++) {
			if (List[i].OwnsName && List[i].DisplayName != NULL) {
				MEM_FREE(List[i].DisplayName);
			}
		}
		MEM_FREE(List);
	}
}

/**
 * Display volume selection menu and get user choice
 */
STATIC EFI_STATUS
FilePickerSelectVolume(
	IN     FILE_PICKER_VOLUME_ENTRY *Entries,
	IN     UINTN                    EntryCount,
	IN     CONST CHAR16             *Title,
	IN OUT INTN                     *SelectedIdx
)
{
	EFI_INPUT_KEY   key;
	INTN            selected;
	UINTN           pageStart = 0;
	UINTN           i;
	UINTN           pageEnd;

	// Use previous selection if valid, otherwise start at 0
	selected = *SelectedIdx;
	if (selected < 0 || (UINTN)selected >= EntryCount) {
		selected = 0;
	}
	// Adjust page to show selected item
	if ((UINTN)selected >= FILE_PICKER_PAGE_SIZE) {
		pageStart = (UINTN)selected - ((UINTN)selected % FILE_PICKER_PAGE_SIZE);
	}

	for (;;) {
		// Clear screen and draw header
		gST->ConOut->ClearScreen(gST->ConOut);
		if (Title != NULL) {
			OUT_PRINT(L"=== %s ===\n\n", Title);
		} else {
			OUT_PRINT(L"=== Select Volume ===\n\n");
		}

		// Calculate page bounds
		pageEnd = pageStart + FILE_PICKER_PAGE_SIZE;
		if (pageEnd > EntryCount) pageEnd = EntryCount;

		// Draw entries
		for (i = pageStart; i < pageEnd; i++) {
			if ((INTN)i == selected) {
				OUT_PRINT(L"%H> ");
			} else {
				OUT_PRINT(L"  ");
			}

			if (Entries[i].DisplayName != NULL) {
				OUT_PRINT(L"%s", Entries[i].DisplayName);
			} else {
				OUT_PRINT(L"Disk %d Partition %d {%g}",
					Entries[i].DiskNum,
					Entries[i].PartNum,
					&Entries[i].PartGuid);
			}

			if (!Entries[i].HasFS) {
				OUT_PRINT(L" %E(no FS)%N");
			}

			if ((INTN)i == selected) {
				OUT_PRINT(L"%N");
			}
			OUT_PRINT(L"\n");
		}

		// Draw navigation hints
		OUT_PRINT(L"\n");
		if (pageStart > 0) {
			OUT_PRINT(L"[PgUp] Previous  ");
		}
		if (pageEnd < EntryCount) {
			OUT_PRINT(L"[PgDn] Next  ");
		}
		OUT_PRINT(L"[Enter] Select  [Esc] Cancel\n");

		// Get input
		key = GetKey();
		FlushInputDelay(50000);

		if (key.ScanCode == SCAN_ESC) {
			return EFI_DCS_USER_CANCELED;
		}

		if (key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
			if (Entries[selected].HasFS) {
				*SelectedIdx = selected;
				return EFI_SUCCESS;
			}
			// Skip volumes without file system
			continue;
		}

		if (key.ScanCode == SCAN_UP) {
			if (selected > 0) {
				selected--;
				if ((UINTN)selected < pageStart) {
					pageStart = (UINTN)selected;
				}
			}
		}

		if (key.ScanCode == SCAN_DOWN) {
			if ((UINTN)selected < EntryCount - 1) {
				selected++;
				if ((UINTN)selected >= pageEnd) {
					pageStart++;
				}
			}
		}

		if (key.ScanCode == SCAN_PAGE_UP) {
			if (pageStart >= FILE_PICKER_PAGE_SIZE) {
				pageStart -= FILE_PICKER_PAGE_SIZE;
				selected = (INTN)pageStart;
			} else {
				pageStart = 0;
				selected = 0;
			}
		}

		if (key.ScanCode == SCAN_PAGE_DOWN) {
			if (pageStart + FILE_PICKER_PAGE_SIZE < EntryCount) {
				pageStart += FILE_PICKER_PAGE_SIZE;
				selected = (INTN)pageStart;
			}
		}
	}
}

/**
 * Build list of directory entries (directories and matching files)
 */
STATIC EFI_STATUS
FilePickerBuildFileList(
	IN  EFI_FILE                *DirFile,
	IN  CONST CHAR16            **Extensions,
	OUT FILE_PICKER_FILE_ENTRY  **Entries,
	OUT UINTN                   *EntryCount,
	IN  BOOLEAN                 IsRoot
)
{
	EFI_STATUS              res;
	UINT8                   *infoBuf;
	EFI_FILE_INFO           *info;
	UINTN                   bufSize = sizeof(EFI_FILE_INFO) + 512;
	FILE_PICKER_FILE_ENTRY  *list = NULL;
	UINTN                   count = 0;
	UINTN                   capacity = 64;
	UINTN                   readSize;
	BOOLEAN                 isDir;
	BOOLEAN                 matchesFilter;
	FILE_PICKER_FILE_ENTRY  *newList;

	infoBuf = MEM_ALLOC(bufSize);
	if (infoBuf == NULL) {
		return EFI_OUT_OF_RESOURCES;
	}
	info = (EFI_FILE_INFO *)infoBuf;

	list = MEM_ALLOC(capacity * sizeof(FILE_PICKER_FILE_ENTRY));
	if (list == NULL) {
		MEM_FREE(infoBuf);
		return EFI_OUT_OF_RESOURCES;
	}

	// Add ".." entry if not root
	if (!IsRoot) {
		StrCpyS(list[count].Name, 256, L"..");
		list[count].Type = FILE_PICKER_ENTRY_PARENT_DIR;
		count++;
	}

	// Reset directory position
	DirFile->SetPosition(DirFile, 0);

	// Read directory entries
	for (;;) {
		readSize = bufSize;
		res = DirFile->Read(DirFile, &readSize, info);

		if (EFI_ERROR(res) || readSize == 0) {
			break;
		}

		// Skip "." and ".."
		if (StrCmp(info->FileName, L".") == 0 ||
			StrCmp(info->FileName, L"..") == 0) {
			continue;
		}

		isDir = (info->Attribute & EFI_FILE_DIRECTORY) != 0;
		matchesFilter = FALSE;

		if (!isDir) {
			// Check if file matches extension filter
			matchesFilter = FilePickerMatchesExtension(info->FileName, Extensions);
		}

		// Include directories always, files only if they match filter
		if (!isDir && !matchesFilter) {
			continue;
		}

		// Grow array if needed
		if (count >= capacity) {
			capacity *= 2;
			newList = MEM_ALLOC(capacity * sizeof(FILE_PICKER_FILE_ENTRY));
			if (newList == NULL) {
				MEM_FREE(list);
				MEM_FREE(infoBuf);
				return EFI_OUT_OF_RESOURCES;
			}
			CopyMem(newList, list, count * sizeof(FILE_PICKER_FILE_ENTRY));
			MEM_FREE(list);
			list = newList;
		}

		// Add entry
		StrCpyS(list[count].Name, 256, info->FileName);
		list[count].Type = isDir ? FILE_PICKER_ENTRY_DIRECTORY : FILE_PICKER_ENTRY_FILE;
		count++;
	}

	MEM_FREE(infoBuf);

	*Entries = list;
	*EntryCount = count;
	return EFI_SUCCESS;
}

/**
 * Display file browser and handle navigation
 */
STATIC EFI_STATUS
FilePickerBrowseFiles(
	IN  EFI_HANDLE       RootHandle,
	IN  CONST CHAR16     **Extensions,
	IN  CONST CHAR16     *Title,
	OUT CHAR16           **SelectedPath
)
{
	EFI_STATUS              res;
	EFI_FILE                *root = NULL;
	EFI_FILE                *currentDir = NULL;
	CHAR16                  currentPath[512];
	FILE_PICKER_FILE_ENTRY  *entries = NULL;
	UINTN                   entryCount = 0;
	INTN                    selected = 0;
	UINTN                   pageStart = 0;
	UINTN                   pageEnd;
	EFI_INPUT_KEY           key;
	BOOLEAN                 isRoot;
	UINTN                   i;
	FILE_PICKER_FILE_ENTRY  *sel;
	CHAR16                  newPath[512];
	EFI_FILE                *newDir;
	CHAR16                  *fullPath;
	CHAR16                  *lastSlash;
	CHAR16                  *p;

	*SelectedPath = NULL;
	StrCpyS(currentPath, 512, L"\\");

	res = FileOpenRoot(RootHandle, &root);
	if (EFI_ERROR(res)) {
		return res;
	}

	currentDir = root;

	for (;;) {
		// Build file list for current directory
		if (entries != NULL) {
			MEM_FREE(entries);
			entries = NULL;
		}

		isRoot = (StrCmp(currentPath, L"\\") == 0);
		res = FilePickerBuildFileList(currentDir, Extensions, &entries, &entryCount, isRoot);
		if (EFI_ERROR(res)) {
			goto cleanup;
		}

		selected = 0;
		pageStart = 0;

		// Display loop for current directory
		for (;;) {
			gST->ConOut->ClearScreen(gST->ConOut);
			if (Title != NULL) {
				OUT_PRINT(L"=== %s: %s ===\n\n", Title, currentPath);
			} else {
				OUT_PRINT(L"=== Browse: %s ===\n\n", currentPath);
			}

			pageEnd = pageStart + FILE_PICKER_PAGE_SIZE;
			if (pageEnd > entryCount) pageEnd = entryCount;

			for (i = pageStart; i < pageEnd; i++) {
				if ((INTN)i == selected) {
					OUT_PRINT(L"%H> ");
				} else {
					OUT_PRINT(L"  ");
				}

				switch (entries[i].Type) {
				case FILE_PICKER_ENTRY_PARENT_DIR:
					OUT_PRINT(L"[..] Parent Directory");
					break;
				case FILE_PICKER_ENTRY_DIRECTORY:
					OUT_PRINT(L"[DIR] %s", entries[i].Name);
					break;
				case FILE_PICKER_ENTRY_FILE:
					OUT_PRINT(L"      %s", entries[i].Name);
					break;
				}

				if ((INTN)i == selected) {
					OUT_PRINT(L"%N");
				}
				OUT_PRINT(L"\n");
			}

			// Navigation hints
			OUT_PRINT(L"\n");
			if (pageStart > 0) {
				OUT_PRINT(L"[PgUp] Previous  ");
			}
			if (pageEnd < entryCount) {
				OUT_PRINT(L"[PgDn] Next  ");
			}
			OUT_PRINT(L"[Enter] Select  [Esc] Back\n");

			key = GetKey();
			FlushInputDelay(50000);

			if (key.ScanCode == SCAN_ESC) {
				res = EFI_DCS_USER_CANCELED;
				goto cleanup;
			}

			if (key.UnicodeChar == CHAR_CARRIAGE_RETURN && entryCount > 0) {
				sel = &entries[selected];

				if (sel->Type == FILE_PICKER_ENTRY_PARENT_DIR) {
					// Go up one level
					if (currentDir != root) {
						FileClose(currentDir);
					}

					// Remove last path component
					lastSlash = NULL;
					for (p = currentPath; *p; p++) {
						if (*p == L'\\') lastSlash = p;
					}
					if (lastSlash && lastSlash != currentPath) {
						*lastSlash = L'\0';
					} else {
						StrCpyS(currentPath, 512, L"\\");
					}

					// Open parent directory
					res = FileOpen(root, currentPath, &currentDir, EFI_FILE_MODE_READ, 0);
					if (EFI_ERROR(res)) {
						currentDir = root;
						StrCpyS(currentPath, 512, L"\\");
					}
					break; // Rebuild list
				}
				else if (sel->Type == FILE_PICKER_ENTRY_DIRECTORY) {
					// Enter subdirectory
					if (StrCmp(currentPath, L"\\") == 0) {
						UnicodeSPrint(newPath, sizeof(newPath), L"\\%s", sel->Name);
					} else {
						UnicodeSPrint(newPath, sizeof(newPath), L"%s\\%s", currentPath, sel->Name);
					}

					res = FileOpen(root, newPath, &newDir, EFI_FILE_MODE_READ, 0);
					if (!EFI_ERROR(res)) {
						if (currentDir != root) {
							FileClose(currentDir);
						}
						currentDir = newDir;
						StrCpyS(currentPath, 512, newPath);
						break; // Rebuild list
					}
				}
				else if (sel->Type == FILE_PICKER_ENTRY_FILE) {
					// Select file
					fullPath = MEM_ALLOC(512 * sizeof(CHAR16));
					if (fullPath != NULL) {
						if (StrCmp(currentPath, L"\\") == 0) {
							UnicodeSPrint(fullPath, 512 * sizeof(CHAR16), L"\\%s", sel->Name);
						} else {
							UnicodeSPrint(fullPath, 512 * sizeof(CHAR16), L"%s\\%s", currentPath, sel->Name);
						}
						*SelectedPath = fullPath;
						res = EFI_SUCCESS;
						goto cleanup;
					}
				}
			}

			// Navigation
			if (key.ScanCode == SCAN_UP && selected > 0) {
				selected--;
				if ((UINTN)selected < pageStart) {
					pageStart = (UINTN)selected;
				}
			}

			if (key.ScanCode == SCAN_DOWN && (UINTN)selected < entryCount - 1) {
				selected++;
				if ((UINTN)selected >= pageEnd) {
					pageStart++;
				}
			}

			if (key.ScanCode == SCAN_PAGE_UP) {
				if (pageStart >= FILE_PICKER_PAGE_SIZE) {
					pageStart -= FILE_PICKER_PAGE_SIZE;
					selected = (INTN)pageStart;
				} else {
					pageStart = 0;
					selected = 0;
				}
			}

			if (key.ScanCode == SCAN_PAGE_DOWN) {
				if (pageStart + FILE_PICKER_PAGE_SIZE < entryCount) {
					pageStart += FILE_PICKER_PAGE_SIZE;
					selected = (INTN)pageStart;
				}
			}
		}
	}

cleanup:
	if (entries != NULL) MEM_FREE(entries);
	if (currentDir != NULL && currentDir != root) FileClose(currentDir);
	if (root != NULL) FileClose(root);
	return res;
}

//////////////////////////////////////////////////////////////////////////
// Public API
//////////////////////////////////////////////////////////////////////////

/**
 * Initialize file picker configuration with defaults
 */
VOID
FilePickerInitConfig(
	OUT FILE_PICKER_CONFIG  *Config
)
{
	if (Config != NULL) {
		ZeroMem(Config, sizeof(FILE_PICKER_CONFIG));
	}
}

/**
 * Display file picker UI with full configuration
 */
EFI_STATUS
EFIAPI
FilePickerShow(
	IN  CONST FILE_PICKER_CONFIG  *Config   OPTIONAL,
	OUT EFI_HANDLE                *SelectedHandle,
	OUT CHAR16                    **SelectedPath
)
{
	EFI_STATUS                res;
	FILE_PICKER_VOLUME_ENTRY  *volumes = NULL;
	UINTN                     volumeCount = 0;
	INTN                      selectedVolume = 0;
	CHAR16                    *selectedPath = NULL;
	EFI_HANDLE                volumeHandle;
	CONST CHAR16              **extensions = NULL;
	CHAR16                    *title = NULL;

	// Validate parameters
	if (SelectedHandle == NULL || SelectedPath == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	*SelectedHandle = NULL;
	*SelectedPath = NULL;

	// Extract config values
	if (Config != NULL) {
		extensions = Config->Extensions;
		title = Config->Title;
	}

	for (;;) {
		// Build volume list
		res = FilePickerBuildVolumeList(Config, &volumes, &volumeCount);
		if (EFI_ERROR(res)) {
			return res;
		}

		// Show volume selection
		res = FilePickerSelectVolume(volumes, volumeCount, title, &selectedVolume);
		if (EFI_ERROR(res)) {
			FilePickerFreeVolumeList(volumes, volumeCount);
			gST->ConOut->ClearScreen(gST->ConOut);
			return res;
		}

		volumeHandle = volumes[selectedVolume].Handle;
		FilePickerFreeVolumeList(volumes, volumeCount);
		volumes = NULL;

		// Browse files on selected volume
		res = FilePickerBrowseFiles(volumeHandle, extensions, title, &selectedPath);
		if (res == EFI_DCS_USER_CANCELED) {
			// User wants to go back to volume selection
			continue;
		}
		if (EFI_ERROR(res)) {
			return res;
		}

		// Success - return results
		*SelectedHandle = volumeHandle;
		*SelectedPath = selectedPath;
		return EFI_SUCCESS;
	}
}

/**
 * Simplified file picker for common use cases
 */
EFI_STATUS
EFIAPI
FilePickerSelectFile(
	IN  CONST CHAR16  **Extensions    OPTIONAL,
	IN  CONST CHAR16  *Title          OPTIONAL,
	OUT EFI_HANDLE    *SelectedHandle,
	OUT CHAR16        **SelectedPath
)
{
	FILE_PICKER_CONFIG config;

	FilePickerInitConfig(&config);
	config.Extensions = Extensions;
	config.Title = (CHAR16 *)Title;

	return FilePickerShow(&config, SelectedHandle, SelectedPath);
}
