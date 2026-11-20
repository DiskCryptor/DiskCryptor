/** @file
EFI firmware variable helpers

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 

This program and the accompanying materials are licensed and made available
under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Library/CommonLib.h>

#include <Uefi.h>
#include <Guid/GlobalVariable.h>
#include <Protocol/DevicePath.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DevicePathLib.h>
#include <Library/BaseMemoryLib.h>

//////////////////////////////////////////////////////////////////////////
// Efi variables
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
EfiGetVar(
   IN  CONST CHAR16*    varName,
   IN  EFI_GUID*        varGuid,
   OUT VOID**           varValue,
   OUT UINTN*           varSize,
   OUT UINT32*          varAttr
   ) {
   EFI_STATUS          Status;
   CHAR8               *varData = NULL;
   if (varSize == NULL) return EFI_INVALID_PARAMETER;
   *varSize = 0;
   if (varGuid == NULL) varGuid = &gEfiDcsVariableGuid;
   Status = gST->RuntimeServices->GetVariable((CHAR16*)varName, varGuid, varAttr, varSize, varData);
   if (Status == EFI_BUFFER_TOO_SMALL) {
      // Extra zeroed CHAR16 (+1 byte for odd sizes) so string callers always see a terminator
      if (*varSize > MAX_UINTN - sizeof(CHAR16) - 1) {
         return EFI_BUFFER_TOO_SMALL;
      }
      varData = MEM_ALLOC(*varSize + sizeof(CHAR16) + 1);
      if (varData == NULL) {
         return EFI_BUFFER_TOO_SMALL;
      }
      Status = gST->RuntimeServices->GetVariable((CHAR16*)varName, varGuid, varAttr, varSize, varData);
      if (EFI_ERROR(Status)) {
         MEM_FREE(varData);
         varData = NULL;
      }
      *varValue = varData;
   }
   return Status;
}


EFI_STATUS
EfiSetVar(
   IN  CONST CHAR16*    varName,
   IN  EFI_GUID*        varGuid,
   IN  VOID*            varValue,
   IN  UINTN            varSize,
   IN  UINT32           varAttr
   ) {
   EFI_STATUS          Status;
   if (varGuid == NULL) varGuid = &gEfiDcsVariableGuid;
   Status = gST->RuntimeServices->SetVariable((CHAR16*)varName, varGuid, varAttr, varSize, varValue);
   return Status;
}

EFI_STATUS
BootOrderInsert(
	IN CHAR16 *OrderVarName,
	IN UINTN index,
	UINT16   value)
{
	EFI_STATUS res = EFI_NOT_READY;
	UINT16*   varBootOrderNew;
	UINT16*   varBootOrder;
	UINTN     varBootOrderSize;
	UINT32    varBootOrderAttr;
	UINTN     BootOrderCount;
	UINTN     i;
	UINTN     j;
	res = EfiGetVar(OrderVarName, &gEfiGlobalVariableGuid, &varBootOrder, &varBootOrderSize, &varBootOrderAttr);
	if (res == EFI_NOT_FOUND) {
		res = EfiSetVar(OrderVarName, &gEfiGlobalVariableGuid, &value, 2,
			EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS);
		return res;
	}
	if (EFI_ERROR(res)) return res;
	BootOrderCount = varBootOrderSize / sizeof(UINT16);
	varBootOrderNew = MEM_ALLOC((BootOrderCount + 1) * sizeof(UINT16));
	if (varBootOrderNew == NULL) {
		MEM_FREE(varBootOrder);
		return EFI_OUT_OF_RESOURCES;
	}
	if (BootOrderCount < index) index = BootOrderCount;
	for (j = 0, i = 0; i < BootOrderCount; ++i) {
		if (j == index) {
			varBootOrderNew[j] = value;
			j++;
		}
		if (varBootOrder[i] == value) {
			continue;
		}
		varBootOrderNew[j] = varBootOrder[i];
		++j;
	}
	// Not inserted inside the loop (index at or past the end): append
	if (j <= index) {
		varBootOrderNew[j] = value;
		j++;
	}
	BootOrderCount = j;

	res = EfiSetVar(OrderVarName, &gEfiGlobalVariableGuid,
		varBootOrderNew, BootOrderCount * sizeof(UINT16),
		EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS);
	MEM_FREE(varBootOrderNew);
	MEM_FREE(varBootOrder);
	return res;
}

EFI_STATUS
BootOrderRemove(
	IN CHAR16 *OrderVarName,
	UINT16   value)
{
	EFI_STATUS res = EFI_NOT_READY;
	UINT16*   varBootOrderNew;
	UINT16*   varBootOrder;
	UINTN     varBootOrderSize;
	UINT32    varBootOrderAttr;
	UINTN     BootOrderCount;
	UINTN     i;
	UINTN     j;

	res = EfiGetVar(OrderVarName, &gEfiGlobalVariableGuid, &varBootOrder, &varBootOrderSize, &varBootOrderAttr);
	if (EFI_ERROR(res)) return res;
	BootOrderCount = varBootOrderSize / sizeof(UINT16);
	varBootOrderNew = MEM_ALLOC((BootOrderCount + 1) * sizeof(UINT16));
	if (varBootOrderNew == NULL) {
		MEM_FREE(varBootOrder);
		return EFI_OUT_OF_RESOURCES;
	}
	for (j = 0, i = 0; i < BootOrderCount; ++i) {
		if (varBootOrder[i] == value) {
			continue;
		}
		varBootOrderNew[j] = varBootOrder[i];
		++j;
	}
	BootOrderCount = j;

	res = EfiSetVar(OrderVarName, &gEfiGlobalVariableGuid,
		varBootOrderNew, BootOrderCount * sizeof(UINT16),
		EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS);

	MEM_FREE(varBootOrderNew);
	MEM_FREE(varBootOrder);
	return res;
}

EFI_STATUS
BootOrderPresent(
    IN CHAR16 *OrderVarName,
    UINT16    value,
    UINTN     *index)
{
    EFI_STATUS res = EFI_NOT_READY;
    UINT16*   varBootOrder;
    UINTN     varBootOrderSize;
    UINT32    varBootOrderAttr;
    UINTN     BootOrderCount;
    UINTN     i;

    res = EfiGetVar(OrderVarName, &gEfiGlobalVariableGuid, &varBootOrder, &varBootOrderSize, &varBootOrderAttr);
    if (EFI_ERROR(res)) return res;
    BootOrderCount = varBootOrderSize / sizeof(UINT16);
    res = EFI_NOT_FOUND;
    for (i = 0; i < BootOrderCount; ++i) {
        if (varBootOrder[i] == value) {
            res = EFI_SUCCESS;
            break;
        }
    }
    if (index != NULL) *index = i;
    MEM_FREE(varBootOrder);
    return res;
}

EFI_STATUS
BootMenuItemRemove(
	IN CHAR16     *VarName
	)
{
	EFI_STATUS res = EFI_NOT_READY;
	res = EfiSetVar(
		VarName, &gEfiGlobalVariableGuid,
		NULL, 0,
		EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS);
	return res;
}

EFI_STATUS
BootMenuItemCreate(
	IN CHAR16     *VarName,
	IN CHAR16     *Desc,
	IN EFI_HANDLE volumeHandle,
	IN CHAR16     *Path,
	IN BOOLEAN    Reduced
	)
{
	EFI_STATUS res = EFI_NOT_READY;
	UINT8*    varBoot;
	UINT8*    TempByteBuffer;
	UINTN     DescSize;
	UINTN     FilePathSize;
	EFI_DEVICE_PATH_PROTOCOL*  DevPath;
	EFI_DEVICE_PATH_PROTOCOL*  DevicePath;
	EFI_DEVICE_PATH_PROTOCOL*  FileNode;
	EFI_DEVICE_PATH_PROTOCOL*  FilePath;

	// Prepare
	DevicePath = DevicePathFromHandle(volumeHandle);
	if (Reduced) {
		DevPath = DevicePath;
		while (!IsDevicePathEnd(DevPath)) {
			if ((DevicePathType(DevPath) == MEDIA_DEVICE_PATH) &&
				(DevicePathSubType(DevPath) == MEDIA_HARDDRIVE_DP)) {

				//
				// If we find it use it instead
				//
				DevicePath = DevPath;
				break;
			}
			DevPath = NextDevicePathNode(DevPath);
		}
	}
	//
	// append the file
	//
	FileNode = FileDevicePath(NULL, Path);
	if (FileNode == NULL) {
		return EFI_OUT_OF_RESOURCES;
	}
	FilePath = AppendDevicePath(DevicePath, FileNode);
	FreePool(FileNode);
	if (FilePath == NULL) {
		return EFI_OUT_OF_RESOURCES;
	}
	//
	// Add the option
	//
	DescSize = StrSize(Desc);
	FilePathSize = GetDevicePathSize(FilePath);

	varBoot = MEM_ALLOC(sizeof(UINT32) + sizeof(UINT16) + DescSize + FilePathSize);
	if (varBoot != NULL) {
		TempByteBuffer = varBoot;
		*((UINT32 *)TempByteBuffer) = LOAD_OPTION_ACTIVE;      // Attributes
		TempByteBuffer += sizeof(UINT32);

		*((UINT16 *)TempByteBuffer) = (UINT16)FilePathSize;    // FilePathListLength
		TempByteBuffer += sizeof(UINT16);

		CopyMem(TempByteBuffer, Desc, DescSize);
		TempByteBuffer += DescSize;
		CopyMem(TempByteBuffer, FilePath, FilePathSize);

		res = EfiSetVar(VarName, &gEfiGlobalVariableGuid,
			varBoot, sizeof(UINT32) + sizeof(UINT16) + DescSize + FilePathSize,
			EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS);
	}
	else {
		FreePool(FilePath);
		return EFI_BUFFER_TOO_SMALL;
	}

	FreePool(FilePath);
	MEM_FREE(varBoot);
	return res;
}
