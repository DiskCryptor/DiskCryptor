/** @file
  This is DCS boot menu lock application

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Uefi.h>
#include <Guid/EventGroup.h>
#include <Guid/GlobalVariable.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeLib.h>
#include <Library/BaseLib.h>
#include <Library/UefiLib.h>

#include <Library/CommonLib.h>

#include <Protocol/DcsBmlProto.h>
#include <DcsConfig.h>
#include "DcsBml.h"

//////////////////////////////////////////////////////////////////////////
// Runtime data to lock
//////////////////////////////////////////////////////////////////////////
typedef struct _BML_GLOBALS {
	UINT64		Signature;
	UINTN			size;
} BML_GLOBALS, *PBML_GLOBALS;

STATIC PBML_GLOBALS   gBmlData = NULL;
STATIC BOOLEAN        BootMenuLocked = FALSE;
EFI_EVENT             mBmlVirtualAddrChangeEvent;
EFI_SET_VARIABLE      orgSetVariable = NULL;

EFI_STATUS
BmlSetVariable(
	IN  CHAR16                       *VariableName,
	IN  EFI_GUID                     *VendorGuid,
	IN  UINT32                       Attributes,
	IN  UINTN                        DataSize,
	IN  VOID                         *Data
	) {
	// DcsBoot remove?
	if (VariableName != NULL && StrStr(VariableName, L"BootDC5B") == VariableName && DataSize == 0) {
		BootMenuLocked = FALSE;
	}

	if (BootMenuLocked) {
		// Block all Boot*
		if (VariableName != NULL && StrStr(VariableName, L"Boot") == VariableName) {
			//return EFI_ACCESS_DENIED;
			return EFI_SUCCESS; // Report success to avoid error messages in logs, but do not allow changes
		}
	}
	return orgSetVariable(VariableName, VendorGuid, Attributes, DataSize, Data);
}

/**
Fixup internal data so that EFI can be called in virtual mode.
Call the passed in Child Notify event and convert any pointers in
lib to virtual mode.

@param[in]    Event   The Event that is being processed
@param[in]    Context Event Context
**/

VOID
EFIAPI
BmlVirtualNotifyEvent(
	IN EFI_EVENT        Event,
	IN VOID             *Context
	)
{
	EfiConvertPointer(0x0, (VOID**)&gBmlData);
	EfiConvertPointer(0x0, (VOID**)&orgSetVariable);
	return;
}

//////////////////////////////////////////////////////////////////////////
// Boot order
//////////////////////////////////////////////////////////////////////////
CHAR16* sDcsBootEfi = L"EFI\\" DCS_DIRECTORY L"\\DcsBoot.efi";
CHAR16* sDcsBootEfiDesc = _T(DCS_CAPTION) L"(DCS) loader";

EFI_STATUS
UpdateBootOrder()
{
    EFI_STATUS          res;
    UINTN               len;
    UINT32              attr;
    CHAR16*             tmp = NULL;
    res = EfiGetVar(L"BootDC5B", &gEfiGlobalVariableGuid, &tmp, &len, &attr);
    if (EFI_ERROR(res)) {
        InitFS();
        res = BootMenuItemCreate(L"BootDC5B", sDcsBootEfiDesc, gFileRootHandle, sDcsBootEfi, TRUE);
        res = BootOrderInsert(L"BootOrder", 0, 0x0DC5B);
    }
    else {
        UINTN               boIndex = 1;
        if (EFI_ERROR(BootOrderPresent(L"BootOrder", 0x0DC5B, &boIndex)) || boIndex != 0) {
            res = BootOrderInsert(L"BootOrder", 0, 0x0DC5B);
        }
    }
    MEM_FREE(tmp);
    return res;
}

//////////////////////////////////////////////////////////////////////////
// DcsBml protocol to control lock in BS mode
//////////////////////////////////////////////////////////////////////////
GUID gEfiDcsBmlProtocolGuid = EFI_DCSBML_INTERFACE_PROTOCOL_GUID;
EFI_DCSBML_PROTOCOL gEfiDcsBmlProtocol = {
    BootMenuLock
};

EFI_STATUS
BootMenuLock(
    IN EFI_DCSBML_PROTOCOL                *This,
    IN     UINT32                          LockFlags
    ) {
    if ((LockFlags & BML_UPDATE_BOOTORDER) == BML_UPDATE_BOOTORDER) {
        UpdateBootOrder();
    }
    if ((LockFlags & BML_SET_BOOTNEXT) == BML_SET_BOOTNEXT) {
        UINT16              DcsBootNum = 0x0DC5B;
        EfiSetVar(L"BootNext", &gEfiGlobalVariableGuid, &DcsBootNum, sizeof(DcsBootNum), EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS);
    }
    if ((LockFlags & BML_LOCK_SETVARIABLE) == BML_LOCK_SETVARIABLE) {
        if (orgSetVariable == NULL) {
            BootMenuLocked = TRUE;
            orgSetVariable = gST->RuntimeServices->SetVariable;
            gST->RuntimeServices->SetVariable = BmlSetVariable;
        }
    }
    return EFI_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
// Driver
//////////////////////////////////////////////////////////////////////////

/**
Unloads an image.

@param  ImageHandle           Handle that identifies the image to be unloaded.

@retval EFI_SUCCESS           The image has been unloaded.
@retval EFI_INVALID_PARAMETER ImageHandle is not a valid image handle.

**/
EFI_STATUS
EFIAPI
DcsBmlUnload(
    IN EFI_HANDLE  ImageHandle
    )
{
    EFI_STATUS  res;

    res = EFI_SUCCESS;
    //
    // Uninstall Driver Supported EFI Version Protocol onto ImageHandle
    //
    res = gBS->UninstallMultipleProtocolInterfaces(
        ImageHandle,
        &gEfiDcsBmlProtocolGuid, &gEfiDcsBmlProtocol,
        NULL
        );

    if (EFI_ERROR(res)) {
        return res;
    }
    // Clean up
    return EFI_SUCCESS;
}

/**
The actual entry point for the application.

@param[in] ImageHandle    The firmware allocated handle for the EFI image.
@param[in] SystemTable    A pointer to the EFI System Table.

@retval EFI_SUCCESS       The entry point executed successfully.
@retval other             Some error occur when executing this entry point.

**/
EFI_STATUS
EFIAPI
DcsBmlMain(
   IN EFI_HANDLE        ImageHandle,
   IN EFI_SYSTEM_TABLE  *SystemTable
   )
{
   EFI_STATUS          res;
   // Check multiple execution of DcsBml
   if (!EFI_ERROR(InitBml())) {
       return EFI_ACCESS_DENIED;
   }

#ifdef DEBUG_BUILD
   OUT_PRINT(L"DcsBml - DEBUG Build %s %s\n", _T(__DATE__), _T(__TIME__));
#endif

   //
   // Install DcsBml protocol onto ImageHandle
   //
   res = gBS->InstallMultipleProtocolInterfaces(
       &ImageHandle,
       &gEfiDcsBmlProtocolGuid, &gEfiDcsBmlProtocol,
       NULL
       );
   ASSERT_EFI_ERROR(res);

   if (EFI_ERROR(res)) {
       ERR_PRINT(L"Install protocol %r\n", res);
       return res;
   }

    // runtime lock
	res = gBS->AllocatePool(
		EfiRuntimeServicesData,
		(UINTN) sizeof(BML_GLOBALS),
		(VOID**)&gBmlData
		);

	if (EFI_ERROR(res)) {
        ERR_PRINT(L"Allocate runtime globals %r\n", res);
		return res;
	}

	//
	// Register for the virtual address change event
	//
	res = gBS->CreateEventEx(
		EVT_NOTIFY_SIGNAL,
		TPL_NOTIFY,
		BmlVirtualNotifyEvent,
		NULL,
		&gEfiEventVirtualAddressChangeGuid,
		&mBmlVirtualAddrChangeEvent
		);

   if (EFI_ERROR(res)) {
		ERR_PRINT(L"Register notify %r\n", res);
		return res;
   }

	return EFI_SUCCESS;
}
