/** @file
Block R/W interceptor

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI
Copyright (c) 2019. DiskCryptor, David Xanatos

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Library/DcsIntLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/DevicePathLib.h>
#include <Library/BaseMemoryLib.h>
#include <DcsConfig.h>

#include <Library/CommonLib.h>

#if 0
 #define TRC_HANDLE_PATH(msg,h)                     \
                   OUT_PRINT(msg);                  \
                   EfiPrintDevicePath(h);           \
                   OUT_PRINT(L"\n")

 #define TRC_DEVICE_PATH(msg,h)                     \
                   OUT_PRINT(msg);                  \
                   EfiPrintPath(h);                 \
                   OUT_PRINT(L"\n")
#else
 #define TRC_HANDLE_PATH(msg,h)
 #define TRC_DEVICE_PATH(msg,h)
#endif

DCSINT_MOUNT*  DcsIntMountFirst = NULL; //< List of mounts head
DCSINT_BLOCK_IO*  DcsIntBlockIoFirst = NULL; //< List of block I/O head
DCSINT_LATE_PARTITION gDcsIntLatePartition = NULL; //< classifier for partitions connected later

EFI_DRIVER_BINDING_PROTOCOL g_DcsIntDriverBinding = {
	DcsIntBindingSupported,
	DcsIntBindingStart,
	DcsIntBindingStop,
	DCSINT_DRIVER_VERSION,
	NULL,
	NULL
};

void HaltPrint(const CHAR16* Msg)
{
	CleanSensitiveData(TRUE); // panic
	Print(L"%s\n", Msg);
	KeyWait(L"Halting Cpu in %02d s\r", 10, 0, 0);
	EfiCpuHalt();
}

//////////////////////////////////////////////////////////////////////////
// List of Mounts
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
AddCryptoMount(
	IN EFI_DEVICE_PATH* DevicePath,
	IN EFI_BLOCK_READ	FilterRead,
	IN EFI_BLOCK_WRITE	FilterWrite,
	IN VOID*			FilterParams
)
{
	DCSINT_MOUNT *DcsIntMount;

	TRC_DEVICE_PATH(L"s:", DevicePath);

	DcsIntMount = (DCSINT_MOUNT *)MEM_ALLOC(sizeof(DCSINT_MOUNT));
	if (DcsIntMount == NULL) {
		return EFI_OUT_OF_RESOURCES;
	}

	// an own copy - the handle's device path is freed when the handle goes away
	DcsIntMount->DevicePath = DuplicateDevicePath(DevicePath);
	if (DcsIntMount->DevicePath == NULL) {
		MEM_FREE(DcsIntMount);
		return EFI_OUT_OF_RESOURCES;
	}

	DcsIntMount->FilterRead = FilterRead;
	DcsIntMount->FilterWrite = FilterWrite;
	DcsIntMount->FilterParams = FilterParams;

	// add to global list
	if (DcsIntMountFirst == NULL) {
		DcsIntMountFirst = DcsIntMount;
		DcsIntMountFirst->Next = NULL;
	}
	else {
		DcsIntMount->Next = DcsIntMountFirst;
		DcsIntMountFirst = DcsIntMount;
	}

	return EFI_SUCCESS;
}

DCSINT_MOUNT*
GetMountByPath(
	IN EFI_DEVICE_PATH *DevicePath)
{
	if (DevicePath == NULL) return NULL;
	DCSINT_MOUNT *DcsIntMount = DcsIntMountFirst;
	while (DcsIntMount != NULL) {
		UINTN Size = GetDevicePathSize(DcsIntMount->DevicePath);
		if (GetDevicePathSize(DevicePath) == Size && CompareMem(DevicePath, DcsIntMount->DevicePath, Size) == 0) {
			return DcsIntMount;
		}
		DcsIntMount = DcsIntMount->Next;
	}
	return NULL;
}

//////////////////////////////////////////////////////////////////////////
// List of block I/O
//////////////////////////////////////////////////////////////////////////

// TRUE while the entry's partition still exists (its handle still carries the hooked BlockIo)
STATIC
BOOLEAN
IntBlockIo_IsLive(
	IN DCSINT_BLOCK_IO *DcsIntBlockIo)
{
	EFI_BLOCK_IO_PROTOCOL *BlockIo = NULL;

	return !EFI_ERROR(gBS->HandleProtocol(DcsIntBlockIo->Controller, &gEfiBlockIoProtocolGuid, (VOID**)&BlockIo)) &&
		BlockIo == DcsIntBlockIo->BlockIo;
}

// Drop the entries of partitions that went away. Unlinked, never freed: a hot plug can
// interrupt a lookup that stands on the entry (its Next stays valid).
STATIC
VOID
IntBlockIo_DropStale(VOID)
{
	DCSINT_BLOCK_IO **Link = &DcsIntBlockIoFirst;

	while (*Link != NULL) {
		DCSINT_BLOCK_IO *Entry = *Link;
		if (!IntBlockIo_IsLive(Entry)) {
			*Link = Entry->Next;
			continue;
		}
		Link = &Entry->Next;
	}
}

DCSINT_BLOCK_IO*
GetBlockIoByHandle(
	IN EFI_HANDLE handle)
{
	DCSINT_BLOCK_IO *DcsIntBlockIo;

	IntBlockIo_DropStale();   // a reused handle value must not look hooked
	DcsIntBlockIo = DcsIntBlockIoFirst;
	while (DcsIntBlockIo != NULL) {
		if (DcsIntBlockIo->Controller == handle) {
			return DcsIntBlockIo;
		}
		DcsIntBlockIo = DcsIntBlockIo->Next;
	}
	return NULL;
}

DCSINT_BLOCK_IO*
GetBlockIoByProtocol(
	IN EFI_BLOCK_IO_PROTOCOL* protocol)
{
	DCSINT_BLOCK_IO *DcsIntBlockIo = DcsIntBlockIoFirst;
	while (DcsIntBlockIo != NULL) {
		if (DcsIntBlockIo->BlockIo == protocol) {
			return DcsIntBlockIo;
		}
		DcsIntBlockIo = DcsIntBlockIo->Next;
	}
	return NULL;
}

//////////////////////////////////////////////////////////////////////////
// Block IO2 hook
//////////////////////////////////////////////////////////////////////////
// The partition's BlockIo2 would bypass the filter: its requests run synchronously through the
// hooked BlockIo, then the caller's token is completed.

STATIC
DCSINT_BLOCK_IO*
GetBlockIoByProtocol2(
	IN EFI_BLOCK_IO2_PROTOCOL* protocol)
{
	DCSINT_BLOCK_IO *DcsIntBlockIo = DcsIntBlockIoFirst;
	while (DcsIntBlockIo != NULL) {
		if (DcsIntBlockIo->BlockIo2 == protocol) {
			return DcsIntBlockIo;
		}
		DcsIntBlockIo = DcsIntBlockIo->Next;
	}
	return NULL;
}

// A request done synchronously: an error is returned as is (the token is not signalled); on success
// a non-blocking caller's token gets the status and its event is signalled.
STATIC
EFI_STATUS
IntBlockIo2_Complete(
	IN EFI_BLOCK_IO2_TOKEN  *Token,
	IN EFI_STATUS           Status)
{
	if (EFI_ERROR(Status)) {
		return Status;
	}
	if (Token != NULL && Token->Event != NULL) {
		Token->TransactionStatus = EFI_SUCCESS;
		gBS->SignalEvent(Token->Event);
	}
	return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
IntBlockIo2_ReadEx(
	IN     EFI_BLOCK_IO2_PROTOCOL *This,
	IN     UINT32                 MediaId,
	IN     EFI_LBA                Lba,
	IN OUT EFI_BLOCK_IO2_TOKEN    *Token,
	IN     UINTN                  BufferSize,
	OUT    VOID                   *Buffer)
{
	DCSINT_BLOCK_IO *DcsIntBlockIo = GetBlockIoByProtocol2(This);
	if (DcsIntBlockIo == NULL || DcsIntBlockIo->BlockIo == NULL) {
		return EFI_DEVICE_ERROR;
	}
	return IntBlockIo2_Complete(Token,
		DcsIntBlockIo->BlockIo->ReadBlocks(DcsIntBlockIo->BlockIo, MediaId, Lba, BufferSize, Buffer));
}

STATIC
EFI_STATUS
EFIAPI
IntBlockIo2_WriteEx(
	IN     EFI_BLOCK_IO2_PROTOCOL *This,
	IN     UINT32                 MediaId,
	IN     EFI_LBA                Lba,
	IN OUT EFI_BLOCK_IO2_TOKEN    *Token,
	IN     UINTN                  BufferSize,
	IN     VOID                   *Buffer)
{
	DCSINT_BLOCK_IO *DcsIntBlockIo = GetBlockIoByProtocol2(This);
	if (DcsIntBlockIo == NULL || DcsIntBlockIo->BlockIo == NULL) {
		return EFI_DEVICE_ERROR;
	}
	return IntBlockIo2_Complete(Token,
		DcsIntBlockIo->BlockIo->WriteBlocks(DcsIntBlockIo->BlockIo, MediaId, Lba, BufferSize, Buffer));
}

//////////////////////////////////////////////////////////////////////////
// Block IO hook
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
IntBlockIo_Hook(
	IN EFI_DRIVER_BINDING_PROTOCOL   *This,
	IN EFI_HANDLE                    Controller
	)
{
	EFI_DEVICE_PATH         *DevicePath;
	DCSINT_MOUNT            *DcsIntMount;
	EFI_BLOCK_IO_PROTOCOL   *BlockIo;
	EFI_BLOCK_IO2_PROTOCOL  *BlockIo2;
	DCSINT_BLOCK_IO         *DcsIntBlockIo = 0;
	EFI_STATUS              Status;
//	EFI_TPL                 Tpl;

	// Already hook?
	DcsIntBlockIo = GetBlockIoByHandle(Controller);
	if (DcsIntBlockIo != NULL) {
		return EFI_SUCCESS;
	}

	DevicePath = DevicePathFromHandle(Controller);

	DcsIntMount = GetMountByPath(DevicePath);
	if (DcsIntMount == NULL) {
		ERR_PRINT(L"\nCan't get mount entry\n");
		return EFI_NOT_FOUND;
	}

	Status = gBS->OpenProtocol(
		Controller,
		&gEfiBlockIoProtocolGuid,
		(VOID**)&BlockIo,
		This->DriverBindingHandle,
		Controller,
		EFI_OPEN_PROTOCOL_GET_PROTOCOL
		);

	if (!EFI_ERROR(Status)) {
		// Check is this protocol already hooked
		DcsIntBlockIo = (DCSINT_BLOCK_IO *)MEM_ALLOC(sizeof(DCSINT_BLOCK_IO));
		if (DcsIntBlockIo == NULL) {
			return EFI_OUT_OF_RESOURCES;
		}

		// construct new DcsIntBlockIo
		DcsIntBlockIo->Sign = DCSINT_BLOCK_IO_SIGN;
		DcsIntBlockIo->Controller = Controller;
		DcsIntBlockIo->BlockIo = BlockIo;
		//DcsIntBlockIo->IsReinstalled = 0;
// Block
//		Tpl = gBS->RaiseTPL(TPL_NOTIFY);
		// Install new routines
		DcsIntBlockIo->FilterParams = DcsIntMount->FilterParams;
		DcsIntBlockIo->LowRead = BlockIo->ReadBlocks;
		DcsIntBlockIo->LowWrite = BlockIo->WriteBlocks;
		BlockIo->ReadBlocks = DcsIntMount->FilterRead;
		BlockIo->WriteBlocks = DcsIntMount->FilterWrite;

		// the same partition's BlockIo2 goes through the hooked BlockIo
		if (!EFI_ERROR(gBS->OpenProtocol(
			Controller,
			&gEfiBlockIo2ProtocolGuid,
			(VOID**)&BlockIo2,
			This->DriverBindingHandle,
			Controller,
			EFI_OPEN_PROTOCOL_GET_PROTOCOL)) && BlockIo2 != NULL) {
			DcsIntBlockIo->BlockIo2 = BlockIo2;
			BlockIo2->ReadBlocksEx = IntBlockIo2_ReadEx;
			BlockIo2->WriteBlocksEx = IntBlockIo2_WriteEx;
		}

		// close protocol before reinstall
		gBS->CloseProtocol(
			Controller,
			&gEfiBlockIoProtocolGuid,
			This->DriverBindingHandle,
			Controller
			);

		// add to global list
		if (DcsIntBlockIoFirst == NULL) {
			DcsIntBlockIoFirst = DcsIntBlockIo;
			DcsIntBlockIoFirst->Next = NULL;
		}
		else {
			DcsIntBlockIo->Next = DcsIntBlockIoFirst;
			DcsIntBlockIoFirst = DcsIntBlockIo;
		}

		// reinstall BlockIo protocol
		//Status = gBS->ReinstallProtocolInterface( // Why does this result in windows boot hanging with a simple passthrough hook?
		//	Controller,
		//	&gEfiBlockIoProtocolGuid,
		//	BlockIo,
		//	BlockIo
		//);

//		gBS->RestoreTPL(Tpl);
		//DcsIntBlockIo->IsReinstalled = 1;

		Status = EFI_SUCCESS;
	}
	return Status;
}

//////////////////////////////////////////////////////////////////////////
// DriverBinding routines
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
DcsIntBindingStart(
	IN EFI_DRIVER_BINDING_PROTOCOL  *This,
	IN EFI_HANDLE                   Controller,
	IN EFI_DEVICE_PATH_PROTOCOL     *RemainingDevicePath
	)
{
	EFI_STATUS     Status;

	TRC_HANDLE_PATH(L"t: ", Controller);

	// a partition connected after the mounts were set up gets its entry now (Supported
	// accepted it through the same callback); if that fails, IntBlockIo_Hook finds no entry
	if (GetMountByPath(DevicePathFromHandle(Controller)) == NULL && gDcsIntLatePartition != NULL) {
		gDcsIntLatePartition(Controller, TRUE);
	}

	// hook blockIo
	Status = IntBlockIo_Hook(This, Controller);
	if (EFI_ERROR(Status)) {
		HaltPrint(L"IO Hook Failed");
	}
	return Status;
}

EFI_STATUS
DcsIntBindingSupported(
	IN EFI_DRIVER_BINDING_PROTOCOL  *This,
	IN EFI_HANDLE                   Controller,
	IN EFI_DEVICE_PATH_PROTOCOL     *RemainingDevicePath
	)
{
	EFI_DEVICE_PATH *DevicePath;

	//TRC_HANDLE_PATH(L"b: ", Controller); // thats a lot

	DevicePath = DevicePathFromHandle(Controller);
	DCSINT_MOUNT* DcsIntMount = GetMountByPath(DevicePath);
	if (DcsIntMount || (DevicePath != NULL && gDcsIntLatePartition != NULL && gDcsIntLatePartition(Controller, FALSE))) {
		DCSINT_BLOCK_IO*  DcsIntBlockIo = NULL;
		// Is installed?
		DcsIntBlockIo = GetBlockIoByHandle(Controller);
		if (DcsIntBlockIo != NULL) {
			return EFI_UNSUPPORTED;
		}
		return EFI_SUCCESS;
	}
	return EFI_UNSUPPORTED;
}

EFI_STATUS
DcsIntBindingStop(
	IN  EFI_DRIVER_BINDING_PROTOCOL  *This,
	IN  EFI_HANDLE                   Controller,
	IN  UINTN                        NumberOfChildren,
	IN  EFI_HANDLE                   *ChildHandleBuffer
	)
{
	TRC_HANDLE_PATH(L"p: ", Controller);
	return EFI_SUCCESS;
}

EFI_STATUS
DscInstallHook(
	IN EFI_HANDLE ImageHandle,
	IN EFI_SYSTEM_TABLE *SystemTable)
{
	return EfiLibInstallDriverBindingComponentName2(
		ImageHandle,
		SystemTable,
		&g_DcsIntDriverBinding,
		ImageHandle,
		&gDcsIntComponentName,
		&gDcsIntComponentName2);

	//Note: For the hook to be applied ConnectAllEfi(); must be called.
}
