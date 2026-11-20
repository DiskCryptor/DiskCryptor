/** @file
Library for DCS Block R/W interceptor

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2019. DiskCryptor, David Xanatos

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#ifndef __DCSINTLIB_H__
#define __DCSINTLIB_H__

#include <Uefi.h>
#include <Protocol/BlockIo.h>
#include <Protocol/BlockIo2.h>
#include <Protocol/ComponentName2.h>
#include <Protocol/ComponentName.h>
#include <Protocol/DriverBinding.h>

#define DCSINT_DRIVER_VERSION 1
#define DCS_SIGNATURE_16(A, B)        ((A) | (B << 8))
#define DCS_SIGNATURE_32(A, B, C, D)  (DCS_SIGNATURE_16 (A, B) | (DCS_SIGNATURE_16 (C, D) << 16))

#define DCSINT_BLOCK_IO_SIGN DCS_SIGNATURE_32('D','C','S', 'I')

extern EFI_COMPONENT_NAME_PROTOCOL  gDcsIntComponentName;
extern EFI_COMPONENT_NAME2_PROTOCOL gDcsIntComponentName2;

typedef struct _DCSINT_MOUNT  DCSINT_MOUNT, *PDCSINT_MOUNT;

typedef struct _DCSINT_MOUNT
{
   EFI_DEVICE_PATH            *DevicePath;

   EFI_BLOCK_READ             FilterRead;
   EFI_BLOCK_WRITE            FilterWrite;
   VOID                       *FilterParams;
	
   DCSINT_MOUNT               *Next;

} DCSINT_MOUNT, *PDCSINT_MOUNT;

typedef struct _DCSINT_BLOCK_IO  DCSINT_BLOCK_IO, *PDCSINT_BLOCK_IO;

typedef struct _DCSINT_BLOCK_IO {
   UINT32                     Sign;
   EFI_HANDLE                 Controller;

   EFI_BLOCK_IO_PROTOCOL      *BlockIo;
   EFI_BLOCK_READ             LowRead;
   EFI_BLOCK_WRITE            LowWrite;
   //UINT32                     IsReinstalled;
   VOID                       *FilterParams;

   // the BlockIo2 of the same partition (NULL if it has none); its reads and writes are
   // routed through the hooked BlockIo above
   EFI_BLOCK_IO2_PROTOCOL     *BlockIo2;

   DCSINT_BLOCK_IO*           Next;
} DCSINT_BLOCK_IO, *PDCSINT_BLOCK_IO;

/**
  Decision for a partition that has no mount entry when it is connected - one that
  appears after the mounts were set up (fast boot, hot plug). With Add FALSE: return TRUE if the
  partition is to be filtered (e.g. blocked). With Add TRUE: add its mount entry (AddCryptoMount)
  and return TRUE on success. NULL: such partitions are left alone.
**/
typedef BOOLEAN (*DCSINT_LATE_PARTITION)(IN EFI_HANDLE Controller, IN BOOLEAN Add);
extern DCSINT_LATE_PARTITION gDcsIntLatePartition;

//
// Functions for Driver Binding Protocol
//

/**
  Check whether the controller is supported.

  @param  This                   The driver binding protocol.
  @param  Controller             The controller handle to check.
  @param  RemainingDevicePath    The remaining device path.

  @retval EFI_SUCCESS            The driver supports this controller.
  @retval other                  This device isn't supported.

**/
EFI_STATUS
EFIAPI
DcsIntBindingSupported (
  IN EFI_DRIVER_BINDING_PROTOCOL  *This,
  IN EFI_HANDLE                   Controller,
  IN EFI_DEVICE_PATH_PROTOCOL     *RemainingDevicePath
  );

/**
  Starts the BlockIo device with this driver.

  @param  This                  The driver binding protocol.
  @param  Controller            The Block MMIO device to start on
  @param  RemainingDevicePath   The remaining device path.

  @retval EFI_SUCCESS           This driver supports this device.
  @retval EFI_UNSUPPORTED       This driver does not support this device.
  @retval EFI_DEVICE_ERROR      This driver cannot be started due to device Error.
  @retval EFI_OUT_OF_RESOURCES  Can't allocate memory resources.
  @retval EFI_ALREADY_STARTED   This driver has been started.

**/
EFI_STATUS
EFIAPI
DcsIntBindingStart (
  IN EFI_DRIVER_BINDING_PROTOCOL  *This,
  IN EFI_HANDLE                   Controller,
  IN EFI_DEVICE_PATH_PROTOCOL     *RemainingDevicePath
  );

/**
  Stop controlling the device.

  @param  This                   The driver binding
  @param  Controller             The device controller controlled by the driver.
  @param  NumberOfChildren       The number of children of this device
  @param  ChildHandleBuffer      The buffer of children handle.

  @retval EFI_SUCCESS            The driver stopped from controlling the device.
  @retval EFI_DEVICE_ERROR       The device could not be stopped due to a device error.
  @retval EFI_UNSUPPORTED        Block I/O Protocol is not installed on Controller.
  @retval Others                 Failed to stop the driver

**/
EFI_STATUS
EFIAPI
DcsIntBindingStop (
  IN  EFI_DRIVER_BINDING_PROTOCOL *This,
  IN  EFI_HANDLE                  Controller,
  IN  UINTN                       NumberOfChildren,
  IN  EFI_HANDLE                  *ChildHandleBuffer
  );

//
// Functions for Block I/O Protocol
//

//
// EFI Component Name Functions
//

/**
  Retrieves a Unicode string that is the user readable name of the driver.

  This function retrieves the user readable name of a driver in the form of a
  Unicode string. If the driver specified by This has a user readable name in
  the language specified by Language, then a pointer to the driver name is
  returned in DriverName, and EFI_SUCCESS is returned. If the driver specified
  by This does not support the language specified by Language,
  then EFI_UNSUPPORTED is returned.

  @param  This                  A pointer to the EFI_COMPONENT_NAME2_PROTOCOL or
                                EFI_COMPONENT_NAME_PROTOCOL instance.
  @param  Language              A pointer to a Null-terminated ASCII string
                                array indicating the language. This is the
                                language of the driver name that the caller is
                                requesting, and it must match one of the
                                languages specified in SupportedLanguages. The
                                number of languages supported by a driver is up
                                to the driver writer. Language is specified
                                in RFC 4646 or ISO 639-2 language code format.
  @param  DriverName            A pointer to the Unicode string to return.
                                This Unicode string is the name of the
                                driver specified by This in the language
                                specified by Language.

  @retval EFI_SUCCESS           The Unicode string for the Driver specified by
                                This and the language specified by Language was
                                returned in DriverName.
  @retval EFI_INVALID_PARAMETER Language is NULL.
  @retval EFI_INVALID_PARAMETER DriverName is NULL.
  @retval EFI_UNSUPPORTED       The driver specified by This does not support
                                the language specified by Language.

**/
EFI_STATUS
EFIAPI
DcsIntComponentNameGetDriverName (
  IN  EFI_COMPONENT_NAME_PROTOCOL  *This,
  IN  CHAR8                        *Language,
  OUT CHAR16                       **DriverName
  );

/**
  Retrieves a Unicode string that is the user readable name of the controller
  that is being managed by a driver.

  This function retrieves the user readable name of the controller specified by
  ControllerHandle and ChildHandle in the form of a Unicode string. If the
  driver specified by This has a user readable name in the language specified by
  Language, then a pointer to the controller name is returned in ControllerName,
  and EFI_SUCCESS is returned.  If the driver specified by This is not currently
  managing the controller specified by ControllerHandle and ChildHandle,
  then EFI_UNSUPPORTED is returned.  If the driver specified by This does not
  support the language specified by Language, then EFI_UNSUPPORTED is returned.

  @param  This                  A pointer to the EFI_COMPONENT_NAME2_PROTOCOL or
                                EFI_COMPONENT_NAME_PROTOCOL instance.
  @param  ControllerHandle      The handle of a controller that the driver
                                specified by This is managing.  This handle
                                specifies the controller whose name is to be
                                returned.
  @param  ChildHandle           The handle of the child controller to retrieve
                                the name of.  This is an optional parameter that
                                may be NULL.  It will be NULL for device
                                drivers.  It will also be NULL for a bus drivers
                                that wish to retrieve the name of the bus
                                controller.  It will not be NULL for a bus
                                driver that wishes to retrieve the name of a
                                child controller.
  @param  Language              A pointer to a Null-terminated ASCII string
                                array indicating the language.  This is the
                                language of the driver name that the caller is
                                requesting, and it must match one of the
                                languages specified in SupportedLanguages. The
                                number of languages supported by a driver is up
                                to the driver writer. Language is specified in
                                RFC 4646 or ISO 639-2 language code format.
  @param  ControllerName        A pointer to the Unicode string to return.
                                This Unicode string is the name of the
                                controller specified by ControllerHandle and
                                ChildHandle in the language specified by
                                Language from the point of view of the driver
                                specified by This.

  @retval EFI_SUCCESS           The Unicode string for the user readable name in
                                the language specified by Language for the
                                driver specified by This was returned in
                                DriverName.
  @retval EFI_INVALID_PARAMETER ControllerHandle is not a valid EFI_HANDLE.
  @retval EFI_INVALID_PARAMETER ChildHandle is not NULL and it is not a valid
                                EFI_HANDLE.
  @retval EFI_INVALID_PARAMETER Language is NULL.
  @retval EFI_INVALID_PARAMETER ControllerName is NULL.
  @retval EFI_UNSUPPORTED       The driver specified by This is not currently
                                managing the controller specified by
                                ControllerHandle and ChildHandle.
  @retval EFI_UNSUPPORTED       The driver specified by This does not support
                                the language specified by Language.

**/
EFI_STATUS
EFIAPI
DcsIntComponentNameGetControllerName (
  IN  EFI_COMPONENT_NAME_PROTOCOL                     *This,
  IN  EFI_HANDLE                                      ControllerHandle,
  IN  EFI_HANDLE                                      ChildHandle        OPTIONAL,
  IN  CHAR8                                           *Language,
  OUT CHAR16                                          **ControllerName
  );

/**
  Adds a crypto mount point for a given device path

  @param[in] DevicePath         Device path
  @param[in] FilterRead         pointer to the reader function
  @param[in] FilterWrite        pointer to the writer function
  @param[in] FilterParams       pointer to a custom parameter object as needed by the reader/writer

  @retval EFI_SUCCESS           Success;
  @retval EFI_OUT_OF_RESOURCES  Memory full;

**/
EFI_STATUS
AddCryptoMount(
  IN EFI_DEVICE_PATH* DevicePath,
  IN EFI_BLOCK_READ	  FilterRead,
  IN EFI_BLOCK_WRITE  FilterWrite,
  IN VOID*			  FilterParams
  );

/**
  Retrives a DCSINT_BLOCK_IO for given protocol

  @param[in] protocol       protocol to retrive the DCSINT_BLOCK_IO for

  @retval DCSINT_BLOCK_IO   found entry

**/
DCSINT_BLOCK_IO*
GetBlockIoByProtocol(
  IN EFI_BLOCK_IO_PROTOCOL* protocol
  );

/**
  Install the block I/O filter

  @param[in] ImageHandle    The firmware allocated handle for the EFI image.
  @param[in] SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS       The hook was installed successfully.
  @retval other             failed to install hook

**/
EFI_STATUS
DscInstallHook(
  IN EFI_HANDLE ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  );



#endif

