/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2026
    * DavidXanatos <info@diskcryptor.org>
    * Copyright (c) 2007-2014
    * ntldr <ntldr@diskcryptor.net> PGP key ID - 0x1B6A24550F33E44A
    *

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 3 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <ntifs.h>
#include "devhook.h"
#include "driver.h"
#include "misc.h"
#include "misc_irp.h"
#include "mount.h"
#include "prng.h"
#include "enc_dec.h"
#include "debug.h"
#include "pnp_irp.h"
#include "dump_helpers.h"

static
NTSTATUS dc_pnp_usage_irp(dev_hook *hook, PIRP irp)
{
	PDEVICE_OBJECT                 devobj = hook->hook_dev;
	PIO_STACK_LOCATION             irp_sp = IoGetCurrentIrpStackLocation(irp);
	BOOLEAN                        pagable_set, complete_irp = FALSE;
	NTSTATUS                       status;

	if (irp_sp->Parameters.UsageNotification.Type != DeviceUsageTypePaging)
	{
		if (irp_sp->Parameters.UsageNotification.Type == DeviceUsageTypeHibernation) 
		{
			if (irp_sp->Parameters.UsageNotification.InPath)
			{
				SetFlag(hook->flags, F_HIBERNATE);

				// prevent hibernating if memory contains encryption keys
				if (dc_dump_helpers.dump_is_hibernation_allowed() == FALSE)
				{
					DbgMsg("hibernation prevented because memory contains encryption keys\n");
					complete_irp = TRUE;
					status = STATUS_UNSUCCESSFUL;
				}
			} else {
				ClearFlag(hook->flags, F_HIBERNATE);
			}
		} else if (irp_sp->Parameters.UsageNotification.Type == DeviceUsageTypeDumpFile)
		{
			if (irp_sp->Parameters.UsageNotification.InPath) {
				SetFlag(hook->flags, F_CRASHDUMP);
			} else {
				ClearFlag(hook->flags, F_CRASHDUMP);
			}
		}

		if (complete_irp) {
			status = dc_complete_irp(irp, status, 0);
		} else {
			IoSkipCurrentIrpStackLocation(irp);
			status = IoCallDriver(hook->orig_dev, irp);
		}
	} else
	{
		// wait on the paging path event
		wait_object_infinity(&hook->paging_count_event);

		// if removing last paging device, need to set DO_POWER_PAGABLE
		// bit here, and possible re-set it below on failure.
		pagable_set = FALSE;

		if (irp_sp->Parameters.UsageNotification.InPath == FALSE && hook->paging_count == 1) {
			SetFlag(devobj->Flags, DO_POWER_PAGABLE);
			pagable_set = TRUE;
		}

		// send the irp synchronously
		status = dc_forward_irp_sync(hook, irp);

		// now deal with the failure and success cases.
		// note that we are not allowed to fail the irp
		// once it is sent to the lower drivers.

		if (NT_SUCCESS(status)) 
		{
			IoAdjustPagingPathCount(&hook->paging_count, irp_sp->Parameters.UsageNotification.InPath);

			// handle first paging file addition
			if (irp_sp->Parameters.UsageNotification.InPath && hook->paging_count == 1) {
				ClearFlag(devobj->Flags, DO_POWER_PAGABLE);
			}
		} else {
			if (pagable_set) ClearFlag(devobj->Flags, DO_POWER_PAGABLE); // cleanup the changes done above
		}

		// set the event so the next one can occur.
		KeSetEvent(&hook->paging_count_event, IO_NO_INCREMENT, FALSE);

		// and complete the irp
		dc_complete_irp(irp, status, irp->IoStatus.Information);
	}

	IoReleaseRemoveLock(&hook->remove_lock, irp);
	return status;
}

NTSTATUS dc_pnp_irp(dev_hook *hook, PIRP irp)
{
	PIO_STACK_LOCATION irp_sp = IoGetCurrentIrpStackLocation(irp);
	BOOLEAN            complete_irp = FALSE;
	NTSTATUS           status;
		
	switch (irp_sp->MinorFunction)
	{
		case IRP_MN_REMOVE_DEVICE:
			DbgMsg("IRP_MN_REMOVE_DEVICE, dev=%ws\n", hook->dev_name);

			dc_set_pnp_state(hook, Deleted);
			IoReleaseRemoveLockAndWait(&hook->remove_lock, irp);
			
			IoSkipCurrentIrpStackLocation(irp);
			status = IoCallDriver(hook->orig_dev, irp);

			dc_process_unmount(hook, MF_NOFSCTL | MF_NOWAIT_IO);
			dc_remove_hook(hook);

			IoDetachDevice(hook->orig_dev);
			IoDeleteDevice(hook->hook_dev);
		break;
		case IRP_MN_SURPRISE_REMOVAL:
			DbgMsg("IRP_MN_SURPRISE_REMOVAL, dev=%ws\n", hook->dev_name);

			dc_set_pnp_state(hook, SurpriseRemove);
			dc_process_unmount(hook, MF_NOFSCTL | MF_NOWAIT_IO);

			status = dc_forward_irp(hook, irp);
		break;
		case IRP_MN_DEVICE_USAGE_NOTIFICATION:
			status = dc_pnp_usage_irp(hook, irp);
		break;
		case IRP_MN_START_DEVICE:
			if ( NT_SUCCESS(status = dc_forward_irp_sync(hook, irp)) )
			{
				if (hook->orig_dev->Characteristics & FILE_REMOVABLE_MEDIA) {
					hook->hook_dev->Characteristics |= FILE_REMOVABLE_MEDIA;
					hook->flags |= F_REMOVABLE;
				}
				dc_set_pnp_state(hook, Started);
			}
			complete_irp = TRUE;
		break;
		case IRP_MN_STOP_DEVICE:
			dc_set_pnp_state(hook, Stopped);
			status = dc_forward_irp_sync(hook, irp);

			if (NT_SUCCESS(status) == FALSE && hook->pnp_state == Stopped) {
				dc_restore_pnp_state(hook);
			}
			complete_irp = TRUE;
		break;
		default:
			status = dc_forward_irp(hook, irp);
	}

	if (complete_irp) {
		dc_complete_irp(irp, status, irp->IoStatus.Information);
		IoReleaseRemoveLock(&hook->remove_lock, irp);
	}
	return status;
}

NTSTATUS dc_add_device(PDRIVER_OBJECT drv_obj, PDEVICE_OBJECT pdo_dev)
{
	PDEVICE_OBJECT high_dev = IoGetAttachedDeviceReference(pdo_dev);
	PDEVICE_OBJECT hook_dev, device, nextdev;
	dev_hook      *hook;
	NTSTATUS       status;

	// reseed PRNG on device attach
	cp_rand_reseed();
	
	// create FDO device
	if ( !NT_SUCCESS(status = IoCreateDevice(drv_obj, sizeof(dev_hook), NULL, high_dev->DeviceType, 0, FALSE, &hook_dev)) ) {
		DbgMsg("IoCreateDevice failed, status=%0.8x\n", status);
		hook_dev = NULL;
		goto cleanup;
	}
	memset( (hook = (dev_hook*)hook_dev->DeviceExtension), 0, sizeof(dev_hook));
	hook->pending_shrink_sectors = -1;

	// get device object name
	if (high_dev->DeviceType == FILE_DEVICE_CD_ROM)
	{
		for (device = high_dev; device != NULL; device = nextdev) {
			dc_query_object_name(device, hook->dev_name, sizeof(hook->dev_name));
			nextdev = wcsncmp(hook->dev_name, L"\\Device\\CdRom", 13) != 0 ? IoGetLowerDeviceObject(device) : NULL;
			if (device != high_dev) ObDereferenceObject(device);
		}
	} else {
		dc_query_object_name(pdo_dev, hook->dev_name, sizeof(hook->dev_name));
	}
	
	// attach device
	hook->hook_dev = hook_dev;
	hook->pdo_dev  = pdo_dev;

	if ( !NT_SUCCESS(status = IoAttachDeviceToDeviceStackSafe(hook_dev, pdo_dev, &hook->orig_dev)) ) {
		DbgMsg("IoAttachDeviceToDeviceStackSafe failed, status=%0.8x\n", status);
		hook->orig_dev = NULL;
		goto cleanup;
	}
	
	// complete initializaion
	if (high_dev->Characteristics & FILE_REMOVABLE_MEDIA) hook->flags |= F_REMOVABLE;
	if (high_dev->DeviceType == FILE_DEVICE_CD_ROM) hook->flags |= F_CDROM;
	
	IoInitializeRemoveLock(&hook->remove_lock, 'LRCD', 0, 0);
	KeInitializeEvent(&hook->paging_count_event, NotificationEvent, TRUE);
	KeInitializeMutex(&hook->busy_lock, 0);

	hook_dev->Characteristics |= high_dev->Characteristics & FILE_REMOVABLE_MEDIA;
	hook_dev->Flags |= high_dev->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE);
	hook_dev->Flags &= ~DO_DEVICE_INITIALIZING;	

	DbgMsg("dc_add_device, dev=%ws\n", hook->dev_name);
	dc_insert_hook(hook);	

cleanup:
	if (NT_SUCCESS(status) == FALSE && hook_dev != NULL) {
		IoDeleteDevice(hook_dev);
	}
	ObDereferenceObject(high_dev);
	return status;
}
