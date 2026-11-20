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
#include "safe_log.h"

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
				dc_hook_set_flags(hook, F_HIBERNATE);
				/* this volume now receives the hibernation image - the no-hibernation
				 * key erase must never apply to it (it may have been mounted with it) */
				if (hook->flags & F_NO_HIBER) {
					DbgMsg("no-hibernation option dropped: %ws became the hibernation volume\n", hook->dev_name);
					dc_hook_clear_flags(hook, F_NO_HIBER);
				}

				// prevent hibernating if memory contains encryption keys (CONF_HIBER_LOCK: the
				// lockable volumes will be locked at S4, see dc_process_power_irp)
				if (dc_dump_helpers.dump_is_hibernation_allowed((dc_conf_flags & CONF_HIBER_LOCK) != 0) == FALSE)
				{
					DbgMsg("hibernation prevented because memory contains encryption keys\n");
					complete_irp = TRUE;
					status = STATUS_UNSUCCESSFUL;
				}
			} else {
				dc_hook_clear_flags(hook, F_HIBERNATE);
			}
		} else if (irp_sp->Parameters.UsageNotification.Type == DeviceUsageTypeDumpFile)
		{
			if (irp_sp->Parameters.UsageNotification.InPath) {
				dc_hook_set_flags(hook, F_CRASHDUMP);
				/* as above, for the crash dump volume */
				if (hook->flags & F_NO_HIBER) {
					DbgMsg("no-hibernation option dropped: %ws became the crash dump volume\n", hook->dev_name);
					dc_hook_clear_flags(hook, F_NO_HIBER);
				}
			} else {
				dc_hook_clear_flags(hook, F_CRASHDUMP);
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

			/* a volume with a paging file is never locked at hibernation, so the
			 * no-hibernation option cannot work on it - drop it. Set-then-test against the
			 * mount: the count was raised above, the mount sets F_NO_HIBER and then tests
			 * paging_count. */
			if (irp_sp->Parameters.UsageNotification.InPath && (hook->flags & F_NO_HIBER)) {
				DbgMsg("no-hibernation option dropped: %ws received a paging file\n", hook->dev_name);
				dc_hook_clear_flags(hook, F_NO_HIBER);
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

/*
 * IRP_MN_SURPRISE_REMOVAL. Read/write IRPs admitted before F_DISABLE may still hold raw
 * key pointers, so the keys are freed only after a drain:
 *  1. F_DISABLE | F_PREVENT_ENC under busy_lock (new read/write IRPs fail, no new
 *     transcryption step).
 *  2. Drain: wait until only the remove lock bias and this IRP's reference are left
 *     (counted busy_lock waiters excluded). Every read/write holds the remove lock across
 *     every key use; one that takes it after step 1 sees F_DISABLE.
 *  3. Drained: unmount. Otherwise (or busy_lock not obtained) leave the volume mounted, keys
 *     kept, I/O failing - IRP_MN_REMOVE_DEVICE unmounts after a full drain.
 * busy_lock is held from 1. through 3. (dc_process_unmount re-acquires it recursively).
 * Both waits are bounded: busy_lock may be held long (a mount's KDF).
 */
#define DC_SURPRISE_WAIT_MS 5000

static void dc_surprise_unmount(dev_hook *hook)
{
	LARGE_INTEGER timeout;
	ULONGLONG     start;

	timeout.QuadPart = -((LONGLONG)DC_SURPRISE_WAIT_MS * 10000); /* relative, 100 ns units */

	/* counted: this IRP holds a remove-lock reference, so a user unmount holding
	 * busy_lock drains without waiting for it */
	if (dc_wait_busy_lock_rl_timeout(hook, &timeout) == STATUS_TIMEOUT) {
		/* block the I/O anyway; the keys are not touched here */
		dc_hook_set_flags(hook, F_DISABLE | F_PREVENT_ENC);
		DbgMsg("surprise removal: busy_lock timeout, unmount left to IRP_MN_REMOVE_DEVICE, dev=%ws\n", hook->dev_name);
		return;
	}
	dc_hook_set_flags(hook, F_DISABLE | F_PREVENT_ENC);

	if (hook->flags & F_ENABLED)
	{
		/* bias (1) + this IRP (1); not the references of requests blocked on busy_lock
		 * (held here) */
		BOOLEAN drained;

		for (start = KeQueryInterruptTime(); (drained = dc_rl_drained(hook, 2)) == FALSE; )
		{
			if (KeQueryInterruptTime() - start >= (ULONGLONG)DC_SURPRISE_WAIT_MS * 10000) {
				break;
			}
			dc_delay(10);
		}
		if (drained) {
			dc_process_unmount(hook, MF_NOFSCTL | MF_NOWAIT_IO); /* busy_lock taken recursively */
		} else {
			DbgMsg("surprise removal: %d references still held, unmount left to IRP_MN_REMOVE_DEVICE, dev=%ws\n",
				hook->remove_lock.Common.IoCount, hook->dev_name);
		}
	}
	/* not mounted: no keys; F_DISABLE stays until the device is deleted */
	KeReleaseMutex(&hook->busy_lock, FALSE);
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

			/* drain every IRP holding the remove lock (no new one gets it from here on) */
			IoReleaseRemoveLockAndWait(&hook->remove_lock, irp);

			/* unmount (save the transcryption state, free the keys) BEFORE the remove is
			 * forwarded, while the stack below is still up. Deleted is set only after this:
			 * io_hook_rw refuses I/O unless the device is Started. */
			dc_process_unmount(hook, MF_NOFSCTL | MF_NOWAIT_IO);

			/* Deleted under busy_lock: a mount / encryption start in progress completes first,
			 * later ones fail their pnp check. Then unmount whatever got mounted in between
			 * (normally ST_NO_MOUNT). */
			wait_object_infinity(&hook->busy_lock);
			dc_set_pnp_state(hook, Deleted);
			KeReleaseMutex(&hook->busy_lock, FALSE);

			dc_process_unmount(hook, MF_NOFSCTL | MF_NOWAIT_IO);

			IoSkipCurrentIrpStackLocation(irp);
			status = IoCallDriver(hook->orig_dev, irp);

			dc_remove_hook(hook);
			/* defensive (the unmount freed it): no journal entry may outlive the hook, the
			 * side table is keyed by its address */
			dc_slog_free(hook);

			IoDetachDevice(hook->orig_dev);
			IoDeleteDevice(hook->hook_dev);
		break;
		case IRP_MN_SURPRISE_REMOVAL:
			DbgMsg("IRP_MN_SURPRISE_REMOVAL, dev=%ws\n", hook->dev_name);

			dc_set_pnp_state(hook, SurpriseRemove);
			dc_surprise_unmount(hook);

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
					/* interlocked: a restart can come while the volume is mounted and
					 * other paths update hook->flags */
					dc_hook_set_flags(hook, F_REMOVABLE);
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
	
#ifdef _M_ARM64
	if (dc_load_flags & DST_UEFI_RETRY)
	{
		int dc_get_uefi_boot_pass();
		DbgMsg("dc_get_boot_pass retry\n");
		if (dc_get_uefi_boot_pass() == ST_OK)
			DbgMsg("boot data block found on retry\n");
		else
			DbgMsg("boot data block NOT found on retry\n");
		InterlockedAnd((volatile LONG*)&dc_load_flags, (LONG)~DST_UEFI_RETRY);
	}
#endif

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
	/* auto-reset, signalled = free: serialises the paging usage notifications of this volume
	 * (dc_pnp_usage_irp waits on it and sets it again on its only exit) */
	KeInitializeEvent(&hook->paging_count_event, SynchronizationEvent, TRUE);
	KeInitializeMutex(&hook->busy_lock, 0);
	KeInitializeSpinLock(&hook->id_lock); /* media identity */
#ifdef DC_CONCURRENT_TRANSCRYPT
	/* Transcrypt state is initialised ONCE per hook, not per session: a step left over from
	 * the previous session may still hold (or be about to win) the in_progress slot, so
	 * re-initialising it would corrupt a live waiter/holder. Idle: all events signalled. */
	KeInitializeSpinLock(&hook->trans.range_lock);
	KeInitializeEvent(&hook->trans.block_complete, NotificationEvent, TRUE); /* no active block */
	KeInitializeEvent(&hook->trans.io_done_event,  NotificationEvent, TRUE); /* no pending I/O */
	KeInitializeEvent(&hook->trans.idle_event,     NotificationEvent, TRUE); /* slot free */
	hook->trans.active_start     = -1;
	hook->trans.active_end       = 0;
	hook->trans.pending_io_count = 0;
	hook->trans.in_progress      = 0;
#endif

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
