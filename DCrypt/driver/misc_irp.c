/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2026
	* DavidXanatos <info@diskcryptor.org>
    * Copyright (c) 2007-2013
    * ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
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
#include "defines.h"
#include "devhook.h"
#include "misc_irp.h"
#include "misc.h"
#include "driver.h"
#include "mount.h"
#include "enc_dec.h"
#include "debug.h"
#include "dump_hook.h"
#include "misc_mem.h"
#include "boot_pass.h"
#include "crypto_functions.h"

typedef struct _pw_irp_ctx {
	WORK_QUEUE_ITEM  wrk_item;
	dev_hook        *hook;
	PIRP             irp;

} pw_irp_ctx;

/* function types declaration */
IO_COMPLETION_ROUTINE dc_sync_complete;
WORKER_THREAD_ROUTINE dc_power_irp_worker;

NTSTATUS dc_complete_irp(PIRP irp, NTSTATUS status, ULONG_PTR bytes)
{
	irp->IoStatus.Status      = status;
	irp->IoStatus.Information = bytes;

	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS dc_release_irp(dev_hook *hook, PIRP irp, NTSTATUS status)
{
	dc_complete_irp(irp, status, 0);
	IoReleaseRemoveLock(&hook->remove_lock, irp);
	return status;
}

NTSTATUS dc_forward_irp(dev_hook *hook, PIRP irp)
{
	NTSTATUS status;

	IoSkipCurrentIrpStackLocation(irp);
	status = IoCallDriver(hook->orig_dev, irp);
			
	IoReleaseRemoveLock(&hook->remove_lock, irp);
	return status;
}

static NTSTATUS dc_sync_complete(PDEVICE_OBJECT dev_obj, PIRP irp, PKEVENT sync)
{
	KeSetEvent(sync, IO_NO_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS dc_forward_irp_sync(dev_hook *hook, PIRP irp)
{
	KEVENT   sync;
	NTSTATUS status;

	KeInitializeEvent(&sync, NotificationEvent, FALSE);
	IoCopyCurrentIrpStackLocationToNext(irp);
    IoSetCompletionRoutine(irp, dc_sync_complete, &sync, TRUE, TRUE, TRUE);

	status = IoCallDriver(hook->orig_dev, irp);

    if (status == STATUS_PENDING) {
		wait_object_infinity(&sync);
		status = irp->IoStatus.Status;
    }
	return status;
}


NTSTATUS dc_create_close_irp(PDEVICE_OBJECT dev_obj, PIRP irp)
{
	PIO_STACK_LOCATION irp_sp = IoGetCurrentIrpStackLocation(irp);
	NTSTATUS           status = STATUS_SUCCESS;
	PEPROCESS          process;
	PACCESS_TOKEN      token;

	/* get requestor process */
	process = IoGetRequestorProcess(irp);
	if (process == NULL) process = IoGetCurrentProcess();
	
	if (irp_sp->MajorFunction == IRP_MJ_CREATE)
	{
		/* check process token */
		if ( (token = PsReferencePrimaryToken(process)) == NULL || SeTokenIsAdmin(token) == FALSE ) {
			status = STATUS_ACCESS_DENIED;
		}
		if (token != NULL) PsDereferencePrimaryToken(token);
	}
	if (irp_sp->MajorFunction == IRP_MJ_CLOSE) {
		// synchronize all encryptions
		dc_sync_all_encs();
	}
	return dc_complete_irp(irp, status, 0);
}

static 
NTSTATUS dc_process_power_irp(dev_hook *hook, PIRP irp)
{
	NTSTATUS           status;
	PIO_STACK_LOCATION irp_sp;

	irp_sp = IoGetCurrentIrpStackLocation(irp);

	if ( irp_sp->MinorFunction == IRP_MN_SET_POWER && irp_sp->Parameters.Power.Type == SystemPowerState )
	{
		wait_object_infinity(&hook->busy_lock);

		if (irp_sp->Parameters.Power.State.SystemState == PowerSystemHibernate)
		{
			// prevent device encryption to sync device and memory state
			hook->flags |= F_PREVENT_ENC;
#ifdef DC_CONCURRENT_TRANSCRYPT
			if (hook->flags & F_SYNC) {
				/* Wait for any in-progress transcryption to complete.
				 * dc_transcrypt_step checks F_PREVENT_ENC and will exit early,
				 * but we need to wait for any step that's already past that check. */
				dc_wait_for_transcrypt(hook);
				/* Save current progress */
				dc_save_enc_state(hook, SYNC_STEP_UPDATE);
			}
#else
			dc_send_sync_packet(hook->dev_name, S_OP_SYNC, 0);
#endif
		}

		if (irp_sp->Parameters.Power.State.SystemState == PowerSystemWorking)
		{
			if (hook->pdo_dev->Flags & DO_SYSTEM_BOOT_PARTITION)
			{
				// search bootloader password in memory after hibernation
				dc_get_boot_pass();
				if ( !(dc_conf_flags & CONF_CACHE_PASSWORD) ) dc_clean_pass_cache();

				// initialize encryption again, because CPU capabilities may be changed
				dc_init_encryption();
			}
			// allow encryption requests
			hook->flags &= ~F_PREVENT_ENC;
		}

		KeReleaseMutex(&hook->busy_lock, FALSE);
	}

	PoStartNextPowerIrp(irp);
	IoSkipCurrentIrpStackLocation(irp);
	status = PoCallDriver(hook->orig_dev, irp);

	IoReleaseRemoveLock(&hook->remove_lock, irp);
	return status;
}

static void dc_power_irp_worker(pw_irp_ctx *pwc)
{
	dc_process_power_irp(pwc->hook, pwc->irp);
	mm_pool_free(pwc);
}

NTSTATUS dc_power_irp(dev_hook *hook, PIRP irp)
{
	pw_irp_ctx *pwc;

	if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
		return dc_process_power_irp(hook, irp);
	}

	if ( (pwc = mm_pool_alloc(sizeof(pw_irp_ctx))) == NULL )
	{
		PoStartNextPowerIrp(irp);		
		return dc_release_irp(hook, irp, STATUS_INSUFFICIENT_RESOURCES);
	}

	pwc->hook = hook;
	pwc->irp  = irp;

	IoMarkIrpPending(irp);

	ExInitializeWorkItem(&pwc->wrk_item, dc_power_irp_worker, pwc);
	ExQueueWorkItem(&pwc->wrk_item, DelayedWorkQueue);

	return STATUS_PENDING;
}
