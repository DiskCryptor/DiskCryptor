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
#include "dump_helpers.h"

typedef struct _pw_irp_ctx {
	WORK_QUEUE_ITEM  wrk_item;
	dev_hook        *hook;
	PIRP             irp;

} pw_irp_ctx;

/*
 * Resume generation: a resume unlock thread still retrying when the system hibernates and
 * resumes again must not wipe the boot keys the newer S0 IRP has fetched. Each S0 of the
 * boot partition bumps resume_gen and fetches the boot keys under resume_lock; secrets are
 * cleared under resume_lock only while the clearer's generation is still current.
 * A KMUTEX (not a FAST_MUTEX): stays at PASSIVE_LEVEL, dc_clean_boot_keys tests the IRQL.
 */
static KMUTEX        resume_lock;
static volatile LONG resume_gen;

void dc_init_power_irp()
{
	KeInitializeMutex(&resume_lock, 0);
	resume_gen = 0;
}

static void dc_resume_clear_secrets(LONG gen)
{
	wait_object_infinity(&resume_lock);

	// clean password cache if CONF_CACHE_PASSWORD is not set - not if a newer resume runs
	if (resume_gen == gen) {
		dc_clear_secrets(FALSE);
	}
	KeReleaseMutex(&resume_lock, FALSE);
}

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

/*
 * Resume from hibernation: unlock the volumes locked at S4 with the cached passwords / boot
 * keys, then drop the secrets that must not stay cached. A system thread, not the S0 power
 * IRP: the KDF may take seconds per volume and the disks may still be powering up.
 */
static void dc_resume_unlock_thread(void *param)
{
	/* with retries: the disks may still be powering up */
	dc_unlock_locked_volumes(TRUE);

	dc_resume_clear_secrets((LONG)(LONG_PTR)param);

	PsTerminateSystemThread(STATUS_SUCCESS);
}

static
NTSTATUS dc_process_power_irp(dev_hook *hook, PIRP irp)
{
	NTSTATUS           status;
	PIO_STACK_LOCATION irp_sp;
	int                do_resume_unlock = 0;
	LONG               gen = 0;

	irp_sp = IoGetCurrentIrpStackLocation(irp);

	/* Veto hibernation (also hybrid sleep / Fast Startup) when the image could not be written
	 * safely; same policy as dc_dump_start. Best effort: critical actions send no query - then
	 * the S4 SET_POWER below locks the volumes that keep the image unsafe, and the DumpStart
	 * refusal remains for volumes that cannot be locked. With CONF_HIBER_LOCK only a volume
	 * that cannot be locked vetoes (the S4 SET_POWER below locks the others). */
	if ( irp_sp->MinorFunction == IRP_MN_QUERY_POWER && irp_sp->Parameters.Power.Type == SystemPowerState &&
		 irp_sp->Parameters.Power.State.SystemState == PowerSystemHibernate &&
		 dc_dump_helpers.dump_is_hibernation_allowed((dc_conf_flags & CONF_HIBER_LOCK) != 0) == FALSE )
	{
		DbgMsg("hibernation vetoed: memory holds keys that the hibernation image could not protect\n");
		PoStartNextPowerIrp(irp);
		return dc_release_irp(hook, irp, STATUS_UNSUCCESSFUL);
	}

	if ( irp_sp->MinorFunction == IRP_MN_SET_POWER && irp_sp->Parameters.Power.Type == SystemPowerState )
	{
		BOOLEAN image_allowed = TRUE;   /* image safe with the predicted locks (no lockable volume locked) */
		BOOLEAN locked_allowed = TRUE;  /* image safe if every lockable volume is locked as well */

		if (irp_sp->Parameters.Power.State.SystemState == PowerSystemHibernate)
		{
			/* from the first S4 SET_POWER until the S0 SET_POWER no volume may be mounted or
			 * unlocked - it would reach the image with live keys after its S4 IRP was handled */
			dc_set_s4_transition(TRUE);

			/* flush a mount / unlock / encryption start of THIS volume that passed its
			 * s4_transition test before the flag was set: they hold busy_lock from the test
			 * until the keys are installed, so after this acquire / release the policy below
			 * sees their result. Counted: this IRP holds a remove-lock reference. */
			dc_wait_busy_lock_rl(hook);
			KeReleaseMutex(&hook->busy_lock, FALSE);

			/* evaluate the dump policy BEFORE taking busy_lock: it takes hooks_sync_resource,
			 * other paths hold that and then wait on a busy_lock (lock order). Only locks of
			 * other volumes can change the result now; the dump-time check is the final word. */
			if ( (image_allowed = dc_dump_helpers.dump_is_hibernation_allowed(FALSE)) == FALSE ) {
				locked_allowed = dc_dump_helpers.dump_is_hibernation_allowed(TRUE);
			}
		}
		else if (irp_sp->Parameters.Power.State.SystemState == PowerSystemWorking)
		{
			/* resumed (or the hibernation was aborted): mounts / unlocks allowed again,
			 * before the resume unlock below runs */
			dc_set_s4_transition(FALSE);
		}

		/* counted: this IRP holds a remove-lock reference, an unmount holding busy_lock
		 * drains without waiting for it. After such an unmount the volume is not F_ENABLED,
		 * so nothing below locks it. */
		dc_wait_busy_lock_rl(hook);

		if (irp_sp->Parameters.Power.State.SystemState == PowerSystemHibernate)
		{
			int save_failed = 0;

			// prevent device encryption to sync device and memory state
			dc_hook_set_flags(hook, F_PREVENT_ENC);
#ifdef DC_CONCURRENT_TRANSCRYPT
			if (hook->flags & F_SYNC) {
				/* Wait for any in-progress transcryption to complete.
				 * dc_transcrypt_step checks F_PREVENT_ENC and will exit early,
				 * but we need to wait for any step that's already past that check. */
				dc_wait_for_transcrypt(hook);
				/* Save current progress; a lock records a failed save */
				save_failed = (dc_save_enc_state(hook, SYNC_STEP_UPDATE) != ST_OK);
			}
#else
			dc_send_sync_packet(hook->dev_name, S_OP_SYNC, 0);
#endif

			/* lock THIS volume before the image is written (each device gets its own power IRP):
			 *  - a no-hibernation volume (DC_WILL_HIBER_ERASE excludes the boot / image / dump
			 *    volume), and
			 *  - any other lockable volume while the image could not be protected (locking makes
			 *    it safe instead of a bugcheck in DumpStart); locked volumes are skipped by the
			 *    policy, so they are locked one by one until the image is safe.
			 * A failed lock leaves the keys live and is marked, so the dump policy refuses the
			 * image. */
			{
				BOOLEAN lock = DC_WILL_HIBER_ERASE(hook);

				if (lock == FALSE && DC_HIBER_LOCKABLE(hook) && image_allowed == FALSE) {
					if (locked_allowed != FALSE) {
						DbgMsg("hibernation goes ahead although the image could not be protected: locking %ws\n", hook->dev_name);
						lock = TRUE;
					} else {
						/* the image would be refused even with every lockable volume
						 * locked - do not lock this volume for nothing */
						DbgMsg("hibernation image refused anyway, %ws not locked\n", hook->dev_name);
					}
				}
				if (lock != FALSE && dc_lock_volume(hook, save_failed) != ST_OK) {
					DbgMsg("lock on hibernate failed, keys stay live, dev=%ws\n", hook->dev_name);
					InterlockedExchange(&hook->lock_failed, 1);
				}
			}
		}

		if (irp_sp->Parameters.Power.State.SystemState == PowerSystemWorking)
		{
			if (hook->pdo_dev->Flags & DO_SYSTEM_BOOT_PARTITION)
			{
				// search bootloader password in memory after hibernation; new resume
				// generation, so that an older resume thread keeps these keys
				wait_object_infinity(&resume_lock);
				gen = InterlockedIncrement(&resume_gen);
				dc_get_boot_pass();
				KeReleaseMutex(&resume_lock, FALSE);

				// initialize encryption again, because CPU capabilities may be changed
				dc_init_encryption();

				// unlock the locked volumes after releasing busy_lock
				do_resume_unlock = 1;
			}
			/* the S4 lock attempt is over (resumed or hibernation aborted) */
			InterlockedExchange(&hook->lock_failed, 0);

			/* allow encryption requests - not on a locked volume: the unlock re-initialises
			 * its session and then clears F_PREVENT_ENC itself */
			if ((hook->flags & F_HIBER_ERASE) == 0) {
				dc_hook_clear_flags(hook, F_PREVENT_ENC);
			}
		}

		KeReleaseMutex(&hook->busy_lock, FALSE);

		/* auto-unlock the volumes locked at S4, AFTER releasing busy_lock (dc_mount_device
		 * takes each volume's busy_lock); see dc_resume_unlock_thread. Inline when there is
		 * nothing to unlock or the thread cannot be created. */
		if (do_resume_unlock)
		{
			if (dc_num_locked() == 0 || start_system_thread(dc_resume_unlock_thread, (void*)(LONG_PTR)gen, NULL) != ST_OK)
			{
				/* inline: no retries, they would hold up this power IRP for seconds */
				dc_unlock_locked_volumes(FALSE);

				dc_resume_clear_secrets(gen);
			}
		}
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
