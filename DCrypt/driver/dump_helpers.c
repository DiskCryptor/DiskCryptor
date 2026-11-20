/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2014
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
#include "dump_helpers.h"
#include "devhook.h"
#include "mount.h"
#include "misc_mem.h"

static dev_hook* current_dump_device = NULL;
static BOOLEAN   current_dump_is_hiber = FALSE; /* set by dc_dump_start for dc_dump_finish */

/*
 * One dump policy for crash dumps and hibernation, used by dc_dump_start and
 * dc_dump_is_hibernation_allowed. A mounted volume needs a protected image as long as its
 * keys are live in memory:
 *  - crash dump: every mounted volume counts, F_NO_HIBER ones too;
 *  - hibernation: a no-hibernation volume is skipped once it is locked in its S4 SET_POWER
 *    IRP - never the image's own target volume (DC_NO_HIBER_FORBIDDEN);
 *  - both: a LOCKED volume (F_HIBER_ERASE) is skipped - its keys are zeroed. The S4 path
 *    also locks every other lockable volume when this policy would refuse the image.
 * The prediction "will be locked in its S4 IRP" (DC_WILL_HIBER_ERASE) is only used AHEAD of
 * time (usage notification, QUERY_POWER, the S4 path's own decision); at DUMP time only the
 * volumes really locked are skipped. Mounts / unlocks are refused between the first S4
 * SET_POWER and the S0 SET_POWER (dc_set_s4_transition), so no volume comes back to life
 * between its lock and the image. Hibernation, hybrid sleep and Fast Startup all arrive as
 * PowerSystemHibernate (S4) IRPs, so the S4 lock runs before every hibernation image.
 */
typedef struct _dc_dump_eval {
	ULONG     number_of_mounts;      /* volumes whose keys would be in the image */
	ULONG     found_dump_devices;    /* volumes flagged as the dump target */
	BOOLEAN   dump_device_encrypted; /* the (last) target can encrypt the image */
	dev_hook *dump_device;
} dc_dump_eval;

/* dc_dump_evaluate modes */
#define DC_EVAL_DUMP           0 /* dump time: skip only the volumes that are locked */
#define DC_EVAL_PREDICT        1 /* ahead of time: also skip the volumes locked in their S4 IRP */
#define DC_EVAL_PREDICT_LOCKED 2 /* ahead of time, as if every DC_HIBER_LOCKABLE volume were locked too */

static void dc_dump_evaluate(BOOLEAN is_hibernation, int mode, dc_dump_eval *ev)
{
	dev_hook *hook;

	ev->number_of_mounts      = 0;
	ev->found_dump_devices    = 0;
	ev->dump_device_encrypted = FALSE;
	ev->dump_device           = NULL;

	for (hook = dc_first_hook(); hook != NULL; hook = dc_next_hook(hook))
	{
		BOOLEAN target = (hook->flags & (is_hibernation ? F_HIBERNATE : F_CRASHDUMP)) != 0;

		if (target)
		{
			// dump device must be mounted,
			// dump device must not contain unencrypted part
			// and encryption keys must not have been erased by dc_clean_keys / mm_clean_secure_memory
			ev->dump_device_encrypted = (hook->flags & F_ENABLED) != 0 &&
				                        (hook->flags & F_PLAIN_IO) == 0 && // decryption just finished, volume is plaintext
				                        ( (hook->flags & F_SYNC) == 0 || (hook->flags & F_REENCRYPT) != 0 ) &&
				                        (hook->dsk_key != NULL && hook->dsk_key->encrypt != NULL) &&
				                        (hook->tmp_key == NULL || hook->tmp_key->encrypt != NULL);
			ev->found_dump_devices++;
			ev->dump_device = hook;
		}

		if ((hook->flags & F_ENABLED) == 0) {
			continue;
		}
		if (hook->flags & F_HIBER_ERASE) {
			/* locked (dc_lock_volume): keys zeroed and its I/O drained - nothing
			 * of it can reach a hibernation image or a crash dump until it is unlocked */
			continue;
		}
		if (mode != DC_EVAL_DUMP && is_hibernation && DC_WILL_HIBER_ERASE(hook) && hook->lock_failed == 0) {
			/* ahead of time only: about to be locked in its own S4 SET_POWER IRP (the S4
			 * path's predicate). Fails closed: a lock that still fails sets lock_failed, the
			 * volume stays counted and the image is refused. */
			continue;
		}
		if (mode == DC_EVAL_PREDICT_LOCKED && is_hibernation && DC_HIBER_LOCKABLE(hook) && hook->lock_failed == 0) {
			/* the S4 path asks whether locking the lockable volumes would make the
			 * image safe at all - only then are they locked */
			continue;
		}
		ev->number_of_mounts++;
	}
}

static NTSTATUS dc_dump_start(__in BOOLEAN is_hibernation)
{
	dc_dump_eval ev;

	/* at dump time only the volumes really locked are skipped */
	dc_dump_evaluate(is_hibernation, DC_EVAL_DUMP, &ev);
	current_dump_device = ev.dump_device;
	current_dump_is_hiber = is_hibernation;

	// prevent saving unencrypted passwords to disk
	if (!ev.dump_device_encrypted)
	{
		dc_clear_secrets(TRUE);
		/* and the user-mode buffers the driver keeps locked (passwords of the GUI /
		 * console): before the image is written */
		mm_clean_usermode_memory();
	}

	// if no active mounts, dump encryption not needed
	if (ev.number_of_mounts == 0)
	{
		return STATUS_FVE_NOT_ENCRYPTED;
	}

	// operation allowed if dump device is correctly encrypted
	if (ev.found_dump_devices == 1 && ev.dump_device_encrypted) return STATUS_SUCCESS;

	// operation not allowed because encryption keys may leak to dump
	return STATUS_ACCESS_DENIED;
}

/*
 * Runs after the image / dump is written. Only a crash dump wipes the live keys and secure
 * memory (the system halts after it). After a hibernation image the system may continue from
 * THIS memory (hybrid sleep wakes from S3, an aborted S4 returns to S0), so the keys stay; what
 * reaches the image is decided before it is written (dc_dump_start, the S4 locks). The bounce
 * buffers are zeroed by the callers (DumpFinish / FinishRoutine).
 */
static void dc_dump_finish()
{
	if (!current_dump_is_hiber) {
		mm_clean_secure_memory();
		dc_clean_keys();
	}
	current_dump_device = NULL;
	current_dump_is_hiber = FALSE;
}

static
NTSTATUS dc_dump_encrypt(
	__inout PLARGE_INTEGER DiskByteOffset,
	__in    PMDL           Mdl,
	__out   PUCHAR         EncryptedData
	)
{
	ULONGLONG offset = DiskByteOffset->QuadPart;
	ULONG     length = Mdl->ByteCount;
	PUCHAR    p_data;
#ifdef _M_IX86
	KIRQL     old_irql;
#endif

	// dump device hook must be known at this point
	if (current_dump_device == NULL) return STATUS_INVALID_DEVICE_STATE;

	// data length and disk byte offset must be multiples of XTS_SECTOR_SIZE
	if ( (length % XTS_SECTOR_SIZE) != 0 || (offset % XTS_SECTOR_SIZE) != 0 ) return STATUS_DATATYPE_MISALIGNMENT_ERROR;

	// Callers of MmGetSystemAddressForMdlSafe must be running at IRQL <= DISPATCH_LEVEL
	// Mdl must be already mapped to system VA
	if ((Mdl->MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL)) == 0) return STATUS_NOT_MAPPED_DATA;
	p_data = (PUCHAR)Mdl->MappedSystemVa;

	if (current_dump_device->flags & F_NO_REDIRECT) {
		// redirection is not used, the data are moved forward by the header length
		DiskByteOffset->QuadPart += current_dump_device->head_len;
	} else {
		// writing to redirected area is not supported
		if (offset < current_dump_device->head_len) return STATUS_NOT_SUPPORTED;

		/* the partition end of a $dcsys$ volume with a backup header is redirected to
		 * tail_off in storage (its place holds the backup header), like io_async_make_chunk;
		 * the redirected offset also decides the key below. A write crossing into the area
		 * is refused like the head case (one call can move only one offset). */
		if ( (current_dump_device->flags & F_HEAD_BACKUP) && current_dump_device->tail_len != 0 &&
			 offset + length > current_dump_device->dsk_size - current_dump_device->tail_len )
		{
			ULONGLONG tail_start = current_dump_device->dsk_size - current_dump_device->tail_len;

			if (offset < tail_start || offset + length > current_dump_device->dsk_size) return STATUS_NOT_SUPPORTED;
			offset = current_dump_device->tail_off + (offset - tail_start);
			DiskByteOffset->QuadPart = offset;
		}
	}

#ifdef _M_IX86
	// raise IRQL to HIGH_LEVEL for disable KeSaveFloatingPointState on x86
	KeRaiseIrql(HIGH_LEVEL, &old_irql);
#endif

	if ((current_dump_device->flags & F_SYNC) && (offset + length > current_dump_device->tmp_size))
	{
		ULONG     part1_length = offset < current_dump_device->tmp_size ? (ULONG)(current_dump_device->tmp_size - offset) : 0;
		ULONGLONG part2_offset = offset < current_dump_device->tmp_size ? current_dump_device->tmp_size : offset;
		ULONG     part2_length = length - part1_length;

		if (part1_length != 0) { // write to part encrypted with master key
			xts_encrypt(p_data, EncryptedData, part1_length, offset, current_dump_device->dsk_key);
		}
		if (part2_length != 0) { // write to part encrypted with temporary key
			xts_encrypt(p_data + part1_length, EncryptedData + part1_length, part2_length, part2_offset, current_dump_device->tmp_key);
		}
	} else { // write only to encrypted part
		xts_encrypt(p_data, EncryptedData, length, offset, current_dump_device->dsk_key);
	}

#ifdef _M_IX86
	KeLowerIrql(old_irql);
#endif

	return STATUS_SUCCESS;
}

static BOOLEAN dc_dump_is_hibernation_allowed(__in BOOLEAN lockable_skipped)
{
	dc_dump_eval ev;

	/* ahead of time (usage notification, QUERY_POWER, S4 SET_POWER): the same policy as
	 * dc_dump_start will apply at dump time, with the no-hibernation volumes locked by then
	 * - and, with lockable_skipped, every DC_HIBER_LOCKABLE volume as well */
	dc_dump_evaluate(TRUE, lockable_skipped ? DC_EVAL_PREDICT_LOCKED : DC_EVAL_PREDICT, &ev);

	// hibernation allowed if no active mounts or hibernation device is fully encrypted
	return ev.number_of_mounts == 0 || (ev.found_dump_devices == 1 && ev.dump_device_encrypted);
}

// dump helpers structure passed to dump filters
DC_DUMP_HELPERS dc_dump_helpers = {
	dc_dump_start,
	dc_dump_finish,
	dc_dump_encrypt,
	dc_dump_is_hibernation_allowed,
};
