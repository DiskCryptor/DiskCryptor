/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2010
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
#include <ntdddisk.h>
#include "defines.h"
#include "devhook.h"
#include "device_io.h"
#include "misc.h"
#include "misc_mem.h"
#include "crc32.h"
#include "debug.h"

/* largest DC-internal read / write request (io_hook_rw_dir): one transcryption block */
#define DC_IO_REQ_MAX (8 * 1024 * 1024)

HANDLE io_open_device(wchar_t *dev_name)
{
	UNICODE_STRING    u_name;
	OBJECT_ATTRIBUTES obj_a;
	IO_STATUS_BLOCK   iosb;
	NTSTATUS          status;
	HANDLE            h_dev;

	RtlInitUnicodeString(&u_name, dev_name);
	InitializeObjectAttributes(&obj_a, &u_name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	status = ZwCreateFile(&h_dev, SYNCHRONIZE | GENERIC_READ, &obj_a, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, 
		FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);

	if (NT_SUCCESS(status) == FALSE) {
		h_dev = NULL;
	}
	return h_dev;
}

NTSTATUS io_device_control(IN  PDEVICE_OBJECT DeviceObject,
	                       IN  ULONG          IoControlCode,
						   IN  PVOID          InputBuffer OPTIONAL,
						   IN  ULONG          InputBufferLength,
						   OUT PVOID          OutputBuffer OPTIONAL,
						   IN  ULONG          OutputBufferLength)
{
	IO_STATUS_BLOCK io_status;
	KEVENT          completion_event;
	NTSTATUS        status;
	PIRP            p_irp;

	KeInitializeEvent(&completion_event, NotificationEvent, FALSE);

	if ( (p_irp = IoBuildDeviceIoControlRequest(IoControlCode, DeviceObject, InputBuffer, InputBufferLength,
		                                        OutputBuffer, OutputBufferLength, FALSE, &completion_event, &io_status)) == NULL )
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	if ( (status = IoCallDriver(DeviceObject, p_irp)) == STATUS_PENDING ) {
		KeWaitForSingleObject(&completion_event, Executive, KernelMode, FALSE, NULL);
		status = io_status.Status;
	}
	return status;
}

NTSTATUS io_device_request(IN     PDEVICE_OBJECT DeviceObject,
	                       IN     ULONG          MajorFunction,
						   IN OUT PVOID          Buffer OPTIONAL,
						   IN     ULONG          Length OPTIONAL,
						   IN     ULONGLONG      StartingOffset OPTIONAL)
{
	IO_STATUS_BLOCK iosb;
	NTSTATUS        status;
	PIRP            irp;
	KEVENT          sync_event;
	ULONG           timeout;
	
	KeInitializeEvent(&sync_event, NotificationEvent,  FALSE);

	timeout = DC_MEM_RETRY_TIMEOUT;
	do
	{
		if (irp = IoBuildSynchronousFsdRequest(MajorFunction, DeviceObject, Buffer, Length, (PLARGE_INTEGER)&StartingOffset, &sync_event, &iosb))
		{
			IoGetNextIrpStackLocation(irp)->Flags |= SL_OVERRIDE_VERIFY_VOLUME;
			break;
		}
		dc_delay(DC_MEM_RETRY_TIME); timeout -= DC_MEM_RETRY_TIME;
	} while (timeout != 0);

	if (irp == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	status = IoCallDriver(DeviceObject, irp);

	if (status == STATUS_PENDING) {
		KeWaitForSingleObject(&sync_event, Executive, KernelMode, FALSE, NULL);
		status = iosb.Status;
	}
	return status;
}

int io_hook_ioctl(dev_hook *hook, u32 code, void *p_in, u32 sz_in, void *p_out, u32 sz_out)
{
	if (hook->pnp_state != Started) {
		DbgMsg("device not started, dev=%ws, pnp_state=%d\n", hook->dev_name, hook->pnp_state);
		return ST_ERROR;
	}
	return NT_SUCCESS( io_device_control(hook->orig_dev, code, p_in, sz_in, p_out, sz_out) ) ? ST_OK : ST_IO_ERROR;
}

/*
 * Never write onto a medium swapped into a removable device while a volume is mounted
 * (DC-internal I/O carries SL_OVERRIDE_VERIFY_VOLUME, so classpnp does not stop it).
 * Before every DC-internal write to a mounted removable volume the media change count is
 * compared with hook->mnt_chg_count. classpnp raises the count on every UNIT ATTENTION (bus
 * reset, S3/S4 resume), so a changed count only triggers an identity test (io_same_medium);
 * the same medium adopts the new count, another is refused.
 */
/*
 * Identity bookkeeping, all under hook->id_lock (steps test it without busy_lock while
 * a session save moves it).
 *  - mnt_id at mnt_id_off: the salt of the DC header the volume was mounted / unlocked from,
 *    or DC last wrote through dc_hook_rw. The strong identity: random per header.
 *  - id_crc0 / id_crcoff: crc32 of the whole sector 0 / the sector at mnt_id_off as a DC write
 *    last left it (wipes, restored partition end). Slot [1] is the last FAILED write attempt
 *    there (it may have reached the medium); a successful write clears it. The whole sector,
 *    because the first 64 bytes are identical on all exFAT and identically formatted media.
 */
void io_id_reset(dev_hook *hook)
{
	KIRQL irql;

	KeAcquireSpinLock(&hook->id_lock, &irql);
	hook->mnt_id_valid    = 0;
	hook->id_crc0_ok[0]   = hook->id_crc0_ok[1]   = 0;
	hook->id_crcoff_ok[0] = hook->id_crcoff_ok[1] = 0;
	KeReleaseSpinLock(&hook->id_lock, irql);
}

void io_id_set_header(dev_hook *hook, const void *salt, u64 off)
{
	KIRQL irql;

	KeAcquireSpinLock(&hook->id_lock, &irql);
	if (!hook->mnt_id_valid || hook->mnt_id_off != off) {
		hook->id_crcoff_ok[0] = hook->id_crcoff_ok[1] = 0; /* belonged to the old place */
	}
	memcpy(hook->mnt_id, salt, sizeof(hook->mnt_id));
	hook->mnt_id_off   = off;
	hook->mnt_id_valid = 1;
	KeReleaseSpinLock(&hook->id_lock, irql);
}

void io_id_set_sector0(dev_hook *hook, const void *sector, u32 len)
{
	u32   crc = crc32(sector, len);
	KIRQL irql;

	KeAcquireSpinLock(&hook->id_lock, &irql);
	hook->id_crc0[0]    = crc;
	hook->id_crc0_ok[0] = 1;
	hook->id_crc0_ok[1] = 0;
	KeReleaseSpinLock(&hook->id_lock, irql);
}

/* the header the identity is at moved (dc_update_volume: backup header written at the new end) */
void io_id_move(dev_hook *hook, u64 old_off, u64 new_off)
{
	KIRQL irql;

	KeAcquireSpinLock(&hook->id_lock, &irql);
	if (hook->mnt_id_valid && hook->mnt_id_off == old_off) {
		hook->mnt_id_off      = new_off;
		hook->id_crcoff_ok[0] = hook->id_crcoff_ok[1] = 0;
	}
	KeReleaseSpinLock(&hook->id_lock, irql);
}

/*
 * A DC write left [lo, hi) of the disk as buff (which starts at disk offset `offset`), or -
 * failed - may have left it so. Sector granular (all DC writes are sector aligned).
 */
static void io_id_track_write(dev_hook *hook, const u8 *buff, u64 offset, u64 lo, u64 hi, int failed)
{
	u32   sec = max(hook->bps, SECTOR_SIZE);
	u32   crc0 = 0, crcoff = 0;
	int   has0, hasoff;
	u64   off;
	KIRQL irql;

	if (!(hook->flags & F_REMOVABLE) || lo >= hi) return;

	/* the crcs are computed outside the lock; mnt_id_off is re-checked under it */
	off    = hook->mnt_id_off;
	has0   = (lo == 0 && hi >= sec);
	hasoff = (off != 0 && lo <= off && off + sec <= hi);
	if (!has0 && !hasoff) return;

	if (has0)   crc0   = crc32(buff + (0 - offset), sec);
	if (hasoff) crcoff = crc32(buff + (off - offset), sec);

	KeAcquireSpinLock(&hook->id_lock, &irql);
	if (has0) {
		hook->id_crc0[failed]    = crc0;
		hook->id_crc0_ok[failed] = 1;
		if (!failed) hook->id_crc0_ok[1] = 0;
	}
	if (hasoff && hook->mnt_id_valid && hook->mnt_id_off == off) {
		hook->id_crcoff[failed]    = crcoff;
		hook->id_crcoff_ok[failed] = 1;
		if (!failed) hook->id_crcoff_ok[1] = 0;
	}
	KeReleaseSpinLock(&hook->id_lock, irql);
}

static int io_crc_in(u32 crc, const u32 *slots, const LONG *ok)
{
	return (ok[0] && slots[0] == crc) || (ok[1] && slots[1] == crc);
}

/*
 * ST_OK: the mounted medium, ST_MEDIA_CHANGED: another one, ST_IO_ERROR: cannot tell now.
 * Without any identity yet (encryption start until its first write at 0) a changed count refuses.
 * "Cannot tell" is ST_IO_ERROR, not ST_RW_ERR: the transcryption step would take a refused
 * (unwritten) piece for a bad sector and pass it.
 */
static int io_same_medium(dev_hook *hook)
{
	u8    id[64];
	u32   crc0[2], crcoff[2];
	LONG  crc0_ok[2], crcoff_ok[2];
	u64   off;
	int   id_ok;
	u32   len = max(hook->bps, SECTOR_SIZE);
	u8   *buf;
	int   resl = ST_MEDIA_CHANGED, unknown = 0, have0 = 0;
	KIRQL irql;

	KeAcquireSpinLock(&hook->id_lock, &irql);
	id_ok = hook->mnt_id_valid;
	off   = hook->mnt_id_off;
	memcpy(id, hook->mnt_id, sizeof(id));
	crc0[0] = hook->id_crc0[0];       crc0[1] = hook->id_crc0[1];
	crc0_ok[0] = hook->id_crc0_ok[0]; crc0_ok[1] = hook->id_crc0_ok[1];
	crcoff[0] = hook->id_crcoff[0];       crcoff[1] = hook->id_crcoff[1];
	crcoff_ok[0] = id_ok && hook->id_crcoff_ok[0]; crcoff_ok[1] = id_ok && hook->id_crcoff_ok[1];
	KeReleaseSpinLock(&hook->id_lock, irql);

	have0 = crc0_ok[0] || crc0_ok[1];
	if (!id_ok && !have0) {
		return ST_MEDIA_CHANGED;
	}
	if ((buf = mm_pool_alloc(len)) == NULL) {
		return ST_IO_ERROR;
	}
	if (id_ok) {
		if (!NT_SUCCESS(io_device_request(hook->orig_dev, IRP_MJ_READ, buf, len, off))) {
			unknown = 1;
		} else if ( memcmp(buf, id, sizeof(id)) == 0 ||
			        (off != 0 && io_crc_in(crc32(buf, len), crcoff, crcoff_ok)) ||
			        (off == 0 && io_crc_in(crc32(buf, len), crc0, crc0_ok)) )
		{
			resl = ST_OK;
		}
	}
	if (resl != ST_OK && have0 && !(id_ok && off == 0)) {
		if (!NT_SUCCESS(io_device_request(hook->orig_dev, IRP_MJ_READ, buf, len, 0))) {
			unknown = 1;
		} else if (io_crc_in(crc32(buf, len), crc0, crc0_ok)) {
			resl = ST_OK;
		}
	}
	mm_pool_free(buf);

	return (resl != ST_OK && unknown) ? ST_IO_ERROR : resl;
}

int io_check_media(dev_hook *hook)
{
	int      resl;
	ULONG    count = 0;
	NTSTATUS status = io_device_control(hook->orig_dev, IOCTL_STORAGE_CHECK_VERIFY, NULL, 0, &count, sizeof(count));

	if (NT_SUCCESS(status)) {
		if (count == hook->mnt_chg_count) {
			return ST_OK;
		}
		DbgMsg("io_check_media: media change count %u, mounted %u, checking identity, dev=%ws\n", count, hook->mnt_chg_count, hook->dev_name);
		if ((resl = io_same_medium(hook)) == ST_OK) {
			hook->mnt_chg_count = count; /* the same medium: adopt the new count */
		}
		return resl;
	}
	DbgMsg("io_check_media: CHECK_VERIFY status %08x, dev=%ws\n", status, hook->dev_name);

	/* not STATUS_DEVICE_NOT_READY: transient after a reset, fails as ST_IO_ERROR below
	 * (nothing written) instead of unmounting */
	if (status == STATUS_NO_MEDIA_IN_DEVICE || status == STATUS_NO_MEDIA || status == STATUS_NO_SUCH_DEVICE ||
		status == STATUS_DEVICE_DOES_NOT_EXIST || status == STATUS_DEVICE_NOT_CONNECTED) {
		return ST_NO_MEDIA;
	}
	if (status == STATUS_VERIFY_REQUIRED || status == STATUS_MEDIA_CHANGED) {
		/* DO_VERIFY_VOLUME is also set after a reset: same identity test (our read carries
		 * SL_OVERRIDE_VERIFY_VOLUME); the count is unknown, the next write asks again */
		return io_same_medium(hook);
	}
	if (status == STATUS_UNRECOGNIZED_MEDIA) {
		return ST_MEDIA_CHANGED;
	}
	return ST_IO_ERROR; /* cannot tell - see io_same_medium */
}

/*
 * io_hook_rw with a direction and a progress report. Without done: requests of up to
 * DC_IO_REQ_MAX - a failed one may have written any of its pieces (the class driver below
 * splits it and runs the pieces in parallel). With done: max_chunk requests issued in order
 * (from the end of the range when reverse is set), stopping at the first failure; *done
 * receives the bytes transferred before it, from the starting side. Only the failed request
 * is undetermined then.
 */
int io_hook_rw_dir(dev_hook *hook, void *buff, u32 length, u64 offset, int is_read, int reverse, u32 *done)
{
	NTSTATUS status;
	u32      bsize, pos, end, moved = 0;
	int      resl;

	if (done != NULL) *done = 0;

	if (hook->pnp_state != Started || hook->max_chunk == 0) {
		DbgMsg("device not started, dev=%ws, pnp_state=%d, max_chunk=%u\n", hook->dev_name, hook->pnp_state, hook->max_chunk);
		return ST_RW_ERR;
	}
	/* never write onto another medium than the mounted one */
	if ( !is_read && (hook->flags & (F_REMOVABLE | F_ENABLED)) == (F_REMOVABLE | F_ENABLED) &&
		 (resl = io_check_media(hook)) != ST_OK )
	{
		return resl;
	}
	for (resl = ST_OK, pos = 0, end = length; pos < end; )
	{
		u32 at;

		/* without a progress report up to DC_IO_REQ_MAX per request, not max_chunk: the class
		 * driver splits a larger request and runs the pieces in parallel, while serial
		 * max_chunk pieces keep a single request in flight (half an NVMe drive's throughput) */
		bsize = min(end - pos, (done != NULL) ? hook->max_chunk : max(hook->max_chunk, DC_IO_REQ_MAX));
		at    = reverse ? end - bsize : pos;  /* reverse: [pos, end) is what is left */

		status = io_device_request(hook->orig_dev, is_read ? IRP_MJ_READ : IRP_MJ_WRITE, p8(buff) + at, bsize, offset + at);

		/* what this write left (or, failed, may have left) on the disk, for the identity
		 * test - per request and before the classification below, which may run that test */
		if (!is_read) {
			io_id_track_write(hook, buff, offset, offset + at, offset + at + bsize, NT_SUCCESS(status) == FALSE);
		}

		if (NT_SUCCESS(status) == FALSE)
		{
			if ( (hook->flags & (F_REMOVABLE | F_CDROM)) &&
				 (status == STATUS_NO_SUCH_DEVICE ||
				  status == STATUS_DEVICE_DOES_NOT_EXIST || status == STATUS_NO_MEDIA_IN_DEVICE) )
			{
				resl = ST_NO_MEDIA;
			} else if ( (hook->flags & F_REMOVABLE) &&
				        (status == STATUS_VERIFY_REQUIRED || status == STATUS_MEDIA_CHANGED) )
			{
				/* also set after a reset - the identity test decides; the
				 * same medium makes it a failed request (nothing known to be written) */
				resl = io_check_media(hook);
				if (resl == ST_OK) resl = ST_IO_ERROR;
			} else {
				resl = ST_RW_ERR;
			}
			DbgMsg("io_hook_rw: dev=%ws, status=%08x\n", hook->dev_name, status);
			break;
		}
		if (reverse) end -= bsize; else pos += bsize;
		moved += bsize;
		if (done != NULL) *done = moved;
	}

	return resl;
}

int io_hook_rw(dev_hook *hook, void *buff, u32 length, u64 offset, int is_read)
{
	return io_hook_rw_dir(hook, buff, length, offset, is_read, 0, NULL);
}

int io_hook_rw_skip_bads(dev_hook *hook, void *buff, u32 length, u64 offset, int is_read)
{
	u32 block;
	int resl, err = ST_OK;

	if ( (resl = io_hook_rw(hook, buff, length, offset, is_read)) == ST_RW_ERR )
	{
		while (block = min(length, 4096))
		{
			resl = io_hook_rw(hook, buff, block, offset, is_read);

			/* ST_IO_ERROR - the medium could not be verified, nothing was written */
			if ( (resl == ST_MEDIA_CHANGED) || (resl == ST_NO_MEDIA) || (resl == ST_IO_ERROR) ) {
				break;
			}
			/* a failed piece is not hidden by a later piece that succeeds */
			if (resl == ST_RW_ERR) err = ST_RW_ERR;
			buff = p8(buff) + block; length -= block; offset += block;
		}
		if (resl == ST_OK) resl = err;
	}
	return resl;
}

/*
 * volume_lib's dc_rw_fn over io_hook_rw. Exists so that io_hook_rw itself,
 * and all of its call sites, stay exactly as they are.
 */
int dc_hook_rw(void *ctx, void *buff, u32 length, u64 offset, int is_read)
{
	dev_hook *hook = (dev_hook*)ctx;
	int       resl = io_hook_rw(hook, buff, length, offset, is_read);

	/* the medium identity follows DC's own header writes: volume_lib writes only header
	 * areas through this function, at 0 or at the header the volume was mounted from.
	 * Reads never set it (a read of a mounted volume may already come from another medium). */
	if ( resl == ST_OK && !is_read && (hook->flags & F_REMOVABLE) && length >= sizeof(hook->mnt_id) &&
		 (offset == 0 || offset == hook->mnt_id_off) )
	{
		io_id_set_header(hook, buff, offset);
	}
	return resl;
}
