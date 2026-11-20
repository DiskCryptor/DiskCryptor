/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2019-2026
	* DavidXanatos <info@diskcryptor.org>
    * Copyright (c) 2007-2010
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
#include "driver.h"
#include "prng.h"
#include "misc.h"
#include "readwrite.h"
#include "mount.h"
#include "enc_dec.h"
#include "data_wipe.h"
#include "misc_irp.h"
#include "fast_crypt.h"
#include "misc_volume.h"
#include "debug.h"
#include "storage.h"
#include "crypto_head.h"
#include "misc_mem.h"
#include "ssd_trim.h"
#include "disk_info.h"
#include "device_io.h"

/* tmp_buff of a transcryption session (allocated with DC_TMP_BUFF_SIZE): [block: ENC_BLOCK_SIZE]
   [FF_SAFE_FAST checksum table: DC_SLOG_SUM_BYTES][bad-sector map: 1 bit per 512-byte unit] */
#define DC_BAD_MAP_BYTES   (ENC_BLOCK_SIZE / 512 / 8)
#define DC_TMP_BUFF_SIZE   (ENC_BLOCK_SIZE + DC_SLOG_SUM_BYTES + DC_BAD_MAP_BYTES)
#define DC_STEP_SUMS(_hook_)    ((u64*)(p8((_hook_)->tmp_buff) + ENC_BLOCK_SIZE))
#define DC_STEP_BAD_MAP(_hook_) ((u32*)(p8((_hook_)->tmp_buff) + ENC_BLOCK_SIZE + DC_SLOG_SUM_BYTES))
/* EF_SAFE_TRANSCRYPT_FAST asked for and possible - a wipe pass destroys the old content the
   checksum recovery needs (dc_safe_complete_sums), so a wiping session uses the full journal */
#define DC_WIPES(_wp_)     ((_wp_) != WP_NONE && (_wp_) != WP_SKIP_UNUSED)
#define DC_SAFE_FAST(_c_)  ( ((_c_)->flags & EF_SAFE_TRANSCRYPT_FAST) != 0 && !DC_WIPES((_c_)->wp_mode) )
#ifdef DC_CONCURRENT_TRANSCRYPT
static void dc_safe_complete_early(dev_hook *hook);
#endif
/* DC_WIPE_BLOCK: enc_dec.h */
#include "header_io.h"
#include "volume_head.h"
#include "crc32.h"
#include "alloc_bitmap.h"
#include "safe_log.h"

/*
 * End of the area that is transcrypted in place (exclusive). With a backup header
 * (F_HEAD_BACKUP) the last head_len bytes are never transcrypted: with a $dcsys$ file the
 * partition end is redirected to storage (tail_len == head_len); with slack storage the
 * backup header lives at dsk_size - head_len (tail_len is 0 after S_INIT_ENC, head_len
 * after a remount: both give the same end).
 */
static u64 dc_data_end(dev_hook *hook)
{
	if (hook->flags & F_HEAD_BACKUP) {
		return hook->dsk_size - (hook->tail_len != 0 ? hook->tail_len : hook->head_len);
	}
	return hook->dsk_size;
}

#ifndef DC_CONCURRENT_TRANSCRYPT

typedef struct _sync_struct {
	KEVENT sync_event;
	int    status;

} sync_struct;

typedef struct _sync_context {
	int finish;
	int saved;
	int winit;

} sync_context;

/* function types declaration */
KSTART_ROUTINE dc_sync_op_routine;


static int dc_enc_update(dev_hook *hook)
{
	u8 *buff = hook->tmp_buff;
	u64 offs = hook->tmp_size;
	u64 data_end;
	u64 remaining;
	u32 size;
	int r_resl, w_resl;

	data_end = dc_data_end(hook); /* excludes the backup header */

	if (offs >= data_end) {
		return ST_FINISHED;
	}
	remaining = data_end - offs;
	size = d32(min(remaining, ENC_BLOCK_SIZE));

	/* Skip unallocated sectors when WP_SKIP_UNUSED optimization is enabled */
	if (DC_BITMAP_IS_VALID(hook->alloc_bitmap)) {
#ifdef DC_AGGRESSIVE_SKIP
		u64 unalloc_len = dc_bitmap_get_unallocated(hook, offs);
		if (unalloc_len > remaining) {
			unalloc_len = remaining;
		}
		if (unalloc_len > 0) {
			/* Skip exactly the unallocated length - clusters are always sector-aligned */
			hook->tmp_size += unalloc_len;
			return ST_OK;
		}
#else
		if (!dc_bitmap_is_allocated(hook, offs, size)) {
			hook->tmp_size += size;
			return ST_OK;
		}
#endif
	}

	do
	{
		r_resl = io_hook_rw_skip_bads(hook, buff, size, offs, 1);

		if ( (r_resl != ST_OK) && (r_resl != ST_RW_ERR) ) {
			break;
		}
		cp_fast_encrypt(buff, buff, size, offs, hook->dsk_key);

		dc_wipe_process(&hook->wp_ctx, offs, size);

		w_resl = io_hook_rw_skip_bads(hook, buff, size, offs, 0);

		if (w_resl == ST_RW_ERR) {
			r_resl = w_resl;
		}
	} while (0);

	if ( (r_resl == ST_OK) || (r_resl == ST_RW_ERR) ) {
		hook->tmp_size += size;
	}
	return r_resl;
}

static int dc_re_enc_update(dev_hook *hook)
{
	u8 *buff = hook->tmp_buff;
	u64 offs = hook->tmp_size;
	u64 data_end;
	u64 remaining;
	u32 size;
	int r_resl, w_resl;

	data_end = dc_data_end(hook); /* excludes the backup header */

	if (offs >= data_end) {
		return ST_FINISHED;
	}
	remaining = data_end - offs;
	size = d32(min(remaining, ENC_BLOCK_SIZE));

	/* Skip unallocated sectors when WP_SKIP_UNUSED optimization is enabled */
	if (DC_BITMAP_IS_VALID(hook->alloc_bitmap)) {
#ifdef DC_AGGRESSIVE_SKIP
		u64 unalloc_len = dc_bitmap_get_unallocated(hook, offs);
		if (unalloc_len > remaining) {
			unalloc_len = remaining;
		}
		if (unalloc_len > 0) {
			/* Skip exactly the unallocated length - clusters are always sector-aligned */
			hook->tmp_size += unalloc_len;
			return ST_OK;
		}
#else
		if (!dc_bitmap_is_allocated(hook, offs, size)) {
			hook->tmp_size += size;
			return ST_OK;
		}
#endif
	}

	do
	{
		r_resl = io_hook_rw_skip_bads(hook, buff, size, offs, 1);

		if ( (r_resl != ST_OK) && (r_resl != ST_RW_ERR) ) {
			break;
		}

		/* wipe old data */
		dc_wipe_process(&hook->wp_ctx, offs, size);

		/* re-encrypt data */
		cp_fast_decrypt(buff, buff, size, offs, hook->tmp_key);
		cp_fast_encrypt(buff, buff, size, offs, hook->dsk_key);

		w_resl = io_hook_rw_skip_bads(hook, buff, size, offs, 0);

		if (w_resl == ST_RW_ERR) {
			r_resl = w_resl;
		}
	} while (0);

	if ( (r_resl == ST_OK) || (r_resl == ST_RW_ERR) ) {
		hook->tmp_size += size;
	}
	return r_resl;
}

#endif

#ifdef DC_CONCURRENT_TRANSCRYPT
/*
 * Wait for all pending I/O to complete (pending_io_count == 0).
 * Used before modifying shared state that I/O depends on.
 * Note: This does NOT set active_start/active_end - use dc_lock_disk_range
 * if you need to block I/O to a specific range.
 */
static void dc_wait_for_pending_io(dev_hook *hook)
{
	transcrypt_state *trans = &hook->trans;
	KIRQL irql;

wait_loop:
	KeAcquireSpinLock(&trans->range_lock, &irql);
	if (trans->pending_io_count > 0) {
		KeReleaseSpinLock(&trans->range_lock, irql);
		KeWaitForSingleObject(&trans->io_done_event, Executive, KernelMode, FALSE, NULL);
		KeClearEvent(&trans->io_done_event);
		goto wait_loop;
	}
	KeReleaseSpinLock(&trans->range_lock, irql);
}

/*
 * Lock [start, end) against concurrent I/O: wait until pending_io_count == 0, then set
 * active_start/active_end in the SAME range_lock section, so no new I/O can start between
 * the check and the lock.
 */
static void dc_lock_disk_range(dev_hook *hook, u64 start, u64 end)
{
	transcrypt_state *trans = &hook->trans;
	KIRQL irql;

wait_for_pending_io:
	KeAcquireSpinLock(&trans->range_lock, &irql);
	if (trans->pending_io_count > 0) {
		KeReleaseSpinLock(&trans->range_lock, irql);
		KeWaitForSingleObject(&trans->io_done_event, Executive, KernelMode, FALSE, NULL);
		KeClearEvent(&trans->io_done_event);
		goto wait_for_pending_io;
	}
	/* No pending I/O - set active range while still holding spinlock */
	KeClearEvent(&trans->block_complete);
	trans->active_start = start;
	trans->active_end = end;
	KeReleaseSpinLock(&trans->range_lock, irql);
}

/*
 * Wait until no read/write admitted WITHOUT F_SYNC is still in flight. Call right after
 * F_SYNC is published (interlocked), before the first range is locked or touched: such a
 * request did not take pending_io_count, so dc_lock_disk_range does not wait for it, and a
 * flush does not either. New requests see F_SYNC and are tracked, so the count only drains.
 * No timeout: none of these requests waits for busy_lock, the step slot or the range lock
 * the caller holds; a stuck disk is logged.
 */
static void dc_drain_untracked_io(dev_hook *hook)
{
	transcrypt_state *trans = &hook->trans;
	ULONGLONG         start, last;

	KeMemoryBarrier(); /* the F_SYNC publish (interlocked) before the count is read */

	for (start = last = KeQueryInterruptTime(); trans->untracked_io > 0; )
	{
		ULONGLONG now = KeQueryInterruptTime();

		if (now - last >= 50000000ull) { /* 5 s */
			DbgMsg("dc_drain_untracked_io: %d requests admitted before F_SYNC still in flight after %I64u ms, dev=%ws\n",
				trans->untracked_io, (now - start) / 10000, hook->dev_name);
			last = now;
		}
		dc_delay(1);
	}
}

/*
 * Unlock a previously locked disk range.
 * Clears active_start/active_end and signals waiting I/O.
 */
static void dc_unlock_disk_range(dev_hook *hook)
{
	transcrypt_state *trans = &hook->trans;
	KIRQL irql;

	KeAcquireSpinLock(&trans->range_lock, &irql);
	trans->active_start = -1;
	trans->active_end = 0;
	KeSetEvent(&trans->block_complete, IO_NO_INCREMENT, FALSE);
	KeReleaseSpinLock(&trans->range_lock, irql);
}
#endif /* DC_CONCURRENT_TRANSCRYPT */

static int dc_store_part_begin(dev_hook* hook)
{
	u8 *buff = hook->tmp_buff;
	u32 done, chunk;
	int resl = ST_OK;

#ifdef DC_CONCURRENT_TRANSCRYPT
	/* [0, head_len) stays locked during the copy, so concurrent I/O cannot use a partially
	 * copied redirect target (S_INIT_ENC already armed the lock: dc_enable_with_head_locked).
	 * The caller wipes the original only once every redirected range is stored. */
	dc_lock_disk_range(hook, 0, hook->head_len);
#endif

	/* save start sectors to storage */
	for (done = 0; done < hook->head_len; done += chunk)
	{
		chunk = min(hook->head_len - done, ENC_BLOCK_SIZE);
		chunk = max((chunk / (u64)hook->bps) * (u64)hook->bps, hook->bps); // align to sector, round down, but at least one

		resl = io_hook_rw(hook, buff, chunk, done, 1);
		if (resl != ST_OK) break;

		resl = io_hook_rw(hook, buff, chunk, hook->stor_off + done, 0);
		if (resl != ST_OK) break;
	}

#ifdef DC_CONCURRENT_TRANSCRYPT
	/* On failure the range stays locked: unlocking would let head I/O through the redirect
	 * into a half-copied storage area. The caller drops the init flags first, then unlocks. */
	if (resl == ST_OK) {
		dc_unlock_disk_range(hook);
	}
#endif

	return resl;
}

#ifdef DC_CONCURRENT_TRANSCRYPT
static int dc_init_enc_undo_begin(dev_hook *hook, u32 clear_flags, u32 set_flags, BOOLEAN wiped);
#endif

/*
 * Copy the partition begin back from storage at the end of a decryption, backwards: offset 0
 * (the DC header io_check_media compares on removable media) is written last, so a reset
 * between chunks cannot find the boot sector there and refuse the rest. On success the volume
 * becomes F_PLAIN_IO (raw pass-through), published while [0, head_len) is still locked; on
 * failure the redirect stays active and storage still holds a valid copy.
 */
static int dc_restore_part_begin(dev_hook* hook)
{
#ifdef DC_CONCURRENT_TRANSCRYPT
	return dc_init_enc_undo_begin(hook, 0, F_PLAIN_IO, TRUE);
#else
	u8 *buff = hook->tmp_buff;
	u32 done, chunk;
	int resl = ST_OK;

	for (done = hook->head_len; done > 0; done -= chunk)
	{
		chunk = min(done, ENC_BLOCK_SIZE);

		resl = io_hook_rw(hook, buff, chunk, hook->stor_off + done - chunk, 1);
		if (resl != ST_OK) { break; }

		resl = io_hook_rw(hook, buff, chunk, done - chunk, 0);
		if (resl != ST_OK) { break; }
	}

	return resl;
#endif
}

/*
 * Overwrite [offset, offset + length) at its raw disk offset with random bytes, in
 * ENC_BLOCK_SIZE pieces, to destroy a header copy. length is a multiple of bps.
 */
static int dc_scrub_raw(dev_hook *hook, u64 offset, u32 length)
{
	u8 *buff = hook->tmp_buff;
	u32 done, chunk;
	int resl = ST_OK;

	for (done = 0; done < length; done += chunk)
	{
		chunk = min(length - done, ENC_BLOCK_SIZE);
		cp_rand_bytes(buff, chunk);
		if ( (resl = io_hook_rw(hook, buff, chunk, offset + done, 0)) != ST_OK ) break;
	}
	return resl;
}

#ifdef DC_CONCURRENT_TRANSCRYPT
/*
 * Switch a plaintext volume into transcryption mode with [0, head_len) already locked.
 * F_ENABLED|F_SYNC turn on the head redirect to stor_off, which does not hold the partition
 * begin until dc_store_part_begin has run; arming the lock in the same range_lock section
 * makes every tracked head I/O wait for the copy.
 */
static void dc_enable_with_head_locked(dev_hook *hook)
{
	transcrypt_state *trans = &hook->trans;
	KIRQL irql;

	KeAcquireSpinLock(&trans->range_lock, &irql);
	KeClearEvent(&trans->block_complete);
	trans->active_start = 0;
	trans->active_end   = hook->head_len;
	dc_hook_set_flags(hook, (F_ENABLED | F_SYNC));
	KeReleaseSpinLock(&trans->range_lock, irql);
}

/*
 * With [0, head_len) locked, copy the partition begin back raw from storage, backwards
 * (offset 0 last, see dc_restore_part_begin). Then, still locked and under range_lock, clear
 * clear_flags and - on success only - set set_flags. Returns the copy-back result.
 * Undo of S_INIT_ENC: before the wipe (wiped = FALSE) the flags are dropped even when the
 * copy-back fails (losing only writes since dc_store_part_begin: the volume has no header
 * and must go back to pass-through). After the wipe (wiped = TRUE) a failed copy-back keeps
 * the flags: the storage copy is the only current partition begin.
 */
static int dc_init_enc_undo_begin(dev_hook *hook, u32 clear_flags, u32 set_flags, BOOLEAN wiped)
{
	transcrypt_state *trans = &hook->trans;
	u8               *buff = hook->tmp_buff;
	u32               done, chunk;
	int               resl = ST_OK;
	KIRQL             irql;

	dc_lock_disk_range(hook, 0, hook->head_len);

	/* head_len is a multiple of bps */
	for (done = hook->head_len; done > 0; done -= chunk)
	{
		chunk = min(done, ENC_BLOCK_SIZE);

		resl = io_hook_rw(hook, buff, chunk, hook->stor_off + done - chunk, 1);
		if (resl != ST_OK) break;

		resl = io_hook_rw(hook, buff, chunk, done - chunk, 0);
		if (resl != ST_OK) break;
	}
	if (resl != ST_OK) {
		DbgMsg("dc_init_enc_undo_begin: copy-back of partition begin failed (%d)\n", resl);
	}

	/* still with [0, head_len) locked: no head request can see the old mapping after this */
	if (resl == ST_OK || !wiped) {
		KeAcquireSpinLock(&trans->range_lock, &irql);
		dc_hook_clear_flags(hook, clear_flags);
		if (resl == ST_OK && set_flags != 0) {
			dc_hook_set_flags(hook, set_flags);
		}
		KeReleaseSpinLock(&trans->range_lock, irql);
	}

	dc_unlock_disk_range(hook);
	return resl;
}
#endif

static int dc_store_part_end(dev_hook* hook, BOOLEAN encrypted);
static int dc_restore_part_end(dev_hook* hook, BOOLEAN encrypted);

/* On removable media an ST_IO_ERROR ("cannot tell", e.g. the medium becoming ready after a
 * reset) is retried 5 times, 200 ms apart. Returns TRUE (after the delay) to repeat. */
static BOOLEAN dc_removable_retry(dev_hook *hook, int resl, int *tries)
{
	if (resl != ST_IO_ERROR || !(hook->flags & F_REMOVABLE) || *tries >= 5) {
		return FALSE;
	}
	dc_delay(200);
	(*tries)++;
	return TRUE;
}

static int dc_dec_finish(dev_hook *hook)
{
	int resl;

	/* Restore the partition end first: dc_restore_part_begin switches the volume to
	 * F_PLAIN_IO, which is only correct once every redirected range is back. */
	if ((hook->flags & F_HEAD_BACKUP) && hook->tail_len != 0)
	{
		resl = dc_restore_part_end(hook, FALSE);
		if (resl != ST_OK) {
			return resl;
		}
	}

	/* restoring the partition begin overwrites the volume header: flush the decrypted data
	 * and the restored end first, so the header cannot be gone while they sit in a cache */
	io_device_request(hook->orig_dev, IRP_MJ_FLUSH_BUFFERS, NULL, 0, 0);

	resl = dc_restore_part_begin(hook);
	if (resl != ST_OK) {
		return resl;
	}
	/* the restored boot sector must be on stable media before $dcsys$ (its only other copy)
	 * is deleted */
	io_device_request(hook->orig_dev, IRP_MJ_FLUSH_BUFFERS, NULL, 0, 0);

	/* slack storage (no tail redirect): the backup header at dsk_size - head_len would stay a
	 * valid DC header a "use backup header" mount applies to the plaintext volume - scrub it.
	 * F_PLAIN_IO now: raw offsets. Best effort: the data is already plaintext and in place. */
	if ( (hook->flags & F_HEAD_BACKUP) && hook->tail_len == 0 &&
		 !(hook->flags & (F_PROTECT_DCSYS | F_NO_REDIRECT | F_CDROM)) )
	{
		if (hook->dsk_size >= hook->head_len &&
			hook->dsk_size - hook->head_len >= hook->stor_off + hook->head_len)
		{
			int tries = 0, sresl;

			do {
				sresl = dc_scrub_raw(hook, hook->dsk_size - hook->head_len, hook->head_len);
			} while (dc_removable_retry(hook, sresl, &tries));
			if (sresl != ST_OK) {
				DbgMsg("dc_dec_finish: failed to scrub the backup header\n");
			}
			io_device_request(hook->orig_dev, IRP_MJ_FLUSH_BUFFERS, NULL, 0, 0);
		}
		dc_hook_clear_flags(hook, F_HEAD_BACKUP);
	}

	return ST_FINISHED;
}

#ifndef DC_CONCURRENT_TRANSCRYPT

static int dc_dec_update(dev_hook *hook)
{
	u8 *buff = hook->tmp_buff;
	u64 data_start = hook->head_len;
	u64 remaining;
	u32 size;
	u64 offs;
	int r_resl, w_resl;

	if (hook->tmp_size <= data_start)
	{
		/* write redirected part back to zero offset */
		return dc_dec_finish(hook);
	}

	remaining = hook->tmp_size - data_start;
	size = d32(min(remaining, ENC_BLOCK_SIZE));
	offs = hook->tmp_size - size;

	/* Skip unallocated sectors when WP_SKIP_UNUSED optimization is enabled */
	if (DC_BITMAP_IS_VALID(hook->alloc_bitmap)) {
#ifdef DC_AGGRESSIVE_SKIP
		u64 unalloc_len = dc_bitmap_get_unallocated_backward(hook, hook->tmp_size);
		if (unalloc_len > remaining) {
			unalloc_len = remaining;
		}
		if (unalloc_len > 0) {
			/* Skip exactly the unallocated length - clusters are always sector-aligned */
			hook->tmp_size -= unalloc_len;
			return ST_OK;
		}
#else
		if (!dc_bitmap_is_allocated(hook, offs, size)) {
			hook->tmp_size -= size;
			return ST_OK;
		}
#endif
	}

	do
	{
		r_resl = io_hook_rw_skip_bads(hook, buff, size, offs, 1);

		if ( (r_resl != ST_OK) && (r_resl != ST_RW_ERR) ) {
			break;
		}
		cp_fast_decrypt(buff, buff, size, offs, hook->dsk_key);

		w_resl = io_hook_rw_skip_bads(hook, buff, size, offs, 0);

		if (w_resl == ST_RW_ERR) {
			r_resl = w_resl;
		}
	} while (0);

	if ( (r_resl == ST_OK) || (r_resl == ST_RW_ERR) ) {
		hook->tmp_size -= size;
	}
	return r_resl;
}

#endif /* !DC_CONCURRENT_TRANSCRYPT - end of sync-only update functions */

/*
 * The backup header write of a state save (dc_save_state_int; busy_lock / step slot as there),
 * flushed. ST_OK or the write error.
 * retry (FINISH / INIT saves) repeats transient failures - a FINISH whose backup write fails
 * is not done; the write is idempotent. A periodic UPDATE does not retry: the next save repairs
 * it, and retries cost seconds under busy_lock and the step slot.
 * bak_clone_once: the backup could not be decrypted at mount - write it once as a full copy of
 * the primary (sealed with the primary header key, as bak_salt / bak_key already are).
 */
static int dc_save_backup(dev_hook *hook, dc_dev *dev, u32 step, BOOLEAN retry)
{
	int     bak_resl = ST_OK;
	int     i;
	BOOLEAN clone = InterlockedCompareExchange(&hook->trans.bak_clone_once, 0, 0) != 0;

	for (i = 0; i < 10; i++) {
		if (clone) {
			/* the space checks of dc_update_backup: never over the head copy (storage at
			 * the end) or over in-place data ($dcsys$ without a full tail) */
			if ( (IS_STORAGE_ON_END(hook->flags) && hook->stor_len < hook->head_len * 2) ||
				 (!IS_STORAGE_ON_END(hook->flags) && hook->tail_len < hook->head_len) ) {
				bak_resl = ST_NF_SPACE;
			} else {
				bak_resl = io_write_header(dev, dc_hook_rw, dev->dsk_size - dev->head_len, hook->tmp_header, hook->hdr_key, NULL, HF_DEFAULT, NULL);
			}
		} else {
			bak_resl = dc_update_backup(dev, dc_hook_rw, hook->tmp_header, hook->bak_salt, hook->bak_key, NULL, (step == SYNC_STEP_UPDATE) ? HF_UPDATE_BASE : HF_DEFAULT);
		}
		if (bak_resl != ST_RW_ERR && bak_resl != ST_IO_ERROR && bak_resl != ST_NOMEM) break;
		if (!retry || hook->pnp_state != Started) break;
		dc_delay(100);
	}
	if (bak_resl == ST_OK) {
		if (clone) {
			InterlockedExchange(&hook->trans.bak_clone_once, 0);
		}
	} else {
		DbgMsg("dc_save_backup: backup header update failed (%d), step=%d, dev=%ws\n", bak_resl, step, hook->dev_name);
	}

	io_device_request(hook->orig_dev, IRP_MJ_FLUSH_BUFFERS, NULL, 0, 0);
	return bak_resl;
}

/* Returns the status of the primary header write (ST_OK when nothing is written after a
 * finished decryption); the backup header is best effort except for a FINISH.
 * tmp_ovr (commit of a pending block): the boundary to write instead of hook->tmp_size. */
static int dc_save_state_int(dev_hook *hook, u32 step, const u64 *tmp_ovr)
{
	dc_dev dev;
	int i;
	int resl = ST_RW_ERR;
	u64 tmp_size;
	dc_slog *slog = dc_slog_get(hook); /* power-loss protected session */
	u32 old_ff = 0;                    /* feature_flags / log_offset before a FINISH */
	u64 old_lo = 0;
	int bak_state = ST_OK;             /* the backup header write (when there is one) */
	BOOLEAN bak_first = FALSE;         /* a FINISH wrote the backup before the primary */
	u32 req_step = step; /* step is rewritten below for the re-encryption finish */
	u8  old_key_2[DISKKEY_SIZE];
	int old_alg_2 = 0;
	BOOLEAN fin_reenc = FALSE; /* re-encryption finish: key_2 / alg_2 saved in old_* */
	BOOLEAN full_once = FALSE; /* this save writes the full header (HF_DEFAULT) */
	int     wr_tries = 10;     /* primary header write attempts */
#ifdef DC_CONCURRENT_TRANSCRYPT
	KIRQL irql;
#endif

	DbgMsg("dc_save_enc_state, step=%d\n", step);

	/* mounted with a damaged header (MF_IGNORE_CRC, read-only): its boundary may be wrong, it
	 * must not reach the disk as a valid header. Before the sanity check (CRC fixed in memory). */
	if (hook->mnt_flags & MF_IGNORE_CRC) {
		DbgMsg("dc_save_enc_state: mounted with a damaged header (MF_IGNORE_CRC), header not written\n");
		return ST_OK;
	}

	/* decryption finished: a header written now would overwrite the restored boot sector.
	 * Before the sanity check: tmp_header may already be freed. */
	if (hook->flags & F_PLAIN_IO) {
		DbgMsg("dc_save_enc_state: decryption finished (F_PLAIN_IO), header not written\n");
		return ST_OK;
	}

	// check header for memory corruption, bugcheck if header invalid
	// and check encryption key for zeroed
	if (hook->tmp_header == NULL || is_volume_header_correct(hook->tmp_header) == FALSE || hook->hdr_key == NULL || hook->hdr_key->encrypt == NULL)
	{
		KeBugCheckEx(STATUS_DISK_CORRUPT_ERROR, __LINE__, 0, 0, 0);
	}

#ifdef DC_CONCURRENT_TRANSCRYPT
	/* the initial full header never reached the disk (S_INIT_ENC kept the session): write the
	 * full header. Steps are refused meanwhile, so the state is still the initial one. */
	if (step == SYNC_STEP_UPDATE && InterlockedCompareExchange(&hook->trans.init_hdr_pending, 0, 0) != 0) {
		step = SYNC_STEP_INIT;
		req_step = step;
		/* a periodic save tries once; the saves that end the session (F_PREVENT_ENC) retry */
		if ((hook->flags & F_PREVENT_ENC) == 0) {
			wr_tries = 1;
		}
	}
	/* mounted from the backup header - the primary gets the full header once. Only the write
	 * mode changes: the save stays an UPDATE / FINISH, so the backup is still updated after a
	 * failed primary write (an INIT save would skip it). */
	if (InterlockedCompareExchange(&hook->trans.full_hdr_once, 0, 0) != 0) {
		full_once = TRUE;
	}
#endif

	/* the header records the current storage place (the layout moves on a resize) */
	dc_header_sync_stor_off(hook, hook->tmp_header);

	/* one snapshot of the 64-bit boundary, under range_lock (steps store it concurrently) */
#ifdef DC_CONCURRENT_TRANSCRYPT
	KeAcquireSpinLock(&hook->trans.range_lock, &irql);
	tmp_size = hook->tmp_size;
	KeReleaseSpinLock(&hook->trans.range_lock, irql);
#else
	tmp_size = hook->tmp_size; /* sync thread build: steps and saves are serialized */
#endif
	if (tmp_ovr != NULL) {
		tmp_size = *tmp_ovr; /* commits a pending block that is durable in place */
	}

	if (step == SYNC_STEP_FINISH)
	{
		hook->tmp_header->flags &= ~(VF_TMP_MODE | VF_REENCRYPT);
		hook->tmp_header->tmp_size = 0;
		hook->tmp_header->tmp_wp_mode = 0;
		/* the journal is no longer part of the volume (the finish zeroes and deletes it) */
		old_ff = hook->tmp_header->feature_flags;
		old_lo = hook->tmp_header->log_offset;
		hook->tmp_header->feature_flags &= ~(FF_SAFE_TRANSCRYPT | FF_SAFE_FAST);
		hook->tmp_header->log_offset = 0;

		// reencryption finished, zero previous encryption key
		if (hook->flags & F_REENCRYPT) {
			/* kept until the write succeeded - a failed finish keeps the session */
			memcpy(old_key_2, hook->tmp_header->key_2, sizeof(old_key_2));
			old_alg_2 = hook->tmp_header->alg_2;
			fin_reenc = TRUE;
			RtlSecureZeroMemory(hook->tmp_header->key_2, sizeof(hook->tmp_header->key_2)); 
			hook->tmp_header->alg_2 = 0;
			step = SYNC_STEP_UPDATE; // when reencrypting don't rewrite the entire header just update base region (full_once still forces HF_DEFAULT)
		}
	} 
	else if (tmp_size > 0)
	{
		hook->tmp_header->flags |= VF_TMP_MODE;
		hook->tmp_header->tmp_size = tmp_size;
		hook->tmp_header->tmp_wp_mode = hook->crypt.wp_mode;

		if (hook->flags & F_REENCRYPT) {
			hook->tmp_header->flags |= VF_REENCRYPT;
		} 
	}
	// update header checksum
	hook->tmp_header->hdr_crc = calculate_header_crc(hook->tmp_header);

	// the layout does not move under us here, so one projection covers both
	// the retry loop and the backup write below
	dc_dev_of(hook, &dev);

	/* flush the data the header is about to claim (steps up to the tmp_size snapshot, the
	 * S_INIT_ENC copies/wipe) BEFORE writing it */
	io_device_request(hook->orig_dev, IRP_MJ_FLUSH_BUFFERS, NULL, 0, 0);

	/* The FINISH save writes the backup header FIRST: a finished primary is mounted without
	 * reading the backup, so a stale backup behind it would never be repaired. The primary
	 * already says "TMP at the data end" (dc_save_enc_state), so every state between the
	 * writes reads correctly from either header. A transient backup write failure is no
	 * finish (the session is kept, the next step retries); a structural error (the layout
	 * holds no backup) does not block it. */
	if (req_step == SYNC_STEP_FINISH && (hook->flags & F_HEAD_BACKUP)) {
		bak_first = TRUE;
		bak_state = dc_save_backup(hook, &dev, step, TRUE);
		if (bak_state == ST_RW_ERR || bak_state == ST_IO_ERROR || bak_state == ST_NOMEM ||
			bak_state == ST_MEDIA_CHANGED || bak_state == ST_NO_MEDIA) {
			DbgMsg("dc_save_enc_state: finish refused, backup header not written (%d), dev=%ws\n", bak_state, hook->dev_name);
			resl = bak_state;
			wr_tries = 0; /* no primary write */
		}
	}

	// write new header to disk (retry 10 times on error; see wr_tries)
	for (i = 0; i < wr_tries; i++) {
		if ( (resl = io_write_header(&dev, dc_hook_rw, 0, hook->tmp_header, hook->hdr_key, NULL, (step == SYNC_STEP_UPDATE && !full_once) ? HF_UPDATE_BASE : HF_DEFAULT, NULL)) == ST_OK ) break;
		if (i + 1 < wr_tries) dc_delay(100);
	}

	// flush disk cache
	if (wr_tries != 0) {
		io_device_request(hook->orig_dev, IRP_MJ_FLUSH_BUFFERS, NULL, 0, 0);
	}

	/* the boundary the primary header now holds (or may hold, after a failed write);
	 * the journal records carry it, the recovery matches it against the header */
	if (slog != NULL && req_step != SYNC_STEP_FINISH && tmp_size > 0) {
		slog->hdr_try = tmp_size;
		if (resl == ST_OK) slog->hdr_ok = tmp_size;
	}

#ifdef DC_CONCURRENT_TRANSCRYPT
	if (step == SYNC_STEP_INIT && resl == ST_OK) {
		InterlockedExchange(&hook->trans.init_hdr_pending, 0); /* header on disk now */
	}
	if ((step != SYNC_STEP_UPDATE || full_once) && resl == ST_OK) {
		InterlockedExchange(&hook->trans.full_hdr_once, 0);    /* full header written */
	}
#endif

	if (req_step == SYNC_STEP_FINISH)
	{
		if (resl != ST_OK) {
			/* dc_transcrypt_finish keeps the session on this failure: put the in-memory header
			 * back into the UPDATE-save state, so later saves and the backup do not describe a
			 * finished volume while the primary on disk is still in TMP mode. */
			hook->tmp_header->flags |= VF_TMP_MODE;
			hook->tmp_header->tmp_size = tmp_size;
			hook->tmp_header->tmp_wp_mode = hook->crypt.wp_mode;
			hook->tmp_header->feature_flags = old_ff; /* the journal stays the session's */
			hook->tmp_header->log_offset = old_lo;
			if (fin_reenc) {
				hook->tmp_header->flags |= VF_REENCRYPT;
				memcpy(hook->tmp_header->key_2, old_key_2, sizeof(old_key_2));
				hook->tmp_header->alg_2 = old_alg_2;
			}
			hook->tmp_header->hdr_crc = calculate_header_crc(hook->tmp_header);
		}
		RtlSecureZeroMemory(old_key_2, sizeof(old_key_2));
	}

	/* If we have a backup header, write it too (errors do not fail the save). Not after a
	 * failed SYNC_STEP_INIT primary write: the caller aborts the start, and a backup that
	 * describes the new session would outlive it. A FINISH save wrote it first, above. */
	if (!bak_first && (hook->flags & F_HEAD_BACKUP) && !(step == SYNC_STEP_INIT && resl != ST_OK))
	{
		/* journal bookkeeping as for the primary */
		bak_state = dc_save_backup(hook, &dev, step, req_step != SYNC_STEP_UPDATE && wr_tries > 1);
		if (slog != NULL && req_step != SYNC_STEP_FINISH && tmp_size > 0) {
			slog->bak_try = tmp_size;
			if (bak_state == ST_OK) slog->bak_ok = tmp_size;
		}
	}

	/* every header holds the exact boundary now, the journal records are obsolete. Only
	 * when the backup write succeeded too: after a failed one a record is all a backup mount
	 * has. */
	if (slog != NULL && req_step != SYNC_STEP_FINISH && resl == ST_OK && bak_state == ST_OK) {
		slog->need_hdr = 0; /* the records are bound to headers on the disk again */
		dc_slog_empty(hook, slog);
	}
	return resl;
}

int dc_save_enc_state(dev_hook *hook, u32 step)
{
	dc_slog *slog = dc_slog_get(hook);

	/* never while a journaled block is pending: later records would carry a header value the
	 * pending record does not, so the recovery would ignore it and use a boundary one block
	 * behind the disk. The next step (dc_safe_resolve) or the next mount's recovery completes it. */
	if (slog != NULL && (slog->pend || slog->dead)) {
		DbgMsg("dc_save_enc_state: a journaled block is pending, header not written, dev=%ws\n", hook->dev_name);
		return ST_LOG_PENDING;
	}
	/* A finish with a backup header takes three writes: (1) the primary as a session at the
	 * data end, (2) the backup as finished, (3) the primary as finished. Whichever write a power
	 * loss interrupts, no header says "finished" while the other claims an earlier boundary.
	 * (1) failing is a failed finish (the session is kept). */
	if (step == SYNC_STEP_FINISH && (hook->flags & F_HEAD_BACKUP)) {
		int resl = dc_save_state_int(hook, SYNC_STEP_UPDATE, NULL);

		if (resl != ST_OK) {
			DbgMsg("dc_save_enc_state: finish refused, the session header at the data end not written (%d), dev=%ws\n", resl, hook->dev_name);
			return resl;
		}
	}
	return dc_save_state_int(hook, step, NULL);
}

static void dc_wipe_sectors(dev_hook *hook, u64 offset, u32 length)
{
	u8      *buff = hook->tmp_buff;
	u32      done, chunk;

	for (done = 0; done < length; done += chunk)
	{
		chunk = min(length - done, ENC_BLOCK_SIZE);
		chunk = max((chunk / (u64)hook->bps) * (u64)hook->bps, hook->bps); // align to sector, round down, but at least one

		dc_wipe_process(&hook->wp_ctx, offset + done, chunk);
	}
}

static int dc_apply_layout(dev_hook *hook, u32 type);

static int dc_init_sync_mode(dev_hook *hook, u32 type)
{
	u32      old_flags = hook->flags;
	int      resl = ST_ERROR;
#ifdef DC_CONCURRENT_TRANSCRYPT
	/* the bits an init path below may set; a failure clears only these (restoring the whole
	 * word would undo concurrent updates of other bits) */
	u32      init_flags = (F_ENABLED | F_SYNC | F_REENCRYPT | F_HEAD_BACKUP) & ~old_flags;
#endif

	do
	{
		switch (type & 0xFF)
		{
			case S_INIT_ENC:
				{
#ifdef DC_CONCURRENT_TRANSCRYPT
					/* initialize encryption process - head locked until it is copied to storage */
					dc_enable_with_head_locked(hook);
					KeMemoryBarrier();

					/* head writes admitted before F_SYNC must be done before the head is copied */
					dc_drain_untracked_io(hook);
					io_device_request(hook->orig_dev, IRP_MJ_FLUSH_BUFFERS, NULL, 0, 0);
#endif

					/* save start sectors to storage */
					resl = dc_store_part_begin(hook);
					if (resl != ST_OK) {
#ifdef DC_CONCURRENT_TRANSCRYPT
						/* the head is still locked: leave redirect mode, then unlock. Nothing
						 * was wiped; the physical head is intact. */
						KIRQL irql;
						KeAcquireSpinLock(&hook->trans.range_lock, &irql);
						dc_hook_clear_flags(hook, init_flags);
						KeReleaseSpinLock(&hook->trans.range_lock, irql);
						dc_unlock_disk_range(hook);
#endif
						break;
					}

					/* the wipe below destroys the original head - on removable media verify the
					 * medium while only the head copy exists (the head-only undo restores it
					 * completely). A "cannot tell" aborts too; the start can be repeated. */
					if (hook->flags & F_REMOVABLE) {
						int tries = 0;

						do {
							resl = io_check_media(hook);
						} while (dc_removable_retry(hook, resl, &tries));
					}
					if ( (hook->flags & F_REMOVABLE) && resl != ST_OK ) {
						DbgMsg("S_INIT_ENC: medium not verified (%d), start aborted\n", resl);
#ifdef DC_CONCURRENT_TRANSCRYPT
						dc_init_enc_undo_begin(hook, init_flags, 0, FALSE);
#endif
						break;
					}

					/* copy EVERYTHING to storage before wiping anything: a wiped begin with a
					 * failed tail copy and no header would be unmountable */
					{
						BOOLEAN tail_stored = FALSE;

						/* save end sectors to storage when backup header is present */
						if (hook->tmp_header && (hook->tmp_header->flags & VF_BACKUP_HEADER))
						{
							if (IS_STORAGE_ON_END(hook->flags)) {
								/* backup header lives in the slack: no tail redirect */
								hook->tail_len = 0;
								hook->tail_off = 0;
								dc_hook_set_flags(hook, F_HEAD_BACKUP);
							} else {
								resl = dc_store_part_end(hook, FALSE);
								if (resl != ST_OK) {
									/* nothing wiped yet and no tail redirect published: put
									 * the head back and leave the redirect mode */
#ifdef DC_CONCURRENT_TRANSCRYPT
									dc_init_enc_undo_begin(hook, init_flags, 0, FALSE);
#endif
									break;
								}
								tail_stored = TRUE;
							}
						}

						/* the storage copies must be on stable media before the originals
						 * are wiped */
						io_device_request(hook->orig_dev, IRP_MJ_FLUSH_BUFFERS, NULL, 0, 0);

						/* all redirected ranges are in storage: wipe the originals */
						dc_wipe_sectors(hook, 0, hook->head_len);
						if (tail_stored) {
							dc_wipe_sectors(hook, hook->dsk_size - hook->tail_len, hook->tail_len);
						}

						/* save initial state */
						resl = dc_save_enc_state(hook, SYNC_STEP_INIT);
						if (resl != ST_OK) {
							int undo = ST_OK;

							/* the originals are wiped and no header is on disk: the begin (and
							 * end) exist only in storage. Put them back (end first) and abort.
							 * If a copy-back fails too, keep the session in redirect mode with
							 * the full header pending (init_hdr_pending): saves retry it, steps
							 * are refused until it is on disk, a decryption can still restore. */
							DbgMsg("S_INIT_ENC: initial header save failed (%d), undoing the start\n", resl);
#ifdef DC_CONCURRENT_TRANSCRYPT
							if (tail_stored) {
								if ( (undo = dc_restore_part_end(hook, FALSE)) == ST_OK ) {
									/* end back in place: a session kept below must not claim a
									 * backup header (flags is CRC-covered) */
									hook->tmp_header->flags &= ~VF_BACKUP_HEADER;
									hook->tmp_header->hdr_crc = calculate_header_crc(hook->tmp_header);
								}
							}
							if (undo == ST_OK) {
								undo = dc_init_enc_undo_begin(hook, init_flags, 0, TRUE);
							}
							if (undo != ST_OK) {
								DbgMsg("S_INIT_ENC: undo failed (%d), session kept with the header pending\n", undo);
								InterlockedExchange(&hook->trans.init_hdr_pending, 1);
								resl = ST_OK;
								break;
							}
							hook->tail_len = 0;
							hook->tail_off = 0;
#endif
							break;
						}
					}
				}
			break;
			case S_INIT_DEC:
				{
#ifdef DC_CONCURRENT_TRANSCRYPT
					dc_hook_set_flags(hook, (F_ENABLED | F_SYNC));
					KeMemoryBarrier();

					/* wait for all I/O that bypassed pending_io_count tracking, then flush */
					dc_drain_untracked_io(hook);
					io_device_request(hook->orig_dev, IRP_MJ_FLUSH_BUFFERS, NULL, 0, 0);
#endif
					resl = ST_OK;
#ifdef DC_CONCURRENT_TRANSCRYPT
					/* a power-loss protected decryption writes its session header (VF_TMP_MODE,
					 * FF_SAFE_TRANSCRYPT, log_offset) before the first step, so the disk knows the
					 * session and the journal. A backup header that could not be read was taken
					 * from the primary (same salt): written as a full copy. */
					if (dc_slog_get(hook) != NULL) {
						if (hook->bak_salt != NULL && hook->tmp_header != NULL &&
							memcmp(hook->bak_salt, hook->tmp_header->salt, HEADER_SALT_SIZE) == 0) {
							InterlockedExchange(&hook->trans.bak_clone_once, 1);
						}
						if ( (resl = dc_save_enc_state(hook, SYNC_STEP_UPDATE)) != ST_OK ) {
							DbgMsg("S_INIT_DEC: session header save failed (%d), start aborted\n", resl);
						}
					}
#endif
				}
			break;
			case S_CONTINUE_ENC: 
				{
#ifdef DC_CONCURRENT_TRANSCRYPT
					dc_safe_complete_early(hook); /* FF_SAFE_FAST, before any I/O meets the block */
					dc_hook_set_flags(hook, (F_ENABLED | F_SYNC));
#endif
					resl = ST_OK;
				}
			break;
			case S_INIT_RE_ENC:
				{
					DbgMsg("S_INIT_RE_ENC\n");

#ifdef DC_CONCURRENT_TRANSCRYPT
					xts_key* new_key;

					/* F_SYNC | F_REENCRYPT must be set BEFORE the keys are swapped (dsk_key = old,
					 * tmp_key = new until here): with F_ENABLED but not F_SYNC, I/O would use
					 * dsk_key = new key for data under the old key. So tmp_key = old key, then the
					 * flags, then dsk_key = new key. tmp_size is head_len here, so all data I/O
					 * uses tmp_key = old key (F_NO_REDIRECT volumes are refused). */

					/* Save new_key pointer before we overwrite tmp_key */
					new_key = hook->tmp_key;

					/* Step 1: Set tmp_key to old_key (for I/O above boundary) */
					hook->tmp_key = hook->dsk_key;

					/* Step 2: flags BEFORE dsk_key changes (InterlockedOr: full barrier, also on ARM64) */
					InterlockedOr((volatile LONG*)&hook->flags, (F_ENABLED | F_SYNC | F_REENCRYPT));

					/* flags globally visible before dsk_key changes */
					KeMemoryBarrier();

					/* wait for all I/O that bypassed pending_io_count tracking, then flush */
					dc_drain_untracked_io(hook);
					io_device_request(hook->orig_dev, IRP_MJ_FLUSH_BUFFERS, NULL, 0, 0);

					/* Step 3: write the initial header (full, new header key) BEFORE dsk_key becomes
					 * the new key, so after a failed write the new key was never visible: the I/O
					 * path reads dsk_key before the flags, which only protects "F_SYNC set, then
					 * key changed". */
					resl = dc_save_enc_state(hook, SYNC_STEP_INIT);
					if (resl != ST_OK) {
						/* Abort before any step ran. A failed write that reached the disk anyway
						 * describes a re-encryption at head_len with key_2 = the old key, which
						 * matches the data: a later mount resumes it. */
						KIRQL irql;

						DbgMsg("S_INIT_RE_ENC: initial header save failed (%d), start aborted\n", resl);

						/* Leave sync mode, then drain the requests admitted under F_SYNC before
						 * F_REENCRYPT goes (without it io_async_make_chunk takes the plaintext
						 * branch). */
						KeAcquireSpinLock(&hook->trans.range_lock, &irql);
						dc_hook_clear_flags(hook, F_SYNC & init_flags);
						KeReleaseSpinLock(&hook->trans.range_lock, irql);
						dc_wait_for_pending_io(hook);

						/* tmp_key gets the new key back, so the cleanup frees the new key, not
						 * the volume key */
						KeAcquireSpinLock(&hook->trans.range_lock, &irql);
						dc_hook_clear_flags(hook, init_flags);
						KeReleaseSpinLock(&hook->trans.range_lock, irql);
						hook->tmp_key = new_key;
						break;
					}

					/* Step 4: Now safe to set dsk_key to new_key */
					hook->dsk_key = new_key;
#else
					// swap keys
					{
						xts_key* tmp = hook->dsk_key;
						hook->dsk_key = hook->tmp_key;
						hook->tmp_key = tmp;
					}

					/* set re-encryption flag */
					dc_hook_set_flags(hook, F_REENCRYPT);

					/* save initial state - use SYNC_STEP_INIT to write the full header with the new
					* cipher's header key, ensuring slot descriptors and extended header are re-encrypted */
					resl = dc_save_enc_state(hook, SYNC_STEP_INIT);
					if (resl != ST_OK) {
						/* abort: undo the swap (see the concurrent branch) */
						xts_key* tmp = hook->dsk_key;
						hook->dsk_key = hook->tmp_key;
						hook->tmp_key = tmp;
						dc_hook_clear_flags(hook, F_REENCRYPT);
						break;
					}
#endif
					resl = ST_OK;
				}
			break;
			case S_CONTINUE_RE_ENC:
				{
					DbgMsg("S_CONTINUE_RE_ENC\n");

					/* the flags are published only AFTER tmp_key is allocated and keyed (below):
					 * a request that sees F_SYNC | F_REENCRYPT must not get a NULL or half-set key */

					/* the unlock of a volume locked at hibernation re-keys the allocation the lock
					 * kept (zeroed) - the I/O path may hold a snapshot of that pointer */
					if ( hook->tmp_key == NULL &&
						 (hook->tmp_key = (xts_key*)mm_secure_alloc(sizeof(xts_key))) == NULL )
					{
						resl = ST_NOMEM; break;
					}

					/* initialize secondary volume key */
					if (!xts_set_key(hook->tmp_header->key_2, hook->tmp_header->alg_2, hook->tmp_key))
					{
						if (hook->flags & F_HIBER_ERASE) {
							RtlSecureZeroMemory(hook->tmp_key, sizeof(xts_key)); /* stays locked: keep it */
						} else {
							mm_secure_free(hook->tmp_key); hook->tmp_key = NULL;
						}
						resl = ST_INVALID_PARAM; break;
					}

#ifdef DC_CONCURRENT_TRANSCRYPT
					/* FF_SAFE_FAST: tmp_key (the old key) is set up now */
					dc_safe_complete_early(hook);
					/* initialize encryption process - interlocked: orders the tmp_key stores
					 * above before the flags */
					dc_hook_set_flags(hook, (F_ENABLED | F_SYNC | F_REENCRYPT));
#endif
					resl = ST_OK;
				}
			break;
			case S_UPDATE_LAYOUT:
				{
					DbgMsg("S_UPDATE_LAYOUT: tasks=%s%s%s%s%s\n",
						(type & S_RESIZE_HEADER)   ? "S_RESIZE_HEADER "   : "",
						(type & S_BACKUP_HEADER)   ? "S_BACKUP_HEADER "   : "",
						(type & S_REMOVE_BACKUP)   ? "S_REMOVE_BACKUP "   : "",
						(type & S_STORAGE_TO_FILE) ? "S_STORAGE_TO_FILE " : "",
						(type & S_STORAGE_TO_END)  ? "S_STORAGE_TO_END "  : "");

					resl = dc_apply_layout(hook, type);
				}
			break;
			default:
				resl = ST_ERROR;
			break;
		}
	} while (0);

#ifdef DC_CONCURRENT_TRANSCRYPT
	/* on failure clear all flags to disable sync mode */
	if (resl != ST_OK && resl != ST_FINISHED) {
		if ((type & 0xFF) == S_UPDATE_LAYOUT) {
			/* dc_apply_layout may already have changed the layout and the on-disk header (the
			 * flags describe that state now): only leave sync mode (dc_transcrypt_init) */
			DbgMsg("dc_init_sync_mode: S_UPDATE_LAYOUT failed, resl=%d\n", resl);
		} else {
			/* clear only the bits this init set, under range_lock (the I/O path re-checks
			 * F_SYNC there) */
			KIRQL irql;

			DbgMsg("dc_init_sync_mode failed, resl=%d, clearing init flags 0x%X\n", resl, init_flags);
			KeAcquireSpinLock(&hook->trans.range_lock, &irql);
			dc_hook_clear_flags(hook, init_flags);
			KeReleaseSpinLock(&hook->trans.range_lock, irql);
		}
	}
#endif

	return resl;
}

#ifndef DC_CONCURRENT_TRANSCRYPT

static int dc_process_sync_packet(dev_hook *hook, sync_packet *packet, sync_context *ctx)
{
	int new_wp = (int)(INT_PTR)(packet->param);
	int resl;

	switch (packet->type)
	{
		case S_OP_ENC_BLOCK:
			{
				if (ctx->finish == 0)
				{
					/* Lazy init bitmap for SSD skip optimization.
					 * Done here (not at mount) to avoid memory waste when paused. */
					if (hook->crypt.wp_mode == WP_SKIP_UNUSED && hook->alloc_bitmap == NULL) {
						dc_bitmap_start_init(hook);
					}

					if ( hook->crypt.wp_mode != WP_SKIP_UNUSED && (new_wp != hook->crypt.wp_mode) && (new_wp < WP_NUM) )
					{
						dc_wipe_free(&hook->wp_ctx);

						resl = dc_wipe_init(
							&hook->wp_ctx, hook, ENC_BLOCK_SIZE, new_wp, hook->crypt.cipher_id);

						if (resl == ST_OK)
						{
							hook->crypt.wp_mode = d8(new_wp);
							dc_save_enc_state(hook, SYNC_STEP_UPDATE);
						} else {
							dc_wipe_init(&hook->wp_ctx, hook, ENC_BLOCK_SIZE, WP_NONE, 0);
						}
					}

					if (hook->flags & F_REENCRYPT) {
						resl = dc_re_enc_update(hook);
					} else {
						resl = dc_enc_update(hook);
					}

					if (resl == ST_FINISHED) {
						dc_save_enc_state(hook, SYNC_STEP_FINISH); ctx->finish = 1;
					} else ctx->saved = 0;
				} else {
					resl = ST_FINISHED;
				}
			}
		break;
		case S_OP_DEC_BLOCK:
			{
				if (hook->flags & F_REENCRYPT) {
					resl = ST_ERROR; break;
				}

				if (ctx->finish == 0)
				{
					/* Lazy init bitmap for SSD skip optimization.
					 * Done here (not at mount) to avoid memory waste when paused. */
					if (hook->crypt.wp_mode == WP_SKIP_UNUSED && hook->alloc_bitmap == NULL) {
						dc_bitmap_start_init(hook);
					}

					if ( (resl = dc_dec_update(hook)) == ST_FINISHED) {
						dc_process_unmount(hook, MF_NOFSCTL | MF_NOSYNC | MF_DECRYPTED);
						ctx->finish = 1;
					} else ctx->saved = 0;
				} else {
					resl = ST_FINISHED;
				}
			}
		break;
		case S_OP_SYNC:
			{
				if ( (ctx->finish == 0) && (ctx->saved == 0) ) {
					dc_save_enc_state(hook, SYNC_STEP_UPDATE); ctx->saved = 1;
				}
				resl = ST_OK;
			}
		break;
		case S_OP_FINALIZE:
			{
				if ( (ctx->finish == 0) && (ctx->saved == 0) ) {
					dc_save_enc_state(hook, SYNC_STEP_UPDATE); ctx->finish = 1;
				}
				resl = ST_FINISHED;						
			}
		break;
	}

	return resl;
}

#endif

static void dc_sync_cleanup(dev_hook *hook)
{
	/* the journal state of the session (the file stays: a later mount recovers from it) */
	dc_slog_free(hook);

	if (hook->tmp_buff != NULL) {
		mm_pool_free(hook->tmp_buff);
		hook->tmp_buff = NULL;
	}

	dc_bitmap_free(hook);

	if (hook->tmp_key != NULL) {
		if (hook->flags & F_HIBER_ERASE) {
			/* locked: like dsk_key, zero tmp_key but keep the allocation - a request preempted
			 * after its key snapshot may still hold this pointer; the unlock re-keys it in place
			 * (S_CONTINUE_RE_ENC). Freed by the unmount. */
			RtlSecureZeroMemory(hook->tmp_key, sizeof(xts_key));
		} else {
			mm_secure_free(hook->tmp_key);
			hook->tmp_key = NULL;
		}
	}

	if (hook->hdr_key != NULL) {
		mm_secure_free(hook->hdr_key);
		hook->hdr_key = NULL;
	}
	if (hook->tmp_header != NULL) {
		mm_secure_free(hook->tmp_header);
		hook->tmp_header = NULL;
	}

	if (hook->bak_key != NULL) {
		mm_secure_free(hook->bak_key);
		hook->bak_key = NULL;
	}
	if (hook->bak_salt != NULL) {
		mm_secure_free(hook->bak_salt);
		hook->bak_salt = NULL;
	}
}

#ifndef DC_CONCURRENT_TRANSCRYPT

static void dc_sync_op_routine(dev_hook *hook)
{
	sync_packet *packet;
	PLIST_ENTRY  entry;
	sync_context sctx;
	int          resl, init_t;
	int          del_storage;
	
	DbgMsg("sync thread started\n");

	dc_reference_hook(hook);

	/* initialize sync mode data */
	InitializeListHead(&hook->sync_req_queue);
	InitializeListHead(&hook->sync_irp_queue);
	KeInitializeSpinLock(&hook->sync_req_lock);

	KeInitializeEvent(
		&hook->sync_req_event, SynchronizationEvent, FALSE);

	/* enable synchronous irp processing */
	hook->flags |= (F_ENABLED | F_SYNC);
	
	memset(&sctx, 0, sizeof(sctx));
	init_t = hook->sync_init_type;
	del_storage = 0;

	/* allocate resources */
	if (hook->tmp_buff = mm_pool_alloc(DC_TMP_BUFF_SIZE))
	{
		/* Initialize wipe context - skip for WP_SKIP_UNUSED mode */
		if (hook->crypt.wp_mode == WP_SKIP_UNUSED) {
			/* no wiping, just skip unused sectors */
			resl = dc_wipe_init(&hook->wp_ctx, hook, ENC_BLOCK_SIZE, WP_NONE, hook->crypt.cipher_id);
		} else {
			resl = dc_wipe_init(&hook->wp_ctx, hook, ENC_BLOCK_SIZE, hook->crypt.wp_mode, hook->crypt.cipher_id);
		}

		if (resl == ST_OK)
		{
			sctx.winit = 1;
			/* init sync mode */
			resl = dc_init_sync_mode(hook, lock_xchg(&hook->sync_init_type, 0));
		}
	} else {
		resl = ST_NOMEM;
	}
	DbgMsg("sync mode initialized\n");
	/* save init status */
	hook->sync_init_status = resl;

	if (resl == ST_OK)
	{
		/* signal of init finished */
		KeSetEvent(
			&hook->sync_enter_event, IO_NO_INCREMENT, FALSE);
	} else
	{
		if (resl == ST_FINISHED) {
			resl = ST_OK; // treat finished as success for init status
		}
		if ( (init_t == S_INIT_ENC) || (init_t == S_CONTINUE_ENC) || (init_t == S_CONTINUE_RE_ENC) ) {
			hook->flags &= ~(F_ENABLED | F_SYNC | F_REENCRYPT | F_PROTECT_DCSYS);
		} else {
			hook->flags &= ~F_SYNC;
		}
		goto cleanup;
	}

	do
	{
		wait_object_infinity(&hook->sync_req_event);

		do
		{
			if (hook->flags & F_SYNC)
			{
				while (entry = ExInterlockedRemoveHeadList(&hook->sync_irp_queue, &hook->sync_req_lock))
				{
					io_encrypted_irp_io(hook, CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry), TRUE);
				}
			}
			if (entry = ExInterlockedRemoveHeadList(&hook->sync_req_queue, &hook->sync_req_lock))
			{
				packet = CONTAINING_RECORD(entry, sync_packet, entry_list);

				/* process packet */
				resl = dc_process_sync_packet(hook, packet, &sctx);

				/* prevent system power state changes */
				PoSetSystemState(ES_SYSTEM_REQUIRED);

				/* disable synchronous irp processing */
				if (resl == ST_FINISHED) 
				{
					del_storage  = !(hook->flags & F_ENABLED) && 
						            (hook->tmp_header->flags & VF_STORAGE_FILE);
					hook->flags &= ~(F_SYNC | F_REENCRYPT);		

					if ( (dc_conf_flags & CONF_DISABLE_TRIM) == 0 &&
						 (packet->type == S_OP_ENC_BLOCK || packet->type == S_OP_DEC_BLOCK) )
					{
						dc_trim_free_space(hook);
					}
				}

				/* signal of packet completion */
				packet->status = resl;
				
				KeSetEvent(&packet->sync_event, IO_NO_INCREMENT, FALSE);

				if ( (resl == ST_MEDIA_CHANGED) || (resl == ST_NO_MEDIA) ) {
					dc_process_unmount(hook, MF_NOFSCTL | MF_NOSYNC);
					resl = ST_FINISHED; sctx.finish = 1;
				}
			}
		} while (entry != NULL);
	} while (hook->flags & F_SYNC);
cleanup:;

	/* pass all IRPs to default routine */
	while (entry = ExInterlockedRemoveHeadList(&hook->sync_irp_queue, &hook->sync_req_lock)) {
		io_read_write_irp(hook, CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry));
	}

	// free resources and prevent leaks
	if (sctx.winit != 0) dc_wipe_free(&hook->wp_ctx);

	dc_sync_cleanup(hook);

	/* report init finished if initialization fails */
	if (resl != ST_FINISHED) {
		KeSetEvent(&hook->sync_enter_event, IO_NO_INCREMENT, FALSE);	
	}

	if (del_storage != 0) {
		dc_delete_storage(hook);
	}

	dc_deref_hook(hook);

	DbgMsg("exit from sync thread\n");

	PsTerminateSystemThread(STATUS_SUCCESS);
}

int dc_enable_sync_mode(dev_hook *hook, u32 type)
{
	int resl;

	do
	{
		if (hook->flags & F_SYNC) {
			resl = ST_ERROR; break;
		}

		hook->sync_init_type = type;

		KeInitializeEvent(
			&hook->sync_enter_event, NotificationEvent, FALSE);		

		resl = start_system_thread(dc_sync_op_routine, hook, NULL);

		if (resl == ST_OK) {
			wait_object_infinity(&hook->sync_enter_event);
			resl = hook->sync_init_status;						
		} else {
			/* failed to start thread, cleanup and return error */
			dc_sync_cleanup(hook);
		}
	} while (0);

	return resl;
}

int dc_send_sync_packet(wchar_t *dev_name, u32 type, void *param)
{
	dev_hook    *hook;
	sync_packet *packet;
	int          mutex = 0;
	int          resl;	

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		if ( !(hook->flags & F_SYNC) ) {			
			resl = ST_ERROR; break;
		}

		if ( (hook->flags & F_PREVENT_ENC) && 
			 ((type == S_OP_ENC_BLOCK) || (type == S_OP_DEC_BLOCK)) )
		{
			resl = ST_CANCEL; break;
		}

		if ( (packet = mm_pool_alloc(sizeof(sync_packet))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		KeInitializeEvent(
			&packet->sync_event, NotificationEvent, FALSE);

		packet->type  = type;
		packet->param = param;		

		ExInterlockedInsertTailList(
			&hook->sync_req_queue, &packet->entry_list, &hook->sync_req_lock);

		KeSetEvent(
			&hook->sync_req_event, IO_NO_INCREMENT, FALSE);

		KeReleaseMutex(&hook->busy_lock, FALSE);

		wait_object_infinity(&packet->sync_event);

		resl = packet->status; mutex = 1;
		mm_pool_free(packet);
	} while (0);

	if (hook != NULL)
	{
		if (mutex == 0) {
			KeReleaseMutex(&hook->busy_lock, FALSE);
		}
		dc_deref_hook(hook);
	}
	return resl;
}

#endif /* !DC_CONCURRENT_TRANSCRYPT - end of sync thread functions */

void dc_sync_all_encs()
{
	dev_hook *hook;

	if (hook = dc_first_hook())
	{
		do
		{
			if (hook->flags & F_SYNC) {
#ifdef DC_CONCURRENT_TRANSCRYPT
				/* For concurrent mode, wait for any in-progress transcryption
				 * to complete, then save state */
				wait_object_infinity(&hook->busy_lock);
				if (hook->flags & F_SYNC) {
					/* hold the step slot across the save - the final decrypt step must
					 * not restore the boot sector (F_PLAIN_IO) between the save's
					 * F_PLAIN_IO test and its header write */
					dc_acquire_step_slot(hook);
					dc_save_enc_state(hook, SYNC_STEP_UPDATE);
					dc_release_step_slot(hook);
				}
				KeReleaseMutex(&hook->busy_lock, FALSE);
#else
				dc_send_sync_packet(hook->dev_name, S_OP_SYNC, 0);
#endif
			}
		} while (hook = dc_next_hook(hook));
	}
}

#ifdef DC_CONCURRENT_TRANSCRYPT
/*
 * Concurrent transcryption implementation.
 * Instead of a dedicated sync thread that processes all I/O,
 * we use per-block spinlock+event synchronization.
 * The UI drives transcryption by sending DC_CTL_ENCRYPT_STEP/DC_CTL_DECRYPT_STEP
 * IOCTLs, which process one block directly in the IOCTL handler context.
 */

int dc_transcrypt_init(dev_hook *hook, u32 type)
{
	transcrypt_state *trans = &hook->trans;
	int               resl;
	KIRQL             irql;

	DbgMsg("dc_transcrypt_init: type=%X\n", type);

	/* range_lock, block_complete, io_done_event and idle_event are initialised once in
	 * dc_add_device, never here: a step left over from the previous session may hold the slot.
	 * Hold the step slot for the whole init / layout operation: dc_init_sync_mode publishes
	 * F_SYNC while it still copies the partition begin/end or rewrites the layout; a step in
	 * that window would replace the single active range lock, share tmp_buff and encrypt
	 * offset 0 or run dc_dec_finish over the header. Callers hold busy_lock. */
	dc_acquire_step_slot(hook);

	/* Reset the block state under range_lock. pending_io_count must be 0; if it is not, do NOT
	 * overwrite it - in-flight requests still decrement it, and a negative count stops
	 * dc_lock_disk_range waiting. */
	KeAcquireSpinLock(&trans->range_lock, &irql);
	trans->active_start = -1;
	trans->active_end = 0;
	if (trans->pending_io_count != 0) {
		DbgMsg("dc_transcrypt_init: pending_io_count=%d at init (expected 0), dev=%ws\n", trans->pending_io_count, hook->dev_name);
	}
	KeSetEvent(&trans->block_complete, IO_NO_INCREMENT, FALSE);
	KeReleaseSpinLock(&trans->range_lock, irql);

	/* a new session starts without read retries pending (slot held) */
	trans->rd_retry_offs = 0;
	trans->rd_retry_cnt  = 0;
	/* set again by S_INIT_ENC below if its header save and undo both fail */
	InterlockedExchange(&trans->init_hdr_pending, 0);
	InterlockedExchange(&trans->full_hdr_once, 0); /* set by the mount afterwards */
	InterlockedExchange(&trans->bak_clone_once, 0); /* set by dc_install_session afterwards */

	/* Pre-allocated: block processing must not allocate (with I/O, including paging I/O,
	 * blocked, an allocation retry there deadlocks). */
	hook->tmp_buff = mm_pool_alloc(DC_TMP_BUFF_SIZE);
	if (hook->tmp_buff == NULL) {
		DbgMsg("dc_transcrypt_init: buffer allocation failed\n");
		/* free the session the caller handed over, like a failed dc_init_sync_mode does */
		if ((hook->flags & F_SYNC) == 0) dc_sync_cleanup(hook);
		dc_release_step_slot(hook);
		return ST_NOMEM;
	}

	/* Initialize wipe context */
	if (hook->crypt.wp_mode == WP_SKIP_UNUSED) {
		resl = dc_wipe_init(&hook->wp_ctx, hook, DC_WIPE_BLOCK, WP_NONE, hook->crypt.cipher_id);
	} else {
		resl = dc_wipe_init(&hook->wp_ctx, hook, DC_WIPE_BLOCK, hook->crypt.wp_mode, hook->crypt.cipher_id);
	}
	if (resl != ST_OK) {
		DbgMsg("dc_transcrypt_init: wipe init failed\n");
		/* tmp_buff and the handed-over session, see above */
		if ((hook->flags & F_SYNC) == 0) {
			dc_sync_cleanup(hook);
		} else {
			mm_pool_free(hook->tmp_buff);
			hook->tmp_buff = NULL;
		}
		dc_release_step_slot(hook);
		return resl;
	}

	resl = dc_init_sync_mode(hook, type);

	if (resl != ST_OK) {
		/* Leave sync mode like dc_transcrypt_cleanup: clear F_SYNC under range_lock, then DRAIN
		 * the I/O admitted under F_SYNC before freeing anything. Also the end of every
		 * S_UPDATE_LAYOUT (ST_FINISHED or failed). */
		KeAcquireSpinLock(&trans->range_lock, &irql);
		dc_hook_clear_flags(hook, F_SYNC);
		KeReleaseSpinLock(&trans->range_lock, irql);
		dc_wait_for_pending_io(hook);
		dc_wipe_free(&hook->wp_ctx);
		dc_sync_cleanup(hook);
		dc_release_step_slot(hook);
		if (resl == ST_FINISHED) {
			DbgMsg("dc_transcrypt_init: finished\n");
			return ST_OK;
		}
		DbgMsg("dc_transcrypt_init: failed, code %d\n", resl);
		return resl;
	}

	DbgMsg("dc_transcrypt_init: success\n");
	/* session ready: steps may run now */
	dc_release_step_slot(hook);
	return ST_OK;
}

/*
 * Bad-sector handling of dc_transcrypt_step.
 *  - a block whose read fails is not written: the boundary stays and the next step re-reads
 *    it after a growing delay (DC_RD_RETRIES tries); the block is still in its old state.
 *  - after the last try the failed pieces are read sector by sector; each sector that still
 *    fails reads back as zeros in the new state (never stale buffer contents or plaintext).
 *  - a failed write is retried from the same buffer (pieces, then sectors), never re-read
 *    and transformed again.
 *  - a read on a device that is no longer started, or a block of which nothing is readable
 *    while a probe read of the disk start fails too (an outage, not bad media), stops with
 *    ST_IO_ERROR without moving the boundary.
 *  - while hibernation / unmount waits (F_PREVENT_ENC) the salvage reads stop with
 *    ST_CANCEL, block untouched; the write retries skip their per-sector round.
 *  - the block is written in the transcryption direction; a write that stops early (medium
 *    removed or swapped, device gone, nothing writable) moves the boundary over the written
 *    part only.
 *  - a step that had to zero-fill or could not write sectors returns ST_RW_ERR (GUI and
 *    dccon report these steps when the operation ends).
 */
#define DC_BAD_UNIT        512   /* bad_map granularity: the XTS sector size */
#define DC_RD_RETRIES      3     /* steps that re-read a failing block before it is salvaged */
#define DC_WR_ROUNDS       3     /* write attempts of the failed pieces (the last per sector) */

static const u32 dc_rd_retry_delay[DC_RD_RETRIES] = { 250, 1000, 2000 }; /* ms */

/* marks exactly the units of [start, start + len) (byte offsets in the block) */
static void dc_bad_map_set(u32 *map, u32 start, u32 len)
{
	u32 i = start / DC_BAD_UNIT, n = (start + len + DC_BAD_UNIT - 1) / DC_BAD_UNIT;

	memset(map, 0, DC_BAD_MAP_BYTES);
	for (; i < n; i++) map[i / 32] |= 1u << (i % 32);
}

static void dc_bad_map_fill(u32 *map, u32 size)
{
	dc_bad_map_set(map, 0, size);
}

static __inline int dc_bad_map_test(const u32 *map, u32 i)
{
	return (map[i / 32] >> (i % 32)) & 1;
}

static u32 dc_bad_map_count(const u32 *map, u32 size)
{
	u32 n = (size + DC_BAD_UNIT - 1) / DC_BAD_UNIT, i, cnt = 0;

	for (i = 0; i < n; i++) cnt += dc_bad_map_test(map, i);
	return cnt;
}

/*
 * Transfers the `piece`-sized pieces (a multiple of DC_BAD_UNIT) of [offs, offs + size) that
 * contain a unit marked in map; a piece that transfers is unmarked. Returns ST_OK when
 * nothing is left marked, ST_RW_ERR when something is, or the error that ends the transfer
 * early (no media; ST_IO_ERROR: device no longer started; ST_CANCEL: read with F_PREVENT_ENC).
 */
static int dc_rw_marked(dev_hook *hook, u8 *buff, u32 size, u64 offs, int is_read, u32 *map, u32 piece,
	                    int reverse, u32 *ok_extent)
{
	u32 n_p = (size + piece - 1) / piece, k;
	u32 pos, len, u, first, n_u;
	int resl, left = 0;

	/* pieces in the transcryption direction (reverse = from the end of the block);
	 * *ok_extent: how far, counted from the side the transfer starts at, the last piece
	 * that transferred in this call reaches (0 if none) */
	if (ok_extent != NULL) *ok_extent = 0;

	for (k = 0; k < n_p; k++)
	{
		pos   = (reverse ? n_p - 1 - k : k) * piece;
		len   = min(size - pos, piece);
		first = pos / DC_BAD_UNIT;
		n_u   = (len + DC_BAD_UNIT - 1) / DC_BAD_UNIT;

		for (u = 0; u < n_u && dc_bad_map_test(map, first + u) == 0; u++);
		if (u == n_u) continue; /* nothing marked in this piece */

		/* hibernation / unmount wait for the slot without a limit: salvage reads stop at once
		 * (nothing is written yet). Writes cannot stop - the block is half written. */
		if (is_read && (hook->flags & F_PREVENT_ENC)) {
			return ST_CANCEL;
		}
		resl = io_hook_rw(hook, buff + pos, len, offs + pos, is_read);

		if (resl == ST_OK) {
			for (u = 0; u < n_u; u++) map[(first + u) / 32] &= ~(1u << ((first + u) % 32));
			if (ok_extent != NULL) *ok_extent = reverse ? size - pos : pos + len;
		} else if (resl == ST_RW_ERR && hook->pnp_state == Started) {
			left = 1;
		} else {
			/* stopped early; a device that is no longer started is not a bad sector */
			return (resl == ST_RW_ERR) ? ST_IO_ERROR : resl;
		}
	}
	return left ? ST_RW_ERR : ST_OK;
}

/* Makes each marked unit read back as zeros in the new state; returns the unit count. */
static u32 dc_zero_marked(dev_hook *hook, u8 *buff, u32 size, u64 offs, const u32 *map, BOOLEAN encrypted)
{
	u32 n = (size + DC_BAD_UNIT - 1) / DC_BAD_UNIT, i, run, cnt = 0;

	for (i = 0; i < n; i += run)
	{
		if (dc_bad_map_test(map, i) == 0) { run = 1; continue; }

		for (run = 1; i + run < n && dc_bad_map_test(map, i + run); run++);

		memset(buff + i * DC_BAD_UNIT, 0, run * DC_BAD_UNIT);
		if (encrypted) {
			cp_fast_encrypt(buff + i * DC_BAD_UNIT, buff + i * DC_BAD_UNIT, run * DC_BAD_UNIT,
				offs + (u64)i * DC_BAD_UNIT, hook->dsk_key);
		}
		cnt += run;
	}
	return cnt;
}

/*
 * Power-loss protected (journaled) transcryption - the step side. See safe_log.c.
 */
#define SL_SKIP_MAX     (256 * 1024 * 1024) /* longest skip run per step */
#define SL_NOT_SKIPPED  (-1)                /* dc_safe_skip*: nothing skipped, transform the block */

/* free length of [rs, re) from its start (backward: from its end), in ENC_BLOCK_SIZE pieces as the
 * step would process them; stops at the first allocated piece. Caller holds range_lock. */
static u64 dc_safe_free_len(dev_hook *hook, u64 rs, u64 re, BOOLEAN backward)
{
	u64 len = 0;

	while (len < re - rs) {
		u32 sz = (u32)min(re - rs - len, (u64)ENC_BLOCK_SIZE);
		u64 o  = backward ? re - len - sz : rs + len;

		if (dc_bitmap_is_allocated(hook, o, sz)) break;
		len += sz;
	}
	return len;
}

/*
 * Write a record (retried like the in-place writes). On a persistent failure the record
 * may still have reached the disk (a failed request is undetermined) - and a durable record would
 * make the recovery apply it after user writes reached the range. So its sector is invalidated;
 * *unknown = 1 when that fails too: the caller quarantines the range (SL_PEND_UNKNOWN).
 */
static int dc_safe_record(dev_hook *hook, dc_slog *s, u32 type, u32 dir, u64 offs, u32 size,
	                      const void *data, u64 tmp_before, int *unknown)
{
	int i, resl;

	*unknown = 0;
	for (i = 0; ; i++) {
		if ( (resl = dc_slog_write_record(hook, s, type, dir, offs, size, data, tmp_before)) == ST_OK ) {
			return ST_OK;
		}
		if (resl == ST_MEDIA_CHANGED || resl == ST_NO_MEDIA || hook->pnp_state != Started || i + 1 >= DC_RD_RETRIES) {
			break;
		}
		dc_delay(dc_rd_retry_delay[i]);
	}
	DbgMsg("dc_safe_record: record %I64u (type %u at %I64x+%u) not written (%d), dev=%ws\n",
		s->seq + 1, type, offs, size, resl, hook->dev_name);

	if (resl == ST_MEDIA_CHANGED || resl == ST_NO_MEDIA || dc_slog_invalidate(hook, s, s->seq + 1) != ST_OK) {
		*unknown = 1;
	}
	return resl;
}

/* commit a block: write its commit sector, or when that is not writable, a header save that
 * claims the block (the pending record then no longer matches the header, which is exact). The
 * block is durable in place (flushed) when this is called. */
static BOOLEAN dc_safe_commit(dev_hook *hook, dc_slog *s, u64 seq, u32 dir, u64 offs, u32 size)
{
	u64 end;

	if (dc_slog_commit(hook, s, seq) == ST_OK) {
		return TRUE;
	}
	end = dc_slog_rec_end(dir, offs, size);
	DbgMsg("dc_safe_commit: commit %I64u not written, committing by a header save at %I64x, dev=%ws\n", seq, end, hook->dev_name);
	if (dc_save_state_int(hook, SYNC_STEP_UPDATE, &end) != ST_OK) {
		return FALSE;
	}
	/* the backup header too - else a backup mount would still take the record as pending and
	 * write its post-image over user writes made after the boundary moved */
	return s->hdr_ok == end && (!(hook->flags & F_HEAD_BACKUP) || s->bak_ok == end);
}

/* quarantine a pending block / run. Caller holds range_lock, the range is still locked (the
 * step's active range), so no request touches it between the lock and the quarantine. */
static void dc_safe_quarantine(dc_slog *s, int kind, u32 type, u64 seq, u64 offs, u32 size, u32 dir, u32 crc)
{
	s->pend      = kind;
	s->pend_type = type;
	s->pend_seq  = seq;
	s->pend_offs = offs;
	s->pend_size = size;
	s->pend_dir  = dir;
	s->pend_crc  = crc;
	s->q_start   = offs;
	s->q_end     = offs + size;
	if (s->quar == 0) {
		s->quar = 1;
		InterlockedIncrement(&dc_slog_quar_cnt);
	}
}

/* the pending block is complete (publish: the boundary moves over it) or released (the record is
 * invalidated, the boundary stays); I/O to the range is accepted again */
static void dc_safe_release(dev_hook *hook, dc_slog *s, BOOLEAN publish)
{
	KIRQL irql;

	KeAcquireSpinLock(&hook->trans.range_lock, &irql);
	if (publish) {
		hook->tmp_size = dc_slog_rec_end(s->pend_dir, s->pend_offs, s->pend_size);
	}
	if (s->quar) {
		s->quar = 0;
		InterlockedDecrement(&dc_slog_quar_cnt);
	}
	s->pend = 0;
	KeReleaseSpinLock(&hook->trans.range_lock, irql);
}

/*
 * FF_SAFE_FAST: complete the pending block unit by unit from what the disk holds and the record's
 * checksums (slot held, the data keys installed): a unit whose checksum matches is written; one
 * that matches after it is transformed as the step did is still the old content (transformed);
 * one that matches neither was torn by the power loss (or cannot be read): zeros in the new
 * state, as an unreadable sector, counted in *lost. The block is written in place, flushed.
 */
static int dc_safe_complete_sums(dev_hook *hook, dc_slog *s, u8 *buff, u32 *lost, BOOLEAN salvage)
{
	u64    *sums  = DC_STEP_SUMS(hook);
	u32    *map   = DC_STEP_BAD_MAP(hook);
	u32     size  = s->pend_size, n = size / SL_SUM_UNIT, i;
	u64     offs  = s->pend_offs;
	u64     xo    = offs - ((hook->flags & F_NO_REDIRECT) ? hook->head_len : 0); /* XTS offset, as the step */
	BOOLEAN enc   = (s->pend_dir != LR_DEC); /* the new state is encrypted */
	u32     piece = max(hook->bps, 4096);
	u32     sec   = (hook->bps >= DC_BAD_UNIT && piece % hook->bps == 0) ? hook->bps : piece;
	int     resl;

	*lost = 0;
	if (buff == NULL || size == 0 || size > ENC_BLOCK_SIZE || (size % SL_SUM_UNIT) != 0 || hook->dsk_key == NULL ||
		(s->pend_dir == LR_REENC && hook->tmp_key == NULL)) {
		return ST_INVALID_PARAM;
	}
	if ( (resl = dc_slog_read_sums(hook, s, sums)) != ST_OK ) {
		return resl;
	}

	/* the block as the disk holds it. A read error is never taken for torn units at once: without
	 * salvage (the mount) the block stays pending; with it (a step) it is re-read with the step's
	 * delays, then piece by piece - nothing readable while the disk start is unreadable too is an
	 * outage, not loss */
	memset(map, 0, DC_BAD_MAP_BYTES);
	resl = io_hook_rw(hook, buff, size, offs, 1);
	if (resl == ST_RW_ERR) {
		int t;

		if (hook->pnp_state != Started) return ST_IO_ERROR;
		if (!salvage) return ST_RW_ERR;
		for (t = 0; t < DC_RD_RETRIES && resl == ST_RW_ERR && hook->pnp_state == Started && !(hook->flags & F_PREVENT_ENC); t++) {
			dc_delay(dc_rd_retry_delay[t]);
			resl = io_hook_rw(hook, buff, size, offs, 1);
		}
	}
	if (resl == ST_RW_ERR) {
		if (hook->pnp_state != Started || (hook->flags & F_PREVENT_ENC)) return ST_IO_ERROR;
		dc_bad_map_fill(map, size);
		resl = dc_rw_marked(hook, buff, size, offs, 1, map, piece, 0, NULL);
		if (resl == ST_RW_ERR && sec < piece) {
			resl = dc_rw_marked(hook, buff, size, offs, 1, map, sec, 0, NULL);
		}
		if (resl == ST_RW_ERR && hook->pnp_state == Started) {
			if (dc_bad_map_count(map, size) >= n && io_hook_rw(hook, buff, min(sec, size), 0, 1) != ST_OK) {
				DbgMsg("dc_safe_complete_sums: block %I64x and the disk start unreadable, left pending, dev=%ws\n", offs, hook->dev_name);
				return ST_IO_ERROR;
			}
			resl = ST_OK; /* what is still marked: bad sectors, lost */
		}
	}
	if (resl != ST_OK) {
		return resl;
	}

	for (i = 0; i < n; i++)
	{
		u8 *u  = buff + (size_t)i * SL_SUM_UNIT;
		u64 uo = xo + (u64)i * SL_SUM_UNIT;

		if (dc_bad_map_test(map, i) == 0) {
			if (dc_slog_sum64(u) == sums[i]) continue; /* written */
			/* not written yet: the old content, transformed as the step did */
			if (s->pend_dir == LR_REENC) {
				cp_fast_decrypt(u, u, SL_SUM_UNIT, uo, hook->tmp_key);
				cp_fast_encrypt(u, u, SL_SUM_UNIT, uo, hook->dsk_key);
			} else if (s->pend_dir == LR_ENC) {
				cp_fast_encrypt(u, u, SL_SUM_UNIT, uo, hook->dsk_key);
			} else {
				cp_fast_decrypt(u, u, SL_SUM_UNIT, uo, hook->dsk_key);
			}
			if (dc_slog_sum64(u) == sums[i]) continue;
		}
		/* torn by the power loss, or unreadable: zeros in the new state */
		memset(u, 0, SL_SUM_UNIT);
		if (enc) cp_fast_encrypt(u, u, SL_SUM_UNIT, uo, hook->dsk_key);
		(*lost)++;
	}
	if (*lost != 0) {
		DbgMsg("dc_safe_complete_sums: block %I64x+%u: %u units torn or unreadable, set to zeros, dev=%ws\n",
			offs, size, *lost, hook->dev_name);
	}
	return dc_slog_write_in_place(hook, buff, size, offs);
}

/*
 * Complete a pending block at the next step (slot held). SL_PEND_WRITTEN: the post-image from the
 * journal (crc checked) is written in place again, flushed, committed; SL_PEND_UNKNOWN: the record
 * sector is invalidated, the block is transformed normally by the next step. ST_OK, or
 * ST_LOG_PENDING while the disk still refuses.
 */
static int dc_safe_resolve(dev_hook *hook, dc_slog *s, u8 *buff, BOOLEAN salvage)
{
	u32 lost = 0;
	int resl;

	if (s->pend == SL_PEND_UNKNOWN) {
		if ( (resl = dc_slog_invalidate(hook, s, s->pend_seq)) == ST_OK ) {
			dc_safe_release(hook, s, FALSE);
		}
	} else {
		if ( (s->pend_type == LR_SUM) ?
			 ((resl = dc_safe_complete_sums(hook, s, buff, &lost, salvage)) == ST_OK) :
			 ((resl = dc_slog_read_post_image(hook, s, buff)) == ST_OK &&
			  (resl = dc_slog_write_in_place(hook, buff, s->pend_size, s->pend_offs)) == ST_OK) )
		{
			if (dc_safe_commit(hook, s, s->pend_seq, s->pend_dir, s->pend_offs, s->pend_size)) {
				dc_safe_release(hook, s, TRUE);
			} else {
				resl = ST_IO_ERROR;
			}
		}
	}
	DbgMsg("dc_safe_resolve: pending %s %I64x+%u: %d, dev=%ws\n", (s->pend == SL_PEND_UNKNOWN) ? "record" : "block",
		s->pend_offs, s->pend_size, resl, hook->dev_name);

	if (resl == ST_OK) return (lost != 0) ? ST_RW_ERR : ST_OK; /* ST_RW_ERR: reported like unreadable sectors */
	return (resl == ST_MEDIA_CHANGED || resl == ST_NO_MEDIA) ? resl : ST_LOG_PENDING;
}

/* FF_SAFE_FAST: a pending block the journal recovery left at the mount (it needs the data keys)
 * - completed right after the session install, step slot held by the caller. A read-only mount
 * leaves it to the first step, as the recovery of a full journal does. */
int dc_safe_resolve_pending(dev_hook *hook)
{
	dc_slog *s = dc_slog_get(hook);

	if (s == NULL || s->pend == 0 || hook->tmp_buff == NULL || (hook->flags & F_SYNC) == 0) return ST_OK;
	if (hook->mnt_flags & MF_READ_ONLY) return ST_OK;
	if (dc_safe_resolve(hook, s, p8(hook->tmp_buff), FALSE) == ST_RW_ERR) {
		s->lost_rep = 1; /* reported by the next step */
	}
	return ST_OK;
}

/* FF_SAFE_FAST: complete a pending block of the journal recovery while the session is being
 * installed (S_CONTINUE_*), before F_ENABLED | F_SYNC are published - no I/O meets its
 * quarantine. Keys and tmp_buff are set up, the step slot is held. Only when the block reads
 * completely and its commit is written; otherwise it stays pending for
 * dc_safe_resolve_pending / the first step. */
static void dc_safe_complete_early(dev_hook *hook)
{
	dc_slog *s = dc_slog_get(hook);
	u32      lost = 0;

	if (s == NULL || s->pend != SL_PEND_WRITTEN || s->pend_type != LR_SUM || hook->tmp_buff == NULL ||
		(hook->mnt_flags & MF_READ_ONLY)) {
		return;
	}
	if (dc_safe_complete_sums(hook, s, p8(hook->tmp_buff), &lost, FALSE) == ST_OK &&
		dc_slog_commit(hook, s, s->pend_seq) == ST_OK)
	{
		DbgMsg("dc_safe_complete_early: pending block %I64x+%u completed (%u units lost), dev=%ws\n",
			s->pend_offs, s->pend_size, lost, hook->dev_name);
		dc_safe_release(hook, s, TRUE);
		if (lost != 0) s->lost_rep = 1;
	}
}

/*
 * Pass [rs, re) without a write - free space (bitmap: tested again under the range lock and
 * cut at the first block that became allocated) or the journal itself. The range lock replaces
 * the range_lock section of the unprotected skip: a disk write must not happen under a spinlock.
 */
static int dc_safe_skip(dev_hook *hook, dc_slog *s, BOOLEAN is_decrypt, BOOLEAN is_reencrypt, u64 rs, u64 re, BOOLEAN bitmap)
{
	transcrypt_state *trans = &hook->trans;
	u32               dir   = dc_slog_dir(is_decrypt, is_reencrypt);
	u64               bnd   = is_decrypt ? re : rs; /* the boundary the run starts at */
	int               resl, unknown = 0;
	KIRQL             irql;

	/* user writes into the run wait from here; those admitted before are drained and have
	 * marked the bitmap (admission marks it under range_lock) */
	dc_lock_disk_range(hook, rs, re);

	if (bitmap) {
		BOOLEAN gone;
		u64     len = 0;

		/* re-test the bitmap under the range lock */
		KeAcquireSpinLock(&trans->range_lock, &irql);
		gone = (hook->flags & F_SYNC) == 0; /* cleanup started; the bitmap may be going away */
		if (!gone) len = dc_safe_free_len(hook, rs, re, is_decrypt);
		KeReleaseSpinLock(&trans->range_lock, irql);

		if (gone || len == 0) {
			dc_unlock_disk_range(hook);
			return gone ? ST_ERROR : SL_NOT_SKIPPED;
		}
		if (is_decrypt) rs = re - len; else re = rs + len;
	}

	/* the record (the commit of a run) */
	resl = dc_safe_record(hook, s, LR_SKIP, dir, rs, (u32)(re - rs), NULL, bnd, &unknown);

	/* publish and unlock in one range_lock section */
	KeAcquireSpinLock(&trans->range_lock, &irql);
	if (resl == ST_OK) {
		hook->tmp_size = is_decrypt ? rs : re;
	} else if (unknown) {
		dc_safe_quarantine(s, SL_PEND_UNKNOWN, LR_SKIP, s->seq + 1, rs, (u32)(re - rs), dir, 0);
	}
	trans->active_start = -1;
	trans->active_end   = 0;
	KeSetEvent(&trans->block_complete, IO_NO_INCREMENT, FALSE);
	KeReleaseSpinLock(&trans->range_lock, irql);

	if (resl == ST_OK) return ST_OK;
	if (resl == ST_MEDIA_CHANGED || resl == ST_NO_MEDIA) return resl;
	return unknown ? ST_LOG_PENDING : ST_IO_ERROR;
}

/* a run of unallocated blocks from the boundary bnd in the direction of travel, up to
 * SL_SKIP_MAX, never into the journal */
static int dc_safe_skip_unused(dev_hook *hook, dc_slog *s, BOOLEAN is_decrypt, BOOLEAN is_reencrypt,
	                           u64 bnd, u64 data_start, u64 data_end)
{
	u64     l0 = s->log_off, l1 = s->log_off + s->log_len;
	u64     rs, re, len = 0;
	BOOLEAN gone;
	KIRQL   irql;

	if (!is_decrypt) {
		re = data_end;
		if (l0 >= bnd && l0 < re) re = l0;
		if (re - bnd > SL_SKIP_MAX) re = bnd + SL_SKIP_MAX;
		rs = bnd;
	} else {
		rs = data_start;
		if (l1 <= bnd && l1 > rs) rs = l1;
		if (bnd - rs > SL_SKIP_MAX) rs = bnd - SL_SKIP_MAX;
		re = bnd;
	}
	if (re <= rs) return SL_NOT_SKIPPED;

	/* a hint only: tested again under the range lock (dc_safe_skip) */
	KeAcquireSpinLock(&hook->trans.range_lock, &irql);
	gone = (hook->flags & F_SYNC) == 0;
	if (!gone) len = dc_safe_free_len(hook, rs, re, is_decrypt);
	KeReleaseSpinLock(&hook->trans.range_lock, irql);

	if (gone) return ST_ERROR;
	if (len == 0) return SL_NOT_SKIPPED;
	if (is_decrypt) rs = re - len; else re = rs + len;

	return dc_safe_skip(hook, s, is_decrypt, is_reencrypt, rs, re, TRUE);
}

int dc_transcrypt_step(dev_hook *hook, BOOLEAN is_decrypt)
{
	transcrypt_state *trans = &hook->trans;
	u8   *buff;   /* read only after in_progress is held and F_SYNC re-checked */
	u64   offs, size, remaining;
	u64   data_start, data_end;
	u64   xts_offs;
	int   resl;
	KIRQL irql;
	BOOLEAN is_encrypt, is_reencrypt;
	u32   adv_len = 0;        /* bytes of the block the boundary moves over */
	u32   n_rd_bad = 0, n_wr_bad = 0, retry_delay = 0;
	u32   piece, sec, cpiece;
	u32   blk;                 /* the block size of this step */
	u32  *bad_map;             /* of this block, DC_STEP_BAD_MAP */
	u32   flags = hook->flags;
	dc_slog *slog = NULL;         /* power-loss protected session */
	BOOLEAN  rec_written = FALSE;  /* record written: the block is pending until its commit */
	int      quar_kind = 0;        /* quarantine this block at the end */
	u64      quar_seq = 0;
	u32      q_crc = 0;

	if (!(flags & F_SYNC)) {
		/* locked at hibernation - the unlock re-initialises the session; ST_CANCEL makes the
		 * caller retry. The lock sets F_HIBER_ERASE before its cleanup clears F_SYNC (both
		 * interlocked), so one snapshot of the word is enough. */
		return (flags & F_HIBER_ERASE) ? ST_CANCEL : ST_ERROR;
	}
	/* mounted with a damaged header (MF_IGNORE_CRC, read-only): its boundary may be wrong and
	 * no state save would record a step - nothing is transcrypted */
	if (hook->mnt_flags & MF_IGNORE_CRC) {
		return ST_ACCESS_DENIED;
	}

	{
		/* short holders of the slot (a state save, a handle close, a resize) are waited for up
		 * to 5 s, so the step loop does not fail because of them. Interrupt time: a clock
		 * change must not stretch the deadline. */
		ULONGLONG deadline = KeQueryInterruptTime() + 50000000ULL; /* 5 s */

		/* let a waiting slot acquirer (dc_acquire_step_slot, holding busy_lock) in first;
		 * a tight step loop would starve it */
		while (InterlockedCompareExchange(&trans->slot_waiters, 0, 0) != 0) {
			if (KeQueryInterruptTime() >= deadline) {
				return ST_ERROR;
			}
			dc_delay(1);
		}

		/* clear idle_event BEFORE the exchange (slot protocol, see dc_acquire_step_slot) */
		KeClearEvent(&trans->idle_event);

		/* one step at a time; wait for a short holder as above */
		if (InterlockedCompareExchange(&trans->in_progress, 1, 0) != 0) {
			LARGE_INTEGER wait;
			ULONGLONG     now;

			for (;;) {
				now = KeQueryInterruptTime();
				if (now >= deadline) {
					return ST_ERROR;
				}
				wait.QuadPart = -(LONGLONG)(deadline - now); /* relative */
				if (KeWaitForSingleObject(&trans->idle_event, Executive, KernelMode, FALSE, &wait) == STATUS_TIMEOUT) {
					return ST_ERROR;
				}
				KeClearEvent(&trans->idle_event);
				if (InterlockedCompareExchange(&trans->in_progress, 1, 0) == 0) {
					break;
				}
			}
		}
	}

	/* Check stop flag after marking in_progress.
	 * Power management sets F_PREVENT_ENC before hibernate/unmount.
	 * We must check AFTER setting in_progress to close the race window. */
	if (hook->flags & F_PREVENT_ENC) {
		dc_release_step_slot(hook);
		return ST_CANCEL;
	}

	/* Decryption already finished (F_PLAIN_IO): a further step would work on a plaintext
	 * volume. F_PLAIN_IO is set by the slot holder, so checking after the exchange is ordered. */
	if (hook->flags & F_PLAIN_IO) {
		DbgMsg("dc_transcrypt_step: decryption already finished, step rejected, dev=%ws\n", hook->dev_name);
		dc_release_step_slot(hook);
		return ST_ERROR;
	}

	/* re-check F_SYNC now that in_progress is held: the session may have been torn down since
	 * the test at the top (cleanup clears F_SYNC before freeing tmp_buff and the keys) */
	if (!(hook->flags & F_SYNC)) {
		dc_release_step_slot(hook);
		return ST_ERROR;
	}
	buff = hook->tmp_buff;

	/* the direction comes from the IOCTL (DC_CTL_ENCRYPT_STEP / DC_CTL_DECRYPT_STEP), not from
	 * stored state (a paused encryption can be reversed) */
	is_encrypt = !is_decrypt;
	is_reencrypt = (hook->flags & F_REENCRYPT) != 0;

	/* Re-encryption only runs forward: a decrypt step would apply the old->new transform to
	 * blocks already under the new key */
	if (is_decrypt && is_reencrypt) {
		DbgMsg("dc_transcrypt_step: decrypt step rejected during re-encryption, dev=%ws\n", hook->dev_name);
		dc_release_step_slot(hook);
		return ST_INVALID_PARAM;
	}

	/* a block the journal holds but the disk did not take is completed (or released) before
	 * anything else - never read and transformed again */
	slog = dc_slog_get(hook);
	if (slog != NULL && slog->lost_rep) {
		/* FF_SAFE_FAST: units of a block completed at the mount were torn (zeros) - reported like
		 * unreadable sectors (GUI / dccon count the step), once */
		slog->lost_rep = 0;
		dc_release_step_slot(hook);
		return ST_RW_ERR;
	}
	if (slog != NULL && slog->pend) {
		resl = dc_safe_resolve(hook, slog, buff, TRUE);
		dc_release_step_slot(hook);
		return resl;
	}
	/* read-only mount with an unreadable journal - the session cannot continue */
	if (slog != NULL && slog->dead) {
		dc_release_step_slot(hook);
		return ST_LOG_PENDING;
	}
	/* after a mount the records must bind to headers on the disk - first a save that
	 * writes every header (and empties the journal), else no record is written */
	if (slog != NULL && slog->need_hdr) {
		dc_save_state_int(hook, SYNC_STEP_UPDATE, NULL);
		if (slog->need_hdr) {
			DbgMsg("dc_transcrypt_step: headers not written after the mount, step refused, dev=%ws\n", hook->dev_name);
			dc_release_step_slot(hook);
			return ST_IO_ERROR;
		}
	}

	/* Lazy init bitmap for SSD skip optimization.
	 * Done here (not at mount) to avoid memory waste when paused. */
	if (hook->crypt.wp_mode == WP_SKIP_UNUSED && hook->alloc_bitmap == NULL) {
		dc_bitmap_start_init(hook);
	}

	/* the block: a protected session journals it as one record - a journal with a smaller data
	 * area (the small fallback of dc_slog_create) limits it */
	blk = (slog == NULL) ? (u32)ENC_BLOCK_SIZE :
	      slog->fast ? min((u32)ENC_BLOCK_SIZE, slog->block_max / 8 * SL_SUM_UNIT) : min((u32)ENC_BLOCK_SIZE, slog->block_max);
	if (is_encrypt && hook->wp_ctx.mode != NULL) {
		blk = min(blk, (u32)DC_WIPE_BLOCK); /* wipe passes (the session's wipe mode is fixed) */
	}
	bad_map = DC_STEP_BAD_MAP(hook);

	/* data area: [head_len, dc_data_end) */
	data_start = hook->head_len;
	data_end = dc_data_end(hook); /* excludes the backup header */

	/* Get current position */
	offs = hook->tmp_size;

	/* Check if finished */
	if (is_encrypt) {
		/* a boundary below the data start would transcrypt the header area */
		if (offs < data_start) {
			DbgMsg("dc_transcrypt_step: boundary %I64x below the data start %I64x, refused, dev=%ws\n", offs, data_start, hook->dev_name);
			dc_release_step_slot(hook);
			return ST_INV_VOLUME;
		}
		/* Encryption/Re-encryption: process from data_start to data_end */
		if (offs >= data_end) {
			dc_release_step_slot(hook);
			return ST_FINISHED;
		}
		remaining = data_end - offs;
		size = min(remaining, blk);
	} else {
		/* Decryption: backwards from data_end to data_start, then dc_dec_finish restores
		 * the redirected partition begin/end. A boundary above the data end (live shrink, or
		 * an older header) starts at the data end - never decrypt the backup header / slack
		 * storage in place. */
		if (offs > data_end) {
			offs = data_end;
		}
		if (offs <= data_start) {
			/* Decryption finished - restore redirected data */
			resl = dc_dec_finish(hook);
			/* a raw I/O error of the restore is not a block with bad sectors: stop; the
			 * redirect stays active and a restart repeats the restore safely */
			if (resl == ST_RW_ERR) {
				resl = ST_IO_ERROR;
			}
			dc_release_step_slot(hook);
			return resl;
		}
		/* Don't decrypt below data_start */
		remaining = offs - data_start;
		size = min(remaining, blk);
		offs = offs - size;
	}

	/* power-loss protected session - the journal range, and skip-unused runs */
	if (slog != NULL)
	{
		u64 bnd = is_encrypt ? offs : offs + size; /* the boundary (clipped to the data end) */
		u64 l0 = slog->log_off, l1 = slog->log_off + slog->log_len;
		u64 rs = 0, re = 0;

		/* the journal is written raw and never transformed: passed with an LR_SKIP record; a
		 * block that would reach into it ends at its edge */
		if (is_encrypt) {
			if (bnd >= l0 && bnd < l1) { rs = bnd; re = min(l1, data_end); }
			else if (bnd < l0 && offs + size > l0) { size = l0 - offs; }
		} else {
			if (bnd > l0 && bnd <= l1) { rs = max(l0, data_start); re = bnd; }
			else if (bnd > l1 && offs < l1) { offs = l1; size = bnd - l1; }
		}
		if (re > rs) {
			resl = dc_safe_skip(hook, slog, is_decrypt, is_reencrypt, rs, re, FALSE);
			dc_release_step_slot(hook);
			return resl;
		}
		if (!(hook->flags & F_NO_REDIRECT) && DC_BITMAP_IS_VALID(hook->alloc_bitmap)) {
			resl = dc_safe_skip_unused(hook, slog, is_decrypt, is_reencrypt, bnd, data_start, data_end);
			if (resl != SL_NOT_SKIPPED) {
				dc_release_step_slot(hook);
				return resl;
			}
		}
	}

	/* Bitmap skip of an unallocated block. The test and the boundary advance are ONE
	 * range_lock section - write admission marks the bitmap and snapshots tmp_size under the
	 * same lock, so an admitted in-flight write to a free cluster is never skipped over. Not
	 * on F_NO_REDIRECT volumes: there tmp_size/offs are disk offsets, the bitmap is not. */
	if (slog == NULL && !(hook->flags & F_NO_REDIRECT) && DC_BITMAP_IS_VALID(hook->alloc_bitmap)) {
		BOOLEAN skip = FALSE;
		BOOLEAN sync_gone = FALSE;

		KeAcquireSpinLock(&trans->range_lock, &irql);
		if (!(hook->flags & F_SYNC)) {
			sync_gone = TRUE;   /* cleanup started; the bitmap may be going away */
		} else if (!dc_bitmap_is_allocated(hook, offs, (u32)size)) {
			/* Block is unallocated and no admitted write touches it - skip it */
			skip = TRUE;
			if (is_encrypt) {
				hook->tmp_size = offs + size;
			} else {
				hook->tmp_size = offs;
			}
		}
		KeReleaseSpinLock(&trans->range_lock, irql);

		if (skip || sync_gone) {
			dc_release_step_slot(hook);
			return skip ? ST_OK : ST_ERROR;
		}
		/* allocated: a write admitted before this point is counted in pending_io_count
		 * and dc_lock_disk_range below waits for it before the block is read */
	}

	/* Wait for all pending I/O to complete and lock the active block range.
	 * This ensures no I/O is using a stale tmp_size snapshot.
	 * Each I/O increments pending_io_count when it starts and decrements when done. */
	dc_lock_disk_range(hook, offs, offs + size);

	/* retry / salvage granularity - 4 KiB pieces (or the sector, when larger), then
	 * single sectors */
	piece = max(hook->bps, 4096);
	sec   = (hook->bps >= DC_BAD_UNIT && piece % hook->bps == 0) ? hook->bps : piece;
	/* the 8 MiB block fails as a whole: first find the failing requests of the device's transfer
	 * size, then only these go in 4 KiB pieces */
	cpiece = max(piece, hook->max_chunk - hook->max_chunk % piece);

	/* Read data */
	resl = io_hook_rw(hook, buff, (u32)size, offs, 1);
	if (resl == ST_RW_ERR) {
		dc_bad_map_fill(bad_map, (u32)size);
		resl = dc_rw_marked(hook, buff, (u32)size, offs, 1, bad_map, cpiece, 0, NULL);
		if (resl == ST_RW_ERR && cpiece > piece) {
			resl = dc_rw_marked(hook, buff, (u32)size, offs, 1, bad_map, piece, 0, NULL);
		}
	}
	if (resl == ST_RW_ERR)
	{
		if (hook->pnp_state != Started) {
			/* device removed: stop, do not move the boundary over it */
			DbgMsg("dc_transcrypt_step: read failed, device not started, dev=%ws\n", hook->dev_name);
			trans->rd_retry_cnt = 0;
			resl = ST_IO_ERROR;
			goto finish_block;
		}
		if (trans->rd_retry_cnt == 0 || trans->rd_retry_offs != offs) {
			trans->rd_retry_offs = offs;
			trans->rd_retry_cnt  = 0;
		}
		if (trans->rd_retry_cnt < DC_RD_RETRIES) {
			/* nothing written: leave the block as it is and read it again in the next step */
			retry_delay = dc_rd_retry_delay[trans->rd_retry_cnt++];
			DbgMsg("dc_transcrypt_step: read error at %I64x, retry %u in %u ms, dev=%ws\n",
				offs, trans->rd_retry_cnt, retry_delay, hook->dev_name);
			resl = ST_OK;
			goto finish_block;
		}
		/* last try: the failed pieces sector by sector, then give up on what is left */
		if (sec < piece) {
			resl = dc_rw_marked(hook, buff, (u32)size, offs, 1, bad_map, sec, 0, NULL);
		}
		if (resl == ST_RW_ERR && hook->pnp_state != Started) {
			trans->rd_retry_cnt = 0;
			resl = ST_IO_ERROR;
			goto finish_block;
		}
		if (resl == ST_RW_ERR) {
			n_rd_bad = dc_bad_map_count(bad_map, (u32)size);
			resl = ST_OK;
			/* nothing of the block readable: may be a device outage PnP has not reported, not
			 * bad sectors (zero-filling would sweep the disk). Probe the disk's first sector
			 * (lands in the first unit of buff, zero-filled below anyway) and stop only when
			 * that fails too, so a large bad area does not block the operation for good. */
			if (n_rd_bad >= ((u32)size + DC_BAD_UNIT - 1) / DC_BAD_UNIT &&
				io_hook_rw(hook, buff, min(sec, (u32)size), 0, 1) != ST_OK)
			{
				DbgMsg("dc_transcrypt_step: block at %I64x and the disk start unreadable, stopping, dev=%ws\n",
					offs, hook->dev_name);
				trans->rd_retry_cnt = 0;
				resl = ST_IO_ERROR;
			}
		}
	}
	if (resl != ST_OK) {
		/* a salvage cut short by hibernation (ST_CANCEL) or a device that stopped
		 * (ST_IO_ERROR) gets the full delayed re-reads again when it resumes */
		if (resl == ST_CANCEL || resl == ST_IO_ERROR) {
			trans->rd_retry_cnt = 0;
		}
		goto finish_block;
	}
	trans->rd_retry_cnt = 0;

	/* XTS offset of the block: on F_NO_REDIRECT volumes tmp_size / offs are disk offsets, but
	 * the data is encrypted from head_len, like readwrite.c does (defensive: sessions are
	 * refused on such volumes). Disk I/O and the wipe keep using offs. */
	xts_offs = offs - ((hook->flags & F_NO_REDIRECT) ? hook->head_len : 0);

	/* Encrypt/Decrypt/Re-encrypt (the wipe passes follow below: they work in place with their own
	 * buffer, after the journal record) */
	if (is_reencrypt) {
		cp_fast_decrypt(buff, buff, (u32)size, xts_offs, hook->tmp_key);
		cp_fast_encrypt(buff, buff, (u32)size, xts_offs, hook->dsk_key);
	} else if (is_encrypt) {
		cp_fast_encrypt(buff, buff, (u32)size, xts_offs, hook->dsk_key);
	} else {
		cp_fast_decrypt(buff, buff, (u32)size, xts_offs, hook->dsk_key);
	}

	/* the sectors that could not be read read back as zeros in the new state */
	if (n_rd_bad != 0) {
		dc_zero_marked(hook, buff, (u32)size, xts_offs, bad_map, is_encrypt);
		DbgMsg("dc_transcrypt_step: %u unreadable sectors at %I64x set to zeros, dev=%ws\n",
			n_rd_bad, offs, hook->dev_name);
	}

	/* the post-image (buff) and its record are durable before anything is written in
	 * place, the wipe passes included */
	if (slog != NULL) {
		int unknown;

		const void *rdata = buff;

		/* FF_SAFE_FAST: a checksum of each 512-byte unit of the post-image, not the post-image */
		if (slog->fast) {
			u64 *sums = DC_STEP_SUMS(hook);
			u32  used = ((u32)size / SL_SUM_UNIT) * 8;

			dc_slog_sums(buff, (u32)size, sums);
			memset(p8(sums) + used, 0, dc_slog_data_len(slog, LR_SUM, (u32)size) - used);
			rdata = sums;
		}
		resl = dc_safe_record(hook, slog, slog->fast ? LR_SUM : LR_STEP, dc_slog_dir(is_decrypt, is_reencrypt), offs, (u32)size, rdata,
			is_encrypt ? offs : offs + size, &unknown);
		if (resl != ST_OK) {
			if (unknown) {
				quar_kind = SL_PEND_UNKNOWN;
				quar_seq  = slog->seq + 1;
			}
			if (resl != ST_MEDIA_CHANGED && resl != ST_NO_MEDIA) {
				resl = unknown ? ST_LOG_PENDING : ST_IO_ERROR;
			}
			adv_len = 0;
			goto finish_block; /* nothing written in place, the boundary stays */
		}
		rec_written = TRUE;
	}

	/* wipe passes over the old data (encryption / re-encryption); never after a checksum record -
	 * its recovery needs the old content (a fast session is never started with wiping) */
	if (is_encrypt && (slog == NULL || !slog->fast)) {
		dc_wipe_process(&hook->wp_ctx, offs, (int)size);
	}

	/* Write data. A failed write is retried from this buffer only (never re-read and
	 * transformed again). Written in the transcryption direction (decryption: from the block
	 * end), so the written part is contiguous at the processed side of the boundary; when the
	 * write stops early the boundary moves over exactly the written part (adv_len). */
	{
		u32 w_done = 0, ok_ext = 0, before = 0;
		int round, completed = 0;

		/* one request for the block, except without a journal on a removable device: a write
		 * that fails there (e.g. VERIFY_REQUIRED after a USB reset) leaves the session running,
		 * so the boundary may only move over what is known to be written - pieces in order.
		 * Elsewhere a failed request leaves w_done 0: the block is written again from buff
		 * below, or (journal) completed from its post-image. */
		if (slog == NULL && (hook->flags & F_REMOVABLE)) {
			resl = io_hook_rw_dir(hook, buff, (u32)size, offs, 0, is_decrypt, &w_done);
		} else {
			resl = io_hook_rw_dir(hook, buff, (u32)size, offs, 0, is_decrypt, NULL);
		}
		adv_len = (resl == ST_OK) ? (u32)size : w_done;

		if (resl == ST_RW_ERR && hook->pnp_state == Started)
		{
			/* the part after the written one: [w_done, size) forward, [0, size - w_done) reverse */
			dc_bad_map_set(bad_map, is_decrypt ? 0 : w_done, (u32)size - w_done);
			before = dc_bad_map_count(bad_map, (u32)size);

			for (round = 0; ; round++) {
				resl = dc_rw_marked(hook, buff, (u32)size, offs, 0, bad_map,
					(round == 0) ? cpiece : (round < DC_WR_ROUNDS - 1) ? piece : sec, is_decrypt, &ok_ext);
				if (ok_ext > adv_len) {
					adv_len = ok_ext; /* written up to here (failed pieces before it: bad sectors) */
				}
				if (resl == ST_OK || resl == ST_RW_ERR) {
					completed = 1; /* every piece was tried on a started device */
				}
				/* while hibernation / unmount waits for the slot, skip the expensive sector
				 * round (up to 16384 writes); the cheap piece retry still runs */
				if (resl != ST_RW_ERR || round == DC_WR_ROUNDS - 1 || hook->pnp_state != Started ||
					((hook->flags & F_PREVENT_ENC) && round + 1 == DC_WR_ROUNDS - 1)) {
					break;
				}
				dc_delay(250);
			}
			n_wr_bad = dc_bad_map_count(bad_map, (u32)size);

			if (resl == ST_OK) {
				adv_len = (u32)size;
			} else if (resl == ST_RW_ERR && completed) {
				/* every piece tried, some still fail. Bad sectors on a working device: pass
				 * the block (ST_RW_ERR reports it). But not when nothing of the rest could be
				 * written (read-only medium, outage) or the disk start cannot be read either
				 * (outage): stop after the written part. */
				if (n_wr_bad < before && io_hook_rw(hook, buff, min(sec, (u32)size), 0, 1) == ST_OK) {
					adv_len = (u32)size;
					DbgMsg("dc_transcrypt_step: %u sectors at %I64x could not be written, dev=%ws\n",
						n_wr_bad, offs, hook->dev_name);
				} else {
					DbgMsg("dc_transcrypt_step: write at %I64x failed, device not writable, stopping after %u bytes, dev=%ws\n",
						offs, adv_len, hook->dev_name);
					resl = ST_IO_ERROR;
				}
			}
			/* else stopped early (no media, media changed, device gone): adv_len as reached */
		}
		else if (resl == ST_RW_ERR)
		{
			resl = ST_IO_ERROR; /* device no longer started */
		}
		if (adv_len > size) {
			adv_len = (u32)size;
		}
		if (adv_len < size) {
			DbgMsg("dc_transcrypt_step: block at %I64x written partly (%u of %I64u bytes), status %d, dev=%ws\n",
				offs, adv_len, size, resl, hook->dev_name);
		}
	}
	/* the block in place is flushed, then committed. A block that is not completely and
	 * durably written stays pending: written again from its post-image (buff), never read and
	 * transformed again; quarantined when the disk keeps refusing. */
	if (rec_written)
	{
		BOOLEAN committed = FALSE;
		BOOLEAN media     = (resl == ST_MEDIA_CHANGED || resl == ST_NO_MEDIA);
		u32     dir       = dc_slog_dir(is_decrypt, is_reencrypt);
		int     i;

		if (dc_slog_flush(hook) != ST_OK) {
			adv_len = 0; /* not known to be durable */
		}
		if (adv_len == size && !media) {
			committed = dc_safe_commit(hook, slog, slog->seq, dir, offs, (u32)size);
		}
		for (i = 0; !committed && !media && hook->pnp_state == Started && i < DC_RD_RETRIES; i++) {
			dc_delay(dc_rd_retry_delay[i]);
			if (dc_slog_write_in_place(hook, buff, (u32)size, offs) == ST_OK) {
				committed = dc_safe_commit(hook, slog, slog->seq, dir, offs, (u32)size);
			}
		}
		if (committed) {
			adv_len = (u32)size;
			if (resl != ST_OK && resl != ST_RW_ERR) resl = ST_OK; /* completed by a retry */
		} else {
			DbgMsg("dc_transcrypt_step: block at %I64x not committed (%d), pending, dev=%ws\n", offs, resl, hook->dev_name);
			adv_len   = 0;
			quar_kind = SL_PEND_WRITTEN;
			quar_seq  = slog->seq;
			if (!media) resl = ST_LOG_PENDING;
		}
	}

	if (resl == ST_OK && n_rd_bad != 0) {
		resl = ST_RW_ERR; /* reported: the block had unreadable sectors */
	}

	/* Prevent system power state changes */
	PoSetSystemState(ES_SYSTEM_REQUIRED);

finish_block:
	/* the post-image checksum for the later completion from the journal (not under the lock) */
	if (quar_kind == SL_PEND_WRITTEN) {
		q_crc = slog->fast ? crc32(p8(DC_STEP_SUMS(hook)), dc_slog_data_len(slog, LR_SUM, (u32)size)) : crc32(buff, (u32)size);
	}

	/* Clear active block and update boundary under spinlock.
	 * tmp_size must be updated atomically with clearing active_start so that
	 * I/O checking overlap sees consistent state: either active block exists
	 * (and I/O waits), or tmp_size is already updated (and I/O uses correct key). */
	KeAcquireSpinLock(&trans->range_lock, &irql);
	if (adv_len != 0) {
		/* adv_len < size after a write that stopped early - the boundary moves over the
		 * written part only (encryption writes from the block start, decryption from its end) */
		if (is_encrypt) {
			hook->tmp_size = offs + adv_len;
		} else {
			hook->tmp_size = offs + size - adv_len;
		}
	}
	if (quar_kind != 0) {
		/* from here on I/O to the block fails instead of waiting, until a later step or the
		 * next mount completes it - set before the range is unlocked below */
		dc_safe_quarantine(slog, quar_kind, slog->fast ? LR_SUM : LR_STEP, quar_seq, offs, (u32)size, dc_slog_dir(is_decrypt, is_reencrypt), q_crc);
	}
	trans->active_start = -1;
	trans->active_end = 0;
	KeSetEvent(&trans->block_complete, IO_NO_INCREMENT, FALSE);
	KeReleaseSpinLock(&trans->range_lock, irql);

	/* Mark transcryption as idle */
	dc_release_step_slot(hook);

	/* a block whose read failed is read again by the next step - wait here, holding
	 * neither the block range nor the step slot (the caller holds a hook reference) */
	if (retry_delay != 0) {
		dc_delay(retry_delay);
	}
	return resl;
}

int dc_transcrypt_finish(dev_hook *hook, BOOLEAN is_decrypt)
{
	DbgMsg("dc_transcrypt_finish: is_decrypt=%d\n", is_decrypt);

	if (!(hook->flags & F_SYNC)) {
		return ST_ERROR;
	}

	/* Wait for any pending I/O to complete before finishing.
	 * This ensures no I/O is using stale boundary snapshots or accessing
	 * resources (like tmp_key) that we're about to free. */
	dc_wait_for_pending_io(hook);

	/* Save final encryption state.
	 * For decryption: skip header write because we just restored the
	 * original boot sector to offset 0 - writing the header would overwrite it.
	 * For encryption/re-encryption: write header with VF_TMP_MODE cleared. */
	if (!is_decrypt) {
		int   resl;
		u64   tmp;
		KIRQL irql;

		/* The finish declares every block transcrypted, but the boundary may have moved since
		 * the step returned ST_FINISHED (a resize, a reversed step). Hold the slot across the
		 * save and require the boundary at the data end; otherwise this is no finish
		 * (ST_DEVICE_BUSY: the caller continues the loop). */
		dc_acquire_step_slot(hook);
		KeAcquireSpinLock(&hook->trans.range_lock, &irql);
		tmp = hook->tmp_size;
		KeReleaseSpinLock(&hook->trans.range_lock, irql);
		if (tmp < dc_data_end(hook)) {
			dc_release_step_slot(hook);
			DbgMsg("dc_transcrypt_finish: boundary %I64x below the data end %I64x, not finished, dev=%ws\n", tmp, dc_data_end(hook), hook->dev_name);
			return ST_DEVICE_BUSY;
		}
		resl = dc_save_enc_state(hook, SYNC_STEP_FINISH);
		dc_release_step_slot(hook);
		if (resl != ST_OK) {
			/* the disk header still says VF_TMP_MODE with the last periodic tmp_size; finishing
			 * anyway would make the next mount encrypt the blocks after it again. Keep the
			 * session: a continued encryption reaches ST_FINISHED at once and retries. */
			DbgMsg("dc_transcrypt_finish: final header save failed (%d), session kept\n", resl);
			/* a swapped / removed medium goes to the caller's media branch */
			return (resl == ST_MEDIA_CHANGED || resl == ST_NO_MEDIA) ? resl : ST_IO_ERROR;
		}
		/* the header no longer points to the journal - zero it (it holds the last
		 * post-images; after a reversal plaintext ones) and delete it */
		{
			dc_slog *slog = dc_slog_get(hook);

			if (slog != NULL) {
				/* a concurrent step must not use the state while it is freed (busy_lock held) */
				dc_acquire_step_slot(hook);
				if (hook->tmp_buff != NULL) {
					memset(hook->tmp_buff, 0, ENC_BLOCK_SIZE);
					if (dc_slog_zero_all(hook, slog, hook->tmp_buff, ENC_BLOCK_SIZE) != ST_OK) {
						DbgMsg("dc_transcrypt_finish: journal not zeroed\n");
					}
				}
				dc_slog_discard(hook);
				dc_release_step_slot(hook);
			}
		}
	}

	/* TRIM free space if enabled */
	if ((dc_conf_flags & CONF_DISABLE_TRIM) == 0) {
		dc_trim_free_space(hook);
	}

	/* Cleanup resources.
	 * dc_transcrypt_cleanup clears F_SYNC under spinlock and waits for pending I/O. */
	dc_transcrypt_cleanup(hook);

	/* The caller deletes the storage file AFTER the unmount (the file system must be
	 * unmounted first). */

	return ST_OK;
}

/*
 * Unmount of a session whose initial header never reached the disk (init_hdr_pending).
 * Nothing is encrypted yet (steps were refused), so moving the redirected ranges back is
 * always correct; on success F_PLAIN_IO is published like at a decryption finish. ONLY for
 * dc_process_unmount, which tears the session down right after (busy_lock held, no step
 * runs). Returns ST_OK when nothing was pending or the begin (and end) are back in place.
 */
int dc_init_pending_undo(dev_hook *hook)
{
	int resl = ST_OK;
	int tries = 0;

	if ( !(hook->flags & F_SYNC) || InterlockedCompareExchange(&hook->trans.init_hdr_pending, 0, 0) == 0 ) {
		return ST_OK;
	}
	if (hook->tmp_buff == NULL) {
		return ST_NOMEM;
	}
	/* both copy-backs are idempotent (a restored tail resets tail_len), so they can be retried */
	do
	{
		resl = ST_OK;
		if (hook->tail_len != 0) {
			resl = dc_restore_part_end(hook, FALSE);
		}
		if (resl == ST_OK) {
			/* F_PLAIN_IO like a decryption finish, published while the head is still locked */
			resl = dc_init_enc_undo_begin(hook, 0, F_PLAIN_IO, TRUE);
		}
	} while (dc_removable_retry(hook, resl, &tries));
	if (resl == ST_OK) {
		InterlockedExchange(&hook->trans.init_hdr_pending, 0);
	}
	DbgMsg("dc_init_pending_undo: %d, dev=%ws\n", resl, hook->dev_name);
	return resl;
}

int dc_encrypt_step(wchar_t *dev_name)
{
	int   resl;
	u32   flags;
	dev_hook *hook = dc_find_hook(dev_name);
	if (hook == NULL) {
		return ST_NF_DEVICE;
	}

	/* Check F_SYNC without holding busy_lock (one snapshot, see dc_transcrypt_step) */
	flags = hook->flags;
	if (!(flags & F_SYNC)) {
		dc_deref_hook(hook);
		/* locked at hibernation - continue after the unlock (caller retries on ST_CANCEL) */
		return (flags & F_HIBER_ERASE) ? ST_CANCEL : ST_ERROR;
	}

	/* the initial header is not on disk yet (init_hdr_pending): retry it. No block is
	 * encrypted before it is there - without a header the data would be lost with the
	 * session. Same locking as dc_sync_step. */
	if (InterlockedCompareExchange(&hook->trans.init_hdr_pending, 0, 0) != 0) {
		resl = ST_OK;
		wait_object_infinity(&hook->busy_lock);
		if ( (hook->flags & F_SYNC) && InterlockedCompareExchange(&hook->trans.init_hdr_pending, 0, 0) != 0 ) {
			dc_acquire_step_slot(hook);
			resl = dc_save_enc_state(hook, SYNC_STEP_INIT);
			dc_release_step_slot(hook);
		}
		KeReleaseMutex(&hook->busy_lock, FALSE);
		if (resl != ST_OK) {
			DbgMsg("dc_encrypt_step: initial header still not written (%d)\n", resl);
			if (resl == ST_MEDIA_CHANGED || resl == ST_NO_MEDIA) {
				dc_process_unmount(hook, MF_NOFSCTL);
			} else {
				resl = ST_IO_ERROR;
			}
			dc_deref_hook(hook);
			return resl;
		}
	}

	/* Process block without holding busy_lock.
	 * dc_transcrypt_step uses in_progress flag to coordinate with power management. */
	resl = dc_transcrypt_step(hook, FALSE);  /* is_decrypt = FALSE */

	if (resl == ST_FINISHED) {
		/* Use busy_lock only for finalization (state change, cleanup) */
		int fin;

		wait_object_infinity(&hook->busy_lock);
		fin = dc_transcrypt_finish(hook, FALSE);  /* is_decrypt = FALSE */
		if (fin != ST_OK && (hook->flags & F_HIBER_ERASE)) {
			/* locked at hibernation between the last step and the finish: after the unlock
			 * the next step returns ST_FINISHED again and the finish is retried */
			resl = ST_CANCEL;
		} else if (fin == ST_DEVICE_BUSY) {
			/* the boundary moved off the data end before the finish (resize, reversed step) -
			 * not finished, the step loop continues */
			resl = ST_OK;
		} else if (fin == ST_IO_ERROR || fin == ST_MEDIA_CHANGED || fin == ST_NO_MEDIA) {
			/* the final header save failed, the session is kept: report the error instead of
			 * a finished encryption (a medium error is handled below) */
			resl = fin;
		}
		KeReleaseMutex(&hook->busy_lock, FALSE);
	}
	if (resl == ST_MEDIA_CHANGED || resl == ST_NO_MEDIA) {
		/* Media error - unmount volume to prevent corruption.
		 * dc_process_unmount waits for I/O and calls dc_transcrypt_cleanup. */
		dc_process_unmount(hook, MF_NOFSCTL);
	}

	dc_deref_hook(hook);
	return resl;
}

int dc_decrypt_step(wchar_t *dev_name)
{
	int   resl;
	u32   flags;
	dev_hook *hook = dc_find_hook(dev_name);
	if (hook == NULL) {
		return ST_NF_DEVICE;
	}

	/* Check F_SYNC without holding busy_lock (one snapshot, see dc_transcrypt_step) */
	flags = hook->flags;
	if (!(flags & F_SYNC)) {
		dc_deref_hook(hook);
		/* locked at hibernation - continue after the unlock (caller retries on ST_CANCEL) */
		return (flags & F_HIBER_ERASE) ? ST_CANCEL : ST_ERROR;
	}

	/* Process block without holding busy_lock.
	 * dc_transcrypt_step uses in_progress flag to coordinate with power management. */
	resl = dc_transcrypt_step(hook, TRUE);  /* is_decrypt = TRUE */

	if (resl == ST_FINISHED) {
		int del_storage;
		int del_log;
		int unmount_opt;

		/* Use busy_lock only for finalization (state change, cleanup).
		 * is_decrypt=TRUE skips header write since boot sector was just restored */
		wait_object_infinity(&hook->busy_lock);

		/* Check if storage file needs deletion BEFORE finalize clears tmp_header. Under
		 * busy_lock: an unmount while this step ran may already have freed tmp_header (then
		 * F_SYNC is gone and the storage file is left in place). */
		del_storage = (hook->flags & F_SYNC) && hook->tmp_header != NULL &&
		              (hook->tmp_header->flags & VF_STORAGE_FILE) != 0;
		/* the $dclog$ journal, like $dcsys$ after the unmount */
		del_log     = (hook->flags & F_SYNC) && dc_slog_get(hook) != NULL;

		/* the journal holds plaintext post-images of the last blocks; deleted they would stay
		 * in free space: zeroed now, deleted after the unmount */
		if (del_log && hook->tmp_buff != NULL) {
			dc_slog *slog;

			dc_acquire_step_slot(hook); /* see dc_transcrypt_finish */
			slog = dc_slog_get(hook);
			memset(hook->tmp_buff, 0, ENC_BLOCK_SIZE);
			if (slog != NULL && dc_slog_zero_all(hook, slog, hook->tmp_buff, ENC_BLOCK_SIZE) != ST_OK) {
				DbgMsg("dc_decrypt_step: journal not zeroed\n");
			}
			dc_release_step_slot(hook);
		}

		dc_transcrypt_finish(hook, TRUE);

		/* finished, drained and passing through as plaintext (F_PLAIN_IO): no request uses
		 * dsk_key any more. The unmount's F_DISABLE + remove-lock drain would only fail the
		 * live file system's I/O and spin with busy_lock held - skip it (MF_NOSYNC). */
		unmount_opt = MF_NOFSCTL | MF_DECRYPTED;
		if ((hook->flags & (F_SYNC | F_PLAIN_IO)) == F_PLAIN_IO) {
			unmount_opt |= MF_NOSYNC;
		}
		KeReleaseMutex(&hook->busy_lock, FALSE);

		/* Unmount and delete storage (unmount acquires lock internally) */
		dc_process_unmount(hook, unmount_opt);

		/* Delete storage file AFTER unmount.
		 * Must be after unmount so F_ENABLED is cleared and I/O passes through
		 * without encryption, allowing filesystem access to delete the file. */
		if (del_storage) {
			dc_delete_storage(hook);
		}
		if (del_log) {
			dc_delete_log_file(hook);
		}
	} else if (resl == ST_MEDIA_CHANGED || resl == ST_NO_MEDIA) {
		/* Media error - unmount volume to prevent corruption.
		 * dc_process_unmount waits for I/O and calls dc_transcrypt_cleanup. */
		dc_process_unmount(hook, MF_NOFSCTL);
	}

	dc_deref_hook(hook);
	return resl;
}

int dc_sync_step(wchar_t *dev_name)
{
	int   resl;
	dev_hook *hook = dc_find_hook(dev_name);
	if (hook == NULL) {
		return ST_NF_DEVICE;
	}

	wait_object_infinity(&hook->busy_lock);
	if (hook->flags & F_SYNC) {
		/* hold the step slot across the save (see dc_sync_all_encs) */
		dc_acquire_step_slot(hook);
		dc_save_enc_state(hook, SYNC_STEP_UPDATE);
		dc_release_step_slot(hook);
		resl = ST_OK;
	} else {
		/* locked - the lock already saved the state; nothing to sync until unlocked */
		resl = (hook->flags & F_HIBER_ERASE) ? ST_CANCEL : ST_ERROR;
	}
	KeReleaseMutex(&hook->busy_lock, FALSE);

	dc_deref_hook(hook);
	return resl;
}

void dc_wait_for_transcrypt(dev_hook* hook)
{
	/* Wait until the slot is really free: one wait on idle_event is not enough (a new step can
	 * take the slot between a holder's release and its KeSetEvent). Callers set F_PREVENT_ENC
	 * first, so a step taking the slot after this returns exits without touching the session. */
	LARGE_INTEGER poll;

	poll.QuadPart = -100000LL; /* 10 ms, relative */
	while (InterlockedCompareExchange(&hook->trans.in_progress, 0, 0) != 0) {
		if (KeWaitForSingleObject(&hook->trans.idle_event, Executive, KernelMode, FALSE, &poll) != STATUS_TIMEOUT) {
			dc_delay(1); /* a stale signalled event must not make this spin */
		}
	}
}

/*
 * Hold the step slot across an operation that must not run concurrently with a
 * transcryption step. Slot protocol (dc_transcrypt_step acquires the same way): clear
 * idle_event BEFORE each in_progress exchange, so the holder's release (in_progress = 0,
 * then KeSetEvent) cannot be missed. Waits instead of failing, counted in slot_waiters so a
 * tight step loop cannot starve it. Not re-entrant. Caller holds busy_lock - steps never
 * take busy_lock while they hold the slot, so this cannot deadlock. PASSIVE_LEVEL.
 */
void dc_acquire_step_slot(dev_hook *hook)
{
	transcrypt_state *trans = &hook->trans;
	LARGE_INTEGER     poll;

	/* announce the wait - steps yield to it (dc_transcrypt_step) */
	InterlockedIncrement(&trans->slot_waiters);
	poll.QuadPart = -100000LL; /* 10 ms: a stale signalled / missed event only costs a poll */
	for (;;) {
		KeClearEvent(&trans->idle_event);
		if (InterlockedCompareExchange(&trans->in_progress, 1, 0) == 0) {
			break;
		}
		KeWaitForSingleObject(&trans->idle_event, Executive, KernelMode, FALSE, &poll);
	}
	InterlockedDecrement(&trans->slot_waiters);
	/* a late KeSetEvent of the previous holder may have signalled it after our clear */
	KeClearEvent(&trans->idle_event);
}

void dc_release_step_slot(dev_hook *hook)
{
	InterlockedExchange(&hook->trans.in_progress, 0);
	KeSetEvent(&hook->trans.idle_event, IO_NO_INCREMENT, FALSE);
}

void dc_transcrypt_cleanup(dev_hook *hook)
{
	transcrypt_state *trans = &hook->trans;
	KIRQL irql;

	/* Clear F_SYNC under spinlock FIRST.
	 * I/O re-checks F_SYNC inside the spinlock, so it will see this and bail out.
	 * This prevents new I/O from starting to use resources we're about to free. */
	KeAcquireSpinLock(&trans->range_lock, &irql);
	dc_hook_clear_flags(hook, F_SYNC | F_REENCRYPT);
	KeReleaseSpinLock(&trans->range_lock, irql);

	/* Wait for pending I/O before freeing resources.
	 * I/O that already incremented pending_io_count has snapshot_tmp_key pointing
	 * to our tmp_key memory. We must wait for all such I/O to complete before
	 * freeing tmp_key to prevent use-after-free. */
	dc_wait_for_pending_io(hook);

	/* Now safe to free resources - no I/O is using them */
	dc_wipe_free(&hook->wp_ctx);

	dc_sync_cleanup(hook);
}

#endif /* DC_CONCURRENT_TRANSCRYPT */

int dc_encrypt_start(wchar_t *dev_name, dc_pass *password, crypt_info *crypt, u32 flags, BOOLEAN confirmed, ULONG *interrupt_cmd)
{
	dc_header *header = NULL;
	dev_hook  *hook;
	xts_key   *hdr_key = NULL;
	int        resl;
	u64        stor_off = 0;
	u32        stor_len;
	u64        slack_size = 0;
	xts_key   *bak_key = NULL;
	u8        *bak_salt = NULL;
	BOOLEAN    prot_set = FALSE; /* F_PROTECT_DCSYS set by this call */
	BOOLEAN    log_made = FALSE; /* $dclog$ created by this call */

	DbgMsg("dc_encrypt_start\n");

	/* the layout / session bits are this function's to set (VF_STORAGE_FILE below);
	 * a caller may only ask for these */
	flags &= (VF_BACKUP_HEADER | VF_NO_HIBER | VF_EXTENDED);

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		if (hook->flags & (F_ENABLED | F_UNSUPRT | F_DISABLE | F_CDROM)) {
			resl = ST_ERROR; break;
		}
		/* no new keys between the first S4 SET_POWER and the S0 SET_POWER - this
		 * volume's S4 IRP may already have been handled (same rule as dc_mount_device) */
		if (dc_s4_transition_active()) {
			resl = ST_CANCEL; break;
		}

		/* safety check */
		if (!confirmed && (hook->flags & F_SYSTEM) && (dc_load_flags & DST_UEFI_BOOT) && !(dc_load_flags & DST_BOOTLOADER)) {
			resl = ST_BL_NOT_PASSED; break;
		}

		/* verify encryption info */
		if ( (crypt->cipher_id >= CF_CIPHERS_NUM) || (crypt->wp_mode != WP_SKIP_UNUSED && crypt->wp_mode >= WP_NUM) ) {
			resl = ST_ERROR; break;
		}

		if (crypt->version == 0) {
			if (crypt->head_len != 0) {
				crypt->version = DC_HDR_VERSION_2;
			} else {
				crypt->head_len = DC_AREA_SIZE;
				crypt->version = DC_HDR_VERSION;
			}
		}
		else if (crypt->version > DC_HDR_VERSION_2 || crypt->version < DC_HDR_VERSION) {
			resl = ST_INVALID_PARAM; break;
		}

		if (crypt->head_len < DC_AREA_SIZE || crypt->head_len > DC_AREA_MAX_SIZE || IS_INVALID_SECTOR_SIZE(crypt->head_len)) {
			resl = ST_INVALID_PARAM; break;
		}

		/* get device params */
		if ( !NT_SUCCESS(dc_fill_device_info(hook)) ) {
			resl = ST_IO_ERROR; break;
		}
		dc_media_baseline(hook);

		/* verify disk size is sector-aligned */
		if (hook->dsk_size % hook->bps != 0) {
			DbgMsg("dc_encrypt_start: dsk_size not sector-aligned\n");
			resl = ST_INV_SECT; break;
		}

		/* set header length */
		if (crypt->version >= DC_HDR_VERSION_2) {
			hook->head_len = ROUND_TO_FULL_SECTORS(crypt->head_len, hook->bps);
			stor_len = hook->head_len;
			if (flags & VF_BACKUP_HEADER) {
				stor_len *= 2;
			}
		} else {
			hook->head_len = ROUND_TO_FULL_SECTORS(DC_AREA_SIZE, hook->bps);
			stor_len = hook->head_len;
			if (flags & VF_BACKUP_HEADER) {
				resl = ST_INVALID_PARAM; break;
			}
		}

		if (!(dc_load_flags & DST_PRO_ENABLED) && (hook->head_len != DC_AREA_SIZE || (flags & VF_BACKUP_HEADER))) {
			resl = ST_NOT_PRO; break;
		}

#ifdef DC_MBR_LEGACY_GUARD
		/* what the legacy BIOS loader cannot boot (see driver.h) */
		if ( DC_MBR_BOOT_VOLUME(hook) &&
			 ( (crypt->version >= DC_HDR_VERSION_2 && crypt->head_len != DC_AREA_SIZE) || (flags & VF_BACKUP_HEADER) ||
			   password->kdf > KDF_SHA512_PKCS5_2 || password->kdf == KDF_NONE || (crypt->flags & EF_USE_SLACK) ) )
		{
			DbgMsg("dc_encrypt_start: option not supported by the legacy BIOS loader (head_len %u, flags %x, kdf %d, crypt flags %x)\n",
				crypt->head_len, flags, password->kdf, crypt->flags);
			resl = ST_LEGACY_BOOT; break;
		}
#endif

		/* Check for volume slack at partition end before creating $dcsys$ file */
		if (crypt->flags & EF_USE_SLACK) {
			DbgMsg("dc_encrypt_start: checking for existing volume slack\n");
			if (dc_get_volume_slack(hook, &slack_size) == ST_OK && slack_size >= stor_len) {
				stor_off = hook->dsk_size - stor_len;
				DbgMsg("dc_encrypt_start: using existing volume slack at offset=%I64x\n", stor_off);
			}
		}

		/* If no existing slack and EF_TRY_SHRINK is set, try to shrink filesystem.
		 * EF_TRY_SHRINK is in crypt->flags; 'flags' holds the header flags. */
		if (stor_off == 0 && (crypt->flags & EF_USE_SLACK) && (crypt->flags & EF_TRY_SHRINK)) {
			DbgMsg("dc_encrypt_start: attempting to shrink filesystem\n");
			if (dc_try_shrink_fs(hook, stor_len) == ST_OK) {
				stor_off = hook->dsk_size - stor_len;
				DbgMsg("dc_encrypt_start: using shrink-created slack at offset=%I64x\n", stor_off);
			}
		}

		/* If volume slack is not used, create redirection storage file */
		if (stor_off == 0) {
			/* stor_len in min size, stor_len out actual size may be larger */
			if ( (resl = dc_create_storage(hook, &stor_off, &stor_len, hook->head_len)) != ST_OK ) {
				break;
			}
			DbgMsg("dc_encrypt_start: created $dcsys$ storage at offset=%I64x\n", stor_off);
			/* Set flag to indicate storage file is used */
			flags |= VF_STORAGE_FILE;
		}

		/* allocate memory for header and keys */
		if ( (header = (dc_header*)mm_secure_alloc(hook->head_len)) == NULL ||
			 (hdr_key = (xts_key*)mm_secure_alloc(sizeof(xts_key))) == NULL ||
			 (hook->dsk_key = (xts_key*)mm_secure_alloc(sizeof(xts_key))) == NULL )
		{
			resl = ST_NOMEM; break;
		}

		/* create volume header */
		memset(header, 0, hook->head_len);

		cp_rand_bytes(pv(header->salt),     HEADER_SALT_SIZE);
		cp_rand_bytes(pv(&header->disk_id), sizeof(u32));
		cp_rand_bytes(pv(header->key_1),    DISKKEY_SIZE);

		header->sign     = DC_VOLUME_SIGN;
		header->version  = crypt->version;
		header->flags    = VF_TMP_MODE | flags;
		header->alg_1    = crypt->cipher_id;
		header->stor_off = stor_off;
		if (header->version >= DC_HDR_VERSION_2) {
			header->stor_len = stor_len;
			header->head_len = hook->head_len;
			if( (resl = init_header_v2(header, crypt, password)) != ST_OK) { 
				break; 
			}
		}
		/* power-loss protection - the journal is created and initialised before the
		 * session header that points to it is written (S_INIT_ENC) */
		if (crypt->flags & (EF_SAFE_TRANSCRYPT | EF_SAFE_TRANSCRYPT_FAST)) {
			if (header->version < DC_HDR_VERSION_2) {
				DbgMsg("dc_encrypt_start: power-loss protection needs a v2 header, not used\n");
			} else {
				u64 log_off = 0;

				hook->disk_id = header->disk_id; /* the journal header carries it */
				if ( (resl = dc_slog_create(hook, hook->head_len, &log_off, DC_SAFE_FAST(crypt))) != ST_OK ) {
					break;
				}
				log_made = TRUE;
				header->feature_flags |= FF_SAFE_TRANSCRYPT | (DC_SAFE_FAST(crypt) ? FF_SAFE_FAST : 0);
				header->log_offset     = log_off;
			}
		}
		header->hdr_crc  = calculate_header_crc(header);

		// initialize volume key
		if ( !xts_set_key(header->key_1, crypt->cipher_id, hook->dsk_key) ) {
			DbgMsg("dc_encrypt_start: failed to set volume key\n");
			resl = ST_INVALID_PARAM; break;
		}
		
		// initialize header key
		if ( !cp_set_header_key(hdr_key, header->salt, crypt->cipher_id, password, interrupt_cmd) ) {
			DbgMsg("dc_encrypt_start: failed to set header key, cipher_id=%d, kdf=%d\n", crypt->cipher_id, password->kdf);
			resl = ST_INVALID_PARAM; break;
		}

		// if backup header is requested, allocate keys and initialize backup header
		if (header->flags & VF_BACKUP_HEADER) {
			if ( (bak_key = (xts_key*)mm_secure_alloc(sizeof(xts_key))) == NULL ||
				 (bak_salt = (u8*)mm_secure_alloc(HEADER_SALT_SIZE)) == NULL )
			{
				resl = ST_NOMEM; break;
			}
			cp_rand_bytes(pv(bak_salt),     HEADER_SALT_SIZE);
			if ( !cp_set_header_key(bak_key, bak_salt, crypt->cipher_id, password, interrupt_cmd) ) {
				DbgMsg("dc_encrypt_start: failed to set backup header key\n");
				resl = ST_INVALID_PARAM; break;
			}
		}
		
		hook->crypt          = crypt[0];
		hook->crypt.head_kdf = password->kdf;
		/* storage in the slack is not volume space, or a file system extend could grow over
		 * the head copy and the backup header */
		hook->use_size       = (flags & VF_STORAGE_FILE) ? hook->dsk_size : hook->dsk_size - stor_len;
		hook->tmp_size       = hook->head_len;
		hook->stor_off       = stor_off;
		hook->stor_len       = stor_len;
		hook->hdr_key        = hdr_key;
		hook->disk_id        = header->disk_id;
		if ((flags & VF_STORAGE_FILE) && !(hook->flags & F_PROTECT_DCSYS)) {
			dc_hook_set_flags(hook, F_PROTECT_DCSYS);
			prot_set = TRUE; /* cleared again below if the start fails */
		}
		hook->tmp_header     = header;

		if (header->flags & VF_BACKUP_HEADER) {
			hook->bak_key = bak_key;
			hook->bak_salt = bak_salt;

			bak_key = NULL;
			bak_salt = NULL;
		}
		
		hdr_key = NULL;
		header = NULL;
#ifdef DC_CONCURRENT_TRANSCRYPT
		if ( (resl = dc_transcrypt_init(hook, S_INIT_ENC)) != ST_OK ) {
#else
		if ( (resl = dc_enable_sync_mode(hook, S_INIT_ENC)) != ST_OK ) {
#endif
			DbgMsg("encrypt start error code=%d\n", resl);
			/* the volume was not started: drop the $dcsys$ protection set above */
			if (prot_set) {
				dc_hook_clear_flags(hook, F_PROTECT_DCSYS);
			}
		}
	} while (0);

	if (hdr_key != NULL) mm_secure_free(hdr_key);
	if (header != NULL)  mm_secure_free(header);

	if (bak_key != NULL) mm_secure_free(bak_key);
	if (bak_salt != NULL)mm_secure_free(bak_salt);

	if (hook != NULL)
	{
		/* a start that failed leaves no journal behind */
		if (log_made && resl != ST_OK) {
			dc_slog_discard(hook);
		}
		if ((hook->flags & F_ENABLED) == 0 && hook->dsk_key != NULL) {
			mm_secure_free(hook->dsk_key);
			hook->dsk_key = NULL;
		}

		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}
	return resl;
}

int dc_reencrypt_start(wchar_t *dev_name, dc_pass *password, crypt_info *crypt, ULONG *interrupt_cmd)
{
	dc_header *header = NULL;
	crypt_info o_crypt;
	dc_dev     dev;
	dev_hook  *hook;
	xts_key   *hdr_key = NULL;
	xts_key   *dsk_key = NULL;
	int        resl;
	dc_header *hback = NULL;
	u8        *bak_salt = NULL;
	xts_key   *bak_key = NULL;
	int        sel_kdf = password->kdf;
	int        found_kdf = -1;
	int        bak_kdf = -1;
	BOOLEAN    log_made = FALSE; /* $dclog$ created by this call */

	DbgMsg("dc_reencrypt_start\n");

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		/* no new sessions while hibernating (see dc_encrypt_start) */
		if (dc_s4_transition_active()) {
			resl = ST_CANCEL; break;
		}

		/* never on a locked volume - its keys are zeroed. Nor on an F_NO_REDIRECT volume:
		 * the mount (dc_check_header) rejects VF_TMP_MODE | VF_REENCRYPT together with
		 * VF_NO_REDIR, so any unmount before the finish would leave it unmountable. */
		if ( !(hook->flags & F_ENABLED) ||
			  (hook->flags & (F_SYNC | F_FORMATTING | F_CDROM | F_NO_REDIRECT | F_HIBER_ERASE)) )
		{
			resl = ST_ERROR; break;
		}

		/* verify encryption info */
		if ( (crypt->cipher_id >= CF_CIPHERS_NUM) || (crypt->wp_mode != WP_SKIP_UNUSED && crypt->wp_mode >= WP_NUM) ) {
			resl = ST_ERROR; break;
		}

#ifdef DC_MBR_LEGACY_GUARD
		/* the new header key is derived with password->kdf - the BIOS loader knows only
		 * PBKDF2 from a typed password (no Argon2, no raw key) */
		if (DC_MBR_BOOT_VOLUME(hook) && (password->kdf > KDF_SHA512_PKCS5_2 || password->kdf == KDF_NONE)) {
			DbgMsg("dc_reencrypt_start: KDF %d not supported by the legacy BIOS loader\n", password->kdf);
			resl = ST_LEGACY_BOOT; break;
		}
#endif

		/* allocate new volume key */
		if ( (dsk_key = mm_secure_alloc(sizeof(xts_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}
		/* allocate new header key */
		if ( (hdr_key = mm_secure_alloc(sizeof(xts_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}
		dc_dev_of(hook, &dev);

		/* the header password only: the new header keys below are derived from the password
		   as the header password - opened through a key slot, the primary would be re-keyed
		   to the slot password and the real one and every slot lost */
		password->slot = 0;

		/* read volume header */
		if ( (resl = io_read_header(&dev, dc_hook_rw, 0, &header, NULL, password, &found_kdf, interrupt_cmd)) != ST_OK ) {
			break;
		}
		/* a KDF selector only searches: the new header keys (cp_set_header_key below) need the
		   KDF the header was found with, which is also the head_kdf it keeps */
		password->kdf = found_kdf;
		/* F_SYNC is not set, so the header must not describe a session. One that does is a
		 * failed initial re-encryption save that reached the disk anyway (its key_1 never
		 * encrypted anything here); a remount resumes it instead. */
		if (header->flags & VF_TMP_MODE) {
			DbgMsg("%s: header describes a session that is not running, flags=0x%x\n", __FUNCTION__, header->flags);
			resl = ST_ERROR; break;
		}
		/* copy current volume key to secondary key */
		memcpy(header->key_2, header->key_1, DISKKEY_SIZE);

		/* generate new volume key */		
		cp_rand_bytes(header->key_1, DISKKEY_SIZE);

		/* generate new salt if no keyslots are present */
		if (!(header->feature_flags & FF_KEY_SLOTS)) {
			cp_rand_bytes(header->salt, HEADER_SALT_SIZE);
		}

		/* change other fields */
		header->alg_2  = header->alg_1;
		header->alg_1  = crypt->cipher_id;
		header->flags |= VF_REENCRYPT;
		/* power-loss protection: the journal before the session header (S_INIT_RE_ENC) */
		if (crypt->flags & (EF_SAFE_TRANSCRYPT | EF_SAFE_TRANSCRYPT_FAST)) {
			if (header->version < DC_HDR_VERSION_2) {
				DbgMsg("dc_reencrypt_start: power-loss protection needs a v2 header, not used\n");
			} else {
				u64 log_off = 0;

				if ( (resl = dc_slog_create(hook, hook->head_len, &log_off, DC_SAFE_FAST(crypt))) != ST_OK ) {
					break;
				}
				log_made = TRUE;
				header->feature_flags |= FF_SAFE_TRANSCRYPT | (DC_SAFE_FAST(crypt) ? FF_SAFE_FAST : 0);
				header->log_offset     = log_off;
			}
		}
		header->hdr_crc = calculate_header_crc(header);

		/* initialize new header key */
		if ( !cp_set_header_key(hdr_key, header->salt, header->alg_1, password, interrupt_cmd) ) {
			resl = ST_INVALID_PARAM; break;
		}

		/* initialize new volume key */
		if ( !xts_set_key(header->key_1, header->alg_1, dsk_key) ){
			resl = ST_INVALID_PARAM; break;
		}

		/* backup header is present, load and verify it */
		if (header->flags & VF_BACKUP_HEADER) {
			if (!(bak_salt = mm_secure_alloc(HEADER_SALT_SIZE))) {
				resl = ST_NOMEM; break;
			}
			/* the primary's KDF first; a backup written with another one is still found
			   when the caller passed a selector */
			resl = io_read_header(&dev, dc_hook_rw, hook->dsk_size - hook->head_len, &hback, &bak_key, password, &bak_kdf, interrupt_cmd);
			if (resl == ST_PASS_ERR && sel_kdf < KDF_NONE) {
				password->kdf = sel_kdf;
				resl = io_read_header(&dev, dc_hook_rw, hook->dsk_size - hook->head_len, &hback, &bak_key, password, &bak_kdf, interrupt_cmd);
				password->kdf = found_kdf;
			}
			if (resl != ST_OK) {
				DbgMsg("reencrypt failed to load backup header, dev=%ws, error=%d\n", hook->dev_name, resl);
				resl = ST_NOT_BACKUP;
				break;
			}
			memcpy(bak_salt, hback->salt, HEADER_SALT_SIZE);

			// initialize new backup header key, as the same salt and password are used only the algorithm is changed key slots will remain intect
			/* with the backup's own KDF: its key slots wrap the key derived with that one */
			password->kdf = bak_kdf;
			if ( !cp_set_header_key(bak_key, bak_salt, header->alg_1, password, interrupt_cmd) ) {
				password->kdf = found_kdf;
				resl = ST_INVALID_PARAM;
				break;
			}
			password->kdf = found_kdf;
		}

		/* save old encryption info */
		o_crypt = hook->crypt;
		/* update encryption info */		
		hook->crypt.cipher_id = crypt->cipher_id;
		hook->crypt.wp_mode = crypt->wp_mode;

		hook->tmp_size       = hook->head_len;
		hook->hdr_key        = hdr_key;
		hook->tmp_key        = dsk_key;
		hook->tmp_header     = header;

		hook->bak_key        = bak_key;
		hook->bak_salt	     = bak_salt;


		header = NULL;
		hdr_key = NULL;
		dsk_key = NULL;

		bak_key = NULL;
		bak_salt = NULL;

#ifdef DC_CONCURRENT_TRANSCRYPT
		if ( (resl = dc_transcrypt_init(hook, S_INIT_RE_ENC)) != ST_OK ) {
#else
		if ( (resl = dc_enable_sync_mode(hook, S_INIT_RE_ENC)) != ST_OK ) {
#endif
			DbgMsg("re-encrypt start error\n");
			/* restore encryption info */
			hook->crypt = o_crypt;
		}
	} while (0);

	/* free resources */
	if (dsk_key != NULL) mm_secure_free(dsk_key);
	if (hdr_key != NULL) mm_secure_free(hdr_key);
	if (header != NULL)  mm_secure_free(header);

	if (bak_key != NULL) mm_secure_free(bak_key);
	if (bak_salt != NULL) mm_secure_free(bak_salt);
	if (hback != NULL)   mm_secure_free(hback);

	if (hook != NULL) {
		if (log_made && resl != ST_OK) {
			dc_slog_discard(hook);
		}
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}
	return resl;
}

int dc_decrypt_start(wchar_t *dev_name, dc_pass *password, crypt_info *crypt, ULONG *interrupt_cmd)
{
	dc_header *header = NULL;
	dc_dev     dev;
	dev_hook  *hook;
	xts_key   *hdr_key = NULL;
	int        resl;
	dc_header *hback = NULL;
	u8        *bak_salt = NULL;
	xts_key   *bak_key = NULL;
	BOOLEAN    bak_fallback = FALSE; /* bak_salt / bak_key taken from the primary */
	BOOLEAN    log_made = FALSE;     /* $dclog$ created by this call */

	DbgMsg("dc_decrypt_start\n");

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		/* no new sessions while hibernating (see dc_encrypt_start) */
		if (dc_s4_transition_active()) {
			resl = ST_CANCEL; break;
		}

		/* never on a locked volume - its keys are zeroed */
		if ( !(hook->flags & F_ENABLED) ||
			  (hook->flags & (F_SYNC | F_FORMATTING | F_CDROM | F_NO_REDIRECT | F_HIBER_ERASE)) )
		{
			resl = ST_ERROR; break;
		}
		dc_dev_of(hook, &dev);

		/* read volume header */
		if ( (resl = io_read_header(&dev, dc_hook_rw, 0, &header, &hdr_key, password, NULL, interrupt_cmd)) != ST_OK ) {
			break;
		}
		/* F_SYNC is not set, so the header must not describe a session. One that does is a
		 * failed initial re-encryption save that reached the disk anyway (its key_1 never
		 * encrypted anything here); a remount resumes it instead. */
		if (header->flags & VF_TMP_MODE) {
			DbgMsg("%s: header describes a session that is not running, flags=0x%x\n", __FUNCTION__, header->flags);
			resl = ST_ERROR; break;
		}

		/* backup header is present, load and verify it */
		if (header->flags & VF_BACKUP_HEADER) {
			if (!(bak_salt = mm_secure_alloc(HEADER_SALT_SIZE))) {
				resl = ST_NOMEM; break;
			}
			// todo: hint at corerct kdf
			resl = io_read_header(&dev, dc_hook_rw, hook->dsk_size - hook->head_len, &hback, &bak_key, password, NULL, interrupt_cmd);
			if (resl != ST_OK) {
				DbgMsg("decrypt failed to load backup header, dev=%ws, error=%d\n", hook->dev_name, resl);
				// restore backup header from primary header
				if ( (bak_key = mm_secure_alloc(sizeof(xts_key))) == NULL ) { 
					resl = ST_NOMEM; break; 
				}
				memcpy(bak_salt, header->salt, HEADER_SALT_SIZE);
				memcpy(bak_key, hdr_key, sizeof(xts_key));
				bak_fallback = TRUE;
			}
			else {
				memcpy(bak_salt, hback->salt, HEADER_SALT_SIZE);
			}
		}

		/* power-loss protection; S_INIT_DEC writes the session header that points to
		 * the journal before the first step */
		if (crypt != NULL && (crypt->flags & (EF_SAFE_TRANSCRYPT | EF_SAFE_TRANSCRYPT_FAST))) {
			if (header->version < DC_HDR_VERSION_2) {
				DbgMsg("dc_decrypt_start: power-loss protection needs a v2 header, not used\n");
			} else {
				u64 log_off = 0;

				if ( (resl = dc_slog_create(hook, dc_data_end(hook), &log_off, DC_SAFE_FAST(crypt))) != ST_OK ) {
					break;
				}
				log_made = TRUE;
				header->feature_flags |= FF_SAFE_TRANSCRYPT | (DC_SAFE_FAST(crypt) ? FF_SAFE_FAST : 0);
				header->log_offset     = log_off;
				header->hdr_crc        = calculate_header_crc(header);
			}
		}

		hook->crypt.cipher_id = d8(header->alg_1);
		hook->crypt.wp_mode   = crypt ? crypt->wp_mode : WP_NONE;
		hook->tmp_size = dc_data_end(hook); /* decryption starts below the backup header */
		hook->hdr_key         = hdr_key;
		hook->tmp_header      = header;

		hook->bak_key        = bak_key;
		hook->bak_salt	     = bak_salt;

		hdr_key = NULL;
		header = NULL;

		bak_key = NULL;
		bak_salt = NULL;

#ifdef DC_CONCURRENT_TRANSCRYPT
		if ( (resl = dc_transcrypt_init(hook, S_INIT_DEC)) != ST_OK ) {
#else
		if ( (resl = dc_enable_sync_mode(hook, S_INIT_DEC)) != ST_OK ) {
#endif
			DbgMsg("decrypt start error\n");	
		}
#ifdef DC_CONCURRENT_TRANSCRYPT
		/* as at mount - an unreadable backup is written as a full copy of the primary by the
		 * next save (set after dc_transcrypt_init, which resets the flag) */
		else if (bak_fallback) {
			InterlockedExchange(&hook->trans.bak_clone_once, 1);
		}
#endif
	} while (0);

	if (hdr_key != NULL) mm_secure_free(hdr_key);
	if (header != NULL)  mm_secure_free(header);

	if (bak_key != NULL) mm_secure_free(bak_key);
	if (bak_salt != NULL) mm_secure_free(bak_salt);
	if (hback != NULL)   mm_secure_free(hback);

	if (hook != NULL) {
		if (log_made && resl != ST_OK) {
			dc_slog_discard(hook);
		}
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}
	return resl;
}



static int dc_store_part_end(dev_hook* hook, BOOLEAN encrypted)
{
	u8 *buff = hook->tmp_buff;
	u32 done, chunk;
	u64 end_stor_off;
	u64 end_disk_off;
	u32 tail_len;
	int resl = ST_OK;

	/* Check if we have enough space in redirection area to store partition end */
	if (hook->stor_len < hook->head_len * 2) {
		return ST_NF_SPACE;
	}

	/* Publish the tail redirect (tail_len, tail_off, F_HEAD_BACKUP) only after the copy
	 * succeeded, while the end range is still locked, so the partition end is never
	 * redirected to a half-copied storage area. */
	tail_len = hook->head_len; // backup header length is the same as main header length

	end_disk_off = hook->dsk_size - tail_len;
	end_stor_off = hook->stor_off + hook->stor_len - tail_len;

#ifdef DC_CONCURRENT_TRANSCRYPT
	/* Lock partition end range during copy to storage */
	dc_lock_disk_range(hook, end_disk_off, hook->dsk_size);
#endif

	for (done = 0; done < tail_len; done += chunk)
	{
		chunk = min(tail_len - done, ENC_BLOCK_SIZE);
		chunk = max((chunk / (u64)hook->bps) * (u64)hook->bps, hook->bps);

		resl = io_hook_rw(hook, buff, chunk, end_disk_off + done, 1);
		if (resl != ST_OK) break;

		if (encrypted)
		{
			cp_fast_decrypt(buff, buff, chunk, end_disk_off + done, hook->dsk_key);
			cp_fast_encrypt(buff, buff, chunk, end_stor_off + done, hook->dsk_key);
		}

		resl = io_hook_rw(hook, buff, chunk, end_stor_off + done, 0);
		if (resl != ST_OK) break;
	}

	if (resl == ST_OK) {
		/* storage now holds the partition end: switch the redirect on (range still locked) */
		hook->tail_len = tail_len;
		hook->tail_off = end_stor_off;
		dc_hook_set_flags(hook, F_HEAD_BACKUP);
	}

#ifdef DC_CONCURRENT_TRANSCRYPT
	dc_unlock_disk_range(hook);
#endif

	if (resl != ST_OK) {
		DbgMsg("dc_store_part_end: error storing partition end: %d\n", resl);
	}

	return resl;
}

static int dc_restore_part_end(dev_hook* hook, BOOLEAN encrypted)
{
	u8 *buff = hook->tmp_buff;
	u32 done, chunk;
	u64 end_stor_off;
	u64 end_disk_off;
	int resl = ST_OK;

	/* read from where the tail redirect actually points (the I/O path uses tail_off): after
	 * a failed layout undo stor_off/stor_len may describe a new storage file, tail_off the
	 * old one */
	end_stor_off = hook->tail_off;
	end_disk_off = hook->dsk_size - hook->tail_len;

#ifdef DC_CONCURRENT_TRANSCRYPT
	/* Lock partition end range to prevent concurrent I/O while restoring */
	dc_lock_disk_range(hook, end_disk_off, hook->dsk_size);
#endif

	/* Restore end sectors from storage */
	for (done = 0; done < hook->tail_len; done += chunk)
	{
		chunk = min(hook->tail_len - done, ENC_BLOCK_SIZE);
		chunk = max((chunk / (u64)hook->bps) * (u64)hook->bps, hook->bps);

		resl = io_hook_rw(hook, buff, chunk, end_stor_off + done, 1);
		if (resl != ST_OK) { break; }

		if (encrypted)
		{
			cp_fast_decrypt(buff, buff, chunk, end_stor_off + done, hook->dsk_key);
			cp_fast_encrypt(buff, buff, chunk, end_disk_off + done, hook->dsk_key);
		}

		resl = io_hook_rw(hook, buff, chunk, end_disk_off + done, 0);
		if (resl != ST_OK) { break; }
	}

	/* Drop the tail redirect only if the restore completed. On failure the storage copy is
	 * still authoritative: keep F_HEAD_BACKUP/tail_len/tail_off so I/O keeps reading the
	 * partition end from storage and a retry restores it again (instead of declaring the
	 * decryption finished and deleting $dcsys$). */
	if (resl == ST_OK) {
		dc_hook_clear_flags(hook, F_HEAD_BACKUP); /* may run inside a step, without busy_lock */
	}

#ifdef DC_CONCURRENT_TRANSCRYPT
	/* Unlock partition end */
	dc_unlock_disk_range(hook);
#endif

	if (resl == ST_OK) {
		hook->tail_len = 0;
		hook->tail_off = 0;
	} else {
		DbgMsg("dc_restore_part_end: error restoring partition end: %d\n", resl);
	}

	return resl;
}

/*
* Copy data between storage locations, handling overlapping ranges.
* src_off and dst_off are absolute disk offsets.
* Uses tmp_buff for chunked copy.
*/
static int dc_copy_storage_range(dev_hook *hook, u64 src_off, u64 dst_off, u32 length)
{
	u8 *buff = hook->tmp_buff;
	u32 done, chunk;
	int resl = ST_OK;
	int forward;

	if (length == 0 || src_off == dst_off) {
		return ST_OK;
	}

	/* Determine copy direction based on overlap:
	* - Forward copy (low to high) when dst < src or no overlap
	* - Backward copy (high to low) when dst > src and ranges overlap */
	forward = (dst_off < src_off) || (dst_off >= src_off + length);

	if (forward) {
		/* Forward copy: low to high addresses */
		for (done = 0; done < length; done += chunk)
		{
			chunk = min(length - done, ENC_BLOCK_SIZE);
			chunk = max((chunk / (u64)hook->bps) * (u64)hook->bps, hook->bps);

			resl = io_hook_rw(hook, buff, chunk, src_off + done, 1);
			if (resl != ST_OK) break;

			cp_fast_decrypt(buff, buff, chunk, src_off + done, hook->dsk_key);
			cp_fast_encrypt(buff, buff, chunk, dst_off + done, hook->dsk_key);

			resl = io_hook_rw(hook, buff, chunk, dst_off + done, 0);
			if (resl != ST_OK) break;
		}
	} else {
		/* Backward copy: high to low addresses */
		done = length;
		while (done > 0)
		{
			chunk = min(done, ENC_BLOCK_SIZE);
			chunk = max((chunk / (u64)hook->bps) * (u64)hook->bps, hook->bps);
			done -= chunk;

			resl = io_hook_rw(hook, buff, chunk, src_off + done, 1);
			if (resl != ST_OK) break;

			cp_fast_decrypt(buff, buff, chunk, src_off + done, hook->dsk_key);
			cp_fast_encrypt(buff, buff, chunk, dst_off + done, hook->dsk_key);

			resl = io_hook_rw(hook, buff, chunk, dst_off + done, 0);
			if (resl != ST_OK) break;
		}
	}

	return resl;
}

/*
* Resize header area by moving sectors between partition begin and storage.
* When expanding: save sectors [old_head_len..new_head_len) to storage
* When shrinking: restore sectors [new_head_len..old_head_len) from storage to partition
*/
static int dc_shrink_header(dev_hook *hook, u32 old_head_len, u32 new_head_len)
{
	u8 *buff = hook->tmp_buff;
	u32 move_len;
	u32 done, chunk;
	u64 part_off, stor_off;
	int resl = ST_OK;

	if (new_head_len >= old_head_len) {
		return ST_OK;
	}

	/* Restore sectors from storage to partition */
	move_len = old_head_len - new_head_len;
	part_off = new_head_len;
	stor_off = hook->stor_off + new_head_len;

#ifdef DC_CONCURRENT_TRANSCRYPT
	dc_lock_disk_range(hook, part_off, part_off + move_len);
#endif

	for (done = 0; done < move_len; done += chunk)
	{
		chunk = min(move_len - done, ENC_BLOCK_SIZE);
		chunk = max((chunk / (u64)hook->bps) * (u64)hook->bps, hook->bps);

		/* Read from storage */
		resl = io_hook_rw(hook, buff, chunk, stor_off + done, 1);
		if (resl != ST_OK) break;

		cp_fast_decrypt(buff, buff, chunk, stor_off + done, hook->dsk_key);
		cp_fast_encrypt(buff, buff, chunk, part_off + done, hook->dsk_key);

		/* Write to partition */
		resl = io_hook_rw(hook, buff, chunk, part_off + done, 0);
		if (resl != ST_OK) break;
	}

	if (resl == ST_OK) {
		hook->head_len = new_head_len;
	}

#ifdef DC_CONCURRENT_TRANSCRYPT
	dc_unlock_disk_range(hook);
#endif

	return resl;
}

static int dc_expand_header(dev_hook *hook, u32 old_head_len, u32 new_head_len)
{
	u8 *buff = hook->tmp_buff;
	u32 move_len;
	u32 done, chunk;
	u64 part_off, stor_off;
	int resl = ST_OK;

	if (new_head_len <= old_head_len) {
		return ST_OK;
	}

	/* Save sectors from partition to storage */
	move_len = new_head_len - old_head_len;
	part_off = old_head_len;
	stor_off = hook->stor_off + old_head_len;

#ifdef DC_CONCURRENT_TRANSCRYPT
	dc_lock_disk_range(hook, part_off, part_off + move_len);
#endif

	for (done = 0; done < move_len; done += chunk)
	{
		chunk = min(move_len - done, ENC_BLOCK_SIZE);
		chunk = max((chunk / (u64)hook->bps) * (u64)hook->bps, hook->bps);

		/* Read from partition */
		resl = io_hook_rw(hook, buff, chunk, part_off + done, 1);
		if (resl != ST_OK) break;

		cp_fast_decrypt(buff, buff, chunk, part_off + done, hook->dsk_key);
		cp_fast_encrypt(buff, buff, chunk, stor_off + done, hook->dsk_key);

		/* Write to storage */
		resl = io_hook_rw(hook, buff, chunk, stor_off + done, 0);
		if (resl != ST_OK) break;
	}

	if (resl == ST_OK) {
		hook->head_len = new_head_len;
	}

#ifdef DC_CONCURRENT_TRANSCRYPT
	dc_unlock_disk_range(hook);
#endif

	return resl;
}

int dc_write_header_safe(dev_hook *hook, u32 flags)
{
	dc_dev dev;
	int i;
	int resl = ST_IO_ERROR;

	DbgMsg("dc_write_header_safe, flags=%x\n", flags);

	/* no header write on a volume mounted with a damaged header (MF_IGNORE_CRC) */
	if (hook->mnt_flags & MF_IGNORE_CRC) {
		return ST_ACCESS_DENIED;
	}

	// check header for memory corruption, bugcheck if header invalid
	// and check encryption key for zeroed
	if (hook->tmp_header == NULL || is_volume_header_correct(hook->tmp_header) == FALSE || hook->hdr_key == NULL || hook->hdr_key->encrypt == NULL)
	{
		KeBugCheckEx(STATUS_DISK_CORRUPT_ERROR, __LINE__, 0, 0, 0);
	}

	dc_dev_of(hook, &dev);

	// write new header to disk (retry 10 times on error)
	for (i = 0; i < 10; i++) {
		if ((resl = io_write_header(&dev, dc_hook_rw, 0, hook->tmp_header, hook->hdr_key, NULL, flags, NULL)) == ST_OK) break;
		dc_delay(100);
	}

	// flush disk cache
	io_device_request(hook->orig_dev, IRP_MJ_FLUSH_BUFFERS, NULL, 0, 0);

	if (resl != ST_OK) {
		DbgMsg("dc_write_header_safe: header write failed after retries (%d)\n", resl);
	}
	return resl; /* layout steps must not write the backup over a header that is not on disk */
}

/*
 * Commit point of a layout step: flush the step's data moves first, so the disk cannot
 * persist the header before the data it describes (data flushed -> header -> flush).
 */
static int dc_layout_write_header(dev_hook *hook, u32 flags)
{
	io_device_request(hook->orig_dev, IRP_MJ_FLUSH_BUFFERS, NULL, 0, 0);
	hook->tmp_header->hdr_crc = calculate_header_crc(hook->tmp_header);
	return dc_write_header_safe(hook, flags);
}

/*
 * Write the backup header (physically at dsk_size - head_len) and flush. With a $dcsys$
 * file layout this overwrites the physical partition end, so it may only run after the
 * primary header that arms the tail redirect is on disk. The projection is refilled here
 * because the layout changes between the steps of dc_apply_layout.
 */
static int dc_layout_write_backup(dev_hook *hook, u8 *bak_key_slots, u32 bak_flags)
{
	dc_dev dev;
	int    resl;

	hook->tmp_header->hdr_crc = calculate_header_crc(hook->tmp_header);
	dc_dev_of(hook, &dev);
	resl = dc_update_backup(&dev, dc_hook_rw, hook->tmp_header, hook->bak_salt, hook->bak_key, bak_key_slots, bak_flags);
	io_device_request(hook->orig_dev, IRP_MJ_FLUSH_BUFFERS, NULL, 0, 0);
	return resl;
}

/*
 * Re-create the $dcsys$ tail redirect after hook->head_len was changed: move the OLD tail
 * back to the partition end, then copy the NEW tail (tail_len = head_len) to storage. The
 * caller flushes and writes the header. Until then the on-disk header still reads the right
 * data: both tail areas end at stor_off + stor_len, so partition offset dsk_size - x maps to
 * the same storage offset.
 * On failure:
 *  - F_HEAD_BACKUP still set: the old tail redirect is intact; the caller has to undo its
 *    head_len change so that the on-disk header matches again.
 *  - F_HEAD_BACKUP clear: the end is back in place but storing the new tail failed: the
 *    primary header is written here without VF_BACKUP_HEADER and with the new head_len
 *    (tmp_header must already carry it). If THAT write fails, *hdr_resl is set and
 *    ST_IO_ERROR is returned.
 */
static int dc_layout_move_tail(dev_hook *hook, int *hdr_resl)
{
	int resl;

	/* the new tail area must not overlap the head copy; check before anything moves */
	if (hook->stor_len < hook->head_len * 2) {
		return ST_NF_SPACE;
	}

	resl = dc_restore_part_end(hook, TRUE);
	if (resl != ST_OK) {
		return resl;
	}

	resl = dc_store_part_end(hook, TRUE);
	if (resl != ST_OK) {
		DbgMsg("dc_layout_move_tail: failed to store new partition end (%d), dropping backup header\n", resl);
		hook->tmp_header->flags &= ~VF_BACKUP_HEADER;
		if (dc_layout_write_header(hook, HF_DEFAULT) != ST_OK) {
			/* the on-disk header still claims the old head_len and the undone tail
			 * redirect: report a header failure, not the (recoverable) store error */
			DbgMsg("dc_layout_move_tail: header write without backup failed\n");
			*hdr_resl = ST_IO_ERROR;
			resl = ST_IO_ERROR;
		}
	}
	return resl;
}

/* commit of a layout step: primary header (base region), then the backup header - never
 * ahead of a failed primary header write (*hdr_resl is sticky) */
static void dc_layout_commit(dev_hook *hook, int *hdr_resl, u8 *bak_key_slots, u32 bak_flags)
{
	if (dc_layout_write_header(hook, HF_UPDATE_BASE) != ST_OK) *hdr_resl = ST_IO_ERROR;
	if ((hook->flags & F_HEAD_BACKUP) && *hdr_resl == ST_OK) {
		dc_layout_write_backup(hook, bak_key_slots, bak_flags);
	}
}

/*
 * dc_layout_move_tail failed (move_resl) after the header area was resized from
 * old_head_len to new_head_len (shrunk: TRUE for a shrink, FALSE for an expand) and
 * crypt.head_len / tmp_header->head_len were updated. Returns the result of the step.
 */
static int dc_layout_move_tail_failed(dev_hook *hook, int move_resl, int *hdr_resl, BOOLEAN shrunk,
	u32 old_head_len, u32 new_head_len, u32 old_crypt_head_len, u8 *bak_key_slots, u32 bak_flags)
{
	BOOLEAN settled = TRUE; /* in-memory layout is describable by one header */
	int     resl = move_resl;

	if (hook->flags & F_HEAD_BACKUP) {
		/* old tail redirect still active: undo the head resize so the unchanged
		 * on-disk header (old head_len) describes the layout again */
		int undo = shrunk ? dc_expand_header(hook, new_head_len, old_head_len)
		                  : dc_shrink_header(hook, new_head_len, old_head_len);

		if (undo == ST_OK) {
			hook->crypt.head_len = old_crypt_head_len;
			if (hook->tmp_header->version >= DC_HDR_VERSION_2) {
				hook->tmp_header->head_len = old_crypt_head_len;
			}
			/* a partial restore may have overwritten the old backup header;
			 * rewrite it - but never ahead of a primary header write that failed */
			if (*hdr_resl == ST_OK) {
				dc_layout_write_backup(hook, bak_key_slots, bak_flags);
			}
		} else {
			DbgMsg("dc_apply_layout: failed to undo header %s\n", shrunk ? "shrink" : "expand");
			settled = FALSE; /* head new, tail old: no header describes it, write nothing */
		}
	}
	/* A primary header write failed: the on-disk header is stale and the caller's break skips
	 * the final header write, so retry it once here for the settled in-memory layout; the
	 * backup header only after that header is on disk. */
	if (*hdr_resl != ST_OK && settled) {
		if (dc_layout_write_header(hook, HF_DEFAULT) == ST_OK) {
			if (hook->flags & F_HEAD_BACKUP) {
				dc_layout_write_backup(hook, bak_key_slots, bak_flags);
			}
		} else {
			DbgMsg("dc_apply_layout: header retry after tail move failure failed\n");
		}
	}
	if (*hdr_resl != ST_OK) {
		resl = ST_IO_ERROR;
	}
	/* else: dc_layout_move_tail wrote the header without backup (F_HEAD_BACKUP clear),
	 * or the undo restored the old layout the on-disk header describes */
	return resl;
}

static int dc_apply_layout(dev_hook *hook, u32 type)
{
	/*
	 * Every step follows the same order: data in place and flushed -> primary header that
	 * refers to it (dc_layout_write_header) -> only then the backup header
	 * (dc_layout_write_backup; with a $dcsys$ file it overwrites the physical partition end)
	 * -> flush. A step that fails after it changed on-disk data leaves a header that
	 * describes the layout the data is actually in.
	 */
	u32 head_len;
	u32 stor_len;
	int resl = ST_OK;
	int add_resl = ST_OK; /* result of adding a backup header */
	int hdr_resl = ST_OK; /* sticky: a primary header write failed */
	/* S_REMOVE_BACKUP scrub owed to the final header write (the removal's own header write
	 * failed); position and the storage it lies in, as they were at the removal */
	u64 scrub_pos = 0, scrub_stor_off = 0, scrub_stor_len = 0;
	u32 scrub_len = 0;
	u8 *bak_key_slots = NULL;
	u32 bak_flags = HF_DEFAULT;

	do
	{
#ifdef DC_CONCURRENT_TRANSCRYPT
		dc_hook_set_flags(hook, F_SYNC); /* atomic: may overlap power/IOCTL flag writers */
		KeMemoryBarrier();
		dc_drain_untracked_io(hook); /* I/O admitted before F_SYNC, then flush */
		io_device_request(hook->orig_dev, IRP_MJ_FLUSH_BUFFERS, NULL, 0, 0);
#endif

		// cache todo and restore current v2 layout
		if (hook->tmp_header->version >= DC_HDR_VERSION_2) {
			head_len = hook->tmp_header->head_len;
			stor_len = hook->tmp_header->stor_len;

			hook->tmp_header->head_len = hook->crypt.head_len;
			hook->tmp_header->stor_len = hook->stor_len;
		}
		else { // v1
			head_len = DC_AREA_SIZE;
			stor_len = ROUND_TO_FULL_SECTORS(head_len, hook->bps);
		}
		
		/* Pre-read backup key slots from OLD position before any layout changes.
		 * This is critical when header size changes since the backup position will shift. */
		if (hook->tmp_header->version >= DC_HDR_VERSION_2 && (hook->tmp_header->feature_flags & FF_KEY_SLOTS) && hook->tmp_header->slot_area_len > 0)
		{
			if ((hook->flags & F_HEAD_BACKUP) && !(type & S_REMOVE_BACKUP)) // has backup and not removing it
			{
				u8* old_backup_raw;

				if ((bak_key_slots = mm_secure_alloc(hook->tmp_header->slot_area_len)) == NULL) {
					resl = ST_NOMEM;
					break;
				}

				/* Read old backup header from OLD position (before header size change) */
				if ((old_backup_raw = mm_secure_alloc(hook->head_len)) == NULL) {
					resl = ST_NOMEM;
					break;
				}
				resl = io_hook_rw(hook, old_backup_raw, hook->head_len, hook->dsk_size - hook->head_len, 1);
				if (resl == ST_OK) {
					if ((u32)DC_BASE_SIZE + hook->tmp_header->slot_area_len <= hook->head_len) {
						/* Extract key slots from old backup header */
						memcpy(bak_key_slots, old_backup_raw + DC_BASE_SIZE, hook->tmp_header->slot_area_len);
					}
					else {
						DbgMsg("dc_apply_layout: old backup header too small to contain key slots, old_head_len=%u, required=%u\n", hook->head_len, DC_BASE_SIZE + hook->tmp_header->slot_area_len);
						resl = ST_NOT_BACKUP;
					}
				}
				else {
					DbgMsg("dc_apply_layout: failed to read old backup key slots from pos %I64u\n", hook->dsk_size - hook->head_len);
				}
				mm_secure_free(old_backup_raw);
				if (resl != ST_OK) {
					break;
				}
			}
			else if ((type & S_BACKUP_HEADER) && !(hook->flags & F_HEAD_BACKUP)) // adding and has no backup
			{
				/* clear backup key slots */
				bak_flags = HF_CLEAR_SLOTS;
			}
		}

		// remove backup
		if ((type & S_REMOVE_BACKUP) && (hook->flags & F_HEAD_BACKUP)) {
			BOOLEAN scrub_bak = FALSE;

			DbgMsg("dc_apply_layout: removing backup header\n");
			if (!IS_STORAGE_ON_END(hook->flags)) {
				/* $dcsys$ storage file: the backup header occupies the partition end in place
				 * and the original end sectors live in storage at tail_off - move them back
				 * (this also overwrites the backup header). */
				resl = dc_restore_part_end(hook, TRUE);
				if (resl != ST_OK) {
					/* tail redirect is kept on failure - don't clear VF_BACKUP_HEADER on disk */
					DbgMsg("dc_apply_layout: failed to restore partition end\n");
					break;
				}
			} else {
				/* storage in the slack: no user data was moved, only the flag has to go; the
				 * old backup header is scrubbed below */
				scrub_bak = TRUE;
				dc_hook_clear_flags(hook, F_HEAD_BACKUP);
			}
			/* partition end restored (above) -> flush -> header without backup */
			hook->tmp_header->flags &= ~VF_BACKUP_HEADER;
			if (dc_layout_write_header(hook, HF_UPDATE_BASE) != ST_OK) {
				hdr_resl = ST_IO_ERROR;
				if (scrub_bak) {
					/* nothing else would scrub it after a successful final header write -
					 * owe it */
					scrub_pos      = hook->dsk_size - hook->head_len;
					scrub_len      = hook->head_len;
					scrub_stor_off = hook->stor_off;
					scrub_stor_len = hook->stor_len;
				}
			} else if (scrub_bak) {
				/* Scrub the old backup header so a valid header with the old key slots does not
				 * stay on disk; never touch the partition-begin copy. Only after the primary
				 * without VF_BACKUP_HEADER is written: until then the backup is the fallback. */
				u64 bak_pos = hook->dsk_size - hook->head_len;

				if (bak_pos >= hook->stor_off + hook->head_len) {
					/* chunked: head_len can exceed tmp_buff (ENC_BLOCK_SIZE) */
					if (dc_scrub_raw(hook, bak_pos, hook->head_len) != ST_OK) {
						DbgMsg("dc_apply_layout: failed to scrub old backup header\n");
					}
				}
			}
		}

		// shrink header
		/* compared with crypt.head_len (like the expand below): for a v1 downgrade
		 * tmp_header->head_len is 0, and the final v1 header claims DC_AREA_SIZE */
		if ((type & S_RESIZE_HEADER) && head_len < hook->crypt.head_len)
		{
			u32 new_head_len = ROUND_TO_FULL_SECTORS(head_len, hook->bps);
			u32 old_head_len = hook->head_len;
			u32 old_crypt_head_len = hook->crypt.head_len;

			DbgMsg("dc_apply_layout: shrinking header from %u to %u bytes\n", old_head_len, new_head_len);

			resl = dc_shrink_header(hook, old_head_len, new_head_len);
			if (resl != ST_OK) {
				DbgMsg("dc_apply_layout: failed to shrink header\n");
				break;
			}

			/* Update header fields (in memory; written below once the tail is in place) */
			hook->crypt.head_len = head_len;
			if (hook->tmp_header->version >= DC_HDR_VERSION_2) {
				hook->tmp_header->head_len = head_len;
			}

			/* with a $dcsys$ file + backup the tail redirect length follows head_len. Move
			 * the tail BEFORE publishing the new head_len: restore old tail -> store new
			 * tail -> flush -> primary header -> backup header (below). */
			if ((hook->flags & F_HEAD_BACKUP) && !IS_STORAGE_ON_END(hook->flags)) {
				resl = dc_layout_move_tail(hook, &hdr_resl);
				if (resl != ST_OK) {
					DbgMsg("dc_apply_layout: failed to move partition end after shrink (%d)\n", resl);
					resl = dc_layout_move_tail_failed(hook, resl, &hdr_resl, TRUE, old_head_len, new_head_len,
					                                  old_crypt_head_len, bak_key_slots, bak_flags);
					break;
				}
			}

			/* primary header, then the backup header with the pre-read key slots */
			dc_layout_commit(hook, &hdr_resl, bak_key_slots, bak_flags);
		}

		if (type & S_STORAGE_TO_FILE)
		{
			if (!IS_STORAGE_ON_END(hook->flags))
			{
				DbgMsg("dc_apply_layout: storage already in file, resizing from %u to %u bytes\n", hook->stor_len, stor_len);

				/* Simple case: storage already in file, resize it */
				u64 old_stor_off = hook->stor_off;
				u32 old_stor_len = hook->stor_len;
				u64 new_stor_off;
				u32 new_stor_len = stor_len;
				u32 head_margin, back_margin, margin;

				/* Calculate margin: max of old and new for both header and backup */
				head_margin = max(hook->head_len, head_len);
				back_margin = (hook->flags & F_HEAD_BACKUP) ? max(hook->tail_len, head_len) : 0;
				margin = max(head_margin, back_margin);

				/* A failed undo can leave the tail redirect pointing outside the current
				 * storage file. Step 4 copies the tail from tail_off, which must lie inside
				 * the file renamed to $dcbak$; refuse before renaming or deleting anything. */
				if ((hook->flags & F_HEAD_BACKUP) && hook->tail_len != 0 &&
					(hook->tail_off < old_stor_off ||
					 hook->tail_off + hook->tail_len > old_stor_off + old_stor_len)) {
					DbgMsg("dc_apply_layout: tail_off %I64u outside storage [%I64u, +%u), refusing resize\n", hook->tail_off, old_stor_off, old_stor_len);
					resl = ST_ERROR;
					break;
				}

				/* Step 1: Rename old storage file */
				dc_delete_storage_by_name(hook, L"$dcbak$");
				resl = dc_rename_storage(hook, L"$dcsys$", L"$dcbak$");
				if (resl != ST_OK) break;

				/* Step 2: Create new storage file */
				resl = dc_create_storage(hook, &new_stor_off, &new_stor_len, margin);
				if (resl != ST_OK) {
					dc_rename_storage(hook, L"$dcbak$", L"$dcsys$"); /* rollback */
					break;
				}

				/* Step 3: Copy partition begin backup to new storage */
#ifdef DC_CONCURRENT_TRANSCRYPT
				dc_lock_disk_range(hook, 0, hook->head_len);
#endif
				resl = dc_copy_storage_range(hook, old_stor_off, new_stor_off, hook->head_len);
				if (resl == ST_OK) {
					hook->stor_off = new_stor_off;
					hook->stor_len = new_stor_len;
				}
#ifdef DC_CONCURRENT_TRANSCRYPT
				dc_unlock_disk_range(hook);
#endif
				if (resl != ST_OK) {
					dc_delete_storage(hook);
					dc_rename_storage(hook, L"$dcbak$", L"$dcsys$"); /* rollback */
					break;
				}

				/* Step 4: Copy backup area if enabled.
				 * Lock the volume tail like step 3 locks the head: a concurrent FS write
				 * redirected to the old tail_off during the copy would be lost with $dcbak$. */
				if ((hook->flags & F_HEAD_BACKUP) && hook->tail_len != 0) {
					/* source is where the redirect actually points (checked above) */
					u64 old_tail_off = hook->tail_off;
					u64 new_tail_off = new_stor_off + new_stor_len - hook->tail_len;

#ifdef DC_CONCURRENT_TRANSCRYPT
					dc_lock_disk_range(hook, hook->dsk_size - hook->tail_len, hook->dsk_size);
#endif
					resl = dc_copy_storage_range(hook, old_tail_off, new_tail_off, hook->tail_len);
					if (resl == ST_OK) {
						hook->tail_off = new_tail_off;
					}
#ifdef DC_CONCURRENT_TRANSCRYPT
					dc_unlock_disk_range(hook);
#endif
					if (resl != ST_OK) {
						DbgMsg("dc_apply_layout: failed to copy backup area\n");
						/* The on-disk header and the tail redirect still point to the old
						 * storage (now $dcbak$), but the head already moved in step 3. Undo
						 * step 3 (under the head lock, keeping writes since) and roll the files
						 * back, so that hook state and on-disk header agree again. */
#ifdef DC_CONCURRENT_TRANSCRYPT
						dc_lock_disk_range(hook, 0, hook->head_len);
#endif
						int undo_resl = dc_copy_storage_range(hook, new_stor_off, old_stor_off, hook->head_len);
						if (undo_resl == ST_OK) {
							hook->stor_off = old_stor_off;
							hook->stor_len = old_stor_len;
						}
#ifdef DC_CONCURRENT_TRANSCRYPT
						dc_unlock_disk_range(hook);
#endif
						if (undo_resl == ST_OK) {
							dc_delete_storage(hook);
							dc_rename_storage(hook, L"$dcbak$", L"$dcsys$"); /* rollback */
						} else {
							/* keep both files: the head lives in the new one, the tail in $dcbak$ */
							DbgMsg("dc_apply_layout: failed to undo storage head move\n");
						}
						break;
					}
				}

				/* Update header: head and tail copies in the new file -> flush -> header -> backup */
				hook->tmp_header->stor_off = hook->stor_off;
				if (hook->tmp_header->version >= DC_HDR_VERSION_2) {
					hook->tmp_header->stor_len = hook->stor_len;
				}
				dc_layout_commit(hook, &hdr_resl, bak_key_slots, bak_flags);

				/* Step 5: Delete old storage file - only once the header that no longer
				 * refers to it is on disk. Otherwise the final header write retries; a
				 * kept $dcbak$ is removed by the next resize (step 1). */
				if (hdr_resl == ST_OK) {
					dc_delete_storage_by_name(hook, L"$dcbak$");
				} else {
					DbgMsg("dc_apply_layout: header write failed, keeping $dcbak$\n");
				}
			}
			else
			{
				DbgMsg("dc_apply_layout: moving storage from partition end to file, new size %u old size %u\n", stor_len, hook->stor_len);

				/* Complex case: move storage from partition end to file */
				u64 old_stor_off = hook->stor_off;
				u32 old_stor_len = hook->stor_len;
				u64 new_stor_off;
				u32 new_stor_len = stor_len;
				u32 head_margin, back_margin, margin;
				u64 slack_reclaim;
				BOOLEAN had_backup = (hook->flags & F_HEAD_BACKUP) != 0;

				/* Calculate margin: max of old and new for header, old backup if any */
				head_margin = max(hook->head_len, head_len);
				back_margin = (hook->flags & F_HEAD_BACKUP) ? hook->tail_len : 0;
				margin = max(head_margin, back_margin);

				/* Create new storage file */
				resl = dc_create_storage(hook, &new_stor_off, &new_stor_len, margin);
				if (resl != ST_OK) break;

				/* Copy partition begin backup to new storage file */
#ifdef DC_CONCURRENT_TRANSCRYPT
				dc_lock_disk_range(hook, 0, hook->head_len);
#endif
				resl = dc_copy_storage_range(hook, old_stor_off, new_stor_off, hook->head_len);
				if (resl == ST_OK) {
					hook->stor_off = new_stor_off;
					hook->stor_len = new_stor_len;
					dc_hook_set_flags(hook, F_PROTECT_DCSYS);
					hook->use_size = hook->dsk_size;
					/* The slack backup header is dropped with the slack: drop F_HEAD_BACKUP
					 * too, so the hook never claims a file-layout backup without a tail
					 * redirect. dc_store_part_end sets it again when the backup is re-created. */
					dc_hook_clear_flags(hook, F_HEAD_BACKUP);
				}
#ifdef DC_CONCURRENT_TRANSCRYPT
				dc_unlock_disk_range(hook);
#endif
				if (resl != ST_OK) {
					dc_delete_storage(hook);
					break;
				}

				/* Update header - clear backup flag temporarily, storage now in file */
				hook->tmp_header->flags &= ~VF_BACKUP_HEADER;
				hook->tmp_header->flags |= VF_STORAGE_FILE;
				hook->tmp_header->stor_off = hook->stor_off;
				if (hook->tmp_header->version >= DC_HDR_VERSION_2) {
					hook->tmp_header->stor_len = hook->stor_len;
				}
				if (dc_layout_write_header(hook, HF_UPDATE_BASE) != ST_OK) hdr_resl = ST_IO_ERROR;

				/* The old slack holds the partition-begin copy the old on-disk header refers
				 * to: give it to the file system (irreversible) and re-create the backup only
				 * once the header pointing to the new file is on disk. */
				if (hdr_resl != ST_OK) {
					DbgMsg("dc_apply_layout: header write failed, slack not reclaimed, backup not re-created\n");
				} else {
					/* Reclaim slack space by expanding filesystem */
					slack_reclaim = old_stor_len;
					hook->wrk_thread_id = PsGetCurrentThreadId();
					dc_try_expand_fs(hook, slack_reclaim); /* ignore failure */
					hook->wrk_thread_id = 0;
				}

				/* Re-create backup at partition end if enabled.
				 * Store partition end -> flush -> primary header with VF_BACKUP_HEADER
				 * -> only then overwrite the physical end with the backup header.
				 * If storing fails, the header above (no backup) stays valid: report it. */
				if (had_backup && hdr_resl == ST_OK) {
					resl = dc_store_part_end(hook, TRUE);
					if (resl != ST_OK) {
						DbgMsg("dc_apply_layout: failed to re-create backup header after moving storage to file\n");
						break;
					}
					hook->tmp_header->flags |= VF_BACKUP_HEADER;
					if (dc_layout_write_header(hook, HF_UPDATE_BASE) == ST_OK) {
						dc_layout_write_backup(hook, bak_key_slots, bak_flags);
					} else {
						/* the header arming the tail redirect is not on disk: undo the
						 * redirect before anything could overwrite the physical end */
						hdr_resl = ST_IO_ERROR;
						if (dc_restore_part_end(hook, TRUE) == ST_OK) {
							hook->tmp_header->flags &= ~VF_BACKUP_HEADER;
						} else {
							/* the redirect stays armed (by design, storage is authoritative):
							 * keep VF_BACKUP_HEADER so the header (final write) describes it */
							DbgMsg("dc_apply_layout: failed to undo tail redirect after header write error\n");
						}
					}
				}
			}
		}
		else if (type & S_STORAGE_TO_END)
		{
			if (IS_STORAGE_ON_END(hook->flags))
			{
				DbgMsg("dc_apply_layout: storage already at partition end, resizing from %u to %u bytes\n", hook->stor_len, stor_len);

				/* Simple case: storage already at partition end, resize it */
				u64 old_stor_off = hook->stor_off;
				u32 old_stor_len = hook->stor_len;
				u64 new_stor_off = hook->dsk_size - stor_len;
				u32 copy_len;
				u64 slack_size;
				int expanding = (stor_len > old_stor_len);

				/* If expanding, check/create slack space.
				 * dc_get_volume_slack returns ALL space behind the file system, which already
				 * contains the current storage, so the new storage needs total slack >= stor_len
				 * (not the growth delta). Re-checked after shrinking (it may fall short). */
				if (expanding) {
					resl = dc_get_volume_slack(hook, &slack_size);
					if (resl != ST_OK || slack_size < stor_len) {
						u64 need = stor_len - (resl == ST_OK ? slack_size : 0);
						hook->wrk_thread_id = PsGetCurrentThreadId();
						resl = dc_try_shrink_fs(hook, need);
						hook->wrk_thread_id = 0;
						if (resl != ST_OK ||
							dc_get_volume_slack(hook, &slack_size) != ST_OK || slack_size < stor_len) {
							DbgMsg("dc_apply_layout: not enough slack for %u bytes of storage at partition end\n", stor_len);
							resl = ST_SHRINK_FAILED;
							break;
						}
					}
				}

				/* Copy partition begin backup to new location (dc_copy_storage_range picks the
				 * safe direction for overlapping ranges: forward when growing, dst < src) */
				copy_len = hook->head_len;
#ifdef DC_CONCURRENT_TRANSCRYPT
				dc_lock_disk_range(hook, 0, hook->head_len);
#endif
				resl = dc_copy_storage_range(hook, old_stor_off, new_stor_off, copy_len);
				if (resl == ST_OK) {
					hook->stor_off = new_stor_off;
					hook->stor_len = stor_len;
					hook->use_size = hook->dsk_size - hook->stor_len;
				}
#ifdef DC_CONCURRENT_TRANSCRYPT
				dc_unlock_disk_range(hook);
#endif
				if (resl != ST_OK) {
					DbgMsg("dc_apply_layout: failed to move storage to partition end\n");
					break;
				}

				/* Update header: head copy moved -> flush -> header -> backup */
				hook->tmp_header->stor_off = hook->stor_off;
				if (hook->tmp_header->version >= DC_HDR_VERSION_2) {
					hook->tmp_header->stor_len = hook->stor_len;
				}
				dc_layout_commit(hook, &hdr_resl, bak_key_slots, bak_flags);

				/* If shrinking, reclaim slack space - not while the on-disk header (old
				 * stor_off) may still refer to the area given away (final write retries) */
				if (!expanding && hdr_resl == ST_OK) {
					hook->wrk_thread_id = PsGetCurrentThreadId();
					resl = dc_try_expand_fs(hook, old_stor_len - stor_len);
					hook->wrk_thread_id = 0;
					if (resl != ST_OK) {
						DbgMsg("dc_apply_layout: failed to reclaim slack space after shrinking storage\n");
						/* Not critical, just continue */
					}
				}
			}
			else
			{
				DbgMsg("dc_apply_layout: moving storage from file to partition end with new size %u bytes, old size %u bytes\n", stor_len, hook->stor_len);

				/* Complex case: move storage from file to partition end */
				u64 old_stor_off = hook->stor_off;
				u64 new_stor_off;
				u64 slack_size;

				/* Check/create slack space at partition end */
				resl = dc_get_volume_slack(hook, &slack_size);
				if (resl != ST_OK || slack_size < stor_len) {
					u64 need = stor_len - (resl == ST_OK ? slack_size : 0);
					hook->wrk_thread_id = PsGetCurrentThreadId();
					resl = dc_try_shrink_fs(hook, need);
					hook->wrk_thread_id = 0;
					/* verify the shrink actually produced enough slack */
					if (resl != ST_OK ||
						dc_get_volume_slack(hook, &slack_size) != ST_OK || slack_size < stor_len) {
						DbgMsg("dc_apply_layout: not enough slack for %u bytes of storage at partition end\n", stor_len);
						resl = ST_SHRINK_FAILED;
						break;
					}
				}

				new_stor_off = hook->dsk_size - stor_len;

				/* Copy partition begin backup to partition end */
#ifdef DC_CONCURRENT_TRANSCRYPT
				dc_lock_disk_range(hook, 0, hook->head_len);
#endif
				resl = dc_copy_storage_range(hook, old_stor_off, new_stor_off, hook->head_len);
				if (resl == ST_OK) {
					hook->stor_off = new_stor_off;
					hook->stor_len = stor_len;
					hook->use_size = hook->dsk_size - hook->stor_len;
					dc_hook_clear_flags(hook, F_PROTECT_DCSYS);
					if (hook->flags & F_HEAD_BACKUP) {
						hook->tail_len = 0;
						hook->tail_off = 0;
					}
				}
#ifdef DC_CONCURRENT_TRANSCRYPT
				dc_unlock_disk_range(hook);
#endif
				if (resl != ST_OK) {
					DbgMsg("dc_apply_layout: failed to move storage to partition end\n");
					break;
				}

				/* Update header - storage now at partition end, not in file */
				hook->tmp_header->flags &= ~VF_STORAGE_FILE;
				hook->tmp_header->stor_off = hook->stor_off;
				if (hook->tmp_header->version >= DC_HDR_VERSION_2) {
					hook->tmp_header->stor_len = hook->stor_len;
				}
				/* head copy at the partition end -> flush -> header -> backup (in the slack) */
				dc_layout_commit(hook, &hdr_resl, bak_key_slots, bak_flags);

				/* Delete old storage file - only once the header that no longer refers to
				 * it is on disk (otherwise the final header write retries) */
				if (hdr_resl == ST_OK) {
					dc_delete_storage(hook);
				} else {
					DbgMsg("dc_apply_layout: header write failed, keeping old storage file\n");
				}
			}
		}

		/* Expand header */
		if ((type & S_RESIZE_HEADER) && head_len > hook->crypt.head_len)
		{
			u32 old_head_len = hook->head_len;
			u32 new_head_len = ROUND_TO_FULL_SECTORS(head_len, hook->bps);
			u32 old_crypt_head_len = hook->crypt.head_len;

			DbgMsg("dc_apply_layout: expanding header from %u to %u bytes\n", old_head_len, new_head_len);

			/* The grown head copy must fit into the storage and, with a backup, must not reach
			 * the tail/backup area at its end. Checked before anything moves. */
			if (hook->stor_len < new_head_len * ((hook->flags & F_HEAD_BACKUP) ? 2 : 1)) {
				DbgMsg("dc_apply_layout: storage too small (%u) for header of %u bytes\n", hook->stor_len, new_head_len);
				resl = ST_NF_SPACE;
				break;
			}
			/* a $dcsys$ file must lie past the grown head area and, with a backup,
			 * before the grown partition-end area (dc_update_layout recreates a file that
			 * does not fit; this is the backstop) */
			if ( (hook->flags & F_PROTECT_DCSYS) && !IS_STORAGE_ON_END(hook->flags) &&
				 ( hook->stor_off < new_head_len ||
				   ((hook->flags & F_HEAD_BACKUP) &&
				    ((u64)new_head_len >= hook->dsk_size || hook->stor_off + hook->stor_len > hook->dsk_size - new_head_len)) ) )
			{
				DbgMsg("dc_apply_layout: $dcsys$ [%I64u, +%u) overlaps the grown head / backup area (%u)\n",
					hook->stor_off, hook->stor_len, new_head_len);
				resl = ST_NF_SPACE;
				break;
			}

			resl = dc_expand_header(hook, old_head_len, new_head_len);
			if (resl != ST_OK) {
				DbgMsg("dc_apply_layout: failed to expand header\n");
				break;
			}

			/* Update header fields (in memory; written below once the tail is in place) */
			hook->crypt.head_len = head_len;
			if (hook->tmp_header->version >= DC_HDR_VERSION_2) {
				hook->tmp_header->head_len = head_len;
			}

			/* mirror image of the shrink - store the larger tail before the new head_len is
			 * published */
			if ((hook->flags & F_HEAD_BACKUP) && !IS_STORAGE_ON_END(hook->flags)) {
				resl = dc_layout_move_tail(hook, &hdr_resl);
				if (resl != ST_OK) {
					DbgMsg("dc_apply_layout: failed to move partition end after expand (%d)\n", resl);
					resl = dc_layout_move_tail_failed(hook, resl, &hdr_resl, FALSE, old_head_len, new_head_len,
					                                  old_crypt_head_len, bak_key_slots, bak_flags);
					break;
				}
			}

			/* primary header, then the backup header with the pre-read key slots */
			dc_layout_commit(hook, &hdr_resl, bak_key_slots, bak_flags);
		}

		/* Add new backup header */
		if ((type & S_BACKUP_HEADER) && !(hook->flags & F_HEAD_BACKUP)) {
			DbgMsg("dc_apply_layout: adding backup header\n");
			if (!IS_STORAGE_ON_END(hook->flags) &&
				(hook->head_len >= hook->dsk_size || hook->stor_off + hook->stor_len > hook->dsk_size - hook->head_len))
			{
				/* the $dcsys$ file reaches into the partition-end area the backup header
				 * and the tail redirect would take (dc_update_layout recreates such a file,
				 * this is the backstop) */
				DbgMsg("dc_apply_layout: $dcsys$ [%I64u, +%u) overlaps the backup header area\n", hook->stor_off, hook->stor_len);
				resl = ST_NF_SPACE;
			}
			else if (!IS_STORAGE_ON_END(hook->flags)) { // backup at partition end not in slack space
				/* the backup header overwrites the physical partition end, so: copy the end
				 * to storage (arms the tail redirect) -> flush -> primary header with
				 * VF_BACKUP_HEADER -> backup header -> flush. A crash before the primary
				 * header mounts without the redirect and the end is untouched; a failed
				 * backup write after it leaves consistent data, only the backup invalid. */
				resl = dc_store_part_end(hook, TRUE);
				if (resl == ST_OK) {
					hook->tmp_header->flags |= VF_BACKUP_HEADER;
					if (dc_layout_write_header(hook, HF_UPDATE_BASE) == ST_OK) {
						resl = dc_layout_write_backup(hook, bak_key_slots, bak_flags);
					} else {
						/* header with the redirect not on disk: undo the redirect, never
						 * overwrite the physical end with the backup header */
						resl = hdr_resl = ST_IO_ERROR;
						if (dc_restore_part_end(hook, TRUE) == ST_OK) {
							hook->tmp_header->flags &= ~VF_BACKUP_HEADER;
						} else {
							/* the redirect stays armed (by design, storage is authoritative):
							 * keep VF_BACKUP_HEADER so the header (final write) describes it */
							DbgMsg("dc_apply_layout: failed to undo tail redirect after header write error\n");
						}
					}
				}
			} else {
				/* Storage in the slack: no data moves, the backup header goes into the
				 * storage area. Write it first, then the primary header (final write below)
				 * refers to it; on failure neither the hook nor the header claims it. */
				if (hook->stor_len < hook->head_len * 2) {
					resl = ST_NF_SPACE;
				} else {
					dc_hook_set_flags(hook, F_HEAD_BACKUP); /* dc_update_backup requires it */
					hook->tmp_header->flags |= VF_BACKUP_HEADER;
					resl = dc_layout_write_backup(hook, bak_key_slots, bak_flags);
					if (resl != ST_OK) {
						dc_hook_clear_flags(hook, F_HEAD_BACKUP);
						hook->tmp_header->flags &= ~VF_BACKUP_HEADER;
					}
				}
			}
			if (resl != ST_OK) {
				DbgMsg("Failed to backup header, error %d\n", resl);
				add_resl = resl;
			}
		}

		/* full header write; on an add-backup failure it describes the layout without
		 * (or, after a failed backup write on a $dcsys$ layout, with an invalid) backup */
		if (dc_layout_write_header(hook, HF_DEFAULT) != ST_OK) {
			hdr_resl = ST_IO_ERROR;
		} else {
			if (hdr_resl != ST_OK && (hook->flags & F_HEAD_BACKUP)) {
				/* an earlier primary header write failed, so the backup writes gated on it were
				 * skipped. The header now on disk describes the current layout: write the
				 * backup once. The earlier failure is still reported below. */
				if (dc_layout_write_backup(hook, bak_key_slots, bak_flags) != ST_OK) {
					DbgMsg("dc_apply_layout: deferred backup header write failed\n");
				}
			}
			/* the removal's owed scrub, now that the primary without the backup is on disk.
			 * Only while the storage it lies in is unchanged (a move / shrink may have given
			 * it to the file system) and it lies past the (maybe resized) head copy. */
			if (scrub_len != 0 && hook->stor_off == scrub_stor_off && hook->stor_len == scrub_stor_len &&
				IS_STORAGE_ON_END(hook->flags) && scrub_pos >= hook->stor_off + hook->head_len &&
				scrub_pos + scrub_len <= hook->dsk_size)
			{
				if (dc_scrub_raw(hook, scrub_pos, scrub_len) != ST_OK) {
					DbgMsg("dc_apply_layout: deferred scrub of the old backup header failed\n");
				}
				io_device_request(hook->orig_dev, IRP_MJ_FLUSH_BUFFERS, NULL, 0, 0);
			}
		}

		if (hdr_resl != ST_OK) {
			/* a primary header write failed: no backup was written after it; report it */
			resl = hdr_resl;
			break;
		}
		if (add_resl != ST_OK) {
			/* report the failed backup instead of claiming success (resl itself may
			 * hold an ignored non-critical error, e.g. from dc_try_expand_fs) */
			resl = add_resl;
			break;
		}

		DbgMsg("dc_apply_layout: finished successfully, device: %S, new head_len=%d, stor_len=%d, hook->flags=0x%X, header->flags=0x%X\n", hook->dev_name, hook->head_len, hook->stor_len, hook->flags, hook->tmp_header->flags);

		resl = ST_FINISHED;
	} while (0);

	if (bak_key_slots != NULL) {
		mm_secure_free(bak_key_slots);
	}

	return resl;
}

int dc_update_layout(wchar_t *dev_name, dc_pass *password, crypt_info *crypt, u32 flags, ULONG *interrupt_cmd)
{
	dc_header *header = NULL;
	dc_dev     dev;
	dev_hook  *hook;
	xts_key   *hdr_key = NULL;
	u32	       head_len;
	u32	       stor_len;
	int        resl;
	dc_header *hback = NULL;
	u8        *bak_salt = NULL;
	xts_key   *bak_key = NULL;
	int        sel_kdf = password->kdf;
	int        found_kdf = -1;

	DbgMsg("dc_update_layout\n");

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		if (!(dc_load_flags & DST_PRO_ENABLED)) {
			/* busy_lock is not held yet - drop the reference here and keep the
			 * cleanup from releasing a mutex this thread does not own */
			dc_deref_hook(hook); hook = NULL;
			resl = ST_NOT_PRO; break;
		}

		wait_object_infinity(&hook->busy_lock);

		/* Volume must be mounted and not in sync mode (nor locked).
		 * Nor F_NO_REDIRECT: such a volume has no storage and its I/O is shifted by head_len -
		 * a header resize would move the whole volume, a backup header would redirect the
		 * partition end over the header at offset 0. */
		if ( !(hook->flags & F_ENABLED) ||
			  (hook->flags & (F_SYNC | F_FORMATTING | F_CDROM | F_NO_REDIRECT | F_HIBER_ERASE)) )
		{
			resl = ST_ERROR; break;
		}
#ifdef DC_MBR_LEGACY_GUARD
		/* what the legacy BIOS loader cannot boot (see driver.h): a larger header, a backup
		 * header, storage moved into the slack. Before the header read (no KDF for a refusal). */
		if ( DC_MBR_BOOT_VOLUME(hook) &&
			 ( (flags & (S_BACKUP_HEADER | S_STORAGE_TO_END)) ||
			   (crypt->version >= DC_HDR_VERSION_2 && crypt->head_len != 0 && crypt->head_len != DC_AREA_SIZE) ) )
		{
			DbgMsg("dc_update_layout: layout not supported by the legacy BIOS loader (flags %x, head_len %u)\n", flags, crypt->head_len);
			resl = ST_LEGACY_BOOT; break;
		}
#endif
		/* filled before dc_apply_layout, which is where the layout moves */
		dc_dev_of(hook, &dev);

		/* a new backup header gets a key derived from the password as the header password:
		   only that one may open the header then (a slot password would become the backup's
		   primary). Everything else uses the keys the reads return, so a slot password works. */
		if ((flags & S_BACKUP_HEADER) && password->slot != 0) {
			password->slot = 0;
		}

		/* read volume header */
		if ( (resl = io_read_header(&dev, dc_hook_rw, 0, &header, &hdr_key, password, &found_kdf, interrupt_cmd)) != ST_OK ) {
			break;
		}
		/* a KDF selector only searches: a new backup header key (cp_set_header_key below)
		   needs the KDF the header was found with */
		password->kdf = found_kdf;

		/* the header claims a backup the mounted layout does not have (the mount ignored it, or
		 * a resize dropped it): align the header with the mounted layout, otherwise the update
		 * looks for the missing backup (ST_NOT_BACKUP) and S_REMOVE_BACKUP, gated on
		 * F_HEAD_BACKUP, never clears the flag. The final header write stores it. */
		if ((header->flags & VF_BACKUP_HEADER) && !(hook->flags & F_HEAD_BACKUP)) {
			DbgMsg("dc_update_layout: header claims a backup header the mounted layout has not, dropped\n");
			header->flags &= ~VF_BACKUP_HEADER;
			header->hdr_crc = calculate_header_crc(header);
		}

		if (crypt->version == 0) {
			DbgMsg("dc_update_layout: invalid version 0\n");
			resl = ST_INVALID_PARAM; break;
		}

		/* sanitize request flags - storage resize is determined implicitly */
		flags &= 0xFFFFFF00;
		if ( ((flags & S_STORAGE_TO_FILE) && (flags & S_STORAGE_TO_END)) 
		  || ((flags & S_BACKUP_HEADER) && (flags & S_REMOVE_BACKUP)) ) {
			DbgMsg("dc_update_layout: conflicting flags\n");
			resl = ST_INVALID_PARAM; break; // can't specify both storage options
		}


		/* Update header fields */
		if (crypt->version >= DC_HDR_VERSION_2) // v2 - upgrade or update
		{
			if (header->version >= DC_HDR_VERSION_2) {
				head_len = header->head_len;
			} else {
				head_len = DC_AREA_SIZE;
			}

			header->version = DC_HDR_VERSION_2;

			if (crypt->head_len) {
				if (crypt->head_len < DC_AREA_SIZE || crypt->head_len > DC_AREA_MAX_SIZE || IS_INVALID_SECTOR_SIZE(crypt->head_len)) {
					DbgMsg("dc_update_layout: invalid heead_len=%d\n", crypt->head_len);
					resl = ST_INVALID_PARAM; break;
				}
				header->head_len = crypt->head_len;
			} else if (header->head_len == 0) { // upgrade from v1
				header->head_len = DC_AREA_SIZE;
			}
			// else leave as is

			if (header->head_len < (u32)DC_BASE_SIZE + header->slot_area_len + (header->key_slot_count * header->slot_info_size)) {
				DbgMsg("header length is too small for the number of slots\n");
				/* break, not return - the cleanup below frees header/hdr_key,
				 * releases busy_lock and drops the hook reference */
				resl = ST_INVALID_PARAM; break;
			}

			if (header->ext_hdr_off != 0) {
				if (header->ext_hdr_off + (u32)MIN_EXT_HDR_SIZE > head_len) {
					resl = ST_INV_VOLUME; break;
				}

				dc_ext_header* ext_hdr = (dc_ext_header*)(((u8*)header) + header->ext_hdr_off);
				if (header->ext_hdr_off + ext_hdr->size > header->head_len) {
					DbgMsg("dc_update_layout: ext_hdr size=%d at %d exceeds head_len=%d\n", ext_hdr->size, header->ext_hdr_off, header->head_len);
					resl = ST_INVALID_PARAM; break;
				}
			}

			if(head_len != header->head_len && !(flags & S_RESIZE_HEADER)) {
				DbgMsg("dc_update_layout: invalid operation, head_len change without S_RESIZE_HEADER\n");
				resl = ST_INVALID_PARAM; break;
			}

			header->stor_len = ROUND_TO_FULL_SECTORS(header->head_len, hook->bps);
			if (((header->flags & VF_BACKUP_HEADER) && !(flags & S_REMOVE_BACKUP)) || (flags & S_BACKUP_HEADER))
				header->stor_len *= 2;


			if (!IS_STORAGE_ON_END(hook->flags)) { // when using $dcsys% file grab real size (due to rounding may be already bigger)
				/* $dcsys$ cannot be opened - the mounted layout's length is the known one */
				if (dc_get_storage_size(hook, &stor_len) != ST_OK) {
					DbgMsg("dc_update_layout: $dcsys$ size unknown, using the mounted storage length %u\n", hook->stor_len);
					stor_len = hook->stor_len;
				}
				if (stor_len > header->stor_len && !(flags & S_RESIZE_HEADER)) { // if we already have a bigger storage file, use that size, unless we are resizing header too
					header->stor_len = stor_len;
				}
			} else {
				stor_len = hook->stor_len;
			}
			// do not schrink storage if not needed
			if (header->stor_len != stor_len && !(flags & (S_STORAGE_TO_FILE | S_STORAGE_TO_END))) {
				flags |= (header->flags & VF_STORAGE_FILE) ? S_STORAGE_TO_FILE : S_STORAGE_TO_END;
			}
			/* a $dcsys$ file kept in place was placed for the OLD head_len. A larger header or a
			 * new backup can make it reach into the head or partition-end area and the redirect
			 * would alias the file: recreate it then (S_STORAGE_TO_FILE uses the new margins). */
			if ( (header->flags & VF_STORAGE_FILE) && !IS_STORAGE_ON_END(hook->flags) &&
				 !(flags & (S_STORAGE_TO_FILE | S_STORAGE_TO_END)) )
			{
				u64 new_h   = ROUND_TO_FULL_SECTORS((u64)header->head_len, (u64)hook->bps);
				int new_bak = ((header->flags & VF_BACKUP_HEADER) && !(flags & S_REMOVE_BACKUP)) || (flags & S_BACKUP_HEADER);

				if ( hook->stor_off < new_h ||
					 (new_bak && (new_h >= hook->dsk_size || hook->stor_off + stor_len > hook->dsk_size - new_h)) )
				{
					DbgMsg("dc_update_layout: $dcsys$ [%I64u, +%u) does not fit the new head %I64u / backup area, recreating it\n",
						hook->stor_off, stor_len, new_h);
					flags |= S_STORAGE_TO_FILE;
				}
			}
		}
		else // v1 - downgrade
		{
			head_len = DC_AREA_SIZE;

			if (header->version > DC_HDR_VERSION) {
				header->version = DC_HDR_VERSION;
				// clear v2 fields
				header->head_len = 0;
				header->stor_len = 0;
				memset(&header->footer_cnt, 0, DC_AREA_SIZE - FIELD_OFFSET(dc_header, footer_cnt));
			}

			stor_len = ROUND_TO_FULL_SECTORS(DC_AREA_SIZE, hook->bps);
			// v1 header requres header to be size of DC_AREA_SIZE
			if (hook->head_len != stor_len) {
				flags |= S_RESIZE_HEADER;
			}
			// v1 header requres storage area at partition end to be same as header size
			if (hook->stor_len != stor_len && !(flags & (S_STORAGE_TO_FILE | S_STORAGE_TO_END))) {
				flags |= (header->flags & VF_STORAGE_FILE) ? S_STORAGE_TO_FILE : S_STORAGE_TO_END;
			}

			// v1 header doesn't support backup header, remove if present
			flags &= ~S_BACKUP_HEADER;
			flags |= S_REMOVE_BACKUP;
		}

		/* if backup header is present and not to be removed, load and verify it */
		if ((header->flags & VF_BACKUP_HEADER) && !(flags & S_REMOVE_BACKUP)) {
			if ((bak_salt = (u8*)mm_secure_alloc(HEADER_SALT_SIZE)) == NULL) {
				resl = ST_NOMEM; break;
			}
			/* the primary's KDF first; a backup written with another one is still found
			   when the caller passed a selector */
			resl = io_read_header(&dev, dc_hook_rw, hook->dsk_size - hook->head_len, &hback, &bak_key, password, NULL, interrupt_cmd);
			if (resl == ST_PASS_ERR && sel_kdf < KDF_NONE) {
				password->kdf = sel_kdf;
				resl = io_read_header(&dev, dc_hook_rw, hook->dsk_size - hook->head_len, &hback, &bak_key, password, NULL, interrupt_cmd);
				password->kdf = found_kdf;
			}
			if (resl != ST_OK) {
				DbgMsg("update failed to load backup header, dev=%ws, error=%d\n", hook->dev_name, resl);
				resl = ST_NOT_BACKUP;
				break;
			}
			memcpy(bak_salt, hback->salt, HEADER_SALT_SIZE);
		}
		// if backup header is requested but not present, create it - key slots wont be valid for the header
		else if (flags & S_BACKUP_HEADER) {
			if ( (bak_key = (xts_key*)mm_secure_alloc(sizeof(xts_key))) == NULL ||
				 (bak_salt = (u8*)mm_secure_alloc(HEADER_SALT_SIZE)) == NULL )
			{
				resl = ST_NOMEM; break;
			}
			cp_rand_bytes(bak_salt, HEADER_SALT_SIZE);
			if ( !cp_set_header_key(bak_key, bak_salt, header->alg_1, password, interrupt_cmd) ) {
				resl = ST_INVALID_PARAM; break;
			}
		}

		/* Update header CRC */
		header->hdr_crc = calculate_header_crc(header);

		/* Store header and key for S_UPDATE_LAYOUT to use */
		hook->hdr_key    = hdr_key;
		hdr_key = NULL;

		if (header->head_len <= hook->head_len) {
			hook->tmp_header = header;
			header = NULL;
		}
		else {
			hook->tmp_header = mm_secure_alloc(ROUND_TO_FULL_SECTORS(header->head_len, hook->bps));
			if (!hook->tmp_header) {
				/* no session is set up - take the header key back so the cleanup frees it */
				hdr_key = hook->hdr_key; hook->hdr_key = NULL;
				resl = ST_NOMEM; break;
			}
			memcpy(hook->tmp_header, header, head_len);
		}
		hook->tmp_size   = 0;

		hook->bak_key = bak_key;
		hook->bak_salt = bak_salt;

		bak_key = NULL;
		bak_salt = NULL;

#ifdef DC_CONCURRENT_TRANSCRYPT
		if ( (resl = dc_transcrypt_init(hook, S_UPDATE_LAYOUT | flags)) != ST_OK) {
#else
		if ( (resl = dc_enable_sync_mode(hook, S_UPDATE_LAYOUT | flags)) != ST_OK) {
#endif
			DbgMsg("dc_update_layout: sync mode error\n");
		}
	} while (0);

	if (hdr_key != NULL) mm_secure_free(hdr_key);
	if (header != NULL)  mm_secure_free(header);

	if (bak_key != NULL) mm_secure_free(bak_key);
	if (bak_salt != NULL) mm_secure_free(bak_salt);
	if (hback != NULL)   mm_secure_free(hback);

	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}
	return resl;
}
