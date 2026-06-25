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
#include "header_io.h"
#include "..\crc32.h"
#include "alloc_bitmap.h"

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

	if ((hook->flags & F_HEAD_BACKUP)) {
		data_end = hook->dsk_size - hook->tail_len;
	} else {
		data_end = hook->dsk_size;
	}

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

	if ((hook->flags & F_HEAD_BACKUP)) {
		data_end = hook->dsk_size - hook->tail_len;
	} else {
		data_end = hook->dsk_size;
	}

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
 * Lock a disk range to prevent concurrent I/O while copying data to/from storage.
 * Uses the same synchronization mechanism as dc_transcrypt_step:
 * 1. Wait for all pending I/O to complete (pending_io_count == 0)
 * 2. Set active_start/active_end to block new I/O to this range
 *
 * IMPORTANT: Steps 1 and 2 are done atomically under the spinlock to prevent
 * new I/O from starting between checking pending_io_count and setting active range.
 *
 * This prevents data corruption when saving partition begin/end to storage
 * or restoring them during decryption finish.
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
	/* Lock partition begin range during copy to storage.
	* This blocks concurrent I/O to this range while we:
	* 1. Copy original data to storage
	* 2. Wipe the original location
	* Without this lock, concurrent I/O could access partially copied
	* or wiped data, leading to corruption. */
	dc_lock_disk_range(hook, 0, hook->head_len);

	hook->flags &= ~F_NO_REDIRECT;
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
	/* Unlock partition begin - data has been saved and wiped */
	dc_unlock_disk_range(hook);
#endif

	return resl;
}

static int dc_restore_part_begin(dev_hook* hook)
{
	u8 *buff = hook->tmp_buff;
	u32 done, chunk;
	int resl = ST_OK;

#ifdef DC_CONCURRENT_TRANSCRYPT
	/* Lock partition begin range to prevent concurrent I/O while restoring.
	* Without this lock, I/O to offset 0..head_len would be redirected to
	* storage even while we're copying data back, causing corruption. */
	dc_lock_disk_range(hook, 0, hook->head_len);
#endif

	/* Restore start sectors from storage */
	for (done = 0; done < hook->head_len; done += chunk)
	{
		chunk = min(hook->head_len - done, ENC_BLOCK_SIZE);
		chunk = max((chunk / (u64)hook->bps) * (u64)hook->bps, hook->bps); // align to sector, round down, but at least one

		resl = io_hook_rw(hook, buff, chunk, hook->stor_off + done, 1);
		if (resl != ST_OK) { break; }

		resl = io_hook_rw(hook, buff, chunk, done, 0);
		if (resl != ST_OK) { break; }
	}

#ifdef DC_CONCURRENT_TRANSCRYPT
	hook->flags |= F_NO_REDIRECT;

	/* Unlock partition begin - data has been restored */
	dc_unlock_disk_range(hook);
#endif

	return resl;
}

static int dc_store_part_end(dev_hook* hook, BOOLEAN encrypted);
static int dc_restore_part_end(dev_hook* hook, BOOLEAN encrypted);

static int dc_dec_finish(dev_hook *hook)
{
	int resl;

	resl = dc_restore_part_begin(hook);
	if (resl != ST_OK) {
		return resl;
	}

	if ((hook->flags & F_HEAD_BACKUP) && !IS_STORAGE_ON_END(hook->flags))
	{
		resl = dc_restore_part_end(hook, FALSE);
		if (resl != ST_OK) {
			return resl;
		}
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

void dc_save_enc_state(dev_hook *hook, u32 step)
{
	int i;

	DbgMsg("dc_save_enc_state, step=%d\n", step);

	// check header for memory corruption, bugcheck if header invalid
	// and check encryption key for zeroed
	if (hook->tmp_header == NULL || is_volume_header_correct(hook->tmp_header) == FALSE || hook->hdr_key == NULL || hook->hdr_key->encrypt == NULL)
	{
		KeBugCheckEx(STATUS_DISK_CORRUPT_ERROR, __LINE__, 0, 0, 0);
	}

	if (step == SYNC_STEP_FINISH)
	{
		hook->tmp_header->flags &= ~(VF_TMP_MODE | VF_REENCRYPT);
		hook->tmp_header->tmp_size = 0;
		hook->tmp_header->tmp_wp_mode = 0;

		// reencryption finished, zero previous encryption key
		if (hook->flags & F_REENCRYPT) {
			RtlSecureZeroMemory(hook->tmp_header->key_2, sizeof(hook->tmp_header->key_2)); 
			hook->tmp_header->alg_2 = 0;
			step = SYNC_STEP_UPDATE; // when reencrypting don't rewrite the entire header just update base region
		}
	} 
	else if (hook->tmp_size > 0)
	{
		hook->tmp_header->flags |= VF_TMP_MODE;
		hook->tmp_header->tmp_size = hook->tmp_size;
		hook->tmp_header->tmp_wp_mode = hook->crypt.wp_mode;

		if (hook->flags & F_REENCRYPT) {
			hook->tmp_header->flags |= VF_REENCRYPT;
		} 
	}
	// update header checksum
	hook->tmp_header->hdr_crc = calculate_header_crc(hook->tmp_header);

	// write new header to disk (retry 10 times on error)
	for (i = 0; i < 10; i++) {
		if (io_write_header(hook, 0, hook->tmp_header, hook->hdr_key, NULL, (step == SYNC_STEP_UPDATE) ? HF_UPDATE_BASE : HF_DEFAULT, NULL) == ST_OK) break;
		dc_delay(100);
	}

	// flush disk cache
	io_device_request(hook->orig_dev, IRP_MJ_FLUSH_BUFFERS, NULL, 0, 0);

	// if we have a backup header, write it too (ignore errors)
	if (hook->flags & F_HEAD_BACKUP)
	{
		dc_update_backup(hook, hook->tmp_header, hook->bak_salt, hook->bak_key, NULL, (step == SYNC_STEP_UPDATE) ? HF_UPDATE_BASE : HF_DEFAULT);

		io_device_request(hook->orig_dev, IRP_MJ_FLUSH_BUFFERS, NULL, 0, 0);
	}
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
	
	do
	{
		switch (type & 0xFF)
		{
			case S_INIT_ENC:
				{
#ifdef DC_CONCURRENT_TRANSCRYPT
					/* initialize encryption process - set F_NO_REDIRECT temporarly, dc_store_part_begin will clear it after it locked the range */
					hook->flags |= (F_ENABLED | F_SYNC | F_NO_REDIRECT);
					KeMemoryBarrier();

					/* Wait for all I/O that bypassed pending_io_count tracking */
					io_device_request(hook->orig_dev, IRP_MJ_FLUSH_BUFFERS, NULL, 0, 0);
#endif

					/* save start sectors to storage */
					resl = dc_store_part_begin(hook);
					if (resl != ST_OK) {
						break;
					}

					/* wipe start sectors in chunks */
					dc_wipe_sectors(hook, 0, hook->head_len);

					/* save end sectors to storage when backup header is present */
					if (hook->tmp_header && (hook->tmp_header->flags & VF_BACKUP_HEADER))
					{
						if (IS_STORAGE_ON_END(hook->flags)) {
							hook->flags |= F_HEAD_BACKUP;
						} else {
							resl = dc_store_part_end(hook, FALSE);
							if (resl != ST_OK) {
								break;
							}

							/* wipe end sectors */
							dc_wipe_sectors(hook, hook->dsk_size - hook->tail_len, hook->tail_len);
						}
					}

					/* save initial state */
					dc_save_enc_state(hook, SYNC_STEP_INIT);
				}
			break;
			case S_INIT_DEC:
				{
#ifdef DC_CONCURRENT_TRANSCRYPT
					hook->flags |= (F_ENABLED | F_SYNC);
					KeMemoryBarrier();

					/* Wait for all I/O that bypassed pending_io_count tracking */
					io_device_request(hook->orig_dev, IRP_MJ_FLUSH_BUFFERS, NULL, 0, 0);
#endif
					resl = ST_OK;
				}
			break;
			case S_CONTINUE_ENC: 
				{
#ifdef DC_CONCURRENT_TRANSCRYPT
					hook->flags |= (F_ENABLED | F_SYNC);
#endif
					resl = ST_OK;
				}
			break;
			case S_INIT_RE_ENC:
				{
					DbgMsg("S_INIT_RE_ENC\n");

#ifdef DC_CONCURRENT_TRANSCRYPT
					xts_key* new_key;

					/* CRITICAL: We must set F_SYNC | F_REENCRYPT BEFORE swapping keys!
					*
					* Before this point: dsk_key = old_key, tmp_key = new_key
					* After swap: dsk_key = new_key, tmp_key = old_key
					*
					* If we swap first, there's a window where:
					* - F_ENABLED is set (volume is mounted)
					* - F_SYNC is NOT set
					* - I/O uses dsk_key = new_key for data encrypted with old_key
					* - CORRUPTION!
					*
					* Fix: Set tmp_key = old_key and F_SYNC first.
					* With tmp_size = 0, all I/O uses tmp_key = old_key (correct).
					* Then set dsk_key = new_key (safe, all I/O uses tmp_key).
					*/

					/* Save new_key pointer before we overwrite tmp_key */
					new_key = hook->tmp_key;

					/* Step 1: Set tmp_key to old_key (for I/O above boundary) */
					hook->tmp_key = hook->dsk_key;

					/* Step 2: Set flags BEFORE changing dsk_key.
					* Use InterlockedOr for atomic flag setting with full barrier semantics.
					* This ensures proper memory ordering on ARM64 (weakly ordered). */
					InterlockedOr((volatile LONG*)&hook->flags, (F_ENABLED | F_SYNC | F_REENCRYPT));

					/* Memory barrier to ensure flags are globally visible before dsk_key changes.
					* InterlockedOr provides barrier, but we add explicit one for clarity. */
					KeMemoryBarrier();

					/* Wait for all I/O that bypassed pending_io_count tracking */
					io_device_request(hook->orig_dev, IRP_MJ_FLUSH_BUFFERS, NULL, 0, 0);

					/* Step 3: Now safe to set dsk_key to new_key */
					hook->dsk_key = new_key;
#else
					// swap keys
					{
						xts_key* tmp = hook->dsk_key;
						hook->dsk_key = hook->tmp_key;
						hook->tmp_key = tmp;
					}

					/* set re-encryption flag */
					hook->flags |= F_REENCRYPT;
#endif
					/* save initial state - use SYNC_STEP_INIT to write the full header with the new
					* cipher's header key, ensuring slot descriptors and extended header are re-encrypted */
					dc_save_enc_state(hook, SYNC_STEP_INIT);

					resl = ST_OK;
				}
			break;
			case S_CONTINUE_RE_ENC:
				{
					DbgMsg("S_CONTINUE_RE_ENC\n");

#ifdef DC_CONCURRENT_TRANSCRYPT
					/* initialize encryption process */
					hook->flags |= (F_ENABLED | F_SYNC | F_REENCRYPT);
#endif

					if ( (hook->tmp_key = (xts_key*)mm_secure_alloc(sizeof(xts_key))) == NULL )
					{
						resl = ST_NOMEM; break;
					}

					/* initialize secondary volume key */
					if (!xts_set_key(hook->tmp_header->key_2, hook->tmp_header->alg_2, hook->tmp_key)) 
					{
						mm_secure_free(hook->tmp_key); hook->tmp_key = NULL;
						resl = ST_INVALID_PARAM; break;
					}

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
		DbgMsg("dc_init_sync_mode failed, resl=%d, restoring flags\n", resl);
		hook->flags = old_flags;
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
	if (hook->tmp_buff != NULL) {
		mm_pool_free(hook->tmp_buff);
		hook->tmp_buff = NULL;
	}

	dc_bitmap_free(hook);

	if (hook->tmp_key != NULL) {
		mm_secure_free(hook->tmp_key);
		hook->tmp_key = NULL;
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
	if (hook->tmp_buff = mm_pool_alloc(ENC_BLOCK_SIZE))
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
					dc_wait_for_transcrypt(hook);
					dc_save_enc_state(hook, SYNC_STEP_UPDATE);
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
	u8               *buff = hook->tmp_buff;
	int               resl;

	DbgMsg("dc_transcrypt_init: type=%X\n", type);

	/* Initialize transcrypt state */
	KeInitializeSpinLock(&trans->range_lock);
	KeInitializeEvent(&trans->block_complete, NotificationEvent, TRUE); /* Initially signaled */
	KeInitializeEvent(&trans->io_done_event, NotificationEvent, TRUE);  /* Initially signaled (no pending I/O) */
	KeInitializeEvent(&trans->idle_event, NotificationEvent, TRUE);     /* Initially signaled (not in progress) */
	trans->active_start = -1;
	trans->active_end = 0;
	trans->pending_io_count = 0;
	trans->in_progress = 0;

	/* Pre-allocate buffer to avoid allocation during block processing.
	 * This is critical to prevent deadlock - the old sync thread deadlocked
	 * because it would retry memory allocation for up to 30 seconds,
	 * blocking all I/O including paging I/O needed to free memory. */
	hook->tmp_buff = mm_pool_alloc(ENC_BLOCK_SIZE);
	if (hook->tmp_buff == NULL) {
		DbgMsg("dc_transcrypt_init: buffer allocation failed\n");
		return ST_NOMEM;
	}

	/* Initialize wipe context */
	if (hook->crypt.wp_mode == WP_SKIP_UNUSED) {
		resl = dc_wipe_init(&hook->wp_ctx, hook, ENC_BLOCK_SIZE, WP_NONE, hook->crypt.cipher_id);
	} else {
		resl = dc_wipe_init(&hook->wp_ctx, hook, ENC_BLOCK_SIZE, hook->crypt.wp_mode, hook->crypt.cipher_id);
	}
	if (resl != ST_OK) {
		DbgMsg("dc_transcrypt_init: wipe init failed\n");
		mm_pool_free(hook->tmp_buff);
		hook->tmp_buff = NULL;
		return resl;
	}

	resl = dc_init_sync_mode(hook, type);

	if (resl != ST_OK) {
		hook->flags &= ~F_SYNC;
		dc_sync_cleanup(hook);
		if (resl == ST_FINISHED) {
			DbgMsg("dc_transcrypt_init: finished\n");
			return ST_OK;
		}
		DbgMsg("dc_transcrypt_init: failed, code %d\n", resl);
		return resl;
	}

	DbgMsg("dc_transcrypt_init: success\n");
	return ST_OK;
}

int dc_transcrypt_step(dev_hook *hook, BOOLEAN is_decrypt)
{
	transcrypt_state *trans = &hook->trans;
	u8   *buff = hook->tmp_buff;
	u64   offs, size, remaining;
	u64   data_start, data_end;
	int   resl;
	KIRQL irql;
	BOOLEAN is_encrypt, is_reencrypt;

	if (!(hook->flags & F_SYNC)) {
		return ST_ERROR;
	}

	/* Clear idle_event BEFORE setting in_progress to avoid race:
	 * Without this ordering, another thread could see in_progress=1 but
	 * idle_event still signaled from previous transcryption, and proceed
	 * without waiting for us to finish. */
	KeClearEvent(&trans->idle_event);

	/* Atomically try to mark transcryption as in progress.
	 * If already in progress (concurrent call), return error.
	 * This prevents two threads from processing blocks simultaneously. */
	if (InterlockedCompareExchange(&trans->in_progress, 1, 0) != 0) {
		return ST_ERROR;
	}

	/* Check stop flag after marking in_progress.
	 * Power management sets F_PREVENT_ENC before hibernate/unmount.
	 * We must check AFTER setting in_progress to close the race window. */
	if (hook->flags & F_PREVENT_ENC) {
		InterlockedExchange(&trans->in_progress, 0);
		KeSetEvent(&trans->idle_event, IO_NO_INCREMENT, FALSE);
		return ST_CANCEL;
	}

	/* Direction is determined by the IOCTL type (DC_CTL_ENCRYPT_STEP vs DC_CTL_DECRYPT_STEP),
	 * not by stored state. This matches how the old sync thread code worked and ensures
	 * correct behavior when resuming after pause. */
	is_encrypt = !is_decrypt;
	is_reencrypt = (hook->flags & F_REENCRYPT) != 0;

	/* Lazy init bitmap for SSD skip optimization.
	 * Done here (not at mount) to avoid memory waste when paused. */
	if (hook->crypt.wp_mode == WP_SKIP_UNUSED && hook->alloc_bitmap == NULL) {
		dc_bitmap_start_init(hook);
	}

	/* Calculate data area boundaries.
	 * The actual data area is from head_len to dsk_size, but when a backup header
	 * is present at the end (F_HEAD_BACKUP and storage not at end), the data area
	 * ends at dsk_size - head_len because the last head_len bytes are reserved
	 * for the backup of the partition end sectors. */
	data_start = hook->head_len;
	if ((hook->flags & F_HEAD_BACKUP)) {
		data_end = hook->dsk_size - hook->tail_len;
	} else {
		data_end = hook->dsk_size;
	}

	/* Get current position */
	offs = hook->tmp_size;

	/* Check if finished */
	if (is_encrypt) {
		/* Encryption/Re-encryption: process from data_start to data_end */
		if (offs >= data_end) {
			InterlockedExchange(&trans->in_progress, 0);
			KeSetEvent(&trans->idle_event, IO_NO_INCREMENT, FALSE);
			return ST_FINISHED;
		}
		remaining = data_end - offs;
		size = min(remaining, ENC_BLOCK_SIZE);
	} else {
		/* Decryption: process backwards from data_end to data_start.
		 * When offs reaches data_start (head_len), we're done decrypting
		 * the data area. Then dc_dec_finish restores the original partition
		 * begin/end sectors from storage. */
		if (offs <= data_start) {
			/* Decryption finished - restore redirected data */
			resl = dc_dec_finish(hook);
			InterlockedExchange(&trans->in_progress, 0);
			KeSetEvent(&trans->idle_event, IO_NO_INCREMENT, FALSE);
			return resl;
		}
		/* Don't decrypt below data_start */
		remaining = offs - data_start;
		size = min(remaining, ENC_BLOCK_SIZE);
		offs = offs - size;
	}

	/* Handle bitmap skip optimization.
	 * In concurrent mode we process fixed ENC_BLOCK_SIZE blocks,
	 * so we just check if the current block is allocated. */
	if (DC_BITMAP_IS_VALID(hook->alloc_bitmap)) {
		if (!dc_bitmap_is_allocated(hook, offs, (u32)size)) {
			/* Block is unallocated - skip it.
			 * Update tmp_size under spinlock for consistency with I/O snapshots. */
			KeAcquireSpinLock(&trans->range_lock, &irql);
			if (is_encrypt) {
				hook->tmp_size = offs + size;
			} else {
				hook->tmp_size = offs;
			}
			KeReleaseSpinLock(&trans->range_lock, irql);
			InterlockedExchange(&trans->in_progress, 0);
			KeSetEvent(&trans->idle_event, IO_NO_INCREMENT, FALSE);
			return ST_OK;
		}
	}

	/* Wait for all pending I/O to complete and lock the active block range.
	 * This ensures no I/O is using a stale tmp_size snapshot.
	 * Each I/O increments pending_io_count when it starts and decrements when done. */
	dc_lock_disk_range(hook, offs, offs + size);

	/* Read data */
	resl = io_hook_rw_skip_bads(hook, buff, (u32)size, offs, 1);
	if (resl != ST_OK && resl != ST_RW_ERR) {
		goto finish_block;
	}

	/* Encrypt/Decrypt/Re-encrypt */
	if (is_reencrypt) {
		dc_wipe_process(&hook->wp_ctx, offs, (int)size);
		cp_fast_decrypt(buff, buff, (u32)size, offs, hook->tmp_key);
		cp_fast_encrypt(buff, buff, (u32)size, offs, hook->dsk_key);
	} else if (is_encrypt) {
		cp_fast_encrypt(buff, buff, (u32)size, offs, hook->dsk_key);
		dc_wipe_process(&hook->wp_ctx, offs, (int)size);
	} else {
		cp_fast_decrypt(buff, buff, (u32)size, offs, hook->dsk_key);
	}

	/* Write data */
	resl = io_hook_rw_skip_bads(hook, buff, (u32)size, offs, 0);

	/* Prevent system power state changes */
	PoSetSystemState(ES_SYSTEM_REQUIRED);

finish_block:
	/* Clear active block and update boundary under spinlock.
	 * tmp_size must be updated atomically with clearing active_start so that
	 * I/O checking overlap sees consistent state: either active block exists
	 * (and I/O waits), or tmp_size is already updated (and I/O uses correct key). */
	KeAcquireSpinLock(&trans->range_lock, &irql);
	if (resl == ST_OK || resl == ST_RW_ERR) {
		if (is_encrypt) {
			hook->tmp_size = offs + size;
		} else {
			hook->tmp_size = offs;
		}
	}
	trans->active_start = -1;
	trans->active_end = 0;
	KeSetEvent(&trans->block_complete, IO_NO_INCREMENT, FALSE);
	KeReleaseSpinLock(&trans->range_lock, irql);

	/* Mark transcryption as idle */
	InterlockedExchange(&trans->in_progress, 0);
	KeSetEvent(&trans->idle_event, IO_NO_INCREMENT, FALSE);

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
		dc_save_enc_state(hook, SYNC_STEP_FINISH);
	}

	/* TRIM free space if enabled */
	if ((dc_conf_flags & CONF_DISABLE_TRIM) == 0) {
		dc_trim_free_space(hook);
	}

	/* Cleanup resources.
	 * dc_transcrypt_cleanup clears F_SYNC under spinlock and waits for pending I/O. */
	dc_transcrypt_cleanup(hook);

	/* Note: Storage file deletion is handled by the caller AFTER unmount.
	 * The old sync thread deleted storage after unmount, and we must do the same
	 * because the filesystem needs to be properly unmounted first. */

	return ST_OK;
}

int dc_encrypt_step(wchar_t *dev_name)
{
	int   resl;
	dev_hook *hook = dc_find_hook(dev_name);
	if (hook == NULL) {
		return ST_NF_DEVICE;
	}

	/* Check F_SYNC without holding busy_lock */
	if (!(hook->flags & F_SYNC)) {
		dc_deref_hook(hook);
		return ST_ERROR;
	}

	/* Process block without holding busy_lock.
	 * dc_transcrypt_step uses in_progress flag to coordinate with power management. */
	resl = dc_transcrypt_step(hook, FALSE);  /* is_decrypt = FALSE */

	if (resl == ST_FINISHED) {
		/* Use busy_lock only for finalization (state change, cleanup) */
		wait_object_infinity(&hook->busy_lock);
		dc_transcrypt_finish(hook, FALSE);  /* is_decrypt = FALSE */
		KeReleaseMutex(&hook->busy_lock, FALSE);
	} else if (resl == ST_MEDIA_CHANGED || resl == ST_NO_MEDIA) {
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
	dev_hook *hook = dc_find_hook(dev_name);
	if (hook == NULL) {
		return ST_NF_DEVICE;
	}

	/* Check F_SYNC without holding busy_lock */
	if (!(hook->flags & F_SYNC)) {
		dc_deref_hook(hook);
		return ST_ERROR;
	}

	/* Process block without holding busy_lock.
	 * dc_transcrypt_step uses in_progress flag to coordinate with power management. */
	resl = dc_transcrypt_step(hook, TRUE);  /* is_decrypt = TRUE */

	if (resl == ST_FINISHED) {
		/* Check if storage file needs deletion BEFORE finalize clears tmp_header */
		int del_storage = (hook->tmp_header->flags & VF_STORAGE_FILE) != 0;

		/* Use busy_lock only for finalization (state change, cleanup).
		 * is_decrypt=TRUE skips header write since boot sector was just restored */
		wait_object_infinity(&hook->busy_lock);
		dc_transcrypt_finish(hook, TRUE);
		KeReleaseMutex(&hook->busy_lock, FALSE);

		/* Unmount and delete storage (unmount acquires lock internally) */
		dc_process_unmount(hook, MF_NOFSCTL | MF_DECRYPTED);

		/* Delete storage file AFTER unmount.
		 * Must be after unmount so F_ENABLED is cleared and I/O passes through
		 * without encryption, allowing filesystem access to delete the file. */
		if (del_storage) {
			dc_delete_storage(hook);
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
		/* Wait for any in-progress transcryption to get latest state */
		dc_wait_for_transcrypt(hook);
		dc_save_enc_state(hook, SYNC_STEP_UPDATE);
		resl = ST_OK;
	} else {
		resl = ST_ERROR;
	}
	KeReleaseMutex(&hook->busy_lock, FALSE);

	dc_deref_hook(hook);
	return resl;
}

void dc_wait_for_transcrypt(dev_hook* hook)
{
	/* Wait for any in-progress transcryption to get latest state */
	if (hook->trans.in_progress) {
		KeWaitForSingleObject(&hook->trans.idle_event,
			Executive, KernelMode, FALSE, NULL);
	}
}

void dc_transcrypt_cleanup(dev_hook *hook)
{
	transcrypt_state *trans = &hook->trans;
	KIRQL irql;

	/* Clear F_SYNC under spinlock FIRST.
	 * I/O re-checks F_SYNC inside the spinlock, so it will see this and bail out.
	 * This prevents new I/O from starting to use resources we're about to free. */
	KeAcquireSpinLock(&trans->range_lock, &irql);
	hook->flags &= ~(F_SYNC | F_REENCRYPT);
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

	DbgMsg("dc_encrypt_start\n");

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);
		
		if (hook->flags & (F_ENABLED | F_UNSUPRT | F_DISABLE | F_CDROM)) {
			resl = ST_ERROR; break;
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

		/* Check for volume slack at partition end before creating $dcsys$ file */
		if (flags & VF_USE_SLACK) {
			DbgMsg("dc_encrypt_start: checking for existing volume slack\n");
			if (dc_get_volume_slack(hook, &slack_size) == ST_OK && slack_size >= stor_len) {
				stor_off = hook->dsk_size - stor_len;
				DbgMsg("dc_encrypt_start: using existing volume slack at offset=%I64x\n", stor_off);
			}
		}

		/* If no existing slack and VF_TRY_SHRINK flag is set, try to shrink filesystem */
		if (stor_off == 0 && (flags & VF_USE_SLACK) && (flags & VF_TRY_SHRINK)) {
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

		/* Clear request-only flags before storing in header */
		flags &= ~( VF_USE_SLACK | VF_TRY_SHRINK );

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
		hook->use_size       = hook->dsk_size;
		hook->tmp_size       = hook->head_len;
		hook->stor_off       = stor_off;
		hook->stor_len       = stor_len;
		hook->hdr_key        = hdr_key;
		hook->disk_id        = header->disk_id;
		if (flags & VF_STORAGE_FILE) {
			hook->flags     |= F_PROTECT_DCSYS;
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
		}
	} while (0);

	if (hdr_key != NULL) mm_secure_free(hdr_key);
	if (header != NULL)  mm_secure_free(header);

	if (bak_key != NULL) mm_secure_free(bak_key);
	if (bak_salt != NULL)mm_secure_free(bak_salt);

	if (hook != NULL)
	{
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
	dev_hook  *hook;
	xts_key   *hdr_key = NULL;
	xts_key   *dsk_key = NULL;
	int        resl;
	dc_header *hback = NULL;
	u8        *bak_salt = NULL;
	xts_key   *bak_key = NULL;

	DbgMsg("dc_reencrypt_start\n");

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		if ( !(hook->flags & F_ENABLED) || 
			  (hook->flags & (F_SYNC | F_FORMATTING | F_CDROM)) ) 
		{
			resl = ST_ERROR; break;
		}

		/* verify encryption info */
		if ( (crypt->cipher_id >= CF_CIPHERS_NUM) || (crypt->wp_mode != WP_SKIP_UNUSED && crypt->wp_mode >= WP_NUM) ) {
			resl = ST_ERROR; break;
		}

		/* allocate new volume key */
		if ( (dsk_key = mm_secure_alloc(sizeof(xts_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}
		/* allocate new header key */
		if ( (hdr_key = mm_secure_alloc(sizeof(xts_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}
		/* read volume header */
		if ( (resl = io_read_header(hook, 0, &header, NULL, password, NULL, interrupt_cmd)) != ST_OK ) {
			break;
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
			// todo: hint at corerct kdf
			resl = io_read_header(hook, hook->dsk_size - hook->head_len, &hback, &bak_key, password, NULL, interrupt_cmd);
			if (resl != ST_OK) {
				DbgMsg("reencrypt failed to load backup header, dev=%ws, error=%d\n", hook->dev_name, resl);
				resl = ST_NOT_BACKUP;
				break;
			}
			memcpy(bak_salt, hback->salt, HEADER_SALT_SIZE);

			// initialize new backup header key, as the same salt and password are used only the algorithm is changed key slots will remain intect
			if ( !cp_set_header_key(bak_key, bak_salt, header->alg_1, password, interrupt_cmd) ) {
				resl = ST_INVALID_PARAM;
				break;
			}
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
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}
	return resl;
}

int dc_decrypt_start(wchar_t *dev_name, dc_pass *password, crypt_info *crypt, ULONG *interrupt_cmd)
{
	dc_header *header = NULL;
	dev_hook  *hook;
	xts_key   *hdr_key = NULL;
	int        resl;
	dc_header *hback = NULL;
	u8        *bak_salt = NULL;
	xts_key   *bak_key = NULL;

	DbgMsg("dc_decrypt_start\n");

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		if ( !(hook->flags & F_ENABLED) ||
			  (hook->flags & (F_SYNC | F_FORMATTING | F_CDROM | F_NO_REDIRECT)) )
		{
			resl = ST_ERROR; break;
		}
		/* read volume header */
		if ( (resl = io_read_header(hook, 0, &header, &hdr_key, password, NULL, interrupt_cmd)) != ST_OK ) {
			break;
		}

		/* backup header is present, load and verify it */
		if (header->flags & VF_BACKUP_HEADER) {
			if (!(bak_salt = mm_secure_alloc(HEADER_SALT_SIZE))) {
				resl = ST_NOMEM; break;
			}
			// todo: hint at corerct kdf
			resl = io_read_header(hook, hook->dsk_size - hook->head_len, &hback, &bak_key, password, NULL, interrupt_cmd);
			if (resl != ST_OK) {
				DbgMsg("decrypt failed to load backup header, dev=%ws, error=%d\n", hook->dev_name, resl);
				// restore backup header from primary header
				if ( (bak_key = mm_secure_alloc(sizeof(xts_key))) == NULL ) { 
					resl = ST_NOMEM; break; 
				}
				memcpy(bak_salt, header->salt, HEADER_SALT_SIZE);
				memcpy(bak_key, hdr_key, sizeof(xts_key));
			}
			else {
				memcpy(bak_salt, hback->salt, HEADER_SALT_SIZE);
			}
		}

		hook->crypt.cipher_id = d8(header->alg_1);
		hook->crypt.wp_mode   = crypt ? crypt->wp_mode : WP_NONE;
		if ((hook->flags & F_HEAD_BACKUP)) {
			hook->tmp_size = hook->dsk_size - hook->tail_len;
		} else {
			hook->tmp_size = hook->dsk_size;
		}
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



static int dc_store_part_end(dev_hook* hook, BOOLEAN encrypted)
{
	u8 *buff = hook->tmp_buff;
	u32 done, chunk;
	u64 end_stor_off;
	u64 end_disk_off;
	int resl = ST_OK;

	/* Check if we have enough space in redirection area to store partition end */
	if (hook->stor_len < hook->head_len * 2) {
		return ST_NF_SPACE;
	}

	hook->tail_len = hook->head_len; // backup header length is the same as main header length
	hook->tail_off = hook->stor_off + hook->stor_len - hook->tail_len;

	end_disk_off = hook->dsk_size - hook->tail_len;
	end_stor_off = hook->stor_off + hook->stor_len - hook->tail_len;

#ifdef DC_CONCURRENT_TRANSCRYPT
	/* Lock partition end range during copy to storage */
	dc_lock_disk_range(hook, end_disk_off, hook->dsk_size);
#endif

	hook->flags |= F_HEAD_BACKUP;

	for (done = 0; done < hook->tail_len; done += chunk)
	{
		chunk = min(hook->tail_len - done, ENC_BLOCK_SIZE);
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

	end_stor_off = hook->stor_off + hook->stor_len - hook->tail_len;
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

	hook->flags &= ~F_HEAD_BACKUP;

#ifdef DC_CONCURRENT_TRANSCRYPT
	/* Unlock partition end - data has been restored */
	dc_unlock_disk_range(hook);
#endif

	hook->tail_len = 0;
	hook->tail_off = 0;

	if (resl != ST_OK) {
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

void dc_write_header_safe(dev_hook *hook, u32 flags)
{
	int i;

	DbgMsg("dc_write_header_safe, flags=%x\n", flags);

	// check header for memory corruption, bugcheck if header invalid
	// and check encryption key for zeroed
	if (hook->tmp_header == NULL || is_volume_header_correct(hook->tmp_header) == FALSE || hook->hdr_key == NULL || hook->hdr_key->encrypt == NULL)
	{
		KeBugCheckEx(STATUS_DISK_CORRUPT_ERROR, __LINE__, 0, 0, 0);
	}

	// write new header to disk (retry 10 times on error)
	for (i = 0; i < 10; i++) {
		if (io_write_header(hook, 0, hook->tmp_header, hook->hdr_key, NULL, flags, NULL) == ST_OK) break;
		dc_delay(100);
	}

	// flush disk cache
	io_device_request(hook->orig_dev, IRP_MJ_FLUSH_BUFFERS, NULL, 0, 0);
}

static int dc_apply_layout(dev_hook *hook, u32 type)
{
	u32 head_len;
	u32 stor_len;
	int resl = ST_OK;
	u8 *bak_key_slots = NULL;
	u32 bak_flags = HF_DEFAULT;

	do
	{
#ifdef DC_CONCURRENT_TRANSCRYPT
		hook->flags |= F_SYNC;
		KeMemoryBarrier();
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
			DbgMsg("dc_apply_layout: removing backup header\n");
			if (IS_STORAGE_ON_END(hook->flags)) { // backup at partition end not in slack space
				resl = dc_restore_part_end(hook, TRUE);
				if (resl != ST_OK) {
					DbgMsg("dc_apply_layout: failed to restore partition end\n");
				}
			} else {
				hook->flags &= ~F_HEAD_BACKUP;
			}
			hook->tmp_header->flags &= ~VF_BACKUP_HEADER;
			hook->tmp_header->hdr_crc = calculate_header_crc(hook->tmp_header);
			dc_write_header_safe(hook, HF_UPDATE_BASE);
		}

		// shrink header
		if ((type & S_RESIZE_HEADER) && head_len < hook->tmp_header->head_len)
		{
			u32 new_head_len = ROUND_TO_FULL_SECTORS(head_len, hook->bps);
			u32 old_head_len = hook->head_len;

			DbgMsg("dc_apply_layout: shrinking header from %u to %u bytes\n", old_head_len, new_head_len);

			resl = dc_shrink_header(hook, old_head_len, new_head_len);
			if (resl != ST_OK) {
				DbgMsg("dc_apply_layout: failed to shrink header\n");
				break;
			}

			/* Update header fields */
			hook->crypt.head_len = head_len;
			if (hook->tmp_header->version >= DC_HDR_VERSION_2) {
				hook->tmp_header->head_len = head_len;
			}
			hook->tmp_header->hdr_crc = calculate_header_crc(hook->tmp_header);
			dc_write_header_safe(hook, HF_UPDATE_BASE);

			/* Update backup header if enabled */
			if (hook->flags & F_HEAD_BACKUP) {
				if (!IS_STORAGE_ON_END(hook->flags)) {
					/* Remove old larger backup space, create new smaller one */
					resl = dc_restore_part_end(hook, TRUE);
					if (resl == ST_OK) {
						resl = dc_store_part_end(hook, TRUE);
					}
				}
				/* Write backup header with pre-read key slots */
				if (resl == ST_OK) {
					dc_update_backup(hook, hook->tmp_header, hook->bak_salt, hook->bak_key, bak_key_slots, bak_flags);
				}
			}
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

				/* Step 4: Copy backup area if enabled */
				if (hook->flags & F_HEAD_BACKUP) {
					u64 old_tail_off = old_stor_off + old_stor_len - hook->tail_len;
					u64 new_tail_off = new_stor_off + new_stor_len - hook->tail_len;

					resl = dc_copy_storage_range(hook, old_tail_off, new_tail_off, hook->tail_len);
					if (resl == ST_OK) {
						hook->tail_off = new_tail_off;
					} else {
						DbgMsg("dc_apply_layout: failed to copy backup area\n");
						break;
					}
				}

				/* Update header */
				hook->tmp_header->stor_off = hook->stor_off;
				if (hook->tmp_header->version >= DC_HDR_VERSION_2) {
					hook->tmp_header->stor_len = hook->stor_len;
				}
				hook->tmp_header->hdr_crc = calculate_header_crc(hook->tmp_header);
				dc_write_header_safe(hook, HF_UPDATE_BASE);
				if (hook->flags & F_HEAD_BACKUP) {
					dc_update_backup(hook, hook->tmp_header, hook->bak_salt, hook->bak_key, bak_key_slots, bak_flags);
				}

				/* Step 5: Delete old storage file */
				dc_delete_storage_by_name(hook, L"$dcbak$");
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
					hook->flags |= F_PROTECT_DCSYS;
					hook->use_size = hook->dsk_size;
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
				hook->tmp_header->hdr_crc = calculate_header_crc(hook->tmp_header);
				dc_write_header_safe(hook, HF_UPDATE_BASE);

				/* Reclaim slack space by expanding filesystem */
				slack_reclaim = old_stor_len;
				hook->wrk_thread_id = PsGetCurrentThreadId();
				dc_try_expand_fs(hook, slack_reclaim); /* ignore failure */
				hook->wrk_thread_id = 0;

				/* Re-create backup at partition end if enabled */
				if (hook->flags & F_HEAD_BACKUP) {
					resl = dc_store_part_end(hook, TRUE);
					if (resl == ST_OK) {
						hook->tmp_header->flags |= VF_BACKUP_HEADER;

						hook->tmp_header->hdr_crc = calculate_header_crc(hook->tmp_header);
						dc_update_backup(hook, hook->tmp_header, hook->bak_salt, hook->bak_key, bak_key_slots, bak_flags);
						
						dc_write_header_safe(hook, HF_UPDATE_BASE);
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

				/* If expanding, check/create slack space */
				if (expanding) {
					u64 need_slack = stor_len - old_stor_len;
					resl = dc_get_volume_slack(hook, &slack_size);
					if (resl != ST_OK || slack_size < need_slack) {
						hook->wrk_thread_id = PsGetCurrentThreadId();
						resl = dc_try_shrink_fs(hook, need_slack - slack_size);
						hook->wrk_thread_id = 0;
						if (resl != ST_OK) {
							resl = ST_SHRINK_FAILED;
							break;
						}
					}
				}

				/* Copy partition begin backup to new location (backward for overlap safety) */
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

				/* Update header */
				hook->tmp_header->stor_off = hook->stor_off;
				if (hook->tmp_header->version >= DC_HDR_VERSION_2) {
					hook->tmp_header->stor_len = hook->stor_len;
				}
				hook->tmp_header->hdr_crc = calculate_header_crc(hook->tmp_header);
				dc_write_header_safe(hook, HF_UPDATE_BASE);
				if (hook->flags & F_HEAD_BACKUP) {
					dc_update_backup(hook, hook->tmp_header, hook->bak_salt, hook->bak_key, bak_key_slots, bak_flags);
				}

				/* If shrinking, reclaim slack space */
				if (!expanding) {
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
					if (resl != ST_OK) {
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
					hook->flags &= ~F_PROTECT_DCSYS;
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
				hook->tmp_header->hdr_crc = calculate_header_crc(hook->tmp_header);
				dc_write_header_safe(hook, HF_UPDATE_BASE);

				/* update backup at partition end if enabled */
				if (hook->flags & F_HEAD_BACKUP) {
					dc_update_backup(hook, hook->tmp_header, hook->bak_salt, hook->bak_key, bak_key_slots, bak_flags);
				}

				/* Delete old storage file */
				dc_delete_storage(hook);
			}
		}

		/* Expand header */
		if ((type & S_RESIZE_HEADER) && head_len > hook->crypt.head_len)
		{
			u32 old_head_len = hook->head_len;
			u32 new_head_len = ROUND_TO_FULL_SECTORS(head_len, hook->bps);

			DbgMsg("dc_apply_layout: expanding header from %u to %u bytes\n", old_head_len, new_head_len);

			resl = dc_expand_header(hook, old_head_len, new_head_len);
			if (resl != ST_OK) {
				DbgMsg("dc_apply_layout: failed to expand header\n");
				break;
			}

			/* Update header fields */
			hook->crypt.head_len = head_len;
			if (hook->tmp_header->version >= DC_HDR_VERSION_2) {
				hook->tmp_header->head_len = head_len;
			}
			hook->tmp_header->hdr_crc = calculate_header_crc(hook->tmp_header);
			dc_write_header_safe(hook, HF_UPDATE_BASE);

			/* Update backup header if enabled */
			if (hook->flags & F_HEAD_BACKUP) {
				if (!IS_STORAGE_ON_END(hook->flags)) {
					/* Remove old smaller backup space, create new larger one */
					resl = dc_restore_part_end(hook, TRUE);
					if (resl == ST_OK) {
						resl = dc_store_part_end(hook, TRUE);
					}
				}
				/* Write backup header with pre-read key slots */
				if (resl == ST_OK) {
					dc_update_backup(hook, hook->tmp_header, hook->bak_salt, hook->bak_key, bak_key_slots, bak_flags);
				}
			}
		}

		/* Add new backup header */
		if ((type & S_BACKUP_HEADER) && !(hook->flags & F_HEAD_BACKUP)) {
			DbgMsg("dc_apply_layout: adding backup header\n");
			if (!IS_STORAGE_ON_END(hook->flags)) { // backup at partition end not in slack space
				resl = dc_store_part_end(hook, TRUE);
			} else {
				/* Check if we have enough space in redirection area to store header backup */
				if (hook->stor_len < hook->head_len * 2) {
					resl = ST_NF_SPACE;
				} else {
					hook->flags |= F_HEAD_BACKUP;
				}
			}
			if (resl == ST_OK) {
				hook->tmp_header->flags |= VF_BACKUP_HEADER;
				hook->tmp_header->hdr_crc = calculate_header_crc(hook->tmp_header);
				
				resl = dc_update_backup(hook, hook->tmp_header, hook->bak_salt, hook->bak_key, bak_key_slots, bak_flags);
			}
			if (resl != ST_OK) {
				DbgMsg("Failed to backup header, error %d\n", resl);
			}
		}

		dc_write_header_safe(hook, HF_DEFAULT);

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
	dev_hook  *hook;
	xts_key   *hdr_key = NULL;
	u32	       head_len;
	u32	       stor_len;
	int        resl;
	dc_header *hback = NULL;
	u8        *bak_salt = NULL;
	xts_key   *bak_key = NULL;

	DbgMsg("dc_update_layout\n");

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		if (!(dc_load_flags & DST_PRO_ENABLED)) {
			resl = ST_NOT_PRO; break;
		}

		wait_object_infinity(&hook->busy_lock);

		/* Volume must be mounted and not in sync mode */
		if ( !(hook->flags & F_ENABLED) ||
			  (hook->flags & (F_SYNC | F_FORMATTING | F_CDROM)) )
		{
			resl = ST_ERROR; break;
		}
		/* read volume header */
		if ( (resl = io_read_header(hook, 0, &header, &hdr_key, password, NULL, interrupt_cmd)) != ST_OK ) {
			break;
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
				return ST_INVALID_PARAM;
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
				dc_get_storage_size(hook, &stor_len);
			} else {
				stor_len = hook->stor_len;
			}
			// do not schrink storage if not needed
			if (header->stor_len != stor_len && !(flags & (S_STORAGE_TO_FILE | S_STORAGE_TO_END))) {
				flags |= (header->flags & VF_STORAGE_FILE) ? S_STORAGE_TO_FILE : S_STORAGE_TO_END;
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
			// todo: hint at corerct kdf
			resl = io_read_header(hook, hook->dsk_size - hook->head_len, &hback, &bak_key, password, NULL, interrupt_cmd);
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
			if (!hook->tmp_header) { resl = ST_NOMEM; break; }
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
