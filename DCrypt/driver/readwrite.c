/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2019-2026
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
#include "misc_irp.h"
#include "readwrite.h"
#include "io_control.h"
#include "mount.h"
#include "driver.h"
#include "fast_crypt.h"
#include "misc_mem.h"
#include "debug.h"
#include "alloc_bitmap.h"
#include "safe_log.h"

#define SSD_PAGE_SIZE				4096
#define SSD_ERASE_BLOCK_SIZE		(128 * 1024)

#define CHUNK_READ_THRESHOLD		(128 * 1024)
#define CHUNK_READ_CHUNK_SIZE		(512 * 1024)
#define CHUNK_MIN_READ_SIZE			(64 * 1024)
#define CHUNK_READ_ALIGN			SSD_PAGE_SIZE

#define CHUNK_WRITE_THRESHOLD		(128 * 1024)
#define CHUNK_WRITE_CHUNK_SIZE		SSD_ERASE_BLOCK_SIZE
#define CHUNK_WRITE_ALIGN			SSD_ERASE_BLOCK_SIZE

#define IS_CHUNKING_NEEDED(_length, _is_read) ( \
	(((_is_read) != 0) && ((_length) >= CHUNK_READ_THRESHOLD)) || \
	(((_is_read) == 0) && ((_length) >= CHUNK_WRITE_THRESHOLD)) )

/*
 * READ_PIPELINE_DEPTH - keep N chunk reads in flight (Q1T1 read performance).
 * The single-chunk read path has one read IRP in flight and needs a work item to issue
 * the next one from the DISPATCH_LEVEL completion, which leaves fast NVMe disks idle.
 * With pre-allocated IRPs/MDLs each completion issues the next read directly.
 * Writes do not need this: encryption (cp_parallelized_crypt) runs ahead of them.
 */
//#define READ_PIPELINE_DEPTH 4

#ifdef READ_PIPELINE_DEPTH
struct _io_context;  // forward declaration

typedef struct _read_slot {
	struct _io_context *ctx;	// back pointer to io_context
	int                 index;	// slot index (0 to READ_PIPELINE_DEPTH-1)
	PIRP                irp;
	PMDL                mdl;
	ULONG               chunk_offset;	// offset within request buffer
	ULONG               chunk_length;	// length of this chunk
	ULONGLONG           chunk_diskof;	// disk offset for I/O
	xts_key            *chunk_key;		// XTS key for decryption
} read_slot;
#endif

typedef struct _io_context {
	dev_hook *hook;
	PIRP      orig_irp;
	PIRP      new_irp;
	//
	PUCHAR buff;
	PUCHAR new_buff;
	int    new_buff_index;		// new_buff lookaside list index (-1, if allocated from pool)
	//
	ULONG     length;			// request length
	ULONGLONG offset;			// request disk offset
	ULONG     completed;		// IO completed bytes
	ULONG     encrypted;		// encrypted bytes
	//
	volatile long refs;			// context references counter

#ifdef DC_CONCURRENT_TRANSCRYPT
	ULONGLONG trans_boundary;	// Snapshotted tmp_size at I/O start (for concurrent transcryption)
	BOOLEAN   trans_io;			// TRUE if this I/O is during transcryption (needs pending count decrement)
	xts_key  *snapshot_dsk_key; // Snapshotted dsk_key at I/O start (prevents race during key changes)
	xts_key  *snapshot_tmp_key; // Snapshotted tmp_key at I/O start (prevents race during key changes)
	BOOLEAN   untracked;        // counted in hook->trans.untracked_io until it completes
#endif
	

	ULONGLONG chunk_diskof;
	ULONG     chunk_length;
	ULONG     chunk_offset;
	xts_key  *chunk_key;
	
	BOOLEAN expected;			// this io operation is expected, enable optimization
	BOOLEAN discontinuous;		// this is a discontinuous chunk (written by the encrypt chain only)
	BOOLEAN write_pending;		// write operation currently pending
	BOOLEAN enc_parked;			// encrypt chain stopped after a discontinuous chunk, waiting for the
								// writes to drain; set/cleared only under write_lock (write path)

	BOOLEAN is_sync;			// this is a synchronous IO operation,
								// io_encrypted_irp_io must not return before this IO completed
	
	ULONGLONG  write_offset;
	ULONG      write_length;
	
	KSPIN_LOCK write_lock;

	KEVENT   done_event;
	NTSTATUS status;

	WORK_QUEUE_ITEM work_item;

#ifdef READ_PIPELINE_DEPTH
	// Parallel read pipeline (replaces single chunk_mdl)
	read_slot  read_slots[READ_PIPELINE_DEPTH];
	ULONG      read_issued;		// bytes for which reads have been issued
	KSPIN_LOCK read_lock;		// protects read_issued and slot management
#endif

} io_context;

// function types declarations
#ifdef READ_PIPELINE_DEPTH
IO_COMPLETION_ROUTINE io_read_slot_complete;	// parallel read completion
#else
WORKER_THREAD_ROUTINE io_async_read_chunk;
IO_COMPLETION_ROUTINE io_chunk_read_complete;
#endif
WORKER_THREAD_ROUTINE io_write_next_chunk;
IO_COMPLETION_ROUTINE io_chunk_write_complete;
WORKER_THREAD_ROUTINE io_async_encrypt_chunk;
#ifdef DC_CONCURRENT_TRANSCRYPT
IO_COMPLETION_ROUTINE io_untracked_fwd_complete;
WORKER_THREAD_ROUTINE io_overlap_retry_worker;
#endif

#define io_context_addref(_ctx)      ( InterlockedIncrement(&(_ctx)->refs) )
#define io_set_status(_ctx, _status) ( (_ctx)->status = (_status) )

static NPAGED_LOOKASIDE_LIST g_io_contexts_list;    // Non-Paged lookaside list for io_context structures allocation
static NPAGED_LOOKASIDE_LIST g_temp_buff_lists[12]; // Lookaside lists for temporary buffers (512 - 2097152 bytes length)

static void io_context_deref(io_context *ctx)
{
	if (InterlockedDecrement(&ctx->refs) == 0)
	{
#ifdef DC_CONCURRENT_TRANSCRYPT
		/* Decrement pending I/O count and signal if zero.
		 * This allows transcryption to proceed once all I/O that
		 * started before it has completed. */
		if (ctx->trans_io) {
			LONG new_count = InterlockedDecrement(&ctx->hook->trans.pending_io_count);
			if (new_count == 0) {
				KeSetEvent(&ctx->hook->trans.io_done_event, IO_NO_INCREMENT, FALSE);
			}
		}
		/* every chunk of this request is done - a transcryption start may go on */
		if (ctx->untracked) {
			InterlockedDecrement(&ctx->hook->trans.untracked_io);
		}
#endif

		// complete the original irp
		if (NT_SUCCESS(ctx->status)) {
			ctx->orig_irp->IoStatus.Status = STATUS_SUCCESS;
			ctx->orig_irp->IoStatus.Information = ctx->length;
		} else {
			/* failed request: report no bytes transferred */
			ctx->orig_irp->IoStatus.Status = ctx->status;
			ctx->orig_irp->IoStatus.Information = 0;
		}
		IoCompleteRequest(ctx->orig_irp, IO_DISK_INCREMENT);

		/* Both after IoCompleteRequest (dc_lock_volume's io_depth drain); io_depth first, the
		 * remove lock last: releasing it may let IRP_MN_REMOVE_DEVICE free the dev_hook.
		 * Nothing below touches ctx->hook. */
		InterlockedDecrement(&ctx->hook->io_depth);
		IoReleaseRemoveLock(&ctx->hook->remove_lock, ctx->orig_irp);

		// free resources

		if (ctx->new_irp)
		{
			IoFreeIrp(ctx->new_irp);
		}

		if (ctx->new_buff)
		{
			if (ctx->new_buff_index >= 0) {
				ExFreeToNPagedLookasideList(&g_temp_buff_lists[ctx->new_buff_index], ctx->new_buff);
			} else {
				ExFreePoolWithTag(ctx->new_buff, '7_cd');
			}
		}

#ifdef READ_PIPELINE_DEPTH
		// Free parallel read pipeline resources
		{
			int i;
			for (i = 0; i < READ_PIPELINE_DEPTH; i++)
			{
				if (ctx->read_slots[i].mdl)
					IoFreeMdl(ctx->read_slots[i].mdl);
				if (ctx->read_slots[i].irp)
					IoFreeIrp(ctx->read_slots[i].irp);
			}
		}
#endif

		// set the completion event if needed
		if (ctx->is_sync) {
			KeSetEvent(&ctx->done_event, IO_NO_INCREMENT, FALSE);
		} else {
			ExFreeToNPagedLookasideList(&g_io_contexts_list, ctx);
		}
	}
}

static ULONG io_read_chunk_length(io_context *ctx)
{
	ULONG remain = ctx->length - ctx->completed;
	ULONG length = min(remain / 2, CHUNK_READ_CHUNK_SIZE);

	// length must be SSD_PAGE_SIZE aligned
	if (length & (SSD_PAGE_SIZE-1))
	{
		length += SSD_PAGE_SIZE - (length & (SSD_PAGE_SIZE-1));
	}

	// don't create chunks that are too small
	if (remain - length < CHUNK_MIN_READ_SIZE)
	{
		length += remain - length;
	}	
	
	// increase the first chunk's size so subsequent chunks start aligned 
	if ( (ctx->chunk_offset == 0) && ((ctx->offset + length) & (CHUNK_READ_ALIGN-1)) )
	{
		length += CHUNK_READ_ALIGN - ((ctx->offset + length) & (CHUNK_READ_ALIGN-1));
	}
	return length;
}

static ULONG io_write_chunk_length(io_context *ctx)
{
	ULONG length = CHUNK_WRITE_CHUNK_SIZE;

	// increase the first chunk's size so subsequent chunks start aligned
	if ( (ctx->chunk_offset == 0) && ((ctx->offset + length) & (CHUNK_WRITE_ALIGN-1)) )
	{
		length += CHUNK_WRITE_ALIGN - ((ctx->offset + length) & (CHUNK_WRITE_ALIGN-1));
	}
	return length;
}

static void io_async_make_chunk(io_context *ctx, BOOLEAN is_read)
{
	dev_hook *hook = ctx->hook;
	ULONG     done = is_read != 0 ? ctx->completed : ctx->encrypted;
	
	ctx->chunk_diskof  = ctx->offset + done;
	ctx->chunk_offset  = done;
#ifdef DC_CONCURRENT_TRANSCRYPT
	/* key snapshotted at I/O start (see io_read_write_irp): stays consistent even if
	 * re-encryption init changes hook->dsk_key meanwhile */
	ctx->chunk_key     = ctx->snapshot_dsk_key;
#else
	ctx->chunk_key     = hook->dsk_key;
#endif
	ctx->discontinuous = FALSE;

	// handle redirected sectors at partition start
	if ( !(hook->flags & F_NO_REDIRECT) && (ctx->chunk_diskof < hook->head_len) )
	{
		/* remaining bytes of the redirected area; must not run past head_len (end of storage) */
		ctx->chunk_length  = hook->head_len - (ULONG)ctx->chunk_diskof;
		ctx->chunk_diskof  = ctx->chunk_diskof + hook->stor_off;
		ctx->discontinuous = TRUE;
	}
	// handle redirected sectors at partition end (backup header area)
	else if ( (hook->flags & F_HEAD_BACKUP) && hook->tail_len != 0 && (ctx->chunk_diskof >= hook->dsk_size - hook->tail_len) )
	{
		/* End sectors are stored at: stor_off + stor_len - head_len + (offset from partition end area) */
		u64 end_area_offset = ctx->chunk_diskof - (hook->dsk_size - hook->tail_len);
		/* Remaining bytes in the backup area from current offset */
		ctx->chunk_length  = hook->tail_len - (ULONG)end_area_offset;
		ctx->chunk_diskof  = hook->tail_off + end_area_offset;
		ctx->discontinuous = TRUE;
	} 
	else 
	{
		if ( (dc_conf_flags & CONF_ENABLE_SSD_OPT) && (hook->flags & F_SSD) &&
			 (hook->io_depth == 1 && ctx->expected) && IS_CHUNKING_NEEDED(ctx->length, is_read) )
		{
			if (is_read) {
				ctx->chunk_length = io_read_chunk_length(ctx);
			} else {
				ctx->chunk_length = io_write_chunk_length(ctx);
			}
		} else {
			/* remaining request bytes (keeps the test below from flagging a chunk whose
			 * request ends before t) */
			ctx->chunk_length = ctx->length - done;
		}

		/* a normal chunk must stop where the redirected partition end begins (t), and is
		 * discontinuous: the tail chunk must not be appended to its write. */
		if ((hook->flags & F_HEAD_BACKUP) && hook->tail_len != 0)
		{
			u64 t = hook->dsk_size - hook->tail_len;

			/* ">= t": a chunk that ends exactly at t must also be marked */
			if (ctx->chunk_diskof < t && ctx->chunk_diskof + ctx->chunk_length >= t)
			{
				ctx->chunk_length  = (ULONG)(t - ctx->chunk_diskof);
				ctx->discontinuous = TRUE;
			}
		}
	}

	// handle partial encrypted state - hook->tmp_size must be > 0
#ifdef DC_CONCURRENT_TRANSCRYPT
	if (ctx->trans_io && ctx->trans_boundary > 0)
	{
		/* boundary and keys snapshotted at I/O start: the pending_io_count reservation
		 * keeps transcryption from processing a new block until this I/O completes */
		ULONGLONG boundary = ctx->trans_boundary;

		if (ctx->chunk_diskof >= boundary)
		{
			ctx->chunk_key = (hook->flags & F_REENCRYPT) ? ctx->snapshot_tmp_key : NULL;
		} else
		{
			if (ctx->chunk_diskof + ctx->chunk_length > boundary)
			{
				ctx->chunk_length = (ULONG)(boundary - ctx->chunk_diskof);
			}
		}
	}
#else
	if ((hook->flags & F_SYNC) && hook->tmp_size > 0)
	{
		if (ctx->chunk_diskof >= hook->tmp_size)
		{
			ctx->chunk_key = (hook->flags & F_REENCRYPT) ? hook->tmp_key : NULL;
		} else
		{
			if (ctx->chunk_diskof + ctx->chunk_length > hook->tmp_size)
			{
				ctx->chunk_length = (ULONG)(hook->tmp_size - ctx->chunk_diskof);
			}
		}
	}
#endif
	if (ctx->chunk_length > ctx->length - done)
	{
		ctx->chunk_length = ctx->length - done;
	}
}

#ifdef READ_PIPELINE_DEPTH
// Calculate chunk parameters for a parallel read at the given offset
static void io_make_read_chunk_at_offset(io_context *ctx, read_slot *slot, ULONG offset)
{
	dev_hook *hook = ctx->hook;

	slot->chunk_offset = offset;
	slot->chunk_diskof = ctx->offset + offset;
#ifdef DC_CONCURRENT_TRANSCRYPT
	slot->chunk_key = ctx->snapshot_dsk_key;
#else
	slot->chunk_key = hook->dsk_key;
#endif

	// Default chunk size for parallel reads
	slot->chunk_length = CHUNK_READ_CHUNK_SIZE;

	// Handle redirected sectors at partition start
	if (!(hook->flags & F_NO_REDIRECT) && (slot->chunk_diskof < hook->head_len))
	{
		slot->chunk_length = hook->head_len - (ULONG)slot->chunk_diskof;
		slot->chunk_diskof = slot->chunk_diskof + hook->stor_off;
	}
	// Handle redirected sectors at partition end (backup header area)
	else if ((hook->flags & F_HEAD_BACKUP) && hook->tail_len != 0 &&
	         (slot->chunk_diskof >= hook->dsk_size - hook->tail_len))
	{
		u64 end_area_offset = slot->chunk_diskof - (hook->dsk_size - hook->tail_len);
		slot->chunk_length = hook->tail_len - (ULONG)end_area_offset;
		slot->chunk_diskof = hook->tail_off + end_area_offset;
	}
	// a normal slot must stop where the redirected partition end begins
	else if ((hook->flags & F_HEAD_BACKUP) && hook->tail_len != 0 &&
	         slot->chunk_diskof + slot->chunk_length > hook->dsk_size - hook->tail_len)
	{
		slot->chunk_length = (ULONG)(hook->dsk_size - hook->tail_len - slot->chunk_diskof);
	}

	// Handle partial encryption state
#ifdef DC_CONCURRENT_TRANSCRYPT
	if (ctx->trans_io && ctx->trans_boundary > 0)
	{
		if (slot->chunk_diskof >= ctx->trans_boundary)
		{
			slot->chunk_key = (hook->flags & F_REENCRYPT) ? ctx->snapshot_tmp_key : NULL;
		}
		else if (slot->chunk_diskof + slot->chunk_length > ctx->trans_boundary)
		{
			slot->chunk_length = (ULONG)(ctx->trans_boundary - slot->chunk_diskof);
		}
	}
#else
	if ((hook->flags & F_SYNC) && hook->tmp_size > 0)
	{
		if (slot->chunk_diskof >= hook->tmp_size)
		{
			slot->chunk_key = (hook->flags & F_REENCRYPT) ? hook->tmp_key : NULL;
		}
		else if (slot->chunk_diskof + slot->chunk_length > hook->tmp_size)
		{
			slot->chunk_length = (ULONG)(hook->tmp_size - slot->chunk_diskof);
		}
	}
#endif

	// Clamp to remaining request length
	if (slot->chunk_length > ctx->length - offset)
	{
		slot->chunk_length = ctx->length - offset;
	}
}

// Issue a read for a specific slot
static void io_issue_read_for_slot(read_slot *slot)
{
	io_context         *ctx = slot->ctx;
	PIO_STACK_LOCATION  new_sp;
	PUCHAR              pbuf_va;

	new_sp = IoGetNextIrpStackLocation(slot->irp);
	new_sp->MajorFunction = IRP_MJ_READ;
	new_sp->Flags         = IoGetCurrentIrpStackLocation(ctx->orig_irp)->Flags;
	new_sp->Parameters.Read.Length              = slot->chunk_length;
	new_sp->Parameters.Read.ByteOffset.QuadPart = slot->chunk_diskof;

	// Build partial MDL for this chunk
	pbuf_va = ((PUCHAR)MmGetMdlVirtualAddress(ctx->orig_irp->MdlAddress)) + slot->chunk_offset;
	IoBuildPartialMdl(ctx->orig_irp->MdlAddress, slot->mdl, pbuf_va, slot->chunk_length);
	slot->irp->MdlAddress = slot->mdl;

	IoSetCompletionRoutine(slot->irp, io_read_slot_complete, slot, TRUE, TRUE, TRUE);
	IoCallDriver(ctx->hook->orig_dev, slot->irp);
}

// Completion routine for parallel read slot
static NTSTATUS io_read_slot_complete(PDEVICE_OBJECT dev_obj, PIRP irp, read_slot *slot)
{
	io_context *ctx      = slot->ctx;
	dev_hook   *hook     = ctx->hook;
	PUCHAR      buff     = ctx->buff + slot->chunk_offset;
	NTSTATUS    status   = irp->IoStatus.Status;
	ULONGLONG   offset   = slot->chunk_diskof;
	ULONG       length   = (ULONG)irp->IoStatus.Information;
	xts_key    *slot_key = slot->chunk_key;
	KLOCK_QUEUE_HANDLE lock_queue;
	ULONG       next_offset;
	BOOLEAN     issue_more = FALSE;

	// Clear MDL pointer (MDL is reused, freed in io_context_deref)
	irp->MdlAddress = NULL;

	if (NT_SUCCESS(status))
	{
		// Check if we should issue another read for this slot
		KeAcquireInStackQueuedSpinLock(&ctx->read_lock, &lock_queue);
		if (ctx->read_issued < ctx->length)
		{
			next_offset = ctx->read_issued;
			io_make_read_chunk_at_offset(ctx, slot, next_offset);
			ctx->read_issued += slot->chunk_length;
			issue_more = TRUE;
		}
		KeReleaseInStackQueuedSpinLock(&lock_queue);

		// Issue next read if needed (before decrypting, to keep pipeline full)
		if (issue_more)
		{
			IoReuseIrp(irp, STATUS_SUCCESS);
			io_context_addref(ctx);
			io_issue_read_for_slot(slot);
		}

		// Decrypt chunk if needed
		if (slot_key != NULL)
		{
			if (hook->flags & F_NO_REDIRECT)
			{
				offset -= hook->head_len;
			}
			io_context_addref(ctx);
			cp_parallelized_crypt(0, slot_key, io_context_deref, ctx, buff, buff, length, offset);
		}
	}
	else
	{
		// On error, set status
		io_set_status(ctx, status);
	}

	io_context_deref(ctx);
	return STATUS_MORE_PROCESSING_REQUIRED;
}

// Start the parallel read pipeline - issues initial batch of reads
static void io_start_read_pipeline(io_context *ctx)
{
	int i;
	KLOCK_QUEUE_HANDLE lock_queue;

	KeInitializeSpinLock(&ctx->read_lock);
	ctx->read_issued = 0;

	for (i = 0; i < READ_PIPELINE_DEPTH; i++)
	{
		read_slot *slot = &ctx->read_slots[i];

		KeAcquireInStackQueuedSpinLock(&ctx->read_lock, &lock_queue);
		if (ctx->read_issued >= ctx->length)
		{
			KeReleaseInStackQueuedSpinLock(&lock_queue);
			break;
		}

		io_make_read_chunk_at_offset(ctx, slot, ctx->read_issued);
		ctx->read_issued += slot->chunk_length;
		KeReleaseInStackQueuedSpinLock(&lock_queue);

		io_context_addref(ctx);
		io_issue_read_for_slot(slot);
	}
}
#else
static NTSTATUS io_chunk_read_complete(PDEVICE_OBJECT dev_obj, PIRP irp, io_context *ctx)
{
	dev_hook* hook   = ctx->hook;
	PUCHAR    buff   = ctx->buff + ctx->chunk_offset;
	NTSTATUS  status = irp->IoStatus.Status;
	ULONGLONG offset = ctx->chunk_diskof;
	ULONG     length = (ULONG)irp->IoStatus.Information;
	xts_key  *chunk_key = ctx->chunk_key;  /* Capture BEFORE starting next chunk */

	// free mdl from the chunk irp
	IoFreeMdl(irp->MdlAddress);
	irp->MdlAddress	= NULL;

	// update completed length
	ctx->completed += ctx->chunk_length;

	if (NT_SUCCESS(status))
	{
		// if reading operation is not completed, start next chunk
		if (ctx->completed < ctx->length)
		{
			IoReuseIrp(irp, STATUS_SUCCESS);
			/* IoReuseIrp re-initialises the IRP: restore thread / file object of the request */
			irp->Tail.Overlay.Thread             = ctx->orig_irp->Tail.Overlay.Thread;
			irp->Tail.Overlay.OriginalFileObject = ctx->orig_irp->Tail.Overlay.OriginalFileObject;
			io_context_addref(ctx);
			io_async_read_chunk(ctx);
		}

		// decrypt chunk if needed
		// IMPORTANT: Use captured chunk_key, not ctx->chunk_key which may have been
		// overwritten by io_async_read_chunk -> io_async_make_chunk for the next chunk
		if (chunk_key != NULL)
		{
			if (hook->flags & F_NO_REDIRECT)
			{
				offset -= hook->head_len; // XTS offset is calculated from the beginning of the volume data
				                          // if redirection not used, subtract the header length
			}
			io_context_addref(ctx);
			cp_parallelized_crypt(0, chunk_key, io_context_deref, ctx, buff, buff, length, offset);
		}
	}

	// record failures only: storing success could overwrite the error of a later chunk
	// that already completed
	if (NT_SUCCESS(status) == FALSE)
	{
		io_set_status(ctx, status);
	}
	io_context_deref(ctx);
	return STATUS_MORE_PROCESSING_REQUIRED;
}

static void io_async_read_chunk(io_context *ctx)
{
	PIO_STACK_LOCATION new_sp;
	PMDL               new_mdl;
	PUCHAR             pbuf_va;

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL) {
		ExInitializeWorkItem(&ctx->work_item, io_async_read_chunk, ctx);
		ExQueueWorkItem(&ctx->work_item, CriticalWorkQueue);
		return;
	}
	io_async_make_chunk(ctx, TRUE);

	new_sp = IoGetNextIrpStackLocation(ctx->new_irp);
	new_sp->MajorFunction = IRP_MJ_READ;
	new_sp->Flags         = IoGetCurrentIrpStackLocation(ctx->orig_irp)->Flags;
	new_sp->Parameters.Read.Length              = ctx->chunk_length;
	new_sp->Parameters.Read.ByteOffset.QuadPart = ctx->chunk_diskof;
	
	pbuf_va = ((PUCHAR)MmGetMdlVirtualAddress(ctx->orig_irp->MdlAddress)) + ctx->chunk_offset;
	new_mdl = mm_allocate_mdl_success(pbuf_va, ctx->chunk_length);

	if (new_mdl == NULL) {
		io_set_status(ctx, STATUS_INSUFFICIENT_RESOURCES);
		io_context_deref(ctx); 
		return;
	}
	IoBuildPartialMdl(ctx->orig_irp->MdlAddress, new_mdl, pbuf_va, ctx->chunk_length);
	ctx->new_irp->MdlAddress = new_mdl;

	IoSetCompletionRoutine(ctx->new_irp, io_chunk_read_complete, ctx, TRUE, TRUE, TRUE);
	IoCallDriver(ctx->hook->orig_dev, ctx->new_irp);
}
#endif /* READ_PIPELINE_DEPTH */

static NTSTATUS io_chunk_write_complete(PDEVICE_OBJECT dev_obj, PIRP irp, io_context *ctx)
{
	KLOCK_QUEUE_HANDLE lock_queue;
	BOOLEAN            need_write;
	BOOLEAN            restart = FALSE;

	// free mdl from the chunk irp
	IoFreeMdl(irp->MdlAddress);
	irp->MdlAddress	= NULL;

	if (NT_SUCCESS(irp->IoStatus.Status))
	{
#ifndef DC_CONCURRENT_TRANSCRYPT
		/* Track writes in allocation bitmap for skip unused sectors (legacy sync build only;
		 * the concurrent build marks them at admission under range_lock, see io_read_write_irp) */
		if (ctx->hook->alloc_bitmap != NULL) {
			dc_bitmap_mark_allocated(ctx->hook, ctx->write_offset, ctx->write_length);
		}
#endif

		KeAcquireInStackQueuedSpinLock(&ctx->write_lock, &lock_queue);

		// update pointers
		ctx->write_offset += ctx->write_length;
		ctx->completed    += ctx->write_length;
		ctx->write_length  = ctx->encrypted - ctx->completed;
		need_write = ctx->write_pending = (ctx->write_length != 0);

		// A parked encrypt chain restarts only once everything encrypted so far is written,
		// so the next (possibly redirected) chunk starts a new write at its own offset.
		// Decided under write_lock with enc_parked: exactly one party restarts it, once.
		if (ctx->enc_parked && !need_write && ctx->completed < ctx->length) {
			ctx->enc_parked = FALSE;
			restart = TRUE;
		}

		KeReleaseInStackQueuedSpinLock(&lock_queue);

		if (restart)
		{
			/* io_chunk_encrypt_complete sets write_offset from that chunk's disk offset */
			io_context_addref(ctx);
			io_async_encrypt_chunk(ctx);
		}

		// if next encrypted part available, start writing it now
		// (io_write_next_chunk re-initialises the chunk IRP with IoReuseIrp)
		if (need_write)
		{
			io_context_addref(ctx);
			io_write_next_chunk(ctx);
		}
	} else {
		/* fail-stop: write_pending stays TRUE, so no further chunk write or chain restart
		 * starts; the request completes with this status once the references drain. */
		DbgMsg("io_chunk_write_complete: write failed, dev=%ws, off=%I64u, len=%u, status=%08x\n",
		       ctx->hook->dev_name, ctx->write_offset, ctx->write_length, irp->IoStatus.Status);
		io_set_status(ctx, irp->IoStatus.Status);
	}
	io_context_deref(ctx);
	return STATUS_MORE_PROCESSING_REQUIRED;
}

static void io_write_next_chunk(io_context *ctx)
{
	PIO_STACK_LOCATION new_sp;
	PIRP               new_irp;

	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)	{
		ExInitializeWorkItem(&ctx->work_item, io_write_next_chunk, ctx);
		ExQueueWorkItem(&ctx->work_item, CriticalWorkQueue);
		return;
	}
	new_irp = ctx->new_irp;
	/* every write reuses the chunk IRP: re-initialise it, restore thread / file object */
	IoReuseIrp(new_irp, STATUS_SUCCESS);
	new_irp->Tail.Overlay.Thread             = ctx->orig_irp->Tail.Overlay.Thread;
	new_irp->Tail.Overlay.OriginalFileObject = ctx->orig_irp->Tail.Overlay.OriginalFileObject;
	new_sp  = IoGetNextIrpStackLocation(new_irp);

	new_sp->MajorFunction = IRP_MJ_WRITE;
	new_sp->Flags         = IoGetCurrentIrpStackLocation(ctx->orig_irp)->Flags;
	new_sp->Parameters.Write.Length              = ctx->write_length;
	new_sp->Parameters.Write.ByteOffset.QuadPart = ctx->write_offset;
	
	if ( (new_irp->MdlAddress = mm_allocate_mdl_success(ctx->new_buff + ctx->completed, ctx->write_length)) == NULL )
	{
		io_set_status(ctx, STATUS_INSUFFICIENT_RESOURCES);
		io_context_deref(ctx);
		return;
	}
	MmBuildMdlForNonPagedPool(new_irp->MdlAddress);
	IoSetCompletionRoutine(new_irp, io_chunk_write_complete, ctx, TRUE, TRUE, TRUE);
	IoCallDriver(ctx->hook->orig_dev, new_irp);
}

static void io_chunk_encrypt_complete(io_context *ctx)
{
	KLOCK_QUEUE_HANDLE lock_queue;
	BOOLEAN            need_write;
	BOOLEAN            cont;

	KeAcquireInStackQueuedSpinLock(&ctx->write_lock, &lock_queue);

	/* A write sequence starts when no write is pending and begins at THIS chunk's disk
	 * offset, which may be redirected. Chunks that must not be merged with a pending write
	 * are discontinuous (io_async_make_chunk), encrypted only once that write is done. */
	if (ctx->write_pending == FALSE) {
		ctx->write_offset = ctx->chunk_diskof;
	}

	// update encrypted length
	ctx->encrypted += ctx->chunk_length;

	if (need_write = (ctx->write_pending == FALSE)) {
		ctx->write_pending = TRUE;
		ctx->write_length = ctx->encrypted - ctx->completed;
	}

	/* Decided under write_lock, before the write below is issued (its completion may restart
	 * a parked chain): a discontinuous chunk parks the chain, the completion that drains the
	 * last pending write restarts it. */
	cont = FALSE;
	if (ctx->encrypted < ctx->length) {
		if (ctx->discontinuous) {
			ctx->enc_parked = TRUE;
		} else {
			cont = TRUE;
		}
	}
	KeReleaseInStackQueuedSpinLock(&lock_queue);

	// write encrypted part if previous write operation completed
	if (need_write)
	{
		io_context_addref(ctx);
		io_write_next_chunk(ctx);
	}

	// encrypt next chunk if needed
	if (cont)
	{
		io_context_addref(ctx);
		io_async_encrypt_chunk(ctx);
	}

	io_context_deref(ctx);
}

static void io_async_encrypt_chunk(io_context *ctx)
{
	PUCHAR    in_buf, out_buf;
	ULONGLONG offset;
			
	io_async_make_chunk(ctx, FALSE);
	
	out_buf = ctx->new_buff + ctx->encrypted;
	in_buf = ctx->buff + ctx->encrypted;
	offset = ctx->chunk_diskof;
		
	if (ctx->chunk_key != NULL)
	{
		if (ctx->hook->flags & F_NO_REDIRECT)
		{
			offset -= ctx->hook->head_len; // XTS offset is calculated from the beginning of the volume data
				                           // if redirection not used, subtract the header length
		}
		cp_parallelized_crypt(1, ctx->chunk_key, io_chunk_encrypt_complete, ctx, in_buf, out_buf, ctx->chunk_length, offset);
	} else {
		memcpy(out_buf, in_buf, ctx->chunk_length);
		io_chunk_encrypt_complete(ctx);
	}
}

#ifdef DC_CONCURRENT_TRANSCRYPT
NTSTATUS io_encrypted_irp_io(dev_hook *hook, PIRP irp, BOOLEAN is_sync, BOOLEAN trans_io, ULONGLONG trans_boundary, xts_key *snapshot_dsk_key, xts_key *snapshot_tmp_key, BOOLEAN untracked)
#else
NTSTATUS io_encrypted_irp_io(dev_hook *hook, PIRP irp, BOOLEAN is_sync)
#endif
{
	PIO_STACK_LOCATION irp_sp = IoGetCurrentIrpStackLocation(irp);
	NTSTATUS           status = STATUS_PENDING;
	io_context*        ctx;
	int                i;

	// allocate the IO context
	if ( (ctx = (io_context*)ExAllocateFromNPagedLookasideList(&g_io_contexts_list)) == NULL )
	{
#ifdef DC_CONCURRENT_TRANSCRYPT
		/* If we allocated a pending I/O slot, release it on failure */
		if (trans_io) {
			LONG new_count = InterlockedDecrement(&hook->trans.pending_io_count);
			if (new_count == 0) {
				KeSetEvent(&hook->trans.io_done_event, IO_NO_INCREMENT, FALSE);
			}
		}
		/* completed here, nothing of it reached the disk */
		if (untracked) {
			InterlockedDecrement(&hook->trans.untracked_io);
		}
#endif
		return dc_release_irp(hook, irp, STATUS_INSUFFICIENT_RESOURCES);
	}

	// initialize new IO context
	memset(ctx, 0, sizeof(io_context));

	ctx->orig_irp = irp;
	ctx->hook = hook;
	ctx->refs = 1;

#ifdef DC_CONCURRENT_TRANSCRYPT
	ctx->trans_io = trans_io;
	ctx->trans_boundary = trans_boundary;
	ctx->snapshot_dsk_key = snapshot_dsk_key;
	ctx->snapshot_tmp_key = snapshot_tmp_key;
	ctx->untracked = untracked;
#endif

	// increment hook IO queue depth
	InterlockedIncrement(&hook->io_depth);

	if (ctx->is_sync = is_sync)
	{
		KeInitializeEvent(&ctx->done_event, NotificationEvent, FALSE);
	}

	/* lock on hibernate: re-check the lock AFTER io_depth is raised (the entry test in
	 * io_read_write_irp can race dc_lock_volume's io_depth drain). Both sides are
	 * interlocked: either the drain sees this request, or this request sees the lock. */
	if (hook->flags & F_HIBER_ERASE)
	{
		status = STATUS_FVE_LOCKED_VOLUME;
		goto on_fail;
	}
	/* order that check before the key contents are read (acquire, see io_read_write_irp) */
	KeMemoryBarrier();

	if (irp_sp->MajorFunction == IRP_MJ_READ) {
		ctx->offset = irp_sp->Parameters.Read.ByteOffset.QuadPart;
		ctx->length = irp_sp->Parameters.Read.Length;
	} else {
		ctx->offset = irp_sp->Parameters.Write.ByteOffset.QuadPart;
		ctx->length = irp_sp->Parameters.Write.Length;
	}

	// IO operations must be within the volume data range, offset and length SECTOR_SIZE
	// aligned. Overflow-safe form: a huge (negative) ByteOffset must not wrap.
	if ( (ctx->length == 0) ||
		 (ctx->length & (SECTOR_SIZE - 1)) || (ctx->offset & (SECTOR_SIZE - 1)) ||
		 (ctx->offset >= hook->use_size) || (ctx->length > hook->use_size - ctx->offset) )
	{
		DbgMsg("unaligned or out of range IO operation, dev=%ws, %s off=%I64u len=%u use_size=%I64u dsk_size=%I64u flags=%08x\n",
			hook->dev_name, irp_sp->MajorFunction == IRP_MJ_READ ? "read" : "write",
			ctx->offset, ctx->length, hook->use_size, hook->dsk_size, hook->flags);
		status = STATUS_INVALID_PARAMETER;
		goto on_fail;
	}

	// writing to redirection area must be blocked for preventing file system corruption
	// (checked after the range validation, so is_intersect never sees a wrapped range)
	if ( irp_sp->MajorFunction != IRP_MJ_READ && !(hook->flags & F_NO_REDIRECT) &&
		  (is_intersect(ctx->offset, ctx->length, hook->stor_off, hook->stor_len) != 0) )
	{
		DbgMsg("writing to redirection area blocked, dev=%ws\n", hook->dev_name);
		status = STATUS_ACCESS_DENIED;
		goto on_fail;
	}

	// detect expected sequential IO operations
	if (InterlockedExchange64(&hook->expect_off, ctx->offset + ctx->length) == ctx->offset)
	{
		ctx->expected = TRUE;
	}

	// if redirection not used, volume data shifted by volume header length
	if (hook->flags & F_NO_REDIRECT)
	{
		ctx->offset += hook->head_len; // add the volume header length
		                               // to get the offset of the data on the storage device
	}

	// allocate resources for processing request
	if ( (ctx->new_irp = mm_allocate_irp_success(hook->orig_dev->StackSize)) == NULL ||
		 (ctx->buff = (PUCHAR)mm_map_mdl_success(irp->MdlAddress)) == NULL )
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto on_fail;
	}
	
	// copy original IRP source to new IRP
	ctx->new_irp->Tail.Overlay.Thread = irp->Tail.Overlay.Thread;
	ctx->new_irp->Tail.Overlay.OriginalFileObject = irp->Tail.Overlay.OriginalFileObject;

	/* the original IRP is marked pending only right before the pipeline starts, after every
	 * allocation that can fail: on_fail returns the error status, legal only if not pending */

	if (irp_sp->MajorFunction == IRP_MJ_WRITE)
	{
		// allocate memory from temporary buffer lookaside list
		for (i = 0; i < sizeof(g_temp_buff_lists) / sizeof(g_temp_buff_lists[0]); i++)
		{
			if ( (ctx->length <= (512u << i)) &&
				 (ctx->new_buff = (PUCHAR)ExAllocateFromNPagedLookasideList(&g_temp_buff_lists[i])) != NULL )
			{
				ctx->new_buff_index = i;
				break;
			}
		}

		// if memory not allocated from lookaside, allocate from pool
		if (ctx->new_buff == NULL)
		{
			if ( (ctx->new_buff = (PUCHAR)mm_alloc_success(NonPagedPool, ctx->length, '7_cd')) == NULL )
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				goto on_fail;
			}
			ctx->new_buff_index = -1;
		}

		KeInitializeSpinLock(&ctx->write_lock);
		IoMarkIrpPending(irp);
		io_async_encrypt_chunk(ctx);
	} else {
#ifdef READ_PIPELINE_DEPTH
		// Pre-allocate IRPs and MDLs for parallel read pipeline at PASSIVE_LEVEL
		// where we can retry on failure. This allows read slots to run at DISPATCH_LEVEL
		// without work queue delay, keeping the disk queue full for better Q1T1 performance.
		int slot_idx;
		for (slot_idx = 0; slot_idx < READ_PIPELINE_DEPTH; slot_idx++)
		{
			read_slot *slot = &ctx->read_slots[slot_idx];
			slot->ctx = ctx;
			slot->index = slot_idx;
			slot->irp = mm_allocate_irp_success(hook->orig_dev->StackSize);
			slot->mdl = mm_allocate_mdl_success(ctx->buff, CHUNK_READ_CHUNK_SIZE);
			if (slot->irp == NULL || slot->mdl == NULL)
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				goto on_fail;
			}
			// Copy original IRP overlay for each slot's IRP
			slot->irp->Tail.Overlay.Thread = irp->Tail.Overlay.Thread;
			slot->irp->Tail.Overlay.OriginalFileObject = irp->Tail.Overlay.OriginalFileObject;
		}
		IoMarkIrpPending(irp);
		io_start_read_pipeline(ctx);
		// Balance initial ref - each slot has its own ref, the initial ref=1 must be consumed
		io_context_deref(ctx);
#else
		// IRP_MJ_READ does not require memory allocation, start reading now
		IoMarkIrpPending(irp);
		io_async_read_chunk(ctx);
#endif
	}

cleanup:
	if (is_sync)
	{
		KeWaitForSingleObject(&ctx->done_event, Executive, KernelMode, FALSE, NULL);
		status = ctx->status;
		ExFreeToNPagedLookasideList(&g_io_contexts_list, ctx);
	}
	return status;

on_fail:
	io_set_status(ctx, status);
	io_context_deref(ctx);
	goto cleanup;
}


#ifdef DC_CONCURRENT_TRANSCRYPT
#define RANGES_OVERLAP(_s0, _e0, _s1, _e1) ( max((_s0), (_s1)) < min((_e0), (_e1)) )

/*
 * Does the request [io_offset, io_end) (volume offsets) touch the locked transcryption
 * block [a0, a1)? The block is locked in disk offsets, the partition begin/end locks in
 * volume offsets, and head / tail are redirected into the data area, so test the volume
 * range and every disk range the request maps to. Called under range_lock.
 */
static BOOLEAN io_touches_active(dev_hook *hook, u64 io_offset, u64 io_end, u64 a0, u64 a1)
{
	/* disk frame of the request, as io_async_make_chunk computes chunk_diskof */
	u64 d0 = io_offset;
	u64 d1 = io_end;

	/* volume range (everything not redirected; also the partition-begin/end locks) */
	if (RANGES_OVERLAP(io_offset, io_end, a0, a1)) {
		return TRUE;
	}
	if (hook->flags & F_NO_REDIRECT)
	{
		/* no head redirect; data is shifted by the header length on disk */
		d0 += hook->head_len;
		d1 += hook->head_len;
		if (RANGES_OVERLAP(d0, d1, a0, a1)) {
			return TRUE;
		}
	}
	else if (d0 < hook->head_len)
	{
		/* partition begin -> storage copy at stor_off */
		u64 e = min(d1, (u64)hook->head_len);

		if (RANGES_OVERLAP(hook->stor_off + d0, hook->stor_off + e, a0, a1)) {
			return TRUE;
		}
	}
	/* partition end -> storage at tail_off (disk frame, regardless of F_NO_REDIRECT, like
	 * io_async_make_chunk) */
	if ((hook->flags & F_HEAD_BACKUP) && hook->tail_len != 0)
	{
		u64 t = hook->dsk_size - hook->tail_len;

		if (d1 > t)
		{
			u64 s = max(d0, t);

			if (RANGES_OVERLAP(hook->tail_off + (s - t), hook->tail_off + (d1 - t), a0, a1)) {
				return TRUE;
			}
		}
	}
	return FALSE;
}
/*
 * An I/O that overlaps the locked transcryption range waits for the block. At DISPATCH_LEVEL
 * (an upper filter calling down from a completion routine or DPC) that wait is illegal: the
 * IRP is marked pending and admitted again from a worker thread. The work item lives in the
 * IRP's DriverContext (no allocation, no failure path); the remove-lock reference taken at
 * dispatch stays with the IRP until it completes, so the hook outlives the wait.
 */
C_ASSERT(sizeof(WORK_QUEUE_ITEM) <= sizeof(((PIRP)0)->Tail.Overlay.DriverContext));

static VOID io_overlap_retry_worker(PVOID param)
{
	PIRP      irp  = (PIRP)param;
	dev_hook *hook = (dev_hook*)IoGetCurrentIrpStackLocation(irp)->DeviceObject->DeviceExtension;

	/* completes or forwards the IRP itself (the dispatch already returned STATUS_PENDING) */
	(void)io_read_write_irp(hook, irp);
}

static NTSTATUS io_defer_overlap_wait(PIRP irp)
{
	PWORK_QUEUE_ITEM wi = (PWORK_QUEUE_ITEM)&irp->Tail.Overlay.DriverContext[0];

	IoMarkIrpPending(irp);
	ExInitializeWorkItem(wi, io_overlap_retry_worker, irp);
	ExQueueWorkItem(wi, DelayedWorkQueue);
	return STATUS_PENDING;
}

/*
 * Requests admitted without F_SYNC are counted until they complete, so that a transcryption
 * start can wait for them (dc_drain_untracked_io; a flush does not wait for them). Count
 * first, then read the flags (the increment is a full barrier): a request either sees F_SYNC
 * (uncounted at once, tracked path) or is counted when the start, which publishes F_SYNC
 * first (interlocked), reads the count.
 */
static void io_untracked_enter(dev_hook *hook)
{
	InterlockedIncrement(&hook->trans.untracked_io);
}

static void io_untracked_leave(dev_hook *hook)
{
	InterlockedDecrement(&hook->trans.untracked_io);
}

/* a counted request forwarded raw: uncounted when the lower driver completes it; the remove
 * lock taken at dispatch is held until then, so the hook is alive here */
static NTSTATUS io_untracked_fwd_complete(PDEVICE_OBJECT dev_obj, PIRP irp, PVOID context)
{
	dev_hook *hook = (dev_hook*)dev_obj->DeviceExtension;

	if (irp->PendingReturned) {
		IoMarkIrpPending(irp);
	}
	UNREFERENCED_PARAMETER(context);
	InterlockedDecrement(&hook->trans.untracked_io);
	IoReleaseRemoveLock(&hook->remove_lock, irp); /* last: may let the removal free the hook */
	return STATUS_CONTINUE_COMPLETION;
}

static NTSTATUS io_forward_untracked(dev_hook *hook, PIRP irp)
{
	IoCopyCurrentIrpStackLocationToNext(irp);
	IoSetCompletionRoutine(irp, io_untracked_fwd_complete, NULL, TRUE, TRUE, TRUE);
	return IoCallDriver(hook->orig_dev, irp);
}

NTSTATUS io_forward_plain_irp(dev_hook *hook, PIRP irp)
{
	io_untracked_enter(hook);

	/* enabled since the caller looked (a mount or a transcryption start): dispatch normally */
	if (hook->flags & (F_ENABLED | F_SYNC)) {
		io_untracked_leave(hook);
		return io_read_write_irp(hook, irp);
	}
	return io_forward_untracked(hook, irp);
}

/* a data-changing IOCTL of a plain volume (TRIM, offload write, pass-through, ...) is counted
 * like a write until it completes. Enabled since the caller looked: dispatched again, so the
 * policy of a mounted volume applies. */
NTSTATUS io_forward_plain_ioctl(dev_hook *hook, PIRP irp)
{
	io_untracked_enter(hook);

	/* F_ENABLED only (dc_io_control_irp routes here exactly when it is clear: no recursion) */
	if (hook->flags & F_ENABLED) {
		io_untracked_leave(hook);
		return dc_io_control_irp(hook, irp);
	}
	return io_forward_untracked(hook, irp);
}
#endif /* DC_CONCURRENT_TRANSCRYPT */

NTSTATUS io_read_write_irp(dev_hook *hook, PIRP irp)
{
#ifdef DC_CONCURRENT_TRANSCRYPT
	xts_key *snapshot_dsk_key;
	xts_key *snapshot_tmp_key;
#endif
	u32 flags;

	// reseed RNG on first 1000 I/O operations for collect initial entropy
	if (InterlockedIncrement(&dc_io_count) < 1000) {
		cp_rand_reseed();
	}

	/* locked volume (keys erased at hibernation, FS still mounted): fail every read/write
	 * like a locked BitLocker volume. Tested before F_DISABLE, which the lock also sets. */
	if (hook->flags & F_HIBER_ERASE) {
		return dc_release_irp(hook, irp, STATUS_FVE_LOCKED_VOLUME);
	}
	if (hook->flags & (F_DISABLE | F_FORMATTING)) {
		return dc_release_irp(hook, irp, STATUS_INVALID_DEVICE_STATE);
	}
	/* mounted with a damaged header taken as it is (MF_IGNORE_CRC): its boundary may be wrong -
	 * read-only for every writer (a raw handle too), not only for the file system */
	if ( (hook->flags & F_ENABLED) && (hook->mnt_flags & MF_IGNORE_CRC) &&
		 IoGetCurrentIrpStackLocation(irp)->MajorFunction == IRP_MJ_WRITE )
	{
		return dc_release_irp(hook, irp, STATUS_MEDIA_WRITE_PROTECTED);
	}

	// Format protection: block all writes to unmounted volumes explicitly detected as raw
	// (no filesystem found; F_FS_RAW is not set if detection never ran)
	if ((dc_conf_flags & CONF_PROTECT_RAW_VOLUMES) &&
	    !(hook->flags & F_ENABLED) &&
	    (hook->flags & F_FS_RAW))
	{
		PIO_STACK_LOCATION irp_sp = IoGetCurrentIrpStackLocation(irp);

		if (irp_sp->MajorFunction == IRP_MJ_WRITE)
		{
			DbgMsg("format protection: blocked write (raw volume, no filesystem), dev=%ws\n", hook->dev_name);
			return dc_release_irp(hook, irp, STATUS_ACCESS_DENIED);
		}
	}

#ifdef DC_CONCURRENT_TRANSCRYPT
	/* order the F_HIBER_ERASE check above before the key loads below (ARM64): the unlock
	 * re-keys dsk_key / tmp_key in place and only then clears the lock (interlocked) */
	KeMemoryBarrier();

	/*
	 * Snapshot the keys BEFORE reading F_SYNC: re-encryption init sets F_SYNC, barrier,
	 * then dsk_key = new key, so a reader that sees the new dsk_key also sees F_SYNC
	 * (never F_SYNC clear with the new key). This snapshot is used by the untracked
	 * path; the tracked (F_SYNC) path re-snapshots both keys under range_lock.
	 */
sync_check:
	snapshot_dsk_key = hook->dsk_key;
	snapshot_tmp_key = hook->tmp_key;
	KeMemoryBarrier();  /* Ensure keys are read before F_SYNC */

	/*
	 * Concurrent transcryption: I/O overlapping the active block waits for it.
	 * Protocol: under range_lock, if no overlap, increment pending_io_count and
	 * snapshot tmp_size; the I/O uses that boundary and decrements the count on
	 * completion; transcryption waits for pending_io_count == 0 before a new block.
	 */
	if (hook->flags & F_SYNC)
	{
		transcrypt_state  *trans = &hook->trans;
		PIO_STACK_LOCATION irp_sp = IoGetCurrentIrpStackLocation(irp);
		KIRQL              irql;
		LONG64             active_start, active_end;
		ULONGLONG          trans_boundary;
		u64                io_offset, io_end;
		u32                io_length;

		/* Get I/O range */
		if (irp_sp->MajorFunction == IRP_MJ_READ) {
			io_offset = irp_sp->Parameters.Read.ByteOffset.QuadPart;
			io_length = irp_sp->Parameters.Read.Length;
		} else {
			io_offset = irp_sp->Parameters.Write.ByteOffset.QuadPart;
			io_length = irp_sp->Parameters.Write.Length;
		}
		io_end = io_offset + io_length;

retry_overlap_check:
		KeAcquireSpinLock(&trans->range_lock, &irql);

		/* Re-check F_SYNC under range_lock: cleanup clears it under this lock before
		 * freeing resources. F_PLAIN_IO is also published under it (decryption finish):
		 * plaintext at natural offsets, normal_io forwards it. */
		if (!(hook->flags & F_SYNC) || (hook->flags & F_PLAIN_IO)) {
			KeReleaseSpinLock(&trans->range_lock, irql);
			goto normal_io;
		}

		/* a quarantined block of a power-loss protected session (a journaled block that could
		 * not be completed) fails instead of waiting: only the journal defines its content */
		if (dc_slog_quar_cnt != 0) {
			u64 q_start, q_end;

			if (dc_slog_quar_range(hook, &q_start, &q_end) &&
				io_touches_active(hook, io_offset, io_end, q_start, q_end))
			{
				KeReleaseSpinLock(&trans->range_lock, irql);
				return dc_release_irp(hook, irp, STATUS_DEVICE_DATA_ERROR);
			}
		}

		active_start = trans->active_start;
		active_end = trans->active_end;

		/* Check overlap: if active_start != -1 and the I/O touches the active block,
		 * directly or through a redirect (see io_touches_active) */
		if (active_start != -1 &&
		    io_touches_active(hook, io_offset, io_end, (u64)active_start, (u64)active_end))
		{
			/* Overlap - release lock and wait for block to complete */
			KeReleaseSpinLock(&trans->range_lock, irql);
			/* no wait at DISPATCH_LEVEL - admit it again from a worker thread */
			if (KeGetCurrentIrql() >= DISPATCH_LEVEL) {
				return io_defer_overlap_wait(irp);
			}
			KeWaitForSingleObject(&trans->block_complete,
			                      Executive, KernelMode, FALSE, NULL);
			goto retry_overlap_check;
		}

		/* skip-unused: mark writes in the allocation bitmap in the same range_lock section
		 * that snapshots the boundary; dc_transcrypt_step tests the bitmap and advances
		 * tmp_size under this lock, so either the block is not skipped or this I/O sees the
		 * new boundary. Any direction (a paused encryption can be reversed); volume offsets.
		 * Cleanup clears F_SYNC under this lock and drains before dc_bitmap_free. */
		if (irp_sp->MajorFunction == IRP_MJ_WRITE && io_length != 0 &&
			io_offset < hook->use_size && io_length <= hook->use_size - io_offset &&
			DC_BITMAP_IS_VALID(hook->alloc_bitmap))
		{
			dc_bitmap_mark_allocated(hook, io_offset, io_length);
		}

		/* no overlap: the pending count reserves this tmp_size value until completion */
		InterlockedIncrement(&trans->pending_io_count);
		trans_boundary = hook->tmp_size;

		/* re-read the key pair with the boundary (the sync_check snapshot may be stale);
		 * barrier: F_SYNC load before the key loads (ARM64). dsk_key can still be the old
		 * key only while tmp_size == head_len, where no data lies below the boundary. */
		KeMemoryBarrier();
		snapshot_dsk_key = hook->dsk_key;
		snapshot_tmp_key = hook->tmp_key;
		KeReleaseSpinLock(&trans->range_lock, irql);

		/* Proceed with async I/O using the snapshotted boundary and keys */
		return io_encrypted_irp_io(hook, irp, FALSE, TRUE, trans_boundary, snapshot_dsk_key, snapshot_tmp_key, FALSE);
	}

normal_io:
	/* counted as untracked BEFORE the flags snapshot below (see io_untracked_enter) */
	io_untracked_enter(hook);

	/* Decide on ONE snapshot of the flags word, so F_ENABLED / F_SYNC / F_PLAIN_IO are
	 * never combined from different states (e.g. at decryption finish). */
	flags = hook->flags;

	/* decryption finished: plaintext at natural offsets, forward untouched */
	if (flags & F_PLAIN_IO) {
		return io_forward_untracked(hook, irp);
	}
	/* transcryption started after the first F_SYNC test: take the tracked path */
	if (flags & F_SYNC) {
		io_untracked_leave(hook);
		goto sync_check;
	}
#else
	if (hook->flags & F_SYNC)
	{
		IoMarkIrpPending(irp);
		ExInterlockedInsertTailList(&hook->sync_irp_queue, &irp->Tail.Overlay.ListEntry, &hook->sync_req_lock);
		KeSetEvent(&hook->sync_req_event, IO_DISK_INCREMENT, FALSE);
		return STATUS_PENDING;
	}
	flags = hook->flags;
#endif /* DC_CONCURRENT_TRANSCRYPT */

	if ((flags & F_ENABLED) == 0)
	{
		// probe for mount new volume
		if ( (hook->flags & (F_UNSUPRT | F_NO_AUTO_MOUNT)) || (hook->mnt_probed != 0) ) {
			if (IS_DEVICE_BLOCKED(dc_conf_flags, hook) != 0) {
#ifdef DC_CONCURRENT_TRANSCRYPT
				io_untracked_leave(hook);
#endif
				return dc_release_irp(hook, irp, STATUS_ACCESS_DENIED);
			}
#ifdef DC_CONCURRENT_TRANSCRYPT
			return io_forward_untracked(hook, irp);
#else
			return dc_forward_irp(hook, irp);
#endif
		}
#ifdef DC_CONCURRENT_TRANSCRYPT
		/* queued for the mount probe: not in flight yet - it is admitted again afterwards
		 * (mount_item_proc: io_read_write_irp or io_forward_plain_irp) */
		io_untracked_leave(hook);
#endif
		return dc_probe_mount(hook, irp);
	}

	// start normal encrypted IO
#ifdef DC_CONCURRENT_TRANSCRYPT
	return io_encrypted_irp_io(hook, irp, FALSE, FALSE, 0, snapshot_dsk_key, snapshot_tmp_key, TRUE);
#else
	return io_encrypted_irp_io(hook, irp, FALSE);
#endif
}

void io_init()
{
	int i;

	for (i = 0; i < sizeof(g_temp_buff_lists) / sizeof(g_temp_buff_lists[0]); i++)
	{
		ExInitializeNPagedLookasideList(&g_temp_buff_lists[i], NULL, NULL, 0, (512u << i), '2_cd', 0);
	}
	ExInitializeNPagedLookasideList(&g_io_contexts_list, mm_alloc_success, NULL, 0, sizeof(io_context), '5_cd', 0);	
}

void io_free()
{
	int i;

	for (i = 0; i < sizeof(g_temp_buff_lists) / sizeof(g_temp_buff_lists[0]); i++)
	{
		ExDeleteNPagedLookasideList(&g_temp_buff_lists[i]);
	}
	ExDeleteNPagedLookasideList(&g_io_contexts_list);
}
