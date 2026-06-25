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
#include "mount.h"
#include "driver.h"
#include "fast_crypt.h"
#include "misc_mem.h"
#include "debug.h"
#include "alloc_bitmap.h"

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
 * READ_PIPELINE_DEPTH - Parallel read pipeline for improved Q1T1 performance
 *
 * BACKGROUND:
 * The original read chunking was designed to overlap I/O with decryption:
 *   Read chunk → Decrypt chunk → Read next chunk (overlap)
 *
 * However, this was a performance killer on modern NVMe SSDs because:
 * 1. Only ONE read IRP was in flight at a time (single chunk)
 * 2. Read completion runs at DISPATCH_LEVEL, requiring work queue to issue next read
 * 3. Work queue scheduling delay (~0.1-1ms) >> NVMe I/O latency (~0.02ms)
 * 4. The disk sat idle waiting for work queue, severely limiting throughput
 *
 * Result: Q1T1 reads achieved only ~25% of raw disk speed (651 MB/s vs 2.5 GB/s)
 *
 * THE FIX (when READ_PIPELINE_DEPTH is defined):
 * Pre-allocate multiple IRPs/MDLs and keep N reads in flight simultaneously.
 * This keeps the NVMe command queue full, similar to how Q8T1 naturally works.
 * Each read completion immediately issues the next read at DISPATCH_LEVEL
 * (no work queue needed since MDLs are pre-allocated).
 *
 * WHY WRITES DON'T HAVE THIS PROBLEM:
 * Encryption runs ahead via cp_parallelized_crypt (multi-threaded CPU work).
 * The encrypted buffer is always full, so writes never starve.
 * Encryption callback runs at PASSIVE_LEVEL, avoiding work queue delays.
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
#endif
	

	ULONGLONG chunk_diskof;
	ULONG     chunk_length;
	ULONG     chunk_offset;
	xts_key  *chunk_key;
	
	BOOLEAN expected;			// this io operation is expected, enable optimization
	BOOLEAN discontinuous;		// this is a discontinuous chunk
	BOOLEAN write_pending;		// write operation currently pending

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
#endif

		// complete the original irp
		if (NT_SUCCESS(ctx->status)) {
			ctx->orig_irp->IoStatus.Status = STATUS_SUCCESS;
			ctx->orig_irp->IoStatus.Information = ctx->length;
		} else {
			ctx->orig_irp->IoStatus.Status = ctx->status;
			ctx->orig_irp->IoStatus.Information = ctx->length;
		}
		IoCompleteRequest(ctx->orig_irp, IO_DISK_INCREMENT);

		// free resources
		IoReleaseRemoveLock(&ctx->hook->remove_lock, ctx->orig_irp);
		InterlockedDecrement(&ctx->hook->io_depth);

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
	/* Use snapshotted dsk_key to prevent race during key changes.
	 * The snapshot was taken at I/O start, before checking F_SYNC.
	 * This ensures we use a consistent key even if re-encryption init
	 * changes dsk_key after we checked but before we reach here. */
	ctx->chunk_key     = ctx->snapshot_dsk_key;
#else
	ctx->chunk_key     = hook->dsk_key;
#endif
	ctx->discontinuous = FALSE;

	// handle redirected sectors at partition start
	if ( !(hook->flags & F_NO_REDIRECT) && (ctx->chunk_diskof < hook->head_len) )
	{
		/* Remaining bytes in the redirected area from current offset.
		 * We must not read/write past head_len as that would go beyond
		 * the valid storage area. */
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
			ctx->chunk_length = ctx->length;
		}
	}
	
	// handle partial encrypted state - hook->tmp_size must be > 0
#ifdef DC_CONCURRENT_TRANSCRYPT
	if (ctx->trans_io && ctx->trans_boundary > 0)
	{
		/* For concurrent mode, use the snapshotted boundary and tmp_key from when I/O started.
		 * This is safe because:
		 * 1. We incremented pending_io_count when we snapshotted the boundary
		 * 2. Transcryption waits for pending_io_count == 0 before processing a new block
		 * 3. Therefore the boundary we snapshotted is still valid for our I/O range
		 * 4. We use snapshot_tmp_key to avoid race during key swap */
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

	// set the completion status if read operation completed or failed.
	if (NT_SUCCESS(status) == FALSE || ctx->completed == ctx->length)
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

	// free mdl from the chunk irp
	IoFreeMdl(irp->MdlAddress);
	irp->MdlAddress	= NULL;

	if (NT_SUCCESS(irp->IoStatus.Status))
	{
		/* Track writes in allocation bitmap for skip unused sectors */
		if (ctx->hook->alloc_bitmap != NULL) {
			dc_bitmap_mark_allocated(ctx->hook, ctx->write_offset, ctx->write_length);
		}

		KeAcquireInStackQueuedSpinLock(&ctx->write_lock, &lock_queue);

		// update pointers
		ctx->write_offset += ctx->write_length;
		ctx->completed    += ctx->write_length;
		ctx->write_length  = ctx->encrypted - ctx->completed;
		need_write = ctx->write_pending = (ctx->write_length != 0);

		KeReleaseInStackQueuedSpinLock(&lock_queue);

		// if discontinuous chunk completed, start encryption of next chunk if needed
		if (ctx->discontinuous && ctx->completed < ctx->length)
		{
			ctx->discontinuous = FALSE;
			ctx->write_offset  = ctx->offset + ctx->completed;
			io_context_addref(ctx);
			io_async_encrypt_chunk(ctx);
		}

		// if next encrypted part available, start writing it now
		if (need_write) 
		{
			IoReuseIrp(irp, STATUS_SUCCESS);
			io_context_addref(ctx);
			io_write_next_chunk(ctx);
		}
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
	
	if (ctx->chunk_offset == 0) {
		ctx->write_offset = ctx->chunk_diskof;
	}
	KeAcquireInStackQueuedSpinLock(&ctx->write_lock, &lock_queue);

	// update encrypted length
	ctx->encrypted += ctx->chunk_length;

	if (need_write = (ctx->write_pending == FALSE)) {
		ctx->write_pending = TRUE;
		ctx->write_length = ctx->encrypted - ctx->completed;
	}
	KeReleaseInStackQueuedSpinLock(&lock_queue);

	// write encrypted part if previous write operation completed
	if (need_write)
	{
		io_context_addref(ctx);
		io_write_next_chunk(ctx);
	}

	// encrypt next chunk if needed
	if (ctx->discontinuous == FALSE && ctx->encrypted < ctx->length)
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
NTSTATUS io_encrypted_irp_io(dev_hook *hook, PIRP irp, BOOLEAN is_sync, BOOLEAN trans_io, ULONGLONG trans_boundary, xts_key *snapshot_dsk_key, xts_key *snapshot_tmp_key)
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
#endif

	// increment hook IO queue depth
	InterlockedIncrement(&hook->io_depth);

	if (ctx->is_sync = is_sync)
	{
		KeInitializeEvent(&ctx->done_event, NotificationEvent, FALSE);
	}

	if (irp_sp->MajorFunction == IRP_MJ_READ) {
		ctx->offset = irp_sp->Parameters.Read.ByteOffset.QuadPart;
		ctx->length = irp_sp->Parameters.Read.Length;
	} else 
	{
		ctx->offset = irp_sp->Parameters.Write.ByteOffset.QuadPart;
		ctx->length = irp_sp->Parameters.Write.Length;

		// writing to redirection area must be blocked for preventing file system corruption
		if ( !(hook->flags & F_NO_REDIRECT) &&
			  (is_intersect(ctx->offset, ctx->length, hook->stor_off, hook->stor_len) != 0) )
		{
			DbgMsg("writing to redirection area blocked, dev=%ws\n", hook->dev_name);
			status = STATUS_ACCESS_DENIED;
			goto on_fail;
		}
	}
	
	// IO operations must be within the volume data range and be SECTOR_SIZE aligned
	if ( (ctx->length == 0) || 
		 (ctx->length & (SECTOR_SIZE - 1)) || (ctx->offset + ctx->length > hook->use_size) )
	{
		DbgMsg("unaligned IO operation, dev=%ws\n", hook->dev_name);
		status = STATUS_INVALID_PARAMETER;
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

	// marg original IRP as pending
	IoMarkIrpPending(irp);

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
		io_start_read_pipeline(ctx);
		// Balance initial ref - each slot has its own ref, the initial ref=1 must be consumed
		io_context_deref(ctx);
#else
		// IRP_MJ_READ does not require memory allocation, start reading now
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


NTSTATUS io_read_write_irp(dev_hook *hook, PIRP irp)
{
#ifdef DC_CONCURRENT_TRANSCRYPT
	xts_key *snapshot_dsk_key;
	xts_key *snapshot_tmp_key;
#endif

	// reseed RNG on first 1000 I/O operations for collect initial entropy
	if (InterlockedIncrement(&dc_io_count) < 1000) {
		cp_rand_reseed();
	}

	if (hook->flags & (F_DISABLE | F_FORMATTING)) {
		return dc_release_irp(hook, irp, STATUS_INVALID_DEVICE_STATE);
	}

	// Format protection for unmounted volumes without recognized filesystem
	// Block ALL writes to prevent accidental formatting or corruption
	// Only applies to volumes explicitly detected as raw (no filesystem found)
	// Safe default: if detection never ran, F_FS_RAW won't be set, so writes are allowed
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
	/*
	 * CRITICAL: Snapshot dsk_key BEFORE checking F_SYNC!
	 *
	 * During re-encryption init, the sequence is:
	 * 1. Set F_SYNC
	 * 2. Memory barrier
	 * 3. Set dsk_key = new_key
	 *
	 * By reading dsk_key FIRST, then F_SYNC, we ensure:
	 * - If we see dsk_key = new_key, the write is visible
	 * - Due to writer's barrier, F_SYNC = TRUE is also visible
	 * - So our subsequent read of F_SYNC will see TRUE
	 *
	 * This prevents the race where we see F_SYNC = FALSE but
	 * later use dsk_key = new_key (which would corrupt data).
	 *
	 * We also snapshot tmp_key to prevent race during key swap
	 * (when dsk_key and tmp_key pointers are exchanged).
	 */
	snapshot_dsk_key = hook->dsk_key;
	snapshot_tmp_key = hook->tmp_key;
	KeMemoryBarrier();  /* Ensure keys are read before F_SYNC */

	/*
	 * Concurrent transcryption mode: check for overlap with active block.
	 * If I/O overlaps the currently-processing transcryption block,
	 * wait for that block to complete before proceeding.
	 * This avoids the deadlock of the old F_SYNC approach which forced
	 * ALL I/O through a single thread.
	 *
	 * Synchronization protocol:
	 * 1. Under spinlock: check overlap, if none then increment pending_io_count
	 *    and snapshot tmp_size
	 * 2. Proceed with I/O using snapshotted boundary
	 * 3. When I/O completes, decrement pending_io_count
	 * 4. Transcryption waits for pending_io_count == 0 before starting new block
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
		/* Atomic check under spinlock:
		 * - Re-check F_SYNC (cleanup clears it under this same spinlock)
		 * - Read active range
		 * - If no overlap, increment pending_io_count and snapshot tmp_size
		 * This ensures transcryption can't start a new block while we hold a reservation */
		KeAcquireSpinLock(&trans->range_lock, &irql);

		/* Re-check F_SYNC inside spinlock.
		 * Cleanup clears F_SYNC under this same spinlock before freeing resources.
		 * If F_SYNC is now FALSE, cleanup is in progress - bail out. */
		if (!(hook->flags & F_SYNC)) {
			KeReleaseSpinLock(&trans->range_lock, irql);
			goto normal_io;
		}

		active_start = trans->active_start;
		active_end = trans->active_end;

		/* Check overlap: if active_start != -1 and ranges intersect */
		if (active_start != -1 &&
		    max(io_offset, (u64)active_start) < min(io_end, (u64)active_end))
		{
			/* Overlap - release lock and wait for block to complete */
			KeReleaseSpinLock(&trans->range_lock, irql);
			KeWaitForSingleObject(&trans->block_complete,
			                      Executive, KernelMode, FALSE, NULL);
			goto retry_overlap_check;
		}

		/* No overlap - increment pending count and snapshot boundary.
		 * The pending count "reserves" our use of this tmp_size value.
		 * Transcryption will wait for us to complete before processing the next block. */
		InterlockedIncrement(&trans->pending_io_count);
		trans_boundary = hook->tmp_size;
		KeReleaseSpinLock(&trans->range_lock, irql);

		/* Proceed with async I/O using the snapshotted boundary and keys */
		return io_encrypted_irp_io(hook, irp, FALSE, TRUE, trans_boundary, snapshot_dsk_key, snapshot_tmp_key);
	}

normal_io:
#else
	if (hook->flags & F_SYNC)
	{
		IoMarkIrpPending(irp);
		ExInterlockedInsertTailList(&hook->sync_irp_queue, &irp->Tail.Overlay.ListEntry, &hook->sync_req_lock);
		KeSetEvent(&hook->sync_req_event, IO_DISK_INCREMENT, FALSE);
		return STATUS_PENDING;
	}
#endif /* DC_CONCURRENT_TRANSCRYPT */
	
	if ((hook->flags & F_ENABLED) == 0)
	{
		// probe for mount new volume
		if ( (hook->flags & (F_UNSUPRT | F_NO_AUTO_MOUNT)) || (hook->mnt_probed != 0) ) {
			if (IS_DEVICE_BLOCKED(dc_conf_flags, hook) != 0) return dc_release_irp(hook, irp, STATUS_ACCESS_DENIED);
			return dc_forward_irp(hook, irp);
		}
		return dc_probe_mount(hook, irp);
	}

	// start normal encrypted IO
#ifdef DC_CONCURRENT_TRANSCRYPT
	return io_encrypted_irp_io(hook, irp, FALSE, FALSE, 0, snapshot_dsk_key, snapshot_tmp_key);
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
