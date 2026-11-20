/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2009-2013
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
#include "misc_mem.h"
#include "misc.h"
#include "debug.h"

typedef struct {
	LIST_ENTRY entry;
	HANDLE     owner_id; // owner process id
	PMDL       map_mdl;  // MDL for mapping usermode memory area to system space 
	PVOID      map_ptr;  // system-space mapped memory
	PVOID      user_ptr; // original usermode pointer
	ULONG      length;   // locked memory length

} USER_MEM_LOCK, *PUSER_MEM_LOCK;

typedef struct {
	LIST_ENTRY entry;
	size_t     length;

	__declspec(align(SYSTEM_CACHE_ALIGNMENT_SIZE)) UCHAR buffer[0]; // cache-aligned data

} SECURE_MEM_BLOCK, *PSECURE_MEM_BLOCK;

static LIST_ENTRY g_usermode_memory_list;
static FAST_MUTEX g_usermode_memory_lock;
static BOOLEAN    g_ps_notify_registered;
static LIST_ENTRY g_secure_memory_list;
static KSPIN_LOCK g_secure_memory_lock;

void *mm_map_mdl_success(PMDL mdl)
{
	void *mem;
	int   timeout;

	for (timeout = DC_MEM_RETRY_TIMEOUT; timeout > 0; timeout -= DC_MEM_RETRY_TIME)
	{
		if (mem = MmGetSystemAddressForMdlSafe(mdl, HighPagePriority)) break;
		if (KeGetCurrentIrql() >= DISPATCH_LEVEL) break;
		dc_delay(DC_MEM_RETRY_TIME);
	}
	return mem;
}

PMDL mm_allocate_mdl_success(void *data, u32 size)
{
	PMDL mdl;
	int  timeout;

	for (timeout = DC_MEM_RETRY_TIMEOUT; timeout > 0; timeout -= DC_MEM_RETRY_TIME)
	{
		if (mdl = IoAllocateMdl(data, size, FALSE, FALSE, NULL)) break;
		if (KeGetCurrentIrql() >= DISPATCH_LEVEL) break;
		dc_delay(DC_MEM_RETRY_TIME);
	}
	return mdl;
}

PIRP mm_allocate_irp_success(CCHAR StackSize)
{
	PIRP irp;
	int  timeout;

	for (timeout = DC_MEM_RETRY_TIMEOUT; timeout > 0; timeout -= DC_MEM_RETRY_TIME)
	{
		if (irp = IoAllocateIrp(StackSize, FALSE)) break;
		if (KeGetCurrentIrql() >= DISPATCH_LEVEL) break;
		dc_delay(DC_MEM_RETRY_TIME);
	}
	return irp;
}

void *mm_alloc_success(POOL_TYPE pool, SIZE_T bytes, u32 tag)
{
	void *mem;
	int   timeout;

	for (timeout = DC_MEM_RETRY_TIMEOUT; timeout > 0; timeout -= DC_MEM_RETRY_TIME)
	{
		if (mem = ExAllocatePoolWithTag(pool, bytes, tag)) break;
		if (KeGetCurrentIrql() >= DISPATCH_LEVEL) break;
		dc_delay(DC_MEM_RETRY_TIME);
	}
	return mem;
}

PVOID mm_secure_alloc(size_t length)
{
	KLOCK_QUEUE_HANDLE lock_queue;
	PSECURE_MEM_BLOCK  block;
	PVOID              p_mem;

	// allocate cache-aligned nonpaged memory attempts to retry on failure
	// if the length requested is PAGE_SIZE or greater, a page-aligned buffer is allocated
	if (length >= PAGE_SIZE)
	{
		if ( (p_mem = mm_alloc_success(NonPagedPool, PAGE_SIZE + length, 'S_CD')) == NULL ) return NULL;
		block = (PSECURE_MEM_BLOCK)((unsigned char*)p_mem + PAGE_SIZE - FIELD_OFFSET(SECURE_MEM_BLOCK, buffer));
	} else {
		if ( (block = (PSECURE_MEM_BLOCK)mm_alloc_success(NonPagedPoolCacheAligned, sizeof(SECURE_MEM_BLOCK) + length, 'S_CD')) == NULL ) return NULL;
	}

	// secure memory must be zero-filled after allocation
	memset(block->buffer, 0, (block->length = length));

	KeAcquireInStackQueuedSpinLock(&g_secure_memory_lock, &lock_queue);
	InsertTailList(&g_secure_memory_list, &block->entry);
	KeReleaseInStackQueuedSpinLock(&lock_queue);

	return block->buffer;
}

void mm_secure_free(PVOID ptr)
{
	KLOCK_QUEUE_HANDLE lock_queue;
	PSECURE_MEM_BLOCK  block = CONTAINING_RECORD(ptr, SECURE_MEM_BLOCK, buffer);

	// data buffer must be zeroed before removing block from blocks list
	RtlSecureZeroMemory(block->buffer, block->length);
	
	KeAcquireInStackQueuedSpinLock(&g_secure_memory_lock, &lock_queue);
	RemoveEntryList(&block->entry);
	KeReleaseInStackQueuedSpinLock(&lock_queue);

	if (block->length >= PAGE_SIZE) {
		ExFreePoolWithTag(PAGE_ALIGN(block), 'S_CD');
	} else {
		ExFreePoolWithTag(block, 'S_CD');
	}
}

NTSTATUS mm_lock_user_memory(HANDLE process_id, PVOID ptr, ULONG length)
{
	PUSER_MEM_LOCK lock = NULL;
	NTSTATUS       status;

	// if PsSetCreateProcessNotifyRoutine fails, we cannot lock usermode memory,
	// because if the process terminated without unlocking the pages, system will BSOD 
	if (g_ps_notify_registered == FALSE)
	{
		status = STATUS_DEVICE_NOT_READY;
		goto cleanup;
	}

	// process for which the locked memory pages, should be current process
	if (process_id != PsGetCurrentProcessId())
	{
		status = STATUS_CONTEXT_MISMATCH;
		goto cleanup;
	}

	if ( (lock = (PUSER_MEM_LOCK)mm_pool_alloc(sizeof(USER_MEM_LOCK))) == NULL ||
		 (lock->map_mdl = IoAllocateMdl(ptr, length, FALSE, FALSE, NULL)) == NULL )
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto cleanup;
	}
	lock->owner_id = process_id;
	lock->user_ptr = ptr;
	lock->length = length;

	__try {
		MmProbeAndLockPages(lock->map_mdl, UserMode, IoModifyAccess);
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
		goto cleanup;
	}
	
	if ( (lock->map_ptr = MmMapLockedPagesSpecifyCache(lock->map_mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority)) == NULL )
	{
		MmUnlockPages(lock->map_mdl);
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto cleanup;
	}

	ExAcquireFastMutex(&g_usermode_memory_lock);

	InsertTailList(&g_usermode_memory_list, &lock->entry);
	status = STATUS_SUCCESS;

	ExReleaseFastMutex(&g_usermode_memory_lock);
cleanup:
	if (status != STATUS_SUCCESS && lock != NULL) {
		if (lock->map_mdl) IoFreeMdl(lock->map_mdl);
		mm_pool_free(lock);
	}
	return status;
}

NTSTATUS mm_unlock_user_memory(HANDLE process_id, PVOID ptr)
{
	PUSER_MEM_LOCK lock;
	PLIST_ENTRY    item;
	NTSTATUS       status = STATUS_NOT_LOCKED;

	ExAcquireFastMutex(&g_usermode_memory_lock);

	for (item = g_usermode_memory_list.Flink; item != &g_usermode_memory_list;)
	{
		lock = CONTAINING_RECORD(item, USER_MEM_LOCK, entry);
		item = item->Flink;

		if (lock->owner_id == process_id && (ptr == NULL || lock->user_ptr == ptr))
		{
			// remove item from lockings list and secure erase memory content
			RemoveEntryList(&lock->entry);
			RtlSecureZeroMemory(lock->map_ptr, lock->length);

			// unmap, unlock pages and free resources
			MmUnmapLockedPages(lock->map_ptr, lock->map_mdl);
			MmUnlockPages(lock->map_mdl);
			IoFreeMdl(lock->map_mdl);
			mm_pool_free(lock);

			status = STATUS_SUCCESS;
		}
	}
	ExReleaseFastMutex(&g_usermode_memory_lock);
	return status;
}

/*
 * Zero only the user-mode buffers locked by the driver (mm_lock_user_memory), at DumpStart
 * when the image will not be encrypted. Called at HIGH_LEVEL there: no mutex (nothing else
 * runs). The buffers stay locked and mapped; their owners see zeroed passwords afterwards.
 */
void mm_clean_usermode_memory()
{
	BOOLEAN     mutex_acquired = FALSE;
	PLIST_ENTRY item;

	if (KeGetCurrentIrql() <= APC_LEVEL) {
		ExAcquireFastMutex(&g_usermode_memory_lock);
		mutex_acquired = TRUE;
	}
	for (item = g_usermode_memory_list.Flink; item != &g_usermode_memory_list; item = item->Flink) {
		PUSER_MEM_LOCK lock = CONTAINING_RECORD(item, USER_MEM_LOCK, entry);
		RtlSecureZeroMemory(lock->map_ptr, lock->length);
	}
	if (mutex_acquired) {
		ExReleaseFastMutex(&g_usermode_memory_lock);
	}
}

void mm_clean_secure_memory()
{
	KLOCK_QUEUE_HANDLE lock_queue;
	BOOLEAN            spinlock_acquired = FALSE;
	PLIST_ENTRY        item;

	// clean secure memory
	if (KeGetCurrentIrql() <= DISPATCH_LEVEL) {
		KeAcquireInStackQueuedSpinLock(&g_secure_memory_lock, &lock_queue);
		spinlock_acquired = TRUE;
	}
	for (item = g_secure_memory_list.Flink; item != &g_secure_memory_list; item = item->Flink) {
		PSECURE_MEM_BLOCK block = CONTAINING_RECORD(item, SECURE_MEM_BLOCK, entry);
		RtlSecureZeroMemory(block->buffer, block->length);
	}
	if (spinlock_acquired) {
		KeReleaseInStackQueuedSpinLock(&lock_queue);
	}
	
	// clean locked usermode memory
	mm_clean_usermode_memory();

	// Write Back and Invalidate CPU Caches
	__wbinvd();
}

static void mm_create_process_notify(IN HANDLE ParentId, IN HANDLE ProcessId, IN BOOLEAN Create)
{
	// when process is exiting, clean and unlock all locked memory regions, otherwise it will BSOD
	if (Create == FALSE) mm_unlock_user_memory(ProcessId, NULL);
}

void mm_init()
{
	InitializeListHead(&g_usermode_memory_list);
	ExInitializeFastMutex(&g_usermode_memory_lock);

	if (NT_SUCCESS(PsSetCreateProcessNotifyRoutine(mm_create_process_notify, FALSE))) {
		DbgMsg("CreateProcessNotifyRoutine installed\n");
		g_ps_notify_registered = TRUE;
	} else {
		DbgMsg("cannot install CreateProcessNotifyRoutine\n");
		g_ps_notify_registered = FALSE;
	}
	InitializeListHead(&g_secure_memory_list);
	KeInitializeSpinLock(&g_secure_memory_lock);
}

void mm_uninit()
{
	if (g_ps_notify_registered) {
		PsSetCreateProcessNotifyRoutine(mm_create_process_notify, TRUE);
		DbgMsg("CreateProcessNotify removed\n");
	}
}
