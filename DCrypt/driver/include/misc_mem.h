#ifndef _MISC_MEM_H_
#define _MISC_MEM_H_

// function types declaration
ALLOCATE_FUNCTION mm_alloc_success;

void *mm_map_mdl_success(PMDL mdl);
PMDL  mm_allocate_mdl_success(void *data, u32 size);
PIRP  mm_allocate_irp_success(CCHAR StackSize);
void *mm_alloc_success(POOL_TYPE pool, SIZE_T bytes, u32 tag);

PVOID mm_secure_alloc(size_t length);
void  mm_secure_free(PVOID ptr);

NTSTATUS mm_lock_user_memory(HANDLE process_id, PVOID ptr, ULONG length);
NTSTATUS mm_unlock_user_memory(HANDLE process_id, PVOID ptr);
void     mm_clean_secure_memory();
void     mm_clean_usermode_memory();

#pragma warning(disable: 4996) // disable deprecation warning

#define mm_pool_alloc(_length) ExAllocatePoolWithTag(NonPagedPool, _length, 'P_CD')
#define mm_pool_free(_ptr)     ExFreePoolWithTag(_ptr, 'P_CD');

void mm_init();
void mm_uninit();

#endif
