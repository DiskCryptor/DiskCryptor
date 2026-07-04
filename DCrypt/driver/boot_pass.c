/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2019-2026
	* DavidXanatos <info@diskcryptor.org>
    * Copyright (c) 2008-2011 
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
#include <stddef.h>
#include "driver.h"
#include "defines.h"
#include "bootloader.h"
#include "boot_pass.h"
#include "mount.h"
#include "debug.h"
//#include "misc_mem.h"


static void *find_8b(u8 *data, int size, u32 s1, u32 s2)
{
	int i;

	for (i = 0; i < size - 8; i++) {
		if (p32(data + i)[0] == s1 && p32(data + i)[1] == s2) return data + i;
	}
	return NULL;
}

static void dc_zero_boot(u64 bd_base, u32 bd_size)
{
	PHYSICAL_ADDRESS addr;
	void            *mem;
	
	/* map bootloader body */
	addr.QuadPart = bd_base;

	if (mem = MmMapIoSpace(addr, bd_size, MmCached)) {
		/* zero bootloader body */
		burn(mem, bd_size);
		MmUnmapIoSpace(mem, bd_size);
	}
}

static void dc_restore_ints(bd_data *bdb)
{
	PHYSICAL_ADDRESS addr;
	void            *mem;

	DbgMsg("dc_restore_ints\n");

	/* map realmode interrupts table */
	addr.HighPart = 0;
	addr.LowPart  = 0;

	if (mem = MmMapIoSpace(addr, 0x1000, MmCached)) 
	{
		p32(mem)[0x13] = bdb->u.bios.old_int13;
		p32(mem)[0x15] = bdb->u.bios.old_int15;
		MmUnmapIoSpace(mem, 0x1000);
	}
}

//
// MmCopyMemory would be the ideal choice for copying from physical memory, but requires windows 8+
// 
//int dc_try_load_bdb(PHYSICAL_ADDRESS addr)
//{
//	int              ret = ST_ERROR;
//	bd_data         *bdb;
//	PVOID			 p_mem = NULL;
//	SIZE_T			 bytes_copied = 0;
//	u64				 base = 0;
//	dc_pass          password;
//	MM_COPY_ADDRESS  copy_addr;
//	NTSTATUS         status;
//	u8               bdb_buffer[sizeof(bd_data)];
//	u32              bdb_offset;
//	PHYSICAL_ADDRESS keys_phys_addr;
//
//	RtlZeroMemory(&password, sizeof(password));
//
//	/* Allocate buffer for initial scan - we need at least bd_data size + some margin */
//	p_mem = mm_pool_alloc(PAGE_SIZE);
//	if (p_mem == NULL) {
//		return ST_ERROR;
//	}
//
//	/* Use MmCopyMemory to safely copy from physical memory */
//	/* This is HVCI compatible and properly handles physical memory access */
//	copy_addr.PhysicalAddress = addr;
//	status = MmCopyMemory(p_mem, copy_addr, PAGE_SIZE, MM_COPY_MEMORY_PHYSICAL, &bytes_copied);
//
//	if (!NT_SUCCESS(status) || bytes_copied < sizeof(bd_data)) {
//		DbgMsg("MmCopyMemory failed for bdb scan: status=0x%08X, copied=%llu\n",
//			status, (ULONGLONG)bytes_copied);
//		mm_pool_free(p_mem);
//		return ST_ERROR;
//	}
//
//	/* Search for boot data block signature in the copied buffer */
//	bdb = find_8b((u8*)p_mem, (int)(bytes_copied - offsetof(bd_data, u.extra)), BDB_SIGN1, BDB_SIGN2);
//	if (bdb == NULL) {
//		mm_pool_free(p_mem);
//		return ST_ERROR;
//	}
//
//	/* Calculate offset of bdb within the page for physical address calculation */
//	bdb_offset = (u32)((u8*)bdb - (u8*)p_mem);
//
//	/* Copy the full bd_data structure to ensure we have all fields */
//	RtlCopyMemory(bdb_buffer, bdb, sizeof(bd_data));
//	bdb = (bd_data*)bdb_buffer;
//
//	base = ((dc_load_flags & DST_UEFI_BOOT) && bdb->bd_base == 0) ? bdb->u.uefi.bd_base64 : (u64)bdb->bd_base;
//
//	DbgMsg("boot data block found at 0x%016I64X (offset=%u)\n", addr.QuadPart, bdb_offset);
//	DbgMsg("boot loader base 0x%016I64X size %d\n", base, bdb->bd_size);
//
//	password.size = bdb->password_size;
//	if (password.size > 0 && password.size <= sizeof(password.pass)) {
//		RtlCopyMemory(password.pass, bdb->password_data, password.size);
//	}
//	password.kdf = 0;
//	password.slot = 0;
//
//	/* restore realmode interrupts */
//	if (bdb->u.bios.old_int13 != 0) {
//		dc_restore_ints(bdb);
//	}
//	else if (bdb->u.uefi.sign3 == BDB_SIGN3)
//	{
//		dc_boot_flags = bdb->u.uefi.flags;
//		DbgMsg("dc_boot_flags=%08x\n", dc_boot_flags);
//
//		password.kdf = bdb->u.uefi.password_kdf;
//		password.slot = bdb->u.uefi.password_slot;
//
//		if ((bdb->u.uefi.flags & BDB_BF_BOOT_KEYS) && bdb->u.uefi.key_count > 0)
//		{
//			DbgMsg("boot keys found, count=%d, offset=%d\n", bdb->u.uefi.key_count, bdb->u.uefi.key_offset);
//
//			/* Calculate physical address of the keys array */
//			/* keys are at: base_phys_addr + offset_of_bdb_in_page + key_offset */
//			keys_phys_addr.QuadPart = addr.QuadPart + bdb_offset + bdb->u.uefi.key_offset;
//
//			DbgMsg("keys physical address: 0x%016I64X\n", keys_phys_addr.QuadPart);
//
//			/* Use safe physical memory copy for the keys */
//			status = dc_copy_boot_keys_from_physical(keys_phys_addr, bdb->u.uefi.key_count);
//			if (!NT_SUCCESS(status)) {
//				DbgMsg("dc_copy_boot_keys_from_physical failed: 0x%08X\n", status);
//			}
//		}
//	}
//
//	/* add password to cache */
//	dc_add_password(&password);
//	/* save bootloader size */
//	dc_boot_kbs = bdb->bd_size / 1024;
//	/* set bootloader load flag */
//	dc_load_flags |= DST_BOOTLOADER;
//	/* zero bootloader body */
//	dc_zero_boot(base, bdb->bd_size);
//
//	ret = ST_OK;
//
//	mm_pool_free(p_mem);
//	burn(&password, sizeof(password));
//
//	return ret;
//}

char dc_boot_pass[SLOT_LABEL_LEN] = "Boot Password";

int dc_try_load_bdb(PHYSICAL_ADDRESS addr)
{
	int              ret = ST_ERROR;
	bd_data         *bdb;
	HANDLE			 h_mem;
	UNICODE_STRING   u_name;
	OBJECT_ATTRIBUTES obj_a;
	NTSTATUS         status;
	PVOID			 p_mem = NULL;
	SIZE_T			 u_size = PAGE_SIZE;
	u64				 base = 0;
	SIZE_T           offset = 0;
	void            *mem;
	dc_pass          password = { 0 };
	u32              i;
	u8              *pass_ptr;

	RtlInitUnicodeString(&u_name, L"\\Device\\PhysicalMemory");
	InitializeObjectAttributes(&obj_a, &u_name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, (HANDLE)NULL, (PSECURITY_DESCRIPTOR)NULL);
	if (NT_SUCCESS(status = ZwOpenSection(&h_mem, SECTION_ALL_ACCESS, &obj_a)))
	{
		if (NT_SUCCESS(status = ZwMapViewOfSection(h_mem, NtCurrentProcess(), &p_mem, 0L, u_size, &addr, &u_size, ViewShare, 0, PAGE_READWRITE)))
		{
			__try 
			{
				if (bdb = find_8b((u8*)p_mem, PAGE_SIZE - offsetof(bd_data, u.extra), BDB_SIGN1, BDB_SIGN2))
				{
					/* set bootloader load flag */
					dc_load_flags |= DST_BOOTLOADER;

					/* determine data block base address */
					base = ((dc_load_flags & DST_UEFI_BOOT) && bdb->bd_base == 0) ? bdb->u.uefi.bd_base64 : (u64)bdb->bd_base;
					offset = ((u8*)bdb - (u8*)p_mem);

					//DbgMsg("boot data block found at %p\n", bdb);
					DbgMsg("boot data block found at 0x%016I64X\n", addr.QuadPart);
					DbgMsg("boot loader base 0x%016I64X size %d\n", base, bdb->bd_size);
					//DbgMsg("boot extra %08x %08x\n", bdb->u.bios.old_int13, bdb->u.uefi.sign3);

					password.size = bdb->password_size;
					RtlCopyMemory(password.pass, bdb->password_data, password.size);
					if (bdb->u.bios.old_int13 != 0)
						dc_restore_ints(bdb);
					else if (bdb->u.uefi.sign3 == BDB_SIGN3) 
					{
						dc_boot_flags = bdb->u.uefi.flags;
						DbgMsg("dc_boot_flags=%08x\n", dc_boot_flags);

						password.kdf = bdb->u.uefi.password_kdf;
						password.slot = bdb->u.uefi.password_slot;
						password.flags = bdb->u.uefi.password_flags;
					}
					/* add password to cache */
					memcpy(password.label, dc_boot_pass, SLOT_LABEL_LEN);
					dc_cache_password(&password);

					/* map full block */
					if (mem = MmMapIoSpace(addr, ROUND_TO_PAGES(bdb->bd_size), MmCached)) {

						/* set boot keys from mapped memory */
						if ((dc_boot_flags & BDB_BF_BOOT_KEYS) && bdb->u.uefi.key_offset)
						{
							DbgMsg("boot keys found, count=%d, offset=%d, size=%d\n", bdb->u.uefi.key_count, bdb->u.uefi.key_offset, bdb->u.uefi.key_size);

							/* validate bounds before accessing keys */
							if (bdb->u.uefi.key_size >= sizeof(header_key) && bdb->u.uefi.key_count > 0 &&
							    offset + bdb->u.uefi.key_offset + (u64)bdb->u.uefi.key_count * bdb->u.uefi.key_size <= bdb->bd_size) {
								dc_set_boot_keys((header_key*)(((u8*)mem) + offset + bdb->u.uefi.key_offset), bdb->u.uefi.key_count);
							}
						}

						/* set cached passwords from mapped memory */
						if ((dc_boot_flags & BDB_BF_PASS_CACHE) && bdb->u.uefi.pass_offset)
						{
							DbgMsg("cached passwords found, count=%d, offset=%d, size=%d\n", bdb->u.uefi.pass_count, bdb->u.uefi.pass_offset, bdb->u.uefi.pass_size);

							/* validate bounds before accessing passwords */
							if (bdb->u.uefi.pass_size > 0 && bdb->u.uefi.pass_count > 0 &&
							    offset + bdb->u.uefi.pass_offset + (u64)bdb->u.uefi.pass_count * bdb->u.uefi.pass_size <= bdb->bd_size) {
								memset(&password, 0, sizeof(password));
								pass_ptr = ((u8*)mem) + offset + bdb->u.uefi.pass_offset;
								for(i = 0; i < bdb->u.uefi.pass_count; i++) {
									memcpy(&password, pass_ptr + i * bdb->u.uefi.pass_size, min(sizeof(password), bdb->u.uefi.pass_size));
									dc_cache_password(&password);
								}
							}
						}

						MmUnmapIoSpace(mem, bdb->bd_size);
					}

					/* save bootloader size */
					dc_boot_kbs = bdb->bd_size / 1024;

					/* zero bootloader body */
					dc_zero_boot(base, bdb->bd_size);

					ret = ST_OK;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DbgMsg("exception while accessing physical memory: 0x%08X\n", GetExceptionCode());
			}

			ZwUnmapViewOfSection(NtCurrentProcess(), &p_mem);
		}

		ZwClose(h_mem);
	}

	burn(&password, sizeof(password));

	return ret;
}

int dc_get_legacy_boot_pass()
{
	PHYSICAL_ADDRESS addr;
	/* scan memory in range 500-640k */
	for (addr.QuadPart = 500*1024; addr.LowPart < 640*1024; addr.LowPart += PAGE_SIZE) {
		if (dc_try_load_bdb(addr) == ST_OK) return ST_OK;
	}
	return ST_ERROR;
}

int dc_get_old_uefi_boot_pass()
{
	PHYSICAL_ADDRESS addr;
	/* scan memory in range 1-16M in steps of 1M */
	for (addr.QuadPart = 0x00100000; addr.LowPart <= 0x01000000; addr.LowPart += (256 * PAGE_SIZE)) {
		if (dc_try_load_bdb(addr) == ST_OK) return ST_OK;
	}
	return ST_ERROR;
}

typedef NTSTATUS (NTAPI * P_NtQuerySystemEnvironmentValueEx)(
	__in PUNICODE_STRING VariableName,
	__in LPGUID VendorGuid,
	__out_bcount_opt(*ValueLength) PVOID Value,
	__inout PULONG ValueLength,
	__out_opt PULONG Attributes
);

P_NtQuerySystemEnvironmentValueEx pNtQuerySystemEnvironmentValueEx = NULL;

BOOLEAN dc_efi_init()
{
	UNICODE_STRING uni;
	RtlInitUnicodeString(&uni, L"ZwQuerySystemEnvironmentValueEx");
	pNtQuerySystemEnvironmentValueEx = MmGetSystemRoutineAddress(&uni);
	if (!pNtQuerySystemEnvironmentValueEx) {
		DbgMsg("NtQuerySystemEnvironmentValueEx not found\n");
		return FALSE;
	}
	return TRUE;
}

BOOLEAN dc_efi_check()
{
	if (!pNtQuerySystemEnvironmentValueEx) 
		return FALSE;

	UNICODE_STRING NameString;
	RtlInitUnicodeString(&NameString, L" ");
	UNICODE_STRING GuidString;
	RtlInitUnicodeString(&GuidString, L"{00000000-0000-0000-0000-000000000000}");
	GUID Guid;
	RtlGUIDFromString(&GuidString, &Guid);

	UCHAR Buffer[4];
	ULONG Length = sizeof(Buffer);
	NTSTATUS status = pNtQuerySystemEnvironmentValueEx(&NameString, &Guid, Buffer, &Length, 0i64);

	DbgMsg("NtQuerySystemEnvironmentValueEx, status=%08x\n", status);

	if(status == STATUS_VARIABLE_NOT_FOUND)
		dc_load_flags |= DST_UEFI_BOOT;
	return TRUE;
}

GUID  gEfiDcsVariableGuid = { 0x101f8560, 0xd73a, 0x4ff7, { 0x89, 0xf6, 0x81, 0x70, 0xf6, 0x61, 0x55, 0x87 } };

NTSTATUS ReadEfiVar(_In_ PCWSTR Name, _In_opt_ const GUID* VendorGuid, _Outptr_result_bytebuffer_(*OutSize) PVOID* OutData, _Out_ PULONG OutSize, _Out_opt_ PULONG OutAttributes)
{
	NTSTATUS status;
	UNICODE_STRING usName;
	ULONG size = 0;
	ULONG attrs = 0;

	*OutData = NULL;
	*OutSize = 0;
	if (OutAttributes) *OutAttributes = 0;

	if (!pNtQuerySystemEnvironmentValueEx)
		return STATUS_ENTRYPOINT_NOT_FOUND;

	RtlInitUnicodeString(&usName, Name);

	status = pNtQuerySystemEnvironmentValueEx(&usName, (LPGUID)(VendorGuid ? VendorGuid : &gEfiDcsVariableGuid), NULL, &size, &attrs);
	if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
		return status; // e.g. STATUS_VARIABLE_NOT_FOUND, STATUS_PRIVILEGE_NOT_HELD, etc.
	}

	PVOID buf = ExAllocatePoolWithTag(NonPagedPool, size, '8_cd');
	if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

	status = pNtQuerySystemEnvironmentValueEx(&usName, (LPGUID)(VendorGuid ? VendorGuid : &gEfiDcsVariableGuid), buf, &size, &attrs);
	if (!NT_SUCCESS(status)) {
		ExFreePool(buf);
		return status;
	}

	*OutData = buf;
	*OutSize = size;
	if (OutAttributes) *OutAttributes = attrs;
	return STATUS_SUCCESS;
}

int dc_get_uefi_boot_pass() 
{
	PVOID data;
	ULONG dataSize;
	ULONG attrs;
	PHYSICAL_ADDRESS addr = {0};

	DbgMsg("DcsBootDataAddr... ");
	NTSTATUS status = ReadEfiVar(L"DcsBootDataAddr", NULL, &data, &dataSize, &attrs);
	if (!NT_SUCCESS(status)) {
		DbgMsg("not found status=%08X\n", status);
#ifdef _M_ARM64
		// on ASUS VivoBook with a Qualcomm Snapdragon X Elite we fail here something needs more init
		// if that happens set up a retry
		if (status == STATUS_NOT_SUPPORTED) {
			dc_load_flags |= DST_UEFI_RETRY;
		}
#endif
		return ST_ERROR;
	}

	if(dataSize < sizeof(u64))
		DbgMsg("size invalid %d\n", dataSize);
	else
		addr.QuadPart = *(u64*)data;

	ExFreePool(data);

	if (!addr.QuadPart) return ST_ERROR;
	
	DbgMsg("value 0x%p\n", addr.QuadPart);

	if (dc_try_load_bdb(addr) == ST_OK) return ST_OK;

	return ST_ERROR;
}

void dc_get_boot_pass()
{
	dc_efi_init();
#ifndef _M_ARM64
	dc_efi_check();
#else // ARM64 always boots via UEFI
	dc_load_flags |= DST_UEFI_BOOT;
#endif

	DbgMsg("dc_get_boot_pass uefi_boot=%d\n", (dc_load_flags & DST_UEFI_BOOT) ? 1 : 0);

	if (dc_load_flags & DST_UEFI_BOOT)
	{
		if (dc_get_uefi_boot_pass() == ST_OK) {
			return;
		}

#ifndef _M_ARM64
		if (dc_get_old_uefi_boot_pass() == ST_OK) {
			return;
		}
#endif
	}
#ifndef _M_ARM64
	else
	{
		if (dc_get_legacy_boot_pass() == ST_OK) {
			return;
		}
	}
#endif

	DbgMsg("boot data block NOT found\n");
}
