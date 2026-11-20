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
#include "misc_mem.h"


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

/*
 * Physical memory and the boot data block.
 *
 * The loaders never leave the block in memory Windows manages: DCS allocates it as
 * EfiMemoryMappedIO (DcsPkg CommonLib EfiMem.c PrepareMemory / PrepareMemoryAny), the BIOS
 * loader hides its body from Windows in its e820 map. So a probe address that lies in Windows
 * RAM cannot hold the block - and mapping such a page is illegal: it is not locked, its contents
 * and attributes can change under the view, and Driver Verifier bugchecks on it (0x1A / 0x1233).
 * The old-loader scans (1-16 MiB, 500-640 KiB) hit such pages on every boot that did not come
 * through DCS, so RAM is skipped and everything else is read with MmMapIoSpace. MmCopyMemory is
 * no alternative: it refuses I/O space (the block's memory type) and does not exist on
 * Windows 7; MmGetPhysicalMemoryRanges does.
 */
#define DC_BDB_MAX_SIZE (1024 * 1024) /* DCS: bd_data + password cache + boot keys, a few KiB */

/* nonzero when any byte of [start, start + len) is RAM Windows manages - and when the ranges
   cannot be queried (then nothing is mapped) */
static int dc_phys_is_ram(u64 start, u64 len)
{
	PPHYSICAL_MEMORY_RANGE r = MmGetPhysicalMemoryRanges();
	int                    ram = 0;
	u32                    i;

	if (r == NULL) return 1;
	/* the array ends with an entry whose base and size are both zero */
	for (i = 0; r[i].BaseAddress.QuadPart != 0 || r[i].NumberOfBytes.QuadPart != 0; i++) {
		u64 b = (u64)r[i].BaseAddress.QuadPart;
		u64 e = b + (u64)r[i].NumberOfBytes.QuadPart;

		if (start < e && b < start + len) { ram = 1; break; }
	}
	ExFreePool(r);
	return ram;
}

/* one page of physical memory into buf; RAM is skipped (see above) */
static int dc_read_phys_page(PHYSICAL_ADDRESS addr, u8 *buf)
{
	void *mem;
	int   ok = 0;

	if (dc_phys_is_ram((u64)addr.QuadPart, PAGE_SIZE)) {
		return 0;
	}
	if ((mem = MmMapIoSpace(addr, PAGE_SIZE, MmCached)) == NULL) {
		return 0;
	}
	__try {
		memcpy(buf, mem, PAGE_SIZE);
		ok = 1;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgMsg("exception while reading physical memory: 0x%08X\n", GetExceptionCode());
	}
	MmUnmapIoSpace(mem, PAGE_SIZE);
	return ok;
}

/*
 * A found block names memory that is mapped (its key / password arrays) and zeroed (base,
 * bd_size) below. It comes from memory nobody vouches for - a scan can also find a stale copy
 * of an earlier boot - so the size has to be plausible and neither range may be Windows RAM.
 */
static int dc_bdb_plausible(PHYSICAL_ADDRESS addr, bd_data *bdb, u8 *page, u64 *out_base)
{
	/* the data block base address */
	u64 base = *out_base = ((dc_load_flags & DST_UEFI_BOOT) && bdb->bd_base == 0) ? bdb->u.uefi.bd_base64 : (u64)bdb->bd_base;
	/* where the block itself was found */
	u64 blk  = (u64)addr.QuadPart + (u64)((u8*)bdb - page);

	/* base is zeroed below over bd_size bytes: it must be the loader's own memory, not anything
	   the block names. DCS puts the block at the start of its allocation (bd_base / bd_base64
	   = the block's address); the BIOS loader's block starts inside its body [base, base + size)
	   (the copy found there sits 384 bytes before the body's end, so it is shorter than bd_data) */
	if (base + bdb->bd_size < base ||
		((dc_load_flags & DST_UEFI_BOOT) ? (base != blk)
		                                 : (blk < base || blk >= base + bdb->bd_size)))
	{
		DbgMsg("boot data block at 0x%016I64X rejected: base 0x%016I64X does not hold it\n", blk, base);
		return 0;
	}

	if (bdb->bd_size == 0 || bdb->bd_size > DC_BDB_MAX_SIZE ||
		dc_phys_is_ram((u64)addr.QuadPart, ROUND_TO_PAGES(bdb->bd_size)) ||
		dc_phys_is_ram(base, bdb->bd_size))
	{
		DbgMsg("boot data block at 0x%016I64X rejected: size %u, base 0x%016I64X\n", addr.QuadPart, bdb->bd_size, base);
		return 0;
	}
	return 1;
}

int dc_try_load_bdb(PHYSICAL_ADDRESS addr)
{
	int              ret = ST_ERROR;
	bd_data         *bdb;
	u8              *page;
	u64				 base = 0;
	SIZE_T           offset = 0;
	void            *mem;
	dc_pass          password = { 0 };
	u32              i;
	u8              *pass_ptr;

	/* the probed page, plus room for a block found near its end (its fields past the page then
	   read as zero); secure memory: it holds the boot password when the block is there */
	if ((page = mm_secure_alloc(PAGE_SIZE + sizeof(bd_data))) == NULL) {
		return ST_NOMEM;
	}

	if (dc_read_phys_page(addr, page))
	{
			__try
			{
				/* only a plausible block is mapped below (MmMapIoSpace of the loader's own
				   memory, to read its key / password arrays and zero it) */
				if ((bdb = find_8b(page, PAGE_SIZE - offsetof(bd_data, u.extra), BDB_SIGN1, BDB_SIGN2)) != NULL &&
					dc_bdb_plausible(addr, bdb, page, &base))
				{
					/* set bootloader load flag */
					InterlockedOr((volatile LONG*)&dc_load_flags, (LONG)DST_BOOTLOADER); /* also on the ARM64 retry at run time */

					offset = ((u8*)bdb - page);

					//DbgMsg("boot data block found at %p\n", bdb);
					DbgMsg("boot data block found at 0x%016I64X\n", addr.QuadPart);
					DbgMsg("boot loader base 0x%016I64X size %d\n", base, bdb->bd_size);
					//DbgMsg("boot extra %08x %08x\n", bdb->u.bios.old_int13, bdb->u.uefi.sign3);

					/* password_size comes from (untrusted) physical memory - copy only a
					 * length that fits password.pass; otherwise leave size 0 so no main
					 * password is cached (dc_cache_password skips size 0) */
					if (bdb->password_size > 0 && bdb->password_size <= (int)sizeof(password.pass)) {
						password.size = bdb->password_size;
						RtlCopyMemory(password.pass, bdb->password_data, password.size);
					}
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
								pass_ptr = ((u8*)mem) + offset + bdb->u.uefi.pass_offset;
								for(i = 0; i < bdb->u.uefi.pass_count; i++) {
									/* start each entry clean (a short pass_size must not
									 * inherit the previous entry's fields) and cache only entries
									 * whose size fits pass[] - the cache feeds size straight into
									 * the KDF and memcmp */
									memset(&password, 0, sizeof(password));
									memcpy(&password, pass_ptr + i * bdb->u.uefi.pass_size, min(sizeof(password), bdb->u.uefi.pass_size));
									if (password.size > 0 && password.size <= (int)sizeof(password.pass)) {
										dc_cache_password(&password);
									}
								}
							}
						}

						MmUnmapIoSpace(mem, ROUND_TO_PAGES(bdb->bd_size)); /* the length it was mapped with */
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
	}

	burn(&password, sizeof(password));
	mm_secure_free(page);

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

/* exported since NT 4 (declared here as in verify.c, ntifs.h does not declare it) */
NTSYSCALLAPI NTSTATUS NTAPI ZwQuerySystemInformation(
	_In_ ULONG SystemInformationClass,
	_Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength);

/* SystemBootEnvironmentInformation (Vista and later): Windows 7 returns { GUID; FIRMWARE_TYPE; },
   Windows 8 and later append a ULONGLONG BootFlags, hence the larger buffer */
#define DC_SYSTEM_BOOT_ENVIRONMENT_INFORMATION 90
#define DC_FIRMWARE_TYPE_BIOS 1
#define DC_FIRMWARE_TYPE_UEFI 2

typedef struct _dc_boot_env_info {
	GUID      boot_identifier;
	ULONG     firmware_type;
	ULONG     reserved;   /* alignment of boot_flags */
	ULONGLONG boot_flags; /* Windows 8 and later */
} dc_boot_env_info;

BOOLEAN dc_efi_check()
{
	/* ask the kernel for the firmware type first: the variable probe below expects
	   STATUS_VARIABLE_NOT_FOUND on UEFI, which only Windows 8 and later return (Windows 7
	   fails it with another status) */
	{
		dc_boot_env_info info;
		ULONG            len = 0;
		NTSTATUS         st;

		RtlZeroMemory(&info, sizeof(info));
		st = ZwQuerySystemInformation(DC_SYSTEM_BOOT_ENVIRONMENT_INFORMATION, &info, sizeof(info), &len);

		DbgMsg("SystemBootEnvironmentInformation, status=%08x len=%u firmware_type=%u\n", st, len, info.firmware_type);

		if (NT_SUCCESS(st) && len >= (ULONG)FIELD_OFFSET(dc_boot_env_info, reserved))
		{
			if (info.firmware_type == DC_FIRMWARE_TYPE_UEFI) {
				InterlockedOr((volatile LONG*)&dc_load_flags, (LONG)DST_UEFI_BOOT);
				return TRUE;
			}
			if (info.firmware_type == DC_FIRMWARE_TYPE_BIOS) {
				return TRUE;
			}
		}
	}

	/* fallback (query failed or type unknown): the variable probe */
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
		InterlockedOr((volatile LONG*)&dc_load_flags, (LONG)DST_UEFI_BOOT);
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
			InterlockedOr((volatile LONG*)&dc_load_flags, (LONG)DST_UEFI_RETRY);
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
	InterlockedOr((volatile LONG*)&dc_load_flags, (LONG)DST_UEFI_BOOT);
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
