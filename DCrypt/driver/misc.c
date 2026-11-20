/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2007-2008 
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
#include <ntddcdrm.h>
#include <stdio.h>
#include <stdarg.h>
#include "defines.h"
#include "driver.h"
#include "misc.h"
#include "devhook.h"
#include "debug.h"
#include "misc_mem.h"
#include "disk_info.h"

void wait_object_infinity(void *wait_obj)
{
	KeWaitForSingleObject(wait_obj, Executive, KernelMode, FALSE, NULL);
}

int start_system_thread(PKSTART_ROUTINE thread_start, void *param, HANDLE *handle)
{
	OBJECT_ATTRIBUTES obj_a;
	HANDLE            h_thread;
	NTSTATUS          status;

	InitializeObjectAttributes(&obj_a, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	status = PsCreateSystemThread(
		&h_thread, THREAD_ALL_ACCESS, &obj_a, NULL, NULL, thread_start, param);

	if (NT_SUCCESS(status) == FALSE) {
		return ST_ERR_THREAD;
	}
	if (handle == NULL) {
		ZwClose(h_thread);
	} else {
		*handle = h_thread;		
	}
	return ST_OK;
}

int dc_resolve_link(wchar_t *sym_link, wchar_t *target, u16 length)
{
	UNICODE_STRING    u_name;
	OBJECT_ATTRIBUTES obj;
	NTSTATUS          status;
	HANDLE            handle;
	int               resl;

	RtlInitUnicodeString(&u_name, sym_link);

	InitializeObjectAttributes(
		&obj, &u_name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	do
	{
		status = ZwOpenSymbolicLinkObject(&handle, GENERIC_READ, &obj);

		if (NT_SUCCESS(status) == FALSE) {
			handle = NULL; resl = ST_ERROR; break;
		}
		u_name.Buffer        = target;
		u_name.Length        = 0;
		u_name.MaximumLength = length - 2;

		status = ZwQuerySymbolicLinkObject(handle, &u_name, NULL);

		if (NT_SUCCESS(status) == FALSE) {
			resl = ST_ERROR; break;
		} else {
			resl = ST_OK;
		}
		target[u_name.Length >> 1] = 0;
	} while (0);

	if (handle != NULL) {
		ZwClose(handle);
	}
	return resl;
}

int dc_get_mount_point(dev_hook *hook, wchar_t *buffer, u16 length)
{
	NTSTATUS       status;
	UNICODE_STRING name;
	int            resl;

	status = IoVolumeDeviceToDosName(hook->orig_dev, &name);

	buffer[0] = 0; resl = ST_ERROR;

	if (NT_SUCCESS(status) != FALSE) 
	{
		if (name.Length < length) {
			mincpy(buffer, name.Buffer, name.Length);
			buffer[name.Length >> 1] = 0; 
			resl = ST_OK;
		} 
		ExFreePool(name.Buffer);
	}
	return resl;
}

void dc_query_object_name(void *object, wchar_t *buffer, u16 length)
{
	u8                       buf[256];
	POBJECT_NAME_INFORMATION inf = pv(buf);
	u32                      bytes;
	NTSTATUS                 status;

	status = ObQueryNameString(object, inf, sizeof(buf), &bytes);

	if (NT_SUCCESS(status) != FALSE) {
		/* leave room for the terminator (and keep a whole number of WCHARs) */
		bytes = min((u32)(length - sizeof(wchar_t)), (u32)inf->Name.Length) & ~1u;
		mincpy(buffer, inf->Name.Buffer, bytes);
		buffer[bytes >> 1] = 0;
	} else {
		buffer[0] = 0;
	}
}

u64 intersect(u64 *i_st, u64 start1, u64 size1, u64 start2, u64 size2)
{
	u64 end, i;	
	end = min(start1 + size1, start2 + size2);
	*i_st = i = max(start1, start2);
	return (i < end) ? end - i : 0;
}

void dc_delay(u32 msecs)
{
	LARGE_INTEGER time;

	time.QuadPart = d64(msecs) * -10000;	
	KeDelayExecutionThread(KernelMode, FALSE, &time);
}

#ifdef _M_IX86
long save_fpu_state(unsigned char state[32]) {
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) return STATUS_UNSUCCESSFUL;
	return KeSaveFloatingPointState((PKFLOATING_SAVE)state);
}
void load_fpu_state(unsigned char state[32]) {
	KeRestoreFloatingPointState((PKFLOATING_SAVE)state);
}
#endif