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
#include "defines.h"
#include "devhook.h"
#include "device_io.h"
#include "misc.h"
#include "debug.h"

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

int io_hook_rw(dev_hook *hook, void *buff, u32 length, u64 offset, int is_read)
{
	NTSTATUS status;
	u32      bsize;
	int      resl;	

	if (hook->pnp_state != Started || hook->max_chunk == 0) {
		DbgMsg("device not started, dev=%ws, pnp_state=%d, max_chunk=%u\n", hook->dev_name, hook->pnp_state, hook->max_chunk);
		return ST_RW_ERR;
	}	
	for (resl = ST_OK; length != 0; )
	{
		bsize  = min(length, hook->max_chunk);
		status = io_device_request(hook->orig_dev, is_read ? IRP_MJ_READ : IRP_MJ_WRITE, buff, bsize, offset);

		if (NT_SUCCESS(status) == FALSE)
		{
			if ( (hook->flags & (F_REMOVABLE | F_CDROM)) && 
				 (status == STATUS_NO_SUCH_DEVICE || 
				  status == STATUS_DEVICE_DOES_NOT_EXIST || status == STATUS_NO_MEDIA_IN_DEVICE) )
			{
				resl = ST_NO_MEDIA;
			} else {
				resl = ST_RW_ERR;
			}
			DbgMsg("io_hook_rw: dev=%ws, status=%08x\n", hook->dev_name, status);
			break;
		} else {
			buff = p8(buff) + bsize; length -= bsize; offset += bsize;
		}
	}
	return resl;
}

int io_hook_rw_skip_bads(dev_hook *hook, void *buff, u32 length, u64 offset, int is_read)
{
	u32 block;
	int resl;

	if ( (resl = io_hook_rw(hook, buff, length, offset, is_read)) == ST_RW_ERR )
	{
		while (block = min(length, 4096))
		{
			resl = io_hook_rw(hook, buff, block, offset, is_read);

			if ( (resl == ST_MEDIA_CHANGED) || (resl == ST_NO_MEDIA) ) {
				break;
			}
			buff = p8(buff) + block; length -= block; offset += block;
		}
	}
	return resl;
}

/*
 * volume_lib's dc_rw_fn over io_hook_rw. Exists so that io_hook_rw itself,
 * and all of its call sites, stay exactly as they are.
 */
int dc_hook_rw(void *ctx, void *buff, u32 length, u64 offset, int is_read)
{
	return io_hook_rw((dev_hook*)ctx, buff, length, offset, is_read);
}
