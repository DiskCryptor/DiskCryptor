/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2019-2026
	* DavidXanatos <info@diskcryptor.org>
    * Copyright (c) 2007-2014
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
#include <stdlib.h>
#include <stdio.h>
#include "defines.h"
#include "driver.h"
#include "prng.h"
#include "misc.h"
#include "dump_hook.h"
#include "dump_filter.h"
#include "misc_irp.h"
#include "devhook.h"
#include "readwrite.h"
#include "enc_dec.h"
#include "io_control.h"
#include "pnp_irp.h"
#include "boot_pass.h"
#include "mount.h"
#include "fast_crypt.h"
#include "debug.h"
#include "misc_mem.h"
#include "minifilter.h"
#include "crypto_functions.h"
#include "bootloader.h"
#include "verify.h"

/* function types declaration */
DRIVER_INITIALIZE DriverEntry;
KSTART_ROUTINE    dc_automount_thread;
DRIVER_DISPATCH   dc_dispatch_irp;

PDEVICE_OBJECT dc_device;
volatile long  dc_io_count;
ULONG          dc_conf_flags; // config flags read from registry
ULONG          dc_load_flags; // other flags set by driver during initialization
ULONG          dc_boot_flags; // flags passed from the bootloader
ULONG          dc_boot_kbs;   // bootloader base memory size in kbs
ULONG          dc_cpu_count;  // CPU count

typedef NTSTATUS (*dc_dispatch)(dev_hook *hook, PIRP irp);

static const dc_dispatch hookdev_procs[IRP_MJ_MAXIMUM_FUNCTION + 1] = {
	dc_forward_irp,    /* IRP_MJ_CREATE */
	dc_forward_irp,    /* IRP_MJ_CREATE_NAMED_PIPE */
	dc_forward_irp,    /* IRP_MJ_CLOSE */
	io_read_write_irp, /* IRP_MJ_READ */
	io_read_write_irp, /* IRP_MJ_WRITE */
	dc_forward_irp,    /* IRP_MJ_QUERY_INFORMATION */
	dc_forward_irp,    /* IRP_MJ_SET_INFORMATION */
	dc_forward_irp,    /* IRP_MJ_QUERY_EA */
	dc_forward_irp,    /* IRP_MJ_SET_EA */
	dc_forward_irp,    /* IRP_MJ_FLUSH_BUFFERS */
	dc_forward_irp,    /* IRP_MJ_QUERY_VOLUME_INFORMATION */
	dc_forward_irp,    /* IRP_MJ_SET_VOLUME_INFORMATION */
	dc_forward_irp,    /* IRP_MJ_DIRECTORY_CONTROL */
	dc_forward_irp,    /* IRP_MJ_FILE_SYSTEM_CONTROL */
	dc_io_control_irp, /* IRP_MJ_DEVICE_CONTROL*/
	dc_forward_irp,    /* IRP_MJ_INTERNAL_DEVICE_CONTROL */
	dc_forward_irp,    /* IRP_MJ_SHUTDOWN */
	dc_forward_irp,    /* IRP_MJ_LOCK_CONTROL */
	dc_forward_irp,    /* IRP_MJ_CLEANUP */
	dc_forward_irp,    /* IRP_MJ_CREATE_MAILSLOT */
	dc_forward_irp,    /* IRP_MJ_QUERY_SECURITY */
	dc_forward_irp,    /* IRP_MJ_SET_SECURITY */
	dc_power_irp,      /* IRP_MJ_POWER */
	dc_forward_irp,    /* IRP_MJ_SYSTEM_CONTROL */
	dc_forward_irp,    /* IRP_MJ_DEVICE_CHANGE */
	dc_forward_irp,    /* IRP_MJ_QUERY_QUOTA */
	dc_forward_irp,    /* IRP_MJ_SET_QUOTA */
	dc_pnp_irp         /* IRP_MJ_PNP */
};


static NTSTATUS dc_dispatch_irp(PDEVICE_OBJECT dev_obj, PIRP irp)
{
	PIO_STACK_LOCATION irp_sp = IoGetCurrentIrpStackLocation(irp);
	dev_hook          *hook   = dev_obj->DeviceExtension;
	NTSTATUS           status;

	if (dev_obj == dc_device) 
	{
		switch (irp_sp->MajorFunction)
		{
			case IRP_MJ_CREATE:
			case IRP_MJ_CLOSE:
				return dc_create_close_irp(dev_obj, irp);
			break;
			case IRP_MJ_DEVICE_CONTROL:
				return dc_drv_control_irp(dev_obj, irp);
			break;
			default:
				return dc_complete_irp(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
			break;
		}
	}	
	status = IoAcquireRemoveLock(&hook->remove_lock, irp);

	if (NT_SUCCESS(status) == FALSE) {
		if (irp_sp->MajorFunction == IRP_MJ_POWER) PoStartNextPowerIrp(irp);
		return dc_complete_irp(irp, status, 0);
	}
	return hookdev_procs[irp_sp->MajorFunction](hook, irp);
}

static void dc_cleanup()
{
	/* clear cached passwords */
	if ( !(dc_conf_flags & CONF_CACHE_PASSWORD) && !(dc_boot_flags & (BDB_BF_HDR_FOUND | BDB_BF_PASS_CACHE)) ) {
		dc_clean_pass_cache();
	}

	/* clear cached boot keys */
	dc_clean_boot_keys();
}

static void dc_automount_thread(void *param)
{
	/* wait 0.5 sec */
	dc_delay(500);

	/* complete automounting */
	dc_mount_all(NULL, 0, NULL);

	dc_cleanup();

	PsTerminateSystemThread(STATUS_SUCCESS);
}

static void dc_reinit_routine(PDRIVER_OBJECT drv_obj, void *context, u32 count)
{
	DbgMsg("dc_reinit_routine\n");

	/* initialize minifilter */
	mf_init(drv_obj);

	if (dc_conf_flags & CONF_AUTOMOUNT_BOOT) {
		start_system_thread(dc_automount_thread, NULL, NULL);
	} else {
		dc_cleanup();
	}
}

static void dc_load_config(PUNICODE_STRING reg_path)
{
	u8                             buff[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(dc_conf_flags)];
	PKEY_VALUE_PARTIAL_INFORMATION info = pv(buff);
	u32                            bytes;
	HANDLE                         key_1, key_2;
	OBJECT_ATTRIBUTES              obj;
	NTSTATUS                       status;
	UNICODE_STRING                 u_name;

	key_1 = NULL; key_2 = NULL;
	do
	{
		InitializeObjectAttributes(&obj, reg_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		status = ZwOpenKey(&key_1, GENERIC_READ, &obj);
		if (NT_SUCCESS(status) == FALSE) break;

		RtlInitUnicodeString(&u_name, L"config");
		InitializeObjectAttributes(&obj, &u_name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, key_1, NULL);

		status = ZwOpenKey(&key_2, GENERIC_READ, &obj);
		if (NT_SUCCESS(status) == FALSE) break;

		RtlInitUnicodeString(&u_name, L"Flags");

		status = ZwQueryValueKey(key_2, &u_name, KeyValuePartialInformation, info, sizeof(buff), &bytes);
		if (NT_SUCCESS(status) == FALSE) break;
		
		/* copy config data */
		memcpy(&dc_conf_flags, info->Data, sizeof(dc_conf_flags));

	} while (0);

	if (key_2 != NULL) ZwClose(key_2);
	if (key_1 != NULL) ZwClose(key_1);
}

static int dc_create_control_device(PDRIVER_OBJECT drv_obj)
{
	UNICODE_STRING dev_name_u;
	UNICODE_STRING dos_name_u;
	NTSTATUS       status;
	int            resl = ST_ERROR;

	RtlInitUnicodeString(&dev_name_u, DC_DEVICE_NAME);
	RtlInitUnicodeString(&dos_name_u, DC_LINK_NAME);
	do
	{
		status = IoCreateDevice(drv_obj, 0, &dev_name_u, FILE_DEVICE_UNKNOWN, 0, FALSE, &dc_device);
		if (NT_SUCCESS(status) == FALSE) break;

		dc_device->Flags               |= DO_BUFFERED_IO;
		dc_device->AlignmentRequirement = FILE_WORD_ALIGNMENT;
		dc_device->Flags               &= ~DO_DEVICE_INITIALIZING;

		status = IoCreateSymbolicLink(&dos_name_u, &dev_name_u);		
		if (NT_SUCCESS(status) == FALSE) { IoDeleteDevice(dc_device); break; }
		resl = ST_OK;		
	} while (0);

	return resl;
}

static void dc_check_base_mem()
{
	PHYSICAL_ADDRESS addr;
	unsigned char   *mem;
	
	/* map first physical memory page */
	addr.HighPart = 0; addr.LowPart = 0;

	if (mem = MmMapIoSpace(addr, PAGE_SIZE, MmCached)) 
	{
		DbgMsg("base_mem: %d kb\n", p16(mem + 0x0413)[0]);
		DbgMsg("boot_mem: %d kb\n", dc_boot_kbs);

		if (p16(mem + 0x0413)[0] + dc_boot_kbs < 512 + DC_BOOTHOOK_SIZE) {
			dc_load_flags |= DST_SMALL_MEM;
		}
		MmUnmapIoSpace(mem, PAGE_SIZE);
	}
}

static int dc_get_cpu_count()
{
	KAFFINITY mask = KeQueryActiveProcessors();
	int       i, count;

	for (i = 0, count = 0; i < sizeof(KAFFINITY) * 8; i++) {
		if (mask & ((KAFFINITY)1 << i)) count++;
	}
	return count;
}

NTSTATUS 
  DriverEntry(
	IN PDRIVER_OBJECT  DriverObject,
    IN PUNICODE_STRING RegistryPath
	)
{
	NTSTATUS status;
	ULONG    os_major = 0, os_minor = 0;
	int      num;

#ifdef DBG_MSG
	dc_dbg_init();
#endif
	PsGetVersion(&os_major, &os_minor, NULL, NULL);

	// try to open dcrypt device in crashdump filter
	if ( os_major >= 6 )
	{
		UNICODE_STRING device_name = RTL_CONSTANT_STRING(DC_DEVICE_NAME);
		PFILE_OBJECT   file_obj;

		if ( NT_SUCCESS(IoGetDeviceObjectPointer(&device_name, GENERIC_ALL, &file_obj, &dc_device)) )
		{
			status = dump_filter_DriverEntry((PFILTER_EXTENSION)DriverObject, (PFILTER_INITIALIZATION_DATA)RegistryPath);
			ObDereferenceObject(file_obj);
			return status;
		}
	}

	DbgMsg("dcrypt.sys started\n");

	// get number of processors in system
	dc_cpu_count = dc_get_cpu_count();
	DbgMsg("%d processors detected\n", dc_cpu_count);

	mm_init();
	dc_load_config(RegistryPath);
	dc_verify_cert();
	dc_init_encryption();
	dc_init_devhook(); 
	dc_init_mount();
	io_init();
	dc_get_boot_pass();
	dc_check_base_mem();

	DbgMsg("dc_load_flags is %08x\n", dc_load_flags);
	
	// setup IRP handlers
	for (num = 0; num <= IRP_MJ_MAXIMUM_FUNCTION; num++) {
		DriverObject->MajorFunction[num] = dc_dispatch_irp;
	}
	DriverObject->DriverExtension->AddDevice = dc_add_device;

	// init random number generator
	if (cp_rand_init() != ST_OK) {
		status = STATUS_UNSUCCESSFUL;
		goto cleanup;
	}
	
	// initialize crashdump port hooking on Windows < Vista
	if ( os_major < 6 ) {
		if ( NT_SUCCESS(status = dump_hook_init(DriverObject)) == FALSE ) goto cleanup;
	}

	// initialize multithreaded encryption
	if (cp_init_fast_crypt() != ST_OK) {
		status = STATUS_UNSUCCESSFUL;
		goto cleanup;
	}

	// initialize dcrypt device
	if (dc_create_control_device(DriverObject) != ST_OK) {
		status = STATUS_UNSUCCESSFUL;
		goto cleanup;
	}
	// all initialized OK
	status = STATUS_SUCCESS;
	
	// register reinit routine for complete automounting and to clear cached passwords	
	IoRegisterDriverReinitialization(DriverObject, dc_reinit_routine, NULL);
	
	// secondary reseed PRNG after all operations
	cp_rand_reseed();
	
cleanup:
	// free resources if initialization failed
	if (NT_SUCCESS(status) == FALSE) 
	{
		cp_free_fast_crypt();
		io_free();
		mm_uninit();
	}
	return status;
}

