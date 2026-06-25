/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2026
    * DavidXanatos <info@diskcryptor.org>
    * Copyright (c) 2010-2013
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
#include <ntddcdrm.h>
#pragma warning( disable : 4091 )
#include <ntddscsi.h>
#pragma warning( default : 4091 )
#include <ntdddisk.h>
#include <ata.h>
#include "defines.h"
#include "devhook.h"
#include "disk_info.h"
#include "misc.h"
#include "device_io.h"
#include "debug.h"

static ULONG dc_get_device_mtl(dev_hook *hook)
{
	STORAGE_PROPERTY_QUERY     sq = { StorageAdapterProperty, PropertyStandardQuery, };
	IO_SCSI_CAPABILITIES       sc;
	STORAGE_ADAPTER_DESCRIPTOR sd;
	ULONG                      max_chunk;

	if ( NT_SUCCESS(io_device_control(hook->orig_dev, IOCTL_STORAGE_QUERY_PROPERTY, &sq, sizeof(sq), &sd, sizeof(sd))) ) {
		max_chunk = min(sd.MaximumTransferLength, (sd.MaximumPhysicalPages ? sd.MaximumPhysicalPages * PAGE_SIZE : 0));
	} else if ( NT_SUCCESS(io_device_control(hook->orig_dev, IOCTL_SCSI_GET_CAPABILITIES, NULL, 0, &sc, sizeof(sc))) ) {
		max_chunk = min(sc.MaximumTransferLength, (sc.MaximumPhysicalPages ? sc.MaximumPhysicalPages * PAGE_SIZE : 0));
	} else {
		// 64k safe for removable devices, 128k safe for internal devices
		max_chunk = ((hook->flags & F_REMOVABLE) ? 64 : 128) * 1024;
	}
	// MaximumTransferLength must be >= 32k and PAGE_SIZE aligned
	max_chunk = max(max_chunk & ~(PAGE_SIZE - 1), 32*1024);
	DbgMsg("device %ws MaximumTransferLength=%dK\n", hook->dev_name, max_chunk / 1024);
	return max_chunk;
}

static BOOLEAN dc_is_this_ssd(dev_hook *hook)
{
	STORAGE_PROPERTY_QUERY         query = { StorageDeviceSeekPenaltyProperty,  PropertyStandardQuery, };
	DEVICE_SEEK_PENALTY_DESCRIPTOR seek  = { 0 };
	char                           buff[sizeof(ATA_PASS_THROUGH_EX) + sizeof(IDENTIFY_DEVICE_DATA)] = { 0 };
    PATA_PASS_THROUGH_EX           pata = (PATA_PASS_THROUGH_EX)buff;
	PIDENTIFY_DEVICE_DATA          idat = (PIDENTIFY_DEVICE_DATA)(buff + sizeof(ATA_PASS_THROUGH_EX));

	if ( NT_SUCCESS(io_device_control(hook->orig_dev, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), &seek, sizeof(seek))) )
	{
		if (seek.Version >= sizeof(DEVICE_SEEK_PENALTY_DESCRIPTOR) && seek.Size >= sizeof(DEVICE_SEEK_PENALTY_DESCRIPTOR)) {
			DbgMsg("device %ws IncursSeekPenalty=%d\n", hook->dev_name, seek.IncursSeekPenalty);
			return seek.IncursSeekPenalty == FALSE;
		}
	}	

	pata->Length             = sizeof(ATA_PASS_THROUGH_EX);
	pata->DataBufferOffset   = sizeof(ATA_PASS_THROUGH_EX);
	pata->DataTransferLength = sizeof(IDENTIFY_DEVICE_DATA);
	pata->AtaFlags           = ATA_FLAGS_DATA_IN;
	pata->TimeOutValue       = 2;
	pata->CurrentTaskFile[6] = IDE_COMMAND_IDENTIFY;

	if ( NT_SUCCESS(io_device_control(hook->orig_dev, IOCTL_ATA_PASS_THROUGH, buff, sizeof(buff), buff, sizeof(buff))) )
	{
		DbgMsg("device %ws NominalMediaRotationRate=%d\n", hook->dev_name, idat->NominalMediaRotationRate);
		return idat->NominalMediaRotationRate == 1;
	}
	return FALSE;
}

NTSTATUS dc_fill_device_info(dev_hook *hook)
{
	DISK_GEOMETRY_EX dgx;
	DISK_GEOMETRY    dg;
	ULONGLONG        dev_length;
	NTSTATUS         status;
	
	if (hook->pnp_state != Started) {
		DbgMsg("device not started, dev=%ws, pnp_state=%d\n", hook->dev_name, hook->pnp_state);
		return STATUS_INVALID_DEVICE_STATE;
	}

	// check media in removable device
	if (hook->flags & F_REMOVABLE)
	{
		if ( !NT_SUCCESS(status = io_device_control(hook->orig_dev,
			                                        IOCTL_STORAGE_CHECK_VERIFY, NULL, 0, &hook->chg_count, sizeof(hook->chg_count))) )
		{
			DbgMsg("removable device has no media, dev=%ws, status=%0.8x\n", hook->dev_name, status);
			return status;
		}
	}
	
	// get device length in bytes
	if (hook->flags & F_CDROM)
	{
		if ( NT_SUCCESS(status = io_device_control(hook->orig_dev, IOCTL_CDROM_GET_DRIVE_GEOMETRY_EX, NULL, 0, &dgx, sizeof(dgx))) ) {
			dev_length = dgx.DiskSize.QuadPart;
			dg.BytesPerSector = dgx.Geometry.BytesPerSector;
		} else if ( NT_SUCCESS(status = io_device_control(hook->orig_dev, IOCTL_CDROM_GET_DRIVE_GEOMETRY, NULL, 0, &dg, sizeof(dg))) ) {
			dev_length = dg.Cylinders.QuadPart * (ULONGLONG)(dg.TracksPerCylinder * dg.SectorsPerTrack * dg.BytesPerSector);
		}
	} else
	{
		PARTITION_INFORMATION    pti;
		PARTITION_INFORMATION_EX ptix;

		if ( !NT_SUCCESS(status = io_device_control(hook->orig_dev, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &dg, sizeof(dg))) )
		{
			DbgMsg("cannot get drive geometry, dev=%ws, status=%0.8x\n", hook->dev_name, status);
			return status;
		}

		if ( NT_SUCCESS(status = io_device_control(hook->orig_dev, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, &ptix, sizeof(ptix))) ) {
			dev_length = ptix.PartitionLength.QuadPart;
		} else if ( NT_SUCCESS(status = io_device_control(hook->orig_dev, IOCTL_DISK_GET_PARTITION_INFO, NULL, 0, &pti, sizeof(pti))) ) {
			dev_length = pti.PartitionLength.QuadPart;
		} else if ( !NT_SUCCESS(status = io_device_control(hook->orig_dev, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &dev_length, sizeof(dev_length))) ) {
			dev_length = dg.Cylinders.QuadPart * (ULONGLONG)(dg.TracksPerCylinder * dg.SectorsPerTrack * dg.BytesPerSector);
			status = STATUS_SUCCESS;
		}
	}
	if ( !NT_SUCCESS(status) ) {
		DbgMsg("cannot get drive size, dev=%ws, status=%0.8x\n", hook->dev_name, status);
		return status;
	} else {
		DbgMsg("device %ws size = %uMB\n", hook->dev_name, (ULONG)(dev_length / 1024 / 1024));
	}

	hook->dsk_size  = dev_length;
	hook->bps       = dg.BytesPerSector;
	hook->max_chunk = dc_get_device_mtl(hook);

	if ( (hook->flags & (F_REMOVABLE | F_CDROM | F_SSD)) == 0 ) {
		if ( dc_is_this_ssd(hook) ) hook->flags |= F_SSD;
	}
	return STATUS_SUCCESS;
}