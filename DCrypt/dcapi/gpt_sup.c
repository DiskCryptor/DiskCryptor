/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2026
    * DavidXanatos <info@diskcryptor.org>
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

#include <windows.h>
#include <stdio.h>
#include <winioctl.h>
#include "dcconst.h"
#include "misc.h"
#include "drv_ioctl.h"
#include "gpt_sup.h"
#include "efiinst.h"

/* Well-known partition type GUIDs */
const GUID GUID_EFI_SYSTEM_PARTITION =
{ 0xc12a7328, 0xf81f, 0x11d2, { 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b } };
const GUID GUID_BASIC_DATA_PARTITION =
{ 0xebd0a0a2, 0xb9e5, 0x4433, { 0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7 } };
const GUID GUID_MICROSOFT_RESERVED =
{ 0xe3c9e316, 0x0b5c, 0x4db8, { 0x81, 0x7d, 0xf9, 0x2d, 0xf0, 0x02, 0x15, 0xae } };

/* Get OS partition number on specified disk */
int dc_get_os_partition(int dsk_num)
{
	wchar_t disk_path[MAX_PATH];
	DWORD bytes;
	int part_num = -1;
	u8 buff[sizeof(DRIVE_LAYOUT_INFORMATION_EX) + sizeof(PARTITION_INFORMATION_EX) * 127];
	PDRIVE_LAYOUT_INFORMATION_EX dli = pv(buff);
	HANDLE hdisk;

	if (dsk_num == -1) {
		dsk_num = dc_efi_get_os_disk();
		if (dsk_num < 0) return -1;
	}

	_snwprintf(disk_path, countof(disk_path), L"\\\\.\\PhysicalDrive%d", dsk_num);
	hdisk = CreateFile(disk_path, GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hdisk != INVALID_HANDLE_VALUE) {
		if (DeviceIoControl(hdisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
			NULL, 0, dli, sizeof(buff), &bytes, NULL)) {
			/* Find the largest Basic Data partition (NTFS) - this is the OS partition */
			u64 max_size = 0;
			for (DWORD i = 0; i < dli->PartitionCount; i++) {
				PPARTITION_INFORMATION_EX part = &dli->PartitionEntry[i];
				if (dli->PartitionStyle == PARTITION_STYLE_GPT) {
					if (IsEqualGUID(&part->Gpt.PartitionType, &GUID_BASIC_DATA_PARTITION)) {
						if (part->PartitionLength.QuadPart > (LONGLONG)max_size) {
							max_size = part->PartitionLength.QuadPart;
							part_num = part->PartitionNumber;
						}
					}
				}
			}
		}
		CloseHandle(hdisk);
	}

	return part_num;
}

/* Shrink partition on specified disk - shrinks filesystem only, partition table
* is updated when we create a new partition in the freed space */
int dc_gpt_shrink_partition(int dsk_num, int part_num, u64 shrink_bytes)
{
	wchar_t volume_path[MAX_PATH];
	HANDLE hVolume;
	DWORD bytes;
	int resl = ST_ERROR;
	NTFS_VOLUME_DATA_BUFFER ntfs_data;
	SHRINK_VOLUME_INFORMATION shrink_info;
	u64 current_sectors, new_sectors;

	/* Find the volume path for this partition (returned without trailing backslash) */
	resl = dc_efi_get_volume_guid_path(dsk_num, part_num, volume_path, MAX_PATH);
	if (resl != ST_OK) {
		return ST_NF_DEVICE;
	}

	hVolume = CreateFile(volume_path, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hVolume == INVALID_HANDLE_VALUE) {
		return ST_ACCESS_DENIED;
	}

	do
	{
		/* Get NTFS volume data */
		if (!DeviceIoControl(hVolume, FSCTL_GET_NTFS_VOLUME_DATA,
			NULL, 0, &ntfs_data, sizeof(ntfs_data), &bytes, NULL)) {
			resl = ST_UNK_FS; break;
		}

		current_sectors = ntfs_data.NumberSectors.QuadPart;

		/* Add one cluster for NTFS backup boot sector */
		shrink_bytes += ntfs_data.BytesPerCluster;

		/* Round up to sector boundary */
		if (shrink_bytes % ntfs_data.BytesPerSector != 0) {
			shrink_bytes = ((shrink_bytes / ntfs_data.BytesPerSector) + 1) * ntfs_data.BytesPerSector;
		}

		new_sectors = current_sectors - (shrink_bytes / ntfs_data.BytesPerSector);

		if (new_sectors >= current_sectors) {
			resl = ST_PART_TOO_SMALL; break;
		}

		/* Step 1: ShrinkPrepare */
		memset(&shrink_info, 0, sizeof(shrink_info));
		shrink_info.ShrinkRequestType = ShrinkPrepare;
		shrink_info.NewNumberOfSectors = (LONGLONG)new_sectors;

		if (!DeviceIoControl(hVolume, FSCTL_SHRINK_VOLUME,
			&shrink_info, sizeof(shrink_info), NULL, 0, &bytes, NULL)) {
			resl = ST_CLUS_USED; break;
		}

		/* Step 2: ShrinkCommit */
		memset(&shrink_info, 0, sizeof(shrink_info));
		shrink_info.ShrinkRequestType = ShrinkCommit;

		if (!DeviceIoControl(hVolume, FSCTL_SHRINK_VOLUME,
			&shrink_info, sizeof(shrink_info), NULL, 0, &bytes, NULL)) {
			/* Try to abort */
			shrink_info.ShrinkRequestType = ShrinkAbort;
			DeviceIoControl(hVolume, FSCTL_SHRINK_VOLUME,
				&shrink_info, sizeof(shrink_info), NULL, 0, &bytes, NULL);
			resl = ST_SHRINK_FAILED; break;
		}

		resl = ST_OK;

	} while (0);

	CloseHandle(hVolume);
	return resl;
}

/* Create new partition at specified offset (or auto-find if start_offset == 0) */
int dc_gpt_create_partition(
	int dsk_num,
	const GUID *type_guid,
	u64 size_bytes,
	u64 start_offset,  /* 0 = auto-find at end of disk */
	const wchar_t *name,
	int *new_part_num)
{
	int resl;
	wchar_t disk_path[MAX_PATH];
	HANDLE hdisk;
	DWORD bytes;
	u8 buff[sizeof(DRIVE_LAYOUT_INFORMATION_EX) + sizeof(PARTITION_INFORMATION_EX) * 127];
	PDRIVE_LAYOUT_INFORMATION_EX dli = pv(buff);
	LONGLONG free_start = 0;
	LONGLONG free_end = 0;
	DISK_GEOMETRY_EX dg;
	GUID new_guid;

	*new_part_num = -1;

	/* Resolve default disk */
	if (dsk_num == -1) {
		dsk_num = dc_efi_get_os_disk();
		if (dsk_num < 0) return ST_NF_DEVICE;
	}

	/* Open disk with write access */
	_snwprintf(disk_path, countof(disk_path), L"\\\\.\\PhysicalDrive%d", dsk_num);
	hdisk = CreateFile(disk_path, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hdisk == INVALID_HANDLE_VALUE) {
		return ST_ACCESS_DENIED;
	}

	do
	{
		/* Get disk geometry for sector size */
		if (!DeviceIoControl(hdisk, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
			NULL, 0, &dg, sizeof(dg), &bytes, NULL)) {
			resl = ST_ERROR; break;
		}

		/* Get current partition layout */
		if (!DeviceIoControl(hdisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
			NULL, 0, dli, sizeof(buff), &bytes, NULL)) {
			resl = ST_ERROR; break;
		}

		if (dli->PartitionStyle != PARTITION_STYLE_GPT) {
			resl = ST_GPT_INVALID; break;
		}

		if (start_offset != 0) {
			/* Use specified start offset */
			free_start = (LONGLONG)start_offset;
#ifdef DEBUG_GPT_SUP
			wprintf(L"DEBUG: Creating partition at specified offset %lld\n", free_start);
#endif
		} else {
			/* Find free space by looking at the end of existing partitions */
			/* Start after the GPT header area (typically 34 sectors = 17408 bytes for 512b sectors) */
			free_start = 34 * dg.Geometry.BytesPerSector;

			/* Find the end of all existing partitions */
			for (DWORD i = 0; i < dli->PartitionCount; i++) {
				PPARTITION_INFORMATION_EX part = &dli->PartitionEntry[i];
				if (part->PartitionLength.QuadPart > 0) {
					LONGLONG part_end = part->StartingOffset.QuadPart + part->PartitionLength.QuadPart;
					if (part_end > free_start) {
						free_start = part_end;
					}
				}
			}

			/* Align to 1MB boundary for best performance */
			free_start = (free_start + 0xFFFFF) & ~0xFFFFFLL;
#ifdef DEBUG_GPT_SUP
			wprintf(L"DEBUG: Auto-detected free space at offset %lld\n", free_start);
#endif
		}

		/* End of usable space (leave room for backup GPT - typically 33 sectors) */
		free_end = dg.DiskSize.QuadPart - (33 * dg.Geometry.BytesPerSector);

		if (free_start + (LONGLONG)size_bytes > free_end) {
			resl = ST_NO_FREE_SPACE; break;
		}

		/* Generate unique partition GUID */
		if (CoCreateGuid(&new_guid) != S_OK) {
			LARGE_INTEGER ticks;
			QueryPerformanceCounter(&ticks);
			memset(&new_guid, 0, sizeof(new_guid));
			new_guid.Data1 = (ULONG)ticks.LowPart;
			new_guid.Data2 = (USHORT)(ticks.HighPart & 0xFFFF);
			new_guid.Data3 = (USHORT)((ticks.HighPart >> 16) & 0xFFFF);
		}

		/* Add new partition entry */
		DWORD new_idx = dli->PartitionCount;
		if (new_idx >= 128) {
			resl = ST_NO_FREE_SPACE; break;
		}

		PPARTITION_INFORMATION_EX new_part = &dli->PartitionEntry[new_idx];
		memset(new_part, 0, sizeof(PARTITION_INFORMATION_EX));
		new_part->PartitionStyle = PARTITION_STYLE_GPT;
		new_part->StartingOffset.QuadPart = free_start;
		new_part->PartitionLength.QuadPart = size_bytes;
		new_part->PartitionNumber = 0; /* Windows will assign */
		new_part->RewritePartition = TRUE;
		memcpy(&new_part->Gpt.PartitionType, type_guid, sizeof(GUID));
		memcpy(&new_part->Gpt.PartitionId, &new_guid, sizeof(GUID));
		new_part->Gpt.Attributes = 0;
		if (name != NULL) {
			wcsncpy_s(new_part->Gpt.Name, 36, name, 35);
		}

		dli->PartitionCount++;

		/* Apply the new layout */
		if (!DeviceIoControl(hdisk, IOCTL_DISK_SET_DRIVE_LAYOUT_EX,
			dli, sizeof(buff), NULL, 0, &bytes, NULL)) {
			DWORD err = GetLastError();
			resl = ST_IO_ERROR; break;
		}

		/* Refresh partition table */
		DeviceIoControl(hdisk, IOCTL_DISK_UPDATE_PROPERTIES, NULL, 0, NULL, 0, &bytes, NULL);

		/* Get updated layout to find the new partition number */
		Sleep(500);
		if (DeviceIoControl(hdisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
			NULL, 0, dli, sizeof(buff), &bytes, NULL)) {
			/* Find our new partition by matching start offset */
			for (DWORD i = 0; i < dli->PartitionCount; i++) {
				if (dli->PartitionEntry[i].StartingOffset.QuadPart == free_start) {
					*new_part_num = dli->PartitionEntry[i].PartitionNumber;
					break;
				}
			}
		}

		if (*new_part_num <= 0) {
			/* Fallback - estimate partition number */
			*new_part_num = new_idx + 1;
		}

		resl = ST_OK;

	} while (0);

	CloseHandle(hdisk);
	return resl;
}

/* Refresh Windows partition cache */
int dc_refresh_disk(int dsk_num)
{
	wchar_t disk_path[MAX_PATH];
	HANDLE hdisk;
	DWORD bytes;
	int resl = ST_OK;

	_snwprintf(disk_path, countof(disk_path), L"\\\\.\\PhysicalDrive%d", dsk_num);

	hdisk = CreateFile(disk_path, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hdisk == INVALID_HANDLE_VALUE) {
		return ST_ACCESS_DENIED;
	}

	if (!DeviceIoControl(hdisk, IOCTL_DISK_UPDATE_PROPERTIES,
		NULL, 0, NULL, 0, &bytes, NULL)) {
		resl = ST_ERROR;
	}

	CloseHandle(hdisk);
	return resl;
}

/* Format partition as FAT32 with optional label */
int dc_gpt_format_partition(int dsk_num, int part_num, const wchar_t *label)
{
	wchar_t volume_path[MAX_PATH];
	int resl;

	/* Wait for Windows to recognize the partition */
#ifdef DEBUG_GPT_SUP
	wprintf(L"DEBUG: Waiting for partition to be ready...\n");
#endif

	/* Get volume GUID path, fall back to GLOBALROOT path */
	if (dc_efi_get_volume_guid_path(dsk_num, part_num, volume_path, MAX_PATH) != ST_OK) {
		swprintf_s(volume_path, MAX_PATH,
			L"\\\\?\\GLOBALROOT\\Device\\Harddisk%d\\Partition%d", dsk_num, part_num);
	}

#ifdef DEBUG_GPT_SUP
	wprintf(L"DEBUG: Formatting %s as FAT32...\n", root_path);
#endif
	resl = dc_format_fs(volume_path, L"FAT32");

	if (resl == ST_OK && label != NULL) {
		wcscat(volume_path, L"\\");
		if (!SetVolumeLabel(volume_path, label)) {
#ifdef DEBUG_GPT_SUP
			wprintf(L"WARNING: SetVolumeLabel failed: %d\n", GetLastError());
#endif
		}
#ifdef DEBUG_GPT_SUP
		else {
			wprintf(L"DEBUG: Volume label set to: %s\n", label);
		}
#endif
	}
#ifdef DEBUG_GPT_SUP
	else if (resl != ST_OK) {
		wprintf(L"ERROR: Format failed\n");
	}
#endif

	return resl;
}

/* Find existing DCS ESP partition by checking GPT name, volume label */
int dc_find_dcs_esp(int dsk_num)
{
	wchar_t disk_path[MAX_PATH];
	HANDLE hdisk;
	DWORD bytes;
	u8 buff[sizeof(DRIVE_LAYOUT_INFORMATION_EX) + sizeof(PARTITION_INFORMATION_EX) * 127];
	PDRIVE_LAYOUT_INFORMATION_EX dli = pv(buff);
	int result = -1;

	if (dsk_num == -1) {
		dsk_num = dc_efi_get_os_disk();
		if (dsk_num < 0) return -1;
	}

	_snwprintf(disk_path, countof(disk_path), L"\\\\.\\PhysicalDrive%d", dsk_num);

	hdisk = CreateFile(disk_path, GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hdisk == INVALID_HANDLE_VALUE) return -1;

	if (DeviceIoControl(hdisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
		NULL, 0, dli, sizeof(buff), &bytes, NULL)) {

		if (dli->PartitionStyle == PARTITION_STYLE_GPT) {
			for (DWORD i = 0; i < dli->PartitionCount; i++) {
				PPARTITION_INFORMATION_EX part = &dli->PartitionEntry[i];

				/* Check if this is an ESP */
				if (!IsEqualGUID(&part->Gpt.PartitionType, &GUID_EFI_SYSTEM_PARTITION))
					continue;

				/* Check GPT partition name first (most reliable - set when creating) */
				if (_wcsicmp(part->Gpt.Name, DCS_BOOT_PARTITION_NAME) == 0) {
#ifdef DEBUG_GPT_SUP
					wprintf(L"DEBUG: Found DCS ESP by GPT name: partition %d\n", part->PartitionNumber);
#endif
					result = part->PartitionNumber;
					break;
				}
			}
		}
	}

	CloseHandle(hdisk);
	return result;
}

/* Find free space on disk suitable for new partition using Windows API */
int dc_find_free_space(int dsk_num, u64 required_bytes, u64 *start_lba, u64 *avail_bytes)
{
	wchar_t disk_path[MAX_PATH];
	HANDLE hdisk;
	DWORD bytes;
	u8 buff[sizeof(DRIVE_LAYOUT_INFORMATION_EX) + sizeof(PARTITION_INFORMATION_EX) * 127];
	PDRIVE_LAYOUT_INFORMATION_EX dli = pv(buff);
	DISK_GEOMETRY_EX dg;
	int resl = ST_NO_FREE_SPACE;
	LONGLONG free_start = 0;
	LONGLONG best_size = 0;
	DWORD sector_size;

	*start_lba = 0;
	*avail_bytes = 0;

	if (dsk_num == -1) {
		dsk_num = dc_efi_get_os_disk();
		if (dsk_num < 0) return ST_NF_DEVICE;
	}

	_snwprintf(disk_path, countof(disk_path), L"\\\\.\\PhysicalDrive%d", dsk_num);
	hdisk = CreateFile(disk_path, GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hdisk == INVALID_HANDLE_VALUE) {
		return ST_ACCESS_DENIED;
	}

	do {
		if (!DeviceIoControl(hdisk, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
			NULL, 0, &dg, sizeof(dg), &bytes, NULL)) {
			resl = ST_ERROR; break;
		}
		sector_size = dg.Geometry.BytesPerSector;

		if (!DeviceIoControl(hdisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
			NULL, 0, dli, sizeof(buff), &bytes, NULL)) {
			resl = ST_ERROR; break;
		}

		if (dli->PartitionStyle != PARTITION_STYLE_GPT) {
			resl = ST_GPT_INVALID; break;
		}

		/* Find the end of all existing partitions */
		LONGLONG last_end = 34 * sector_size; /* After GPT header */
		for (DWORD i = 0; i < dli->PartitionCount; i++) {
			PPARTITION_INFORMATION_EX part = &dli->PartitionEntry[i];
			if (part->PartitionLength.QuadPart > 0) {
				LONGLONG part_end = part->StartingOffset.QuadPart + part->PartitionLength.QuadPart;
				if (part_end > last_end) {
					last_end = part_end;
				}
			}
		}

		/* Align to 1MB boundary */
		free_start = (last_end + 0xFFFFF) & ~0xFFFFFLL;

		/* End of usable space (leave room for backup GPT) */
		LONGLONG free_end = dg.DiskSize.QuadPart - (33 * sector_size);

		if (free_start + (LONGLONG)required_bytes <= free_end) {
			best_size = free_end - free_start;
			*start_lba = free_start / sector_size;
			*avail_bytes = best_size;
			resl = ST_OK;
		}

	} while (0);

	CloseHandle(hdisk);
	return resl;
}

/* Delete a partition using Windows API */
int dc_gpt_delete_partition(int dsk_num, int part_num)
{
	wchar_t disk_path[MAX_PATH];
	HANDLE hdisk;
	DWORD bytes;
	u8 buff[sizeof(DRIVE_LAYOUT_INFORMATION_EX) + sizeof(PARTITION_INFORMATION_EX) * 127];
	PDRIVE_LAYOUT_INFORMATION_EX dli = pv(buff);
	int resl;
	int part_idx = -1;

	if (dsk_num == -1) {
		dsk_num = dc_efi_get_os_disk();
		if (dsk_num < 0) return ST_NF_DEVICE;
	}

	_snwprintf(disk_path, countof(disk_path), L"\\\\.\\PhysicalDrive%d", dsk_num);
	hdisk = CreateFile(disk_path, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hdisk == INVALID_HANDLE_VALUE) {
		return ST_ACCESS_DENIED;
	}

	do {
		if (!DeviceIoControl(hdisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
			NULL, 0, dli, sizeof(buff), &bytes, NULL)) {
			resl = ST_ERROR; break;
		}

		if (dli->PartitionStyle != PARTITION_STYLE_GPT) {
			resl = ST_GPT_INVALID; break;
		}

		/* Find the partition to delete */
		for (DWORD i = 0; i < dli->PartitionCount; i++) {
			if (dli->PartitionEntry[i].PartitionNumber == part_num) {
				part_idx = i;
				break;
			}
		}

		if (part_idx < 0) {
			resl = ST_NF_DEVICE; break;
		}

		/* Clear the partition entry by zeroing it */
		memset(&dli->PartitionEntry[part_idx], 0, sizeof(PARTITION_INFORMATION_EX));
		dli->PartitionEntry[part_idx].RewritePartition = TRUE;

		/* Apply the new layout */
		if (!DeviceIoControl(hdisk, IOCTL_DISK_SET_DRIVE_LAYOUT_EX,
			dli, sizeof(buff), NULL, 0, &bytes, NULL)) {
			resl = ST_IO_ERROR; break;
		}

		/* Refresh partition table */
		DeviceIoControl(hdisk, IOCTL_DISK_UPDATE_PROPERTIES, NULL, 0, NULL, 0, &bytes, NULL);

		resl = ST_OK;

	} while (0);

	CloseHandle(hdisk);
	return resl;
}

/* Create DCS ESP partition - shrinks OS partition if needed */
int dc_create_dcs_esp(int dsk_num, u64 esp_size, wchar_t *esp_path, int *new_part_num)
{
	int resl;
	u64 free_start, free_avail;
	wchar_t disk_path[MAX_PATH];
	HANDLE hdisk;
	DWORD bytes;
	u8 buff[sizeof(DRIVE_LAYOUT_INFORMATION_EX) + sizeof(PARTITION_INFORMATION_EX) * 127];
	PDRIVE_LAYOUT_INFORMATION_EX dli = pv(buff);
	DISK_GEOMETRY_EX dg;
	int os_part_idx = -1;
	int os_part_num;
	GUID new_guid;
	LONGLONG os_part_end, next_part_start, gap_size;

	*new_part_num = -1;

	if (dsk_num == -1) {
		dsk_num = dc_efi_get_os_disk();
		if (dsk_num < 0) return ST_NF_DEVICE;
	}

	/* First check if there's already free space at end of disk */
	resl = dc_find_free_space(dsk_num, esp_size, &free_start, &free_avail);

	if (resl == ST_OK) {
		/* Free space exists at end - create partition there */
		resl = dc_gpt_create_partition(dsk_num, &GUID_EFI_SYSTEM_PARTITION,
			esp_size, 0, DCS_BOOT_PARTITION_NAME, new_part_num);
		if (resl != ST_OK) return resl;
		goto format_partition;
	}

	/* No free space at end - need to shrink OS partition */
	os_part_num = dc_get_os_partition(dsk_num);
	if (os_part_num < 0) return ST_NF_DEVICE;

	/* Open disk */
	_snwprintf(disk_path, countof(disk_path), L"\\\\.\\PhysicalDrive%d", dsk_num);
	hdisk = CreateFile(disk_path, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hdisk == INVALID_HANDLE_VALUE) {
		return ST_ACCESS_DENIED;
	}

	do {
		if (!DeviceIoControl(hdisk, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
			NULL, 0, &dg, sizeof(dg), &bytes, NULL)) {
			resl = ST_ERROR; break;
		}

		if (!DeviceIoControl(hdisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
			NULL, 0, dli, sizeof(buff), &bytes, NULL)) {
			resl = ST_ERROR; break;
		}

		if (dli->PartitionStyle != PARTITION_STYLE_GPT) {
			resl = ST_GPT_INVALID; break;
		}

		/* Find OS partition and calculate its end */
		for (DWORD i = 0; i < dli->PartitionCount; i++) {
			if (dli->PartitionEntry[i].PartitionNumber == os_part_num) {
				os_part_idx = i;
				break;
			}
		}

		if (os_part_idx < 0) {
			resl = ST_NF_DEVICE; break;
		}

		os_part_end = dli->PartitionEntry[os_part_idx].StartingOffset.QuadPart +
			dli->PartitionEntry[os_part_idx].PartitionLength.QuadPart;

		/* Find the NEXT partition after OS partition (by offset) */
		/* Default to end of usable disk space (before backup GPT - 33 sectors) */
		DWORD sector_size = dg.Geometry.BytesPerSector;
		next_part_start = dg.DiskSize.QuadPart - (33 * sector_size);
		for (DWORD i = 0; i < dli->PartitionCount; i++) {
			if (i == (DWORD)os_part_idx) continue;
			LONGLONG start = dli->PartitionEntry[i].StartingOffset.QuadPart;
			if (start >= os_part_end && start < next_part_start) {
				next_part_start = start;
			}
		}

		/* Calculate current gap between OS partition and next partition */
		gap_size = next_part_start - os_part_end;

		/* If gap is already big enough, just create partition there */
		if (gap_size >= (LONGLONG)esp_size) {
			/* Align start to 1MB */
			LONGLONG new_start = (os_part_end + 0xFFFFF) & ~0xFFFFFLL;
			if (new_start + (LONGLONG)esp_size <= next_part_start) {
#ifdef DEBUG_GPT_SUP
				wprintf(L"DEBUG: Found existing gap of %lld MB after OS partition\n", gap_size / (1024*1024));
				wprintf(L"DEBUG: Creating partition in gap at offset %lld\n", new_start);
#endif
				CloseHandle(hdisk);
				/* Create partition in existing gap at specific offset */
				resl = dc_gpt_create_partition(dsk_num, &GUID_EFI_SYSTEM_PARTITION,
					esp_size, (u64)new_start, DCS_BOOT_PARTITION_NAME, new_part_num);
				if (resl != ST_OK) return resl;
				goto format_partition;
			}
		}

		/* Need to shrink OS partition to create space */
		/* Calculate how much we need to shrink:
		* - esp_size for the new partition
		* - minus any existing gap
		* - plus 2MB for alignment overhead (we align DOWN twice)
		*/
		LONGLONG need_space = (LONGLONG)esp_size - gap_size + (2 * 1024 * 1024);
		if (need_space < (LONGLONG)esp_size) need_space = esp_size + (2 * 1024 * 1024);

		CloseHandle(hdisk);
		hdisk = INVALID_HANDLE_VALUE;

		/* Shrink the filesystem */
#ifdef DEBUG_GPT_SUP
		wprintf(L"DEBUG: Shrinking filesystem by %lld MB...\n", need_space / (1024*1024));
#endif

		resl = dc_gpt_shrink_partition(dsk_num, os_part_num, need_space);
		if (resl != ST_OK) return resl;

#ifdef DEBUG_GPT_SUP
		wprintf(L"DEBUG: Filesystem shrunk successfully\n");
#endif

		/* Re-open disk and get updated layout */
		hdisk = CreateFile(disk_path, GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (hdisk == INVALID_HANDLE_VALUE) {
			resl = ST_ACCESS_DENIED; break;
		}

		if (!DeviceIoControl(hdisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
			NULL, 0, dli, sizeof(buff), &bytes, NULL)) {
			resl = ST_ERROR; break;
		}

		/* Re-find OS partition */
		os_part_idx = -1;
		for (DWORD i = 0; i < dli->PartitionCount; i++) {
			if (dli->PartitionEntry[i].PartitionNumber == os_part_num) {
				os_part_idx = i;
				break;
			}
		}
		if (os_part_idx < 0) {
			resl = ST_NF_DEVICE; break;
		}

		/* Debug: show all partitions */
#ifdef DEBUG_GPT_SUP
		wprintf(L"\nDEBUG: Current partition layout (after FS shrink):\n");
		for (DWORD i = 0; i < dli->PartitionCount; i++) {
			PPARTITION_INFORMATION_EX p = &dli->PartitionEntry[i];
			if (p->PartitionLength.QuadPart == 0) continue;
			LONGLONG start = p->StartingOffset.QuadPart;
			LONGLONG end = start + p->PartitionLength.QuadPart;
			wprintf(L"  Part %d: start=%lld end=%lld size=%lld MB%s\n",
				p->PartitionNumber, start, end,
				p->PartitionLength.QuadPart / (1024*1024),
				(i == (DWORD)os_part_idx) ? L" (OS)" : L"");
		}
		wprintf(L"  Disk size: %lld, usable end: %lld\n\n",
			dg.DiskSize.QuadPart, dg.DiskSize.QuadPart - (33 * sector_size));
#endif

		/* Calculate new partition positions working BACKWARDS from next partition */
		/* This ensures we never overlap with other partitions */

		LONGLONG os_part_start = dli->PartitionEntry[os_part_idx].StartingOffset.QuadPart;
		LONGLONG old_os_length = dli->PartitionEntry[os_part_idx].PartitionLength.QuadPart;

		/* ESP must end at or before next_part_start (or backup GPT area) */
		/* Align next_part_start DOWN to 1MB boundary for ESP end */
		LONGLONG esp_end = next_part_start & ~0xFFFFFLL;

		/* ESP starts esp_size before its end, aligned DOWN to 1MB */
		LONGLONG new_esp_start = (esp_end - (LONGLONG)esp_size) & ~0xFFFFFLL;

		/* OS partition ends where ESP starts */
		LONGLONG new_os_end = new_esp_start;
		LONGLONG new_os_length = new_os_end - os_part_start;

#ifdef DEBUG_GPT_SUP
		/* Debug output */
		wprintf(L"DEBUG: os_part_start     = %lld (0x%llX)\n", os_part_start, os_part_start);
		wprintf(L"DEBUG: old_os_length     = %lld (0x%llX)\n", old_os_length, old_os_length);
		wprintf(L"DEBUG: old_os_end        = %lld (0x%llX)\n", os_part_start + old_os_length, os_part_start + old_os_length);
		wprintf(L"DEBUG: next_part_start   = %lld (0x%llX)\n", next_part_start, next_part_start);
		wprintf(L"DEBUG: esp_end           = %lld (0x%llX)\n", esp_end, esp_end);
		wprintf(L"DEBUG: new_esp_start     = %lld (0x%llX)\n", new_esp_start, new_esp_start);
		wprintf(L"DEBUG: esp_size          = %llu (0x%llX)\n", esp_size, esp_size);
		wprintf(L"DEBUG: new_os_length     = %lld (0x%llX)\n", new_os_length, new_os_length);
		wprintf(L"DEBUG: new_os_end        = %lld (0x%llX)\n", new_os_end, new_os_end);
		wprintf(L"DEBUG: shrink amount     = %lld MB\n", (old_os_length - new_os_length) / (1024*1024));
		wprintf(L"DEBUG: need_space was    = %lld MB\n", need_space / (1024*1024));
#endif

		/* Verify we didn't shrink OS partition too much */
		if (new_os_length <= 0) {
#ifdef DEBUG_GPT_SUP
			wprintf(L"ERROR: new_os_length <= 0\n");
#endif
			resl = ST_PART_TOO_SMALL; break;
		}

		/* Verify new partition can hold the shrunk filesystem */
		/* The filesystem was shrunk by need_space, so it now occupies approx (old_os_length - need_space) */
		LONGLONG shrunk_fs_size = old_os_length - need_space;
		if (new_os_length < shrunk_fs_size) {
#ifdef DEBUG_GPT_SUP
			wprintf(L"ERROR: new_os_length (%lld) < shrunk_fs_size (%lld)\n", new_os_length, shrunk_fs_size);
			wprintf(L"       The partition would be smaller than the filesystem!\n");
#endif
			resl = ST_PART_TOO_SMALL; break;
		}

		/* Double-check: ESP must not overlap with next partition */
		if (new_esp_start + (LONGLONG)esp_size > next_part_start) {
#ifdef DEBUG_GPT_SUP
			wprintf(L"ERROR: ESP would overlap next partition\n");
#endif
			resl = ST_NO_FREE_SPACE; break;
		}

		/* Validate against ALL partitions to ensure no overlap */
		int overlap_found = 0;
		for (DWORD i = 0; i < dli->PartitionCount; i++) {
			if (i == (DWORD)os_part_idx) continue;
			PPARTITION_INFORMATION_EX p = &dli->PartitionEntry[i];
			if (p->PartitionLength.QuadPart == 0) continue;

			LONGLONG p_start = p->StartingOffset.QuadPart;
			LONGLONG p_end = p_start + p->PartitionLength.QuadPart;

			/* Check if new ESP overlaps with this partition */
			LONGLONG esp_end_actual = new_esp_start + (LONGLONG)esp_size;
			if (new_esp_start < p_end && esp_end_actual > p_start) {
#ifdef DEBUG_GPT_SUP
				wprintf(L"ERROR: ESP [%lld-%lld] overlaps partition %d [%lld-%lld]\n",
					new_esp_start, esp_end_actual, p->PartitionNumber, p_start, p_end);
#endif
				overlap_found = 1;
				break;
			}

#ifdef DEBUG_GPT_SUP
			/* Check if new OS partition overlaps with this partition */
			if (os_part_start < p_end && new_os_end > p_start) {
				/* This is only an error if this isn't the OS partition itself */
				wprintf(L"WARNING: OS [%lld-%lld] overlaps partition %d [%lld-%lld]\n",
					os_part_start, new_os_end, p->PartitionNumber, p_start, p_end);
			}
#endif
		}
		if (overlap_found) {
			resl = ST_NO_FREE_SPACE; break;
		}

		/* STEP A: Shrink OS partition using IOCTL_DISK_GROW_PARTITION */
		/* This is safer than IOCTL_DISK_SET_DRIVE_LAYOUT_EX for shrinking */
		LONGLONG shrink_amount = old_os_length - new_os_length;

#ifdef DEBUG_GPT_SUP
		wprintf(L"DEBUG: Shrinking OS partition by %lld bytes (%lld MB)\n",
			shrink_amount, shrink_amount / (1024*1024));
#endif

		DISK_GROW_PARTITION growPart;
		growPart.PartitionNumber = os_part_num;
		growPart.BytesToGrow.QuadPart = -shrink_amount;  /* Negative = shrink */

		if (!DeviceIoControl(hdisk, IOCTL_DISK_GROW_PARTITION,
			&growPart, sizeof(growPart), NULL, 0, &bytes, NULL)) {
#ifdef DEBUG_GPT_SUP
			wprintf(L"ERROR: IOCTL_DISK_GROW_PARTITION failed, error %d\n", GetLastError());
#endif
			resl = ST_IO_ERROR; break;
		}

#ifdef DEBUG_GPT_SUP
		wprintf(L"DEBUG: OS partition shrunk successfully\n");
#endif
		DeviceIoControl(hdisk, IOCTL_DISK_UPDATE_PROPERTIES, NULL, 0, NULL, 0, &bytes, NULL);

		/* Re-read partition table to get updated layout */
		if (!DeviceIoControl(hdisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
			NULL, 0, dli, sizeof(buff), &bytes, NULL)) {
			resl = ST_ERROR; break;
		}

		/* Re-find OS partition index (may have changed) */
		os_part_idx = -1;
		for (DWORD i = 0; i < dli->PartitionCount; i++) {
			if (dli->PartitionEntry[i].PartitionNumber == os_part_num) {
				os_part_idx = i;
				break;
			}
		}
		if (os_part_idx < 0) {
			resl = ST_NF_DEVICE; break;
		}

		/* Verify shrink worked */
		LONGLONG actual_os_length = dli->PartitionEntry[os_part_idx].PartitionLength.QuadPart;
#ifdef DEBUG_GPT_SUP
		wprintf(L"DEBUG: OS partition now: %lld bytes (%lld MB)\n",
			actual_os_length, actual_os_length / (1024*1024));
#endif

		/* Recalculate new_esp_start based on actual shrunk partition */
		LONGLONG actual_os_end = dli->PartitionEntry[os_part_idx].StartingOffset.QuadPart + actual_os_length;
		new_esp_start = (actual_os_end + 0xFFFFF) & ~0xFFFFFLL;  /* Align to 1MB */
#ifdef DEBUG_GPT_SUP
		wprintf(L"DEBUG: ESP will start at: %lld\n", new_esp_start);
#endif

		/* Generate GUID for new partition */
		if (CoCreateGuid(&new_guid) != S_OK) {
			LARGE_INTEGER ticks;
			QueryPerformanceCounter(&ticks);
			memset(&new_guid, 0, sizeof(new_guid));
			new_guid.Data1 = (ULONG)ticks.LowPart;
			new_guid.Data2 = (USHORT)(ticks.HighPart & 0xFFFF);
			new_guid.Data3 = (USHORT)((ticks.HighPart >> 16) & 0xFFFF);
		}

		/* Set RewritePartition = FALSE for all existing partitions */
		for (DWORD i = 0; i < dli->PartitionCount; i++) {
			dli->PartitionEntry[i].RewritePartition = FALSE;
		}

		/* STEP B: Now add the new partition */
#ifdef DEBUG_GPT_SUP
		wprintf(L"DEBUG: STEP B - Adding new partition\n");
#endif

		/* Find the correct position to insert (sorted by offset) */
		DWORD insert_idx = dli->PartitionCount;
		for (DWORD i = 0; i < dli->PartitionCount; i++) {
			if (dli->PartitionEntry[i].StartingOffset.QuadPart > new_esp_start) {
				insert_idx = i;
				break;
			}
		}

#ifdef DEBUG_GPT_SUP
		wprintf(L"DEBUG: Inserting new partition at index %d (sorted by offset)\n", insert_idx);
#endif

		/* Shift entries after insert_idx to make room */
		if (insert_idx < dli->PartitionCount) {
			memmove(&dli->PartitionEntry[insert_idx + 1],
				&dli->PartitionEntry[insert_idx],
				(dli->PartitionCount - insert_idx) * sizeof(PARTITION_INFORMATION_EX));
		}

		/* Insert new partition entry at correct position */
		PPARTITION_INFORMATION_EX new_part = &dli->PartitionEntry[insert_idx];
		memset(new_part, 0, sizeof(PARTITION_INFORMATION_EX));
		new_part->PartitionStyle = PARTITION_STYLE_GPT;
		new_part->StartingOffset.QuadPart = new_esp_start;
		new_part->PartitionLength.QuadPart = esp_size;
		new_part->PartitionNumber = 0;
		new_part->RewritePartition = TRUE;
		memcpy(&new_part->Gpt.PartitionType, &GUID_EFI_SYSTEM_PARTITION, sizeof(GUID));
		memcpy(&new_part->Gpt.PartitionId, &new_guid, sizeof(GUID));
		new_part->Gpt.Attributes = 0;
		wcsncpy_s(new_part->Gpt.Name, 36, DCS_BOOT_PARTITION_NAME, 35);

		dli->PartitionCount++;

		/* Final validation: ESP must be in the gap between shrunk OS and next partition */
		LONGLONG esp_actual_end = new_esp_start + (LONGLONG)esp_size;

#ifdef DEBUG_GPT_SUP
		wprintf(L"DEBUG: Validation:\n");
		wprintf(L"  Shrunk OS end: %lld\n", actual_os_end);
		wprintf(L"  New ESP:   %lld to %lld\n", new_esp_start, esp_actual_end);
		wprintf(L"  Next part: %lld\n", next_part_start);
#endif

		if (new_esp_start < actual_os_end) {
#ifdef DEBUG_GPT_SUP
			wprintf(L"ERROR: ESP start (%lld) < shrunk OS end (%lld)!\n",
				new_esp_start, actual_os_end);
#endif
			resl = ST_NO_FREE_SPACE; break;
		}
		if (esp_actual_end > next_part_start) {
#ifdef DEBUG_GPT_SUP
			wprintf(L"ERROR: ESP end (%lld) > next partition start (%lld)!\n",
				esp_actual_end, next_part_start);
#endif
			resl = ST_NO_FREE_SPACE; break;
		}

#ifdef DEBUG_GPT_SUP
		wprintf(L"DEBUG: Adding ESP at offset %lld, size %llu\n", new_esp_start, esp_size);
		wprintf(L"DEBUG: New partition table will have %d entries\n", dli->PartitionCount);
#endif

		/* Show final layout before writing */
#ifdef DEBUG_GPT_SUP
		wprintf(L"DEBUG: Final partition layout to write:\n");
		for (DWORD i = 0; i < dli->PartitionCount; i++) {
			PPARTITION_INFORMATION_EX p = &dli->PartitionEntry[i];
			if (p->PartitionLength.QuadPart == 0 && !p->RewritePartition) continue;
			wprintf(L"  [%d] start=%lld end=%lld rewrite=%d%s\n",
				i,
				p->StartingOffset.QuadPart,
				p->StartingOffset.QuadPart + p->PartitionLength.QuadPart,
				p->RewritePartition,
				(i == (DWORD)os_part_idx) ? L" (OS-shrunk)" :
				(i == insert_idx) ? L" (NEW-ESP)" : L"");
		}
#endif

		/* Apply all changes in one operation */
		if (!DeviceIoControl(hdisk, IOCTL_DISK_SET_DRIVE_LAYOUT_EX,
			dli, sizeof(buff), NULL, 0, &bytes, NULL)) {
#ifdef DEBUG_GPT_SUP
			wprintf(L"ERROR: IOCTL_DISK_SET_DRIVE_LAYOUT_EX failed, error %d\n", GetLastError());
#endif
			resl = ST_IO_ERROR; break;
		}

#ifdef DEBUG_GPT_SUP
		wprintf(L"DEBUG: Partition table updated successfully\n");
#endif

		DeviceIoControl(hdisk, IOCTL_DISK_UPDATE_PROPERTIES, NULL, 0, NULL, 0, &bytes, NULL);

		/* Find new partition number and verify what Windows actually wrote */
		Sleep(1000);
		if (DeviceIoControl(hdisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
			NULL, 0, dli, sizeof(buff), &bytes, NULL)) {

#ifdef DEBUG_GPT_SUP
			wprintf(L"DEBUG: Partition table AFTER write (what Windows stored):\n");
#endif
			for (DWORD i = 0; i < dli->PartitionCount; i++) {
				PPARTITION_INFORMATION_EX p = &dli->PartitionEntry[i];
				if (p->PartitionLength.QuadPart == 0) continue;
#ifdef DEBUG_GPT_SUP
				wprintf(L"  Part %d: start=%lld end=%lld size=%lld MB\n",
					p->PartitionNumber,
					p->StartingOffset.QuadPart,
					p->StartingOffset.QuadPart + p->PartitionLength.QuadPart,
					p->PartitionLength.QuadPart / (1024*1024));
#endif

				if (p->StartingOffset.QuadPart == new_esp_start) {
					*new_part_num = p->PartitionNumber;
#ifdef DEBUG_GPT_SUP
					wprintf(L"DEBUG: ^ This is our new ESP (partition %d)\n", *new_part_num);
#endif
				}
			}
		}

		if (*new_part_num <= 0) {
#ifdef DEBUG_GPT_SUP
			wprintf(L"WARNING: Could not find new partition at offset %lld\n", new_esp_start);
#endif
			*new_part_num = insert_idx + 1;
		}

		resl = ST_OK;

	} while (0);

	if (hdisk != INVALID_HANDLE_VALUE) CloseHandle(hdisk);

	if (resl != ST_OK) return resl;

format_partition:
#ifdef DEBUG_GPT_SUP
	wprintf(L"DEBUG: Refreshing disk %d...\n", dsk_num);
#endif

	/* Refresh Windows partition cache */
	resl = dc_refresh_disk(dsk_num);
	if (resl != ST_OK) {
#ifdef DEBUG_GPT_SUP
		wprintf(L"DEBUG: dc_refresh_disk failed with %d\n", resl);
#endif
		return resl;
	}

#ifdef DEBUG_GPT_SUP
	wprintf(L"DEBUG: Waiting for partition to be recognized...\n");
#endif

	/* Format as FAT32 with DCS_BOOT label */
#ifdef DEBUG_GPT_SUP
	wprintf(L"DEBUG: Formatting partition %d as FAT32...\n", *new_part_num);
#endif
	resl = dc_gpt_format_partition(dsk_num, *new_part_num, DCS_ESP_LABEL);
	if (resl != ST_OK) {
#ifdef DEBUG_GPT_SUP
		wprintf(L"DEBUG: dc_gpt_format_partition failed with %d\n", resl);
#endif
		return resl;
	}
#ifdef DEBUG_GPT_SUP
	wprintf(L"DEBUG: Format successful\n");
#endif

	/* Wait for Windows to fully recognize the new formatted volume */
#ifdef DEBUG_GPT_SUP
	wprintf(L"DEBUG: Waiting for volume to be mounted...\n");
#endif

	wchar_t vol_guid_path[MAX_PATH] = {0};
	wchar_t test_path[MAX_PATH];
	DWORD attrs;
	int accessible = 0;

	/* Retry loop - wait for Windows to mount the volume */
	for (int retry = 0; retry < 10; retry++) {
		Sleep(1000);

		/* Try to find the Volume GUID path (returned without trailing backslash) */
		if (dc_efi_get_volume_guid_path(dsk_num, *new_part_num, vol_guid_path, MAX_PATH) == ST_OK) {
			/* Test if we can access the volume */
			swprintf_s(test_path, MAX_PATH, L"%s\\", vol_guid_path);
			attrs = GetFileAttributes(test_path);
			if (attrs != INVALID_FILE_ATTRIBUTES) {
				accessible = 1;
#ifdef DEBUG_GPT_SUP
				wprintf(L"DEBUG: Volume accessible after %d seconds\n", retry + 1);
#endif
				break;
			}
		}

#ifdef DEBUG_GPT_SUP
		wprintf(L"DEBUG: Waiting... (%d/10)\n", retry + 1);
#endif
	}

	if (accessible) {
		wcscpy_s(esp_path, MAX_PATH, vol_guid_path);
#ifdef DEBUG_GPT_SUP
		wprintf(L"DEBUG: Using volume GUID path: %s\n", esp_path);
#endif
	} else {
		/* Fall back to GLOBALROOT path */
		swprintf_s(esp_path, MAX_PATH,
			L"\\\\?\\GLOBALROOT\\Device\\Harddisk%d\\Partition%d",
			dsk_num, *new_part_num);
#ifdef DEBUG_GPT_SUP
		wprintf(L"WARNING: Volume not accessible, using GLOBALROOT path: %s\n", esp_path);
#endif
	}

	return ST_OK;
}

/* Get or create DCS ESP - finds existing or creates new one */
int dc_get_or_create_dcs_esp(int *dsk_num, wchar_t *esp_path, int *esp_part)
{
	int existing_part;
	int resl;

	if (*dsk_num == -1) {
		*dsk_num = dc_efi_get_os_disk();
		if (*dsk_num < 0) return ST_NF_DEVICE;
	}

	/* First check for existing DCS ESP */
	existing_part = dc_find_dcs_esp(*dsk_num);

	if (existing_part > 0) {
		/* Use existing */
		*esp_part = existing_part;
		swprintf_s(esp_path, MAX_PATH,
			L"\\\\?\\GLOBALROOT\\Device\\Harddisk%d\\Partition%d",
			*dsk_num, existing_part);
		return ST_OK;
	}

	/* Create new DCS ESP (64MB) */
	resl = dc_create_dcs_esp(*dsk_num, 64 * 1024 * 1024, esp_path, esp_part);

	return resl;
}
