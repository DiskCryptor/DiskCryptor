#ifndef _GPT_SUP_H_
#define _GPT_SUP_H_

#include "dcapi.h"
#include "misc.h"

#pragma pack(push, 1)

/* GPT Header structure (92 bytes, padded to sector size) */
typedef struct _GPT_HEADER {
	char     Signature[8];          /* "EFI PART" (0x5452415020494645) */
	u32      Revision;              /* Usually 0x00010000 */
	u32      HeaderSize;            /* Usually 92 */
	u32      HeaderCRC32;           /* CRC32 of header (with this field zeroed) */
	u32      Reserved;              /* Must be zero */
	u64      MyLBA;                 /* LBA of this header (1 for primary) */
	u64      AlternateLBA;          /* LBA of backup header */
	u64      FirstUsableLBA;        /* First usable LBA for partitions */
	u64      LastUsableLBA;         /* Last usable LBA for partitions */
	GUID     DiskGUID;              /* Unique disk identifier */
	u64      PartitionEntryLBA;     /* LBA of partition entry array (usually 2) */
	u32      NumberOfPartitionEntries; /* Number of entries (usually 128) */
	u32      SizeOfPartitionEntry;  /* Size of each entry (usually 128) */
	u32      PartitionArrayCRC32;   /* CRC32 of partition entry array */
} GPT_HEADER;

/* GPT Partition Entry (128 bytes) */
typedef struct _GPT_PARTITION_ENTRY {
	GUID     PartitionTypeGUID;     /* Partition type */
	GUID     UniquePartitionGUID;   /* Unique identifier for this partition */
	u64      StartingLBA;           /* First LBA of partition */
	u64      EndingLBA;             /* Last LBA (inclusive) */
	u64      Attributes;            /* Partition attributes */
	wchar_t  PartitionName[36];     /* Null-terminated UTF-16LE name */
} GPT_PARTITION_ENTRY;

#pragma pack(pop)

/* Well-known partition type GUIDs */
extern dc_api const GUID GUID_EFI_SYSTEM_PARTITION;
extern dc_api const GUID GUID_BASIC_DATA_PARTITION;
extern dc_api const GUID GUID_MICROSOFT_RESERVED;

/* GPT read/write functions */
int dc_api dc_gpt_read(dc_disk_p *dp, GPT_HEADER *hdr, GPT_PARTITION_ENTRY **entries, u32 *entry_count);
int dc_api dc_gpt_write(dc_disk_p *dp, GPT_HEADER *hdr, GPT_PARTITION_ENTRY *entries);
void dc_api dc_gpt_free_entries(GPT_PARTITION_ENTRY *entries);

/* OS partition detection (dc_efi_get_os_disk is in efiinst.h) */
int dc_api dc_get_os_partition(int dsk_num);

/* Partition shrinking (shrinks NTFS filesystem then updates GPT) */
int dc_api dc_gpt_shrink_partition(int dsk_num, int part_num, u64 shrink_bytes);

/* Create new partition in free space */
int dc_api dc_gpt_create_partition(
	int dsk_num,
	const GUID *type_guid,
	u64 size_bytes,
	u64 start_offset,  /* 0 = auto-find at end of disk */
	const wchar_t *name,
	int *new_part_num);

/* Format partition as FAT32 with optional label */
int dc_api dc_gpt_format_partition(int dsk_num, int part_num, const wchar_t *label);

/* Delete a partition from GPT */
int dc_api dc_gpt_delete_partition(int dsk_num, int part_num);

/* Refresh Windows partition cache after GPT modification */
int dc_api dc_refresh_disk(int dsk_num);

/* DCS ESP volume label */
#define DCS_ESP_LABEL L"DCS_BOOT"
#define DCS_BOOT_PARTITION_NAME L"DCS Boot Partition"

/* Find existing DCS ESP partition by checking for GPT name, volume label, or \EFI\DCS folder
 * Returns partition number or -1 if not found */
int dc_api dc_find_dcs_esp(int dsk_num);

/* Find free space on disk suitable for new partition
 * Prefers: 1) end of disk, 2) gap between partitions before OS partition
 * Returns ST_OK if found, sets start_lba and available size */
int dc_api dc_find_free_space(int dsk_num, u64 required_bytes, u64 *start_lba, u64 *avail_bytes);

/* Create DCS ESP partition - tries free space first, falls back to shrinking OS
 * Sets label to DCS_BOOT, formats as FAT32
 * Returns path to new ESP in esp_path */
int dc_api dc_create_dcs_esp(int dsk_num, u64 esp_size, wchar_t *esp_path, int *new_part_num);

/* Get or create DCS ESP - finds existing or creates new one
 * Returns partition number and path */
int dc_api dc_get_or_create_dcs_esp(int *dsk_num, wchar_t *esp_path, int *esp_part);

#endif /* _GPT_SUP_H_ */
