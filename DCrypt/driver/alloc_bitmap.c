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

#include <ntifs.h>
#include "defines.h"
#include "devhook.h"
#include "alloc_bitmap.h"
#include "device_io.h"
#include "misc.h"
#include "misc_mem.h"
#include "debug.h"

/* Maximum bitmap size: 512MB */
#define MAX_BITMAP_BYTES (512 * 1024 * 1024)

/* Chunk size for reading disk bitmap: 64KB */
#define BITMAP_READ_CHUNK (64 * 1024)

/* NTFS FSCTL codes */
#ifndef FSCTL_GET_NTFS_VOLUME_DATA
#define FSCTL_GET_NTFS_VOLUME_DATA CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 25, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#ifndef FSCTL_GET_VOLUME_BITMAP
#define FSCTL_GET_VOLUME_BITMAP CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 27, METHOD_NEITHER, FILE_ANY_ACCESS)
#endif

/* ReFS FSCTL code */
#ifndef FSCTL_GET_REFS_VOLUME_DATA
#define FSCTL_GET_REFS_VOLUME_DATA CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 182, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

/* Filesystem type enumeration */
typedef enum _DC_FS_TYPE {
    DC_FS_UNKNOWN = 0,
    DC_FS_NTFS,
    DC_FS_REFS,
    DC_FS_FAT16,
    DC_FS_FAT32,
    DC_FS_EXFAT
} DC_FS_TYPE;

/* Buffer for FileFsAttributeInformation query */
typedef struct _DC_FS_ATTRIBUTE_INFO {
    ULONG FileSystemAttributes;
    LONG  MaximumComponentNameLength;
    ULONG FileSystemNameLength;
    WCHAR FileSystemName[16];  /* Enough for "NTFS", "ReFS", etc. */
} DC_FS_ATTRIBUTE_INFO;

/* NTFS volume data structure */
typedef struct _DC_NTFS_VOLUME_DATA {
    LARGE_INTEGER VolumeSerialNumber;
    LARGE_INTEGER NumberSectors;
    LARGE_INTEGER TotalClusters;
    LARGE_INTEGER FreeClusters;
    LARGE_INTEGER TotalReserved;
    ULONG         BytesPerSector;
    ULONG         BytesPerCluster;
    ULONG         BytesPerFileRecordSegment;
    ULONG         ClustersPerFileRecordSegment;
    LARGE_INTEGER MftValidDataLength;
    LARGE_INTEGER MftStartLcn;
    LARGE_INTEGER Mft2StartLcn;
    LARGE_INTEGER MftZoneStart;
    LARGE_INTEGER MftZoneEnd;
} DC_NTFS_VOLUME_DATA;

/* ReFS volume data structure */
typedef struct _DC_REFS_VOLUME_DATA {
    ULONG         ByteCount;
    ULONG         MajorVersion;
    ULONG         MinorVersion;
    ULONG         BytesPerPhysicalSector;
    LARGE_INTEGER VolumeSerialNumber;
    LARGE_INTEGER NumberSectors;
    LARGE_INTEGER TotalClusters;
    LARGE_INTEGER FreeClusters;
    LARGE_INTEGER TotalReserved;
    ULONG         BytesPerSector;
    ULONG         BytesPerCluster;
    LARGE_INTEGER MaximumSizeOfResidentFile;
    USHORT        FastTierDataFillRatio;
    USHORT        SlowTierDataFillRatio;
    ULONG         DestagesFastTierToSlowTierRate;
    LARGE_INTEGER Reserved[9];
} DC_REFS_VOLUME_DATA;

#pragma pack(push, 1)

/* FAT16 Boot Parameter Block */
typedef struct _DC_FAT16_BOOT_SECTOR {
    u8  jmp_boot[3];
    u8  oem_name[8];
    u16 bytes_per_sector;      /* offset 11 */
    u8  sectors_per_cluster;   /* offset 13 */
    u16 reserved_sectors;      /* offset 14 */
    u8  num_fats;              /* offset 16 */
    u16 root_entries;          /* offset 17 */
    u16 total_sectors_16;      /* offset 19 */
    u8  media_type;            /* offset 21 */
    u16 fat_size_16;           /* offset 22 */
    u16 sectors_per_track;     /* offset 24 */
    u16 num_heads;             /* offset 26 */
    u32 hidden_sectors;        /* offset 28 */
    u32 total_sectors_32;      /* offset 32 */
    /* Extended BPB fields at offset 36 */
    u8  drive_number;
    u8  reserved1;
    u8  boot_signature;
    u32 volume_id;
    u8  volume_label[11];
    u8  fs_type[8];            /* "FAT16   " at offset 54 */
} DC_FAT16_BOOT_SECTOR;

/* FAT32 Boot Parameter Block */
typedef struct _DC_FAT32_BOOT_SECTOR {
    u8  jmp_boot[3];
    u8  oem_name[8];
    u16 bytes_per_sector;
    u8  sectors_per_cluster;
    u16 reserved_sectors;
    u8  num_fats;
    u16 root_entries;          /* Always 0 for FAT32 */
    u16 total_sectors_16;      /* Always 0 for FAT32 */
    u8  media_type;
    u16 fat_size_16;           /* Always 0 for FAT32 */
    u16 sectors_per_track;
    u16 num_heads;
    u32 hidden_sectors;
    u32 total_sectors_32;
    u32 fat_size_32;           /* FAT size for FAT32 */
    u16 ext_flags;
    u16 fs_version;
    u32 root_cluster;
    u16 fs_info;
    u16 backup_boot_sector;
    u8  reserved[12];
    u8  drive_number;
    u8  reserved1;
    u8  boot_signature;
    u32 volume_id;
    u8  volume_label[11];
    u8  fs_type[8];            /* "FAT32   " at offset 82 */
} DC_FAT32_BOOT_SECTOR;

/* exFAT Boot Parameter Block */
typedef struct _DC_EXFAT_BOOT_SECTOR {
    u8  jmp_boot[3];
    u8  oem_name[8];           /* "EXFAT   " */
    u8  zeros[53];             /* Must be zero */
    u64 partition_offset;
    u64 volume_length;         /* Total sectors */
    u32 fat_offset;            /* FAT offset in sectors */
    u32 fat_length;            /* FAT size in sectors */
    u32 cluster_heap_offset;   /* Data area offset in sectors */
    u32 cluster_count;         /* Total clusters */
    u32 first_cluster_of_root; /* Root directory cluster */
    u32 volume_serial;
    u16 fs_revision;
    u16 volume_flags;
    u8  bytes_per_sector_shift;   /* log2(bytes_per_sector) */
    u8  sectors_per_cluster_shift;/* log2(sectors_per_cluster) */
    u8  num_fats;
    u8  drive_select;
    u8  percent_in_use;
    u8  reserved[7];
    u8  boot_code[390];
    u16 boot_signature;        /* 0xAA55 */
} DC_EXFAT_BOOT_SECTOR;

/* exFAT Directory Entry (generic header) */
typedef struct _DC_EXFAT_DIR_ENTRY {
    u8  entry_type;
    u8  data[31];
} DC_EXFAT_DIR_ENTRY;

/* exFAT Allocation Bitmap Entry (entry_type = 0x81) */
typedef struct _DC_EXFAT_BITMAP_ENTRY {
    u8  entry_type;            /* 0x81 */
    u8  bitmap_flags;          /* Bit 0: second bitmap */
    u8  reserved[18];
    u32 first_cluster;         /* Cluster where bitmap starts */
    u64 data_length;           /* Bitmap size in bytes */
} DC_EXFAT_BITMAP_ENTRY;

#pragma pack(pop)

/* Starting LCN input buffer for FSCTL_GET_VOLUME_BITMAP */
typedef struct _DC_STARTING_LCN_INPUT {
    LARGE_INTEGER StartingLcn;
} DC_STARTING_LCN_INPUT;

/* Volume bitmap buffer for FSCTL_GET_VOLUME_BITMAP */
typedef struct _DC_VOLUME_BITMAP_BUFFER {
    LARGE_INTEGER StartingLcn;
    LARGE_INTEGER BitmapSize;
    UCHAR         Buffer[1];
} DC_VOLUME_BITMAP_BUFFER;

/* Header size = StartingLcn + BitmapSize = 16 bytes (don't use sizeof due to padding) */
#define VOLUME_BITMAP_HEADER_SIZE (sizeof(LARGE_INTEGER) + sizeof(LARGE_INTEGER))

/* Forward declaration for dc_bitmap_mark_cluster (used by FAT loaders) */
static void dc_bitmap_mark_cluster(dc_alloc_bitmap *bmp, u64 cluster, KIRQL *irql_ptr, BOOLEAN holding_lock);

/*
 * Helper: set a bit in our allocation bitmap
 */
static void dc_bitmap_set_bit(dc_alloc_bitmap *bmp, u64 bit_index)
{
    u64 byte_index = bit_index / 8;
    u8  bit_mask = (u8)(1 << (bit_index % 8));

    if (byte_index < bmp->bitmap_size) {
        bmp->bitmap[byte_index] |= bit_mask;
    }
}

/*
 * Helper: check if a bit is set in our allocation bitmap
 */
static BOOLEAN dc_bitmap_test_bit(dc_alloc_bitmap *bmp, u64 bit_index)
{
    u64 byte_index = bit_index / 8;
    u8  bit_mask = (u8)(1 << (bit_index % 8));

    if (byte_index < bmp->bitmap_size) {
        return (bmp->bitmap[byte_index] & bit_mask) != 0;
    }
    return TRUE; /* Out of range = assume allocated */
}

/*
 * Helper: detect filesystem type from volume handle
 */
static DC_FS_TYPE dc_detect_fs_type(HANDLE h_dev)
{
    DC_FS_ATTRIBUTE_INFO fs_info;
    IO_STATUS_BLOCK      iosb;
    NTSTATUS             status;

    RtlZeroMemory(&fs_info, sizeof(fs_info));

    status = ZwQueryVolumeInformationFile(
        h_dev,
        &iosb,
        &fs_info,
        sizeof(fs_info),
        FileFsAttributeInformation
    );

    if (!NT_SUCCESS(status)) {
        DbgMsg("dc_detect_fs_type: query failed, status=%08x\n", status);
        return DC_FS_UNKNOWN;
    }

    /* Compare filesystem name (case-insensitive) */
    if (fs_info.FileSystemNameLength >= 4 * sizeof(WCHAR)) {
        if (_wcsnicmp(fs_info.FileSystemName, L"NTFS", 4) == 0) {
            return DC_FS_NTFS;
        }
        if (_wcsnicmp(fs_info.FileSystemName, L"ReFS", 4) == 0) {
            return DC_FS_REFS;
        }
    }

    DbgMsg("dc_detect_fs_type: unsupported filesystem '%.16ws'\n", fs_info.FileSystemName);
    return DC_FS_UNKNOWN;
}

/*
 * Helper: detect FAT filesystem type from raw boot sector
 */
static DC_FS_TYPE dc_detect_fs_type_raw(dev_hook *hook, void **boot_sector_out)
{
    u8 *sector;
    int resl;
    DC_FS_TYPE type = DC_FS_UNKNOWN;

    /* Allocate sector buffer */
    sector = mm_pool_alloc(ROUND_TO_FULL_SECTORS(512, hook->bps));
    if (sector == NULL) return DC_FS_UNKNOWN;

    /* Read boot sector */
    resl = io_hook_rw(hook, sector, ROUND_TO_FULL_SECTORS(512, hook->bps), 0, 1);
    if (resl != ST_OK) {
        mm_pool_free(sector);
        return DC_FS_UNKNOWN;
    }

    /* Check boot signature */
    if (sector[510] != 0x55 || sector[511] != 0xAA) {
        mm_pool_free(sector);
        return DC_FS_UNKNOWN;
    }

    /* Detect filesystem type */
    if (memcmp(sector + 3, "EXFAT   ", 8) == 0) {
        type = DC_FS_EXFAT;
    } else if (memcmp(sector + 82, "FAT32   ", 8) == 0) {
        type = DC_FS_FAT32;
    } else if (memcmp(sector + 54, "FAT16   ", 8) == 0) {
        type = DC_FS_FAT16;
    } else if (memcmp(sector + 54, "FAT12   ", 8) == 0) {
        type = DC_FS_UNKNOWN; /* FAT12 not supported (too small to matter) */
    }

    if (boot_sector_out && type != DC_FS_UNKNOWN) {
        *boot_sector_out = sector;
    } else {
        mm_pool_free(sector);
    }

    return type;
}

/*
 * Helper: load FAT16/FAT32 allocation bitmap from FAT table
 */
static int dc_bitmap_load_fat(dev_hook *hook, dc_alloc_bitmap *bmp, void *boot_sector, DC_FS_TYPE fs_type)
{
    DC_FAT16_BOOT_SECTOR *fat16 = (DC_FAT16_BOOT_SECTOR*)boot_sector;
    DC_FAT32_BOOT_SECTOR *fat32 = (DC_FAT32_BOOT_SECTOR*)boot_sector;

    u32 bytes_per_sector;
    u32 sectors_per_cluster;
    u32 reserved_sectors;
    u32 num_fats;
    u32 root_dir_sectors;
    u32 fat_size;
    u64 total_sectors;
    u64 data_sectors;
    u64 total_clusters;
    u64 fat_offset;
    u8 *fat_buffer = NULL;
    u32 fat_bytes;
    u64 entries_read;
    KIRQL irql;
    int resl = ST_OK;

    /* Parse BPB based on filesystem type */
    bytes_per_sector = fat16->bytes_per_sector;
    sectors_per_cluster = fat16->sectors_per_cluster;
    reserved_sectors = fat16->reserved_sectors;
    num_fats = fat16->num_fats;

    if (fs_type == DC_FS_FAT32) {
        fat_size = fat32->fat_size_32;
        root_dir_sectors = 0; /* FAT32 has root in data area */
        total_sectors = fat32->total_sectors_32;
    } else {
        fat_size = fat16->fat_size_16;
        root_dir_sectors = ((fat16->root_entries * 32) + (bytes_per_sector - 1)) / bytes_per_sector;
        total_sectors = fat16->total_sectors_16 ? fat16->total_sectors_16 : fat16->total_sectors_32;
    }

    data_sectors = total_sectors - reserved_sectors - (num_fats * fat_size) - root_dir_sectors;
    total_clusters = data_sectors / sectors_per_cluster;
    fat_offset = (u64)reserved_sectors * bytes_per_sector;

    /* Calculate FAT size in bytes */
    if (fs_type == DC_FS_FAT32) {
        fat_bytes = (u32)((total_clusters + 2) * 4);  /* 4 bytes per entry */
    } else {
        fat_bytes = (u32)((total_clusters + 2) * 2);  /* 2 bytes per entry */
    }

    DbgMsg("dc_bitmap_load_fat: fs_type=%d, total_clusters=%I64u, fat_offset=%I64u, fat_bytes=%u\n",
           fs_type, total_clusters, fat_offset, fat_bytes);

    /* Read FAT in chunks */
    fat_buffer = mm_pool_alloc(BITMAP_READ_CHUNK);
    if (fat_buffer == NULL) return ST_NOMEM;

    entries_read = 0;

    while (entries_read < total_clusters + 2) {
        u64 fat_read_offset;
        u32 chunk_size;
        u32 entries_in_chunk;
        u32 i;

        /* Check if bitmap was freed while we were loading */
        if (hook->alloc_bitmap != bmp) {
            DbgMsg("dc_bitmap_load_fat: bitmap changed, aborting\n");
            resl = ST_ERROR;
            break;
        }

        if (fs_type == DC_FS_FAT32) {
            fat_read_offset = fat_offset + (entries_read * 4);
            chunk_size = (u32)min(BITMAP_READ_CHUNK, fat_bytes - (u32)(entries_read * 4));
            entries_in_chunk = chunk_size / 4;
        } else {
            fat_read_offset = fat_offset + (entries_read * 2);
            chunk_size = (u32)min(BITMAP_READ_CHUNK, fat_bytes - (u32)(entries_read * 2));
            entries_in_chunk = chunk_size / 2;
        }

        if (chunk_size == 0) break;

        resl = io_hook_rw(hook, fat_buffer, ROUND_TO_FULL_SECTORS(chunk_size, hook->bps), fat_read_offset, 1);
        if (resl != ST_OK) {
            DbgMsg("dc_bitmap_load_fat: read failed at offset=%I64u, status=%d\n", fat_read_offset, resl);
            break;
        }

        KeAcquireSpinLock(&bmp->lock, &irql);

        if (fs_type == DC_FS_FAT32) {
            u32 *fat32_entries = (u32*)fat_buffer;
            for (i = 0; i < entries_in_chunk && entries_read + i < total_clusters + 2; i++) {
                u32 entry = fat32_entries[i] & 0x0FFFFFFF;  /* Lower 28 bits */
                if (entry != 0) {  /* Non-zero = allocated */
                    u64 cluster_idx = entries_read + i;
                    if (cluster_idx >= 2) {  /* Clusters 0,1 are reserved */
                        dc_bitmap_mark_cluster(bmp, cluster_idx - 2, &irql, TRUE);
                    }
                }
            }
        } else {
            u16 *fat16_entries = (u16*)fat_buffer;
            for (i = 0; i < entries_in_chunk && entries_read + i < total_clusters + 2; i++) {
                u16 entry = fat16_entries[i];
                if (entry != 0) {  /* Non-zero = allocated */
                    u64 cluster_idx = entries_read + i;
                    if (cluster_idx >= 2) {
                        dc_bitmap_mark_cluster(bmp, cluster_idx - 2, &irql, TRUE);
                    }
                }
            }
        }

        KeReleaseSpinLock(&bmp->lock, irql);
        entries_read += entries_in_chunk;

        /* Yield periodically to avoid hogging CPU */
        if ((entries_read % (256 * 1024)) == 0) {
            dc_delay(1);
        }
    }

    mm_pool_free(fat_buffer);
    return resl;
}

/*
 * Helper: load exFAT allocation bitmap from Allocation Bitmap metadata file
 */
static int dc_bitmap_load_exfat(dev_hook *hook, dc_alloc_bitmap *bmp, void *boot_sector)
{
    DC_EXFAT_BOOT_SECTOR *exfat = (DC_EXFAT_BOOT_SECTOR*)boot_sector;

    u32 bytes_per_sector;
    u32 sectors_per_cluster;
    u32 cluster_size;
    u64 cluster_heap_offset;
    u32 root_cluster;
    u8 *dir_buffer = NULL;
    u8 *bitmap_buffer = NULL;
    DC_EXFAT_BITMAP_ENTRY *bitmap_entry = NULL;
    u32 bitmap_cluster;
    u64 bitmap_size;
    u64 bitmap_offset;
    u64 bytes_read;
    u32 i;
    KIRQL irql;
    int resl;

    bytes_per_sector = 1 << exfat->bytes_per_sector_shift;
    sectors_per_cluster = 1 << exfat->sectors_per_cluster_shift;
    cluster_size = bytes_per_sector * sectors_per_cluster;
    cluster_heap_offset = (u64)exfat->cluster_heap_offset * bytes_per_sector;
    root_cluster = exfat->first_cluster_of_root;

    DbgMsg("dc_bitmap_load_exfat: bytes_per_sector=%u, cluster_size=%u, root_cluster=%u\n",
           bytes_per_sector, cluster_size, root_cluster);

    /* Read root directory to find Allocation Bitmap entry */
    dir_buffer = mm_pool_alloc(cluster_size);
    if (dir_buffer == NULL) return ST_NOMEM;

    {
        u64 root_offset = cluster_heap_offset + (u64)(root_cluster - 2) * cluster_size;
        resl = io_hook_rw(hook, dir_buffer, cluster_size, root_offset, 1);
        if (resl != ST_OK) {
            DbgMsg("dc_bitmap_load_exfat: failed to read root directory\n");
            mm_pool_free(dir_buffer);
            return resl;
        }
    }

    /* Find Allocation Bitmap entry (type 0x81) */
    for (i = 0; i < cluster_size / 32; i++) {
        DC_EXFAT_DIR_ENTRY *entry = (DC_EXFAT_DIR_ENTRY*)(dir_buffer + i * 32);
        if (entry->entry_type == 0x81) {
            bitmap_entry = (DC_EXFAT_BITMAP_ENTRY*)entry;
            break;
        }
        if (entry->entry_type == 0x00) break;  /* End of directory */
    }

    if (bitmap_entry == NULL) {
        DbgMsg("dc_bitmap_load_exfat: Allocation Bitmap entry not found\n");
        mm_pool_free(dir_buffer);
        return ST_ERROR;
    }

    bitmap_cluster = bitmap_entry->first_cluster;
    bitmap_size = bitmap_entry->data_length;
    mm_pool_free(dir_buffer);

    DbgMsg("dc_bitmap_load_exfat: bitmap_cluster=%u, bitmap_size=%I64u\n", bitmap_cluster, bitmap_size);

    /* Read allocation bitmap */
    bitmap_offset = cluster_heap_offset + (u64)(bitmap_cluster - 2) * cluster_size;
    bitmap_buffer = mm_pool_alloc(BITMAP_READ_CHUNK);
    if (bitmap_buffer == NULL) return ST_NOMEM;

    bytes_read = 0;

    while (bytes_read < bitmap_size) {
        u32 chunk = (u32)min(BITMAP_READ_CHUNK, bitmap_size - bytes_read);

        /* Check if bitmap was freed while we were loading */
        if (hook->alloc_bitmap != bmp) {
            DbgMsg("dc_bitmap_load_exfat: bitmap changed, aborting\n");
            resl = ST_ERROR;
            break;
        }

        resl = io_hook_rw(hook, bitmap_buffer, ROUND_TO_FULL_SECTORS(chunk, hook->bps),
                          bitmap_offset + bytes_read, 1);
        if (resl != ST_OK) {
            DbgMsg("dc_bitmap_load_exfat: read failed at offset=%I64u\n", bitmap_offset + bytes_read);
            break;
        }

        /* Copy bitmap data - exFAT bitmap format matches our format */
        KeAcquireSpinLock(&bmp->lock, &irql);
        for (i = 0; i < chunk; i++) {
            u64 cluster_base = (bytes_read + i) * 8;
            u8 bit;
            for (bit = 0; bit < 8; bit++) {
                if (bitmap_buffer[i] & (1 << bit)) {
                    if (cluster_base + bit < bmp->total_clusters) {
                        dc_bitmap_mark_cluster(bmp, cluster_base + bit, &irql, TRUE);
                    }
                }
            }
        }
        KeReleaseSpinLock(&bmp->lock, irql);

        bytes_read += chunk;

        /* Yield periodically to avoid hogging CPU */
        if ((bytes_read % (256 * 1024)) == 0) {
            dc_delay(1);
        }
    }

    mm_pool_free(bitmap_buffer);
    return resl;
}

/*
 * Helper: mark a cluster as allocated (thread-safe)
 */
static void dc_bitmap_mark_cluster(dc_alloc_bitmap *bmp, u64 cluster, KIRQL *irql_ptr, BOOLEAN holding_lock)
{
    u64 bit_index;

    if (bmp == NULL || cluster >= bmp->total_clusters) {
        return;
    }

    bit_index = cluster / bmp->clusters_per_bit;

    if (!holding_lock) {
        KeAcquireSpinLock(&bmp->lock, irql_ptr);
    }

    dc_bitmap_set_bit(bmp, bit_index);

    if (!holding_lock) {
        KeReleaseSpinLock(&bmp->lock, *irql_ptr);
    }
}

int dc_bitmap_create(dev_hook *hook)
{
    DC_NTFS_VOLUME_DATA ntfs_data;
    DC_REFS_VOLUME_DATA refs_data;
    dc_alloc_bitmap    *bmp;
    u64                 total_clusters;
    u64                 number_sectors;
    u32                 bytes_per_cluster;
    u32                 bytes_per_sector;
    u64                 mft_start_lcn;
    u64                 mft2_start_lcn;
    u64                 mft_zone_start;
    u64                 mft_zone_end;
    u64                 protected_start;
    u32                 ideal_bytes;
    u32                 clusters_per_bit;
    u64                 bitmap_bits;
    u32                 bitmap_bytes;
    HANDLE              h_dev = NULL;
    IO_STATUS_BLOCK     iosb;
    NTSTATUS            status;
    DC_FS_TYPE          fs_type;
    void               *fat_boot_sector = NULL;

    DbgMsg("dc_bitmap_create: dev=%ws\n", hook->dev_name);

    /* Already have a bitmap? */
    if (DC_BITMAP_IS_VALID(hook->alloc_bitmap)) {
        DbgMsg("dc_bitmap_create: bitmap already exists\n");
        return ST_OK;
    }

    /* Open the volume to send file system queries */
    h_dev = io_open_device(hook->dev_name);
    if (h_dev == NULL) {
        DbgMsg("dc_bitmap_create: failed to open device\n");
        return ST_ERROR;
    }

    /* Detect filesystem type using Windows API first */
    fs_type = dc_detect_fs_type(h_dev);

    /* If Windows API doesn't recognize it, try raw boot sector detection for FAT */
    if (fs_type == DC_FS_UNKNOWN) {
        ZwClose(h_dev);
        h_dev = NULL;
        fs_type = dc_detect_fs_type_raw(hook, &fat_boot_sector);
        if (fs_type == DC_FS_UNKNOWN) {
            DbgMsg("dc_bitmap_create: unsupported filesystem\n");
            return ST_ERROR;
        }
    }

    /* Get volume data based on filesystem type */
    if (fs_type == DC_FS_NTFS) {
        status = ZwFsControlFile(
            h_dev, NULL, NULL, NULL, &iosb,
            FSCTL_GET_NTFS_VOLUME_DATA,
            NULL, 0,
            &ntfs_data, sizeof(ntfs_data)
        );

        if (!NT_SUCCESS(status)) {
            ZwClose(h_dev);
            DbgMsg("dc_bitmap_create: FSCTL_GET_NTFS_VOLUME_DATA failed, status=%08x\n", status);
            return ST_ERROR;
        }

        total_clusters = (u64)ntfs_data.TotalClusters.QuadPart;
        number_sectors = (u64)ntfs_data.NumberSectors.QuadPart;
        bytes_per_cluster = ntfs_data.BytesPerCluster;
        bytes_per_sector = ntfs_data.BytesPerSector;
        mft_start_lcn = (u64)ntfs_data.MftStartLcn.QuadPart;
        mft2_start_lcn = (u64)ntfs_data.Mft2StartLcn.QuadPart;
        mft_zone_start = (u64)ntfs_data.MftZoneStart.QuadPart;
        mft_zone_end = (u64)ntfs_data.MftZoneEnd.QuadPart;
        protected_start = bytes_per_cluster;  /* Just first cluster (boot sector) */
        DbgMsg("dc_bitmap_create: NTFS volume\n");

    } else if (fs_type == DC_FS_REFS) {
        status = ZwFsControlFile(
            h_dev, NULL, NULL, NULL, &iosb,
            FSCTL_GET_REFS_VOLUME_DATA,
            NULL, 0,
            &refs_data, sizeof(refs_data)
        );

        if (!NT_SUCCESS(status)) {
            ZwClose(h_dev);
            DbgMsg("dc_bitmap_create: FSCTL_GET_REFS_VOLUME_DATA failed, status=%08x\n", status);
            return ST_ERROR;
        }

        total_clusters = (u64)refs_data.TotalClusters.QuadPart;
        number_sectors = (u64)refs_data.NumberSectors.QuadPart;
        bytes_per_cluster = refs_data.BytesPerCluster;
        bytes_per_sector = refs_data.BytesPerSector;
        /* ReFS has no MFT */
        mft_start_lcn = 0;
        mft2_start_lcn = 0;
        mft_zone_start = 0;
        mft_zone_end = 0;
        protected_start = bytes_per_cluster;  /* Just first cluster */
        DbgMsg("dc_bitmap_create: ReFS volume (v%u.%u)\n",
               refs_data.MajorVersion, refs_data.MinorVersion);

    } else if (fs_type == DC_FS_FAT16 || fs_type == DC_FS_FAT32) {
        /* FAT16/FAT32: Parse boot sector */
        DC_FAT16_BOOT_SECTOR *fat16 = (DC_FAT16_BOOT_SECTOR*)fat_boot_sector;
        DC_FAT32_BOOT_SECTOR *fat32 = (DC_FAT32_BOOT_SECTOR*)fat_boot_sector;
        u32 fat_size;
        u32 root_dir_sectors;
        u64 data_sectors;

        bytes_per_sector = fat16->bytes_per_sector;
        bytes_per_cluster = fat16->sectors_per_cluster * bytes_per_sector;

        if (fs_type == DC_FS_FAT32) {
            fat_size = fat32->fat_size_32;
            root_dir_sectors = 0;
            number_sectors = fat32->total_sectors_32;
        } else {
            fat_size = fat16->fat_size_16;
            root_dir_sectors = ((fat16->root_entries * 32) + (bytes_per_sector - 1)) / bytes_per_sector;
            number_sectors = fat16->total_sectors_16 ? fat16->total_sectors_16 : fat16->total_sectors_32;
        }

        data_sectors = number_sectors - fat16->reserved_sectors - (fat16->num_fats * fat_size) - root_dir_sectors;
        total_clusters = data_sectors / fat16->sectors_per_cluster;

        /* FAT has no MFT */
        mft_start_lcn = 0;
        mft2_start_lcn = 0;
        mft_zone_start = 0;
        mft_zone_end = 0;

        /* Protected area: boot sector(s), FAT tables, and root directory (FAT16) */
        protected_start = (u64)(fat16->reserved_sectors + (fat16->num_fats * fat_size) + root_dir_sectors) * bytes_per_sector;

        DbgMsg("dc_bitmap_create: %s volume, fat_size=%u, root_dir_sectors=%u\n",
               fs_type == DC_FS_FAT32 ? "FAT32" : "FAT16", fat_size, root_dir_sectors);

    } else if (fs_type == DC_FS_EXFAT) {
        /* exFAT: Parse boot sector */
        DC_EXFAT_BOOT_SECTOR *exfat = (DC_EXFAT_BOOT_SECTOR*)fat_boot_sector;

        bytes_per_sector = 1 << exfat->bytes_per_sector_shift;
        bytes_per_cluster = bytes_per_sector * (1 << exfat->sectors_per_cluster_shift);
        total_clusters = exfat->cluster_count;
        number_sectors = exfat->volume_length;

        /* exFAT has no MFT */
        mft_start_lcn = 0;
        mft2_start_lcn = 0;
        mft_zone_start = 0;
        mft_zone_end = 0;

        /* Protected area: everything before cluster heap (boot region, FAT, etc.) */
        protected_start = (u64)exfat->cluster_heap_offset * bytes_per_sector;

        DbgMsg("dc_bitmap_create: exFAT volume, cluster_heap_offset=%u\n", exfat->cluster_heap_offset);

    } else {
        /* Should not reach here */
        if (h_dev) ZwClose(h_dev);
        if (fat_boot_sector) mm_pool_free(fat_boot_sector);
        DbgMsg("dc_bitmap_create: unsupported filesystem type %d\n", fs_type);
        return ST_ERROR;
    }

    if (h_dev) ZwClose(h_dev);

    DbgMsg("dc_bitmap_create: total_clusters=%I64u, bytes_per_cluster=%u, bytes_per_sector=%u\n",
           total_clusters, bytes_per_cluster, bytes_per_sector);
    DbgMsg("dc_bitmap_create: number_sectors=%I64u, volume_size=%I64u, cluster_area=%I64u\n",
           number_sectors,
           number_sectors * bytes_per_sector,
           total_clusters * bytes_per_cluster);

    /* Determine ratio based on memory constraints */
    ideal_bytes = (u32)((total_clusters + 7) / 8);
    clusters_per_bit = 1;

    while (ideal_bytes / clusters_per_bit > MAX_BITMAP_BYTES && clusters_per_bit < 256) {
        clusters_per_bit *= 2;
    }

    bitmap_bits = (total_clusters + clusters_per_bit - 1) / clusters_per_bit;
    bitmap_bytes = (u32)((bitmap_bits + 7) / 8);

    DbgMsg("dc_bitmap_create: clusters_per_bit=%u, bitmap_bytes=%u\n",
           clusters_per_bit, bitmap_bytes);

    /* Allocate bitmap (NonPagedPoolNx, zeroed = all unallocated) */
    bmp = (dc_alloc_bitmap*)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(dc_alloc_bitmap) + bitmap_bytes,
        'pmtB'
    );

    if (bmp == NULL) {
        DbgMsg("dc_bitmap_create: allocation failed\n");
        if (fat_boot_sector) {
            mm_pool_free(fat_boot_sector);
        }
        return ST_NOMEM;
    }

    bmp->total_clusters = total_clusters;
    bmp->cluster_size = bytes_per_cluster;
    bmp->sector_size = bytes_per_sector;
    bmp->cluster_area_size = (u64)total_clusters * bytes_per_cluster;
    bmp->volume_size = (u64)number_sectors * bytes_per_sector;
    bmp->clusters_per_bit = clusters_per_bit;
    bmp->bitmap_size = bitmap_bytes;
    bmp->loading = 1; /* Mark as loading */
    KeInitializeSpinLock(&bmp->lock);

    /* Store MFT locations (in bytes) - ReFS/FAT have no MFT, values are 0 */
    bmp->mft_start = mft_start_lcn * bytes_per_cluster;
    bmp->mft2_start = mft2_start_lcn * bytes_per_cluster;
    bmp->mft_zone_start = mft_zone_start * bytes_per_cluster;
    bmp->mft_zone_end = mft_zone_end * bytes_per_cluster;

    /*
     * Set protected start area (calculated above for each filesystem type):
     * - NTFS/ReFS: First cluster (boot sector)
     * - FAT16/FAT32: Boot sector + FAT tables + root directory (FAT16)
     * - exFAT: Everything before cluster heap
     * If bitmap loading fails, the entire optimization is disabled
     */
    bmp->protected_start = protected_start;

    DbgMsg("dc_bitmap_create: cluster_area_size=%I64u, volume_size=%I64u, reserved_end=%I64u\n",
           bmp->cluster_area_size, bmp->volume_size,
           bmp->volume_size > bmp->cluster_area_size ? bmp->volume_size - bmp->cluster_area_size : 0);
    DbgMsg("dc_bitmap_create: mft_start=%I64u, mft2_start=%I64u, mft_zone=%I64u-%I64u\n",
           bmp->mft_start, bmp->mft2_start, bmp->mft_zone_start, bmp->mft_zone_end);
    DbgMsg("dc_bitmap_create: protected_start=%I64u bytes (%I64u clusters)\n",
           bmp->protected_start, bmp->protected_start / bmp->cluster_size);

    /* Bitmap array is already zeroed by ExAllocatePoolZero */

    hook->alloc_bitmap = bmp;

    /* Free boot sector buffer if we have one (FAT filesystems) */
    if (fat_boot_sector) {
        mm_pool_free(fat_boot_sector);
    }

    DbgMsg("dc_bitmap_create: success, bitmap at %p\n", bmp);

    return ST_OK;
}

/*
 * Helper: Load NTFS/ReFS bitmap using FSCTL_GET_VOLUME_BITMAP
 */
static int dc_bitmap_load_ntfs_refs(dev_hook *hook, dc_alloc_bitmap *bmp, HANDLE h_dev)
{
    DC_STARTING_LCN_INPUT   start_lcn;
    DC_VOLUME_BITMAP_BUFFER *disk_bitmap;
    u32                     buffer_size;
    u64                     lcn;
    u64                     clusters_in_chunk;
    u64                     i;
    KIRQL                   irql;
    IO_STATUS_BLOCK         iosb;
    NTSTATUS                status;
    int                     resl = ST_OK;

    /* Allocate buffer for disk bitmap chunks */
    buffer_size = sizeof(DC_VOLUME_BITMAP_BUFFER) + BITMAP_READ_CHUNK;
    disk_bitmap = (DC_VOLUME_BITMAP_BUFFER*)mm_pool_alloc(buffer_size);

    if (disk_bitmap == NULL) {
        return ST_NOMEM;
    }

    lcn = 0;

    while (lcn < bmp->total_clusters) {
        u64 actual_start_lcn;
        u64 bitmap_bytes_returned;

        /* Check if bitmap was freed while we were loading */
        if (hook->alloc_bitmap != bmp) {
            DbgMsg("dc_bitmap_load_ntfs_refs: bitmap changed, aborting\n");
            resl = ST_ERROR;
            break;
        }

        start_lcn.StartingLcn.QuadPart = lcn;

        status = ZwFsControlFile(
            h_dev, NULL, NULL, NULL, &iosb,
            FSCTL_GET_VOLUME_BITMAP,
            &start_lcn, sizeof(start_lcn),
            disk_bitmap, buffer_size
        );

        if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW) {
            DbgMsg("dc_bitmap_load_ntfs_refs: FSCTL failed at lcn=%I64u, status=%08x\n",
                   lcn, status);
            resl = ST_ERROR;
            break;
        }

        /* Use the ACTUAL starting LCN returned, not our requested one */
        actual_start_lcn = disk_bitmap->StartingLcn.QuadPart;

        /* BitmapSize is total clusters from StartingLcn to end of volume - NOT what's in buffer!
         * We need to calculate actual clusters from bytes returned in iosb.Information */
        if (iosb.Information <= VOLUME_BITMAP_HEADER_SIZE) {
            /* No bitmap data returned */
            if (actual_start_lcn < bmp->total_clusters) {
                DbgMsg("dc_bitmap_load_ntfs_refs: no data at lcn=%I64u, info=%Iu\n",
                       actual_start_lcn, iosb.Information);
                resl = ST_ERROR;
            }
            break;
        }

        /* Calculate actual bitmap bytes returned (subtract header) */
        bitmap_bytes_returned = iosb.Information - VOLUME_BITMAP_HEADER_SIZE;

        /* Clusters in this chunk = bits in returned bitmap data */
        clusters_in_chunk = bitmap_bytes_returned * 8;

        /* But don't exceed what BitmapSize says is remaining */
        if (clusters_in_chunk > (u64)disk_bitmap->BitmapSize.QuadPart) {
            clusters_in_chunk = disk_bitmap->BitmapSize.QuadPart;
        }

        DbgMsg("dc_bitmap_load_ntfs_refs: lcn=%I64u, actual=%I64u, info=%Iu, bytes=%I64u, clusters=%I64u\n",
               lcn, actual_start_lcn, iosb.Information, bitmap_bytes_returned, clusters_in_chunk);

        /* For each set bit in disk bitmap, set our bitmap */
        KeAcquireSpinLock(&bmp->lock, &irql);

        for (i = 0; i < clusters_in_chunk; i++) {
            u64 byte_idx = i / 8;
            u8  bit_mask = (u8)(1 << (i % 8));

            if (disk_bitmap->Buffer[byte_idx] & bit_mask) {
                /* Cluster is allocated on disk - mark in our bitmap */
                dc_bitmap_mark_cluster(bmp, actual_start_lcn + i, &irql, TRUE);
            }
        }

        KeReleaseSpinLock(&bmp->lock, irql);

        /* Advance to next chunk - use actual_start_lcn + clusters processed */
        lcn = actual_start_lcn + clusters_in_chunk;

        /* Yield periodically to avoid hogging CPU */
        if ((lcn % (1024 * 1024)) == 0) {
            dc_delay(1);
        }
    }

    mm_pool_free(disk_bitmap);
    return resl;
}

void dc_bitmap_load_from_disk(dev_hook *hook)
{
    dc_alloc_bitmap        *bmp;
    HANDLE                  h_dev = NULL;
    DC_FS_TYPE              fs_type;
    void                   *boot_sector = NULL;
    int                     load_result;

    /* Note: Hook is already referenced by dc_bitmap_start_init.
     * We must call dc_deref_hook before returning.
     * hook->alloc_bitmap is DC_BITMAP_LOADING when we start. */

    /* Create the bitmap structure.
     * This runs in this worker thread to avoid deadlock with F_SYNC. */
    if (hook->alloc_bitmap == DC_BITMAP_LOADING) {
        if (dc_bitmap_create(hook) != ST_OK) {
            DbgMsg("dc_bitmap_load_from_disk: create failed, no optimization\n");
            hook->alloc_bitmap = DC_BITMAP_INIT_FAILED;
            dc_deref_hook(hook);
            return;
        }
    }

    bmp = hook->alloc_bitmap;
    if (!DC_BITMAP_IS_VALID(bmp)) {
        /* This shouldn't happen, but handle it gracefully */
        if (hook->alloc_bitmap == DC_BITMAP_LOADING) {
            hook->alloc_bitmap = DC_BITMAP_INIT_FAILED;
        }
        dc_deref_hook(hook);
        return;
    }

    DbgMsg("dc_bitmap_load_from_disk: starting, dev=%ws\n", hook->dev_name);

    /* First try to open the volume and detect filesystem type via Windows API */
    h_dev = io_open_device(hook->dev_name);
    if (h_dev != NULL) {
        fs_type = dc_detect_fs_type(h_dev);
    } else {
        fs_type = DC_FS_UNKNOWN;
    }

    /* If Windows API doesn't recognize it, try raw boot sector detection for FAT */
    if (fs_type == DC_FS_UNKNOWN) {
        if (h_dev) {
            ZwClose(h_dev);
            h_dev = NULL;
        }
        fs_type = dc_detect_fs_type_raw(hook, &boot_sector);
    }

    if (fs_type == DC_FS_UNKNOWN) {
        DbgMsg("dc_bitmap_load_from_disk: failed to detect filesystem - DISABLING OPTIMIZATION\n");
        if (hook->alloc_bitmap == bmp) {
            ExFreePoolWithTag(bmp, 'pmtB');
            hook->alloc_bitmap = DC_BITMAP_INIT_FAILED;
        } else {
            InterlockedExchange(&bmp->loading, 0);
        }
        dc_deref_hook(hook);
        return;
    }

    /* Load bitmap based on filesystem type */
    if (fs_type == DC_FS_NTFS || fs_type == DC_FS_REFS) {
        /* Use FSCTL_GET_VOLUME_BITMAP for NTFS/ReFS */
        if (h_dev == NULL) {
            h_dev = io_open_device(hook->dev_name);
        }
        if (h_dev == NULL) {
            DbgMsg("dc_bitmap_load_from_disk: failed to open device - DISABLING OPTIMIZATION\n");
            if (hook->alloc_bitmap == bmp) {
                ExFreePoolWithTag(bmp, 'pmtB');
                hook->alloc_bitmap = DC_BITMAP_INIT_FAILED;
            } else {
                InterlockedExchange(&bmp->loading, 0);
            }
            dc_deref_hook(hook);
            return;
        }
        load_result = dc_bitmap_load_ntfs_refs(hook, bmp, h_dev);
        ZwClose(h_dev);
    } else if (fs_type == DC_FS_FAT16 || fs_type == DC_FS_FAT32) {
        /* Read and parse FAT table directly */
        if (h_dev) {
            ZwClose(h_dev);
            h_dev = NULL;
        }
        load_result = dc_bitmap_load_fat(hook, bmp, boot_sector, fs_type);
    } else if (fs_type == DC_FS_EXFAT) {
        /* Read exFAT Allocation Bitmap from root directory */
        if (h_dev) {
            ZwClose(h_dev);
            h_dev = NULL;
        }
        load_result = dc_bitmap_load_exfat(hook, bmp, boot_sector);
    } else {
        load_result = ST_ERROR;
    }

    /* Free boot sector if we have one */
    if (boot_sector) {
        mm_pool_free(boot_sector);
    }

    /*
     * CRITICAL: If loading failed at any point, disable the optimization entirely.
     * A partially loaded bitmap would incorrectly mark clusters as unallocated,
     * causing critical data to be skipped during encryption!
     */
    if (load_result != ST_OK) {
        DbgMsg("dc_bitmap_load_from_disk: FAILED (result=%d) - DISABLING OPTIMIZATION\n", load_result);
        /* Only free if unmount hasn't started (hook->alloc_bitmap still points to bmp) */
        if (hook->alloc_bitmap == bmp) {
            ExFreePoolWithTag(bmp, 'pmtB');
            hook->alloc_bitmap = DC_BITMAP_INIT_FAILED;
        } else {
            /* Unmount is waiting - just signal we're done, let dc_bitmap_free handle it */
            InterlockedExchange(&bmp->loading, 0);
        }
        dc_deref_hook(hook);
        return;
    }

    /* Mark loading as complete - bitmap is now valid */
    InterlockedExchange(&bmp->loading, 0);

    DbgMsg("dc_bitmap_load_from_disk: SUCCESS, fs_type=%d\n", fs_type);
    dc_deref_hook(hook);
}

void dc_bitmap_free(dev_hook *hook)
{
    dc_alloc_bitmap *bmp;

    /* If loading is in progress, wait for it to complete.
     * The loading thread will set alloc_bitmap to either a valid pointer
     * or DC_BITMAP_INIT_FAILED when done. */
    while (hook->alloc_bitmap == DC_BITMAP_LOADING) {
        dc_delay(10);
    }

    bmp = hook->alloc_bitmap;
    hook->alloc_bitmap = NULL;

    /* Handle sentinel value - just clear it, nothing to free */
    if (bmp == DC_BITMAP_INIT_FAILED) {
        DbgMsg("dc_bitmap_free: cleared init-failed sentinel\n");
        return;
    }

    if (bmp != NULL) {
        /* Wait for any pending load operations on the bitmap */
        while (bmp->loading) {
            dc_delay(10);
        }

        ExFreePoolWithTag(bmp, 'pmtB');

        DbgMsg("dc_bitmap_free: bitmap freed\n");
    }
}

void dc_bitmap_start_init(dev_hook *hook)
{
    int resl;
    PVOID prev;

    /* Only start if not already initialized, loading, or failed.
     * Use atomic compare-exchange to prevent race condition where two threads
     * both see NULL and try to start initialization simultaneously. */
    prev = InterlockedCompareExchangePointer(
        (PVOID*)&hook->alloc_bitmap,
        DC_BITMAP_LOADING,
        NULL);

    if (prev != NULL) {
        return;  /* Already initialized, loading, or failed */
    }

    DbgMsg("dc_bitmap_start_init: starting lazy init for dev=%ws\n", hook->dev_name);

    /* alloc_bitmap is now DC_BITMAP_LOADING (set atomically above) */

    /* Reference hook BEFORE starting thread to prevent use-after-free.
     * The worker thread will dereference when done. */
    dc_reference_hook(hook);

    /* Start worker thread that will create and load the bitmap.
     * This runs in a separate thread to avoid deadlock with F_SYNC. */
    resl = start_system_thread(
        (PKSTART_ROUTINE)dc_bitmap_load_from_disk, hook, NULL);

    if (resl != ST_OK) {
        /* Thread failed to start - mark as failed and dereference */
        hook->alloc_bitmap = DC_BITMAP_INIT_FAILED;
        dc_deref_hook(hook);
    }
}

BOOLEAN dc_bitmap_is_allocated(dev_hook *hook, u64 offset, u32 size)
{
    dc_alloc_bitmap *bmp;
    u64              start_cluster;
    u64              end_cluster;
    u64              start_bit;
    u64              end_bit;
    u64              b;
    BOOLEAN          allocated;
    KIRQL            irql;

    bmp = hook->alloc_bitmap;

    /* No bitmap or init failed = assume allocated (safe default) */
    if (!DC_BITMAP_IS_VALID(bmp)) {
        return TRUE;
    }

    /* Still loading = assume allocated (safe default) */
    if (bmp->loading) {
        return TRUE;
    }

    /*
     * CRITICAL AREA PROTECTION (Deterministic):
     * First cluster contains boot sector - not tracked by $Bitmap
     * Always treat as allocated
     */
    if (offset < bmp->protected_start) {
        return TRUE;
    }

    /*
     * CRITICAL AREA PROTECTION (Deterministic):
     * Area beyond cluster region contains backup boot sector - not tracked by $Bitmap
     * Always treat as allocated
     */
    if (offset >= bmp->cluster_area_size || (offset + size) > bmp->cluster_area_size) {
        return TRUE;
    }

    /* Everything else is determined by $Bitmap - trust it completely */

    /* Calculate cluster range */
    start_cluster = offset / bmp->cluster_size;
    end_cluster = (offset + size - 1) / bmp->cluster_size;

    /* Convert to bitmap bit indices */
    start_bit = start_cluster / bmp->clusters_per_bit;
    end_bit = end_cluster / bmp->clusters_per_bit;

    KeAcquireSpinLock(&bmp->lock, &irql);

    allocated = FALSE;
    for (b = start_bit; b <= end_bit; b++) {
        if (dc_bitmap_test_bit(bmp, b)) {
            allocated = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&bmp->lock, irql);

    return allocated;
}

void dc_bitmap_mark_allocated(dev_hook *hook, u64 offset, u32 size)
{
    dc_alloc_bitmap *bmp;
    u64              start_cluster;
    u64              end_cluster;
    u64              start_bit;
    u64              end_bit;
    u64              b;
    KIRQL            irql;

    bmp = hook->alloc_bitmap;

    if (!DC_BITMAP_IS_VALID(bmp)) {
        return;
    }

    /* Calculate cluster range */
    start_cluster = offset / bmp->cluster_size;
    end_cluster = (offset + size - 1) / bmp->cluster_size;

    /* Convert to bitmap bit indices */
    start_bit = start_cluster / bmp->clusters_per_bit;
    end_bit = end_cluster / bmp->clusters_per_bit;

    KeAcquireSpinLock(&bmp->lock, &irql);

    for (b = start_bit; b <= end_bit; b++) {
        dc_bitmap_set_bit(bmp, b);
    }

    KeReleaseSpinLock(&bmp->lock, irql);
}

#ifdef DC_AGGRESSIVE_SKIP

u64 dc_bitmap_get_unallocated(dev_hook *hook, u64 offset)
{
    dc_alloc_bitmap *bmp;
    u64              start_cluster;
    u64              start_bit;
    u64              total_bits;
    u64              b;
    u64              unalloc_bits;
    u64              unalloc_bytes;
    KIRQL            irql;

    bmp = hook->alloc_bitmap;

    /* No bitmap or init failed = assume allocated (return 0) */
    if (!DC_BITMAP_IS_VALID(bmp)) {
        return 0;
    }

    /* Still loading = assume allocated (return 0) */
    if (bmp->loading) {
        return 0;
    }

    /*
     * CRITICAL AREA PROTECTION (Deterministic):
     * First cluster contains boot sector - not tracked by $Bitmap
     */
    if (offset < bmp->protected_start) {
        return 0;
    }

    /*
     * CRITICAL AREA PROTECTION (Deterministic):
     * Area beyond cluster region contains backup boot sector - not tracked by $Bitmap
     */
    if (offset >= bmp->cluster_area_size) {
        return 0;
    }

    /* Everything else is determined by $Bitmap - trust it completely */

    /* Calculate starting cluster and bit */
    start_cluster = offset / bmp->cluster_size;
    start_bit = start_cluster / bmp->clusters_per_bit;
    total_bits = (bmp->total_clusters + bmp->clusters_per_bit - 1) / bmp->clusters_per_bit;

    /* Check if starting position is allocated */
    KeAcquireSpinLock(&bmp->lock, &irql);

    if (dc_bitmap_test_bit(bmp, start_bit)) {
        /* Starting position is allocated */
        KeReleaseSpinLock(&bmp->lock, irql);
        return 0;
    }

    /* Count consecutive unallocated bits */
    unalloc_bits = 0;
    for (b = start_bit; b < total_bits; b++) {
        if (dc_bitmap_test_bit(bmp, b)) {
            break; /* Found allocated bit */
        }
        unalloc_bits++;
    }

    KeReleaseSpinLock(&bmp->lock, irql);

    /* Convert bits to bytes */
    /* Each bit represents clusters_per_bit clusters */
    /* Each cluster is cluster_size bytes */
    unalloc_bytes = unalloc_bits * bmp->clusters_per_bit * bmp->cluster_size;

    /* Adjust for the starting offset within the first cluster group */
    {
        u64 bit_start_offset = start_bit * bmp->clusters_per_bit * bmp->cluster_size;
        if (offset > bit_start_offset) {
            u64 offset_adjustment = offset - bit_start_offset;
            if (unalloc_bytes > offset_adjustment) {
                unalloc_bytes -= offset_adjustment;
            } else {
                unalloc_bytes = 0;
            }
        }
    }

    /*
     * CRITICAL AREA PROTECTION (Deterministic):
     * Don't skip past the cluster area boundary - stop before the reserved end area
     * (backup boot sector beyond cluster region)
     */
    if (offset + unalloc_bytes > bmp->cluster_area_size) {
        if (offset < bmp->cluster_area_size) {
            unalloc_bytes = bmp->cluster_area_size - offset;
        } else {
            unalloc_bytes = 0;
        }
    }

    return unalloc_bytes;
}

u64 dc_bitmap_get_unallocated_backward(dev_hook *hook, u64 end_offset)
{
    dc_alloc_bitmap *bmp;
    u64              end_cluster;
    u64              end_bit;
    u64              first_protected_bit;
    u64              b;
    u64              unalloc_bits;
    u64              unalloc_bytes;
    KIRQL            irql;

    bmp = hook->alloc_bitmap;

    /* No bitmap or init failed = assume allocated (return 0) */
    if (!DC_BITMAP_IS_VALID(bmp)) {
        return 0;
    }

    /* Still loading = assume allocated (return 0) */
    if (bmp->loading) {
        return 0;
    }

    /* Sanity check */
    if (end_offset == 0) {
        return 0;
    }

    /*
     * CRITICAL AREA PROTECTION (Deterministic):
     * Never skip the protected start area - contains boot sector
     */
    if (end_offset <= bmp->protected_start) {
        return 0;
    }

    /*
     * CRITICAL AREA PROTECTION (Deterministic):
     * Never skip areas beyond the cluster region - contains backup boot sector
     */
    if (end_offset > bmp->cluster_area_size) {
        return 0;
    }

    /* Everything else is determined by $Bitmap - trust it completely */

    /* Calculate ending cluster and bit (for the byte just before end_offset) */
    end_cluster = (end_offset - 1) / bmp->cluster_size;
    end_bit = end_cluster / bmp->clusters_per_bit;

    /* Calculate the first bit that must not be skipped (protects start area) */
    first_protected_bit = (bmp->protected_start / bmp->cluster_size) / bmp->clusters_per_bit;

    /* Check if ending position is allocated */
    KeAcquireSpinLock(&bmp->lock, &irql);

    if (dc_bitmap_test_bit(bmp, end_bit)) {
        /* Ending position is allocated */
        KeReleaseSpinLock(&bmp->lock, irql);
        return 0;
    }

    /* Count consecutive unallocated bits going backward, but don't go past protected area */
    unalloc_bits = 0;
    for (b = end_bit; ; b--) {
        if (dc_bitmap_test_bit(bmp, b)) {
            break; /* Found allocated bit */
        }
        unalloc_bits++;
        if (b <= first_protected_bit) {
            break; /* Reached protected area (first cluster) */
        }
    }

    KeReleaseSpinLock(&bmp->lock, irql);

    /* Convert bits to bytes */
    unalloc_bytes = unalloc_bits * bmp->clusters_per_bit * bmp->cluster_size;

    /* Adjust for the ending offset within the last cluster group */
    {
        u64 bit_end_offset = (end_bit + 1) * bmp->clusters_per_bit * bmp->cluster_size;
        if (end_offset < bit_end_offset) {
            u64 offset_adjustment = bit_end_offset - end_offset;
            if (unalloc_bytes > offset_adjustment) {
                unalloc_bytes -= offset_adjustment;
            } else {
                unalloc_bytes = 0;
            }
        }
    }

    /*
     * CRITICAL AREA PROTECTION (Deterministic):
     * Don't skip past the protected start area (boot sector)
     */
    if (end_offset - unalloc_bytes < bmp->protected_start) {
        if (end_offset > bmp->protected_start) {
            unalloc_bytes = end_offset - bmp->protected_start;
        } else {
            unalloc_bytes = 0;
        }
    }

    return unalloc_bytes;
}

#endif