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

#ifndef FSCTL_GET_RETRIEVAL_POINTER_BASE
#define FSCTL_GET_RETRIEVAL_POINTER_BASE CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 141, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

/* Output of FSCTL_GET_RETRIEVAL_POINTER_BASE: volume-relative sector offset of the
 * first allocatable unit (LCN 0). 0 on NTFS/ReFS, the data area start on FAT/exFAT. */
typedef struct _DC_RETRIEVAL_POINTER_BASE {
    LARGE_INTEGER FileAreaOffset;
} DC_RETRIEVAL_POINTER_BASE;

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

/*
 * The loaders hold bmp->lock while merging a chunk. Write admission takes
 * bmp->lock nested inside range_lock, so every tracked I/O on the volume waits
 * while the loader holds it. Release and re-take the lock every
 * LOADER_LOCK_BURST iterations to keep those stalls short.
 */
#define LOADER_LOCK_BURST 4096
#define LOADER_LOCK_YIELD(_bmp_, _irql_, _n_) \
    do { if ((((_n_) + 1) % LOADER_LOCK_BURST) == 0) { \
        KeReleaseSpinLock(&(_bmp_)->lock, (_irql_)); \
        YieldProcessor(); YieldProcessor(); /* give a spinning waiter a chance (unfair lock) */ \
        KeAcquireSpinLock(&(_bmp_)->lock, &(_irql_)); } } while (0)

/* Forward declaration for dc_bitmap_mark_cluster (used by the FSCTL loader) */
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
    /* FAT family: exact names as reported by fastfat ("FAT" = FAT12/16, "FAT32") and
     * exfat ("exFAT"). */
    if (fs_info.FileSystemNameLength == 5 * sizeof(WCHAR)) {
        if (_wcsnicmp(fs_info.FileSystemName, L"FAT32", 5) == 0) {
            return DC_FS_FAT32;
        }
        if (_wcsnicmp(fs_info.FileSystemName, L"exFAT", 5) == 0) {
            return DC_FS_EXFAT;
        }
    }
    if (fs_info.FileSystemNameLength == 3 * sizeof(WCHAR) &&
        _wcsnicmp(fs_info.FileSystemName, L"FAT", 3) == 0) {
        return DC_FS_FAT16;
    }

    DbgMsg("dc_detect_fs_type: unsupported filesystem '%.16ws'\n", fs_info.FileSystemName);
    return DC_FS_UNKNOWN;
}

/*
 * Publishing and unpublishing hook->alloc_bitmap.
 *
 * In the concurrent build every non-loader access to the bitmap runs under
 * hook->trans.range_lock, so swapping the pointer under the same lock guarantees:
 *  - publish: a reader that sees the new pointer also sees the fully
 *    initialised structure (release/acquire through the lock, also on ARM64);
 *  - unpublish: once the lock is released no reader still holds the old pointer,
 *    so the caller may free it.
 */
static void dc_bitmap_publish(dev_hook *hook, dc_alloc_bitmap *bmp)
{
#ifdef DC_CONCURRENT_TRANSCRYPT
    KIRQL irql;

    KeAcquireSpinLock(&hook->trans.range_lock, &irql);
    InterlockedExchangePointer((PVOID volatile*)&hook->alloc_bitmap, bmp);
    KeReleaseSpinLock(&hook->trans.range_lock, irql);
#else
    InterlockedExchangePointer((PVOID volatile*)&hook->alloc_bitmap, bmp);
#endif
}

/*
 * Replace bmp by DC_BITMAP_INIT_FAILED if it is still the published bitmap.
 * Returns TRUE if the caller won and now owns bmp (it may free it).
 * Returns FALSE if dc_bitmap_free already took it; then dc_bitmap_free frees it
 * once bmp->loading drops to 0.
 */
static BOOLEAN dc_bitmap_unpublish(dev_hook *hook, dc_alloc_bitmap *bmp)
{
    PVOID prev;
#ifdef DC_CONCURRENT_TRANSCRYPT
    KIRQL irql;

    KeAcquireSpinLock(&hook->trans.range_lock, &irql);
    prev = InterlockedCompareExchangePointer((PVOID volatile*)&hook->alloc_bitmap, DC_BITMAP_INIT_FAILED, bmp);
    KeReleaseSpinLock(&hook->trans.range_lock, irql);
#else
    prev = InterlockedCompareExchangePointer((PVOID volatile*)&hook->alloc_bitmap, DC_BITMAP_INIT_FAILED, bmp);
#endif
    return prev == bmp;
}

/* Loader failure: drop the bitmap and disable the optimisation. */
static void dc_bitmap_abort_load(dev_hook *hook, dc_alloc_bitmap *bmp)
{
    if (dc_bitmap_unpublish(hook, bmp)) {
        ExFreePoolWithTag(bmp, 'pmtB');
    } else {
        /* dc_bitmap_free owns it and waits for loading == 0 */
        InterlockedExchange(&bmp->loading, 0);
    }
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

int dc_bitmap_create(dev_hook *hook, dc_alloc_bitmap **out_bmp)
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
    u64                 data_start = 0;   /* volume offset of LCN 0; 0 for NTFS/ReFS */

    *out_bmp = NULL;

    DbgMsg("dc_bitmap_create: dev=%ws\n", hook->dev_name);

    /* Only called by the loader thread, while hook->alloc_bitmap is DC_BITMAP_LOADING */

    /* Open the volume to send file system queries */
    h_dev = io_open_device(hook->dev_name);
    if (h_dev == NULL) {
        DbgMsg("dc_bitmap_create: failed to open device\n");
        return ST_ERROR;
    }

    /* Detect filesystem type from the mounted file system. No raw boot-sector fallback:
     * during transcryption raw sector 0 is the DC header and raw metadata may be
     * ciphertext or stale. Without a recognised file system the optimisation stays off. */
    fs_type = dc_detect_fs_type(h_dev);
    if (fs_type == DC_FS_UNKNOWN) {
        ZwClose(h_dev);
        DbgMsg("dc_bitmap_create: unsupported filesystem\n");
        return ST_ERROR;
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

    } else if (fs_type == DC_FS_FAT16 || fs_type == DC_FS_FAT32 || fs_type == DC_FS_EXFAT) {
        /*
         * FAT12/16/32 and exFAT. Geometry comes from the file system itself:
         * - FileFsSizeInformation: cluster size and cluster count;
         * - FSCTL_GET_RETRIEVAL_POINTER_BASE: volume offset of LCN 0, the first data
         *   cluster (FAT cluster #2 / start of the exFAT cluster heap).
         * FSCTL_GET_VOLUME_BITMAP LCNs are relative to that base, so the bitmap is
         * indexed by (volume offset - data_start) / cluster_size.
         */
        FILE_FS_SIZE_INFORMATION   fs_size;
        DC_RETRIEVAL_POINTER_BASE  ptr_base;
        u64                        cluster_bytes;

        RtlZeroMemory(&fs_size, sizeof(fs_size));
        status = ZwQueryVolumeInformationFile(h_dev, &iosb, &fs_size, sizeof(fs_size), FileFsSizeInformation);
        if (!NT_SUCCESS(status) || iosb.Information < sizeof(fs_size)) {
            ZwClose(h_dev);
            DbgMsg("dc_bitmap_create: FileFsSizeInformation failed, status=%08x\n", status);
            return ST_ERROR;
        }
        RtlZeroMemory(&ptr_base, sizeof(ptr_base));
        status = ZwFsControlFile(
            h_dev, NULL, NULL, NULL, &iosb,
            FSCTL_GET_RETRIEVAL_POINTER_BASE,
            NULL, 0,
            &ptr_base, sizeof(ptr_base)
        );
        if (!NT_SUCCESS(status) || iosb.Information < sizeof(ptr_base)) {
            ZwClose(h_dev);
            DbgMsg("dc_bitmap_create: FSCTL_GET_RETRIEVAL_POINTER_BASE failed, status=%08x, info=%Iu\n", status, iosb.Information);
            return ST_ERROR;
        }

        bytes_per_sector = fs_size.BytesPerSector;
        cluster_bytes    = (u64)fs_size.SectorsPerAllocationUnit * fs_size.BytesPerSector;
        total_clusters   = (u64)fs_size.TotalAllocationUnits.QuadPart;

        /* Be strict: the loader's bitmap length cross-check cannot confirm data_start,
         * and a wrong frame would skip live data. FileAreaOffset must be > 0 (every FAT
         * and exFAT volume has a boot area + FAT before the first data cluster) and is
         * bounded by the volume before multiplying (no wrap). */
        if (bytes_per_sector < 512 || bytes_per_sector > 4096 || (bytes_per_sector & (bytes_per_sector - 1)) != 0 ||
            cluster_bytes == 0 || cluster_bytes > 0x80000000ull ||
            ptr_base.FileAreaOffset.QuadPart <= 0 ||
            (u64)ptr_base.FileAreaOffset.QuadPart > hook->use_size / bytes_per_sector)
        {
            ZwClose(h_dev);
            DbgMsg("dc_bitmap_create: implausible FAT geometry, bps=%u, cluster=%I64u, file_area=%I64d\n",
                   bytes_per_sector, cluster_bytes, ptr_base.FileAreaOffset.QuadPart);
            return ST_ERROR;
        }
        bytes_per_cluster = (u32)cluster_bytes;
        data_start        = (u64)ptr_base.FileAreaOffset.QuadPart * bytes_per_sector;
        number_sectors    = (data_start + total_clusters * bytes_per_cluster) / bytes_per_sector;

        mft_start_lcn = 0;
        mft2_start_lcn = 0;
        mft_zone_start = 0;
        mft_zone_end = 0;

        /* Everything before the first data cluster (boot sector(s), FATs, FAT12/16
         * root directory, exFAT boot region) is never skipped. */
        protected_start = data_start;

        DbgMsg("dc_bitmap_create: %s volume, data_start=%I64u, clusters=%I64u, cluster=%u\n",
               fs_type == DC_FS_EXFAT ? "exFAT" : (fs_type == DC_FS_FAT32 ? "FAT32" : "FAT"),
               data_start, total_clusters, bytes_per_cluster);

    } else {
        /* Should not reach here */
        ZwClose(h_dev);
        DbgMsg("dc_bitmap_create: unsupported filesystem type %d\n", fs_type);
        return ST_ERROR;
    }

    ZwClose(h_dev);

    /* Validate the geometry against use_size before trusting it for skip decisions.
     * On doubt the optimisation stays off (everything is transcrypted). */
    if (bytes_per_sector < 512 || bytes_per_sector > 4096 || (bytes_per_sector & (bytes_per_sector - 1)) != 0 ||
        bytes_per_cluster < bytes_per_sector || (bytes_per_cluster & (bytes_per_cluster - 1)) != 0 ||
        total_clusters == 0 || data_start > hook->use_size ||
        total_clusters > (hook->use_size - data_start) / bytes_per_cluster)
    {
        DbgMsg("dc_bitmap_create: geometry rejected, bps=%u, cluster=%u, clusters=%I64u, data_start=%I64u, use_size=%I64u\n",
               bytes_per_sector, bytes_per_cluster, total_clusters, data_start, hook->use_size);
        return ST_ERROR;
    }

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

    /* Allocate bitmap (zeroed = all unallocated). NonPagedPoolNx is invalid on Windows 7, so
     * it is chosen at run time; zeroed here, not via ExAllocatePoolZero (its WDK inline may
     * call ExAllocatePool2, Windows 10 2004+). */
    bmp = (dc_alloc_bitmap*)ExAllocatePoolWithTag(
        RtlIsNtDdiVersionAvailable(NTDDI_WIN8) ? NonPagedPoolNx : NonPagedPool,
        sizeof(dc_alloc_bitmap) + bitmap_bytes,
        'pmtB'
    );

    if (bmp == NULL) {
        DbgMsg("dc_bitmap_create: allocation failed\n");
        return ST_NOMEM;
    }
    RtlZeroMemory(bmp, sizeof(dc_alloc_bitmap) + bitmap_bytes);

    bmp->total_clusters = total_clusters;
    bmp->cluster_size = bytes_per_cluster;
    bmp->sector_size = bytes_per_sector;
    bmp->data_start = data_start;
    bmp->fs_type = (u32)fs_type;
    /* END offset of the cluster area (volume offset); validated above to fit use_size */
    bmp->cluster_area_size = data_start + (u64)total_clusters * bytes_per_cluster;
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
     * - FAT/FAT32/exFAT: everything before the first data cluster (data_start)
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

    /* publish under range_lock: readers must never see the pointer before the fields */
    dc_bitmap_publish(hook, bmp);
    *out_bmp = bmp;

    DbgMsg("dc_bitmap_create: success, bitmap at %p\n", bmp);

    return ST_OK;
}

/*
 * Helper: load the allocation bitmap of any supported file system with
 * FSCTL_GET_VOLUME_BITMAP, the file system's in-memory allocation state (an
 * allocation always precedes the data write it is made for). LCNs are relative to
 * bmp->data_start. check_total (FAT family): the bitmap length reported for LCN 0
 * must equal the geometry's cluster count, so LCNs and data_start share one frame.
 */
static int dc_bitmap_load_fsctl(dev_hook *hook, dc_alloc_bitmap *bmp, HANDLE h_dev, BOOLEAN check_total)
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
            DbgMsg("dc_bitmap_load_fsctl: bitmap changed, aborting\n");
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
            DbgMsg("dc_bitmap_load_fsctl: FSCTL failed at lcn=%I64u, status=%08x\n",
                   lcn, status);
            resl = ST_ERROR;
            break;
        }

        /* Use the ACTUAL starting LCN returned, not our requested one */
        actual_start_lcn = disk_bitmap->StartingLcn.QuadPart;

        /* File systems may round StartingLcn DOWN (NTFS and fastfat round to a multiple
         * of 8), never up: a larger value would leave unloaded zero bits = skippable
         * allocated clusters. Accept only actual in (lcn - 8, lcn]. */
        if (disk_bitmap->StartingLcn.QuadPart < 0 || actual_start_lcn > lcn || lcn - actual_start_lcn >= 8 ||
            disk_bitmap->BitmapSize.QuadPart <= 0)
        {
            DbgMsg("dc_bitmap_load_fsctl: unexpected reply at lcn=%I64u: StartingLcn=%I64d, BitmapSize=%I64d\n",
                   lcn, disk_bitmap->StartingLcn.QuadPart, disk_bitmap->BitmapSize.QuadPart);
            resl = ST_ERROR;
            break;
        }

        /* FAT family: the first reply must cover LCN 0 and report exactly the cluster
         * count the geometry came from (same cluster area, same numbering). */
        if (check_total && lcn == 0 &&
            (actual_start_lcn != 0 || (u64)disk_bitmap->BitmapSize.QuadPart != bmp->total_clusters))
        {
            DbgMsg("dc_bitmap_load_fsctl: bitmap size %I64u != cluster count %I64u, geometry mismatch\n",
                   (u64)disk_bitmap->BitmapSize.QuadPart, bmp->total_clusters);
            resl = ST_ERROR;
            break;
        }

        /* BitmapSize is total clusters from StartingLcn to end of volume - NOT what's in buffer!
         * We need to calculate actual clusters from bytes returned in iosb.Information */
        if (iosb.Information <= VOLUME_BITMAP_HEADER_SIZE) {
            /* No bitmap data returned */
            if (actual_start_lcn < bmp->total_clusters) {
                DbgMsg("dc_bitmap_load_fsctl: no data at lcn=%I64u, info=%Iu\n",
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
        /* No progress possible (and lcn must advance past the requested value) */
        if (clusters_in_chunk == 0 || actual_start_lcn + clusters_in_chunk <= lcn) {
            DbgMsg("dc_bitmap_load_fsctl: no progress at lcn=%I64u\n", lcn);
            resl = ST_ERROR;
            break;
        }

        DbgMsg("dc_bitmap_load_fsctl: lcn=%I64u, actual=%I64u, info=%Iu, bytes=%I64u, clusters=%I64u\n",
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
            LOADER_LOCK_YIELD(bmp, irql, i);
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
    int                     load_result;

    /* Note: Hook is already referenced by dc_bitmap_start_init.
     * We must call dc_deref_hook before returning.
     * hook->alloc_bitmap is DC_BITMAP_LOADING when we start. */

    /* Create the bitmap structure.
     * This runs in this worker thread to avoid deadlock with F_SYNC. */
    if (hook->alloc_bitmap != DC_BITMAP_LOADING) {
        /* only this thread moves the pointer away from LOADING; nothing to do */
        dc_deref_hook(hook);
        return;
    }
    if (dc_bitmap_create(hook, &bmp) != ST_OK) {
        DbgMsg("dc_bitmap_load_from_disk: create failed, no optimization\n");
        InterlockedCompareExchangePointer((PVOID volatile*)&hook->alloc_bitmap, DC_BITMAP_INIT_FAILED, DC_BITMAP_LOADING);
        dc_deref_hook(hook);
        return;
    }
    /* Use the pointer create handed back, never re-read hook->alloc_bitmap: dc_bitmap_free
     * may take it right after the publish and then waits for bmp->loading == 0, which
     * dc_bitmap_abort_load (unpublish lost) provides. */

    DbgMsg("dc_bitmap_load_from_disk: starting, dev=%ws\n", hook->dev_name);

    /* Open the volume and detect the mounted file system (no raw fallback, see dc_bitmap_create) */
    h_dev = io_open_device(hook->dev_name);
    fs_type = (h_dev != NULL) ? dc_detect_fs_type(h_dev) : DC_FS_UNKNOWN;

    /* The geometry (data_start frame, cluster count) was taken in dc_bitmap_create from
     * the file system mounted then; a different one now (dismount + reformat in between)
     * must not be loaded into that frame. */
    if (fs_type == DC_FS_UNKNOWN || (u32)fs_type != bmp->fs_type) {
        DbgMsg("dc_bitmap_load_from_disk: failed to detect filesystem (or it changed) - DISABLING OPTIMIZATION\n");
        if (h_dev != NULL) ZwClose(h_dev);
        dc_bitmap_abort_load(hook, bmp); /* unpublish under range_lock BEFORE freeing */
        dc_deref_hook(hook);
        return;
    }

    /* The FAT family also cross-checks the bitmap length against the geometry */
    load_result = dc_bitmap_load_fsctl(hook, bmp, h_dev,
                                       (BOOLEAN)(fs_type != DC_FS_NTFS && fs_type != DC_FS_REFS));
    ZwClose(h_dev);

    /*
     * CRITICAL: If loading failed at any point, disable the optimization entirely.
     * A partially loaded bitmap would incorrectly mark clusters as unallocated,
     * causing critical data to be skipped during encryption!
     */
    if (load_result != ST_OK) {
        DbgMsg("dc_bitmap_load_from_disk: FAILED (result=%d) - DISABLING OPTIMIZATION\n", load_result);
        /* Free only if unmount hasn't taken it (atomic swap under range_lock);
         * otherwise just signal we're done and let dc_bitmap_free handle it */
        dc_bitmap_abort_load(hook, bmp);
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

    /* Wait while loading (the loader moves LOADING to a valid pointer or
     * DC_BITMAP_INIT_FAILED), then take the pointer with a CAS that never takes the
     * LOADING sentinel. Terminates: start_init only arms while F_SYNC is set (under
     * range_lock), and cleanup clears F_SYNC under range_lock before calling us. */
    for (;;) {
        bmp = hook->alloc_bitmap;
        if (bmp == DC_BITMAP_LOADING) {
            dc_delay(10);
            continue;
        }
        if (InterlockedCompareExchangePointer((PVOID volatile*)&hook->alloc_bitmap, NULL, bmp) == bmp) {
            break;
        }
    }

    /* After the CAS exactly one side owns bmp: if we got it, the loader's unpublish
     * fails and it only clears bmp->loading, which we wait for below. Called from
     * dc_sync_cleanup after F_SYNC was cleared under range_lock and tracked I/O
     * drained, so no admission or step can still be using the pointer. */
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
#ifdef DC_CONCURRENT_TRANSCRYPT
    KIRQL irql;
#endif

    /* Only start from NULL (not initialized, loading, or failed); the CAS lets exactly
     * one caller start. */
#ifdef DC_CONCURRENT_TRANSCRYPT
    /* Arm only while transcryption is live, decided under range_lock:
     * dc_transcrypt_cleanup clears F_SYNC under this lock before dc_bitmap_free
     * runs, so no bitmap can be re-armed after the free (stale bits in the next session). */
    prev = (PVOID)DC_BITMAP_INIT_FAILED; /* "do not start" */
    KeAcquireSpinLock(&hook->trans.range_lock, &irql);
    if ((hook->flags & F_SYNC) && !(hook->flags & (F_PLAIN_IO | F_NO_REDIRECT))) {
        prev = InterlockedCompareExchangePointer(
            (PVOID volatile*)&hook->alloc_bitmap,
            DC_BITMAP_LOADING,
            NULL);
    }
    KeReleaseSpinLock(&hook->trans.range_lock, irql);
#else
    prev = InterlockedCompareExchangePointer(
        (PVOID*)&hook->alloc_bitmap,
        DC_BITMAP_LOADING,
        NULL);
#endif

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
        InterlockedExchangePointer((PVOID volatile*)&hook->alloc_bitmap, DC_BITMAP_INIT_FAILED);
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

    /* Degenerate or wrapping range, or a structure that is not usable:
     * assume allocated (safe default, never skip on doubt) */
    if (size == 0 || offset + size < offset || bmp->cluster_size == 0 || bmp->clusters_per_bit == 0) {
        return TRUE;
    }

    /*
     * CRITICAL AREA PROTECTION (Deterministic): the protected start area (first cluster /
     * boot sector, or the whole FAT/exFAT metadata area; protected_start >= data_start)
     * is not tracked by the bitmap. Always treat as allocated.
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

    /* Calculate cluster range. LCNs count from data_start, the first data cluster:
     * 0 for NTFS/ReFS, the start of the cluster heap for FAT and exFAT. */
    start_cluster = (offset - bmp->data_start) / bmp->cluster_size;
    end_cluster = (offset + size - 1 - bmp->data_start) / bmp->cluster_size;

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
    u64              end;

    bmp = hook->alloc_bitmap;

    if (!DC_BITMAP_IS_VALID(bmp)) {
        return;
    }

    /* Called at write admission with IRP parameters: never trust them (size == 0 would
     * wrap end_cluster and loop ~2^52 times under two spinlocks). Ranges outside the
     * cluster area are never skipped, so clamp to it. */
    if (size == 0 || bmp->cluster_size == 0 || bmp->clusters_per_bit == 0 ||
        offset >= bmp->cluster_area_size) {
        return;
    }
    end = offset + size;
    if (end < offset || end > bmp->cluster_area_size) {
        end = bmp->cluster_area_size;
    }
    /* Writes into the metadata area before the first data cluster (FAT/exFAT boot
     * region, FATs) need no mark: that area is protected and never skipped. */
    if (end <= bmp->data_start) {
        return;
    }
    if (offset < bmp->data_start) {
        offset = bmp->data_start;
    }

    /* Calculate cluster range, relative to the first data cluster (LCN 0) */
    start_cluster = (offset - bmp->data_start) / bmp->cluster_size;
    end_cluster = (end - 1 - bmp->data_start) / bmp->cluster_size;

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
    start_cluster = (offset - bmp->data_start) / bmp->cluster_size;  /* LCNs count from data_start */
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
        u64 bit_start_offset = bmp->data_start + start_bit * bmp->clusters_per_bit * bmp->cluster_size;
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
    end_cluster = (end_offset - 1 - bmp->data_start) / bmp->cluster_size;  /* LCNs count from data_start */
    end_bit = end_cluster / bmp->clusters_per_bit;

    /* Calculate the first bit that must not be skipped (protects start area) */
    first_protected_bit = ((bmp->protected_start - bmp->data_start) / bmp->cluster_size) / bmp->clusters_per_bit;

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
        u64 bit_end_offset = bmp->data_start + (end_bit + 1) * bmp->clusters_per_bit * bmp->cluster_size;
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