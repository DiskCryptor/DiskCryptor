#ifndef _ALLOC_BITMAP_H_
#define _ALLOC_BITMAP_H_

#include "defines.h"

/*
 * Allocation bitmap structure for tracking used/unused clusters
 *
 * Supported filesystems: NTFS, ReFS, FAT12/FAT16 (DC_FS_FAT16), FAT32, exFAT, all through
 * the mounted file system (FSCTL_GET_VOLUME_BITMAP), never raw metadata. FAT family
 * geometry: FileFsSizeInformation + FSCTL_GET_RETRIEVAL_POINTER_BASE (data_start).
 *
 * Initialization (writes are not blocked):
 * 1. Create bitmap with all bits = 0 (all marked unallocated)
 * 2. Every tracked write sets its bits to 1 at admission, under trans.range_lock
 * 3. In parallel, read the file system's volume bitmap and OR the 1's into our bitmap
 * Bits are only ever set, never cleared: false 1's are safe (an extra block is
 * transcrypted), false 0's are impossible. Skip decisions wait until loading is done.
 */

typedef struct _dc_alloc_bitmap {
    u64            total_clusters;    /* Total clusters in volume */
    u64            data_start;        /* Volume offset of LCN 0 / first data cluster (0 for NTFS/ReFS) */
    u64            cluster_area_size; /* END volume offset of the cluster area (data_start + total_clusters * cluster_size) */
    u64            volume_size;       /* Total volume size in bytes (may be > cluster_area_size) */
    u64            mft_start;         /* MFT start offset in bytes */
    u64            mft2_start;        /* MFT mirror start offset in bytes */
    u64            mft_zone_start;    /* MFT zone start offset in bytes */
    u64            mft_zone_end;      /* MFT zone end offset in bytes */
    u64            protected_start;   /* Protected area at start (in bytes) - never skip */
    u32            cluster_size;      /* Bytes per cluster */
    u32            sector_size;       /* Bytes per sector */
    u32            clusters_per_bit;  /* How many clusters per bitmap bit (1, 2, 4, 8...) */
    u32            bitmap_size;       /* Size of bitmap in bytes */
    u32            fs_type;           /* DC_FS_TYPE the geometry was taken from; the loader must see the same */
    volatile LONG  loading;           /* 1 while disk bitmap is being loaded */
    KSPIN_LOCK     lock;              /* Protect bitmap access */
    u8             bitmap[];          /* 1 bit per (clusters_per_bit) clusters - flexible array */
} dc_alloc_bitmap;

/* Forward declaration */
struct _dev_hook;

//#define DC_AGGRESSIVE_SKIP // marginally faster but adds complexits

/*
 * Sentinel values for alloc_bitmap pointer:
 * - DC_BITMAP_LOADING: Loading thread is running, dc_bitmap_free must wait
 * - DC_BITMAP_INIT_FAILED: Init failed, don't retry
 * Must be cleared on unmount.
 */
#define DC_BITMAP_LOADING      ((dc_alloc_bitmap*)(LONG_PTR)-2)
#define DC_BITMAP_INIT_FAILED  ((dc_alloc_bitmap*)(LONG_PTR)-1)

/* Check if bitmap pointer is valid (not NULL and not a sentinel) */
#define DC_BITMAP_IS_VALID(bmp)  ((bmp) != NULL && (bmp) != DC_BITMAP_INIT_FAILED && (bmp) != DC_BITMAP_LOADING)

/*
 * Create empty bitmap and start write monitoring.
 * Returns ST_OK on success, ST_ERROR if unsupported filesystem, ST_NOMEM if allocation fails.
 * Supports NTFS, ReFS, FAT12/FAT16 (DC_FS_FAT16), FAT32, and exFAT.
 * After this call, all bits are 0 (unallocated) and loading flag is set.
 * On success *out_bmp receives the published bitmap; use it instead of re-reading
 * hook->alloc_bitmap (dc_bitmap_free may already have taken it).
 */
int dc_bitmap_create(struct _dev_hook *hook, dc_alloc_bitmap **out_bmp);

/*
 * Load disk bitmap in parallel (called from worker thread).
 * Reads the file system's live allocation state (FSCTL_GET_VOLUME_BITMAP); any doubt
 * disables the optimisation.
 * Sets corresponding bits to 1 for allocated clusters.
 * Clears loading flag when done.
 */
void dc_bitmap_load_from_disk(struct _dev_hook *hook);

/*
 * Free bitmap and release resources.
 * Also clears DC_BITMAP_INIT_FAILED sentinel if set.
 */
void dc_bitmap_free(struct _dev_hook *hook);

/*
 * Start lazy bitmap initialization in a worker thread.
 * Called during transcryption when WP_SKIP_UNUSED is set but bitmap is NULL.
 * Sets alloc_bitmap to DC_BITMAP_INIT_FAILED if initialization fails.
 */
void dc_bitmap_start_init(struct _dev_hook *hook);

/*
 * Check if any sector in the given range is allocated.
 * Returns TRUE if allocated (should be encrypted), FALSE if unallocated (can skip).
 * Returns TRUE if no bitmap exists or bitmap is still loading (safe default).
 * Concurrent build: the caller must hold hook->trans.range_lock (the skip test and the
 * boundary advance in dc_transcrypt_step form one section; it also keeps the bitmap
 * from being freed).
 */
BOOLEAN dc_bitmap_is_allocated(struct _dev_hook *hook, u64 offset, u32 size);

/*
 * Mark sectors in the given range as allocated (volume offsets; clamped to the cluster area).
 * Concurrent build: called for tracked writes at admission (io_read_write_irp); the
 * caller must hold hook->trans.range_lock (also keeps the bitmap from being freed).
 */
void dc_bitmap_mark_allocated(struct _dev_hook *hook, u64 offset, u32 size);

#ifdef DC_AGGRESSIVE_SKIP

/*
 * Get the length of consecutive unallocated space starting at offset (forward scan).
 * Returns 0 if offset is allocated (caller should process normally).
 * Returns unallocated length in bytes if offset is unallocated (caller can skip).
 */
u64 dc_bitmap_get_unallocated(struct _dev_hook *hook, u64 offset);

/*
 * Get the length of consecutive unallocated space ending at end_offset (backward scan).
 * Returns 0 if position before end_offset is allocated (caller should process normally).
 * Returns unallocated length in bytes if position is unallocated (caller can skip).
 * Used for decryption which processes backward from high to low offsets.
 */
u64 dc_bitmap_get_unallocated_backward(struct _dev_hook *hook, u64 end_offset);

#endif

#endif /* _ALLOC_BITMAP_H_ */
