#include <Library/BaseMemoryLib.h>

#include "include\defines.h"
#include "include\volume_header.h"
#include "include\bootloader.h"
#include "include\dc_header.h"
#include "include\dc_io.h"

/*
 * intersect - Calculate the intersection of two sector ranges
 *
 * Given two ranges [start1, start1 + size1) and [start2, start2 + size2),
 * this function computes their intersection (overlap). Used to determine
 * which portion of an I/O request falls within a specific partition region.
 *
 * Example:
 *   Range 1 (I/O request): [100, 200)  (start1=100, size1=100)
 *   Range 2 (partition region): [150, 300)  (start2=150, size2=150)
 *   Intersection: [150, 200) -> i_st=150, returns 50
 *
 *   Range 1: |--------|
 *   Range 2:     |----------|
 *   Result:      |---|
 *            100 150  200  300
 *
 * @param i_st    Output: starting sector position of the intersection
 * @param start1  Start of the first range (typically the I/O request offset)
 * @param size1   Size of the first range in sectors (I/O request size)
 * @param start2  Start of the second range (partition region start)
 * @param size2   Size of the second range in sectors (partition region size)
 * @return        Size of the intersection in sectors (0 if no overlap)
 */
static u16 intersect(u64 *i_st, u64 start1, u32 size1, u64 start2, u64 size2)
{
	u64 end, i;

	/* Intersection end: minimum of both range ends */
	end = min(start1 + size1, start2 + size2);

	/* Intersection start: maximum of both range starts */
	*i_st = i = max(start1, start2);

	/* Return intersection size, or 0 if ranges don't overlap (start >= end) */
	return d16((i < end) ? end - i : 0);
}

/*
 * dc_crypt_io - Perform encrypted I/O on a partition's data region
 *
 * This function handles transparent encryption/decryption for disk I/O operations.
 * It uses XTS mode encryption with the provided key to protect data at rest.
 *
 * For reads:  disk -> buffer -> decrypt -> caller receives plaintext
 * For writes: plaintext -> encrypt -> disk, then decrypt buffer to preserve original
 *
 * The XTS tweak value is derived from the sector offset, ensuring each sector
 * is encrypted with a unique tweak for protection against copy/move attacks.
 *
 * Note: On write, the buffer is re-decrypted after writing to preserve the
 * original plaintext data for the caller (e.g., for caching or retry scenarios).
 *
 * @param mount   Mount information containing partition geometry and BlockIo
 * @param buff    Buffer for data transfer (plaintext on entry/exit)
 * @param sectors Number of sectors to transfer
 * @param start   Starting sector offset relative to partition begin (partition-relative LBA)
 * @param read    1 for read operation, 0 for write operation
 * @param key     XTS encryption key to use for this I/O
 * @return        1 on success, 0 on failure
 */
static int dc_crypt_io(mount_inf *mount, u8 *buff, u16 sectors, u64 start, int read, xts_key *key)
{
	int succs;

	if (read != 0)
	{
		/* read from partition - start is partition-relative */
		succs = dc_direct_io(mount, buff, sectors, start, 1);

		/* decrypt buffer */
		xts_decrypt(buff, buff, (sectors * mount->bps), (start * mount->bps), key);
	}
	else
	{
		/* encrypt buffer for writing */
		xts_encrypt(buff, buff, (sectors * mount->bps), (start * mount->bps), key);

		/* write buffer to partition - start is partition-relative */
		succs = dc_direct_io(mount, buff, sectors, start, 0);

		/* decrypt buffer to keep it plaintext */
		xts_decrypt(buff, buff, (sectors * mount->bps), (start * mount->bps), key);
	}

	return succs;
}

/*
 * dc_mount_io - Handle I/O for a mounted encrypted partition
 *
 * This function routes read/write requests to the appropriate handler based on
 * which region of the partition is being accessed. The partition is divided into
 * up to four distinct regions.
 *
 * Note: 'size' below refers to mount->size which is the partition size.
 *
 * Partition layout (normal mode):
 *   [0 ... head_len)                        -> Primary header (redirected to storage)
 *   [head_len ... size)                     -> Encrypted data
 *
 * Partition layout (normal mode with backup header):
 *   [0 ... head_len)                        -> Primary header (redirected to storage)
 *   [head_len ... size - head_len)          -> Encrypted data
 *   [size - head_len ... size)              -> Backup header (redirected to storage)
 *
 * Partition layout (temp/reencrypt mode):
 *   [0 ... head_len)                        -> Primary header (redirected to storage)
 *   [head_len ... tmp_size)                 -> Encrypted with current key
 *   [tmp_size ... size)                     -> Encrypted with old key (reencrypt) or plaintext
 *
 * Partition layout (temp/reencrypt mode with backup header):
 *   [0 ... head_len)                        -> Primary header (redirected to storage)
 *   [head_len ... tmp_size)                 -> Encrypted with current key
 *   [tmp_size ... size - head_len)          -> Encrypted with old key (reencrypt) or plaintext
 *   [size - head_len ... size)              -> Backup header (redirected to storage)
 *
 * Storage area layout (when backup header enabled):
 *   [stor_off ... stor_off + head_len)      -> Primary header data
 *   [stor_off + stor_len - head_len ... stor_off + stor_len) -> Backup header data
 *
 * @param mount   Mount information structure containing partition geometry and keys
 * @param buff    Buffer for data to read into or write from
 * @param sectors Number of sectors to transfer
 * @param start   Starting sector offset relative to partition begin
 * @param read    1 for read operation, 0 for write operation
 * @return        1 on success, 0 on failure
 */
int dc_mount_io(mount_inf *mount, u8 *buff, u16 sectors, u64 start, int read)
{
	/* Intersection offsets - absolute start position within each region */
	u64 primary_hdr_offset;
	u64 encrypted_data_offset;
	u64 tail_region_offset;
	u64 backup_hdr_offset;

	/* Intersection sizes - number of sectors overlapping each region */
	u16 primary_hdr_sectors;
	u16 encrypted_data_sectors;
	u16 tail_region_sectors;
	u16 backup_hdr_sectors;

	/* Buffer pointers for each region's data */
	u8 *encrypted_data_buff;
	u8 *tail_region_buff;
	u8 *backup_hdr_buff;

	int result;

	/* Check if backup header redirection is enabled */
	int has_backup_header = (mount->flags & VF_STORAGE_FILE) && (mount->flags & VF_BACKUP_HEADER);

	/* Backup header starts at head_len sectors before partition end */
	u64 backup_hdr_start = mount->size - mount->head_len;

	/* Calculate intersection with primary header region [0, head_len) */
	primary_hdr_sectors = intersect(&primary_hdr_offset, start, sectors, 0, mount->head_len);

	if (mount->flags & VF_TMP_MODE) {
		/*
		 * Temporary/reencryption mode:
		 * - Encrypted data uses current key from head_len to tmp_size
		 * - Tail region uses old key (reencrypt) or is plaintext
		 */
		encrypted_data_sectors = intersect(&encrypted_data_offset, start, sectors,
		                                   mount->head_len, (mount->tmp_size - mount->head_len));
		if (has_backup_header) {
			/* Tail region excludes the backup header at the end */
			tail_region_sectors = intersect(&tail_region_offset, start, sectors,
			                                mount->tmp_size, backup_hdr_start - mount->tmp_size);
			backup_hdr_sectors = intersect(&backup_hdr_offset, start, sectors,
			                               backup_hdr_start, mount->head_len);
		} else {
			tail_region_sectors = intersect(&tail_region_offset, start, sectors,
			                                mount->tmp_size, mount->size - mount->tmp_size);
			backup_hdr_sectors = 0;
		}
	} else {
		if (has_backup_header) {
			/*
			 * Backup header mode:
			 * - Encrypted data region is reduced to exclude backup header space
			 * - Backup header at partition end is redirected to end of storage area
			 */
			encrypted_data_sectors = intersect(&encrypted_data_offset, start, sectors,
			                                   mount->head_len, mount->size - 2 * mount->head_len);
			backup_hdr_sectors = intersect(&backup_hdr_offset, start, sectors,
			                               backup_hdr_start, mount->head_len);
		} else {
			/*
			 * Normal mode:
			 * - All data after header is encrypted
			 * - No backup header
			 */
			encrypted_data_sectors = intersect(&encrypted_data_offset, start, sectors,
			                                   mount->head_len, mount->size - mount->head_len);
			backup_hdr_sectors = 0;
		}
		tail_region_sectors = 0;
	}

	/* Calculate buffer offsets for each region (regions are contiguous in buffer) */
	encrypted_data_buff = buff + (primary_hdr_sectors * mount->bps);
	tail_region_buff = encrypted_data_buff + (encrypted_data_sectors * mount->bps);
	backup_hdr_buff = tail_region_buff + (tail_region_sectors * mount->bps);

	do
	{
		/* Handle primary header I/O - redirect to storage area */
		if (primary_hdr_sectors != 0)
		{
			u64 storage_offset = mount->stor_off + primary_hdr_offset;
			if ((result = dc_mount_io(mount, buff, primary_hdr_sectors, storage_offset, read)) == 0) {
				break;
			}
		}

		/* Handle encrypted data I/O - decrypt on read, encrypt on write */
		if (encrypted_data_sectors != 0)
		{
			if ((result = dc_crypt_io(mount, encrypted_data_buff, encrypted_data_sectors,
			                          encrypted_data_offset, read, mount->d_key)) == 0) {
				break;
			}
		}

		/* Handle tail region I/O - either reencrypt with old key or plaintext */
		if (tail_region_sectors != 0)
		{
			if (mount->flags & VF_REENCRYPT) {
				result = dc_crypt_io(mount, tail_region_buff, tail_region_sectors,
				                     tail_region_offset, read, mount->o_key);
			} else {
				/* Plaintext region - direct I/O with partition-relative offset */
				result = dc_direct_io(mount, tail_region_buff, tail_region_sectors,
				                tail_region_offset, read);
			}
		}

		/* Handle backup header I/O - redirect to end of storage area */
		if (backup_hdr_sectors != 0)
		{
			/*
			 * Map partition end to storage end:
			 * [size - head_len ... size) -> [stor_off + stor_len - head_len ... stor_off + stor_len)
			 */
			u64 offset_within_backup = backup_hdr_offset - backup_hdr_start;
			u64 storage_offset = mount->stor_off + mount->stor_len - mount->head_len + offset_within_backup;
			if ((result = dc_mount_io(mount, backup_hdr_buff, backup_hdr_sectors, storage_offset, read)) == 0) {
				break;
			}
		}
	} while (0);

	return result;
}