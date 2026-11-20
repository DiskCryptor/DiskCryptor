/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2019-2026
	* DavidXanatos <info@diskcryptor.org>
    * Copyright (c) 2008-2010
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
#include <ntstrsafe.h>
#include "defines.h"
#include "devhook.h"
#include "misc.h"
#include "debug.h"
#include "storage.h"
#include "misc_mem.h"
#include "device_io.h"

#pragma pack (push, 1)

typedef struct _fat_bpb {
	s8	ignored[3];	/* Boot strap short or near jump */
	s8	system_id[8];	/* Name - can be used to special case
				   partition manager volumes */
	u8	bytes_per_sect[2];	/* bytes per logical sector */
	u8	sects_per_clust;/* sectors/cluster */
	u16	reserved_sects;	/* reserved sectors */
	u8	num_fats;	/* number of FATs */
	u16	dir_entries;	/* root directory entries */
	u8	short_sectors[2];	/* number of sectors */
	u8	media;		/* media code (unused) */
	u16	fat_length;	/* sectors/FAT */
	u16	secs_track;	/* sectors per track */
	u16	heads;		/* number of heads */
	u32	hidden;		/* hidden sectors (unused) */
	u32	long_sectors;	/* number of sectors (if short_sectors == 0) */

	/* The following fields are only used by FAT32 */
	u32	fat32_length;	/* sectors/FAT */
	u16	flags;		   /* bit 8: fat mirroring, low 4: active fat */
	u8	version[2];	   /* major, minor filesystem version */
	u32	root_cluster;	/* first cluster in root directory */
	u16	info_sector;	/* filesystem info sector */
	u16	backup_boot;	/* backup boot sector */
	u16	reserved2[6];	/* Unused */

} fat_bpb;

typedef struct exfat_bpb {
	u8	jmp_boot[3];	     /* boot strap short or near jump */
	u8	oem_id[8];		     /* oem-id */
	u8	unused0;		     /* 0x00... */
	u32	unused1[13];
	u64	start_sector;		 /* start sector of partition */
	u64	nr_sectors;		     /* number of sectors of partition */
	u32	fat_blocknr;		 /* start blocknr of FAT */
	u32	fat_block_counts;	 /* number of FAT blocks */
	u32	clus_blocknr;		 /* start blocknr of cluster */
	u32	total_clusters;		 /* number of total clusters */
	u32	rootdir_clusnr;		 /* start clusnr of rootdir */
	u32	serial_number;		 /* volume serial number */
	u8	xxxx01;			     /* ??? (0x00 or any value (?)) */
	u8	xxxx02;			     /* ??? (0x01 or 0x00 (?)) */
	u16	state;			     /* state of this volume */
	u8	blocksize_bits;		 /* bits of block size */
	u8	block_per_clus_bits; /* bits of blocks per cluster */
	u8	xxxx03;			     /* ??? (0x01 or 0x00 (?)) */
	u8	xxxx04;			     /* ??? (0x80 or any value (?)) */
	u8	allocated_percent;	 /* percentage of allocated space (?) */
	u8	xxxx05[397];		 /* ??? (0x00...) */
	u16	signature;		     /* 0xaa55 */

} exfat_bpb; 

#pragma pack (pop)

#define FAT_DIRENTRY_LENGTH 32
#define MAX_RETRY           128

/* NTFS FSCTL codes */
#ifndef FSCTL_GET_NTFS_VOLUME_DATA
#define FSCTL_GET_NTFS_VOLUME_DATA CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 25, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

/* ReFS FSCTL code */
#ifndef FSCTL_GET_REFS_VOLUME_DATA
#define FSCTL_GET_REFS_VOLUME_DATA CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 182, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

/* NTFS volume data structure for slack detection */
typedef struct _DC_NTFS_VOL_DATA {
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
} DC_NTFS_VOL_DATA;

/* ReFS volume data structure for slack detection */
typedef struct _DC_REFS_VOL_DATA {
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
    USHORT        MetadataChecksumType;
    USHORT        Reserved0;
    ULONG         Reserved1;
} DC_REFS_VOL_DATA;

/*
 * NUL-terminate FileSystemName inside a FileFsAttributeInformation query buffer of
 * buf_size bytes. A name that exactly fills the buffer is truncated by one character
 * (it can never match a supported FS name).
 */
static void dc_term_fs_name(PFILE_FS_ATTRIBUTE_INFORMATION inf, u32 buf_size)
{
	u32 cap = (buf_size - (u32)FIELD_OFFSET(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName)) / (u32)sizeof(WCHAR);
	u32 len = (u32)inf->FileSystemNameLength / (u32)sizeof(WCHAR);

	inf->FileSystemName[min(len, cap - 1)] = 0;
}

/*
 * Calculate volume slack - space between filesystem end and partition end.
 * Uses FSCTL queries for NTFS/ReFS, boot sector parsing for FAT/exFAT.
 * Returns ST_OK and sets *slack_size, or error code if size cannot be determined.
 */
int dc_get_volume_slack(dev_hook *hook, u64 *slack_size)
{
    u8                             fs_buf[sizeof(FILE_FS_ATTRIBUTE_INFORMATION) + 0x20];
    PFILE_FS_ATTRIBUTE_INFORMATION fs_info = pv(fs_buf);
    DC_NTFS_VOL_DATA               ntfs_data;
    DC_REFS_VOL_DATA               refs_data;
    IO_STATUS_BLOCK                iosb;
    HANDLE                         h_dev;
    NTSTATUS                       status;
    u64                            fs_total_size = 0;
    void                          *head = NULL;
    LARGE_INTEGER                  vofs = {0};

    *slack_size = 0;

    /* Open volume device */
    if ((h_dev = io_open_device(hook->dev_name)) == NULL) {
        DbgMsg("dc_get_volume_slack: failed to open device\n");
        return ST_IO_ERROR;
    }

    /* Query filesystem type */
    status = ZwQueryVolumeInformationFile(
        h_dev, &iosb, fs_info, sizeof(fs_buf), FileFsAttributeInformation);

    if (!NT_SUCCESS(status)) {
        ZwClose(h_dev);
        DbgMsg("dc_get_volume_slack: FileFsAttributeInformation failed, status=%08x\n", status);
        return ST_UNK_FS;
    }
    dc_term_fs_name(fs_info, (u32)sizeof(fs_buf));

    DbgMsg("dc_get_volume_slack: filesystem=%ws\n", fs_info->FileSystemName);

    /* Get filesystem total size based on type */
    if (_wcsicmp(fs_info->FileSystemName, L"NTFS") == 0) {
        status = ZwFsControlFile(h_dev, NULL, NULL, NULL, &iosb,
            FSCTL_GET_NTFS_VOLUME_DATA, NULL, 0, &ntfs_data, sizeof(ntfs_data));
        if (NT_SUCCESS(status)) {
            /*
             * NTFS reserves space at the end of the partition for a backup copy
             * of the boot sector. This backup is stored in the last sector of
             * the partition (not the last sector of the filesystem).
             *
             * The filesystem size is TotalClusters * BytesPerCluster, but we must
             * NOT use the last sector of the partition as it contains the backup
             * boot sector. Add one cluster to the "used" size to protect it.
             */
            fs_total_size = (u64)ntfs_data.TotalClusters.QuadPart *
                           (u64)ntfs_data.BytesPerCluster;
            /* Reserve at least one cluster for NTFS backup boot sector */
            fs_total_size += ntfs_data.BytesPerCluster;
            DbgMsg("dc_get_volume_slack: NTFS TotalClusters=%I64u, BytesPerCluster=%u (reserved extra cluster for backup boot sector)\n",
                   ntfs_data.TotalClusters.QuadPart, ntfs_data.BytesPerCluster);
        } else {
            DbgMsg("dc_get_volume_slack: FSCTL_GET_NTFS_VOLUME_DATA failed, status=%08x\n", status);
        }
    }
    else if (_wcsicmp(fs_info->FileSystemName, L"ReFS") == 0) {
        status = ZwFsControlFile(h_dev, NULL, NULL, NULL, &iosb,
            FSCTL_GET_REFS_VOLUME_DATA, NULL, 0, &refs_data, sizeof(refs_data));
        if (NT_SUCCESS(status)) {
            fs_total_size = (u64)refs_data.TotalClusters.QuadPart *
                           (u64)refs_data.BytesPerCluster;
            DbgMsg("dc_get_volume_slack: ReFS TotalClusters=%I64u, BytesPerCluster=%u\n",
                   refs_data.TotalClusters.QuadPart, refs_data.BytesPerCluster);
        } else {
            DbgMsg("dc_get_volume_slack: FSCTL_GET_REFS_VOLUME_DATA failed, status=%08x\n", status);
        }
    }
    else if (_wcsicmp(fs_info->FileSystemName, L"FAT") == 0 ||
             _wcsicmp(fs_info->FileSystemName, L"FAT32") == 0) {
        /* Parse FAT boot sector - use existing fat_bpb structure */
        if ((head = mm_pool_alloc(hook->bps)) != NULL) {
            if (NT_SUCCESS(ZwReadFile(h_dev, NULL, NULL, NULL, &iosb,
                                       head, hook->bps, &vofs, NULL))) {
                fat_bpb *bpb = (fat_bpb*)head;
                u32 total_sectors = bpb->short_sectors[0] | (bpb->short_sectors[1] << 8);
                if (total_sectors == 0) total_sectors = bpb->long_sectors;
                fs_total_size = (u64)total_sectors * (u64)hook->bps;
                DbgMsg("dc_get_volume_slack: FAT total_sectors=%u\n", total_sectors);
            }
            mm_pool_free(head);
        }
    }
    else if (_wcsicmp(fs_info->FileSystemName, L"exFAT") == 0) {
        /* Parse exFAT boot sector - use existing exfat_bpb structure */
        if ((head = mm_pool_alloc(hook->bps)) != NULL) {
            if (NT_SUCCESS(ZwReadFile(h_dev, NULL, NULL, NULL, &iosb,
                                       head, hook->bps, &vofs, NULL))) {
                exfat_bpb *bpb = (exfat_bpb*)head;
                fs_total_size = bpb->nr_sectors * (u64)hook->bps;
                DbgMsg("dc_get_volume_slack: exFAT nr_sectors=%I64u\n", bpb->nr_sectors);
            }
            mm_pool_free(head);
        }
    }

    ZwClose(h_dev);

    /* Calculate slack if we got the filesystem size */
    if (fs_total_size > 0 && fs_total_size < hook->dsk_size) {
        *slack_size = hook->dsk_size - fs_total_size;
        DbgMsg("dc_get_volume_slack: fs_size=%I64u, dsk_size=%I64u, slack=%I64u\n",
               fs_total_size, hook->dsk_size, *slack_size);
        return ST_OK;
    }

    DbgMsg("dc_get_volume_slack: no slack (fs_size=%I64u, dsk_size=%I64u)\n",
           fs_total_size, hook->dsk_size);
    return ST_OK; /* Return OK with slack=0 */
}

/* FSCTL_SHRINK_VOLUME control code */
#ifndef FSCTL_SHRINK_VOLUME
#define FSCTL_SHRINK_VOLUME CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 108, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

/* Shrink request types */
typedef enum _DC_SHRINK_REQUEST_TYPE {
    DcShrinkPrepare = 1,
    DcShrinkCommit,
    DcShrinkAbort
} DC_SHRINK_REQUEST_TYPE;

/* Shrink volume information structure */
typedef struct _DC_SHRINK_VOLUME_INFO {
    DC_SHRINK_REQUEST_TYPE ShrinkRequestType;
    DWORDLONG              Flags;
    LONGLONG               NewNumberOfSectors;
} DC_SHRINK_VOLUME_INFO;

/*
 * Try to shrink the filesystem to create slack space at the end.
 * This only works for NTFS when there are no files in the area to be reclaimed.
 * Returns ST_OK if shrink succeeded, error code otherwise.
 */
int dc_try_shrink_fs(dev_hook *hook, u64 shrink_bytes)
{
    u8                             fs_buf[sizeof(FILE_FS_ATTRIBUTE_INFORMATION) + 0x20];
    PFILE_FS_ATTRIBUTE_INFORMATION fs_info = pv(fs_buf);
    DC_NTFS_VOL_DATA               ntfs_data;
    DC_SHRINK_VOLUME_INFO          shrink_info;
    IO_STATUS_BLOCK                iosb;
    HANDLE                         h_dev;
    NTSTATUS                       status;
    u64                            new_sectors;
    u64                            current_sectors;

    DbgMsg("dc_try_shrink_fs: attempting to shrink by %I64u bytes\n", shrink_bytes);

    /* Open volume device */
    if ((h_dev = io_open_device(hook->dev_name)) == NULL) {
        DbgMsg("dc_try_shrink_fs: failed to open device\n");
        return ST_IO_ERROR;
    }

    /* Query filesystem type - only NTFS is supported for shrinking */
    status = ZwQueryVolumeInformationFile(
        h_dev, &iosb, fs_info, sizeof(fs_buf), FileFsAttributeInformation);

    if (!NT_SUCCESS(status)) {
        ZwClose(h_dev);
        DbgMsg("dc_try_shrink_fs: FileFsAttributeInformation failed\n");
        return ST_UNK_FS;
    }
    dc_term_fs_name(fs_info, (u32)sizeof(fs_buf));

    if (_wcsicmp(fs_info->FileSystemName, L"NTFS") != 0) {
        ZwClose(h_dev);
        DbgMsg("dc_try_shrink_fs: only NTFS is supported, got %ws\n", fs_info->FileSystemName);
        return ST_UNK_FS;
    }

    /* Get current NTFS volume data */
    status = ZwFsControlFile(h_dev, NULL, NULL, NULL, &iosb,
        FSCTL_GET_NTFS_VOLUME_DATA, NULL, 0, &ntfs_data, sizeof(ntfs_data));

    if (!NT_SUCCESS(status)) {
        ZwClose(h_dev);
        DbgMsg("dc_try_shrink_fs: FSCTL_GET_NTFS_VOLUME_DATA failed, status=%08x\n", status);
        return ST_ERROR;
    }

    current_sectors = (u64)ntfs_data.NumberSectors.QuadPart;

    /*
     * Calculate new number of sectors after shrink.
     * We need to shrink by shrink_bytes PLUS one cluster to account for
     * the NTFS backup boot sector that Windows places at the end of the
     * partition. dc_get_volume_slack reserves this cluster, so we need
     * to create extra space for it.
     */
    shrink_bytes += ntfs_data.BytesPerCluster;

    if (shrink_bytes % ntfs_data.BytesPerSector != 0) {
        /* Round up shrink_bytes to full sectors */
        shrink_bytes = ((shrink_bytes / ntfs_data.BytesPerSector) + 1) * ntfs_data.BytesPerSector;
    }

    new_sectors = current_sectors - (shrink_bytes / ntfs_data.BytesPerSector);

    if (new_sectors >= current_sectors) {
        ZwClose(h_dev);
        DbgMsg("dc_try_shrink_fs: invalid shrink size\n");
        return ST_INVALID_PARAM;
    }

    DbgMsg("dc_try_shrink_fs: current_sectors=%I64u, new_sectors=%I64u\n",
           current_sectors, new_sectors);

    /* Step 1: ShrinkPrepare */
    memset(&shrink_info, 0, sizeof(shrink_info));
    shrink_info.ShrinkRequestType = DcShrinkPrepare;
    shrink_info.NewNumberOfSectors = (LONGLONG)new_sectors;

    status = ZwFsControlFile(h_dev, NULL, NULL, NULL, &iosb,
        FSCTL_SHRINK_VOLUME, &shrink_info, sizeof(shrink_info), NULL, 0);

    if (!NT_SUCCESS(status)) {
        ZwClose(h_dev);
        DbgMsg("dc_try_shrink_fs: ShrinkPrepare failed, status=%08x (files at end?)\n", status);
        return ST_CLUS_USED; /* Files exist in the area to shrink */
    }

    /* Step 2: ShrinkCommit */
    memset(&shrink_info, 0, sizeof(shrink_info));
    shrink_info.ShrinkRequestType = DcShrinkCommit;
    shrink_info.NewNumberOfSectors = 0; /* Must be 0 for commit */

    status = ZwFsControlFile(h_dev, NULL, NULL, NULL, &iosb,
        FSCTL_SHRINK_VOLUME, &shrink_info, sizeof(shrink_info), NULL, 0);

    if (!NT_SUCCESS(status)) {
        /* Try to abort */
        shrink_info.ShrinkRequestType = DcShrinkAbort;
        ZwFsControlFile(h_dev, NULL, NULL, NULL, &iosb,
            FSCTL_SHRINK_VOLUME, &shrink_info, sizeof(shrink_info), NULL, 0);
        ZwClose(h_dev);
        DbgMsg("dc_try_shrink_fs: ShrinkCommit failed, status=%08x\n", status);
        return ST_ERROR;
    }

    ZwClose(h_dev);
    DbgMsg("dc_try_shrink_fs: successfully shrunk filesystem by %I64u bytes\n", shrink_bytes);
    return ST_OK;
}

static int dc_fill_dcsys(HANDLE h_file, u32 *stor_len)
{
	FILE_FS_SIZE_INFORMATION info;
	IO_STATUS_BLOCK          iosb;
	NTSTATUS                 status;
	u32                      length;
	void                    *buff;
	u64                      state = COMPRESSION_FORMAT_NONE;

	status = ZwQueryVolumeInformationFile(
		h_file, &iosb, &info, sizeof(info), FileFsSizeInformation);

	if (NT_SUCCESS(status) == FALSE) {
		return 0;
	} else {
		length = ROUND_TO_FULL_SECTORS(*stor_len, info.SectorsPerAllocationUnit * info.BytesPerSector);
		*stor_len = length;
	}
	if ( (buff = mm_pool_alloc(length)) == NULL )
	{
		return 0;
	}
	memset(buff, 0, length);
	
	ZwFsControlFile(h_file, NULL, NULL, NULL, &iosb, FSCTL_SET_COMPRESSION, &state, sizeof(state), NULL, 0);
	status = ZwWriteFile(h_file, NULL, NULL, NULL, &iosb, buff, length, NULL, NULL);

	mm_pool_free(buff);
	return NT_SUCCESS(status) != FALSE;
}

NTSTATUS dc_delete_file(HANDLE h_file)
{
	FILE_BASIC_INFORMATION       binf = { {0}, {0}, {0}, {0}, FILE_ATTRIBUTE_NORMAL };
	FILE_DISPOSITION_INFORMATION dinf = { TRUE };
	IO_STATUS_BLOCK              iosb;

	ZwSetInformationFile(h_file, &iosb, &binf, sizeof(binf), FileBasicInformation);
	return ZwSetInformationFile(h_file, &iosb, &dinf, sizeof(dinf), FileDispositionInformation);
}

static void dc_rename_file(dev_hook *hook, HANDLE h_file, const wchar_t *name)
{
	char                     buff[sizeof(FILE_RENAME_INFORMATION) + 64];
	PFILE_RENAME_INFORMATION info = pv(buff);
	IO_STATUS_BLOCK          iosb;

	info->ReplaceIfExists = TRUE;
	info->RootDirectory   = NULL;
	RtlStringCchPrintfW(info->FileName, 32, L"%s_fail_%x", name, (u32)__rdtsc());
	info->FileNameLength = (ULONG)(wcslen(info->FileName) * sizeof(wchar_t));

	/* the minifilter denies renaming $dcsys$ for every thread but the worker thread */
	hook->wrk_thread_id = PsGetCurrentThreadId();
	ZwSetInformationFile(h_file, &iosb, info, sizeof(buff), FileRenameInformation);
	hook->wrk_thread_id = NULL;
}

/*
 * Explicit descriptor for a NEW $dcsys$: SYSTEM full access, Administrators read, protected
 * (no inheritance of the root ACL). With the inherited root ACL any user could open or
 * hard-link the new file before the minifilter protection is armed and keep that handle /
 * link. The driver's own opens are kernel-mode (no access check). FAT/exFAT have no ACLs:
 * there the minifilter is the only protection.
 */
typedef struct _dcsys_sd {
	SECURITY_DESCRIPTOR sd;
	ULONG               acl_buf[32];  /* 128 bytes, ULONG aligned; two ACEs need ~52 */
} dcsys_sd;

static BOOLEAN dc_build_dcsys_sd(dcsys_sd *dsd)
{
	PACL  acl = (PACL)dsd->acl_buf;
	PSID  sys_sid = SeExports->SeLocalSystemSid;
	PSID  adm_sid = SeExports->SeAliasAdminsSid;
	ULONG acl_len;

	acl_len = (ULONG)(sizeof(ACL) +
		(sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG) + RtlLengthSid(sys_sid)) +
		(sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG) + RtlLengthSid(adm_sid)));
	acl_len = (acl_len + 3) & ~3UL;

	if (acl_len > sizeof(dsd->acl_buf)) return FALSE;

	if ( !NT_SUCCESS(RtlCreateAcl(acl, acl_len, ACL_REVISION)) ||
		 !NT_SUCCESS(RtlAddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS, sys_sid)) ||
		 !NT_SUCCESS(RtlAddAccessAllowedAce(acl, ACL_REVISION, FILE_GENERIC_READ, adm_sid)) ||
		 !NT_SUCCESS(RtlCreateSecurityDescriptor(&dsd->sd, SECURITY_DESCRIPTOR_REVISION)) ||
		 !NT_SUCCESS(RtlSetDaclSecurityDescriptor(&dsd->sd, TRUE, acl, FALSE)) )
	{
		return FALSE;
	}
	dsd->sd.Control |= SE_DACL_PROTECTED;
	return TRUE;
}

/* $dcsys$ or $dclog$: the storage files are created / opened the same way */
static HANDLE dc_create_named(dev_hook *hook, const wchar_t *name, u32 *stor_len)
{
	OBJECT_ATTRIBUTES obj_a;
	UNICODE_STRING    u_name;
	IO_STATUS_BLOCK   iosb;
	wchar_t           buff[MAX_PATH];
	HANDLE            h_file;
	NTSTATUS          status;
	dcsys_sd          dsd;
	PVOID             sd = NULL;

	status = RtlStringCchPrintfW(buff, MAX_PATH, L"%s\\%s", hook->dev_name, name);
	if (NT_SUCCESS(status) == FALSE) return NULL;

	/* a new file (stor_len != NULL: FILE_CREATE) gets the protected descriptor; if it
	 * cannot be built the root ACL is inherited (the minifilter still applies) */
	if (stor_len != NULL) {
		if (dc_build_dcsys_sd(&dsd)) {
			sd = &dsd.sd;
		} else {
			DbgMsg("dc_create_dcsys: cannot build the security descriptor, dev=%ws\n", hook->dev_name);
		}
	}

	RtlInitUnicodeString(&u_name, buff);
	InitializeObjectAttributes(&obj_a, &u_name, OBJ_KERNEL_HANDLE, NULL, sd);

	hook->wrk_thread_id = PsGetCurrentThreadId();
	status = ZwCreateFile(&h_file, (stor_len == NULL ? FILE_WRITE_ATTRIBUTES | DELETE : GENERIC_WRITE), 
		&obj_a, &iosb, NULL, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY, 0, 
		(stor_len == NULL ? FILE_OPEN : FILE_CREATE), 
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_WRITE_THROUGH, NULL, 0);
	hook->wrk_thread_id = NULL;

	if (NT_SUCCESS(status) == FALSE) {
		return NULL;
	}
	if ( (stor_len != NULL) && (dc_fill_dcsys(h_file, stor_len) == 0) ) {
		dc_delete_file(h_file);
		ZwClose(h_file); h_file = NULL;
	}
	/* a new $dcsys$ (new file ID) exists, or the failed one is gone */
	InterlockedIncrement(&hook->stor_gen);
	return h_file;
}

static int dc_num_fragments(HANDLE h_file, u64 *cluster)
{
	char                       buff[sizeof(RETRIEVAL_POINTERS_BUFFER) + 16*4];
	STARTING_VCN_INPUT_BUFFER  svcn = {0};
	RETRIEVAL_POINTERS_BUFFER *prpb = pv(buff);
	IO_STATUS_BLOCK            iosb;
	NTSTATUS                   status;
	
	status = ZwFsControlFile(
		h_file, NULL, NULL, NULL, &iosb, FSCTL_GET_RETRIEVAL_POINTERS, &svcn, sizeof(svcn), prpb, sizeof(buff));

	if (NT_SUCCESS(status) != FALSE) {
		cluster[0] = prpb->Extents[0].Lcn.QuadPart; 
		return prpb->ExtentCount;
	}
	return 0;
}

static int dc_first_cluster_offset(HANDLE h_dev, u32 bps, u64 *offset)
{
	u8                             buff[sizeof(FILE_FS_ATTRIBUTE_INFORMATION) + 0x20];
	PFILE_FS_ATTRIBUTE_INFORMATION ainf = pv(buff);
	LARGE_INTEGER                  vofs = {0};
	IO_STATUS_BLOCK                iosb;
	void                          *head;
	int                            resl;
	
	if (NT_SUCCESS(ZwQueryVolumeInformationFile(
		           h_dev, &iosb, ainf, sizeof(buff), FileFsAttributeInformation)) == FALSE) 
	{
		return ST_ERROR;
	} else {
		dc_term_fs_name(ainf, (u32)sizeof(buff));
	}
	if (_wcsicmp(ainf->FileSystemName, L"NTFS") == 0) {
		*offset = 0; return ST_OK;
	}
	if ( (head = mm_pool_alloc(bps)) == NULL ) {
		return ST_NOMEM;
	}
	if (NT_SUCCESS(ZwReadFile(h_dev, NULL, NULL, NULL, &iosb, head, bps, &vofs, NULL)) == FALSE) {
		mm_pool_free(head); return ST_RW_ERR;
	}
	if ( (_wcsicmp(ainf->FileSystemName, L"FAT") == 0) || (_wcsicmp(ainf->FileSystemName, L"FAT32") == 0) )
	{
		fat_bpb *bpb = head;
		u32      fat_offset = bpb->reserved_sects;
		u32      fat_length = bpb->fat_length ? bpb->fat_length : bpb->fat32_length;
		u32      root_offs  = fat_offset + (bpb->num_fats * fat_length);
		u32      root_max, data_offs;

		if (root_max = bpb->dir_entries * FAT_DIRENTRY_LENGTH) {
			data_offs = root_offs + ((root_max - 1) / bps) + 1;
		} else {
			data_offs = root_offs;
		}
		*offset = data_offs; resl = ST_OK;
	} else if (_wcsicmp(ainf->FileSystemName, L"exFAT") == 0) {
		exfat_bpb *bpb = head; *offset = bpb->clus_blocknr; 
		resl = ST_OK;
	} else {
		resl = ST_UNK_FS;
	}
	mm_pool_free(head); return resl;
}

static int dc_cluster_to_offset(dev_hook *hook, HANDLE h_file, u64 cluster, u64 *offset)
{
	FILE_FS_SIZE_INFORMATION sinf;
	IO_STATUS_BLOCK          iosb;
	NTSTATUS                 status;
	int                      resl;
	RETRIEVAL_POINTER_BASE   base;
	HANDLE                   h_dev;
	
	if (NT_SUCCESS(ZwQueryVolumeInformationFile(
		           h_file, &iosb, &sinf, sizeof(sinf), FileFsSizeInformation)) == FALSE)
	{
		return ST_ERROR;
	}
	if ( (h_dev = io_open_device(hook->dev_name)) == NULL ) {
		return ST_IO_ERROR;
	}
	status = ZwFsControlFile(
		h_dev, NULL, NULL, NULL, &iosb, FSCTL_GET_RETRIEVAL_POINTER_BASE, NULL, 0, &base, sizeof(base));

	if (NT_SUCCESS(status) == FALSE) {
		resl = dc_first_cluster_offset(h_dev, sinf.BytesPerSector, &base.FileAreaOffset.QuadPart);
	} else {
		resl = ST_OK;
	}
	if (resl == ST_OK) 
	{
		*offset = (base.FileAreaOffset.QuadPart * d64(sinf.BytesPerSector)) + 
			      (cluster * d64(sinf.SectorsPerAllocationUnit) * d64(sinf.BytesPerSector));
	}	
	ZwClose(h_dev); return resl;
}

static void dc_delete_named(dev_hook *hook, const wchar_t *name);

/* a contiguous file outside the header areas: $dcsys$ (dc_create_storage) or $dclog$ */
/* max_try: attempts (0 or above MAX_RETRY: MAX_RETRY) - each failed one keeps its clusters
   (an open, deleted file) so that the next one lands elsewhere */
static int dc_create_contig(dev_hook *hook, const wchar_t *name, u64 *storage, u32 *stor_len, u32 margin, int max_try)
{
	HANDLE h_files[MAX_RETRY];
	u32    n_files = 0;
	HANDLE h_file  = NULL;
	u64    cluster;
	u64    offset;
	int    i, resl;

	if (max_try <= 0 || max_try > MAX_RETRY) max_try = MAX_RETRY;

	/* delete an old file of this name first */
	dc_delete_named(hook, name);

	/* try to create contiguous $dcsys$ file that doesn't overlap with header area */
	for (i = 0; ; i++)
	{
		if (h_file != NULL) {
			dc_rename_file(hook, h_file, name);
			dc_delete_file(h_file);
			h_files[n_files++] = h_file; h_file = NULL;
		}

		if (i >= max_try) {
			DbgMsg("%ws create failed after %d attempts\n", name, max_try);
			break;
		}

		if ( (h_file = dc_create_named(hook, name, stor_len)) == NULL ) {
			continue;
		}
		if (dc_num_fragments(h_file, &cluster) != 1) {
			continue;
		}
		if ( (resl = dc_cluster_to_offset(hook, h_file, cluster, &offset)) != ST_OK ) {
			dc_delete_file(h_file);
			ZwClose(h_file); h_file = NULL;
			continue;
		}

		/* check if storage offset is past the header area to prevent overlap */
		if (offset < margin) {
			DbgMsg("$dcsys$ offset %x:%0.8x overlaps header (margin=%x), retrying\n",
				d32(offset >> 32), d32(offset), d32(margin));
			continue;
		}

		/* check if storage overlaps with backup header at end of partition */
		if (offset + *stor_len > hook->dsk_size - margin) {
			DbgMsg("$dcsys$ offset %x:%0.8x overlaps backup (margin=%x), retrying\n",
				d32(offset >> 32), d32(offset), d32(margin));
			continue;
		}

		break;
	}
	/* close all failed handles */
	while (n_files != 0) {
		ZwClose(h_files[--n_files]);
	}
	/* failed attempts were renamed away from $dcsys$ and are deleted now */
	InterlockedIncrement(&hook->stor_gen);
	if (h_file == NULL) {
		return ST_CLUS_USED;
	}
	DbgMsg("%ws created, cluster %x:%0.8x; offset: %x:%0.8x\n", name,
		d32(cluster >> 32), d32(cluster), d32(offset >> 32), d32(offset));

	*storage = offset;
	ZwClose(h_file); return ST_OK;
}

int dc_create_storage(dev_hook *hook, u64 *storage, u32 *stor_len, u32 margin)
{
	return dc_create_contig(hook, L"$dcsys$", storage, stor_len, margin, MAX_RETRY);
}

/*
 * The $dclog$ journal of a power-loss protected session: contiguous, outside the header
 * areas (margin at both ends, like $dcsys$). A leftover $dclog$ is deleted first. *log_len in:
 * the minimum size, out: the size allocated (cluster multiple). Returns its partition offset.
 * max_try: attempts, 0 = the default (MAX_RETRY).
 */
int dc_create_log_file(dev_hook *hook, u64 *offset, u32 *log_len, u32 margin, int max_try)
{
	return dc_create_contig(hook, L"$dclog$", offset, log_len, margin, max_try);
}

void dc_delete_log_file(dev_hook *hook)
{
	dc_delete_named(hook, L"$dclog$");
}

static void dc_delete_named(dev_hook *hook, const wchar_t *name)
{
	HANDLE h_file;

	if (h_file = dc_create_named(hook, name, NULL)) {
		dc_delete_file(h_file);
		ZwClose(h_file);
		/* the file is deleted on this close */
		InterlockedIncrement(&hook->stor_gen);
	}
}

void dc_delete_storage(dev_hook *hook)
{
	dc_delete_named(hook, L"$dcsys$");
}

/*
 * Get the actual size of the $dcsys$ storage file.
 * The file size is rounded up to cluster boundaries, which may be larger
 * than the requested stor_len. This is needed for proper header v1->v2 upgrade.
 * Returns ST_OK and sets *size, or error code if file doesn't exist or can't be queried.
 */
int dc_get_storage_size(dev_hook *hook, u32 *stor_len)
{
	OBJECT_ATTRIBUTES        obj_a;
	UNICODE_STRING           u_name;
	IO_STATUS_BLOCK          iosb;
	FILE_STANDARD_INFORMATION finfo;
	wchar_t                  buff[MAX_PATH];
	HANDLE                   h_file;
	NTSTATUS                 status;

	status = RtlStringCchPrintfW(buff, MAX_PATH, L"%s\\$dcsys$", hook->dev_name);
	if (!NT_SUCCESS(status)) {
		return ST_ERROR;
	}

	RtlInitUnicodeString(&u_name, buff);
	InitializeObjectAttributes(&obj_a, &u_name, OBJ_KERNEL_HANDLE, NULL, NULL);

	/* Open file for reading attributes only */
	status = ZwCreateFile(&h_file, FILE_READ_ATTRIBUTES | SYNCHRONIZE,
		&obj_a, &iosb, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);

	if (!NT_SUCCESS(status)) {
		DbgMsg("dc_get_storage_size: failed to open $dcsys$, status=%08x\n", status);
		return ST_NF_FILE;
	}

	/* Query file size */
	status = ZwQueryInformationFile(h_file, &iosb, &finfo, sizeof(finfo), FileStandardInformation);
	ZwClose(h_file);

	if (!NT_SUCCESS(status)) {
		DbgMsg("dc_get_storage_size: failed to query file info, status=%08x\n", status);
		return ST_IO_ERROR;
	}

	if (finfo.AllocationSize.HighPart != 0) {
		DbgMsg("dc_get_storage_size: file size too large, size=%I64u\n", (u64)finfo.AllocationSize.QuadPart);
		return ST_ERROR;
	}

	*stor_len = (u32)finfo.AllocationSize.QuadPart;
	DbgMsg("dc_get_storage_size: $dcsys$ size=%I64u\n", (u64)finfo.AllocationSize.QuadPart);
	return ST_OK;
}

/*
 * Rename a storage file from old_name to new_name.
 * Used for safe storage relocation with rollback support.
 */
int dc_rename_storage(dev_hook *hook, wchar_t *old_name, wchar_t *new_name)
{
	OBJECT_ATTRIBUTES        obj_a;
	UNICODE_STRING           u_name;
	IO_STATUS_BLOCK          iosb;
	wchar_t                  buff[MAX_PATH];
	char                     ren_buff[sizeof(FILE_RENAME_INFORMATION) + MAX_PATH * sizeof(wchar_t)];
	PFILE_RENAME_INFORMATION ren_info = pv(ren_buff);
	HANDLE                   h_file;
	NTSTATUS                 status;

	status = RtlStringCchPrintfW(buff, MAX_PATH, L"%s\\%s", hook->dev_name, old_name);
	if (!NT_SUCCESS(status)) {
		return ST_ERROR;
	}

	RtlInitUnicodeString(&u_name, buff);
	InitializeObjectAttributes(&obj_a, &u_name, OBJ_KERNEL_HANDLE, NULL, NULL);

	/* Open file for rename */
	hook->wrk_thread_id = PsGetCurrentThreadId();
	status = ZwCreateFile(&h_file, DELETE | SYNCHRONIZE,
		&obj_a, &iosb, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
	hook->wrk_thread_id = NULL;

	if (!NT_SUCCESS(status)) {
		DbgMsg("dc_rename_storage: failed to open %ws, status=%08x\n", old_name, status);
		return ST_NF_FILE;
	}

	/* Set up rename info */
	ren_info->ReplaceIfExists = TRUE;
	ren_info->RootDirectory = NULL;
	RtlStringCchCopyW(ren_info->FileName, MAX_PATH, new_name);
	ren_info->FileNameLength = (ULONG)(wcslen(ren_info->FileName) * sizeof(wchar_t));

	/*
	 * The minifilter denies renames onto $dcsys$ / $dcbak$ in the volume root for every
	 * thread but the worker thread (kernel-mode requests included), so the rename (incl.
	 * the $dcbak$ -> $dcsys$ rollback of dc_apply_layout) runs as the worker thread.
	 */
	hook->wrk_thread_id = PsGetCurrentThreadId();
	status = ZwSetInformationFile(h_file, &iosb, ren_info, sizeof(ren_buff), FileRenameInformation);
	hook->wrk_thread_id = NULL;
	ZwClose(h_file);
	/* the storage file IDs may have changed (FAT: IDs follow the dirent) */
	InterlockedIncrement(&hook->stor_gen);

	if (!NT_SUCCESS(status)) {
		DbgMsg("dc_rename_storage: rename %ws to %ws failed, status=%08x\n", old_name, new_name, status);
		return ST_ERROR;
	}

	DbgMsg("dc_rename_storage: renamed %ws to %ws\n", old_name, new_name);
	return ST_OK;
}

/*
 * Delete a storage file by specific name (e.g., $dcsys$_old).
 * Used to cleanup old storage after successful relocation.
 */
void dc_delete_storage_by_name(dev_hook *hook, wchar_t *name)
{
	OBJECT_ATTRIBUTES obj_a;
	UNICODE_STRING    u_name;
	IO_STATUS_BLOCK   iosb;
	wchar_t           buff[MAX_PATH];
	HANDLE            h_file;
	NTSTATUS          status;

	status = RtlStringCchPrintfW(buff, MAX_PATH, L"%s\\%s", hook->dev_name, name);
	if (!NT_SUCCESS(status)) {
		return;
	}

	RtlInitUnicodeString(&u_name, buff);
	InitializeObjectAttributes(&obj_a, &u_name, OBJ_KERNEL_HANDLE, NULL, NULL);

	/* the minifilter protects $dcbak$ like $dcsys$ (it holds the live storage during
	 * dc_apply_layout relocation), so open it as the worker thread */
	hook->wrk_thread_id = PsGetCurrentThreadId();
	status = ZwCreateFile(&h_file, FILE_WRITE_ATTRIBUTES | DELETE | SYNCHRONIZE,
		&obj_a, &iosb, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
	hook->wrk_thread_id = NULL;

	if (!NT_SUCCESS(status)) {
		DbgMsg("dc_delete_storage_by_name: failed to open %ws, status=%08x\n", name, status);
		return;
	}

	status = dc_delete_file(h_file);
	ZwClose(h_file);
	/* the file is gone after this close */
	InterlockedIncrement(&hook->stor_gen);

	if (!NT_SUCCESS(status)) {
		DbgMsg("dc_delete_storage_by_name: failed to delete %ws, status=%08x\n", name, status);
	} else {
		DbgMsg("dc_delete_storage_by_name: deleted %ws\n", name);
	}
}

/*
 * Expand filesystem to reclaim slack space after moving storage to file.
 * This is the reverse of dc_try_shrink_fs - it extends the filesystem
 * to use all available partition space.
 * Returns ST_OK if expansion succeeded, error code otherwise.
 */
int dc_try_expand_fs(dev_hook *hook, u64 expand_bytes)
{
	u8                             fs_buf[sizeof(FILE_FS_ATTRIBUTE_INFORMATION) + 0x20];
	PFILE_FS_ATTRIBUTE_INFORMATION fs_info = pv(fs_buf);
	DC_NTFS_VOL_DATA               ntfs_data;
	IO_STATUS_BLOCK                iosb;
	HANDLE                         h_dev;
	NTSTATUS                       status;
	u64                            new_sectors;
	u64                            current_sectors;

	DbgMsg("dc_try_expand_fs: attempting to expand by %I64u bytes\n", expand_bytes);

	/* Open volume device */
	if ((h_dev = io_open_device(hook->dev_name)) == NULL) {
		DbgMsg("dc_try_expand_fs: failed to open device\n");
		return ST_IO_ERROR;
	}

	/* Query filesystem type - only NTFS is supported for expansion */
	status = ZwQueryVolumeInformationFile(
		h_dev, &iosb, fs_info, sizeof(fs_buf), FileFsAttributeInformation);

	if (!NT_SUCCESS(status)) {
		ZwClose(h_dev);
		DbgMsg("dc_try_expand_fs: FileFsAttributeInformation failed\n");
		return ST_UNK_FS;
	}
	dc_term_fs_name(fs_info, (u32)sizeof(fs_buf));

	if (_wcsicmp(fs_info->FileSystemName, L"NTFS") != 0) {
		ZwClose(h_dev);
		DbgMsg("dc_try_expand_fs: only NTFS is supported, got %ws\n", fs_info->FileSystemName);
		return ST_UNK_FS;
	}

	/* Get current NTFS volume data */
	status = ZwFsControlFile(h_dev, NULL, NULL, NULL, &iosb,
		FSCTL_GET_NTFS_VOLUME_DATA, NULL, 0, &ntfs_data, sizeof(ntfs_data));

	if (!NT_SUCCESS(status)) {
		ZwClose(h_dev);
		DbgMsg("dc_try_expand_fs: FSCTL_GET_NTFS_VOLUME_DATA failed, status=%08x\n", status);
		return ST_ERROR;
	}

	current_sectors = (u64)ntfs_data.NumberSectors.QuadPart;

	/* Calculate new number of sectors after expansion */
	if (expand_bytes % ntfs_data.BytesPerSector != 0) {
		/* Round down expand_bytes to full sectors */
		expand_bytes = (expand_bytes / ntfs_data.BytesPerSector) * ntfs_data.BytesPerSector;
	}

	new_sectors = current_sectors + (expand_bytes / ntfs_data.BytesPerSector);

	DbgMsg("dc_try_expand_fs: current_sectors=%I64u, new_sectors=%I64u\n",
		   current_sectors, new_sectors);

	/* FSCTL_EXTEND_VOLUME takes the new total sector count as a LONGLONG */
	status = ZwFsControlFile(h_dev, NULL, NULL, NULL, &iosb,
		FSCTL_EXTEND_VOLUME, &new_sectors, sizeof(new_sectors), NULL, 0);

	ZwClose(h_dev);

	if (!NT_SUCCESS(status)) {
		DbgMsg("dc_try_expand_fs: FSCTL_EXTEND_VOLUME failed, status=%08x\n", status);
		return ST_ERROR;
	}

	DbgMsg("dc_try_expand_fs: successfully expanded filesystem by %I64u bytes\n", expand_bytes);
	return ST_OK;
}