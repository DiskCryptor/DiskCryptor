#ifndef _DCCONST_H_
#define _DCCONST_H_

/* hook control flags */
#define F_NONE              0x0000
#define F_ENABLED           0x0001 // device mounted
#define F_SYNC              0x0002 // synchronous IRP processing mode
#define F_SYSTEM            0x0004 // this is a system device
#define F_REMOVABLE         0x0008 // this is removable device
#define F_HIBERNATE         0x0010 // this device used for hibernation
#define F_CRASHDUMP         0x0020 // this device used for crashdumping
#define F_UNSUPRT           0x0040 // device unsupported
#define F_DISABLE           0x0080 // device temporary disabled
#define F_REENCRYPT         0x0100 // reencryption in progress
#define F_FORMATTING        0x0200 // formatting in progress
#define F_NO_AUTO_MOUNT     0x0400 // automounting disabled for this device
#define F_PROTECT_DCSYS     0x0800 // protect $dcsys$ file from any access
#define F_PREVENT_ENC       0x1000 // fail any encrypt/decrypt requests with ST_CANCEL status
#define F_CDROM             0x2000 // this is CD-ROM device
#define F_NO_REDIRECT       0x4000 // redirection area is not used
#define F_SSD               0x8000 // this is SSD disk
#define F_PENDING	    0x00010000 // this device has a pending header
#define F_FS_RAW        0x00020000 // raw volume - no valid filesystem detected in sector 0
#define F_HEAD_BACKUP   0x00040000 // backup header exists at partition end
#define F_PROTECT_DCLOG 0x00080000 // protect the $dclog$ journal of a power-loss protected session like $dcsys$
#define F_NO_HIBER      0x00100000 // critical volume - erase keys on hibernation (VF_NO_HIBER)
#define F_HIBER_ERASE   0x00200000 // volume LOCKED: keys erased at hibernation, see F_LOCKED below
#define F_PLAIN_IO      0x00400000 // decryption finished: volume is plaintext at its natural offsets, forward I/O untouched until unmount

/*
 * Locked volume ("lock on hibernate").
 * At hibernation (also hybrid sleep and Fast Startup) the driver erases the keys of every
 * mounted volume that must not leak into the hibernation image (VF_NO_HIBER / MF_NO_HIBER
 * volumes, and every other lockable volume when the image could not be protected). The
 * volume and its file system stay mounted, but every read/write fails with
 * STATUS_FVE_LOCKED_VOLUME until it is unlocked.
 * A locked volume reports F_ENABLED | F_LOCKED in dc_status.flags (F_DISABLE and
 * F_PREVENT_ENC are set as well while it is locked). Unlock in place: DC_CTL_MOUNT with the
 * password (the driver also tries the cached passwords / boot keys on resume). A paused or
 * running transcryption continues after the unlock; its steps return ST_CANCEL while locked.
 * DC_CTL_UNMOUNT dismounts a locked volume (MF_FORCE when the FS refuses the volume lock).
 */
#define F_LOCKED        F_HIBER_ERASE
#define DC_IS_LOCKED(_flags) ( ((_flags) & (F_ENABLED | F_LOCKED)) == (F_ENABLED | F_LOCKED) )

#define F_CLEAR_ON_UNMOUNT ( \
	F_ENABLED | F_SYNC | F_REENCRYPT | F_FORMATTING | F_PROTECT_DCSYS | F_NO_REDIRECT | F_HEAD_BACKUP | F_NO_HIBER | F_HIBER_ERASE | F_PLAIN_IO | F_PROTECT_DCLOG )

/* encrypt flags */
#define EF_NONE           0x0000
#define EF_USE_SLACK      0x0010 // try to use slack space after the filesystem for redirection area
#define EF_TRY_SHRINK     0x0020 // try to shrink filesystem to create slack space
#define EF_SAFE_TRANSCRYPT 0x0040 // power-loss protection - journal every block in $dclog$ (v2 headers; encryption, decryption, re-encryption start)
#define EF_SAFE_TRANSCRYPT_FAST 0x0080 // power-loss protection with a checksum per 512-byte unit instead of a copy of each block (faster; a torn unit is detected, not repaired - it reads as zeros). Instead of EF_SAFE_TRANSCRYPT; with wipe passes the full journal is used

/* unmount flags */
#define MF_FORCE          0x0001 // unmount volume if FSCTL_LOCK_VOLUME fail
#define MF_NOFSCTL        0x0002 // no send FSCTL_DISMOUNT_VOLUME
#define MF_NOSYNC         0x0004 // no stop synchronous mode thread
#define MF_NOWAIT_IO      0x0010 // no wait for IO IRPs completion
#define MF_DECRYPTED      0x0080 // volume was decrypted, don't set F_FS_RAW

/* mount flags */
#define MF_DELMP          0x0008 // delete volume mount point when unmount
#define MF_READ_ONLY      0x0020 // mount volume as read only
#define MF_NO_HIBER       0x0100 // critical volume - erase keys on hibernation (F_NO_HIBER)
#define MF_USE_BACKUP     0x0200 // try to mount from backup header (also honored by an unlock of a locked volume)
#define MF_IGNORE_CRC     0x0400 // a primary header whose checksum does not match (signature and the other checks right)
                                 // that neither the backup header nor a tmp_size repair restores is mounted as it is -
                                 // read-only, no header write, no transcryption step. Kept in the volume's mnt_flags only then

/* header operation flags */
#define HF_DEFAULT        0x0000 // default operation - write entire header
#define HF_UPDATE_BASE    0x0001 // only update header base
#define HF_UPDATE_SLOTS   0x0002 // update key slots only
#define HF_UPDATE_EXT     0x0004 // update extended header
//#define HF_UPDATE_EXP     0x0008 // update expanded header
#define HF_CLEAR_SLOTS    0x0010 // clear key slots area
#define HF_HEADER_FILL    0x0020 // wipe header sectors before updating
#define HF_KEEP_SALT      0x0040 // keep original salt
#define HF_BACKUP_HEADER  0x0080 // handle backup header at partition end instead of primary header at sector 0

#define HF_UPDATE_ALL (HF_UPDATE_BASE | HF_UPDATE_SLOTS | HF_UPDATE_EXT)

/* Update layout flags passed by Init type & 0xFFFFFF00 */
#define S_RESIZE_HEADER   0x0100 // resize header
                         // 0x0200
#define S_BACKUP_HEADER   0x0400 // create header backup at partition end
#define S_REMOVE_BACKUP   0x0800 // remove header backup from partition end
#define S_STORAGE_TO_FILE 0x1000 // move storage area to file - does not reclaim slack space
#define S_STORAGE_TO_END  0x2000 // move storage area to partition end - atempts to schrink the FS when not enough slack space is available
                         // 0x4000
						 // 0x8000

/* operation status codes */
#define ST_OK			    0  /* operation completed successfully */
#define ST_ERROR            1  /* unknown error    */
#define ST_NF_DEVICE        2  /* device not found */
#define ST_RW_ERR           3  /* read/write error */
#define ST_PASS_ERR         4  /* invalid password */
#define ST_ALR_MOUNT        5  /* device is already mounted */
#define ST_NO_MOUNT         6  /* device not mounted */
#define ST_LOCK_ERR         7  /* error on volume locking  */
#define ST_UNMOUNTABLE      8  /* device is unmountable */
#define ST_NOMEM            9  /* not enough memory */
#define ST_ERR_THREAD       10 /* error on creating system thread */
#define ST_INV_WIPE_MODE    11 /* invalid data wipe mode */
#define ST_INV_DATA_SIZE    12 /* invalid data size */
#define ST_ACCESS_DENIED    13 /* access denied */
#define ST_NF_FILE          14 /* file not found */
#define ST_IO_ERROR         15 /* disk I/O error */
#define ST_UNK_FS           16 /* unsupported file system */
#define ST_ERR_BOOT         17 /* invalid FS bootsector, please format partition */      
#define ST_MBR_ERR          18 /* MBR is corrupted */
#define ST_BLDR_INSTALLED   19 /* bootloader is already installed */
#define ST_NF_SPACE         20 /* not enough space after partitions to install bootloader */
#define ST_BLDR_NOTINST     21 /* bootloader is not installed */
#define ST_INV_BLDR_SIZE    22 /* invalid bootloader size */
#define ST_BLDR_NO_CONF     23 /* bootloader corrupted, config not found */
#define ST_BLDR_OLD_VER     24 /* old bootloader cannot be configured */
#define ST_AUTORUNNED       25 /* */
#define ST_NEED_EXIT        26 /* */
#define ST_NO_ADMIN         27 /* user does not have admin privileges */
#define ST_NF_BOOT_DEV      28 /* boot device not found */
#define ST_REG_ERROR        29 /* cannot open registry key */
#define ST_NF_REG_KEY       30 /* registry key not found */
#define ST_SCM_ERROR        31 /* cannot open SCM database */
#define ST_FINISHED         32 /* encryption finished */
#define ST_INV_SECT         34 /* device has unsupported sector size */
#define ST_CLUS_USED        35 /* shrinking error, last clusters are used */
#define ST_NF_PT_SPACE      36 /* not enough free space in partition to continue encrypting */
#define ST_MEDIA_CHANGED    37 /* removable media changed */
#define ST_NO_MEDIA         38 /* no removable media in device */
#define ST_DEVICE_BUSY      39 /* device is busy */
#define ST_INV_MEDIA_TYPE   40 /* media type not supported */
#define ST_FORMAT_NEEDED    41 /* */
#define ST_CANCEL           42 /* operation canceled */
#define ST_INV_VOL_VER      43 /* invalid volume version */
#define ST_EMPTY_KEYFILES   44 /* keyfiles not found */
#define ST_NOT_BACKUP       45 /* this is not a backup file */
#define ST_NO_OPEN_FILE     46 /* cannot open file */
#define ST_NO_CREATE_FILE   47 /* cannot create file */
#define ST_INV_VOLUME       48 /* invalid volume header */
#define ST_OLD_VERSION      49 /* */
#define ST_NEW_VERSION      50 /* */
#define ST_ENCRYPTED        51 /* */
#define ST_INCOMPATIBLE     52 /* */
#define ST_LOADED           53 /* */
#define ST_VOLUME_TOO_NEW   54 /* */
#define ST_INVALID_PARAM    55 /* an invalid parameter was provided */
#define ST_INV_FORMAT       56 /* disk has incompatible partition format */
#define ST_NO_OPEN_DIR      57 /* cannot open directory */
#define ST_DIR_NOT_EMPTY    58 /* directory is not empty */
#define ST_BL_NOT_PASSED    59 /* bootloader check not passed */
#define ST_SB_NO_PASS	    60 /* secureboot enabled and not accepting DCS signature */
#define ST_SHIM_MISSING	    61 /* shim package is missing */
#define ST_HEADER_TO_BIG    62 /* volume header is to big */
#define ST_SMALL_BUFF       63 /* buffer too small */
#define ST_BAD_INDEX        64 /* bad index */
#define ST_SLOT_NOT_OK      65 /* failed to set up keyslot */
#define ST_SHRINK_FAILED    66 /* failed to shrink filesystem */
#define ST_PASS_NOT_FOUND   67 /* password not found in cache */
#define ST_MORE_DATA        68 /* more data available than buffer can hold */
#define ST_NO_TPM           69 /* no TPM available */
#define ST_TPM_ERROR        70 /* TPM command failed */
#define ST_NOT_SUPPORTED    71 /* operation not supported */
#define ST_FORMAT_ERR       72 /* invalid data format */
#define ST_TPM_NV_NOT_FOUND 73 /* NV index not found */
#define ST_TPM_WRONG_PIN    74 /* TPM authentication failed (wrong PIN) */
#define ST_TPM_PCR_MISMATCH 75 /* TPM PCR values don't match sealed policy */
#define ST_TPM_LOCKOUT      76 /* TPM is in dictionary attack lockout */
#define ST_TPM_INTEGRITY    77 /* TPM sealed data integrity check failed */
#define ST_GPT_INVALID      78 /* Invalid GPT structure */
#define ST_NO_FREE_SPACE    79 /* No unallocated space on disk */
#define ST_PART_TOO_SMALL   80 /* Partition too small to shrink */
#define ST_NOT_PRO          81 /* DC is not Pro */
#define ST_LEGACY_BOOT      82 /* option not supported on a volume booted by the legacy (MBR) bootloader */
#define ST_LOG_CREATE       83 /* the power-loss protection journal ($dclog$) could not be created */
#define ST_LOG_CONFLICT     84 /* the power-loss protection journal contradicts the volume header */
#define ST_LOG_PENDING      85 /* a journaled block could not be completed (disk refuses writes); the rest of the volume works */
#define ST_HDR_DAMAGED      86 /* the password is right but the volume header is damaged (checksum mismatch) and could not be repaired */

/* data wipe modes */
#define WP_NONE				0 // no data wipe
#define WP_DOD_E			1 // US DoD 5220.22-M (8-306. / E)
#define WP_DOD				2 // US DoD 5220.22-M (8-306. / E, C and E)
#define WP_GUTMANN			3 // Gutmann
#define WP_NUM				4

#define WP_SKIP_UNUSED      0xFF // special wipe mode: skip unused sectors

/* Keyfile mixing modes */
#define KEYFILE_MIX_LEGACY	0 // aditive mixing of keyfile and password (legacy mode)
#define KEYFILE_MIX_HASHED	1 // canonical hashed mixing of keyfile and password (recommended mode)

/* registry config flags */
#define CONF_FORCE_DISMOUNT        0x0001
#define CONF_CACHE_PASSWORD        0x0002
#define CONF_EXPLORER_MOUNT        0x0004
#define CONF_WIPEPAS_LOGOFF        0x0008
#define CONF_DISMOUNT_LOGOFF       0x0010
#define CONF_AUTO_START            0x0020
#define CONF_HIDE_DCSYS            0x0040
#define CONF_HW_CRYPTO             0x0080
#define CONF_AUTOMOUNT_BOOT        0x0100
#define CONF_DISABLE_TRIM          0x0200
#define CONF_ENABLE_SSD_OPT        0x0400
#define CONF_BLOCK_UNENC_REMOVABLE 0x0800
#define CONF_BLOCK_UNENC_HDDS      0x1000
#define CONF_BLOCK_UNENC_CDROM     0x2000
#define CONF_PROTECT_RAW_VOLUMES   0x4000
#define CONF_SECURE_DESKTOP        0x8000
/* hibernation with an image that cannot protect the keys (e.g. the system volume is not
   encrypted): allowed - every lockable encrypted volume is locked at S4 (keys erased, unlocked
   with its password after the resume) instead of the hibernation being refused. Volumes that
   cannot be locked (paging file, being formatted, ...) still refuse it. */
#define CONF_HIBER_LOCK            0x10000

/* GUI / dccon step loops: save the transcryption state every N steps (DC_CTL_SYNC_STATE).
   About 32 MiB with the driver's 8 MiB steps - how far the on-disk boundary of a session
   without power-loss protection may lag. With a journal the mount takes the boundary from the
   newest record, so the interval only sets how often the header is rewritten in place. */
#define DC_SYNC_EVERY_STEPS        4

#define IS_BLOCK_UNENC_HDDS_DISABLED(_sysdev_flags) \
	(/*(_sysdev_flags & (F_SYNC | F_FORMATTING)) ||*/ (_sysdev_flags & F_ENABLED) == 0)

/* driver status flags */
#define DST_VIA_PADLOCK	             0x01 // VIA Padlock instructions available
#define DST_INTEL_NI                 0x02 // AES_NI instructions available
#define DST_INSTR_SSE2               0x04 // SSE2 instructions available
#define DST_INSTR_AVX                0x08 // AVX instructions available
#define DST_ARM64_CE                0x100 // ARM64 Crypto Extensions available
#define DST_ARM64_NEON              0x200 // ARM64 NEON available
#define DST_HW_CRYPTO   (DST_VIA_PADLOCK | DST_INTEL_NI | DST_ARM64_CE)

#define DST_BOOTLOADER               0x10 // system started via DC bootloader
#define DST_SMALL_MEM                0x20 // BIOS base memory too small for DC bootloader
#define DST_UEFI_BOOT                0x40 // booted in UEFI mode
#define DST_ARGON2_OK                0x80 // Argon2id selftest passed (may fail on low memory systems)
#define DST_UEFI_RETRY         0x40000000 // failed to read efi variable, retry later
#define DST_PRO_ENABLED        0x80000000

/* bootloader */
#define DC_BOOTHOOK_SIZE    30 // bootloader resident memory needed

#endif