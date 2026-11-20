/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2019-2026
	* DavidXanatos <info@diskcryptor.org>
    * Copyright (c) 2007-2008 
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
#include "defines.h"
#include "devhook.h"
#include "driver.h"
#include "misc.h"
#include "crc32.h"
#include "enc_dec.h"
#include "misc_irp.h"
#include "readwrite.h"
#include "mount.h"
#include "fast_crypt.h"
#include "misc_volume.h"
#include "debug.h"
#include "misc_mem.h"
#include "crypto_head.h"
#include "disk_info.h"
#include "device_io.h"
#include "header_io.h"
#include "storage.h"
#include "safe_log.h"
#include "bootloader.h"

typedef struct _dsk_pass {
	struct _dsk_pass *next;
	dc_pass           pass;
} dsk_pass;

typedef struct _mount_ctx {
	WORK_QUEUE_ITEM   wrk_item;
	PIRP              irp;
	dev_hook         *hook;
	u32               chg_mount; /* mount counter when queued (dc_unmount_async, dc_probe_mount) */
	
} mount_ctx;

/* function types declaration */
WORKER_THREAD_ROUTINE unmount_item_proc;
KSTART_ROUTINE        unmount_thread_proc;
WORKER_THREAD_ROUTINE mount_item_proc;

static dsk_pass      *pass_cache;
static ERESOURCE      mount_sync_resource;
static header_key    *boot_keys;
static int            boot_key_count;

/*
 * S4 transition in progress - set by the first S4 SET_POWER IRP before any volume is locked,
 * cleared by the S0 SET_POWER IRP. While set, mount and unlock are refused (ST_CANCEL): a
 * volume mounted / unlocked after its own S4 IRP would reach the image with live keys. Tested
 * under the volume's busy_lock, which the S4 path acquires and releases after setting it.
 */
static volatile LONG  s4_transition;

void dc_set_s4_transition(BOOLEAN active)
{
	InterlockedExchange(&s4_transition, active ? 1 : 0);
}

BOOLEAN dc_s4_transition_active()
{
	return InterlockedCompareExchange(&s4_transition, 0, 0) != 0;
}


/* Check if kdf1 covers kdf2:
 * KDF_ALL covers everything, otherwise must match exactly */
static int kdf_covers(int kdf1, int kdf2) {
	if (kdf1 == KDF_ALL) return 1;
	return (kdf1 == kdf2);
}

/* Check if slot1 covers slot2:
 * slot < 0 means header + slots 1..abs(slot)
 * slot = 0 means header only
 * slot > 0 means specific slot */
static int slot_covers(int slot1, int slot2) {
	if (slot1 < 0) {
		int max_slot = -slot1;
		if (slot2 < 0) {
			return (-slot2) <= max_slot;
		} else if (slot2 == 0) {
			return 1; /* negative slot covers header */
		} else {
			return slot2 <= max_slot;
		}
	} else if (slot1 == 0) {
		return slot2 == 0;
	} else {
		return slot2 == slot1;
	}
}

/* Check if pass1 covers pass2 (same password with broader kdf/slot scope) */
static int password_covers(dc_pass *pass1, dc_pass *pass2) {
	if (pass1->size != pass2->size) return 0;
	if (memcmp(pass1->pass, pass2->pass, pass1->size) != 0) return 0;
	return kdf_covers(pass1->kdf, pass2->kdf) && slot_covers(pass1->slot, pass2->slot);
}

extern char dc_boot_pass[SLOT_LABEL_LEN];

int dc_add_password(dc_pass *pass)
{
	dsk_pass *d_pass;
	dsk_pass **pp;

	if (memcmp(pass->label, dc_boot_pass, SLOT_LABEL_LEN) == 0) {
		return ST_BAD_INDEX;
	}
	/* backstop (the entry points validate it already): a cached size beyond the buffer
	 * would make every later KDF / memcmp read past it */
	if (pass->size < 0 || pass->size > (int)sizeof(pass->pass)) {
		return ST_INVALID_PARAM;
	}

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&mount_sync_resource, TRUE);

	/* Check for tag match first - update or remove existing tagged entry */
	if (*pass->label) {
		for (pp = &pass_cache; *pp; pp = &(*pp)->next) {
			if (memcmp((*pp)->pass.label, pass->label, SLOT_LABEL_LEN) == 0) {
				if (pass->size == 0) {
					/* Remove entry when new password size is 0 */
					dsk_pass *to_remove = *pp;
					*pp = to_remove->next;
					burn(to_remove, sizeof(dsk_pass));
					mm_secure_free(to_remove);
				} else {
					/* Update existing entry */
					memcpy(&(*pp)->pass, pass, sizeof(dc_pass));
				}
				goto done;
			}
		}
	}

	/* Nothing to add if password is empty */
	if (pass->size == 0) goto done;

	/* Check if any existing entry already covers the new password */
	for (d_pass = pass_cache; d_pass; d_pass = d_pass->next) {
		if (password_covers(&d_pass->pass, pass)) {
			goto done; /* Already covered, skip */
		}
	}

	/* Remove any entries that would be covered by the new password */
	pp = &pass_cache;
	while (*pp) {
		if (password_covers(pass, &(*pp)->pass)) {
			dsk_pass *to_remove = *pp;
			*pp = to_remove->next;
			burn(to_remove, sizeof(dsk_pass));
			mm_secure_free(to_remove);
		} else {
			pp = &(*pp)->next;
		}
	}

	/* Add new entry */
	if ((d_pass = mm_secure_alloc(sizeof(dsk_pass))) != NULL) {
		memcpy(&d_pass->pass, pass, sizeof(dc_pass));
		d_pass->next = pass_cache;
		pass_cache = d_pass;
	}

done:
	ExReleaseResourceLite(&mount_sync_resource);
	KeLeaveCriticalRegion();

	return ST_OK;
}

void dc_cache_password(dc_pass *pass)
{
	dsk_pass *d_pass;

	/* backstop, see dc_add_password */
	if (pass->size > 0 && pass->size <= (int)sizeof(pass->pass))
	{
		KeEnterCriticalRegion();
		ExAcquireResourceExclusiveLite(&mount_sync_resource, TRUE);

		if ( (d_pass = mm_secure_alloc(sizeof(dsk_pass))) != NULL )
		{
			memcpy(&d_pass->pass, pass, sizeof(dc_pass));

			DbgMsg("dc_cache_password: size=%d, tag='%.*s', kdf=%d, slot=%d\n", pass->size, SLOT_LABEL_LEN, pass->label, pass->kdf, pass->slot);

			d_pass->next = pass_cache;
			pass_cache       = d_pass;
		}

		ExReleaseResourceLite(&mount_sync_resource);
		KeLeaveCriticalRegion();
	}
}

int dc_lookup_password(const char* label, dc_pass *pass)
{
	dsk_pass* d_pass;

	if (!label || !*label)
		return ST_INVALID_PARAM;

	KeEnterCriticalRegion();
	ExAcquireResourceSharedLite(&mount_sync_resource, TRUE);

	for (d_pass = pass_cache; d_pass; d_pass = d_pass->next)
	{
		if (memcmp(d_pass->pass.label, label, SLOT_LABEL_LEN) == 0) {
			// return password bytes and kdf but nothign more
			memcpy(pass, &d_pass->pass, FIELD_OFFSET(dc_pass, slot));
			break;
		}
	}

	ExReleaseResourceLite(&mount_sync_resource);
	KeLeaveCriticalRegion();

	return (d_pass != NULL) ? ST_OK : ST_PASS_NOT_FOUND;
}

int dc_enum_pass_cache(dc_pass_info *items, int max_count, int *total_count)
{
	dsk_pass *d_pass;
	int       count = 0;
	int       total = 0;

	KeEnterCriticalRegion();
	ExAcquireResourceSharedLite(&mount_sync_resource, TRUE);

	for (d_pass = pass_cache; d_pass; d_pass = d_pass->next)
	{
		if (count < max_count) {
			memcpy(items[count].label, d_pass->pass.label, SLOT_LABEL_LEN);
			items[count].kdf = d_pass->pass.kdf;
			count++;
		}
		total++;
	}

	ExReleaseResourceLite(&mount_sync_resource);
	KeLeaveCriticalRegion();

	*total_count = total;
	return count;
}

/* entries burned above PASSIVE_LEVEL (dump time) cannot be freed there - kept here and
   freed by the next PASSIVE_LEVEL call */
static dsk_pass *pass_cache_burned;

void dc_clean_pass_cache()
{
	dsk_pass *d_pass;
	dsk_pass *c_pass;
	int       loirql;

	DbgMsg("dc_clean_pass_cache\n");

	if (loirql = (KeGetCurrentIrql() == PASSIVE_LEVEL)) {
		KeEnterCriticalRegion();
		ExAcquireResourceExclusiveLite(&mount_sync_resource, TRUE);

		for (d_pass = pass_cache_burned; d_pass;) {
			c_pass = d_pass;
			d_pass = d_pass->next;
			mm_secure_free(c_pass);
		}
		pass_cache_burned = NULL;
	}

	for (d_pass = pass_cache; d_pass;)
	{
		c_pass = d_pass;
		d_pass = d_pass->next;
		/* zero password data */
		burn(c_pass, sizeof(dsk_pass));
		/* free memory if possible */
		if (loirql != 0) {
			mm_secure_free(c_pass);
		} else {
			c_pass->next = pass_cache_burned;
			pass_cache_burned = c_pass;
		}
	}
	pass_cache = NULL;

	if (loirql != 0) {
		ExReleaseResourceLite(&mount_sync_resource);
		KeLeaveCriticalRegion();
	}
}

void dc_clean_keys() 
{
	dev_hook *hook;

	for (hook = dc_first_hook(); hook != NULL; hook = dc_next_hook(hook))
	{
		if (hook->dsk_key != NULL) RtlSecureZeroMemory(hook->dsk_key, sizeof(xts_key));
		if (hook->tmp_key != NULL) RtlSecureZeroMemory(hook->tmp_key, sizeof(xts_key));

		if (hook->hdr_key != NULL) RtlSecureZeroMemory(hook->hdr_key, sizeof(xts_key));
		if (hook->tmp_header != NULL) RtlSecureZeroMemory(hook->tmp_header, hook->head_len);

		if (hook->bak_key != NULL) RtlSecureZeroMemory(hook->bak_key, sizeof(xts_key));
		if (hook->bak_salt != NULL) RtlSecureZeroMemory(hook->bak_salt, HEADER_SALT_SIZE);
	}

	// Write Back and Invalidate CPU Caches
	__wbinvd();
}

void dc_set_boot_keys(struct _header_key* keys, int count)
{
	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&mount_sync_resource, TRUE);

	/* a previous set (possibly zeroed at dump time, see dc_clean_boot_keys) */
	if (boot_keys != NULL) {
		mm_secure_free(boot_keys);
		boot_keys = NULL;
		boot_key_count = 0;
	}
	boot_keys = mm_secure_alloc(sizeof(header_key) * count);
	if (boot_keys != NULL) {
		__try  {
			memcpy(boot_keys, keys, sizeof(header_key) * count);
			boot_key_count = count;
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			DbgMsg("exception while copying boot keys, code: 0x%X\n", GetExceptionCode());
		}
	}

	ExReleaseResourceLite(&mount_sync_resource);
	KeLeaveCriticalRegion();
}

void dc_clean_boot_keys()
{
	/* at dump time (HIGH_LEVEL) only zero the keys, like dc_clean_pass_cache; the zeroed
	 * block is freed by the next call at PASSIVE_LEVEL */
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
		if (boot_keys != NULL) {
			burn(boot_keys, sizeof(header_key) * boot_key_count);
		}
		boot_key_count = 0;
		return;
	}

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&mount_sync_resource, TRUE);

	if (boot_keys != NULL) {
		mm_secure_free(boot_keys);
		boot_keys = NULL;
		boot_key_count = 0;
	}

	ExReleaseResourceLite(&mount_sync_resource);
	KeLeaveCriticalRegion();
}

static
void dc_detect_filesystem(dev_hook *hook)
{
	u8  *sector = NULL;
	int  sector_size;
	int  resl;
	int  i;
	int  all_zero, all_ff;

	/* device not ready */
	if (hook->bps == 0) return;

	/* If volume is already mounted (encrypted), don't touch the flags. */
	if (hook->flags & F_ENABLED) return;

	/* F_FS_RAW is updated interlocked below: this runs without busy_lock, so the F_ENABLED
	 * test above is only a snapshot and other bits of hook->flags may change meanwhile. */

	/* NOTE: We do NOT check hook->orig_dev->Vpb->Flags & VPB_MOUNTED here.
	 * The VPB_MOUNTED flag can be transiently set during boot/device enumeration
	 * even when no real filesystem is mounted. */

	sector_size = ROUND_TO_FULL_SECTORS(SECTOR_SIZE, hook->bps);

	if ( (sector = mm_pool_alloc(sector_size)) == NULL ) return;

	/* Read sector 0 */
	resl = io_hook_rw(hook, sector, sector_size, 0, 1);
	if (resl != ST_OK) goto cleanup;

	/* Check for all-zeros or all-0xFF sector (empty/wiped - can't be valid encrypted header) */
	/* Compare as 64-bit integers for speed */
	all_zero = 1;
	all_ff = 1;
	{
		u64 *p64 = (u64*)sector;
		int  n64 = sector_size / sizeof(u64);
		for (i = 0; i < n64; i++) {
			if (p64[i] != 0) all_zero = 0;
			if (p64[i] != 0xFFFFFFFFFFFFFFFFULL) all_ff = 0;
			if (!all_zero && !all_ff) break;
		}
	}
	if (all_zero || all_ff) {
		dc_hook_clear_flags(hook, F_FS_RAW);  /* empty/wiped volume, not encrypted - clear raw flag */
		DbgMsg("empty/wiped sector detected (not encrypted), dev=%ws\n", hook->dev_name);
		goto cleanup;
	}

	/* Check for valid boot sector signature 0x55AA at offset 510-511.
	* This signature is present in NTFS, FAT12/16/32, and exFAT boot sectors. */
	if (sector_size >= 512 && sector[510] == 0x55 && sector[511] == 0xAA) {
		/* Identify filesystem type for logging */
		if (memcmp(sector + 3, "NTFS    ", 8) == 0) {
			dc_hook_clear_flags(hook, F_FS_RAW);  /* NTFS found - clear raw flag */
			DbgMsg("filesystem detected: NTFS, dev=%ws\n", hook->dev_name);
		} else if (memcmp(sector + 3, "EXFAT   ", 8) == 0) {
			dc_hook_clear_flags(hook, F_FS_RAW);  /* exFAT found - clear raw flag */
			DbgMsg("filesystem detected: exFAT, dev=%ws\n", hook->dev_name);
		} else if (memcmp(sector + 54, "FAT", 3) == 0 || memcmp(sector + 82, "FAT", 3) == 0) {
			dc_hook_clear_flags(hook, F_FS_RAW);  /* FAT found - clear raw flag */
			DbgMsg("filesystem detected: FAT, dev=%ws\n", hook->dev_name);
		} /*else {
		  DbgMsg("filesystem detected: boot signature found, dev=%ws\n", hook->dev_name);
		  }*/
		goto cleanup;
	}

	/* ReFS: "ReFS" signature at offset 3 */
	if (memcmp(sector + 3, "ReFS", 4) == 0) {
		dc_hook_clear_flags(hook, F_FS_RAW);  /* ReFS found - clear raw flag */
		DbgMsg("filesystem detected: ReFS, dev=%ws\n", hook->dev_name);
		goto cleanup;
	}

	/* No filesystem detected - mark as raw volume (potentially encrypted) */
	dc_hook_set_flags(hook, F_FS_RAW);
	DbgMsg("no filesystem detected (raw volume), dev=%ws\n", hook->dev_name);

cleanup:
	if (sector != NULL) mm_pool_free(sector);
}

/* damaged: NULL - only a valid header; else a header whose signature decrypts but which does
 * not validate is returned too, with *damaged = 1 (password and cached passwords only; boot
 * keys only open valid headers) */
static
int dc_probe_decrypt_at(dev_hook *hook, dc_header **header, xts_key **res_key, dc_pass *password, int* out_kdf, u64 read_pos, int hdr_len, int *damaged, ULONG *interrupt_cmd)
{
	xts_key  *hdr_key = NULL;
	dsk_pass *d_pass;
	int       i;
	int       resl, succs = 0;

	*header = NULL;
	if (damaged != NULL) *damaged = 0;
	do
	{
		/* read raw volume header */
		if ( (*header = mm_secure_alloc(hdr_len)) == NULL ) {
			resl = ST_NOMEM; break;
		}
		if ( (resl = io_hook_rw(hook, *header, hdr_len, read_pos, 1)) != ST_OK ) {
			break;
		}
		if ( (hdr_key = mm_secure_alloc(sizeof(xts_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		/* derive header key and decrypt header */
		do
		{
			if (password != NULL)
			{
				/* probe mount with entered password */
				if (succs = cp_decrypt_header_ex(hdr_key, *header, hdr_len, password, out_kdf, NULL, NULL, damaged, interrupt_cmd)) {
					break;
				}
			}

			KeEnterCriticalRegion();
			ExAcquireResourceSharedLite(&mount_sync_resource, TRUE);

			/* probe mount with boot keys */
			if (boot_keys != NULL) {
				for (i = 0; i < boot_key_count; i++) {
					if (memcmp(boot_keys[i].guid, (*header)->salt, sizeof(boot_keys[i].guid)) != 0) {
						continue;
					}
					if (succs = cp_try_decrypt_header_ex(boot_keys[i].key, boot_keys[i].alg, hdr_key, *header, damaged)) {
						if (out_kdf) *out_kdf = boot_keys[i].kdf;
						DbgMsg("header decrypted with boot key, dev=%ws\n", hook->dev_name);
						goto found;
					}
				}
			}

			/* probe mount with cached passwords */
			for (d_pass = pass_cache; d_pass; d_pass = d_pass->next)
			{
				if (succs = cp_decrypt_header_ex(hdr_key, *header, hdr_len, &d_pass->pass, out_kdf, NULL, NULL, damaged, interrupt_cmd)) {
					break;
				}
			}

		found:
			ExReleaseResourceLite(&mount_sync_resource);
			KeLeaveCriticalRegion();
		} while (0);

		if (succs != 0) {
			*res_key = hdr_key; hdr_key = NULL; resl = ST_OK;
		} else {
			resl = ST_PASS_ERR;
		}
	} while (0);

	if (resl != ST_OK && *header != NULL) {
		mm_secure_free(*header); *header = NULL;
	}
	if (hdr_key != NULL) {
		mm_secure_free(hdr_key);
	}
	return resl;
}

/*
 * The primary header decrypted (signature right) but does not validate - a header rewrite
 * torn by a power loss: a transcryption save changes hdr_crc (sector 0) and tmp_size
 * (sector 1), and on 512-byte media only one of them may have reached the disk. The newer of
 * the two saves is the right boundary (the data up to it was flushed before its header write).
 *  1. VF_TMP_MODE: restore the tmp_size the sector 0 checksum was made for; the backup header
 *     (written after the primary) tells which save is newer.
 *  2. no tmp_size fits: the backup header, only if it is of this state (same transcryption
 *     flags, cipher and key) - one from before / after the session would mount a partly
 *     transcrypted volume without its session.
 *  3. MF_IGNORE_CRC: taken as it is - the caller mounts it read-only and nothing is written.
 * Otherwise ST_HDR_DAMAGED (not ST_PASS_ERR: the password is right). On success *header /
 * *res_key / *pos / *hdr_len describe the header to mount and *repair says how it was obtained.
 * The candidate list and the newer-save rule are in volume_lib (dc_header_recover_tmp),
 * shared with the boot loader; this is the I/O around it.
 */
#if ENC_BLOCK_SIZE != DC_REPAIR_STEP_BLOCK || DC_WIPE_BLOCK != DC_REPAIR_STEP_WIPE
#error the header repair steps differ from volume_lib's (header_io.h)
#endif

static int dc_header_recover(dev_hook *hook, dc_header **header, xts_key **res_key, dc_pass *password, int *out_kdf,
                             u32 mnt_flags, u64 *pos, int *hdr_len, int *repair, ULONG *interrupt_cmd)
{
	dc_header *h      = *header;
	dc_header *hb     = NULL; /* the backup header, when it is of this state */
	xts_key   *bk     = NULL;
	u32        blen;
	int        bkdf   = 0;
	u64        hints[DC_REPAIR_HINTS];
	int        n_hints = 0;
	u64       *cand   = NULL;
	int        r;

	DbgMsg("dc_header_recover: the primary header does not validate (signature right), dev=%ws\n", hook->dev_name);

	/* the backup header (its head_len lies in sector 1, unchanged by a session's saves) */
	if ( (blen = dc_header_backup_len(h, hook->dsk_size, hook->bps)) != 0 &&
		 dc_probe_decrypt_at(hook, &hb, &bk, password, &bkdf, hook->dsk_size - blen, blen, NULL, interrupt_cmd) == ST_OK )
	{
		if (!dc_header_same_state(h, hb)) {
			DbgMsg("dc_header_recover: the backup header is not of this state (flags %x / %x), not used, dev=%ws\n",
				hb->flags, h->flags, hook->dev_name);
			mm_secure_free(hb); hb = NULL;
			mm_secure_free(bk); bk = NULL;
		}
	}

	/* 1. the tmp_size of a torn transcryption save (2. the backup, decided there too) */
	if ( (h->flags & VF_TMP_MODE) &&
		 (cand = (u64*)mm_pool_alloc(sizeof(u64) * DC_REPAIR_CAND)) != NULL )
	{
		n_hints = dc_slog_tmp_hints(hook, h, hints, DC_REPAIR_HINTS);
	}
	r = dc_header_recover_tmp(h, hb, hook->dsk_size, hook->bps, hints, n_hints, cand);
	if (cand != NULL) mm_pool_free(cand);

	if (r == DC_REPAIR_TMP || r == DC_REPAIR_BAD) {
		if (hb != NULL) { mm_secure_free(hb); mm_secure_free(bk); }
		if (r == DC_REPAIR_BAD) {
			mm_secure_free(*header);  *header  = NULL;
			mm_secure_free(*res_key); *res_key = NULL;
			return ST_HDR_DAMAGED;
		}
		DbgMsg("dc_header_recover: tmp_size restored to %I64x, dev=%ws\n", h->tmp_size, hook->dev_name);
		*repair = DC_HDR_REPAIRED;
		return ST_OK;
	}

	/* 2. the backup header of this state */
	if (r == DC_REPAIR_BACKUP) {
		mm_secure_free(h);
		mm_secure_free(*res_key);
		*header  = hb;
		*res_key = bk;
		*pos     = hook->dsk_size - blen;
		*hdr_len = blen;
		if (out_kdf) *out_kdf = bkdf;
		*repair  = DC_HDR_BACKUP;
		DbgMsg("dc_header_recover: mounted from the backup header, dev=%ws\n", hook->dev_name);
		return ST_OK;
	}

	/* 3. taken as it is, on request: the CRC is fixed in memory only (MF_IGNORE_CRC keeps it
	 * off the disk). A footer_cnt outside the header has no CRC range. */
	if (mnt_flags & MF_IGNORE_CRC) {
		h->hdr_crc = calculate_header_crc(h);
		if (is_volume_header_correct(h) != FALSE) {
			*repair = DC_HDR_FORCED;
			DbgMsg("dc_header_recover: damaged header accepted as it is (MF_IGNORE_CRC), dev=%ws\n", hook->dev_name);
			return ST_OK;
		}
	}

	mm_secure_free(*header);  *header  = NULL;
	mm_secure_free(*res_key); *res_key = NULL;
	return ST_HDR_DAMAGED;
}

/* repair (may be NULL): DC_HDR_* - how the header was obtained (dc_header_recover) */
static
int dc_probe_decrypt(dev_hook *hook, dc_header **header, xts_key **res_key, dc_pass *password, int* out_kdf, u32 mnt_flags, u64* out_pos, int* out_hdr_len, int *repair, ULONG *interrupt_cmd)
{
	dsk_pass *d_pass;
	int       min_len;
	int       hdr_len;
	u64       read_pos = 0;
	int       resl;
	int       damaged = 0;
	int       how = DC_HDR_INTACT;

	*header = NULL;

	if (mnt_flags & MF_USE_BACKUP) {
		/* Try to mount from backup header at partition end */
		/* Try different sizes: 2k, 4k, 8k, ... up to 4M */
		u32 try_len;
		resl = ST_PASS_ERR;
		for (try_len = 2048; try_len <= 4 * 1024 * 1024; try_len *= 2) {
			read_pos = hook->dsk_size - try_len;
			hdr_len = try_len;
			resl = dc_probe_decrypt_at(hook, header, res_key, password, out_kdf, read_pos, hdr_len, NULL, interrupt_cmd);
			if (resl == ST_OK) {
				DbgMsg("mounted from backup header at offset -%u, dev=%ws\n", try_len, hook->dev_name);
				break;
			}
		}
	} else {
		/* determine minimum header length for key slots */
		min_len = DC_AREA_SIZE;
		if (password != NULL)
		{
			min_len = cp_get_min_header_len(password);
		}

		KeEnterCriticalRegion();
		ExAcquireResourceSharedLite(&mount_sync_resource, TRUE);

		for (d_pass = pass_cache; d_pass; d_pass = d_pass->next)
		{
			hdr_len = cp_get_min_header_len(&d_pass->pass);
			if (hdr_len > min_len) {
				min_len = hdr_len;
			}
		}

		ExReleaseResourceLite(&mount_sync_resource);
		KeLeaveCriticalRegion();

		if (min_len < DC_AREA_SIZE) {
			return ST_PASS_ERR;
		}

		hdr_len = ROUND_TO_FULL_SECTORS(min_len, hook->bps);
		read_pos = 0;

		/* Try to mount from primary header at position 0 */
		resl = dc_probe_decrypt_at(hook, header, res_key, password, out_kdf, read_pos, hdr_len, &damaged, interrupt_cmd);

		/* signature right, CRC not - repair or refuse */
		if (resl == ST_OK && damaged) {
			resl = dc_header_recover(hook, header, res_key, password, out_kdf, mnt_flags, &read_pos, &hdr_len, &how, interrupt_cmd);
		}
	}

	if (resl == ST_OK) {
		if (out_pos) *out_pos = read_pos;
		if (out_hdr_len) *out_hdr_len = hdr_len;
	}
	if (repair) *repair = (resl == ST_OK) ? how : DC_HDR_INTACT;

	return resl;
}

/*
 * The layout a decrypted volume header describes on this device. A mount applies it to
 * the hook; an unlock in place only compares it with the hook, which must still describe
 * exactly this volume (the file system above stayed mounted on that layout).
 */
typedef struct _dc_hdr_layout {
	ULONG     head_len;
	u64       use_size;
	ULONGLONG stor_off;
	ULONG     stor_len;
	u32       crypt_head_len;
	u32       flags;         /* DC_LAYOUT_FLAGS */
	ULONG     tail_len;
	ULONGLONG tail_off;
} dc_hdr_layout;

#define DC_LAYOUT_FLAGS (F_PROTECT_DCSYS | F_NO_REDIRECT | F_HEAD_BACKUP)

static void dc_header_layout(dev_hook *hook, dc_header *hcopy, dc_hdr_layout *lt)
{
	if (hcopy->version >= DC_HDR_VERSION_2) {
		lt->head_len = ROUND_TO_FULL_SECTORS(hcopy->head_len, hook->bps);
		if (hcopy->flags & VF_STORAGE_FILE) {
			lt->use_size = hook->dsk_size;
			lt->stor_off = hcopy->stor_off;
		} else {
			lt->use_size = hook->dsk_size - hcopy->stor_len;
			lt->stor_off = lt->use_size;
		}
		lt->stor_len = hcopy->stor_len;
		lt->crypt_head_len = hcopy->head_len;
	} else {
		lt->head_len = ROUND_TO_FULL_SECTORS(DC_AREA_SIZE, hook->bps);
		if (hcopy->flags & VF_STORAGE_FILE) {
			lt->use_size = hook->dsk_size;
			lt->stor_off = hcopy->stor_off;
		} else {
			lt->use_size = hook->dsk_size - lt->head_len;
			lt->stor_off = lt->use_size;
		}
		lt->stor_len = lt->head_len;
		lt->crypt_head_len = DC_AREA_SIZE;
	}

	lt->flags = 0;
	if (hcopy->flags & VF_STORAGE_FILE) {
		lt->flags |= F_PROTECT_DCSYS;
	}
	if (hcopy->flags & VF_NO_REDIR) {
		lt->flags |= F_NO_REDIRECT;
		lt->stor_off = 0;
	}
	if (hcopy->flags & VF_BACKUP_HEADER) {
		lt->flags |= F_HEAD_BACKUP;
	}

	/* Tail redirect only for redirected volumes with a $dcsys$ storage file. Tested directly,
	 * not via IS_STORAGE_ON_END: that macro requires F_ENABLED, not set yet at mount. */
	if ((lt->flags & (F_HEAD_BACKUP | F_PROTECT_DCSYS | F_NO_REDIRECT)) == (F_HEAD_BACKUP | F_PROTECT_DCSYS)) {
		lt->tail_len = lt->head_len;
		lt->tail_off = lt->stor_off + lt->stor_len - lt->tail_len;
	} else {
		lt->tail_len = 0;
		lt->tail_off = 0;
	}
}

/*
 * Install the transcryption session of a VF_TMP_MODE header: backup header key/salt,
 * hdr_key and tmp_header (ownership moves to the hook: *p_hcopy / *p_hdr_key are set to
 * NULL), tmp_size, wipe mode, then dc_transcrypt_init (S_CONTINUE_ENC / S_CONTINUE_RE_ENC).
 * Shared by a mount and by the unlock in place. busy_lock held.
 *
 * pre (unlock): the backup header was already probed without busy_lock (its KDF must not run
 * under it); ownership of pre->hback / pre->bak_key moves here. NULL (mount): probed here.
 *
 * A power-loss protected session (FF_SAFE_TRANSCRYPT) is recovered from its journal first
 * (dc_slog_mount) and the header is saved right after the install, so it holds the exact
 * boundary and the journal is empty. from_bak: hcopy is the backup header.
 */
typedef struct _dc_bak_probe {
	int        done;    /* the probe below was made by the caller */
	int        resl;    /* its result */
	dc_header *hback;   /* decrypted backup header (resl == ST_OK) */
	xts_key   *bak_key; /* its header key (resl == ST_OK) */
} dc_bak_probe;

static int dc_install_session(dev_hook *hook, dc_header **p_hcopy, xts_key **p_hdr_key, dc_pass *password, ULONGLONG tmp_size, ULONG *interrupt_cmd, dc_bak_probe *pre, BOOLEAN from_bak, BOOLEAN save_now)
{
	dc_header *hcopy    = *p_hcopy;
	dc_header *hback    = NULL;
	u8        *bak_salt = NULL;
	xts_key   *bak_key  = NULL;
	u32        sync_type;
	int        resl;
	BOOLEAN    bak_fallback = FALSE; /* bak_salt / bak_key taken from the primary */
	u64        other_tmp = 0;        /* tmp_size of the header the volume is not mounted from */
	BOOLEAN    other_ok = FALSE;
	int        recovered = 0;

	if (hcopy->flags & VF_BACKUP_HEADER) {
		if ( (bak_salt = mm_secure_alloc(HEADER_SALT_SIZE)) == NULL ) {
			return ST_NOMEM;
		}
		if (pre != NULL && pre->done) {
			resl = pre->resl;
			hback = pre->hback;     pre->hback = NULL;
			bak_key = pre->bak_key; pre->bak_key = NULL;
		} else {
			// todo: hint at corerct kdf
			resl = dc_probe_decrypt_at(hook, &hback, &bak_key, password, NULL, hook->dsk_size - hook->head_len, hook->head_len, NULL, interrupt_cmd);
		}
		if (resl != ST_OK) {
			DbgMsg("mount failed to load backup header, dev=%ws, error=%d\n", hook->dev_name, resl);
			// restore backup header from primary header
			if ( (bak_key = mm_secure_alloc(sizeof(xts_key))) == NULL ) {
				mm_secure_free(bak_salt);
				return ST_NOMEM;
			}
			memcpy(bak_salt, hcopy->salt, HEADER_SALT_SIZE);
			memcpy(bak_key, *p_hdr_key, sizeof(xts_key));
			bak_fallback = TRUE;
		} else {
			memcpy(bak_salt, hback->salt, HEADER_SALT_SIZE);
			/* the other header only when mounted from the primary (from the backup, the probe
			 * found the same header again) */
			if (!from_bak) {
				other_tmp = hback->tmp_size;
				other_ok  = TRUE;
			}
			mm_secure_free(hback);
		}
	}

	/* recover a power-loss protected session from its journal before anything uses the
	 * boundary (no I/O is routed yet: the session install below publishes F_ENABLED / F_SYNC) */
	if ( (resl = dc_slog_mount(hook, hcopy, from_bak, other_tmp, other_ok, &tmp_size, &recovered)) != ST_OK ) {
		DbgMsg("dc_install_session: journal recovery failed (%d), dev=%ws\n", resl, hook->dev_name);
		if (bak_key != NULL)  mm_secure_free(bak_key);
		if (bak_salt != NULL) mm_secure_free(bak_salt);
		return resl;
	}

	hook->tmp_size      = tmp_size;
	hook->hdr_key       = *p_hdr_key;
	hook->crypt.wp_mode = hcopy->tmp_wp_mode;
	hook->tmp_header    = hcopy;
	hook->bak_key       = bak_key;
	hook->bak_salt      = bak_salt;

	*p_hdr_key = NULL;
	*p_hcopy   = NULL;

	sync_type = (hcopy->flags & VF_REENCRYPT) ? S_CONTINUE_RE_ENC : S_CONTINUE_ENC;

#ifdef DC_CONCURRENT_TRANSCRYPT
	if ( (resl = dc_transcrypt_init(hook, sync_type)) != ST_OK ) {
#else
	if ( (resl = dc_enable_sync_mode(hook, sync_type)) != ST_OK ) {
#endif
		DbgMsg("dc_install_session: sync mode error %d\n", resl);

		/* defensive (dc_transcrypt_init frees the session itself on failure): no session
		 * runs, free whatever is left instead of leaking it into the next mount */
		if ((hook->flags & F_SYNC) == 0) {
			if (hook->tmp_key != NULL) {
				if (hook->flags & F_HIBER_ERASE) {
					/* a failed unlock stays locked - keep the allocation, zeroed */
					RtlSecureZeroMemory(hook->tmp_key, sizeof(xts_key));
				} else {
					mm_secure_free(hook->tmp_key); hook->tmp_key = NULL;
				}
			}
			if (hook->hdr_key != NULL)    { mm_secure_free(hook->hdr_key);    hook->hdr_key = NULL; }
			if (hook->tmp_header != NULL) { mm_secure_free(hook->tmp_header); hook->tmp_header = NULL; }
			if (hook->bak_key != NULL)    { mm_secure_free(hook->bak_key);    hook->bak_key = NULL; }
			if (hook->bak_salt != NULL)   { mm_secure_free(hook->bak_salt);   hook->bak_salt = NULL; }
		}
	}
#ifdef DC_CONCURRENT_TRANSCRYPT
	/* after dc_transcrypt_init (it resets the flag) */
	if (resl == ST_OK && bak_fallback) {
		InterlockedExchange(&hook->trans.bak_clone_once, 1);
	}
	/* A power-loss protected session saves its header now: the recovered boundary reaches the
	 * disk, both headers carry the same value and the journal is emptied. Mounted from the
	 * backup: the primary gets the full header. A pending block refuses the save
	 * (ST_LOG_PENDING) and stays in the journal. save_now: the primary was damaged and the
	 * session comes from the backup or a repaired header - written now, not at the next save. */
	if (resl == ST_OK && (dc_slog_get(hook) != NULL || save_now)) {
		int sresl;

		if (from_bak) {
			InterlockedExchange(&hook->trans.full_hdr_once, 1);
		}
		dc_acquire_step_slot(hook);
		/* FF_SAFE_FAST: a block the recovery left pending is completed now that the keys are
		 * installed (else it stays quarantined and the save below refuses) */
		dc_safe_resolve_pending(hook);
		sresl = dc_save_enc_state(hook, SYNC_STEP_UPDATE);
		dc_release_step_slot(hook);
		DbgMsg("dc_install_session: %s session, recovered %d, header save %d, boundary %I64x, dev=%ws\n",
			(dc_slog_get(hook) != NULL) ? "protected" : "repaired", recovered, sresl, hook->tmp_size, hook->dev_name);
	}
#endif
	return resl;
}

/* key check value of a data key: a zero sector encrypted at offset 0 */
static void dc_key_check_value(xts_key *key, u8 kcv[32])
{
	u8 sector[SECTOR_SIZE];

	memset(sector, 0, sizeof(sector));
	cp_fast_encrypt(sector, sector, SECTOR_SIZE, 0, key);
	memcpy(kcv, sector, 32);
	burn(sector, sizeof(sector));
}

/*
 * Lock on hibernate: lock a mounted volume at S4. busy_lock held; the caller
 * (dc_process_power_irp) has already set F_PREVENT_ENC, waited for a running transcryption
 * step and saved the transcryption state.
 *
 * The volume and its file system stay mounted (F_ENABLED), so the FS never sees raw
 * pass-through. Every read/write fails with STATUS_FVE_LOCKED_VOLUME until dc_mount_device
 * unlocks it in place, or until it is dismounted.
 *
 * Order: block new I/O (F_DISABLE | F_HIBER_ERASE, one interlocked update), drain the I/O in
 * flight (io_depth -> 0, see the re-check in io_encrypted_irp_io), only then tear the session
 * down and zero the keys - no request runs with zeroed keys or after F_SYNC dropped. Our S4 IRP
 * is not forwarded yet, so the stack below is assumed to still complete requests. On timeout
 * the lock is rolled back before anything was destroyed: the volume stays usable with live
 * keys and the caller marks it so that the dump policy counts it (fail closed).
 *
 * Kept for the unlock: disk_id, crypt info, layout, tmp_size, mnt_flags, F_NO_HIBER and the
 * (zeroed) dsk_key / tmp_key allocations - the I/O path may hold a snapshot of those pointers,
 * the unlock re-keys them in place. Plus a key check value of the data key and whether the
 * state save right before failed (save_failed -> DC_LOCK_SAVE_FAILED).
 */
#define DC_LOCK_DRAIN_TIMEOUT (2000 * 10000ULL) /* 2 s in KeQueryInterruptTime units (100 ns) */

int dc_lock_volume(dev_hook *hook, int save_failed)
{
	ULONGLONG start;
	u32       pre_disable;

	if ((hook->flags & F_ENABLED) == 0) {
		return ST_NO_MOUNT;
	}
	if (hook->flags & F_HIBER_ERASE) {
		return ST_OK; /* already locked (e.g. hibernated again before the unlock) */
	}
	if (hook->flags & F_FORMATTING) {
		return ST_ERROR; /* format steps use the keys under busy_lock without an I/O drain */
	}
	if (hook->paging_count > 0) {
		/* paging reads after the resume would fail (KERNEL_DATA_INPAGE_ERROR); the caller
		 * marks it lock_failed and the dump policy counts it */
		return ST_DEVICE_BUSY;
	}
	if (hook->dsk_key == NULL || hook->dsk_key->encrypt == NULL) {
		return ST_ERROR; /* no usable key to fingerprint (zeroed by a dump?) */
	}

	DbgMsg("dc_lock_volume: locking %ws\n", hook->dev_name);

	/* no transcryption step may start or run (the caller did this already) */
	dc_hook_set_flags(hook, F_PREVENT_ENC);
#ifdef DC_CONCURRENT_TRANSCRYPT
	dc_wait_for_transcrypt(hook);
#else
	if (hook->flags & F_SYNC) {
		return ST_ERROR; /* the sync thread owns the session: not supported */
	}
#endif

	/* remember the data key and the session to verify / restore them at unlock */
	dc_key_check_value(hook->dsk_key, hook->lock_kcv);
	hook->lock_flags = hook->flags & (F_SYNC | F_REENCRYPT);
	if ((hook->lock_flags & F_SYNC) && save_failed) {
		hook->lock_flags |= DC_LOCK_SAVE_FAILED; /* the header may hold an older boundary */
	}

	/* block new read/write IRPs. F_DISABLE may already be set by IRP_MN_SURPRISE_REMOVAL -
	 * a rollback below must not clear it then. */
	pre_disable = hook->flags & F_DISABLE;
	dc_hook_set_flags(hook, F_DISABLE | F_HIBER_ERASE);

	/* Drain the I/O in flight, bounded by interrupt time (dc_delay may sleep longer than
	 * asked). Requests failed meanwhile stay failed after a rollback (as any I/O error). */
	for (start = KeQueryInterruptTime(); hook->io_depth > 0; )
	{
		if (KeQueryInterruptTime() - start >= DC_LOCK_DRAIN_TIMEOUT) {
			DbgMsg("dc_lock_volume: %d requests still in flight after %I64u ms, lock rolled back, dev=%ws\n",
				hook->io_depth, (KeQueryInterruptTime() - start) / 10000, hook->dev_name);
			dc_hook_clear_flags(hook, F_HIBER_ERASE | (pre_disable ? 0 : F_DISABLE)); /* only what this lock set */
			hook->lock_flags = 0;
			RtlSecureZeroMemory(hook->lock_kcv, sizeof(hook->lock_kcv));
			return ST_DEVICE_BUSY;
		}
		dc_delay(10);
	}

#ifdef DC_CONCURRENT_TRANSCRYPT
	/* the state was saved by the caller; frees and wipes the session (tmp_header holds the
	 * master keys); tmp_key is only zeroed (F_HIBER_ERASE is set) */
	if (hook->flags & F_SYNC) {
		dc_transcrypt_cleanup(hook);
	}
#endif

	/* zero the data key, keep its allocation (see above) */
	RtlSecureZeroMemory(hook->dsk_key, sizeof(xts_key));

	/* same for tmp_key (re-encryption); freed by the unmount of the locked volume */
	if (hook->tmp_key != NULL) {
		RtlSecureZeroMemory(hook->tmp_key, sizeof(xts_key));
	}

	/* anything left outside a session (normally all NULL by now) */
	if (hook->hdr_key != NULL)    { mm_secure_free(hook->hdr_key);    hook->hdr_key = NULL; }
	if (hook->tmp_header != NULL) { mm_secure_free(hook->tmp_header); hook->tmp_header = NULL; }
	if (hook->bak_key != NULL)    { mm_secure_free(hook->bak_key);    hook->bak_key = NULL; }
	if (hook->bak_salt != NULL)   { mm_secure_free(hook->bak_salt);   hook->bak_salt = NULL; }

	InterlockedExchange(&hook->lock_failed, 0);
	hook->lock_seq++; /* an unlock that probed the header before this lock must start over */

	// Flush CPU caches to ensure keys not recoverable
	__wbinvd();

	DbgMsg("dc_lock_volume: %ws locked\n", hook->dev_name);
	return ST_OK;
}

/*
 * Unlock a locked volume in place with its decrypted (and checked) header. busy_lock held.
 * The header must describe the very volume and layout the FS is still mounted on, and carry
 * the same data key (key check value) - otherwise ST_MEDIA_CHANGED and the volume stays
 * locked. The mount flags (MF_READ_ONLY, ...) stay those of the original mount.
 */
static int dc_unlock_in_place(dev_hook *hook, dc_header **p_hcopy, xts_key **p_hdr_key, dc_pass *password, int head_kdf, ULONG *interrupt_cmd, dc_bak_probe *bak, BOOLEAN from_bak)
{
	dc_header    *hcopy = *p_hcopy;
	dc_hdr_layout lt;
	u8            kcv[32];
	int           same_key;
	int           resl;

	dc_header_layout(hook, hcopy, &lt);

	/* Compared: everything that maps the FS's offsets to disk offsets. Not compared: use_size
	 * and crypt.head_len - a remount may derive other values from the same header than a
	 * session started in this boot; the in-memory ones are what the mounted FS uses. */
	if ( hcopy->disk_id != hook->disk_id ||
		 lt.head_len != hook->head_len ||
		 lt.stor_off != hook->stor_off || lt.stor_len != hook->stor_len ||
		 lt.flags != (hook->flags & DC_LAYOUT_FLAGS) ||
		 lt.tail_len != hook->tail_len || lt.tail_off != hook->tail_off ||
		 ((hcopy->flags & VF_TMP_MODE) != 0) != ((hook->lock_flags & F_SYNC) != 0) ||
		 ( (hcopy->flags & VF_TMP_MODE) && ((hcopy->flags & VF_REENCRYPT) != 0) != ((hook->lock_flags & F_REENCRYPT) != 0) ) )
	{
		DbgMsg("unlock: header does not match the locked volume (disk_id %x/%x, head_len %u/%u, stor_off %I64u/%I64u, "
			"stor_len %u/%u, flags %x/%x, tmp_mode %d/%d), dev=%ws\n",
			hcopy->disk_id, hook->disk_id, lt.head_len, hook->head_len, lt.stor_off, hook->stor_off,
			lt.stor_len, hook->stor_len, lt.flags, hook->flags & DC_LAYOUT_FLAGS,
			(hcopy->flags & VF_TMP_MODE) != 0, (hook->lock_flags & F_SYNC) != 0, hook->dev_name);
		return ST_MEDIA_CHANGED;
	}

	/* re-key the kept allocation; I/O is blocked and drained, nothing reads it now */
	if ( !xts_set_key(hcopy->key_1, hcopy->alg_1, hook->dsk_key) ) {
		RtlSecureZeroMemory(hook->dsk_key, sizeof(xts_key));
		return ST_INVALID_PARAM;
	}
	dc_key_check_value(hook->dsk_key, kcv);
	same_key = (memcmp(kcv, hook->lock_kcv, sizeof(kcv)) == 0);
	burn(kcv, sizeof(kcv));

	if (same_key == 0) {
		DbgMsg("unlock: data key differs from the locked volume's, dev=%ws\n", hook->dev_name);
		RtlSecureZeroMemory(hook->dsk_key, sizeof(xts_key));
		return ST_MEDIA_CHANGED;
	}

	/* header metadata a mount takes (slots / KDF may have changed while locked elsewhere) */
	hook->crypt.cipher_id = d8(hcopy->alg_1);
	hook->crypt.version   = hcopy->version;
	if (hcopy->version >= DC_HDR_VERSION_2 && (hcopy->feature_flags & FF_KEY_SLOTS)) {
		hook->crypt.head_kdf   = hcopy->head_kdf;
		hook->crypt.slot_count = hcopy->key_slot_count;
	} else {
		hook->crypt.head_kdf = head_kdf;
	}

	if (hcopy->flags & VF_TMP_MODE)
	{
		/* Re-initialise the session the lock tore down, with the in-memory boundary. The
		 * header's differs legitimately only if the lock's state save failed; otherwise the
		 * volume was transcrypted elsewhere while this system hibernated. */
		if (hcopy->tmp_size != hook->tmp_size) {
			if ((hook->lock_flags & DC_LOCK_SAVE_FAILED) == 0) {
				DbgMsg("unlock: header tmp_size %I64u differs from the locked state %I64u, volume changed elsewhere, dev=%ws\n",
					hcopy->tmp_size, hook->tmp_size, hook->dev_name);
				RtlSecureZeroMemory(hook->dsk_key, sizeof(xts_key));
				return ST_MEDIA_CHANGED;
			}
			DbgMsg("unlock: header tmp_size %I64u differs from the locked state %I64u (state save failed), using the latter, dev=%ws\n",
				hcopy->tmp_size, hook->tmp_size, hook->dev_name);
		}
		if ( (resl = dc_install_session(hook, p_hcopy, p_hdr_key, password, hook->tmp_size, interrupt_cmd, bak, from_bak, FALSE)) != ST_OK ) {
			RtlSecureZeroMemory(hook->dsk_key, sizeof(xts_key));
			return resl;
		}
	}

	/* keys and session are in place: drop the lock last (interlocked, full barrier, so a
	 * request that sees the lock gone also sees the keys) */
	hook->lock_flags = 0;
	RtlSecureZeroMemory(hook->lock_kcv, sizeof(hook->lock_kcv));
	InterlockedExchange(&hook->lock_failed, 0);
	dc_hook_clear_flags(hook, F_HIBER_ERASE | F_DISABLE | F_PREVENT_ENC);

	DbgMsg("unlock: %ws unlocked\n", hook->dev_name);
	return ST_OK;
}

/*
 * The geometry a decrypted header describes must fit this device - checked before
 * dc_header_layout derives the hook layout from it (its unsigned arithmetic wraps on a bad
 * header). The checks are volume_lib's dc_check_header_geometry, shared with the boot loader;
 * it may clear VF_BACKUP_HEADER in hcopy.
 */
static int dc_check_geometry(dev_hook *hook, dc_header *hcopy)
{
	int resl = dc_check_header_geometry(hcopy, hook->dsk_size, hook->bps);

	if (resl != ST_OK) {
		DbgMsg("mount: header geometry does not fit the device (size %I64u, bps %u), dev=%ws\n",
			hook->dsk_size, hook->bps, hook->dev_name);
	}
	return resl;
}

/* volume header checks, shared by a mount and an unlock in place */
static int dc_check_header(dev_hook *hook, dc_header *hcopy)
{
	if ( ( (hcopy->flags & VF_NO_REDIR) && (hcopy->flags & (VF_TMP_MODE | VF_REENCRYPT | VF_STORAGE_FILE)) ) ||
		 ( (hcopy->flags & VF_STORAGE_FILE) && (hcopy->stor_off == 0) ) ||
		 (hcopy->alg_1 >= CF_CIPHERS_NUM) ||
		 (hcopy->alg_2 >= CF_CIPHERS_NUM) ||
		 (hcopy->tmp_wp_mode != WP_SKIP_UNUSED && hcopy->tmp_wp_mode >= WP_NUM) ||
		 ( (hook->flags & F_CDROM) && (hcopy->flags & (VF_TMP_MODE | VF_STORAGE_FILE)) ) )
	{
		return ST_INV_VOLUME;
	}
	if (hcopy->version > DC_HDR_VERSION_2) {
		return ST_VOLUME_TOO_NEW;
	}
	return dc_check_geometry(hook, hcopy);
}

/*
 * Unlock a locked volume in place. Entered with busy_lock held and the volume locked;
 * returns with busy_lock RELEASED.
 *
 * The header probe and decryption (KDF: seconds per password) run WITHOUT busy_lock - the
 * power IRPs, unmount and the other paths of this volume wait on it. Re-taken afterwards, the
 * volume must still be the same locked volume: no unlock, unmount / remount (chg_mount),
 * re-lock (lock_seq) or hibernation start in between. The layout the probe needs is
 * snapshotted under busy_lock; only an unmount changes it (and bumps chg_mount).
 *
 * A volume mounted from its backup header (MF_USE_BACKUP) is unlocked from it as well.
 */
static int dc_unlock_hook(dev_hook *hook, dc_pass *password, u32 mnt_flags, ULONG *interrupt_cmd)
{
	dc_header   *hcopy     = NULL;
	xts_key     *hdr_key   = NULL;
	dc_bak_probe bak       = { 0 };
	dc_dev       dev;
	u32          chg_mount = hook->chg_mount;
	u32          lock_seq  = hook->lock_seq;
	u64          dsk_size  = hook->dsk_size;
	ULONG        head_len  = hook->head_len;
	int          use_bak;
	u64          hdr_pos   = 0;
	int          hdr_len   = 0;
	int          head_kdf  = 0;
	int          resl;
	int          repair    = DC_HDR_INTACT;
	u32          forced    = hook->mnt_flags & MF_IGNORE_CRC; /* mounted with a damaged header */

	mnt_flags |= hook->mnt_flags & MF_USE_BACKUP;
	/* the damaged header of a forced mount is accepted again by its unlock; a regular mount
	 * never becomes a forced one in place (it would lose its writes) */
	mnt_flags = (mnt_flags & ~MF_IGNORE_CRC) | forced;
	use_bak = (mnt_flags & MF_USE_BACKUP) && (hook->flags & F_HEAD_BACKUP);
	dc_dev_of(hook, &dev);

	KeReleaseMutex(&hook->busy_lock, FALSE);

	do
	{
		if (use_bak) {
			/* the backup header of a mounted volume is at a known place (as in dc_update_header) */
			hdr_pos = dsk_size - head_len;
			hdr_len = head_len;
			resl = dc_probe_decrypt_at(hook, &hcopy, &hdr_key, password, &head_kdf, hdr_pos, hdr_len, NULL, interrupt_cmd);
		} else {
			resl = dc_probe_decrypt(hook, &hcopy, &hdr_key, password, &head_kdf, mnt_flags, &hdr_pos, &hdr_len, &repair, interrupt_cmd);
		}
		if (resl != ST_OK) {
			break;
		}
		if (repair != DC_HDR_INTACT) {
			DbgMsg("unlock: damaged primary header, recovered (%d), dev=%ws\n", repair, hook->dev_name);
		}

		/* read and decrypt rest of v2 header */
		if ( (resl = io_read_header_full(&dev, dc_hook_rw, hdr_pos, &hcopy, hdr_key, hdr_len)) != ST_OK ) {
			break;
		}
		if ( (resl = dc_check_header(hook, hcopy)) != ST_OK ) {
			break;
		}

		/* the backup header a session keeps (dc_install_session), probed here for the same reason */
		if ((hcopy->flags & (VF_TMP_MODE | VF_BACKUP_HEADER)) == (VF_TMP_MODE | VF_BACKUP_HEADER)) {
			// todo: hint at corerct kdf
			bak.resl = dc_probe_decrypt_at(hook, &bak.hback, &bak.bak_key, password, NULL, dsk_size - head_len, head_len, NULL, interrupt_cmd);
			bak.done = 1;
		}

		/* counted for the mount probe (it holds an IRP's remove-lock reference) */
		if (mnt_flags & MF_PROBE_RL) {
			dc_wait_busy_lock_rl(hook);
		} else {
			wait_object_infinity(&hook->busy_lock);
		}

		if (dc_s4_transition_active()) {
			resl = ST_CANCEL;       /* hibernating again */
		} else if ((hook->flags & F_ENABLED) == 0) {
			resl = ST_NO_MOUNT;     /* dismounted meanwhile */
		} else if (DC_HOOK_LOCKED(hook) == 0) {
			resl = ST_ALR_MOUNT;    /* unlocked meanwhile */
		} else if (hook->chg_mount != chg_mount || hook->lock_seq != lock_seq) {
			resl = ST_DEVICE_BUSY;  /* another volume / another lock: probe again */
		} else if (hook->pnp_state == SurpriseRemove || hook->pnp_state == Deleted) {
			/* the device is going away (state set before its F_DISABLE / drain / key free):
			 * do not clear F_DISABLE / install keys behind that drain */
			resl = ST_NF_DEVICE;
		} else if ( (hook->flags & (F_PLAIN_IO | F_FORMATTING)) || hook->dsk_key == NULL || hook->bps == 0 ) {
			resl = ST_ERROR;
		} else {
			/* the salt may differ from the pre-hibernation identity (password changed
			 * elsewhere). Set before dc_unlock_in_place re-enables I/O. The media change count
			 * is NOT adopted here (a medium may have been swapped in after the header was
			 * read); the first write tests the identity and adopts it. */
			if (hook->flags & F_REMOVABLE) {
				io_id_set_header(hook, hcopy->salt, hdr_pos);
			}
			resl = dc_unlock_in_place(hook, &hcopy, &hdr_key, password, head_kdf, interrupt_cmd, &bak, hdr_pos != 0);
#ifdef DC_CONCURRENT_TRANSCRYPT
			/* unlocked from the backup header with a session: the next save writes the
			 * full primary */
			if (resl == ST_OK && hdr_pos != 0 && (hook->flags & F_SYNC)) {
				InterlockedExchange(&hook->trans.full_hdr_once, 1);
			}
#endif
		}

		KeReleaseMutex(&hook->busy_lock, FALSE);
	} while (0);

	if (hdr_key != NULL)     mm_secure_free(hdr_key);
	if (hcopy != NULL)       mm_secure_free(hcopy);
	if (bak.bak_key != NULL) mm_secure_free(bak.bak_key);
	if (bak.hback != NULL)   mm_secure_free(bak.hback);

	return resl;
}

/*
 * Mount a volume - or unlock it in place when it is locked (F_ENABLED | F_HIBER_ERASE, see
 * dc_unlock_hook): same password probing (password NULL: cached only) and header checks.
 * MF_USE_BACKUP selects the backup header for both. Returns ST_OK, ST_PASS_ERR,
 * ST_MEDIA_CHANGED (unlock: the header is not the locked volume's), ST_ALR_MOUNT (mounted and
 * not locked), ST_CANCEL (hibernation in progress), ...
 *
 * unlock_only: decided under busy_lock, a volume that is no longer locked returns ST_NO_MOUNT
 * (dismounted) / ST_ALR_MOUNT (unlocked) instead of being mounted from scratch.
 */
static int dc_mount_hook(dev_hook *hook, dc_pass *password, u32 mnt_flags, ULONG *interrupt_cmd, int unlock_only, u32 probe_chg_mount)
{
	dc_header *hcopy = NULL;
	dc_ext_header* ext_hdr = NULL;
	dc_dev     dev;
	xts_key   *hdr_key = NULL;
	int        resl;
	int        head_kdf = 0;
	u64        hdr_pos = 0;
	int        hdr_len = 0;
	int        layout_set = 0; /* the header layout was applied to the hook */
	int        repair = DC_HDR_INTACT;
	dc_hdr_layout lt;

	/* counted for the mount probe (it holds an IRP's remove-lock reference); the state is
	 * re-validated below */
	if (mnt_flags & MF_PROBE_RL) {
		dc_wait_busy_lock_rl(hook);
	} else {
		wait_object_infinity(&hook->busy_lock);
	}

	do
	{
		/* a mount / unmount ran while the probe waited: do not undo the user's unmount by
		 * auto-mounting with cached passwords (mount_item_proc stops probing) */
		if ((mnt_flags & MF_PROBE_RL) && hook->chg_mount != probe_chg_mount) {
			resl = ST_DEVICE_BUSY; break;
		}
		if (dc_s4_transition_active()) {
			/* between the first S4 SET_POWER and the S0 SET_POWER */
			DbgMsg("mount / unlock refused: hibernation in progress, dev=%ws\n", hook->dev_name);
			resl = ST_CANCEL; break;
		}

		if (hook->flags & F_ENABLED)
		{
			if (DC_HOOK_LOCKED(hook) == 0) {
				resl = ST_ALR_MOUNT; break;
			}
			/* unlock in place. Not after a finished decryption (F_PLAIN_IO: the header is
			 * gone). The device info is not re-read: the hook must keep describing the
			 * mounted volume. */
			if ( (hook->flags & (F_PLAIN_IO | F_FORMATTING)) || hook->dsk_key == NULL || hook->bps == 0 ) {
				resl = ST_ERROR; break;
			}
			/* releases busy_lock */
			return dc_unlock_hook(hook, password, mnt_flags, interrupt_cmd);
		}

		if (unlock_only) {
			resl = ST_NO_MOUNT; break; /* not mounted (any more) - nothing to unlock */
		}

		if (hook->flags & (F_UNSUPRT | F_DISABLE | F_FORMATTING)) {
			resl = ST_ERROR; break;
		}

		if ( !NT_SUCCESS(dc_fill_device_info(hook)) ) {
			resl = ST_IO_ERROR; break;
		}
		dc_media_baseline(hook);

		if ( ( (hook->flags & F_CDROM) && (hook->bps != CD_SECTOR_SIZE) ) ||
			 (!(hook->flags & F_CDROM) && IS_INVALID_SECTOR_SIZE(hook->bps) ) )
		{
			/* interlocked - other bits are set without busy_lock */
			dc_hook_set_flags(hook, F_UNSUPRT); resl = ST_ERROR; break;
		}

		resl = dc_probe_decrypt(hook, &hcopy, &hdr_key, password, &head_kdf, mnt_flags, &hdr_pos, &hdr_len, &repair, interrupt_cmd);
		if (resl != ST_OK) {
			break;
		}
		/* a damaged header taken as it is mounts read-only and stays MF_IGNORE_CRC (no header
		 * write, no step); otherwise the flag is dropped - the header in hand is valid */
		if (repair == DC_HDR_FORCED) {
			mnt_flags |= MF_READ_ONLY | MF_IGNORE_CRC;
		} else {
			mnt_flags &= ~MF_IGNORE_CRC;
		}

		/* read and decrypt rest of v2 header */
		dc_dev_of(hook, &dev);

		if ( (resl = io_read_header_full(&dev, dc_hook_rw, hdr_pos, &hcopy, hdr_key, hdr_len)) != ST_OK ) {
			break;
		}

		/* check volume header */
		if ( (resl = dc_check_header(hook, hcopy)) != ST_OK ) {
			break;
		}
		/* identity of the medium for io_check_media: the salt of the header just
		 * authenticated, at the place it was read from */
		if (hook->flags & F_REMOVABLE) {
			io_id_set_header(hook, hcopy->salt, hdr_pos);

			/* mounted from the backup header: DC may overwrite that place itself before the
			 * primary is written. Also record what sector 0 holds now. */
			if (hdr_pos != 0) {
				u32 s0_len = max(hook->bps, SECTOR_SIZE);
				u8 *s0     = mm_pool_alloc(s0_len);

				if (s0 != NULL) {
					if (NT_SUCCESS(io_device_request(hook->orig_dev, IRP_MJ_READ, s0, s0_len, 0))) {
						io_id_set_sector0(hook, s0, s0_len);
					}
					mm_pool_free(s0);
				}
			}
		}
#if 0
		/* update volume header if needed */
		if ( (hcopy->version < DC_HDR_VERSION) && !(hook->flags & F_CDROM) )
		{
			hcopy->version = DC_HDR_VERSION;
			memset(hcopy->deprecated, 0, sizeof(hcopy->deprecated));

			io_write_header(&dev, dc_hook_rw, 0, hcopy, hdr_key, NULL, HF_DEFAULT, NULL);
		}
#endif

		DbgMsg("hdr_key=%p\n", hdr_key);

		// initialize volume key
		if ( (hook->dsk_key = (xts_key*)mm_secure_alloc(sizeof(xts_key))) == NULL ) {
			resl = ST_NOMEM;
			break;
		}
		if ( !xts_set_key(hcopy->key_1, hcopy->alg_1, hook->dsk_key)) {
			resl = ST_INVALID_PARAM;
			break;
		}

		DbgMsg("device mounted\n");

		dc_header_layout(hook, hcopy, &lt);

		memset(&hook->crypt, 0, sizeof(hook->crypt));
		hook->head_len        = lt.head_len;
		hook->use_size        = lt.use_size;
		hook->stor_off        = lt.stor_off;
		hook->stor_len        = lt.stor_len;
		hook->crypt.head_len  = lt.crypt_head_len;
		hook->crypt.cipher_id = d8(hcopy->alg_1);
		hook->disk_id         = hcopy->disk_id;
		hook->crypt.version   = hcopy->version;
		hook->tmp_size        = 0;
		hook->mnt_flags       = mnt_flags & ~MF_PROBE_RL; /* internal */

		DbgMsg("hook->crypt.version %d\n", hook->crypt.version);
		DbgMsg("hook->bps %d\n", hook->bps);
		DbgMsg("hook->head_len %d\n", hook->head_len);
		DbgMsg("hook->stor_off %I64d\n", hook->stor_off);
		DbgMsg("hook->stor_len %d\n", hook->stor_len);
		DbgMsg("hook->disk_id %x\n", hook->disk_id);
		DbgMsg("hcopy->flags %x\n", hcopy->flags);

		get_ext_header(hcopy, &ext_hdr);
		if (ext_hdr != NULL) {
			DbgMsg("extended header size %d, version: %d\n", ext_hdr->size, ext_hdr->version);
		}

		if (hcopy->version >= DC_HDR_VERSION_2 && (hcopy->feature_flags & FF_KEY_SLOTS)) {
			hook->crypt.head_kdf = hcopy->head_kdf;
			hook->crypt.slot_count = hcopy->key_slot_count;
		} else {
			hook->crypt.head_kdf = head_kdf;
		}

		/* atomic flag updates: power/unmount paths may change other bits concurrently.
		 * The layout bits are set to exactly this header's; not mounted yet, so no I/O uses
		 * them. Undone below if this mount fails. */
		layout_set = 1;
		if ((hook->flags & DC_LAYOUT_FLAGS & ~lt.flags) != 0) {
			dc_hook_clear_flags(hook, DC_LAYOUT_FLAGS & ~lt.flags);
		}
		if (lt.flags != 0) {
			dc_hook_set_flags(hook, lt.flags); /* F_PROTECT_DCSYS / F_NO_REDIRECT / F_HEAD_BACKUP */
		}
		if ((hcopy->flags & VF_NO_HIBER) || (mnt_flags & MF_NO_HIBER)) {
			/* not on the system / hibernation / crash dump volume, nor on one with a paging
			 * file. Set first, then re-check: the usage notification sets its flags and then
			 * tests F_NO_HIBER without busy_lock; with both sides set-then-test (interlocked)
			 * at least one of them sees the other and the flag is cleared. */
			dc_hook_set_flags(hook, F_NO_HIBER);
			if (DC_NO_HIBER_FORBIDDEN(hook) || hook->paging_count > 0) {
				DbgMsg("no-hibernation option ignored on system/dump/paging volume %ws\n", hook->dev_name);
				dc_hook_clear_flags(hook, F_NO_HIBER);
			}
		}
		/* tail redirect: see dc_header_layout */
		hook->tail_len = lt.tail_len;
		hook->tail_off = lt.tail_off;

		if (hcopy->flags & VF_TMP_MODE) {
			resl = dc_install_session(hook, &hcopy, &hdr_key, password, hcopy->tmp_size, interrupt_cmd, NULL, hdr_pos != 0,
				(repair == DC_HDR_BACKUP || repair == DC_HDR_REPAIRED) && !(mnt_flags & MF_READ_ONLY));
#ifdef DC_CONCURRENT_TRANSCRYPT
			/* the session header is the backup's - the next save writes the full primary */
			if (resl == ST_OK && hdr_pos != 0) {
				InterlockedExchange(&hook->trans.full_hdr_once, 1);
			}
#endif
		} else {
			dc_hook_set_flags(hook, F_ENABLED);
			resl = ST_OK;
		}
		if (resl == ST_OK) {
			/* Clear raw flag - volume is now mounted and handled properly */
			dc_hook_clear_flags(hook, F_FS_RAW);
			/* increment mount changes counter */
			lock_inc(&hook->chg_mount);
		}
	} while (0);

	if (hdr_key != NULL) mm_secure_free(hdr_key);
	if (hcopy != NULL)   mm_secure_free(hcopy);

	if ((hook->flags & F_ENABLED) == 0 && hook->dsk_key != NULL) {
		mm_secure_free(hook->dsk_key);
		hook->dsk_key = NULL;
	}

	/* a failed mount after the layout was applied: drop what this mount put on the hook, as
	 * an unmount would, so no stale layout reaches a later format, encryption start or mount.
	 * F_ENABLED was never published on these paths, so no I/O used the layout. */
	if (layout_set && (hook->flags & F_ENABLED) == 0) {
		dc_hook_clear_flags(hook, DC_LAYOUT_FLAGS | F_NO_HIBER | F_PROTECT_DCLOG); /* F_PROTECT_DCLOG: set by a journal recovery */
		hook->tail_len = 0;
		hook->tail_off = 0;
		hook->tmp_size = 0;
		/* like an unmount: a later encryption start never sets mnt_flags */
		hook->mnt_flags = 0;
		hook->use_size  = hook->dsk_size;
	}

	KeReleaseMutex(&hook->busy_lock, FALSE);
	return resl;
}

/* see mount.h */
void dc_wait_busy_lock_rl(dev_hook *hook)
{
	InterlockedIncrement(&hook->rl_waiters);
	wait_object_infinity(&hook->busy_lock);
	InterlockedDecrement(&hook->rl_waiters);
}

NTSTATUS dc_wait_busy_lock_rl_timeout(dev_hook *hook, PLARGE_INTEGER timeout)
{
	NTSTATUS status;

	InterlockedIncrement(&hook->rl_waiters);
	status = KeWaitForSingleObject(&hook->busy_lock, Executive, KernelMode, FALSE, timeout);
	InterlockedDecrement(&hook->rl_waiters);
	if (status == STATUS_TIMEOUT) {
		/* leaves without busy_lock, possibly while a drain runs: bumped AFTER the decrement
		 * and before the caller releases its remove-lock reference (see dc_rl_drained) */
		InterlockedIncrement(&hook->rl_timeouts);
	}
	return status;
}

/*
 * The drain test. rl_waiters is read before IoCount (a waiter counts itself only after
 * taking its remove-lock reference, so a waiter missed here is still in IoCount). A counted
 * waiter leaves without busy_lock only by a timeout, which bumps rl_timeouts: a change across
 * the reads means not drained. A timed-out waiter between its rl_waiters decrement and its
 * rl_timeouts increment can still be counted as blocked; benign, only dc_surprise_unmount
 * uses the timeout and it touches no keys on that path.
 * base: the references the drain itself expects (bias, and the caller's own IRP).
 */
BOOLEAN dc_rl_drained(dev_hook *hook, LONG base)
{
	LONG t  = InterlockedCompareExchange(&hook->rl_timeouts, 0, 0);
	LONG w  = InterlockedCompareExchange(&hook->rl_waiters, 0, 0);
	LONG io = InterlockedCompareExchange((volatile LONG*)&hook->remove_lock.Common.IoCount, 0, 0);

	return (io <= base + w) && (InterlockedCompareExchange(&hook->rl_timeouts, 0, 0) == t);
}

int dc_mount_device(wchar_t *dev_name, dc_pass *password, u32 mnt_flags, ULONG *interrupt_cmd)
{
	dev_hook *hook;
	int       resl;

	DbgMsg("dc_mount_device %ws\n", dev_name);

	if ( (hook = dc_find_hook(dev_name)) == NULL ) {
		return ST_NF_DEVICE;
	}
	resl = dc_mount_hook(hook, password, mnt_flags, interrupt_cmd, 0, 0);
	dc_deref_hook(hook);

	return resl;
}

/* retry schedule of the automatic unlock after resume, about 10 s in all */
static const u32 dc_unlock_retry_delays[] = { 250, 500, 1000, 2000, 3000, 3250 }; /* ms */
#define DC_UNLOCK_RETRIES ((int)(sizeof(dc_unlock_retry_delays) / sizeof(dc_unlock_retry_delays[0])))

/* an I/O-class failure - the disk may still be powering up after the resume. Not
 * ST_PASS_ERR / ST_MEDIA_CHANGED (final; a retry would only run the KDF again). */
static int dc_unlock_retryable(int resl)
{
	return resl == ST_RW_ERR || resl == ST_IO_ERROR || resl == ST_NO_MEDIA || resl == ST_NOMEM || resl == ST_DEVICE_BUSY;
}

/*
 * Unlock every locked volume with password (NULL: the cached passwords / boot keys only).
 * hooks_sync_resource is NOT held across dc_mount_hook (see dc_mount_all): the locked hooks
 * are collected and referenced, the list is released, then they are unlocked one by one.
 * retry: retry the I/O-class failures with a backoff. Returns the number unlocked.
 */
static int dc_unlock_hooks(dc_pass *password, u32 mnt_flags, ULONG *interrupt_cmd, int retry)
{
	dev_hook **list;
	dev_hook  *hook;
	int        cap = 0, n = 0, num = 0;
	int        i, round, pending;

	for (hook = dc_first_hook(); hook != NULL; hook = dc_next_hook(hook)) {
		if (DC_HOOK_LOCKED(hook)) cap++;
	}
	if (cap == 0) {
		return 0;
	}
	if ( (list = (dev_hook**)mm_pool_alloc(cap * sizeof(dev_hook*))) == NULL ) {
		DbgMsg("dc_unlock_hooks: no memory for %d hooks\n", cap);
		return 0;
	}
	/* walked to the end: dc_next_hook releases the list resource there */
	for (hook = dc_first_hook(); hook != NULL; hook = dc_next_hook(hook)) {
		if (DC_HOOK_LOCKED(hook) && n < cap) {
			dc_reference_hook(hook);
			list[n++] = hook;
		}
	}

	for (round = 0; ; round++)
	{
		pending = 0;

		for (i = 0; i < n; i++)
		{
			int resl;

			if (list[i] == NULL) continue;

			resl = dc_mount_hook(list[i], password, mnt_flags, interrupt_cmd, 1, 0);
			DbgMsg("unlock of locked volume, dev=%ws, status=%d, round=%d\n", list[i]->dev_name, resl, round);

			if (resl == ST_OK) num++;

			if (retry && round < DC_UNLOCK_RETRIES && dc_unlock_retryable(resl)) {
				pending++; continue; /* again after the delay */
			}
			dc_deref_hook(list[i]);
			list[i] = NULL;
		}
		if (pending == 0) {
			break;
		}
		dc_delay(dc_unlock_retry_delays[round]);
	}

	mm_pool_free(list);
	return num;
}

/*
 * On resume, try to unlock every locked volume with the cached passwords and the boot keys.
 * A volume none of them fits stays locked until the user unlocks or dismounts it. No
 * busy_lock held. retry: see dc_unlock_hooks. Returns the number unlocked.
 */
int dc_unlock_locked_volumes(int retry)
{
	return dc_unlock_hooks(NULL, 0, NULL, retry);
}

int dc_num_locked()
{
	dev_hook *hook;
	int       num = 0;

	for (hook = dc_first_hook(); hook != NULL; hook = dc_next_hook(hook)) {
		if (DC_HOOK_LOCKED(hook)) num++;
	}
	return num;
}

/*
   this routine process unmounting the device
   unmount options:
    UM_NOFSCTL - unmount without reporting to FS
	UM_FORCE   - force unmounting
*/
int dc_process_unmount(dev_hook *hook, int opt)
{
	IO_STATUS_BLOCK iosb;
	NTSTATUS        status;
	HANDLE          h_dev  = NULL;
	int             locked = 0;
	int             was_locked = 0; /* volume locked at hibernation */
	int             undone = 0;     /* a pending initial header was undone (plaintext again) */
	int             resl;

	DbgMsg("dc_process_unmount, dev=%ws\n", hook->dev_name);
	
	if ((hook->flags & F_ENABLED) == 0)
	{
		return ST_NO_MOUNT;
	}

	wait_object_infinity(&hook->busy_lock);

	if ((hook->flags & F_ENABLED) == 0)
	{
		resl = ST_NO_MOUNT;
		goto cleanup;
	}

	do
	{
		if (hook->flags & F_FORMATTING) {
			dc_format_done(hook->dev_name);
		}

		if ( !(hook->flags & F_SYSTEM) && !(opt & MF_NOFSCTL) )
		{
			h_dev = io_open_device(hook->dev_name);

			if ( (h_dev == NULL) && !(opt & MF_FORCE) )	{
				resl = ST_LOCK_ERR; break;
			}

			if (h_dev != NULL)
			{
				status = ZwFsControlFile(h_dev, NULL, NULL, NULL, &iosb, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0);

				if ( (NT_SUCCESS(status) == FALSE) && !(opt & MF_FORCE) ) {
					resl = ST_LOCK_ERR; break;
				}
				locked = (NT_SUCCESS(status) != FALSE);

				ZwFsControlFile(h_dev, NULL, NULL, NULL, &iosb, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0);				
			}
		}

		if ((opt & MF_NOSYNC) == 0)
		{
			// temporarily disable IRP processing and transcryption
			dc_hook_set_flags(hook, F_DISABLE | F_PREVENT_ENC); /* a transcrypt step may be updating flags concurrently */

			// wait for pending IRPs completion
			/* not for references whose holder is blocked on busy_lock (held here) - they
			 * could never complete; such a waiter re-validates after this unmount */
			if ((opt & MF_NOWAIT_IO) == 0) {
				while (!dc_rl_drained(hook, 1)) dc_delay(20);
			}
			if (hook->flags & F_SYNC) {
#ifdef DC_CONCURRENT_TRANSCRYPT
				/* Wait for any in-progress transcryption to complete.
				 * F_PREVENT_ENC prevents new transcryption steps from starting,
				 * but we need to wait for any step that's already in progress. */
				dc_wait_for_transcrypt(hook);
				/* Save state for resume and cleanup resources.
				 * A session whose initial header is still not on disk is undone
				 * instead (its head would be lost with the redirect) */
				if (dc_save_enc_state(hook, SYNC_STEP_UPDATE) != ST_OK &&
					InterlockedCompareExchange(&hook->trans.init_hdr_pending, 0, 0) != 0)
				{
					/* not MF_DECRYPTED (it would clear CONF_BLOCK_UNENC_HDDS for a system volume);
					 * not marked F_FS_RAW below (no re-probe follows). The $dcsys$ file stays. */
					undone = (dc_init_pending_undo(hook) == ST_OK);
				}
				dc_transcrypt_cleanup(hook);
#else
				// send signal to synchronous mode thread
				dc_send_sync_packet(hook->dev_name, S_OP_FINALIZE, 0);
#endif
			}
		}

		was_locked = (hook->flags & F_HIBER_ERASE) != 0;
		dc_hook_clear_flags(hook, F_CLEAR_ON_UNMOUNT);
		/* no tail redirect may survive into a later mount or encryption start */
		hook->tail_len = 0;
		hook->tail_off = 0;
		if (!(opt & MF_DECRYPTED) && !undone) {
			dc_hook_set_flags(hook, F_FS_RAW);  // mark as raw volume to protect from writes until re-probed
		}
		else if ((opt & MF_DECRYPTED) && (hook->flags & F_SYSTEM) && (dc_conf_flags & CONF_BLOCK_UNENC_HDDS)) {
			/* a finished decryption only - not an undone start */
			DbgMsg("decrypting system volume, clearing CONF_BLOCK_UNENC_HDDS\n");
			dc_conf_flags &= ~CONF_BLOCK_UNENC_HDDS;
		}
		hook->use_size  = hook->dsk_size;
		hook->tmp_size  = 0;
		hook->mnt_flags = 0;
		resl            = ST_OK;

		// increment mount changes counter
		lock_inc(&hook->chg_mount);

		// free encryption key
		if (hook->dsk_key != NULL) {
			mm_secure_free(hook->dsk_key);
			hook->dsk_key = NULL;
		}

		/* forget the lock state (a locked volume has no session left; its I/O fails fast, so
		 * the drain above cannot hang on it) */
		hook->lock_flags = 0;
		RtlSecureZeroMemory(hook->lock_kcv, sizeof(hook->lock_kcv));
		InterlockedExchange(&hook->lock_failed, 0);

		/* a re-encryption locked at hibernation kept its (zeroed) tmp_key allocation for
		 * the unlock - free it with the volume */
		if (was_locked && hook->tmp_key != NULL) {
			mm_secure_free(hook->tmp_key);
			hook->tmp_key = NULL;
		}

		/* enable IRP processing and transcryption (always after a lock, which set them).
		 * Not on a removed device: F_DISABLE keeps raw I/O off the unmounted hook (the FS
		 * may stay mounted) until the device is deleted */
		if ( ((opt & MF_NOSYNC) == 0 || was_locked) &&
			 hook->pnp_state != SurpriseRemove && hook->pnp_state != Deleted )
		{
			dc_hook_clear_flags(hook, F_DISABLE | F_PREVENT_ENC);
		}
	} while (0);

	if (h_dev != NULL) 
	{
		if (locked != 0) {
			ZwFsControlFile(h_dev, NULL, NULL, NULL, &iosb, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0);
		}
		ZwClose(h_dev);
	}

cleanup:
	KeReleaseMutex(&hook->busy_lock, FALSE);	
	return resl;
}

static void unmount_thread_proc(mount_ctx *mnt) 
{
	dev_hook *hook = mnt->hook;
	
	dc_process_unmount(hook, MF_NOFSCTL);

	/* reset the device info under busy_lock, and only while the hook is still not mounted -
	 * otherwise the stores could land inside a mount / encryption start between
	 * dc_fill_device_info and the layout derived from dsk_size */
	wait_object_infinity(&hook->busy_lock);

	/* a mount that completed after the media change was seen may have mounted the OLD
	 * medium's header and key: unmount it as well (a mount of the new medium can simply
	 * be repeated) */
	if ((hook->flags & F_ENABLED) && hook->chg_mount != mnt->chg_mount)
	{
		DbgMsg("media change during a mount, unmounting again, dev=%ws\n", hook->dev_name);
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_process_unmount(hook, MF_NOFSCTL);
		wait_object_infinity(&hook->busy_lock);
	}

	if ((hook->flags & F_ENABLED) == 0)
	{
		hook->dsk_size      = 0;
		hook->use_size      = 0;
		hook->mnt_probed    = 0;
		hook->mnt_probe_cnt = 0;
	}
	KeReleaseMutex(&hook->busy_lock, FALSE);

	dc_deref_hook(hook);
	mm_pool_free(mnt);
	PsTerminateSystemThread(STATUS_SUCCESS);
}

static void unmount_item_proc(mount_ctx *mnt)
{
	if (start_system_thread(unmount_thread_proc, mnt, NULL) != ST_OK) {
		dc_deref_hook(mnt->hook);
		mm_pool_free(mnt);
	}
}

void dc_unmount_async(dev_hook *hook)
{
	mount_ctx *mnt;

	DbgMsg("dc_unmount_async at IRQL %d\n", KeGetCurrentIrql());

	if (mnt = mm_pool_alloc(sizeof(mount_ctx)))
	{
		mnt->hook = hook; dc_reference_hook(hook);
		mnt->chg_mount = hook->chg_mount;

		if (KeGetCurrentIrql() != PASSIVE_LEVEL) 
		{
			ExInitializeWorkItem(&mnt->wrk_item, unmount_item_proc, mnt);
			ExQueueWorkItem(&mnt->wrk_item, DelayedWorkQueue);
		} else {
			unmount_item_proc(mnt);
		}
	}
}


int dc_unmount_device(wchar_t *dev_name, int force)
{
	dev_hook *hook;
	int       resl;

	DbgMsg("dc_unmount_device %ws\n", dev_name);

	if (hook = dc_find_hook(dev_name)) 
	{
		if (IS_UNMOUNTABLE(hook)) {
			resl = dc_process_unmount(hook, force);
		} else {
			resl = ST_UNMOUNTABLE;
		}
		dc_deref_hook(hook);
	} else {
		resl = ST_NF_DEVICE;
	}

	return resl;
}

/*
 * hooks_sync_resource is NOT held across the mounts: holding it while dc_mount_hook waits for
 * a volume's busy_lock would invert the lock order of the format path (busy_lock ->
 * dc_find_hook) and deadlock once an exclusive waiter is queued. The hooks are collected and
 * referenced, the list is released, then they are probed and mounted one by one.
 */
int dc_mount_all(dc_pass *password, u32 flags, ULONG *interrupt_cmd)
{
	dev_hook **list;
	dev_hook  *hook;
	int        cap = 0, n = 0, num = 0;
	int        i;

	for (hook = dc_first_hook(); hook != NULL; hook = dc_next_hook(hook)) {
		cap++;
	}
	if (cap != 0)
	{
		if ( (list = (dev_hook**)mm_pool_alloc(cap * sizeof(dev_hook*))) == NULL ) {
			DbgMsg("dc_mount_all: no memory for %d hooks\n", cap);
		} else
		{
			/* walked to the end: dc_next_hook releases the list resource there */
			for (hook = dc_first_hook(); hook != NULL; hook = dc_next_hook(hook)) {
				if (n < cap) {
					dc_reference_hook(hook);
					list[n++] = hook;
				}
			}

			for (i = 0; i < n; i++)
			{
				hook = list[i];

				/* a volume locked at hibernation is unlocked in place below (dc_unlock_hooks) */
				if (!DC_HOOK_LOCKED(hook))
				{
					/* Check for filesystem signatures BEFORE attempting decryption.
					 * This avoids expensive Argon2id key derivation on volumes
					 * that clearly have a valid filesystem (not encrypted). */
					dc_detect_filesystem(hook);

					if ( (hook->flags & F_FS_RAW) &&
						 dc_mount_hook(hook, password, flags, interrupt_cmd, 0, 0) == ST_OK )
					{
						num++;
					}
				}
				dc_deref_hook(hook);
			}
			mm_pool_free(list);
		}
	}

	/* the locked volumes (unlock only) */
	num += dc_unlock_hooks(password, flags, interrupt_cmd, FALSE);

	return num;
}

int dc_num_mount()
{
	dev_hook *hook;
	int       num = 0;

	if (hook = dc_first_hook()) 
	{
		do 
		{
			num += (hook->flags & F_ENABLED);		
		} while (hook = dc_next_hook(hook));
	}

	return num;
}

static void mount_item_proc(mount_ctx *mnt)
{
	dev_hook *hook;
	int       resl;

	hook = mnt->hook;

	/* Fill device info first to get sector size for filesystem detection */
	if ( !NT_SUCCESS(dc_fill_device_info(hook)) ) {
		resl = ST_IO_ERROR;
		goto done;
	}

	/* Check for filesystem signatures BEFORE attempting mount.
	 * This avoids expensive Argon2id password derivation on volumes
	 * that clearly have a valid filesystem (not encrypted). */
	dc_detect_filesystem(hook);

	if (!(hook->flags & F_FS_RAW)) {
		/* Filesystem found - skip mount attempt, mark as probed */
		hook->mnt_probed = 1;
		resl = ST_PASS_ERR; /* Not an encrypted volume */
		goto done;
	}

	/* Raw volume (no filesystem) - try to mount as encrypted volume */
	/* this probe holds mnt->irp and its remove-lock reference (which also keeps the hook) */
	resl = dc_mount_hook(hook, NULL, MF_PROBE_RL, NULL, 0, mnt->chg_mount);

	/* ST_CANCEL: refused during a hibernation transition - probe again later */
	if ( (resl != ST_RW_ERR) && (resl != ST_MEDIA_CHANGED) && (resl != ST_NO_MEDIA) && (resl != ST_CANCEL) ) {
		hook->mnt_probed = 1;
	}

	/* ST_CANCEL does not count either: an S4 transition is no failed probe */
	if (resl != ST_OK && resl != ST_CANCEL)
	{
		if (lock_inc(&hook->mnt_probe_cnt) > MAX_MNT_PROBES) {
			hook->mnt_probed = 1;
		}
	}

done:

	if (hook->flags & F_ENABLED) {
		io_read_write_irp(hook, mnt->irp);
	} else
	{
		if (IS_DEVICE_BLOCKED(dc_conf_flags, hook) != 0) {
			dc_release_irp(hook, mnt->irp, STATUS_ACCESS_DENIED);
		} else {
			/* counted until it completes (a transcryption start drains it) */
			io_forward_plain_irp(hook, mnt->irp);
		}
	}
	mm_pool_free(mnt);
}

NTSTATUS dc_probe_mount(dev_hook *hook, PIRP irp)
{
	mount_ctx *mnt;

	if ( (mnt = mm_pool_alloc(sizeof(mount_ctx))) == NULL ) {
		return dc_release_irp(hook, irp, STATUS_INSUFFICIENT_RESOURCES);
	}
	IoMarkIrpPending(irp);

	mnt->irp  = irp;
	mnt->hook = hook;
	mnt->chg_mount = hook->chg_mount; /* the probe must not undo a mount + unmount that happens while it waits */
		
	ExInitializeWorkItem(&mnt->wrk_item, mount_item_proc, mnt);
	ExQueueWorkItem(&mnt->wrk_item, DelayedWorkQueue);

	return STATUS_PENDING;
}

void dc_init_mount()
{
	ExInitializeResourceLite(&mount_sync_resource);
	pass_cache = NULL;
	boot_keys = NULL;
	boot_key_count = 0;
}

int dc_get_pending_encrypt(wchar_t *dev_name, wchar_t* path)
{
	OBJECT_ATTRIBUTES obj_a;
	UNICODE_STRING    u_name;	
	IO_STATUS_BLOCK   iosb;
	HANDLE            h_file;
	xts_key			 *hdr_key = NULL;
	/* zeroed - dc_lookup_password copies only size/pass/kdf; slot must be 0 (the pending
	 * header is a v1 header without key slots), flags 0 and the label empty */
	dc_pass		      password = { 0 };
	crypt_info        crypt;
	u32               flags;
	int				  resl, succs;
	dc_header		 *header = NULL;
	int               hdr_len = sizeof(dc_header);

	RtlInitUnicodeString(&u_name, path);
	InitializeObjectAttributes(&obj_a, &u_name, OBJ_KERNEL_HANDLE, NULL, NULL);

	if (NT_SUCCESS(ZwCreateFile(&h_file, GENERIC_READ, &obj_a, &iosb, NULL, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY, 0, 
		FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_WRITE_THROUGH, NULL, 0)) == FALSE) {
		return ST_NF_FILE;
	}

	do
	{
		if ( (header = mm_secure_alloc(hdr_len)) == NULL ) {
			resl = ST_NOMEM; break;
		}
		if ( (hdr_key = mm_secure_alloc(sizeof(xts_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}

		if (!NT_SUCCESS(ZwReadFile(h_file, NULL, NULL, NULL, &iosb, header, hdr_len, NULL, NULL))) {
			resl = ST_RW_ERR; break;
		}

		if ( (resl = dc_lookup_password(dc_boot_pass, &password)) != ST_OK ) {
			resl = ST_PASS_NOT_FOUND; break;
		}

		if (!cp_decrypt_header(hdr_key, header, hdr_len, &password, NULL, NULL, NULL, NULL)) {
			resl = ST_PASS_ERR; break;
		}

		dc_delete_file(h_file);
		
		password.kdf = header->head_kdf;
		memcpy(&crypt, header->space, sizeof(crypt_info));
		flags = header->flags & (VF_BACKUP_HEADER);

		resl = dc_encrypt_start(dev_name, &password, &crypt, flags, TRUE, NULL);

	} while (0);

	burn(&password, sizeof(password));
	if (header != NULL) {
		mm_secure_free(header);
	}
	if (hdr_key != NULL) {
		mm_secure_free(hdr_key);
	}
	ZwClose(h_file);

	return resl;
}