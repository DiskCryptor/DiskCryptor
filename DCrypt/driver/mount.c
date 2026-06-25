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
#include "..\crc32.h"
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
#include "bootloader.h"

typedef struct _dsk_pass {
	struct _dsk_pass *next;
	dc_pass           pass;
} dsk_pass;

typedef struct _mount_ctx {
	WORK_QUEUE_ITEM   wrk_item;
	PIRP              irp;
	dev_hook         *hook;
	
} mount_ctx;

/* function types declaration */
WORKER_THREAD_ROUTINE unmount_item_proc;
KSTART_ROUTINE        unmount_thread_proc;
WORKER_THREAD_ROUTINE mount_item_proc;

static dsk_pass      *pass_cache;
static ERESOURCE      mount_sync_resource;
static header_key    *boot_keys;
static int            boot_key_count;


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

	if (pass->size != 0)
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

void dc_clean_pass_cache()
{
	dsk_pass *d_pass;
	dsk_pass *c_pass;
	int       loirql;

	DbgMsg("dc_clean_pass_cache\n");

	if (loirql = (KeGetCurrentIrql() == PASSIVE_LEVEL)) {
		KeEnterCriticalRegion();
		ExAcquireResourceExclusiveLite(&mount_sync_resource, TRUE);
	}

	for (d_pass = pass_cache; d_pass;)
	{
		c_pass = d_pass;
		d_pass = d_pass->next;
		/* zero password data */
		burn(c_pass, sizeof(dsk_pass));
		/* free memory if possible */
		if (loirql != 0) mm_secure_free(c_pass);
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
		hook->flags &= ~F_FS_RAW;  /* empty/wiped volume, not encrypted - clear raw flag */
		DbgMsg("empty/wiped sector detected (not encrypted), dev=%ws\n", hook->dev_name);
		goto cleanup;
	}

	/* Check for valid boot sector signature 0x55AA at offset 510-511.
	* This signature is present in NTFS, FAT12/16/32, and exFAT boot sectors. */
	if (sector_size >= 512 && sector[510] == 0x55 && sector[511] == 0xAA) {
		/* Identify filesystem type for logging */
		if (memcmp(sector + 3, "NTFS    ", 8) == 0) {
			hook->flags &= ~F_FS_RAW;  /* NTFS found - clear raw flag */
			DbgMsg("filesystem detected: NTFS, dev=%ws\n", hook->dev_name);
		} else if (memcmp(sector + 3, "EXFAT   ", 8) == 0) {
			hook->flags &= ~F_FS_RAW;  /* exFAT found - clear raw flag */
			DbgMsg("filesystem detected: exFAT, dev=%ws\n", hook->dev_name);
		} else if (memcmp(sector + 54, "FAT", 3) == 0 || memcmp(sector + 82, "FAT", 3) == 0) {
			hook->flags &= ~F_FS_RAW;  /* FAT found - clear raw flag */
			DbgMsg("filesystem detected: FAT, dev=%ws\n", hook->dev_name);
		} /*else {
		  DbgMsg("filesystem detected: boot signature found, dev=%ws\n", hook->dev_name);
		  }*/
		goto cleanup;
	}

	/* ReFS: "ReFS" signature at offset 3 */
	if (memcmp(sector + 3, "ReFS", 4) == 0) {
		hook->flags &= ~F_FS_RAW;  /* ReFS found - clear raw flag */
		DbgMsg("filesystem detected: ReFS, dev=%ws\n", hook->dev_name);
		goto cleanup;
	}

	/* No filesystem detected - mark as raw volume (potentially encrypted) */
	hook->flags |= F_FS_RAW;
	DbgMsg("no filesystem detected (raw volume), dev=%ws\n", hook->dev_name);

cleanup:
	if (sector != NULL) mm_pool_free(sector);
}

static
int dc_probe_decrypt_at(dev_hook *hook, dc_header **header, xts_key **res_key, dc_pass *password, int* out_kdf, u64 read_pos, int hdr_len, ULONG *interrupt_cmd)
{
	xts_key  *hdr_key = NULL;
	dsk_pass *d_pass;
	int       i;
	int       resl, succs = 0;

	*header = NULL;
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
				if (succs = cp_decrypt_header(hdr_key, *header, hdr_len, password, out_kdf, interrupt_cmd)) {
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
					if (succs = cp_try_decrypt_header(boot_keys[i].key, boot_keys[i].alg, hdr_key, *header)) {
						if (out_kdf) *out_kdf = boot_keys[i].kdf;
						DbgMsg("header decrypted with boot key, dev=%ws\n", hook->dev_name);
						goto found;
					}
				}
			}

			/* probe mount with cached passwords */
			for (d_pass = pass_cache; d_pass; d_pass = d_pass->next)
			{
				if (succs = cp_decrypt_header(hdr_key, *header, hdr_len, &d_pass->pass, out_kdf, interrupt_cmd)) {
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

static
int dc_probe_decrypt(dev_hook *hook, dc_header **header, xts_key **res_key, dc_pass *password, int* out_kdf, u32 mnt_flags, u64* out_pos, int* out_hdr_len, ULONG *interrupt_cmd)
{
	dsk_pass *d_pass;
	int       min_len;
	int       hdr_len;
	u64       read_pos = 0;
	int       resl;

	*header = NULL;

	if (mnt_flags & MF_USE_BACKUP) {
		/* Try to mount from backup header at partition end */
		/* Try different sizes: 2k, 4k, 8k, ... up to 4M */
		u32 try_len;
		resl = ST_PASS_ERR;
		for (try_len = 2048; try_len <= 4 * 1024 * 1024; try_len *= 2) {
			read_pos = hook->dsk_size - try_len;
			hdr_len = try_len;
			resl = dc_probe_decrypt_at(hook, header, res_key, password, out_kdf, read_pos, hdr_len, interrupt_cmd);
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
		resl = dc_probe_decrypt_at(hook, header, res_key, password, out_kdf, read_pos, hdr_len, interrupt_cmd);
	}

	if (resl == ST_OK) {
		if (out_pos) *out_pos = read_pos;
		if (out_hdr_len) *out_hdr_len = hdr_len;
	}

	return resl;
}

int dc_mount_device(wchar_t *dev_name, dc_pass *password, u32 mnt_flags, ULONG *interrupt_cmd)
{
	dc_header *hcopy = NULL;
	dc_ext_header* ext_hdr = NULL;
	dev_hook  *hook  = NULL;
	xts_key   *hdr_key = NULL;
	int        resl;
	int        sync_type = 0;
	int        head_kdf = 0;
	dc_header *hback = NULL;
	u8        *bak_salt = NULL;
	xts_key   *bak_key = NULL;
	u64        hdr_pos = 0;
	int        hdr_len = 0;

	DbgMsg("dc_mount_device %ws\n", dev_name);

	do 
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		if (hook->flags & F_ENABLED) {
			resl = ST_ALR_MOUNT; break;
		}
		if (hook->flags & (F_UNSUPRT | F_DISABLE | F_FORMATTING)) {
			resl = ST_ERROR; break;
		}

		if ( !NT_SUCCESS(dc_fill_device_info(hook)) ) {
			resl = ST_IO_ERROR; break;
		}

		if ( ( (hook->flags & F_CDROM) && (hook->bps != CD_SECTOR_SIZE) ) ||
			 (!(hook->flags & F_CDROM) && IS_INVALID_SECTOR_SIZE(hook->bps) ) )
		{
			hook->flags |= F_UNSUPRT; resl = ST_ERROR; break;
		}

		if ( (resl = dc_probe_decrypt(hook, &hcopy, &hdr_key, password, &head_kdf, mnt_flags, &hdr_pos, &hdr_len, interrupt_cmd)) != ST_OK ) {
			break;
		}

		/* read and decrypt rest of v2 header */
		if ( (resl = io_read_header_full(hook, hdr_pos, &hcopy, hdr_key, hdr_len)) != ST_OK ) {
			break;
		}

		/* check volume header */		
		if ( ( (hcopy->flags & VF_NO_REDIR) && (hcopy->flags & (VF_TMP_MODE | VF_REENCRYPT | VF_STORAGE_FILE)) ) ||
			 ( (hcopy->flags & VF_STORAGE_FILE) && (hcopy->stor_off == 0) ) ||
			 (hcopy->alg_1 >= CF_CIPHERS_NUM) ||
			 (hcopy->alg_2 >= CF_CIPHERS_NUM) || 
			 (hcopy->tmp_wp_mode != WP_SKIP_UNUSED && hcopy->tmp_wp_mode >= WP_NUM) ||
			 ( (hook->flags & F_CDROM) && (hcopy->flags & (VF_TMP_MODE | VF_STORAGE_FILE)) ) )
		{
			resl = ST_INV_VOLUME; break;
		}
		if (hcopy->version > DC_HDR_VERSION_2) {
			resl = ST_VOLUME_TOO_NEW; break;
		}
#if 0
		/* update volume header if needed */
		if ( (hcopy->version < DC_HDR_VERSION) && !(hook->flags & F_CDROM) )
		{
			hcopy->version = DC_HDR_VERSION;
			memset(hcopy->deprecated, 0, sizeof(hcopy->deprecated));
			
			io_write_header(hook, 0, hcopy, hdr_key, NULL, HF_DEFAULT, NULL);
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

		memset(&hook->crypt, 0, sizeof(hook->crypt));
		if (hcopy->version >= DC_HDR_VERSION_2) {
			hook->head_len = ROUND_TO_FULL_SECTORS(hcopy->head_len, hook->bps);
			if (hcopy->flags & VF_STORAGE_FILE) {
				hook->use_size = hook->dsk_size;
				hook->stor_off = hcopy->stor_off;
			} else {
				hook->use_size = hook->dsk_size - hcopy->stor_len;
				hook->stor_off = hook->use_size;
			}
			hook->stor_len = hcopy->stor_len;
			hook->crypt.head_len = hcopy->head_len;
		} else {
			hook->head_len = ROUND_TO_FULL_SECTORS(DC_AREA_SIZE, hook->bps);
			if (hcopy->flags & VF_STORAGE_FILE) {
				hook->use_size = hook->dsk_size;
				hook->stor_off = hcopy->stor_off;
			} else {
				hook->use_size = hook->dsk_size - hook->head_len;
				hook->stor_off = hook->use_size;
			}
			hook->stor_len = hook->head_len;
			hook->crypt.head_len = DC_AREA_SIZE;
		}
		hook->crypt.cipher_id = d8(hcopy->alg_1);
		hook->disk_id         = hcopy->disk_id;
		hook->crypt.version   = hcopy->version;
		hook->tmp_size        = 0;
		hook->mnt_flags       = mnt_flags;

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

		if (hcopy->flags & VF_STORAGE_FILE) {
			hook->flags |= F_PROTECT_DCSYS;
		}
		if (hcopy->flags & VF_NO_REDIR) {
			hook->flags   |= F_NO_REDIRECT;
			hook->stor_off = 0;			
		}
		if (hcopy->flags & VF_BACKUP_HEADER) {
			hook->flags |= F_HEAD_BACKUP;
		}
		if (hook->flags & F_HEAD_BACKUP && !IS_STORAGE_ON_END(hook->flags)) {
			hook->tail_len = hook->head_len;
			hook->tail_off = hook->stor_off + hook->stor_len - hook->tail_len;
		} else {
			hook->tail_len = 0;
			hook->tail_off = 0;
		}

		if (hcopy->flags & VF_TMP_MODE)
		{
			if (hcopy->flags & VF_BACKUP_HEADER) {
				if (!(bak_salt = mm_secure_alloc(HEADER_SALT_SIZE))) {
					resl = ST_NOMEM; break;
				}
				// todo: hint at corerct kdf
				resl = dc_probe_decrypt_at(hook, &hback, &bak_key, password, NULL, hook->dsk_size - hook->head_len, hook->head_len, interrupt_cmd);
				if (resl != ST_OK) {
					DbgMsg("mount failed to load backup header, dev=%ws, error=%d\n", hook->dev_name, resl);
					// restore backup header from primary header
					if ( (bak_key = mm_secure_alloc(sizeof(xts_key))) == NULL ) { 
						resl = ST_NOMEM; break; 
					}
					memcpy(bak_salt, hcopy->salt, HEADER_SALT_SIZE);
					memcpy(bak_key, hdr_key, sizeof(xts_key));
				}
				else {
					memcpy(bak_salt, hback->salt, HEADER_SALT_SIZE);
				}
			}


			hook->tmp_size      = hcopy->tmp_size;
			hook->hdr_key       = hdr_key;
			hook->crypt.wp_mode = hcopy->tmp_wp_mode;			
			hook->tmp_header    = hcopy;

			hook->bak_key       = bak_key;
			hook->bak_salt      = bak_salt;

			if (hcopy->flags & VF_REENCRYPT) {
				sync_type = S_CONTINUE_RE_ENC;
			} else {
				sync_type = S_CONTINUE_ENC;
			}

			hdr_key = NULL;
			hcopy = NULL;

			bak_key = NULL;
			bak_salt = NULL;

#ifdef DC_CONCURRENT_TRANSCRYPT
			if ( (resl = dc_transcrypt_init(hook, sync_type)) != ST_OK ) {
#else
			if ( (resl = dc_enable_sync_mode(hook, sync_type)) != ST_OK ) {
#endif
				DbgMsg("dc_mount_device: sync mode error\n");
			}
		} else {
			hook->flags |= F_ENABLED;
			resl = ST_OK;
		}
		if (resl == ST_OK) {
			/* Clear raw flag - volume is now mounted and handled properly */
			hook->flags &= ~F_FS_RAW;
			/* increment mount changes counter */
			lock_inc(&hook->chg_mount);
		}
	} while (0);

	if (hdr_key != NULL) mm_secure_free(hdr_key);
	if (hcopy != NULL)   mm_secure_free(hcopy);

	if (bak_key != NULL) mm_secure_free(bak_key);
	if (bak_salt != NULL) mm_secure_free(bak_salt);
	if (hback != NULL)   mm_secure_free(hback);

	if (hook != NULL)
	{
		if ((hook->flags & F_ENABLED) == 0 && hook->dsk_key != NULL) {
			mm_secure_free(hook->dsk_key);
			hook->dsk_key = NULL;
		}

		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}
	return resl;
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
			hook->flags |= (F_DISABLE | F_PREVENT_ENC);

			// wait for pending IRPs completion
			if ((opt & MF_NOWAIT_IO) == 0) {
				while (hook->remove_lock.Common.IoCount > 1) dc_delay(20);
			}
			if (hook->flags & F_SYNC) {
#ifdef DC_CONCURRENT_TRANSCRYPT
				/* Wait for any in-progress transcryption to complete.
				 * F_PREVENT_ENC prevents new transcryption steps from starting,
				 * but we need to wait for any step that's already in progress. */
				dc_wait_for_transcrypt(hook);
				/* Save state for resume and cleanup resources */
				dc_save_enc_state(hook, SYNC_STEP_UPDATE);
				dc_transcrypt_cleanup(hook);
#else
				// send signal to synchronous mode thread
				dc_send_sync_packet(hook->dev_name, S_OP_FINALIZE, 0);
#endif
			}
		}

		hook->flags    &= ~F_CLEAR_ON_UNMOUNT;
		if (!(opt & MF_DECRYPTED)) {
			hook->flags |= F_FS_RAW;  // mark as raw volume to protect from writes until re-probed
		} 
		else if ((hook->flags & F_SYSTEM) && (dc_conf_flags & CONF_BLOCK_UNENC_HDDS)) {
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

		if ((opt & MF_NOSYNC) == 0) {
			/* enable IRP processing and transcryption */
			hook->flags &= ~(F_DISABLE | F_PREVENT_ENC);
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

	hook->dsk_size      = 0;
	hook->use_size      = 0;
	hook->mnt_probed    = 0;
	hook->mnt_probe_cnt = 0;

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

int dc_mount_all(dc_pass *password, u32 flags, ULONG *interrupt_cmd)
{
	dev_hook *hook;
	int       num = 0;

	if (hook = dc_first_hook())
	{
		do
		{
			/* Check for filesystem signatures BEFORE attempting decryption.
			* This avoids expensive Argon2id key derivation on volumes
			* that clearly have a valid filesystem (not encrypted). */
			dc_detect_filesystem(hook);
			if (!(hook->flags & F_FS_RAW)) {
				continue; /* Filesystem detected - not an encrypted volume */
			}

			if (dc_mount_device(hook->dev_name, password, flags, interrupt_cmd) == ST_OK) {
				num++;
			}
		} while (hook = dc_next_hook(hook));
	}

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
	resl = dc_mount_device(hook->dev_name, NULL, 0, NULL);

	if ( (resl != ST_RW_ERR) && (resl != ST_MEDIA_CHANGED) && (resl != ST_NO_MEDIA) ) {
		hook->mnt_probed = 1;
	}

	if (resl != ST_OK)
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
			dc_forward_irp(hook, mnt->irp);
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
	dc_pass		      password;	
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

		if (!cp_decrypt_header(hdr_key, header, hdr_len, &password, NULL, NULL)) {
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