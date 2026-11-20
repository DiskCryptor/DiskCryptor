/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2026
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
#include <ntddvol.h>
#include "defines.h"
#include "devhook.h"
#include "misc_volume.h"
#include "misc.h"
#include "mount.h"
#include "prng.h"
#include "fast_crypt.h"
#include "debug.h"
#include "crypto_head.h"
#include "misc_mem.h"
#include "disk_info.h"
#include "device_io.h"
#include "header_io.h"
#include "volume_head.h"
#include "storage.h"
#include "crc32.h"
#include "enc_dec.h" /* dc_save_enc_state / dc_wait_for_transcrypt */

int dc_backup_header(wchar_t *dev_name, dc_pass *password, void *out, int *size, u32 flags, ULONG *interrupt_cmd)
{
	dc_header *header  = NULL;
	xts_key   *hdr_key = NULL;
	xts_key   *bak_key = NULL;
	dc_dev     dev;
	dev_hook  *hook    = NULL;
	int        head_len;
	int        resl;
	u64        read_pos = 0;
	int        password_kdf = -1;

	if (password->slot != 0) {
		return ST_INVALID_PARAM;
	}

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}
		wait_object_infinity(&hook->busy_lock);

		if (hook->flags & (F_SYNC | F_UNSUPRT | F_DISABLE | F_CDROM)) {
			resl = ST_ERROR; break;
		}
		/* get device params */
		if (hook->dsk_size == 0)
		{
			if ( !NT_SUCCESS(dc_fill_device_info(hook)) ) {
				resl = ST_IO_ERROR; break;
			}
		}

		/* the layout is fixed for the rest of this call */
		dc_dev_of(hook, &dev);

		/* Fast path: if password is empty and volume is mounted, read raw encrypted header */
		if (password->size == 0)
		{
			u64 raw_pos;

			if ((hook->flags & F_ENABLED) && hook->crypt.head_len > 0) {
				if ((u32)*size < hook->crypt.head_len) {
					resl = ST_SMALL_BUFF; break;
				}
				head_len = ROUND_TO_FULL_SECTORS(hook->crypt.head_len, hook->bps);
			} else {
				head_len = ROUND_TO_FULL_SECTORS(*size, hook->bps);
			}

			/* Determine read position */
			if (flags & HF_BACKUP_HEADER) {
				raw_pos = hook->dsk_size - head_len;
			} else {
				raw_pos = 0;
			}
			
			/* io_hook_rw fails when given a user buffer */
			if ( (header = mm_secure_alloc(head_len)) == NULL ) { resl = ST_NOMEM; break; }

			/* Read raw encrypted header directly from disk */
			resl = io_hook_rw(hook, header, head_len, raw_pos, 1);
			//DbgMsg("Fast header backup: read raw header from %I64u, head_len = %d, resl = %d\n", raw_pos, head_len, resl);
			if (resl != ST_OK) break;

			memcpy(out, header, min(*size, head_len));

			*size = head_len;
			break;
		}

		/* read volume header */
		if (flags & HF_BACKUP_HEADER) {
			/* Read backup header from partition end */
			if (hook->flags & F_ENABLED) {
				/* Volume is mounted, use known head_len */
				read_pos = hook->dsk_size - hook->head_len;
				resl = io_read_header(&dev, dc_hook_rw, read_pos, &header, &hdr_key, password, &password_kdf, interrupt_cmd);
			} else {
				/* Volume not mounted, try different offsets: 2k, 4k, 8k, ... up to 4M */
				u32 try_len;
				resl = ST_INV_VOLUME;
				for (try_len = 2048; try_len <= 4 * 1024 * 1024; try_len *= 2) {
					read_pos = hook->dsk_size - try_len;
					if (io_read_header(&dev, dc_hook_rw, read_pos, &header, &hdr_key, password, &password_kdf, interrupt_cmd) == ST_OK) {
						resl = ST_OK;
						break;
					}
				}
			}
		} else {
			resl = io_read_header(&dev, dc_hook_rw, 0, &header, &hdr_key, password, &password_kdf, interrupt_cmd);
		}
		if (resl != ST_OK) break;
		password->kdf = password_kdf;

		/* determine header length  */
		if (header->version >= DC_HDR_VERSION_2) {

			head_len = header->head_len;
			/* bounded and sector aligned: the XTS loops step in XTS_SECTOR_SIZE until the
			 * length reaches 0 exactly, a misaligned length runs past the header buffer
			 * (same rule as the mount, dc_check_header_geometry) */
			if (head_len < DC_AREA_SIZE || head_len > DC_AREA_MAX_SIZE || IS_INVALID_SECTOR_SIZE(head_len)) {
				resl = ST_INV_VOLUME; break;
			}

			if ((header->feature_flags & FF_KEY_SLOTS) && DC_BASE_SIZE + header->slot_area_len > head_len) {
				resl = ST_INV_VOLUME; break;
			}
		} else {
			head_len = DC_AREA_SIZE;
		}
		if (*size < head_len) {
			resl = ST_SMALL_BUFF; break;
		}

		/* v2 headers handling */
		if (header->version >= DC_HDR_VERSION_2)
		{
			/* when keyslots are in use we don't change the header key */
			if ((header->feature_flags & FF_KEY_SLOTS) && !(flags & HF_CLEAR_SLOTS)) {
				flags |= HF_KEEP_SALT;
			}
		}

		/* use header key for backup - preserver salt */
		if ((flags & HF_KEEP_SALT)) {
			bak_key = hdr_key;
			hdr_key = NULL;
		}
		
		if (bak_key == NULL) {
			/* generate new salt */
			cp_rand_bytes(header->salt, HEADER_SALT_SIZE);

			/* init new header key */
			if ((bak_key = mm_secure_alloc(sizeof(xts_key))) == NULL) {
				resl = ST_NOMEM; break;
			}
			if (!cp_set_header_key(bak_key, header->salt, header->alg_1, password, interrupt_cmd)) {
				resl = ST_INVALID_PARAM; break;
			}
		}

		/* encrypt header with new key */
		xts_encrypt(pv(header), out, head_len, 0, bak_key);
		/* restore original salt */
		memcpy(out, header->salt, HEADER_SALT_SIZE);

		/* restore raw keyslot data to output from header */
		if (header->version >= DC_HDR_VERSION_2 && (header->feature_flags & FF_KEY_SLOTS) && !(flags & HF_CLEAR_SLOTS)) {
			cp_copy_keylots(header, (u8*)header, (u8*)out);
		}

		*size = head_len;
		resl = ST_OK;
	} while (0);

	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}
	/* free memory */	
	if (header != NULL) mm_secure_free(header);
	if (hdr_key != NULL) mm_secure_free(hdr_key);
	if (bak_key != NULL) mm_secure_free(bak_key);
	return resl;
}

int dc_restore_header(wchar_t *dev_name, dc_pass *password, void *in, int size, u32 flags, ULONG *interrupt_cmd)
{
	dc_header *header  = NULL;
	xts_key   *bak_key = NULL;
	xts_key   *hdr_key = NULL;
	dc_dev     dev;
	dev_hook  *hook    = NULL;
	int        head_len;
	u64        write_pos;
	int        resl;
	int        password_kdf = -1;

	if (password->slot != 0) {
		return ST_INVALID_PARAM;
	}
	/* the input is copied and decrypted as DC_AREA_SIZE bytes into a size-byte
	   allocation, before the size < head_len check */
	if (size < DC_AREA_SIZE || size > DC_AREA_MAX_SIZE) {
		return ST_INV_VOLUME;
	}

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}
		wait_object_infinity(&hook->busy_lock);

		if (hook->flags & (F_ENABLED | F_CDROM)) {
			resl = ST_ERROR; break;
		}
		/* get device params */
		if (hook->dsk_size == 0)
		{
			if ( !NT_SUCCESS(dc_fill_device_info(hook)) ) {
				resl = ST_IO_ERROR; break;
			}
		}

		/* the layout is fixed for the rest of this call */
		dc_dev_of(hook, &dev);

		/* copy header from input */
		if ( (header = mm_secure_alloc(size)) == NULL ) {
			resl = ST_NOMEM; break;
		}
		memcpy(header, in, DC_AREA_SIZE);

		/* decrypt header */
		if ( (bak_key = mm_secure_alloc(sizeof(xts_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}
		if (cp_decrypt_header(bak_key, header, size, password, &password_kdf, NULL, NULL, interrupt_cmd) == 0) {
			resl = ST_PASS_ERR; break;
		}
		password->kdf = password_kdf;

		/* determine header length - validate v2 header */
		if (header->version >= DC_HDR_VERSION_2) {

			head_len = header->head_len;
			/* bounded and sector aligned, see dc_backup_header */
			if (head_len < DC_AREA_SIZE || head_len > DC_AREA_MAX_SIZE || IS_INVALID_SECTOR_SIZE(head_len)) {
				resl = ST_INV_VOLUME; break;
			}

			if ((header->feature_flags & FF_KEY_SLOTS) && DC_BASE_SIZE + header->slot_area_len > head_len) {
				resl = ST_INV_VOLUME; break;
			}
		} else {
			head_len = DC_AREA_SIZE;
		}
		if (size < head_len) {
			resl = ST_INV_VOLUME; break;
		}

		/* v2 headers handling */
		if (header->version >= DC_HDR_VERSION_2)
		{
			/* decrypt remaining header, cp_decrypt_header only decrypts DC_AREA_SIZE */
			if (head_len > DC_AREA_SIZE) {
				/* the tail ciphertext starts at in + DC_AREA_SIZE (XTS offset DC_AREA_SIZE) */
				xts_decrypt(((u8*)in) + DC_AREA_SIZE, ((u8*)header) + DC_AREA_SIZE, head_len - DC_AREA_SIZE, DC_AREA_SIZE, bak_key);
			}

			/* when keyslots are in use we don't change the header key */
			if ((header->feature_flags & FF_KEY_SLOTS) && !(flags & HF_CLEAR_SLOTS)) {
				flags |= HF_KEEP_SALT;
				/* restore raw keyslot data to header from input */
				cp_copy_keylots(header, (u8*)in, (u8*)header);
			}
		}

		/* use backup key for restore - preserver salt */
		if (flags & HF_KEEP_SALT) {
			hdr_key = bak_key;
		}

		/* write volume header */
		if (flags & HF_BACKUP_HEADER) {
			write_pos = hook->dsk_size - ROUND_TO_FULL_SECTORS(head_len, hook->bps);
			resl = io_write_header(&dev, dc_hook_rw, write_pos, header, hdr_key, password, flags & HF_CLEAR_SLOTS, interrupt_cmd);
		} else {
			resl = io_write_header(&dev, dc_hook_rw, 0, header, hdr_key, password, flags & HF_CLEAR_SLOTS, interrupt_cmd);
		}
	} while (0);

	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}
	/* free memory */
	if (bak_key != NULL) mm_secure_free(bak_key);
	if (header != NULL) mm_secure_free(header);

	return resl;
}

int dc_update_header(wchar_t *dev_name, dc_pass *password, void *in, int size, u32 flags, ULONG *interrupt_cmd)
{
	dc_header *header = NULL;
	dc_header *upd_header = NULL;
	dc_ext_header* ext_hdr = NULL;
	xts_key   *hdr_key = NULL;
	dc_dev     dev;
	dev_hook  *hook    = NULL;
	u32        offset;
	int        head_len;
	u64	       stor_size;
	u64        hdr_pos = 0;
	int        password_kdf = -1;
	int        resl;

	if (password->slot != 0) {
		return ST_INVALID_PARAM;
	}

	flags &= (HF_UPDATE_ALL | HF_CLEAR_SLOTS | HF_BACKUP_HEADER); // clean up flags
	if (flags & HF_CLEAR_SLOTS) {
		flags |= HF_UPDATE_SLOTS; // clear slots implies updating slots
	}
	if ((flags & HF_UPDATE_ALL) == 0) {
		flags |= HF_UPDATE_ALL; // full update == all patrial updates
	}

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}
		wait_object_infinity(&hook->busy_lock);

		// todo: when hook->flags & F_SYNC work on the hook->tmp_header

		if (hook->flags & (F_SYNC | F_UNSUPRT | F_DISABLE | F_CDROM)) {
			resl = ST_ERROR; break;
		}
		/* get device params */
		if (hook->dsk_size == 0)
		{
			if ( !NT_SUCCESS(dc_fill_device_info(hook)) ) {
				resl = ST_IO_ERROR; break;
			}
		}

		/* the layout is fixed for the rest of this call */
		dc_dev_of(hook, &dev);

		/* determine header position */
		if (flags & HF_BACKUP_HEADER)
		{
			if (hook->flags & F_ENABLED) {
				/* volume is mounted, use known head_len */
				hdr_pos = hook->dsk_size - hook->head_len;
				resl = io_read_header(&dev, dc_hook_rw, hdr_pos, &header, &hdr_key, password, &password_kdf, interrupt_cmd);
			} else {
				/* volume not mounted, try different offsets */
				u32 try_len;
				resl = ST_INV_VOLUME;
				for (try_len = DC_AREA_SIZE; try_len <= DC_AREA_MAX_SIZE; try_len *= 2) {
					hdr_pos = hook->dsk_size - try_len;
					if (io_read_header(&dev, dc_hook_rw, hdr_pos, &header, &hdr_key, password, &password_kdf, interrupt_cmd) == ST_OK) {
						resl = ST_OK;
						break;
					}
				}
			}
		}
		else
		{
			/* read primary header */
			resl = io_read_header(&dev, dc_hook_rw, 0, &header, &hdr_key, password, &password_kdf, interrupt_cmd);
		}
		if (resl != ST_OK) {
			DbgMsg("dc_update_header: failed to read current header, dev=%ws, error=%d\n", hook->dev_name, resl);
			break;
		}
		password->kdf = password_kdf;

		/* determine header length  */
		if (header->version >= DC_HDR_VERSION_2) {
			head_len = header->head_len;
		} else {
			head_len = DC_AREA_SIZE;
		}

		/* when only clearing slots no input is needed */
		if (size < DC_AREA_SIZE) {
			if (flags != (HF_CLEAR_SLOTS | HF_UPDATE_SLOTS)) {
				resl = ST_INVALID_PARAM; break;
			}
			goto update;
		}

		/* copy header from input */
		if ( (upd_header = mm_secure_alloc(size)) == NULL ) {
			resl = ST_NOMEM; break;
		}
		memcpy(upd_header, in, DC_AREA_SIZE);

		/* decrypt updated header - update must be encrypted with the current header key */
		xts_decrypt(pv(upd_header), pv(upd_header), DC_AREA_SIZE, 0, hdr_key);
		if (!is_volume_header_correct(upd_header)) {
			DbgMsg("dc_update_header: invalid header, or header key\n");
			resl = ST_INV_VOLUME; break;
		}
		/* restore original salt */
		memcpy(upd_header->salt, header->salt, HEADER_SALT_SIZE);

		/* changing header size not permittet - use layout change mechanism */
		if (head_len != ((upd_header->version >= DC_HDR_VERSION_2) ? upd_header->head_len : DC_AREA_SIZE)) {
			DbgMsg("dc_update_header: changing header size required layout change\n");
			resl = ST_INVALID_PARAM; break;
		}

		if (size < head_len) {
			DbgMsg("dc_update_header: input size is smaller than header size\n");
			resl = ST_INVALID_PARAM; break;
		}

		/* decrypt the remaining header before the slot / ext header validation below reads it;
		   the tail ciphertext starts at in + DC_AREA_SIZE (XTS offset DC_AREA_SIZE) */
		if (head_len > DC_AREA_SIZE) {
			xts_decrypt(((u8*)in) + DC_AREA_SIZE, ((u8*)upd_header) + DC_AREA_SIZE, head_len - DC_AREA_SIZE, DC_AREA_SIZE, hdr_key);
		}

		/* special case header upgrade/downgrade */
		if (upd_header->version != header->version)
		{
			/* critical safety checks */
			/* reject a change of either the cipher or the disk key (the header below
			 * replaces the on-disk one wholesale) */
			if (upd_header->alg_1 != header->alg_1 || memcmp(upd_header->key_1, header->key_1, DISKKEY_SIZE) != 0) {
				DbgMsg("dc_update_header: disk key can not be updated, re-encrypt volume\n");
				resl = ST_INVALID_PARAM; break;
			}
			if (upd_header->tmp_size != 0) {
				DbgMsg("dc_update_header: tmp_size size must be zero\n");
				resl = ST_INVALID_PARAM; break;
			}
			/* not while the on-disk header is mid-transcryption (a paused, unmounted volume is
			 * not F_SYNC): the wholesale replacement would mark a half-encrypted volume as fully
			 * encrypted; nor with a different re-encryption (old) key */
			if ( header->tmp_size != 0 || (header->flags & (VF_TMP_MODE | VF_REENCRYPT)) ||
				 (upd_header->flags & (VF_TMP_MODE | VF_REENCRYPT)) ||
				 upd_header->alg_2 != header->alg_2 || memcmp(upd_header->key_2, header->key_2, DISKKEY_SIZE) != 0 )
			{
				DbgMsg("dc_update_header: version change of a volume in transcryption, or of its second key\n");
				resl = ST_INVALID_PARAM; break;
			}
			/* v1 has no room for a backup header (its storage holds only the head copy):
			 * remove the backup first, through the layout update */
			if (upd_header->version < DC_HDR_VERSION_2 && ((upd_header->flags | header->flags) & VF_BACKUP_HEADER)) {
				DbgMsg("dc_update_header: downgrade to v1 with a backup header, remove the backup first\n");
				resl = ST_INVALID_PARAM; break;
			}

			// update size fields - v2 header has variable header size, v1 header size is fixed
			if (upd_header->version >= DC_HDR_VERSION_2)  {
				upd_header->head_len = head_len;
				upd_header->stor_len = ROUND_TO_FULL_SECTORS(upd_header->head_len, hook->bps);
				if (!IS_STORAGE_ON_END(hook->flags)) { // when using $dcsys% file grab real size (due to rounding may be bigger)
					dc_get_storage_size(hook, &upd_header->stor_len);
				}
			} else {
				upd_header->head_len = 0;
				upd_header->stor_len = 0;
			}

			DbgMsg("dc_update_header: new header version %d, head_len: %d, stor_len: %d\n", upd_header->version, upd_header->head_len, upd_header->stor_len);

			upd_header->hdr_crc = calculate_header_crc(upd_header);

			/* replace entire header */
			memcpy(header, upd_header, head_len);

			flags = HF_UPDATE_ALL;
			goto update;
		}

		/* v2 headers handling - and validation */
		if (upd_header->version >= DC_HDR_VERSION_2)
		{
			/* validate slot area length */
			offset = DC_BASE_SIZE;
			if (upd_header->feature_flags & FF_KEY_SLOTS) {
				offset += upd_header->slot_area_len + (upd_header->key_slot_count * upd_header->slot_info_size);
			}
			if (offset > (u32)head_len) {
				DbgMsg("dc_update_header: invalid slot area length, slot count, or info entry size\n");
				resl = ST_INV_VOLUME; break;
			}

			/* validate extended header offset */
			if (upd_header->ext_hdr_off != 0) {
				if ((resl = get_ext_header(upd_header, &ext_hdr)) != ST_OK) {
					break;
				}
			}

			/* load keyslots */
			if (upd_header->feature_flags & FF_KEY_SLOTS) {
				cp_copy_keylots(upd_header, (u8*)in, (u8*)upd_header);
			}

			if (!(flags & HF_UPDATE_BASE))
			{
				if (header->feature_flags != upd_header->feature_flags) {
					DbgMsg("dc_update_header: feature flags can not be changed without updating header base\n");
					resl = ST_INVALID_PARAM; break;
				}

				if ((flags & HF_UPDATE_SLOTS) && (
					header->slot_area_len != upd_header->slot_area_len ||
					header->key_slot_count != upd_header->key_slot_count ||
					header->slot_info_size != upd_header->slot_info_size)) {
					DbgMsg("dc_update_header: slot layout can not be changed without updating header base\n");
					resl = ST_INVALID_PARAM; break;
				}

				if ((flags & HF_UPDATE_EXT) && (
					header->ext_hdr_off != upd_header->ext_hdr_off)) {
					DbgMsg("dc_update_header: ext header offset can not be changed without updating header base\n");
					resl = ST_INVALID_PARAM; break;
				}
			}

			/* update header base - only a few fields can be updated */
			if (flags & HF_UPDATE_BASE) 
			{
				header->feature_flags = upd_header->feature_flags;

				if (header->slot_area_len != upd_header->slot_area_len ||
					header->key_slot_count != upd_header->key_slot_count ||
					header->slot_info_size != upd_header->slot_info_size) {

					/* wipe old slot data */
					if (header->feature_flags & FF_KEY_SLOTS) {
						cp_rand_bytes(((u8*)header) + DC_BASE_SIZE, header->slot_area_len);
					}

					header->slot_area_len = upd_header->slot_area_len;
					header->key_slot_count = upd_header->key_slot_count;
					header->slot_info_size = upd_header->slot_info_size;

					/* we need to update entire header to ensure old slot area will be overwritten */
					flags = HF_UPDATE_ALL; 
				}

				if (header->ext_hdr_off != upd_header->ext_hdr_off) {

					header->ext_hdr_off = upd_header->ext_hdr_off;

					/* ensure we write the extended header to the new location */
					if (ext_hdr != NULL) flags |= HF_UPDATE_EXT;
				}

				header->flags = upd_header->flags;

				header->disk_id = upd_header->disk_id;

				header->footer_cnt = upd_header->footer_cnt;
				header->hdr_crc = calculate_header_crc(header);
			}

			if ((flags & HF_UPDATE_SLOTS) && (upd_header->feature_flags & FF_KEY_SLOTS))
			{
				memcpy(((u8*)header) + DC_BASE_SIZE, ((u8*)upd_header) + DC_BASE_SIZE, header->slot_area_len + (header->key_slot_count * header->slot_info_size));
			}

			if ((flags & HF_UPDATE_EXT) && ext_hdr != NULL) 
			{
				memcpy(((u8*)header) + header->ext_hdr_off, ext_hdr, ext_hdr->size);
			}
		}

	update:

		if ((flags & HF_UPDATE_EXT) && header->ext_hdr_off < DC_BASE_SIZE) { // ext header embedded in base header footer
			flags &= ~HF_UPDATE_EXT;
			flags |= HF_UPDATE_BASE;
		}

		/* update metadata */
		hook->crypt.version = header->version;

		/* update flags */
		if ((header->flags & VF_NO_HIBER) && DC_NO_HIBER_FORBIDDEN(hook)) {
			/* the option cannot work on the system / hibernation / crash dump volume: drop it
			 * instead of rejecting the update, so other header properties stay editable */
			DbgMsg("dc_update_header: VF_NO_HIBER dropped on system/dump volume %ws\n", hook->dev_name);
			header->flags &= ~VF_NO_HIBER;
			header->hdr_crc = calculate_header_crc(header);
		}
		if ((hook->flags & F_NO_HIBER) != (header->flags & VF_NO_HIBER)) {
			if (header->flags & VF_NO_HIBER)
				dc_hook_set_flags(hook, F_NO_HIBER);
			else
				dc_hook_clear_flags(hook, F_NO_HIBER);
		}
		/* set-then-re-check against a concurrent usage notification (see dc_mount_device) */
		if ((hook->flags & F_NO_HIBER) && DC_NO_HIBER_FORBIDDEN(hook)) {
			dc_hook_clear_flags(hook, F_NO_HIBER);
		}

		dc_header_sync_stor_off(hook, header);

		/* write updated volume header */
		resl = io_write_header(&dev, dc_hook_rw, hdr_pos, header, hdr_key, password, flags, interrupt_cmd);

		/* the header may carry another disk_id now: the unlock of a volume locked at
		 * hibernation verifies hook->disk_id against the header */
		if (resl == ST_OK && hdr_pos == 0 && (hook->flags & F_ENABLED)) {
			hook->disk_id = header->disk_id;
		}
	} while (0);

	/*if (resl != ST_OK && upd_header) {
		DbgMsg("failed to update header, error code: %d\n", resl);
		DumpHex("old ", header, size);
		DumpHex("new ", upd_header, size);
		DumpHex("in ", in, size);
	}*/

	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}
	/* free memory */
	if (hdr_key != NULL) mm_secure_free(hdr_key);
	if (header != NULL) mm_secure_free(header);
	if (upd_header != NULL) mm_secure_free(upd_header);

	return resl;
}

/*
 * Composes a fresh v2 header. Stays in the driver rather than moving into
 * volume_lib with the rest of header_io.c: it takes a crypt_info, which is
 * a driver type, and composing a header is the one thing kernel mode is not
 * supposed to do in the volume_lib split - see volume_lib/DESIGN.md. It is
 * called from enc_dec.c during volume creation.
 */
int init_header_v2(dc_header *header, crypt_info *crypt, dc_pass *password)
{
	int slot_type = 0;

	if (crypt->slot_count > KEY_SLOT_MAX) {
		DbgMsg("invalid slot count %d, max is %d\n", crypt->slot_count, KEY_SLOT_COUNT);
		return ST_INVALID_PARAM;
	}

	if (crypt->head_len < DC_BASE_SIZE + (crypt->slot_count * (cp_get_key_slot_size(slot_type) + sizeof(dc_slot_info)))) {
		DbgMsg("header length is too small for the number of slots\n");
		return ST_INVALID_PARAM;
	}

	if (crypt->slot_count > 0)
	{
		header->feature_flags |= FF_KEY_SLOTS;
		header->key_slot_count = (u8)crypt->slot_count;
		header->slot_area_len = header->key_slot_count * cp_get_key_slot_size(slot_type);
		header->slot_info_size = sizeof(dc_slot_info);

		/* fill slot area with random data */
		cp_rand_bytes(((u8*)header) + DC_BASE_SIZE, header->slot_area_len);
		//memset(((u8*)header) + DC_BASE_SIZE + header->slot_area_len, 0, (header->key_slot_count * header->slot_info_size));
	}

	// metadata
	header->head_kdf = (u8)password->kdf;

#if 0
	// extended hreader
	header->ext_hdr_off = DC_BASE_SIZE;
	if (header->feature_flags & FF_KEY_SLOTS) {
		header->ext_hdr_off += header->slot_area_len + (header->key_slot_count * header->slot_info_size);
	}

	if(header->ext_hdr_off + 128 > header->head_len) {
		DbgMsg("not enough space for extended header, disabling it\n");
		header->ext_hdr_off = 0; // not enough space for ext header, disable it
		return ST_OK;
	}

	dc_ext_header* ext_hdr = (dc_ext_header*)(((u8*)header) + header->ext_hdr_off);
	ext_hdr->size = 128;
	ext_hdr->version = DC_EXT_VERSION;

	ext_hdr->crc = crc32((const unsigned char*)&ext_hdr->size, ext_hdr->size - 4);
#endif

	return ST_OK;
}

int dc_format_start(wchar_t *dev_name, dc_pass *password, crypt_info *crypt, u32 flags, ULONG *interrupt_cmd)
{
	IO_STATUS_BLOCK iosb;
	NTSTATUS        status;
	dc_header      *header  = NULL;
	dc_dev          dev;
	dev_hook       *hook    = NULL;
	xts_key        *tmp_key = NULL;
	HANDLE          h_dev   = NULL;
	u8             *buff    = NULL;
	int             w_init  = 0;
	u8              key_buf[32];
	int             resl;

	DbgMsg("dc_format_start\n");

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		if (hook->flags & (F_ENABLED | F_UNSUPRT | F_DISABLE | F_CDROM)) {
			resl = ST_ERROR; break;
		}
		/* no new keys while hibernating (see dc_encrypt_start) */
		if (dc_s4_transition_active()) {
			resl = ST_CANCEL; break;
		}

		/* verify encryption info */
		if ( (crypt->cipher_id >= CF_CIPHERS_NUM) || (crypt->wp_mode != WP_SKIP_UNUSED && crypt->wp_mode >= WP_NUM) || (crypt->version > DC_HDR_VERSION_2)) {
			resl = ST_ERROR; break;
		}

		if (crypt->version == 0) {
			if (crypt->head_len != 0) {
				crypt->version = DC_HDR_VERSION_2;
			} else {
				crypt->head_len = DC_AREA_SIZE;
				crypt->version = DC_HDR_VERSION;
			}
		}
		else if (crypt->version > DC_HDR_VERSION_2 || crypt->version < DC_HDR_VERSION) {
			resl = ST_INVALID_PARAM; break;
		}

		if (crypt->head_len < DC_AREA_SIZE || crypt->head_len > DC_AREA_MAX_SIZE || IS_INVALID_SECTOR_SIZE(crypt->head_len)) {
			resl = ST_INVALID_PARAM; break;
		}

		/* get device params */
		if ( !NT_SUCCESS(dc_fill_device_info(hook)) ) {
			resl = ST_IO_ERROR; break;
		}
		dc_media_baseline(hook);

		/* set header length */
		if (crypt->version >= DC_HDR_VERSION_2) {
			hook->head_len = ROUND_TO_FULL_SECTORS(crypt->head_len, hook->bps);
			hook->stor_len = hook->head_len;
			if (flags & VF_BACKUP_HEADER) {
				hook->stor_len *= 2;
			}
		} else {
			hook->head_len = ROUND_TO_FULL_SECTORS(DC_AREA_SIZE, hook->bps);
			hook->stor_len = hook->head_len;
			if (flags & VF_BACKUP_HEADER) {
				resl = ST_INVALID_PARAM; break;
			}
		}

		if ( (header = mm_secure_alloc(hook->head_len)) == NULL ) {
			resl = ST_NOMEM; break;
		}
		if ( (buff = mm_pool_alloc(ENC_BLOCK_SIZE)) == NULL ) {
			resl = ST_NOMEM; break;
		}
		if ( (tmp_key = mm_secure_alloc(sizeof(xts_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}		

		/* temporarily disable automounting (interlocked: the usage notification and
		 * START_DEVICE update the same word without busy_lock) */
		dc_hook_set_flags(hook, F_NO_AUTO_MOUNT);

		/* open volume device */
		if ( (h_dev = io_open_device(hook->dev_name)) == NULL ) {
			resl = ST_LOCK_ERR; break; 
		}		
		/* lock volume */
		status = ZwFsControlFile(
			h_dev, NULL, NULL, NULL, &iosb, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0);

		if (NT_SUCCESS(status) == FALSE) {
			resl = ST_LOCK_ERR; break; 
		}

		/* enable automounting */
		dc_hook_clear_flags(hook, F_NO_AUTO_MOUNT);
		/* set encryption info */
		hook->crypt = *crypt;

		/* init data wiping */
		/* WP_SKIP_UNUSED is no wipe mode (a format writes every sector anyway): WP_NONE,
		 * as the encryption start does */
		resl = dc_wipe_init(
			&hook->wp_ctx, hook, ENC_BLOCK_SIZE,
			(crypt->wp_mode == WP_SKIP_UNUSED) ? WP_NONE : crypt->wp_mode, crypt->cipher_id);

		if (resl == ST_OK) {
			w_init = 1;			
		} else break;

		/* wipe first sectors */
		dc_wipe_process(&hook->wp_ctx, 0, hook->head_len);

		/* create random temporary key */
		cp_rand_bytes(key_buf, sizeof(key_buf));

		if (!xts_set_key(key_buf, crypt->cipher_id, tmp_key)) {
			resl = ST_INVALID_PARAM; break;
		}

		/* create volume header */
		memset(header, 0, hook->head_len);

		cp_rand_bytes(pv(header->salt),     HEADER_SALT_SIZE);
		cp_rand_bytes(pv(&header->disk_id), sizeof(u32));
		cp_rand_bytes(pv(header->key_1),    DISKKEY_SIZE);

		header->sign    = DC_VOLUME_SIGN;
		header->version = crypt->version;
		/* as dc_encrypt_start: only what a caller may ask for (VF_STORAGE_FILE /
		 * VF_TMP_MODE / VF_REENCRYPT / VF_NO_REDIR make an inconsistent fresh header) */
		header->flags   = flags & (VF_BACKUP_HEADER | VF_NO_HIBER | VF_EXTENDED);
		header->head_len= crypt->head_len;
		header->alg_1   = crypt->cipher_id;
		if (header->version >= DC_HDR_VERSION_2) {
			header->stor_len = hook->stor_len;
			header->head_len = hook->head_len;
			if( (resl = init_header_v2(header, crypt, password)) != ST_OK) { 
				break; 
			}
		}
		header->hdr_crc = calculate_header_crc(header);

		/* head_len and stor_len were set above and do not move again here */
		dc_dev_of(hook, &dev);

		/* write volume header */
		if ( (resl = io_write_header(&dev, dc_hook_rw, 0, header, NULL, password, HF_DEFAULT, interrupt_cmd)) != ST_OK ) {
			break;
		}

		/* write backup header, with a new salt, to partition end */
		if( flags & VF_BACKUP_HEADER) {
			cp_rand_bytes(pv(header->salt), HEADER_SALT_SIZE);
			if ( (resl = io_write_header(&dev, dc_hook_rw, hook->dsk_size - hook->head_len, header, NULL, password, HF_DEFAULT, interrupt_cmd)) != ST_OK ) {
				break;
			}
		}

		/* mount device */
		if ( (resl = dc_mount_device(dev_name, password, 0, interrupt_cmd)) != ST_OK ) {
			break;
		}		
		/* set hook fields */
		dc_hook_set_flags(hook, F_FORMATTING); /* interlocked, the volume is mounted here */
		hook->tmp_size   = hook->head_len;
		hook->tmp_buff   = buff;
		hook->tmp_key    = tmp_key;
	} while (0);

	if (resl != ST_OK)
	{
		/* never leave F_NO_AUTO_MOUNT set on failure - the volume would never be probed
		 * again. Only this function sets it. */
		if (hook != NULL) {
			dc_hook_clear_flags(hook, F_NO_AUTO_MOUNT);
		}
		if (w_init != 0) {
			dc_wipe_free(&hook->wp_ctx);
		}

		if (buff != NULL)
		{
			if (hook != NULL && hook->tmp_buff == buff) hook->tmp_buff = NULL;
			mm_pool_free(buff);
		}
		if (tmp_key != NULL)
		{
			if (hook != NULL && hook->tmp_key == tmp_key) hook->tmp_key = NULL;
			mm_secure_free(tmp_key);
		}
	}
	if (header != NULL) {
		mm_secure_free(header);
	}
	if (hook != NULL) { 
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}
	/* prevent leaks */
	burn(key_buf, sizeof(key_buf));
	
	if (h_dev != NULL)
	{
		if (resl != ST_LOCK_ERR)
		{
			/* dismount volume */
			ZwFsControlFile(
				h_dev, NULL, NULL, NULL, &iosb, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0);

			/* unlock volume */
			ZwFsControlFile(
				h_dev, NULL, NULL, NULL, &iosb, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0);
		}
		/* close device */
		ZwClose(h_dev);
	}		

	return resl;
}

int dc_format_step(wchar_t *dev_name, int wp_mode)
{
	dev_hook *hook = NULL;
	u8       *buff;
	int       resl;
	u64       offs;
	u64       end;
	u32       size;

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}

		wait_object_infinity(&hook->busy_lock);

		if ( !(hook->flags & F_FORMATTING) ) {
			resl = ST_ERROR; break;
		}

		/* stop before the backup header dc_format_start wrote at the partition end (raw
		   writes, nothing redirects or protects it); same bound as dc_data_end() in enc_dec.c */
		end = hook->dsk_size;
		if (hook->flags & F_HEAD_BACKUP) {
			end -= (hook->tail_len != 0) ? hook->tail_len : hook->head_len;
		}

		offs = hook->tmp_size;
		buff = hook->tmp_buff;
		size = (offs < end) ? d32(min(end - offs, ENC_BLOCK_SIZE)) : 0;

		if (size == 0) {
			dc_format_done(dev_name);
			resl = ST_FINISHED; break;
		}

		if (hook->crypt.wp_mode != wp_mode)
		{
			dc_wipe_free(&hook->wp_ctx);

			resl = dc_wipe_init(
				&hook->wp_ctx, hook, ENC_BLOCK_SIZE, wp_mode, hook->crypt.cipher_id);

			if (resl == ST_OK) {
				hook->crypt.wp_mode = d8(wp_mode);
			} else {
				dc_wipe_init(&hook->wp_ctx, hook, ENC_BLOCK_SIZE, WP_NONE, 0);
				hook->crypt.wp_mode = WP_NONE;
			}
		}

		/* wipe sectors */
		dc_wipe_process(&hook->wp_ctx, offs, size);

		/* zero buffer */
		memset(buff, 0, size);
		/* encrypt buffer with temporary key */
		cp_fast_encrypt(buff, buff, size, offs, hook->tmp_key);

		/* write pseudo-random data to device */
		resl = io_hook_rw(hook, buff, size, offs, 0);

		if ( (resl == ST_OK) || (resl == ST_RW_ERR) ) {
			hook->tmp_size += size;
		}
		if ( (resl == ST_MEDIA_CHANGED) || (resl == ST_NO_MEDIA) ) {			
			dc_process_unmount(hook, MF_NOFSCTL); resl = ST_FINISHED;
		}
	} while (0);

	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}
	return resl;
}

int dc_format_done(wchar_t *dev_name)
{
	dev_hook *hook = NULL;
	int       resl;

	DbgMsg("dc_format_done\n");

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}
		wait_object_infinity(&hook->busy_lock);

		if ( !(hook->flags & F_FORMATTING) ) {
			resl = ST_ERROR; break;
		}
		/* set hook fields */
		hook->tmp_size = 0;
		dc_hook_clear_flags(hook, F_FORMATTING); /* interlocked */
		
		// free resources
		dc_wipe_free(&hook->wp_ctx);
		
		if (hook->tmp_buff != NULL) {
			mm_pool_free(hook->tmp_buff);
			hook->tmp_buff = NULL;
		}
		
		if (hook->tmp_key != NULL) {
			mm_secure_free(hook->tmp_key);
			hook->tmp_key = NULL;
		}

		resl = ST_OK;
	} while (0);

	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}
	return resl;
}

int dc_change_pass(wchar_t *dev_name, dc_pass *old_pass, dc_pass *new_pass, u32 flags, ULONG *interrupt_cmd)
{
	dc_header *header = NULL;
	xts_key   *hdr_key = NULL;
	dc_dev     dev;
	dev_hook  *hook   = NULL;
	int        wp_init = 0;
	int        old_kdf = -1;
	int        kdf_sel = old_pass->kdf; /* the caller's, a selector or a concrete KDF */
	int        resl;
	wipe_ctx   wipe;

	if (old_pass->slot != 0) {
		return ST_INVALID_PARAM;
	}
	/* the new password is derived: a KDF selector (KDF_DEFAULT / KDF_ALL) is no KDF */
	if (new_pass->kdf < KDF_NONE) {
		return ST_INVALID_PARAM;
	}

	do
	{
		if ( (hook = dc_find_hook(dev_name)) == NULL ) {
			resl = ST_NF_DEVICE; break;
		}
		wait_object_infinity(&hook->busy_lock);

		if ( !(hook->flags & F_ENABLED) ) {
			resl = ST_NO_MOUNT; break;
		}
		/* not on a locked volume - unlock it first */
		if (hook->flags & (F_SYNC | F_FORMATTING | F_CDROM | F_HIBER_ERASE)) {
			resl = ST_ERROR; break;
		}

#ifdef DC_MBR_LEGACY_GUARD
		/* the BIOS loader derives the header key only with PBKDF2 from a typed password. Slot
		 * passwords (slot != 0) keep the header key and are ignored by it - not restricted. */
		if (DC_MBR_BOOT_VOLUME(hook) && new_pass->slot == 0 && (new_pass->kdf > KDF_SHA512_PKCS5_2 || new_pass->kdf == KDF_NONE)) {
			DbgMsg("dc_change_pass: KDF %d not supported by the legacy BIOS loader\n", new_pass->kdf);
			resl = ST_LEGACY_BOOT; break;
		}
#endif

		/* the layout is fixed for the rest of this call */
		dc_dev_of(hook, &dev);

		/* read old volume header */
		if ( (resl = io_read_header(&dev, dc_hook_rw, 0, &header, &hdr_key, old_pass, &old_kdf, interrupt_cmd)) != ST_OK ) {
			DbgMsg("failed to read header, error code: %d\n", resl);
			break;
		}
		/* dc_change_slot_pass and dc_update_key_slots derive the old key again and need the
		   KDF the header was found with, not a selector */
		old_pass->kdf = old_kdf;

		/* change slot password  */
		if (new_pass->slot != 0)
		{
			if ( (resl = dc_change_slot_pass(header, old_pass, new_pass, interrupt_cmd)) != ST_OK) {
				break;
			}

			flags |= HF_UPDATE_SLOTS;
		}

		/* change primary password  */
		else
		{
			/* io_write_header changes salt and creates new key from password when hdr_key is not NULL */
			mm_secure_free(hdr_key);
			hdr_key = NULL;

			/* v2 headers handling - keyslot update */
			if (header->version >= DC_HDR_VERSION_2 && (header->feature_flags & FF_KEY_SLOTS))
			{
				if (flags & HF_CLEAR_SLOTS) {
					/* clear slots with random data and clear slot info */
					cp_rand_bytes(((u8*)header) + DC_BASE_SIZE, header->slot_area_len);
					memset(((u8*)header) + DC_BASE_SIZE + header->slot_area_len, 0, header->key_slot_count * header->slot_info_size);
				}
				else {
					/* update key slots with new password (preserve header salt) */
					if ((resl = dc_update_key_slots(header, &hdr_key, old_pass, new_pass, interrupt_cmd)) != ST_OK) {
						break;
					}
				}
			}

			/* update meta data */
			if (header->version >= DC_HDR_VERSION_2)
			{
				header->head_kdf = (u8)new_pass->kdf;

				header->hdr_crc = calculate_header_crc(header);
			}
		}

		if (flags & HF_HEADER_FILL) {
			/* init data wipe */
			if ((resl = dc_wipe_init(
				&wipe, hook, hook->head_len, WP_GUTMANN, hook->crypt.cipher_id)) == ST_OK)
			{
				wp_init = 1;
			}
			else break;

			/* wipe volume header */
			dc_wipe_process(&wipe, 0, hook->head_len);
		}

		dc_header_sync_stor_off(hook, header);

		/* write new volume header */
		if ((resl = io_write_header(&dev, dc_hook_rw, 0, header, hdr_key, new_pass, flags, interrupt_cmd)) != ST_OK) {
			DbgMsg("failed to write new header, error code: %d\n", resl);
			break;
		}
		if (new_pass->slot == 0) {
			hook->crypt.head_kdf = new_pass->kdf;
		}

		/* update backup header if present */
		if (hook->flags & F_HEAD_BACKUP)
		{
			resl = dc_change_pass_bak(&dev, dc_hook_rw, header, old_pass, kdf_sel, new_pass, flags, &wipe, interrupt_cmd);
			/* for backup errors always return ST_NOT_BACKUP to indicate that backup header is not valid */
			if (resl != ST_OK) {
				DbgMsg("failed to change backup header pasword, error code: %d\n", resl);
				if ((flags & HF_CLEAR_SLOTS) || !(header->feature_flags & FF_KEY_SLOTS)) {
					/* replace backup header with primary header */
					DbgMsg("restoring backup header from primary header\n");
					resl = dc_update_backup(&dev, dc_hook_rw, header, header->salt, hdr_key, NULL, HF_DEFAULT);
				}
			}
			if (resl != ST_OK){
				resl = ST_NOT_BACKUP;
			}
		}
	} while (0);

	if (wp_init != 0) {
		dc_wipe_free(&wipe);
	}
	if (hook != NULL) {
		KeReleaseMutex(&hook->busy_lock, FALSE);
		dc_deref_hook(hook);
	}	

	if (header != NULL) mm_secure_free(header);
	if (hdr_key != NULL) mm_secure_free(hdr_key);

	return resl;
}

/*
 * Encrypt (or decrypt) a raw range at its natural disk offset with the key the I/O path uses
 * there: below the transcryption boundary the volume key, above it plaintext - or the old key
 * (tmp_key) while re-encrypting; a range crossing it is split. Without a session: the volume
 * key. The caller holds the step slot (tmp_size cannot move); boundary and range are multiples
 * of bps.
 */
static void dc_end_xform(dev_hook *hook, u8 *buff, u32 len, u64 off, int encrypt)
{
	u32 part1 = len; /* below the boundary: volume key */

#ifdef DC_CONCURRENT_TRANSCRYPT
	if (hook->flags & F_SYNC) {
		KIRQL irql;
		u64   bnd;

		KeAcquireSpinLock(&hook->trans.range_lock, &irql);
		bnd = hook->tmp_size;
		KeReleaseSpinLock(&hook->trans.range_lock, irql);

		/* as the I/O path: a zero boundary means no split (readwrite.c, trans_boundary > 0) */
		if (bnd != 0) {
			part1 = (off >= bnd) ? 0 : ((off + len <= bnd) ? len : (u32)(bnd - off));
		}
	}
#endif
	if (part1 != 0) {
		if (encrypt) cp_fast_encrypt(buff, buff, part1, off, hook->dsk_key);
		else         cp_fast_decrypt(buff, buff, part1, off, hook->dsk_key);
	}
	if (len > part1 && (hook->flags & F_REENCRYPT) && hook->tmp_key != NULL) {
		if (encrypt) cp_fast_encrypt(buff + part1, buff + part1, len - part1, off + part1, hook->tmp_key);
		else         cp_fast_decrypt(buff + part1, buff + part1, len - part1, off + part1, hook->tmp_key);
	}
	/* else: above the boundary of an encryption / decryption - plaintext, no transform */
}

NTSTATUS dc_restore_end_sectors(dev_hook *hook, void *buff)
{
	NTSTATUS status;
	u64 end_off = hook->dsk_size - hook->tail_len;

	DbgMsg("dc_restore_end_sectors: dsk_size=%I64u, tail_len=%u, end_off=%I64u, tail_off=%I64u\n",
		hook->dsk_size, hook->tail_len, end_off, hook->tail_off);

	/* Read from storage via hook_dev (redirection + auto-decrypt with storage XTS) */
	if ( !NT_SUCCESS(status = io_device_request(hook->hook_dev, IRP_MJ_READ, buff, hook->tail_len, end_off)) ) {
		DbgMsg("dc_restore_end_sectors: read from storage failed: 0x%X\n", status);
		return status;
	}

	/* Encrypt with partition end XTS tweak and write to actual partition end (with the
	 * key the I/O path uses at end_off, see dc_end_xform) */
	dc_end_xform(hook, (u8*)buff, hook->tail_len, end_off, 1);

	/* Write to actual partition end via orig_dev (raw encrypted) */
	status = io_device_request(hook->orig_dev, IRP_MJ_WRITE, buff, hook->tail_len, end_off);
	DbgMsg("dc_restore_end_sectors: write to disk status: 0x%X\n", status);

	return status;
}

NTSTATUS dc_save_end_sectors(dev_hook *hook, void *buff)
{
	NTSTATUS status;
	u64 end_off = hook->dsk_size - hook->tail_len;

	DbgMsg("dc_save_end_sectors: dsk_size=%I64u, tail_len=%u, end_off=%I64u, tail_off=%I64u\n",
		hook->dsk_size, hook->tail_len, end_off, hook->tail_off);

	/* Read from actual partition end via orig_dev (raw encrypted) */
	if ( !NT_SUCCESS(status = io_device_request(hook->orig_dev, IRP_MJ_READ, buff, hook->tail_len, end_off)) ) {
		DbgMsg("dc_save_end_sectors: read from disk failed: 0x%X\n", status);
		return status;
	}

	/* Decrypt with partition end XTS tweak (key per dc_end_xform) */
	dc_end_xform(hook, (u8*)buff, hook->tail_len, end_off, 0);

	/* Write to storage via hook_dev (redirection + auto-encrypt with storage XTS) */
	status = io_device_request(hook->hook_dev, IRP_MJ_WRITE, buff, hook->tail_len, end_off);
	DbgMsg("dc_save_end_sectors: write to storage status: 0x%X\n", status);

	return status;
}

/*
 * After a resize of a volume with its storage in the slack, overwrite the old storage
 * [old_stor_off, old_len) with random data, except where the already written new head copy
 * and new backup header lie (old and new places overlap when the size changed by less than
 * stor_len). The old backup header wraps the master key under the password(s) of that time,
 * which a later password change would not revoke; an old head copy in space the file system
 * grows into could be found through a stale stor_off. Raw writes, best effort (on a shrink the old
 * place may already lie past the partition end). buff holds at least stor_len bytes; all
 * offsets are multiples of bps.
 */
static void dc_scrub_old_storage(dev_hook *hook, u8 *buff, ULONGLONG old_stor_off, ULONGLONG old_len, ULONGLONG new_len, int has_backup)
{
	ULONGLONG cov_start[2], cov_end[2];
	ULONGLONG pos = old_stor_off, end = old_len;
	int       n_cov = has_backup ? 2 : 1;
	int       i;

	/* ordered and disjoint: stor_len >= 2 * head_len with a backup header (dc_check_header_geometry) */
	cov_start[0] = hook->stor_off;           cov_end[0] = hook->stor_off + hook->head_len;
	cov_start[1] = new_len - hook->head_len; cov_end[1] = new_len;

	for (i = 0; i <= n_cov && pos < end; i++)
	{
		ULONGLONG piece_end = (i < n_cov) ? min(cov_start[i], end) : end;

		if (piece_end > pos) {
			NTSTATUS status;

			cp_rand_bytes(buff, (u32)(piece_end - pos));
			status = io_device_request(hook->orig_dev, IRP_MJ_WRITE, buff, (u32)(piece_end - pos), pos);
			DbgMsg("dc_update_volume: old storage scrubbed at %I64u, len %I64u: 0x%X\n", pos, piece_end - pos, status);
			UNREFERENCED_PARAMETER(status); /* !DBG_MSG builds: DbgMsg is __noop */
		}
		if (i < n_cov) pos = max(pos, cov_end[i]);
	}
}

/*
 * Storage in the slack: the layout derives stor_off from the partition size, the header field
 * is only a record (stale after a resize). Every header base write with a key sets the current
 * one first.
 */
void dc_header_sync_stor_off(dev_hook *hook, dc_header *header)
{
	if ( IS_STORAGE_ON_END(hook->flags) && !(header->flags & (VF_STORAGE_FILE | VF_NO_REDIR)) &&
		 header->stor_off != hook->stor_off )
	{
		header->stor_off = hook->stor_off;
		header->hdr_crc  = calculate_header_crc(header); /* CRC-covered */
	}
}

/* $dcsys$ + backup header: nonzero if the partition-end area [new_len - tail, new_len) of a
 * new_len-byte partition (tail redirect, backup header) does not lie behind the storage file */
int dc_dcsys_end_overlap(dev_hook *hook, u64 new_len)
{
	u64 tail = max((u64)hook->head_len, (u64)hook->tail_len);

	return new_len < tail || new_len - tail < hook->stor_off + hook->stor_len;
}

NTSTATUS dc_update_volume(dev_hook *hook, ULONGLONG new_len)
{
	LARGE_INTEGER timeout = { 0xffe17b80, 0xffffffff }; // 200ms timeout
	ULONGLONG     old_len;
	ULONGLONG     old_stor_off, old_use_size;
	PVOID         pb_buff = NULL;
	PVOID         hdr_backup = NULL;
	NTSTATUS      status = STATUS_SUCCESS;
	int           stor_moved = 0; /* on-end storage was relocated, header stor_off is stale */
	int           slot_held = 0;  /* the transcryption step slot is held */
	int           end_restored = 0; /* end sectors were (possibly partly) written over the backup header */
	int           is_ioctl = (new_len == 0); /* IOCTL_VOLUME_UPDATE_PROPERTIES (else the ShrinkCommit post-op) */
	int           props_sent = 0; /* IOCTL_VOLUME_UPDATE_PROPERTIES was passed to orig_dev */
	int           bak_overlap = 0; /* $dcsys$, the new backup header place lies in the storage file */
	int           bak_written = 0; /* the backup header was written to its new place */

	DbgMsg("dc_update_volume: enter, new_len=%I64u\n", new_len);

	/* a volume mounted with a damaged header (MF_IGNORE_CRC) writes nothing - no relocation */
	if ((hook->flags & F_ENABLED) && (hook->mnt_flags & MF_IGNORE_CRC)) {
		DbgMsg("dc_update_volume: mounted with a damaged header - the layout is not relocated, dev=%ws\n", hook->dev_name);
		/* the lower volume still learns the new size */
		if (is_ioctl) {
			(void)io_device_control(hook->orig_dev, IOCTL_VOLUME_UPDATE_PROPERTIES, NULL, 0, NULL, 0);
		}
		return STATUS_MEDIA_WRITE_PROTECTED;
	}

	/*
	 * The partition table has already changed when IOCTL_VOLUME_UPDATE_PROPERTIES arrives, and
	 * a storage-on-end volume derives stor_off from the partition size at the next mount, so the
	 * storage MUST move now: the IOCTL path waits without a limit (it holds a remove-lock
	 * reference, so the unmount drain counts the wait). The ShrinkCommit post-op keeps the
	 * bounded wait; its pre-op already holds busy_lock (the commit is refused without it), so
	 * this recursive acquisition does not wait and the relocation is never skipped after the
	 * commit.
	 */
	if (is_ioctl) {
		dc_wait_busy_lock_rl(hook);
	} else if (KeWaitForSingleObject(&hook->busy_lock, Executive, KernelMode, FALSE, &timeout) == STATUS_TIMEOUT) {
		return STATUS_DEVICE_NOT_READY;
	}
	old_len      = hook->dsk_size;
	old_stor_off = hook->stor_off;
	old_use_size = hook->use_size;

	/* unmounted while waiting, or the decryption finished (F_PLAIN_IO): nothing to relocate,
	 * but the lower volume still needs the notification and its result is the answer */
	if (is_ioctl && (!(hook->flags & F_ENABLED) || (hook->flags & F_PLAIN_IO))) {
		status = io_device_control(hook->orig_dev, IOCTL_VOLUME_UPDATE_PROPERTIES, NULL, 0, NULL, 0);
		props_sent = 1;
		goto finish;
	}
	/* F_PLAIN_IO: no DC layout is left and hook_dev I/O passes through untranslated -
	 * re-writing the "storage" copy would overwrite live file system data at the partition start.
	 * F_HIBER_ERASE (locked): keys and tmp_header are zeroed - a header rewrite would be
	 * encrypted with a zeroed key. */
	if (!(hook->flags & F_ENABLED) || hook->pnp_state != Started || (hook->flags & (F_DISABLE | F_PLAIN_IO | F_HIBER_ERASE)))
	{
		DbgMsg("dc_update_volume: device state changed during update, aborting\n");
		status = STATUS_INVALID_DEVICE_STATE;
		goto finish;
	}
	/* the relocation writes through io_device_request (no medium check, unlike io_hook_rw) and
	 * re-reads the size of whatever medium is inserted - verify it. "Cannot tell" (ST_IO_ERROR)
	 * is retried for up to 1 s. The post-op (new_len != 0) runs after the file system has
	 * committed: it gives up only on a definite answer (another medium / none); the ShrinkCommit
	 * pre-op verified the medium just before the commit. F_ENABLED is cleared only under
	 * busy_lock, so the check above still holds. */
	if (hook->flags & F_REMOVABLE)
	{
		int media, tries;

		for (tries = 0; (media = io_check_media(hook)) == ST_IO_ERROR && tries < 5; tries++) {
			dc_delay(200);
		}
		if (media != ST_OK && (new_len == 0 || media != ST_IO_ERROR)) {
			DbgMsg("dc_update_volume: mounted medium not verified (%d), aborting\n", media);
			status = STATUS_MEDIA_CHANGED;
			goto finish;
		}
	}

#ifdef DC_CONCURRENT_TRANSCRYPT
	/* no transcryption step may run during the move: dc_dec_finish reads the storage at
	 * hook->stor_off (updated below before the new copy is written), and tmp_header is updated
	 * below. A step arriving now waits for the slot (up to 5 s, then ST_ERROR). */
	dc_acquire_step_slot(hook);
	slot_held = 1;
#endif

	/* IOCTL path: learn the new size BEFORE anything is touched - the notification often comes
	 * without a size change, and the full path rewrites the partition end (a crash in between
	 * loses the backup header). Unchanged -> nothing to do; a failed query takes the full path. */
	if (is_ioctl)
	{
		ULONGLONG cur_len;

		props_sent = 1;
		if ( !NT_SUCCESS(status = io_device_control(hook->orig_dev, IOCTL_VOLUME_UPDATE_PROPERTIES, NULL, 0, NULL, 0)) ) {
			DbgMsg("dc_update_volume: failed to update volume properties error: 0x%X\n", status);
			goto finish;
		}
		/* the same query dc_fill_device_info sets dsk_size from (partition info first) */
		if ( NT_SUCCESS(dc_query_dev_length(hook, &cur_len, NULL)) && cur_len == old_len )
		{
			DbgMsg("dc_update_volume: size unchanged, nothing to do\n");
			status = STATUS_SUCCESS;
			goto finish;
		}
	}

	/* Cache backup header FIRST before any operations that modify partition end */
	if (hook->flags & F_HEAD_BACKUP)
	{
		/* Allocate buffer for backup header
		* Note: hook->head_len and hook->tail_len are almost always same, except during volume layout editing
		* hence we always use hook->head_len, volume layout editing and partition resize should never be done at the same time.
		*/

		if ( (hdr_backup = mm_secure_alloc(max(hook->head_len, PAGE_SIZE))) == NULL )
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto finish;
		}

		DbgMsg("dc_update_volume: F_HEAD_BACKUP read backup header: off=%I64u, len=%u\n",
			hook->dsk_size - hook->head_len, hook->head_len);

		/* Cache backup header from partition end */
		if ( !NT_SUCCESS(status = io_device_request(hook->orig_dev, IRP_MJ_READ, hdr_backup, hook->head_len, hook->dsk_size - hook->head_len)) ) {
			DbgMsg("dc_update_volume: failed to read backup header error: 0x%X\n", status);
			goto finish;
		}
	}

	if (IS_STORAGE_ON_END(hook->flags))
	{
		if ( (pb_buff = mm_secure_alloc(max(hook->stor_len, PAGE_SIZE))) == NULL )
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto finish;
		}

		/* only [0, head_len) is redirected to the storage; past head_len hook_dev
		 * addresses live file system data */
		if (!NT_SUCCESS(status = io_device_request(hook->hook_dev, IRP_MJ_READ, pb_buff, hook->head_len, 0))) {
			DbgMsg("dc_update_volume: failed to read storage error: 0x%X\n", status);
			goto finish;
		}
	}
	else if (hook->flags & F_HEAD_BACKUP)
	{
		/*
		 * F_HEAD_BACKUP with storage file ($dcsys$) - backup header at partition end,
		 * storage file in middle of partition.
		 *
		 * Layout:
		 * - Storage file at stor_off contains: [start sectors][end sectors]
		 * - end sector offset stored in stor_off
		 * - end sector offset is cached in tail_off
		 * - Backup header at dsk_size - tail_len (replaces original end sector data)
		 *
		 * On resize:
		 * 1. Cache backup header from partition end (done above)
		 * 2. Restore original end sectors from storage to partition end
		 * 3. Allow resize (dsk_size changes)
		 * 4. Save new end sectors to storage
		 * 5. Write backup header to new partition end
		 *
		 * Note: stor_off does NOT change (storage file location is fixed)
		 *
		 * Storage access via hook_dev at offset dsk_size - tail_len triggers
		 * end sector redirection and handles XTS encryption automatically.
		 * Actual partition end access requires orig_dev + manual encryption.
		 */

		if ( (pb_buff = mm_secure_alloc(max(hook->tail_len, PAGE_SIZE))) == NULL )
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto finish;
		}

		/* Restore original end sectors from storage to actual partition end */
		end_restored = 1; /* set before the call - a failed write may still have hit the disk */
		if ( !NT_SUCCESS(status = dc_restore_end_sectors(hook, pb_buff)) ) {
			DbgMsg("dc_update_volume: failed to restore end sectors error: 0x%X\n", status);
			goto finish;
		}
	}

	if (new_len != 0)
	{
		/* Shrink post-op: use the known new size from ShrinkPrepare.
		* This may briefly differ from partition manager's view,
		* but IOCTL_VOLUME_UPDATE_PROPERTIES will arrive shortly and validate/rectify. */
		hook->dsk_size = new_len;
	}
	else
	{
		/* IOCTL path: the new size (IOCTL_VOLUME_UPDATE_PROPERTIES was passed down above) */
		if ( !NT_SUCCESS(status = dc_fill_device_info(hook)))  {
			DbgMsg("dc_update_volume: failed to get updated device info error: 0x%X\n", status);
			goto finish;
		}
		new_len = hook->dsk_size;
	}

	if (new_len == old_len) {
		DbgMsg("dc_update_volume: size unchanged, nothing to do\n");
		status = STATUS_SUCCESS;
		goto finish;
	}

	DbgMsg("dc_update_volume: old_len: %I64u, new_len: %I64u\n", old_len, new_len);

	/* storage in the slack: the file system may address the grown range only once the old
	 * storage there is scrubbed, so use_size is published below (the storage write through
	 * hook_dev stays inside the old use_size). The $dcsys$ path needs it now
	 * (dc_save_end_sectors writes the new end through hook_dev). */
	if (!(IS_STORAGE_ON_END(hook->flags) && pb_buff != NULL)) {
		hook->use_size += new_len - old_len;
	}

	/* Backstop (the ShrinkPrepare pre-op refuses this for a file system shrink; reachable when
	 * the partition is cut below the file system): on a $dcsys$ volume with a backup header the
	 * new partition-end area must lie behind the storage file, else saving the end sectors and
	 * writing the backup header would alias the file. Drop the backup layout instead: no tail
	 * redirect, the new end is accessed in place (those bytes belong to $dcsys$), and a session
	 * header no longer claims a backup. Without a session the on-disk header still does: the
	 * next mount logs the overlap (dc_check_geometry). The resize itself is not undone. */
	if ( !IS_STORAGE_ON_END(hook->flags) && (hook->flags & F_HEAD_BACKUP) && hdr_backup != NULL &&
		 dc_dcsys_end_overlap(hook, new_len) )
	{
		DbgMsg("dc_update_volume: new end area %I64u overlaps $dcsys$ [%I64u, +%u), backup header layout dropped\n",
			new_len - max((u64)hook->head_len, (u64)hook->tail_len), hook->stor_off, hook->stor_len);
		dc_hook_clear_flags(hook, F_HEAD_BACKUP);
		hook->tail_len = 0;
		hook->tail_off = 0;
		bak_overlap = 1;
#ifdef DC_CONCURRENT_TRANSCRYPT
		if ((hook->flags & F_SYNC) && hook->tmp_header != NULL && hook->hdr_key != NULL) {
			/* the step slot is held (above): no step touches tmp_header */
			hook->tmp_header->flags &= ~VF_BACKUP_HEADER;
			hook->tmp_header->hdr_crc = calculate_header_crc(hook->tmp_header); /* CRC-covered */
			if (dc_save_enc_state(hook, SYNC_STEP_UPDATE) != ST_OK) {
				DbgMsg("dc_update_volume: failed to write header without backup\n");
			}
		}
#endif
	}

	if (IS_STORAGE_ON_END(hook->flags) && pb_buff != NULL)
	{
		/* written through hook_dev: the redirect encrypts the head copy for its new place, with
		 * the key the I/O path picks there (a session's boundary included) */
		hook->stor_off = new_len - hook->stor_len;
		status = io_device_request(hook->hook_dev, IRP_MJ_WRITE, pb_buff, hook->head_len, 0);
		if (NT_SUCCESS(status)) {
			/* the copy must be on stable media before anything relies on the new place */
			io_device_request(hook->orig_dev, IRP_MJ_FLUSH_BUFFERS, NULL, 0, 0);
		} else {
			/* roll back - the hook keeps describing the old layout, whose storage copy is intact
			 * unless old and new place overlap (below); a later IOCTL_VOLUME_UPDATE_PROPERTIES /
			 * resize retries (not after a storage-on-end shrink: the old storage then lies past
			 * the new end). */
			DbgMsg("dc_update_volume: failed to write storage error: 0x%X, layout rolled back\n", status);
			hook->stor_off = old_stor_off;
			hook->use_size = old_use_size;
			hook->dsk_size = old_len;
			/* when old and new place overlap (size changed by less than head_len) the failed
			 * write may have hit part of the old copy - and on some extends part of the old
			 * backup header. Both are in memory: write them back (the head copy through the
			 * redirect, at the old stor_off again; the backup header raw). Best effort; on a
			 * shrink the old place may already lie past the partition end. */
			{
				u64 h     = hook->head_len;
				u64 new_c = new_len - hook->stor_len;  /* new head copy [new_c, new_c + h) */
				u64 old_c = old_stor_off;              /* old head copy [old_c, old_c + h) */

				if (new_c < old_c + h && old_c < new_c + h) {
					/* only the overlapping slice (in head offsets): a file system write that
					 * landed on the untouched rest after pb_buff was read must survive */
					u64      a  = max(new_c, old_c) - old_c;
					u64      e  = min(new_c, old_c) + h - old_c;
					NTSTATUS rb = io_device_request(hook->hook_dev, IRP_MJ_WRITE, (u8*)pb_buff + a, (u32)(e - a), a);
					DbgMsg("dc_update_volume: old head copy [%I64u, %I64u) rewritten: 0x%X\n", a, e, rb);
					UNREFERENCED_PARAMETER(rb);
				}
				if ( (hook->flags & F_HEAD_BACKUP) && hdr_backup != NULL &&
					 new_c < old_len && old_len - h < new_c + h )
				{
					NTSTATUS rb = io_device_request(hook->orig_dev, IRP_MJ_WRITE, hdr_backup, hook->head_len, old_len - h);
					DbgMsg("dc_update_volume: old backup header rewritten: 0x%X\n", rb);
					UNREFERENCED_PARAMETER(rb);
				}
				io_device_request(hook->orig_dev, IRP_MJ_FLUSH_BUFFERS, NULL, 0, 0);
			}
			goto finish;
		}
		stor_moved = 1;
	}
	else if ((hook->flags & F_HEAD_BACKUP) && hdr_backup != NULL)
	{
		/* Save new end sectors from partition end to storage */
		if ( !NT_SUCCESS(status = dc_save_end_sectors(hook, pb_buff)) ) {
			DbgMsg("dc_update_volume: failed to save end sectors error: 0x%X\n", status);
			goto finish;
		}
	}

finish:
	/*
	 * Storage file + backup header: dc_restore_end_sectors overwrote the backup header with the
	 * original end sectors. On a failure while dsk_size is still old_len put the cached backup
	 * header back (that range is still redirected to the storage file: the exact pre-call
	 * on-disk state). After the size changed (dc_save_end_sectors failed) nothing is written -
	 * the new physical end was not saved to the storage and must not be overwritten.
	 */
	if (!NT_SUCCESS(status) && end_restored && hdr_backup != NULL && hook->dsk_size == old_len)
	{
		NTSTATUS bak_status = io_device_request(hook->orig_dev, IRP_MJ_WRITE, hdr_backup, hook->head_len, old_len - hook->head_len);
		DbgMsg("dc_update_volume: failure path, backup header rewritten at %I64u: 0x%X\n", old_len - hook->head_len, bak_status);
		UNREFERENCED_PARAMETER(bak_status); /* !DBG_MSG builds: DbgMsg is __noop */
	}

	/* If backup header is also at partition end, write it to new location */
	if (NT_SUCCESS(status) && (hook->flags & F_HEAD_BACKUP) && hdr_backup != NULL && !bak_overlap)
	{
		DbgMsg("dc_update_volume: IS_STORAGE_ON_END + F_HEAD_BACKUP write backup header: off=%I64u, len=%u\n",
			new_len - hook->head_len, hook->head_len);

		if ( !NT_SUCCESS(status = io_device_request(hook->orig_dev, IRP_MJ_WRITE, hdr_backup, hook->head_len, new_len - hook->head_len)) ) {
			DbgMsg("dc_update_volume: failed to write backup header error: 0x%X\n", status);
		} else {
			/* if mounted from the backup header, its identity moved with it (same bytes) */
			io_id_move(hook, old_len - hook->head_len, new_len - hook->head_len);
			bak_written = 1;
		}
	}

	/* the storage (and its backup header) moved; the old copies must not stay. With a backup
	 * header only once the new one is written (otherwise the old one is the only backup left).
	 * pb_buff (>= stor_len) is free again after the storage write. */
	if ( stor_moved && pb_buff != NULL &&
		 (!(hook->flags & F_HEAD_BACKUP) || hdr_backup == NULL || bak_written) )
	{
		/* On a shrink only the old backup header: the ShrinkCommit post-op runs before the
		 * partition is shrunk, and if that never happens (crash, VDS failure, an FS-only shrink
		 * tool) the next mount derives the storage from the unchanged size and needs the old
		 * head copy there (it holds no key material). The whole old storage only on an extend.
		 * Trade-off: without a session the on-disk stor_off stays stale and the BIOS loader
		 * reads it, so a BIOS-booted system volume with its storage in the slack no longer
		 * boots after an extend without a session. */
		ULONGLONG scrub_from = (new_len < old_len) ? old_len - hook->head_len : old_stor_off;

		io_device_request(hook->orig_dev, IRP_MJ_FLUSH_BUFFERS, NULL, 0, 0);
		if (new_len >= old_len || (hook->flags & F_HEAD_BACKUP)) {
			dc_scrub_old_storage(hook, pb_buff, scrub_from, old_len, new_len, (hook->flags & F_HEAD_BACKUP) != 0);
		}
		io_device_request(hook->orig_dev, IRP_MJ_FLUSH_BUFFERS, NULL, 0, 0);
	}

	/* the storage moved (slack layout): only now may the file system address the grown
	 * range. Also after a failed raw backup write - the layout moved. */
	if (stor_moved) {
		hook->use_size = old_use_size + (new_len - old_len);
	}

	/*
	 * The on-disk header still carries the old stor_off. The driver and the EFI loader derive
	 * it from dsk_size for !VF_STORAGE_FILE, the BIOS loader reads it. Rewriting the header
	 * needs the header key, which the hook only holds during a transcryption session (F_SYNC:
	 * tmp_header + hdr_key): then publish the new stor_off in tmp_header (every later session
	 * header write carries it) and write it now. dc_save_enc_state flushes, writes the primary
	 * header, flushes, then the backup header. On stor_moved alone: the storage has moved even
	 * if the raw backup write failed. Without a session the header cannot be rewritten (the key
	 * is freed after mount).
	 */
	if (stor_moved)
	{
		if ((hook->flags & F_SYNC) && hook->tmp_header != NULL && hook->hdr_key != NULL)
		{
			/* the step slot is held (above): no step touches tmp_header */
			hook->tmp_header->stor_off = hook->stor_off;
			/* stor_off is inside the CRC area - dc_save_enc_state verifies the CRC before
			 * it writes (and bugchecks on a mismatch) */
			hook->tmp_header->hdr_crc = calculate_header_crc(hook->tmp_header);
#ifdef DC_CONCURRENT_TRANSCRYPT
			if (dc_save_enc_state(hook, SYNC_STEP_UPDATE) != ST_OK) {
				DbgMsg("dc_update_volume: failed to write header with new stor_off\n");
			}
#endif
			/* !DC_CONCURRENT_TRANSCRYPT: the sync thread's next S_OP_SYNC writes it */
		}
		else
		{
			DbgMsg("dc_update_volume: no header key in memory, on-disk header stor_off left stale (new %I64u)\n", hook->stor_off);
		}
	}

	/* the lower volume must learn the new size even when the relocation failed or was not
	 * attempted (the IOCTL is completed here, not forwarded) */
	if (is_ioctl && !props_sent) {
		NTSTATUS fwd = io_device_control(hook->orig_dev, IOCTL_VOLUME_UPDATE_PROPERTIES, NULL, 0, NULL, 0);
		DbgMsg("dc_update_volume: update properties passed down after failure: 0x%X\n", fwd);
		UNREFERENCED_PARAMETER(fwd);
	}

	if (pb_buff != NULL) mm_secure_free(pb_buff);
	if (hdr_backup != NULL) mm_secure_free(hdr_backup);
#ifdef DC_CONCURRENT_TRANSCRYPT
	if (slot_held) {
		dc_release_step_slot(hook);
	}
#endif
	KeReleaseMutex(&hook->busy_lock, FALSE);
	DbgMsg("dc_update_volume: exit with status: 0x%X\n", status);
	return status;
}
