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
#include "storage.h"
#include "..\crc32.h"

int dc_backup_header(wchar_t *dev_name, dc_pass *password, void *out, int *size, u32 flags, ULONG *interrupt_cmd)
{
	dc_header *header  = NULL;
	xts_key   *hdr_key = NULL;
	xts_key   *bak_key = NULL;
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
				resl = io_read_header(hook, read_pos, &header, &hdr_key, password, &password_kdf, interrupt_cmd);
			} else {
				/* Volume not mounted, try different offsets: 2k, 4k, 8k, ... up to 4M */
				u32 try_len;
				resl = ST_INV_VOLUME;
				for (try_len = 2048; try_len <= 4 * 1024 * 1024; try_len *= 2) {
					read_pos = hook->dsk_size - try_len;
					if (io_read_header(hook, read_pos, &header, &hdr_key, password, &password_kdf, interrupt_cmd) == ST_OK) {
						resl = ST_OK;
						break;
					}
				}
			}
		} else {
			resl = io_read_header(hook, 0, &header, &hdr_key, password, &password_kdf, interrupt_cmd);
		}
		if (resl != ST_OK) break;
		password->kdf = password_kdf;

		/* determine header length  */
		if (header->version >= DC_HDR_VERSION_2) {

			head_len = header->head_len;
			if (head_len < DC_AREA_SIZE) {
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
	dev_hook  *hook    = NULL;
	int        head_len;
	u64        write_pos;
	int        resl;
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
		/* copy header from input */
		if ( (header = mm_secure_alloc(size)) == NULL ) {
			resl = ST_NOMEM; break;
		}
		memcpy(header, in, DC_AREA_SIZE);

		/* decrypt header */
		if ( (bak_key = mm_secure_alloc(sizeof(xts_key))) == NULL ) {
			resl = ST_NOMEM; break;
		}
		if (cp_decrypt_header(bak_key, header, size, password, &password_kdf, interrupt_cmd) == 0) {
			resl = ST_PASS_ERR; break;
		}
		password->kdf = password_kdf;

		/* determine header length - validate v2 header */
		if (header->version >= DC_HDR_VERSION_2) {

			head_len = header->head_len;
			if (head_len < DC_AREA_SIZE) {
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
				xts_decrypt((u8*)in, ((u8*)header) + DC_AREA_SIZE, head_len - DC_AREA_SIZE, DC_AREA_SIZE, bak_key);
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
			resl = io_write_header(hook, write_pos, header, hdr_key, password, flags & HF_CLEAR_SLOTS, interrupt_cmd);
		} else {
			resl = io_write_header(hook, 0, header, hdr_key, password, flags & HF_CLEAR_SLOTS, interrupt_cmd);
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

		/* determine header position */
		if (flags & HF_BACKUP_HEADER)
		{
			if (hook->flags & F_ENABLED) {
				/* volume is mounted, use known head_len */
				hdr_pos = hook->dsk_size - hook->head_len;
				resl = io_read_header(hook, hdr_pos, &header, &hdr_key, password, &password_kdf, interrupt_cmd);
			} else {
				/* volume not mounted, try different offsets */
				u32 try_len;
				resl = ST_INV_VOLUME;
				for (try_len = DC_AREA_SIZE; try_len <= DC_AREA_MAX_SIZE; try_len *= 2) {
					hdr_pos = hook->dsk_size - try_len;
					if (io_read_header(hook, hdr_pos, &header, &hdr_key, password, &password_kdf, interrupt_cmd) == ST_OK) {
						resl = ST_OK;
						break;
					}
				}
			}
		}
		else
		{
			/* read primary header */
			resl = io_read_header(hook, 0, &header, &hdr_key, password, &password_kdf, interrupt_cmd);
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

		/* special case header upgrade/downgrade */
		if (upd_header->version != header->version)
		{
			/* critical safety checks */
			if (upd_header->alg_1 != header->alg_1 && memcmp(upd_header->key_1, header->key_1, DISKKEY_SIZE) != 0) {
				DbgMsg("dc_update_header: disk key can not be updated, re-encrypt volume\n");
				resl = ST_INVALID_PARAM; break;
			}
			if (upd_header->tmp_size != 0) {
				DbgMsg("dc_update_header: tmp_size size must be zero\n");
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

			/* decrypt remaining header, cp_decrypt_header only decrypts DC_AREA_SIZE */
			if (head_len > DC_AREA_SIZE) {
				xts_decrypt((u8*)in, ((u8*)upd_header) + DC_AREA_SIZE, head_len - DC_AREA_SIZE, DC_AREA_SIZE, hdr_key);
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

		/* write updated volume header */
		resl = io_write_header(hook, hdr_pos, header, hdr_key, password, flags, interrupt_cmd);
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

int dc_format_start(wchar_t *dev_name, dc_pass *password, crypt_info *crypt, u32 flags, ULONG *interrupt_cmd)
{
	IO_STATUS_BLOCK iosb;
	NTSTATUS        status;
	dc_header      *header  = NULL;
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

		/* temporarily disable automounting */
		hook->flags |= F_NO_AUTO_MOUNT;

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
		hook->flags &= ~F_NO_AUTO_MOUNT;
		/* set encryption info */
		hook->crypt = *crypt;

		/* init data wiping */
		resl = dc_wipe_init(
			&hook->wp_ctx, hook, ENC_BLOCK_SIZE, crypt->wp_mode, crypt->cipher_id);

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
		header->flags   = flags;
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

		/* write volume header */
		if ( (resl = io_write_header(hook, 0, header, NULL, password, HF_DEFAULT, interrupt_cmd)) != ST_OK ) {
			break;
		}

		/* write backup header, with a new salt, to partition end */
		if( flags & VF_BACKUP_HEADER) {
			cp_rand_bytes(pv(header->salt), HEADER_SALT_SIZE);
			if ( (resl = io_write_header(hook, hook->dsk_size - hook->head_len, header, NULL, password, HF_DEFAULT, interrupt_cmd)) != ST_OK ) {
				break;
			}
		}

		/* mount device */
		if ( (resl = dc_mount_device(dev_name, password, 0, interrupt_cmd)) != ST_OK ) {
			break;
		}		
		/* set hook fields */
		hook->flags     |= F_FORMATTING;
		hook->tmp_size   = hook->head_len;
		hook->tmp_buff   = buff;
		hook->tmp_key    = tmp_key;
	} while (0);

	if (resl != ST_OK)
	{
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

		offs = hook->tmp_size;
		buff = hook->tmp_buff;
		size = d32(min(hook->dsk_size - offs, ENC_BLOCK_SIZE));

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
		hook->flags   &= ~F_FORMATTING;		
		
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

static int dc_update_key_slots(dc_header *header, xts_key **hdr_key, dc_pass *old_pass, dc_pass *new_pass, ULONG *interrupt_cmd)
{
	int        slot_size;
	int        used_slots = 0;
	int        i;
	dc_slot_info* slot_info = NULL;
	u8*        key_slot = NULL;
	u32        info_crc = 0;
	u8         old_dk[PKCS_DERIVE_MAX];
	u8         new_dk[PKCS_DERIVE_MAX];
	int        resl = ST_OK;

	dc_derive_key(old_pass, old_pass->kdf, header->salt, old_dk, interrupt_cmd);
	dc_derive_key(new_pass, new_pass->kdf, header->salt, new_dk, interrupt_cmd);

	/* update key slots */
	slot_size = header->slot_area_len / header->key_slot_count;
	//slot_size = cp_get_key_slot_size(slot_type);
	for (i = 0; i < header->key_slot_count; i++) {
		key_slot = ((u8*)header) + DC_BASE_SIZE + (slot_size * i);
		slot_info = (dc_slot_info*)(((u8*)header) + DC_BASE_SIZE + header->slot_area_len + (header->slot_info_size * i));
		if ((slot_info->flags & SF_ACTIVE) && !(slot_info->flags & SF_CORRUPT)) {
			info_crc = crc32(pv(&slot_info->flags), header->slot_info_size - 4);
			if (slot_info->crc == crc32_combine(info_crc, crc32(key_slot, slot_size), slot_size)) {
				if (!cp_swap_slot_key(key_slot, old_dk, new_dk, slot_info->type)) {
					resl = ST_SLOT_NOT_OK;
					break;
				}
				slot_info->crc = crc32_combine(info_crc, crc32(key_slot, slot_size), slot_size);
				used_slots++;
				continue;
			}
			slot_info->flags |= SF_CORRUPT;
			DbgMsg("slot %d is corrupted, clearing\n", i);
		}
		// if slot is not active or corrupted we just fill it with random data
		cp_rand_bytes(key_slot, slot_size);
		slot_info->crc = 0;
	}

	/* prevent leaks */
	burn(old_dk, sizeof(old_dk));
	burn(new_dk, sizeof(new_dk));

	if ( used_slots > 0 )
	{
		/* prepare header key - preserve salt */
		if ((*hdr_key = mm_secure_alloc(sizeof(xts_key))) == NULL) {
			resl = ST_NOMEM;
		}
		else if (!cp_set_header_key(*hdr_key, header->salt, header->alg_1, new_pass, interrupt_cmd)) {
			resl = ST_INVALID_PARAM;
		}
	}

	return resl;
}

int dc_change_slot_pass(dev_hook *hook, dc_header *header, dc_pass *old_pass, dc_pass *new_pass, ULONG *interrupt_cmd)
{
	u8         dk[PKCS_DERIVE_MAX];
	u8         sk[PKCS_DERIVE_MAX];
	u8        *slot;
	dc_slot_info *info;
	int        slot_index;
	int        slot_size;
	u32        slot_off;
	u32        info_off;
	u32        info_crc;
	int        resl = ST_OK;

	do
	{
		if (header->version < DC_HDR_VERSION_2 || !(header->feature_flags & FF_KEY_SLOTS)) {
			DbgMsg("dc_change_slot_pass: key slots not supported by header\n");
			resl = ST_INVALID_PARAM;
			break;
		}

		if (new_pass->slot < 1 || new_pass->slot > header->key_slot_count) {
			DbgMsg("dc_change_slot_pass: invalid slot number %d\n", new_pass->slot);
			resl = ST_INVALID_PARAM;
			break;
		}

		/* validate slot layout fits within header */
		if (header->key_slot_count == 0 || header->slot_area_len == 0 || header->slot_info_size < sizeof(dc_slot_info)) {
			DbgMsg("dc_change_slot_pass: invalid slot layout\n");
			resl = ST_INV_VOLUME;
			break;
		}

		slot_index = new_pass->slot - 1;
		slot_size = header->slot_area_len / header->key_slot_count;
		slot_off = DC_BASE_SIZE + (slot_size * slot_index);
		info_off = DC_BASE_SIZE + header->slot_area_len + (header->slot_info_size * slot_index);

		/* validate offsets are within header bounds */
		if (slot_off + slot_size > header->head_len) {
			DbgMsg("dc_change_slot_pass: slot offset %u + size %d exceeds header length %u\n", slot_off, slot_size, header->head_len);
			resl = ST_INV_VOLUME;
			break;
		}
		if (info_off + header->slot_info_size > header->head_len) {
			DbgMsg("dc_change_slot_pass: info offset %u + size %u exceeds header length %u\n", info_off, header->slot_info_size, header->head_len);
			resl = ST_INV_VOLUME;
			break;
		}

		slot = ((u8*)header) + slot_off;
		info = (dc_slot_info*)(((u8*)header) + info_off);

		if (!dc_derive_key(old_pass, old_pass->kdf, header->salt, dk, interrupt_cmd)) {
			DbgMsg("dc_change_slot_pass: failed to derive old password key\n");
			resl = ST_INVALID_PARAM;
			break;
		}

		if (!dc_derive_key(new_pass, new_pass->kdf, header->salt, sk, interrupt_cmd)) {
			DbgMsg("dc_change_slot_pass: failed to derive new password key\n");
			resl = ST_INVALID_PARAM;
			break;
		}

		/* update slot info */
		info->flags |= SF_ACTIVE;
		info->flags &= ~SF_CORRUPT;
		info->type = DC_SLOT_TYPE_0;
		info->data_0.slot_kdf = (u8)new_pass->kdf;

		/* wrap the header key into the slot */
		if (!cp_wrap_header_key(slot, sk, dk, info->type)) {
			resl = ST_SLOT_NOT_OK;
			break;
		}

		/* compute and set CRC: crc32(info excluding crc field) combined with crc32(slot data) */
		info_crc = crc32(pv(&info->flags), header->slot_info_size - 4);
		info->crc = crc32_combine(info_crc, crc32(slot, slot_size), slot_size);

	} while (0);

	/* prevent leaks */
	burn(dk, sizeof(dk));
	burn(sk, sizeof(sk));

	return resl;
}

int dc_change_pass_bak(dev_hook *hook, dc_header *header, dc_pass *old_pass, dc_pass *new_pass, u32 flags, wipe_ctx* wipe, ULONG *interrupt_cmd)
{
	dc_header *hback = NULL;
	xts_key   *bak_key = NULL;
	u64        backup_pos = hook->dsk_size - hook->head_len;
	int        slots_valid = 0;
	int        slots_len = 0;
	int        resl;

	do
	{
		/* read and validate backup header */
		if ((resl = io_read_header(hook, backup_pos, &hback, &bak_key, old_pass, NULL, interrupt_cmd)) != ST_OK) {
			DbgMsg("failed to read backup header, error code: %d\n", resl);
			resl = ST_INV_VOLUME;
			break;
		}

		/* check if slot layout matches between primary and backup */
		if (header->version >= DC_HDR_VERSION_2 && (header->feature_flags & FF_KEY_SLOTS))
		{
			slots_len = header->slot_area_len + (header->key_slot_count * header->slot_info_size);

			if (hback->slot_area_len == header->slot_area_len &&
				hback->key_slot_count == header->key_slot_count &&
				hback->slot_info_size == header->slot_info_size) {
				slots_valid = 1;
			} else {
				DbgMsg("backup header slot layout mismatch, clearing slots\n");
			}
		}

		/* copy primary header data to backup, skipping salt and key slots+info */
		memcpy(((u8*)hback) + HEADER_SALT_SIZE, ((u8*)header) + HEADER_SALT_SIZE, DC_BASE_SIZE - HEADER_SALT_SIZE);

		/* copy data after slot area (ext header, etc.) */
		if ((u32)DC_BASE_SIZE + slots_len < hook->head_len) {
			memcpy(((u8*)hback) + DC_BASE_SIZE + slots_len, ((u8*)header) + DC_BASE_SIZE + slots_len, hook->head_len - DC_BASE_SIZE - slots_len);
		}

		/* change slot password on backup header */
		if (new_pass->slot != 0)
		{
			if ( (resl = dc_change_slot_pass(hook, hback, old_pass, new_pass, interrupt_cmd)) != ST_OK) {
				break;
			}

			flags |= HF_UPDATE_SLOTS;
		}

		/* change primary password  */
		else
		{
			/* io_write_header changes salt and creates new key from password when hdr_key is not NULL */
			mm_secure_free(bak_key);
			bak_key = NULL;

			if (slots_valid && !(flags & HF_CLEAR_SLOTS)) {
				/* update all key slots with new primary password (uses backup's salt) */
				if ((resl = dc_update_key_slots(hback, &bak_key, old_pass, new_pass, interrupt_cmd)) != ST_OK) {
					break;
				}
			}
			else if (slots_len > 0) {
				/* slot layout mismatch, or clearing - fill slots with random data and clear slot info */
				cp_rand_bytes(((u8*)hback) + DC_BASE_SIZE, header->slot_area_len);
				memset(((u8*)hback) + DC_BASE_SIZE + header->slot_area_len, 0, header->key_slot_count * header->slot_info_size);
			}
		}

		if (flags & HF_HEADER_FILL) {
			/* wipe backup header area */
			dc_wipe_process(wipe, backup_pos, hook->head_len);
		}

		/* write new backup header */
		if ((resl = io_write_header(hook, backup_pos, hback, bak_key, new_pass, flags, interrupt_cmd)) != ST_OK) {
			DbgMsg("failed to write new backup header, error code: %d\n", resl);
			break;
		}

	} while (0);

	if (hback != NULL)   mm_secure_free(hback);
	if (bak_key != NULL) mm_secure_free(bak_key);

	return resl;
}

int dc_change_pass(wchar_t *dev_name, dc_pass *old_pass, dc_pass *new_pass, u32 flags, ULONG *interrupt_cmd)
{
	dc_header *header = NULL;
	xts_key   *hdr_key = NULL;
	dev_hook  *hook   = NULL;
	int        wp_init = 0;
	int        resl;
	wipe_ctx   wipe;
	
	if (old_pass->slot != 0) {
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
		if (hook->flags & (F_SYNC | F_FORMATTING | F_CDROM)) {
			resl = ST_ERROR; break;
		}

		/* read old volume header */
		if ( (resl = io_read_header(hook, 0, &header, &hdr_key, old_pass, NULL, interrupt_cmd)) != ST_OK ) {
			DbgMsg("failed to read header, error code: %d\n", resl);
			break;
		}

		/* change slot password  */
		if (new_pass->slot != 0)
		{
			if ( (resl = dc_change_slot_pass(hook, header, old_pass, new_pass, interrupt_cmd)) != ST_OK) {
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

		/* write new volume header */
		if ((resl = io_write_header(hook, 0, header, hdr_key, new_pass, flags, interrupt_cmd) != ST_OK)) {
			DbgMsg("failed to write new header, error code: %d\n", resl);
			break;
		}
		if (new_pass->slot == 0) {
			hook->crypt.head_kdf = new_pass->kdf;
		}

		/* update backup header if present */
		if (hook->flags & F_HEAD_BACKUP)
		{
			resl = dc_change_pass_bak(hook, header, old_pass, new_pass, flags, &wipe, interrupt_cmd);
			/* for backup errors always return ST_NOT_BACKUP to indicate that backup header is not valid */
			if (resl != ST_OK) {
				DbgMsg("failed to change backup header pasword, error code: %d\n", resl);
				if ((flags & HF_CLEAR_SLOTS) || !(header->feature_flags & FF_KEY_SLOTS)) {
					/* replace backup header with primary header */
					DbgMsg("restoring backup header from primary header\n");
					resl = dc_update_backup(hook, header, header->salt, hdr_key, NULL, HF_DEFAULT);
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

int dc_update_backup(dev_hook *hook, dc_header *header, u8 *bak_salt, xts_key *bak_key, u8 *key_slots, u32 flags)
{
	dc_header *hcopy = NULL;
	u8        *old_backup = NULL;
	u64        backup_pos = hook->dsk_size - hook->head_len;
	int        resl;
	int        slot_size;
	int        i;
	dc_slot_info* slot_info = NULL;
	u8*        key_slot = NULL;
	u32        info_crc = 0;

	if (!(hook->flags & F_HEAD_BACKUP)) {
		return ST_ERROR;
	}

	/* validate header */
	if (!is_volume_header_correct(header)) {
		resl = ST_INV_VOLUME;
		goto finish;
	}

	/* Use provided key or fall back to hook->hdr_key */
	if (bak_salt == NULL || bak_key == NULL || bak_key->encrypt == NULL) {
		resl = ST_ERROR;
		goto finish;
	}

	/* validate storage size for backup header */
	if (IS_STORAGE_ON_END(hook->flags)) {
		if (hook->stor_len < hook->head_len * 2) {
			resl = ST_NF_SPACE;
			goto finish;
		}
	} else {
		if (hook->tail_len < hook->head_len) {
			resl = ST_NF_SPACE;
			goto finish;
		}
	}

	/* prepare backup header copy with its own salt */
	if ((hcopy = mm_secure_alloc(hook->head_len)) == NULL) {
		return ST_NOMEM;
	}
	memcpy(hcopy, header, hook->head_len);
	memcpy(hcopy->salt, bak_salt, HEADER_SALT_SIZE);

	/* Key slots are encrypted with a key derived from the header salt.
	* The backup header has its own salt, so we must preserve the backup's
	* existing keyslot area which is encrypted with the backup salt.
	* The passed 'header' is the primary header whose key slots are bound
	* to the primary salt - we cannot use those for the backup. */
	if (header->version >= DC_HDR_VERSION_2 && (header->feature_flags & FF_KEY_SLOTS) && header->slot_area_len > 0)
	{
		if ((u32)DC_BASE_SIZE + header->slot_area_len > hook->head_len) {
			DbgMsg("dc_update_backup: invalid slot area length %u\n", header->slot_area_len);
			resl = ST_INV_VOLUME;
			goto finish;
		}

		if (flags & HF_CLEAR_SLOTS) {
			/* clear slots with random data and clear slot info */
			cp_rand_bytes(((u8*)hcopy) + DC_BASE_SIZE, header->slot_area_len);
			memset(((u8*)hcopy) + DC_BASE_SIZE + header->slot_area_len, 0, header->key_slot_count * header->slot_info_size);
		}
		else 
		{
			if (key_slots != NULL) {
				/* Use provided key slots directly */
				memcpy(((u8*)hcopy) + DC_BASE_SIZE, key_slots, header->slot_area_len);
			}
			else {
				/* read old backup header raw bytes from disk */
				if ((old_backup = mm_secure_alloc(hook->head_len)) == NULL) {
					resl = ST_NOMEM;
					goto finish;
				}
				if ((resl = io_hook_rw(hook, old_backup, hook->head_len, backup_pos, 1)) != ST_OK) {
					DbgMsg("dc_update_backup: failed to read old backup header\n");
					goto finish;
				}

				/* copy the raw keyslot area from old backup header to hcopy
				* (key slots start at DC_BASE_SIZE with length slot_area_len) */
				memcpy(((u8*)hcopy) + DC_BASE_SIZE, old_backup + DC_BASE_SIZE, header->slot_area_len);
			}

			/* update key slotinto crc */
			slot_size = hcopy->slot_area_len / hcopy->key_slot_count;
			//slot_size = cp_get_key_slot_size(slot_type);
			for (i = 0; i < hcopy->key_slot_count; i++) {
				key_slot = ((u8*)hcopy) + DC_BASE_SIZE + (slot_size * i);
				slot_info = (dc_slot_info*)(((u8*)hcopy) + DC_BASE_SIZE + hcopy->slot_area_len + (hcopy->slot_info_size * i));
				if ((slot_info->flags & SF_ACTIVE) && !(slot_info->flags & SF_CORRUPT)) {
					info_crc = crc32(pv(&slot_info->flags), hcopy->slot_info_size - 4);
					slot_info->crc = crc32_combine(info_crc, crc32(key_slot, slot_size), slot_size);
				}
			}
		}
	}

	resl = io_write_header(hook, backup_pos, hcopy, bak_key, NULL, flags, NULL);

finish:
	if (old_backup != NULL) mm_secure_free(old_backup);
	if (hcopy != NULL) mm_secure_free(hcopy);
	DbgMsg("dc_update_backupfinished: pos=%I64u; resl=%d\n", backup_pos, resl);
	return resl;
}

NTSTATUS dc_restore_end_sectors(dev_hook *hook, void *buff)
{
	NTSTATUS status;
	u64 end_off = hook->dsk_size - hook->tail_len;

	/* Read from storage via hook_dev (redirection + auto-decrypt with storage XTS) */
	if ( !NT_SUCCESS(status = io_device_request(hook->hook_dev, IRP_MJ_READ, buff, hook->tail_len, end_off)) ) {
		return status;
	}

	/* Encrypt with partition end XTS tweak and write to actual partition end */
	cp_fast_encrypt(buff, buff, hook->tail_len, end_off - hook->tail_len, hook->dsk_key);

	/* Write to actual partition end via orig_dev (raw encrypted) */
	status = io_device_request(hook->orig_dev, IRP_MJ_WRITE, buff, hook->tail_len, end_off);

	return status;
}

NTSTATUS dc_save_end_sectors(dev_hook *hook, void *buff)
{
	NTSTATUS status;
	u64 end_off = hook->dsk_size - hook->tail_len;

	/* Read from actual partition end via orig_dev (raw encrypted) */
	if ( !NT_SUCCESS(status = io_device_request(hook->orig_dev, IRP_MJ_READ, buff, hook->tail_len, end_off)) ) {
		return status;
	}

	/* Decrypt with partition end XTS tweak */
	cp_fast_decrypt(buff, buff, hook->tail_len, end_off - hook->tail_len, hook->dsk_key);

	/* Write to storage via hook_dev (redirection + auto-encrypt with storage XTS) */
	status = io_device_request(hook->hook_dev, IRP_MJ_WRITE, buff, hook->tail_len, end_off);

	return status;
}

NTSTATUS dc_update_volume(dev_hook *hook, ULONGLONG new_len)
{
	LARGE_INTEGER timeout = { 0xffe17b80, 0xffffffff }; // 200ms timeout
	ULONGLONG     old_len = hook->dsk_size;
	PVOID         pb_buff = NULL;
	PVOID         hdr_backup = NULL;
	NTSTATUS      status = STATUS_SUCCESS;

	DbgMsg("dc_update_volume: enter, new_len=%I64u\n", new_len);

	if (KeWaitForSingleObject(&hook->busy_lock, Executive, KernelMode, FALSE, &timeout) == STATUS_TIMEOUT)
	{
		return STATUS_DEVICE_NOT_READY;
	}
	if (hook->dsk_size != old_len || hook->pnp_state != Started || (hook->flags & F_DISABLE))
	{
		DbgMsg("dc_update_volume: device state changed during update, aborting\n");
		status = STATUS_INVALID_DEVICE_STATE;
		goto cleanup;
	}

	if (IS_STORAGE_ON_END(hook->flags))
	{
		if ( (pb_buff = mm_secure_alloc(max(hook->stor_len, PAGE_SIZE))) == NULL )
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto cleanup;
		}

		if (!NT_SUCCESS(status = io_device_request(hook->hook_dev, IRP_MJ_READ, pb_buff, hook->stor_len, 0))) {
			DbgMsg("dc_update_volume: failed to read storage error: 0x%X\n", status);
			goto cleanup;
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
		 * 1. Cache backup header from partition end
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

		if ( (pb_buff = mm_secure_alloc(max(hook->head_len, PAGE_SIZE))) == NULL )
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto cleanup;
		}
		if ( (hdr_backup = mm_secure_alloc(max(hook->tail_len, PAGE_SIZE))) == NULL )
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto cleanup;
		}

		/* Cache backup header from partition end (direct access via orig_dev - raw encrypted header) */
		if ( !NT_SUCCESS(status = io_device_request(hook->orig_dev, IRP_MJ_READ, hdr_backup, hook->tail_len, hook->dsk_size - hook->tail_len)) ) {
			DbgMsg("dc_update_volume: failed to read backup header error: 0x%X\n", status);
			goto cleanup;
		}

		/* Restore original end sectors from storage to actual partition end */
		if ( !NT_SUCCESS(status = dc_restore_end_sectors(hook, pb_buff)) ) {
			DbgMsg("dc_update_volume: failed to restore end sectors error: 0x%X\n", status);
			goto cleanup;
		}
	}

	if (new_len == 0)
	{
		/* Update size fields early to maintain internal consistency with stor_off.
		* For shrink post-op, this may briefly differ from partition manager's view,
		* but IOCTL_VOLUME_UPDATE_PROPERTIES will arrive shortly and validate/rectify. */
		hook->dsk_size = new_len;
	}
	else
	{
		/* Expand or IOCTL path: query partition manager for new size */
		if ( !NT_SUCCESS(status = io_device_control(hook->orig_dev, IOCTL_VOLUME_UPDATE_PROPERTIES, NULL, 0, NULL, 0)) ) {
			DbgMsg("dc_update_volume: failed to update volume properties error: 0x%X\n", status);
			goto cleanup;
		}
		if ( !NT_SUCCESS(status = dc_fill_device_info(hook)))  {
			DbgMsg("dc_update_volume: failed to get updated device info error: 0x%X\n", status);
			goto cleanup;
		}
		new_len = hook->dsk_size;
	}

	if (new_len == old_len) {
		DbgMsg("dc_update_volume: size unchanged, nothing to do\n");
		status = STATUS_SUCCESS;
		goto cleanup;
	}

	DbgMsg("dc_update_volume: old_len: %I64u, new_len: %I64u\n", old_len, new_len);

	hook->use_size += new_len - old_len;

	if (IS_STORAGE_ON_END(hook->flags) && pb_buff != NULL)
	{
		hook->stor_off = new_len - hook->stor_len;
		if ( !NT_SUCCESS(status = io_device_request(hook->hook_dev, IRP_MJ_WRITE, pb_buff, hook->stor_len, 0)) ) {
			DbgMsg("dc_update_volume: failed to write storage error: 0x%X\n", status);
			goto cleanup;
		}
	}
	else if ((hook->flags & F_HEAD_BACKUP) && hdr_backup != NULL)
	{
		DbgMsg("dc_update_volume: old tail_off: %I64u\n", hook->tail_off);
		hook->tail_off = hook->stor_off + hook->stor_len - hook->tail_len;
		DbgMsg("dc_update_volume: new tail_off: %I64u\n", hook->tail_off);

		/* Save new end sectors from partition end to storage */
		if ( !NT_SUCCESS(status = dc_save_end_sectors(hook, pb_buff)) ) {
			DbgMsg("dc_update_volume: failed to save end sectors error: 0x%X\n", status);
			goto cleanup;
		}

		/* Write backup header to new partition end (raw, not encrypted with volume key) */
		if ( !NT_SUCCESS(status = io_device_request(hook->orig_dev, IRP_MJ_WRITE, hdr_backup, hook->tail_len, new_len - hook->tail_len)) ) {
			DbgMsg("dc_update_volume: failed to write backup header error: 0x%X\n", status);
			goto cleanup;
		}
	}

cleanup:
	if (pb_buff != NULL) mm_secure_free(pb_buff);
	if (hdr_backup != NULL) mm_secure_free(hdr_backup);
	KeReleaseMutex(&hook->busy_lock, FALSE);
	DbgMsg("dc_update_volume: exit with status: 0x%X\n", status);
	return status;
}