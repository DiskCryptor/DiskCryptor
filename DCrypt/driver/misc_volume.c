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
	dc_dev     dev;
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
		if ((hook->flags & F_NO_HIBER) != (header->flags & VF_NO_HIBER)) {
			if (header->flags & VF_NO_HIBER)
				hook->flags |= F_NO_HIBER;
			else
				hook->flags &= ~F_NO_HIBER;
		}

		/* write updated volume header */
		resl = io_write_header(&dev, dc_hook_rw, hdr_pos, header, hdr_key, password, flags, interrupt_cmd);
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

int dc_change_pass(wchar_t *dev_name, dc_pass *old_pass, dc_pass *new_pass, u32 flags, ULONG *interrupt_cmd)
{
	dc_header *header = NULL;
	xts_key   *hdr_key = NULL;
	dc_dev     dev;
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

		/* the layout is fixed for the rest of this call */
		dc_dev_of(hook, &dev);

		/* read old volume header */
		if ( (resl = io_read_header(&dev, dc_hook_rw, 0, &header, &hdr_key, old_pass, NULL, interrupt_cmd)) != ST_OK ) {
			DbgMsg("failed to read header, error code: %d\n", resl);
			break;
		}

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

		/* write new volume header */
		if ((resl = io_write_header(&dev, dc_hook_rw, 0, header, hdr_key, new_pass, flags, interrupt_cmd) != ST_OK)) {
			DbgMsg("failed to write new header, error code: %d\n", resl);
			break;
		}
		if (new_pass->slot == 0) {
			hook->crypt.head_kdf = new_pass->kdf;
		}

		/* update backup header if present */
		if (hook->flags & F_HEAD_BACKUP)
		{
			resl = dc_change_pass_bak(&dev, dc_hook_rw, header, old_pass, new_pass, flags, &wipe, interrupt_cmd);
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

	/* Encrypt with partition end XTS tweak and write to actual partition end */
	cp_fast_encrypt(buff, buff, hook->tail_len, end_off, hook->dsk_key);

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

	/* Decrypt with partition end XTS tweak */
	cp_fast_decrypt(buff, buff, hook->tail_len, end_off, hook->dsk_key);

	/* Write to storage via hook_dev (redirection + auto-encrypt with storage XTS) */
	status = io_device_request(hook->hook_dev, IRP_MJ_WRITE, buff, hook->tail_len, end_off);
	DbgMsg("dc_save_end_sectors: write to storage status: 0x%X\n", status);

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
		goto finish;
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

		if (!NT_SUCCESS(status = io_device_request(hook->hook_dev, IRP_MJ_READ, pb_buff, hook->stor_len, 0))) {
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
		/* Expand or IOCTL path: query partition manager for new size */
		if ( !NT_SUCCESS(status = io_device_control(hook->orig_dev, IOCTL_VOLUME_UPDATE_PROPERTIES, NULL, 0, NULL, 0)) ) {
			DbgMsg("dc_update_volume: failed to update volume properties error: 0x%X\n", status);
			goto finish;
		}
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

	hook->use_size += new_len - old_len;

	if (IS_STORAGE_ON_END(hook->flags) && pb_buff != NULL)
	{
		hook->stor_off = new_len - hook->stor_len;
		if ( !NT_SUCCESS(status = io_device_request(hook->hook_dev, IRP_MJ_WRITE, pb_buff, hook->stor_len, 0)) ) {
			DbgMsg("dc_update_volume: failed to write storage error: 0x%X\n", status);
			goto finish;
		}
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
	/* If backup header is also at partition end, write it to new location */
	if (NT_SUCCESS(status) && (hook->flags & F_HEAD_BACKUP) && hdr_backup != NULL)
	{
		DbgMsg("dc_update_volume: IS_STORAGE_ON_END + F_HEAD_BACKUP write backup header: off=%I64u, len=%u\n",
			new_len - hook->head_len, hook->head_len);

		if ( !NT_SUCCESS(status = io_device_request(hook->orig_dev, IRP_MJ_WRITE, hdr_backup, hook->head_len, new_len - hook->head_len)) ) {
			DbgMsg("dc_update_volume: failed to write backup header error: 0x%X\n", status);
		}
	}

	if (pb_buff != NULL) mm_secure_free(pb_buff);
	if (hdr_backup != NULL) mm_secure_free(hdr_backup);
	KeReleaseMutex(&hook->busy_lock, FALSE);
	DbgMsg("dc_update_volume: exit with status: 0x%X\n", status);
	return status;
}