/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2026
    * DavidXanatos <info@diskcryptor.org>
    * Copyright (c) 2010-2011
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

#include "defines.h"
#include "header_io.h"
#include "misc_mem.h"
#include "crypto_head.h"
#include "device_io.h"
#include "debug.h"
#include "..\crc32.h"

int io_read_header_full(dev_hook *hook, u64 pos, dc_header **header, xts_key *hdr_key, int hdr_len)
{
	int      buff_len = ROUND_TO_FULL_SECTORS(max(hdr_len, PAGE_SIZE), hook->bps);
	u8      *buff = NULL;
	u8      *buff2 = NULL;
	int      resl = ST_OK;

	/* v2 headers handling */
	if ((*header)->version < DC_HDR_VERSION_2) {
		return ST_OK; /* nothing to do for v1 headers */
	}

	do
	{
		/* allocate raw buffer and read raw header data from disk */
		if ( (buff = mm_secure_alloc(buff_len)) == NULL ) { resl = ST_NOMEM; break; }
		if ( (resl = io_hook_rw(hook, buff, hdr_len, pos, 1)) != ST_OK ) break;

		/* if header length is greater than read length, reallocate header buffer and read the rest of header */
		if (hdr_len < (int)(*header)->head_len)
		{
			/* reallocate raw buffer */
			buff2 = buff;
			buff_len = ROUND_TO_FULL_SECTORS(max((int)(*header)->head_len, PAGE_SIZE), hook->bps);
			if ( (buff = mm_secure_alloc(buff_len)) == NULL ) { resl = ST_NOMEM; break; }
			memcpy(buff, buff2, hdr_len);

			/* reallocate (partially) decrypted header */
			memcpy(buff2, *header, hdr_len);
			mm_secure_free(*header);
			buff_len = ROUND_TO_FULL_SECTORS(((dc_header*)buff2)->head_len, hook->bps);
			if ((*header = mm_secure_alloc(buff_len)) == NULL) { resl = ST_NOMEM; break; }
			memcpy(*header, buff2, hdr_len);

			mm_secure_free(buff2);
			buff2 = NULL;

			/* read the rest of header */
			if ( (resl = io_hook_rw(hook, buff + hdr_len, (int)(*header)->head_len - hdr_len, pos + hdr_len, 1)) != ST_OK ) break;

			hdr_len = (int)(*header)->head_len;
		}

		/* decrypt remaining header, cp_decrypt_header only decrypts DC_AREA_SIZE */
		if (hdr_len > DC_AREA_SIZE) {
			xts_decrypt(buff, ((u8*)*header) + DC_AREA_SIZE, hdr_len - DC_AREA_SIZE, DC_AREA_SIZE, hdr_key);
		}

		/* load keyslots */
		if ((*header)->feature_flags & FF_KEY_SLOTS) {
			cp_copy_keylots(*header, buff, (u8*)*header);
		}
	} while (0);

	if (resl != ST_OK) {
		mm_secure_free(*header); *header = NULL;
	}
	if (buff != NULL) mm_secure_free(buff);
	if (buff2 != NULL) mm_secure_free(buff2);
	return resl;
}

int io_read_header(dev_hook *hook, u64 pos, dc_header **header, xts_key **out_key, dc_pass *password, int* out_kdf, ULONG *interrupt_cmd)
{
	xts_key *hdr_key = NULL;
	int      hdr_len = ROUND_TO_FULL_SECTORS(max((int)hook->head_len, cp_get_min_header_len(password)), hook->bps);
	int      resl;

	//DbgMsg("io_read_header: pos %I64d; password kdf %d, slot id %d, size %d\n", pos , password->kdf, password->slot, password->size);

	do
	{
		/* allocate memory for header */
		if ( (*header = mm_secure_alloc(hdr_len)) == NULL ) { resl = ST_NOMEM; break; }

		/* read volume header */
		if ( (resl = io_hook_rw(hook, *header, hdr_len, pos, 1)) != ST_OK ) break;

		/* allocate memory for header key */
		if ( (hdr_key = mm_secure_alloc(sizeof(xts_key))) == NULL ) { resl = ST_NOMEM; break; }
		/* try to decrypt header */
		if (cp_decrypt_header(hdr_key, *header, hdr_len, password, out_kdf, interrupt_cmd) == 0) { resl = ST_PASS_ERR; break; }

		/* read and decrypt rest of v2 header */
		if ( (resl = io_read_header_full(hook, pos, header, hdr_key, hdr_len)) != ST_OK ) break;

		/* save decrypted header and key */
		if (out_key != NULL) { *out_key = hdr_key; hdr_key = NULL; }
	} while (0);

	if (resl != ST_OK) {
		mm_secure_free(*header); *header = NULL;
	}
	if (hdr_key != NULL) mm_secure_free(hdr_key);
	return resl;
}

unsigned long calculate_header_crc(dc_header* header)
{
	if (header->version >= DC_HDR_VERSION_2) {
		// version 2 and later have the CRC calculated only over the header base
		return crc32((const unsigned char*)&header->version, DC_CRC_AREA_SIZE_2 - ((int)header->footer_cnt << 4));
	}
	return crc32((const unsigned char*)&header->version, DC_CRC_AREA_SIZE_1);
}

BOOLEAN is_volume_header_correct(dc_header *header)
{
	unsigned char v = 0;
	size_t        i;

	// check salt bytes, correct headers must not have zero salt
	for (i = 0; i < sizeof(header->salt); i++) v |= header->salt[i];
	if (v == 0) return FALSE;

	// check header signature and checksum
	if (header->sign != DC_VOLUME_SIGN) return FALSE;
	if (header->hdr_crc != calculate_header_crc(header)) return FALSE;

	return TRUE;
}

int io_write_header(dev_hook *hook, u64 pos, dc_header *header, xts_key *hdr_key, dc_pass *password, u32 flags, ULONG *interrupt_cmd)
{
	u8         salt[HEADER_SALT_SIZE];
	int        hdr_len = ROUND_TO_FULL_SECTORS(DC_AREA_SIZE, hook->bps);
	int        mem_len = DC_AREA_SIZE;
	dc_header *hcopy = NULL;
	u8        *buff = NULL;
	xts_key   *h_key = hdr_key;
	u64        offset = 0;
	u32        length = hdr_len;
	int        resl;

	if (hdr_key != NULL && hdr_key->encrypt == NULL) return ST_ERROR;
	if (password != NULL && password->size == 0) return ST_ERROR;

	if (header->version >= DC_HDR_VERSION_2)
	{
		hdr_len = ROUND_TO_FULL_SECTORS(header->head_len, hook->bps);
		mem_len = header->head_len;

		/* when updating header calculate minumum required write length and offset and check header correctness */
		if ((flags & HF_UPDATE_ALL) != 0 && (flags & HF_UPDATE_ALL) != HF_UPDATE_ALL)
		{
			if (hdr_key == NULL) {
				DbgMsg("partial header update atempt without header key\n");
				return ST_ERROR;
			}

			length = DC_BASE_SIZE;
			if (header->feature_flags & FF_KEY_SLOTS) {
				length += header->slot_area_len + (header->key_slot_count * header->slot_info_size);
			}

			if (flags & HF_UPDATE_EXT) {
				if (header->ext_hdr_off == 0) {
					DbgMsg("extended header update atempt but ext_hdr_off is zero\n");
					flags &= ~HF_UPDATE_EXT;
				}
				else if ((u32)header->ext_hdr_off + MIN_EXT_HDR_SIZE >= header->head_len || header->ext_hdr_off < length) {
					DbgMsg("invalid extended header offset\n");
					return ST_INV_VOLUME;
				}
			}

			if (flags & HF_UPDATE_SLOTS) {
				if (!(header->feature_flags & FF_KEY_SLOTS)) {
					DbgMsg("slots area update atempt but slot not enabled\n");
					flags &= ~HF_UPDATE_SLOTS;
				}
				else if (header->head_len <= length) {
					DbgMsg("invalid keyslot area length\n");
					return ST_INV_VOLUME;
				}
			}

			if (flags & HF_UPDATE_BASE)
				offset = 0;
			else if (flags & HF_UPDATE_SLOTS)
				offset = DC_BASE_SIZE;
			else if (flags & HF_UPDATE_EXT)
				offset = header->ext_hdr_off;
			else
				return ST_OK; // nothing to do
			offset = (offset / (u64)hook->bps) * (u64)hook->bps; // align to sector, round down

			if (flags & HF_UPDATE_EXT)
				length = header->head_len;
			else if (flags & HF_UPDATE_SLOTS)
				length = DC_BASE_SIZE + header->slot_area_len + (header->key_slot_count * header->slot_info_size);
			else if (flags & HF_UPDATE_BASE)
				length = DC_BASE_SIZE;
			length = (u32)ROUND_TO_FULL_SECTORS((length - offset), hook->bps); // align to sector, round up

			if (offset + length > header->head_len) {
				DbgMsg("invalid header, update range %I64u, %d is invalid\n", offset, length);
				return ST_INV_VOLUME;
			}
		}
		else // full header write
		{
			length = hdr_len;
		}

		if ((flags & HF_CLEAR_SLOTS) && (header->feature_flags & FF_KEY_SLOTS)) {
			/* clear key slots and info - use random data for slots area, and zero info area */
			cp_rand_bytes(((u8*)header) + DC_BASE_SIZE, header->slot_area_len);
			memset(((u8*)header) + DC_BASE_SIZE + header->slot_area_len, 0, (header->key_slot_count * header->slot_info_size));
		}
	}

	//DbgMsg("io_write_header: offset %I64u, length %u, flags 0x%X\n", offset, length, flags);

	do
	{
		if ( (hcopy = mm_secure_alloc(max(hdr_len, PAGE_SIZE))) == NULL ) { resl = ST_NOMEM; break; }
		memcpy(hcopy, header, mem_len);
		
		if (is_volume_header_correct(hcopy) == FALSE) {
			resl = ST_INV_VOLUME;
			break;
		}
		
		if (h_key == NULL) {
		
			if ( (h_key = mm_secure_alloc(sizeof(xts_key))) == NULL ) { resl = ST_NOMEM; break; }

			/* add volume header to random pool because RNG not 
			   have sufficient entropy at boot time 
			*/
			cp_rand_add_seed(header, DC_AREA_SIZE);
			/* generate new salt */
			cp_rand_bytes(salt, HEADER_SALT_SIZE);
			/* copy salt to header */
			memcpy(hcopy->salt, salt, HEADER_SALT_SIZE);
			/* init new header key */
			if ( !cp_set_header_key(h_key, salt, header->alg_1, password, interrupt_cmd) )		{
				resl = ST_INVALID_PARAM; break;
			}
		} else {
			/* save original salt */
			memcpy(salt, header->salt, HEADER_SALT_SIZE);
		}
		/* encrypt header with new key */
		xts_encrypt(pv(hcopy), pv(hcopy), mem_len, 0, h_key);
		/* restore original salt */
		memcpy(hcopy->salt, salt, HEADER_SALT_SIZE);

		if (header->version >= DC_HDR_VERSION_2 && !(flags & HF_CLEAR_SLOTS))
		{
			/* store keyslots - if we are going to write that range */
			if ((header->feature_flags & FF_KEY_SLOTS) && offset + length > DC_BASE_SIZE && offset < DC_BASE_SIZE + header->slot_area_len) {
				cp_copy_keylots(header, (u8*)header, (u8*)hcopy);
			}
		}

		/* fill the gap with random numbers */
		if ((offset + length) > mem_len) {
			cp_rand_bytes(((u8*)hcopy) + mem_len, (int)(offset + length) - mem_len);
		}
		/* write new header */
		resl = io_hook_rw(hook, ((u8*)hcopy) + offset, length, offset + pos, 0);
	} while (0);

	//DumpHex("header_io: plain", pv(header), (int)hdr_len);
	//DumpHex("header_io: crypt", pv(hcopy), (int)hdr_len);

	/* prevent leaks */
	burn(salt, sizeof(salt));
	/* free resources */
	if (h_key != NULL && h_key != hdr_key) mm_secure_free(h_key);
	if (hcopy != NULL) mm_secure_free(hcopy);
	if (buff != NULL) mm_secure_free(buff);
	return resl;
}

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

int get_ext_header(dc_header *header, dc_ext_header **out_ext_hdr)
{
	dc_ext_header* ext_hdr;

	*out_ext_hdr = NULL;

	if (header->version < DC_HDR_VERSION_2) 
		return ST_INCOMPATIBLE;

	if (header->ext_hdr_off == 0) 
		return ST_INCOMPATIBLE;

	if (header->ext_hdr_off < DC_BASE_SIZE + ((header->feature_flags & FF_KEY_SLOTS) ? (header->slot_area_len + (header->key_slot_count * header->slot_info_size)) : 0)) {
		DbgMsg("invalid extended header offset, overlaps with key slots area\n");
		return ST_INV_VOLUME;
	}

	if ((u32)header->ext_hdr_off + MIN_EXT_HDR_SIZE > header->head_len) {
		DbgMsg("invalid extended header offset %d\n", header->ext_hdr_off);
		return ST_INV_VOLUME;
	}
	
	ext_hdr = (dc_ext_header*)(((u8*)header) + header->ext_hdr_off);
	if (header->ext_hdr_off + ext_hdr->size > header->head_len || ext_hdr->size < MIN_EXT_HDR_SIZE) {
		DbgMsg("invalid extended header size %d\n", ext_hdr->size);
		return ST_INV_VOLUME;
	}

	if (ext_hdr->crc != crc32((const unsigned char*)&ext_hdr->size, ext_hdr->size - 4)) {
		DbgMsg("invalid extended header CRC\n");
		return ST_INV_VOLUME;
	}

	*out_ext_hdr = ext_hdr;
	return ST_OK;
}
