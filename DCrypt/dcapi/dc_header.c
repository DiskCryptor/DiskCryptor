/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2026
    * DavidXanatos <info@diskcryptor.org>
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

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include "misc/SVariant.h"
#include "dc_header.h"
#include "misc.h"
#include "drvinst.h"
#include "dcconst.h"
#include "volume_header.h"
#include "..\crc32.h"
//#ifdef _M_ARM64
//#include "sha512_pkcs5_2_small.h"
//#else
#include "sha512_pkcs5_2.h"
//#endif
#include "../crypto/Argon2/argon2.h"

/*
* Initialize crypto subsystem
*/
int dc_init_crypto()
{
    static int initialized = 0;
    if (!initialized) {

        dc_conf_data  conf;
        if (dc_load_config(&conf) == NO_ERROR) {
            xts_init(conf.conf_flags & CONF_HW_CRYPTO);
        } else {
            xts_init(0);
        }

        initialized = 1;
    }
    return 1;
}

/*
 * Calculate CRC for a header structure
 */
unsigned long calculate_header_crc_um(struct _dc_header* header)
{
    if (header->version >= DC_HDR_VERSION_2) {
        // version 2 and later have the CRC calculated only over the header base
        return crc32((const unsigned char*)&header->version, DC_CRC_AREA_SIZE_2 - ((int)header->footer_cnt << 4));
    }
    return crc32((const unsigned char*)&header->version, DC_CRC_AREA_SIZE_1);
}

const int dc_default_kdfs[] = {0, KDF_ARGON_DEFAULT, -1};
const int dc_all_kdfs[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, -1 };

/*
* Helper function to expand a single cost parameter into memory_cost, time_cost and parallelism.
*/
int argon2_mk_params_um(int kdf, u32* memory_cost, u32* time_cost, u32* parallelism)
{
    static const u32 memory_mib_table[] = {
        64, 128, 192, 256, // +64
		384, 512, // +128
		768, 1024, // +256
		1536, 2048 // +512
    };

    static const u32 time_cost_table[] = {
		3, // for 64 MiB
		3, // for 128 MiB
		4, // for 192 MiB
		4, // for 256 MiB
		5, // for 384 MiB
		5, // for 512 MiB
		5, // for 768 MiB
		6, // for 1024 MiB
		6, // for 1536 MiB
		6  // for 2048 MiB
    };

    const int min_cost = 1;
    const int max_cost = (int)(sizeof(memory_mib_table) / sizeof(memory_mib_table[0]));

    if (kdf < min_cost || kdf > max_cost)
        return 0;

    const int idx = kdf - 1;

    if (memory_cost) *memory_cost = memory_mib_table[idx] * 1024U; // Argon2 expects KiB
    if (time_cost) *time_cost = time_cost_table[idx];
    if (parallelism) *parallelism = 4;

    return 1;
}

/*
* Derive key material from the password using either legacy PBKDF2-SHA512
* or Argon2id. For Argon2id we always derive DISKKEY_SIZE (256 bytes) even
* though currently only PKCS_DERIVE_MAX (192 bytes) are used.
*
* Unlike PBKDF2, Argon2 output depends on the requested length, meaning
* Argon2(...,192) and Argon2(...,256) produce completely different results.
* By deriving the full 256 bytes now and truncating to 192, we reserve
* additional key material for possible future cipher cascades without
* requiring a KDF length change that would alter existing derived keys.
*/
int dc_derive_key_um(dc_pass *password, int kdf, u8 *salt, u8 *dk, volatile LONG *abort)
{
    u8 ak[DISKKEY_SIZE];
    if (kdf == KDF_NONE) {
        /* raw key */
        if (password->size == DISKKEY_SIZE) {
            memcpy(dk, password->pass, PKCS_DERIVE_MAX);
            return 1;
        }
    }
    else if (kdf == 0) {
        /* Existing SHA512-PBKDF2 */
        sha512_pkcs5_2(1000, password->pass, password->size, salt, HEADER_SALT_SIZE, dk, PKCS_DERIVE_MAX);
        return 1;
    }
    else {
        /* Argon2id key derivation */
        u32 memory_cost, time_cost, parallelism;
        if (!argon2_mk_params_um(kdf, &memory_cost, &time_cost, &parallelism))
            return 0;
        int ret = argon2id_hash_raw(time_cost, memory_cost, parallelism, password->pass, password->size, salt, HEADER_SALT_SIZE, ak, DISKKEY_SIZE, abort);
        if (ret == ARGON2_OPERATION_CANCELLED) {
            burn(ak, sizeof(ak));
            return -1; /* Cancelled */
        }
        if (ret == ARGON2_OK) { // if not ok ak remaind uninitialized
            memcpy(dk, ak, PKCS_DERIVE_MAX);
            burn(ak, sizeof(ak));
            return 1;
        }
    }
    return 0;
}

/*
 * Check if decrypted header has correct format and valid CRC
 */
BOOLEAN is_volume_header_correct_um(dc_header *header)
{
    unsigned char v = 0;
    size_t        i;

    // check salt bytes, correct headers must not have zero salt
    for (i = 0; i < sizeof(header->salt); i++) v |= header->salt[i];
    if (v == 0) return FALSE;

    // check header signature and checksum
    if (header->sign != DC_VOLUME_SIGN) return FALSE;
    if (header->hdr_crc != calculate_header_crc_um(header)) return FALSE;

    return TRUE;
}

/*
 * Try to decrypt header with derived key, testing all cipher types
 */
int dc_try_decrypt_header_um(u8 *dk, xts_key *hdr_key, u8 *enc_header, dc_header *hcopy, int header_len)
{
    int i;

    for (i = 0; i < CF_CIPHERS_NUM; i++)
    {
        if (!xts_set_key(dk, i, hdr_key)) continue;

        xts_decrypt(enc_header, (u8*)hcopy, header_len, 0, hdr_key);

        if(is_volume_header_correct_um(hcopy))
            return 1;
    }
    return 0;
}

/*
* Copy key slots from input buffer to header structure, decrypting if necessary
*/
void dc_copy_keylots(dc_header *header, u8 *in_buff, u8 *out_buff)
{
    int           slot_size;
    int           i;
    dc_slot_info *slot_info = NULL;

    slot_size = header->slot_area_len / header->key_slot_count;
    //slot_size = cp_get_key_slot_size(slot_type);
    for (i = 0; i < header->key_slot_count; i++) {
        slot_info = (dc_slot_info*)(((u8*)header) + DC_BASE_SIZE + header->slot_area_len + (header->slot_info_size * i));
        if ( !(slot_info->flags & SF_DISABLED) ) {
            memcpy(out_buff + DC_BASE_SIZE + (slot_size * i), in_buff + DC_BASE_SIZE + (slot_size * i), slot_size);
        }
    }
}

/*
 * Decrypt an encrypted header backup
 */
static int dc_decrypt_header_kdf(u8 *enc_header, int enc_len, dc_pass *password, int kdf,
    dc_header **out_header, xts_key **out_key, int *out_len, u8 *out_dk, volatile LONG *abort)
{
    int           head_len = DC_AREA_SIZE;
    dc_header    *header = NULL;
    xts_key      *hdr_key = NULL;
    u8            dk[PKCS_DERIVE_MAX];
    int           resl = ST_ERROR;
    int           derive_result;

    if (enc_len < DC_AREA_SIZE) {
        return ST_INV_VOLUME;
    }

    do {
        /* Allocate buffers */
        header = (dc_header*)secure_alloc(enc_len);
        if (!header) { resl = ST_NOMEM; break; }

        hdr_key = (xts_key*)secure_alloc(sizeof(xts_key));
        if (!hdr_key) { resl = ST_NOMEM; break; }

        /* Derive key from password */
        derive_result = dc_derive_key_um(password, kdf, enc_header, dk, abort);
        if (derive_result == -1) {
            resl = ST_CANCEL; break; /* Cancelled */
        }
        if (derive_result == 0) {
            resl = ST_ERROR; break;
        }

        /* Try to decrypt with each cipher */
        if (!dc_try_decrypt_header_um(dk, hdr_key, enc_header, header, DC_AREA_SIZE)) {
            resl = ST_PASS_ERR; break;
        }

        /* Restore salt */
        memcpy(header->salt, enc_header, HEADER_SALT_SIZE);

        /* For v2 headers, handle extended data */
        if (header->version >= DC_HDR_VERSION_2)
        {
            head_len = header->head_len;
            if (enc_len < head_len) {
                return ST_INV_VOLUME;
            }

            /* Decrypt rest of header */
            if (head_len > DC_AREA_SIZE) {
                xts_decrypt(enc_header + DC_AREA_SIZE, ((u8*)header) + DC_AREA_SIZE, head_len - DC_AREA_SIZE, DC_AREA_SIZE, hdr_key);
            }

            /* For v2 headers with slot area, restore raw slot data (it's not encrypted with header key) */
            if ((header->feature_flags & FF_KEY_SLOTS) && header->slot_area_len > 0 && header->key_slot_count >= 0) {
				dc_copy_keylots(header, enc_header, (u8*)header);
            }
        }

        /* Success - return decrypted header and key */
        *out_header = header;
        if (out_key) {
            *out_key = hdr_key;
            hdr_key = NULL;
        }
        if (out_len) *out_len = head_len;
        /* Return derived key for caching if requested */
        if (out_dk) {
            memcpy(out_dk, dk, PKCS_DERIVE_MAX);
        }
        header = NULL;
        resl = ST_OK;
    } while (0);

    /* Cleanup */
    burn(dk, sizeof(dk));
    if (header) secure_free(header);
    if (hdr_key) secure_free(hdr_key);

    return resl;
}

/*
* Decrypt an encrypted header backup
*/
int dc_decrypt_header(u8 *enc_header, int enc_len, dc_pass *password,
    dc_header **out_header, xts_key **out_key, int *out_len, int* out_kdf,
    u8 *out_dk, volatile LONG *abort)
{
    int resl;
    int* kdfs;
    int kdf = password->kdf;

    dc_init_crypto();

    // If cost is negative, try multiple KDFs
    if (kdf < -1) {
        if (kdf == KDF_ALL) {
            kdfs = (int*)dc_all_kdfs;
        } else if (kdf == KDF_DEFAULT) {
            kdfs = (int*)dc_default_kdfs;
        } else {
            return ST_INVALID_PARAM; // invalid cost value
        }

        for (int i = 0; ; i++) {
            kdf = kdfs[i];
            if (kdf == -1) { // end of list
                return ST_PASS_ERR; // no valid KDF found
            }
            resl = dc_decrypt_header_kdf(enc_header, enc_len, password, kdf, out_header, out_key, out_len, out_dk, abort);
            if (resl == ST_CANCEL) {
                return ST_CANCEL; /* Cancelled */
            }
            if (resl == ST_OK) {
				if (out_kdf) *out_kdf = kdf;
                return ST_OK;
            }
        }
    }

    resl = dc_decrypt_header_kdf(enc_header, enc_len, password, kdf, out_header, out_key, out_len, out_dk, abort);
    if (resl == ST_OK) {
        if (out_kdf) *out_kdf = kdf;
        return ST_OK;
    }
    return resl;
}

/*
 * Encrypt a header for storage
 *
 * The encryption layout matches what the driver expects:
 * - First DC_AREA_SIZE bytes: XTS encrypted with offset 0
 * - Bytes beyond DC_AREA_SIZE: XTS encrypted with offset DC_AREA_SIZE
 * - Salt (first HEADER_SALT_SIZE bytes): Restored raw (not encrypted)
 * - Slot ciphertexts (DC_BASE_SIZE to DC_BASE_SIZE+slot_area_len): Restored raw
 */
int dc_encrypt_header(dc_header *header, int header_len, xts_key *hdr_key, u8 **out_enc)
{
    u8           *enc_header = NULL;
    int           resl = ST_ERROR;

    dc_init_crypto();

    if (!header || !hdr_key || !out_enc) {
        return ST_ERROR;
    }

    /* Allocate buffer for encrypted header */
    enc_header = (u8*)secure_alloc(header_len);
    if (!enc_header) {
        return ST_NOMEM;
    }

    /* Copy header */
    memcpy(enc_header, header, header_len);

    /* Update CRC */
    ((dc_header*)enc_header)->hdr_crc = calculate_header_crc_um((dc_header*)enc_header);

    /* Encrypt first part (up to DC_AREA_SIZE) with XTS offset 0 */
    xts_encrypt(enc_header, enc_header, DC_AREA_SIZE, 0, hdr_key);

    /* Restore salt (not encrypted) */
    memcpy(enc_header, header->salt, HEADER_SALT_SIZE);

    if (header->version >= DC_HDR_VERSION_2)
    {
        /* Encrypt rest (if any) with XTS offset DC_AREA_SIZE */
        if (header_len > DC_AREA_SIZE) {
            xts_encrypt(enc_header + DC_AREA_SIZE, enc_header + DC_AREA_SIZE, header_len - DC_AREA_SIZE, DC_AREA_SIZE, hdr_key);
        }

        /* Restore raw slot data for v2 headers (not encrypted with header key) */
        if ((header->feature_flags & FF_KEY_SLOTS) && header->slot_area_len > 0 && header->key_slot_count >= 0) {
			dc_copy_keylots(header, (u8*)header, enc_header);
        }
    }

    *out_enc = enc_header;
    return ST_OK;
}

/*
 * Load and decrypt header from a backup file
 */
int dc_load_header_file(wchar_t *file_path, dc_pass *password,
    dc_header **out_header, xts_key **out_key, int *out_len,
    u8 *out_dk, volatile LONG *abort)
{
    u8  *file_data = NULL;
    int  file_size = 0;
    int  resl;

    /* Load file contents */
    resl = load_file(file_path, (void**)&file_data, &file_size);
    if (resl != ST_OK) {
        return resl;
    }

    /* Decrypt header - write actually found kdf back to password */
    resl = dc_decrypt_header(file_data, file_size, password, out_header, out_key, out_len, &password->kdf, out_dk, abort);

    secure_free(file_data);
    return resl;
}

/*
 * Save encrypted header to a file
 */
int dc_save_header_file(wchar_t *file_path, dc_header *header, int header_len, xts_key *hdr_key)
{
    u8  *enc_header = NULL;
    int  resl;

    /* Encrypt header */
    resl = dc_encrypt_header(header, header_len, hdr_key, &enc_header);
    if (resl != ST_OK) {
        return resl;
    }

    /* Save to file */
    resl = save_file(file_path, enc_header, header_len);

    secure_free(enc_header);
    return resl;
}

/*
 * Get the size of the keyslot payload for a given slot type
 */
int dc_get_key_slot_size(int type)
{
    if (type == 0)
    {
        return PKCS_DERIVE_MAX;
    }

    return 0;
}

/* 
 * Helper to check if key slots are available 
 */
BOOL dc_has_key_slots(dc_header* header)
{
    if (!header) return FALSE;
    if (header->version < DC_HDR_VERSION_2) return FALSE;
    if (!(header->feature_flags & FF_KEY_SLOTS)) return FALSE;
    if (header->slot_area_len == 0) return FALSE;
    if (header->key_slot_count == 0) return FALSE;
    if (header->slot_info_size == 0) return FALSE;
    return TRUE;
}

/* 
 * Helper to get slot info pointer 
 */
int dc_get_slot_info(dc_header* header, int slot_idx, dc_slot_info* info)
{
    if (!dc_has_key_slots(header)) return ST_INCOMPATIBLE;
    if (slot_idx < 0 || slot_idx >= header->key_slot_count) return ST_BAD_INDEX;

    int slot_size = header->slot_area_len / header->key_slot_count;

    u8 *slot_info_start = ((u8*)header) + DC_BASE_SIZE + header->slot_area_len;
    dc_slot_info* slot_info = (dc_slot_info*)(slot_info_start + slot_idx * header->slot_info_size);

	memcpy(info, slot_info, min(sizeof(dc_slot_info), header->slot_info_size));
    if(sizeof(dc_slot_info) > header->slot_info_size) {
        memset(((u8*)info) + header->slot_info_size, 0, sizeof(dc_slot_info) - header->slot_info_size);
	}

    if (!(info->flags & SF_ACTIVE)) {
        return ST_OK;
    }

    u8* key_slot = ((u8*)header) + DC_BASE_SIZE + slot_idx * slot_size;

    u32 info_crc = crc32((const unsigned char*)&slot_info->flags, header->slot_info_size - 4);
    u32 slot_crc = crc32((const unsigned char*)key_slot, slot_size);
    if (slot_info->crc != crc32_combine(info_crc, slot_crc, slot_size)) {
        info->flags |= SF_CORRUPT;
    }

    return ST_OK;
}

/* 
 * Helper to get slot ciphertext pointer 
 */
int dc_get_slot_payload(dc_header* header, int slot_idx, u8* payload, int len)
{
    if (!dc_has_key_slots(header)) return ST_INCOMPATIBLE;
    if (slot_idx < 0 || slot_idx >= header->key_slot_count) return ST_BAD_INDEX;
    
    int slot_size = header->slot_area_len / header->key_slot_count;
    if (payload && len > slot_size) return ST_SMALL_BUFF;

    u8* key_slot = ((u8*)header) + DC_BASE_SIZE + slot_idx * slot_size;

	memcpy(payload, key_slot, min(len, slot_size));

    return ST_OK;
}

/* 
 * Helper to set slot data 
 */
int dc_set_slot(dc_header* header, int slot_idx, dc_slot_info* info, u8* payload, int len)
{
    if (!dc_has_key_slots(header)) return ST_INCOMPATIBLE;
    if (slot_idx < 0 || slot_idx >= header->key_slot_count) return ST_BAD_INDEX;

    int slot_size = header->slot_area_len / header->key_slot_count;
	if (payload && len > slot_size) return ST_INVALID_PARAM;

    u8 *slot_info_start = ((u8*)header) + DC_BASE_SIZE + header->slot_area_len;
    dc_slot_info* slot_info = (dc_slot_info*)(slot_info_start + slot_idx * header->slot_info_size);
    if (info == ((dc_slot_info*)-1)) {
		memset(slot_info, 0, header->slot_info_size);
    } else if (info != NULL) {
        memcpy(slot_info, info, min(sizeof(dc_slot_info), header->slot_info_size));
    }

    u8* key_slot = ((u8*)header) + DC_BASE_SIZE + slot_idx * slot_size;
    if (payload != NULL) {
        if (payload != ((u8*)-1)) {
            memcpy(key_slot, payload, len);
        }
        if(len < slot_size) {
            dc_device_control(DC_CTL_GET_RAND, NULL, 0, key_slot, slot_size - len);
		}
    }

    u32 info_crc = crc32((const unsigned char*)&slot_info->flags, header->slot_info_size - 4);
    u32 slot_crc = crc32((const unsigned char*)key_slot, slot_size);
    slot_info->crc = crc32_combine(info_crc, slot_crc, slot_size);

    return ST_OK;
}

/* 
 * Helper to wrap the header key with slot key
 */
int dc_wrap_header_key(u8* slot, u8* sk, u8* dk, int type)
{
    int i;

    if (type == 0)
    {
        for (i = 0; i < PKCS_DERIVE_MAX; i += 8) {
            *(__int64*)(slot + i) = *(__int64*)(sk + i) ^ *(__int64*)(dk + i);
        }
        return 1;
    }

    return 0;
}

/* 
* Calculate CRC for the extended header
*/
unsigned long calculate_ext_header_crc_um(struct _dc_ext_header* ext_hdr)
{
    return crc32((const unsigned char*)&ext_hdr->size, ext_hdr->size - 4);
}

/*
* Reads extended data from the extended header.
*/
int read_ext_header(u8* data, int size, dc_ext_data* ext_data)
{
    VARIANT vData;
    if (!Variant_FromBuffer(data, size, &vData))
		return ST_ERROR;

  //  VARIANT vGuid;
  //  if (Variant_Get(&vData, EXT_HDR_GUID, &vGuid) && vGuid.uSize == sizeof(ext_data->volume_guid)) {
		//memcpy(ext_data->volume_guid, vGuid.pData, sizeof(ext_data->volume_guid));
  //  }

    VARIANT vComment;
	if (Variant_Get(&vData, EXT_HDR_COMMENT, &vComment) && vComment.uSize < sizeof(ext_data->volume_comment)) {
		memcpy(ext_data->volume_comment, vComment.pData, min(vComment.uSize, sizeof(ext_data->volume_comment) -1));
        ext_data->volume_comment[min(vComment.uSize, sizeof(ext_data->volume_comment) -1)] = 0;
	}

    return ST_OK;
}

/*
* Writes extended data to the extended header and updates the CRC.
*/
int write_ext_header(dc_ext_data* ext_data, u8* data, int size)
{
    VARIANT vData;
    Variant_Prepare(VAR_TYPE_INDEX, data, size, &vData);                                                            // + 1 (type) + 2 (length, for size <= 0xFFFF, 4 when larger)

	//if (!Variant_AddBytes(&vData, EXT_HDR_GUID, ext_data->volume_guid, sizeof(ext_data->volume_guid))) return 0;    // + 4 (id) + 1 (type) + 1 (len) + 16 (data)

	if (!Variant_AddAStr(&vData, EXT_HDR_COMMENT, ext_data->volume_comment, strlen(ext_data->volume_comment))) return 0;  // + 4 (id) + 1 (type) + 1 (len) + 40

    return (int)Variant_Finish(data, &vData);                                                                       // = MIN_EXT_HDR_SIZE + 71 (hdr_data) = 81 byte
}