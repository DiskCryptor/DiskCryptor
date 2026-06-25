/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2026
    * DavidXanatos <info@diskcryptor.org>
    * Copyright (c) 2010
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
#include "debug.h"
#include "crypto_head.h"
#include "header_io.h"
#ifdef _M_ARM64
#include "sha512_pkcs5_2_small.h"
#else
#include "sha512_pkcs5_2.h"
#endif
#include "misc_mem.h"
#include "../Argon2/argon2.h"
#include "../Argon2/blake2/blake2b.h"

const int dc_default_kdfs[] = {0, KDF_ARGON_DEFAULT, -1};
const int dc_all_kdfs[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, -1 };

int argon2_mk_params(int kdf, u32* memory_cost, u32* time_cost, u32* parallelism)
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
int dc_derive_key(dc_pass* password, int kdf, u8* salt, u8* dk, ULONG *interrupt_cmd)
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
		if (!argon2_mk_params(kdf, &memory_cost, &time_cost, &parallelism))
			return 0;
		int ret = argon2id_hash_raw(time_cost, memory_cost, parallelism, password->pass, password->size, salt, HEADER_SALT_SIZE, ak, DISKKEY_SIZE, (volatile long*)interrupt_cmd);
		if (ret == ARGON2_OK) { // if not ok ak remaind uninitialized
			memcpy(dk, ak, PKCS_DERIVE_MAX);
			burn(ak, sizeof(ak));
			return 1;
		}
	}
	return 0;
}

int try_decrypt_header(u8* dk, xts_key* hdr_key, dc_header* header, dc_header* hcopy)
{
	int i;

	for (i = 0; i < CF_CIPHERS_NUM; i++)
	{
		if (!xts_set_key(dk, i, hdr_key)) continue;

		xts_decrypt(pv(header), pv(hcopy), DC_AREA_SIZE, 0, hdr_key);

		if(is_volume_header_correct(hcopy))
			return 1;
	}

	return 0;
}

int cp_try_decrypt_header(u8* dk, int alg, xts_key* hdr_key, dc_header* header)
{
	int succs = 0;
	dc_header *hcopy;

	if ( (hcopy = mm_secure_alloc(DC_AREA_SIZE)) == NULL ) {
		return 0;
	}

	if (xts_set_key(dk, alg, hdr_key))
	{
		xts_decrypt(pv(header), pv(hcopy), DC_AREA_SIZE, 0, hdr_key);

		if (is_volume_header_correct(hcopy)) {
			succs = 1;
			memcpy(&header->sign, &hcopy->sign, (DC_AREA_SIZE - HEADER_SALT_SIZE));
		}
	}

	/* prevent leaks */
	mm_secure_free(hcopy);

	return succs;
}

int cp_get_key_slot_size(int type)
{
	if (type == 0)
	{
		return PKCS_DERIVE_MAX;
	}

	return 0;
}

/**
 * try_decrypt_slot - Unwrap a header key from a keyslot using XOR
 * @dk:   Derived key from password (via PBKDF2/Argon2)
 * @key:  Slot ciphertext (stored in header)
 * @sk:   Output buffer for the unwrapped header key
 * @type: Slot type (currently only type 0 is implemented)
 *
 * Type 0 implementation:
 * 
 * XOR the derived key with the slot ciphertext to get the header key.
 * slot_ciphertext = header_key XOR derived_key  (at encryption time)
 * header_key = slot_ciphertext XOR derived_key  (at decryption time)
 * 
 * Security: XOR-based key wrapping is safe here because it is effectively a
 *   stream cipher where the derived key serves as the keystream:
 *   1. The derived key is the same length as the wrapped key (PKCS_DERIVE_MAX)
 *   2. The derived key is cryptographically random (output of strong KDF)
 *   3. Each slot uses its own unique derived key (the keystream is never reused)
 * 
 * Key Management Property:
 *   This approach allows re-encrypting the header with a new header key while
 *   keeping all password slots valid WITHOUT needing to know the original secrets
 *   used for key derivation. Given access to the current header key and slot data:
 *
 *     derived_key = slot_ciphertext XOR old_header_key   (recover derived key)
 *     new_slot    = new_header_key XOR derived_key       (wrap new header key)
 *
 *   This enables header key rotation (e.g., after password change or cipher
 *   upgrade) without requiring all users to re-authenticate their slots.
 */

int try_decrypt_slot(u8* dk, u8* slot, u8* sk, int type)
{
	int i;

	if (type == 0)
	{
		for (i = 0; i < PKCS_DERIVE_MAX; i += 8) {
			*(__int64*)(sk + i) = *(__int64*)(slot + i) ^ *(__int64*)(dk + i);
		}
		return 1;
	}
	// For future use if we want to support other slot types (e.g., with different wrapping)

	return 0;
}

int cp_wrap_header_key(u8* slot, u8* sk, u8* dk, int type)
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

int cp_swap_slot_key(u8* slot, u8* old_dk, u8* new_dk, int type)
{
	int i;
	__int64 temp;

	if (type == 0)
	{
		for (i = 0; i < PKCS_DERIVE_MAX; i += 8) {
			temp = *(__int64*)(slot + i) ^ *(__int64*)(old_dk + i); // recover header key chunk
			*(__int64*)(slot + i) = temp ^ *(__int64*)(new_dk + i); // wrap new derived key
		}
		return 1;
	}
	
	return 0;
}

int cp_get_min_header_len(dc_pass *password)
{
	int       slot_type = 0; // if we get other types it will be noted on the password
	int       slot_size;
	int       slot_count;

	if (password->slot != 0)
	{
		slot_count = min(abs(password->slot), KEY_SLOT_MAX);
		slot_size = cp_get_key_slot_size(slot_type) + sizeof(dc_slot_info);
		return max(DC_BASE_SIZE + (slot_size * slot_count), DC_AREA_SIZE);
	}

	return DC_AREA_SIZE;
}

int cp_decrypt_header_with_kdf(xts_key *hdr_key, dc_header *header, int hdr_len, dc_pass *password, int kdf, ULONG *interrupt_cmd)
{
	u8        dk[PKCS_DERIVE_MAX];
	u8        sk[PKCS_DERIVE_MAX];
	int       succs = 0;
	int       i = 0;
	dc_header *hcopy;
	int       slot_type = 0; // if we get other types it will be noted on the password
	int       slot_size;
	int       slot = password->slot;

	if ( (hcopy = mm_secure_alloc(DC_AREA_SIZE)) == NULL ) {
		return 0;
	}

	if ( !dc_derive_key(password, kdf, header->salt, dk, interrupt_cmd) )
		return 0;

	if (slot <= 0)
	{
		succs = try_decrypt_header(dk, hdr_key, header, hcopy);
	}

	if (slot > 0) {
		i = slot - 1;
	} else if (slot < 0) {
		slot = -slot;
	}

	slot_size = cp_get_key_slot_size(slot_type);

	for (; i < slot && !succs; i++)
	{
		if (hdr_len < DC_BASE_SIZE + (slot_size * (i + 1)))
			break; // we did not read enough of the header

		if (!try_decrypt_slot(dk, ((u8*)header) + DC_BASE_SIZE + (slot_size * i), sk, slot_type))
			continue;

		/* Use the recovered header key (sk) to decrypt, not the slot derived key (dk) */
		succs = try_decrypt_header(sk, hdr_key, header, hcopy);
	}

	/* Restore salt */
	if (succs) {
		memcpy(&header->sign, &hcopy->sign, (DC_AREA_SIZE - HEADER_SALT_SIZE));
	}

	/* prevent leaks */
	burn(dk, sizeof(dk));
	burn(sk, sizeof(sk));
	mm_secure_free(hcopy);

	return succs;
}

int cp_decrypt_header(xts_key* hdr_key, dc_header* header, int hdr_len, dc_pass* password, int* out_kdf, ULONG *interrupt_cmd)
{
	int* kdfs;
	int kdf = password->kdf;

	// If cost is negative, try multiple KDFs
	if (kdf < -1) {
		if (kdf == KDF_ALL) {
			kdfs = (int*)dc_all_kdfs;
		} else if (kdf == KDF_DEFAULT) {
			kdfs = (int*)dc_default_kdfs;
		} else {
			return 0; // invalid cost value
		}

		for (int i = 0; ; i++) {
			kdf = kdfs[i];
			if (kdf == -1) { // end of list
				return 0; // no valid KDF found
			}

			if (interrupt_cmd && *interrupt_cmd) {
				DbgMsg("key derivation interrupted\n");
				return 0;
			}
			if (cp_decrypt_header_with_kdf(hdr_key, header, hdr_len, password, kdf, interrupt_cmd)) {
				if (out_kdf) *out_kdf = kdf;
				return 1;
			}
		}
	}
	// else try only the sellected one
	else {

		if (interrupt_cmd && *interrupt_cmd) {
			DbgMsg("key derivation interrupted\n");
			return 0;
		}
		if (cp_decrypt_header_with_kdf(hdr_key, header, hdr_len, password, kdf, interrupt_cmd)) {
			if (out_kdf) *out_kdf = kdf;
			return 1;
		}
	}

	return 0;
}

int cp_set_header_key(xts_key *hdr_key, u8 salt[HEADER_SALT_SIZE], int cipher, dc_pass *password, ULONG *interrupt_cmd)
{
	u8 dk[PKCS_DERIVE_MAX];

	if ( !dc_derive_key(password, password->kdf, salt, dk, interrupt_cmd) ) {
		return 0;
	}

	if ( !xts_set_key(dk, cipher, hdr_key) ) {
		return 0;
	}

	/* prevent leaks */
	burn(dk, sizeof(dk));

	return 1;
}

int cp_copy_keylots(dc_header *header, u8 *in_buff, u8 *out_buff)
{
	int        slot_size;
	int        i;
	dc_slot_info* slot_info = NULL;

	DbgMsg("cp_copy_keylots, feature_flags = 0x%08X, key_slot_count = %u, slot_area_len = %u, slot_info_size = %u, head_len = %u\n", header->feature_flags, header->key_slot_count, header->slot_area_len, header->slot_info_size, header->head_len);

	if ( !(header->feature_flags & FF_KEY_SLOTS) || header->key_slot_count == 0) {
		DbgMsg("Header does not indicate presence of key slots, skipping key slot loading\n");
		return 0; // header does not indicate presence of key slots
	}

	if ( (u32)DC_BASE_SIZE + header->slot_area_len + header->key_slot_count * header->slot_info_size > header->head_len ) {
		DbgMsg("Invalid header size for key slots\n");
		return 0; // invalid header size
	}

	slot_size = header->slot_area_len / header->key_slot_count;
	//slot_size = cp_get_key_slot_size(slot_type);
	for (i = 0; i < header->key_slot_count; i++) {
		slot_info = (dc_slot_info*)(((u8*)header) + DC_BASE_SIZE + header->slot_area_len + (header->slot_info_size * i));
		if ( !(slot_info->flags & SF_DISABLED) ) {
			memcpy(out_buff + DC_BASE_SIZE + (slot_size * i), in_buff + DC_BASE_SIZE + (slot_size * i), slot_size);
			//DbgMsg("Copy key slot %d: type=%d, flags=0x%08X, name=\"%.*s\"\n", i + 1, slot_info->type, slot_info->flags, SLOT_LABEL_LEN, slot_info->slot_name);
		}
	}

	return 1;
}

/* Header MAC constants */

//static int cp_derive_header_mac(dc_header* header, u8* mac_out)
//{
//	u8 mac_key[HDR_MAC_LEN];
//	const int data_len = FIELD_OFFSET(dc_header, hdr_mac) - FIELD_OFFSET(dc_header, version);
//
//	/* Derive MAC key from disk_id using BLAKE2b */
//	if (blake2b(mac_key, sizeof(mac_key), pv(&header->disk_id), sizeof(header->disk_id), NULL, 0) != 0) {
//		return 0;
//	}
//
//	/* Compute BLAKE2b-128 MAC over header bytes [72..1007] */
//	if (blake2b(mac_out, HDR_MAC_LEN, pv(&header->version), data_len, mac_key, sizeof(mac_key)) != 0) {
//		return 0;
//	}
//
//	return 1;
//}
//
//int cp_calculate_header_mac(dc_header* header)
//{
//	return cp_derive_header_mac(header, header->hdr_mac);
//}
//
//int cp_validate_header_mac(dc_header* header)
//{
//	u8 computed_mac[HDR_MAC_LEN];
//	int i, result;
//
//	if (!cp_derive_header_mac(header, computed_mac)) {
//		return 0;
//	}
//
//	/* Constant-time comparison to prevent timing attacks */
//	result = 0;
//	for (i = 0; i < HDR_MAC_LEN; i++) {
//		result |= (computed_mac[i] ^ header->hdr_mac[i]);
//	}
//
//	return (result == 0) ? 1 : 0;
//}