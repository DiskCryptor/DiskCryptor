#include <Library/BaseMemoryLib.h>

#include "include\defines.h"
#include "include\dc_header.h"
#ifdef SMALL
#include "crypto_small\sha512_pkcs5_2_small.h"
#else
#include "crypto_fast/sha512_pkcs5_2.h"
#endif
#include "Argon2\argon2.h"
#include "crypto_fast/crc32.h"


const int dc_default_kdfs[] = {0, KDF_ARGON_DEFAULT, -1};
const int dc_all_kdfs[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, -1 };


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
int dc_derive_key(dc_pass* password, int kdf, u8* salt, u8* dk)
{
	u8 ak[DISKKEY_SIZE];
	if (kdf == KDF_NONE) {
		/* raw key */
		if (password->size < DISKKEY_SIZE)
			return 0;
		memcpy(dk, password->pass, PKCS_DERIVE_MAX);
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
		int ret = argon2id_hash_raw(time_cost, memory_cost, parallelism, password->pass, password->size, salt, HEADER_SALT_SIZE, ak, DISKKEY_SIZE, NULL);
		if (ret == ARGON2_OK) { // if not ok ak remaind uninitialized
			memcpy(dk, ak, PKCS_DERIVE_MAX);
			MEM_BURN(ak, sizeof(ak));
			return 1;
		}
	}
	return 0;
}

int try_decrypt_header(u8* dk, int* alg, xts_key* hdr_key, dc_header* header, dc_header* hcopy)
{
	int i;

	for (i = 0; i < CF_CIPHERS_NUM; i++)
	{
		xts_set_key(dk, i, hdr_key);

		xts_decrypt(pv(header), pv(hcopy), DC_AREA_SIZE, 0, hdr_key);

		if (is_volume_header_correct(hcopy)) {
			if (alg) *alg = i;
			return 1;
		}
	}

	return 0;
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
 * try_decrypt_slot - Unwrap a header key from a key slot using XOR
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

int dc_get_min_header_len(dc_pass *password)
{
	int       slot_type = 0; // if we get other types it will be noted on the password
	int       slot_size;
	int       slot_count;

	if (password->slot != 0)
	{
		slot_count = min(ABS(password->slot), KEY_SLOT_MAX);
		slot_size = cp_get_key_slot_size(slot_type) + sizeof(dc_slot_info);
		return max(DC_BASE_SIZE + (slot_size * slot_count), DC_AREA_SIZE);
	}

	return DC_AREA_SIZE;
}

int dc_decrypt_header_with_kdf(dc_header *header, int hdr_len, dc_pass *password, int* out_alg, u8 *out_key, int kdf, int* out_slot)
{
	u8        dk[PKCS_DERIVE_MAX];
	u8        sk[PKCS_DERIVE_MAX];
	int       succs = 0;
	int       i = 0;
	int	      alg = 0;
	xts_key   hdr_key;
	dc_header *hcopy;
	int       slot_type = 0; // if we get other types it will be noted on the password
	int       slot_size;
	int       slot = password->slot;

	if ( (hcopy = (dc_header*)MEM_ALLOC(DC_AREA_SIZE)) == NULL ) {
		return 0;
	}

	if (!dc_derive_key(password, kdf, header->salt, dk))
		return 0;

	if (slot <= 0)
	{
		if ((succs = try_decrypt_header(dk, &alg, &hdr_key, header, hcopy)) != 0) {
			slot = 0;
			goto finish;
		}
	}

	if (slot > 0) {
		i = slot - 1;
	} else if (slot < 0) {
		slot = -slot;
	}

	slot_size = cp_get_key_slot_size(slot_type);

	for (; i < slot; i++)
	{
		if (hdr_len < DC_BASE_SIZE + (slot_size * (i + 1)))
			break; // we did not read enough of the header

		if (!try_decrypt_slot(dk, ((u8*)header) + DC_BASE_SIZE + (slot_size * i), sk, slot_type))
			continue;

		/* Use the recovered header key (sk) to decrypt, not the slot derived key (dk) */
		if ((succs = try_decrypt_header(sk, &alg, &hdr_key, header, hcopy)) != 0) {
			slot = i + 1;
			goto finish;
		}
	}

finish:
	if (succs) {
		if (out_slot) *out_slot = slot;
		if (out_alg) *out_alg = alg;
		if (out_key) memcpy(out_key, slot ? sk : dk, PKCS_DERIVE_MAX);
		memcpy(&header->sign, &hcopy->sign, (DC_AREA_SIZE - HEADER_SALT_SIZE));
	}

	/* prevent leaks */
	MEM_BURN(dk, sizeof(dk));
	MEM_BURN(sk, sizeof(sk));
	MEM_BURN(&hdr_key, sizeof(xts_key));
	MEM_BURN(hcopy, DC_AREA_SIZE);
	MEM_FREE(hcopy);

	return succs;
}

int dc_decrypt_header(dc_header *header, int hdr_len, dc_pass *password, int* out_alg, u8 *out_key, int* out_kdf, int* out_slot)
{
	int* kdfs;
	int  kdf = password->kdf;

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
			if (dc_decrypt_header_with_kdf(header, hdr_len, password, out_alg, out_key, kdf, out_slot)) {
				if (out_kdf) *out_kdf = kdf;
				return 1;
			}
		}
	}

	if (dc_decrypt_header_with_kdf(header, hdr_len, password, out_alg, out_key, kdf, out_slot)) {
		if (out_kdf) *out_kdf = kdf;
		return 1;
	}

	return 0;
}
