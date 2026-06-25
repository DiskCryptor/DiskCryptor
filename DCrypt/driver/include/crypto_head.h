#ifndef _CRYPTO_HEAD_H_
#define _CRYPTO_HEAD_H_

#include "volume_header.h"
#ifdef _M_ARM64
#include "xts_small.h"
#else
#include "xts_fast.h"
#endif

int argon2_mk_params(int kdf, u32* memory_cost, u32* time_cost, u32* parallelism);
int dc_derive_key(dc_pass* password, int kdf, u8* salt, u8* dk, ULONG *interrupt_cmd);
int cp_try_decrypt_header(u8* dk, int alg, xts_key* hdr_key, dc_header* header);
int cp_get_key_slot_size(int type);
int cp_swap_slot_key(u8* slot, u8* old_dk, u8* new_dk, int type);
int cp_wrap_header_key(u8* slot, u8* sk, u8* dk, int type);
int cp_get_min_header_len(dc_pass *password);
int cp_decrypt_header(xts_key *hdr_key, dc_header *header, int hdr_len, dc_pass *password, int* out_kdf, ULONG *interrupt_cmd);
int cp_set_header_key(xts_key *hdr_key, u8 salt[HEADER_SALT_SIZE], int cipher, dc_pass *password, ULONG *interrupt_cmd);
int cp_copy_keylots(dc_header *header, u8 *in_buff, u8 *out_buff);
//int cp_calculate_header_mac(dc_header* header);
//int cp_validate_header_mac(dc_header* header);

#endif