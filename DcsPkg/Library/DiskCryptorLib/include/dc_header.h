#ifndef _DC_HEADER_H_
#define _DC_HEADER_H_

#include "volume_header.h"

#if defined(_M_IX86) //|| defined(_M_ARM64)
#define SMALL
#endif

#ifdef SMALL
#include "..\crypto_small\xts_small.h"
#else
#include "..\crypto_fast\xts_fast.h"
#endif

int dc_get_min_header_len(dc_pass *password);
int dc_decrypt_header(dc_header *header, int hdr_len, dc_pass *password, int* out_alg, u8 *out_key, int* out_kdf, int* out_slot);

int dc_derive_key(dc_pass* password, int kdf, u8* salt, u8* dk);

#endif
