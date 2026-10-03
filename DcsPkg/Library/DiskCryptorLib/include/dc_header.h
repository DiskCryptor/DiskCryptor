#ifndef _DC_HEADER_H_
#define _DC_HEADER_H_

/*
 * Step 7 of the volume_lib extraction.
 *
 * DiskCryptorLib's own dc_header.c is gone. crypto_head.c and header_io.c from
 * volume_lib are compiled in its place, so cp_get_min_header_len,
 * dc_derive_key, cp_decrypt_header, cp_get_key_slot_size, try_decrypt_slot,
 * cp_swap_slot_key and the rest are declared by volume_lib/crypto_head.h -
 * include that, not this.
 *
 * What is left here is the one function whose signature DCS keeps, because it
 * also wants the cipher back: dc_decrypt_header, adapted in dc_host_efi.c.
 *
 * Note that dc_derive_key is deliberately NOT declared here any more. The
 * library's has the same name and one extra trailing argument - an abort
 * pointer the driver uses - so declaring the old four-argument form alongside
 * it would be a conflicting redeclaration rather than a silent mismatch. The
 * two call sites in DcsTpmSupport.c pass NULL.
 */

#include "volume_header.h"


#include "../crypto_lib/xts_fast.h"

/* the library declares cp_get_min_header_len, dc_derive_key and the rest */
#include "../volume_lib/crypto_head.h"

/*
 * Decrypt a header in place and report what opened it.
 *
 * out_alg   cipher the header was sealed with (its own alg_1)
 * out_key   PKCS_DERIVE_MAX bytes: the key that worked - password-derived for a
 *           header-key unlock, unwrapped from the slot otherwise
 * out_kdf   KDF that worked
 * out_slot  0 for the header key, otherwise the 1-based slot index
 *
 * Any of the four may be NULL. Returns 1 on success, 0 if nothing matched.
 */
int dc_decrypt_header(dc_header *header, int hdr_len, dc_pass *password,
                      int *out_alg, u8 *out_key, int *out_kdf, int *out_slot);

/* Installs the volume_lib host. Call once before anything above. */
int dcs_volume_lib_init(void);

#endif
