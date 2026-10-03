/*
##  @file
#   volume_lib host for the EFI build, plus the one signature adapter DCS needs.
#
# Copyright (c) 2026. DiskCryptor, David Xanatos
#
# This program and the accompanying materials
# are licensed and made available under the terms and conditions
# of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).
##
*/

/*
 * Step 7 of the volume_lib extraction. DiskCryptorLib used to carry its own
 * dc_header.c - a fourth copy of the header logic. It is gone; volume_lib's
 * crypto_head.c and header_io.c are compiled in its place, through the
 * volume_lib junction that ci_build_dcs.cmd creates.
 *
 * Only three of that file's functions were used anywhere else, and two of them
 * line up with the library directly:
 *
 *   dc_get_min_header_len  ->  cp_get_min_header_len   (renamed at the call site)
 *   dc_derive_key          ->  dc_derive_key           (same name, gained a
 *                                                       trailing abort pointer)
 *   dc_decrypt_header      ->  needs the adapter below
 *
 * The third differs because DCS also wants the cipher and the key slot back,
 * which cp_decrypt_header reports differently.
 */

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/RngLib.h>

#include "include/defines.h"
#include "include/volume_header.h"
#include "volume_lib/dc_dev.h"
#include "volume_lib/crypto_head.h"
#include "include/dc_header.h"

/* ---------------------------------------------------------------------------
 * Host
 * ------------------------------------------------------------------------ */

/*
 * EFI has no paging, so "secure" here is only about not leaving key material
 * behind: the size is stored in front of the block so that the free path can
 * wipe it.
 */
static void *dcs_secure_alloc(size_t size)
{
    UINTN *p = (UINTN*)AllocatePool(size + sizeof(UINTN));

    if (p == NULL) return NULL;
    *p = size;
    ZeroMem(p + 1, size);
    return (void*)(p + 1);
}

static void dcs_secure_free(void *ptr)
{
    UINTN *p;

    if (ptr == NULL) return;
    p = ((UINTN*)ptr) - 1;
    ZeroMem(ptr, *p);
    FreePool(p);
}

/*
 * Only reached if something writes a header. DCS does not - it opens volumes
 * and reads them - but dc_lib_init insists on an RNG rather than letting a
 * caller discover the gap the hard way, so wire up the one EFI provides.
 */
static void dcs_rand_bytes(void *buff, size_t size)
{
    UINT8  *out = (UINT8*)buff;
    UINT64  v;

    while (size >= sizeof(UINT64)) {
        if (!GetRandomNumber64(&v)) { ZeroMem(out, size); return; }
        CopyMem(out, &v, sizeof(UINT64));
        out  += sizeof(UINT64);
        size -= sizeof(UINT64);
    }
    if (size != 0) {
        if (!GetRandomNumber64(&v)) { ZeroMem(out, size); return; }
        CopyMem(out, &v, size);
    }
}

/*
 * crypto_lib's Argon2 allocates through these two names
 * (crypto_lib/cl_alloc.h). Same allocator as above, at the signature
 * that header declares - which is also dcapi/misc.c's.
 */
void *secure_alloc(unsigned long length)
{
    return dcs_secure_alloc((size_t)length);
}

void secure_free(void *ptr)
{
    dcs_secure_free(ptr);
}

static const dc_host gDcsHost = {
    dcs_secure_alloc,
    dcs_secure_free,
    dcs_rand_bytes,
    NULL,   /* no entropy contribution */
    NULL,   /* no diagnostic sink: DCS prints through g_Con, not printf */
    NULL    /* no wipe: DCS never changes a backup header */
};

int dcs_volume_lib_init(void)
{
    return dc_lib_init(&gDcsHost);
}

/* ---------------------------------------------------------------------------
 * dc_decrypt_header
 * ------------------------------------------------------------------------ */

/*
 * cp_decrypt_header reports the KDF, the key material that worked and the slot
 * that worked; DCS additionally wants the cipher. That is not a separate
 * search result - a header is sealed with the cipher named in its own alg_1
 * field, which is exactly what cp_set_header_key uses when writing one - so it
 * can simply be read off the decrypted header.
 *
 * out_key receives PKCS_DERIVE_MAX bytes, as it did before: it is the key that
 * opened the header, which is the password-derived key for a header-key unlock
 * and the unwrapped key for a slot unlock.
 */
int dc_decrypt_header(dc_header *header, int hdr_len, dc_pass *password,
                      int *out_alg, u8 *out_key, int *out_kdf, int *out_slot)
{
    xts_key *hdr_key;
    int      succs;

    hdr_key = (xts_key*)dcs_secure_alloc(sizeof(xts_key));
    if (hdr_key == NULL) return 0;

    succs = cp_decrypt_header(hdr_key, header, hdr_len, password,
                              out_kdf, out_key, out_slot, NULL);

    if (succs && out_alg != NULL) {
        *out_alg = header->alg_1;
    }

    dcs_secure_free(hdr_key);
    return succs;
}
