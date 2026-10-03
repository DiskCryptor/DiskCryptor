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

/*
 * Step 6 of the volume_lib extraction: this file no longer implements anything
 * about the volume header. It is the translation layer between dcapi's exported
 * names and volume_lib.
 *
 * The names and signatures are unchanged, deliberately. gui/, dccon/ and
 * anything else linking dcapi.dll keeps building untouched, and the `_um`
 * suffix survives only as an export alias - the implementation it used to
 * distinguish itself from is now the same code.
 *
 * Two things genuinely stay here:
 *
 *   - read_ext_header / write_ext_header. They are a serialisation format, not
 *     a header format, and they are built on misc/SVariant.c, which pulls in
 *     <stdlib.h> and would follow volume_lib into kernel and EFI builds that
 *     cannot use it. cp_ext_header_crc and get_ext_header, the parts that are
 *     about the header, are in the library.
 *   - dc_init_crypto, which reads dcapi's configuration to decide hw_crypt.
 *
 * See volume_lib/DESIGN.md.
 */
/*
 * Lean windows.h: misc/SVariant.h defines its own VARIANT, and the full
 * windows.h pulls ole2.h -> oaidl.h, which defines another one. Nothing in
 * this file needs OLE.
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

/* volume_lib */
#include "dc_dev.h"
#include "crypto_head.h"
#include "header_io.h"
#include "head_util.h"
#include "crc32.h"

/* ---------------------------------------------------------------------------
 * Host
 * ------------------------------------------------------------------------ */

/*
 * Randomness comes from the driver, as it always has in dcapi: the library
 * asks its host, the host asks DC_CTL_GET_RAND.
 */
static void dcapi_rand_bytes(void *buff, size_t size)
{
    dc_device_control(DC_CTL_GET_RAND, NULL, 0, buff, (ULONG)size);
}

static void *dcapi_secure_alloc(size_t size)
{
    return secure_alloc((ULONG)size);
}

static void dcapi_secure_free(void *p)
{
    secure_free(p);
}

static const dc_host g_dcapi_host = {
    dcapi_secure_alloc,
    dcapi_secure_free,
    dcapi_rand_bytes,
    NULL,       /* no entropy contribution: the driver's pool is the source */
    NULL,       /* no diagnostic sink in user mode */
    NULL        /* no wipe: dcapi never calls dc_change_pass_bak */
};

int dc_init_crypto()
{
    static int initialized = 0;

    if (!initialized)
    {
        dc_conf_data conf;

        dc_lib_init(&g_dcapi_host);

        /* volume_lib deliberately does not do this: only the caller knows when
           the configuration that decides hw_crypt has been read. */
        if (dc_load_config(&conf) == NO_ERROR) {
            xts_init(conf.conf_flags & CONF_HW_CRYPTO);
        } else {
            xts_init(0);
        }

        initialized = 1;
    }
    return 1;
}

/* ---------------------------------------------------------------------------
 * Header format and keys - straight aliases
 * ------------------------------------------------------------------------ */

unsigned long calculate_header_crc_um(struct _dc_header *header)
{
    return calculate_header_crc(header);
}

BOOLEAN is_volume_header_correct_um(dc_header *header)
{
    return is_volume_header_correct(header);
}

int argon2_mk_params_um(int kdf, u32 *memory_cost, u32 *time_cost, u32 *parallelism)
{
    return argon2_mk_params(kdf, memory_cost, time_cost, parallelism);
}

int dc_derive_key_um(dc_pass *password, int kdf, u8 *salt, u8 *dk, volatile LONG *abort)
{
    /* dcapi says volatile LONG*, the driver says ULONG*; they have always been
       the same thing passed through a cast, and the library kept the driver's
       spelling. */
    return dc_derive_key(password, kdf, salt, dk, (ULONG*)abort);
}

int dc_try_decrypt_header_um(u8 *dk, xts_key *hdr_key, u8 *enc_header, dc_header *hcopy, int header_len)
{
    int i;

    /* Not cp_try_decrypt_header: that one works in place on the ciphertext and
       preserves the salt, this one decrypts into a separate buffer. Only the
       cipher loop is shared, and that is xts_*, not header logic. */
    for (i = 0; i < CF_CIPHERS_NUM; i++)
    {
        if (!xts_set_key(dk, i, hdr_key)) continue;

        xts_decrypt(enc_header, (u8*)hcopy, header_len, 0, hdr_key);

        if (is_volume_header_correct(hcopy)) return 1;
    }
    return 0;
}

void dc_copy_keylots(dc_header *header, u8 *in_buff, u8 *out_buff)
{
    cp_copy_keylots(header, in_buff, out_buff);
}

int dc_get_key_slot_size(int type)
{
    return cp_get_key_slot_size(type);
}

int dc_wrap_header_key(u8 *slot, u8 *sk, u8 *dk, int type)
{
    return cp_wrap_header_key(slot, sk, dk, type);
}

/* ---------------------------------------------------------------------------
 * Key slots
 * ------------------------------------------------------------------------ */

BOOL dc_has_key_slots(dc_header *header)
{
    return cp_has_key_slots(header) ? TRUE : FALSE;
}

int dc_get_slot_info(dc_header *header, int slot_idx, dc_slot_info *info)
{
    return cp_get_slot_info(header, slot_idx, info);
}

int dc_get_slot_payload(dc_header *header, int slot_idx, u8 *payload, int len)
{
    return cp_get_slot_payload(header, slot_idx, payload, len);
}

int dc_set_slot(dc_header *header, int slot_idx, dc_slot_info *info, u8 *payload, int len)
{
    /* the (dc_slot_info*)-1 and (u8*)-1 sentinels are CP_SLOT_CLEAR and
       CP_SLOT_RANDOM; same values, so callers need no change */
    return cp_set_slot(header, slot_idx, info, payload, len);
}

/* ---------------------------------------------------------------------------
 * Whole-header operations
 * ------------------------------------------------------------------------ */

int dc_decrypt_header(u8 *enc_header, int enc_len, dc_pass *password,
    dc_header **out_header, xts_key **out_key, int *out_len, int *out_kdf,
    u8 *out_dk, volatile LONG *abort)
{
    dc_header *header  = NULL;
    xts_key   *hdr_key = NULL;
    int        head_len = DC_AREA_SIZE;
    int        resl = ST_ERROR;

    dc_init_crypto();

    if (enc_header == NULL || out_header == NULL) return ST_INVALID_PARAM;
    if (enc_len < DC_AREA_SIZE) return ST_INV_VOLUME;

    do
    {
        if ((header = (dc_header*)secure_alloc(enc_len)) == NULL) { resl = ST_NOMEM; break; }
        if ((hdr_key = (xts_key*)secure_alloc(sizeof(xts_key))) == NULL) { resl = ST_NOMEM; break; }

        memcpy(header, enc_header, enc_len);

        /* the whole search - every KDF, every slot, every cipher - is one call */
        if (cp_decrypt_header(hdr_key, header, enc_len, password, out_kdf, out_dk, NULL, (ULONG*)abort) == 0) {
            resl = ST_PASS_ERR; break;
        }

        if (header->version >= DC_HDR_VERSION_2)
        {
            head_len = header->head_len;

            /*
             * Strict here, deliberately, and unlike ImBox's version of this
             * function. Every caller on this side already holds the whole
             * header - the GUI reads DC_AREA_MAX_SIZE from the driver,
             * dc_load_header_file reads the file - so a buffer shorter than
             * head_len means a truncated backup, which is exactly what should
             * be refused.
             *
             * ImBox reads cp_get_min_header_len() bytes first and cannot know
             * head_len until the base is open, so its copy decrypts what it has
             * and reports the length instead of failing.
             */
            if (enc_len < head_len) { resl = ST_INV_VOLUME; break; }

            /* cp_decrypt_header only covers DC_AREA_SIZE; the tail continues at
               that XTS offset. io_read_header_full does the same for a device. */
            if (head_len > DC_AREA_SIZE) {
                xts_decrypt(enc_header + DC_AREA_SIZE, ((u8*)header) + DC_AREA_SIZE,
                            head_len - DC_AREA_SIZE, DC_AREA_SIZE, hdr_key);
            }

            /* slots are wrapped under their own keys, so carry them over raw */
            if (header->feature_flags & FF_KEY_SLOTS) {
                cp_copy_keylots(header, enc_header, (u8*)header);
            }
        }

        *out_header = header;
        header = NULL;
        if (out_key != NULL) { *out_key = hdr_key; hdr_key = NULL; }
        if (out_len != NULL) *out_len = head_len;
        resl = ST_OK;
    } while (0);

    if (header  != NULL) secure_free(header);
    if (hdr_key != NULL) secure_free(hdr_key);
    return resl;
}

int dc_encrypt_header(dc_header *header, int header_len, xts_key *hdr_key, u8 **out_enc)
{
    dc_header *scratch = NULL;
    u8        *enc = NULL;
    int        resl;

    dc_init_crypto();

    if (header == NULL || hdr_key == NULL || out_enc == NULL) return ST_ERROR;

    /*
     * dcapi refreshes the CRC before sealing, which the driver's write path
     * does not - it expects a header that is already correct. cp_encrypt_header
     * seals what it is given, so the CRC is fixed on a copy first.
     */
    if ((scratch = (dc_header*)secure_alloc(header_len)) == NULL) return ST_NOMEM;
    if ((enc = (u8*)secure_alloc(header_len)) == NULL) {
        secure_free(scratch);
        return ST_NOMEM;
    }

    memcpy(scratch, header, header_len);
    scratch->hdr_crc = calculate_header_crc(scratch);

    resl = cp_encrypt_header(scratch, header_len, hdr_key, enc);

    secure_free(scratch);

    if (resl != ST_OK) {
        secure_free(enc);
        return resl;
    }
    *out_enc = enc;
    return ST_OK;
}

int dc_load_header_file(wchar_t *file_path, dc_pass *password,
    dc_header **out_header, xts_key **out_key, int *out_len,
    u8 *out_dk, volatile LONG *abort)
{
    u8  *file_data = NULL;
    int  file_size = 0;
    int  resl;

    resl = load_file(file_path, (void**)&file_data, &file_size);
    if (resl != ST_OK) {
        return resl;
    }

    /* write the KDF that actually worked back to the password */
    resl = dc_decrypt_header(file_data, file_size, password,
                             out_header, out_key, out_len, &password->kdf, out_dk, abort);

    secure_free(file_data);
    return resl;
}

int dc_save_header_file(wchar_t *file_path, dc_header *header, int header_len, xts_key *hdr_key)
{
    u8  *enc_header = NULL;
    int  resl;

    resl = dc_encrypt_header(header, header_len, hdr_key, &enc_header);
    if (resl != ST_OK) {
        return resl;
    }

    resl = save_file(file_path, enc_header, header_len);

    secure_free(enc_header);
    return resl;
}

/* ---------------------------------------------------------------------------
 * Extended header
 *
 * The CRC is the library's; the serialisation is not. See the note at the top.
 * ------------------------------------------------------------------------ */

unsigned long calculate_ext_header_crc_um(struct _dc_ext_header *ext_hdr)
{
    return cp_ext_header_crc(ext_hdr);
}

int read_ext_header(u8 *data, int size, dc_ext_data *ext_data)
{
    /* struct tag, not the bare typedef: <windows.h> also defines a VARIANT */
    struct _VARIANT vData;
    struct _VARIANT vComment;

    if (!Variant_FromBuffer(data, size, &vData))
        return ST_ERROR;

    if (Variant_Get(&vData, EXT_HDR_COMMENT, &vComment) && vComment.uSize < sizeof(ext_data->volume_comment)) {
        memcpy(ext_data->volume_comment, vComment.pData, min(vComment.uSize, sizeof(ext_data->volume_comment) - 1));
        ext_data->volume_comment[min(vComment.uSize, sizeof(ext_data->volume_comment) - 1)] = 0;
    }

    return ST_OK;
}

int write_ext_header(dc_ext_data *ext_data, u8 *data, int size)
{
    /* struct tag, not the bare typedef: <windows.h> also defines a VARIANT */
    struct _VARIANT vData;

    Variant_Prepare(VAR_TYPE_INDEX, data, size, &vData);

    if (!Variant_AddAStr(&vData, EXT_HDR_COMMENT, ext_data->volume_comment, strlen(ext_data->volume_comment))) return 0;

    return (int)Variant_Finish(data, &vData);
}
