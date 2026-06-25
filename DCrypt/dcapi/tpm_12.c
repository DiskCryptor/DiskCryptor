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
 * TPM 1.2 Support for Windows
 *
 * This module implements TPM 1.2 SRK-based sealing/unsealing.
 * It uses the Windows TPM Base Services (TBS) API for TPM communication.
 *
 * Compatibility: Matches bootloader implementation at DcsPkg/Library/DcsTpmLib/Tpm12.c
 */

#include <windows.h>
#include <bcrypt.h>
#include <stdlib.h>
#include "dcconst.h"
#include "misc.h"
#include "drv_ioctl.h"
#include "tpm_sup.h"
#include "tpm_12.h"
#include "..\crc32.h"

#pragma comment(lib, "bcrypt.lib")

#ifndef BCRYPT_SUCCESS
#define BCRYPT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif


/*
 * TPM 1.2 Command/Response Tags
 */
#define TPM12_TAG_RQU_COMMAND           0x00C1  /* Request without auth */
#define TPM12_TAG_RQU_AUTH1_COMMAND     0x00C2  /* Request with 1 auth session */
#define TPM12_TAG_RQU_AUTH2_COMMAND     0x00C3  /* Request with 2 auth sessions */
#define TPM12_TAG_RSP_COMMAND           0x00C4  /* Response without auth */
#define TPM12_TAG_RSP_AUTH1_COMMAND     0x00C5  /* Response with 1 auth session */
#define TPM12_TAG_RSP_AUTH2_COMMAND     0x00C6  /* Response with 2 auth sessions */

/*
 * TPM 1.2 Ordinals (Commands)
 */
#define TPM12_ORD_OIAP                  0x0000000A  /* Open Independent Auth Protocol */
#define TPM12_ORD_OSAP                  0x0000000B  /* Open Shared Auth Protocol */
#define TPM12_ORD_Seal                  0x00000017  /* Seal data under key */
#define TPM12_ORD_Unseal                0x00000018  /* Unseal data */
#define TPM12_ORD_GetRandom             0x00000046  /* Get random bytes */
#define TPM12_ORD_GetCapability         0x00000065  /* Get TPM capabilities */
#define TPM12_ORD_PcrRead               0x00000015
#define TPM12_ORD_Extend                0x00000014
#define TPM12_ORD_NV_DefineSpace        0x000000CC
#define TPM12_ORD_NV_WriteValue         0x000000CD
#define TPM12_ORD_NV_ReadValue          0x000000CF
#define TPM12_ORD_NV_ReadValueAuth      0x000000D0

/*
 * TPM 1.2 NV attributes
 */
#define TPM12_NV_PER_OWNERWRITE         0x00000002  /* Owner can write */
#define TPM12_NV_PER_AUTHREAD           0x00040000  /* Auth required to read */

/*
 * TPM 1.2 NV data types
 */
#define TPM12_TAG_NV_DATA_PUBLIC        0x0018
#define TPM12_TAG_NV_ATTRIBUTES         0x0017

/*
 * TPM 1.2 TPM_ENTITY_TYPE
 */
#define TPM12_ET_OWNER                  0x0002

/*
 * TPM 1.2 Reserved Key Handles
 */
#define TPM12_KH_OWNER                  0x40000001

/*
 * TPM 1.2 Well-Known Handles
 */
#define TPM12_KH_SRK                    0x40000000  /* Storage Root Key handle */

/*
 * TPM 1.2 Entity Types (for OSAP)
 */
#define TPM12_ET_KEYHANDLE              0x0001      /* Key handle entity - used for SRK */

/*
 * TPM 1.2 Capability Areas
 */
#define TPM12_CAP_VERSION_VAL           0x0000001A  /* Get TPM_CAP_VERSION_INFO */
#define TPM12_CAP_NV_INDEX              0x00000011

/*
 * TPM 1.2 Constants
 */
#define TPM12_SHA1_HASH_SIZE            20
#define TPM12_NONCE_SIZE                20
#define TPM12_DIGEST_SIZE               20
#define TPM12_AUTH_BLOCK_SIZE           45  /* authHandle(4) + nonce(20) + continue(1) + hmac(20) */

/*
 * TPM 1.2 Return Codes
 */
#define TPM12_SUCCESS                   0x00000000
#define TPM12_AUTHFAIL                  0x00000001
#define TPM12_BADINDEX                  0x00000002

/*
 * TPM 1.2 OIAP Session Structure
 */
typedef struct _TPM12_OIAP_SESSION {
    u32  authHandle;                        /* Session handle from TPM */
    u8   nonceEven[TPM12_NONCE_SIZE];       /* TPM-generated nonce */
    u8   nonceOdd[TPM12_NONCE_SIZE];        /* Our nonce */
} TPM12_OIAP_SESSION;

/*
 * TPM 1.2 OSAP Session Structure
 */
typedef struct _TPM12_OSAP_SESSION {
    u32  authHandle;                        /* Session handle from TPM */
    u8   nonceEven[TPM12_NONCE_SIZE];       /* TPM session nonce */
    u8   nonceEvenOSAP[TPM12_NONCE_SIZE];   /* TPM OSAP nonce */
    u8   nonceOdd[TPM12_NONCE_SIZE];        /* Our session nonce */
    u8   nonceOddOSAP[TPM12_NONCE_SIZE];    /* Our OSAP nonce */
    u8   sharedSecret[TPM12_SHA1_HASH_SIZE]; /* HMAC(entityAuth, nonceEvenOSAP || nonceOddOSAP) */
} TPM12_OSAP_SESSION;


/*
 * SHA-1 hash using Windows bcrypt
 */
int tpm12_sha1_hash(const u8 *data, u32 data_size, u8 *hash_out)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;
    int resl = ST_ERROR;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    status = BCryptHashData(hHash, (PUCHAR)data, data_size, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    status = BCryptFinishHash(hHash, hash_out, TPM12_SHA1_HASH_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    resl = ST_OK;

cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return resl;
}

 /*
 * HMAC-SHA1 using Windows bcrypt (NV section local version)
 */
static int hmac_sha1(const u8 *key, u32 key_size, const u8 *data, u32 data_size, u8 *hmac_out)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;
    int resl = ST_ERROR;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, (PUCHAR)key, key_size, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    status = BCryptHashData(hHash, (PUCHAR)data, data_size, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    status = BCryptFinishHash(hHash, hmac_out, TPM12_SHA1_HASH_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    resl = ST_OK;

cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return resl;
}

///*
// * HMAC-SHA1 with multiple data blocks
// */
//static int hmac_sha1_multi(const u8 *key, u32 key_size,
//                           const u8 *data1, u32 data1_size,
//                           const u8 *data2, u32 data2_size,
//                           u8 *hmac_out)
//{
//    BCRYPT_ALG_HANDLE hAlg = NULL;
//    BCRYPT_HASH_HANDLE hHash = NULL;
//    NTSTATUS status;
//    int resl = ST_ERROR;
//
//    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
//    if (!BCRYPT_SUCCESS(status)) {
//        goto cleanup;
//    }
//
//    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, (PUCHAR)key, key_size, 0);
//    if (!BCRYPT_SUCCESS(status)) {
//        goto cleanup;
//    }
//
//    if (data1 && data1_size > 0) {
//        status = BCryptHashData(hHash, (PUCHAR)data1, data1_size, 0);
//        if (!BCRYPT_SUCCESS(status)) {
//            goto cleanup;
//        }
//    }
//
//    if (data2 && data2_size > 0) {
//        status = BCryptHashData(hHash, (PUCHAR)data2, data2_size, 0);
//        if (!BCRYPT_SUCCESS(status)) {
//            goto cleanup;
//        }
//    }
//
//    status = BCryptFinishHash(hHash, hmac_out, TPM12_SHA1_HASH_SIZE, 0);
//    if (!BCRYPT_SUCCESS(status)) {
//        goto cleanup;
//    }
//
//    resl = ST_OK;
//
//cleanup:
//    if (hHash) BCryptDestroyHash(hHash);
//    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
//    return resl;
//}

/*
* SHA-1 hash with multiple data blocks (NV section local version)
*/
static int sha1_hash_multi(const u8 *data1, u32 data1_size,
    const u8 *data2, u32 data2_size,
    u8 *hash_out)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;
    int resl = ST_ERROR;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    if (data1 && data1_size > 0) {
        status = BCryptHashData(hHash, (PUCHAR)data1, data1_size, 0);
        if (!BCRYPT_SUCCESS(status)) {
            goto cleanup;
        }
    }

    if (data2 && data2_size > 0) {
        status = BCryptHashData(hHash, (PUCHAR)data2, data2_size, 0);
        if (!BCRYPT_SUCCESS(status)) {
            goto cleanup;
        }
    }

    status = BCryptFinishHash(hHash, hash_out, TPM12_SHA1_HASH_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    resl = ST_OK;

cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return resl;
}

///*
// * TPM_GetRandom - Get random bytes from TPM 1.2
// */
//static int tpm12_get_random(u8 *buffer, u32 size)
//{
//    u8 cmd[32];
//    u8 rsp[256];
//    u32 rsp_size = sizeof(rsp);
//    u8 *p;
//    u32 cmd_size;
//    int resl;
//
//    if (size > 200) {
//        return ST_SMALL_BUFF;
//    }
//
//    p = cmd;
//    write_be16(p, TPM12_TAG_RQU_COMMAND); p += 2;
//    p += 4;  /* size placeholder */
//    write_be32(p, TPM12_ORD_GetRandom); p += 4;
//    write_be32(p, size); p += 4;
//
//    cmd_size = (u32)(p - cmd);
//    write_be32(cmd + 2, cmd_size);
//
//    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
//    if (resl != ST_OK) {
//        return resl;
//    }
//
//    /* Parse response: tag(2) + size(4) + rc(4) + randomBytesSize(4) + randomBytes */
//    if (rsp_size < 14) {
//        return ST_TPM_ERROR;
//    }
//
//    u32 rc = read_be32(rsp + 6);
//    if (rc != 0) {
//        return ST_TPM_ERROR;
//    }
//
//    u32 bytes_size = read_be32(rsp + 10);
//    if (bytes_size > size || bytes_size + 14 > rsp_size) {
//        return ST_TPM_ERROR;
//    }
//
//    memcpy(buffer, rsp + 14, bytes_size);
//    return ST_OK;
//}

///*
// * TPM_PCRExtend - Extend a PCR with a hash
// * Matches bootloader's Tpm12PcrExtend()
// */
//int tpm12_pcr_extend(u32 pcr_index, const u8 *data, u32 data_size)
//{
//    u8 cmd[64];
//    u8 rsp[64];
//    u32 rsp_size = sizeof(rsp);
//    u8 *p;
//    u32 cmd_size;
//    u8 hash[TPM12_SHA1_HASH_SIZE];
//    int resl;
//
//    /* Hash the input data first */
//    resl = tpm12_sha1_hash(data, data_size, hash);
//    if (resl != ST_OK) {
//        return resl;
//    }
//
//    p = cmd;
//    write_be16(p, TPM12_TAG_RQU_COMMAND); p += 2;
//    p += 4;  /* size placeholder */
//    write_be32(p, TPM12_ORD_Extend); p += 4;
//    write_be32(p, pcr_index); p += 4;
//    memcpy(p, hash, TPM12_SHA1_HASH_SIZE); p += TPM12_SHA1_HASH_SIZE;
//
//    cmd_size = (u32)(p - cmd);
//    write_be32(cmd + 2, cmd_size);
//
//    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
//
//    burn(hash, sizeof(hash));
//    return resl;
//}


//////////////////////////////////////////////////////////////////////////
// TPM Operations (NV-based storage mode)
//////////////////////////////////////////////////////////////////////////

/*
 * TPM 1.2 NV index derivation (matches bootloader DcsTpmLib.h)
 * PCR mask index is derived from data index using bit 21
 */
#define DC_TPM_NV_PCRS_BIT              0x200000
#define DC_TPM_NV_INDEX_TO_PCRS(idx)    ((idx) | DC_TPM_NV_PCRS_BIT)


/*
 * Read current PCR values
 */
static int tpm12_pcr_read(u32 pcr_index, u8 *pcr_value)
{
    u8 cmd[16];
    u8 rsp[64];
    u32 rsp_size = sizeof(rsp);
    u8 *p;
    u32 cmd_size;
    int resl;

    p = cmd;
    write_be16(p, TPM12_TAG_RQU_COMMAND); p += 2;
    p += 4;
    write_be32(p, TPM12_ORD_PcrRead); p += 4;
    write_be32(p, pcr_index); p += 4;

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        return resl;
    }

    if (rsp_size < 30) {
        return ST_TPM_ERROR;
    }

    memcpy(pcr_value, rsp + 10, TPM12_SHA1_HASH_SIZE);
    return ST_OK;
}

/*
 * Save current PCR values for the given mask
 */
static int tpm12_pcrs_save(u32 pcr_mask, u8 pcrs[][TPM12_SHA1_HASH_SIZE])
{
    int i;
    int resl;

    for (i = 0; i < 24; i++) {
        if (pcr_mask & (1 << i)) {
            resl = tpm12_pcr_read(i, pcrs[i]);
            if (resl != ST_OK) {
                return resl;
            }
        }
    }
    return ST_OK;
}

/*
 * Public wrapper for tpm12_pcr_read
 */
int dc_tpm_12_pcr_read(u32 pcr_index, u8 *pcr_value)
{
    return tpm12_pcr_read(pcr_index, pcr_value);
}

/*
 * Compute PCR composite digest for NV policy binding
 * Matches bootloader's Tpm12PcrsDigest()
 */
static int compute_pcr_digest(u16 size_of_select, const u8 *pcr_select,
                              u8 pcrs[][TPM12_SHA1_HASH_SIZE], u8 *digest)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;
    int resl = ST_ERROR;
    u32 i, j, k;
    u32 value_size;

    /* Count selected PCRs */
    k = 0;
    for (i = 0; i < size_of_select; i++) {
        u8 tmp = pcr_select[i];
        for (j = 0; j < 8; j++) {
            if (tmp & 1) k++;
            tmp >>= 1;
        }
    }
    if (k == 0) {
        memset(digest, 0, TPM12_SHA1_HASH_SIZE);
        return ST_OK;
    }

    value_size = k * TPM12_SHA1_HASH_SIZE;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    /* Hash: sizeOfSelect(2) + pcrSelect + valueSize(4) + pcrValues */
    u8 size_be[2];
    write_be16(size_be, size_of_select);
    status = BCryptHashData(hHash, size_be, 2, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    status = BCryptHashData(hHash, (PUCHAR)pcr_select, size_of_select, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    u8 value_size_be[4];
    write_be32(value_size_be, value_size);
    status = BCryptHashData(hHash, value_size_be, 4, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    /* Hash each selected PCR value */
    k = 0;
    for (i = 0; i < size_of_select; i++) {
        u8 tmp = pcr_select[i];
        for (j = 0; j < 8; j++) {
            if (tmp & 1) {
                status = BCryptHashData(hHash, pcrs[k], TPM12_SHA1_HASH_SIZE, 0);
                if (!BCRYPT_SUCCESS(status)) goto cleanup;
            }
            tmp >>= 1;
            k++;
        }
    }

    status = BCryptFinishHash(hHash, digest, TPM12_SHA1_HASH_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    resl = ST_OK;

cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return resl;
}

/*
 * OSAP session for owner operations
 */
static int tpm12_osap_owner(TPM12_OSAP_SESSION *session, const wchar_t *owner_pwd)
{
    u8 cmd[64];
    u8 rsp[128];
    u32 rsp_size = sizeof(rsp);
    u8 *p;
    u32 cmd_size;
    int resl;
    u8 owner_auth[TPM12_SHA1_HASH_SIZE];
    u8 hmac_data[TPM12_NONCE_SIZE * 2];

    /* Hash owner password to get auth value */
    if (owner_pwd != NULL && owner_pwd[0] != L'\0') {
        resl = tpm12_sha1_hash((const u8 *)owner_pwd, (u32)(wcslen(owner_pwd) * sizeof(wchar_t)), owner_auth);
        if (resl != ST_OK) return resl;
    } else {
        memset(owner_auth, 0, sizeof(owner_auth));
    }

    /* Generate our OSAP nonces */
    resl = dc_device_control(DC_CTL_GET_RAND, NULL, 0, session->nonceOddOSAP, TPM12_NONCE_SIZE);
    if (resl != NO_ERROR) {
        BCryptGenRandom(NULL, session->nonceOddOSAP, TPM12_NONCE_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    }

    resl = dc_device_control(DC_CTL_GET_RAND, NULL, 0, session->nonceOdd, TPM12_NONCE_SIZE);
    if (resl != NO_ERROR) {
        BCryptGenRandom(NULL, session->nonceOdd, TPM12_NONCE_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    }

    /* Build TPM_OSAP command */
    p = cmd;
    write_be16(p, TPM12_TAG_RQU_COMMAND); p += 2;
    p += 4;
    write_be32(p, TPM12_ORD_OSAP); p += 4;
    write_be16(p, TPM12_ET_OWNER); p += 2;  /* entityType */
    write_be32(p, TPM12_KH_OWNER); p += 4;  /* entityValue */
    memcpy(p, session->nonceOddOSAP, TPM12_NONCE_SIZE); p += TPM12_NONCE_SIZE;

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        burn(owner_auth, sizeof(owner_auth));
        return resl;
    }

    if (rsp_size < 50) {
        burn(owner_auth, sizeof(owner_auth));
        return ST_TPM_ERROR;
    }

    session->authHandle = read_be32(rsp + 10);
    memcpy(session->nonceEven, rsp + 14, TPM12_NONCE_SIZE);
    memcpy(session->nonceEvenOSAP, rsp + 34, TPM12_NONCE_SIZE);

    /* Compute shared secret: HMAC(ownerAuth, nonceEvenOSAP || nonceOddOSAP) */
    memcpy(hmac_data, session->nonceEvenOSAP, TPM12_NONCE_SIZE);
    memcpy(hmac_data + TPM12_NONCE_SIZE, session->nonceOddOSAP, TPM12_NONCE_SIZE);

    resl = hmac_sha1(owner_auth, TPM12_SHA1_HASH_SIZE, hmac_data, sizeof(hmac_data), session->sharedSecret);

    burn(owner_auth, sizeof(owner_auth));
    burn(hmac_data, sizeof(hmac_data));
    return resl;
}

/*
 * TPM_NV_DefineSpace - Create NV space with PCR binding and optional auth
 * Matches bootloader's Tpm12NvSpaceWithAuth()
 */
static int tpm12_nv_define_space(
    u32 nv_index,
    u32 data_size,
    const wchar_t *owner_pwd,
    u8 pcrs[][TPM12_SHA1_HASH_SIZE],
    u32 pcr_read_mask,
    u32 pcr_write_mask,
    u32 nv_attributes,
    const u8 *nv_auth)  /* NULL = no auth */
{
    u8 cmd[256];
    u8 rsp[64];
    u32 rsp_size = sizeof(rsp);
    u8 *p, *params_start;
    u32 cmd_size;
    int resl;
    TPM12_OSAP_SESSION osap;
    u8 enc_auth[TPM12_SHA1_HASH_SIZE];
    u8 cmd_digest[TPM12_SHA1_HASH_SIZE];
    u8 auth_hmac[TPM12_SHA1_HASH_SIZE];
    u8 hmac_input[128];
    u8 *hp;
    u8 pcr_select_r[3], pcr_select_w[3];
    u8 digest_r[TPM12_SHA1_HASH_SIZE], digest_w[TPM12_SHA1_HASH_SIZE];

    /* Start OSAP session with owner */
    resl = tpm12_osap_owner(&osap, owner_pwd);
    if (resl != ST_OK) {
        return resl;
    }

    /* Build PCR select bytes */
    pcr_select_r[0] = (u8)(pcr_read_mask & 0xFF);
    pcr_select_r[1] = (u8)((pcr_read_mask >> 8) & 0xFF);
    pcr_select_r[2] = (u8)((pcr_read_mask >> 16) & 0xFF);

    pcr_select_w[0] = (u8)(pcr_write_mask & 0xFF);
    pcr_select_w[1] = (u8)((pcr_write_mask >> 8) & 0xFF);
    pcr_select_w[2] = (u8)((pcr_write_mask >> 16) & 0xFF);

    /* Compute PCR digests */
    compute_pcr_digest(3, pcr_select_r, pcrs, digest_r);
    compute_pcr_digest(3, pcr_select_w, pcrs, digest_w);

    /* Encrypt nvAuth using ADIP if provided */
    if (nv_auth != NULL) {
        u8 xor_key[TPM12_SHA1_HASH_SIZE];
        int i;

        /* encAuth = SHA1(sharedSecret || nonceEven) XOR nvAuth */
        resl = sha1_hash_multi(osap.sharedSecret, TPM12_SHA1_HASH_SIZE,
                               osap.nonceEven, TPM12_NONCE_SIZE, xor_key);
        if (resl != ST_OK) goto cleanup;

        for (i = 0; i < TPM12_SHA1_HASH_SIZE; i++) {
            enc_auth[i] = xor_key[i] ^ nv_auth[i];
        }
        burn(xor_key, sizeof(xor_key));
    } else {
        memset(enc_auth, 0xEA, sizeof(enc_auth));  /* Dummy auth */
    }

    /* Build TPM_NV_DefineSpace command */
    p = cmd;
    write_be16(p, TPM12_TAG_RQU_AUTH1_COMMAND); p += 2;
    p += 4;  /* size placeholder */
    write_be32(p, TPM12_ORD_NV_DefineSpace); p += 4;

    params_start = p;

    /* TPM_NV_DATA_PUBLIC structure */
    write_be16(p, TPM12_TAG_NV_DATA_PUBLIC); p += 2; /* tag */
    write_be32(p, nv_index); p += 4;

    /* PCR_INFO_SHORT for read */
    write_be16(p, 3); p += 2;  /* sizeOfSelect */
    memcpy(p, pcr_select_r, 3); p += 3;
    *p++ = 0x1F;  /* localityAtRelease */
    memcpy(p, digest_r, TPM12_SHA1_HASH_SIZE); p += TPM12_SHA1_HASH_SIZE;

    /* PCR_INFO_SHORT for write */
    write_be16(p, 3); p += 2;
    memcpy(p, pcr_select_w, 3); p += 3;
    *p++ = 0x1F;
    memcpy(p, digest_w, TPM12_SHA1_HASH_SIZE); p += TPM12_SHA1_HASH_SIZE;

    /* Permission */
    write_be16(p, TPM12_TAG_NV_ATTRIBUTES); p += 2;  /* tag */
    write_be32(p, nv_attributes); p += 4;

    *p++ = 0;  /* bReadSTClear */
    *p++ = 0;  /* bWriteSTClear */
    *p++ = 0;  /* bWriteDefine */

    write_be32(p, data_size); p += 4;

    /* encAuth */
    memcpy(p, enc_auth, TPM12_SHA1_HASH_SIZE); p += TPM12_SHA1_HASH_SIZE;

    /* Calculate command digest */
    {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;

        BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
        BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
        BCryptHashData(hHash, cmd + 6, 4, 0);  /* ordinal */
        BCryptHashData(hHash, params_start, (ULONG)(p - params_start), 0);
        BCryptFinishHash(hHash, cmd_digest, TPM12_SHA1_HASH_SIZE, 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    /* Calculate auth HMAC */
    hp = hmac_input;
    memcpy(hp, cmd_digest, TPM12_SHA1_HASH_SIZE); hp += TPM12_SHA1_HASH_SIZE;
    memcpy(hp, osap.nonceEven, TPM12_NONCE_SIZE); hp += TPM12_NONCE_SIZE;
    memcpy(hp, osap.nonceOdd, TPM12_NONCE_SIZE); hp += TPM12_NONCE_SIZE;
    *hp++ = 0;  /* continueSession */

    resl = hmac_sha1(osap.sharedSecret, TPM12_SHA1_HASH_SIZE,
                     hmac_input, (u32)(hp - hmac_input), auth_hmac);
    if (resl != ST_OK) goto cleanup;

    /* Append auth block */
    write_be32(p, osap.authHandle); p += 4;
    memcpy(p, osap.nonceOdd, TPM12_NONCE_SIZE); p += TPM12_NONCE_SIZE;
    *p++ = 0;
    memcpy(p, auth_hmac, TPM12_SHA1_HASH_SIZE); p += TPM12_SHA1_HASH_SIZE;

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);

cleanup:
    burn(&osap, sizeof(osap));
    burn(enc_auth, sizeof(enc_auth));
    burn(auth_hmac, sizeof(auth_hmac));
    burn(hmac_input, sizeof(hmac_input));
    return resl;
}

/*
 * TPM_NV_WriteValue - Write data to NV space (owner auth)
 */
static int tpm12_nv_write(u32 nv_index, const u8 *data, u32 data_size, const wchar_t *owner_pwd)
{
    u8 cmd[768];
    u8 rsp[64];
    u32 rsp_size = sizeof(rsp);
    u8 *p, *params_start;
    u32 cmd_size;
    int resl;
    TPM12_OSAP_SESSION osap;
    u8 cmd_digest[TPM12_SHA1_HASH_SIZE];
    u8 auth_hmac[TPM12_SHA1_HASH_SIZE];
    u8 hmac_input[128];
    u8 *hp;

    resl = tpm12_osap_owner(&osap, owner_pwd);
    if (resl != ST_OK) return resl;

    p = cmd;
    write_be16(p, TPM12_TAG_RQU_AUTH1_COMMAND); p += 2;
    p += 4;
    write_be32(p, TPM12_ORD_NV_WriteValue); p += 4;

    params_start = p;
    write_be32(p, nv_index); p += 4;
    write_be32(p, 0); p += 4;  /* offset */
    write_be32(p, data_size); p += 4;
    memcpy(p, data, data_size); p += data_size;

    /* Calculate command digest */
    {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;

        BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
        BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
        BCryptHashData(hHash, cmd + 6, 4, 0);
        BCryptHashData(hHash, params_start, (ULONG)(p - params_start), 0);
        BCryptFinishHash(hHash, cmd_digest, TPM12_SHA1_HASH_SIZE, 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    hp = hmac_input;
    memcpy(hp, cmd_digest, TPM12_SHA1_HASH_SIZE); hp += TPM12_SHA1_HASH_SIZE;
    memcpy(hp, osap.nonceEven, TPM12_NONCE_SIZE); hp += TPM12_NONCE_SIZE;
    memcpy(hp, osap.nonceOdd, TPM12_NONCE_SIZE); hp += TPM12_NONCE_SIZE;
    *hp++ = 0;

    resl = hmac_sha1(osap.sharedSecret, TPM12_SHA1_HASH_SIZE,
                     hmac_input, (u32)(hp - hmac_input), auth_hmac);
    if (resl != ST_OK) goto cleanup;

    write_be32(p, osap.authHandle); p += 4;
    memcpy(p, osap.nonceOdd, TPM12_NONCE_SIZE); p += TPM12_NONCE_SIZE;
    *p++ = 0;
    memcpy(p, auth_hmac, TPM12_SHA1_HASH_SIZE); p += TPM12_SHA1_HASH_SIZE;

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);

cleanup:
    burn(&osap, sizeof(osap));
    burn(auth_hmac, sizeof(auth_hmac));
    burn(hmac_input, sizeof(hmac_input));
    return resl;
}

/*
 * TPM_NV_ReadValue - Read data from NV space (no auth, relies on PCR binding)
 */
static int tpm12_nv_read(u32 nv_index, u8 *data, u32 *data_size)
{
    u8 cmd[32];
    u8 rsp[640];
    u32 rsp_size = sizeof(rsp);
    u8 *p;
    u32 cmd_size;
    int resl;

    p = cmd;
    write_be16(p, TPM12_TAG_RQU_COMMAND); p += 2;
    p += 4;
    write_be32(p, TPM12_ORD_NV_ReadValue); p += 4;
    write_be32(p, nv_index); p += 4;
    write_be32(p, 0); p += 4;  /* offset */
    write_be32(p, *data_size); p += 4;

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        return resl;
    }

    if (rsp_size < 14) {
        return ST_TPM_ERROR;
    }

    u32 out_size = read_be32(rsp + 10);
    if (out_size > *data_size) {
        return ST_SMALL_BUFF;
    }

    memcpy(data, rsp + 14, out_size);
    *data_size = out_size;
    return ST_OK;
}

/*
 * Open OIAP session (local version for NV operations)
 */
static int tpm12_nv_oiap_open(TPM12_OIAP_SESSION *session)
{
    u8 cmd[16];
    u8 rsp[64];
    u32 rsp_size = sizeof(rsp);
    u8 *p;
    u32 cmd_size;
    int resl;

    /* Generate our nonce */
    if (dc_device_control(DC_CTL_GET_RAND, NULL, 0, session->nonceOdd, TPM12_NONCE_SIZE) != NO_ERROR) {
        BCryptGenRandom(NULL, session->nonceOdd, TPM12_NONCE_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    }

    /* Build TPM_OIAP command */
    p = cmd;
    write_be16(p, TPM12_TAG_RQU_COMMAND); p += 2;
    p += 4;  /* size placeholder */
    write_be32(p, TPM12_ORD_OIAP); p += 4;

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        return resl;
    }

    /* Parse response: tag(2) + size(4) + rc(4) + authHandle(4) + nonceEven(20) */
    if (rsp_size < 30) {
        return ST_TPM_ERROR;
    }

    session->authHandle = read_be32(rsp + 10);
    memcpy(session->nonceEven, rsp + 14, TPM12_NONCE_SIZE);

    return ST_OK;
}

/*
 * TPM_NV_ReadValueAuth - Read data from NV space with PIN auth
 */
static int tpm12_nv_read_auth(u32 nv_index, u8 *data, u32 *data_size, const u8 *nv_auth)
{
    u8 cmd[256];
    u8 rsp[640];
    u32 rsp_size = sizeof(rsp);
    u8 *p, *params_start;
    u32 cmd_size;
    int resl;
    TPM12_OIAP_SESSION oiap;
    u8 cmd_digest[TPM12_SHA1_HASH_SIZE];
    u8 auth_hmac[TPM12_SHA1_HASH_SIZE];
    u8 hmac_input[128];
    u8 *hp;

    /* Open OIAP session */
    resl = tpm12_nv_oiap_open(&oiap);
    if (resl != ST_OK) return resl;

    p = cmd;
    write_be16(p, TPM12_TAG_RQU_AUTH1_COMMAND); p += 2;
    p += 4;
    write_be32(p, TPM12_ORD_NV_ReadValueAuth); p += 4;

    params_start = p;
    write_be32(p, nv_index); p += 4;
    write_be32(p, 0); p += 4;  /* offset */
    write_be32(p, *data_size); p += 4;

    /* Calculate command digest */
    {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;

        BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
        BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
        BCryptHashData(hHash, cmd + 6, 4, 0);
        BCryptHashData(hHash, params_start, (ULONG)(p - params_start), 0);
        BCryptFinishHash(hHash, cmd_digest, TPM12_SHA1_HASH_SIZE, 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    hp = hmac_input;
    memcpy(hp, cmd_digest, TPM12_SHA1_HASH_SIZE); hp += TPM12_SHA1_HASH_SIZE;
    memcpy(hp, oiap.nonceEven, TPM12_NONCE_SIZE); hp += TPM12_NONCE_SIZE;
    memcpy(hp, oiap.nonceOdd, TPM12_NONCE_SIZE); hp += TPM12_NONCE_SIZE;
    *hp++ = 0;

    resl = hmac_sha1(nv_auth, TPM12_SHA1_HASH_SIZE,
                     hmac_input, (u32)(hp - hmac_input), auth_hmac);
    if (resl != ST_OK) goto cleanup;

    write_be32(p, oiap.authHandle); p += 4;
    memcpy(p, oiap.nonceOdd, TPM12_NONCE_SIZE); p += TPM12_NONCE_SIZE;
    *p++ = 0;
    memcpy(p, auth_hmac, TPM12_SHA1_HASH_SIZE); p += TPM12_SHA1_HASH_SIZE;

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) goto cleanup;

    if (rsp_size < 14) {
        resl = ST_TPM_ERROR;
        goto cleanup;
    }

    u32 out_size = read_be32(rsp + 10);
    if (out_size > *data_size) {
        resl = ST_SMALL_BUFF;
        goto cleanup;
    }

    memcpy(data, rsp + 14, out_size);
    *data_size = out_size;

cleanup:
    burn(&oiap, sizeof(oiap));
    burn(auth_hmac, sizeof(auth_hmac));
    burn(hmac_input, sizeof(hmac_input));
    return resl;
}

/*
 * Create TPM 1.2 NV entry with PCR binding
 * Compatible with bootloader's DcTpm12SealPassword()
 *
 * nv_index: NV index (DC_TPM_NV_INDEX_PRIMARY or DC_TPM_NV_INDEX_RECOVERY)
 * owner_pwd: TPM owner password (UTF-16) for NV space creation
 * pin_auth: PIN authentication data (raw bytes, can be NULL)
 * pin_auth_size: Size of pin_auth in bytes
 * pcr_mask: PCR mask for binding (0 = no PCR binding)
 * data: Data to seal
 * data_size: Size of data
 * data_type: Type of data (DCS_TPM_SECRET_TYPE_*)
 * info: Optional plaintext info to store (can be NULL)
 * info_size: Size of info data
 * Returns: ST_OK on success
 */
int dc_tpm_12_create_nv_entry(
    u32 nv_index,
    const wchar_t *owner_pwd,
    const u8 *pin_auth,
    u32 pin_auth_size,
    u32 pcr_mask,
    //u8 custom_pcrs[][TPM12_SHA1_HASH_SIZE],  /* Custom PCR values or NULL */
    const u8 *data,
    u32 data_size,
    u32 data_type,
    const void *info,
    u32 info_size)
{
    int resl;
    u32 data_nv_index;
    u32 pcr_info_nv_index;
    u8 sealed_buffer[DC_TPM_SRK_SEALED_BLOB_MAX];
    DC_TPM_SEALED_DATA *sealed_data = (DC_TPM_SEALED_DATA *)sealed_buffer;
    u32 sealed_size;
    u8 pcr_info_buf[DC_TPM_PCRINFO_BASE_SIZE + DC_TPM_INFO_MAX_SIZE];
    DC_TPM_PCRINFO_DATA *pcr_info = (DC_TPM_PCRINFO_DATA *)pcr_info_buf;
    u32 pcr_info_size;
    u8 nv_auth[TPM12_SHA1_HASH_SIZE];
    u8 *p_nv_auth = NULL;
    u32 nv_attributes;
    u8 pcrs[24][TPM12_SHA1_HASH_SIZE];

    if (data == NULL || data_size == 0 || owner_pwd == NULL) {
        return ST_INVALID_PARAM;
    }
    if (data_size > DC_TPM_SRK_PASSWORD_MAX_SIZE) {
        return ST_SMALL_BUFF;
    }
    if (info_size > DC_TPM_INFO_MAX_SIZE) {
        return ST_SMALL_BUFF;
    }

    resl = dc_tpm_init();
    if (resl != ST_OK) return resl;

    /* Calculate padded sealed data size */
    sealed_size = dc_tpm_sealed_data_size((u16)data_size);

    /* Derive nvAuth from PIN if provided */
    if (pin_auth_size > 0) {
        tpm12_sha1_hash(pin_auth, pin_auth_size, nv_auth);
        p_nv_auth = nv_auth;
    }

    /* Limit PCR mask to 24 PCRs */
    pcr_mask &= 0x00FFFFFF;

    data_nv_index = nv_index;  /* TPM 1.2 uses index directly */
    pcr_info_nv_index = DC_TPM_NV_INDEX_TO_PCRS(data_nv_index);

//    /* Use custom PCR values or read current ones */
//    if (custom_pcrs != NULL) {
//        memcpy(pcrs, custom_pcrs, sizeof(pcrs));
//    } else {
    /* Save current PCR values */
    resl = tpm12_pcrs_save(pcr_mask, pcrs);
    if (resl != ST_OK) return resl;
//    }

    /* Delete existing NV spaces (ignore errors) */
    tpm12_nv_define_space(data_nv_index, 0, owner_pwd, pcrs, 0, 0, TPM12_NV_PER_OWNERWRITE, NULL);
    tpm12_nv_define_space(pcr_info_nv_index, 0, owner_pwd, pcrs, 0, 0, TPM12_NV_PER_OWNERWRITE, NULL);

    /* Set NV attributes */
    nv_attributes = TPM12_NV_PER_OWNERWRITE;

    /*
     * IMPORTANT: For PCR binding to be enforced, AUTHREAD must be set.
     * TPM_NV_ReadValue (unauthenticated) does NOT check pcrInfoRead.
     * Only TPM_NV_ReadValueAuth checks PCRs.
     * So if pcr_mask is set, we MUST use AUTHREAD even without a PIN.
     */
    if (p_nv_auth != NULL || pcr_mask != 0) {
        nv_attributes |= TPM12_NV_PER_AUTHREAD;
        /* If no PIN but PCR binding requested, use well-known (zeros) auth */
        if (p_nv_auth == NULL) {
            memset(nv_auth, 0, sizeof(nv_auth));
            p_nv_auth = nv_auth;
        }
    }

    /* Create NV space with PCR protection */
    resl = tpm12_nv_define_space(data_nv_index, sealed_size, owner_pwd,
                                  pcrs, pcr_mask, 0, nv_attributes, p_nv_auth);
    if (resl != ST_OK) goto cleanup;

    /* Prepare sealed data structure */
    memset(sealed_buffer, 0, sealed_size);
    sealed_data->Magic = DC_TPM_SEALED_MAGIC;
    sealed_data->Version = DC_TPM_SEALED_VERSION;
    sealed_data->PasswordSize = (u16)data_size;
    sealed_data->PasswordType = data_type;
    memcpy(sealed_data->Password, data, data_size);

    /* Calculate checksum */
    /* uses crc32 from ..\crc32.h */
    sealed_data->Checksum = crc32(data, data_size);

    /* Write sealed data */
    resl = tpm12_nv_write(data_nv_index, (const u8 *)sealed_data, sealed_size, owner_pwd);
    if (resl != ST_OK) goto cleanup;

    /* Create and write PCR info NV */
    pcr_info_size = DC_TPM_PCRINFO_BASE_SIZE + info_size;
    memset(pcr_info_buf, 0, sizeof(pcr_info_buf));
    pcr_info->Magic = DC_TPM_PCRINFO_MAGIC;
    pcr_info->Version = DC_TPM_PCRINFO_VERSION;
    pcr_info->PcrMask = pcr_mask;
    pcr_info->Flags = 0;
    if (p_nv_auth != NULL) {
        pcr_info->Flags |= DC_TPM_FLAG_PIN_REQUIRED;
    }
    pcr_info->InfoSize = (u16)info_size;
    if (info != NULL && info_size > 0) {
        memcpy(pcr_info->InfoData, info, info_size);
    }

    resl = tpm12_nv_define_space(pcr_info_nv_index, pcr_info_size, owner_pwd,
                                  pcrs, 0, 0, TPM12_NV_PER_OWNERWRITE, NULL);
    if (resl != ST_OK) goto cleanup;

    resl = tpm12_nv_write(pcr_info_nv_index, pcr_info_buf, pcr_info_size, owner_pwd);

cleanup:
    burn(sealed_buffer, sizeof(sealed_buffer));
    burn(pcr_info_buf, sizeof(pcr_info_buf));
    burn(nv_auth, sizeof(nv_auth));
    return resl;
}

/*
* Query TPM 1.2 NV entry size using GetCapability
* Returns: ST_OK on success with *nv_size set, error otherwise
*/
static int tpm12_nv_get_size(u32 nv_index, u32 *nv_size)
{
    u8 cmd[32];
    u8 rsp[256];
    u32 rsp_size = sizeof(rsp);
    u8 *p;
    u32 cmd_size;
    int resl;

    /*
    * Use TPM_GetCapability with TPM12_CAP_NV_INDEX to get NV_DATA_PUBLIC.
    * This doesn't require auth and works even with AUTHREAD set.
    */
    p = cmd;
    write_be16(p, TPM12_TAG_RQU_COMMAND); p += 2;
    p += 4;  /* size placeholder */
    write_be32(p, TPM12_ORD_GetCapability); p += 4;
    write_be32(p, TPM12_CAP_NV_INDEX); p += 4;
    write_be32(p, 4); p += 4;  /* subCapSize = 4 */
    write_be32(p, nv_index); p += 4;  /* subCap = nv_index */

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) return resl;

    /* Response: tag(2) + size(4) + rc(4) + respSize(4) + NV_DATA_PUBLIC */
    if (rsp_size < 14) return ST_TPM_ERROR;

    u32 resp_data_size = read_be32(rsp + 10);
    if (resp_data_size == 0) return ST_TPM_NV_NOT_FOUND;

    /*
    * Parse NV_DATA_PUBLIC to find dataSize at the end:
    * - tag (2)
    * - nvIndex (4)
    * - pcrInfoRead: sizeOfSelect(2) + pcrSelect(variable) + localityAtRelease(1) + digestAtRelease(20)
    * - pcrInfoWrite: same structure
    * - permission: tag(2) + attributes(4)
    * - bReadSTClear (1)
    * - bWriteSTClear (1)
    * - bWriteDefine (1)
    * - dataSize (4)
    */
    u8 *nv_pub = rsp + 14;
    u32 offset = 2 + 4;  /* Skip tag and nvIndex */

    /* Skip pcrInfoRead */
    if (offset + 2 > resp_data_size) return ST_FORMAT_ERR;
    u16 select_size_r = read_be16(nv_pub + offset);
    offset += 2 + select_size_r + 1 + 20;  /* sizeOfSelect + pcrSelect + locality + digest */

    /* Skip pcrInfoWrite */
    if (offset + 2 > resp_data_size) return ST_FORMAT_ERR;
    u16 select_size_w = read_be16(nv_pub + offset);
    offset += 2 + select_size_w + 1 + 20;

    /* Skip permission (tag + attributes) + bReadSTClear + bWriteSTClear + bWriteDefine */
    offset += 2 + 4 + 1 + 1 + 1;

    /* Read dataSize */
    if (offset + 4 > resp_data_size) return ST_FORMAT_ERR;
    *nv_size = read_be32(nv_pub + offset);

    return ST_OK;
}


/*
* Query TPM 1.2 NV entry details using GetCapability
* Returns: ST_OK on success with details filled, error otherwise
*/
static int tpm12_nv_get_details(u32 nv_index, u32 *nv_size, u32 *attributes, u32 *pcr_read, u32 *pcr_write)
{
    u8 cmd[32];
    u8 rsp[256];
    u32 rsp_size = sizeof(rsp);
    u8 *p;
    u32 cmd_size;
    int resl;

    p = cmd;
    write_be16(p, TPM12_TAG_RQU_COMMAND); p += 2;
    p += 4;  /* size placeholder */
    write_be32(p, TPM12_ORD_GetCapability); p += 4;
    write_be32(p, TPM12_CAP_NV_INDEX); p += 4;
    write_be32(p, 4); p += 4;  /* subCapSize = 4 */
    write_be32(p, nv_index); p += 4;  /* subCap = nv_index */

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) return resl;

    /* Response: tag(2) + size(4) + rc(4) + respSize(4) + NV_DATA_PUBLIC */
    if (rsp_size < 14) return ST_TPM_ERROR;

    u32 resp_data_size = read_be32(rsp + 10);
    if (resp_data_size == 0) return ST_TPM_NV_NOT_FOUND;

    /*
    * Parse NV_DATA_PUBLIC:
    * - tag (2)
    * - nvIndex (4)
    * - pcrInfoRead: sizeOfSelect(2) + pcrSelect(variable) + localityAtRelease(1) + digestAtRelease(20)
    * - pcrInfoWrite: same structure
    * - permission: tag(2) + attributes(4)
    * - bReadSTClear (1)
    * - bWriteSTClear (1)
    * - bWriteDefine (1)
    * - dataSize (4)
    */
    u8 *nv_pub = rsp + 14;
    u32 offset = 2 + 4;  /* Skip tag and nvIndex */

    /* Parse pcrInfoRead */
    if (offset + 2 > resp_data_size) return ST_FORMAT_ERR;
    u16 select_size_r = read_be16(nv_pub + offset);
    offset += 2;

    /* Extract PCR read mask */
    if (pcr_read != NULL && select_size_r > 0) {
        *pcr_read = nv_pub[offset];
        if (select_size_r > 1) *pcr_read |= nv_pub[offset + 1] << 8;
        if (select_size_r > 2) *pcr_read |= nv_pub[offset + 2] << 16;
    } else if (pcr_read != NULL) {
        *pcr_read = 0;
    }
    offset += select_size_r + 1 + 20;  /* pcrSelect + locality + digest */

    /* Parse pcrInfoWrite */
    if (offset + 2 > resp_data_size) return ST_FORMAT_ERR;
    u16 select_size_w = read_be16(nv_pub + offset);
    offset += 2;

    /* Extract PCR write mask */
    if (pcr_write != NULL && select_size_w > 0) {
        *pcr_write = nv_pub[offset];
        if (select_size_w > 1) *pcr_write |= nv_pub[offset + 1] << 8;
        if (select_size_w > 2) *pcr_write |= nv_pub[offset + 2] << 16;
    } else if (pcr_write != NULL) {
        *pcr_write = 0;
    }
    offset += select_size_w + 1 + 20;

    /* Parse permission (tag + attributes) */
    offset += 2;  /* Skip permission tag */
    if (offset + 4 > resp_data_size) return ST_FORMAT_ERR;
    if (attributes != NULL) {
        *attributes = read_be32(nv_pub + offset);
    }
    offset += 4;

    /* Skip bReadSTClear + bWriteSTClear + bWriteDefine */
    offset += 3;

    /* Read dataSize */
    if (offset + 4 > resp_data_size) return ST_FORMAT_ERR;
    if (nv_size != NULL) {
        *nv_size = read_be32(nv_pub + offset);
    }

    return ST_OK;
}

/*
 * Unseal password from TPM 1.2 NV
 * Compatible with bootloader's DcTpm12UnsealPassword()
 *
 * nv_index: NV index (DC_TPM_NV_INDEX_PRIMARY or DC_TPM_NV_INDEX_RECOVERY)
 * pin_auth: PIN authentication data (raw bytes, can be NULL if not required)
 * pin_auth_size: Size of pin_auth in bytes
 * data: Output buffer for unsealed data
 * data_size: In: buffer size, Out: actual data size
 * data_type: Output for data type (DCS_TPM_SECRET_TYPE_*)
 * Returns: ST_OK on success
 */
int dc_tpm_12_unseal_nv_entry(
    u32 nv_index,
    const u8 *pin_auth,
    u32 pin_auth_size,
    u8 *data,
    u32 *data_size,
    u32 *data_type)
{
    int resl;
    u32 data_nv_index;
    u32 pcr_info_nv_index;
    u8 sealed_buffer[DC_TPM_SRK_SEALED_BLOB_MAX];
    DC_TPM_SEALED_DATA *sealed_data = (DC_TPM_SEALED_DATA *)sealed_buffer;
    u32 nv_size;
    u32 sz;
    u32 crc;
    int pin_required = 0;
    u8 nv_auth[TPM12_SHA1_HASH_SIZE];
    u8 pcr_info_buf[DC_TPM_PCRINFO_BASE_SIZE];
    DC_TPM_PCRINFO_DATA *pcr_info = (DC_TPM_PCRINFO_DATA *)pcr_info_buf;
    u32 pcr_info_sz;
    u32 pcr_info_nv_size;

    if (data == NULL || data_size == NULL || data_type == NULL) {
        return ST_INVALID_PARAM;
    }

    resl = dc_tpm_init();
    if (resl != ST_OK) return resl;

    data_nv_index = nv_index;
    pcr_info_nv_index = DC_TPM_NV_INDEX_TO_PCRS(data_nv_index);

    /* Query sealed data NV size first */
    resl = tpm12_nv_get_size(data_nv_index, &nv_size);
    if (resl != ST_OK) return resl;
    if (nv_size < DC_TPM_SEALED_MIN_SIZE || nv_size > sizeof(sealed_buffer)) {
        return ST_FORMAT_ERR;
    }
    sz = nv_size;

    /* Check if PIN is required and if PCR binding exists by reading PcrInfo NV */
    /* PCR info NV is public (no AUTHREAD), so we can read it directly */
    int pcr_binding = 0;
    int pcr_info_valid = 0;
    resl = tpm12_nv_get_size(pcr_info_nv_index, &pcr_info_nv_size);
    if (resl == ST_OK && pcr_info_nv_size >= DC_TPM_PCRINFO_BASE_SIZE) {
        pcr_info_sz = (pcr_info_nv_size < sizeof(pcr_info_buf)) ? pcr_info_nv_size : DC_TPM_PCRINFO_BASE_SIZE;
        resl = tpm12_nv_read(pcr_info_nv_index, pcr_info_buf, &pcr_info_sz);
        if (resl == ST_OK && pcr_info->Magic == DC_TPM_PCRINFO_MAGIC) {
            pin_required = (pcr_info->Flags & DC_TPM_FLAG_PIN_REQUIRED) != 0;
            pcr_binding = (pcr_info->PcrMask != 0);
            pcr_info_valid = 1;
        }
    }

    /*
     * Read sealed data.
     * IMPORTANT: If PCR binding exists, we MUST use authenticated read
     * because TPM_NV_ReadValue doesn't check PCRs, only TPM_NV_ReadValueAuth does.
     *
     * Fallback logic: If we couldn't read PCR info but a PIN was provided,
     * assume the entry needs PIN auth (AUTHREAD is likely set).
     */
    int use_pin_auth = pin_required || (!pcr_info_valid && pin_auth_size > 0);

    if (use_pin_auth) {
        if (pin_auth_size == 0) {
            return ST_PASS_ERR;  /* PIN required but not provided */
        }
        tpm12_sha1_hash(pin_auth, pin_auth_size, nv_auth);
        resl = tpm12_nv_read_auth(data_nv_index, sealed_buffer, &sz, nv_auth);
        burn(nv_auth, sizeof(nv_auth));
    } else if (pcr_binding) {
        /* PCR binding without PIN - use well-known (zeros) auth */
        memset(nv_auth, 0, sizeof(nv_auth));
        resl = tpm12_nv_read_auth(data_nv_index, sealed_buffer, &sz, nv_auth);
    } else {
        resl = tpm12_nv_read(data_nv_index, sealed_buffer, &sz);
    }

    if (resl != ST_OK) {
        /* Return specific error if known, otherwise generic TPM error */
        goto cleanup;
    }

    /* Validate */
    if (sz < DC_TPM_SEALED_MIN_SIZE || sealed_data->Magic != DC_TPM_SEALED_MAGIC) {
        resl = ST_FORMAT_ERR;
        goto cleanup;
    }
    if (sealed_data->Version != DC_TPM_SEALED_VERSION) {
        resl = ST_INCOMPATIBLE;
        goto cleanup;
    }
    if (sealed_data->PasswordSize > sz - DC_TPM_SEALED_BASE_SIZE) {
        resl = ST_FORMAT_ERR;
        goto cleanup;
    }

    /* Verify checksum */
    /* uses crc32 from ..\crc32.h */
    crc = crc32(sealed_data->Password, sealed_data->PasswordSize);
    if (crc != sealed_data->Checksum) {
        resl = ST_FORMAT_ERR;
        goto cleanup;
    }

    if (sealed_data->PasswordSize > *data_size) {
        resl = ST_SMALL_BUFF;
        goto cleanup;
    }

    memcpy(data, sealed_data->Password, sealed_data->PasswordSize);
    *data_size = sealed_data->PasswordSize;
    *data_type = sealed_data->PasswordType;
    resl = ST_OK;

cleanup:
    burn(sealed_buffer, sizeof(sealed_buffer));
    return resl;
}

/*
 * Check if TPM 1.2 NV entry exists
 * nv_index: NV index to check
 * Returns: 1 if exists, 0 otherwise
 */
int dc_tpm_12_nv_exists(u32 nv_index)
{
    u32 nv_size;
    int resl;

    resl = dc_tpm_init();
    if (resl != ST_OK) return 0;

    resl = tpm12_nv_get_size(nv_index, &nv_size);
    return (resl == ST_OK) ? 1 : 0;
}

/*
 * Get info about TPM 1.2 NV entry
 * Reads the PCR mask, flags, and optional info data from the associated PCR info NV entry.
 *
 * nv_index: NV index (DC_TPM_NV_INDEX_PRIMARY or DC_TPM_NV_INDEX_RECOVERY)
 * pcr_mask: Output for PCR mask (can be NULL)
 * flags: Output for flags (DC_TPM_FLAG_*, can be NULL)
 * info_buffer: Optional output buffer for info data (can be NULL)
 * info_size: In/out - on input: buffer size, on output: actual info size (can be NULL)
 * Returns: ST_OK on success
 */
int dc_tpm_12_nv_get_info(u32 nv_index, u32 *pcr_mask, u32 *flags, void *info_buffer, u32 *info_size)
{
    int resl;
    u32 pcr_info_nv_index;
    u8 pcr_info_buf[DC_TPM_PCRINFO_BASE_SIZE + DC_TPM_INFO_MAX_SIZE];
    DC_TPM_PCRINFO_DATA *pcr_info = (DC_TPM_PCRINFO_DATA *)pcr_info_buf;
    u32 nv_size;
    u32 sz;

    resl = dc_tpm_init();
    if (resl != ST_OK) return resl;

    pcr_info_nv_index = DC_TPM_NV_INDEX_TO_PCRS(nv_index);

    /* Query NV size first - PCR info NV is public */
    resl = tpm12_nv_get_size(pcr_info_nv_index, &nv_size);
    if (resl != ST_OK) return resl;
    if (nv_size < DC_TPM_PCRINFO_BASE_SIZE || nv_size > sizeof(pcr_info_buf)) {
        return ST_FORMAT_ERR;
    }

    /* Read the base structure to get Magic, PcrMask, Flags, InfoSize */
    sz = (nv_size < DC_TPM_PCRINFO_BASE_SIZE) ? nv_size : DC_TPM_PCRINFO_BASE_SIZE;
    resl = tpm12_nv_read(pcr_info_nv_index, pcr_info_buf, &sz);
    if (resl != ST_OK) return resl;

    if (sz < DC_TPM_PCRINFO_BASE_SIZE) return ST_FORMAT_ERR;

    if (pcr_info->Magic != DC_TPM_PCRINFO_MAGIC) {
        return ST_FORMAT_ERR;
    }

    if (pcr_mask) *pcr_mask = pcr_info->PcrMask;
    if (flags) *flags = pcr_info->Flags;

    if (info_size != NULL) {
        *info_size = pcr_info->InfoSize;
        if (info_buffer != NULL && pcr_info->InfoSize > 0) {
            if (*info_size < pcr_info->InfoSize) {
                return ST_SMALL_BUFF;
            }
            /* Need to read the full data including InfoData */
            sz = DC_TPM_PCRINFO_BASE_SIZE + pcr_info->InfoSize;
            if (sz > nv_size) sz = nv_size;  /* Don't exceed actual NV size */
            if (sz > sizeof(pcr_info_buf)) sz = sizeof(pcr_info_buf);
            resl = tpm12_nv_read(pcr_info_nv_index, pcr_info_buf, &sz);
            if (resl != ST_OK) return resl;
            memcpy(info_buffer, pcr_info->InfoData, pcr_info->InfoSize);
        }
    }

    return ST_OK;
}

/*
 * Delete TPM 1.2 NV entry (data + PCR info)
 * nv_index: NV index (DC_TPM_NV_INDEX_PRIMARY or DC_TPM_NV_INDEX_RECOVERY)
 * owner_pwd: TPM owner password (UTF-16)
 * Returns: ST_OK on success
 */
int dc_tpm_12_delete_nv_entry(u32 nv_index, const wchar_t *owner_pwd)
{
    int resl;
    u32 data_nv_index;
    u32 pcr_info_nv_index;
    u8 pcrs[24][TPM12_SHA1_HASH_SIZE];

    resl = dc_tpm_init();
    if (resl != ST_OK) return resl;

    data_nv_index = nv_index;
    pcr_info_nv_index = DC_TPM_NV_INDEX_TO_PCRS(data_nv_index);

    memset(pcrs, 0, sizeof(pcrs));

    /* Delete PCR info NV (ignore error) */
    tpm12_nv_define_space(pcr_info_nv_index, 0, owner_pwd, pcrs, 0, 0, TPM12_NV_PER_OWNERWRITE, NULL);

    /* Delete main NV (size=0 deletes) */
    resl = tpm12_nv_define_space(data_nv_index, 0, owner_pwd, pcrs, 0, 0, TPM12_NV_PER_OWNERWRITE, NULL);

    return resl;
}

//////////////////////////////////////////////////////////////////////////
// TPM Operations (File-based storage mode)
//////////////////////////////////////////////////////////////////////////

/* Well-known SRK authorization (20 bytes of zeros) */
static const u8 g_well_known_auth[TPM12_SHA1_HASH_SIZE] = {0};

/*
 * Generate random nonce
 */
static int generate_nonce(u8 *nonce)
{
    if (dc_device_control(DC_CTL_GET_RAND, NULL, 0, nonce, TPM12_NONCE_SIZE) == NO_ERROR) {
        return ST_OK;
    }
    /* Fallback to bcrypt random */
    if (BCRYPT_SUCCESS(BCryptGenRandom(NULL, nonce, TPM12_NONCE_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        return ST_OK;
    }
    return ST_ERROR;
}

/*
 * Open OIAP session
 * Returns session handle and TPM nonce
 */
static int tpm12_oiap_open(TPM12_OIAP_SESSION *session)
{
    u8 cmd[16];
    u8 rsp[64];
    u32 rsp_size = sizeof(rsp);
    u8 *p;
    u32 cmd_size;
    int resl;

    /* Generate our nonce */
    resl = generate_nonce(session->nonceOdd);
    if (resl != ST_OK) {
        return resl;
    }

    /* Build TPM_OIAP command */
    p = cmd;
    write_be16(p, TPM12_TAG_RQU_COMMAND); p += 2;
    p += 4;  /* size placeholder */
    write_be32(p, TPM12_ORD_OIAP); p += 4;

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        return resl;
    }

    /* Parse response: tag(2) + size(4) + rc(4) + authHandle(4) + nonceEven(20) */
    if (rsp_size < 30) {
        return ST_TPM_ERROR;
    }

    session->authHandle = read_be32(rsp + 10);
    memcpy(session->nonceEven, rsp + 14, TPM12_NONCE_SIZE);

    return ST_OK;
}

/*
 * Open OSAP session with SRK using raw auth value
 * Matches bootloader's Tpm12OSAPStartRaw()
 */
static int tpm12_osap_start_raw(TPM12_OSAP_SESSION *session, const u8 *auth_value)
{
    u8 cmd[64];
    u8 rsp[128];
    u32 rsp_size = sizeof(rsp);
    u8 *p;
    u32 cmd_size;
    int resl;
    u8 hmac_data[TPM12_NONCE_SIZE * 2];

    /* Generate our OSAP nonce */
    resl = generate_nonce(session->nonceOddOSAP);
    if (resl != ST_OK) {
        return resl;
    }

    /* Also generate session nonce (used later) */
    resl = generate_nonce(session->nonceOdd);
    if (resl != ST_OK) {
        return resl;
    }

    /* Build TPM_OSAP command */
    p = cmd;
    write_be16(p, TPM12_TAG_RQU_COMMAND); p += 2;
    p += 4;  /* size placeholder */
    write_be32(p, TPM12_ORD_OSAP); p += 4;
    write_be16(p, TPM12_ET_KEYHANDLE); p += 2;  /* entityType = key handle */
    write_be32(p, TPM12_KH_SRK); p += 4;        /* entityValue = SRK handle */
    memcpy(p, session->nonceOddOSAP, TPM12_NONCE_SIZE); p += TPM12_NONCE_SIZE;

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        return resl;
    }

    /* Parse response: tag(2) + size(4) + rc(4) + authHandle(4) + nonceEven(20) + nonceEvenOSAP(20) */
    if (rsp_size < 50) {
        return ST_TPM_ERROR;
    }

    session->authHandle = read_be32(rsp + 10);
    memcpy(session->nonceEven, rsp + 14, TPM12_NONCE_SIZE);
    memcpy(session->nonceEvenOSAP, rsp + 34, TPM12_NONCE_SIZE);

    /* Compute shared secret: HMAC(authValue, nonceEvenOSAP || nonceOddOSAP) */
    memcpy(hmac_data, session->nonceEvenOSAP, TPM12_NONCE_SIZE);
    memcpy(hmac_data + TPM12_NONCE_SIZE, session->nonceOddOSAP, TPM12_NONCE_SIZE);

    resl = hmac_sha1(auth_value, TPM12_SHA1_HASH_SIZE,
                     hmac_data, sizeof(hmac_data),
                     session->sharedSecret);

    burn(hmac_data, sizeof(hmac_data));
    return resl;
}

/*
 * Compute PCR composite digest for PCR binding
 * Matches bootloader's Tpm12PcrsDigest()
 */
static int compute_pcr_composite_digest(u32 pcr_mask/*, u8 pcr_values[][TPM12_SHA1_HASH_SIZE]*/, u8 *digest)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;
    int resl = ST_ERROR;
    u8 pcr_select[2];
    u32 value_size;
    u8 pcr_value[TPM12_SHA1_HASH_SIZE];
    int i, num_pcrs = 0;

    /* Count selected PCRs */
    for (i = 0; i < 16; i++) {
        if (pcr_mask & (1 << i)) {
            num_pcrs++;
        }
    }

    value_size = num_pcrs * TPM12_SHA1_HASH_SIZE;

    /* Build PCR select (2 bytes for 16 PCRs) */
    pcr_select[0] = (u8)(pcr_mask & 0xFF);
    pcr_select[1] = (u8)((pcr_mask >> 8) & 0xFF);

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    /* Hash: sizeOfSelect(2) + pcrSelect(2) + valueSize(4) + pcrValues */
    u8 size_of_select[2] = {0x00, 0x02};  /* Big-endian 2 */
    status = BCryptHashData(hHash, size_of_select, 2, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    status = BCryptHashData(hHash, pcr_select, 2, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    u8 value_size_be[4];
    write_be32(value_size_be, value_size);
    status = BCryptHashData(hHash, value_size_be, 4, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    /* Hash each selected PCR value */
    for (i = 0; i < 16; i++) {
        if (pcr_mask & (1 << i)) {
//            if (pcr_values) {
//                status = BCryptHashData(hHash, pcr_values[i], TPM12_SHA1_HASH_SIZE, 0);
//            }
//            else {
            resl = tpm12_pcr_read(i, pcr_value);
            if (resl != ST_OK) {
                goto cleanup;
            }
            status = BCryptHashData(hHash, pcr_value, TPM12_SHA1_HASH_SIZE, 0);
  //          }
            if (!BCRYPT_SUCCESS(status)) goto cleanup;
        }
    }

    status = BCryptFinishHash(hHash, digest, TPM12_SHA1_HASH_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    resl = ST_OK;

cleanup:
    burn(pcr_value, sizeof(pcr_value));
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return resl;
}

/*
 * TPM_GetCapability for TPM info
 */
int dc_tpm_12_get_info(DC_TPM_INFO *info)
{
    u8 cmd[32];
    u8 rsp[128];
    u32 rsp_size = sizeof(rsp);
    u8 *p;
    u32 cmd_size;
    int resl;

    if (info == NULL) {
        return ST_ERROR;
    }

    memset(info, 0, sizeof(DC_TPM_INFO));
    info->version = 1;  /* TPM 1.2 */

    resl = dc_tpm_init();
    if (resl != ST_OK) {
        return resl;
    }

    /* Build TPM_GetCapability command for version info */
    p = cmd;
    write_be16(p, TPM12_TAG_RQU_COMMAND); p += 2;
    p += 4;  /* size placeholder */
    write_be32(p, TPM12_ORD_GetCapability); p += 4;
    write_be32(p, TPM12_CAP_VERSION_VAL); p += 4;  /* capArea */
    write_be32(p, 0); p += 4;  /* subCapSize = 0 */

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        return resl;
    }

    /* Parse response: tag(2) + size(4) + rc(4) + respSize(4) + TPM_CAP_VERSION_INFO */
    if (rsp_size < 14) {
        return ST_TPM_ERROR;
    }

    u32 resp_size = read_be32(rsp + 10);
    u8 *resp_data = rsp + 14;

    if (resp_size >= 15) {
        /* TPM_CAP_VERSION_INFO structure:
         * tag(2) + version(4) + specLevel(2) + errataRev(1) + tpmVendorID(4) + vendorSpecificSize(2) + ... */

        /* Skip tag */
        resp_data += 2;

        /* Version: major(1) + minor(1) + revMajor(1) + revMinor(1) */
        u8 major = resp_data[0];
        u8 minor = resp_data[1];
        u8 revMajor = resp_data[2];
        u8 revMinor = resp_data[3];
        resp_data += 4;

        info->firmware_v1 = (major << 16) | minor;
        info->firmware_v2 = (revMajor << 16) | revMinor;

        /* specLevel(2) + errataRev(1) */
        resp_data += 3;

        /* tpmVendorID (4 bytes as ASCII) */
        memcpy(info->vendor_str, resp_data, 4);
        info->vendor_str[4] = '\0';
        info->vendor_id = read_be32(resp_data);
    }

    /* TPM 1.2 doesn't have lockout counter like TPM 2.0 */
    info->lockout_counter = 0;
    info->lockout_max = 0;
    info->lockout_interval = 0;
    info->lockout_recovery = 0;
    info->is_locked_out = 0;

    return ST_OK;
}

/*
 * TPM_Seal - Seal data under SRK
 * Matches bootloader's Tpm12Seal()
 */
int tpm12_seal(
    const u8 *srk_auth,
    u32 pcr_mask,
    //u8 pcr_values[][TPM12_SHA1_HASH_SIZE],  /* Custom PCR values or NULL for current */
    const u8 *pin_auth,
    u32 pin_auth_size,
    const u8 *data,
    u32 data_size,
    u8 *sealed_blob,
    u32 *sealed_blob_size)
{
    u8 cmd[1024];
    u8 rsp[1024];
    u32 rsp_size = sizeof(rsp);
    u8 *p, *params_start;
    u32 cmd_size;
    int resl;
    TPM12_OSAP_SESSION osap;
    u8 enc_auth[TPM12_SHA1_HASH_SIZE];
    u8 xor_mask[TPM12_SHA1_HASH_SIZE];
    u8 pcr_digest[TPM12_SHA1_HASH_SIZE];
    u8 cmd_digest[TPM12_SHA1_HASH_SIZE];
    u8 auth_hmac[TPM12_SHA1_HASH_SIZE];
    u8 hmac_input[128];
    u8 *hp;
    int i;
    u8 data_auth[TPM12_SHA1_HASH_SIZE];

	/* Use provided srk_auth or well-known zeros if NULL (SRK auth is often not set) */
    if (srk_auth == NULL) {
        srk_auth = g_well_known_auth;
	}

    /* Use provided data_auth or well-known zeros */
    if (pin_auth_size > 0) {
        tpm12_sha1_hash(pin_auth, pin_auth_size, data_auth);
    } else {
		memset(data_auth, 0, sizeof(data_auth));
    }

    if (data_size > 256) {
        return ST_SMALL_BUFF;  /* TPM_Seal has RSA size limits */
    }

    /* Limit PCR mask to PCRs 0-15 (matching bootloader) */
    pcr_mask &= 0xFFFF;

    /* Start OSAP session with SRK */
    resl = tpm12_osap_start_raw(&osap, srk_auth);
    if (resl != ST_OK) {
        return resl;
    }

    /* Compute ADIP encryption: encAuth = SHA1(sharedSecret || nonceEven) XOR dataAuth */
    resl = sha1_hash_multi(osap.sharedSecret, TPM12_SHA1_HASH_SIZE,
                           osap.nonceEven, TPM12_NONCE_SIZE,
                           xor_mask);
    if (resl != ST_OK) {
        goto cleanup;
    }

    for (i = 0; i < TPM12_SHA1_HASH_SIZE; i++) {
        enc_auth[i] = xor_mask[i] ^ data_auth[i];
    }

    /* Build TPM_Seal command */
    p = cmd;
    write_be16(p, TPM12_TAG_RQU_AUTH1_COMMAND); p += 2;
    p += 4;  /* size placeholder */
    write_be32(p, TPM12_ORD_Seal); p += 4;
    write_be32(p, TPM12_KH_SRK); p += 4;  /* keyHandle (NOT part of hash) */

    params_start = p;  /* Start of hashed params */

    memcpy(p, enc_auth, TPM12_SHA1_HASH_SIZE); p += TPM12_SHA1_HASH_SIZE;  /* encAuth */

    /* PCR_INFO structure */
    if (pcr_mask == 0) {
        /* No PCR binding */
        write_be32(p, 0); p += 4;  /* pcrInfoSize = 0 */
    } else {
        /* Build PCR_INFO: sizeOfSelect(2) + pcrSelect(2) + digestAtRelease(20) + digestAtCreation(20) */
        u32 pcr_info_size = 2 + 2 + 20 + 20;  /* 44 bytes */
        write_be32(p, pcr_info_size); p += 4;

        write_be16(p, 2); p += 2;  /* sizeOfSelect = 2 */

        u8 pcr_select[2];
        pcr_select[0] = (u8)(pcr_mask & 0xFF);
        pcr_select[1] = (u8)((pcr_mask >> 8) & 0xFF);
        memcpy(p, pcr_select, 2); p += 2;

        /* Compute PCR composite digest */
        resl = compute_pcr_composite_digest(pcr_mask/*, pcr_values*/, pcr_digest);
        if (resl != ST_OK) {
            goto cleanup;
        }

        memcpy(p, pcr_digest, TPM12_SHA1_HASH_SIZE); p += TPM12_SHA1_HASH_SIZE;  /* digestAtRelease */
        memcpy(p, pcr_digest, TPM12_SHA1_HASH_SIZE); p += TPM12_SHA1_HASH_SIZE;  /* digestAtCreation */
    }

    /* inData */
    write_be32(p, data_size); p += 4;
    memcpy(p, data, data_size); p += data_size;

    /* Calculate command digest: SHA1(ordinal || params) */
    /* ordinal at cmd+6, params from params_start to p */
    {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;

        BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
        BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
        BCryptHashData(hHash, cmd + 6, 4, 0);  /* ordinal */
        BCryptHashData(hHash, params_start, (ULONG)(p - params_start), 0);
        BCryptFinishHash(hHash, cmd_digest, TPM12_SHA1_HASH_SIZE, 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    /* Calculate auth HMAC: HMAC(sharedSecret, cmdDigest || nonceEven || nonceOdd || continueSession) */
    hp = hmac_input;
    memcpy(hp, cmd_digest, TPM12_SHA1_HASH_SIZE); hp += TPM12_SHA1_HASH_SIZE;
    memcpy(hp, osap.nonceEven, TPM12_NONCE_SIZE); hp += TPM12_NONCE_SIZE;
    memcpy(hp, osap.nonceOdd, TPM12_NONCE_SIZE); hp += TPM12_NONCE_SIZE;
    *hp++ = 0;  /* continueSession = FALSE */

    resl = hmac_sha1(osap.sharedSecret, TPM12_SHA1_HASH_SIZE,
                     hmac_input, (u32)(hp - hmac_input),
                     auth_hmac);
    if (resl != ST_OK) {
        goto cleanup;
    }

    /* Append auth block */
    write_be32(p, osap.authHandle); p += 4;
    memcpy(p, osap.nonceOdd, TPM12_NONCE_SIZE); p += TPM12_NONCE_SIZE;
    *p++ = 0;  /* continueSession */
    memcpy(p, auth_hmac, TPM12_SHA1_HASH_SIZE); p += TPM12_SHA1_HASH_SIZE;

    /* Fill in command size */
    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    /* Submit command */
    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        goto cleanup;
    }

    /* Parse response - TPM_STORED_DATA structure (no size prefix) */
    /* tag(2) + size(4) + rc(4) + [TPM_STORED_DATA] + auth */
    if (rsp_size < 14) {
        resl = ST_TPM_ERROR;
        goto cleanup;
    }

    /* Calculate sealed data size by parsing TPM_STORED_DATA:
     * ver(4) + sealInfoSize(4) + sealInfo(var) + encDataSize(4) + encData(var) */
    u8 *resp_data = rsp + 10;
    u32 pos = 0;

    /* ver */
    pos += 4;

    /* sealInfoSize */
    u32 seal_info_size = read_be32(resp_data + pos);
    pos += 4 + seal_info_size;

    /* encDataSize */
    u32 enc_data_size = read_be32(resp_data + pos);
    pos += 4 + enc_data_size;

    if (pos > *sealed_blob_size) {
        resl = ST_SMALL_BUFF;
        goto cleanup;
    }

    memcpy(sealed_blob, resp_data, pos);
    *sealed_blob_size = pos;

    resl = ST_OK;

cleanup:
    burn(&osap, sizeof(osap));
    burn(enc_auth, sizeof(enc_auth));
    burn(xor_mask, sizeof(xor_mask));
    burn(auth_hmac, sizeof(auth_hmac));
    burn(hmac_input, sizeof(hmac_input));
    burn(cmd_digest, sizeof(cmd_digest));
    return resl;
}

/*
 * TPM_Unseal - Unseal data from SRK with dual OIAP auth
 * Matches bootloader's Tpm12UnsealWithAuth()
 */
int tpm12_unseal_with_auth(
    const u8 *sealed_blob,
    u32 sealed_blob_size,
    const u8 *pin_auth,
    u32 pin_auth_size,
    u8 *data,
    u32 *data_size)
{
    u8 cmd[1024];
    u8 rsp[512];
    u32 rsp_size = sizeof(rsp);
    u8 *p;
    u32 cmd_size;
    int resl;
    TPM12_OIAP_SESSION oiap1, oiap2;
    u8 cmd_digest[TPM12_SHA1_HASH_SIZE];
    u8 auth1[TPM12_SHA1_HASH_SIZE];
    u8 auth2[TPM12_SHA1_HASH_SIZE];
    u8 hmac_input[128];
    u8 *hp;
    u8 data_auth[TPM12_SHA1_HASH_SIZE];

    /* Use provided data_auth or well-known zeros */
    if (pin_auth_size > 0) {
        tpm12_sha1_hash(pin_auth, pin_auth_size, data_auth);
    } else {
        memset(data_auth, 0, sizeof(data_auth));
    }

    /* Open two OIAP sessions */
    resl = tpm12_oiap_open(&oiap1);
    if (resl != ST_OK) {
        return resl;
    }

    resl = tpm12_oiap_open(&oiap2);
    if (resl != ST_OK) {
        return resl;
    }

    /* Build TPM_Unseal command */
    p = cmd;
    write_be16(p, TPM12_TAG_RQU_AUTH2_COMMAND); p += 2;
    p += 4;  /* size placeholder */
    write_be32(p, TPM12_ORD_Unseal); p += 4;
    write_be32(p, TPM12_KH_SRK); p += 4;  /* parentHandle (NOT part of hash) */

    /* inData = TPM_STORED_DATA (no size prefix - self-describing) */
    u8 *params_start = p;
    memcpy(p, sealed_blob, sealed_blob_size); p += sealed_blob_size;

    /* Calculate command digest: SHA1(ordinal || inData) */
    {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;

        BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
        BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
        BCryptHashData(hHash, cmd + 6, 4, 0);  /* ordinal */
        BCryptHashData(hHash, params_start, (ULONG)(p - params_start), 0);
        BCryptFinishHash(hHash, cmd_digest, TPM12_SHA1_HASH_SIZE, 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    /* First auth block (SRK - well-known auth) */
    write_be32(p, oiap1.authHandle); p += 4;
    memcpy(p, oiap1.nonceOdd, TPM12_NONCE_SIZE); p += TPM12_NONCE_SIZE;
    *p++ = 0;  /* continueSession = FALSE */

    /* Compute auth1 HMAC */
    hp = hmac_input;
    memcpy(hp, cmd_digest, TPM12_SHA1_HASH_SIZE); hp += TPM12_SHA1_HASH_SIZE;
    memcpy(hp, oiap1.nonceEven, TPM12_NONCE_SIZE); hp += TPM12_NONCE_SIZE;
    memcpy(hp, oiap1.nonceOdd, TPM12_NONCE_SIZE); hp += TPM12_NONCE_SIZE;
    *hp++ = 0;

    resl = hmac_sha1(g_well_known_auth, TPM12_SHA1_HASH_SIZE,
                     hmac_input, (u32)(hp - hmac_input),
                     auth1);
    if (resl != ST_OK) {
        goto cleanup;
    }

    memcpy(p, auth1, TPM12_SHA1_HASH_SIZE); p += TPM12_SHA1_HASH_SIZE;

    /* Second auth block (blob auth) */
    write_be32(p, oiap2.authHandle); p += 4;
    memcpy(p, oiap2.nonceOdd, TPM12_NONCE_SIZE); p += TPM12_NONCE_SIZE;
    *p++ = 0;

    /* Compute auth2 HMAC */
    hp = hmac_input;
    memcpy(hp, cmd_digest, TPM12_SHA1_HASH_SIZE); hp += TPM12_SHA1_HASH_SIZE;
    memcpy(hp, oiap2.nonceEven, TPM12_NONCE_SIZE); hp += TPM12_NONCE_SIZE;
    memcpy(hp, oiap2.nonceOdd, TPM12_NONCE_SIZE); hp += TPM12_NONCE_SIZE;
    *hp++ = 0;

    resl = hmac_sha1(data_auth, TPM12_SHA1_HASH_SIZE,
                     hmac_input, (u32)(hp - hmac_input),
                     auth2);
    if (resl != ST_OK) {
        goto cleanup;
    }

    memcpy(p, auth2, TPM12_SHA1_HASH_SIZE); p += TPM12_SHA1_HASH_SIZE;

    /* Fill in command size */
    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    /* Submit command */
    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        goto cleanup;
    }

    /* Parse response: tag(2) + size(4) + rc(4) + dataSize(4) + data + auth1 + auth2 */
    if (rsp_size < 14) {
        resl = ST_TPM_ERROR;
        goto cleanup;
    }

    u32 out_size = read_be32(rsp + 10);
    if (out_size > *data_size) {
        resl = ST_SMALL_BUFF;
        goto cleanup;
    }

    memcpy(data, rsp + 14, out_size);
    *data_size = out_size;

    resl = ST_OK;

cleanup:
    burn(&oiap1, sizeof(oiap1));
    burn(&oiap2, sizeof(oiap2));
    burn(auth1, sizeof(auth1));
    burn(auth2, sizeof(auth2));
    burn(hmac_input, sizeof(hmac_input));
    burn(cmd_digest, sizeof(cmd_digest));
    return resl;
}


/*
 * Enumerate TPM 1.2 NV entries using TPM_GetCapability
 */
int dc_tpm_12_enum_nv(DC_TPM_NV_ENTRY *entries, u32 *count)
{
    u8 cmd[32];
    u8 rsp[1024];
    u32 rsp_size = sizeof(rsp);
    u32 cmd_size;
    u8 *p;
    int resl;
    u32 max_count;
    u32 found_count = 0;

    if (entries == NULL || count == NULL) {
        return ST_INVALID_PARAM;
    }

    max_count = *count;
    *count = 0;

    resl = dc_tpm_init();
    if (resl != ST_OK) {
        return resl;
    }

    if (g_tpm_version != 1) {
        return ST_NOT_SUPPORTED;
    }

    /*
     * Build TPM_GetCapability command:
     * capArea (4): TPM_CAP_NV_LIST (0x0000000D)
     * subCapSize (4): 0
     */
    p = cmd;
    write_be16(p, TPM12_TAG_RQU_COMMAND); p += 2;
    p += 4;  // Size placeholder
    write_be32(p, TPM12_ORD_GetCapability); p += 4;
    write_be32(p, 0x0000000D); p += 4;  // TPM_CAP_NV_LIST
    write_be32(p, 0); p += 4;  // subCapSize = 0

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        return resl;
    }

    /*
     * Parse response:
     * tag (2) + size (4) + rc (4) + respSize (4) + data
     * data = list of NV indices (4 bytes each)
     */
    if (rsp_size < 14) {
        return ST_OK;  // No entries
    }

    u32 resp_size = read_be32(rsp + 10);
    u8 *resp_data = rsp + 14;

    u32 num_indices = resp_size / 4;
    for (u32 i = 0; i < num_indices && found_count < max_count; i++) {
        u32 nv_index = read_be32(resp_data + i * 4);
        u32 nv_size = 0;
        u32 attrs = 0;
        u32 pcr_r = 0;
        u32 pcr_w = 0;

        if (tpm12_nv_get_details(nv_index, &nv_size, &attrs, &pcr_r, &pcr_w) == ST_OK) {
            entries[found_count].nv_index = nv_index;
            entries[found_count].attributes = attrs;
            entries[found_count].data_size = (u16)nv_size;
            entries[found_count].pcr_mask = pcr_r | pcr_w;  // Combined PCR mask
            entries[found_count].description[0] = L'\0';  // Filled by wrapper
            found_count++;
        }
    }

    *count = found_count;
    return ST_OK;
}


/*
 * Delete TPM 1.2 NV entry by index (low-level, any NV index)
 * nv_index: Full NV index handle to delete
 * owner_pwd: TPM owner password (UTF-16)
 * Returns: ST_OK on success
 */
int dc_tpm_12_delete_nv(u32 nv_index, const wchar_t *owner_pwd)
{
    int resl;
    u8 pcrs[24][TPM12_SHA1_HASH_SIZE];

    resl = dc_tpm_init();
    if (resl != ST_OK) return resl;

    if (g_tpm_version != 1) {
        return ST_NOT_SUPPORTED;
    }

    memset(pcrs, 0, sizeof(pcrs));

    // Define space with size=0 deletes the NV entry
    resl = tpm12_nv_define_space(nv_index, 0, owner_pwd, pcrs, 0, 0, TPM12_NV_PER_OWNERWRITE, NULL);

    return resl;
}
