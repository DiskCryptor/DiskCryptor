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
 * Windows TPM NV Access via TBS API
 *
 * This module implements reading PIN-protected secrets from TPM NV memory.
 * It uses the Windows TPM Base Services (TBS) API for TPM communication.
 */

#include <windows.h>
#include <winioctl.h>
#include <io.h>
#include <stdlib.h>
#include "dcconst.h"
#include "misc.h"
#include "drv_ioctl.h"
#include "tpm_sup.h"
#include "tpm_20.h"
#include "..\crc32.h"

/* Windows CryptoAPI for AES-256-CBC */
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#ifndef BCRYPT_SUCCESS
#define BCRYPT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define TPM_CAP_HANDLES          0x00000001

//////////////////////////////////////////////////////////////////////////
// TPM Operations (NV-based storage mode)
//////////////////////////////////////////////////////////////////////////

/*
 * Read NV data without authentication (for public NV indices)
 * Uses TPM_RS_PW session with empty password.
 * nv_index: NV index to read
 * read_size: number of bytes to read
 * data: output buffer
 * data_size: in: buffer size, out: actual size read
 * Returns: ST_OK on success
 */
static int tpm2_nv_read_no_auth(
    u32 nv_index,
    u16 read_size,
    u8 *data,
    u16 *data_size)
{
    u8 cmd[128];
    u8 rsp[256];
    u32 rsp_size = sizeof(rsp);
    u32 cmd_size;
    u8 *p;
    int resl;

    /*
     * Build TPM2_NV_Read command with empty password auth:
     * Header (10 bytes):
     *   tag (2): TPM_ST_SESSIONS
     *   size (4): total command size
     *   code (4): TPM_CC_NV_Read
     * Handles (8 bytes):
     *   authHandle (4): nv_index
     *   nvIndex (4): nv_index
     * Authorization (13 bytes for empty auth):
     *   authSize (4): 9
     *   session (4): TPM_RS_PW
     *   nonceCaller (2): 0 (empty)
     *   sessionAttributes (1): 0
     *   hmac (2): 0 (empty)
     * Parameters (4 bytes):
     *   size (2): bytes to read
     *   offset (2): 0
     */

    p = cmd;

    // Header
    write_be16(p, TPM_ST_SESSIONS); p += 2;
    p += 4;  // Size placeholder
    write_be32(p, TPM_CC_NV_Read); p += 4;

    // Handles
    write_be32(p, nv_index); p += 4;  // authHandle
    write_be32(p, nv_index); p += 4;  // nvIndex

    // Authorization area
    write_be32(p, 9); p += 4;         // authSize = 9 bytes
    write_be32(p, TPM_RS_PW); p += 4; // session = password
    write_be16(p, 0); p += 2;         // nonceCaller = empty
    *p++ = 0;                          // sessionAttributes = 0
    write_be16(p, 0); p += 2;         // hmac = empty (no password)

    // Parameters
    write_be16(p, read_size); p += 2;  // size to read
    write_be16(p, 0); p += 2;          // offset = 0

    // Fill in total command size
    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    // Submit command
    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        return resl;
    }

    /*
     * Parse response:
     * Header (10 bytes)
     * Parameter size (4 bytes)
     * Data as TPM2B (2 + n bytes)
     */
    if (rsp_size < 16) {
        return ST_TPM_ERROR;
    }

    // Skip to data (after header + param size)
    u8 *rsp_data = rsp + 10;
    u32 param_size = read_be32(rsp_data);
    rsp_data += 4;

    u16 returned_size = read_be16(rsp_data);
    rsp_data += 2;

    if (returned_size > *data_size) {
        return ST_SMALL_BUFF;
    }

    memcpy(data, rsp_data, returned_size);
    *data_size = returned_size;

    return ST_OK;
}


/*
 * Start a policy session for PCR-bound NV access
 * Returns session handle in session_handle
 */
static int tpm2_start_policy_session(u32 *session_handle)
{
    u8 cmd[128];
    u8 rsp[256];
    u32 rsp_size = sizeof(rsp);
    u32 cmd_size;
    u8 *p;
    int resl;

    /*
     * Build TPM2_StartAuthSession command:
     * Header (10 bytes):
     *   tag (2): TPM_ST_NO_SESSIONS
     *   size (4): total command size
     *   code (4): TPM_CC_StartAuthSession
     * Parameters:
     *   tpmKey (4): TPM_RH_NULL (unbound session)
     *   bind (4): TPM_RH_NULL (unbound session)
     *   nonceCaller (2+32): 32-byte random nonce
     *   encryptedSalt (2+0): empty (no salt)
     *   sessionType (1): TPM_SE_POLICY
     *   symmetric (4): TPM_ALG_NULL
     *   authHash (2): TPM_ALG_SHA256
     */
    p = cmd;

    // Header
    write_be16(p, TPM_ST_NO_SESSIONS); p += 2;
    p += 4;  // Size placeholder
    write_be32(p, TPM_CC_StartAuthSession); p += 4;

    // tpmKey = TPM_RH_NULL (unbound)
    write_be32(p, TPM_RH_NULL); p += 4;

    // bind = TPM_RH_NULL (unbound)
    write_be32(p, TPM_RH_NULL); p += 4;

    // nonceCaller - use a simple nonce (32 bytes of 0x01)
    // In production, this should be random
    write_be16(p, 32); p += 2;
    memset(p, 0x01, 32);
    p += 32;

    // encryptedSalt = empty
    write_be16(p, 0); p += 2;

    // sessionType = TPM_SE_POLICY
    *p++ = TPM_SE_POLICY;

    // symmetric = TPM_ALG_NULL (no encryption)
    write_be16(p, TPM_ALG_NULL); p += 2;

    // authHash = TPM_ALG_SHA256
    write_be16(p, TPM_ALG_SHA256); p += 2;

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        return resl;
    }

    /*
     * Parse response:
     * Header (10 bytes)
     * sessionHandle (4 bytes)
     * nonceTPM (TPM2B)
     */
    if (rsp_size < 14) {
        return ST_TPM_ERROR;
    }

    *session_handle = read_be32(rsp + 10);
    return ST_OK;
}


/*
 * Execute TPM2_PolicyPCR to extend policy session with PCR values
 * session_handle: policy session handle
 * pcr_mask: bitmask of PCRs to include (e.g., 0x07 = PCRs 0,1,2)
 */
static int tpm2_policy_pcr(u32 session_handle, u32 pcr_mask)
{
    u8 cmd[128];
    u8 rsp[256];
    u32 rsp_size = sizeof(rsp);
    u32 cmd_size;
    u8 *p;
    int resl;

    /*
     * Build TPM2_PolicyPCR command:
     * Header (10 bytes):
     *   tag (2): TPM_ST_NO_SESSIONS
     *   size (4): total command size
     *   code (4): TPM_CC_PolicyPCR
     * Parameters:
     *   policySession (4): session handle
     *   pcrDigest (2+0): empty (use current PCR values)
     *   pcrs (TPML_PCR_SELECTION):
     *     count (4): 1
     *     pcrSelection[0]:
     *       hash (2): TPM_ALG_SHA256
     *       sizeofSelect (1): 3
     *       pcrSelect (3): bitmap
     */
    p = cmd;

    // Header
    write_be16(p, TPM_ST_NO_SESSIONS); p += 2;
    p += 4;  // Size placeholder
    write_be32(p, TPM_CC_PolicyPCR); p += 4;

    // policySession
    write_be32(p, session_handle); p += 4;

    // pcrDigest = empty (use current PCR values, not expected values)
    write_be16(p, 0); p += 2;

    // pcrs (TPML_PCR_SELECTION)
    write_be32(p, 1); p += 4;  // count = 1

    // pcrSelection[0]
    write_be16(p, TPM_ALG_SHA256); p += 2;  // hash = SHA256
    *p++ = 3;  // sizeofSelect = 3 bytes (for PCRs 0-23)

    // pcrSelect bitmap - convert mask to bytes
    // PCRs 0-7 in byte 0, 8-15 in byte 1, 16-23 in byte 2
    *p++ = (u8)(pcr_mask & 0xFF);
    *p++ = (u8)((pcr_mask >> 8) & 0xFF);
    *p++ = (u8)((pcr_mask >> 16) & 0xFF);

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        return resl;
    }

    // Response is just the header (10 bytes) with RC_SUCCESS
    return ST_OK;
}


/*
 * Execute TPM2_PolicyPassword to allow password auth in policy session
 * This is used when both PCR and PIN are required
 */
static int tpm2_policy_password(u32 session_handle)
{
    u8 cmd[32];
    u8 rsp[64];
    u32 rsp_size = sizeof(rsp);
    u32 cmd_size;
    u8 *p;
    int resl;

    /*
     * Build TPM2_PolicyPassword command:
     * Header (10 bytes):
     *   tag (2): TPM_ST_NO_SESSIONS
     *   size (4): total command size
     *   code (4): TPM_CC_PolicyPassword
     * Parameters:
     *   policySession (4): session handle
     */
    p = cmd;

    // Header
    write_be16(p, TPM_ST_NO_SESSIONS); p += 2;
    p += 4;  // Size placeholder
    write_be32(p, TPM_CC_PolicyPassword); p += 4;

    // policySession
    write_be32(p, session_handle); p += 4;

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        return resl;
    }

    return ST_OK;
}


/*
 * Get the policy digest from a policy session
 * session_handle: policy session handle
 * policy_digest: output buffer (32 bytes for SHA256)
 */
static int tpm2_policy_get_digest(u32 session_handle, u8 *policy_digest)
{
    u8 cmd[32];
    u8 rsp[128];
    u32 rsp_size = sizeof(rsp);
    u32 cmd_size;
    u8 *p;
    int resl;

    /*
     * Build TPM2_PolicyGetDigest command:
     * Header (10 bytes):
     *   tag (2): TPM_ST_NO_SESSIONS
     *   size (4): total command size
     *   code (4): TPM_CC_PolicyGetDigest
     * Parameters:
     *   policySession (4): session handle
     */
    p = cmd;

    // Header
    write_be16(p, TPM_ST_NO_SESSIONS); p += 2;
    p += 4;  // Size placeholder
    write_be32(p, TPM_CC_PolicyGetDigest); p += 4;

    // policySession
    write_be32(p, session_handle); p += 4;

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        return resl;
    }

    /*
     * Parse response:
     * Header (10 bytes)
     * policyDigest (TPM2B_DIGEST): 2 + 32 bytes for SHA256
     */
    if (rsp_size < 44) {
        return ST_TPM_ERROR;
    }

    u16 digest_size = read_be16(rsp + 10);
    if (digest_size != 32) {
        return ST_TPM_ERROR;  // Expected SHA256 digest
    }

    memcpy(policy_digest, rsp + 12, 32);
    return ST_OK;
}


/*
 * Compute policy digest for PCR + optional PIN policy
 * Uses a trial session to compute what the policy digest will be
 * pcr_mask: PCR mask (must be != 0)
 * pin_required: whether PIN auth is also required
 * policy_digest: output buffer (32 bytes for SHA256)
 */
static int tpm2_compute_policy_digest(u32 pcr_mask, BOOL pin_required, u8 *policy_digest)
{
    u32 session_handle = 0;
    int resl;
    u8 cmd[128];
    u8 rsp[256];
    u32 rsp_size;
    u32 cmd_size;
    u8 *p;

    /*
     * Start a TRIAL policy session
     * Trial sessions compute the policy digest without requiring satisfaction
     */
    p = cmd;

    // Header
    write_be16(p, TPM_ST_NO_SESSIONS); p += 2;
    p += 4;  // Size placeholder
    write_be32(p, TPM_CC_StartAuthSession); p += 4;

    // tpmKey = TPM_RH_NULL (unbound)
    write_be32(p, TPM_RH_NULL); p += 4;

    // bind = TPM_RH_NULL (unbound)
    write_be32(p, TPM_RH_NULL); p += 4;

    // nonceCaller - 32 bytes
    write_be16(p, 32); p += 2;
    memset(p, 0x02, 32);  // Different nonce from regular session
    p += 32;

    // encryptedSalt = empty
    write_be16(p, 0); p += 2;

    // sessionType = TPM_SE_TRIAL
    *p++ = TPM_SE_TRIAL;

    // symmetric = TPM_ALG_NULL (no encryption)
    write_be16(p, TPM_ALG_NULL); p += 2;

    // authHash = TPM_ALG_SHA256
    write_be16(p, TPM_ALG_SHA256); p += 2;

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    rsp_size = sizeof(rsp);
    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        return resl;
    }

    if (rsp_size < 14) {
        return ST_TPM_ERROR;
    }

    session_handle = read_be32(rsp + 10);

    // Apply PolicyPCR to the trial session
    resl = tpm2_policy_pcr(session_handle, pcr_mask);
    if (resl != ST_OK) {
        tpm2_flush_context(session_handle);
        return resl;
    }

    // Apply PolicyPassword if PIN is required
    if (pin_required) {
        resl = tpm2_policy_password(session_handle);
        if (resl != ST_OK) {
            tpm2_flush_context(session_handle);
            return resl;
        }
    }

    // Get the computed policy digest
    resl = tpm2_policy_get_digest(session_handle, policy_digest);

    // Clean up trial session
    tpm2_flush_context(session_handle);

    return resl;
}


/*
 * Read NV data using a policy session (for PCR-bound NV indices)
 * session_handle: policy session (already has PolicyPCR and optionally PolicyPassword applied)
 * nv_index: NV index to read
 * pin_auth: PIN auth data (can be NULL if no PIN required)
 * pin_size: size of PIN auth data
 * data: output buffer
 * data_size: in: buffer size, out: actual size read
 */
static int tpm2_nv_read_with_policy(
    u32 session_handle,
    u32 nv_index,
    const u8 *pin_auth,
    u16 pin_size,
    u8 *data,
    u16 *data_size)
{
    u8 cmd[256];
    u8 rsp[1024];
    u32 rsp_size = sizeof(rsp);
    u32 cmd_size;
    u8 *p;
    int resl;
    u16 read_size = *data_size;

    /*
     * Build TPM2_NV_Read command with policy session:
     * Header (10 bytes):
     *   tag (2): TPM_ST_SESSIONS
     *   size (4): total command size
     *   code (4): TPM_CC_NV_Read
     * Handles (8 bytes):
     *   authHandle (4): nv_index
     *   nvIndex (4): nv_index
     * Authorization (variable):
     *   authSize (4): size of auth area
     *   session (4): policy session handle
     *   nonceCaller (2+0): empty
     *   sessionAttributes (1): continueSession = 0
     *   hmac (2+n): PIN auth if PolicyPassword was used
     * Parameters:
     *   size (2): bytes to read
     *   offset (2): 0
     */
    p = cmd;

    // Header
    write_be16(p, TPM_ST_SESSIONS); p += 2;
    p += 4;  // Size placeholder
    write_be32(p, TPM_CC_NV_Read); p += 4;

    // Handles
    write_be32(p, nv_index); p += 4;  // authHandle
    write_be32(p, nv_index); p += 4;  // nvIndex

    // Authorization area size (filled later)
    u8 *auth_size_ptr = p;
    p += 4;

    // Session: policy session handle
    write_be32(p, session_handle); p += 4;

    // nonceCaller: empty TPM2B
    write_be16(p, 0); p += 2;

    // sessionAttributes: 0 (don't continue session)
    *p++ = 0;

    // hmac: PIN auth data as TPM2B (used if PolicyPassword was applied)
    write_be16(p, pin_size); p += 2;
    if (pin_size > 0 && pin_auth != NULL) {
        memcpy(p, pin_auth, pin_size);
        p += pin_size;
    }

    // Fill in auth area size
    u32 auth_size = (u32)(p - auth_size_ptr - 4);
    write_be32(auth_size_ptr, auth_size);

    // Parameters
    write_be16(p, read_size); p += 2;  // size to read
    write_be16(p, 0); p += 2;  // offset

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        return resl;
    }

    /*
     * Parse response:
     * Header (10 bytes)
     * Parameter size (4 bytes)
     * Data as TPM2B (2 + n bytes)
     */
    if (rsp_size < 16) {
        return ST_TPM_ERROR;
    }

    // Skip to data (after header + param size)
    u8 *rsp_data = rsp + 10;
    u32 param_size = read_be32(rsp_data);
    rsp_data += 4;

    u16 returned_size = read_be16(rsp_data);
    rsp_data += 2;

    if (returned_size > *data_size) {
        return ST_SMALL_BUFF;
    }

    memcpy(data, rsp_data, returned_size);
    *data_size = returned_size;

    return ST_OK;
}


/*
 * Read NV data with password authentication (PIN-only backup)
 * This is used when PcrMask == 0 (no PCR requirement)
 */
static int tpm2_nv_read_with_password(
    u32 nv_index,
    const u8 *pin_auth,
    u16 pin_size,
    u8 *data,
    u16 *data_size)
{
    u8 cmd[256];
    u8 rsp[1024];
    u32 rsp_size = sizeof(rsp);
    u32 cmd_size;
    u8 *p;
    int resl;
    u16 read_size = *data_size;  // Use input size as read size

    /*
     * Build TPM2_NV_Read command:
     * Header (10 bytes):
     *   tag (2): TPM_ST_SESSIONS
     *   size (4): total command size
     *   code (4): TPM_CC_NV_Read
     * Handles (8 bytes):
     *   authHandle (4): nv_index
     *   nvIndex (4): nv_index
     * Authorization (variable):
     *   authSize (4): size of auth area
     *   session (4): TPM_RS_PW
     *   nonceCaller (2+0): empty
     *   sessionAttributes (1): 0
     *   hmac (2+n): PIN auth data
     * Parameters:
     *   size (2): bytes to read
     *   offset (2): 0
     */

    p = cmd;

    // Header
    write_be16(p, TPM_ST_SESSIONS); p += 2;
    p += 4;  // Size placeholder
    write_be32(p, TPM_CC_NV_Read); p += 4;

    // Handles
    write_be32(p, nv_index); p += 4;  // authHandle
    write_be32(p, nv_index); p += 4;  // nvIndex

    // Authorization area size (filled later)
    u8 *auth_size_ptr = p;
    p += 4;

    // Session: TPM_RS_PW
    write_be32(p, TPM_RS_PW); p += 4;

    // nonceCaller: empty TPM2B
    write_be16(p, 0); p += 2;

    // sessionAttributes: 0 (continue session = no)
    *p++ = 0;

    // hmac: PIN auth data as TPM2B
    write_be16(p, pin_size); p += 2;
    if (pin_size > 0 && pin_auth != NULL) {
        memcpy(p, pin_auth, pin_size);
        p += pin_size;
    }

    // Fill in auth area size
    u32 auth_size = (u32)(p - auth_size_ptr - 4);
    write_be32(auth_size_ptr, auth_size);

    // Parameters
    write_be16(p, read_size); p += 2;  // size to read
    write_be16(p, 0); p += 2;  // offset

    // Fill in total command size
    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    // Submit command
    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        return resl;
    }

    /*
     * Parse response:
     * Header (10 bytes)
     * Parameter size (4 bytes)
     * Data as TPM2B (2 + n bytes)
     */
    if (rsp_size < 16) {
        return ST_TPM_ERROR;
    }

    // Skip to data (after header + param size)
    u8 *rsp_data = rsp + 10;
    u32 param_size = read_be32(rsp_data);
    rsp_data += 4;

    u16 returned_size = read_be16(rsp_data);
    rsp_data += 2;

    if (returned_size > *data_size) {
        return ST_SMALL_BUFF;
    }

    memcpy(data, rsp_data, returned_size);
    *data_size = returned_size;

    return ST_OK;
}


/* Forward declaration */
static int tpm2_nv_read_public(u32 nv_index, u32 *nv_size, u32 *nv_attributes);

/*
 * Read the PCR info for an NV index from the associated PCR NV entry
 * The PCR info is stored in a separate NV index: (nv_index | DC_TPM_NV_INDEX_PCR_FLAG)
 * This NV entry should be readable without authentication.
 *
 * nv_index: base NV index (not the PCR index)
 * pcr_mask: output for PCR mask (can be NULL)
 * flags: output for flags (DC_TPM_FLAG_*, can be NULL)
 * info_buffer: optional output buffer for info data (can be NULL)
 * info_size: in/out - on input: buffer size, on output: actual info size (can be NULL)
 * Returns: ST_OK on success, or error code. If NV doesn't exist, returns ST_OK with *pcr_mask=0, *flags=0
 */
static int tpm2_nv_read_pcr_info(u32 nv_index, u32 *pcr_mask, u32 *flags, u8 *info_buffer, u32 *info_size)
{
    u32 pcr_nv_index = nv_index | DC_TPM_NV_INDEX_PCR_FLAG;
    u32 nv_data_size = 0;
    u8 header_buf[DC_TPM_PCRINFO_BASE_SIZE];
    u16 header_read_size;
    int resl;

    // Initialize outputs
    if (pcr_mask != NULL) *pcr_mask = 0;
    if (flags != NULL) *flags = 0;
    if (info_size != NULL) *info_size = 0;

    // First, check the NV index size
    resl = tpm2_nv_read_public(pcr_nv_index, &nv_data_size, NULL);
    if (resl != ST_OK) {
        // NV index doesn't exist - no PCR info
        return ST_OK;
    }

    if (nv_data_size < DC_TPM_PCRINFO_BASE_SIZE) {
        // Invalid/too small entry
        return ST_OK;
    }

    // Read the header portion of DC_TPM_PCRINFO_DATA
    header_read_size = DC_TPM_PCRINFO_BASE_SIZE;
    resl = tpm2_nv_read_no_auth(pcr_nv_index, header_read_size, header_buf, &header_read_size);
    if (resl != ST_OK || header_read_size < DC_TPM_PCRINFO_BASE_SIZE) {
        // Read failed
        return ST_OK;
    }

    // Parse header (native little-endian, matching bootloader format)
    DC_TPM_PCRINFO_DATA *pcrInfo = (DC_TPM_PCRINFO_DATA *)header_buf;
    u32 magic = pcrInfo->Magic;
    u16 version = pcrInfo->Version;
    u16 stored_info_size = pcrInfo->InfoSize;
    u32 stored_pcr_mask = pcrInfo->PcrMask;
    u32 stored_flags = pcrInfo->Flags;

    // Validate magic
    if (magic != DC_TPM_PCRINFO_MAGIC) {
        // Invalid magic - not a valid PCR info structure
        return ST_OK;
    }

    // Return values
    if (pcr_mask != NULL) *pcr_mask = stored_pcr_mask;
    if (flags != NULL) *flags = stored_flags;

    // Check for info data
    if (info_buffer != NULL && info_size != NULL && stored_info_size > 0) {
        u16 buffer_size = (u16)*info_size;
        u16 copy_size = (stored_info_size <= buffer_size) ? stored_info_size : buffer_size;

        if (copy_size > 0 && nv_data_size >= (u32)(DC_TPM_PCRINFO_BASE_SIZE + stored_info_size)) {
            // Read the full structure including info data
            u16 full_size = (u16)(DC_TPM_PCRINFO_BASE_SIZE + stored_info_size);
            u8 *full_data = (u8*)malloc(full_size);
            if (full_data != NULL) {
                u16 full_read = full_size;
                resl = tpm2_nv_read_no_auth(pcr_nv_index, full_size, full_data, &full_read);
                if (resl == ST_OK && full_read >= DC_TPM_PCRINFO_BASE_SIZE + copy_size) {
                    memcpy(info_buffer, full_data + DC_TPM_PCRINFO_BASE_SIZE, copy_size);
                    *info_size = copy_size;
                }
                free(full_data);
            }
        }
    }

    return ST_OK;
}


/*
 * Unseal password from TPM NV with PIN authentication
 * nv_index: DC_TPM2_NV_INDEX_DEFAULT or DC_TPM2_NV_INDEX_BACKUP
 * pin: PIN string (UTF-16, used for NV authentication)
 * password: output buffer for password
 * password_size: in/out buffer size
 * password_type: output password type
 * Returns: ST_OK on success
 */
int dc_tpm_20_nv_unseal_password(
    u32 nv_index,
    const u8 *pin_auth,
    u32 pin_auth_size,
    void *password,
    u32 *password_size,
    u32 *password_type)
{
    u8 sealed_buffer[DC_TPM_SRK_SEALED_BLOB_MAX];
    DC_TPM_SEALED_DATA *sealed_data = (DC_TPM_SEALED_DATA *)sealed_buffer;
    u32 nv_size = 0;
    u16 sealed_size;
    u32 pcr_mask = 0;
    u32 flags = 0;
    u32 crc;
    int resl;

    // Initialize TPM if not already done
    resl = dc_tpm_init();
    if (resl != ST_OK) {
        return resl;
    }

    // Only TPM 2.0 is supported for PIN backup
    if (g_tpm_version != 2) {
        return ST_NOT_SUPPORTED;
    }

    // Query NV size first
    resl = tpm2_nv_read_public(nv_index, &nv_size, NULL);
    if (resl != ST_OK) {
        return resl;
    }
    if (nv_size < DC_TPM_SEALED_MIN_SIZE || nv_size > sizeof(sealed_buffer)) {
        return ST_FORMAT_ERR;
    }
    sealed_size = (u16)nv_size;

    // Try to read PCR info from the associated NV index
    // This tells us whether PIN and/or PCR policy is required
    resl = tpm2_nv_read_pcr_info(nv_index, &pcr_mask, &flags, NULL, NULL);
    if (resl != ST_OK) {
        return resl;
    }

    // Extract PIN requirement
    BOOL pin_required = (flags & DC_TPM_FLAG_PIN_REQUIRED) != 0;

    // Prepare PIN authentication data
    if (pin_required) {
        if (pin_auth_size == 0) {
            // PIN is required but not provided
            return ST_PASS_ERR;
        }
    }

    // Read NV data using appropriate method based on PCR mask
    if (pcr_mask != 0) {
        // PCR policy is required - use policy session
        u32 session_handle = 0;

        // Start a policy session
        resl = tpm2_start_policy_session(&session_handle);
        if (resl != ST_OK) {
            return resl;
        }

        // Apply PCR policy - this binds the session to current PCR values
        resl = tpm2_policy_pcr(session_handle, pcr_mask);
        if (resl != ST_OK) {
            tpm2_flush_context(session_handle);
            return resl;
        }

        // If PIN is also required, apply PolicyPassword
        // This allows the HMAC field to carry the PIN auth
        if (pin_required) {
            resl = tpm2_policy_password(session_handle);
            if (resl != ST_OK) {
                tpm2_flush_context(session_handle);
                return resl;
            }
        }

        // Read NV data using the policy session
        resl = tpm2_nv_read_with_policy(
            session_handle,
            nv_index,
            pin_auth,
            (u16)pin_auth_size,
            sealed_buffer,
            &sealed_size);

        // Clean up session (even if read failed)
        tpm2_flush_context(session_handle);
    } else {
        // No PCR requirement - use simple password authentication
        resl = tpm2_nv_read_with_password(
            nv_index,
            pin_auth,
            (u16)pin_auth_size,
            sealed_buffer,
            &sealed_size);
    }

    if (resl != ST_OK) {
        return resl;
    }

    // Validate sealed data
    if (sealed_size < DC_TPM_SEALED_MIN_SIZE || sealed_data->Magic != DC_TPM_SEALED_MAGIC) {
        burn(sealed_buffer, sizeof(sealed_buffer));
        return ST_FORMAT_ERR;
    }

    if (sealed_data->Version != DC_TPM_SEALED_VERSION) {
        burn(sealed_buffer, sizeof(sealed_buffer));
        return ST_INCOMPATIBLE;
    }

    // Validate password size fits within read data
    if (sealed_data->PasswordSize > sealed_size - DC_TPM_SEALED_BASE_SIZE) {
        burn(sealed_buffer, sizeof(sealed_buffer));
        return ST_FORMAT_ERR;
    }

    // Verify CRC
    crc = crc32(sealed_data->Password, sealed_data->PasswordSize);
    if (crc != sealed_data->Checksum) {
        burn(sealed_buffer, sizeof(sealed_buffer));
        return ST_FORMAT_ERR;
    }

    // Copy password to output
    if (sealed_data->PasswordSize > *password_size) {
        burn(sealed_buffer, sizeof(sealed_buffer));
        return ST_SMALL_BUFF;
    }

    memcpy(password, sealed_data->Password, sealed_data->PasswordSize);
    *password_size = sealed_data->PasswordSize;

    if (password_type != NULL) {
        *password_type = sealed_data->PasswordType;
    }

    // Clean up
    burn(sealed_buffer, sizeof(sealed_buffer));

    return ST_OK;
}


/*
 * Read NV public area to check if index exists
 * Returns: ST_OK if exists, ST_TPM_NV_NOT_FOUND if not, error otherwise
 */
static int tpm2_nv_read_public(u32 nv_index, u32 *nv_size, u32 *nv_attributes)
{
    u8 cmd[32];
    u8 rsp[256];
    u32 rsp_size = sizeof(rsp);
    u32 cmd_size;
    u8 *p;
    int resl;

    /*
     * Build TPM2_NV_ReadPublic command:
     * Header (10 bytes):
     *   tag (2): TPM_ST_NO_SESSIONS
     *   size (4): total command size
     *   code (4): TPM_CC_NV_ReadPublic
     * Parameters:
     *   nvIndex (4): NV index to query
     */
    p = cmd;
    write_be16(p, TPM_ST_NO_SESSIONS); p += 2;
    p += 4;  // Size placeholder
    write_be32(p, TPM_CC_NV_ReadPublic); p += 4;
    write_be32(p, nv_index); p += 4;

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        return resl;
    }

    /*
     * Parse response:
     * Header (10 bytes)
     * nvPublic as TPM2B_NV_PUBLIC:
     *   size (2)
     *   nvIndex (4)
     *   nameAlg (2)
     *   attributes (4)
     *   authPolicy size (2)
     *   authPolicy data (variable)
     *   dataSize (2)
     */
    if (rsp_size < 22) {
        return ST_TPM_ERROR;
    }

    u8 *rsp_data = rsp + 10;
    u16 pub_size = read_be16(rsp_data);
    rsp_data += 2;

    if (pub_size >= 12) {
        // Skip nvIndex (4) and nameAlg (2)
        rsp_data += 6;
        if (nv_attributes) {
            *nv_attributes = read_be32(rsp_data);
        }
        rsp_data += 4;
        // Skip authPolicy
        u16 policy_size = read_be16(rsp_data);
        rsp_data += 2 + policy_size;
        if (nv_size) {
            *nv_size = read_be16(rsp_data);
        }
    }

    return ST_OK;
}


/*
 * Check if a specific NV index exists
 * nv_index: DC_TPM2_NV_INDEX_DEFAULT or DC_TPM2_NV_INDEX_BACKUP
 * Returns: 1 if exists, 0 otherwise
 */
int dc_tpm_20_nv_exists(u32 nv_index)
{
    int resl;

    resl = dc_tpm_init();
    if (resl != ST_OK) {
        return 0;
    }

    if (g_tpm_version != 2) {
        return 0;
    }

    resl = tpm2_nv_read_public(nv_index, NULL, NULL);
    return (resl == ST_OK) ? 1 : 0;
}


/*
 * Get a single TPM property value
 */
static int tpm2_get_property(u32 property, u32 *value)
{
    u8 cmd[32];
    u8 rsp[128];
    u32 rsp_size = sizeof(rsp);
    u32 cmd_size;
    u8 *p;
    int resl;

    /*
     * Build TPM2_GetCapability command:
     * Header (10 bytes)
     * capability (4): TPM_CAP_TPM_PROPERTIES
     * property (4): property to query
     * propertyCount (4): 1
     */
    p = cmd;
    write_be16(p, TPM_ST_NO_SESSIONS); p += 2;
    p += 4;  // Size placeholder
    write_be32(p, TPM_CC_GetCapability); p += 4;
    write_be32(p, TPM_CAP_TPM_PROPERTIES); p += 4;
    write_be32(p, property); p += 4;
    write_be32(p, 1); p += 4;  // propertyCount = 1

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        return resl;
    }

    /*
     * Parse response:
     * Header (10 bytes)
     * moreData (1)
     * capabilityData:
     *   capability (4)
     *   tpmProperties:
     *     count (4)
     *     tpmProperty[0]:
     *       property (4)
     *       value (4)
     */
    if (rsp_size < 27) {
        return ST_TPM_ERROR;
    }

    u8 *rsp_data = rsp + 10;
    // Skip moreData (1), capability (4), count (4), property (4)
    rsp_data += 13;
    *value = read_be32(rsp_data);

    return ST_OK;
}


/*
 * Get TPM information (vendor, firmware, lockout status)
 */
int dc_tpm_20_get_info(DC_TPM_INFO *info)
{
    int resl;
    u32 val;

    if (info == NULL) {
        return ST_ERROR;
    }

    memset(info, 0, sizeof(DC_TPM_INFO));

    resl = dc_tpm_init();
    if (resl != ST_OK) {
        return resl;
    }

    info->version = g_tpm_version;

    if (g_tpm_version != 2) {
        return ST_OK;  // Only TPM 2.0 supports GetCapability
    }

    // Get manufacturer
    if (tpm2_get_property(TPM_PT_MANUFACTURER, &val) == ST_OK) {
        info->vendor_id = val;
        // Convert to string (4 ASCII chars)
        info->vendor_str[0] = (char)(val >> 24);
        info->vendor_str[1] = (char)(val >> 16);
        info->vendor_str[2] = (char)(val >> 8);
        info->vendor_str[3] = (char)(val);
        info->vendor_str[4] = '\0';
    }

    // Get firmware version
    if (tpm2_get_property(TPM_PT_FIRMWARE_VERSION_1, &val) == ST_OK) {
        info->firmware_v1 = val;
    }
    if (tpm2_get_property(TPM_PT_FIRMWARE_VERSION_2, &val) == ST_OK) {
        info->firmware_v2 = val;
    }

    // Get lockout info
    if (tpm2_get_property(TPM_PT_LOCKOUT_COUNTER, &val) == ST_OK) {
        info->lockout_counter = val;
    }
    if (tpm2_get_property(TPM_PT_MAX_AUTH_FAIL, &val) == ST_OK) {
        info->lockout_max = val;
    }
    if (tpm2_get_property(TPM_PT_LOCKOUT_INTERVAL, &val) == ST_OK) {
        info->lockout_interval = val;
    }
    if (tpm2_get_property(TPM_PT_LOCKOUT_RECOVERY, &val) == ST_OK) {
        info->lockout_recovery = val;
    }

    // Determine if TPM is currently in DA lockout
    // TPM is locked out when lockout_counter >= lockout_max (and lockout_max > 0)
    info->is_locked_out = (info->lockout_max > 0 && info->lockout_counter >= info->lockout_max) ? 1 : 0;

    return ST_OK;
}


/*
 * Get PCR info for an NV index
 * Reads the PCR mask, flags, and optional info data from the associated PCR NV entry.
 */
int dc_tpm_20_nv_get_info(
    u32 nv_index,
    u32 *pcr_mask,
    u32 *flags,
    void *info_buffer,
    u32 *info_size)
{
    int resl;

    resl = dc_tpm_init();
    if (resl != ST_OK) {
        return resl;
    }

    if (g_tpm_version != 2) {
        return ST_NOT_SUPPORTED;
    }

    return tpm2_nv_read_pcr_info(nv_index, pcr_mask, flags, (u8*)info_buffer, info_size);
}


/*
 * Write PCR info to the associated PCR NV entry
 * This stores the PCR mask, flags, and optional info data using DC_TPM_PCRINFO_DATA format
 * info_buffer: optional info data to store (can be NULL)
 * info_size: size of info data (0 if none)
 */
static int tpm2_nv_write_pcr_info(u32 nv_index, u32 pcr_mask, u32 flags, const u8 *info_buffer, u32 info_size)
{
    u8 cmd[1024];  // Larger buffer to accommodate info data
    u8 rsp[256];
    u32 rsp_size;
    u32 cmd_size;
    u8 *p;
    int resl;
    u32 pcr_nv_index = nv_index | DC_TPM_NV_INDEX_PCR_FLAG;
    u8 *pcr_info_data = NULL;
    u16 total_data_size;

    // Validate info_size
    if (info_size > DC_TPM_INFO_MAX_SIZE) {
        return ST_SMALL_BUFF;
    }

    // Calculate total data size
    total_data_size = DC_TPM_PCRINFO_BASE_SIZE + (u16)info_size;

    // Allocate buffer for PCR info data
    pcr_info_data = (u8*)malloc(total_data_size);
    if (pcr_info_data == NULL) {
        return ST_NOMEM;
    }
    memset(pcr_info_data, 0, total_data_size);  // Zero fill like bootloader

    // Build DC_TPM_PCRINFO_DATA structure (native little-endian, matching bootloader)
    DC_TPM_PCRINFO_DATA *pcrInfoStruct = (DC_TPM_PCRINFO_DATA *)pcr_info_data;
    pcrInfoStruct->Magic = DC_TPM_PCRINFO_MAGIC;
    pcrInfoStruct->Version = DC_TPM_PCRINFO_VERSION;
    pcrInfoStruct->InfoSize = (u16)info_size;
    pcrInfoStruct->PcrMask = pcr_mask;
    pcrInfoStruct->Flags = flags;

    // Copy info data if provided
    if (info_buffer != NULL && info_size > 0) {
        memcpy(pcr_info_data + DC_TPM_PCRINFO_BASE_SIZE, info_buffer, info_size);
    }

    // Check if NV index already exists - if so, undefine it first
    if (tpm2_nv_read_public(pcr_nv_index, NULL, NULL) == ST_OK) {
        p = cmd;
        write_be16(p, TPM_ST_SESSIONS); p += 2;
        p += 4;
        write_be32(p, TPM_CC_NV_UndefineSpace); p += 4;
        write_be32(p, TPM_RH_OWNER); p += 4;
        write_be32(p, pcr_nv_index); p += 4;
        write_be32(p, 9); p += 4;
        write_be32(p, TPM_RS_PW); p += 4;
        write_be16(p, 0); p += 2;
        *p++ = 0;
        write_be16(p, 0); p += 2;
        cmd_size = (u32)(p - cmd);
        write_be32(cmd + 2, cmd_size);
        rsp_size = sizeof(rsp);
        tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    }

    // Define the PCR info NV space (public readable, owner writable)
    p = cmd;
    write_be16(p, TPM_ST_SESSIONS); p += 2;
    p += 4;
    write_be32(p, TPM_CC_NV_DefineSpace); p += 4;
    write_be32(p, TPM_RH_OWNER); p += 4;
    write_be32(p, 9); p += 4;
    write_be32(p, TPM_RS_PW); p += 4;
    write_be16(p, 0); p += 2;
    *p++ = 0;
    write_be16(p, 0); p += 2;
    write_be16(p, 0); p += 2;  // auth (empty - public read)

    u8 *pub_size_ptr = p;
    p += 2;
    write_be32(p, pcr_nv_index); p += 4;
    write_be16(p, TPM_ALG_SHA256); p += 2;
    // Match bootloader: OWNERREAD | OWNERWRITE | AUTHREAD | NO_DA
    u32 nv_attrs = TPMA_NV_OWNERREAD | TPMA_NV_OWNERWRITE | TPMA_NV_AUTHREAD | TPMA_NV_NO_DA;
    write_be32(p, nv_attrs); p += 4;
    write_be16(p, 0); p += 2;  // authPolicy
    write_be16(p, total_data_size); p += 2;  // dataSize
    write_be16(pub_size_ptr, (u16)(p - pub_size_ptr - 2));

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    rsp_size = sizeof(rsp);
    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        return resl;
    }

    // Write the PCR info data
    p = cmd;
    write_be16(p, TPM_ST_SESSIONS); p += 2;
    p += 4;
    write_be32(p, TPM_CC_NV_Write); p += 4;
    write_be32(p, TPM_RH_OWNER); p += 4;  // authHandle = owner (for OWNERWRITE)
    write_be32(p, pcr_nv_index); p += 4;
    write_be32(p, 9); p += 4;
    write_be32(p, TPM_RS_PW); p += 4;
    write_be16(p, 0); p += 2;
    *p++ = 0;
    write_be16(p, 0); p += 2;
    write_be16(p, total_data_size); p += 2;  // data size
    memcpy(p, pcr_info_data, total_data_size); p += total_data_size;
    write_be16(p, 0); p += 2;  // offset

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    free(pcr_info_data);

    rsp_size = sizeof(rsp);
    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);

    return resl;
}


/*
 * Create a new NV entry with PIN and/or PCR protection
 * nv_index: DC_TPM2_NV_INDEX_DEFAULT or DC_TPM2_NV_INDEX_BACKUP
 * pin: PIN for NV access authentication (can be NULL)
 * pcr_mask: PCR mask for sealing (0 = no PCR binding)
 * password: password data to store
 * password_size: size of password data
 * password_type: type of password
 * info: optional plaintext info to store (can be NULL)
 * info_size: size of info data
 * Returns: ST_OK on success
 */
int dc_tpm_20_create_nv_entry(
    u32 nv_index,
    const u8 *pin_auth,
    u32 pin_auth_size,
    u32 pcr_mask,
    const void *password,
    u32 password_size,
    u32 password_type,
    const void *info,
    u32 info_size)
{
    u8 cmd[1024];  // Large enough for NV_Write with sealed data + headers + auth
    u8 rsp[256];
    u32 rsp_size;
    u32 cmd_size;
    u8 *p;
    int resl;
    u8 sealed_buffer[DC_TPM_SRK_SEALED_BLOB_MAX];
    DC_TPM_SEALED_DATA *sealed_data = (DC_TPM_SEALED_DATA *)sealed_buffer;
    u32 sealed_size;
    
    if (password == NULL) {
        return ST_ERROR;
    }

    resl = dc_tpm_init();
    if (resl != ST_OK) {
        return resl;
    }

    if (g_tpm_version != 2) {
        return ST_NOT_SUPPORTED;
    }

    // Calculate padded size for sealed data
    if (password_size > DC_TPM_SRK_PASSWORD_MAX_SIZE) {
        return ST_SMALL_BUFF;
    }
    sealed_size = dc_tpm_sealed_data_size((u16)password_size);

    // Prepare sealed data structure
    // Note: PcrMask and Flags are stored separately in the PCR info NV entry,
    // not inside DC_TPM_SEALED_DATA (which matches DcsTpmLib.h format)
    memset(sealed_buffer, 0, sealed_size);
    sealed_data->Magic = DC_TPM_SEALED_MAGIC;
    sealed_data->Version = DC_TPM_SEALED_VERSION;
    sealed_data->PasswordSize = (u16)password_size;
    sealed_data->PasswordType = password_type;

    memcpy(sealed_data->Password, password, password_size);
    sealed_data->Checksum = crc32(sealed_data->Password, sealed_data->PasswordSize);

    // Check if NV index already exists - if so, undefine it first
    if (tpm2_nv_read_public(nv_index, NULL, NULL) == ST_OK) {
        // Undefine existing NV space (requires owner auth - try empty password)
        p = cmd;
        write_be16(p, TPM_ST_SESSIONS); p += 2;
        p += 4;  // Size placeholder
        write_be32(p, TPM_CC_NV_UndefineSpace); p += 4;
        write_be32(p, TPM_RH_OWNER); p += 4;  // authHandle
        write_be32(p, nv_index); p += 4;  // nvIndex

        // Auth area (empty password for owner)
        write_be32(p, 9); p += 4;
        write_be32(p, TPM_RS_PW); p += 4;
        write_be16(p, 0); p += 2;
        *p++ = 0;
        write_be16(p, 0); p += 2;

        cmd_size = (u32)(p - cmd);
        write_be32(cmd + 2, cmd_size);

        rsp_size = sizeof(rsp);
        tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);

        // Ignore errors - owner auth might be set
    }

    /*
     * Build TPM2_NV_DefineSpace command
     */
    p = cmd;
    write_be16(p, TPM_ST_SESSIONS); p += 2;
    p += 4;  // Size placeholder
    write_be32(p, TPM_CC_NV_DefineSpace); p += 4;
    write_be32(p, TPM_RH_OWNER); p += 4;  // authHandle = owner

    // Auth area (empty password for owner)
    write_be32(p, 9); p += 4;
    write_be32(p, TPM_RS_PW); p += 4;
    write_be16(p, 0); p += 2;  // nonce
    *p++ = 0;  // attributes
    write_be16(p, 0); p += 2;  // hmac (empty)

    // auth TPM2B (PIN for NV access)
    write_be16(p, (u16)pin_auth_size); p += 2;
    if (pin_auth_size > 0) {
        memcpy(p, pin_auth, pin_auth_size);
        p += pin_auth_size;
    }

    // Compute policy digest if PCR mask is set
    u8 policy_digest[32];
    u16 policy_digest_size = 0;
    BOOL pin_required = (pin_auth_size > 0);

    if (pcr_mask != 0) {
        resl = tpm2_compute_policy_digest(pcr_mask, pin_required, policy_digest);
        if (resl != ST_OK) {
            burn(sealed_buffer, sizeof(sealed_buffer));
            return resl;
        }
        policy_digest_size = 32;
    }

    // publicInfo as TPM2B_NV_PUBLIC
    u8 *pub_size_ptr = p;
    p += 2;  // Size placeholder

    write_be32(p, nv_index); p += 4;  // nvIndex
    write_be16(p, TPM_ALG_SHA256); p += 2;  // nameAlg

    // Set NV attributes based on protection mode (matching bootloader behavior)
    u32 nv_attrs = TPMA_NV_OWNERWRITE | TPMA_NV_POLICYWRITE;

    if (pcr_mask == 0) {
        // PIN-only (backup): auth-based read, owner cannot bypass PIN
        // CRITICAL: Do NOT set OWNERREAD for backup - owner must not bypass PIN!
        nv_attrs |= TPMA_NV_AUTHREAD;      // Read requires PIN auth
        // NO_DA = 0: ENABLE dictionary attack protection against PIN brute force
    } else if (pin_required) {
        // PCR + PIN: Combined policy (PolicyPCR + PolicyPassword)
        // Both PCRs and PIN are TPM-enforced via policy
        nv_attrs |= TPMA_NV_OWNERREAD;     // Owner can read (but needs policy)
        nv_attrs |= TPMA_NV_POLICYREAD;    // Read requires policy
        // NO_DA = 0: ENABLE dictionary attack protection (PIN can be brute forced)
    } else {
        // PCR only: Use policy for read - no PIN to brute force
        nv_attrs |= TPMA_NV_OWNERREAD;     // Owner can read (but needs policy)
        nv_attrs |= TPMA_NV_POLICYREAD;    // Read requires policy
        nv_attrs |= TPMA_NV_NO_DA;         // No PIN, DA protection not needed
    }
    write_be32(p, nv_attrs); p += 4;

    // authPolicy - policy digest for PCR-bound indices, empty for PIN-only
    write_be16(p, policy_digest_size); p += 2;
    if (policy_digest_size > 0) {
        memcpy(p, policy_digest, policy_digest_size);
        p += policy_digest_size;
    }

    write_be16(p, (u16)sealed_size); p += 2;  // dataSize

    // Fill in publicInfo size
    write_be16(pub_size_ptr, (u16)(p - pub_size_ptr - 2));

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    rsp_size = sizeof(rsp);
    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        burn(sealed_buffer, sizeof(sealed_buffer));
        return resl;
    }

    /*
     * Write the sealed data to NV
     * Use TPM_RH_OWNER as authHandle since we set OWNERWRITE attribute
     */
    p = cmd;
    write_be16(p, TPM_ST_SESSIONS); p += 2;
    p += 4;  // Size placeholder
    write_be32(p, TPM_CC_NV_Write); p += 4;
    write_be32(p, TPM_RH_OWNER); p += 4;  // authHandle = owner (for OWNERWRITE)
    write_be32(p, nv_index); p += 4;  // nvIndex

    // Auth area (empty owner password)
    write_be32(p, 9); p += 4;  // authSize = 9 bytes
    write_be32(p, TPM_RS_PW); p += 4;
    write_be16(p, 0); p += 2;  // nonce
    *p++ = 0;  // attributes
    write_be16(p, 0); p += 2;  // hmac (empty owner password)

    // data as TPM2B
    write_be16(p, (u16)sealed_size); p += 2;
    memcpy(p, sealed_data, sealed_size);
    p += sealed_size;

    // offset
    write_be16(p, 0); p += 2;

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    burn(sealed_buffer, sizeof(sealed_buffer));

    rsp_size = sizeof(rsp);
    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        return resl;
    }

    tpm2_nv_write_pcr_info(nv_index, pcr_mask, pin_auth_size > 0 ? DC_TPM_FLAG_PIN_REQUIRED : DC_TPM_FLAG_NONE, (const u8 *)info, (u16)info_size);

    return ST_OK;
}


/*
 * Delete an NV entry and its associated PCR info entry
 * nv_index: DC_TPM2_NV_INDEX_DEFAULT or DC_TPM2_NV_INDEX_BACKUP
 * Returns: ST_OK on success
 */
int dc_tpm_20_delete_nv_entry(u32 nv_index)
{
    u8 cmd[64];
    u8 rsp[256];
    u32 rsp_size;
    u32 cmd_size;
    u8 *p;
    int resl;
    u32 pcr_nv_index;

    resl = dc_tpm_init();
    if (resl != ST_OK) {
        return resl;
    }

    if (g_tpm_version != 2) {
        return ST_NOT_SUPPORTED;
    }

    // Check if NV index exists
    if (tpm2_nv_read_public(nv_index, NULL, NULL) != ST_OK) {
        return ST_TPM_NV_NOT_FOUND;
    }

    /*
     * Build TPM2_NV_UndefineSpace command
     * This requires owner authorization
     */
    p = cmd;
    write_be16(p, TPM_ST_SESSIONS); p += 2;
    p += 4;  // Size placeholder
    write_be32(p, TPM_CC_NV_UndefineSpace); p += 4;
    write_be32(p, TPM_RH_OWNER); p += 4;  // authHandle = owner
    write_be32(p, nv_index); p += 4;  // nvIndex

    // Auth area (empty password for owner)
    write_be32(p, 9); p += 4;
    write_be32(p, TPM_RS_PW); p += 4;
    write_be16(p, 0); p += 2;  // nonce
    *p++ = 0;  // attributes
    write_be16(p, 0); p += 2;  // hmac (empty)

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    rsp_size = sizeof(rsp);
    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        return resl;
    }

    // Also try to delete the associated PCR info NV entry
    pcr_nv_index = nv_index | DC_TPM_NV_INDEX_PCR_FLAG;
    if (tpm2_nv_read_public(pcr_nv_index, NULL, NULL) == ST_OK) {
        p = cmd;
        write_be16(p, TPM_ST_SESSIONS); p += 2;
        p += 4;
        write_be32(p, TPM_CC_NV_UndefineSpace); p += 4;
        write_be32(p, TPM_RH_OWNER); p += 4;
        write_be32(p, pcr_nv_index); p += 4;
        write_be32(p, 9); p += 4;
        write_be32(p, TPM_RS_PW); p += 4;
        write_be16(p, 0); p += 2;
        *p++ = 0;
        write_be16(p, 0); p += 2;
        cmd_size = (u32)(p - cmd);
        write_be32(cmd + 2, cmd_size);

        rsp_size = sizeof(rsp);
        tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
        // Ignore errors for PCR info deletion
    }

    return ST_OK;
}

//////////////////////////////////////////////////////////////////////////
// TPM Operations (File-based storage mode)
//////////////////////////////////////////////////////////////////////////

/*
* TPM SRK-based Sealing Support
*
* This module implements creation and management of SRK-sealed secrets stored
* in files on the EFI partition. The file format matches the UEFI DcsTpmLib
* implementation for compatibility.
*
* SRK sealing uses envelope encryption:
*   1. Generate random 32-byte KEK (Key Encryption Key)
*   2. Seal KEK using TPM2_CreatePrimary (SRK) + TPM2_Create
*   3. Build DC_TPM_SEALED_DATA structure with password + CRC
*   4. Encrypt DC_TPM_SEALED_DATA with AES-256-CBC using the KEK
*   5. Store: [Header][SealedBlob][Encrypted DC_TPM_SEALED_DATA][InfoData]
*
* Unsealing happens at UEFI boot time, not from Windows.
*/

/*
* TPM2 Sealed Blob Structure (within file, after header)
*/
#pragma pack(push, 1)
typedef struct _DC_TPM2_SEALED_BLOB {
    u16  PrivateSize;     /* Size of TPM private blob */
    u16  PublicSize;      /* Size of TPM public blob */
    u8   Data[1];         /* [PrivateBlob][PublicBlob] */
} DC_TPM2_SEALED_BLOB;
#pragma pack(pop)


/*
* TPM2_CreatePrimary - Create SRK (Storage Root Key)
* Returns the SRK handle
*/
int tpm2_create_primary(u32 *srk_handle)
{
    u8 cmd[512];
    u8 rsp[1024];
    u32 rsp_size = sizeof(rsp);
    u8 *p;
    u32 cmd_size;
    int resl;

    /*
    * Build TPM2_CreatePrimary command for RSA-2048 storage key:
    * - Primary handle: TPM_RH_OWNER
    * - Auth: empty (well-known)
    * - Template: RSA-2048 restricted decrypt storage key
    */
    p = cmd;

    /* Header */
    write_be16(p, TPM_ST_SESSIONS); p += 2;
    p += 4;  /* Size placeholder */
    write_be32(p, TPM_CC_CreatePrimary); p += 4;

    /* Primary handle */
    write_be32(p, TPM_RH_OWNER); p += 4;

    /* Auth area (empty password) */
    write_be32(p, 9); p += 4;         /* authSize */
    write_be32(p, TPM_RS_PW); p += 4; /* session = password */
    write_be16(p, 0); p += 2;         /* nonceCaller = empty */
    *p++ = 0;                          /* sessionAttributes */
    write_be16(p, 0); p += 2;         /* hmac = empty */

    /* inSensitive (TPM2B_SENSITIVE_CREATE) */
    write_be16(p, 4); p += 2;         /* size */
    write_be16(p, 0); p += 2;         /* userAuth = empty */
    write_be16(p, 0); p += 2;         /* data = empty */

    /* inPublic (TPM2B_PUBLIC) - RSA 2048 storage key template */
    u8 *pub_size_ptr = p;
    p += 2;  /* Size placeholder */

    write_be16(p, TPM_ALG_RSA); p += 2;    /* type = RSA */
    write_be16(p, TPM_ALG_SHA256); p += 2; /* nameAlg */

    /* objectAttributes - must match bootloader's 0x00030472 */
    u32 attrs = TPMA_OBJECT_FIXEDTPM |
        TPMA_OBJECT_FIXEDPARENT |
        TPMA_OBJECT_SENSITIVEDATAORIGIN |
        TPMA_OBJECT_USERWITHAUTH |
        TPMA_OBJECT_NODA |           /* Required for compatibility with bootloader */
        TPMA_OBJECT_RESTRICTED |
        TPMA_OBJECT_DECRYPT;
    write_be32(p, attrs); p += 4;

    write_be16(p, 0); p += 2;  /* authPolicy = empty */

    /* TPMS_RSA_PARMS */
    write_be16(p, TPM_ALG_AES); p += 2;   /* symmetric.algorithm */
    write_be16(p, 128); p += 2;           /* symmetric.keyBits */
    write_be16(p, TPM_ALG_CFB); p += 2;   /* symmetric.mode */
    write_be16(p, TPM_ALG_NULL); p += 2;  /* scheme.scheme = NULL */
    write_be16(p, 2048); p += 2;          /* keyBits = 2048 */
    write_be32(p, 0); p += 4;             /* exponent = 0 (default 65537) */

    /* unique (TPM2B_PUBLIC_KEY_RSA) = empty */
    write_be16(p, 0); p += 2;

    /* Fill in public area size */
    write_be16(pub_size_ptr, (u16)(p - pub_size_ptr - 2));

    /* outsideInfo = empty */
    write_be16(p, 0); p += 2;

    /* creationPCR = empty (TPML_PCR_SELECTION with count=0) */
    write_be32(p, 0); p += 4;

    /* Fill in command size */
    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    /* Submit command */
    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        return resl;
    }

    /*
    * Parse response:
    * Header (10 bytes)
    * objectHandle (4 bytes)
    * ...
    */
    if (rsp_size < 14) {
        return ST_TPM_ERROR;
    }

    *srk_handle = read_be32(rsp + 10);
    return ST_OK;
}

/*
* TPM2_FlushContext - Release a transient handle
*/
int tpm2_flush_context(u32 handle)
{
    u8 cmd[16];
    u8 rsp[32];
    u32 rsp_size = sizeof(rsp);
    u8 *p;
    u32 cmd_size;

    p = cmd;
    write_be16(p, TPM_ST_NO_SESSIONS); p += 2;
    p += 4;  /* Size placeholder */
    write_be32(p, TPM_CC_FlushContext); p += 4;
    write_be32(p, handle); p += 4;

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    /* Submit - ignore errors */
    tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    return ST_OK;
}

/*
* TPM2_Create - Create sealed object under parent (SRK)
* Seals the provided data with optional PCR policy and PIN
*/

int tpm2_create_sealed(
    u32 parent_handle,
    const u8 *data,
    u32 data_size,
    u32 pcr_mask,
    const u8 *pin_auth,
    u32 pin_auth_size,
    u8 *sealed_blob,
    u32 *sealed_blob_size)
{
    u8 cmd[1024];
    u8 rsp[1024];
    u32 rsp_size = sizeof(rsp);
    u8 *p;
    u32 cmd_size;
    int resl;

    if (data_size > 128) {
        /* TPM seal max is ~128 bytes */
        return ST_SMALL_BUFF;
    }

    /*
    * Build TPM2_Create command for sealed keyedHash:
    * - Parent: SRK handle
    * - Auth: password session with parent auth (empty for SRK)
    * - Data to seal goes in inSensitive.data
    * - PIN auth goes in inSensitive.userAuth
    */
    p = cmd;

    /* Header */
    write_be16(p, TPM_ST_SESSIONS); p += 2;
    p += 4;  /* Size placeholder */
    write_be32(p, TPM_CC_Create); p += 4;

    /* parentHandle */
    write_be32(p, parent_handle); p += 4;

    /* Auth area (empty password for SRK) */
    write_be32(p, 9); p += 4;
    write_be32(p, TPM_RS_PW); p += 4;
    write_be16(p, 0); p += 2;
    *p++ = 0;
    write_be16(p, 0); p += 2;

    /* inSensitive (TPM2B_SENSITIVE_CREATE) */
    u8 *sens_size_ptr = p;
    p += 2;

    /* userAuth - PIN auth */
    write_be16(p, (u16)pin_auth_size); p += 2;
    if (pin_auth_size > 0 && pin_auth != NULL) {
        memcpy(p, pin_auth, pin_auth_size);
        p += pin_auth_size;
    }

    /* data - data to seal */
    write_be16(p, (u16)data_size); p += 2;
    memcpy(p, data, data_size);
    p += data_size;

    write_be16(sens_size_ptr, (u16)(p - sens_size_ptr - 2));

    /* inPublic (TPM2B_PUBLIC) - keyedHash for sealing */
    u8 *pub_size_ptr = p;
    p += 2;

    write_be16(p, TPM_ALG_KEYEDHASH); p += 2; /* type */
    write_be16(p, TPM_ALG_SHA256); p += 2;    /* nameAlg */

    /* objectAttributes */
    u32 attrs = TPMA_OBJECT_FIXEDTPM |
        TPMA_OBJECT_FIXEDPARENT;

    if (pin_auth_size > 0 || pcr_mask == 0) {
        /* Use userWithAuth if PIN provided or no PCR binding */
        attrs |= TPMA_OBJECT_USERWITHAUTH;
    }

    write_be32(p, attrs); p += 4;

    /* authPolicy - PCR policy digest if needed */
    if (pcr_mask != 0) {
        /* TODO: Compute policy digest for PCR binding */
        /* For now, just use userWithAuth */
        write_be16(p, 0); p += 2;
    } else {
        write_be16(p, 0); p += 2;
    }

    /* TPMS_KEYEDHASH_PARMS */
    write_be16(p, TPM_ALG_NULL); p += 2; /* scheme = NULL (seal) */

    /* unique (TPM2B_DIGEST) = empty */
    write_be16(p, 0); p += 2;

    write_be16(pub_size_ptr, (u16)(p - pub_size_ptr - 2));

    /* outsideInfo = empty */
    write_be16(p, 0); p += 2;

    /* creationPCR - PCR selection if needed */
    if (pcr_mask != 0) {
        /* TODO: Add PCR selection */
        write_be32(p, 0); p += 4; /* count = 0 for now */
    } else {
        write_be32(p, 0); p += 4;
    }

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        return resl;
    }

    /*
    * Parse response:
    * Header (10 bytes)
    * parameterSize (4 bytes)
    * outPrivate (TPM2B_PRIVATE)
    * outPublic (TPM2B_PUBLIC)
    */
    if (rsp_size < 18) {
        return ST_TPM_ERROR;
    }

    u8 *resp_data = rsp + 10;
    u32 param_size = read_be32(resp_data);
    resp_data += 4;

    /* Read private blob size */
    u16 priv_size = read_be16(resp_data);
    resp_data += 2;

    if (priv_size > 300) {
        return ST_TPM_ERROR;
    }

    /* Read public blob (after private) */
    u8 *pub_ptr = resp_data + priv_size;
    u16 pub_size = read_be16(pub_ptr);
    pub_ptr += 2;

    /* Build DC_TPM2_SEALED_BLOB structure */
    u32 total_size = 4 + priv_size + pub_size;  /* 2 + 2 + priv + pub */
    if (total_size > *sealed_blob_size) {
        return ST_SMALL_BUFF;
    }

    DC_TPM2_SEALED_BLOB *blob = (DC_TPM2_SEALED_BLOB *)sealed_blob;
    blob->PrivateSize = priv_size;
    blob->PublicSize = pub_size;
    memcpy(blob->Data, resp_data, priv_size);
    memcpy(blob->Data + priv_size, pub_ptr, pub_size);

    *sealed_blob_size = total_size;
    return ST_OK;
}

/*
* TPM2_Load - Load sealed blob under parent (SRK)
* Returns the loaded object handle
*/
int tpm2_load(
    u32 parent_handle,
    const u8 *sealed_blob,
    u32 sealed_blob_size,
    u32 *object_handle)
{
    u8 cmd[1024];
    u8 rsp[512];
    u32 rsp_size = sizeof(rsp);
    u8 *p;
    u32 cmd_size;
    int resl;
    DC_TPM2_SEALED_BLOB *blob;

    if (sealed_blob == NULL || sealed_blob_size < 4) {
        return ST_ERROR;
    }

    blob = (DC_TPM2_SEALED_BLOB *)sealed_blob;

    /* Validate blob sizes */
    if (blob->PrivateSize > 300 || blob->PublicSize > 300) {
        return ST_FORMAT_ERR;
    }
    if ((u32)(4 + blob->PrivateSize + blob->PublicSize) > sealed_blob_size) {
        return ST_FORMAT_ERR;
    }

    /*
    * Build TPM2_Load command:
    * - parentHandle: SRK handle
    * - Auth: password session with parent auth (empty for SRK)
    * - inPrivate: TPM2B_PRIVATE
    * - inPublic: TPM2B_PUBLIC
    */
    p = cmd;

    /* Header */
    write_be16(p, TPM_ST_SESSIONS); p += 2;
    p += 4;  /* Size placeholder */
    write_be32(p, TPM_CC_Load); p += 4;

    /* parentHandle */
    write_be32(p, parent_handle); p += 4;

    /* Auth area (empty password for SRK) */
    write_be32(p, 9); p += 4;
    write_be32(p, TPM_RS_PW); p += 4;
    write_be16(p, 0); p += 2;
    *p++ = 0;
    write_be16(p, 0); p += 2;

    /* inPrivate (TPM2B_PRIVATE) */
    write_be16(p, blob->PrivateSize); p += 2;
    memcpy(p, blob->Data, blob->PrivateSize);
    p += blob->PrivateSize;

    /* inPublic (TPM2B_PUBLIC) */
    write_be16(p, blob->PublicSize); p += 2;
    memcpy(p, blob->Data + blob->PrivateSize, blob->PublicSize);
    p += blob->PublicSize;

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        return resl;
    }

    /*
    * Parse response:
    * Header (10 bytes)
    * objectHandle (4 bytes)
    * ...
    */
    if (rsp_size < 14) {
        return ST_TPM_ERROR;
    }

    *object_handle = read_be32(rsp + 10);
    return ST_OK;
}

/*
* TPM2_Unseal - Unseal data from a loaded sealed object
* Returns the unsealed data
*/
int tpm2_unseal(
    u32 object_handle,
    const u8 *pin_auth,
    u32 pin_auth_size,
    u8 *data,
    u32 *data_size)
{
    u8 cmd[512];
    u8 rsp[512];
    u32 rsp_size = sizeof(rsp);
    u8 *p;
    u32 cmd_size;
    int resl;

    /*
    * Build TPM2_Unseal command:
    * - itemHandle: sealed object handle
    * - Auth: password session with object auth (PIN if provided)
    */
    p = cmd;

    /* Header */
    write_be16(p, TPM_ST_SESSIONS); p += 2;
    p += 4;  /* Size placeholder */
    write_be32(p, TPM_CC_Unseal); p += 4;

    /* itemHandle */
    write_be32(p, object_handle); p += 4;

    /* Auth area */
    u8 *auth_size_ptr = p;
    p += 4;
    write_be32(p, TPM_RS_PW); p += 4;
    write_be16(p, 0); p += 2;  /* nonceCaller = empty */
    *p++ = 0;                   /* sessionAttributes */

    /* hmac = PIN auth */
    write_be16(p, (u16)pin_auth_size); p += 2;
    if (pin_auth_size > 0 && pin_auth != NULL) {
        memcpy(p, pin_auth, pin_auth_size);
        p += pin_auth_size;
    }

    write_be32(auth_size_ptr, (u32)(p - auth_size_ptr - 4));

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        return resl;
    }

    /*
    * Parse response:
    * Header (10 bytes)
    * parameterSize (4 bytes)
    * outData (TPM2B_SENSITIVE_DATA)
    */
    if (rsp_size < 18) {
        return ST_TPM_ERROR;
    }

    u8 *resp_data = rsp + 10;
    u32 param_size = read_be32(resp_data);
    resp_data += 4;

    /* outData as TPM2B */
    u16 out_size = read_be16(resp_data);
    resp_data += 2;

    if (out_size > *data_size) {
        return ST_SMALL_BUFF;
    }

    memcpy(data, resp_data, out_size);
    *data_size = out_size;

    return ST_OK;
}


/*
 * Read a PCR value (SHA256 bank)
 * pcr_index: PCR index (0-23)
 * pcr_value: output buffer for PCR value (32 bytes for SHA256)
 * pcr_size: in/out - buffer size / actual size
 * Returns: ST_OK on success
 */
int dc_tpm_20_pcr_read(u32 pcr_index, u8 *pcr_value, u32 *pcr_size)
{
    u8 cmd[64];
    u8 rsp[128];
    u32 rsp_size = sizeof(rsp);
    u32 cmd_size;
    u8 *p;
    int resl;

    if (pcr_value == NULL || pcr_size == NULL || *pcr_size < 32) {
        return ST_SMALL_BUFF;
    }

    if (pcr_index > 23) {
        return ST_INVALID_PARAM;
    }

    resl = dc_tpm_init();
    if (resl != ST_OK) {
        return resl;
    }

    if (g_tpm_version != 2) {
        return ST_NOT_SUPPORTED;
    }

    /*
     * Build TPM2_PCR_Read command:
     * Header (10 bytes):
     *   tag (2): TPM_ST_NO_SESSIONS
     *   size (4): total command size
     *   code (4): TPM_CC_PCR_Read
     * Parameters:
     *   pcrSelectionIn (TPML_PCR_SELECTION):
     *     count (4): 1
     *     TPMS_PCR_SELECTION:
     *       hash (2): TPM_ALG_SHA256
     *       sizeofSelect (1): 3
     *       pcrSelect (3): bitmap for PCR index
     */
    p = cmd;

    // Header
    write_be16(p, TPM_ST_NO_SESSIONS); p += 2;
    p += 4;  // Size placeholder
    write_be32(p, TPM_CC_PCR_Read); p += 4;

    // pcrSelectionIn
    write_be32(p, 1); p += 4;  // count = 1

    // TPMS_PCR_SELECTION
    write_be16(p, TPM_ALG_SHA256); p += 2;  // hash = SHA256
    *p++ = 3;  // sizeofSelect = 3 bytes (supports PCR 0-23)

    // Build PCR select bitmap
    u8 pcr_select[3] = {0, 0, 0};
    pcr_select[pcr_index / 8] = 1 << (pcr_index % 8);
    memcpy(p, pcr_select, 3); p += 3;

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
    if (resl != ST_OK) {
        return resl;
    }

    /*
     * Parse response:
     * Header (10 bytes)
     * pcrUpdateCounter (4 bytes)
     * pcrSelectionOut (TPML_PCR_SELECTION)
     *   count (4)
     *   TPMS_PCR_SELECTION:
     *     hash (2)
     *     sizeofSelect (1)
     *     pcrSelect (3)
     * pcrValues (TPML_DIGEST)
     *   count (4)
     *   TPM2B_DIGEST:
     *     size (2)
     *     buffer (32 for SHA256)
     */
    if (rsp_size < 10 + 4 + 10 + 4 + 2 + 32) {
        return ST_TPM_ERROR;
    }

    // Skip to pcrValues
    u8 *resp = rsp + 10;  // Skip header
    resp += 4;  // Skip pcrUpdateCounter

    // Skip pcrSelectionOut
    u32 sel_count = read_be32(resp); resp += 4;
    for (u32 i = 0; i < sel_count; i++) {
        resp += 2;  // hash
        u8 sel_size = *resp++;
        resp += sel_size;  // pcrSelect
    }

    // Read pcrValues
    u32 digest_count = read_be32(resp); resp += 4;
    if (digest_count < 1) {
        return ST_TPM_ERROR;
    }

    // Read first digest (TPM2B_DIGEST)
    u16 digest_size = read_be16(resp); resp += 2;
    if (digest_size != 32) {
        return ST_TPM_ERROR;  // Expected SHA256
    }

    memcpy(pcr_value, resp, 32);
    *pcr_size = 32;

    return ST_OK;
}


/*
 * Enumerate all NV entries using GetCapability
 */
int dc_tpm_20_enum_nv(DC_TPM_NV_ENTRY *entries, u32 *count)
{
    u8 cmd[32];
    u8 rsp[1024];
    u32 rsp_size;
    u32 cmd_size;
    u8 *p;
    int resl;
    u32 max_count;
    u32 found_count = 0;
    u32 next_handle = 0x01000000;  // Start of NV handle range
    BOOL more_data = TRUE;

    if (entries == NULL || count == NULL) {
        return ST_INVALID_PARAM;
    }

    max_count = *count;
    *count = 0;

    resl = dc_tpm_init();
    if (resl != ST_OK) {
        return resl;
    }

    if (g_tpm_version != 2) {
        return ST_NOT_SUPPORTED;
    }

    while (more_data && found_count < max_count) {
        /*
         * Build TPM2_GetCapability command:
         * capability (4): TPM_CAP_HANDLES
         * property (4): handle range start
         * propertyCount (4): max handles to return
         */
        p = cmd;
        write_be16(p, TPM_ST_NO_SESSIONS); p += 2;
        p += 4;  // Size placeholder
        write_be32(p, TPM_CC_GetCapability); p += 4;
        write_be32(p, TPM_CAP_HANDLES); p += 4;
        write_be32(p, next_handle); p += 4;
        write_be32(p, 32); p += 4;  // Request up to 32 handles

        cmd_size = (u32)(p - cmd);
        write_be32(cmd + 2, cmd_size);

        rsp_size = sizeof(rsp);
        resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);
        if (resl != ST_OK) {
            break;
        }

        if (rsp_size < 17) {
            break;
        }

        /*
         * Parse response:
         * Header (10 bytes)
         * moreData (1 byte)
         * capabilityData:
         *   capability (4): TPM_CAP_HANDLES
         *   data.handles:
         *     count (4)
         *     handle[] (4 each)
         */
        u8 *resp = rsp + 10;
        more_data = *resp++;
        u32 cap = read_be32(resp); resp += 4;

        if (cap != TPM_CAP_HANDLES) {
            break;
        }

        u32 handle_count = read_be32(resp); resp += 4;

        if (handle_count == 0) {
            break;
        }

        for (u32 i = 0; i < handle_count && found_count < max_count; i++) {
            u32 nv_index = read_be32(resp); resp += 4;
            next_handle = nv_index + 1;

            // Get NV public info
            u32 nv_size = 0;
            u32 nv_attrs = 0;
            if (tpm2_nv_read_public(nv_index, &nv_size, &nv_attrs) == ST_OK) {
                entries[found_count].nv_index = nv_index;
                entries[found_count].attributes = nv_attrs;
                entries[found_count].data_size = (u16)nv_size;
                entries[found_count].pcr_mask = 0;  // TPM 2.0 doesn't expose PCR mask directly
                entries[found_count].description[0] = L'\0';  // Filled by wrapper
                found_count++;
            }
        }
    }

    *count = found_count;
    return ST_OK;
}


/*
 * Delete an NV entry by index (low-level, any NV index)
 * nv_index: Full NV index handle to delete
 * Returns: ST_OK on success
 */
int dc_tpm_20_delete_nv(u32 nv_index)
{
    u8 cmd[64];
    u8 rsp[256];
    u32 rsp_size;
    u32 cmd_size;
    u8 *p;
    int resl;

    resl = dc_tpm_init();
    if (resl != ST_OK) {
        return resl;
    }

    if (g_tpm_version != 2) {
        return ST_NOT_SUPPORTED;
    }

    // Check if NV index exists
    if (tpm2_nv_read_public(nv_index, NULL, NULL) != ST_OK) {
        return ST_TPM_NV_NOT_FOUND;
    }

    /*
     * Build TPM2_NV_UndefineSpace command
     */
    p = cmd;
    write_be16(p, TPM_ST_SESSIONS); p += 2;
    p += 4;  // Size placeholder
    write_be32(p, TPM_CC_NV_UndefineSpace); p += 4;
    write_be32(p, TPM_RH_OWNER); p += 4;  // authHandle = owner
    write_be32(p, nv_index); p += 4;  // nvIndex

    // Auth area (empty password for owner)
    write_be32(p, 9); p += 4;
    write_be32(p, TPM_RS_PW); p += 4;
    write_be16(p, 0); p += 2;  // nonce
    *p++ = 0;  // attributes
    write_be16(p, 0); p += 2;  // hmac (empty)

    cmd_size = (u32)(p - cmd);
    write_be32(cmd + 2, cmd_size);

    rsp_size = sizeof(rsp);
    resl = tpm_submit_command(cmd, cmd_size, rsp, &rsp_size);

    return resl;
}

