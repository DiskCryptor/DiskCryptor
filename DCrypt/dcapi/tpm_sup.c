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

#include <windows.h>
#include <winioctl.h>
#include <io.h>
#include <stdlib.h>
#include "dcconst.h"
#include "misc.h"
#include "drv_ioctl.h"
#include "tpm_sup.h"
#include "tpm_20.h"
#include "tpm_12.h"
#include "dc_header.h"
#include "..\crc32.h"

#ifdef _M_ARM64
#include "xts_small.h"
#else
#include "xts_fast.h"
#endif


#define DC_TPM_SRK_FILE_MAGIC       0x4B525344  /* "DSRK" */
#define DC_TPM_SRK_VERSION          1

/*
* TPM SRK File Header Structure (matching edk2 DcsTpmLib.h)
* File format:
*   [DC_TPM_SRK_FILE_HEADER]
*   [SealedBlob (DC_TPM_SEALED_BLOB)]
*   [Encrypted DC_TPM_SEALED_DATA]
*   [InfoData (optional)]
*/
#pragma pack(push, 1)
typedef struct _DC_TPM_SRK_FILE_HEADER {
    u32  Magic;           /* DC_TPM_SRK_FILE_MAGIC (0x4B525344) */
    u16  Version;         /* DC_TPM_SRK_VERSION */
    u16  Reserved1;       /* Reserved for alignment */
    u32  Flags;           /* DC_TPM_FLAG_* */
    u32  PcrMask;         /* PCR mask used for sealing */
    u16  SealedBlobSize;  /* Size of sealed KEK blob */
    u16  EncryptedSize;   /* Size of encrypted DC_TPM_SEALED_DATA (with padding) */
    u8   Iv[16];          /* AES IV for envelope encryption */
    u16  InfoSize;        /* Size of plaintext info data (0=none, max DC_TPM_INFO_MAX_SIZE) */
    /* Followed by: sealed KEK blob + encrypted DC_TPM_SEALED_DATA + InfoData */
} DC_TPM_SRK_FILE_HEADER;
#pragma pack(pop)



/*
* TPM Backup File Constants (matching UEFI DcsTpmSupport.c)
*/
#define DC_TPM_BACKUP_MAGIC             0x4B424344  // "DCBK"
#define DC_TPM_BACKUP_VERSION           1
#define DC_TPM_BACKUP_FILE_SIZE         1024
#define DC_TPM_BACKUP_ENCRYPTED_OFF     64          // HEADER_SALT_SIZE
#define DC_TPM_BACKUP_ENCRYPTED_SIZE    960
#define DC_TPM_BACKUP_CRC_OFF           8           // Offset of CRC calculation start within decrypted area
#define DC_TPM_BACKUP_CRC_SIZE          952         // Size of CRC calculation area
#define DC_TPM_BACKUP_DATA_SPACE        896

#define DC_TPM_BACKUP_FILE_PATH         L"\\EFI\\DCS\\tpm_backup.dat"

/*
* Secret type constants
*/
#define DCS_TPM_SECRET_TYPE_PLAIN       0   // Plain password
#define DCS_TPM_SECRET_TYPE_1           1   // TPM secret structure
#define DC_TPM_SECRET_TYPE_RECOVERY     (-1)  // Recovery data (includes PCR mask and PIN for re-seal)

#define DC_TPM_BACKUP_PROVISIONING	    0x00000001

/*
* TPM Backup File Structure
* File format:
*   [0-63]   Salt (plaintext, 64 bytes)
*   [64-1023] Encrypted data (XTS-AES, 960 bytes)
*            After decryption:
*            [0-3]   Magic (0x4B424344)
*            [4-7]   CRC32 (of bytes 8-959)
*            [8-9]   Version (2)
*            [10-959] tpm_backup_data
*/
#pragma pack(push, 1)

typedef struct _DC_TPM_BACKUP_FILE {
    // Plaintext (64 bytes)
    u8   Salt[64];

    // Everything below is XTS-encrypted (960 bytes)
    u32  Magic;
    u32  Crc;
    u16  Version;
    u16  BackupSize;
    u32  BackupType;
    u8   Reserved[48];
    u8   Backup[DC_TPM_BACKUP_DATA_SPACE];
} DC_TPM_BACKUP_FILE;

/*
* TPM Backup Data Structure (stored in encrypted backup)
*/
typedef struct _tpm_backup {
    u32  PcrMask;      // Original PCR mask used for sealing
    u32  Flags;        // Original flags (DC_TPM_FLAG_*)
    u16  PinSize;      // Size of original TPM PIN (follows secret_data)
    u32  SecretType;   // 0 = plain password, 1 = tpm_secret structure
    u16  SecretSize;   // Size of secret_data
    u8   SecretData[0];// Variable-length secret, followed by PIN if pin_size > 0
} tpm_backup;

/*
* TPM Secret Structure (when secret_type == DCS_TPM_SECRET_TYPE_1)
*/
#define DCS_TPM_FLAG_REQ_PASS   0x01    // Password also required in addition to TPM secret
#define DC_KF_HASH_SIZE         64      // Size of TPM secret hash

typedef struct _tpm_secret {
    u32  Flags;         // DCS_TPM_FLAG_REQ_PASS if password also required
    int  Kdf;           // KDF used for this secret
    int  Slot;          // Key slot (-KEY_SLOT_COUNT to use all)
    u16  SecretSize;    // Must equal DC_KF_HASH_SIZE (64 bytes)
    u8   SecretData[0]; // 64-byte random secret
} tpm_secret;

#pragma pack(pop)



/*
* TBS API definitions and dynamic loading
* TBS API was introduced in Windows Vista, but project targets Windows 2000.
* We load tbs.dll dynamically to support both old and new Windows versions.
*/

typedef struct _TBS_CONTEXT_PARAMS {
    UINT32 version;
} TBS_CONTEXT_PARAMS, *PTBS_CONTEXT_PARAMS;
typedef const TBS_CONTEXT_PARAMS *PCTBS_CONTEXT_PARAMS;

typedef struct _TBS_CONTEXT_PARAMS2 {
    UINT32 version;
    union {
        struct {
            UINT32 requestRaw : 1;
            UINT32 includeTpm12 : 1;
            UINT32 includeTpm20 : 1;
        };
        UINT32 asUINT32;
    };
} TBS_CONTEXT_PARAMS2, *PTBS_CONTEXT_PARAMS2;

/* TBS function declarations - loaded dynamically */
typedef TBS_RESULT (WINAPI *PFN_Tbsi_Context_Create)(PCTBS_CONTEXT_PARAMS, TBS_HCONTEXT*);
typedef TBS_RESULT (WINAPI *PFN_Tbsip_Context_Close)(TBS_HCONTEXT);
typedef TBS_RESULT (WINAPI *PFN_Tbsip_Submit_Command)(TBS_HCONTEXT, UINT32, UINT32, const BYTE*, UINT32, BYTE*, UINT32*);

static PFN_Tbsi_Context_Create  pfn_Tbsi_Context_Create = NULL;
static PFN_Tbsip_Context_Close  pfn_Tbsip_Context_Close = NULL;
PFN_Tbsip_Submit_Command        pfn_Tbsip_Submit_Command = NULL;  /* Non-static for tpm_srk.c access */
static HMODULE                  g_tbs_module = NULL;
static BOOL                     g_tbs_loaded = FALSE;

static BOOL load_tbs_functions(void)
{
    if (g_tbs_loaded) return (g_tbs_module != NULL);
    g_tbs_loaded = TRUE;

    g_tbs_module = LoadLibraryA("tbs.dll");
    if (g_tbs_module == NULL) return FALSE;

    pfn_Tbsi_Context_Create = (PFN_Tbsi_Context_Create)GetProcAddress(g_tbs_module, "Tbsi_Context_Create");
    pfn_Tbsip_Context_Close = (PFN_Tbsip_Context_Close)GetProcAddress(g_tbs_module, "Tbsip_Context_Close");
    pfn_Tbsip_Submit_Command = (PFN_Tbsip_Submit_Command)GetProcAddress(g_tbs_module, "Tbsip_Submit_Command");

    if (!pfn_Tbsi_Context_Create || !pfn_Tbsip_Context_Close || !pfn_Tbsip_Submit_Command) {
        FreeLibrary(g_tbs_module);
        g_tbs_module = NULL;
        return FALSE;
    }

    return TRUE;
}



/*
* TBS Context Management
* g_tbs_context is non-static for tpm_srk.c access
*/
TBS_HCONTEXT g_tbs_context = NULL;
int g_tpm_version = 0;  // 0=unknown, 1=TPM1.2, 2=TPM2.0


/*
* Initialize TPM access
* Returns: ST_OK on success
*/
int dc_tpm_init(void)
{
    TBS_RESULT result;
    TBS_CONTEXT_PARAMS2 params2 = {0};
    TBS_CONTEXT_PARAMS params = {0};

    if (g_tbs_context != NULL) {
        return ST_OK;  // Already initialized
    }

    // Load TBS functions dynamically
    if (!load_tbs_functions()) {
        return ST_NO_TPM;
    }

    // Try TPM 2.0 first
    params2.version = TBS_CONTEXT_VERSION_TWO;
    params2.includeTpm20 = 1;
    result = pfn_Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params2, &g_tbs_context);

    if (result == TBS_SUCCESS) {
        g_tpm_version = 2;
        return ST_OK;
    }

    // Try TPM 1.2
    params.version = TBS_CONTEXT_VERSION_ONE;
    result = pfn_Tbsi_Context_Create(&params, &g_tbs_context);

    if (result == TBS_SUCCESS) {
        g_tpm_version = 1;
        return ST_OK;
    }

    g_tbs_context = NULL;
    g_tpm_version = 0;
    return ST_NO_TPM;
}


/*
* Close TPM access
*/
void dc_tpm_close(void)
{
    if (g_tbs_context != NULL && pfn_Tbsip_Context_Close != NULL) {
        pfn_Tbsip_Context_Close(g_tbs_context);
        g_tbs_context = NULL;
        g_tpm_version = 0;
    }
}


/*
* Get TPM version
* Returns: 1 for TPM 1.2, 2 for TPM 2.0, 0 if not initialized
*/
int dc_tpm_get_version(void)
{
    int resl;

    // Initialize TPM if not already done
    resl = dc_tpm_init();
    if (resl != ST_OK) {
        return 0;
    }

    return g_tpm_version;
}


/*
* TPM 2.0 response codes for common errors
*/
#define TPM2_RC_AUTH_FAIL       0x08E  /* Authorization failure (wrong PIN) */
#define TPM2_RC_POLICY_FAIL     0x126  /* Policy check failed (PCR mismatch) */
#define TPM2_RC_LOCKOUT         0x921  /* TPM is in DA lockout */
#define TPM2_RC_INTEGRITY       0x09F  /* Integrity check failed */
#define TPM2_RC_SENSITIVE       0x155  /* Sensitive data integrity failed */
#define TPM2_RC_AUTH_UNAVAILABLE 0x12F /* Auth unavailable for entity */

/*
* Last TPM error code for debugging
*/
static u32 g_last_tpm_rc = 0;

u32 dc_api dc_tpm_get_last_error(void) {
    return g_last_tpm_rc;
}

/*
* Translate TPM response code to DiskCryptor status code
*/
static int tpm_rc_to_status(u32 rc)
{
    g_last_tpm_rc = rc;

    /* TPM 1.2 error codes (values 0-255) */
    if (rc > 0 && rc < 0x100) {
        switch (rc) {
        case 0x01:  /* TPM_AUTHFAIL */
            return ST_TPM_WRONG_PIN;
        case 0x19:
        case 0x02:  /* TPM_BADINDEX */
            return ST_TPM_NV_NOT_FOUND;
        case 0x03:  /* TPM_BAD_PARAMETER */
            return ST_INVALID_PARAM;
        case 0x18:  /* TPM_WRONGPCRVAL */
            return ST_TPM_PCR_MISMATCH;
        case 0x1D:  /* TPM_AUTH2FAIL */
            return ST_TPM_WRONG_PIN;
        default:
            return ST_TPM_ERROR;
        }
    }

    /* Mask off parameter/session/handle indicators for format 1 codes */
    u32 base_rc = rc & 0x0FF;  /* Lower 8 bits for format 0 */

    /* Check common error codes */
    switch (rc) {
    case TPM_RC_SUCCESS:
        return ST_OK;
    case TPM2_RC_AUTH_FAIL:
        return ST_TPM_WRONG_PIN;
    case TPM2_RC_POLICY_FAIL:
        return ST_TPM_PCR_MISMATCH;
    case TPM2_RC_LOCKOUT:
        return ST_TPM_LOCKOUT;
    case TPM2_RC_INTEGRITY:
    case TPM2_RC_SENSITIVE:
        return ST_TPM_INTEGRITY;
    case TPM2_RC_AUTH_UNAVAILABLE:
        return ST_TPM_WRONG_PIN;  /* Often means wrong auth type */
    }

    /* Check base error code (for format 1 errors with parameter indicators) */
    switch (base_rc) {
    case 0x8E:  /* AUTH_FAIL */
        return ST_TPM_WRONG_PIN;
    case 0x26:  /* POLICY (0x126 & 0xFF = 0x26) */
        return ST_TPM_PCR_MISMATCH;
    case 0x9F:  /* INTEGRITY */
        return ST_TPM_INTEGRITY;
    }

    /* Check for lockout (format 0 warning) */
    if ((rc & 0x900) == 0x900) {
        return ST_TPM_LOCKOUT;
    }

    return ST_TPM_ERROR;
}

/*
* Submit a TPM command and get the response
*/
int tpm_submit_command(const u8 *cmd, u32 cmd_size, u8 *rsp, u32 *rsp_size)
{
    TBS_RESULT result;

    if (g_tbs_context == NULL || pfn_Tbsip_Submit_Command == NULL) {
        return ST_NO_TPM;
    }

    result = pfn_Tbsip_Submit_Command(
        g_tbs_context,
        TBS_COMMAND_LOCALITY_ZERO,
        TBS_COMMAND_PRIORITY_NORMAL,
        cmd,
        cmd_size,
        rsp,
        rsp_size);

    if (result != TBS_SUCCESS) {
        return ST_TPM_ERROR;
    }

    // Check TPM response code
    if (*rsp_size < 10) {
        return ST_TPM_ERROR;
    }

    u32 rc = read_be32(rsp + 6);
    return tpm_rc_to_status(rc);
}

/*
 * Get TPM information (vendor, firmware, lockout status)
 * info: Output structure for TPM info
 * Returns: ST_OK on success
 */
int dc_tpm_get_info(DC_TPM_INFO* info)
{
    int resl;

    // Initialize TPM if not already done
    resl = dc_tpm_init();
    if (resl != ST_OK) {
        return ST_NOT_SUPPORTED;
    }

    if (g_tpm_version == 1)
        return dc_tpm_12_get_info(info);

    if (g_tpm_version == 2)
        return dc_tpm_20_get_info(info);

    return ST_NOT_SUPPORTED;
}

/*
 * Read a PCR value
 * pcr_index: PCR index (0-23)
 * pcr_value: Output buffer for PCR value (32 bytes for SHA256, 20 bytes for SHA1)
 * pcr_size: In/out - buffer size / actual size
 * Returns: ST_OK on success
 */
int dc_tpm_read_pcr(u32 pcr_index, u8 *pcr_value, u32 *pcr_size)
{
    int resl;

    // Initialize TPM if not already done
    resl = dc_tpm_init();
    if (resl != ST_OK) {
        return ST_NOT_SUPPORTED;
    }

    if (g_tpm_version == 1) {
        // TPM 1.2 uses SHA-1 (20 bytes)
        if (pcr_size == NULL || *pcr_size < 20) {
            return ST_SMALL_BUFF;
        }
        resl = dc_tpm_12_pcr_read(pcr_index, pcr_value);
        if (resl == ST_OK) {
            *pcr_size = 20;
        }
        return resl;
    }

    if (g_tpm_version == 2) {
        // TPM 2.0 uses SHA-256 (32 bytes)
        return dc_tpm_20_pcr_read(pcr_index, pcr_value, pcr_size);
    }

    return ST_NOT_SUPPORTED;
}

// DC_TPM_NV_PCRS_BIT marks info entries for sealed data
#define DC_TPM_NV_PCRS_BIT  0x200000

static void _tpm_get_nv_label(u32 nv_index, wchar_t *label, int max_len)
{
    u32 base_index = nv_index & 0x00FFFFFF;

    // DCS/DiskCryptor entries (0xDC50-0xDC5F range)
    if ((base_index & 0xFFFF0) == 0x0DC50) {
        if (base_index & DC_TPM_NV_PCRS_BIT) {
            wcscpy(label, L"DCS Entry (Info)");
        } else {
            wcscpy(label, L"DCS Entry");
        }
        return;
    }

    // TCG defined indices (PC Client spec)
    if (nv_index == 0x01C00002) { wcscpy(label, L"TCG Boot Service"); return; }
    if (nv_index == 0x01C00003) { wcscpy(label, L"TCG Owner Policy"); return; }
    if (nv_index == 0x01C00004) { wcscpy(label, L"TCG Auth Policy"); return; }
    if (nv_index == 0x01C10102) { wcscpy(label, L"Windows BitLocker"); return; }
    if (nv_index == 0x01C10103) { wcscpy(label, L"Windows BitLocker (alt)"); return; }
    if (nv_index == 0x01C10104) { wcscpy(label, L"Windows Resume Key"); return; }

    // Platform indices by range
    if ((nv_index & 0xFF000000) == 0x01000000) { wcscpy(label, L"Owner Defined"); return; }
    if ((nv_index & 0xFF000000) == 0x01400000) { wcscpy(label, L"Platform Defined"); return; }
    if ((nv_index & 0xFF000000) == 0x01800000) { wcscpy(label, L"Endorsement Defined"); return; }
    if ((nv_index & 0xFF000000) == 0x01C00000) { wcscpy(label, L"TCG Defined"); return; }

    // Unknown
    label[0] = L'\0';
}

/*
 * Enumerate all NV entries
 * entries: Output array for NV entries
 * count: In/out - on input: max entries, on output: actual count
 * Returns: ST_OK on success
 */
int dc_tpm_enum_nv(DC_TPM_NV_ENTRY *entries, u32 *count)
{
    int resl;
    u32 i;

    // Initialize TPM if not already done
    resl = dc_tpm_init();
    if (resl != ST_OK) {
        return ST_NOT_SUPPORTED;
    }

    if (g_tpm_version == 1) {
        resl = dc_tpm_12_enum_nv(entries, count);
    } else if (g_tpm_version == 2) {
        resl = dc_tpm_20_enum_nv(entries, count);
    } else {
        return ST_NOT_SUPPORTED;
    }

    if (resl != ST_OK) {
        return resl;
    }

    // Populate descriptions for all entries
    for (i = 0; i < *count; i++) {
        _tpm_get_nv_label(entries[i].nv_index, entries[i].description, 64);
    }

    return ST_OK;
}

/*
 * Delete an NV entry by index (low-level, any NV index)
 * nv_index: Full NV index handle to delete
 * owner_pwd: TPM owner password for TPM 1.2 (UTF-16), NULL for TPM 2.0
 * Returns: ST_OK on success
 */
int dc_tpm_delete_nv(u32 nv_index, const wchar_t* owner_pwd)
{
    int resl;

    // Initialize TPM if not already done
    resl = dc_tpm_init();
    if (resl != ST_OK) {
        return ST_NOT_SUPPORTED;
    }

    if (g_tpm_version == 1) {
        return dc_tpm_12_delete_nv(nv_index, owner_pwd);
    }

    if (g_tpm_version == 2) {
        return dc_tpm_20_delete_nv(nv_index);
    }

    return ST_NOT_SUPPORTED;
}

int dc_tpm_wrap_payload(const dc_pass* pass, u32 backup_flags, u8* data, u32* data_size, u32* data_type)
{
    u8  password[DC_TPM_SRK_PASSWORD_MAX_SIZE];

    // Determine password type and size based on pass->flags
    if (pass->flags & PF_KEYFILE_MIXED) {
        // Keyfile mode - store as tpm_secret structure
        if (pass->size != DC_KF_HASH_SIZE) {
            return ST_PASS_ERR;  // Invalid keyfile hash size
        }
        *data_type = DCS_TPM_SECRET_TYPE_1;
        *data_size = sizeof(tpm_secret);

        // Build tpm_secret structure in Password field
        tpm_secret *secret = (tpm_secret *)password;
        secret->Flags = 0;
        secret->Kdf = pass->kdf;
        secret->Slot = pass->slot;
        secret->SecretSize = DC_KF_HASH_SIZE;
        memcpy(secret->SecretData, pass->pass, DC_KF_HASH_SIZE);
    } 
    else {
        // Plain password
        *data_type = DCS_TPM_SECRET_TYPE_PLAIN;
        *data_size = pass->size;

        memcpy(password, pass->pass, pass->size);
    }

    if (backup_flags == 0) {
		memcpy(data, password, *data_size);
		burn(password, sizeof(password));
        return ST_OK;
    }

    // Fill in tpm_backup_data in the Backup area
    tpm_backup* backup = (tpm_backup *)data;
	memset(backup, 0, sizeof(tpm_backup));
    backup->PcrMask = 0;
    backup->Flags = backup_flags;
    backup->PinSize = 0;
    backup->SecretType = *data_type;
    backup->SecretSize = (u16)*data_size;


    *data_type = DC_TPM_SECRET_TYPE_RECOVERY;
    *data_size = sizeof(tpm_backup) + backup->SecretSize;

    memcpy(backup->SecretData, password, backup->SecretSize);
    burn(password, sizeof(password));
    return ST_OK;
}

int dc_tpm_unwrap_payload(const u8* data, u32 data_size, u32 data_type, dc_pass* pass)
{
    if (data_type == DC_TPM_SECRET_TYPE_RECOVERY) {
        if (data_size < sizeof(tpm_backup)) {
            return ST_FORMAT_ERR;
        }
        tpm_backup* backup = (tpm_backup*)data;
        if (backup->SecretSize > data_size - sizeof(tpm_backup)) {
            return ST_FORMAT_ERR;
        }

        data = backup->SecretData;
		data_type = backup->SecretType;
		data_size = backup->SecretSize;
    }

    if (data_type == DCS_TPM_SECRET_TYPE_PLAIN) {
        if (data_size > sizeof(pass->pass)) {
            return ST_SMALL_BUFF;
        }
        pass->size = data_size;
		memcpy(pass->pass, data, data_size);
        return ST_OK;
    } 
    else if (data_type == DCS_TPM_SECRET_TYPE_1) {
        if (data_size < sizeof(tpm_secret)) {
            return ST_FORMAT_ERR;
        }
        tpm_secret* secret = (tpm_secret *)data;
        if (secret->SecretSize != DC_KF_HASH_SIZE) {
            return ST_FORMAT_ERR;
        }
		pass->size = secret->SecretSize;
        memcpy(pass->pass, secret->SecretData, secret->SecretSize);
        pass->kdf = secret->Kdf;
        pass->slot = secret->Slot;
        pass->flags = PF_KEYFILE_MIXED;
        return ST_OK;
    }
    
    return ST_FORMAT_ERR;
}

//////////////////////////////////////////////////////////////////////////
// TPM Operations (NV-based storage mode)
//////////////////////////////////////////////////////////////////////////

/*
 * Create a new NV entry with PIN and/or PCR protection
 * nv_index: DC_TPM_NV_INDEX_PRIMARY or DC_TPM_NV_INDEX_RECOVERY
 * pin: PIN for protection (UTF-16, can be NULL for no PIN)
 * pcr_mask: PCR mask for sealing (0 = no PCR binding)
 * pass: Password to store (if flags & PF_KEYFILE_MIXED, stored as tpm_secret)
 * info: Optional plaintext info to store (can be NULL)
 * info_size: Size of info data (0 if info is NULL)
 * owner_pwd: TPM owner password for TPM 1.2 (UTF-16), NULL for TPM 2.0
 * Returns: ST_OK on success
 */
int dc_tpm_create_nv_entry(u32 nv_index, const wchar_t* pin, u32 pcr_mask, const dc_pass* pass, const void* info, u32 info_size, const wchar_t* owner_pwd)
{
    int resl;
    u8  data[DC_TPM_SRK_PASSWORD_MAX_SIZE];
	u32 data_size = sizeof(data);
    u32 data_type = 0;
    int use_pin = 0;

    /* Prepare PIN auth if provided */
    if (pin != NULL && pin[0] != L'\0') {
        use_pin = 1;
    }

    if (pass == NULL) {
        return ST_INVALID_PARAM;
    }

    // Initialize TPM if not already done
    resl = dc_tpm_init();
    if (resl != ST_OK) {
        return ST_NOT_SUPPORTED;
    }

    resl = dc_tpm_wrap_payload(pass, nv_index == DC_TPM_NV_INDEX_RECOVERY ? DC_TPM_BACKUP_PROVISIONING : 0, data, &data_size, &data_type);
    if (resl != ST_OK) {
        goto cleanup;
	}

    resl = ST_NOT_SUPPORTED;

    if (g_tpm_version == 1) {
        resl = dc_tpm_12_create_nv_entry(
            nv_index,
            owner_pwd,
            use_pin ? (u8*)pin : NULL,
            use_pin ? (u32)(wcslen(pin) * sizeof(wchar_t)) : 0,
            pcr_mask,
            data,
            data_size,
            data_type,
            info,
            info_size);
    }

    if (g_tpm_version == 2) {
        resl = dc_tpm_20_create_nv_entry(
            0x01000000 | nv_index, // TPM 2.0 owner-defined range
            use_pin ? (u8*)pin : NULL,
            use_pin ? (u32)(wcslen(pin) * sizeof(wchar_t)) : 0,
            pcr_mask,
            data,
            data_size,
            data_type,
            info,
            info_size);
    }

cleanup:
	burn(data, sizeof(data));
    return resl;
}

/*
 * Check if a specific NV index exists
 * nv_index: DC_TPM_NV_INDEX_PRIMARY or DC_TPM_NV_INDEX_RECOVERY
 * Returns: 1 if exists, 0 otherwise
 */
int dc_tpm_nv_entry_exists(u32 nv_index)
{
    int resl;

    // Initialize TPM if not already done
    resl = dc_tpm_init();
    if (resl != ST_OK) {
        return 0;
    }

    if (g_tpm_version == 1)
        return dc_tpm_12_nv_exists(nv_index);

    if (g_tpm_version == 2)
        return dc_tpm_20_nv_exists(0x01000000 | nv_index); // TPM 2.0 owner-defined range

    return 0;
}

/*
 * Get PCR info for an NV index
 * Reads the PCR mask, flags, and optional info data from the associated PCR NV entry.
 *
 * nv_index: DC_TPM_NV_INDEX_PRIMARY or DC_TPM_NV_INDEX_RECOVERY
 * pcr_mask: Output for PCR mask (can be NULL)
 * flags: Output for flags (DC_TPM_FLAG_*, can be NULL)
 * info_buffer: Optional output buffer for info data (can be NULL)
 * info_size: In/out - on input: buffer size, on output: actual info size (can be NULL)
 * Returns: ST_OK on success
 */
int dc_tpm_nv_get_info(u32 nv_index, u32 *pcr_mask, u32 *flags, void *info_buffer, u32 *info_size)
{
    int resl;

    // Initialize TPM if not already done
    resl = dc_tpm_init();
    if (resl != ST_OK) {
        return ST_NOT_SUPPORTED;
    }

    if (g_tpm_version == 1)
        return dc_tpm_12_nv_get_info(nv_index, pcr_mask, flags, info_buffer, info_size);

    if (g_tpm_version == 2)
        return dc_tpm_20_nv_get_info(0x01000000 | nv_index, pcr_mask, flags, info_buffer, info_size); // TPM 2.0 owner-defined range

	return ST_NOT_SUPPORTED;
}

/*
 * Unseal password from TPM NV with PIN authentication
 * nv_index: DC_TPM_NV_INDEX_PRIMARY or DC_TPM_NV_INDEX_RECOVERY
 * pin: PIN string (UTF-16, can be NULL if not required)
 * pass: Output for unsealed password
 * Returns: ST_OK on success, error code otherwise
 */
int dc_tpm_unseal_nv_entry(u32 nv_index, const wchar_t* pin, dc_pass* pass)
{
    int resl = ST_NOT_SUPPORTED;
    u8  data[DC_TPM_SRK_PASSWORD_MAX_SIZE];
    u32 data_size = sizeof(data);
    u32 data_type = 0;
    int use_pin = 0;

    /* Prepare PIN auth if provided */
    if (pin != NULL && pin[0] != L'\0') {
        use_pin = 1;
    }

    // Initialize TPM if not already done
    resl = dc_tpm_init();
    if (resl != ST_OK) {
        return ST_NOT_SUPPORTED;
    }

	memset(pass, 0, sizeof(dc_pass));

    if (g_tpm_version == 1) {
        resl = dc_tpm_12_unseal_nv_entry(
            nv_index, 
            use_pin ? (u8*)pin : NULL,
            use_pin ? (u32)(wcslen(pin) * sizeof(wchar_t)) : 0,
            data, 
            &data_size, 
            &data_type);
    }

    if (g_tpm_version == 2) {
        resl = dc_tpm_20_nv_unseal_password(
            0x01000000 | nv_index, // TPM 2.0 owner-defined range
            use_pin ? (u8*)pin : NULL,
            use_pin ? (u32)(wcslen(pin) * sizeof(wchar_t)) : 0,
            data, 
            &data_size, 
            &data_type);
    }

    if (resl != ST_OK) {
		goto cleanup;
	}

	resl = dc_tpm_unwrap_payload(data, data_size, data_type, pass);

cleanup:
	burn(data, sizeof(data));
	return resl;
}

/*
 * Delete a DiskCryptor NV entry (data + PCR info)
 * nv_index: DC_TPM_NV_INDEX_PRIMARY or DC_TPM_NV_INDEX_RECOVERY
 * owner_pwd: TPM owner password for TPM 1.2 (UTF-16), NULL for TPM 2.0
 * Returns: ST_OK on success
 */
int dc_tpm_delete_nv_entry(u32 nv_index, const wchar_t* owner_pwd)
{
    int resl;

    // Initialize TPM if not already done
    resl = dc_tpm_init();
    if (resl != ST_OK) {
        return ST_NOT_SUPPORTED;
    }

    if (g_tpm_version == 1)
        return dc_tpm_12_delete_nv_entry(nv_index, owner_pwd);

    if (g_tpm_version == 2)
        return dc_tpm_20_delete_nv_entry(0x01000000 | nv_index); // TPM 2.0 owner-defined range

	return ST_NOT_SUPPORTED;
}


//////////////////////////////////////////////////////////////////////////
// TPM Operations (File-based storage mode)
//////////////////////////////////////////////////////////////////////////

/* External functions from efiinst.c and misc.c */
extern int dc_efi_get_sys_part(int dsk_num, int esp_part, wchar_t* path);
extern int dc_load_efi_file(const wchar_t *root, const wchar_t* fileName, void **data, int *size);
extern int dc_save_efi_file(const wchar_t *root, const wchar_t* fileName, void *data, int size);

/*
* AES-256-CBC encryption using Windows CryptoAPI (bcrypt)
* Input size must be a multiple of 16 bytes (no padding added)
*/
static int aes256_cbc_encrypt(
    const u8 *key,
    const u8 *iv,
    u8 *data,
    u32 data_size)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    ULONG cbResult = 0;
    u8 iv_copy[16];
    int resl = ST_ERROR;

    /* Input must be block-aligned */
    if (data_size == 0 || (data_size % 16) != 0) {
        return ST_ERROR;
    }

    /* Copy IV since bcrypt modifies it */
    memcpy(iv_copy, iv, 16);

    /* Open AES algorithm provider */
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    /* Set CBC chaining mode */
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    /* Generate key object */
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, 32, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    /* Encrypt in-place */
    status = BCryptEncrypt(hKey, data, data_size, NULL,
        iv_copy, 16, data, data_size, &cbResult, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    resl = ST_OK;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    burn(iv_copy, sizeof(iv_copy));

    return resl;
}

/*
* AES-256-CBC decryption using Windows CryptoAPI (bcrypt)
* Input size must be a multiple of 16 bytes (no padding removed)
*/
static int aes256_cbc_decrypt(
    const u8 *key,
    const u8 *iv,
    u8 *data,
    u32 data_size)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    ULONG cbResult = 0;
    u8 iv_copy[16];
    int resl = ST_ERROR;

    /* Input must be block-aligned */
    if (data_size == 0 || (data_size % 16) != 0) {
        return ST_ERROR;
    }

    /* Copy IV since bcrypt modifies it */
    memcpy(iv_copy, iv, 16);

    /* Open AES algorithm provider */
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    /* Set CBC chaining mode */
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    /* Generate key object */
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, 32, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    /* Decrypt in-place */
    status = BCryptDecrypt(hKey, data, data_size, NULL,
        iv_copy, 16, data, data_size, &cbResult, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    resl = ST_OK;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    burn(iv_copy, sizeof(iv_copy));

    return resl;
}

/*
 * Create a new SRK sealed file on EFI partition
 * file_path: DC_TPM_SRK_FILE_PRIMARY or DC_TPM_SRK_FILE_RECOVERY
 * pass: Password to seal (if flags & PF_KEYFILE_MIXED, stored as tpm_secret)
 * pcr_mask: PCR mask for sealing (0 = no PCR binding, PIN-only)
 * pin: Optional PIN for TPM auth (NULL = no PIN)
 * info: Optional plaintext info to store (NULL = none)
 * info_size: Size of info data
 * Returns: ST_OK on success, error code otherwise
 */
int dc_tpm_srk_create_file(const wchar_t* file_path, const dc_pass* pass, u32 pcr_mask, const wchar_t* pin, const void* info, u32 info_size)
{
    int resl;
    u8  data[DC_TPM_SRK_PASSWORD_MAX_SIZE];
    u32 data_size = sizeof(data);
    u32 data_type = 0;
    u32 encrypted_size;
    wchar_t root[MAX_PATH];
    int use_pin = 0;
    u8 kek[DC_TPM_SRK_KEK_SIZE];
    u8 iv[DC_TPM_SRK_IV_SIZE];
    u8 sealed_blob[DC_TPM_SRK_SEALED_BLOB_MAX];
    u32 sealed_blob_size = sizeof(sealed_blob);
    u8 plaintext_data[DC_TPM_SRK_SEALED_BLOB_MAX];
    DC_TPM_SEALED_DATA* sealed_data = (DC_TPM_SEALED_DATA*)plaintext_data;
    u8 encrypted_data[DC_TPM_SRK_SEALED_BLOB_MAX];
    DC_TPM_SRK_FILE_HEADER header;
    u8 *file_buffer = NULL;
    u32 file_size;
    u8 *write_ptr;

    if (file_path == NULL || pass == NULL) {
        return ST_INVALID_PARAM;
    }
    
    /* Initialize TPM */
    resl = dc_tpm_init();
    if (resl != ST_OK) {
        return resl;
    }

    resl = dc_tpm_wrap_payload(pass, (_wcsicmp(file_path, DC_TPM_SRK_FILE_RECOVERY) == 0) ? DC_TPM_BACKUP_PROVISIONING : 0, data, &data_size, &data_type);
    if (resl != ST_OK) {
        goto cleanup;
    }

    /* Get EFI partition */
    resl = dc_efi_get_sys_part(-1, -1, root);
    if (resl != ST_OK) {
        goto cleanup;
    }

    /* Prepare PIN auth if provided */
    if (pin != NULL && pin[0] != L'\0') {
        use_pin = 1;
    }

    /* Generate random KEK and IV */
    if (dc_device_control(DC_CTL_GET_RAND, NULL, 0, kek, sizeof(kek)) != NO_ERROR) {
        resl =  ST_ERROR;
        goto cleanup;
    }
    if (dc_device_control(DC_CTL_GET_RAND, NULL, 0, iv, sizeof(iv)) != NO_ERROR) {
        resl =  ST_ERROR;
        goto cleanup;
    }

    resl = ST_NOT_SUPPORTED;

    if (g_tpm_version == 1)
    {
        resl = tpm12_seal(NULL, 
            pcr_mask,
            use_pin ? (u8*)pin : NULL,
            use_pin ? (u32)(wcslen(pin) * sizeof(wchar_t)) : 0,
            kek, sizeof(kek),
            sealed_blob, &sealed_blob_size);
    }

    if (g_tpm_version == 2)
    {
        u32 srk_handle = 0;

        /* Create SRK */
        resl = tpm2_create_primary(&srk_handle);
        if (resl != ST_OK) {
            goto cleanup;
        }

        /* Seal KEK under SRK */
        resl = tpm2_create_sealed(
            srk_handle,
            kek, sizeof(kek),
            pcr_mask,
            use_pin ? (u8*)pin : NULL,
            use_pin ? (u32)(wcslen(pin) * sizeof(wchar_t)) : 0,
            sealed_blob, &sealed_blob_size);

        /* Flush SRK */
        tpm2_flush_context(srk_handle);
    }

    if (resl != ST_OK) {
        goto cleanup;
    }

    /* Build DC_TPM_SEALED_DATA structure */
    encrypted_size = dc_tpm_sealed_data_size((u16)data_size);
    memset(sealed_data, 0, encrypted_size);
    sealed_data->Magic = DC_TPM_SEALED_MAGIC;
    sealed_data->Version = DC_TPM_SEALED_VERSION;
    sealed_data->PasswordSize = (u16)data_size;
    sealed_data->PasswordType = data_type;

    memcpy(sealed_data->Password, data, data_size);

    sealed_data->Checksum = crc32(sealed_data->Password, data_size);

    /* Encrypt DC_TPM_SEALED_DATA with AES-256-CBC (padded to 16-byte boundary, min 96 bytes) */
    memcpy(encrypted_data, sealed_data, encrypted_size);
    burn(sealed_data, encrypted_size);

    resl = aes256_cbc_encrypt(kek, iv, encrypted_data, encrypted_size);
    burn(kek, sizeof(kek));

    if (resl != ST_OK) {
        burn(iv, sizeof(iv));
        burn(sealed_blob, sizeof(sealed_blob));
        burn(encrypted_data, encrypted_size);
        return resl;
    }

    /* Build file header */
    memset(&header, 0, sizeof(header));
    header.Magic = DC_TPM_SRK_FILE_MAGIC;
    header.Version = DC_TPM_SRK_VERSION;
    header.Flags = use_pin ? DC_TPM_FLAG_PIN_REQUIRED : DC_TPM_FLAG_NONE;
    header.PcrMask = pcr_mask;
    header.SealedBlobSize = (u16)sealed_blob_size;
    header.EncryptedSize = (u16)encrypted_size;
    memcpy(header.Iv, iv, sizeof(header.Iv));
    header.InfoSize = (u16)info_size;

    burn(iv, sizeof(iv));

    /* Calculate total file size */
    file_size = sizeof(header) + sealed_blob_size + encrypted_size + info_size;
    file_buffer = (u8 *)malloc(file_size);
    if (file_buffer == NULL) {
        burn(sealed_blob, sizeof(sealed_blob));
        burn(encrypted_data, sizeof(encrypted_data));
        return ST_NOMEM;
    }

    /* Assemble file: [Header][SealedBlob][EncryptedData][Info] */
    write_ptr = file_buffer;
    memcpy(write_ptr, &header, sizeof(header));
    write_ptr += sizeof(header);
    memcpy(write_ptr, sealed_blob, sealed_blob_size);
    write_ptr += sealed_blob_size;
    memcpy(write_ptr, encrypted_data, encrypted_size);
    write_ptr += encrypted_size;
    if (info != NULL && info_size > 0) {
        memcpy(write_ptr, info, info_size);
    }

    burn(sealed_blob, sizeof(sealed_blob));
    burn(encrypted_data, sizeof(encrypted_data));

    /* Save file */
    resl = dc_save_efi_file(root, file_path, file_buffer, file_size);

    burn(file_buffer, file_size);
    free(file_buffer);

cleanup:
    burn(data, sizeof(data));
    burn(kek, sizeof(kek));
    burn(iv, sizeof(iv));
    burn(sealed_blob, sizeof(sealed_blob));
    burn(encrypted_data, sizeof(encrypted_data));
    burn(plaintext_data, sizeof(plaintext_data));
    return resl;
}


/*
* Check if SRK sealed file exists on EFI partition
*/
int dc_tpm_srk_file_exists(const wchar_t *file_path)
{
    wchar_t root[MAX_PATH];
    wchar_t path[MAX_PATH];
    int resl;

    if (file_path == NULL) {
        return 0;
    }

    resl = dc_efi_get_sys_part(-1, -1, root);
    if (resl != ST_OK) {
        return 0;
    }

    swprintf_s(path, MAX_PATH, L"%s%s", root, file_path);
    return (_waccess(path, 0) != -1) ? 1 : 0;
}

/*
 * Get info about an SRK sealed file
 * file_path: DC_TPM_SRK_FILE_PRIMARY or DC_TPM_SRK_FILE_RECOVERY
 * pcr_mask: Output for PCR mask (can be NULL)
 * flags: Output for flags (DC_TPM_FLAG_*, can be NULL)
 * info_buffer: Optional output buffer for info data (can be NULL)
 * info_size: In/out - on input: buffer size, on output: actual info size (can be NULL)
 * Returns: ST_OK on success
 */
int dc_tpm_srk_get_file_info(const wchar_t* file_path, u32* pcr_mask, u32* flags, void* info_buffer, u32* info_size)
{
    wchar_t root[MAX_PATH];
    void *file_data = NULL;
    int file_size = 0;
    DC_TPM_SRK_FILE_HEADER *header;
    int resl;

    if (file_path == NULL) {
        return ST_ERROR;
    }

    /* Get EFI partition */
    resl = dc_efi_get_sys_part(-1, -1, root);
    if (resl != ST_OK) {
        return resl;
    }

    /* Load file */
    resl = dc_load_efi_file(root, file_path, &file_data, &file_size);
    if (resl != ST_OK) {
        return resl;
    }

    /* Check minimum size for header */
    if (file_size < (int)sizeof(DC_TPM_SRK_FILE_HEADER)) {
        free(file_data);
        return ST_FORMAT_ERR;
    }

    header = (DC_TPM_SRK_FILE_HEADER *)file_data;

    /* Validate magic */
    if (header->Magic != DC_TPM_SRK_FILE_MAGIC) {
        free(file_data);
        return ST_FORMAT_ERR;
    }

    /* Header is valid, extract info */
    if (flags) *flags = header->Flags;
    if (pcr_mask) *pcr_mask = header->PcrMask;

    if (info_buffer) {
        if (!info_size || *info_size < header->InfoSize) {
            free(file_data);
            return ST_SMALL_BUFF;
        }
        memcpy(info_buffer, (u8*)file_data + sizeof(DC_TPM_SRK_FILE_HEADER) + header->SealedBlobSize + header->EncryptedSize, header->InfoSize);
		*info_size = header->InfoSize;
    }

    free(file_data);
    return ST_OK;
}

/*
 * Unseal password from SRK sealed file with PIN authentication
 * file_path: DC_TPM_SRK_FILE_PRIMARY or DC_TPM_SRK_FILE_RECOVERY
 * pin: PIN string (UTF-16, can be NULL if not required)
 * pass: Output for unsealed password
 * Returns: ST_OK on success, error code otherwise
 */
int dc_tpm_srk_unseal_file(const wchar_t* file_path, const wchar_t* pin, dc_pass* pass)
{
    wchar_t root[MAX_PATH];
    void *file_data = NULL;
    int file_size = 0;
    DC_TPM_SRK_FILE_HEADER *header;
    u8 *sealed_blob;
    u8 *encrypted_data;
	u8 plaintext_data[DC_TPM_SRK_SEALED_BLOB_MAX];
	DC_TPM_SEALED_DATA* sealed_data = (DC_TPM_SEALED_DATA*)plaintext_data;
    u8 kek[DC_TPM_SRK_KEK_SIZE];
    int use_pin = 0;
    u32 kek_size;
    u32 crc;
    int resl;

    if (file_path == NULL || pass == NULL) {
        return ST_INVALID_PARAM;
    }

    memset(pass, 0, sizeof(dc_pass));

    /* Initialize TPM */
    resl = dc_tpm_init();
    if (resl != ST_OK) {
        return resl;
    }

    /* Get EFI partition */
    resl = dc_efi_get_sys_part(-1, -1, root);
    if (resl != ST_OK) {
        return resl;
    }

    /* Load file */
    resl = dc_load_efi_file(root, file_path, &file_data, &file_size);
    if (resl != ST_OK) {
        return resl;
    }

    /* Check minimum size for header */
    if (file_size < (int)sizeof(DC_TPM_SRK_FILE_HEADER)) {
        resl = ST_FORMAT_ERR;
        goto cleanup;
    }

    header = (DC_TPM_SRK_FILE_HEADER *)file_data;

    /* Validate magic */
    if (header->Magic != DC_TPM_SRK_FILE_MAGIC) {
        resl = ST_FORMAT_ERR;
        goto cleanup;
    }

    /* Validate version */
    if (header->Version != DC_TPM_SRK_VERSION) {
        resl = ST_INCOMPATIBLE;
        goto cleanup;
    }

    /* Validate file size */
    if (file_size < (int)(sizeof(DC_TPM_SRK_FILE_HEADER) + header->SealedBlobSize + header->EncryptedSize)) {
        resl = ST_FORMAT_ERR;
        goto cleanup;
    }

    /* Validate encrypted size - must be 16-byte aligned and at least minimum size */
    if (header->EncryptedSize < DC_TPM_SEALED_MIN_SIZE ||
        (header->EncryptedSize & 15) != 0 ||
        header->EncryptedSize > DC_TPM_SRK_SEALED_BLOB_MAX) {
        resl = ST_FORMAT_ERR;
        goto cleanup;
    }

    /* Prepare PIN auth if provided */
    if (pin != NULL && pin[0] != L'\0') {
        use_pin = 1;
    }

    /* Get pointers to sealed blob and encrypted data */
    sealed_blob = (u8 *)file_data + sizeof(DC_TPM_SRK_FILE_HEADER);
    encrypted_data = sealed_blob + header->SealedBlobSize;

    /* Unseal KEK using TPM */
    resl = ST_NOT_SUPPORTED;
    kek_size = sizeof(kek);

    if (g_tpm_version == 1)
    {
        resl = tpm12_unseal_with_auth(
            sealed_blob, 
            header->SealedBlobSize,
            use_pin ? (u8*)pin : NULL,
            use_pin ? (u32)(wcslen(pin) * sizeof(wchar_t)) : 0,
            kek, &kek_size);
    }

    if (g_tpm_version == 2)
    {
        u32 srk_handle = 0;
        u32 sealed_handle = 0;

        /* Create SRK */
        resl = tpm2_create_primary(&srk_handle);
        if (resl != ST_OK) {
            goto cleanup;
        }

        /* Load sealed object under SRK */
        resl = tpm2_load(srk_handle, sealed_blob, header->SealedBlobSize, &sealed_handle);
        if (resl != ST_OK) {
            tpm2_flush_context(srk_handle);
            goto cleanup;
        }

        /* Unseal KEK */
        resl = tpm2_unseal(sealed_handle, 
            use_pin ? (u8*)pin : NULL,
            use_pin ? (u32)(wcslen(pin) * sizeof(wchar_t)) : 0,
            kek, &kek_size);

        /* Flush handles */
        tpm2_flush_context(sealed_handle);
        tpm2_flush_context(srk_handle);
    }

    if (resl != ST_OK) {
        goto cleanup;
    }

    /* Validate KEK size */
    if (kek_size != DC_TPM_SRK_KEK_SIZE) {
        resl = ST_FORMAT_ERR;
        goto cleanup;
    }

    /* Copy encrypted data to work buffer */
    memcpy(sealed_data, encrypted_data, header->EncryptedSize);

    /* Decrypt using AES-256-CBC */
    resl = aes256_cbc_decrypt(kek, header->Iv, (u8 *)sealed_data, header->EncryptedSize);
    burn(kek, sizeof(kek));

    if (resl != ST_OK) {
        goto cleanup;
    }

    /* Validate decrypted data */
    if (sealed_data->Magic != DC_TPM_SEALED_MAGIC) {
        resl = ST_FORMAT_ERR;
        goto cleanup;
    }

    if (sealed_data->Version != DC_TPM_SEALED_VERSION) {
        resl = ST_INCOMPATIBLE;
        goto cleanup;
    }

    /* Validate password size fits within encrypted data */
    if (sealed_data->PasswordSize > header->EncryptedSize - DC_TPM_SEALED_BASE_SIZE) {
        resl = ST_FORMAT_ERR;
        goto cleanup;
    }

    /* Verify CRC */
    crc = crc32(sealed_data->Password, sealed_data->PasswordSize);
    if (crc != sealed_data->Checksum) {
        resl = ST_FORMAT_ERR;
        goto cleanup;
    }

    /* Unwrap payload to dc_pass */
    resl = dc_tpm_unwrap_payload(sealed_data->Password, sealed_data->PasswordSize, sealed_data->PasswordType, pass);

cleanup:
    burn(plaintext_data, sizeof(plaintext_data));
    burn(kek, sizeof(kek));

    if (file_data != NULL) {
        burn(file_data, file_size);
        free(file_data);
    }

    return resl;
}

/*
* Delete SRK sealed file from EFI partition
*/
int dc_tpm_srk_delete_file(const wchar_t* file_path)
{
    wchar_t root[MAX_PATH];
    wchar_t path[MAX_PATH];
    int resl;

    if (file_path == NULL) {
        return ST_ERROR;
    }

    resl = dc_efi_get_sys_part(-1, -1, root);
    if (resl != ST_OK) {
        return resl;
    }

    swprintf_s(path, MAX_PATH, L"%s%s", root, file_path);

    if (_wremove(path) == 0 || _waccess(path, 0) == -1) {
        return ST_OK;
    }

    return ST_ERROR;
}


//////////////////////////////////////////////////////////////////////////
// Secret Backup
//////////////////////////////////////////////////////////////////////////

/*
* Check if TPM backup file exists on the EFI partition
* Returns: 1 if file exists, 0 otherwise
*/
int dc_tpm_backup_file_exists()
{
    wchar_t root[MAX_PATH];
    wchar_t path[MAX_PATH];
    int resl;

    resl = dc_efi_get_sys_part(-1, -1, root);
    if (resl != ST_OK) {
        return 0;
    }

    swprintf_s(path, MAX_PATH, L"%s%s", root, DC_TPM_BACKUP_FILE_PATH);

    return (_waccess(path, 0) != -1) ? 1 : 0;
}

/*
 * Create a new TPM backup file on EFI partition
 * password: Encryption password for the backup file
 * pass: Secret to store (if flags & PF_KEYFILE_MIXED, stored as tpm_secret)
 * kdf: KDF to use (0 = PKCS5.2, 5 = Argon2id)
 * cipher: Cipher to use (0 = AES)
 * Returns: ST_OK on success
 */
int dc_tpm_backup_file_create(dc_pass *password, dc_pass *pass, int kdf, int cipher)
{
    wchar_t root[MAX_PATH];
    DC_TPM_BACKUP_FILE file_data;
    UINT32 data_size = DC_TPM_BACKUP_DATA_SPACE;
    UINT32 data_type = 0;
    u8 dk[PKCS_DERIVE_MAX];
    xts_key hdr_key;
    int resl;

    // Validate parameters
    if (password == NULL || pass == NULL) {
        return ST_ERROR;
    }

    // Initialize crypto
    dc_init_crypto();

    // Get EFI partition path
    resl = dc_efi_get_sys_part(-1, -1, root);
    if (resl != ST_OK) {
        return resl;
    }

    // Initialize file structure
    memset(&file_data, 0, sizeof(file_data));

    // Generate random salt
    if (dc_device_control(DC_CTL_GET_RAND, NULL, 0, file_data.Salt, sizeof(file_data.Salt)) != NO_ERROR) {
        return ST_ERROR;
    }

    // Set up the backup structure
    file_data.Magic = DC_TPM_BACKUP_MAGIC;
    file_data.Version = DC_TPM_BACKUP_VERSION;

    // Fill in tpm_backup_data in the Backup area
	dc_tpm_wrap_payload(pass, DC_TPM_BACKUP_PROVISIONING, file_data.Backup, &data_size, &data_type);

    file_data.BackupSize = (u16)data_size;
    file_data.BackupType = data_type;

    // Calculate CRC (covers from Version field to end of Backup)
    file_data.Crc = crc32((u8*)&file_data.Version, DC_TPM_BACKUP_CRC_SIZE);

    // Derive encryption key from password and salt
    if (!dc_derive_key_um(password, kdf, file_data.Salt, dk, NULL)) {
        burn(&file_data, sizeof(file_data));
        return ST_ERROR;
    }

    // Set up XTS key
    if (!xts_set_key(dk, cipher, &hdr_key)) {
        burn(dk, sizeof(dk));
        burn(&file_data, sizeof(file_data));
        return ST_ERROR;
    }

    // Encrypt the entire file (salt becomes garbage in encrypted output, but we copy it back)
    u8 encrypted[DC_TPM_BACKUP_FILE_SIZE];
    u8 salt_backup[64];
    memcpy(salt_backup, file_data.Salt, sizeof(salt_backup));

    xts_encrypt(
        (u8*)&file_data,
        encrypted,
        DC_TPM_BACKUP_FILE_SIZE,
        0,
        &hdr_key);

    // Restore salt in plaintext at the beginning
    memcpy(encrypted, salt_backup, sizeof(salt_backup));

    // Clean up sensitive data
    burn(dk, sizeof(dk));
    burn(&hdr_key, sizeof(hdr_key));
    burn(&file_data, sizeof(file_data));
    burn(salt_backup, sizeof(salt_backup));

    // Save to file
    resl = dc_save_efi_file(root, DC_TPM_BACKUP_FILE_PATH, encrypted, DC_TPM_BACKUP_FILE_SIZE);

    burn(encrypted, sizeof(encrypted));

    return resl;
}

/*
* Unseal TPM backup file from EFI partition
* password: input password
* pass: output unsealed password
* Returns: ST_OK on success, error code otherwise
*/
int dc_tpm_unseal_backup_file(dc_pass* password, dc_pass* pass)
{
    wchar_t root[MAX_PATH];
    DC_TPM_BACKUP_FILE *file_data = NULL;
    int file_size = 0;
    int resl;
    u8 dk[PKCS_DERIVE_MAX];
    xts_key hdr_key;
    DC_TPM_BACKUP_FILE decrypted;
    //tpm_backup *backup;
    u32 crc;
    int i;
    int kdf_idx;
    int *kdfs;
    int oneKdf[] = { 0, -1 };

    if (password->kdf == KDF_ALL) {
        extern const int dc_all_kdfs[];
        kdfs = (int*)dc_all_kdfs;
    }
    else if (password->kdf == KDF_DEFAULT) {
        extern const int dc_default_kdfs[];
        kdfs = (int*)dc_default_kdfs;
    }
    else {
        oneKdf[0] = password->kdf;
        kdfs = oneKdf;
    }

    // Initialize crypto if not already done
    dc_init_crypto();

    // Get EFI partition path
    resl = dc_efi_get_sys_part(-1, -1, root);
    if (resl != ST_OK) {
        return resl;
    }

    // Load backup file
    resl = dc_load_efi_file(root, DC_TPM_BACKUP_FILE_PATH, &file_data, &file_size);
    if (resl != ST_OK) {
        return resl;
    }

    // Verify file size
    if (file_size < DC_TPM_BACKUP_FILE_SIZE) {
        free(file_data);
        return ST_FORMAT_ERR;
    }

    // Try decryption with each KDF
    resl = ST_PASS_ERR;
    for (kdf_idx = 0; kdfs[kdf_idx] >= 0 && resl == ST_PASS_ERR; kdf_idx++) {
       
        // Derive key from password and salt (salt is plaintext in file)
        if (!dc_derive_key_um(password, kdfs[kdf_idx], file_data->Salt, dk, NULL)) {
            continue;
        }

        // Try all ciphers
        for (i = 0; i < CF_CIPHERS_NUM; i++) {

            if (!xts_set_key(dk, i, &hdr_key)) {
                continue;
            }

            // Decrypt entire buffer from offset 0 (like dc_header)
            // Salt area in decrypted buffer becomes garbage, but we don't need it
            xts_decrypt(
                (u8*)file_data,
                (u8*)&decrypted,
                DC_TPM_BACKUP_FILE_SIZE,
                0,
                &hdr_key);

            // Check magic
            if (decrypted.Magic != DC_TPM_BACKUP_MAGIC) {
                continue;
            }

            // Check CRC (covers from Version field to end)
            crc = crc32((u8*)&decrypted.Version, DC_TPM_BACKUP_CRC_SIZE);
            if (crc != decrypted.Crc) {
                continue;
            }

            // Check version
            if (decrypted.Version != DC_TPM_BACKUP_VERSION) {
                resl = ST_INCOMPATIBLE;
                goto cleanup;
            }
            
            if (decrypted.BackupSize > DC_TPM_BACKUP_DATA_SPACE) {
                resl = ST_SMALL_BUFF;
                goto cleanup;
            }

            resl = ST_OK;
			break;
        }
    }

    if (resl != ST_OK) goto cleanup;

	resl = dc_tpm_unwrap_payload(decrypted.Backup, decrypted.BackupSize, decrypted.BackupType, pass);

cleanup:
    burn(&decrypted, sizeof(decrypted));
    burn(dk, sizeof(dk));
    burn(&hdr_key, sizeof(hdr_key));

    burn(file_data, file_size);
    free(file_data);

    return resl;
}

/*
* Delete TPM backup file from EFI partition
* Returns: ST_OK on success, error code otherwise
*/
int dc_tpm_backup_file_delete(void)
{
    wchar_t root[MAX_PATH];
    wchar_t path[MAX_PATH];
    int resl;

    resl = dc_efi_get_sys_part(-1, -1, root);
    if (resl != ST_OK) {
        return resl;
    }

    swprintf_s(path, MAX_PATH, L"%s%s", root, DC_TPM_BACKUP_FILE_PATH);

    if (_wremove(path) == 0 || _waccess(path, 0) == -1) {
        return ST_OK;
    }

    return ST_ERROR;
}
