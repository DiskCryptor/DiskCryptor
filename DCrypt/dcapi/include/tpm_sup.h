#ifndef _TPM_SUP_H_
#define _TPM_SUP_H_

#include "dcapi.h"
#include "volume_header.h"

/*
* TPM NV Index Constants
*/
#define DC_TPM_NV_INDEX_PRIMARY     0x0000DC5C   // Default NV index (PCR protected)
#define DC_TPM_NV_INDEX_RECOVERY    0x0000DC5E   // Backup NV index (PIN protected)

/*
* Sealed data flags (matching DcsTpmLib.h)
*/
#define DC_TPM_FLAG_NONE            0x00000000
#define DC_TPM_FLAG_PIN_REQUIRED    0x00000001  // TPM-validated PIN is required to unseal

/*
* TPM Sealed Data Structure (stored in NV or encrypted in SRK file)
* Variable-length password with padding to 16-byte boundary, minimum 96 bytes
*/
#pragma pack(push, 1)
typedef struct _DC_TPM_SEALED_DATA {
    u32  Magic;             // DC_TPM_SEALED_MAGIC (0x50544344)
    u16  Version;           // Structure version (DC_TPM_SEALED_VERSION)
    u16  PasswordSize;      // Password size in bytes
    u32  PasswordType;      // Password type (DiskCryptor-specific)
    u32  Checksum;          // CRC32 of password data
    u8   Reserved[16];      // Reserved for future use
    u8   Password[0];       // Variable-length password data (padded to 16-byte boundary)
} DC_TPM_SEALED_DATA;
#pragma pack(pop)

#define DC_TPM_SEALED_MAGIC         0x50544344  // "DCTP"
#define DC_TPM_SEALED_VERSION       1
#define DC_TPM_SEALED_BASE_SIZE     32          // Size of header without Password[]
#define DC_TPM_SEALED_MIN_SIZE      96          // Minimum total size (6 x 16-byte blocks)

/*
* Calculate padded size for DC_TPM_SEALED_DATA
* Returns size aligned to 16 bytes, minimum 96 bytes
*/
static inline u32 dc_tpm_sealed_data_size(u16 password_size) {
    u32 size = DC_TPM_SEALED_BASE_SIZE + password_size;
    size = (size + 15) & ~15;  // Round up to 16-byte boundary
    if (size < DC_TPM_SEALED_MIN_SIZE) {
        size = DC_TPM_SEALED_MIN_SIZE;
    }
    return size;
}

/*
* PCR Info data structure for NV-based plaintext storage
* Compatible with DC_TPM_PCRINFO_DATA from DcsTpmLib.h
*/
#pragma pack(push, 1)
typedef struct _DC_TPM_PCRINFO_DATA {
    u32  Magic;             // DC_TPM_PCRINFO_MAGIC
    u16  Version;           // Structure version (currently 1)
    u16  InfoSize;          // Size of InfoData (0 = none, max DC_TPM_INFO_MAX_SIZE)
    u32  PcrMask;           // PCR mask used for sealing
    u32  Flags;             // Flags (DC_TPM_FLAG_*)
    u8   InfoData[0];       // Variable-length payload
} DC_TPM_PCRINFO_DATA;
#pragma pack(pop)

#define DC_TPM_PCRINFO_MAGIC        0x49524350  // "PCRI" - PCR info structure
#define DC_TPM_PCRINFO_VERSION      1
#define DC_TPM_PCRINFO_BASE_SIZE    16  // Size of header without InfoData

/*
* TPM SRK File Constants (matching UEFI DcsTpmLib.h)
* These files contain TPM-sealed secrets using SRK (Storage Root Key)
*/

#define DC_TPM_SRK_FILE_PRIMARY     L"\\EFI\\DCS\\tpm_sealed.dat"
#define DC_TPM_SRK_FILE_RECOVERY    L"\\EFI\\DCS\\tpm_recovery.dat"

#define DC_TPM_SRK_KEK_SIZE             32      /* AES-256 key for envelope */
#define DC_TPM_SRK_IV_SIZE              16      /* AES IV size */
#define DC_TPM_INFO_MAX_SIZE            512     /* Max plaintext info */
#define DC_TPM_SRK_PASSWORD_MAX_SIZE    480     /* Max password size */
#define DC_TPM_SRK_SEALED_BLOB_MAX      512     /* Max sealed blob size (for backwards compat) */


//////////////////////////////////////////////////////////////////////////
// TPM Initialization and Command Submission
//////////////////////////////////////////////////////////////////////////

/*
* Initialize TPM access
* Opens TBS context and detects TPM version
* Returns: ST_OK on success, ST_NO_TPM if no TPM available
*/
int dc_api dc_tpm_init(void);

/*
* Close TPM access
* Releases TBS context
*/
void dc_api dc_tpm_close(void);

/*
* Get TPM version
* Returns: 1 for TPM 1.2, 2 for TPM 2.0, 0 if not initialized
*/
int dc_api dc_tpm_get_version(void);

/*
* Submit a TPM command and get the response
*/
int tpm_submit_command(
    const u8 *cmd,
    u32 cmd_size,
    u8 *rsp,
    u32 *rsp_size);

/*
* TPM Properties Structure
*/
typedef struct _DC_TPM_INFO {
    int     version;            // 0=none, 1=TPM1.2, 2=TPM2.0
    u32     vendor_id;          // TPM vendor ID
    char    vendor_str[8];      // Vendor as string (4 chars + null)
    u32     firmware_v1;        // Firmware version part 1
    u32     firmware_v2;        // Firmware version part 2
    u32     lockout_counter;    // Current lockout counter (failed auth attempts)
    u32     lockout_max;        // Max lockout attempts before DA lockout
    u32     lockout_interval;   // Seconds before counter can be decremented
    u32     lockout_recovery;   // Seconds between counter decrements
    int     is_locked_out;      // 1 if TPM is in DA lockout, 0 otherwise
} DC_TPM_INFO;

/*
* Get TPM information (vendor, firmware, lockout status)
* info: output structure for TPM info
* Returns: ST_OK on success
*/
int dc_api dc_tpm_get_info(DC_TPM_INFO *info);

/*
* Read a PCR value
* pcr_index: PCR index (0-23)
* pcr_value: output buffer for PCR value (32 bytes for SHA256, 20 bytes for SHA1)
* pcr_size: in/out - buffer size / actual size
* Returns: ST_OK on success
*/
int dc_api dc_tpm_read_pcr(u32 pcr_index, u8 *pcr_value, u32 *pcr_size);

/*
* NV Entry Information Structure
*/
#define DC_TPM_NV_MAX_ENTRIES   64

typedef struct _DC_TPM_NV_ENTRY {
    u32     nv_index;           // NV index handle
    u32     attributes;         // NV attributes (TPM 2.0) or permissions (TPM 1.2)
    u16     data_size;          // Size of data in NV
    u32     pcr_mask;           // PCR mask if applicable (TPM 1.2)
    wchar_t description[64];    // Description if available
} DC_TPM_NV_ENTRY;

/*
* Enumerate all NV entries
* entries: output array for NV entries
* count: in/out - on input: max entries, on output: actual count
* Returns: ST_OK on success
*/
int dc_api dc_tpm_enum_nv(DC_TPM_NV_ENTRY *entries, u32 *count);

/*
* Delete an NV entry by index (low-level, any NV index)
* nv_index: Full NV index handle to delete
* owner_pwd: TPM owner password for TPM 1.2 (UTF-16), NULL for TPM 2.0
* Returns: ST_OK on success
*/
int dc_api dc_tpm_delete_nv(u32 nv_index, const wchar_t* owner_pwd);

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
int dc_api dc_tpm_create_nv_entry(
    u32 nv_index,
    const wchar_t *pin,
    u32 pcr_mask,
    const dc_pass *pass,
    const void *info,
    u32 info_size,
    const wchar_t* owner_pwd);

/*
* Check if a specific NV index exists
* nv_index: DC_TPM_NV_INDEX_PRIMARY or DC_TPM_NV_INDEX_RECOVERY
* Returns: 1 if exists, 0 otherwise
*/
int dc_api dc_tpm_nv_entry_exists(u32 nv_index);

/*
* Get PCR info for an NV index
* Reads the PCR mask, flags, and optional info data from the associated PCR NV entry.
*
* nv_index: DC_TPM_NV_INDEX_PRIMARY or DC_TPM_NV_INDEX_RECOVERY
* pcr_mask: output for PCR mask (can be NULL)
* flags: output for flags (DC_TPM_FLAG_*, can be NULL)
* info_buffer: optional output buffer for info data (can be NULL)
* info_size: in/out - on input: buffer size, on output: actual info size (can be NULL)
* Returns: ST_OK on success
*/
int dc_api dc_tpm_nv_get_info(
    u32 nv_index,
    u32 *pcr_mask,
    u32 *flags,
    void *info_buffer,
    u32 *info_size);

/*
* Unseal password from TPM NV with PIN authentication
* nv_index: DC_TPM_NV_INDEX_PRIMARY or DC_TPM_NV_INDEX_RECOVERY
* pin: PIN string (UTF-16, can be NULL if not required)
* pass: output
* Returns: ST_OK on success, error code otherwise
*
*/
int dc_api dc_tpm_unseal_nv_entry(
    u32 nv_index,
    const wchar_t *pin,
    dc_pass* pass);

/*
* Delete a DiskCryptor NV entry (data + PCR info)
* nv_index: DC_TPM_NV_INDEX_PRIMARY or DC_TPM_NV_INDEX_RECOVERY
* owner_pwd: TPM owner password for TPM 1.2 (UTF-16), NULL for TPM 2.0
* Returns: ST_OK on success
*/
int dc_api dc_tpm_delete_nv_entry(u32 nv_index, const wchar_t* owner_pwd);


//////////////////////////////////////////////////////////////////////////
// TPM Operations (File-based storage mode)
//////////////////////////////////////////////////////////////////////////

/*
* Create a new SRK sealed file on EFI partition
* file_path: DC_TPM_SRK_FILE_PRIMARY or DC_TPM_SRK_FILE_RECOVERY
* pass: password to seal (if flags & PF_KEYFILE_MIXED, stored as tpm_secret)
* pcr_mask: PCR mask for sealing (0 = no PCR binding, PIN-only)
* pin: optional PIN for TPM auth (NULL = no PIN)
* info: optional plaintext info to store (NULL = none)
* info_size: size of info data
* Returns: ST_OK on success, error code otherwise
*/
int dc_api dc_tpm_srk_create_file(
    const wchar_t *file_path,
    const dc_pass *pass,
    u32 pcr_mask,
    const wchar_t *pin,
    const void *info,
    u32 info_size);

/*
* Check if SRK sealed file exists on the EFI partition
* file_path: DC_TPM_SRK_FILE_PRIMARY or DC_TPM_SRK_FILE_RECOVERY
* Returns: 1 if file exists, 0 otherwise
*/
int dc_api dc_tpm_srk_file_exists(const wchar_t *file_path);

/*
* Get info about an SRK sealed file
* file_path: DC_TPM_SRK_FILE_PRIMARY or DC_TPM_SRK_FILE_RECOVERY
* 
* pcr_mask: output for PCR mask (can be NULL)
* flags: output for flags (DC_TPM_FLAG_*, can be NULL)
* info_buffer: optional output buffer for info data (can be NULL)
* info_size: in/out - on input: buffer size, on output: actual info size (can be NULL)
* Returns: ST_OK on success
*/
int dc_api dc_tpm_srk_get_file_info(
    const wchar_t *file_path,
    u32 *pcr_mask,
    u32 *flags,
    void *info_buffer,
    u32 *info_size);

/*
* Unseal password from TPM NV with PIN authentication
* file_path: DC_TPM_SRK_FILE_PRIMARY or DC_TPM_SRK_FILE_RECOVERY
* 
* pin: PIN string (UTF-16, can be NULL if not required)
* pass: output
* Returns: ST_OK on success, error code otherwise
*
*/
int dc_api dc_tpm_srk_unseal_file(
    const wchar_t *file_path,
    const wchar_t *pin,
    dc_pass* pass);

/*
* Delete SRK sealed file from EFI partition
* file_path: DC_TPM_SRK_FILE_PRIMARY or DC_TPM_SRK_FILE_RECOVERY
* Returns: ST_OK on success, error code otherwise
*/
int dc_api dc_tpm_srk_delete_file(const wchar_t *file_path);


//////////////////////////////////////////////////////////////////////////
// Secret Backup
//////////////////////////////////////////////////////////////////////////

/*
* Create a new TPM backup file on EFI partition
* file_path: file path relative to EFI partition
* password: encryption password
* pass: secret to store (if flags & PF_KEYFILE_MIXED, stored as tpm_secret)
* kdf: KDF to use (0 = PKCS5.2, 5 = Argon2id)
* cipher: cipher to use (0 = AES)
* Returns: ST_OK on success
*/
int dc_api dc_tpm_backup_file_create(
    dc_pass *password,
    dc_pass *pass,
    int kdf,
    int cipher);

/*
* Check if TPM backup file exists on the EFI partition
* Returns: 1 if file exists, 0 otherwise
*/
int dc_api dc_tpm_backup_file_exists();

/*
* Restore TPM backup from password-encrypted file on EFI partition
* password: backup password
* pass: unsealed secret
* Returns: ST_OK on success, error code otherwise
*/
int dc_api dc_tpm_unseal_backup_file(
    dc_pass *password, 
    dc_pass *pass);

/*
* Delete TPM backup file from EFI partition
* Returns: ST_OK on success, error code otherwise
*/
int dc_api dc_tpm_backup_file_delete(void);


//////////////////////////////////////////////////////////////////////////
// TPM Defines and Constants
//////////////////////////////////////////////////////////////////////////

/*
* TPM 2.0 Command/Response Tags
*/
#define TPM_ST_NO_SESSIONS      0x8001
#define TPM_ST_SESSIONS         0x8002

/*
* TPM 2.0 Command Codes
*/
#define TPM_CC_NV_ReadPublic    0x00000169
#define TPM_CC_NV_Read          0x0000014E
#define TPM_CC_StartAuthSession 0x00000176
#define TPM_CC_PolicyPCR        0x0000017F
#define TPM_CC_PolicyPassword   0x0000018C
#define TPM_CC_PolicyGetDigest  0x00000189
#define TPM_CC_PolicyAuthValue  0x0000016B  // Used in policy digest (PolicyPassword uses same digest)
#define TPM_CC_FlushContext     0x00000165
#define TPM_CC_GetCapability    0x0000017A
#define TPM_CC_CreatePrimary    0x00000131
#define TPM_CC_Create           0x00000153
#define TPM_CC_PCR_Read         0x0000017E
#define TPM_CC_Load             0x00000157
#define TPM_CC_Unseal           0x0000015E

/*
* TPM 2.0 Response Codes
*/
#define TPM_RC_SUCCESS          0x00000000

/*
* TPM 2.0 Session Types
*/
#define TPM_SE_HMAC             0x00
#define TPM_SE_POLICY           0x01
#define TPM_SE_TRIAL            0x03

/*
* Attribute flags for storage keys 
*/
#define TPMA_OBJECT_FIXEDTPM            0x00000002
#define TPMA_OBJECT_FIXEDPARENT         0x00000010
#define TPMA_OBJECT_SENSITIVEDATAORIGIN 0x00000020
#define TPMA_OBJECT_USERWITHAUTH        0x00000040
#define TPMA_OBJECT_ADMINWITHPOLICY     0x00000080
#define TPMA_OBJECT_NODA                0x00000400
#define TPMA_OBJECT_RESTRICTED          0x00010000
#define TPMA_OBJECT_DECRYPT             0x00020000

/*
* TPM 2.0 Well-known Handles
*/
#define TPM_RS_PW               0x40000009  // Password session
#define TPM_RH_NULL             0x40000007  // Null handle
#define TPM_RH_OWNER            0x40000001  // Owner hierarchy

/*
* TPM 2.0 Algorithm IDs
*/
#define TPM_ALG_RSA             0x0001
#define TPM_ALG_SHA256          0x000B
#define TPM_ALG_AES             0x0006
#define TPM_ALG_CFB             0x0043
#define TPM_ALG_NULL            0x0010
#define TPM_ALG_KEYEDHASH       0x0008

/*
* TPM 2.0 Capability Constants
*/
#define TPM_CAP_TPM_PROPERTIES  0x00000006
#define TPM_PT_MANUFACTURER     0x00000105
#define TPM_PT_VENDOR_STRING_1  0x00000106
#define TPM_PT_VENDOR_STRING_2  0x00000107
#define TPM_PT_FIRMWARE_VERSION_1 0x0000010B
#define TPM_PT_FIRMWARE_VERSION_2 0x0000010C
#define TPM_PT_LOCKOUT_COUNTER  0x0000020E
#define TPM_PT_MAX_AUTH_FAIL    0x0000020F
#define TPM_PT_LOCKOUT_INTERVAL 0x00000210
#define TPM_PT_LOCKOUT_RECOVERY 0x00000211

/*
* TPM 2.0 Additional Command Codes
*/
#define TPM_CC_NV_ReadPublic    0x00000169
#define TPM_CC_NV_DefineSpace   0x0000012A
#define TPM_CC_NV_Write         0x00000137
#define TPM_CC_NV_UndefineSpace 0x00000122

/*
* TPM 2.0 Handle Types
*/
#define TPM_RH_OWNER            0x40000001
#define TPM_RH_PLATFORM         0x4000000C

/*
* TPM 2.0 NV Attributes
*/
#define TPMA_NV_PPWRITE         0x00000001
#define TPMA_NV_OWNERWRITE      0x00000002
#define TPMA_NV_AUTHWRITE       0x00000004
#define TPMA_NV_POLICYWRITE     0x00000008
#define TPMA_NV_PPREAD          0x00010000
#define TPMA_NV_OWNERREAD       0x00020000
#define TPMA_NV_AUTHREAD        0x00040000
#define TPMA_NV_POLICYREAD      0x00080000
#define TPMA_NV_NO_DA           0x02000000
#define TPMA_NV_WRITTEN         0x20000000
#define TPMA_NV_WRITELOCK       0x40000000

#ifndef TBS_SUCCESS
#define TBS_SUCCESS 0
#endif

#ifndef TBS_CONTEXT_VERSION_ONE
#define TBS_CONTEXT_VERSION_ONE 1
#endif

#ifndef TBS_CONTEXT_VERSION_TWO
#define TBS_CONTEXT_VERSION_TWO 2
#endif

#ifndef TBS_COMMAND_LOCALITY_ZERO
#define TBS_COMMAND_LOCALITY_ZERO 0
#endif

#ifndef TBS_COMMAND_PRIORITY_NORMAL
#define TBS_COMMAND_PRIORITY_NORMAL 200
#endif

typedef UINT32 TBS_RESULT;
typedef void *TBS_HCONTEXT;

/*
* Byte order helpers (big-endian, TPM native order)
*/
static inline void write_be16(u8 *p, u16 v) {
    p[0] = (u8)(v >> 8);
    p[1] = (u8)(v);
}

static inline void write_be32(u8 *p, u32 v) {
    p[0] = (u8)(v >> 24);
    p[1] = (u8)(v >> 16);
    p[2] = (u8)(v >> 8);
    p[3] = (u8)(v);
}

static inline u16 read_be16(const u8 *p) {
    return ((u16)p[0] << 8) | p[1];
}

static inline u32 read_be32(const u8 *p) {
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3];
}

extern TBS_HCONTEXT g_tbs_context;
extern int g_tpm_version;

#endif /* _TPM_SUP_H_ */