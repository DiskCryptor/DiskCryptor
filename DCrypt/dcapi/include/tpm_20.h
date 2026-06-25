#ifndef _TPM_20_H_
#define _TPM_20_H_

#include "dcapi.h"
#include "volume_header.h"


//////////////////////////////////////////////////////////////////////////
// TPM Operations (NV-based storage mode)
//////////////////////////////////////////////////////////////////////////

#define DC_TPM_NV_INDEX_PCR_FLAG    0x00200000   // Flag to derive PCR index

/*
 * Unseal password from TPM NV with PIN and/or PCR authentication
 * nv_index: DC_TPM2_NV_INDEX_DEFAULT or DC_TPM2_NV_INDEX_BACKUP
 * pin: PIN string (UTF-16, can be NULL if not required)
 * password: output buffer for password
 * password_size: in: buffer size, out: actual password size
 * password_type: output password type (can be NULL)
 * Returns: ST_OK on success, error code otherwise
 *
 * Supports:
 *   - PIN-only (PcrMask == 0): Uses password authentication
 *   - PCR-only (PcrMask != 0, no PIN): Uses PCR policy session
 *   - PCR+PIN (PcrMask != 0, with PIN): Uses PCR policy + PolicyPassword
 */
int dc_tpm_20_nv_unseal_password(
    u32 nv_index,
    const u8 *pin_auth,
    u32 pin_auth_size,
    void *password,
    u32 *password_size,
    u32 *password_type);

/*
 * Get TPM information (vendor, firmware, lockout status)
 * info: output structure for TPM info
 * Returns: ST_OK on success
 */
int dc_tpm_20_get_info(DC_TPM_INFO *info);

/*
 * Read a PCR value (SHA256 bank)
 * pcr_index: PCR index (0-23)
 * pcr_value: output buffer for PCR value (32 bytes for SHA256)
 * pcr_size: in/out - buffer size / actual size
 * Returns: ST_OK on success
 */
int dc_tpm_20_pcr_read(u32 pcr_index, u8 *pcr_value, u32 *pcr_size);

/*
 * Enumerate all NV entries
 * entries: output array for NV entries
 * count: in/out - on input: max entries, on output: actual count
 * Returns: ST_OK on success
 */
int dc_tpm_20_enum_nv(DC_TPM_NV_ENTRY *entries, u32 *count);

/*
 * Delete an NV entry by index (low-level, any NV index)
 * nv_index: Full NV index handle to delete
 * Returns: ST_OK on success
 */
int dc_tpm_20_delete_nv(u32 nv_index);

/*
 * Check if a specific NV index exists
 * nv_index: DC_TPM2_NV_INDEX_DEFAULT or DC_TPM2_NV_INDEX_BACKUP
 * Returns: 1 if exists, 0 otherwise
 */
int dc_tpm_20_nv_exists(u32 nv_index);

/*
 * Create a new NV entry with PIN and/or PCR protection
 * nv_index: DC_TPM2_NV_INDEX_DEFAULT or DC_TPM2_NV_INDEX_BACKUP
 * pin: PIN for protection (UTF-16, can be NULL)
 * pcr_mask: PCR mask for sealing (0 = no PCR binding)
 * password: password to store
 * password_size: size of password data
 * password_type: type of password (e.g. DCS_TPM_SECRET_TYPE_1 for tpm_secret structure)
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
    u32 info_size);

/*
 * Get PCR info for an NV index
 * Reads the PCR mask, flags, and optional info data from the associated PCR NV entry.
 *
 * nv_index: DC_TPM2_NV_INDEX_DEFAULT or DC_TPM2_NV_INDEX_BACKUP
 * pcr_mask: output for PCR mask (can be NULL)
 * flags: output for flags (DC_TPM_FLAG_*, can be NULL)
 * info_buffer: optional output buffer for info data (can be NULL)
 * info_size: in/out - on input: buffer size, on output: actual info size (can be NULL)
 * Returns: ST_OK on success
 */
int dc_tpm_20_nv_get_info(
    u32 nv_index,
    u32 *pcr_mask,
    u32 *flags,
    void *info_buffer,
    u32 *info_size);

/*
 * Delete an NV entry
 * nv_index: DC_TPM2_NV_INDEX_DEFAULT or DC_TPM2_NV_INDEX_BACKUP
 * Returns: ST_OK on success
 */
int dc_tpm_20_delete_nv_entry(u32 nv_index);


//////////////////////////////////////////////////////////////////////////
// TPM Operations (File-based storage mode)
//////////////////////////////////////////////////////////////////////////

/*
 * TPM2_CreatePrimary - Create SRK (Storage Root Key)
 * srk_handle: Output for the SRK handle
 * Returns: ST_OK on success
 */
int tpm2_create_primary(u32 *srk_handle);

/*
 * TPM2_Create - Create sealed object under parent (SRK)
 * Seals the provided data with optional PCR policy and PIN
 *
 * parent_handle: Parent key handle (SRK)
 * data: Data to seal
 * data_size: Size of data
 * pcr_mask: PCR mask for policy (0 = no PCR binding)
 * pin_auth: PIN authentication data (raw bytes, can be NULL)
 * pin_auth_size: Size of pin_auth
 * sealed_blob: Output buffer for sealed blob (public + private)
 * sealed_blob_size: In: buffer size, Out: actual size
 * Returns: ST_OK on success
 */
int tpm2_create_sealed(
    u32 parent_handle,
    const u8 *data,
    u32 data_size,
    u32 pcr_mask,
    const u8 *pin_auth,
    u32 pin_auth_size,
    u8 *sealed_blob,
    u32 *sealed_blob_size);

/*
 * TPM2_FlushContext - Release a transient handle
 * handle: Handle to flush
 * Returns: ST_OK on success
 */
int tpm2_flush_context(u32 handle);

/*
 * TPM2_Load - Load sealed blob under parent (SRK)
 * parent_handle: Parent key handle (SRK)
 * sealed_blob: Sealed blob data (public + private)
 * sealed_blob_size: Size of sealed blob
 * object_handle: Output for loaded object handle
 * Returns: ST_OK on success
 */
int tpm2_load(
    u32 parent_handle,
    const u8 *sealed_blob,
    u32 sealed_blob_size,
    u32 *object_handle);

/*
 * TPM2_Unseal - Unseal data from a loaded sealed object
 * object_handle: Handle of loaded sealed object
 * pin_auth: PIN authentication data (raw bytes, can be NULL)
 * pin_auth_size: Size of pin_auth
 * data: Output buffer for unsealed data
 * data_size: In: buffer size, Out: actual size
 * Returns: ST_OK on success
 */
int tpm2_unseal(
    u32 object_handle,
    const u8 *pin_auth,
    u32 pin_auth_size,
    u8 *data,
    u32 *data_size);



#endif /* _TPM_20_H_ */
