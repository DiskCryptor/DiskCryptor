#ifndef _TPM_12_H_
#define _TPM_12_H_

#include "dcapi.h"
#include "tpm_sup.h"


/*
 * Get TPM 1.2 information (vendor, firmware, etc.)
 * Fills DC_TPM_INFO structure with TPM 1.2 specific values.
 * Returns: ST_OK on success
 */
int dc_tpm_12_get_info(DC_TPM_INFO *info);

/*
 * Read a PCR value (SHA-1 bank, 20 bytes)
 * pcr_index: PCR index (0-23)
 * pcr_value: output buffer for PCR value (20 bytes for SHA-1)
 * Returns: ST_OK on success
 */
int dc_tpm_12_pcr_read(u32 pcr_index, u8 *pcr_value);

/*
 * Enumerate all NV entries
 * entries: output array for NV entries
 * count: in/out - on input: max entries, on output: actual count
 * Returns: ST_OK on success
 */
int dc_tpm_12_enum_nv(DC_TPM_NV_ENTRY *entries, u32 *count);

/*
 * Delete an NV entry by index
 * nv_index: NV index to delete
 * owner_pwd: owner password (UTF-16)
 * Returns: ST_OK on success
 */
int dc_tpm_12_delete_nv(u32 nv_index, const wchar_t *owner_pwd);

/*
 * Seal data under SRK with optional PCR binding (TPM 1.2)
 * Matches bootloader's Tpm12Seal() for cross-compatibility.
 *
 * srk_auth: 20-byte SRK authorization (zeros for well-known)
 * data_auth: 20-byte authorization for sealed blob (SHA1(PIN) or zeros)
 * pcr_mask: PCR mask for binding (0 = no PCR binding, limited to PCRs 0-15)
 * data: Data to seal
 * data_size: Size of data (max ~256 bytes due to RSA)
 * sealed_blob: Output buffer for TPM_STORED_DATA
 * sealed_blob_size: In: buffer size, Out: actual size
 * Returns: ST_OK on success
 */
int tpm12_seal(
    const u8 *srk_auth,
    u32 pcr_mask,
    const u8 *pin_auth,
    u32 pin_auth_size,
    const u8 *data,
    u32 data_size,
    u8 *sealed_blob,
    u32 *sealed_blob_size);

/*
 * Unseal data from SRK (TPM 1.2)
 * Matches bootloader's Tpm12UnsealWithAuth() for cross-compatibility.
 * Uses two OIAP sessions: one for SRK (well-known), one for blob auth.
 *
 * sealed_blob: TPM_STORED_DATA from tpm12_seal
 * sealed_blob_size: Size of sealed blob
 * data_auth: 20-byte authorization for sealed blob (NULL = well-known zeros)
 * data: Output buffer for unsealed data
 * data_size: In: buffer size, Out: actual size
 * Returns: ST_OK on success
 */
int tpm12_unseal_with_auth(
    const u8 *sealed_blob,
    u32 sealed_blob_size,
    const u8 *pin_auth,
    u32 pin_auth_size,
    u8 *data,
    u32 *data_size);

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
    const u8 *data,
    u32 data_size,
    u32 data_type,
    const void *info,
    u32 info_size);

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
    u32 *data_type);

/*
 * Check if TPM 1.2 NV entry exists
 * nv_index: NV index to check
 * Returns: 1 if exists, 0 otherwise
 */
int dc_tpm_12_nv_exists(u32 nv_index);

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
int dc_tpm_12_nv_get_info(
    u32 nv_index,
    u32 *pcr_mask,
    u32 *flags,
    void *info_buffer,
    u32 *info_size);

/*
 * Delete TPM 1.2 NV entry (data + PCR info)
 * nv_index: NV index (DC_TPM_NV_INDEX_PRIMARY or DC_TPM_NV_INDEX_RECOVERY)
 * owner_pwd: TPM owner password (UTF-16)
 * Returns: ST_OK on success
 */
int dc_tpm_12_delete_nv_entry(
    u32 nv_index,
    const wchar_t *owner_pwd);

#endif /* _TPM_12_H_ */
