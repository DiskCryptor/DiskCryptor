#ifndef _WEB_UTILS_H_
#define _WEB_UTILS_H_

#include "dcapi.h"

#include "defines.h"

/*
 * Download data from HTTPS URL
 * Returns TRUE on success, FALSE on failure
 * Caller must free *pData with free()
 */
BOOLEAN dc_api dc_web_download(
    const WCHAR* Host,       /* e.g., L"diskcryptor.org" */
    const WCHAR* Path,       /* e.g., L"/get_cert.php?SN=..." */
    PSTR* pData,             /* OUT: allocated buffer with response */
    ULONG* pDataLength       /* OUT: length of response */
);

/*
 * Get system UUID from SMBIOS firmware table
 * Returns TRUE on success
 * uuid buffer should be at least 40 characters
 */
BOOLEAN dc_api dc_get_system_uuid(WCHAR* uuid, size_t uuid_size);

/*
 * Download certificate from server using serial key
 * Returns ST_OK on success, error code on failure
 * Caller must free *pCertificate with free()
 */
int dc_api dc_download_certificate(
    const WCHAR* serial,     /* Serial key (DC20_-XXXXX-XXXXX-XXXXX-XXXXX) */
    PSTR* pCertificate,      /* OUT: allocated buffer with certificate */
    ULONG* pCertLength       /* OUT: length of certificate */
);

/*
 * Save certificate to registry
 * Registry key: HKLM\SYSTEM\CurrentControlSet\Services\dcrypt\config
 * Value: Certificate (REG_MULTI_SZ)
 */
int dc_api dc_save_certificate(const WCHAR* certificate);

/*
 * Load certificate from registry
 * Returns ST_OK on success, ST_NF_REG_KEY if not found
 */
int dc_api dc_load_certificate(WCHAR* certificate, size_t cert_size);

#endif /* _WEB_UTILS_H_ */
