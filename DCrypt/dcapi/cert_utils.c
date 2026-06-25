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
#include <winhttp.h>
#include <stdio.h>
#include "cert_utils.h"
#include "misc.h"
#include "dcconst.h"

/* SMBIOS structures for UUID retrieval */
#pragma pack(push, 1)
typedef struct _RawSMBIOSData {
    BYTE    Used20CallingMethod;
    BYTE    SMBIOSMajorVersion;
    BYTE    SMBIOSMinorVersion;
    BYTE    DmiRevision;
    DWORD   Length;
    BYTE    SMBIOSTableData[1];
} RawSMBIOSData;

typedef struct _dmi_header {
    BYTE    type;
    BYTE    length;
    WORD    handle;
} dmi_header;
#pragma pack(pop)

/* Server configuration */
#define UPDATE_DOMAIN   L"diskcryptor.org"

/* WinHttp function pointer types */
typedef HINTERNET (WINAPI *PFN_WinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET (WINAPI *PFN_WinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET (WINAPI *PFN_WinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
typedef BOOL (WINAPI *PFN_WinHttpSetOption)(HINTERNET, DWORD, LPVOID, DWORD);
typedef BOOL (WINAPI *PFN_WinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL (WINAPI *PFN_WinHttpReceiveResponse)(HINTERNET, LPVOID);
typedef BOOL (WINAPI *PFN_WinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI *PFN_WinHttpCloseHandle)(HINTERNET);

/* WinHttp function pointers */
static HMODULE g_hWinHttp = NULL;
static PFN_WinHttpOpen pfnWinHttpOpen = NULL;
static PFN_WinHttpConnect pfnWinHttpConnect = NULL;
static PFN_WinHttpOpenRequest pfnWinHttpOpenRequest = NULL;
static PFN_WinHttpSetOption pfnWinHttpSetOption = NULL;
static PFN_WinHttpSendRequest pfnWinHttpSendRequest = NULL;
static PFN_WinHttpReceiveResponse pfnWinHttpReceiveResponse = NULL;
static PFN_WinHttpReadData pfnWinHttpReadData = NULL;
static PFN_WinHttpCloseHandle pfnWinHttpCloseHandle = NULL;

/*
 * Load WinHttp.dll dynamically
 */
static BOOLEAN LoadWinHttp(void)
{
    if (g_hWinHttp != NULL)
        return TRUE;

    g_hWinHttp = LoadLibraryW(L"winhttp.dll");
    if (g_hWinHttp == NULL)
        return FALSE;

    pfnWinHttpOpen = (PFN_WinHttpOpen)GetProcAddress(g_hWinHttp, "WinHttpOpen");
    pfnWinHttpConnect = (PFN_WinHttpConnect)GetProcAddress(g_hWinHttp, "WinHttpConnect");
    pfnWinHttpOpenRequest = (PFN_WinHttpOpenRequest)GetProcAddress(g_hWinHttp, "WinHttpOpenRequest");
    pfnWinHttpSetOption = (PFN_WinHttpSetOption)GetProcAddress(g_hWinHttp, "WinHttpSetOption");
    pfnWinHttpSendRequest = (PFN_WinHttpSendRequest)GetProcAddress(g_hWinHttp, "WinHttpSendRequest");
    pfnWinHttpReceiveResponse = (PFN_WinHttpReceiveResponse)GetProcAddress(g_hWinHttp, "WinHttpReceiveResponse");
    pfnWinHttpReadData = (PFN_WinHttpReadData)GetProcAddress(g_hWinHttp, "WinHttpReadData");
    pfnWinHttpCloseHandle = (PFN_WinHttpCloseHandle)GetProcAddress(g_hWinHttp, "WinHttpCloseHandle");

    if (!pfnWinHttpOpen || !pfnWinHttpConnect || !pfnWinHttpOpenRequest ||
        !pfnWinHttpSetOption || !pfnWinHttpSendRequest || !pfnWinHttpReceiveResponse ||
        !pfnWinHttpReadData || !pfnWinHttpCloseHandle)
    {
        FreeLibrary(g_hWinHttp);
        g_hWinHttp = NULL;
        return FALSE;
    }

    return TRUE;
}

/*
 * Read HTTP response data into allocated buffer
 */
static void GetWebPayload(HINTERNET hRequest, PSTR* pData, ULONG* pDataLength)
{
    ULONG allocatedLength;
    ULONG dataLength;
    ULONG returnLength;
    BYTE buffer[0x1000];

    if (pData == NULL)
        return;

    allocatedLength = sizeof(buffer);
    *pData = (PSTR)malloc(allocatedLength);
    dataLength = 0;

    while (pfnWinHttpReadData(hRequest, buffer, sizeof(buffer), &returnLength))
    {
        if (returnLength == 0)
            break;

        if (allocatedLength < dataLength + returnLength)
        {
            allocatedLength *= 2;
            *pData = (PSTR)realloc(*pData, allocatedLength);
        }

        memcpy(*pData + dataLength, buffer, returnLength);
        dataLength += returnLength;
    }

    if (allocatedLength < dataLength + 1)
    {
        allocatedLength++;
        *pData = (PSTR)realloc(*pData, allocatedLength);
    }

    /* Ensure buffer is null-terminated */
    (*pData)[dataLength] = 0;

    if (pDataLength != NULL)
        *pDataLength = dataLength;
}

/*
 * Download data from HTTPS URL
 */
BOOLEAN dc_web_download(const WCHAR* Host, const WCHAR* Path, PSTR* pData, ULONG* pDataLength)
{
    BOOLEAN success = FALSE;
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    DWORD dwOptions;

    /* Load WinHttp dynamically */
    if (!LoadWinHttp())
        return FALSE;

    do
    {
        /* Open WinHttp session */
        hSession = pfnWinHttpOpen(
            L"DiskCryptor/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0
        );
        if (!hSession)
            break;

        /* Connect to server (HTTPS port 443) */
        hConnect = pfnWinHttpConnect(hSession, Host, 443, 0);
        if (!hConnect)
            break;

        /* Create request */
        hRequest = pfnWinHttpOpenRequest(
            hConnect,
            L"GET",
            Path,
            NULL,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE | WINHTTP_FLAG_REFRESH
        );
        if (!hRequest)
            break;

        /* Disable keep-alive */
        dwOptions = WINHTTP_DISABLE_KEEP_ALIVE;
        pfnWinHttpSetOption(hRequest, WINHTTP_OPTION_DISABLE_FEATURE, &dwOptions, sizeof(dwOptions));

        /* Send request */
        if (!pfnWinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0))
            break;

        /* Receive response */
        if (!pfnWinHttpReceiveResponse(hRequest, NULL))
            break;

        /* Read response data */
        GetWebPayload(hRequest, pData, pDataLength);

        success = TRUE;

    } while (0);

    /* Cleanup */
    if (hRequest) pfnWinHttpCloseHandle(hRequest);
    if (hConnect) pfnWinHttpCloseHandle(hConnect);
    if (hSession) pfnWinHttpCloseHandle(hSession);

    return success;
}

/*
 * Get system UUID from SMBIOS firmware table
 */
BOOLEAN dc_get_system_uuid(WCHAR* uuid, size_t uuid_size)
{
    DWORD size;
    BYTE* buffer = NULL;
    RawSMBIOSData* smbios;
    BYTE* data;
    BYTE* end;
    BOOLEAN found = FALSE;

    if (uuid == NULL || uuid_size < 40)
        return FALSE;

    /* Get SMBIOS table size */
    size = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    if (size == 0)
        return FALSE;

    buffer = (BYTE*)malloc(size);
    if (buffer == NULL)
        return FALSE;

    /* Get SMBIOS table data */
    if (GetSystemFirmwareTable('RSMB', 0, buffer, size) != size)
    {
        free(buffer);
        return FALSE;
    }

    smbios = (RawSMBIOSData*)buffer;
    data = smbios->SMBIOSTableData;
    end = data + smbios->Length;

    /* Parse SMBIOS structures */
    while (data < end)
    {
        dmi_header* header = (dmi_header*)data;

        /* Look for Type 1 (System Information) */
        if (header->type == 1 && header->length >= 0x19)
        {
            BYTE* uuid_bytes = data + 0x08;

            /* Check for valid UUID (not all zeros or all 0xFF) */
            int all_zero = 1, all_ff = 1;
            for (int i = 0; i < 16; i++)
            {
                if (uuid_bytes[i] != 0x00) all_zero = 0;
                if (uuid_bytes[i] != 0xFF) all_ff = 0;
            }

            if (!all_zero && !all_ff)
            {
                /* Format UUID as string
                 * SMBIOS uses mixed-endian format:
                 * - First 3 fields (8 bytes) are little-endian
                 * - Last 2 fields (8 bytes) are big-endian
                 */
                _snwprintf(uuid, uuid_size,
                    L"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                    uuid_bytes[3], uuid_bytes[2], uuid_bytes[1], uuid_bytes[0],
                    uuid_bytes[5], uuid_bytes[4],
                    uuid_bytes[7], uuid_bytes[6],
                    uuid_bytes[8], uuid_bytes[9],
                    uuid_bytes[10], uuid_bytes[11], uuid_bytes[12], uuid_bytes[13], uuid_bytes[14], uuid_bytes[15]
                );
                found = TRUE;
            }
            break;
        }

        /* Move to next structure */
        data += header->length;
        /* Skip strings (double null terminated) */
        while (data < end && !(data[0] == 0 && data[1] == 0))
            data++;
        data += 2;
    }

    free(buffer);
    return found;
}

/*
 * Download certificate from server using serial key
 */
int dc_download_certificate(const WCHAR* serial, PSTR* pCertificate, ULONG* pCertLength)
{
    WCHAR path[512];
    WCHAR hwid[40] = {0};
    PSTR response = NULL;
    ULONG response_len = 0;

    if (serial == NULL || pCertificate == NULL)
        return ST_INVALID_PARAM;

    *pCertificate = NULL;
    if (pCertLength) *pCertLength = 0;

    /* Build URL path */
    _snwprintf(path, countof(path), L"/get_cert.php?SN=%s", serial);

    /* Only transmit hardware ID for node-locked licenses (DC20N-...) */
    if (wcslen(serial) >= 5 && serial[4] == L'N')
    {
        dc_get_system_uuid(hwid, countof(hwid));
        if (wcslen(hwid) > 0)
        {
            wcscat(path, L"&HwId=");
            wcscat(path, hwid);
        }
    }

    /* Download certificate */
    if (!dc_web_download(UPDATE_DOMAIN, path, &response, &response_len))
    {
        return ST_ERROR;
    }

    /* Check for error response (JSON with "error" field) */
    if (response && response[0] == '{')
    {
        /* Simple JSON error check */
        if (strstr(response, "\"error\"") && strstr(response, "true"))
        {
            free(response);
            return ST_ERROR;
        }
    }

    *pCertificate = response;
    if (pCertLength) *pCertLength = response_len;

    return ST_OK;
}

/* Registry key for DiskCryptor config */
static const WCHAR g_dcrypt_config_key[] = L"SYSTEM\\CurrentControlSet\\Services\\dcrypt\\config";

/*
 * Save certificate to registry as REG_MULTI_SZ
 * If certificate is NULL or empty, deletes the registry value
 */
int dc_save_certificate(const WCHAR* certificate)
{
    HKEY hKey;
    LONG status;
    size_t src_len, dst_len;
    WCHAR* multi_sz = NULL;
    size_t i, j;

    src_len = certificate ? wcslen(certificate) : 0;

    /* Open or create registry key */
    status = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        g_dcrypt_config_key,
        0, NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        NULL,
        &hKey,
        NULL
    );

    if (status != ERROR_SUCCESS)
        return ST_REG_ERROR;

    /* If empty, delete the registry value */
    if (src_len == 0)
    {
        RegDeleteValueW(hKey, L"Certificate");
        RegCloseKey(hKey);
        return ST_OK;
    }

    /* Allocate buffer for multi-sz conversion (same size is enough since we're removing chars) */
    multi_sz = (WCHAR*)malloc((src_len + 2) * sizeof(WCHAR));
    if (multi_sz == NULL)
    {
        RegCloseKey(hKey);
        return ST_NOMEM;
    }

    /* Convert to REG_MULTI_SZ format:
     * - Skip \r characters
     * - Replace \n with \0
     */
    j = 0;
    for (i = 0; i < src_len; i++)
    {
        if (certificate[i] == L'\r')
        {
            /* Skip carriage return */
            continue;
        }
        else if (certificate[i] == L'\n')
        {
            /* Replace newline with null terminator */
            multi_sz[j++] = 0;
        }
        else
        {
            multi_sz[j++] = certificate[i];
        }
    }

    /* Double-null terminate */
    multi_sz[j] = 0;
    multi_sz[j + 1] = 0;
    dst_len = j + 2;

    status = RegSetValueExW(
        hKey,
        L"Certificate",
        0,
        REG_MULTI_SZ,
        (const BYTE*)multi_sz,
        (DWORD)(dst_len * sizeof(WCHAR))
    );

    free(multi_sz);
    RegCloseKey(hKey);

    return (status == ERROR_SUCCESS) ? ST_OK : ST_REG_ERROR;
}

/*
 * Load certificate from registry
 */
int dc_load_certificate(WCHAR* certificate, size_t cert_size)
{
    HKEY hKey;
    LONG status;
    DWORD type;
    DWORD cb;
    WCHAR* temp_buf = NULL;
    size_t i, j, temp_len;

    if (certificate == NULL || cert_size == 0)
        return ST_INVALID_PARAM;

    certificate[0] = 0;

    status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        g_dcrypt_config_key,
        0,
        KEY_READ,
        &hKey
    );

    if (status != ERROR_SUCCESS)
        return ST_NF_REG_KEY;

    /* First query the size */
    cb = 0;
    RegQueryValueExW(hKey, L"Certificate", NULL, &type, NULL, &cb);

    if (cb == 0)
    {
        RegCloseKey(hKey);
        return ST_NF_REG_KEY;
    }

    /* Allocate temp buffer */
    temp_buf = (WCHAR*)malloc(cb);
    if (temp_buf == NULL)
    {
        RegCloseKey(hKey);
        return ST_NOMEM;
    }

    status = RegQueryValueExW(
        hKey,
        L"Certificate",
        NULL,
        &type,
        (BYTE*)temp_buf,
        &cb
    );

    RegCloseKey(hKey);

    if (status != ERROR_SUCCESS)
    {
        free(temp_buf);
        return ST_NF_REG_KEY;
    }

    /* Convert multi-sz back to \r\n line endings */
    temp_len = cb / sizeof(WCHAR);
    j = 0;
    for (i = 0; i < temp_len && j < cert_size - 2; i++)
    {
        if (temp_buf[i] == 0)
        {
            /* Check if this is the final double-null */
            if (i + 1 >= temp_len || temp_buf[i + 1] == 0)
                break;

            /* Replace null with \r\n */
            certificate[j++] = L'\r';
            certificate[j++] = L'\n';
        }
        else
        {
            certificate[j++] = temp_buf[i];
        }
    }
    certificate[j] = 0;

    free(temp_buf);
    return ST_OK;
}
