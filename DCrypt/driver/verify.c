/*
 * Copyright (C) 2016 wj32
 * Copyright (C) 2021-2025 David Xanatos, xanasoft.com
 * Adapted for DiskCryptor
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <ntifs.h>
#include <ntstrsafe.h>
#include "debug.h"
#include "defines.h"
#include "misc_mem.h"
#include "dcconst.h"
#include "driver.h"

#include <bcrypt.h>

//---------------------------------------------------------------------------
// Kernel-mode function declarations and helpers
//---------------------------------------------------------------------------

// Include ntddk.h for SYSTEM_FIRMWARE_TABLE_INFORMATION
#include <ntddk.h>

// ZwQuerySystemInformation is not declared in ntifs.h for all info classes
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

// Simple _wtoi replacement for kernel mode
static int Verify_wtoi(const WCHAR* str)
{
    int result = 0;
    int sign = 1;

    while (*str == L' ' || *str == L'\t') str++;

    if (*str == L'-') {
        sign = -1;
        str++;
    } else if (*str == L'+') {
        str++;
    }

    while (*str >= L'0' && *str <= L'9') {
        result = result * 10 + (*str - L'0');
        str++;
    }

    return result * sign;
}

// Simple _wtol replacement for kernel mode
static long Verify_wtol(const WCHAR* str)
{
    return (long)Verify_wtoi(str);
}

// Macro replacements
#define _wtoi Verify_wtoi
#define _wtol Verify_wtol

#ifdef __BCRYPT_H__
#define KPH_SIGN_ALGORITHM BCRYPT_ECDSA_P256_ALGORITHM
#define KPH_SIGN_ALGORITHM_BITS 256
#define KPH_HASH_ALGORITHM BCRYPT_SHA256_ALGORITHM
#define KPH_BLOB_PUBLIC BCRYPT_ECCPUBLIC_BLOB
#endif

#define KPH_SIGNATURE_MAX_SIZE (128 * 1024) // 128 kB

#define FILE_BUFFER_SIZE (2 * PAGE_SIZE)
#define FILE_MAX_SIZE (128 * 1024 * 1024) // 128 MB

#define CONF_LINE_LEN 512

// Memory allocation tag for verify module
#define VERIFY_TAG 'V_CD'

static UCHAR KphpTrustedPublicKey[] =
{
    0x45, 0x43, 0x53, 0x31, 0x20, 0x00, 0x00, 0x00, 

    // gTrustedPublicKeyX
    0x05, 0x7A, 0x12, 0x5A, 0xF8, 0x54, 0x01, 0x42,
    0xDB, 0x19, 0x87, 0xFC, 0xC4, 0xE3, 0xD3, 0x8D, 
    0x46, 0x7B, 0x74, 0x01, 0x12, 0xFC, 0x78, 0xEB,
    0xEF, 0x7F, 0xF6, 0xAF, 0x4D, 0x9A, 0x3A, 0xF6, 

    // gTrustedPublicKeyY
    0x64, 0x90, 0xDB, 0xE3, 0x48, 0xAB, 0x3E, 0xA7,
    0x2F, 0xC1, 0x18, 0x32, 0xBD, 0x23, 0x02, 0x9D, 
    0x3F, 0xF3, 0x27, 0x86, 0x71, 0x45, 0x26, 0x14,
    0x14, 0xF5, 0x19, 0xAA, 0x2D, 0xEE, 0x50, 0x10
};


typedef struct {
    BCRYPT_ALG_HANDLE algHandle;
    BCRYPT_HASH_HANDLE handle;
    PVOID object;
} MY_HASH_OBJ;

VOID MyFreeHash(MY_HASH_OBJ* pHashObj)
{
    if (pHashObj->handle)
        BCryptDestroyHash(pHashObj->handle);
    if (pHashObj->object)
        ExFreePoolWithTag(pHashObj->object, VERIFY_TAG);
    if (pHashObj->algHandle)
        BCryptCloseAlgorithmProvider(pHashObj->algHandle, 0);
}

NTSTATUS MyInitHash(MY_HASH_OBJ* pHashObj)
{
    NTSTATUS status;
    ULONG hashObjectSize;
    ULONG querySize;
    memset(pHashObj, 0, sizeof(MY_HASH_OBJ));

    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&pHashObj->algHandle, KPH_HASH_ALGORITHM, NULL, 0)))
        goto CleanupExit;

    if (!NT_SUCCESS(status = BCryptGetProperty(pHashObj->algHandle, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hashObjectSize, sizeof(ULONG), &querySize, 0)))
        goto CleanupExit;

    pHashObj->object = ExAllocatePoolWithTag(PagedPool, hashObjectSize, VERIFY_TAG);
    if (!pHashObj->object) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto CleanupExit;
    }

    if (!NT_SUCCESS(status = BCryptCreateHash(pHashObj->algHandle, &pHashObj->handle, (PUCHAR)pHashObj->object, hashObjectSize, NULL, 0, 0)))
        goto CleanupExit;

CleanupExit:
    // on failure the caller must call MyFreeHash

    return status;
}

NTSTATUS MyHashData(MY_HASH_OBJ* pHashObj, PVOID Data, ULONG DataSize)
{
    return BCryptHashData(pHashObj->handle, (PUCHAR)Data, DataSize, 0);
}

NTSTATUS MyFinishHash(MY_HASH_OBJ* pHashObj, PVOID* Hash, PULONG HashSize)
{
    NTSTATUS status;
    ULONG querySize;

    if (!NT_SUCCESS(status = BCryptGetProperty(pHashObj->algHandle, BCRYPT_HASH_LENGTH, (PUCHAR)HashSize, sizeof(ULONG), &querySize, 0)))
        goto CleanupExit;

    *Hash = ExAllocatePoolWithTag(PagedPool, *HashSize, VERIFY_TAG);
    if (!*Hash) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto CleanupExit;
    }

    if (!NT_SUCCESS(status = BCryptFinishHash(pHashObj->handle, (PUCHAR)*Hash, *HashSize, 0)))
        goto CleanupExit;

    return STATUS_SUCCESS;

CleanupExit:
    if (*Hash) {
        ExFreePoolWithTag(*Hash, VERIFY_TAG);
        *Hash = NULL;
    }

    return status;
}

NTSTATUS KphHashFile(
    _In_ PUNICODE_STRING FileName,
    _Out_ PVOID *Hash,
    _Out_ PULONG HashSize
    )
{
    NTSTATUS status;
    MY_HASH_OBJ hashObj;
    ULONG querySize;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK iosb;
    HANDLE fileHandle = NULL;
    FILE_STANDARD_INFORMATION standardInfo;
    ULONG remainingBytes;
    ULONG bytesToRead;
    PVOID buffer = NULL;

    if(!NT_SUCCESS(status = MyInitHash(&hashObj)))
        goto CleanupExit;

    // Open the file and compute the hash.

    InitializeObjectAttributes(&objectAttributes, FileName, OBJ_KERNEL_HANDLE, NULL, NULL);

    if (!NT_SUCCESS(status = ZwCreateFile(&fileHandle, FILE_GENERIC_READ, &objectAttributes,
        &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)))
    {
        goto CleanupExit;
    }

    if (!NT_SUCCESS(status = ZwQueryInformationFile(fileHandle, &iosb, &standardInfo,
        sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation)))
    {
        goto CleanupExit;
    }

    if (standardInfo.EndOfFile.QuadPart <= 0)
    {
        status = STATUS_UNSUCCESSFUL;
        goto CleanupExit;
    }
    if (standardInfo.EndOfFile.QuadPart > FILE_MAX_SIZE)
    {
        status = STATUS_FILE_TOO_LARGE;
        goto CleanupExit;
    }

    if (!(buffer = ExAllocatePoolWithTag(PagedPool, FILE_BUFFER_SIZE, VERIFY_TAG)))
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto CleanupExit;
    }

    remainingBytes = (ULONG)standardInfo.EndOfFile.QuadPart;

    while (remainingBytes != 0)
    {
        bytesToRead = FILE_BUFFER_SIZE;
        if (bytesToRead > remainingBytes)
            bytesToRead = remainingBytes;

        if (!NT_SUCCESS(status = ZwReadFile(fileHandle, NULL, NULL, NULL, &iosb, buffer, bytesToRead,
            NULL, NULL)))
        {
            goto CleanupExit;
        }
        if ((ULONG)iosb.Information != bytesToRead)
        {
            status = STATUS_INTERNAL_ERROR;
            goto CleanupExit;
        }

        if (!NT_SUCCESS(status = MyHashData(&hashObj, buffer, bytesToRead)))
            goto CleanupExit;

        remainingBytes -= bytesToRead;
    }

    if (!NT_SUCCESS(status = MyFinishHash(&hashObj, Hash, HashSize)))
        goto CleanupExit;

CleanupExit:
    if (buffer)
        ExFreePoolWithTag(buffer, VERIFY_TAG);
    if (fileHandle)
        ZwClose(fileHandle);
    MyFreeHash(&hashObj);

    return status;
}

NTSTATUS KphVerifySignature(
    _In_ PVOID Hash,
    _In_ ULONG HashSize,
    _In_ PUCHAR Signature,
    _In_ ULONG SignatureSize
    )
{
    NTSTATUS status;
    BCRYPT_ALG_HANDLE signAlgHandle = NULL;
    BCRYPT_KEY_HANDLE keyHandle = NULL;
    PVOID hash = NULL;
    ULONG hashSize;

    // Import the trusted public key.

    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&signAlgHandle, KPH_SIGN_ALGORITHM, NULL, 0)))
        goto CleanupExit;
    if (!NT_SUCCESS(status = BCryptImportKeyPair(signAlgHandle, NULL, KPH_BLOB_PUBLIC, &keyHandle,
        KphpTrustedPublicKey, sizeof(KphpTrustedPublicKey), 0)))
    {
        goto CleanupExit;
    }

    // Verify the hash.

    if (!NT_SUCCESS(status = BCryptVerifySignature(keyHandle, NULL, Hash, HashSize, Signature,
        SignatureSize, 0)))
    {
        goto CleanupExit;
    }

CleanupExit:
    if (keyHandle)
        BCryptDestroyKey(keyHandle);
    if (signAlgHandle)
        BCryptCloseAlgorithmProvider(signAlgHandle, 0);

    return status;
}

NTSTATUS KphVerifyFile(
    _In_ PUNICODE_STRING FileName,
    _In_ PUCHAR Signature,
    _In_ ULONG SignatureSize
    )
{
    NTSTATUS status;
    PVOID hash = NULL;
    ULONG hashSize;

    // Hash the file.

    if (!NT_SUCCESS(status = KphHashFile(FileName, &hash, &hashSize)))
        goto CleanupExit;

    // Verify the hash.

    if (!NT_SUCCESS(status = KphVerifySignature(hash, hashSize, Signature, SignatureSize)))
    {
        goto CleanupExit;
    }

CleanupExit:
    if (hash)
        ExFreePoolWithTag(hash, VERIFY_TAG);

    return status;
}

NTSTATUS KphVerifyBuffer(
    _In_ PUCHAR Buffer,
    _In_ ULONG BufferSize,
    _In_ PUCHAR Signature,
    _In_ ULONG SignatureSize
    )
{
    NTSTATUS status;
    MY_HASH_OBJ hashObj;
    PVOID hash = NULL;
    ULONG hashSize;

    // Hash the Buffer.

    if(!NT_SUCCESS(status = MyInitHash(&hashObj)))
        goto CleanupExit;

    MyHashData(&hashObj, Buffer, BufferSize);

    if(!NT_SUCCESS(status = MyFinishHash(&hashObj, &hash, &hashSize)))
        goto CleanupExit;

    // Verify the hash.

    if (!NT_SUCCESS(status = KphVerifySignature(hash, hashSize, Signature, SignatureSize)))
    {
        goto CleanupExit;
    }

CleanupExit:

    if (hash)
        ExFreePoolWithTag(hash, VERIFY_TAG);

    MyFreeHash(&hashObj);

    return status;
}

NTSTATUS KphReadSignature(
    _In_ PUNICODE_STRING FileName,
    _Out_ PUCHAR *Signature,
    _Out_ ULONG *SignatureSize
    )
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK iosb;
    HANDLE fileHandle = NULL;
    FILE_STANDARD_INFORMATION standardInfo;

    // Open the file and read it.

    InitializeObjectAttributes(&objectAttributes, FileName, OBJ_KERNEL_HANDLE, NULL, NULL);

    if (!NT_SUCCESS(status = ZwCreateFile(&fileHandle, FILE_GENERIC_READ, &objectAttributes,
        &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)))
    {
        goto CleanupExit;
    }

    if (!NT_SUCCESS(status = ZwQueryInformationFile(fileHandle, &iosb, &standardInfo,
        sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation)))
    {
        goto CleanupExit;
    }

    if (standardInfo.EndOfFile.QuadPart <= 0)
    {
        status = STATUS_UNSUCCESSFUL;
        goto CleanupExit;
    }
    if (standardInfo.EndOfFile.QuadPart > KPH_SIGNATURE_MAX_SIZE)
    {
        status = STATUS_FILE_TOO_LARGE;
        goto CleanupExit;
    }

    *SignatureSize = (ULONG)standardInfo.EndOfFile.QuadPart;

    *Signature = ExAllocatePoolWithTag(PagedPool, *SignatureSize, VERIFY_TAG);
    if(!*Signature)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto CleanupExit;
    }

    if (!NT_SUCCESS(status = ZwReadFile(fileHandle, NULL, NULL, NULL, &iosb, *Signature, *SignatureSize,
        NULL, NULL)))
    {
        goto CleanupExit;
    }

CleanupExit:
    if (fileHandle)
        ZwClose(fileHandle);

    return status;
}

NTSTATUS KphVerifyCurrentProcess(void)
{
    NTSTATUS status;
    PUNICODE_STRING processFileName = NULL;
    PUNICODE_STRING signatureFileName = NULL;
    ULONG signatureSize = 0;
    PUCHAR signature = NULL;

    if (!NT_SUCCESS(status = SeLocateProcessImageName(PsGetCurrentProcess(), &processFileName)))
        goto CleanupExit;

    signatureFileName = ExAllocatePoolWithTag(PagedPool, sizeof(UNICODE_STRING) + processFileName->MaximumLength + 5 * sizeof(WCHAR), VERIFY_TAG);
    if (!signatureFileName)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto CleanupExit;
    }
    signatureFileName->Buffer = (PWCH)(((PUCHAR)signatureFileName) + sizeof(UNICODE_STRING));
    signatureFileName->MaximumLength = processFileName->MaximumLength + 5 * sizeof(WCHAR);

    wcscpy(signatureFileName->Buffer, processFileName->Buffer);
    signatureFileName->Length = processFileName->Length;

    wcscat(signatureFileName->Buffer, L".sig");
    signatureFileName->Length += 4 * sizeof(WCHAR);

    if (!NT_SUCCESS(status = KphReadSignature(signatureFileName, &signature, &signatureSize)))
        goto CleanupExit;

    status = KphVerifyFile(processFileName, signature, signatureSize);

CleanupExit:
    if (signature)
        ExFreePoolWithTag(signature, VERIFY_TAG);
    if (processFileName)
        ExFreePool(processFileName);
    if (signatureFileName)
        ExFreePoolWithTag(signatureFileName, VERIFY_TAG);

    return status;
}


//---------------------------------------------------------------------------
// Base64 functions - include local implementation
//---------------------------------------------------------------------------

// Include the full base64 implementation
#include "base64.c"

// Inline base64 decode for certificate parsing
static size_t Verify_B64DecodedSize(const wchar_t *in)
{
    return b64_decoded_size(in);
}

static int Verify_B64Decode(const wchar_t *in, unsigned char *out, size_t outlen)
{
    return b64_decode(in, out, outlen);
}


//---------------------------------------------------------------------------
// Date parsing helpers
//---------------------------------------------------------------------------

static BOOLEAN KphParseDate(const WCHAR* date_str, LARGE_INTEGER* date)
{
    TIME_FIELDS timeFiled = { 0 };
    const WCHAR* ptr = date_str;
    for (; *ptr == ' '; ptr++); // trim left
    const WCHAR* end = wcschr(ptr, L'.');
    if (end) {
        timeFiled.Day = (CSHORT)_wtoi(ptr);
        ptr = end + 1;

        end = wcschr(ptr, L'.');
        if (end) {
            timeFiled.Month = (CSHORT)_wtoi(ptr);
            ptr = end + 1;

            timeFiled.Year = (CSHORT)_wtoi(ptr);

            RtlTimeFieldsToTime(&timeFiled, date);

            return TRUE;
        }
    }
    return FALSE;
}

// Example of __DATE__ string: "Jul 27 2012"
//                              0123456789A

#define BUILD_YEAR_CH0 (__DATE__[ 7])
#define BUILD_YEAR_CH1 (__DATE__[ 8])
#define BUILD_YEAR_CH2 (__DATE__[ 9])
#define BUILD_YEAR_CH3 (__DATE__[10])

#define BUILD_MONTH_IS_JAN (__DATE__[0] == 'J' && __DATE__[1] == 'a' && __DATE__[2] == 'n')
#define BUILD_MONTH_IS_FEB (__DATE__[0] == 'F')
#define BUILD_MONTH_IS_MAR (__DATE__[0] == 'M' && __DATE__[1] == 'a' && __DATE__[2] == 'r')
#define BUILD_MONTH_IS_APR (__DATE__[0] == 'A' && __DATE__[1] == 'p')
#define BUILD_MONTH_IS_MAY (__DATE__[0] == 'M' && __DATE__[1] == 'a' && __DATE__[2] == 'y')
#define BUILD_MONTH_IS_JUN (__DATE__[0] == 'J' && __DATE__[1] == 'u' && __DATE__[2] == 'n')
#define BUILD_MONTH_IS_JUL (__DATE__[0] == 'J' && __DATE__[1] == 'u' && __DATE__[2] == 'l')
#define BUILD_MONTH_IS_AUG (__DATE__[0] == 'A' && __DATE__[1] == 'u')
#define BUILD_MONTH_IS_SEP (__DATE__[0] == 'S')
#define BUILD_MONTH_IS_OCT (__DATE__[0] == 'O')
#define BUILD_MONTH_IS_NOV (__DATE__[0] == 'N')
#define BUILD_MONTH_IS_DEC (__DATE__[0] == 'D')

#define BUILD_DAY_CH0 ((__DATE__[4] >= '0') ? (__DATE__[4]) : '0')
#define BUILD_DAY_CH1 (__DATE__[ 5])

#define CH2N(c) (c - '0')

static VOID KphGetBuildDate(LARGE_INTEGER* date)
{
    TIME_FIELDS timeFiled = { 0 };
    timeFiled.Day = CH2N(BUILD_DAY_CH0) * 10 + CH2N(BUILD_DAY_CH1);
    timeFiled.Month = (
        (BUILD_MONTH_IS_JAN) ?  1 : (BUILD_MONTH_IS_FEB) ?  2 : (BUILD_MONTH_IS_MAR) ?  3 :
        (BUILD_MONTH_IS_APR) ?  4 : (BUILD_MONTH_IS_MAY) ?  5 : (BUILD_MONTH_IS_JUN) ?  6 :
        (BUILD_MONTH_IS_JUL) ?  7 : (BUILD_MONTH_IS_AUG) ?  8 : (BUILD_MONTH_IS_SEP) ?  9 :
        (BUILD_MONTH_IS_OCT) ? 10 : (BUILD_MONTH_IS_NOV) ? 11 : (BUILD_MONTH_IS_DEC) ? 12 : 0);
    timeFiled.Year = CH2N(BUILD_YEAR_CH0) * 1000 + CH2N(BUILD_YEAR_CH1) * 100 + CH2N(BUILD_YEAR_CH2) * 10 + CH2N(BUILD_YEAR_CH3);
    RtlTimeFieldsToTime(&timeFiled, date);
}

static LONGLONG KphGetDate(CSHORT days, CSHORT months, CSHORT years)
{
    LARGE_INTEGER date;
    TIME_FIELDS timeFiled = { 0 };
    timeFiled.Day = days;
    timeFiled.Month = months;
    timeFiled.Year = years;
    RtlTimeFieldsToTime(&timeFiled, &date);
    return date.QuadPart;
}

static LONGLONG KphGetDateInterval(CSHORT days, CSHORT months, CSHORT years)
{
    return ((LONGLONG)days + (LONGLONG)months * 30ll + (LONGLONG)years * 365ll) * 24ll * 3600ll * 10000000ll; // 100ns steps -> 1sec
}


//---------------------------------------------------------------------------
// Certificate data source - define VERIFY_CERT_FROM_REGISTRY to load from registry
// Registry path: HKLM\SYSTEM\CurrentControlSet\Services\dcrypt\config
// Value: "Certificate" (REG_MULTI_SZ)
//---------------------------------------------------------------------------

#define VERIFY_CERT_FROM_REGISTRY

#ifdef VERIFY_CERT_FROM_REGISTRY

//---------------------------------------------------------------------------
// Registry-based certificate reading (REG_MULTI_SZ)
//---------------------------------------------------------------------------

typedef struct _VERIFY_STREAM {
    PWCHAR Data;        // REG_MULTI_SZ data
    ULONG DataSize;     // Total size in bytes
    PWCHAR CurrentLine; // Current position in multi-sz
    BOOLEAN Eof;
} VERIFY_STREAM;

static NTSTATUS Verify_StreamOpenRegistry(VERIFY_STREAM **stream)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING keyPath;
    UNICODE_STRING valueName;
    HANDLE keyHandle = NULL;
    VERIFY_STREAM *s = NULL;
    PKEY_VALUE_PARTIAL_INFORMATION valueInfo = NULL;
    ULONG resultLength = 0;

    *stream = NULL;

    RtlInitUnicodeString(&keyPath, L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\dcrypt\\config");
    InitializeObjectAttributes(&objectAttributes, &keyPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwOpenKey(&keyHandle, KEY_READ, &objectAttributes);
    if (!NT_SUCCESS(status))
        return status;

    RtlInitUnicodeString(&valueName, L"Certificate");

    // Query size first
    status = ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation, NULL, 0, &resultLength);
    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
        ZwClose(keyHandle);
        return STATUS_NOT_FOUND;
    }

    valueInfo = ExAllocatePoolWithTag(PagedPool, resultLength, VERIFY_TAG);
    if (!valueInfo) {
        ZwClose(keyHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation, valueInfo, resultLength, &resultLength);
    ZwClose(keyHandle);

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(valueInfo, VERIFY_TAG);
        return status;
    }

    if (valueInfo->Type != REG_MULTI_SZ || valueInfo->DataLength < sizeof(WCHAR)) {
        ExFreePoolWithTag(valueInfo, VERIFY_TAG);
        return STATUS_INVALID_PARAMETER;
    }

    s = ExAllocatePoolWithTag(PagedPool, sizeof(VERIFY_STREAM), VERIFY_TAG);
    if (!s) {
        ExFreePoolWithTag(valueInfo, VERIFY_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    memset(s, 0, sizeof(VERIFY_STREAM));

    // Allocate and copy the multi-sz data
    s->Data = ExAllocatePoolWithTag(PagedPool, valueInfo->DataLength, VERIFY_TAG);
    if (!s->Data) {
        ExFreePoolWithTag(s, VERIFY_TAG);
        ExFreePoolWithTag(valueInfo, VERIFY_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    memcpy(s->Data, valueInfo->Data, valueInfo->DataLength);
    s->DataSize = valueInfo->DataLength;
    s->CurrentLine = s->Data;
    s->Eof = FALSE;

    ExFreePoolWithTag(valueInfo, VERIFY_TAG);

    *stream = s;
    return STATUS_SUCCESS;
}

static VOID Verify_StreamClose(VERIFY_STREAM *stream)
{
    if (stream) {
        if (stream->Data)
            ExFreePoolWithTag(stream->Data, VERIFY_TAG);
        ExFreePoolWithTag(stream, VERIFY_TAG);
    }
}

static NTSTATUS Verify_ReadLine(VERIFY_STREAM *stream, WCHAR *line, int *linenum)
{
    ULONG linepos = 0;
    ULONG maxlen = CONF_LINE_LEN - 1;

    line[0] = L'\0';

    if (stream->Eof || stream->CurrentLine == NULL)
        return STATUS_END_OF_FILE;

    // Check if we've reached the end (double null terminator)
    if (*stream->CurrentLine == L'\0') {
        stream->Eof = TRUE;
        return STATUS_END_OF_FILE;
    }

    // Copy the current string (until null terminator)
    while (*stream->CurrentLine != L'\0' && linepos < maxlen) {
        WCHAR ch = *stream->CurrentLine++;

        // Skip leading whitespace
        if (linepos == 0 && (ch == L' ' || ch == L'\t'))
            continue;

        line[linepos++] = ch;
    }

    // Skip the null terminator to move to next string
    if (*stream->CurrentLine == L'\0')
        stream->CurrentLine++;

    // Trim trailing whitespace
    while (linepos > 0 && (line[linepos - 1] == L' ' || line[linepos - 1] == L'\t'))
        linepos--;

    line[linepos] = L'\0';

    if (linenum)
        (*linenum)++;

    return STATUS_SUCCESS;
}

#else /* !VERIFY_CERT_FROM_REGISTRY */

//---------------------------------------------------------------------------
// File-based certificate reading
//---------------------------------------------------------------------------

// Global path to driver home directory - must be set by driver initialization
WCHAR Verify_HomePathDos[MAX_PATH] = { 0 };

typedef struct _VERIFY_STREAM {
    HANDLE FileHandle;
    PVOID Buffer;
    ULONG BufferSize;
    ULONG BufferPos;
    ULONG BufferFilled;
    BOOLEAN Eof;
    BOOLEAN IsUnicode;
} VERIFY_STREAM;

static NTSTATUS Verify_StreamOpen(VERIFY_STREAM **stream, const WCHAR *path)
{
    NTSTATUS status;
    UNICODE_STRING fileName;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK iosb;
    VERIFY_STREAM *s;

    *stream = NULL;

    s = ExAllocatePoolWithTag(PagedPool, sizeof(VERIFY_STREAM), VERIFY_TAG);
    if (!s)
        return STATUS_INSUFFICIENT_RESOURCES;

    memset(s, 0, sizeof(VERIFY_STREAM));

    s->Buffer = ExAllocatePoolWithTag(PagedPool, FILE_BUFFER_SIZE, VERIFY_TAG);
    if (!s->Buffer) {
        ExFreePoolWithTag(s, VERIFY_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    s->BufferSize = FILE_BUFFER_SIZE;

    RtlInitUnicodeString(&fileName, path);
    InitializeObjectAttributes(&objectAttributes, &fileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwCreateFile(&s->FileHandle, FILE_GENERIC_READ, &objectAttributes,
        &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(s->Buffer, VERIFY_TAG);
        ExFreePoolWithTag(s, VERIFY_TAG);
        return status;
    }

    *stream = s;
    return STATUS_SUCCESS;
}

static VOID Verify_StreamClose(VERIFY_STREAM *stream)
{
    if (stream) {
        if (stream->FileHandle)
            ZwClose(stream->FileHandle);
        if (stream->Buffer)
            ExFreePoolWithTag(stream->Buffer, VERIFY_TAG);
        ExFreePoolWithTag(stream, VERIFY_TAG);
    }
}

static NTSTATUS Verify_StreamFillBuffer(VERIFY_STREAM *stream)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    if (stream->Eof)
        return STATUS_END_OF_FILE;

    status = ZwReadFile(stream->FileHandle, NULL, NULL, NULL, &iosb,
        stream->Buffer, stream->BufferSize, NULL, NULL);

    if (status == STATUS_END_OF_FILE) {
        stream->Eof = TRUE;
        stream->BufferFilled = 0;
        return STATUS_END_OF_FILE;
    }

    if (!NT_SUCCESS(status))
        return status;

    stream->BufferFilled = (ULONG)iosb.Information;
    stream->BufferPos = 0;

    if (stream->BufferFilled == 0) {
        stream->Eof = TRUE;
        return STATUS_END_OF_FILE;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS Verify_StreamReadBom(VERIFY_STREAM *stream)
{
    NTSTATUS status;
    UCHAR *buf;

    status = Verify_StreamFillBuffer(stream);
    if (!NT_SUCCESS(status))
        return status;

    buf = (UCHAR*)stream->Buffer;

    // Check for UTF-16 LE BOM (0xFF 0xFE)
    if (stream->BufferFilled >= 2 && buf[0] == 0xFF && buf[1] == 0xFE) {
        stream->IsUnicode = TRUE;
        stream->BufferPos = 2;
    }
    // Check for UTF-8 BOM (0xEF 0xBB 0xBF)
    else if (stream->BufferFilled >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF) {
        stream->IsUnicode = FALSE;
        stream->BufferPos = 3;
    }
    else {
        stream->IsUnicode = FALSE;
        stream->BufferPos = 0;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS Verify_ReadLine(VERIFY_STREAM *stream, WCHAR *line, int *linenum)
{
    NTSTATUS status;
    int linepos = 0;
    int maxlen = CONF_LINE_LEN - 1;

    line[0] = L'\0';

    while (linepos < maxlen) {
        WCHAR ch;

        // Refill buffer if needed
        if (stream->BufferPos >= stream->BufferFilled) {
            status = Verify_StreamFillBuffer(stream);
            if (status == STATUS_END_OF_FILE) {
                if (linepos > 0) {
                    line[linepos] = L'\0';
                    if (linenum) (*linenum)++;
                    return STATUS_SUCCESS;
                }
                return STATUS_END_OF_FILE;
            }
            if (!NT_SUCCESS(status))
                return status;
        }

        // Read character
        if (stream->IsUnicode) {
            if (stream->BufferPos + 1 >= stream->BufferFilled) {
                // Not enough data for a wchar
                if (linepos > 0) {
                    line[linepos] = L'\0';
                    if (linenum) (*linenum)++;
                    return STATUS_SUCCESS;
                }
                return STATUS_END_OF_FILE;
            }
            ch = *((WCHAR*)((UCHAR*)stream->Buffer + stream->BufferPos));
            stream->BufferPos += 2;
        } else {
            // UTF-8/ANSI - simple single-byte for now
            ch = (WCHAR)(*((UCHAR*)stream->Buffer + stream->BufferPos));
            stream->BufferPos++;
        }

        // Handle line endings
        if (ch == L'\r') {
            continue; // Skip CR
        }
        if (ch == L'\n') {
            line[linepos] = L'\0';
            if (linenum) (*linenum)++;
            return STATUS_SUCCESS;
        }

        // Skip leading whitespace for non-empty lines
        if (linepos == 0 && (ch == L' ' || ch == L'\t'))
            continue;

        line[linepos++] = ch;
    }

    line[linepos] = L'\0';
    if (linenum) (*linenum)++;
    return STATUS_SUCCESS;
}

#endif /* VERIFY_CERT_FROM_REGISTRY */


//---------------------------------------------------------------------------
// Verify certificate info and helpers
//---------------------------------------------------------------------------

#include "verify.h"

SCertInfo Verify_CertInfo = { 0 };

NTSTATUS KphValidateCertificate(void)
{
    BOOLEAN CertDbg = TRUE;

    NTSTATUS status;
    VERIFY_STREAM *stream = NULL;
#ifndef VERIFY_CERT_FROM_REGISTRY
    static const WCHAR *path_cert = L"%s\\Certificate.dat";
    ULONG path_len = 0;
    WCHAR *path = NULL;
#endif

    MY_HASH_OBJ hashObj;
    ULONG hashSize;
    PUCHAR hash = NULL;
    ULONG signatureSize = 0;
    PUCHAR signature = NULL;

    const int line_size = (CONF_LINE_LEN + 2) * sizeof(WCHAR);
    WCHAR *line = NULL;
    char *temp = NULL;
    int line_num = 0;
    BOOLEAN SoftwareOK = FALSE;

    WCHAR* type = NULL;
    WCHAR* level = NULL;
    //WCHAR* options = NULL;
    LONG amount = 1;
    WCHAR* key = NULL;
    LARGE_INTEGER cert_date = { 0 };
    LARGE_INTEGER check_date = { 0 };
    LONG days = 0;
    BOOLEAN node_lock = FALSE;
    BOOLEAN node_pass = FALSE;

    Verify_CertInfo.State = 0; // clear

    if(!NT_SUCCESS(status = MyInitHash(&hashObj)))
        goto CleanupExit;

    //
    // Read certificate data
    //

    line = ExAllocatePoolWithTag(PagedPool, line_size, VERIFY_TAG);
    temp = ExAllocatePoolWithTag(PagedPool, line_size, VERIFY_TAG);
    if (!line || !temp) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto CleanupExit;
    }

#ifdef VERIFY_CERT_FROM_REGISTRY
    //
    // Read from registry: HKLM\SYSTEM\CurrentControlSet\Services\dcrypt\config\Certificate
    //
    status = Verify_StreamOpenRegistry(&stream);
    if (!NT_SUCCESS(status)) {
        status = STATUS_NOT_FOUND;
        goto CleanupExit;
    }
#else
    //
    // Read from file: (Home Path)\Certificate.dat
    //
    path_len = (ULONG)(wcslen(Verify_HomePathDos) * sizeof(WCHAR));
    path_len += 64;     // room for \Certificate.dat
    path = ExAllocatePoolWithTag(PagedPool, path_len, VERIFY_TAG);
    if (!path) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto CleanupExit;
    }

    RtlStringCbPrintfW(path, path_len, path_cert, Verify_HomePathDos);

    status = Verify_StreamOpen(&stream, path);
    if (!NT_SUCCESS(status)) {
        status = STATUS_NOT_FOUND;
        goto CleanupExit;
    }

    if(!NT_SUCCESS(status = Verify_StreamReadBom(stream)))
        goto CleanupExit;
#endif

    status = Verify_ReadLine(stream, line, &line_num);
    while (NT_SUCCESS(status)) {

        WCHAR *ptr;
        WCHAR *name;
        WCHAR *value;
        ULONG temp_len;

        // Skip empty lines
        if (line[0] == L'\0') {
            status = Verify_ReadLine(stream, line, &line_num);
            continue;
        }

        // parse tag name: value

        ptr = wcschr(line, L':');
        if ((! ptr) || ptr == line) {
            status = Verify_ReadLine(stream, line, &line_num);
            continue;
        }
        value = &ptr[1];

        // eliminate trailing whitespace in the tag name

        while (ptr > line) {
            --ptr;
            if (*ptr > 32) {
                ++ptr;
                break;
            }
        }
        *ptr = L'\0';

        name = line;

        // eliminate leading and trailing whitespace in value

        while (*value <= 32) {
            if (! (*value))
                break;
            ++value;
        }

        if (*value == L'\0') {
            status = Verify_ReadLine(stream, line, &line_num);
            continue;
        }

        ptr = value + wcslen(value);
        while (ptr > value) {
            --ptr;
            if (*ptr > 32) {
                ++ptr;
                break;
            }
        }
        *ptr = L'\0';

        //
        // Extract and decode the signature
        //

        if (_wcsicmp(L"SIGNATURE", name) == 0 && signature == NULL) {
            signatureSize = (ULONG)Verify_B64DecodedSize(value);
            signature = ExAllocatePoolWithTag(PagedPool, signatureSize, VERIFY_TAG);
            if (!signature) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto CleanupExit;
            }
            Verify_B64Decode(value, signature, signatureSize);
            goto next;
        }

        //
        // Hash the tag
        //

        if (NT_SUCCESS(RtlUnicodeToUTF8N(temp, line_size, &temp_len, name, (ULONG)(wcslen(name) * sizeof(wchar_t)))))
            MyHashData(&hashObj, temp, temp_len);

        if (NT_SUCCESS(RtlUnicodeToUTF8N(temp, line_size, &temp_len, value, (ULONG)(wcslen(value) * sizeof(wchar_t)))))
            MyHashData(&hashObj, temp, temp_len);

        //
        // Note: when parsing we may change the value of value, by adding \0's, hence we do all that after the hashing
        //

        if(CertDbg) DbgMsg("Cert Value: %S: %S\n", name, value);

        if (_wcsicmp(L"DATE", name) == 0) {
            if (cert_date.QuadPart != 0) {
                status = STATUS_BAD_FUNCTION_TABLE;
                goto CleanupExit;
            }
            // DD.MM.YYYY
            if (KphParseDate(value, &cert_date)) {

                // DD.MM.YYYY +Days
                WCHAR* ptr2 = wcschr(value, L'+');
                if (ptr2)
                    days = _wtol(ptr2);

                // DD.MM.YYYY [+Days] / DD.MM.YYYY
                ptr2 = wcschr(value, L'/');
                if (ptr2)
                    KphParseDate(ptr2 + 1, &check_date);
            }
        }
        else if (_wcsicmp(L"DAYS", name) == 0) {
            if (days != 0) {
                status = STATUS_BAD_FUNCTION_TABLE;
                goto CleanupExit;
            }
            days = _wtol(value);
        }
        else if (_wcsicmp(L"TYPE", name) == 0) {
            // TYPE-LEVEL
            if (type != NULL) {
                status = STATUS_BAD_FUNCTION_TABLE;
                goto CleanupExit;
            }
            WCHAR* ptr2 = wcschr(value, L'-');
            if (ptr2 != NULL) {
                *ptr2++ = L'\0';
                size_t len = wcslen(ptr2) + 1;
                level = ExAllocatePoolWithTag(PagedPool, len * sizeof(WCHAR), VERIFY_TAG);
                if (level) wcscpy(level, ptr2);
            }
            size_t len = wcslen(value) + 1;
            type = ExAllocatePoolWithTag(PagedPool, len * sizeof(WCHAR), VERIFY_TAG);
            if (type) wcscpy(type, value);
        }
        //else if (_wcsicmp(L"OPTIONS", name) == 0) {
        //    if (options != NULL) {
        //        status = STATUS_BAD_FUNCTION_TABLE;
        //        goto CleanupExit;
        //    }
        //    size_t len = wcslen(value) + 1;
        //    options = ExAllocatePoolWithTag(PagedPool, len * sizeof(WCHAR), VERIFY_TAG);
        //    if (options) wcscpy(options, value);
        //}
        else if (_wcsicmp(L"UPDATEKEY", name) == 0) {
            if (key != NULL) {
                status = STATUS_BAD_FUNCTION_TABLE;
                goto CleanupExit;
            }
            size_t len = wcslen(value) + 1;
            key = ExAllocatePoolWithTag(PagedPool, len * sizeof(WCHAR), VERIFY_TAG);
            if (key) wcscpy(key, value);
        }
        else if (_wcsicmp(L"AMOUNT", name) == 0) {
            amount = _wtol(value);
        }
        else if (_wcsicmp(L"SOFTWARE", name) == 0) { // if software is specified it must be the right one
            if (_wcsicmp(value, SOFTWARE_NAME) == 0) 
                SoftwareOK = TRUE;
        }
        else if (_wcsicmp(L"HWID", name) == 0) { // if HwId is specified it must be the right one
            node_lock = TRUE;
            if (_wcsicmp(value, g_uuid_str) == 0)
                node_pass = TRUE;
        }

    next:
        status = Verify_ReadLine(stream, line, &line_num);
    }

    if(!NT_SUCCESS(status = MyFinishHash(&hashObj, &hash, &hashSize)))
        goto CleanupExit;

    if(CertDbg) DumpHex("Hash ", hash, hashSize);

    if (!signature) {
        status = STATUS_INVALID_SECURITY_DESCR;
        goto CleanupExit;
    }

    if (!SoftwareOK) {
        status = STATUS_OBJECT_TYPE_MISMATCH;
        goto CleanupExit;
    }

    status = KphVerifySignature(hash, hashSize, signature, signatureSize);

    //if (NT_SUCCESS(status) && key) {
    //    if (_wcsicmp(key, L"00000000000000000000000000000000") == 0)
    //    {
    //        DbgMsg("Found Blocked UpdateKey %S\n", key);
    //        status = STATUS_CONTENT_BLOCKED;
    //    }
    //}

    if (!NT_SUCCESS(status))
        goto CleanupExit;

    // signature OK
    if (node_lock) {
        Verify_CertInfo.locked = 1;
        if (!node_pass) {
            status = STATUS_FIRMWARE_IMAGE_INVALID;
            goto CleanupExit;
        }
    }

    Verify_CertInfo.active = 1;

    if (CertDbg) {
        if(level) DbgMsg("Cert type: %S-%S\n", type, level);
        else DbgMsg("Cert type: %S\n", type);
    }

    TIME_FIELDS timeFiled = { 0 };
    if (CertDbg) {
        RtlTimeToTimeFields(&cert_date, &timeFiled);
        DbgMsg("Cert date: %02d.%02d.%d +%d\n", timeFiled.Day, timeFiled.Month, timeFiled.Year, days);

        if (check_date.QuadPart != 0) {
            RtlTimeToTimeFields(&check_date, &timeFiled);
            DbgMsg("Check date: %02d.%02d.%d\n", timeFiled.Day, timeFiled.Month, timeFiled.Year);
        }
    }

    if (!check_date.QuadPart) // a freshly created cert may not have yet been checked
        check_date.QuadPart = cert_date.QuadPart;

    LARGE_INTEGER BuildDate = { 0 };
    KphGetBuildDate(&BuildDate);

    if (CertDbg) {
        RtlTimeToTimeFields(&BuildDate, &timeFiled);
        if (CertDbg) DbgMsg("Build date: %02d.%02d.%d\n", timeFiled.Day, timeFiled.Month, timeFiled.Year);
    }

    LARGE_INTEGER UtcTime;
    KeQuerySystemTime(&UtcTime);
    if (CertDbg) {
        RtlTimeToTimeFields(&UtcTime, &timeFiled);
        DbgMsg("Current UTC time: %02d:%02d:%02d %02d.%02d.%d\n"
            , timeFiled.Hour, timeFiled.Minute, timeFiled.Second, timeFiled.Day, timeFiled.Month, timeFiled.Year);
    }

    if (!type && level) { // fix for some early hand crafted contributor certificates
        type = level;
        level = NULL;
    }


    LARGE_INTEGER expiration_date = { 0 };

    if (!type) // type is mandatory
        ;
    else if (_wcsicmp(type, L"CONTRIBUTOR") == 0)
        Verify_CertInfo.type = eCertContributor;
    else if (_wcsicmp(type, L"ETERNAL") == 0)
        Verify_CertInfo.type = eCertEternal;
    else if (_wcsicmp(type, L"BUSINESS") == 0)
        Verify_CertInfo.type = eCertBusiness;
    else if (_wcsicmp(type, L"EVALUATION") == 0 || _wcsicmp(type, L"TEST") == 0)
        Verify_CertInfo.type = eCertEvaluation;
    else if (_wcsicmp(type, L"HOME") == 0)
        Verify_CertInfo.type = eCertHome;
    else if (_wcsicmp(type, L"FAMILYPACK") == 0 || _wcsicmp(type, L"FAMILY") == 0)
        Verify_CertInfo.type = eCertFamily;
    // patreon >>>
    else if (wcsstr(type, L"PATREON") != NULL) // TYPE: [CLASS]_PATREON-[LEVEL]
    {
        if(_wcsnicmp(type, L"GREAT", 5) == 0)
            Verify_CertInfo.type = eCertGreatPatreon;
        else if (_wcsnicmp(type, L"ENTRY", 5) == 0) { // new patreons get only 3 months for start
            Verify_CertInfo.type = eCertEntryPatreon;
            expiration_date.QuadPart = cert_date.QuadPart + KphGetDateInterval(0, 3, 0);
        } else
            Verify_CertInfo.type = eCertPatreon;

    }
    // <<< patreon
    else //if (_wcsicmp(type, L"PERSONAL") == 0 || _wcsicmp(type, L"SUPPORTER") == 0)
    {
        Verify_CertInfo.type = eCertPersonal;
    }

    if(CertDbg) DbgMsg("Cert type: %X\n", Verify_CertInfo.type);

    //if (CERT_IS_TYPE(Verify_CertInfo, eCertEternal)) // includes contributor
    //    Verify_CertInfo.level = eCertMaxLevel;
    //else if (CERT_IS_TYPE(Verify_CertInfo, eCertDeveloper))
    //    Verify_CertInfo.level = eCertMaxLevel;
    //else if (CERT_IS_TYPE(Verify_CertInfo, eCertEvaluation)) // in evaluation the level field holds the amount of days to allow evaluation for
    //{
    //    if(days) expiration_date.QuadPart = cert_date.QuadPart + KphGetDateInterval((CSHORT)(days), 0, 0);
    //    else expiration_date.QuadPart = cert_date.QuadPart + KphGetDateInterval((CSHORT)(level ? _wtoi(level) : 7), 0, 0); // x days, default 7
    //    Verify_CertInfo.level = eCertMaxLevel;
    //}
    //else if (!level || _wcsicmp(level, L"STANDARD") == 0) // not used, default does not have explicit level
    //    Verify_CertInfo.level = eCertStandard;
    //else if (_wcsicmp(level, L"ADVANCED") == 0)
    //{
    //    if(Verify_CertInfo.type == eCertGreatPatreon)
    //        Verify_CertInfo.level = eCertMaxLevel;
    //    else if(Verify_CertInfo.type == eCertPatreon || Verify_CertInfo.type == eCertEntryPatreon)
    //        Verify_CertInfo.level = eCertAdvanced1;
    //    else
    //        Verify_CertInfo.level = eCertAdvanced;
    //}
    //
    //if(CertDbg) DbgMsg("Cert level: %X\n", Verify_CertInfo.level);

    //if (options) {
    //
    //    if(CertDbg) DbgMsg("Cert options: %S\n", options);
    //
    //    for (WCHAR* option = options; ; )
    //    {
    //        while (*option == L' ' || *option == L'\t') option++;
    //        WCHAR* end = wcschr(option, L',');
    //        if (!end) end = wcschr(option, L'\0');
    //
    //        if (CertDbg) DbgMsg("Cert UNKNOWN option: %.*S\n", (ULONG)(end - option), option);
    //
    //        if (*end == L'\0')
    //            break;
    //        option = end + 1;
    //    }
    //}

    if (CERT_IS_TYPE(Verify_CertInfo, eCertEternal))
        expiration_date.QuadPart = -1; // at the end of time (never)
    else if (!expiration_date.QuadPart) {
        if (days) expiration_date.QuadPart = cert_date.QuadPart + KphGetDateInterval((CSHORT)(days), 0, 0);
        else expiration_date.QuadPart = cert_date.QuadPart + KphGetDateInterval(0, 0, 1); // default 1 year, unless set differently already
    }

    // check if this is a subscription type certificate
    BOOLEAN isSubscription = CERT_IS_SUBSCRIPTION(Verify_CertInfo);

    if (expiration_date.QuadPart == -2)
        Verify_CertInfo.expired = 1; // but not outdated
    else if (expiration_date.QuadPart != -1)
    {
        // check if this certificate is expired
        if (expiration_date.QuadPart < UtcTime.QuadPart)
            Verify_CertInfo.expired = 1;
        Verify_CertInfo.expirers_in_sec = (ULONG)((expiration_date.QuadPart - UtcTime.QuadPart) / 10000000ll); // 100ns steps -> 1sec

        // check if a non subscription type certificate is valid for the current build
        if (!isSubscription && expiration_date.QuadPart < BuildDate.QuadPart)
            Verify_CertInfo.outdated = 1;
    }

    // check if the certificate is valid
    if (isSubscription ? Verify_CertInfo.expired : Verify_CertInfo.outdated)
    {
        if (!CERT_IS_TYPE(Verify_CertInfo, eCertEvaluation)) { // non eval certs get 1 month extra
            if (expiration_date.QuadPart + KphGetDateInterval(0, 1, 0) >= UtcTime.QuadPart)
                Verify_CertInfo.grace_period = 1;
        }

        if (!Verify_CertInfo.grace_period) {
            Verify_CertInfo.active = 0;
            status = STATUS_ACCOUNT_EXPIRED;
        }
    }


CleanupExit:
    if(CertDbg) DbgMsg("Cert status: %08x; active: %d\n", status, Verify_CertInfo.active);

#ifndef VERIFY_CERT_FROM_REGISTRY
    if(path)        ExFreePoolWithTag(path, VERIFY_TAG);
#endif
    if(line)        ExFreePoolWithTag(line, VERIFY_TAG);
    if(temp)        ExFreePoolWithTag(temp, VERIFY_TAG);

    if (type)       ExFreePoolWithTag(type, VERIFY_TAG);
    if (level)      ExFreePoolWithTag(level, VERIFY_TAG);
    //if (options)    ExFreePoolWithTag(options, VERIFY_TAG);
    if (key)        ExFreePoolWithTag(key, VERIFY_TAG);

                    MyFreeHash(&hashObj);
    if(hash)        ExFreePoolWithTag(hash, VERIFY_TAG);
    if(signature)   ExFreePoolWithTag(signature, VERIFY_TAG);

    if(stream)      Verify_StreamClose(stream);

    return status;
}


//---------------------------------------------------------------------------
// SMBIOS UUID extraction
//---------------------------------------------------------------------------

// SMBIOS Structure header as described at
// see https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.3.0.pdf (para 6.1.2)
typedef struct _dmi_header
{
  UCHAR type;
  UCHAR length;
  USHORT handle;
  UCHAR data[1];
} dmi_header;

// Structure needed to get the SMBIOS table using GetSystemFirmwareTable API.
// see https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable
typedef struct _RawSMBIOSData {
  UCHAR  Used20CallingMethod;
  UCHAR  SMBIOSMajorVersion;
  UCHAR  SMBIOSMinorVersion;
  UCHAR  DmiRevision;
  DWORD  Length;
  UCHAR  SMBIOSTableData[1];
} RawSMBIOSData;

#define SystemFirmwareTableInformation 76

static BOOLEAN GetFwUuid(unsigned char* uuid)
{
    BOOLEAN result = FALSE;

    SYSTEM_FIRMWARE_TABLE_INFORMATION sfti;
    sfti.Action = SystemFirmwareTable_Get;
    sfti.ProviderSignature = 'RSMB';
    sfti.TableID = 0;
    sfti.TableBufferLength = 0;

    ULONG Length = sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION);
    NTSTATUS status = ZwQuerySystemInformation(SystemFirmwareTableInformation, &sfti, Length, &Length);
    if (status != STATUS_BUFFER_TOO_SMALL)
        return result;

    ULONG BufferSize = sfti.TableBufferLength;

    Length = BufferSize + sizeof(SYSTEM_FIRMWARE_TABLE_INFORMATION);
    SYSTEM_FIRMWARE_TABLE_INFORMATION* pSfti = ExAllocatePoolWithTag(PagedPool, Length, VERIFY_TAG);
    if (!pSfti)
        return result;
    *pSfti = sfti;
    pSfti->TableBufferLength = BufferSize;

    status = ZwQuerySystemInformation(SystemFirmwareTableInformation, pSfti, Length, &Length);
    if (NT_SUCCESS(status))
    {
        RawSMBIOSData* smb = (RawSMBIOSData*)pSfti->TableBuffer;

        for (UCHAR* data = smb->SMBIOSTableData; data < smb->SMBIOSTableData + smb->Length;)
        {
            dmi_header* h = (dmi_header*)data;
            if (h->length < 4)
                break;

            //Search for System Information structure with type 0x01 (see para 7.2)
            if (h->type == 0x01 && h->length >= 0x19)
            {
                data += 0x08; //UUID is at offset 0x08

                // check if there is a valid UUID (not all 0x00 or all 0xff)
                BOOLEAN all_zero = TRUE, all_one = TRUE;
                for (int i = 0; i < 16 && (all_zero || all_one); i++)
                {
                    if (data[i] != 0x00) all_zero = FALSE;
                    if (data[i] != 0xFF) all_one = FALSE;
                }

                if (!all_zero && !all_one)
                {
                    // As off version 2.6 of the SMBIOS specification, the first 3 fields
                    // of the UUID are supposed to be encoded on little-endian. (para 7.2.1)
                    *uuid++ = data[3];
                    *uuid++ = data[2];
                    *uuid++ = data[1];
                    *uuid++ = data[0];
                    *uuid++ = data[5];
                    *uuid++ = data[4];
                    *uuid++ = data[7];
                    *uuid++ = data[6];
                    for (int i = 8; i < 16; i++)
                        *uuid++ = data[i];

                    result = TRUE;
                }

                break;
            }

            //skip over formatted area
            UCHAR* next = data + h->length;

            //skip over unformatted area of the structure (marker is 0000h)
            while (next < smb->SMBIOSTableData + smb->Length && (next[0] != 0 || next[1] != 0))
                next++;

            next += 2;

            data = next;
        }
    }

    ExFreePoolWithTag(pSfti, VERIFY_TAG);

    return result;
}

static wchar_t* hexbyte(UCHAR b, wchar_t* ptr)
{
    static const wchar_t* digits = L"0123456789ABCDEF";
    *ptr++ = digits[b >> 4];
    *ptr++ = digits[b & 0x0f];
    return ptr;
}

wchar_t g_uuid_str[40] = { 0 };

void InitFwUuid(void)
{
    UCHAR uuid[16];
    if (GetFwUuid(uuid))
    {
        wchar_t* ptr = g_uuid_str;
        int i;
        for (i = 0; i < 4; i++)
            ptr = hexbyte(uuid[i], ptr);
        *ptr++ = '-';
        for (; i < 6; i++)
            ptr = hexbyte(uuid[i], ptr);
        *ptr++ = '-';
        for (; i < 8; i++)
            ptr = hexbyte(uuid[i], ptr);
        *ptr++ = '-';
        for (; i < 10; i++)
            ptr = hexbyte(uuid[i], ptr);
        *ptr++ = '-';
        for (; i < 16; i++)
            ptr = hexbyte(uuid[i], ptr);
        *ptr++ = 0;
    }
    else // fallback to null guid on error
        wcscpy(g_uuid_str, L"00000000-0000-0000-0000-000000000000");

    DbgMsg("DC FW-UUID: %S\n", g_uuid_str);
}


NTSTATUS dc_verify_cert()
{
    NTSTATUS status = KphValidateCertificate();
    
    if (Verify_CertInfo.active) {
		dc_load_flags |= DST_PRO_ENABLED;
    } else {
        dc_load_flags &= ~DST_PRO_ENABLED;   
	}

	return status;
}