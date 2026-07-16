/** @file
  Certificate Verification Implementation

  This module provides certificate verification for DiskCryptor.

  Copyright (C) 2026 David Xanatos, xanasoft.com

**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/BaseCryptLib.h>
#include "../MiscUtilsLib/MiscUtilsLib.h"
#include "verify.h"

//#define DEBUG_BUILD

//
// Certificate verification constants
//
#define SOFTWARE_NAME           L"DiskCryptor"
#define DCS_CERT_FILE_PATH      L"\\EFI\\DCS\\Certificate.dat"

#define CONF_LINE_LEN           512

//
// Crypto algorithm constants
//
#define SHA256_HASH_SIZE        32
#define ECC_P256_KEY_SIZE       32
#define ECC_P256_SIG_SIZE       64

//
// Trusted public key for signature verification (ECDSA P-256)
//
CONST UINT8 gTrustedPublicKeyX[ECC_P256_KEY_SIZE] = {
    0x05, 0x7A, 0x12, 0x5A, 0xF8, 0x54, 0x01, 0x42,
    0xDB, 0x19, 0x87, 0xFC, 0xC4, 0xE3, 0xD3, 0x8D,
    0x46, 0x7B, 0x74, 0x01, 0x12, 0xFC, 0x78, 0xEB,
    0xEF, 0x7F, 0xF6, 0xAF, 0x4D, 0x9A, 0x3A, 0xF6
};

CONST UINT8 gTrustedPublicKeyY[ECC_P256_KEY_SIZE] = {
    0x64, 0x90, 0xDB, 0xE3, 0x48, 0xAB, 0x3E, 0xA7,
    0x2F, 0xC1, 0x18, 0x32, 0xBD, 0x23, 0x02, 0x9D,
    0x3F, 0xF3, 0x27, 0x86, 0x71, 0x45, 0x26, 0x14,
    0x14, 0xF5, 0x19, 0xAA, 0x2D, 0xEE, 0x50, 0x10
};

//
// Global certificate info
//
SCERT_INFO gVerifyCertInfo = { 0 };

//
// UUID string for hardware locking
//
CHAR16 gUuidStr[40] = { 0 };

//---------------------------------------------------------------------------
// SHA-256 hashing using BaseCryptLib
//---------------------------------------------------------------------------

STATIC
EFI_STATUS
HashBuffer (
    IN  CONST UINT8  *Data,
    IN  UINTN        DataSize,
    OUT UINT8        *Hash,
    IN  UINTN        HashSize
    )
{
    VOID     *HashCtx;
    UINTN    CtxSize;
    BOOLEAN  Status;

    if (HashSize < SHA256_HASH_SIZE) {
        return EFI_BUFFER_TOO_SMALL;
    }

    CtxSize = Sha256GetContextSize();
    HashCtx = AllocatePool(CtxSize);
    if (HashCtx == NULL) {
        return EFI_OUT_OF_RESOURCES;
    }

    Status = Sha256Init(HashCtx);
    if (!Status) {
        FreePool(HashCtx);
        return EFI_ABORTED;
    }

    Status = Sha256Update(HashCtx, Data, DataSize);
    if (!Status) {
        FreePool(HashCtx);
        return EFI_ABORTED;
    }

    Status = Sha256Final(HashCtx, Hash);
    FreePool(HashCtx);

    return Status ? EFI_SUCCESS : EFI_ABORTED;
}

#if 1
//---------------------------------------------------------------------------
// ECDSA P-256 signature verification custom implementation in ec_dsa.c
//
// We using openssl this adds ~1MiB to the binary size, like with DcsLdr.efi,
// so we implement our own minimal ECDSA verification.
//---------------------------------------------------------------------------

EFI_STATUS
VerifyEcdsaSignature (
    IN CONST UINT8  *Hash,
    IN UINTN        HashSize,
    IN CONST UINT8  *Signature,
    IN UINTN        SignatureSize
    );

#else
//---------------------------------------------------------------------------
// ECDSA P-256 signature verification using EDK2 BaseCryptLib
//
// We create a minimal X509 certificate template with our public key,
// then use EcGetPublicKeyFromX509() + EcDsaVerify() from BaseCryptLib.
// We need the bigger ssl build for EC_DSA:
//  OpensslLib|CryptoPkg/Library/OpensslLib/OpensslLibFull.inf
//---------------------------------------------------------------------------

//
// Minimal X509 certificate template for EC P-256 public key.
// This is a self-signed certificate with minimal fields.
// The public key (65 bytes: 0x04 || X || Y) is at offset 126.
//
// Structure:
//   Certificate ::= SEQUENCE {
//     tbsCertificate, signatureAlgorithm, signatureValue
//   }
//
//
// Minimal X509 certificate template for EC P-256 public key.
// DER encoded with carefully calculated length fields.
//
// Total size: 194 bytes (3 header + 191 content)
// TBSCertificate: 174 bytes (3 header + 171 content)
// Public key (0x04 marker) is at offset 112
//
#define X509_EC_P256_PUBKEY_OFFSET    112

STATIC CONST UINT8 gX509EcP256Template[] = {
    // SEQUENCE Certificate (content length = 191 = 0xBF)
    0x30, 0x81, 0xBF,

    // SEQUENCE TBSCertificate (content length = 171 = 0xAB)
    0x30, 0x81, 0xAB,

    // [0] EXPLICIT Version v3 (5 bytes)
    0xA0, 0x03, 0x02, 0x01, 0x02,

    // INTEGER serialNumber = 1 (3 bytes)
    0x02, 0x01, 0x01,

    // SEQUENCE signatureAlgorithm ecdsa-with-SHA256 (12 bytes)
    0x30, 0x0A, 0x06, 0x08,
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,

    // SEQUENCE issuer CN=C (14 bytes)
    0x30, 0x0C, 0x31, 0x0A, 0x30, 0x08,
    0x06, 0x03, 0x55, 0x04, 0x03,       // OID commonName
    0x0C, 0x01, 0x43,                   // UTF8String "C"

    // SEQUENCE validity (32 bytes)
    0x30, 0x1E,
    // UTCTime notBefore "200101000000Z"
    0x17, 0x0D, 0x32, 0x30, 0x30, 0x31, 0x30, 0x31,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A,
    // UTCTime notAfter "491231235959Z"
    0x17, 0x0D, 0x34, 0x39, 0x31, 0x32, 0x33, 0x31,
    0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5A,

    // SEQUENCE subject CN=C (14 bytes)
    0x30, 0x0C, 0x31, 0x0A, 0x30, 0x08,
    0x06, 0x03, 0x55, 0x04, 0x03,
    0x0C, 0x01, 0x43,

    // SEQUENCE subjectPublicKeyInfo (91 bytes: 2 header + 89 content)
    0x30, 0x59,
    // SEQUENCE AlgorithmIdentifier (21 bytes: 2 header + 19 content)
    0x30, 0x13,
    // OID ecPublicKey 1.2.840.10045.2.1
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
    // OID prime256v1 1.2.840.10045.3.1.7
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
    // BIT STRING publicKey (68 bytes: 3 header + 65 content)
    0x03, 0x42, 0x00,
    // Offset 109: uncompressed EC point (0x04 || X || Y)
    0x04,
    // X coordinate (32 bytes) - placeholder
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // Y coordinate (32 bytes) - placeholder
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // SEQUENCE signatureAlgorithm (12 bytes)
    0x30, 0x0A, 0x06, 0x08,
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,

    // BIT STRING signatureValue - minimal empty (5 bytes)
    0x03, 0x03, 0x00, 0x30, 0x00
};

STATIC
EFI_STATUS
VerifyEcdsaSignature (
    IN CONST UINT8  *Hash,
    IN UINTN        HashSize,
    IN CONST UINT8  *Signature,
    IN UINTN        SignatureSize
)
{
    UINT8    Cert[sizeof(gX509EcP256Template)];
    VOID     *EcContext = NULL;
    BOOLEAN  Result;

    if (Hash == NULL || Signature == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    if (HashSize != SHA256_HASH_SIZE || SignatureSize != ECC_P256_SIG_SIZE) {
        ERR_PRINT(L"Verify: Invalid hash/sig size: %d/%d\n", HashSize, SignatureSize);
        return EFI_INVALID_PARAMETER;
    }

    //
    // Build X509 certificate with our public key
    //
    CopyMem(Cert, gX509EcP256Template, sizeof(Cert));

    // Insert public key X coordinate (after 0x04 prefix at X509_EC_P256_PUBKEY_OFFSET)
    CopyMem(&Cert[X509_EC_P256_PUBKEY_OFFSET + 1], gTrustedPublicKeyX, ECC_P256_KEY_SIZE);

    // Insert public key Y coordinate (after X)
    CopyMem(&Cert[X509_EC_P256_PUBKEY_OFFSET + 1 + ECC_P256_KEY_SIZE], gTrustedPublicKeyY, ECC_P256_KEY_SIZE);

    //
    // Extract EC context from the certificate
    //
    Result = EcGetPublicKeyFromX509(Cert, sizeof(Cert), &EcContext);
    if (!Result || EcContext == NULL) {
        ERR_PRINT(L"Verify: Failed to extract EC key from X509\n");
        return EFI_SECURITY_VIOLATION;
    }

    //
    // Verify the signature using OpenSSL's ECDSA
    //
    Result = EcDsaVerify(
        EcContext,
        CRYPTO_NID_SHA256,
        Hash,
        HashSize,
        Signature,
        SignatureSize
    );

    EcFree(EcContext);

    if (Result) {
#ifdef DEBUG_BUILD
        //ERR_PRINT(L"Verify: Signature verification succeeded\n");
#endif
        return EFI_SUCCESS;
    }

    ERR_PRINT(L"Verify: Signature verification failed\n");
    return EFI_SECURITY_VIOLATION;
}
#endif

//---------------------------------------------------------------------------
// Date parsing and build date helpers
//---------------------------------------------------------------------------

//
// Build date from __DATE__ macro
// Format: "Jun 19 2026"
//
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

#define CH2N(c) ((c) - '0')

STATIC
EFI_TIME
GetBuildDate (
    VOID
    )
{
    EFI_TIME  Time;

    ZeroMem(&Time, sizeof(Time));

    Time.Day = (UINT8)(CH2N(BUILD_DAY_CH0) * 10 + CH2N(BUILD_DAY_CH1));
    Time.Month = (UINT8)(
        (BUILD_MONTH_IS_JAN) ?  1 : (BUILD_MONTH_IS_FEB) ?  2 : (BUILD_MONTH_IS_MAR) ?  3 :
        (BUILD_MONTH_IS_APR) ?  4 : (BUILD_MONTH_IS_MAY) ?  5 : (BUILD_MONTH_IS_JUN) ?  6 :
        (BUILD_MONTH_IS_JUL) ?  7 : (BUILD_MONTH_IS_AUG) ?  8 : (BUILD_MONTH_IS_SEP) ?  9 :
        (BUILD_MONTH_IS_OCT) ? 10 : (BUILD_MONTH_IS_NOV) ? 11 : (BUILD_MONTH_IS_DEC) ? 12 : 0);
    Time.Year = (UINT16)(CH2N(BUILD_YEAR_CH0) * 1000 + CH2N(BUILD_YEAR_CH1) * 100 +
                         CH2N(BUILD_YEAR_CH2) * 10 + CH2N(BUILD_YEAR_CH3));

    return Time;
}

//
// Convert EFI_TIME to seconds since epoch (simplified - days only precision)
//
STATIC
INT64
TimeToSeconds (
    IN CONST EFI_TIME  *Time
    )
{
    INT64  Days;
    INT64  Year;
    INT64  Month;
    INT64  DaysInMonth[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

    Year = Time->Year;
    Month = Time->Month;

    // Calculate days from year 2000
    Days = (Year - 2000) * 365;
    Days += (Year - 2000 + 3) / 4;  // Leap years (simplified)

    // Add days from months
    for (INT64 i = 0; i < Month - 1; i++) {
        Days += DaysInMonth[i];
    }

    // Add leap day if applicable
    if (Month > 2 && (Year % 4 == 0) && (Year % 100 != 0 || Year % 400 == 0)) {
        Days++;
    }

    Days += Time->Day;

    return Days * 24 * 3600;
}

STATIC
BOOLEAN
ParseDate (
    IN  CONST CHAR16  *DateStr,
    OUT EFI_TIME      *Date
    )
{
    CONST CHAR16  *Ptr;
    CONST CHAR16  *End;
    CHAR16        Buf[16];
    UINTN         Len;

    ZeroMem(Date, sizeof(EFI_TIME));

    Ptr = DateStr;
    while (*Ptr == L' ') Ptr++;

    // Parse day
    End = StrStr(Ptr, L".");
    if (End == NULL || End == Ptr) return FALSE;

    Len = End - Ptr;
    if (Len >= sizeof(Buf) / sizeof(CHAR16)) return FALSE;
    CopyMem(Buf, Ptr, Len * sizeof(CHAR16));
    Buf[Len] = L'\0';
    Date->Day = (UINT8)StrDecimalToUintn(Buf);

    Ptr = End + 1;

    // Parse month
    End = StrStr(Ptr, L".");
    if (End == NULL || End == Ptr) return FALSE;

    Len = End - Ptr;
    if (Len >= sizeof(Buf) / sizeof(CHAR16)) return FALSE;
    CopyMem(Buf, Ptr, Len * sizeof(CHAR16));
    Buf[Len] = L'\0';
    Date->Month = (UINT8)StrDecimalToUintn(Buf);

    Ptr = End + 1;

    // Parse year (may be followed by space or other characters)
    Len = 0;
    while (Ptr[Len] >= L'0' && Ptr[Len] <= L'9' && Len < 15) Len++;
    if (Len == 0) return FALSE;

    CopyMem(Buf, Ptr, Len * sizeof(CHAR16));
    Buf[Len] = L'\0';
    Date->Year = (UINT16)StrDecimalToUintn(Buf);

    return TRUE;
}

STATIC
INT64
GetDateInterval (
    IN INT16  Days,
    IN INT16  Months,
    IN INT16  Years
    )
{
    // Return interval in seconds
    return ((INT64)Days + (INT64)Months * 30 + (INT64)Years * 365) * 24 * 3600;
}

//---------------------------------------------------------------------------
// Certificate validation from EFI variable
//---------------------------------------------------------------------------

//
// Certificate is stored in file: \EFI\DCS\Certificate.dat
// Format: null-separated key:value pairs (REG_MULTI_SZ style)
//

typedef struct _VERIFY_STREAM {
    CHAR16   *Data;
    UINTN    DataSize;
    CHAR16   *CurrentLine;
    BOOLEAN  Eof;
} VERIFY_STREAM;

/**
  Convert UTF-8 string to Unicode (UCS-2).

  @param[in]   Utf8Str     UTF-8 encoded string.
  @param[in]   Utf8Size    Size of UTF-8 string in bytes.
  @param[out]  UnicodeStr  Receives allocated Unicode string.
  @param[out]  UnicodeSize Receives size in bytes (including null terminator).

  @retval EFI_SUCCESS           Conversion successful.
  @retval EFI_OUT_OF_RESOURCES  Memory allocation failed.
**/
STATIC
EFI_STATUS
Utf8ToUnicode (
    IN  CONST CHAR8   *Utf8Str,
    IN  UINTN         Utf8Size,
    OUT CHAR16        **UnicodeStr,
    OUT UINTN         *UnicodeSize
    )
{
    UINTN   i;
    UINTN   j;
    CHAR16  *Result;
    UINTN   ResultLen;

    if (Utf8Str == NULL || UnicodeStr == NULL || UnicodeSize == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    // First pass: count characters needed
    ResultLen = 0;
    for (i = 0; i < Utf8Size && Utf8Str[i] != '\0'; ) {
        UINT8 c = (UINT8)Utf8Str[i];
        if ((c & 0x80) == 0) {
            // Single byte (ASCII)
            i += 1;
        } else if ((c & 0xE0) == 0xC0) {
            // Two bytes
            i += 2;
        } else if ((c & 0xF0) == 0xE0) {
            // Three bytes
            i += 3;
        } else if ((c & 0xF8) == 0xF0) {
            // Four bytes (surrogate pair needed, but we'll use replacement char)
            i += 4;
        } else {
            // Invalid, skip
            i += 1;
        }
        ResultLen++;
    }

    // Allocate result buffer (including null terminator)
    Result = AllocatePool((ResultLen + 1) * sizeof(CHAR16));
    if (Result == NULL) {
        return EFI_OUT_OF_RESOURCES;
    }

    // Second pass: convert
    j = 0;
    for (i = 0; i < Utf8Size && Utf8Str[i] != '\0' && j < ResultLen; ) {
        UINT8 c = (UINT8)Utf8Str[i];
        if ((c & 0x80) == 0) {
            // Single byte (ASCII)
            Result[j++] = (CHAR16)c;
            i += 1;
        } else if ((c & 0xE0) == 0xC0 && i + 1 < Utf8Size) {
            // Two bytes
            Result[j++] = (CHAR16)(((c & 0x1F) << 6) | (Utf8Str[i + 1] & 0x3F));
            i += 2;
        } else if ((c & 0xF0) == 0xE0 && i + 2 < Utf8Size) {
            // Three bytes
            Result[j++] = (CHAR16)(((c & 0x0F) << 12) |
                                   ((Utf8Str[i + 1] & 0x3F) << 6) |
                                   (Utf8Str[i + 2] & 0x3F));
            i += 3;
        } else if ((c & 0xF8) == 0xF0 && i + 3 < Utf8Size) {
            // Four bytes - use replacement character (BMP only)
            Result[j++] = 0xFFFD;
            i += 4;
        } else {
            // Invalid, use replacement character
            Result[j++] = 0xFFFD;
            i += 1;
        }
    }
    Result[j] = L'\0';

    *UnicodeStr = Result;
    *UnicodeSize = (j + 1) * sizeof(CHAR16);
    return EFI_SUCCESS;
}

STATIC
EFI_STATUS
StreamOpenFile (
    IN  CHAR16         *Path,
    IN  BOOLEAN        IsUnicode,
    OUT VERIFY_STREAM  **Stream
    )
{
    EFI_STATUS     Status;
    VOID           *FileBuffer = NULL;
    UINTN          FileSize = 0;
    CHAR16         *UnicodeData = NULL;
    UINTN          UnicodeSize = 0;
    VERIFY_STREAM  *s;

    *Stream = NULL;

    //
    // Load certificate file
    //
    if (IsPxeBoot()) {
        Status = PxeDownloadFile(Path, &FileBuffer, &FileSize);
    } else {
        Status = SimpleFileLoad(NULL, Path, &FileBuffer, &FileSize);
    }

    if (EFI_ERROR(Status)) {
        return Status;
    }

    if (FileBuffer == NULL || FileSize == 0) {
        if (FileBuffer != NULL) {
            FreePool(FileBuffer);
        }
        return EFI_NOT_FOUND;
    }

    //
    // Convert to Unicode if file is ASCII/UTF-8
    //
    if (IsUnicode) {
        // File is already Unicode
        UnicodeData = (CHAR16*)FileBuffer;
        UnicodeSize = FileSize;
    } else {
        // Convert from UTF-8 to Unicode
        Status = Utf8ToUnicode((CHAR8*)FileBuffer, FileSize, &UnicodeData, &UnicodeSize);
        FreePool(FileBuffer);  // Free the original ASCII buffer

        if (EFI_ERROR(Status)) {
            return Status;
        }
    }

    s = AllocateZeroPool(sizeof(VERIFY_STREAM));
    if (s == NULL) {
        FreePool(UnicodeData);
        return EFI_OUT_OF_RESOURCES;
    }

    s->Data = UnicodeData;
    s->DataSize = UnicodeSize;
    s->CurrentLine = s->Data;
    s->Eof = FALSE;

    *Stream = s;
    return EFI_SUCCESS;
}

STATIC
VOID
StreamClose (
    IN VERIFY_STREAM  *Stream
    )
{
    if (Stream != NULL) {
        if (Stream->Data != NULL) {
            FreePool(Stream->Data);
        }
        FreePool(Stream);
    }
}

STATIC
EFI_STATUS
StreamReadLine (
    IN  VERIFY_STREAM  *Stream,
    OUT CHAR16         *Line,
    IN  UINTN          LineSize
    )
{
    UINTN   LinePos;
    UINTN   MaxLen;
    CHAR16  *DataEnd;

    Line[0] = L'\0';

    if (Stream->Eof || Stream->CurrentLine == NULL) {
        return EFI_END_OF_FILE;
    }

    // Calculate end of data
    DataEnd = (CHAR16*)((UINT8*)Stream->Data + Stream->DataSize);

    // Check if we've reached the end
    if (Stream->CurrentLine >= DataEnd) {
        Stream->Eof = TRUE;
        return EFI_END_OF_FILE;
    }

    LinePos = 0;
    MaxLen = LineSize / sizeof(CHAR16) - 1;

    // Skip leading whitespace and empty lines
    while (Stream->CurrentLine < DataEnd) {
        CHAR16 Ch = *Stream->CurrentLine;
        if (Ch == L'\r' || Ch == L'\n' || Ch == L' ' || Ch == L'\t') {
            Stream->CurrentLine++;
        } else if (Ch == L'\0') {
            // End of string
            Stream->Eof = TRUE;
            return EFI_END_OF_FILE;
        } else {
            break;
        }
    }

    // Check again after skipping whitespace
    if (Stream->CurrentLine >= DataEnd) {
        Stream->Eof = TRUE;
        return EFI_END_OF_FILE;
    }

    // Copy until end of line or end of data
    while (Stream->CurrentLine < DataEnd && LinePos < MaxLen) {
        CHAR16 Ch = *Stream->CurrentLine;

        // Stop at line break or null
        if (Ch == L'\r' || Ch == L'\n' || Ch == L'\0') {
            break;
        }

        Line[LinePos++] = Ch;
        Stream->CurrentLine++;
    }

    // Skip line break characters
    while (Stream->CurrentLine < DataEnd) {
        CHAR16 Ch = *Stream->CurrentLine;
        if (Ch == L'\r' || Ch == L'\n') {
            Stream->CurrentLine++;
        } else {
            break;
        }
    }

    // Trim trailing whitespace
    while (LinePos > 0 && (Line[LinePos - 1] == L' ' || Line[LinePos - 1] == L'\t')) {
        LinePos--;
    }

    Line[LinePos] = L'\0';
    return EFI_SUCCESS;
}

//---------------------------------------------------------------------------
// Certificate validation main function
//---------------------------------------------------------------------------

EFI_STATUS
ValidateCertificate (
    IN  CHAR16         *Path
    )
{
    EFI_STATUS      Status;
    VERIFY_STREAM   *Stream = NULL;
    VOID            *HashCtx = NULL;
    UINTN           CtxSize;
    UINT8           Hash[SHA256_HASH_SIZE];
    UINT8           *Signature = NULL;
    UINTN           SignatureSize = 0;
    CHAR16          Line[CONF_LINE_LEN];
    CHAR8           TempUtf8[CONF_LINE_LEN * 4];
    CHAR16          *Type = NULL;
    CHAR16          *Level = NULL;
    INT32           Amount = 1;
    CHAR16          *Key = NULL;
    EFI_TIME        CertDate = { 0 };
    EFI_TIME        CheckDate = { 0 };
    INT32           Days = 0;
    BOOLEAN         NodeLock = FALSE;
    BOOLEAN         NodePass = FALSE;
    EFI_TIME        BuildDate;
    EFI_TIME        CurrentTime;
    INT64           CertDateSec, CheckDateSec, BuildDateSec, CurrentTimeSec;
    INT64           ExpirationDateSec = 0;
    BOOLEAN         IsSubscription;
    BOOLEAN         SoftwareOK = FALSE;

    gVerifyCertInfo.State = 0;

    //
    // Initialize hash context
    //
    CtxSize = Sha256GetContextSize();
    HashCtx = AllocatePool(CtxSize);
    if (HashCtx == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        goto CleanupExit;
    }

    if (!Sha256Init(HashCtx)) {
        Status = EFI_ABORTED;
        goto CleanupExit;
    }

    //
    // Open certificate file
    //
    Status = StreamOpenFile(Path, FALSE, &Stream);  // Certificate file is UTF-8
    if (EFI_ERROR(Status)) {
        Status = EFI_NOT_FOUND;
#ifdef DEBUG_BUILD
        ERR_PRINT(L"Verify: Certificate %s not found: %r\n", Path, Status);
#endif
        goto CleanupExit;
    }

    //
    // Parse certificate lines
    //
    while (!EFI_ERROR(StreamReadLine(Stream, Line, sizeof(Line)))) {
        CHAR16  *Ptr;
        CHAR16  *Name;
        CHAR16  *Value;

#ifdef DEBUG_BUILD
        //OUT_PRINT(L"Verify: Line: %s\n", Line);
#endif

        // Skip empty lines
        if (Line[0] == L'\0') continue;

        // Parse "Name: Value" format
        Ptr = StrStr(Line, L":");
        if (Ptr == NULL || Ptr == Line) continue;

        Value = Ptr + 1;

        // Trim trailing whitespace from name
        while (Ptr > Line && *(Ptr - 1) <= 32) Ptr--;
        *Ptr = L'\0';
        Name = Line;

        // Trim leading whitespace from value
        while (*Value && *Value <= 32) Value++;
        if (*Value == L'\0') continue;

        // Trim trailing whitespace from value
        Ptr = Value + StrLen(Value);
        while (Ptr > Value && *(Ptr - 1) <= 32) Ptr--;
        *Ptr = L'\0';

        //
        // Extract signature (don't hash it)
        //
        if (StrCmpI(Name, L"SIGNATURE") == 0 && Signature == NULL) {
            SignatureSize = DcsBase64DecodedSize(Value);
            Signature = AllocatePool(SignatureSize);
            if (Signature != NULL) {
                if (!DcsBase64Decode(Value, Signature, SignatureSize)) {
                    FreePool(Signature);
                    Signature = NULL;
                    SignatureSize = 0;
                }
            }
            continue;
        }

        //
        // Hash the name and value (converted to UTF-8)
        //
        Status = UnicodeStrToAsciiStrS(Name, TempUtf8, sizeof(TempUtf8));
        if (!EFI_ERROR(Status)) {
            Sha256Update(HashCtx, (UINT8*)TempUtf8, AsciiStrLen(TempUtf8));
        }

        Status = UnicodeStrToAsciiStrS(Value, TempUtf8, sizeof(TempUtf8));
        if (!EFI_ERROR(Status)) {
            Sha256Update(HashCtx, (UINT8*)TempUtf8, AsciiStrLen(TempUtf8));
        }

#ifdef DEBUG_BUILD
        OUT_PRINT(L"Verify: Cert Value: %s: %s\n", Name, Value);
#endif

        //
        // Parse certificate fields
        //
        if (StrCmpI(Name, L"DATE") == 0) {
            if (CertDate.Year != 0) {
                Status = EFI_INVALID_PARAMETER;
                goto CleanupExit;
            }
            ParseDate(Value, &CertDate);

            // Check for "+Days" suffix
            Ptr = StrStr(Value, L"+");
            if (Ptr != NULL) {
                Days = (INT32)StrDecimalToUintn(Ptr + 1);
            }

            // Check for "/ DD.MM.YYYY" check date
            Ptr = StrStr(Value, L"/");
            if (Ptr != NULL) {
                ParseDate(Ptr + 1, &CheckDate);
            }
        }
        else if (StrCmpI(Name, L"DAYS") == 0) {
            if (Days != 0) {
                Status = EFI_INVALID_PARAMETER;
                goto CleanupExit;
            }
            Days = (INT32)StrDecimalToUintn(Value);
        }
        else if (StrCmpI(Name, L"TYPE") == 0) {
            if (Type != NULL) {
                Status = EFI_INVALID_PARAMETER;
                goto CleanupExit;
            }

            // Check for TYPE-LEVEL format
            Ptr = StrStr(Value, L"-");
            if (Ptr != NULL) {
                *Ptr++ = L'\0';
                Level = AllocateCopyPool((StrLen(Ptr) + 1) * sizeof(CHAR16), Ptr);
            }
            Type = AllocateCopyPool((StrLen(Value) + 1) * sizeof(CHAR16), Value);
        }
        else if (StrCmpI(Name, L"UPDATEKEY") == 0) {
            if (Key != NULL) {
                Status = EFI_INVALID_PARAMETER;
                goto CleanupExit;
            }
            Key = AllocateCopyPool((StrLen(Value) + 1) * sizeof(CHAR16), Value);
        }
        else if (StrCmpI(Name, L"AMOUNT") == 0) {
            Amount = (INT32)StrDecimalToUintn(Value);
        }
        else if (StrCmpI(Name, L"SOFTWARE") == 0) {
            if (StrCmpI(Value, SOFTWARE_NAME) == 0)
                SoftwareOK = TRUE;
        }
        else if (StrCmpI(Name, L"HWID") == 0) {
            NodeLock = TRUE;
            if (StrCmpI(Value, gUuidStr) == 0) {
                NodePass = TRUE;
            }
        }
    }

    //
    // Finalize hash
    //
    if (!Sha256Final(HashCtx, Hash)) {
        Status = EFI_ABORTED;
        goto CleanupExit;
    }

#ifdef DEBUG_BUILD
    //OUT_PRINT(L"Verify: Hash: ");
    //UefiPrintBytes(Hash, SHA256_HASH_SIZE);
    //OUT_PRINT(L"\n");
#endif

    //
    // Verify signature
    //
    if (Signature == NULL) {
        ERR_PRINT(L"Verify: Signature missing\n");
        Status = EFI_SECURITY_VIOLATION;
        goto CleanupExit;
    }

    if (!SoftwareOK) {
        Status = EFI_INCOMPATIBLE_VERSION;
        goto CleanupExit;
    }

    Status = VerifyEcdsaSignature(Hash, SHA256_HASH_SIZE, Signature, SignatureSize);

    //
    // Check for blocked update keys
    //
    //if (!EFI_ERROR(Status) && Key != NULL) {
    //    if (StrCmpI(Key, L"00000000000000000000000000000000") == 0) {
    //        ERR_PRINT(L"Verify: Blocked UpdateKey: %s\n", Key);
    //        Status = EFI_ACCESS_DENIED;
    //    }
    //}

    if (EFI_ERROR(Status)) {
        goto CleanupExit;
    }

    //
    // Signature verified - check node lock
    //
    if (NodeLock) {
        gVerifyCertInfo.s.locked = 1;
        if (!NodePass) {
            Status = EFI_ACCESS_DENIED;
            goto CleanupExit;
        }
    }

    gVerifyCertInfo.s.active = 1;

    //
    // Fix for early contributor certificates
    //
    if (Type == NULL && Level != NULL) {
        Type = Level;
        Level = NULL;
    }

    //
    // Determine certificate type
    //
    if (Type == NULL) {
        // No type specified
    }
    else if (StrCmpI(Type, L"CONTRIBUTOR") == 0) {
        gVerifyCertInfo.s.type = eCertContributor;
    }
    else if (StrCmpI(Type, L"ETERNAL") == 0) {
        gVerifyCertInfo.s.type = eCertEternal;
    }
    else if (StrCmpI(Type, L"BUSINESS") == 0) {
        gVerifyCertInfo.s.type = eCertBusiness;
    }
    else if (StrCmpI(Type, L"EVALUATION") == 0 || StrCmpI(Type, L"TEST") == 0) {
        gVerifyCertInfo.s.type = eCertEvaluation;
    }
    else if (StrCmpI(Type, L"HOME") == 0) {
        gVerifyCertInfo.s.type = eCertHome;
    }
    else if (StrCmpI(Type, L"FAMILYPACK") == 0 || StrCmpI(Type, L"FAMILY") == 0) {
        gVerifyCertInfo.s.type = eCertFamily;
    }
    else if (StrStr(Type, L"PATREON") != NULL) {
        if (StrnCmp(Type, L"GREAT", 5) == 0) {
            gVerifyCertInfo.s.type = eCertGreatPatreon;
        }
        else if (StrnCmp(Type, L"ENTRY", 5) == 0) {
            gVerifyCertInfo.s.type = eCertEntryPatreon;
        }
        else {
            gVerifyCertInfo.s.type = eCertPatreon;
        }
    }
    else {
        gVerifyCertInfo.s.type = eCertPersonal;
    }

    //
    // Determine certificate level
    //
    //if (CERT_IS_TYPE(gVerifyCertInfo, eCertEternal) ||
    //    CERT_IS_TYPE(gVerifyCertInfo, eCertDeveloper)) {
    //    gVerifyCertInfo.s.level = eCertMaxLevel;
    //}
    //else if (CERT_IS_TYPE(gVerifyCertInfo, eCertEvaluation)) {
    //    gVerifyCertInfo.s.level = eCertMaxLevel;
    //}
    //else if (Level == NULL || StrCmpI(Level, L"STANDARD") == 0) {
    //    gVerifyCertInfo.s.level = eCertStandard;
    //}
    //else if (StrCmpI(Level, L"ADVANCED") == 0) {
    //    if (gVerifyCertInfo.s.type == eCertGreatPatreon) {
    //        gVerifyCertInfo.s.level = eCertMaxLevel;
    //    }
    //    else if (gVerifyCertInfo.s.type == eCertPatreon || gVerifyCertInfo.s.type == eCertEntryPatreon) {
    //        gVerifyCertInfo.s.level = eCertAdvanced1;
    //    }
    //    else {
    //        gVerifyCertInfo.s.level = eCertAdvanced;
    //    }
    //}

    //
    // Calculate expiration
    //
    BuildDate = GetBuildDate();
    gRT->GetTime(&CurrentTime, NULL);

    CertDateSec = TimeToSeconds(&CertDate);
    CheckDateSec = CheckDate.Year ? TimeToSeconds(&CheckDate) : CertDateSec;
    BuildDateSec = TimeToSeconds(&BuildDate);
    CurrentTimeSec = TimeToSeconds(&CurrentTime);

    if (CERT_IS_TYPE(gVerifyCertInfo, eCertEternal)) {
        ExpirationDateSec = -1;  // Never expires
    }
    else if (CERT_IS_TYPE(gVerifyCertInfo, eCertEvaluation)) {
        if (Days) {
            ExpirationDateSec = CertDateSec + GetDateInterval((INT16)Days, 0, 0);
        } else {
            ExpirationDateSec = CertDateSec + GetDateInterval(Level ? (INT16)StrDecimalToUintn(Level) : 7, 0, 0);
        }
    }
    else if (gVerifyCertInfo.s.type == eCertEntryPatreon) {
        ExpirationDateSec = CertDateSec + GetDateInterval(0, 3, 0);
    }
    else if (Days) {
        ExpirationDateSec = CertDateSec + GetDateInterval((INT16)Days, 0, 0);
    }
    else {
        ExpirationDateSec = CertDateSec + GetDateInterval(0, 0, 1);  // Default 1 year
    }

    IsSubscription = CERT_IS_SUBSCRIPTION(gVerifyCertInfo);

    if (ExpirationDateSec != -1) {
        if (ExpirationDateSec < CurrentTimeSec) {
            gVerifyCertInfo.s.expired = 1;
        }
        gVerifyCertInfo.s.expirers_in_sec = (INT32)(ExpirationDateSec - CurrentTimeSec);

        if (!IsSubscription && ExpirationDateSec < BuildDateSec) {
            gVerifyCertInfo.s.outdated = 1;
        }
    }

    //
    // Check validity with grace period
    //
    if (IsSubscription ? gVerifyCertInfo.s.expired : gVerifyCertInfo.s.outdated) {
        if (!CERT_IS_TYPE(gVerifyCertInfo, eCertEvaluation)) {
            if (ExpirationDateSec + GetDateInterval(0, 1, 0) >= CurrentTimeSec) {
                gVerifyCertInfo.s.grace_period = 1;
            }
        }

        if (!gVerifyCertInfo.s.grace_period) {
            gVerifyCertInfo.s.active = 0;
            Status = EFI_TIMEOUT;  // Certificate expired
        }
    }

CleanupExit:
#ifdef DEBUG_BUILD
    OUT_PRINT(L"Verify: Cert status: %r; active: %d\n", Status, gVerifyCertInfo.s.active);
#endif

    if (HashCtx != NULL) FreePool(HashCtx);
    if (Signature != NULL) FreePool(Signature);
    if (Type != NULL) FreePool(Type);
    if (Level != NULL) FreePool(Level);
    if (Key != NULL) FreePool(Key);
    if (Stream != NULL) StreamClose(Stream);

    return Status;
}

//---------------------------------------------------------------------------
// Buffer verification function
//---------------------------------------------------------------------------

EFI_STATUS
VerifyBuffer (
    IN CONST UINT8  *Buffer,
    IN UINTN        BufferSize,
    IN CONST UINT8  *Signature,
    IN UINTN        SignatureSize
    )
{
    EFI_STATUS  Status;
    UINT8       Hash[SHA256_HASH_SIZE];

    Status = HashBuffer(Buffer, BufferSize, Hash, sizeof(Hash));
    if (EFI_ERROR(Status)) {
        return Status;
    }

    return VerifyEcdsaSignature(Hash, SHA256_HASH_SIZE, Signature, SignatureSize);
}

//---------------------------------------------------------------------------
// Public API
//---------------------------------------------------------------------------

/**
  Initialize firmware UUID and validate certificate.

  @retval EFI_SUCCESS    Certificate validated successfully
  @retval Other          Validation failed

**/
EFI_STATUS
VerifyInit (
    VOID
    )
{
    EFI_STATUS  Status;
    CHAR16      Path[128];

//#ifdef EC_DEBUG
//    // Run self-test
//    if (!VerifySelfTest()) {
//        ERR_PRINT(L"Verify: Self-test FAILED!\n");
//    }
//#endif

    GetSystemUuid(gUuidStr, sizeof(gUuidStr));
    Status = ValidateCertificate(DCS_CERT_FILE_PATH);

    //
    // If certificate not found and PXE booting, try UUID-specific path
    // Format: \EFI\DCS\Certificate-{UUID}.dat
    //
    if (Status == EFI_NOT_FOUND && IsPxeBoot()) {
        UnicodeSPrint(
            Path,
            sizeof(Path),
            L"\\EFI\\DCS\\Certificate-%s.dat",
            gUuidStr
            );
        Status = ValidateCertificate(Path);
    }

    return Status;
}
