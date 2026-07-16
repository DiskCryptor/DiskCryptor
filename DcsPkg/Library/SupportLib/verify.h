/** @file
  DCS TPM Certificate Verification Header

  This header provides certificate verification declarations for DiskCryptor UEFI.

  Copyright (C) 2021-2026 David Xanatos, xanasoft.com
  Adapted for DiskCryptor UEFI

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

**/

#ifndef _DCS_TPM_VERIFY_H_
#define _DCS_TPM_VERIFY_H_

#include <Uefi.h>

//
// Software name for certificate validation
//
#define SOFTWARE_NAME  L"DiskCryptor"

//
// Certificate types
//
typedef enum {
    eCertNoType         = 0b00000,

    eCertEternal        = 0b00100,
    eCertContributor    = 0b00101,

    eCertBusiness       = 0b01000,

    eCertPersonal       = 0b01100,

    eCertHome           = 0b10000,
    eCertFamily         = 0b10001,

    eCertDeveloper      = 0b10100,

    eCertPatreon        = 0b11000,
    eCertGreatPatreon   = 0b11001,
    eCertEntryPatreon   = 0b11010,

    eCertEvaluation     = 0b11100
} ECERT_TYPE;

//
// Certificate levels
//
//typedef enum {
//    eCertNoLevel        = 0b000,
//    eCertStandard       = 0b010,
//    eCertStandard2      = 0b011,
//    eCertAdvanced1      = 0b100,
//    eCertAdvanced       = 0b101,
//    eCertMaxLevel       = 0b111,
//} ECERT_LEVEL;

//
// Certificate information structure
//
typedef union _SCERT_INFO {
    UINT64 State;
    struct {
        UINT32
            active      : 1,    // certificate is active
            expired     : 1,    // certificate is expired but may be active
            outdated    : 1,    // certificate is expired, not anymore valid for the current build
            grace_period: 1,    // the certificate is expired and or outdated but we keep it valid for 1 extra month
            locked      : 1,    // certificate is locked to a specific machine
            reserved_1  : 3,

            type        : 5,
            level       : 3,

            reserved_3  : 8,

            reserved_4  : 8;

        INT32 expirers_in_sec;
    } s;
} SCERT_INFO;

//
// Macros for certificate type checking
//
#define CERT_IS_TYPE(cert, t)        (((cert).s.type & 0b11100) == (UINT32)(t))
#define CERT_IS_SUBSCRIPTION(cert)   (CERT_IS_TYPE(cert, eCertBusiness) || CERT_IS_TYPE(cert, eCertHome) || (cert).s.type == eCertEntryPatreon || CERT_IS_TYPE(cert, eCertEvaluation))
#define CERT_IS_INSIDER(cert)        (CERT_IS_TYPE(cert, eCertEternal) || (cert).s.type == eCertGreatPatreon || (cert).s.type == eCertDeveloper)

//
// Global certificate info (defined in verify.c)
//
extern SCERT_INFO gVerifyCertInfo;

//
// Global UUID string (defined in verify.c)
//
extern CHAR16 gUuidStr[40];

/**
  Initialize firmware UUID and validate certificate.

  This function retrieves the SMBIOS UUID and validates
  the DiskCryptor certificate stored in UEFI variables.

  @retval EFI_SUCCESS        Certificate validated successfully
  @retval EFI_NOT_FOUND      No certificate found
  @retval EFI_SECURITY_VIOLATION  Signature verification failed
  @retval EFI_ACCESS_DENIED  Certificate is locked to different hardware
  @retval EFI_TIMEOUT        Certificate has expired
  @retval Other              Other error

**/
EFI_STATUS
VerifyInit (
    VOID
    );

/**
  Verify a buffer's signature.

  @param[in]  Buffer         Data buffer to verify
  @param[in]  BufferSize     Size of buffer
  @param[in]  Signature      ECDSA P-256 signature (64 bytes, r||s format)
  @param[in]  SignatureSize  Size of signature

  @retval EFI_SUCCESS             Signature verified
  @retval EFI_SECURITY_VIOLATION  Signature invalid
  @retval Other                   Error during verification

**/
EFI_STATUS
VerifyBuffer (
    IN CONST UINT8  *Buffer,
    IN UINTN        BufferSize,
    IN CONST UINT8  *Signature,
    IN UINTN        SignatureSize
    );


#endif // _DCS_TPM_VERIFY_H_
