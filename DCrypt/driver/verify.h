#ifndef _VERIFY_H_
#define _VERIFY_H_

#define SOFTWARE_NAME L"DiskCryptor"

typedef union _SCertInfo {
    unsigned long long State;
    struct {
        unsigned long
            active      : 1,    // certificate is active
            expired     : 1,    // certificate is expired but may be active
            outdated    : 1,    // certificate is expired, not anymore valid for the current build
            grace_period: 1,    // the certificate is expired and or outdated but we keep it valid for 1 extra month
			locked      : 1,    // certificate is locked to a specific machine
            reservd_1   : 3,

            type        : 5,
            level       : 3,

            reservd_3   : 8,

            reservd_4   : 8;

        long expirers_in_sec;
    };
} SCertInfo;

enum ECertType {
    eCertNoType         = 0b00000,

    eCertEternal        = 0b00100,
    eCertContributor    = 0b00101,
//  eCert               = 0b00110,
//  eCert               = 0b00111,
            
    eCertBusiness       = 0b01000,
//  eCertEnterprise     = 0b01001,
//  eCertDataCenter     = 0b01010,
//  eCert               = 0b01011,

    eCertPersonal       = 0b01100,
//  eCert               = 0b01101, 
//  eCert               = 0b01110,
//  eCert               = 0b01111,

    eCertHome           = 0b10000,
    eCertFamily         = 0b10001, 
//  eCert               = 0b10010,
//  eCert               = 0b10011,
            
    eCertDeveloper      = 0b10100,
//  eCert               = 0b10101, 
//  eCert               = 0b10110,
//  eCert               = 0b10111,

    eCertPatreon        = 0b11000,
    eCertGreatPatreon   = 0b11001,
    eCertEntryPatreon   = 0b11010,
//  eCert               = 0b11011,

    eCertEvaluation     = 0b11100
};

//enum ECertLevel {
//    eCertNoLevel        = 0b000,
////  eCertBasic          = 0b001,
//    eCertStandard       = 0b010,
//    eCertStandard2      = 0b011,
//    eCertAdvanced1      = 0b100,
//    eCertAdvanced       = 0b101,
////  eCertUltimate       = 0b110,
//    eCertMaxLevel       = 0b111,
//};

#define CERT_IS_TYPE(cert,t)        ((cert.type & 0b11100) == (unsigned long)(t))
#define CERT_IS_SUBSCRIPTION(cert)  (CERT_IS_TYPE(cert, eCertBusiness) || CERT_IS_TYPE(cert, eCertHome) || cert.type == eCertEntryPatreon || CERT_IS_TYPE(cert, eCertEvaluation))
#define CERT_IS_INSIDER(cert)       (CERT_IS_TYPE(cert, eCertEternal) || cert.type == eCertGreatPatreon || cert.type == eCertDeveloper)

#ifdef IS_DRIVER
extern SCertInfo Verify_CertInfo;
extern wchar_t g_uuid_str[40];

// Initialize firmware UUID
void InitFwUuid(void);

// Validate certificate from file
NTSTATUS KphValidateCertificate(void);

// Verify signature of a buffer
NTSTATUS KphVerifyBuffer(PUCHAR Buffer, ULONG BufferSize, PUCHAR Signature, ULONG SignatureSize);

// Verify current process signature
NTSTATUS KphVerifyCurrentProcess(void);

// Hash a file
NTSTATUS KphHashFile(PUNICODE_STRING FileName, PVOID *Hash, PULONG HashSize);

// Verify a file against a signature
NTSTATUS KphVerifyFile(PUNICODE_STRING FileName, PUCHAR Signature, ULONG SignatureSize);

NTSTATUS dc_verify_cert();
#endif

#endif /* _VERIFY_H_ */
