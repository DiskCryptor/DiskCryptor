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

#define SHA256_HASH_SIZE        32
#define ECC_P256_KEY_SIZE       32
#define ECC_P256_SIG_SIZE       64

extern CONST UINT8 gTrustedPublicKeyX[ECC_P256_KEY_SIZE];
extern CONST UINT8 gTrustedPublicKeyY[ECC_P256_KEY_SIZE];

//#define EC_DEBUG

#ifdef EC_DEBUG
//
// Debug log buffer for TFTP upload
//
#define DEBUG_LOG_SIZE  (64 * 1024)
STATIC CHAR8  *gDebugLog = NULL;
STATIC UINTN  gDebugLogPos = 0;

STATIC
VOID
DebugLogInit (
    VOID
)
{
    if (gDebugLog == NULL) {
        gDebugLog = AllocateZeroPool(DEBUG_LOG_SIZE);
        gDebugLogPos = 0;
    }
}

STATIC
VOID
DebugLogPrint (
    IN CONST CHAR8  *Format,
    ...
)
{
    VA_LIST  Args;
    UINTN    Len;

    if (gDebugLog == NULL || gDebugLogPos >= DEBUG_LOG_SIZE - 256) {
        return;
    }

    VA_START(Args, Format);
    Len = AsciiVSPrint(gDebugLog + gDebugLogPos, DEBUG_LOG_SIZE - gDebugLogPos, Format, Args);
    VA_END(Args);

    gDebugLogPos += Len;
}

// DebugLogBn256 is defined after BN256 type

STATIC
VOID
DebugLogUpload (
    VOID
)
{
    if (gDebugLog != NULL && gDebugLogPos > 0 && IsPxeBoot()) {
        PxeUploadFile(L"\\verify_debug.log", gDebugLog, gDebugLogPos);
    }
}

STATIC
VOID
DebugLogFree (
    VOID
)
{
    if (gDebugLog != NULL) {
        FreePool(gDebugLog);
        gDebugLog = NULL;
        gDebugLogPos = 0;
    }
}
#endif


//---------------------------------------------------------------------------
// 256-bit Big Integer Arithmetic for ECDSA P-256
//---------------------------------------------------------------------------

//
// 256-bit integer represented as 8 x 32-bit words (little-endian)
// bn[0] = least significant, bn[7] = most significant
//
typedef struct {
    UINT32  Word[8];
} BN256;

#ifdef EC_DEBUG
STATIC
VOID
DebugLogBn256 (
    IN CONST CHAR8   *Name,
    IN CONST BN256   *N
)
{
    // Use explicit casting to avoid 64-bit variadic promotion issues
    DebugLogPrint("%a: %08x%08x%08x%08x%08x%08x%08x%08x\r\n",
        Name,
        (unsigned int)N->Word[7], (unsigned int)N->Word[6],
        (unsigned int)N->Word[5], (unsigned int)N->Word[4],
        (unsigned int)N->Word[3], (unsigned int)N->Word[2],
        (unsigned int)N->Word[1], (unsigned int)N->Word[0]);
}
#endif

//
// P-256 curve prime: p = 2^256 - 2^224 + 2^192 + 2^96 - 1
// p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
// In 32-bit words (big-endian): FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFF
// Little-endian: Word[0]=FFFFFFFF (LSB), ..., Word[7]=FFFFFFFF (MSB)
//
STATIC CONST BN256 gP256Prime = {{
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
        0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF
    }};

//
// 2^256 mod p = 2^256 - p (used for carry correction in modular arithmetic)
// p = FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFF
// 2^256 - p = 00000000 FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 00000000 00000000 00000001
// Little-endian: Word[0]=00000001, Word[1]=00000000, Word[2]=00000000, Word[3]=FFFFFFFF, ...
//
STATIC CONST BN256 gP256CarryCorrection = {{
        0x00000001, 0x00000000, 0x00000000, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0x00000000
    }};

//
// P-256 curve order: n (order of base point G)
// n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
//
STATIC CONST BN256 gP256Order = {{
        0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD,
        0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF
    }};

//
// 2^256 mod n = 2^256 - n (carry correction for curve order)
// = 0x00000000FFFFFFFF00000000000000004319055258E8617B0C46353D039CDAAF
//
STATIC CONST BN256 gP256OrderCarryCorrection = {{
        0x039CDAAF, 0x0C46353D, 0x58E8617B, 0x43190552,
        0x00000000, 0x00000000, 0xFFFFFFFF, 0x00000000
    }};

//
// P-256 base point G (generator)
//
STATIC CONST BN256 gP256Gx = {{
        0xD898C296, 0xF4A13945, 0x2DEB33A0, 0x77037D81,
        0x63A440F2, 0xF8BCE6E5, 0xE12C4247, 0x6B17D1F2
    }};

STATIC CONST BN256 gP256Gy = {{
        0x37BF51F5, 0xCBB64068, 0x6B315ECE, 0x2BCE3357,
        0x7C0F9E16, 0x8EE7EB4A, 0xFE1A7F9B, 0x4FE342E2
    }};

STATIC
VOID
Bn256Zero (
    OUT BN256  *R
)
{
    ZeroMem(R, sizeof(BN256));
}

STATIC
VOID
Bn256Copy (
    OUT BN256        *R,
    IN  CONST BN256  *A
)
{
    CopyMem(R, A, sizeof(BN256));
}

STATIC
INT32
Bn256Cmp (
    IN CONST BN256  *A,
    IN CONST BN256  *B
)
{
    INTN  i;

    for (i = 7; i >= 0; i--) {
        if (A->Word[i] > B->Word[i]) return 1;
        if (A->Word[i] < B->Word[i]) return -1;
    }
    return 0;
}

STATIC
BOOLEAN
Bn256IsZero (
    IN CONST BN256  *A
)
{
    UINTN  i;

    for (i = 0; i < 8; i++) {
        if (A->Word[i] != 0) return FALSE;
    }
    return TRUE;
}

//
// R = A + B, returns carry
//
STATIC
UINT32
Bn256Add (
    OUT BN256        *R,
    IN  CONST BN256  *A,
    IN  CONST BN256  *B
)
{
    UINT64  Carry = 0;
    UINTN   i;

    for (i = 0; i < 8; i++) {
        Carry += (UINT64)A->Word[i] + (UINT64)B->Word[i];
        R->Word[i] = (UINT32)Carry;
        Carry >>= 32;
    }
    return (UINT32)Carry;
}

//
// R = A - B, returns borrow
//
STATIC
UINT32
Bn256Sub (
    OUT BN256        *R,
    IN  CONST BN256  *A,
    IN  CONST BN256  *B
)
{
    INT64  Borrow = 0;
    UINTN  i;

    for (i = 0; i < 8; i++) {
        Borrow += (INT64)A->Word[i] - (INT64)B->Word[i];
        R->Word[i] = (UINT32)Borrow;
        Borrow >>= 32;
    }
    return (UINT32)(Borrow & 1);
}

//
// R = (A + B) mod P (for P-256 prime field)
//
STATIC
VOID
Bn256ModAddP (
    OUT BN256        *R,
    IN  CONST BN256  *A,
    IN  CONST BN256  *B
)
{
    UINT32  Carry;
    BN256   Tmp;

    Carry = Bn256Add(R, A, B);
    if (Carry || Bn256Cmp(R, &gP256Prime) >= 0) {
        Bn256Sub(R, R, &gP256Prime);
    }
    (void)Tmp;
}

//
// R = (A - B) mod P (for P-256 prime field)
//
STATIC
VOID
Bn256ModSubP (
    OUT BN256        *R,
    IN  CONST BN256  *A,
    IN  CONST BN256  *B
)
{
    UINT32  Borrow;

    Borrow = Bn256Sub(R, A, B);
    if (Borrow) {
        Bn256Add(R, R, &gP256Prime);
    }
}

//
// R = (A + B) mod N (for P-256 order)
//
STATIC
VOID
Bn256ModAddN (
    OUT BN256        *R,
    IN  CONST BN256  *A,
    IN  CONST BN256  *B
)
{
    UINT32  Carry;

    Carry = Bn256Add(R, A, B);
    if (Carry || Bn256Cmp(R, &gP256Order) >= 0) {
        Bn256Sub(R, R, &gP256Order);
    }
}

//
// R = (R + R) mod M (modular doubling)
// Uses carry correction constants for P-256 prime and order
//
STATIC
VOID
Bn256ModDouble (
    IN OUT BN256     *R,
    IN CONST BN256   *M
)
{
    UINT32 Carry = Bn256Add(R, R, R);

    if (Carry) {
        // True value is R + 2^256. Add (2^256 mod M) to get correct result.
        if (Bn256Cmp(M, &gP256Prime) == 0) {
            Bn256Add(R, R, &gP256CarryCorrection);
        } else if (Bn256Cmp(M, &gP256Order) == 0) {
            Bn256Add(R, R, &gP256OrderCarryCorrection);
        } else {
            // Generic fallback - may not be correct for arbitrary moduli
            // but we only use gP256Prime and gP256Order
            Bn256Sub(R, R, M);
        }
    }

    // Final reduction if still >= M
    while (Bn256Cmp(R, M) >= 0) {
        Bn256Sub(R, R, M);
    }
}

//
// Helper: Modular add with carry correction
//
STATIC
VOID
Bn256ModAdd (
    IN OUT BN256     *R,
    IN CONST BN256   *A,
    IN CONST BN256   *M
)
{
    UINT32 Carry = Bn256Add(R, R, A);

    if (Carry) {
        // True value is R + 2^256. Add (2^256 mod M) to get correct result.
        if (Bn256Cmp(M, &gP256Prime) == 0) {
            Bn256Add(R, R, &gP256CarryCorrection);
        } else if (Bn256Cmp(M, &gP256Order) == 0) {
            Bn256Add(R, R, &gP256OrderCarryCorrection);
        }
    }

    // Final reduction if still >= M
    while (Bn256Cmp(R, M) >= 0) {
        Bn256Sub(R, R, M);
    }
}

//
// R = (A * B) mod M using double-and-add with interleaved reduction
// This is slower but simpler and more reliable
//
#ifdef EC_DEBUG
STATIC BOOLEAN gMulDebug = FALSE;
#endif

STATIC
VOID
Bn256ModMulGeneric (
    OUT BN256        *R,
    IN  CONST BN256  *A,
    IN  CONST BN256  *B,
    IN  CONST BN256  *M
)
{
    BN256   Acc;
    BN256   Temp;
    INTN    i;
    UINT32  Bit;
#ifdef EC_DEBUG
    INTN    BitCount = 0;
#endif

    // Ensure inputs are reduced
    Bn256Copy(&Temp, A);
    while (Bn256Cmp(&Temp, M) >= 0) {
        Bn256Sub(&Temp, &Temp, M);
    }

    Bn256Zero(&Acc);

    // Process B from MSB to LSB using double-and-add
    for (i = 255; i >= 0; i--) {
        // Acc = 2 * Acc mod M
        Bn256ModDouble(&Acc, M);

        // If bit i of B is set, Acc = Acc + A mod M
        Bit = B->Word[i / 32] & (1U << (i % 32));
        if (Bit) {
            Bn256ModAdd(&Acc, &Temp, M);
#ifdef EC_DEBUG
            if (gMulDebug && BitCount < 5) {
                DebugLogPrint("  After bit %d: ", (int)i);
                DebugLogBn256("Acc", &Acc);
                BitCount++;
            }
#endif
        }
    }

    Bn256Copy(R, &Acc);
}

//
// R = A^E mod M using square-and-multiply
//
STATIC
VOID
Bn256ModExp (
    OUT BN256        *R,
    IN  CONST BN256  *A,
    IN  CONST BN256  *E,
    IN  CONST BN256  *M
)
{
    BN256  Base, Exp, Result;
    INTN   i;
    UINT32 Bit;

    Bn256Copy(&Base, A);
    Bn256Copy(&Exp, E);

    // Result = 1
    Bn256Zero(&Result);
    Result.Word[0] = 1;

    // Square-and-multiply from LSB to MSB
    for (i = 0; i < 256; i++) {
        Bit = Exp.Word[i / 32] & (1U << (i % 32));
        if (Bit) {
            Bn256ModMulGeneric(&Result, &Result, &Base, M);
        }
        Bn256ModMulGeneric(&Base, &Base, &Base, M);
    }

    Bn256Copy(R, &Result);
}

//
// R = A^(-1) mod M using Fermat's little theorem: a^(-1) = a^(M-2) mod M
// Only works when M is prime (which is true for P-256 prime and order)
//
STATIC
BOOLEAN
Bn256ModInv (
    OUT BN256        *R,
    IN  CONST BN256  *A,
    IN  CONST BN256  *M
)
{
    BN256  Exp;
    BN256  Two;

    if (Bn256IsZero(A)) {
        return FALSE;
    }

    // Exp = M - 2
    Bn256Zero(&Two);
    Two.Word[0] = 2;
    Bn256Sub(&Exp, M, &Two);

    // R = A^(M-2) mod M
    Bn256ModExp(R, A, &Exp, M);

    return TRUE;
}

//
// Load big-endian bytes into BN256
//
STATIC
VOID
Bn256FromBytes (
    OUT BN256        *R,
    IN  CONST UINT8  *Bytes
)
{
    INTN  i, j;

    for (i = 0; i < 8; i++) {
        j = (7 - i) * 4;
        R->Word[i] = ((UINT32)Bytes[j] << 24) |
            ((UINT32)Bytes[j + 1] << 16) |
            ((UINT32)Bytes[j + 2] << 8) |
            ((UINT32)Bytes[j + 3]);
    }
}

//
// Store BN256 to big-endian bytes
//
STATIC
VOID
Bn256ToBytes (
    IN  CONST BN256  *A,
    OUT UINT8        *Bytes
)
{
    INTN  i, j;

    for (i = 0; i < 8; i++) {
        j = (7 - i) * 4;
        Bytes[j]     = (UINT8)(A->Word[i] >> 24);
        Bytes[j + 1] = (UINT8)(A->Word[i] >> 16);
        Bytes[j + 2] = (UINT8)(A->Word[i] >> 8);
        Bytes[j + 3] = (UINT8)(A->Word[i]);
    }
}

//---------------------------------------------------------------------------
// Debug helper - must be defined before use
//---------------------------------------------------------------------------

#ifdef EC_DEBUG
STATIC
VOID
PrintBn256 (
    IN CONST CHAR16  *Name,
    IN CONST BN256   *N
)
{
    // Use explicit casting to avoid 64-bit variadic promotion issues
    OUT_PRINT(L"%s: %08x%08x%08x%08x%08x%08x%08x%08x\n",
        Name,
        (unsigned int)N->Word[7], (unsigned int)N->Word[6],
        (unsigned int)N->Word[5], (unsigned int)N->Word[4],
        (unsigned int)N->Word[3], (unsigned int)N->Word[2],
        (unsigned int)N->Word[1], (unsigned int)N->Word[0]);
}
#endif

//---------------------------------------------------------------------------
// Elliptic Curve Point Operations for P-256
//---------------------------------------------------------------------------

//
// Point in Jacobian coordinates (X, Y, Z)
// Affine (x, y) = (X/Z^2, Y/Z^3)
// Point at infinity: Z = 0
//
typedef struct {
    BN256  X;
    BN256  Y;
    BN256  Z;
} P256_POINT;

STATIC
VOID
P256PointZero (
    OUT P256_POINT  *P
)
{
    Bn256Zero(&P->X);
    Bn256Zero(&P->Y);
    Bn256Zero(&P->Z);
}

STATIC
BOOLEAN
P256PointIsInfinity (
    IN CONST P256_POINT  *P
)
{
    return Bn256IsZero(&P->Z);
}

STATIC
VOID
P256PointCopy (
    OUT P256_POINT        *R,
    IN  CONST P256_POINT  *P
)
{
    Bn256Copy(&R->X, &P->X);
    Bn256Copy(&R->Y, &P->Y);
    Bn256Copy(&R->Z, &P->Z);
}

//
// Convert affine (x, y) to Jacobian (X, Y, 1)
//
STATIC
VOID
P256PointFromAffine (
    OUT P256_POINT     *P,
    IN  CONST BN256  *X,
    IN  CONST BN256  *Y
)
{
    Bn256Copy(&P->X, X);
    Bn256Copy(&P->Y, Y);
    Bn256Zero(&P->Z);
    P->Z.Word[0] = 1;
}

//
// Point doubling in Jacobian coordinates
// R = 2*P
// Using formulas from "Guide to Elliptic Curve Cryptography"
//
#ifdef EC_DEBUG
STATIC BOOLEAN gPointDoubleDebug = FALSE;
#endif

STATIC
VOID
P256PointDouble (
    OUT P256_POINT        *R,
    IN  CONST P256_POINT  *P
)
{
    BN256  S, M, X3, Y3, Z3;
    BN256  Tmp1, Tmp2, Y2, Y4;

    if (P256PointIsInfinity(P)) {
        P256PointZero(R);
        return;
    }

    // Y^2 (used multiple times)
    Bn256ModMulGeneric(&Y2, &P->Y, &P->Y, &gP256Prime);

#ifdef EC_DEBUG
    if (gPointDoubleDebug) {
        DebugLogPrint("PointDouble intermediates:\r\n");
        DebugLogBn256("  Y^2", &Y2);
    }
#endif

    // S = 4 * X * Y^2
    Bn256ModMulGeneric(&S, &P->X, &Y2, &gP256Prime);       // X * Y^2
    Bn256ModAddP(&S, &S, &S);                               // 2 * X * Y^2
    Bn256ModAddP(&S, &S, &S);                               // 4 * X * Y^2

#ifdef EC_DEBUG
    if (gPointDoubleDebug) {
        DebugLogBn256("  S=4XY^2", &S);
    }
#endif

    // M = 3 * X^2 + a * Z^4  (a = -3 for P-256)
    Bn256ModMulGeneric(&Tmp1, &P->X, &P->X, &gP256Prime);  // X^2

#ifdef EC_DEBUG
    if (gPointDoubleDebug) {
        DebugLogBn256("  X^2", &Tmp1);
    }
#endif

    Bn256ModAddP(&M, &Tmp1, &Tmp1);                         // 2 * X^2
    Bn256ModAddP(&M, &M, &Tmp1);                            // 3 * X^2

#ifdef EC_DEBUG
    if (gPointDoubleDebug) {
        DebugLogBn256("  3X^2", &M);
    }
#endif

    Bn256ModMulGeneric(&Tmp1, &P->Z, &P->Z, &gP256Prime);  // Z^2
    Bn256ModMulGeneric(&Tmp2, &Tmp1, &Tmp1, &gP256Prime);  // Z^4

#ifdef EC_DEBUG
    if (gPointDoubleDebug) {
        DebugLogBn256("  Z^4", &Tmp2);
    }
#endif

    Bn256ModAddP(&Tmp1, &Tmp2, &Tmp2);                      // 2 * Z^4
    Bn256ModAddP(&Tmp1, &Tmp1, &Tmp2);                      // 3 * Z^4

#ifdef EC_DEBUG
    if (gPointDoubleDebug) {
        DebugLogBn256("  3Z^4", &Tmp1);
    }
#endif

    Bn256ModSubP(&M, &M, &Tmp1);                            // 3*X^2 - 3*Z^4

#ifdef EC_DEBUG
    if (gPointDoubleDebug) {
        DebugLogBn256("  M=3X^2-3Z^4", &M);
    }
#endif

    // X3 = M^2 - 2*S
    Bn256ModMulGeneric(&X3, &M, &M, &gP256Prime);          // M^2
    Bn256ModSubP(&X3, &X3, &S);                             // M^2 - S
    Bn256ModSubP(&X3, &X3, &S);                             // M^2 - 2*S

#ifdef EC_DEBUG
    if (gPointDoubleDebug) {
        DebugLogBn256("  X3=M^2-2S", &X3);
    }
#endif

    // Y3 = M * (S - X3) - 8 * Y^4
    Bn256ModSubP(&Tmp1, &S, &X3);                           // S - X3
    Bn256ModMulGeneric(&Y3, &M, &Tmp1, &gP256Prime);       // M * (S - X3)

    // Y^4 = (Y^2)^2
    Bn256ModMulGeneric(&Y4, &Y2, &Y2, &gP256Prime);        // Y^4

#ifdef EC_DEBUG
    if (gPointDoubleDebug) {
        DebugLogBn256("  Y^4", &Y4);
    }
#endif

    Bn256ModAddP(&Tmp1, &Y4, &Y4);                          // 2 * Y^4
    Bn256ModAddP(&Tmp1, &Tmp1, &Tmp1);                      // 4 * Y^4
    Bn256ModAddP(&Tmp1, &Tmp1, &Tmp1);                      // 8 * Y^4

#ifdef EC_DEBUG
    if (gPointDoubleDebug) {
        DebugLogBn256("  8Y^4", &Tmp1);
    }
#endif

    Bn256ModSubP(&Y3, &Y3, &Tmp1);                          // M*(S-X3) - 8*Y^4

#ifdef EC_DEBUG
    if (gPointDoubleDebug) {
        DebugLogBn256("  Y3", &Y3);
    }
#endif

    // Z3 = 2 * Y * Z
    Bn256ModMulGeneric(&Z3, &P->Y, &P->Z, &gP256Prime);    // Y * Z
    Bn256ModAddP(&Z3, &Z3, &Z3);                            // 2 * Y * Z

#ifdef EC_DEBUG
    if (gPointDoubleDebug) {
        DebugLogBn256("  Z3=2YZ", &Z3);
    }
#endif

    Bn256Copy(&R->X, &X3);
    Bn256Copy(&R->Y, &Y3);
    Bn256Copy(&R->Z, &Z3);
}

//
// Point addition in Jacobian coordinates
// R = P + Q
//
STATIC
VOID
P256PointAdd (
    OUT P256_POINT        *R,
    IN  CONST P256_POINT  *P,
    IN  CONST P256_POINT  *Q
)
{
    BN256  U1, U2, S1, S2, H, HH, HHH, rr, V;
    BN256  X3, Y3, Z3, Tmp1, Tmp2;

    if (P256PointIsInfinity(P)) {
        P256PointCopy(R, Q);
        return;
    }
    if (P256PointIsInfinity(Q)) {
        P256PointCopy(R, P);
        return;
    }

    // U1 = X1 * Z2^2
    Bn256ModMulGeneric(&Tmp1, &Q->Z, &Q->Z, &gP256Prime);  // Z2^2
    Bn256ModMulGeneric(&U1, &P->X, &Tmp1, &gP256Prime);    // X1 * Z2^2

    // U2 = X2 * Z1^2
    Bn256ModMulGeneric(&Tmp2, &P->Z, &P->Z, &gP256Prime);  // Z1^2
    Bn256ModMulGeneric(&U2, &Q->X, &Tmp2, &gP256Prime);    // X2 * Z1^2

    // S1 = Y1 * Z2^3
    Bn256ModMulGeneric(&Tmp1, &Tmp1, &Q->Z, &gP256Prime);  // Z2^3
    Bn256ModMulGeneric(&S1, &P->Y, &Tmp1, &gP256Prime);    // Y1 * Z2^3

    // S2 = Y2 * Z1^3
    Bn256ModMulGeneric(&Tmp2, &Tmp2, &P->Z, &gP256Prime);  // Z1^3
    Bn256ModMulGeneric(&S2, &Q->Y, &Tmp2, &gP256Prime);    // Y2 * Z1^3

    // H = U2 - U1
    Bn256ModSubP(&H, &U2, &U1);

    // If H == 0, points have same x-coordinate
    if (Bn256IsZero(&H)) {
        // r = S2 - S1
        Bn256ModSubP(&rr, &S2, &S1);
        if (Bn256IsZero(&rr)) {
            // P == Q, do point doubling
            P256PointDouble(R, P);
            return;
        } else {
            // P == -Q, result is infinity
            P256PointZero(R);
            return;
        }
    }

    // r = S2 - S1
    Bn256ModSubP(&rr, &S2, &S1);

    // HH = H^2
    Bn256ModMulGeneric(&HH, &H, &H, &gP256Prime);

    // HHH = H^3
    Bn256ModMulGeneric(&HHH, &HH, &H, &gP256Prime);

    // V = U1 * HH
    Bn256ModMulGeneric(&V, &U1, &HH, &gP256Prime);

    // X3 = r^2 - HHH - 2*V
    Bn256ModMulGeneric(&X3, &rr, &rr, &gP256Prime);        // r^2
    Bn256ModSubP(&X3, &X3, &HHH);                           // r^2 - HHH
    Bn256ModSubP(&X3, &X3, &V);                             // r^2 - HHH - V
    Bn256ModSubP(&X3, &X3, &V);                             // r^2 - HHH - 2*V

    // Y3 = r * (V - X3) - S1 * HHH
    Bn256ModSubP(&Tmp1, &V, &X3);                           // V - X3
    Bn256ModMulGeneric(&Y3, &rr, &Tmp1, &gP256Prime);      // r * (V - X3)
    Bn256ModMulGeneric(&Tmp1, &S1, &HHH, &gP256Prime);     // S1 * HHH
    Bn256ModSubP(&Y3, &Y3, &Tmp1);                          // r*(V-X3) - S1*HHH

    // Z3 = Z1 * Z2 * H
    Bn256ModMulGeneric(&Z3, &P->Z, &Q->Z, &gP256Prime);    // Z1 * Z2
    Bn256ModMulGeneric(&Z3, &Z3, &H, &gP256Prime);         // Z1 * Z2 * H

    Bn256Copy(&R->X, &X3);
    Bn256Copy(&R->Y, &Y3);
    Bn256Copy(&R->Z, &Z3);
}

//
// Scalar multiplication using double-and-add
// R = k * P
//
STATIC
VOID
P256PointMul (
    OUT P256_POINT        *R,
    IN  CONST BN256     *K,
    IN  CONST P256_POINT  *P
)
{
    P256_POINT  Tmp, Acc;
    INTN      i, j;
    UINT32    Bit;

    P256PointZero(&Acc);  // Start with point at infinity
    P256PointCopy(&Tmp, P);

    // Double-and-add from LSB to MSB
    for (i = 0; i < 8; i++) {
        for (j = 0; j < 32; j++) {
            Bit = (K->Word[i] >> j) & 1;
            if (Bit) {
                P256PointAdd(&Acc, &Acc, &Tmp);
            }
            P256PointDouble(&Tmp, &Tmp);
        }
    }

    P256PointCopy(R, &Acc);
}

//
// Convert Jacobian to Affine coordinates
// x = X / Z^2, y = Y / Z^3
//
STATIC
BOOLEAN
P256PointToAffine (
    OUT BN256           *X,
    OUT BN256           *Y,
    IN  CONST P256_POINT  *P
)
{
    BN256  ZInv, ZInv2, ZInv3;

    if (P256PointIsInfinity(P)) {
        return FALSE;
    }

    // ZInv = Z^(-1) mod p
    if (!Bn256ModInv(&ZInv, &P->Z, &gP256Prime)) {
        return FALSE;
    }

    // ZInv2 = ZInv^2
    Bn256ModMulGeneric(&ZInv2, &ZInv, &ZInv, &gP256Prime);

    // ZInv3 = ZInv^3
    Bn256ModMulGeneric(&ZInv3, &ZInv2, &ZInv, &gP256Prime);

    // x = X * ZInv2
    Bn256ModMulGeneric(X, &P->X, &ZInv2, &gP256Prime);

    // y = Y * ZInv3
    Bn256ModMulGeneric(Y, &P->Y, &ZInv3, &gP256Prime);

    return TRUE;
}

//
// P-256 curve parameter b for point validation
// b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
//
STATIC CONST BN256 gP256B = {{
        0x27D2604B, 0x3BCE3C3E, 0xCC53B0F6, 0x651D06B0,
        0x769886BC, 0xB3EBBD55, 0xAA3A93E7, 0x5AC635D8
    }};

//
// Verify that point (x, y) is on the P-256 curve: y^2 = x^3 - 3x + b (mod p)
//
STATIC
BOOLEAN
P256PointOnCurve (
    IN CONST BN256  *X,
    IN CONST BN256  *Y
)
{
    BN256  Left, Right, Tmp, Three;

    // Left = y^2 mod p
    Bn256ModMulGeneric(&Left, Y, Y, &gP256Prime);

    // Right = x^3 mod p
    Bn256ModMulGeneric(&Tmp, X, X, &gP256Prime);      // x^2
    Bn256ModMulGeneric(&Right, &Tmp, X, &gP256Prime); // x^3

    // Right = x^3 - 3x mod p
    Bn256Zero(&Three);
    Three.Word[0] = 3;
    Bn256ModMulGeneric(&Tmp, &Three, X, &gP256Prime); // 3x
    Bn256ModSubP(&Right, &Right, &Tmp);               // x^3 - 3x

    // Right = x^3 - 3x + b mod p
    Bn256ModAddP(&Right, &Right, &gP256B);

    // Check if Left == Right
    return (Bn256Cmp(&Left, &Right) == 0);
}

//---------------------------------------------------------------------------
// ECDSA P-256 Signature Verification
//---------------------------------------------------------------------------

EFI_STATUS
VerifyEcdsaSignature (
    IN CONST UINT8  *Hash,
    IN UINTN        HashSize,
    IN CONST UINT8  *Signature,
    IN UINTN        SignatureSize
)
{
    BN256     R, S, Z, SInv, U1, U2;
    BN256     Qx, Qy, ResultX, ResultY;
    P256_POINT  G, Q, P1, P2, Sum;

    if (Hash == NULL || Signature == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    if (HashSize != SHA256_HASH_SIZE || SignatureSize != ECC_P256_SIG_SIZE) {
        ERR_PRINT(L"Verify: Invalid hash/sig size: %d/%d\n", HashSize, SignatureSize);
        return EFI_INVALID_PARAMETER;
    }

    // Parse signature (r, s) - each is 32 bytes big-endian
    Bn256FromBytes(&R, Signature);
    Bn256FromBytes(&S, Signature + 32);

#ifdef EC_DEBUG
    PrintBn256(L"sig.r", &R);
    PrintBn256(L"sig.s", &S);
#endif

    // Check r and s are in range [1, n-1]
    if (Bn256IsZero(&R) || Bn256Cmp(&R, &gP256Order) >= 0) {
        ERR_PRINT(L"Verify: r out of range\n");
        return EFI_SECURITY_VIOLATION;
    }
    if (Bn256IsZero(&S) || Bn256Cmp(&S, &gP256Order) >= 0) {
        ERR_PRINT(L"Verify: s out of range\n");
        return EFI_SECURITY_VIOLATION;
    }

    // Parse hash as integer z
    Bn256FromBytes(&Z, Hash);

#ifdef EC_DEBUG
    PrintBn256(L"hash z", &Z);
#endif

    // Reduce z mod n if needed
    while (Bn256Cmp(&Z, &gP256Order) >= 0) {
        Bn256Sub(&Z, &Z, &gP256Order);
    }

    // Compute s^(-1) mod n
    if (!Bn256ModInv(&SInv, &S, &gP256Order)) {
        ERR_PRINT(L"Verify: Failed to compute s inverse\n");
        return EFI_SECURITY_VIOLATION;
    }

    // u1 = z * s^(-1) mod n
    Bn256ModMulGeneric(&U1, &Z, &SInv, &gP256Order);
    while (Bn256Cmp(&U1, &gP256Order) >= 0) {
        Bn256Sub(&U1, &U1, &gP256Order);
    }

    // u2 = r * s^(-1) mod n
    Bn256ModMulGeneric(&U2, &R, &SInv, &gP256Order);
    while (Bn256Cmp(&U2, &gP256Order) >= 0) {
        Bn256Sub(&U2, &U2, &gP256Order);
    }

    // Set up base point G
    P256PointFromAffine(&G, &gP256Gx, &gP256Gy);

#ifdef EC_DEBUG
    // Verify G is on curve
    if (!P256PointOnCurve(&gP256Gx, &gP256Gy)) {
        ERR_PRINT(L"Verify: Generator G is NOT on curve!\n");
    }
#endif

    // Set up public key Q
    Bn256FromBytes(&Qx, gTrustedPublicKeyX);
    Bn256FromBytes(&Qy, gTrustedPublicKeyY);
    P256PointFromAffine(&Q, &Qx, &Qy);

#ifdef EC_DEBUG
    PrintBn256(L"Qx", &Qx);
    PrintBn256(L"Qy", &Qy);
    // Verify Q is on curve
    if (!P256PointOnCurve(&Qx, &Qy)) {
        ERR_PRINT(L"Verify: Public key Q is NOT on curve!\n");
    } else {
        ERR_PRINT(L"Verify: Public key Q is on curve\n");
    }
    PrintBn256(L"u1", &U1);
    PrintBn256(L"u2", &U2);
#endif

    // P1 = u1 * G
    P256PointMul(&P1, &U1, &G);

    // P2 = u2 * Q
    P256PointMul(&P2, &U2, &Q);

    // Sum = P1 + P2
    P256PointAdd(&Sum, &P1, &P2);

    // Check if result is point at infinity
    if (P256PointIsInfinity(&Sum)) {
        ERR_PRINT(L"Verify: Result is point at infinity\n");
        return EFI_SECURITY_VIOLATION;
    }

    // Convert to affine and get x-coordinate
    if (!P256PointToAffine(&ResultX, &ResultY, &Sum)) {
        ERR_PRINT(L"Verify: Failed to convert to affine\n");
        return EFI_SECURITY_VIOLATION;
    }

#ifdef EC_DEBUG
    PrintBn256(L"result.x", &ResultX);
    PrintBn256(L"sig.r", &R);
#endif

    // Reduce x mod n
    while (Bn256Cmp(&ResultX, &gP256Order) >= 0) {
        Bn256Sub(&ResultX, &ResultX, &gP256Order);
    }

    // Verify: x mod n == r
    if (Bn256Cmp(&ResultX, &R) != 0) {
#ifdef EC_DEBUG
        PrintBn256(L"result.x mod n", &ResultX);
        ERR_PRINT(L"Verify: x mod n != r, verification failed\n");
#endif
        ERR_PRINT(L"Verify: Signature verification failed\n");
        return EFI_SECURITY_VIOLATION;
    }

    return EFI_SUCCESS;
}





#ifdef EC_DEBUG
//
// Self-test: Verify 2*G computation
// 2*G for P-256 is:
// x = 0x7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978
// y = 0x07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1
//
STATIC CONST BN256 g2Gx = {{
        0x47669978, 0xA60B48FC, 0x77F21B35, 0xC08969E2,
        0x04B51AC3, 0x8A523803, 0x8D034F7E, 0x7CF27B18
    }};

STATIC CONST BN256 g2Gy = {{
        0x227873D1, 0x9E04B79D, 0x3CE98229, 0xBA7DADE6,
        0x9F7430DB, 0x293D9AC6, 0xDB8ED040, 0x07775510
    }};

STATIC
BOOLEAN
VerifySelfTest (
    VOID
)
{
    BN256 A, B, R;
    P256_POINT G, TwoG_dbl, TwoG_mul;
    BN256 Rx_dbl, Ry_dbl, Rx_mul, Ry_mul;
    BN256 Two;
    BOOLEAN Result = TRUE;

    DebugLogInit();
    DebugLogPrint("=== ECDSA P-256 Self-Test ===\r\n\r\n");

    // Log constants for verification
    DebugLogPrint("Constants:\r\n");
    DebugLogBn256("P256Prime", &gP256Prime);
    DebugLogBn256("P256Order", &gP256Order);
    DebugLogBn256("P256CarryCorr", &gP256CarryCorrection);
    DebugLogBn256("Gx", &gP256Gx);
    DebugLogBn256("Gy", &gP256Gy);
    DebugLogBn256("Expected2Gx", &g2Gx);
    DebugLogBn256("Expected2Gy", &g2Gy);
    DebugLogPrint("\r\n");

    // First test: verify basic modular multiplication
    DebugLogPrint("Test 1: 2 * 3 mod p\r\n");
    Bn256Zero(&A);
    Bn256Zero(&B);
    A.Word[0] = 2;
    B.Word[0] = 3;
    Bn256ModMulGeneric(&R, &A, &B, &gP256Prime);
    DebugLogBn256("Result", &R);

    if (R.Word[0] != 6 || R.Word[1] != 0 || R.Word[2] != 0 || R.Word[3] != 0 ||
        R.Word[4] != 0 || R.Word[5] != 0 || R.Word[6] != 0 || R.Word[7] != 0) {
        DebugLogPrint("FAILED! Expected 6\r\n\r\n");
        Result = FALSE;
        goto Done;
    }
    DebugLogPrint("PASSED\r\n\r\n");

    // Verify all critical constants word-by-word
    DebugLogPrint("Verifying constants word-by-word:\r\n");

    // P-256 prime p = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    DebugLogPrint("Prime p:\r\n");
    DebugLogPrint("  [7]=%08x [6]=%08x [5]=%08x [4]=%08x\r\n",
        (unsigned int)gP256Prime.Word[7], (unsigned int)gP256Prime.Word[6],
        (unsigned int)gP256Prime.Word[5], (unsigned int)gP256Prime.Word[4]);
    DebugLogPrint("  [3]=%08x [2]=%08x [1]=%08x [0]=%08x\r\n",
        (unsigned int)gP256Prime.Word[3], (unsigned int)gP256Prime.Word[2],
        (unsigned int)gP256Prime.Word[1], (unsigned int)gP256Prime.Word[0]);
    DebugLogPrint("  (expect: FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFF)\r\n");

    // Check if prime is correct
    if (gP256Prime.Word[7] != 0xFFFFFFFF || gP256Prime.Word[6] != 0x00000001 ||
        gP256Prime.Word[5] != 0x00000000 || gP256Prime.Word[4] != 0x00000000 ||
        gP256Prime.Word[3] != 0x00000000 || gP256Prime.Word[2] != 0xFFFFFFFF ||
        gP256Prime.Word[1] != 0xFFFFFFFF || gP256Prime.Word[0] != 0xFFFFFFFF) {
        DebugLogPrint("  ERROR: Prime is WRONG!\r\n");
    } else {
        DebugLogPrint("  Prime is correct.\r\n");
    }

    // b parameter
    DebugLogPrint("Curve b:\r\n");
    DebugLogPrint("  [7]=%08x [6]=%08x [5]=%08x [4]=%08x\r\n",
        (unsigned int)gP256B.Word[7], (unsigned int)gP256B.Word[6],
        (unsigned int)gP256B.Word[5], (unsigned int)gP256B.Word[4]);
    DebugLogPrint("  [3]=%08x [2]=%08x [1]=%08x [0]=%08x\r\n",
        (unsigned int)gP256B.Word[3], (unsigned int)gP256B.Word[2],
        (unsigned int)gP256B.Word[1], (unsigned int)gP256B.Word[0]);
    DebugLogPrint("  (expect: 5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E 27D2604B)\r\n");
    DebugLogPrint("\r\n");

    // Test multiplication identity: Gx * 1 = Gx
    DebugLogPrint("Test 1b: Gx * 1 = Gx\r\n");
    {
        BN256 One, MulResult;
        Bn256Zero(&One);
        One.Word[0] = 1;
        Bn256ModMulGeneric(&MulResult, &gP256Gx, &One, &gP256Prime);
        DebugLogBn256("  Gx", &gP256Gx);
        DebugLogBn256("  Gx*1", &MulResult);
        if (Bn256Cmp(&MulResult, &gP256Gx) != 0) {
            DebugLogPrint("FAILED! Gx * 1 != Gx\r\n\r\n");
            Result = FALSE;
            goto Done;
        }
        DebugLogPrint("PASSED\r\n\r\n");
    }

    // Test: Gy * 2 should equal Gy + Gy
    DebugLogPrint("Test 1c: Gy * 2 = Gy + Gy\r\n");
    {
        BN256 Scalar2, GyTimes2, GyPlusGy;
        Bn256Zero(&Scalar2);
        Scalar2.Word[0] = 2;

        // Compute Gy * 2
        Bn256ModMulGeneric(&GyTimes2, &gP256Gy, &Scalar2, &gP256Prime);
        DebugLogBn256("  Gy*2", &GyTimes2);

        // Compute Gy + Gy
        Bn256ModAddP(&GyPlusGy, &gP256Gy, &gP256Gy);
        DebugLogBn256("  Gy+Gy", &GyPlusGy);

        if (Bn256Cmp(&GyTimes2, &GyPlusGy) != 0) {
            DebugLogPrint("FAILED! Gy * 2 != Gy + Gy\r\n\r\n");
            Result = FALSE;
            goto Done;
        }
        DebugLogPrint("PASSED\r\n\r\n");
    }

    // Test: Gy * 3 should equal Gy + Gy + Gy
    DebugLogPrint("Test 1c2: Gy * 3 = Gy + Gy + Gy\r\n");
    {
        BN256 Scalar3, GyTimes3, GySum3, Tmp;
        Bn256Zero(&Scalar3);
        Scalar3.Word[0] = 3;

        // Compute Gy * 3
        Bn256ModMulGeneric(&GyTimes3, &gP256Gy, &Scalar3, &gP256Prime);
        DebugLogBn256("  Gy*3", &GyTimes3);

        // Compute Gy + Gy + Gy
        Bn256ModAddP(&Tmp, &gP256Gy, &gP256Gy);
        Bn256ModAddP(&GySum3, &Tmp, &gP256Gy);
        DebugLogBn256("  Gy+Gy+Gy", &GySum3);

        if (Bn256Cmp(&GyTimes3, &GySum3) != 0) {
            DebugLogPrint("FAILED! Gy * 3 != Gy + Gy + Gy\r\n\r\n");
            Result = FALSE;
            goto Done;
        }
        DebugLogPrint("PASSED\r\n\r\n");
    }

    // Test: Gy * 9 should equal ((Gy * 2) * 2 * 2) + Gy
    DebugLogPrint("Test 1c3: Gy * 9 = 8*Gy + Gy\r\n");
    {
        BN256 Scalar9, GyTimes9, Gy8, GySum9;
        Bn256Zero(&Scalar9);
        Scalar9.Word[0] = 9;

        // Compute Gy * 9
        Bn256ModMulGeneric(&GyTimes9, &gP256Gy, &Scalar9, &gP256Prime);
        DebugLogBn256("  Gy*9", &GyTimes9);

        // Compute 8*Gy + Gy via repeated doubling
        Bn256Copy(&Gy8, &gP256Gy);
        Bn256ModDouble(&Gy8, &gP256Prime);  // 2*Gy
        Bn256ModDouble(&Gy8, &gP256Prime);  // 4*Gy
        Bn256ModDouble(&Gy8, &gP256Prime);  // 8*Gy
        Bn256ModAddP(&GySum9, &Gy8, &gP256Gy);  // 9*Gy
        DebugLogBn256("  8*Gy+Gy", &GySum9);

        if (Bn256Cmp(&GyTimes9, &GySum9) != 0) {
            DebugLogPrint("FAILED! Gy * 9 != 8*Gy + Gy\r\n\r\n");
            Result = FALSE;
            goto Done;
        }
        DebugLogPrint("PASSED\r\n\r\n");
    }

    // Test: Compare 9*Gy (from multiplication) with intermediate value from Gy*Gy
    // After processing bit 251 in Gy*Gy, Acc should equal 9*Gy
    DebugLogPrint("Test 1d: Verify 9*Gy intermediate\r\n");
    {
        BN256 Scalar9, GyTimes9;
        Bn256Zero(&Scalar9);
        Scalar9.Word[0] = 9;
        Bn256ModMulGeneric(&GyTimes9, &gP256Gy, &Scalar9, &gP256Prime);
        DebugLogBn256("  9*Gy (from mul)", &GyTimes9);
        // Compare with the "After bit 251" value: CEFD59FCEEEE7C760627459E5C8C8EC78A3FCE12C4BC5543296843A9F5B9E19F
        DebugLogPrint("  (After bit 251 was: CEFD59FCEEEE7C760627459E5C8C8EC78A3FCE12C4BC5543296843A9F5B9E19F)\r\n");
        DebugLogPrint("\r\n");
    }

    // Test: Verify squaring using identity (Gx+Gy)� = Gx� + 2�Gx�Gy + Gy�
    DebugLogPrint("Test 1e: Verify (Gx+Gy)^2 = Gx^2 + 2*Gx*Gy + Gy^2\r\n");
    {
        BN256 GxPlusGy, GxPlusGySquared;
        BN256 GxSquared, GySquared, GxTimesGy, TwoGxGy;
        BN256 RHS, Tmp;
        BN256 Scalar2;

        // Left side: (Gx + Gy)�
        Bn256ModAddP(&GxPlusGy, &gP256Gx, &gP256Gy);
        Bn256ModMulGeneric(&GxPlusGySquared, &GxPlusGy, &GxPlusGy, &gP256Prime);
        DebugLogBn256("  (Gx+Gy)^2", &GxPlusGySquared);

        // Right side: Gx� + 2�Gx�Gy + Gy�
        Bn256ModMulGeneric(&GxSquared, &gP256Gx, &gP256Gx, &gP256Prime);
        Bn256ModMulGeneric(&GySquared, &gP256Gy, &gP256Gy, &gP256Prime);
        Bn256ModMulGeneric(&GxTimesGy, &gP256Gx, &gP256Gy, &gP256Prime);

        Bn256Zero(&Scalar2);
        Scalar2.Word[0] = 2;
        Bn256ModMulGeneric(&TwoGxGy, &GxTimesGy, &Scalar2, &gP256Prime);

        Bn256ModAddP(&Tmp, &GxSquared, &TwoGxGy);
        Bn256ModAddP(&RHS, &Tmp, &GySquared);
        DebugLogBn256("  Gx^2+2GxGy+Gy^2", &RHS);

        if (Bn256Cmp(&GxPlusGySquared, &RHS) != 0) {
            DebugLogPrint("MISMATCH! Squaring identity failed\r\n");
            DebugLogBn256("  Gx^2", &GxSquared);
            DebugLogBn256("  Gy^2", &GySquared);
            DebugLogBn256("  Gx*Gy", &GxTimesGy);
            DebugLogBn256("  2*Gx*Gy", &TwoGxGy);
        } else {
            DebugLogPrint("MATCH - identity holds\r\n");
        }
        DebugLogPrint("\r\n");
    }

    // Second test: verify G is on curve
    DebugLogPrint("Test 2: G is on curve\r\n");
    {
        BN256 Left, Right, Tmp, X2, X3, ThreeX;

        // Left = Gy^2 mod p
        Bn256ModMulGeneric(&Left, &gP256Gy, &gP256Gy, &gP256Prime);
        DebugLogBn256("  Gy^2", &Left);
        // Expected Gy^2 mod p (from known-good implementation):
        // 4219F59550C28E968E9D0748930B1B78B4ACDFDC95C0B0B785B7DEDB64292D44
        DebugLogPrint("  (expect 4219F59550C28E968E9D0748930B1B78B4ACDFDC95C0B0B785B7DEDB64292D44)\r\n");

        // X^2
        Bn256ModMulGeneric(&X2, &gP256Gx, &gP256Gx, &gP256Prime);
        DebugLogBn256("  Gx^2", &X2);

        // X^3
        Bn256ModMulGeneric(&X3, &X2, &gP256Gx, &gP256Prime);
        DebugLogBn256("  Gx^3", &X3);

        // 3*X
        BN256 Three;
        Bn256Zero(&Three);
        Three.Word[0] = 3;
        Bn256ModMulGeneric(&ThreeX, &Three, &gP256Gx, &gP256Prime);
        DebugLogBn256("  3*Gx", &ThreeX);

        // X^3 - 3X
        Bn256ModSubP(&Tmp, &X3, &ThreeX);
        DebugLogBn256("  Gx^3-3Gx", &Tmp);

        // X^3 - 3X + b
        Bn256ModAddP(&Right, &Tmp, &gP256B);
        DebugLogBn256("  Gx^3-3Gx+b", &Right);

        DebugLogPrint("  Left == Right? %a\r\n", Bn256Cmp(&Left, &Right) == 0 ? "YES" : "NO");
    }
    if (!P256PointOnCurve(&gP256Gx, &gP256Gy)) {
        DebugLogPrint("FAILED! G is NOT on curve\r\n\r\n");
        Result = FALSE;
        goto Done;
    }
    DebugLogPrint("PASSED\r\n\r\n");

    // Test 2b: verify modular inverse works (5 * 5^(-1) mod p = 1)
    DebugLogPrint("Test 2b: Modular inverse (5 * 5^(-1) mod p = 1)\r\n");
    {
        BN256 Five, FiveInv, Product;
        Bn256Zero(&Five);
        Five.Word[0] = 5;
        if (!Bn256ModInv(&FiveInv, &Five, &gP256Prime)) {
            DebugLogPrint("FAILED! Could not compute inverse\r\n\r\n");
            Result = FALSE;
            goto Done;
        }
        DebugLogBn256("5^(-1) mod p", &FiveInv);
        Bn256ModMulGeneric(&Product, &Five, &FiveInv, &gP256Prime);
        DebugLogBn256("5 * 5^(-1)", &Product);
        if (Product.Word[0] != 1 || Product.Word[1] != 0 || Product.Word[2] != 0 ||
            Product.Word[3] != 0 || Product.Word[4] != 0 || Product.Word[5] != 0 ||
            Product.Word[6] != 0 || Product.Word[7] != 0) {
            DebugLogPrint("FAILED! Product should be 1\r\n\r\n");
            Result = FALSE;
            goto Done;
        }
    }
    DebugLogPrint("PASSED\r\n\r\n");

    // Third test: compute 2*G via point doubling
    DebugLogPrint("Test 3: 2*G via point doubling\r\n");
    P256PointFromAffine(&G, &gP256Gx, &gP256Gy);

    DebugLogPrint("G in Jacobian:\r\n");
    DebugLogBn256("  G.X", &G.X);
    DebugLogBn256("  G.Y", &G.Y);
    DebugLogBn256("  G.Z", &G.Z);

    gPointDoubleDebug = TRUE;
    P256PointDouble(&TwoG_dbl, &G);
    gPointDoubleDebug = FALSE;

    DebugLogPrint("2G in Jacobian:\r\n");
    DebugLogBn256("  2G.X", &TwoG_dbl.X);
    DebugLogBn256("  2G.Y", &TwoG_dbl.Y);
    DebugLogBn256("  2G.Z", &TwoG_dbl.Z);

    if (!P256PointToAffine(&Rx_dbl, &Ry_dbl, &TwoG_dbl)) {
        DebugLogPrint("FAILED! Could not convert to affine\r\n\r\n");
        Result = FALSE;
        goto Done;
    }

    DebugLogPrint("2G in Affine:\r\n");
    DebugLogBn256("  2G.x", &Rx_dbl);
    DebugLogBn256("  2G.y", &Ry_dbl);
    DebugLogBn256("  Exp.x", &g2Gx);
    DebugLogBn256("  Exp.y", &g2Gy);

    if (Bn256Cmp(&Rx_dbl, &g2Gx) != 0) {
        DebugLogPrint("FAILED! x mismatch\r\n\r\n");
        Result = FALSE;
        goto Done;
    }
    if (Bn256Cmp(&Ry_dbl, &g2Gy) != 0) {
        DebugLogPrint("FAILED! y mismatch\r\n\r\n");
        Result = FALSE;
        goto Done;
    }
    DebugLogPrint("PASSED\r\n\r\n");

    // Fourth test: compute 2*G via scalar multiplication
    DebugLogPrint("Test 4: 2*G via scalar multiplication\r\n");
    Bn256Zero(&Two);
    Two.Word[0] = 2;
    DebugLogBn256("Scalar k", &Two);

    P256PointMul(&TwoG_mul, &Two, &G);

    DebugLogPrint("k*G in Jacobian:\r\n");
    DebugLogBn256("  kG.X", &TwoG_mul.X);
    DebugLogBn256("  kG.Y", &TwoG_mul.Y);
    DebugLogBn256("  kG.Z", &TwoG_mul.Z);

    if (!P256PointToAffine(&Rx_mul, &Ry_mul, &TwoG_mul)) {
        DebugLogPrint("FAILED! Could not convert to affine\r\n\r\n");
        Result = FALSE;
        goto Done;
    }

    DebugLogPrint("k*G in Affine:\r\n");
    DebugLogBn256("  kG.x", &Rx_mul);
    DebugLogBn256("  kG.y", &Ry_mul);

    if (Bn256Cmp(&Rx_mul, &g2Gx) != 0) {
        DebugLogPrint("FAILED! x mismatch\r\n\r\n");
        Result = FALSE;
        goto Done;
    }
    if (Bn256Cmp(&Ry_mul, &g2Gy) != 0) {
        DebugLogPrint("FAILED! y mismatch\r\n\r\n");
        Result = FALSE;
        goto Done;
    }
    DebugLogPrint("PASSED\r\n\r\n");

    DebugLogPrint("=== All Self-Tests PASSED ===\r\n");

Done:
    DebugLogUpload();
    DebugLogFree();

    if (Result) {
        ERR_PRINT(L"SelfTest: PASSED\n");
    } else {
        ERR_PRINT(L"SelfTest: FAILED - see verify_debug.log\n");
    }

    return Result;
}
#endif
