/** @file
  Safe RNG Library for platforms where hardware RNG is not accessible.

  Uses a simple LFSR-based PRNG seeded from performance counter.
  NOT cryptographically secure - for compatibility only.

  Copyright (c) 2024-2026 DiskCryptor Project
  SPDX-License-Identifier: LGPL-3.0
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/RngLib.h>
#include <Library/UefiBootServicesTableLib.h>

STATIC UINT64 gRngState = 0;
STATIC BOOLEAN gRngInitialized = FALSE;

/**
  Initialize PRNG state using available entropy sources.
**/
STATIC
VOID
InitializeRng (
  VOID
  )
{
  EFI_TIME Time;
  UINT64 Counter;
  UINTN StackAddr;

  if (gRngInitialized) {
    return;
  }

  // Use stack address as initial entropy (ASLR provides some randomness)
  StackAddr = (UINTN)&StackAddr;
  gRngState = (UINT64)StackAddr;

  // Mix in monotonic counter if available
  if (gBS != NULL) {
    if (!EFI_ERROR(gBS->GetNextMonotonicCount(&Counter))) {
      gRngState ^= Counter;
      gRngState ^= (Counter << 32);
    }
  }

  // Mix in current time for additional entropy
  if (gST != NULL && gST->RuntimeServices != NULL) {
    if (!EFI_ERROR(gST->RuntimeServices->GetTime(&Time, NULL))) {
      gRngState ^= ((UINT64)Time.Second << 0);
      gRngState ^= ((UINT64)Time.Minute << 8);
      gRngState ^= ((UINT64)Time.Hour << 16);
      gRngState ^= ((UINT64)Time.Day << 24);
      gRngState ^= ((UINT64)Time.Nanosecond << 32);
    }
  }

  // Ensure state is non-zero
  if (gRngState == 0) {
    gRngState = 0x123456789ABCDEF0ULL;
  }

  gRngInitialized = TRUE;
}

/**
  Simple xorshift64 PRNG - fast and reasonable distribution.
**/
STATIC
UINT64
NextRandom64 (
  VOID
  )
{
  InitializeRng();

  // xorshift64
  gRngState ^= gRngState << 13;
  gRngState ^= gRngState >> 7;
  gRngState ^= gRngState << 17;

  return gRngState;
}

/**
  Generates a 16-bit random number.

  @param[out] Rand     Buffer pointer to store the 16-bit random value.

  @retval TRUE         Random number generated successfully.
  @retval FALSE        Failed to generate the random number.
**/
BOOLEAN
EFIAPI
GetRandomNumber16 (
  OUT UINT16  *Rand
  )
{
  if (Rand == NULL) {
    return FALSE;
  }

  *Rand = (UINT16)NextRandom64();
  return TRUE;
}

/**
  Generates a 32-bit random number.

  @param[out] Rand     Buffer pointer to store the 32-bit random value.

  @retval TRUE         Random number generated successfully.
  @retval FALSE        Failed to generate the random number.
**/
BOOLEAN
EFIAPI
GetRandomNumber32 (
  OUT UINT32  *Rand
  )
{
  if (Rand == NULL) {
    return FALSE;
  }

  *Rand = (UINT32)NextRandom64();
  return TRUE;
}

/**
  Generates a 64-bit random number.

  @param[out] Rand     Buffer pointer to store the 64-bit random value.

  @retval TRUE         Random number generated successfully.
  @retval FALSE        Failed to generate the random number.
**/
BOOLEAN
EFIAPI
GetRandomNumber64 (
  OUT UINT64  *Rand
  )
{
  if (Rand == NULL) {
    return FALSE;
  }

  *Rand = NextRandom64();
  return TRUE;
}

/**
  Generates a 128-bit random number.

  @param[out] Rand     Buffer pointer to store the 128-bit random value.

  @retval TRUE         Random number generated successfully.
  @retval FALSE        Failed to generate the random number.
**/
BOOLEAN
EFIAPI
GetRandomNumber128 (
  OUT UINT64  *Rand
  )
{
  if (Rand == NULL) {
    return FALSE;
  }

  Rand[0] = NextRandom64();
  Rand[1] = NextRandom64();
  return TRUE;
}

/**
  Get a GUID identifying the RNG algorithm implementation.

  @param [out] RngGuid  If success, contains the GUID identifying
                        the RNG algorithm implementation.

  @retval EFI_SUCCESS             Success.
  @retval EFI_UNSUPPORTED         Not supported.
  @retval EFI_INVALID_PARAMETER   Invalid parameter.
**/
EFI_STATUS
EFIAPI
GetRngGuid (
  GUID  *RngGuid
  )
{
  // No specific algorithm GUID for PRNG fallback
  return EFI_UNSUPPORTED;
}
