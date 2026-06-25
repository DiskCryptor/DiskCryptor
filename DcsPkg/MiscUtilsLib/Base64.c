/** @file
  Base64 Decoding Implementation for DiskCryptor UEFI

  SPDX-License-Identifier: MIT

  Copyright (c) 2026 David Xanatos

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.

**/

#include <Uefi.h>
#include <Library/BaseLib.h>

#include "MiscUtilsLib.h"

//
// Base64 inverse lookup table (for characters '+' through 'z')
// Index = character - 43 ('+' = 43 in ASCII)
//
STATIC CONST INT32 mBase64InverseTable[] = {
    62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
    59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
    6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
    29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
    43, 44, 45, 46, 47, 48, 49, 50, 51
};

/**
  Check if a character is a valid Base64 character.

  @param[in]  Char  The character to check.

  @retval TRUE   Character is valid for Base64.
  @retval FALSE  Character is not valid for Base64.

**/
STATIC
BOOLEAN
IsBase64Char (
    IN CHAR16  Char
    )
{
    if (Char >= L'0' && Char <= L'9') return TRUE;
    if (Char >= L'A' && Char <= L'Z') return TRUE;
    if (Char >= L'a' && Char <= L'z') return TRUE;
    if (Char == L'+' || Char == L'/' || Char == L'=') return TRUE;
    return FALSE;
}

/**
  Calculate the decoded size of a Base64 encoded Unicode string.

  @param[in]  Input  Null-terminated Base64 encoded Unicode string.

  @return  The number of bytes needed to store the decoded data,
           or 0 if Input is NULL.

**/
UINTN
EFIAPI
DcsBase64DecodedSize (
    IN CONST CHAR16  *Input
    )
{
    UINTN  Len;
    UINTN  Size;
    UINTN  i;

    if (Input == NULL) {
        return 0;
    }

    Len = StrLen(Input);
    Size = Len / 4 * 3;

    // Account for padding characters
    for (i = Len; i > 0; i--) {
        if (Input[i - 1] == L'=') {
            Size--;
        } else {
            break;
        }
    }

    return Size;
}

/**
  Decode a Base64 encoded Unicode string to binary data.

  @param[in]   Input       Null-terminated Base64 encoded Unicode string.
  @param[out]  Output      Buffer to receive decoded data.
  @param[in]   OutputSize  Size of the output buffer in bytes.

  @retval TRUE   Decoding successful.
  @retval FALSE  Invalid input, null pointer, or buffer too small.

**/
BOOLEAN
EFIAPI
DcsBase64Decode (
    IN  CONST CHAR16  *Input,
    OUT UINT8         *Output,
    IN  UINTN         OutputSize
    )
{
    UINTN  Len;
    UINTN  i;
    UINTN  j;
    INT32  Value;

    if (Input == NULL || Output == NULL) {
        return FALSE;
    }

    Len = StrLen(Input);

    // Base64 encoded data must be a multiple of 4 characters
    if (Len % 4 != 0) {
        return FALSE;
    }

    // Check if output buffer is large enough
    if (OutputSize < DcsBase64DecodedSize(Input)) {
        return FALSE;
    }

    // Validate all characters
    for (i = 0; i < Len; i++) {
        if (!IsBase64Char(Input[i])) {
            return FALSE;
        }
    }

    // Decode 4 characters at a time into 3 bytes
    for (i = 0, j = 0; i < Len; i += 4, j += 3) {
        Value = mBase64InverseTable[Input[i] - 43];
        Value = (Value << 6) | mBase64InverseTable[Input[i + 1] - 43];
        Value = Input[i + 2] == L'=' ? Value << 6 : (Value << 6) | mBase64InverseTable[Input[i + 2] - 43];
        Value = Input[i + 3] == L'=' ? Value << 6 : (Value << 6) | mBase64InverseTable[Input[i + 3] - 43];

        Output[j] = (UINT8)((Value >> 16) & 0xFF);
        if (Input[i + 2] != L'=') {
            Output[j + 1] = (UINT8)((Value >> 8) & 0xFF);
        }
        if (Input[i + 3] != L'=') {
            Output[j + 2] = (UINT8)(Value & 0xFF);
        }
    }

    return TRUE;
}
