/** @file
  CliUtils - Console/CLI utility functions for DiskCryptor UEFI

  SPDX-License-Identifier: MIT

  Copyright (c) 2024-2026 DiskCryptor contributors

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

#ifndef _CLI_UTILS_H_
#define _CLI_UTILS_H_

#include <Uefi.h>

//////////////////////////////////////////////////////////////////////////
// Console Input
//////////////////////////////////////////////////////////////////////////

/**
  Wait for and return a single key press.

  Blocks until the user presses a key, then returns the key data.

  @return  The EFI_INPUT_KEY that was pressed.

**/
EFI_INPUT_KEY
EFIAPI
UefiGetKey (
    VOID
    );

/**
  Flush pending keyboard input with a configurable delay.

  Creates a timer event and discards any keystrokes that arrive before
  the timer fires. Used to drain buffered input after prompts.

  @param[in]  Delay  Timer period in 100-nanosecond units
                     (e.g., 1000000 = 100ms).

**/
VOID
EFIAPI
UefiFlushInputDelay (
    IN UINTN  Delay
    );

/**
  Flush pending keyboard input using a 100ms delay.

  Convenience wrapper around UefiFlushInputDelay with a 100ms period.

**/
VOID
EFIAPI
UefiFlushInput (
    VOID
    );

/**
  Wait for a key press with a countdown timer.

  Displays a countdown prompt and waits for either a key press or timeout.
  The prompt format string should contain a %d or %2d specifier for the
  remaining seconds. If the countdown expires without a key press, returns
  the specified default key values.

  @param[in]  Prompt       Format string for countdown display
                           (e.g., L"\\rWait %2d seconds...").
  @param[in]  Seconds      Number of seconds to count down.
  @param[in]  DefaultScan  Scan code to return on timeout.
  @param[in]  DefaultChar  Unicode character to return on timeout.

  @return  The key that was pressed, or default values if timeout occurred.

**/
EFI_INPUT_KEY
EFIAPI
UefiKeyWait (
    IN CHAR16  *Prompt,
    IN UINTN   Seconds,
    IN UINT16  DefaultScan,
    IN UINT16  DefaultChar
    );

//////////////////////////////////////////////////////////////////////////
// Console Output
//////////////////////////////////////////////////////////////////////////

/**
  Print a byte buffer in hexadecimal format to the console.

  Outputs each byte as a two-digit hex value with no separators.

  @param[in]  Data  Pointer to the data buffer.
  @param[in]  Size  Number of bytes to print.

**/
VOID
EFIAPI
UefiPrintBytes (
    IN UINT8  *Data,
    IN UINTN  Size
    );

#endif // _CLI_UTILS_H_
