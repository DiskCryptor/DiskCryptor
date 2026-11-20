/** @file
Text console implementation - wraps standard UEFI console functions

Copyright (c) 2026. DiskCryptor, David Xanatos

This program and the accompanying materials are licensed and made available
under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>

#include <Library/CommonLib.h>
#include <Library/ConsoleLib.h>

//////////////////////////////////////////////////////////////////////////
// Output Functions
//////////////////////////////////////////////////////////////////////////

/**
  Standard print to console.

  @param[in] Format   Format string with optional arguments.
**/
VOID
TextConsolePrint(
    IN CONST CHAR16 *Format,
    ...
    )
{
    VA_LIST Args;

    VA_START(Args, Format);
    // Use VAttrPrintEx directly to preserve %N, %E, %V, %O color codes
    VAttrPrintEx(-1, -1, Format, Args);
    VA_END(Args);
}

/**
  Print error message in red text.

  @param[in] Format   Format string with optional arguments.
**/
VOID
TextConsolePrintError(
    IN CONST CHAR16 *Format,
    ...
    )
{
    VA_LIST Args;
    CHAR16 Buffer[512];

    // Pre-format the user's message
    VA_START(Args, Format);
    UnicodeVSPrint(Buffer, sizeof(Buffer), Format, Args);
    VA_END(Args);

    // Wrap with %E and %N color codes
    AttrPrintEx(-1, -1, L"%E%s%N", Buffer);
}

/**
  Print warning message in orange/yellow text.

  @param[in] Format   Format string with optional arguments.
**/
VOID
TextConsolePrintWarning(
    IN CONST CHAR16 *Format,
    ...
    )
{
    VA_LIST Args;
    CHAR16 Buffer[512];

    // Pre-format the user's message
    VA_START(Args, Format);
    UnicodeVSPrint(Buffer, sizeof(Buffer), Format, Args);
    VA_END(Args);

    // Wrap with %O and %N color codes
    AttrPrintEx(-1, -1, L"%O%s%N", Buffer);
}

/**
  Print at specific cursor position.

  @param[in] Col      Column position (-1 for current).
  @param[in] Row      Row position (-1 for current).
  @param[in] Format   Format string with optional arguments.
**/
VOID
TextConsolePrintAt(
    IN INT32 Col,
    IN INT32 Row,
    IN CONST CHAR16 *Format,
    ...
    )
{
    VA_LIST Args;

    VA_START(Args, Format);
    // Use VAttrPrintEx directly to preserve %N, %E, %V, %O color codes
    VAttrPrintEx(Col, Row, Format, Args);
    VA_END(Args);
}

//////////////////////////////////////////////////////////////////////////
// Screen Control Functions
//////////////////////////////////////////////////////////////////////////

/**
  Clear the console screen.
**/
VOID
TextConsoleClear(VOID)
{
    if (gST->ConOut != NULL) {
        gST->ConOut->ClearScreen(gST->ConOut);
    }
}

/**
  Set cursor position.

  @param[in] Col    Column position.
  @param[in] Row    Row position.
**/
VOID
TextConsoleSetCursor(
    IN INT32 Col,
    IN INT32 Row
    )
{
    if (gST->ConOut != NULL) {
        gST->ConOut->SetCursorPosition(gST->ConOut, (UINTN)Col, (UINTN)Row);
    }
}

/**
  Enable or disable cursor visibility.

  @param[in] Enable   TRUE to show cursor, FALSE to hide.
**/
VOID
TextConsoleEnableCursor(
    IN BOOLEAN Enable
    )
{
    if (gST->ConOut != NULL) {
        gST->ConOut->EnableCursor(gST->ConOut, Enable);
    }
}

/**
  Get current cursor position.

  @param[out] Col   Current column position.
  @param[out] Row   Current row position.
**/
VOID
TextConsoleGetCursor(
    OUT INT32 *Col,
    OUT INT32 *Row
    )
{
    if (gST->ConOut != NULL && gST->ConOut->Mode != NULL) {
        if (Col != NULL) *Col = (INT32)gST->ConOut->Mode->CursorColumn;
        if (Row != NULL) *Row = (INT32)gST->ConOut->Mode->CursorRow;
    } else {
        if (Col != NULL) *Col = 0;
        if (Row != NULL) *Row = 0;
    }
}

/**
  Get console dimensions.

  @param[out] Cols   Number of columns.
  @param[out] Rows   Number of rows.
**/
VOID
TextConsoleGetSize(
    OUT INT32 *Cols,
    OUT INT32 *Rows
    )
{
    UINTN cols = 80;
    UINTN rows = 25;

    if (gST->ConOut != NULL) {
        gST->ConOut->QueryMode(gST->ConOut, gST->ConOut->Mode->Mode, &cols, &rows);
    }

    if (Cols != NULL) *Cols = (INT32)cols;
    if (Rows != NULL) *Rows = (INT32)rows;
}

//////////////////////////////////////////////////////////////////////////
// Input Functions
//////////////////////////////////////////////////////////////////////////

/**
  Wait for and return a key press.

  @return   The key that was pressed.
**/
EFI_INPUT_KEY
TextConsoleGetKey(VOID)
{
    return GetKey();
}

/**
  Wait for key with timeout and countdown display.

  @param[in] Prompt           Format string for countdown (should contain %d for seconds).
  @param[in] MilliDelay       Delay in milliseconds (actually seconds in current impl).
  @param[in] DefaultScanCode  Default scan code to return on timeout.
  @param[in] DefaultChar      Default unicode char to return on timeout.

  @return   The key that was pressed, or default key on timeout.
**/
EFI_INPUT_KEY
TextConsoleKeyWait(
    IN CHAR16 *Prompt,
    IN UINTN MilliDelay,
    IN UINT16 DefaultScanCode,
    IN UINT16 DefaultChar
    )
{
    return KeyWait(Prompt, MilliDelay, DefaultScanCode, DefaultChar);
}

/**
  Flush input buffer with delay.

  @param[in] DelayUs   Delay in microseconds.
**/
VOID
TextConsoleFlushInput(
    IN UINTN DelayUs
    )
{
    FlushInputDelay(DelayUs);
    KbResetState();   // also a key held after a dead key
}

/**
  Read a line of input from console.

  @param[out] Length      Length of input received.
  @param[out] Line        Wide character buffer for input.
  @param[out] AsciiLine   ASCII character buffer for input (optional).
  @param[in]  MaxLen      Maximum input length.
  @param[in]  ShowChars   TRUE to echo characters, FALSE to show asterisks.

  @retval TRUE   Input was received successfully.
  @retval FALSE  Input was cancelled (ESC pressed).
**/
BOOLEAN
TextConsoleReadLine(
    OUT UINTN *Length,
    OUT CHAR16 *Line,
    OUT CHAR8 *AsciiLine,
    IN UINTN MaxLen,
    IN UINT8 ShowChars
    )
{
    return GetLine(Length, Line, AsciiLine, MaxLen, ShowChars);
}

/**
  Ask a yes/no confirmation question.

  @param[in] Prompt    Prompt string to display.
  @param[in] Visible   TRUE to show input, FALSE to hide.

  @retval 1   User answered yes.
  @retval 0   User answered no.
**/
UINT8
TextConsoleAskYesNo(
    IN CHAR8 *Prompt,
    IN UINT8 Visible
    )
{
    return AskConfirm(Prompt, Visible);
}

