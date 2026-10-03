/** @file
CLI helper functions for DiskCryptor - password entry and prompts using ConsoleLib

Copyright (c) 2026. DiskCryptor, David Xanatos

This program and the accompanying materials are licensed and made available
under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/PrintLib.h>
#include <Library/BaseMemoryLib.h>

#include <Library/CommonLib.h>
#include <Library/ConsoleLib.h>
#include <Library/PasswordLib.h>

// SET_VAR_CHAR and GET_VAR_CHAR macros are defined in PasswordLib.h

//////////////////////////////////////////////////////////////////////////
// Password Entry
//////////////////////////////////////////////////////////////////////////

#define STATUS_LINE_LENGTH 80

STATIC VOID
PrintConsolePwd(
    VOID *asciiLine,
    UINT32 count,
    UINT32 pos,
    UINT8 show,
    BOOLEAN wide
    )
{
    UINTN i;
    INT32 curCol, curRow;

    g_Con->GetCursor(&curCol, &curRow);

    if (count != pos) {
        g_Con->SetCursor(curCol + (INT32)(count - pos), curRow);
    }

    for (i = 0; i < count; i++) {
        g_Con->Print(L"\b");
    }

    if (show) {
        if (wide)
            g_Con->Print(L"%s", asciiLine);
        else
            g_Con->Print(L"%a", asciiLine);
    } else {
        if (gPasswordProgress) {
            for (i = 0; i < count; i++) {
                g_Con->Print(L"*");
            }
        }
    }

    if (count != pos) {
        g_Con->GetCursor(&curCol, &curRow);
        g_Con->SetCursor(curCol - (INT32)(count - pos), curRow);
    }
}

STATIC VOID
PrintStatusLine(
    IN CHAR16 *statusStr,
    IN INT32 statusRow
    )
{
    INT32 curCol, curRow;

    g_Con->GetCursor(&curCol, &curRow);

    // Move to status line
    g_Con->SetCursor(0, statusRow);

    // Print status
    g_Con->Print(L"%s", statusStr);

    // Return to original position
    g_Con->SetCursor(curCol, curRow);
}

/**
  Console password entry with full callback support.
  Uses g_Con abstraction for all console operations.
**/
VOID
DcsAskConsolePwd(
    IN  CONST CHAR8 *Msg,
    OUT UINT32      *Length,
    OUT VOID        *Buffer,
    OUT INT32       *RetCode,
    IN  UINTN       MaxLen,
    IN  UINT8       ShowPassword,
    IN  BOOLEAN     Wide,
    IN  INT32       (*KeyFilter)(IN EFI_INPUT_KEY Key, IN VOID *Param),
    IN  VOID        (*GetStatus)(IN CHAR16 *StatusStr, IN UINTN StatusStrLen, IN VOID *Param),
    IN  VOID        *Param
    )
{
    EFI_INPUT_KEY key;
    UINT32 count = 0;
    UINT32 pos = 0;
    UINTN i;
    UINTN lineMax = MaxLen;
    INT32 statusRow = -1;
    INT32 curCol, curRow;
    CHAR16 statusStr[STATUS_LINE_LENGTH + 1];
    UINT8 show = ShowPassword;

    if (Wide)
        lineMax /= 2;

    if (Msg && *Msg) {
        // Print status line first, then msg on next line
        if (GetStatus) {
            g_Con->Print(L"\n");
            g_Con->GetCursor(&curCol, &curRow);
            statusRow = curRow - 1;
            GetStatus(statusStr, STATUS_LINE_LENGTH, Param);
            PrintStatusLine(statusStr, statusRow);
        }
        g_Con->Print(L"%a", Msg);
    }

    if (*Length > 0) {
        count = *Length;
        if (Wide)
            count /= 2;
        pos = count;

        if (gPasswordProgress) {
            for (i = 0; i < pos; i++) {
                g_Con->Print(L"*");
            }
        }
    } else {
        if ((Buffer != NULL) && (lineMax >= 1))
            SET_VAR_CHAR(Buffer, Wide, 0, '\0');
    }

    g_Con->EnableCursor(TRUE);

    if (gPasswordTimeout) {
        EFI_EVENT InputEvents[2];
        UINTN EventIndex = 0;
        InputEvents[0] = gST->ConIn->WaitForKey;
        gBS->CreateEvent(EVT_TIMER, 0, (EFI_EVENT_NOTIFY)NULL, NULL, &InputEvents[1]);
        gBS->SetTimer(InputEvents[1], TimerRelative, 10000000 * gPasswordTimeout);
        gBS->WaitForEvent(2, InputEvents, &EventIndex);
        gBS->SetTimer(InputEvents[1], TimerCancel, 0);
        gBS->CloseEvent(InputEvents[1]);
        if (EventIndex == 1) {
            *RetCode = AskPwdRetTimeout;
            return;
        }
    }

    do {
        key = g_Con->GetKey();
        // Brief debounce delay (10ms) - don't flush keyboard buffer to avoid losing fast typing
        gBS->Stall(10000);

        if (key.ScanCode == SCAN_ESC) {
            *RetCode = AskPwdRetCancel;
            break;
        }

        *RetCode = KeyFilter ? KeyFilter(key, Param) : AskPwdRetNone;

        if (*RetCode == AskPwdRetShow) {
            show = show ? 0 : 1;
            PrintConsolePwd(Buffer, count, pos, show, Wide);
            continue;
        }

        if (*RetCode == AskPwdRetStatus) {
            if (!GetStatus) continue;
            GetStatus(statusStr, STATUS_LINE_LENGTH, Param);
            if (statusRow > -1) {
                PrintStatusLine(statusStr, statusRow);
            } else {
                ConsoleShowTip(statusStr, 10000000);
            }
            continue;
        }

        if (*RetCode != AskPwdRetNone) {
            break;
        }

        g_Con->GetCursor(&curCol, &curRow);

        if (key.ScanCode == SCAN_RIGHT) {
            if (pos < count) {
                if (!show && gPasswordProgress) {
                    // Hide current char, show next char
                    if (pos < count) {
                        g_Con->Print(L"*");
                    }
                    pos++;
                    if (pos < count) {
                        g_Con->Print(L"%c", GET_VAR_CHAR(Buffer, Wide, pos));
                        g_Con->GetCursor(&curCol, &curRow);
                        g_Con->SetCursor(curCol - 1, curRow);
                    }
                } else {
                    g_Con->SetCursor(curCol + 1, curRow);
                    pos++;
                }
            }
            continue;
        }

        if (key.ScanCode == SCAN_LEFT) {
            if (pos > 0) {
                if (!show && gPasswordProgress) {
                    if (pos < count) {
                        g_Con->Print(L"*");
                        g_Con->GetCursor(&curCol, &curRow);
                        g_Con->SetCursor(curCol - 1, curRow);
                    }
                    g_Con->GetCursor(&curCol, &curRow);
                    g_Con->SetCursor(curCol - 1, curRow);
                    pos--;
                    g_Con->Print(L"%c", GET_VAR_CHAR(Buffer, Wide, pos));
                    g_Con->GetCursor(&curCol, &curRow);
                    g_Con->SetCursor(curCol - 1, curRow);
                } else {
                    g_Con->SetCursor(curCol - 1, curRow);
                    pos--;
                }
            }
            continue;
        }

        if (key.ScanCode == SCAN_END) {
            if (pos < count) {
                if (!show && gPasswordProgress) {
                    g_Con->Print(L"*");
                    g_Con->GetCursor(&curCol, &curRow);
                    g_Con->SetCursor(curCol + (INT32)(count - pos - 1), curRow);
                } else {
                    g_Con->SetCursor(curCol + (INT32)(count - pos), curRow);
                }
                pos = count;
            }
            continue;
        }

        if (key.ScanCode == SCAN_HOME) {
            if (pos > 0) {
                if (!show && gPasswordProgress) {
                    if (pos < count) {
                        g_Con->Print(L"*");
                        g_Con->GetCursor(&curCol, &curRow);
                        g_Con->SetCursor(curCol - 1, curRow);
                    }
                    g_Con->GetCursor(&curCol, &curRow);
                    g_Con->SetCursor(curCol - (INT32)pos, curRow);
                    g_Con->Print(L"%c", GET_VAR_CHAR(Buffer, Wide, 0));
                    g_Con->GetCursor(&curCol, &curRow);
                    g_Con->SetCursor(curCol - 1, curRow);
                } else {
                    g_Con->SetCursor(curCol - (INT32)pos, curRow);
                }
                pos = 0;
            }
            continue;
        }

        if (key.ScanCode == SCAN_DELETE) {
            if (pos < count) {
                for (i = pos; i < count; i++) {
                    SET_VAR_CHAR(Buffer, Wide, i, GET_VAR_CHAR(Buffer, Wide, i + 1));
                }
                count--;

                // Clear last char
                g_Con->GetCursor(&curCol, &curRow);
                g_Con->SetCursor(curCol + (INT32)(count - pos), curRow);
                g_Con->Print(L" \b");
                g_Con->SetCursor(curCol, curRow);

                PrintConsolePwd(Buffer, count, pos, show, Wide);
            }
            continue;
        }

        if (key.ScanCode == SCAN_INSERT) {
            if (pos < count && (pos < lineMax - 1)) {
                count++;
                for (i = count; i >= pos; i--) {
                    SET_VAR_CHAR(Buffer, Wide, i + 1, GET_VAR_CHAR(Buffer, Wide, i));
                }
                SET_VAR_CHAR(Buffer, Wide, pos, ' ');

                PrintConsolePwd(Buffer, count, pos, show, Wide);
            }
            continue;
        }

        if (key.ScanCode == SCAN_UP || key.ScanCode == SCAN_DOWN) {
            continue;
        }

        if (key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
            *RetCode = AskPwdRetLogin;
            break;
        }

        if (key.UnicodeChar == CHAR_BACKSPACE) {
            if (count == 0 || count != pos)
                continue;
            if (gPasswordProgress || show) {
                g_Con->Print(L"\b \b");
            }
            if (Buffer != NULL)
                SET_VAR_CHAR(Buffer, Wide, (pos = --count), '\0');
            continue;
        }

        if (count >= (lineMax - 1) ||
            key.UnicodeChar == CHAR_NULL ||
            key.UnicodeChar == CHAR_TAB ||
            key.UnicodeChar == CHAR_LINEFEED ||
            key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
            continue;
        }

        // Check size of line
        if (pos < lineMax - 1) {
            if (show) {
                g_Con->Print(L"%c", key.UnicodeChar);
            } else if (gPasswordProgress) {
                g_Con->Print(L"*");
            }
            // Save char
            if (Buffer != NULL) {
                SET_VAR_CHAR(Buffer, Wide, pos++, (CHAR8)key.UnicodeChar);
                if (pos > count)
                    SET_VAR_CHAR(Buffer, Wide, (count = pos), '\0');
            }
        }
    } while (key.UnicodeChar != CHAR_CARRIAGE_RETURN);

    // Hide revealed char after exiting loop
    if (!show && gPasswordProgress && pos < count) {
        g_Con->Print(L"*");
        g_Con->GetCursor(&curCol, &curRow);
        g_Con->SetCursor(curCol - 1, curRow);
    }

    if (Length != NULL) {
        *Length = count;
        if (Wide)
            *Length *= 2;
    }

    MEM_BURN(&key, sizeof(key));

    // Set end of line
    if (Buffer != NULL) {
        if (count != pos) {
            g_Con->GetCursor(&curCol, &curRow);
            g_Con->SetCursor(curCol + (INT32)(count - pos), curRow);
        }
        SET_VAR_CHAR(Buffer, Wide, count, '\0');
        if (show) {
            for (i = 0; i < count; i++) {
                g_Con->Print(L"\b \b");
            }
            if (gPasswordProgress) {
                for (i = 0; i < count; i++) {
                    g_Con->Print(L"*");
                }
            }
        }
    }
    g_Con->Print(L"\n");
}

//////////////////////////////////////////////////////////////////////////
// Yes/No Prompt
//////////////////////////////////////////////////////////////////////////

/**
  Ask user a yes/no question and wait for valid input.

  @param[in] Prompt       The prompt to display (should include [y/N] or [Y/n] hint)
  @param[in] DefaultYes   If TRUE, Enter defaults to Yes; if FALSE, Enter defaults to No

  @return TRUE if user answered Yes, FALSE if No or cancelled (ESC)
**/
BOOLEAN
DcsAskYesNo(
    IN CHAR16 *Prompt,
    IN BOOLEAN DefaultYes
    )
{
    EFI_INPUT_KEY key;

    g_Con->Print(L"%s", Prompt);

    for (;;) {
        key = g_Con->GetKey();

        // Yes
        if (key.UnicodeChar == L'y' || key.UnicodeChar == L'Y') {
            g_Con->Print(L"y\n");
            return TRUE;
        }

        // No
        if (key.UnicodeChar == L'n' || key.UnicodeChar == L'N') {
            g_Con->Print(L"n\n");
            return FALSE;
        }

        // Enter - use default
        if (key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
            g_Con->Print(L"%c\n", DefaultYes ? L'y' : L'n');
            return DefaultYes;
        }

        // ESC - cancel (same as No)
        if (key.ScanCode == SCAN_ESC) {
            g_Con->Print(L"\n");
            return FALSE;
        }

        // Invalid key - ignore and wait for valid input
    }
}

//////////////////////////////////////////////////////////////////////////
// Password Entry Wrapper
//////////////////////////////////////////////////////////////////////////

/**
  Password entry using console abstraction.
  Works for both text mode and touch mode through g_Con interface.
**/
VOID
DcsAskPassword(
    IN  CONST CHAR8 *Msg,
    OUT UINT32      *Length,
    OUT VOID        *Buffer,
    OUT INT32       *RetCode,
    IN  UINTN       MaxLen,
    IN  UINT8       ShowPassword,
    IN  BOOLEAN     Wide,
    IN  INT32       (*KeyFilter)(IN EFI_INPUT_KEY Key, IN VOID *Param),
    IN  VOID        (*GetStatus)(IN CHAR16 *StatusStr, IN UINTN StatusStrLen, IN VOID *Param),
    IN  VOID        *Param
    )
{
    // Always use console-based password entry
    // g_Con->GetKey() handles both physical and touch keyboard in touch mode
    DcsAskConsolePwd(Msg, Length, Buffer, RetCode, MaxLen, ShowPassword, Wide,
                     KeyFilter, GetStatus, Param);
}
