/** @file
Ask password from console

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI
Copyright (c) 2019-2026. DiskCryptor, David Xanatos

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Uefi.h>
#include "Library/CommonLib.h"
#include "Library/PasswordLib.h"
#include <Library/UefiBootServicesTableLib.h>
#include <Library/PrintLib.h>

VOID
PrintConsolePwd(
	VOID *asciiLine, 
	UINT32 count, UINT32 pos, 
	UINT8 show, 
	BOOLEAN  wide
)
{
	UINTN i;

	if(count != pos)
		gST->ConOut->SetCursorPosition(gST->ConOut, gST->ConOut->Mode->CursorColumn + (count - pos), gST->ConOut->Mode->CursorRow);

	for (i = 0; i < count; i++) {
		OUT_PRINT(L"\b");
	}

	if (show) {
		if (wide)
			OUT_PRINT(L"%s", asciiLine);
		else
			OUT_PRINT(L"%a", asciiLine);
	}
	else {
		if (gPasswordProgress) {
			for (i = 0; i < count; i++) {
				OUT_PRINT(L"*");
			}
		}
	}

	if(count != pos)
		gST->ConOut->SetCursorPosition(gST->ConOut, gST->ConOut->Mode->CursorColumn - (count - pos), gST->ConOut->Mode->CursorRow);
}

#define STATUS_LINE_LENGTH 80

static VOID
PrintStatusLine(
	IN CHAR16* statusStr,
	IN INT32 statusRow
)
{
	INT32 curCol = gST->ConOut->Mode->CursorColumn;
	INT32 curRow = gST->ConOut->Mode->CursorRow;

	// Move to status line
	gST->ConOut->SetCursorPosition(gST->ConOut, 0, statusRow);

	// Move to status line
	gST->ConOut->SetCursorPosition(gST->ConOut, 0, statusRow);
	// Print status
	OUT_PRINT(L"%s", statusStr);

	// Return to original position
	gST->ConOut->SetCursorPosition(gST->ConOut, curCol, curRow);
}

VOID
AskConsolePwdEx(
	IN  CONST char* msg,
	OUT UINT32   *length,
	OUT VOID     *asciiLine,
	OUT INT32    *retCode,
	IN  UINTN    length_max,
	IN  UINT8    show,
	IN  BOOLEAN  wide,
	IN  INT32 (*KeyFilter)(IN EFI_INPUT_KEY key, IN VOID *Param),
	IN  VOID (*GetStatus)(IN CHAR16* statusStr, IN UINTN statusStrLen, IN VOID *Param),
	IN  VOID *Param
)
{
	EFI_INPUT_KEY key;
	UINT32 count = 0;
	UINT32 pos = 0;
	UINTN i;
	UINTN line_max = length_max;
	INT32 statusRow = -1;
	CHAR16 statusStr[STATUS_LINE_LENGTH + 1];
	if (wide)
		line_max /= 2;

	if (msg) {
		// Print status line first, then msg on next line
		if (GetStatus) {
			OUT_PRINT(L"\n");
			statusRow = gST->ConOut->Mode->CursorRow - 1;
			GetStatus(statusStr, STATUS_LINE_LENGTH, Param);
			PrintStatusLine(statusStr, statusRow);
		}
		OUT_PRINT(L"%a", msg);
	}


	if (*length > 0)
	{
		count = *length;
		if (wide)
			count /= 2;
		pos = count;

		if (gPasswordProgress) {
			for (i = 0; i < pos; i++) {
				OUT_PRINT(L"*");
			}
		}
	}
	else
	{
		if ((asciiLine != NULL) && (line_max >= 1))
			SET_VAR_CHAR(asciiLine, wide, 0, '\0'); //asciiLine[0] = '\0';
	}

	gST->ConOut->EnableCursor(gST->ConOut, TRUE);
	if (gPasswordTimeout) {
		EFI_EVENT      InputEvents[2];
		UINTN          EventIndex = 0;
		InputEvents[0] = gST->ConIn->WaitForKey;
		gBS->CreateEvent(EVT_TIMER, 0, (EFI_EVENT_NOTIFY)NULL, NULL, &InputEvents[1]);
		gBS->SetTimer(InputEvents[1], TimerRelative, 10000000 * gPasswordTimeout);
		gBS->WaitForEvent(2, InputEvents, &EventIndex);
		gBS->SetTimer(InputEvents[1], TimerCancel, 0);
		gBS->CloseEvent(InputEvents[1]);
		if (EventIndex == 1) {
			*retCode = AskPwdRetTimeout;
			return ;
		}
	}

	do {
		key = GetKey();
		// Remove dirty chars 0.1s
		FlushInputDelay(100000);

		if (key.ScanCode == SCAN_ESC) {
			*retCode = AskPwdRetCancel;
			break;
		}

		*retCode = KeyFilter ? KeyFilter(key, Param) : AskPwdRetNone;

		if (*retCode == AskPwdRetShow) {
			show = show ? 0 : 1;
			PrintConsolePwd(asciiLine, count, pos, show, wide);
			continue;
		}

		if (*retCode == AskPwdRetStatus) {
			if (!GetStatus) continue;
			GetStatus(statusStr, STATUS_LINE_LENGTH, Param);
			if (statusRow > -1) {
				PrintStatusLine(statusStr, statusRow);
			}
			else {
				ConsoleShowTip(statusStr, 10000000);
			}
			continue;
		}

		if (*retCode != AskPwdRetNone) {
			break;
		}

		if (key.ScanCode == SCAN_RIGHT) {
			if (pos < count) {
				if (!show && gPasswordProgress) {
					// Hide current char, show next char
					if (pos < count) {
						OUT_PRINT(L"*");  // Hide current position
					}
					pos++;
					if (pos < count) {
						// Show char at new position, move cursor back onto it
						OUT_PRINT(L"%c", GET_VAR_CHAR(asciiLine, wide, pos));
						gST->ConOut->SetCursorPosition(gST->ConOut, gST->ConOut->Mode->CursorColumn - 1, gST->ConOut->Mode->CursorRow);
					}
				} else {
					gST->ConOut->SetCursorPosition(gST->ConOut, gST->ConOut->Mode->CursorColumn + 1, gST->ConOut->Mode->CursorRow);
					pos++;
				}
			}
			continue;
		}

		if (key.ScanCode == SCAN_LEFT) {
			if (pos > 0) {
				if (!show && gPasswordProgress) {
					// Hide current char (if not at end), show previous char
					if (pos < count) {
						OUT_PRINT(L"*");  // Hide current position
						gST->ConOut->SetCursorPosition(gST->ConOut, gST->ConOut->Mode->CursorColumn - 1, gST->ConOut->Mode->CursorRow);
					}
					gST->ConOut->SetCursorPosition(gST->ConOut, gST->ConOut->Mode->CursorColumn - 1, gST->ConOut->Mode->CursorRow);
					pos--;
					// Show char at new position, move cursor back onto it
					OUT_PRINT(L"%c", GET_VAR_CHAR(asciiLine, wide, pos));
					gST->ConOut->SetCursorPosition(gST->ConOut, gST->ConOut->Mode->CursorColumn - 1, gST->ConOut->Mode->CursorRow);
				} else {
					gST->ConOut->SetCursorPosition(gST->ConOut, gST->ConOut->Mode->CursorColumn - 1, gST->ConOut->Mode->CursorRow);
					pos--;
				}
			}
			continue;
		}

		if (key.ScanCode == SCAN_END) {
			if (pos < count) {
				if (!show && gPasswordProgress) {
					// Hide current char before moving
					OUT_PRINT(L"*");
					gST->ConOut->SetCursorPosition(gST->ConOut, gST->ConOut->Mode->CursorColumn + (count - pos - 1), gST->ConOut->Mode->CursorRow);
				} else {
					gST->ConOut->SetCursorPosition(gST->ConOut, gST->ConOut->Mode->CursorColumn + (count - pos), gST->ConOut->Mode->CursorRow);
				}
				pos = count;
			}
			continue;
		}

		if (key.ScanCode == SCAN_HOME) {
			if (pos > 0) {
				if (!show && gPasswordProgress) {
					// Hide current char before moving (if not at end)
					if (pos < count) {
						OUT_PRINT(L"*");
						gST->ConOut->SetCursorPosition(gST->ConOut, gST->ConOut->Mode->CursorColumn - 1, gST->ConOut->Mode->CursorRow);
					}
					gST->ConOut->SetCursorPosition(gST->ConOut, gST->ConOut->Mode->CursorColumn - pos, gST->ConOut->Mode->CursorRow);
					// Show first char
					OUT_PRINT(L"%c", GET_VAR_CHAR(asciiLine, wide, 0));
					gST->ConOut->SetCursorPosition(gST->ConOut, gST->ConOut->Mode->CursorColumn - 1, gST->ConOut->Mode->CursorRow);
				} else {
					gST->ConOut->SetCursorPosition(gST->ConOut, gST->ConOut->Mode->CursorColumn - pos, gST->ConOut->Mode->CursorRow);
				}
				pos = 0;
			}
			continue;
		}

		if (key.ScanCode == SCAN_DELETE) {
			if (pos < count) {
				for (i = pos; i < count; i++) {
					SET_VAR_CHAR(asciiLine, wide, i, GET_VAR_CHAR(asciiLine, wide, i+1));
				}
				count--;

				// clear last char
				gST->ConOut->SetCursorPosition(gST->ConOut, gST->ConOut->Mode->CursorColumn + (count - pos), gST->ConOut->Mode->CursorRow); // go to end
				OUT_PRINT(L" \b");
				gST->ConOut->SetCursorPosition(gST->ConOut, gST->ConOut->Mode->CursorColumn - (count - pos), gST->ConOut->Mode->CursorRow); // go back to pos

				PrintConsolePwd(asciiLine, count, pos, show, wide);
			}
			continue;
		}

		if (key.ScanCode == SCAN_INSERT) {
			if (pos < count && (pos < line_max - 1)) {
				count++;
				for (i = count; i >= pos; i--) {
					SET_VAR_CHAR(asciiLine, wide, i+1, GET_VAR_CHAR(asciiLine, wide, i));
				}
				SET_VAR_CHAR(asciiLine, wide, pos, ' '); // set inserted char value

				PrintConsolePwd(asciiLine, count, pos, show, wide);
			}
			continue;
		}

		if (key.ScanCode == SCAN_UP) {
			continue;
		}

		if (key.ScanCode == SCAN_DOWN) {
			continue;
		}

		if (key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
			*retCode = AskPwdRetLogin;
			break;
		}

		if (key.UnicodeChar == CHAR_BACKSPACE) {
			if (count == 0 || count != pos)
				continue;
			if (gPasswordProgress || show) {
				OUT_PRINT(L"\b \b");
			}
			if (asciiLine != NULL) 
				SET_VAR_CHAR(asciiLine, wide, (pos = --count), '\0'); //asciiLine[--count] = '\0';
			continue;
		}

		if (count >= (line_max - 1) ||
			key.UnicodeChar == CHAR_NULL ||
			key.UnicodeChar == CHAR_TAB ||
			key.UnicodeChar == CHAR_LINEFEED ||
			key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
			continue;
		}

		// check size of line
		if (pos < line_max - 1) {
			if (show) {
				OUT_PRINT(L"%c", key.UnicodeChar);
			} else if (gPasswordProgress) {
				OUT_PRINT(L"*");
			}
			// save char
			if (asciiLine != NULL) {
				SET_VAR_CHAR(asciiLine, wide, pos++, (CHAR8)key.UnicodeChar); //asciiLine[count++] = (CHAR8)key.UnicodeChar;
				if(pos > count)
					SET_VAR_CHAR(asciiLine, wide, (count = pos), '\0'); //asciiLine[count] = 0;
			}
		}
	} while (key.UnicodeChar != CHAR_CARRIAGE_RETURN);

	// Hide revealed char after exiting loop
	if (!show && gPasswordProgress && pos < count) {
		OUT_PRINT(L"*");
		gST->ConOut->SetCursorPosition(gST->ConOut, gST->ConOut->Mode->CursorColumn - 1, gST->ConOut->Mode->CursorRow);
	}

	if (length != NULL) {
		*length = count;
		if (wide)
			*length *= 2;
	}
	MEM_BURN (&key, sizeof (key));
	// Set end of line
	if (asciiLine != NULL) {
		if(count != pos)
			gST->ConOut->SetCursorPosition(gST->ConOut, gST->ConOut->Mode->CursorColumn + (count - pos), gST->ConOut->Mode->CursorRow);
		SET_VAR_CHAR(asciiLine, wide, count, '\0'); //asciiLine[count] = '\0';
		if (show) {
			for (i = 0; i < count; i++) {
				OUT_PRINT(L"\b \b");
			}
			//OUT_PRINT(L"*");
			if (gPasswordProgress) {
				for (i = 0; i < count; i++) {
					OUT_PRINT(L"*");
				}
			}
		}
	}
	OUT_PRINT(L"\n");
}

static INT32
HandleFuncKeys(
	IN EFI_INPUT_KEY key,
	IN VOID *Param
)
{
	// SCAN_F1

	if (key.ScanCode == SCAN_F2) {
		return AskPwdRetChange;
	}

	// SCAN_F3

	// SCAN_F4

	if (key.ScanCode == SCAN_F5) {
		return AskPwdRetShow;
	}

	// SCAN_F6

	if (key.ScanCode == SCAN_F7) {
		gPlatformLocked = gPlatformLocked ? 0 : 1;
		return AskPwdRetStatus;
	}

	if (key.ScanCode == SCAN_F8) {
		gTPMLocked = gTPMLocked ? 0 : 1;
		return AskPwdRetStatus;
	}

	if (key.ScanCode == SCAN_F9) {
		gSCLocked = gSCLocked ? 0 : 1;
		return AskPwdRetStatus;
	}

	// SCAN_F10

	// SCAN_F11
	
	// SCAN_F12

	if (key.UnicodeChar == CHAR_TAB) {
		
	}

	return AskPwdRetNone;
}

static VOID
FormatStatus(
	IN CHAR16* statusStr,
	IN UINTN statusStrLen,
	IN VOID *Param
)
{
	UnicodeSPrint(statusStr, statusStrLen * 2, L"          [F7] Platform: %s  [F8] TPM: %s  [F9] SC: %s",
		gPlatformLocked ? L"Yes" : L"No ",
		gTPMLocked ? L"Yes" : L"No ",
		gSCLocked ? L"Yes" : L"No ");
}

VOID
AskConsolePwdInt(
	IN  CONST char*msg,
	OUT UINT32   *length,
	OUT VOID     *asciiLine,
	OUT INT32    *retCode,
	IN  UINTN    length_max,
	IN  UINT8    show,
	IN  BOOLEAN  wide
)
{
	AskConsolePwdEx(msg, length, asciiLine, retCode, length_max, show, wide, HandleFuncKeys, FormatStatus, NULL);
}