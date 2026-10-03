/** @file
EFI Variable Management for DiskCryptor

Provides interactive UI for listing, dumping, overwriting, creating,
and hex-editing UEFI variables.

Copyright (c) 2026. DiskCryptor, David Xanatos

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Uefi.h>
#include "DcsDiskCryptor.h"
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Guid/GlobalVariable.h>
#include <Library/CommonLib.h>
#include <Library/ConsoleLib.h>
#include <Library/BaseLib.h>
#include <DcsConfig.h>
#include "../Library/MiscUtilsLib/MiscUtilsLib.h"
#include "../Library/MiscUtilsLib/FsUtils.h"

#define VAR_DUMP_DIR       L"\\EFI\\"  DCS_DIRECTORY  "\\vars\\"
#define VAR_MAX_COLLECT    512
#define VAR_NAME_MAX       256
#define VAR_GUID_STR_SIZE  40
#define HEX_BYTES_PER_LINE 16
#define HEX_EDITOR_MAX     (256 * 1024)

//////////////////////////////////////////////////////////////////////////
// Variable Entry
//////////////////////////////////////////////////////////////////////////

typedef struct {
	CHAR16     Name[VAR_NAME_MAX];
	EFI_GUID   Guid;
	UINT32     Attributes;
	UINTN      DataSize;
} EFI_VAR_ENTRY;

//////////////////////////////////////////////////////////////////////////
// Attribute Abbreviation
//////////////////////////////////////////////////////////////////////////

STATIC
VOID
VarFormatAttributes(
	IN  UINT32  Attr,
	OUT CHAR16  *Buf,
	IN  UINTN   BufSize
)
{
	Buf[0] = L'\0';

	if (Attr & EFI_VARIABLE_NON_VOLATILE)
		StrCatS(Buf, BufSize, L"NV ");
	if (Attr & EFI_VARIABLE_BOOTSERVICE_ACCESS)
		StrCatS(Buf, BufSize, L"BS ");
	if (Attr & EFI_VARIABLE_RUNTIME_ACCESS)
		StrCatS(Buf, BufSize, L"RT ");
	if (Attr & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)
		StrCatS(Buf, BufSize, L"TB ");
	if (Attr & EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS)
		StrCatS(Buf, BufSize, L"AW ");
	if (Attr & EFI_VARIABLE_APPEND_WRITE)
		StrCatS(Buf, BufSize, L"AP ");
	if (Attr & EFI_VARIABLE_HARDWARE_ERROR_RECORD)
		StrCatS(Buf, BufSize, L"HR ");

	// Trim trailing space
	UINTN len = StrLen(Buf);
	if (len > 0 && Buf[len - 1] == L' ')
		Buf[len - 1] = L'\0';
}

//////////////////////////////////////////////////////////////////////////
// GUID Formatting
//////////////////////////////////////////////////////////////////////////

STATIC
VOID
VarFormatGuid(
	IN  EFI_GUID  *Guid,
	OUT CHAR16    *Buf,
	IN  UINTN     BufSize
)
{
	UnicodeSPrint(Buf, BufSize * sizeof(CHAR16),
		L"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		Guid->Data1, Guid->Data2, Guid->Data3,
		Guid->Data4[0], Guid->Data4[1],
		Guid->Data4[2], Guid->Data4[3],
		Guid->Data4[4], Guid->Data4[5],
		Guid->Data4[6], Guid->Data4[7]);
}

//////////////////////////////////////////////////////////////////////////
// File path construction
//////////////////////////////////////////////////////////////////////////

STATIC
VOID
VarBuildFilePath(
	IN  CHAR16  *VarName,
	OUT CHAR16  *PathBuf,
	IN  UINTN   PathBufSize
)
{
	UnicodeSPrint(PathBuf, PathBufSize * sizeof(CHAR16),
		L"%s%s.bin", VAR_DUMP_DIR, VarName);
}

//////////////////////////////////////////////////////////////////////////
// Collect all EFI variables
//////////////////////////////////////////////////////////////////////////

STATIC
EFI_STATUS
VarCollectAll(
	OUT EFI_VAR_ENTRY  **Entries,
	OUT UINTN          *Count
)
{
	EFI_STATUS    status;
	UINTN         nameSize;
	CHAR16        name[VAR_NAME_MAX];
	EFI_GUID      guid;
	EFI_VAR_ENTRY *list;
	UINTN         count = 0;
	UINTN         capacity = 128;

	list = MEM_ALLOC(capacity * sizeof(EFI_VAR_ENTRY));
	if (list == NULL)
		return EFI_OUT_OF_RESOURCES;

	name[0] = L'\0';
	ZeroMem(&guid, sizeof(guid));

	for (;;) {
		nameSize = VAR_NAME_MAX * sizeof(CHAR16);
		status = gST->RuntimeServices->GetNextVariableName(&nameSize, name, &guid);

		if (status == EFI_NOT_FOUND)
			break;
		if (EFI_ERROR(status)) {
			MEM_FREE(list);
			return status;
		}

		// Grow array if needed
		if (count >= capacity) {
			UINTN newCap = capacity * 2;
			EFI_VAR_ENTRY *newList = MEM_ALLOC(newCap * sizeof(EFI_VAR_ENTRY));
			if (newList == NULL) {
				MEM_FREE(list);
				return EFI_OUT_OF_RESOURCES;
			}
			CopyMem(newList, list, count * sizeof(EFI_VAR_ENTRY));
			MEM_FREE(list);
			list = newList;
			capacity = newCap;
		}

		// Store entry
		StrnCpyS(list[count].Name, VAR_NAME_MAX, name, VAR_NAME_MAX - 1);
		CopyMem(&list[count].Guid, &guid, sizeof(EFI_GUID));

		// Get attributes and size - must do a real read for attributes
		{
			UINTN dataSize = 0;
			UINT32 attrs = 0;
			UINT8  *tmpBuf;

			status = gST->RuntimeServices->GetVariable(
				name, &guid, &attrs, &dataSize, NULL);
			if (status == EFI_BUFFER_TOO_SMALL && dataSize > 0) {
				tmpBuf = MEM_ALLOC(dataSize);
				if (tmpBuf != NULL) {
					status = gST->RuntimeServices->GetVariable(
						name, &guid, &attrs, &dataSize, tmpBuf);
					MEM_FREE(tmpBuf);
				}
			}
			if (!EFI_ERROR(status) || status == EFI_BUFFER_TOO_SMALL) {
				list[count].Attributes = attrs;
				list[count].DataSize = dataSize;
			} else {
				list[count].Attributes = 0;
				list[count].DataSize = 0;
			}
		}

		count++;
	}

	*Entries = list;
	*Count = count;
	return EFI_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
// Read variable data
//////////////////////////////////////////////////////////////////////////

STATIC
EFI_STATUS
VarReadData(
	IN  CHAR16    *Name,
	IN  EFI_GUID  *Guid,
	OUT UINT32    *Attributes,
	OUT UINT8     **Data,
	OUT UINTN     *DataSize
)
{
	EFI_STATUS status;
	UINTN      size = 0;
	UINT32     attrs = 0;
	UINT8      *buf;

	status = gST->RuntimeServices->GetVariable(Name, Guid, &attrs, &size, NULL);
	if (status != EFI_BUFFER_TOO_SMALL)
		return (EFI_ERROR(status)) ? status : EFI_NOT_FOUND;

	buf = MEM_ALLOC(size);
	if (buf == NULL)
		return EFI_OUT_OF_RESOURCES;

	status = gST->RuntimeServices->GetVariable(Name, Guid, &attrs, &size, buf);
	if (EFI_ERROR(status)) {
		MEM_FREE(buf);
		return status;
	}

	*Attributes = attrs;
	*Data = buf;
	*DataSize = size;
	return EFI_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
// Hex Editor
//////////////////////////////////////////////////////////////////////////

typedef struct {
	UINT8   *Data;
	UINTN   Size;
	UINTN   Capacity;
	UINTN   CursorPos;
	BOOLEAN InAsciiMode;
	BOOLEAN Modified;
	BOOLEAN HexNibbleHigh;
	UINTN   TopLine;
	INT32   ScreenRows;
	INT32   ScreenCols;
	INT32   DataRows;
	INT32   HeaderRows;
	BOOLEAN ReadOnly;
} HEX_EDITOR_STATE;

STATIC
VOID
HexEditorDrawLine(
	IN HEX_EDITOR_STATE *State,
	IN UINTN            LineIdx,
	IN INT32            Row
)
{
	UINTN offset = LineIdx * HEX_BYTES_PER_LINE;
	UINTN i;
	UINTN curLine = State->CursorPos / HEX_BYTES_PER_LINE;
	UINTN curCol = State->CursorPos % HEX_BYTES_PER_LINE;

	g_Con->SetCursor(0, Row);

	if (offset >= State->Size && offset > 0) {
		// Empty line - clear it
		g_Con->Print(L"%-79s", L"");
		return;
	}

	// Address
	g_Con->Print(L"%08X  ", (UINT32)offset);

	// Hex bytes (two groups of 8)
	for (i = 0; i < HEX_BYTES_PER_LINE; i++) {
		if (i == 8)
			g_Con->Print(L" ");

		if (offset + i < State->Size) {
			BOOLEAN isCursor = (LineIdx == curLine && i == curCol && !State->InAsciiMode);
			if (isCursor)
				g_Con->Print(L"%V%02X%N ", State->Data[offset + i]);
			else
				g_Con->Print(L"%02X ", State->Data[offset + i]);
		} else {
			g_Con->Print(L"   ");
		}
	}

	g_Con->Print(L" ");

	// ASCII
	for (i = 0; i < HEX_BYTES_PER_LINE; i++) {
		if (offset + i < State->Size) {
			UINT8 ch = State->Data[offset + i];
			BOOLEAN isCursor = (LineIdx == curLine && i == curCol && State->InAsciiMode);
			if (ch < 0x20 || ch > 0x7E)
				ch = '.';
			if (isCursor)
				g_Con->Print(L"%V%c%N", (CHAR16)ch);
			else
				g_Con->Print(L"%c", (CHAR16)ch);
		} else {
			g_Con->Print(L" ");
		}
	}
}

STATIC
VOID
HexEditorDraw(
	IN HEX_EDITOR_STATE *State
)
{
	INT32 row;
	UINTN line;

	g_Con->SetCursor(0, 0);
	g_Con->Print(L"Offset    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  ASCII           ");

	g_Con->SetCursor(0, 1);
	for (INT32 c = 0; c < State->ScreenCols && c < 80; c++)
		g_Con->Print(L"-");

	for (row = 0; row < State->DataRows; row++) {
		line = State->TopLine + (UINTN)row;
		HexEditorDrawLine(State, line, State->HeaderRows + row);
	}

	// Footer
	INT32 footerRow = State->HeaderRows + State->DataRows;
	g_Con->SetCursor(0, footerRow);
	for (INT32 c = 0; c < State->ScreenCols && c < 80; c++)
		g_Con->Print(L"-");

	g_Con->SetCursor(0, footerRow + 1);
	if (State->ReadOnly) {
		g_Con->Print(L"Pos:%04X/%04X %s [VIEW-ONLY]  Arrows:navigate Esc:exit                ",
			(UINT32)State->CursorPos, (UINT32)State->Size,
			State->InAsciiMode ? L"ASCII" : L"HEX  ");
	} else {
		g_Con->Print(L"Pos:%04X/%04X %s %s  Tab:mode Ins/Del Enter:save Esc:cancel        ",
			(UINT32)State->CursorPos, (UINT32)State->Size,
			State->InAsciiMode ? L"ASCII" : L"HEX  ",
			State->Modified ? L"[MOD]" : L"     ");
	}
}

STATIC
VOID
HexEditorEnsureVisible(
	IN HEX_EDITOR_STATE *State
)
{
	UINTN curLine = State->CursorPos / HEX_BYTES_PER_LINE;

	if (curLine < State->TopLine)
		State->TopLine = curLine;

	if (curLine >= State->TopLine + (UINTN)State->DataRows)
		State->TopLine = curLine - (UINTN)State->DataRows + 1;
}

STATIC
BOOLEAN
HexEditorInsertByte(
	IN OUT HEX_EDITOR_STATE *State,
	IN     UINTN             Pos
)
{
	if (State->Size >= State->Capacity) {
		UINTN newCap = State->Capacity + 4096;
		if (newCap > HEX_EDITOR_MAX)
			return FALSE;
		UINT8 *newBuf = MEM_ALLOC(newCap);
		if (newBuf == NULL)
			return FALSE;
		CopyMem(newBuf, State->Data, State->Size);
		MEM_FREE(State->Data);
		State->Data = newBuf;
		State->Capacity = newCap;
	}

	if (Pos < State->Size) {
		CopyMem(State->Data + Pos + 1, State->Data + Pos, State->Size - Pos);
	}
	State->Data[Pos] = 0;
	State->Size++;
	State->Modified = TRUE;
	return TRUE;
}

STATIC
VOID
HexEditorDeleteByte(
	IN OUT HEX_EDITOR_STATE *State,
	IN     UINTN             Pos
)
{
	if (State->Size == 0 || Pos >= State->Size)
		return;

	if (Pos < State->Size - 1) {
		CopyMem(State->Data + Pos, State->Data + Pos + 1, State->Size - Pos - 1);
	}
	State->Size--;
	State->Modified = TRUE;

	if (State->CursorPos >= State->Size && State->Size > 0)
		State->CursorPos = State->Size - 1;
}

STATIC
INT32
HexCharValue(
	IN CHAR16 Ch
)
{
	if (Ch >= L'0' && Ch <= L'9') return Ch - L'0';
	if (Ch >= L'a' && Ch <= L'f') return Ch - L'a' + 10;
	if (Ch >= L'A' && Ch <= L'F') return Ch - L'A' + 10;
	return -1;
}

STATIC
EFI_STATUS
HexEditorRun(
	IN OUT UINT8   **DataPtr,
	IN OUT UINTN   *DataSizePtr,
	IN     BOOLEAN ReadOnly
)
{
	HEX_EDITOR_STATE state;
	EFI_INPUT_KEY    key;
	UINTN            origSize = *DataSizePtr;

	ZeroMem(&state, sizeof(state));

	// Allocate working copy
	state.Capacity = origSize + 4096;
	if (state.Capacity > HEX_EDITOR_MAX)
		state.Capacity = HEX_EDITOR_MAX;
	if (state.Capacity < 4096)
		state.Capacity = 4096;

	state.Data = MEM_ALLOC(state.Capacity);
	if (state.Data == NULL)
		return EFI_OUT_OF_RESOURCES;

	if (origSize > 0 && *DataPtr != NULL) {
		CopyMem(state.Data, *DataPtr, origSize);
	}
	state.Size = origSize;
	state.CursorPos = 0;
	state.InAsciiMode = FALSE;
	state.Modified = FALSE;
	state.HexNibbleHigh = TRUE;
	state.TopLine = 0;
	state.ReadOnly = ReadOnly;
	state.HeaderRows = 2;

	g_Con->GetSize(&state.ScreenCols, &state.ScreenRows);
	// Data rows: screen minus header (2) and footer (2)
	state.DataRows = state.ScreenRows - 4;
	if (state.DataRows < 4)
		state.DataRows = 4;

	g_Con->Clear();
	g_Con->EnableCursor(FALSE);

	for (;;) {
		HexEditorEnsureVisible(&state);
		HexEditorDraw(&state);

		key = g_Con->GetKey();

		// Escape - exit without saving
		if (key.ScanCode == SCAN_ESC) {
			MEM_FREE(state.Data);
			g_Con->EnableCursor(TRUE);
			return EFI_ABORTED;
		}

		// Enter - save if modified (or just exit in read-only)
		if (key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
			if (ReadOnly) {
				MEM_FREE(state.Data);
				g_Con->EnableCursor(TRUE);
				return EFI_ABORTED;
			}
			if (state.Modified) {
				g_Con->SetCursor(0, state.ScreenRows - 1);
				if (DcsAskYesNo(L"Write changes? [Y/n]: ", TRUE)) {
					// Replace caller's data
					MEM_FREE(*DataPtr);
					*DataPtr = state.Data;
					*DataSizePtr = state.Size;
					g_Con->EnableCursor(TRUE);
					return EFI_SUCCESS;
				}
				// Redraw after dialog
				g_Con->Clear();
				continue;
			}
			// No changes - just exit
			MEM_FREE(state.Data);
			g_Con->EnableCursor(TRUE);
			return EFI_ABORTED;
		}

		// Tab - switch mode
		if (key.UnicodeChar == CHAR_TAB) {
			state.InAsciiMode = !state.InAsciiMode;
			state.HexNibbleHigh = TRUE;
			continue;
		}

		// Arrow keys
		if (key.ScanCode == SCAN_UP) {
			if (state.CursorPos >= HEX_BYTES_PER_LINE)
				state.CursorPos -= HEX_BYTES_PER_LINE;
			state.HexNibbleHigh = TRUE;
			continue;
		}
		if (key.ScanCode == SCAN_DOWN) {
			UINTN newPos = state.CursorPos + HEX_BYTES_PER_LINE;
			if (newPos < state.Size)
				state.CursorPos = newPos;
			else if (state.Size > 0)
				state.CursorPos = state.Size - 1;
			state.HexNibbleHigh = TRUE;
			continue;
		}
		if (key.ScanCode == SCAN_LEFT) {
			if (state.CursorPos > 0)
				state.CursorPos--;
			state.HexNibbleHigh = TRUE;
			continue;
		}
		if (key.ScanCode == SCAN_RIGHT) {
			if (state.CursorPos + 1 < state.Size)
				state.CursorPos++;
			state.HexNibbleHigh = TRUE;
			continue;
		}

		// Page Up/Down
		if (key.ScanCode == SCAN_PAGE_UP) {
			UINTN jump = (UINTN)state.DataRows * HEX_BYTES_PER_LINE;
			if (state.CursorPos >= jump)
				state.CursorPos -= jump;
			else
				state.CursorPos = state.CursorPos % HEX_BYTES_PER_LINE;
			state.HexNibbleHigh = TRUE;
			continue;
		}
		if (key.ScanCode == SCAN_PAGE_DOWN) {
			UINTN jump = (UINTN)state.DataRows * HEX_BYTES_PER_LINE;
			UINTN newPos = state.CursorPos + jump;
			if (newPos < state.Size)
				state.CursorPos = newPos;
			else if (state.Size > 0)
				state.CursorPos = state.Size - 1;
			state.HexNibbleHigh = TRUE;
			continue;
		}

		// Home/End
		if (key.ScanCode == SCAN_HOME) {
			state.CursorPos = (state.CursorPos / HEX_BYTES_PER_LINE) * HEX_BYTES_PER_LINE;
			state.HexNibbleHigh = TRUE;
			continue;
		}
		if (key.ScanCode == SCAN_END) {
			UINTN lineStart = (state.CursorPos / HEX_BYTES_PER_LINE) * HEX_BYTES_PER_LINE;
			UINTN lineEnd = lineStart + HEX_BYTES_PER_LINE - 1;
			if (lineEnd >= state.Size && state.Size > 0)
				lineEnd = state.Size - 1;
			state.CursorPos = lineEnd;
			state.HexNibbleHigh = TRUE;
			continue;
		}

		// All editing operations blocked in read-only mode
		if (ReadOnly)
			continue;

		// Insert key - insert a byte at cursor
		if (key.ScanCode == SCAN_INSERT) {
			if (!HexEditorInsertByte(&state, state.CursorPos)) {
				g_Con->SetCursor(0, state.ScreenRows - 1);
				g_Con->PrintError(L"Cannot insert: maximum size reached");
			}
			g_Con->Clear();
			continue;
		}

		// Delete key - remove byte at cursor
		if (key.ScanCode == SCAN_DELETE) {
			HexEditorDeleteByte(&state, state.CursorPos);
			g_Con->Clear();
			continue;
		}

		// Typing in hex mode
		if (!state.InAsciiMode && key.UnicodeChar != 0) {
			INT32 val = HexCharValue(key.UnicodeChar);
			if (val >= 0) {
				// Auto-append if cursor at end
				if (state.CursorPos >= state.Size) {
					if (!HexEditorInsertByte(&state, state.Size))
						continue;
					state.CursorPos = state.Size - 1;
				}

				if (state.HexNibbleHigh) {
					state.Data[state.CursorPos] = (UINT8)((val << 4) | (state.Data[state.CursorPos] & 0x0F));
					state.HexNibbleHigh = FALSE;
				} else {
					state.Data[state.CursorPos] = (UINT8)((state.Data[state.CursorPos] & 0xF0) | val);
					state.HexNibbleHigh = TRUE;
					// Advance cursor
					if (state.CursorPos + 1 < state.Size)
						state.CursorPos++;
					else
						state.CursorPos = state.Size; // one past end for append
				}
				state.Modified = TRUE;
			}
			continue;
		}

		// Typing in ASCII mode
		if (state.InAsciiMode && key.UnicodeChar >= 0x20 && key.UnicodeChar <= 0x7E) {
			// Auto-append if cursor at end
			if (state.CursorPos >= state.Size) {
				if (!HexEditorInsertByte(&state, state.Size))
					continue;
				state.CursorPos = state.Size - 1;
			}

			state.Data[state.CursorPos] = (UINT8)key.UnicodeChar;
			state.Modified = TRUE;
			if (state.CursorPos + 1 < state.Size)
				state.CursorPos++;
			else
				state.CursorPos = state.Size;
			continue;
		}
	}
}

//////////////////////////////////////////////////////////////////////////
// GUID Parsing
//////////////////////////////////////////////////////////////////////////

STATIC
BOOLEAN
VarParseGuid(
	IN  CHAR16    *Str,
	OUT EFI_GUID  *Guid
)
{
	// Format: 8-4-4-4-12 hex chars
	// Example: 12345678-1234-1234-1234-123456789ABC
	UINTN len = StrLen(Str);
	if (len != 36)
		return FALSE;

	if (Str[8] != L'-' || Str[13] != L'-' || Str[18] != L'-' || Str[23] != L'-')
		return FALSE;

	UINT32 d1 = 0, d2 = 0, d3 = 0;
	UINTN  i;
	INT32  v;

	// Data1 (8 hex)
	for (i = 0; i < 8; i++) {
		v = HexCharValue(Str[i]);
		if (v < 0) return FALSE;
		d1 = (d1 << 4) | (UINT32)v;
	}
	Guid->Data1 = d1;

	// Data2 (4 hex)
	for (i = 9; i < 13; i++) {
		v = HexCharValue(Str[i]);
		if (v < 0) return FALSE;
		d2 = (d2 << 4) | (UINT32)v;
	}
	Guid->Data2 = (UINT16)d2;

	// Data3 (4 hex)
	for (i = 14; i < 18; i++) {
		v = HexCharValue(Str[i]);
		if (v < 0) return FALSE;
		d3 = (d3 << 4) | (UINT32)v;
	}
	Guid->Data3 = (UINT16)d3;

	// Data4[0..1] (4 hex)
	for (i = 0; i < 2; i++) {
		UINT8 b = 0;
		v = HexCharValue(Str[19 + i * 2]);
		if (v < 0) return FALSE;
		b = (UINT8)(v << 4);
		v = HexCharValue(Str[19 + i * 2 + 1]);
		if (v < 0) return FALSE;
		b |= (UINT8)v;
		Guid->Data4[i] = b;
	}

	// Data4[2..7] (12 hex)
	for (i = 0; i < 6; i++) {
		UINT8 b = 0;
		v = HexCharValue(Str[24 + i * 2]);
		if (v < 0) return FALSE;
		b = (UINT8)(v << 4);
		v = HexCharValue(Str[24 + i * 2 + 1]);
		if (v < 0) return FALSE;
		b |= (UINT8)v;
		Guid->Data4[2 + i] = b;
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////////
// Parse attribute string to UINT32
//////////////////////////////////////////////////////////////////////////

STATIC
UINT32
VarParseAttributes(
	IN CHAR16 *Str
)
{
	UINT32 attr = 0;

	// Simple parsing: look for known tokens separated by space or +
	while (*Str) {
		// Skip delimiters
		while (*Str == L' ' || *Str == L'+' || *Str == L',')
			Str++;

		if (StrnCmp(Str, L"NV", 2) == 0) {
			attr |= EFI_VARIABLE_NON_VOLATILE;
			Str += 2;
		} else if (StrnCmp(Str, L"BS", 2) == 0) {
			attr |= EFI_VARIABLE_BOOTSERVICE_ACCESS;
			Str += 2;
		} else if (StrnCmp(Str, L"RT", 2) == 0) {
			attr |= EFI_VARIABLE_RUNTIME_ACCESS;
			Str += 2;
		} else if (StrnCmp(Str, L"TB", 2) == 0) {
			attr |= EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
			Str += 2;
		} else if (StrnCmp(Str, L"AW", 2) == 0) {
			attr |= EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS;
			Str += 2;
		} else if (StrnCmp(Str, L"AP", 2) == 0) {
			attr |= EFI_VARIABLE_APPEND_WRITE;
			Str += 2;
		} else if (StrnCmp(Str, L"HR", 2) == 0) {
			attr |= EFI_VARIABLE_HARDWARE_ERROR_RECORD;
			Str += 2;
		} else {
			Str++;
		}
	}

	return attr;
}

//////////////////////////////////////////////////////////////////////////
// Read a line of text from console
//////////////////////////////////////////////////////////////////////////

STATIC
UINTN
VarReadLine(
	OUT CHAR16  *Buf,
	IN  UINTN   MaxLen
)
{
	UINTN len;
	CHAR16 lineBuf[512];

	ZeroMem(lineBuf, sizeof(lineBuf));
	len = 0;
	if (MaxLen > 510)
		MaxLen = 510;

	g_Con->ReadLine(&len, lineBuf, NULL, MaxLen, TRUE);

	if (len > 0)
		StrnCpyS(Buf, MaxLen + 1, lineBuf, len);
	else
		Buf[0] = L'\0';

	return len;
}

//////////////////////////////////////////////////////////////////////////
// Dump variable to file
//////////////////////////////////////////////////////////////////////////

STATIC
VOID
VarEnsureDumpDir(VOID)
{
	if (!IsPxeBoot()) {
		FsDirectoryCreate(NULL, L"\\EFI\\" DCS_DIRECTORY L"\\vars");
	}
}

STATIC
VOID
VarDoDump(
	IN EFI_VAR_ENTRY *Entry
)
{
	EFI_STATUS status;
	UINT8      *data = NULL;
	UINTN      dataSize = 0;
	UINT32     attrs = 0;
	CHAR16     path[512];

	status = VarReadData(Entry->Name, &Entry->Guid, &attrs, &data, &dataSize);
	if (EFI_ERROR(status)) {
		g_Con->PrintError(L"Failed to read variable: %r\n", status);
		return;
	}

	VarEnsureDumpDir();
	VarBuildFilePath(Entry->Name, path, 512);

	g_Con->Print(L"Dumping '%s' (%d bytes) to %s... ", Entry->Name, (UINT32)dataSize, path);

	status = UefiFileWritePath(path, data, (UINT32)dataSize);
	MEM_FREE(data);

	if (EFI_ERROR(status)) {
		g_Con->PrintError(L"Failed: %r\n", status);
	} else {
		g_Con->Print(L"%VDone.%N\n");
	}
}

//////////////////////////////////////////////////////////////////////////
// Overwrite variable from file
//////////////////////////////////////////////////////////////////////////

STATIC
VOID
VarDoOverwrite(
	IN EFI_VAR_ENTRY *Entry
)
{
	EFI_STATUS status;
	CHAR16     path[512];
	UINT8      *fileData = NULL;
	UINT32     fileSize = 0;

	VarBuildFilePath(Entry->Name, path, 512);

	if (!UefiFileExistsPath(path)) {
		g_Con->PrintError(L"File not found: %s\n", path);
		return;
	}

	g_Con->Print(L"Overwrite variable '%s' from %s?\n", Entry->Name, path);
	if (!DcsAskYesNo(L"Confirm overwrite [y/N]: ", FALSE))
		return;

	status = UefiFileReadPath(path, &fileData, &fileSize);
	if (EFI_ERROR(status)) {
		g_Con->PrintError(L"Failed to read file: %r\n", status);
		return;
	}

	g_Con->Print(L"Writing %d bytes to variable '%s'... ", fileSize, Entry->Name);

	status = gST->RuntimeServices->SetVariable(
		Entry->Name, &Entry->Guid,
		Entry->Attributes,
		(UINTN)fileSize, fileData);

	MEM_FREE(fileData);

	if (EFI_ERROR(status)) {
		g_Con->PrintError(L"Failed: %r\n", status);
	} else {
		g_Con->Print(L"%VDone.%N\n");
		Entry->DataSize = fileSize;
	}
}

//////////////////////////////////////////////////////////////////////////
// Erase (delete) a variable
//////////////////////////////////////////////////////////////////////////

STATIC
VOID
VarDoErase(
	IN EFI_VAR_ENTRY *Entry
)
{
	EFI_STATUS status;

	g_Con->Print(L"Delete variable '%s'?\n", Entry->Name);
	g_Con->PrintWarning(L"This cannot be undone.\n");

	if (!DcsAskYesNo(L"Confirm delete [y/N]: ", FALSE))
		return;

	g_Con->Print(L"Deleting variable '%s'... ", Entry->Name);

	status = gST->RuntimeServices->SetVariable(
		Entry->Name, &Entry->Guid,
		0,    // attributes = 0
		0,    // size = 0 => delete
		NULL);

	if (EFI_ERROR(status)) {
		g_Con->PrintError(L"Failed: %r\n", status);
	} else {
		g_Con->Print(L"%VDone.%N\n");
	}
}

//////////////////////////////////////////////////////////////////////////
// Create new variable
//////////////////////////////////////////////////////////////////////////

STATIC
VOID
VarDoCreate(VOID)
{
	EFI_STATUS status;
	CHAR16     name[VAR_NAME_MAX];
	CHAR16     guidStr[VAR_GUID_STR_SIZE];
	CHAR16     attrStr[64];
	EFI_GUID   guid;
	UINT32     attrs;
	CHAR16     path[512];
	UINT8      *fileData = NULL;
	UINT32     fileSize = 0;
	UINTN      len;

	g_Con->Print(L"\n--- Create New Variable ---\n\n");

	// Name
	g_Con->Print(L"Variable name: ");
	len = VarReadLine(name, VAR_NAME_MAX - 1);
	if (len == 0) {
		g_Con->Print(L"Cancelled.\n");
		return;
	}

	// GUID
	g_Con->Print(L"GUID (empty for default): ");
	len = VarReadLine(guidStr, VAR_GUID_STR_SIZE - 1);
	if (len == 0) {
		EFI_GUID gDefaultFileVarGuid = {
			0xDC5F11E5, 0x0001, 0x0001, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }
		};
		CopyMem(&guid, &gDefaultFileVarGuid, sizeof(EFI_GUID));
		//CopyMem(&guid, &gEfiGlobalVariableGuid, sizeof(EFI_GUID));
		g_Con->Print(L"Using global GUID.\n");
	} else {
		if (!VarParseGuid(guidStr, &guid)) {
			g_Con->PrintError(L"Invalid GUID format. Use: 12345678-1234-1234-1234-123456789ABC\n");
			return;
		}
	}

	// Attributes
	g_Con->Print(L"Attributes (NV BS RT TB AW AP HR, space-separated): ");
	len = VarReadLine(attrStr, 63);
	if (len == 0) {
		attrs = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;
		g_Con->Print(L"Using default: NV BS RT\n");
	} else {
		attrs = VarParseAttributes(attrStr);
		if (attrs == 0) {
			g_Con->PrintError(L"No valid attributes specified.\n");
			return;
		}
	}

	// Reject if neither BS nor RT — variable would be permanently inaccessible
	if (!(attrs & (EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS))) {
		g_Con->PrintError(L"At least one of BS or RT must be set.\n");
		g_Con->Print(L"Without access attributes the variable would be permanently inaccessible.\n");
		return;
	}

	// Warn if BS is missing — variable won't be visible during boot services
	if (!(attrs & EFI_VARIABLE_BOOTSERVICE_ACCESS)) {
		g_Con->PrintWarning(L"BS not set - variable will be invisible to DCS during boot.\n");
		if (!DcsAskYesNo(L"Continue anyway? [y/N]: ", FALSE))
			return;
	}

	// Load content from file
	VarBuildFilePath(name, path, 512);

	if (!UefiFileExistsPath(path)) {
		g_Con->PrintError(L"Content file not found: %s\n", path);
		g_Con->Print(L"Create the file first, then retry.\n");
		return;
	}

	status = UefiFileReadPath(path, &fileData, &fileSize);
	if (EFI_ERROR(status)) {
		g_Con->PrintError(L"Failed to read content file: %r\n", status);
		return;
	}

	g_Con->Print(L"Creating variable '%s' (%d bytes)... ", name, fileSize);

	status = gST->RuntimeServices->SetVariable(
		name, &guid, attrs,
		(UINTN)fileSize, fileData);

	MEM_FREE(fileData);

	if (EFI_ERROR(status)) {
		g_Con->PrintError(L"Failed: %r\n", status);
	} else {
		g_Con->Print(L"%VDone.%N\n");
	}
}

//////////////////////////////////////////////////////////////////////////
// Hex-edit a variable
//////////////////////////////////////////////////////////////////////////

STATIC
VOID
VarDoHexEdit(
	IN EFI_VAR_ENTRY *Entry,
	IN BOOLEAN        ReadOnly
)
{
	EFI_STATUS status;
	UINT8      *data = NULL;
	UINTN      dataSize = 0;
	UINT32     attrs = 0;

	status = VarReadData(Entry->Name, &Entry->Guid, &attrs, &data, &dataSize);
	if (EFI_ERROR(status)) {
		g_Con->PrintError(L"Failed to read variable: %r\n", status);
		return;
	}

	status = HexEditorRun(&data, &dataSize, ReadOnly);

	if (!EFI_ERROR(status) && !ReadOnly) {
		// Write back
		g_Con->Clear();
		g_Con->Print(L"Writing %d bytes to variable '%s'... ", (UINT32)dataSize, Entry->Name);

		status = gST->RuntimeServices->SetVariable(
			Entry->Name, &Entry->Guid,
			attrs,
			dataSize, data);

		if (EFI_ERROR(status)) {
			g_Con->PrintError(L"Failed: %r\n", status);
		} else {
			g_Con->Print(L"%VDone.%N\n");
			Entry->DataSize = dataSize;
		}

		g_Con->Print(L"\nPress any key to continue...\n");
		g_Con->GetKey();
	}

	MEM_FREE(data);
}

//////////////////////////////////////////////////////////////////////////
// Variable List Display
//////////////////////////////////////////////////////////////////////////

STATIC
VOID
VarListDrawEntry(
	IN EFI_VAR_ENTRY *Entry,
	IN INT32          Row,
	IN BOOLEAN        Selected,
	IN INT32          ScreenCols
)
{
	CHAR16 guidStr[VAR_GUID_STR_SIZE];
	CHAR16 attrStr[32];
	CHAR16 nameShort[28];
	UINTN  nameLen;

	VarFormatGuid(&Entry->Guid, guidStr, VAR_GUID_STR_SIZE);
	VarFormatAttributes(Entry->Attributes, attrStr, 32);

	// Truncate name if needed
	nameLen = StrLen(Entry->Name);
	if (nameLen > 26) {
		StrnCpyS(nameShort, 28, Entry->Name, 24);
		StrCatS(nameShort, 28, L"..");
	} else {
		StrnCpyS(nameShort, 28, Entry->Name, 27);
	}

	g_Con->SetCursor(0, Row);

	if (Selected)
		g_Con->Print(L"%V>%-26s %5d %-11s%N", nameShort, (UINT32)Entry->DataSize, attrStr);
	else
		g_Con->Print(L" %-26s %5d %-11s", nameShort, (UINT32)Entry->DataSize, attrStr);

	// Clear remainder of line
	g_Con->Print(L"          ");
}

//////////////////////////////////////////////////////////////////////////
// Main entry point
//////////////////////////////////////////////////////////////////////////

VOID
DcShowEfiVariables(VOID)
{
	EFI_STATUS     status;
	EFI_VAR_ENTRY  *entries = NULL;
	UINTN          count = 0;
	INT32          selected = 0;
	INT32          screenRows = 25;
	INT32          screenCols = 80;
	INT32          entriesPerPage;
	UINTN          currentPage = 0;
	UINTN          totalPages;
	EFI_INPUT_KEY  key;
	BOOLEAN        readOnly;

	readOnly = IsSecureBootEnabled();

	// Collect all variables
	g_Con->Clear();
	g_Con->Print(L"Enumerating EFI variables...\n");

	status = VarCollectAll(&entries, &count);
	if (EFI_ERROR(status)) {
		g_Con->PrintError(L"Failed to enumerate variables: %r\n", status);
		g_Con->Print(L"\nPress any key to continue...\n");
		g_Con->GetKey();
		return;
	}

	if (count == 0) {
		g_Con->Print(L"No EFI variables found.\n");
		g_Con->Print(L"\nPress any key to continue...\n");
		g_Con->GetKey();
		return;
	}

	g_Con->GetSize(&screenCols, &screenRows);
	// Header (3) + footer (3) = 6 lines reserved
	entriesPerPage = screenRows - 6;
	if (entriesPerPage < 4)
		entriesPerPage = 4;

	for (;;) {
		totalPages = (count + (UINTN)entriesPerPage - 1) / (UINTN)entriesPerPage;
		currentPage = (UINTN)selected / (UINTN)entriesPerPage;

		UINTN startIdx = currentPage * (UINTN)entriesPerPage;
		UINTN endIdx = startIdx + (UINTN)entriesPerPage;
		if (endIdx > count)
			endIdx = count;

		g_Con->Clear();
		if (readOnly)
			g_Con->Print(L"--- EFI Variables (%d total) [READ-ONLY: Secure Boot] --- Page %d/%d\n",
				(UINT32)count, (UINT32)(currentPage + 1), (UINT32)totalPages);
		else
			g_Con->Print(L"--- EFI Variables (%d total) --- Page %d/%d\n",
				(UINT32)count, (UINT32)(currentPage + 1), (UINT32)totalPages);
		g_Con->Print(L" %-26s %5s %-11s\n", L"Name", L"Size", L"Attributes");

		// Draw entries
		for (UINTN i = startIdx; i < endIdx; i++) {
			VarListDrawEntry(&entries[i], (INT32)(2 + i - startIdx),
				((INT32)i == selected), screenCols);
		}

		// Show GUID of selected entry at bottom
		{
			CHAR16 guidStr[VAR_GUID_STR_SIZE];
			VarFormatGuid(&entries[selected].Guid, guidStr, VAR_GUID_STR_SIZE);

			INT32 footerRow = 2 + entriesPerPage;
			g_Con->SetCursor(0, footerRow);
			g_Con->Print(L"GUID: %s\n", guidStr);
			if (readOnly)
				g_Con->Print(L"D:Dump A:DumpAll Enter:View Esc:Exit  %O[SB: read-only]%N\n");
			else
				g_Con->Print(L"D:Dump A:DumpAll O:Overwrite N:New E:Erase Enter:Edit Esc:Exit\n");
		}

		g_Con->EnableCursor(FALSE);

		key = g_Con->GetKey();
		g_Con->FlushInput(100000);

		// Navigation
		if (key.ScanCode == SCAN_UP) {
			if (selected > 0)
				selected--;
			continue;
		}
		if (key.ScanCode == SCAN_DOWN) {
			if (selected < (INT32)count - 1)
				selected++;
			continue;
		}
		if (key.ScanCode == SCAN_PAGE_UP) {
			selected -= entriesPerPage;
			if (selected < 0)
				selected = 0;
			continue;
		}
		if (key.ScanCode == SCAN_PAGE_DOWN) {
			selected += entriesPerPage;
			if (selected >= (INT32)count)
				selected = (INT32)count - 1;
			continue;
		}
		if (key.ScanCode == SCAN_HOME) {
			selected = 0;
			continue;
		}
		if (key.ScanCode == SCAN_END) {
			selected = (INT32)count - 1;
			continue;
		}

		// Exit
		if (key.ScanCode == SCAN_ESC) {
			break;
		}

		// Dump single
		if (key.UnicodeChar == L'd' || key.UnicodeChar == L'D') {
			g_Con->EnableCursor(TRUE);
			g_Con->Clear();
			VarDoDump(&entries[selected]);
			g_Con->Print(L"\nPress any key to continue...\n");
			g_Con->GetKey();
			continue;
		}

		// Dump all
		if (key.UnicodeChar == L'a' || key.UnicodeChar == L'A') {
			g_Con->EnableCursor(TRUE);
			g_Con->Clear();
			g_Con->Print(L"Dump all %d variables to %s?\n", (UINT32)count, VAR_DUMP_DIR);
			if (!DcsAskYesNo(L"Confirm [y/N]: ", FALSE))
				continue;
			VarEnsureDumpDir();
			g_Con->Print(L"Dumping all %d variables...\n\n", (UINT32)count);
			for (UINTN di = 0; di < count; di++) {
				VarDoDump(&entries[di]);
			}
			g_Con->Print(L"\nDone. Press any key to continue...\n");
			g_Con->GetKey();
			continue;
		}

		// Overwrite
		if (key.UnicodeChar == L'o' || key.UnicodeChar == L'O') {
			if (readOnly) {
				g_Con->SetCursor(0, screenRows - 1);
				g_Con->PrintError(L"Write operations disabled (Secure Boot active)");
				g_Con->GetKey();
				continue;
			}
			g_Con->EnableCursor(TRUE);
			g_Con->Clear();
			VarDoOverwrite(&entries[selected]);
			g_Con->Print(L"\nPress any key to continue...\n");
			g_Con->GetKey();
			continue;
		}

		// Erase variable
		if (key.UnicodeChar == L'e' || key.UnicodeChar == L'E') {
			if (readOnly) {
				g_Con->SetCursor(0, screenRows - 1);
				g_Con->PrintError(L"Write operations disabled (Secure Boot active)");
				g_Con->GetKey();
				continue;
			}
			g_Con->EnableCursor(TRUE);
			g_Con->Clear();
			VarDoErase(&entries[selected]);
			g_Con->Print(L"\nPress any key to continue...\n");
			g_Con->GetKey();

			// Refresh list
			MEM_FREE(entries);
			entries = NULL;
			count = 0;
			g_Con->Clear();
			g_Con->Print(L"Refreshing variable list...\n");
			status = VarCollectAll(&entries, &count);
			if (EFI_ERROR(status) || count == 0) {
				if (count == 0) {
					g_Con->Print(L"No variables remaining.\n");
					g_Con->Print(L"\nPress any key to continue...\n");
					g_Con->GetKey();
				} else {
					g_Con->PrintError(L"Failed to refresh: %r\n", status);
					g_Con->Print(L"\nPress any key to continue...\n");
					g_Con->GetKey();
				}
				break;
			}
			if (selected >= (INT32)count)
				selected = (INT32)count - 1;
			continue;
		}

		// New variable
		if (key.UnicodeChar == L'n' || key.UnicodeChar == L'N') {
			if (readOnly) {
				g_Con->SetCursor(0, screenRows - 1);
				g_Con->PrintError(L"Write operations disabled (Secure Boot active)");
				g_Con->GetKey();
				continue;
			}
			g_Con->EnableCursor(TRUE);
			g_Con->Clear();
			VarDoCreate();
			g_Con->Print(L"\nPress any key to continue...\n");
			g_Con->GetKey();

			// Refresh list
			MEM_FREE(entries);
			entries = NULL;
			count = 0;
			g_Con->Clear();
			g_Con->Print(L"Refreshing variable list...\n");
			status = VarCollectAll(&entries, &count);
			if (EFI_ERROR(status) || count == 0) {
				g_Con->PrintError(L"Failed to refresh: %r\n", status);
				g_Con->Print(L"\nPress any key to continue...\n");
				g_Con->GetKey();
				break;
			}
			if (selected >= (INT32)count)
				selected = (INT32)count - 1;
			continue;
		}

		// Hex edit
		if (key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
			g_Con->EnableCursor(TRUE);
			VarDoHexEdit(&entries[selected], readOnly);
			continue;
		}
	}

	g_Con->EnableCursor(TRUE);
	if (entries != NULL)
		MEM_FREE(entries);
	g_Con->Clear();
}
