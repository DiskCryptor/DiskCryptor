/** @file
DcsOwner confirmation UI

Interactive dialog for reviewing and selectively accepting pending
variable changes. Includes a read-only hex viewer and SHA-256
certificate fingerprint display.

Copyright (c) 2026. DiskCryptor, David Xanatos

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include "DcsOwner.h"

#include <Library/CommonLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseCryptLib.h>
#include <Guid/ImageAuthentication.h>

#define CONFIRM_MAX_ITEMS    16
#define HEX_BYTES_PER_LINE   16
#define DESC_BUF_CHARS       80

//////////////////////////////////////////////////////////////////////////
// Certificate fingerprint (SHA-256 of first X.509 cert in signature list)
//////////////////////////////////////////////////////////////////////////

VOID
DescribeCertFingerprint (
    IN  VOID    *Data,
    IN  UINTN   Size,
    OUT CHAR16  *Buf,
    IN  UINTN   BufChars
    )
{
    EFI_SIGNATURE_LIST  *SigList;
    UINT8               *CertData;
    UINTN               CertSize;
    UINT8               Hash[32];
    UINTN               i, Off;

    if (Data == NULL || Size < sizeof(EFI_SIGNATURE_LIST)) {
        UnicodeSPrint(Buf, BufChars * sizeof(CHAR16), L"%d bytes", (int)Size);
        return;
    }

    SigList = (EFI_SIGNATURE_LIST *)Data;
    if (SigList->SignatureSize <= sizeof(EFI_GUID) ||
        SigList->SignatureListSize > Size) {
        UnicodeSPrint(Buf, BufChars * sizeof(CHAR16), L"%d bytes", (int)Size);
        return;
    }

    CertData = (UINT8 *)SigList
             + sizeof(EFI_SIGNATURE_LIST)
             + SigList->SignatureHeaderSize
             + sizeof(EFI_GUID);
    CertSize = SigList->SignatureSize - sizeof(EFI_GUID);

    if (!Sha256HashAll(CertData, CertSize, Hash)) {
        UnicodeSPrint(Buf, BufChars * sizeof(CHAR16), L"%d bytes (hash failed)", (int)Size);
        return;
    }

    Off = 0;
    for (i = 0; i < 10 && Off + 3 < BufChars; i++) {
        if (i > 0 && Off + 1 < BufChars)
            Buf[Off++] = L':';
        UnicodeSPrint(&Buf[Off], (BufChars - Off) * sizeof(CHAR16), L"%02X", Hash[i]);
        Off += 2;
    }
    if (Off + 4 < BufChars) {
        Buf[Off++] = L'.';
        Buf[Off++] = L'.';
        Buf[Off++] = L'.';
    }
    Buf[Off] = L'\0';
}

//////////////////////////////////////////////////////////////////////////
// Read-only hex viewer
//////////////////////////////////////////////////////////////////////////

typedef struct {
    UINT8   *Data;
    UINTN    Size;
    UINTN    CursorPos;
    UINTN    TopLine;
    INT32    ScreenRows;
    INT32    ScreenCols;
    INT32    DataRows;
} HEX_VIEW_STATE;

STATIC
VOID
HexViewDrawLine (
    IN HEX_VIEW_STATE  *St,
    IN UINTN            LineIdx,
    IN INT32             Row
    )
{
    UINTN  offset = LineIdx * HEX_BYTES_PER_LINE;
    UINTN  i;

    gST->ConOut->SetCursorPosition(gST->ConOut, 0, Row);

    if (offset >= St->Size) {
        OUT_PRINT(L"%-79s", L"");
        return;
    }

    OUT_PRINT(L"%08X  ", (UINT32)offset);

    for (i = 0; i < HEX_BYTES_PER_LINE; i++) {
        if (i == 8) OUT_PRINT(L" ");
        if (offset + i < St->Size) {
            BOOLEAN isCur = (offset + i == St->CursorPos);
            if (isCur)
                OUT_PRINT(L"%V%02X%N ", St->Data[offset + i]);
            else
                OUT_PRINT(L"%02X ", St->Data[offset + i]);
        } else {
            OUT_PRINT(L"   ");
        }
    }

    OUT_PRINT(L" ");
    for (i = 0; i < HEX_BYTES_PER_LINE; i++) {
        if (offset + i < St->Size) {
            UINT8 ch = St->Data[offset + i];
            BOOLEAN isCur = (offset + i == St->CursorPos);
            if (ch < 0x20 || ch > 0x7E) ch = '.';
            if (isCur)
                OUT_PRINT(L"%V%c%N", (CHAR16)ch);
            else
                OUT_PRINT(L"%c", (CHAR16)ch);
        } else {
            OUT_PRINT(L" ");
        }
    }
}

STATIC
VOID
HexViewEnsureVisible (
    IN HEX_VIEW_STATE  *St
    )
{
    UINTN curLine = St->CursorPos / HEX_BYTES_PER_LINE;
    if (curLine < St->TopLine)
        St->TopLine = curLine;
    if (curLine >= St->TopLine + (UINTN)St->DataRows)
        St->TopLine = curLine - (UINTN)St->DataRows + 1;
}

STATIC
VOID
HexViewDraw (
    IN HEX_VIEW_STATE  *St,
    IN CONST CHAR16    *Title
    )
{
    INT32  row;
    UINTN  line;

    gST->ConOut->SetCursorPosition(gST->ConOut, 0, 0);
    OUT_PRINT(L"%-79s", Title);

    gST->ConOut->SetCursorPosition(gST->ConOut, 0, 1);
    OUT_PRINT(L"Offset    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  ASCII           ");

    gST->ConOut->SetCursorPosition(gST->ConOut, 0, 2);
    for (INT32 c = 0; c < 80; c++) OUT_PRINT(L"-");

    for (row = 0; row < St->DataRows; row++) {
        line = St->TopLine + (UINTN)row;
        HexViewDrawLine(St, line, 3 + row);
    }

    INT32 footerRow = 3 + St->DataRows;
    gST->ConOut->SetCursorPosition(gST->ConOut, 0, footerRow);
    for (INT32 c = 0; c < 80; c++) OUT_PRINT(L"-");

    gST->ConOut->SetCursorPosition(gST->ConOut, 0, footerRow + 1);
    OUT_PRINT(L"Pos:%04X/%04X [VIEW-ONLY]  Arrows:navigate  Esc/Left:back               ",
        (UINT32)St->CursorPos, (UINT32)St->Size);
}

STATIC
VOID
HexViewRun (
    IN UINT8         *Data,
    IN UINTN          Size,
    IN CONST CHAR16  *Title
    )
{
    HEX_VIEW_STATE  st;
    EFI_INPUT_KEY   key;
    UINTN           cols, rows;

    ZeroMem(&st, sizeof(st));
    st.Data = Data;
    st.Size = Size;

    gST->ConOut->QueryMode(gST->ConOut, gST->ConOut->Mode->Mode, &cols, &rows);
    st.ScreenRows = (INT32)rows;
    st.ScreenCols = (INT32)cols;
    st.DataRows   = st.ScreenRows - 5;
    if (st.DataRows < 4) st.DataRows = 4;

    gST->ConOut->ClearScreen(gST->ConOut);
    gST->ConOut->EnableCursor(gST->ConOut, FALSE);

    for (;;) {
        HexViewEnsureVisible(&st);
        HexViewDraw(&st, Title);

        {
            UINTN EventIndex;
            gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &EventIndex);
        }
        if (EFI_ERROR(gST->ConIn->ReadKeyStroke(gST->ConIn, &key)))
            continue;

        if (key.ScanCode == SCAN_ESC || key.ScanCode == SCAN_LEFT)
            break;

        if (key.ScanCode == SCAN_UP && st.CursorPos >= HEX_BYTES_PER_LINE)
            st.CursorPos -= HEX_BYTES_PER_LINE;

        if (key.ScanCode == SCAN_DOWN) {
            UINTN np = st.CursorPos + HEX_BYTES_PER_LINE;
            if (np < st.Size) st.CursorPos = np;
            else if (st.Size > 0) st.CursorPos = st.Size - 1;
        }

        if (key.ScanCode == SCAN_RIGHT && st.CursorPos + 1 < st.Size)
            st.CursorPos++;

        if (key.ScanCode == SCAN_PAGE_UP) {
            UINTN jump = (UINTN)st.DataRows * HEX_BYTES_PER_LINE;
            if (st.CursorPos >= jump) st.CursorPos -= jump;
            else st.CursorPos = st.CursorPos % HEX_BYTES_PER_LINE;
        }

        if (key.ScanCode == SCAN_PAGE_DOWN) {
            UINTN jump = (UINTN)st.DataRows * HEX_BYTES_PER_LINE;
            UINTN np = st.CursorPos + jump;
            if (np < st.Size) st.CursorPos = np;
            else if (st.Size > 0) st.CursorPos = st.Size - 1;
        }
    }
}

//////////////////////////////////////////////////////////////////////////
// Confirmation dialog
//////////////////////////////////////////////////////////////////////////

typedef struct {
    CONST CHAR16  *Label;
    CHAR16         Desc[DESC_BUF_CHARS];
    VOID          *NewData;
    UINTN          NewSize;
    BOOLEAN        Accepted;
    INT32          MapIndex;    // -1 = SecureBootOverride, >=0 = gVarMap index
} CONFIRM_ITEM;

STATIC
VOID
ConfirmDrawItem (
    IN CONFIRM_ITEM  *Item,
    IN INT32          Row,
    IN BOOLEAN        Selected
    )
{
    gST->ConOut->SetCursorPosition(gST->ConOut, 0, Row);

    if (Selected)
        OUT_PRINT(L"%V> [%c] %s  %s",
            Item->Accepted ? L'X' : L' ',
            Item->Label,
            Item->Desc);
    else
        OUT_PRINT(L"  [%c] %s  %s",
            Item->Accepted ? L'X' : L' ',
            Item->Label,
            Item->Desc);

    // pad to end of line
    {
        UINTN col = (UINTN)gST->ConOut->Mode->CursorColumn;
        while (col < 79) { OUT_PRINT(L" "); col++; }
    }

    if (Selected)
        OUT_PRINT(L"%N");
}

STATIC
CONST CHAR16*
GetOverrideDesc (
    IN UINT8  Value
    )
{
    static CHAR16 Hex[12] = {0};
    switch (Value)
    {
	case DCSOWNER_SB_DISABLED:    return L"Disabled";
	case DCSOWNER_SB_REPORT_OFF:  return L"Report Off";
	case DCSOWNER_SB_REPORT_ON:   return L"Report On";
    default:
		UnicodeSPrint(Hex, sizeof(Hex), L"0x%2X", (int)Value);
        return Hex;
    }
}

EFI_STATUS
DcsOwnerConfirmChanges (
    IN  BOOLEAN   SbChanged,
    IN  UINT8     OldSb,
    IN  UINT8     NewSb,
    OUT BOOLEAN  *SbAccepted,
    OUT BOOLEAN  *VarAccepted
    )
{
    CONFIRM_ITEM  items[CONFIRM_MAX_ITEMS];
    INT32         count = 0;
    INT32         selected = 0;
    INT32         baseRow;
    INT32         i;
    EFI_INPUT_KEY key;
    ZeroMem(items, sizeof(items));
    *SbAccepted = FALSE;

    // SecureBootOverride change
    if (SbChanged && count < CONFIRM_MAX_ITEMS) {
        items[count].Label    = L"SecureBootOverride";
        items[count].MapIndex = -1;
        items[count].Accepted = FALSE;
        UnicodeSPrint(items[count].Desc, sizeof(items[count].Desc),
			L"%s -> %s", GetOverrideDesc(OldSb), GetOverrideDesc(NewSb));
        items[count].NewData = NULL;
        items[count].NewSize = 0;
        count++;
    }

    // Mapped variable changes
    for (i = 0; i < (INT32)gVarMapCount && count < CONFIRM_MAX_ITEMS; i++) {
        VOID  *PrivData, *RtData;
        UINTN  PrivSize, RtSize;

        PrivData = CfgGetBytes((CHAR16 *)gVarMap[i].NameBS, &PrivSize);
        RtData   = CfgGetBytes((CHAR16 *)gVarMap[i].NameRT, &RtSize);

        if (!BytesEqual(RtData, RtSize, PrivData, PrivSize)) {
            items[count].Label    = gVarMap[i].Name;
            items[count].MapIndex = i;
            items[count].Accepted = FALSE;
            items[count].NewData  = RtData;
            items[count].NewSize  = RtSize;
            RtData = NULL;  // ownership transferred

            if (gVarMap[i].Describe != NULL) {
                gVarMap[i].Describe(
                    items[count].NewData, items[count].NewSize,
                    items[count].Desc, DESC_BUF_CHARS);
            } else {
                UnicodeSPrint(items[count].Desc, sizeof(items[count].Desc),
                    L"%d bytes", (int)items[count].NewSize);
            }
            count++;
        }

        if (PrivData != NULL) MEM_FREE(PrivData);
        if (RtData != NULL)   MEM_FREE(RtData);
    }

    if (count == 0)
        return EFI_NOT_FOUND;

    // Initialize VarAccepted to FALSE
    for (i = 0; i < (INT32)gVarMapCount; i++)
        VarAccepted[i] = FALSE;

    // Draw
    gST->ConOut->ClearScreen(gST->ConOut);
    OUT_PRINT(L"--- DcsOwner: Pending Changes ---\r\n");
    OUT_PRINT(L"Space:toggle  Right:hex view  Enter:apply  Esc:exit\r\n");

    {
        UINTN col, row;
        gST->ConOut->QueryMode(gST->ConOut, gST->ConOut->Mode->Mode, &col, &row);
        baseRow = (INT32)gST->ConOut->Mode->CursorRow;
    }

    for (i = 0; i < count; i++) {
        ConfirmDrawItem(&items[i], baseRow + i, (i == selected));
    }

    gST->ConOut->EnableCursor(gST->ConOut, FALSE);

    BOOLEAN Confirmed = FALSE;

    for (;;) {
        UINTN EventIndex;
        gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &EventIndex);
        if (EFI_ERROR(gST->ConIn->ReadKeyStroke(gST->ConIn, &key)))
            continue;

        // Escape: exit with no changes applied or reverted
        if (key.ScanCode == SCAN_ESC)
            break;

        // Enter: apply what's checked
        if (key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
            Confirmed = TRUE;
            break;
        }

        // Space: toggle
        if (key.UnicodeChar == L' ') {
            items[selected].Accepted = !items[selected].Accepted;
            ConfirmDrawItem(&items[selected], baseRow + selected, TRUE);
            continue;
        }

        // Up
        if (key.ScanCode == SCAN_UP && selected > 0) {
            INT32 prev = selected;
            selected--;
            ConfirmDrawItem(&items[prev], baseRow + prev, FALSE);
            ConfirmDrawItem(&items[selected], baseRow + selected, TRUE);
            continue;
        }

        // Down
        if (key.ScanCode == SCAN_DOWN && selected < count - 1) {
            INT32 prev = selected;
            selected++;
            ConfirmDrawItem(&items[prev], baseRow + prev, FALSE);
            ConfirmDrawItem(&items[selected], baseRow + selected, TRUE);
            continue;
        }

        // Right arrow: open hex viewer for selected item
        if (key.ScanCode == SCAN_RIGHT) {
            if (items[selected].NewData != NULL && items[selected].NewSize > 0) {
                CHAR16 title[80];
                UnicodeSPrint(title, sizeof(title), L"New value: %s", items[selected].Label);
                HexViewRun(items[selected].NewData, items[selected].NewSize, title);

                // Redraw after returning from hex viewer
                gST->ConOut->ClearScreen(gST->ConOut);
                gST->ConOut->SetCursorPosition(gST->ConOut, 0, 0);
                OUT_PRINT(L"--- DcsOwner: Pending Changes ---\r\n");
                OUT_PRINT(L"Space:toggle  Right:hex view  Enter:apply  Esc:exit\r\n");
                for (i = 0; i < count; i++) {
                    ConfirmDrawItem(&items[i], baseRow + i, (i == selected));
                }
                gST->ConOut->EnableCursor(gST->ConOut, FALSE);
            }
            continue;
        }
    }

    // Collect results only if user pressed Enter
    if (Confirmed) {
        for (i = 0; i < count; i++) {
            if (items[i].MapIndex == -1) {
                *SbAccepted = items[i].Accepted;
            } else {
                VarAccepted[items[i].MapIndex] = items[i].Accepted;
            }
        }
    }

    // Free data buffers
    for (i = 0; i < count; i++) {
        if (items[i].NewData != NULL) {
            MEM_FREE(items[i].NewData);
            items[i].NewData = NULL;
        }
    }

    gST->ConOut->EnableCursor(gST->ConOut, TRUE);
    gST->ConOut->ClearScreen(gST->ConOut);
    return Confirmed ? EFI_SUCCESS : EFI_ABORTED;
}
