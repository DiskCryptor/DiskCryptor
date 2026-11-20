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
// Signature database summary of the whole value (size, lists, signatures); the dialog shows
// the SHA-256 of the whole value below the list.
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
    UINTN               Off = 0;
    UINTN               Lists = 0;
    UINTN               Sigs = 0;
    UINTN               Payload;

    if (Data == NULL || Size == 0) {
        UnicodeSPrint(Buf, BufChars * sizeof(CHAR16), L"(removed)");
        return;
    }

    while (Off < Size) {
        if (Size - Off < sizeof(EFI_SIGNATURE_LIST))
            break;
        SigList = (EFI_SIGNATURE_LIST *)((UINT8 *)Data + Off);
        if (SigList->SignatureListSize < sizeof(EFI_SIGNATURE_LIST) ||
            SigList->SignatureListSize > Size - Off ||
            SigList->SignatureSize <= sizeof(EFI_GUID) ||
            SigList->SignatureHeaderSize > SigList->SignatureListSize - sizeof(EFI_SIGNATURE_LIST))
            break;
        Payload = SigList->SignatureListSize - sizeof(EFI_SIGNATURE_LIST) - SigList->SignatureHeaderSize;
        if (Payload % SigList->SignatureSize != 0)
            break;
        Sigs  += Payload / SigList->SignatureSize;
        Lists += 1;
        Off   += SigList->SignatureListSize;
    }

    if (Off != Size) {
        UnicodeSPrint(Buf, BufChars * sizeof(CHAR16), L"%d bytes, NOT a valid signature list", (int)Size);
        return;
    }
    UnicodeSPrint(Buf, BufChars * sizeof(CHAR16), L"%d bytes, %d list(s), %d signature(s)",
                  (int)Size, (int)Lists, (int)Sigs);
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
    UINT8          Hash[32];    // SHA-256 of the whole new value
    BOOLEAN        HashOk;
} CONFIRM_ITEM;

/**
  The detail line under the list - the SHA-256 of the whole new value of the
  selected item, so a value can be checked against the one that was staged.
**/
STATIC
VOID
ConfirmDrawDetail (
    IN CONFIRM_ITEM  *Item,
    IN INT32          Row
    )
{
    UINTN i;

    gST->ConOut->SetCursorPosition(gST->ConOut, 0, Row);
    if (Item->MapIndex < 0) {
        // SecureBootOverride: the line above says it all
    } else if (Item->NewData == NULL || Item->NewSize == 0) {
        OUT_PRINT(L"  New value: (removed)");
    } else if (!Item->HashOk) {
        OUT_PRINT(L"  SHA-256: (failed)");
    } else {
        // "  SHA-256: " (11) + 64 hex = 75 fits an 80-column line
        OUT_PRINT(L"  SHA-256: ");
        for (i = 0; i < 32; i++) OUT_PRINT(L"%02x", Item->Hash[i]);
    }
    {
        UINTN col = (UINTN)gST->ConOut->Mode->CursorColumn;
        while (col < 79) { OUT_PRINT(L" "); col++; }
    }
}

/**
  A value without a describer - a one-byte flag is shown decoded, anything longer by
  its size (its SHA-256 is on the detail line).
**/
STATIC
VOID
DescribeFlagOrSize (
    IN  CONST CHAR16  *Name,
    IN  VOID          *Data,
    IN  UINTN          Size,
    OUT CHAR16        *Buf,
    IN  UINTN          BufChars
    )
{
    UINT8         v;
    CONST CHAR16  *m = NULL;

    if (Data == NULL || Size == 0) {
        UnicodeSPrint(Buf, BufChars * sizeof(CHAR16), L"(removed)");
        return;
    }
    if (Size != 1) {
        UnicodeSPrint(Buf, BufChars * sizeof(CHAR16), L"%d bytes", (int)Size);
        return;
    }
    v = *(UINT8 *)Data;
    if (StrCmp(Name, L"PrivacyDeveloper") == 0) {
        m = (v == 0x00) ? L"No" : (v == 0x01) ? L"Allow User Signing" :
            (v == 0x03) ? L"Allow Signing & Debugging" : L"unknown value";
    } else if (StrCmp(Name, L"SuspendIsolator") == 0) {
        m = (v == 0) ? L"False" : (v == 1) ? L"True" : L"unknown value";
    }
    if (m != NULL) {
        UnicodeSPrint(Buf, BufChars * sizeof(CHAR16), L"0x%02X = %s", (int)v, m);
    } else {
        UnicodeSPrint(Buf, BufChars * sizeof(CHAR16), L"1 byte: 0x%02X", (int)v);
    }
}

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

// Into the caller's buffer (old and new value are formatted together); a non-canonical value
// is shown by what DcsOwner makes of it (DCSOWNER_SB_ACTIVE/VALUE) plus its hex
STATIC
VOID
GetOverrideDesc (
    IN  UINT8    Value,
    OUT CHAR16  *Buf,
    IN  UINTN    BufChars
    )
{
    CONST CHAR16 *Name = !DCSOWNER_SB_ACTIVE(Value) ? L"Disabled" :
                         DCSOWNER_SB_VALUE(Value)   ? L"Report On" : L"Report Off";

    if (Value == DCSOWNER_SB_DISABLED || Value == DCSOWNER_SB_REPORT_OFF || Value == DCSOWNER_SB_REPORT_ON) {
        UnicodeSPrint(Buf, BufChars * sizeof(CHAR16), L"%s", Name);
    } else {
        UnicodeSPrint(Buf, BufChars * sizeof(CHAR16), L"%s (0x%02X)", Name, (int)Value);
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
        CHAR16 OldDesc[24];
        CHAR16 NewDesc[24];
        GetOverrideDesc(OldSb, OldDesc, sizeof(OldDesc) / sizeof(OldDesc[0]));
        GetOverrideDesc(NewSb, NewDesc, sizeof(NewDesc) / sizeof(NewDesc[0]));
        UnicodeSPrint(items[count].Desc, sizeof(items[count].Desc),
			L"%s -> %s", OldDesc, NewDesc);
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

            if (items[count].NewData != NULL && items[count].NewSize > 0) {
                items[count].HashOk = Sha256HashAll(items[count].NewData, items[count].NewSize, items[count].Hash);
            }
            if (gVarMap[i].Describe != NULL) {
                gVarMap[i].Describe(
                    items[count].NewData, items[count].NewSize,
                    items[count].Desc, DESC_BUF_CHARS);
            } else {
                DescribeFlagOrSize(gVarMap[i].Name, items[count].NewData, items[count].NewSize,
                    items[count].Desc, DESC_BUF_CHARS);
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

    // Dialog waits indefinitely for the operator; stop the 5-min boot watchdog
    gBS->SetWatchdogTimer(0, 0, 0, NULL);

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
    ConfirmDrawDetail(&items[selected], baseRow + count + 1);

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
            ConfirmDrawDetail(&items[selected], baseRow + count + 1);
            continue;
        }

        // Down
        if (key.ScanCode == SCAN_DOWN && selected < count - 1) {
            INT32 prev = selected;
            selected++;
            ConfirmDrawItem(&items[prev], baseRow + prev, FALSE);
            ConfirmDrawItem(&items[selected], baseRow + selected, TRUE);
            ConfirmDrawDetail(&items[selected], baseRow + count + 1);
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
                ConfirmDrawDetail(&items[selected], baseRow + count + 1);
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
