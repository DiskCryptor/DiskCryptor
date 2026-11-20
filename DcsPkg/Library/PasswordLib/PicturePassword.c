/** @file
Picture password

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>

#include <Library/CommonLib.h>
#include <Library/GraphLib.h>
#include <Library/PasswordLib.h>

CHAR16*	gPasswordPictureFileName = NULL;

CHAR8*	gPasswordPictureChars = NULL;
//CHAR8*gPasswordPictureCharsDefault = "MN/[aQ-eyPr}GT: |V^UqiI_gbdA9YwZ%f8t6S@D\"7uXl\\30R#+zH*,W4J?=&BLFv]hx~E;$<.o'sp1`(>C)O{!5j2nmkcK";
CHAR8*	gPasswordPictureCharsDefault = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\b";
UINTN	gPasswordPictureCharsLen = 96;

UINT8	gPasswordVisible = 0;
int		gPasswordHideLetters = 1;
int		gPasswordShowMark = 0;
UINT8	gPasswordProgress = 1;
int		gPasswordTimeout = 0;

int		gPlatformLocked = 0;
int		gTPMLocked = 0;
int		gTPMLockedInfoDelay = 9;
int		gSCLocked = 0;


//////////////////////////////////////////////////////////////////////////
// Picture password
//////////////////////////////////////////////////////////////////////////
CONST CHAR16* BmpName = L"Test.bmp";
VOID*		gPictPwdBmp = NULL;
UINTN		gPictPwdBmpSize = 0;
BLT_HEADER*	bltPwd = NULL;
UINTN		   posPictX, posPictY;
BLT_HEADER*	bltScrn = NULL;
UINTN*		cellSelected = NULL;
UINTN			picPwdIdx = 0;
UINTN			sHeight;
UINTN			sWidth;
UINTN			step;

DRAW_CONTEXT ctxCursor;
DRAW_CONTEXT ctxCell;
DRAW_CONTEXT ctxMark;
DRAW_CONTEXT ctxSet;

VOID
CellUpdate(
	IN OUT BLT_HEADER*	blt,
	IN UINTN		x,
	IN UINTN		y,
	IN BOOLEAN  selected) {
	if (selected && gPasswordShowMark && gPasswordHideLetters) {
		BltCircle(blt, &ctxMark, (INT32)(x * step + step / 2), (INT32)(y * step + step / 2), (INT32)(step / 3), TRUE);
		BltCircle(blt, &ctxCell, (INT32)(x * step + step / 2), (INT32)(y * step + step / 2), (INT32)(step / 9), TRUE);
	}
	else {
		CHAR8	ch[2] = { 0,0 };
		BltCircle(blt, &ctxCell, (INT32)(x * step + step / 2), (INT32)(y * step + step / 2), (INT32)(step / 3), FALSE);
		if (gPasswordVisible || !gPasswordHideLetters) {
			ch[0] = gPasswordPictureChars[(x + blt->Width / step * y) % gPasswordPictureCharsLen];
			BltText(blt, &ctxCell, (INT32)(x * step + step / 2 - 12), (INT32)(y * step + step / 2 - 12), 256, ch, FALSE);
		}
	}
}

BOOLEAN
CellGetSelected(
	IN OUT BLT_HEADER*	blt,
	IN UINTN		x,
	IN UINTN		y,
	OUT UINTN*	cellX,
	OUT UINTN*	cellY) {
	RECT	reg;
	UINTN	sen;
	if (x > blt->Width || y > blt->Height) return FALSE;
	*cellX = x / step;
	*cellY = y / step;
	sen = step / 5;	// zone sensible
	reg.left = (UINT32)(*cellX * step + step / 2 - sen);
	reg.right = (UINT32)(*cellX * step + step / 2 + sen);
	reg.top = (UINT32)(*cellY * step + step / 2 - sen);
	reg.bottom = (UINT32)(*cellY * step + step / 2 + sen);
	return (x > reg.left && x < reg.right && y > reg.top && y < reg.bottom);
}

VOID
DrawCursor(IN OUT BLT_HEADER*	blt,
	IN UINTN		x,
	IN UINTN		y
	) {
	BltLine(blt, &ctxCursor, (INT32)(x - 10), (INT32)y, (INT32)(x + 10), (INT32)y);
	BltLine(blt, &ctxCursor, (INT32)x, (INT32)(y - 10), (INT32)x, (INT32)(y + 10));
}

typedef struct _TOUCH_ZONE {
	UINTN		Zone;
	CHAR8*	Message;
	UINTN		RetCode;
	INT32		TextScale;
} TOUCH_ZONE, *PTOUCH_ZONE;

enum TouchZoneIds {
	tznLogin = 1,
	tznBeep,
	tznShow,
	tznChange
};

CHAR8*	msgLogin = "LOGIN";
CHAR8*	msgBeepOn = "Beep\non";
CHAR8*	msgBeepOff = "Beep\noff";
CHAR8*	msgChg = "Change\npwd";
CHAR8*	msgShowPwd = "Show\npwd";
CHAR8*	msgHidePwd = "Hide\npwd";
CHAR8*	msgNewPwd = "New\npwd";
CHAR8*	msgConfirmPwd = "Confirm\npwd";
CHAR8*	msgPlatformLocked = "PLT\nlkd";
CHAR8*	msgPlatformUnLocked = "PLT\nunlkd";
CHAR8*	msgTpmLocked = "TPM\nlkd";
CHAR8*	msgTpmUnLocked = "TPM\nunlkd";
CHAR8*	msgSCLocked = "SC\nlkd";
CHAR8*	msgSCUnLocked = "SC\nunlkd";

TOUCH_ZONE	TZN_Login = { 0, NULL, tznLogin, 128 };
TOUCH_ZONE	TZN_Speaker = { 2, NULL, tznBeep, 64 };
TOUCH_ZONE	TZN_Show = { 3, NULL, tznShow, 64 };
TOUCH_ZONE	TZN_Change = { 5, NULL, tznChange, 32 };
TOUCH_ZONE	TZN_Platform = { 6, NULL, 0, 32 };
TOUCH_ZONE	TZN_Tpm = { 7, NULL, 0, 32 };
TOUCH_ZONE	TZN_SC = { 8, NULL, 0, 32 };

VOID
DrawTouchZone(
	IN PTOUCH_ZONE zone
	) {
	BltFill(bltScrn, gColorBlack, (INT32)(sWidth - step), (INT32)(2 + zone->Zone * step), (INT32)(INT32)(sWidth - 2), (INT32)(step + zone->Zone * step));
	BltBox(bltScrn, &ctxCell, (INT32)(sWidth - step), (INT32)(2 + zone->Zone * step), (INT32)(INT32)(sWidth - 2), (INT32)(step + zone->Zone * step));
	BltText(bltScrn, &ctxCell, (INT32)(sWidth - step * 3 / 4), (INT32)(step * 1 / 3 + zone->Zone * step), 128, zone->Message, FALSE);
}

BOOLEAN
IsTouchZone(
	IN PTOUCH_ZONE zone,
	IN UINTN		   x,
	IN UINTN		   y
	) {
	if (x > sWidth - step &&
		(y > (zone->Zone * step)) &&
		(y < (step + zone->Zone * step))) {
		return TRUE;
	}
	return FALSE;
}

VOID
DrawPwdZone(
	IN CHAR8*	pwd, 
	IN UINT32   pwdMax,
	IN BOOLEAN  wide) 
{
	INT32 pwdGrphMaxLen = (INT32)(sWidth - 2 * step);
	BltFill(bltScrn, gColorBlack, 0, 0, (INT32)(sWidth - 2 * step), (INT32)(posPictY));
	if (gPasswordProgress || gPasswordVisible) {
		if (gPasswordVisible) {
			BltText(bltScrn, &ctxCell, 0, 0, 256, pwd, wide);
		}
		else {
			INT32 pwdGrphLen = (INT32)(pwdGrphMaxLen * picPwdIdx / pwdMax);
			INT32 pwdGrphHeight = (INT32)(posPictY) / 2;
			INT32 pwdGrphTop = (INT32)(posPictY) / 4;
			BltFill(bltScrn, gColorGreen, 0, pwdGrphTop, pwdGrphLen, pwdGrphHeight + pwdGrphTop);
			BltFill(bltScrn, gColorBlack, pwdGrphLen, pwdGrphTop, pwdGrphMaxLen, pwdGrphHeight + pwdGrphTop);
		}
	}
}

EFI_STATUS
DrawPwdPicture()
{
	EFI_STATUS   res;
	UINTN		    idx;
	UINTN		    cellX, cellY;

	if (bltPwd != NULL) MEM_FREE(bltPwd);

	res = BmpToBlt(gPictPwdBmp, gPictPwdBmpSize, &bltPwd);
	if (EFI_ERROR(res)) {
		return res;
	}
	cellY = 0;
	do {
		cellX = 0;
		do {
			CellUpdate(bltPwd, cellX, cellY, FALSE);
			cellX++;
		} while ((cellX + 1) * step <= (bltPwd->Width));
		cellY++;
	} while ((cellY + 1)* step <= (bltPwd->Height));

	// Update selected
	for (idx = 0; idx < picPwdIdx; ++idx) {
		if (cellSelected[idx * 2] != MAX_INTN) {
			CellUpdate(bltPwd, cellSelected[idx * 2], cellSelected[idx * 2 + 1], TRUE);
		}
	}
	return EFI_SUCCESS;
}

VOID
CreateDraws() {
	// Set
	ctxSet.Color = gColorGray;
	ctxSet.DashLine = 0xFFFFFFFF;
	ctxSet.Op = DrawOpSet;
	ctxSet.Brush = NULL;

	// Cursor
	ctxCursor.Color = gColorWhite;
	ctxCursor.DashLine = 0xFFFFFFFF;
	ctxCursor.Op = DrawOpXor;
	ctxCursor.Brush = NULL;

	// Cell
	ctxCell.Color = gColorGreen;
	ctxCell.DashLine = 0xFFFFFFFF;
	ctxCell.Op = DrawOpSet;
	ctxCell.Brush = gBrush3;

	// Shade (close to black)
	ctxMark.AlphaColor = gColorWhite;
	ctxMark.Alpha = 128;
	ctxMark.Op = DrawOpAlpha;
	ctxMark.Brush = NULL;
}

enum PictPwdAction {
	PwdActNone = 0,
	PwdActLogin,
	PwdActCancel,
	PwdActChange,
	PwdActShow,
	PwdActBeep,
	PwdActNewChar,
	PwdActUpdateZones,
};

VOID
AskPictPwdInt(
	IN  UINTN	pwdType,
	IN  UINTN	pwdMax,
	OUT VOID*	pwd,
	OUT UINT32*	pwdLen,
	OUT INT32*	retCode,
	IN  BOOLEAN wide
	) {
	EFI_STATUS	res;
	UINTN		   cellX, cellY;
	UINTN		   cellPrevX, cellPrevY;
	UINTN		   curX, curY;
	UINTN		   curPrevX, curPrevY;
	EFI_INPUT_KEY key;
	EFI_EVENT      UpdateEvent;
	EFI_EVENT      BeepOffEvent;
	EFI_EVENT      InputEvents[3];
	UINTN          EventIndex = 0;
	UINTN          eventsCount = 2;
	EFI_ABSOLUTE_POINTER_STATE		aps = {0};
	BOOLEAN        showCursor = FALSE;
	BOOLEAN        beepOn = FALSE;
	UINTN          pwdAction = PwdActNone;
	CHAR8          pwdNewChar = 0;
	if (wide)
		pwdMax /= 2;

	if (gPasswordTimeout) {
		InputEvents[0] = gST->ConIn->WaitForKey;
		eventsCount = 2;
		if (gTouchPointer != NULL) {
			eventsCount = 3;
			InputEvents[2] = gTouchPointer->WaitForInput;
		}
		gBS->CreateEvent(EVT_TIMER, 0, (EFI_EVENT_NOTIFY)NULL, NULL, &InputEvents[1]);
		gBS->SetTimer(InputEvents[1], TimerPeriodic, MultU64x32(10000000ULL, (UINT32)gPasswordTimeout));
		gBS->WaitForEvent(eventsCount, InputEvents, &EventIndex);
		gPasswordTimeout = 0;
		gBS->CloseEvent(InputEvents[1]);
		if (EventIndex == 1) {
			*retCode = AskPwdRetCancel;
			return;
		}
	}

	InitConsoleControl();
	if (gBeepEnabled) {
		InitSpeaker();
	}

	if (gPictPwdBmp == NULL) {
		if (gPasswordPictureFileName != NULL) {
			res = FileLoad(NULL, (CHAR16*)gPasswordPictureFileName, &gPictPwdBmp, &gPictPwdBmpSize);
			if (EFI_ERROR(res)) {
				ERR_PRINT(L"File load - %r\n", res);
				return;
			}
		}	else {
			ERR_PRINT(L"Picture file name undefined\n");
			return;
		}
	}
	// Init draws
	CreateDraws();

	// Init screen
	if (bltScrn != NULL) MEM_FREE(bltScrn);
	if (EFI_ERROR(ScreenSaveBlt(&bltScrn)) || bltScrn == NULL) {
		ERR_PRINT(L"Cannot save screen\n");
		*retCode = AskPwdRetCancel;
		return;
	}
	sWidth = bltScrn->Width;
	sHeight = bltScrn->Height;
	step = sWidth >> 4;

	// Init picture password
	picPwdIdx = 0;
	res = DrawPwdPicture();
	if (EFI_ERROR(res)) {
		MEM_FREE(bltScrn);
		ERR_PRINT(L"BmpToBlt - %r", res);
		return;
	}

	// Touch zones
	switch (pwdType) {
	case AskPwdConfirm:
		TZN_Login.Message = msgConfirmPwd;
		break;
	case AskPwdNew:
		TZN_Login.Message = msgNewPwd;
		break;
	case AskPwdLogin:
	default:
		TZN_Login.Message = msgLogin;
	}
	DrawTouchZone(&TZN_Login);

	if (pwdType == AskPwdLogin) {
		TZN_Change.Message = msgChg;
		DrawTouchZone(&TZN_Change);
	}

	if (gBeepControlEnabled) {
		TZN_Speaker.Message = gBeepEnabled ? msgBeepOff : msgBeepOn;
		DrawTouchZone(&TZN_Speaker);
	}

	TZN_Platform.Message = gPlatformLocked? msgPlatformLocked : msgPlatformUnLocked;
	DrawTouchZone(&TZN_Platform);

	TZN_Tpm.Message = gTPMLocked ? msgTpmLocked : msgTpmUnLocked;
	DrawTouchZone(&TZN_Tpm);

	TZN_SC.Message = gSCLocked ? msgSCLocked : msgSCUnLocked;
	DrawTouchZone(&TZN_SC);

	TZN_Show.Message = gPasswordVisible ? msgHidePwd : msgShowPwd;
	DrawTouchZone(&TZN_Show);
	cellSelected = MEM_ALLOC(sizeof(UINTN) * 2 * (pwdMax + 1));

	ScreenUpdateDirty(bltScrn);

	// Prepare cursors
	posPictX = (sWidth - bltPwd->Width) >> 1;
	posPictY = (sHeight - bltPwd->Height) >> 1;
	cellPrevX = MAX_INTN;
	cellPrevY = MAX_INTN;
	curX = sWidth / 2;
	curY = posPictY / 2;
	BltDrawBlt(bltScrn, bltPwd, posPictX, posPictY);

	// Prepare events
	InputEvents[0] = gST->ConIn->WaitForKey;
	gBS->CreateEvent(EVT_TIMER, 0, (EFI_EVENT_NOTIFY)NULL, NULL, &InputEvents[1]);
	gBS->CreateEvent(EVT_TIMER, 0, (EFI_EVENT_NOTIFY)NULL, NULL, &BeepOffEvent);
	gBS->CreateEvent(EVT_TIMER, 0, (EFI_EVENT_NOTIFY)NULL, NULL, &UpdateEvent);
	gBS->SetTimer(UpdateEvent, TimerRelative, 500000);			// 20 times per second to update
	gBS->SetTimer(BeepOffEvent, TimerRelative, gBeepDurationDefault * 10);
	gBS->SetTimer(InputEvents[1], TimerRelative, 5000000);

	if (gTouchPointer != NULL) {
		eventsCount = 3;
		InputEvents[2] = gTouchPointer->WaitForInput;
		while (gBS->CheckEvent(InputEvents[2]) == EFI_SUCCESS) {
			gTouchPointer->GetState(gTouchPointer, &aps);
		}
	}
	while (gBS->CheckEvent(InputEvents[0]) == EFI_SUCCESS) {
		gST->ConIn->ReadKeyStroke(gST->ConIn, &key);
	}
	do
	{
		curPrevX = curX;
		curPrevY = curY;
		ZeroMem(&key, sizeof(key));
		res = gBS->WaitForEvent(eventsCount, InputEvents, &EventIndex);
		if (EventIndex == 0) {
			res = gST->ConIn->ReadKeyStroke(gST->ConIn, &key);
			if (EFI_ERROR(res)) {
				continue;
			}
		}
		// OUT_PRINT(L" \r%05d %05d", (UINT32)curX, (UINT32)curY, );
		// recharge timeout event and stop beep
		if (gBeepControlEnabled && gBeepEnabled && beepOn) {
			if (gBS->CheckEvent(BeepOffEvent) == EFI_SUCCESS) {
				beepOn = FALSE;
				SpeakerBeep((UINT16)gBeepToneDefault, 0, 0, 0);
				gBS->SetTimer(InputEvents[1], TimerRelative, 5000000);
			}
		}
		else {
			gBS->SetTimer(InputEvents[1], TimerRelative, 5000000);
		}

		// hide cursor
		if (showCursor && EventIndex != 1) {
			DrawCursor(bltScrn, curX, curY);
			showCursor = FALSE;
		}

		// Blink cursor
		if (EventIndex == 1) {
			DrawCursor(bltScrn, curX, curY);
			showCursor = !showCursor;
		}

		if (EventIndex == 0) {
//			gST->ConIn->ReadKeyStroke(gST->ConIn, &key);
			// OUT_PRINT(L" %04x, %04x\r", key.ScanCode, key.UnicodeChar);
			// Remove dirty chars 0.1s
			FlushInputDelay(100000);
			switch (key.ScanCode)
			{
			case SCAN_HOME:
				curX -= gTouchSimulateStep;
				curY -= gTouchSimulateStep;
				break;
			case SCAN_LEFT:
				curX -= gTouchSimulateStep;
				break;
			case SCAN_END:
				curX -= gTouchSimulateStep;
				curY += gTouchSimulateStep;
				break;
			case SCAN_DOWN:
				curY += gTouchSimulateStep;
				break;
			case SCAN_PAGE_DOWN:
				curX += gTouchSimulateStep;
				curY += gTouchSimulateStep;
				break;
			case SCAN_RIGHT:
				curX += gTouchSimulateStep;
				break;
			case SCAN_PAGE_UP:
				curX += gTouchSimulateStep;
				curY -= gTouchSimulateStep;
				break;
			case SCAN_UP:
				curY -= gTouchSimulateStep;
				break;
			case SCAN_F11:
				if (gTouchSimulateStep > 1)
					gTouchSimulateStep--;
				break;
			case SCAN_F12:
				gTouchSimulateStep++;
				break;
			case SCAN_ESC:
				pwdAction = PwdActCancel;
				break;
			case SCAN_F2:
				if (pwdType == AskPwdLogin) {
					pwdAction = PwdActChange;
				}
				break;
			case SCAN_F4:
				if (gBeepControlEnabled) {
					pwdAction = PwdActBeep;
				}
				break;
			case SCAN_F5:
				pwdAction = PwdActShow;
				break;
			case SCAN_F7:
				gPlatformLocked = gPlatformLocked ? 0 : 1;
				pwdAction = PwdActUpdateZones;
				break;
			case SCAN_F8:
				gTPMLocked = gTPMLocked ? 0 : 1;
				pwdAction = PwdActUpdateZones;
				break;
			case SCAN_F9:
				gSCLocked = gSCLocked ? 0 : 1;
				pwdAction = PwdActUpdateZones;
				break;
			default:
				;
			}

			if (key.UnicodeChar != 0) {
				if (key.UnicodeChar == 0x0d) {
					pwdAction = PwdActLogin;
				}
				else {
					pwdNewChar = (CHAR8)key.UnicodeChar;
					pwdAction = PwdActNewChar;
					cellSelected[picPwdIdx * 2] = MAX_INTN;
				}
			}

		}

		if (EventIndex == 2) {
			res = gTouchPointer->GetState(gTouchPointer, &aps);
			if (!EFI_ERROR(res)) {
				curX = (UINTN)(aps.CurrentX * sWidth / (gTouchPointer->Mode->AbsoluteMaxX - gTouchPointer->Mode->AbsoluteMinX));
				curY = (UINTN)(aps.CurrentY * sHeight / (gTouchPointer->Mode->AbsoluteMaxY - gTouchPointer->Mode->AbsoluteMinY));
			}
		}

		if (curX > sWidth) curX = sWidth;
		if (curY > sHeight) curY = sHeight;

		// Cell check
		if (CellGetSelected(bltPwd, curX - posPictX, curY - posPictY, &cellX, &cellY) && picPwdIdx < pwdMax) {
			if (cellPrevX != cellX || cellPrevY != cellY) {
				cellPrevX = cellX;
				cellPrevY = cellY;
				cellSelected[picPwdIdx * 2] = cellX;
				cellSelected[picPwdIdx * 2 + 1] = cellY;
				CellUpdate(bltPwd, cellX, cellY, TRUE);
				BltDrawBlt(bltScrn, bltPwd, posPictX, posPictY);
				pwdAction = PwdActNewChar;
				pwdNewChar = gPasswordPictureChars[(cellX + bltPwd->Width / step * cellY) % gPasswordPictureCharsLen];
			}
			else if (EventIndex == 2 && aps.ActiveButtons == 0) {
				cellPrevX = MAX_INTN;
				cellPrevY = MAX_INTN;
				curX = posPictX + cellX * step;
				curY = posPictY + cellY * step;
				while (gBS->CheckEvent(InputEvents[2]) == EFI_SUCCESS) {
					gTouchPointer->GetState(gTouchPointer, &aps);
				}
			}
		}

		if (pwdAction == PwdActNone) {
			if (IsTouchZone(&TZN_Login, curX, curY)) {
				pwdAction = PwdActLogin;
			}

			if (pwdType == AskPwdLogin && IsTouchZone(&TZN_Change, curX, curY)) {
				pwdAction = PwdActChange;
			}

			if (curPrevX != curX || curPrevY != curY) {
				if (gSpeakerCount > 0 && IsTouchZone(&TZN_Speaker, curX, curY)) {
					pwdAction = PwdActBeep;
				}
				if (IsTouchZone(&TZN_Show, curX, curY)) {
					pwdAction = PwdActShow;
				}
				if (IsTouchZone(&TZN_Tpm, curX, curY)) {
					gTPMLocked = gTPMLocked ? 0 : 1;
					pwdAction = PwdActUpdateZones;
				}
				if (IsTouchZone(&TZN_Platform, curX, curY)) {
					gPlatformLocked = gPlatformLocked ? 0 : 1;
					pwdAction = PwdActUpdateZones;
				}
				if (IsTouchZone(&TZN_SC, curX, curY)) {
					gSCLocked = gSCLocked ? 0 : 1;
					pwdAction = PwdActUpdateZones;
				}
			}
		}

		if (PwdActNewChar == pwdAction) {
			BOOLEAN bUpdPwdZone = FALSE;
			if (pwdNewChar == '\b' && picPwdIdx > 0) {
				picPwdIdx--;
				SET_VAR_CHAR(pwd, wide, picPwdIdx, 0); //pwd[picPwdIdx] = 0;
				bUpdPwdZone = TRUE;
			} else if ((picPwdIdx < pwdMax - 1) && (pwdNewChar >= 32)) {
				SET_VAR_CHAR(pwd, wide, picPwdIdx++, pwdNewChar); //pwd[picPwdIdx++] = pwdNewChar;
				SET_VAR_CHAR(pwd, wide, picPwdIdx, 0); //pwd[picPwdIdx] = 0;
				bUpdPwdZone = TRUE;
			}
			if(bUpdPwdZone) {
				*pwdLen = (int)picPwdIdx;
				if (wide)
					*pwdLen *= 2;
				DrawPwdZone(pwd, (INT32)pwdMax, wide);
				if (gBeepControlEnabled && gBeepEnabled) {
					SpeakerBeep((UINT16)gBeepToneDefault, gBeepNumberDefault, 0, 0);
					gBS->SetTimer(BeepOffEvent, TimerRelative, gBeepDurationDefault * 10);
					gBS->SetTimer(InputEvents[1], TimerRelative, gBeepDurationDefault * 10);
					beepOn = TRUE;
				}
			}
		}
		else if (PwdActBeep == pwdAction && gBeepControlEnabled) {
			if (gBeepEnabled && beepOn) {
				beepOn = FALSE;
				SpeakerBeep((UINT16)gBeepToneDefault, 0, 0, 0);
			}
			gBeepEnabled = gBeepEnabled ? 0 : 1;
			TZN_Speaker.Message = gBeepEnabled ? msgBeepOff : msgBeepOn;
			DrawTouchZone(&TZN_Speaker);
		}
		else if (PwdActShow == pwdAction) {
			gPasswordVisible = gPasswordVisible ? 0 : 1;
			DrawPwdZone(pwd, (INT32)pwdMax, wide);
			DrawPwdPicture();
			BltDrawBlt(bltScrn, bltPwd, posPictX, posPictY);
			TZN_Show.Message = gPasswordVisible ? msgHidePwd : msgShowPwd;
			DrawTouchZone(&TZN_Show);
		}
		else if (PwdActLogin == pwdAction) {
			*retCode = AskPwdRetLogin;
			break;
		}
		else if (pwdType == AskPwdLogin && PwdActChange == pwdAction) {
			*retCode = AskPwdRetChange;
			break;
		}
		else if (PwdActCancel == pwdAction){
			*retCode = AskPwdRetCancel;
			break;
		}
		else if (PwdActUpdateZones == pwdAction) {
			TZN_Platform.Message = gPlatformLocked ? msgPlatformLocked : msgPlatformUnLocked;
			DrawTouchZone(&TZN_Platform);

			TZN_Tpm.Message = gTPMLocked ? msgTpmLocked : msgTpmUnLocked;
			DrawTouchZone(&TZN_Tpm);

			TZN_SC.Message = gSCLocked ? msgSCLocked : msgSCUnLocked;
			DrawTouchZone(&TZN_SC);
		}

		if ((curPrevX != curX || curPrevY != curY) && (EventIndex != 2)) {
			DrawCursor(bltScrn, curX, curY);
			showCursor = TRUE;
		}
		// Time to update screen?
		if (gBS->CheckEvent(UpdateEvent) == EFI_SUCCESS) {
			ScreenUpdateDirty(bltScrn);
			gBS->SetTimer(UpdateEvent, TimerRelative, 500000);			// 20 times per second to update
		}

		pwdAction = PwdActNone;
	} while (TRUE);
	MEM_BURN (&key, sizeof (key));
	MEM_BURN (&pwdNewChar, sizeof (pwdNewChar));
	gBS->CloseEvent(InputEvents[1]);
	gBS->CloseEvent(UpdateEvent);
	gBS->CloseEvent(BeepOffEvent);
	ScreenFillRect(&gColorBlack, 0, 0, sWidth, sHeight);
	gBS->Stall(500000);
}
