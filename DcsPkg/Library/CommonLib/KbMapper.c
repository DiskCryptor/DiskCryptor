/** @file
EFI keyboard layout mapper

Copyright (c) 2019. DiskCryptor, David Xanatos

This program and the accompanying materials are licensed and made available
under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Library/CommonLib.h>
#include <Protocol/SimpleTextInEx.h>

int gKeyboardLayout = 0;

CHAR16 to_qwertz(CHAR16 c)
{
	switch (c) {
		case L'y': return L'z';
		case L'Y': return L'Z';
		case L'z': return L'y';
		case L'Z': return L'Y';
	}
	return c;
}

// French AZERTY as Windows types it, from the US characters the firmware reports.
// The numeric keypad arrives as the digit row, so it types what the digit row does (& e-acute "...).
CHAR16 to_azerty(CHAR16 c)
{
	switch (c) {
		// letters
		case L'q': return L'a';
		case L'Q': return L'A';
		case L'a': return L'q';
		case L'A': return L'Q';
		case L'w': return L'z';
		case L'W': return L'Z';
		case L'z': return L'w';
		case L'Z': return L'W';
		case L';': return L'm';
		case L':': return L'M';
		case L'm': return L',';
		case L'M': return L'?';
		// digit row: the symbols unshifted, the digits with Shift
		case L'`': return 0x00B2;   // superscript two
		case L'~': return 0;        // Shift + superscript-two key types nothing
		case L'1': return L'&';
		case L'!': return L'1';
		case L'2': return 0x00E9;   // e acute
		case L'@': return L'2';
		case L'3': return L'"';
		case L'#': return L'3';
		case L'4': return L'\'';
		case L'$': return L'4';
		case L'5': return L'(';
		case L'%': return L'5';
		case L'6': return L'-';
		case L'^': return L'6';
		case L'7': return 0x00E8;   // e grave
		case L'&': return L'7';
		case L'8': return L'_';
		case L'*': return L'8';
		case L'9': return 0x00E7;   // c cedilla
		case L'(': return L'9';
		case L'0': return 0x00E0;   // a grave
		case L')': return L'0';
		case L'-': return L')';
		case L'_': return 0x00B0;   // degree sign
		// '=' and '+' are the same on both layouts
		// top letter row, right end
		case L'[': return L'^';     // dead key (KbComposeDeadKey)
		case L'{': return 0x00A8;   // diaeresis, dead key
		case L']': return L'$';
		case L'}': return 0x00A3;   // pound sign
		// home row, right end
		case L'\'': return 0x00F9;  // u grave
		case L'"': return L'%';
		case L'\\': return L'*';
		case L'|': return 0x00B5;   // micro sign
		// bottom row, right end
		case L',': return L';';
		case L'<': return L'.';
		case L'.': return L':';
		case L'>': return L'/';
		case L'/': return L'!';
		case L'?': return 0x00A7;   // section sign
	}
	return c;
}

// The AltGr layer of French AZERTY (Right Alt, or Ctrl+Alt as on Windows), by the US
// character of the key. 0: the key has no AltGr character. '~' (AltGr+2) and '`' (AltGr+7) are dead
// keys, as on Windows.
STATIC
CHAR16
to_azerty_altgr(CHAR16 c)
{
	switch (c) {
		case L'2': return L'~';
		case L'3': return L'#';
		case L'4': return L'{';
		case L'5': return L'[';
		case L'6': return L'|';
		case L'7': return L'`';
		case L'8': return L'\\';
		case L'9': return L'^';
		case L'0': return L'@';
		case L'-': return L']';
		case L'=': return L'}';
		case L'e':
		case L'E': return 0x20AC;   // euro sign
		case L']': return 0x00A4;   // currency sign
	}
	return 0;
}

// Caps Lock as Windows French applies it. The firmware already flips the case of US
// letters; on AZERTY that is right for the letter keys, but the comma key (US 'm') must not change
// and the M key (US ';') must. Caps Lock also acts as Shift on the digit row.
STATIC
CHAR16
azerty_caps_lock(CHAR16 c)
{
	STATIC CONST CHAR16 Plain[]   = { L'1', L'2', L'3', L'4', L'5', L'6', L'7', L'8', L'9', L'0' };
	STATIC CONST CHAR16 Shifted[] = { L'!', L'@', L'#', L'$', L'%', L'^', L'&', L'*', L'(', L')' };
	UINTN i;

	switch (c) {
		case L'm': return L'M';   // undo the firmware's flip: the comma key ignores Caps Lock
		case L'M': return L'm';
		case L';': return L':';   // the M key follows Caps Lock
		case L':': return L';';
	}
	for (i = 0; i < sizeof(Plain) / sizeof(Plain[0]); i++) {
		if (c == Plain[i]) return Shifted[i];
		if (c == Shifted[i]) return Plain[i];
	}
	return c;
}

/**
  Map a key from the US layout the firmware reports to the configured layout.

  @param[in]  key          The key as read.
  @param[in]  ShiftState   EFI_KEY_STATE.KeyShiftState from ReadKeyStrokeEx, or 0 if unknown
                           (then AltGr characters cannot be typed).
  @param[in]  ToggleState  EFI_KEY_STATE.KeyToggleState, or 0 if unknown (Caps Lock then only
                           acts as the firmware applies it).
  @param[out] DeadKey      Optional: TRUE if the key is an AZERTY dead key (^, diaeresis, and with
                           AltGr ~ and `), whose character combines with the next key (KbComposeDeadKey).
**/
EFI_INPUT_KEY
MapKeyboardKeyEx(
	IN  EFI_INPUT_KEY  key,
	IN  UINT32         ShiftState,
	IN  UINT8          ToggleState,
	OUT BOOLEAN        *DeadKey OPTIONAL
	)
{
	BOOLEAN altGr = FALSE;

	if (DeadKey != NULL) {
		*DeadKey = FALSE;
	}
	if ((ShiftState & EFI_SHIFT_STATE_VALID) != 0) {
		BOOLEAN alt  = (ShiftState & (EFI_LEFT_ALT_PRESSED | EFI_RIGHT_ALT_PRESSED)) != 0;
		BOOLEAN ctrl = (ShiftState & (EFI_LEFT_CONTROL_PRESSED | EFI_RIGHT_CONTROL_PRESSED)) != 0;
		altGr = ((ShiftState & EFI_RIGHT_ALT_PRESSED) != 0) || (alt && ctrl);
	}

	switch (gKeyboardLayout)
	{
	case KB_MAP_QWERTZ: key.UnicodeChar = to_qwertz(key.UnicodeChar); break;
	case KB_MAP_AZERTY:
		if (key.UnicodeChar == 0) {
			break;
		}
		if (altGr) {
			CHAR16 c = key.UnicodeChar;
			if (c >= 1 && c <= 26) {
				c = (CHAR16)(L'a' + c - 1);   // a Ctrl+letter control code
			}
			if (DeadKey != NULL && (c == L'2' || c == L'7')) {
				*DeadKey = TRUE;              // tilde and grave
			}
			key.UnicodeChar = to_azerty_altgr(c);
			break;
		}
		if ((ToggleState & EFI_TOGGLE_STATE_VALID) != 0 && (ToggleState & EFI_CAPS_LOCK_ACTIVE) != 0) {
			key.UnicodeChar = azerty_caps_lock(key.UnicodeChar);
		}
		if (DeadKey != NULL && (key.UnicodeChar == L'[' || key.UnicodeChar == L'{')) {
			*DeadKey = TRUE;
		}
		key.UnicodeChar = to_azerty(key.UnicodeChar);
		break;
	}
	return key;
}

EFI_INPUT_KEY MapKeyboardKey(EFI_INPUT_KEY key)
{
	return MapKeyboardKeyEx(key, 0, 0, NULL);
}

/**
  Compose an AZERTY dead key with the next character, as Windows does: a letter that
  takes the accent gets it, Space types the dead key's own character. 0: no composition (Windows
  then types both).
**/
CHAR16
KbComposeDeadKey(
	IN CHAR16  Dead,
	IN CHAR16  Next
	)
{
	STATIC CONST CHAR16 Base[]       = { L'a', L'e', L'i', L'o', L'u', L'y', L'n', L'A', L'E', L'I', L'O', L'U', L'N' };
	STATIC CONST CHAR16 Circumflex[] = { 0x00E2, 0x00EA, 0x00EE, 0x00F4, 0x00FB, 0,      0,      0x00C2, 0x00CA, 0x00CE, 0x00D4, 0x00DB, 0 };
	STATIC CONST CHAR16 Diaeresis[]  = { 0x00E4, 0x00EB, 0x00EF, 0x00F6, 0x00FC, 0x00FF, 0,      0x00C4, 0x00CB, 0x00CF, 0x00D6, 0x00DC, 0 };
	STATIC CONST CHAR16 Tilde[]      = { 0x00E3, 0,      0,      0x00F5, 0,      0,      0x00F1, 0x00C3, 0,      0,      0x00D5, 0,      0x00D1 };
	STATIC CONST CHAR16 Grave[]      = { 0x00E0, 0x00E8, 0x00EC, 0x00F2, 0x00F9, 0,      0,      0x00C0, 0x00C8, 0x00CC, 0x00D2, 0x00D9, 0 };
	UINTN i;

	if (Next == L' ') {
		return Dead;
	}
	for (i = 0; i < sizeof(Base) / sizeof(Base[0]); i++) {
		if (Base[i] == Next) {
			switch (Dead) {
				case L'^':   return Circumflex[i];
				case 0x00A8: return Diaeresis[i];
				case L'~':   return Tilde[i];
				case L'`':   return Grave[i];
			}
			return 0;
		}
	}
	return 0;
}
