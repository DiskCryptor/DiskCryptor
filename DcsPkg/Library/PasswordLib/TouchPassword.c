/** @file
Touch keyboard password input

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI
Copyright (c) 2019. DiskCryptor, David Xanatos

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
#include <Library/PrintLib.h>

#include <Library/CommonLib.h>
#include <Library/GraphLib.h>
#include <Library/PasswordLib.h>

//////////////////////////////////////////////////////////////////////////
// Touch Keyboard Layout Definitions
//////////////////////////////////////////////////////////////////////////

// Key types
#define KEY_TYPE_CHAR      0   // Regular character key
#define KEY_TYPE_SHIFT     1   // Shift modifier
#define KEY_TYPE_CAPS      2   // Caps Lock
#define KEY_TYPE_ALTGR     3   // AltGr modifier
#define KEY_TYPE_BACKSPACE 4   // Backspace
#define KEY_TYPE_ENTER     5   // Enter/Login
#define KEY_TYPE_SPACE     6   // Space bar
#define KEY_TYPE_TAB       7   // Tab
#define KEY_TYPE_FN        8   // Function key (F1-F12)
#define KEY_TYPE_ESC       9   // Escape
#define KEY_TYPE_ARROW_L   10  // Left arrow
#define KEY_TYPE_ARROW_R   11  // Right arrow
#define KEY_TYPE_DELETE    12  // Delete
#define KEY_TYPE_INSERT    13  // Insert (inserts space)
#define KEY_TYPE_ARROW_U   14  // Up arrow
#define KEY_TYPE_ARROW_D   15  // Down arrow

typedef struct _TOUCH_KEY {
	CHAR8    Label[8];       // Display label
	CHAR8    Normal;         // Normal character
	CHAR8    Shifted;        // Shifted character
	CHAR8    AltGr;          // AltGr character (for special chars)
	UINT8    Type;           // Key type
	UINT8    Width;          // Key width multiplier (1 = standard, 2 = double, etc.)
	UINT16   ScanCode;       // Scan code for function keys
} TOUCH_KEY;

typedef struct _KEY_BUTTON {
	INT32    X;
	INT32    Y;
	INT32    Width;
	INT32    Height;
	TOUCH_KEY* Key;
	BOOLEAN  Pressed;
} KEY_BUTTON;

//////////////////////////////////////////////////////////////////////////
// Toolbar/Layout bar button types
//////////////////////////////////////////////////////////////////////////
#define TOOLBAR_BTN_SHOW         0

#define LAYOUTBAR_BTN_PREV       0
#define LAYOUTBAR_BTN_NEXT       1

typedef struct _TOOLBAR_BUTTON {
	INT32    X;
	INT32    Y;
	INT32    Width;
	INT32    Height;
	UINT8    Type;
	CHAR8    Label[16];
	BOOLEAN  Pressed;
} TOOLBAR_BUTTON;

//////////////////////////////////////////////////////////////////////////
// Layout names
//////////////////////////////////////////////////////////////////////////
static CHAR8* gLayoutNames[] = {
	"QWERTY",   // KB_MAP_QWERTY = 0
	"QWERTZ",   // KB_MAP_QWERTZ = 1
	"AZERTY"    // KB_MAP_AZERTY = 2
};
#define LAYOUT_COUNT 3

//////////////////////////////////////////////////////////////////////////
// Status area configuration
//////////////////////////////////////////////////////////////////////////
#define STATUS_BUFFER_SIZE 2048  // Large buffer for multi-line status text

//////////////////////////////////////////////////////////////////////////
// QWERTY Layout
//////////////////////////////////////////////////////////////////////////
static TOUCH_KEY gQwertyRow0[] = {
	{"Esc",  0,    0,   0,   KEY_TYPE_ESC,    1, SCAN_ESC},
	{"F1",   0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F1},
	{"F2",   0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F2},
	{"F3",   0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F3},
	{"F4",   0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F4},
	{"F5",   0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F5},
	{"F6",   0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F6},
	{"F7",   0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F7},
	{"F8",   0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F8},
	{"F9",   0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F9},
	{"F10",  0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F10},
	{"F11",  0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F11},
	{"F12",  0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F12},
	{0}
};

static TOUCH_KEY gQwertyRow1[] = {
	{"`",   '`',  '~',  0,   KEY_TYPE_CHAR, 1, 0},
	{"1",   '1',  '!',  0,   KEY_TYPE_CHAR, 1, 0},
	{"2",   '2',  '@',  0,   KEY_TYPE_CHAR, 1, 0},
	{"3",   '3',  '#',  0,   KEY_TYPE_CHAR, 1, 0},
	{"4",   '4',  '$',  0,   KEY_TYPE_CHAR, 1, 0},
	{"5",   '5',  '%',  0,   KEY_TYPE_CHAR, 1, 0},
	{"6",   '6',  '^',  0,   KEY_TYPE_CHAR, 1, 0},
	{"7",   '7',  '&',  0,   KEY_TYPE_CHAR, 1, 0},
	{"8",   '8',  '*',  0,   KEY_TYPE_CHAR, 1, 0},
	{"9",   '9',  '(',  0,   KEY_TYPE_CHAR, 1, 0},
	{"0",   '0',  ')',  0,   KEY_TYPE_CHAR, 1, 0},
	{"-",   '-',  '_',  0,   KEY_TYPE_CHAR, 1, 0},
	{"=",   '=',  '+',  0,   KEY_TYPE_CHAR, 1, 0},
	{"<-",  '\b', '\b', 0,   KEY_TYPE_BACKSPACE, 2, 0},
	{0}
};

static TOUCH_KEY gQwertyRow2[] = {
	{"Tab",  '\t', '\t', 0,  KEY_TYPE_TAB,  1, 0},
	{"Q",   'q',  'Q',  0,   KEY_TYPE_CHAR, 1, 0},
	{"W",   'w',  'W',  0,   KEY_TYPE_CHAR, 1, 0},
	{"E",   'e',  'E',  0,   KEY_TYPE_CHAR, 1, 0},
	{"R",   'r',  'R',  0,   KEY_TYPE_CHAR, 1, 0},
	{"T",   't',  'T',  0,   KEY_TYPE_CHAR, 1, 0},
	{"Y",   'y',  'Y',  0,   KEY_TYPE_CHAR, 1, 0},
	{"U",   'u',  'U',  0,   KEY_TYPE_CHAR, 1, 0},
	{"I",   'i',  'I',  0,   KEY_TYPE_CHAR, 1, 0},
	{"O",   'o',  'O',  0,   KEY_TYPE_CHAR, 1, 0},
	{"P",   'p',  'P',  0,   KEY_TYPE_CHAR, 1, 0},
	{"[",   '[',  '{',  0,   KEY_TYPE_CHAR, 1, 0},
	{"]",   ']',  '}',  0,   KEY_TYPE_CHAR, 1, 0},
	{"\\",  '\\', '|',  0,   KEY_TYPE_CHAR, 2, 0},
	{0}
};

static TOUCH_KEY gQwertyRow3[] = {
	{"Caps", 0,    0,   0,   KEY_TYPE_CAPS,   2, 0},
	{"A",   'a',  'A',  0,   KEY_TYPE_CHAR, 1, 0},
	{"S",   's',  'S',  0,   KEY_TYPE_CHAR, 1, 0},
	{"D",   'd',  'D',  0,   KEY_TYPE_CHAR, 1, 0},
	{"F",   'f',  'F',  0,   KEY_TYPE_CHAR, 1, 0},
	{"G",   'g',  'G',  0,   KEY_TYPE_CHAR, 1, 0},
	{"H",   'h',  'H',  0,   KEY_TYPE_CHAR, 1, 0},
	{"J",   'j',  'J',  0,   KEY_TYPE_CHAR, 1, 0},
	{"K",   'k',  'K',  0,   KEY_TYPE_CHAR, 1, 0},
	{"L",   'l',  'L',  0,   KEY_TYPE_CHAR, 1, 0},
	{";",   ';',  ':',  0,   KEY_TYPE_CHAR, 1, 0},
	{"'",   '\'', '"',  0,   KEY_TYPE_CHAR, 1, 0},
	{"Enter", '\r', '\r', 0, KEY_TYPE_ENTER, 2, 0},
	{0}
};

static TOUCH_KEY gQwertyRow4[] = {
	{"Shift", 0,   0,   0,   KEY_TYPE_SHIFT, 2, 0},
	{"Z",   'z',  'Z',  0,   KEY_TYPE_CHAR, 1, 0},
	{"X",   'x',  'X',  0,   KEY_TYPE_CHAR, 1, 0},
	{"C",   'c',  'C',  0,   KEY_TYPE_CHAR, 1, 0},
	{"V",   'v',  'V',  0,   KEY_TYPE_CHAR, 1, 0},
	{"B",   'b',  'B',  0,   KEY_TYPE_CHAR, 1, 0},
	{"N",   'n',  'N',  0,   KEY_TYPE_CHAR, 1, 0},
	{"M",   'm',  'M',  0,   KEY_TYPE_CHAR, 1, 0},
	{",",   ',',  '<',  0,   KEY_TYPE_CHAR, 1, 0},
	{".",   '.',  '>',  0,   KEY_TYPE_CHAR, 1, 0},
	{"/",   '/',  '?',  0,   KEY_TYPE_CHAR, 1, 0},
	{"Shift", 0,   0,   0,   KEY_TYPE_SHIFT, 3, 0},
	{0}
};

static TOUCH_KEY gQwertyRow5[] = {
	{"AltGr", 0,   0,   0,   KEY_TYPE_ALTGR, 2, 0},
	{"Space", ' ', ' ', 0,   KEY_TYPE_SPACE, 6, 0},
	{"Ins",  0,   0,   0,   KEY_TYPE_INSERT, 1, 0},
	{"Del",  0,   0,   0,   KEY_TYPE_DELETE, 1, 0},
	{"^",    0,   0,   0,   KEY_TYPE_ARROW_U, 1, SCAN_UP},
	{"v",    0,   0,   0,   KEY_TYPE_ARROW_D, 1, SCAN_DOWN},
	{"<",    0,   0,   0,   KEY_TYPE_ARROW_L, 1, SCAN_LEFT},
	{">",    0,   0,   0,   KEY_TYPE_ARROW_R, 1, SCAN_RIGHT},
	{0}
};

static TOUCH_KEY* gQwertyLayout[] = {
	gQwertyRow0, gQwertyRow1, gQwertyRow2, gQwertyRow3, gQwertyRow4, gQwertyRow5, NULL
};

//////////////////////////////////////////////////////////////////////////
// QWERTZ Layout (German)
//////////////////////////////////////////////////////////////////////////
static TOUCH_KEY gQwertzRow0[] = {
	{"Esc",  0,    0,   0,   KEY_TYPE_ESC,    1, SCAN_ESC},
	{"F1",   0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F1},
	{"F2",   0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F2},
	{"F3",   0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F3},
	{"F4",   0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F4},
	{"F5",   0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F5},
	{"F6",   0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F6},
	{"F7",   0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F7},
	{"F8",   0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F8},
	{"F9",   0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F9},
	{"F10",  0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F10},
	{"F11",  0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F11},
	{"F12",  0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F12},
	{0}
};

static TOUCH_KEY gQwertzRow1[] = {
	{"^",   '^',  '~',  0,   KEY_TYPE_CHAR, 1, 0},
	{"1",   '1',  '!',  0,   KEY_TYPE_CHAR, 1, 0},
	{"2",   '2',  '"',  '@', KEY_TYPE_CHAR, 1, 0},
	{"3",   '3',  '#',  0,   KEY_TYPE_CHAR, 1, 0},
	{"4",   '4',  '$',  0,   KEY_TYPE_CHAR, 1, 0},
	{"5",   '5',  '%',  0,   KEY_TYPE_CHAR, 1, 0},
	{"6",   '6',  '&',  0,   KEY_TYPE_CHAR, 1, 0},
	{"7",   '7',  '/',  '{', KEY_TYPE_CHAR, 1, 0},
	{"8",   '8',  '(',  '[', KEY_TYPE_CHAR, 1, 0},
	{"9",   '9',  ')',  ']', KEY_TYPE_CHAR, 1, 0},
	{"0",   '0',  '=',  '}', KEY_TYPE_CHAR, 1, 0},
	{"-",   '-',  '_',  '\\',KEY_TYPE_CHAR, 1, 0},
	{"'",   '\'', '`',  0,   KEY_TYPE_CHAR, 1, 0},
	{"<-",  '\b', '\b', 0,   KEY_TYPE_BACKSPACE, 2, 0},
	{0}
};

static TOUCH_KEY gQwertzRow2[] = {
	{"Tab",  '\t', '\t', 0,  KEY_TYPE_TAB,  1, 0},
	{"Q",   'q',  'Q',  '@', KEY_TYPE_CHAR, 1, 0},
	{"W",   'w',  'W',  0,   KEY_TYPE_CHAR, 1, 0},
	{"E",   'e',  'E',  0,   KEY_TYPE_CHAR, 1, 0},
	{"R",   'r',  'R',  0,   KEY_TYPE_CHAR, 1, 0},
	{"T",   't',  'T',  0,   KEY_TYPE_CHAR, 1, 0},
	{"Z",   'z',  'Z',  0,   KEY_TYPE_CHAR, 1, 0},  // QWERTZ: Z and Y swapped
	{"U",   'u',  'U',  0,   KEY_TYPE_CHAR, 1, 0},
	{"I",   'i',  'I',  0,   KEY_TYPE_CHAR, 1, 0},
	{"O",   'o',  'O',  0,   KEY_TYPE_CHAR, 1, 0},
	{"P",   'p',  'P',  0,   KEY_TYPE_CHAR, 1, 0},
	{"+",   '+',  '*',  '~', KEY_TYPE_CHAR, 1, 0},
	{"#",   '#',  '\'', 0,   KEY_TYPE_CHAR, 1, 0},
	{"<",   '<',  '>',  '|', KEY_TYPE_CHAR, 2, 0},
	{0}
};

static TOUCH_KEY gQwertzRow3[] = {
	{"Caps", 0,    0,   0,   KEY_TYPE_CAPS,   2, 0},
	{"A",   'a',  'A',  0,   KEY_TYPE_CHAR, 1, 0},
	{"S",   's',  'S',  0,   KEY_TYPE_CHAR, 1, 0},
	{"D",   'd',  'D',  0,   KEY_TYPE_CHAR, 1, 0},
	{"F",   'f',  'F',  0,   KEY_TYPE_CHAR, 1, 0},
	{"G",   'g',  'G',  0,   KEY_TYPE_CHAR, 1, 0},
	{"H",   'h',  'H',  0,   KEY_TYPE_CHAR, 1, 0},
	{"J",   'j',  'J',  0,   KEY_TYPE_CHAR, 1, 0},
	{"K",   'k',  'K',  0,   KEY_TYPE_CHAR, 1, 0},
	{"L",   'l',  'L',  0,   KEY_TYPE_CHAR, 1, 0},
	{";",   ';',  ':',  0,   KEY_TYPE_CHAR, 1, 0},
	{"'",   '\'', '"',  0,   KEY_TYPE_CHAR, 1, 0},
	{"Enter", '\r', '\r', 0, KEY_TYPE_ENTER, 2, 0},
	{0}
};

static TOUCH_KEY gQwertzRow4[] = {
	{"Shift", 0,   0,   0,   KEY_TYPE_SHIFT, 2, 0},
	{"Y",   'y',  'Y',  0,   KEY_TYPE_CHAR, 1, 0},  // QWERTZ: Z and Y swapped
	{"X",   'x',  'X',  0,   KEY_TYPE_CHAR, 1, 0},
	{"C",   'c',  'C',  0,   KEY_TYPE_CHAR, 1, 0},
	{"V",   'v',  'V',  0,   KEY_TYPE_CHAR, 1, 0},
	{"B",   'b',  'B',  0,   KEY_TYPE_CHAR, 1, 0},
	{"N",   'n',  'N',  0,   KEY_TYPE_CHAR, 1, 0},
	{"M",   'm',  'M',  0,   KEY_TYPE_CHAR, 1, 0},
	{",",   ',',  ';',  0,   KEY_TYPE_CHAR, 1, 0},
	{".",   '.',  ':',  0,   KEY_TYPE_CHAR, 1, 0},
	{"-",   '-',  '_',  0,   KEY_TYPE_CHAR, 1, 0},
	{"Shift", 0,   0,   0,   KEY_TYPE_SHIFT, 3, 0},
	{0}
};

static TOUCH_KEY gQwertzRow5[] = {
	{"AltGr", 0,   0,   0,   KEY_TYPE_ALTGR, 2, 0},
	{"Space", ' ', ' ', 0,   KEY_TYPE_SPACE, 6, 0},
	{"Ins",  0,   0,   0,   KEY_TYPE_INSERT, 1, 0},
	{"Del",  0,   0,   0,   KEY_TYPE_DELETE, 1, 0},
	{"^",    0,   0,   0,   KEY_TYPE_ARROW_U, 1, SCAN_UP},
	{"v",    0,   0,   0,   KEY_TYPE_ARROW_D, 1, SCAN_DOWN},
	{"<",    0,   0,   0,   KEY_TYPE_ARROW_L, 1, SCAN_LEFT},
	{">",    0,   0,   0,   KEY_TYPE_ARROW_R, 1, SCAN_RIGHT},
	{0}
};

static TOUCH_KEY* gQwertzLayout[] = {
	gQwertzRow0, gQwertzRow1, gQwertzRow2, gQwertzRow3, gQwertzRow4, gQwertzRow5, NULL
};

//////////////////////////////////////////////////////////////////////////
// AZERTY Layout (French)
//////////////////////////////////////////////////////////////////////////
static TOUCH_KEY gAzertyRow0[] = {
	{"Esc",  0,    0,   0,   KEY_TYPE_ESC,    1, SCAN_ESC},
	{"F1",   0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F1},
	{"F2",   0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F2},
	{"F3",   0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F3},
	{"F4",   0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F4},
	{"F5",   0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F5},
	{"F6",   0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F6},
	{"F7",   0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F7},
	{"F8",   0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F8},
	{"F9",   0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F9},
	{"F10",  0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F10},
	{"F11",  0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F11},
	{"F12",  0,    0,   0,   KEY_TYPE_FN,     1, SCAN_F12},
	{0}
};

static TOUCH_KEY gAzertyRow1[] = {
	{"2",   '&',  '1',  0,   KEY_TYPE_CHAR, 1, 0},
	{"~",   '~',  '2',  0,   KEY_TYPE_CHAR, 1, 0},
	{"\"",  '"',  '3',  '#', KEY_TYPE_CHAR, 1, 0},
	{"'",   '\'', '4',  '{', KEY_TYPE_CHAR, 1, 0},
	{"(",   '(',  '5',  '[', KEY_TYPE_CHAR, 1, 0},
	{"-",   '-',  '6',  '|', KEY_TYPE_CHAR, 1, 0},
	{"`",   '`',  '7',  0,   KEY_TYPE_CHAR, 1, 0},
	{"_",   '_',  '8',  '\\',KEY_TYPE_CHAR, 1, 0},
	{"^",   '^',  '9',  0,   KEY_TYPE_CHAR, 1, 0},
	{"@",   '@',  '0',  0,   KEY_TYPE_CHAR, 1, 0},
	{")",   ')',  '-',  ']', KEY_TYPE_CHAR, 1, 0},
	{"=",   '=',  '+',  '}', KEY_TYPE_CHAR, 1, 0},
	{"<-",  '\b', '\b', 0,   KEY_TYPE_BACKSPACE, 2, 0},
	{0}
};

static TOUCH_KEY gAzertyRow2[] = {
	{"Tab",  '\t', '\t', 0,  KEY_TYPE_TAB,  1, 0},
	{"A",   'a',  'A',  0,   KEY_TYPE_CHAR, 1, 0},
	{"Z",   'z',  'Z',  0,   KEY_TYPE_CHAR, 1, 0},
	{"E",   'e',  'E',  0,   KEY_TYPE_CHAR, 1, 0},
	{"R",   'r',  'R',  0,   KEY_TYPE_CHAR, 1, 0},
	{"T",   't',  'T',  0,   KEY_TYPE_CHAR, 1, 0},
	{"Y",   'y',  'Y',  0,   KEY_TYPE_CHAR, 1, 0},
	{"U",   'u',  'U',  0,   KEY_TYPE_CHAR, 1, 0},
	{"I",   'i',  'I',  0,   KEY_TYPE_CHAR, 1, 0},
	{"O",   'o',  'O',  0,   KEY_TYPE_CHAR, 1, 0},
	{"P",   'p',  'P',  0,   KEY_TYPE_CHAR, 1, 0},
	{"$",   '$',  '*',  0,   KEY_TYPE_CHAR, 1, 0},
	{"<",   '<',  '>',  0,   KEY_TYPE_CHAR, 2, 0},
	{0}
};

static TOUCH_KEY gAzertyRow3[] = {
	{"Caps", 0,    0,   0,   KEY_TYPE_CAPS,   2, 0},
	{"Q",   'q',  'Q',  0,   KEY_TYPE_CHAR, 1, 0},
	{"S",   's',  'S',  0,   KEY_TYPE_CHAR, 1, 0},
	{"D",   'd',  'D',  0,   KEY_TYPE_CHAR, 1, 0},
	{"F",   'f',  'F',  0,   KEY_TYPE_CHAR, 1, 0},
	{"G",   'g',  'G',  0,   KEY_TYPE_CHAR, 1, 0},
	{"H",   'h',  'H',  0,   KEY_TYPE_CHAR, 1, 0},
	{"J",   'j',  'J',  0,   KEY_TYPE_CHAR, 1, 0},
	{"K",   'k',  'K',  0,   KEY_TYPE_CHAR, 1, 0},
	{"L",   'l',  'L',  0,   KEY_TYPE_CHAR, 1, 0},
	{"M",   'm',  'M',  0,   KEY_TYPE_CHAR, 1, 0},
	{"%",   '%',  '!',  0,   KEY_TYPE_CHAR, 1, 0},
	{"Enter", '\r', '\r', 0, KEY_TYPE_ENTER, 2, 0},
	{0}
};

static TOUCH_KEY gAzertyRow4[] = {
	{"Shift", 0,   0,   0,   KEY_TYPE_SHIFT, 2, 0},
	{"W",   'w',  'W',  0,   KEY_TYPE_CHAR, 1, 0},
	{"X",   'x',  'X',  0,   KEY_TYPE_CHAR, 1, 0},
	{"C",   'c',  'C',  0,   KEY_TYPE_CHAR, 1, 0},
	{"V",   'v',  'V',  0,   KEY_TYPE_CHAR, 1, 0},
	{"B",   'b',  'B',  0,   KEY_TYPE_CHAR, 1, 0},
	{"N",   'n',  'N',  0,   KEY_TYPE_CHAR, 1, 0},
	{",",   ',',  '?',  0,   KEY_TYPE_CHAR, 1, 0},
	{";",   ';',  '.',  0,   KEY_TYPE_CHAR, 1, 0},
	{":",   ':',  '/',  0,   KEY_TYPE_CHAR, 1, 0},
	{"!",   '!',  '&',  0,   KEY_TYPE_CHAR, 1, 0},
	{"Shift", 0,   0,   0,   KEY_TYPE_SHIFT, 3, 0},
	{0}
};

static TOUCH_KEY gAzertyRow5[] = {
	{"AltGr", 0,   0,   0,   KEY_TYPE_ALTGR, 2, 0},
	{"Space", ' ', ' ', 0,   KEY_TYPE_SPACE, 6, 0},
	{"Ins",  0,   0,   0,   KEY_TYPE_INSERT, 1, 0},
	{"Del",  0,   0,   0,   KEY_TYPE_DELETE, 1, 0},
	{"^",    0,   0,   0,   KEY_TYPE_ARROW_U, 1, SCAN_UP},
	{"v",    0,   0,   0,   KEY_TYPE_ARROW_D, 1, SCAN_DOWN},
	{"<",    0,   0,   0,   KEY_TYPE_ARROW_L, 1, SCAN_LEFT},
	{">",    0,   0,   0,   KEY_TYPE_ARROW_R, 1, SCAN_RIGHT},
	{0}
};

static TOUCH_KEY* gAzertyLayout[] = {
	gAzertyRow0, gAzertyRow1, gAzertyRow2, gAzertyRow3, gAzertyRow4, gAzertyRow5, NULL
};

//////////////////////////////////////////////////////////////////////////
// Touch Keyboard State
//////////////////////////////////////////////////////////////////////////

static BLT_HEADER*     gTouchKbdScreen = NULL;
static KEY_BUTTON*     gKeyButtons = NULL;
static UINTN           gKeyButtonCount = 0;
static TOOLBAR_BUTTON  gToolbarButtons[1];   // Show/Hide button only
static TOOLBAR_BUTTON  gLayoutBarButtons[2]; // << and >> buttons for layout switching
static UINTN           gTouchKbdWidth;
static UINTN           gTouchKbdHeight;
static INT32           gKeyWidth;
static INT32           gKeyHeight;
static INT32           gKeySpacing;
static INT32           gKeyboardTop;
static INT32           gKeyboardBottom;      // Bottom of keyboard (for layout bar)
static INT32           gLayoutBarHeight;
static INT32           gLayoutBarTop;
static INT32           gPasswordZoneTop;
static INT32           gPasswordZoneHeight;
static INT32           gStatusLineTop;
static INT32           gStatusLineHeight;
static INT32           gCurrentLayout;

static BOOLEAN         gShiftActive = FALSE;
static BOOLEAN         gCapsLockActive = FALSE;
static BOOLEAN         gAltGrActive = FALSE;

static DRAW_CONTEXT    gCtxKeyNormal;
static DRAW_CONTEXT    gCtxKeyPressed;
static DRAW_CONTEXT    gCtxKeyModifier;
static DRAW_CONTEXT    gCtxKeyText;
static DRAW_CONTEXT    gCtxPasswordBox;
static DRAW_CONTEXT    gCtxToolbar;
static DRAW_CONTEXT    gCtxStatusLine;

//////////////////////////////////////////////////////////////////////////
// Helper functions
//////////////////////////////////////////////////////////////////////////

STATIC
VOID
TouchKbdCreateDrawContexts(VOID)
{
	// Normal key
	gCtxKeyNormal.Color = gColorGray;
	gCtxKeyNormal.DashLine = 0xFFFFFFFF;
	gCtxKeyNormal.Op = DrawOpSet;
	gCtxKeyNormal.Brush = gBrush3;

	// Pressed key
	gCtxKeyPressed.Color = gColorGreen;
	gCtxKeyPressed.DashLine = 0xFFFFFFFF;
	gCtxKeyPressed.Op = DrawOpSet;
	gCtxKeyPressed.Brush = gBrush3;

	// Modifier key (active)
	gCtxKeyModifier.Color = gColorBlue;
	gCtxKeyModifier.DashLine = 0xFFFFFFFF;
	gCtxKeyModifier.Op = DrawOpSet;
	gCtxKeyModifier.Brush = gBrush3;

	// Key text
	gCtxKeyText.Color = gColorWhite;
	gCtxKeyText.DashLine = 0xFFFFFFFF;
	gCtxKeyText.Op = DrawOpSet;
	gCtxKeyText.Brush = NULL;

	// Password box
	gCtxPasswordBox.Color = gColorGreen;
	gCtxPasswordBox.DashLine = 0xFFFFFFFF;
	gCtxPasswordBox.Op = DrawOpSet;
	gCtxPasswordBox.Brush = gBrush3;

	// Toolbar
	gCtxToolbar.Color = gColorGray;
	gCtxToolbar.DashLine = 0xFFFFFFFF;
	gCtxToolbar.Op = DrawOpSet;
	gCtxToolbar.Brush = gBrush3;

	// Status line
	gCtxStatusLine.Color = gColorWhite;
	gCtxStatusLine.DashLine = 0xFFFFFFFF;
	gCtxStatusLine.Op = DrawOpSet;
	gCtxStatusLine.Brush = NULL;
}

STATIC
TOUCH_KEY**
TouchKbdGetLayout(VOID)
{
	switch (gCurrentLayout) {
	case KB_MAP_QWERTZ:
		return gQwertzLayout;
	case KB_MAP_AZERTY:
		return gAzertyLayout;
	case KB_MAP_QWERTY:
	default:
		return gQwertyLayout;
	}
}

STATIC
VOID
TouchKbdDrawKey(
	IN KEY_BUTTON* Button,
	IN BOOLEAN     Pressed
	)
{
	PDRAW_CONTEXT ctx;
	CHAR8 displayLabel[16];
	CHAR8 ch;
	INT32 textX, textY;
	INT32 labelLen;
	INT32 i;

	// Select context based on key state
	if (Pressed) {
		ctx = &gCtxKeyPressed;
	} else if (Button->Key->Type == KEY_TYPE_SHIFT && gShiftActive) {
		ctx = &gCtxKeyModifier;
	} else if (Button->Key->Type == KEY_TYPE_CAPS && gCapsLockActive) {
		ctx = &gCtxKeyModifier;
	} else if (Button->Key->Type == KEY_TYPE_ALTGR && gAltGrActive) {
		ctx = &gCtxKeyModifier;
	} else {
		ctx = &gCtxKeyNormal;
	}

	// Draw key background
	BltFill(gTouchKbdScreen, gColorBlack,
		Button->X, Button->Y,
		Button->X + Button->Width, Button->Y + Button->Height);

	// Draw key border
	BltBox(gTouchKbdScreen, ctx,
		Button->X + 2, Button->Y + 2,
		Button->X + Button->Width - 2, Button->Y + Button->Height - 2);

	// Determine what character to display
	if (Button->Key->Type == KEY_TYPE_CHAR) {
		if (gAltGrActive && Button->Key->AltGr != 0) {
			ch = Button->Key->AltGr;
		} else if (gShiftActive != gCapsLockActive) {
			ch = Button->Key->Shifted;
		} else {
			ch = Button->Key->Normal;
		}
		displayLabel[0] = ch;
		displayLabel[1] = 0;
	} else {
		// Copy label
		for (i = 0; i < 7 && Button->Key->Label[i]; i++) {
			displayLabel[i] = Button->Key->Label[i];
		}
		displayLabel[i] = 0;
	}

	// Calculate text position (centered)
	labelLen = 0;
	while (displayLabel[labelLen]) labelLen++;

	textX = Button->X + (Button->Width / 2) - (labelLen * 6);
	textY = Button->Y + (Button->Height / 2) - 8;

	// Draw label
	BltText(gTouchKbdScreen, &gCtxKeyText, textX, textY, 128, displayLabel, FALSE);

	Button->Pressed = Pressed;
}

STATIC
VOID
TouchKbdDrawToolbarButton(
	IN TOOLBAR_BUTTON* Button,
	IN BOOLEAN         Pressed
	)
{
	PDRAW_CONTEXT ctx = Pressed ? &gCtxKeyPressed : &gCtxToolbar;
	INT32 textX, textY;
	INT32 labelLen = 0;

	// Draw button background
	BltFill(gTouchKbdScreen, gColorBlack,
		Button->X, Button->Y,
		Button->X + Button->Width, Button->Y + Button->Height);

	// Draw button border
	BltBox(gTouchKbdScreen, ctx,
		Button->X + 2, Button->Y + 2,
		Button->X + Button->Width - 2, Button->Y + Button->Height - 2);

	// Calculate text position
	while (Button->Label[labelLen]) labelLen++;
	textX = Button->X + (Button->Width / 2) - (labelLen * 6);
	textY = Button->Y + (Button->Height / 2) - 8;

	// Draw label
	BltText(gTouchKbdScreen, &gCtxKeyText, textX, textY, 128, Button->Label, FALSE);

	Button->Pressed = Pressed;
}

STATIC
VOID
TouchKbdDrawStatusLine(
	IN CHAR16* statusStr
	)
{
	// Clear entire status area (from top to password zone)
	BltFill(gTouchKbdScreen, gColorBlack, 10, gStatusLineTop, (INT32)gTouchKbdWidth - 10, gStatusLineTop + gStatusLineHeight);

	// Calculate scale to fit 80+ characters per line
	INT32 statusScale = 96;
		
	// The simplex font has ~18-20 units per character spacing on average
	// At scale 64 (1/4 size): ~4.5-5 pixels per char, so 80 chars = ~400 pixels (fits easily)
	// Scale 64 gives readable small text while fitting 80+ characters per line
	// Line height at scale 64: 30 * 64 / 256 = ~7.5 pixels per line
	//INT32 statusScale = 64;
	
	// Use same scale as keyboard keys (128) for consistent text size
	// At scale 128: ~9-10 pixels per char, ~15 pixels line height
	//INT32 statusScale = 128;

	// Start text at top of status area with small padding
	// Use wide=TRUE to render CHAR16 directly without ASCII conversion
	INT32 textY = gStatusLineTop + 5;
	BltText(gTouchKbdScreen, &gCtxStatusLine, 20, textY, statusScale, statusStr, TRUE);
}

STATIC
VOID
TouchKbdDrawLayoutBar(VOID)
{
	INT32 centerX = (INT32)gTouchKbdWidth / 2;
	INT32 btnWidth = 50;
	INT32 btnHeight = gLayoutBarHeight - 8;
	INT32 labelWidth = 100;  // Wider for spacing
	INT32 totalWidth = btnWidth + labelWidth + btnWidth;  // prev + label + next
	INT32 startX;
	INT32 textX, textY;
	CHAR8* layoutName;
	UINTN i;

	// Find the space bar to align with it
	for (i = 0; i < gKeyButtonCount; i++) {
		if (gKeyButtons[i].Key->Type == KEY_TYPE_SPACE) {
			// Center on the space bar
			centerX = gKeyButtons[i].X + gKeyButtons[i].Width / 2;
			break;
		}
	}
	startX = centerX - totalWidth / 2;

	// Clear layout bar area
	BltFill(gTouchKbdScreen, gColorBlack, 0, gLayoutBarTop, (INT32)gTouchKbdWidth, gLayoutBarTop + gLayoutBarHeight);

	// Layout prev button
	gLayoutBarButtons[0].X = startX;
	gLayoutBarButtons[0].Y = gLayoutBarTop + 4;
	gLayoutBarButtons[0].Width = btnWidth;
	gLayoutBarButtons[0].Height = btnHeight;
	gLayoutBarButtons[0].Type = LAYOUTBAR_BTN_PREV;
	gLayoutBarButtons[0].Label[0] = '<';
	gLayoutBarButtons[0].Label[1] = '<';
	gLayoutBarButtons[0].Label[2] = 0;
	TouchKbdDrawToolbarButton(&gLayoutBarButtons[0], FALSE);

	// Layout label (not a button, just text)
	layoutName = gLayoutNames[gCurrentLayout];
	textX = startX + btnWidth + (labelWidth / 2) - 20;
	textY = gLayoutBarTop + 4 + btnHeight / 2 - 8;
	BltText(gTouchKbdScreen, &gCtxKeyText, textX, textY, 128, layoutName, FALSE);

	// Layout next button
	gLayoutBarButtons[1].X = startX + btnWidth + labelWidth;
	gLayoutBarButtons[1].Y = gLayoutBarTop + 4;
	gLayoutBarButtons[1].Width = btnWidth;
	gLayoutBarButtons[1].Height = btnHeight;
	gLayoutBarButtons[1].Type = LAYOUTBAR_BTN_NEXT;
	gLayoutBarButtons[1].Label[0] = '>';
	gLayoutBarButtons[1].Label[1] = '>';
	gLayoutBarButtons[1].Label[2] = 0;
	TouchKbdDrawToolbarButton(&gLayoutBarButtons[1], FALSE);
}

STATIC
UINTN
TouchKbdCountKeys(
	IN TOUCH_KEY** Layout
	)
{
	UINTN count = 0;
	UINTN row, col;

	for (row = 0; Layout[row] != NULL; row++) {
		for (col = 0; Layout[row][col].Label[0] != 0; col++) {
			count++;
		}
	}
	return count;
}

STATIC
VOID
TouchKbdCalculateLayout(VOID)
{
	TOUCH_KEY** layout = TouchKbdGetLayout();
	UINTN row, col;
	INT32 x, y;
	UINTN buttonIdx = 0;
	INT32 maxRowWidth = 0;
	UINTN numRows = 0;
	INT32 totalUnits;

	// Count rows and find max width
	for (row = 0; layout[row] != NULL; row++) {
		numRows++;
		totalUnits = 0;
		for (col = 0; layout[row][col].Label[0] != 0; col++) {
			totalUnits += layout[row][col].Width;
		}
		if (totalUnits > maxRowWidth) {
			maxRowWidth = totalUnits;
		}
	}

	// Calculate layout zones
	gKeySpacing = 4;
	gLayoutBarHeight = 36;
	gPasswordZoneHeight = 50;

	// Calculate available space for keyboard
	INT32 topMargin = 10;  // Small top margin for status area
	INT32 bottomMargin = gLayoutBarHeight + 40;  // Space below layout bar
	INT32 availableWidth = (INT32)gTouchKbdWidth - 40;  // 20px margin each side
	INT32 availableHeight = (INT32)gTouchKbdHeight - topMargin - bottomMargin;

	// Status area starts at the very top
	gStatusLineTop = 5;

	// Calculate key size
	gKeyWidth = (availableWidth - (maxRowWidth + 1) * gKeySpacing) / maxRowWidth;
	gKeyHeight = (availableHeight - ((INT32)numRows + 1) * gKeySpacing) / (INT32)numRows;

	// Limit key height to reasonable size (make it more square-ish)
	if (gKeyHeight > gKeyWidth) {
		gKeyHeight = gKeyWidth;
	}

	// Calculate keyboard dimensions
	INT32 keyboardHeight = (INT32)numRows * (gKeyHeight + gKeySpacing);

	// Position keyboard in lower portion of screen, leaving room for password zone above
	INT32 keyboardAreaTop = (INT32)gTouchKbdHeight - keyboardHeight - bottomMargin;
	gKeyboardTop = keyboardAreaTop;
	gKeyboardBottom = gKeyboardTop + keyboardHeight;

	// Position layout bar below keyboard
	gLayoutBarTop = gKeyboardBottom + 5;

	// Position password zone close to keyboard (small gap above keyboard)
	INT32 passwordGap = 10;  // Small gap between password zone and keyboard
	gPasswordZoneTop = gKeyboardTop - gPasswordZoneHeight - passwordGap;

	// Status area height fills from top to just above password zone (with small gap)
	INT32 statusGap = 5;  // Small gap between status and password zone
	gStatusLineHeight = gPasswordZoneTop - gStatusLineTop - statusGap;

	// Now create button layout
	y = gKeyboardTop;
	for (row = 0; layout[row] != NULL; row++) {
		// Calculate row width to center it
		totalUnits = 0;
		for (col = 0; layout[row][col].Label[0] != 0; col++) {
			totalUnits += layout[row][col].Width;
		}

		INT32 rowWidth = totalUnits * (gKeyWidth + gKeySpacing) - gKeySpacing;
		x = ((INT32)gTouchKbdWidth - rowWidth) / 2;

		for (col = 0; layout[row][col].Label[0] != 0; col++) {
			TOUCH_KEY* key = &layout[row][col];
			KEY_BUTTON* button = &gKeyButtons[buttonIdx++];

			button->Key = key;
			button->X = x;
			button->Y = y;
			button->Width = key->Width * (gKeyWidth + gKeySpacing) - gKeySpacing;
			button->Height = gKeyHeight;
			button->Pressed = FALSE;

			x += button->Width + gKeySpacing;
		}
		y += gKeyHeight + gKeySpacing;
	}
}

STATIC
VOID
TouchKbdDrawAllKeys(VOID)
{
	UINTN i;
	for (i = 0; i < gKeyButtonCount; i++) {
		TouchKbdDrawKey(&gKeyButtons[i], FALSE);
	}
}

STATIC
VOID
TouchKbdDrawPasswordZone(
	IN VOID*    pwd,
	IN UINTN    pwdLen,
	IN UINTN    pwdPos,
	IN UINTN    pwdMax,
	IN BOOLEAN  visible,
	IN BOOLEAN  wide
	)
{
	INT32 btnWidth = 60;
	INT32 btnHeight = gPasswordZoneHeight - 10;
	INT32 boxLeft = 20;
	INT32 boxTop = gPasswordZoneTop;
	INT32 boxRight = (INT32)gTouchKbdWidth - btnWidth - 40;  // Leave room for Show button
	INT32 boxBottom = gPasswordZoneTop + gPasswordZoneHeight;
	UINTN i;
	UINTN charCount = pwdLen;  // pwdLen is already the character count, not byte count

	// Clear entire password zone area including button
	BltFill(gTouchKbdScreen, gColorBlack, boxLeft, boxTop, (INT32)gTouchKbdWidth - 20, boxBottom);

	// Draw password box border
	BltBox(gTouchKbdScreen, &gCtxPasswordBox, boxLeft, boxTop, boxRight, boxBottom);

	// Draw Show/Hide button to the right of password box
	gToolbarButtons[0].X = boxRight + 10;
	gToolbarButtons[0].Y = boxTop + 5;
	gToolbarButtons[0].Width = btnWidth;
	gToolbarButtons[0].Height = btnHeight;
	gToolbarButtons[0].Type = TOOLBAR_BTN_SHOW;
	if (visible) {
		gToolbarButtons[0].Label[0] = 'H';
		gToolbarButtons[0].Label[1] = 'i';
		gToolbarButtons[0].Label[2] = 'd';
		gToolbarButtons[0].Label[3] = 'e';
		gToolbarButtons[0].Label[4] = 0;
	} else {
		gToolbarButtons[0].Label[0] = 'S';
		gToolbarButtons[0].Label[1] = 'h';
		gToolbarButtons[0].Label[2] = 'o';
		gToolbarButtons[0].Label[3] = 'w';
		gToolbarButtons[0].Label[4] = 0;
	}
	TouchKbdDrawToolbarButton(&gToolbarButtons[0], FALSE);

	if (visible) {
		// Show actual password with cursor
		CHAR8 displayBuf[256];
		UINTN displayLen = 0;

		for (i = 0; i < charCount && displayLen < 250; i++) {
			CHAR8 ch = (CHAR8)GET_VAR_CHAR(pwd, wide, i);
			if (i == pwdPos) {
				displayBuf[displayLen++] = '[';
				displayBuf[displayLen++] = ch;
				displayBuf[displayLen++] = ']';
			} else {
				displayBuf[displayLen++] = ch;
			}
		}
		// Cursor at end
		if (pwdPos >= charCount) {
			displayBuf[displayLen++] = '_';
		}
		displayBuf[displayLen] = 0;

		BltText(gTouchKbdScreen, &gCtxKeyText, boxLeft + 10, boxTop + 15, 256, displayBuf, FALSE);
	} else {
		// Show asterisks with cursor position indicator
		CHAR8 displayBuf[256];
		UINTN displayLen = 0;

		for (i = 0; i < charCount && displayLen < 250; i++) {
			if (i == pwdPos) {
				// Show the actual character at cursor position for editing
				CHAR8 ch = (CHAR8)GET_VAR_CHAR(pwd, wide, i);
				displayBuf[displayLen++] = '[';
				displayBuf[displayLen++] = ch;
				displayBuf[displayLen++] = ']';
			} else {
				displayBuf[displayLen++] = '*';
			}
		}
		// Cursor at end
		if (pwdPos >= charCount) {
			displayBuf[displayLen++] = '_';
		}
		displayBuf[displayLen] = 0;

		if (charCount > 0 || pwdPos == 0) {
			BltText(gTouchKbdScreen, &gCtxKeyText, boxLeft + 10, boxTop + 15, 256, displayBuf, FALSE);
		}
	}
}

STATIC
KEY_BUTTON*
TouchKbdHitTestKey(
	IN UINTN X,
	IN UINTN Y
	)
{
	UINTN i;
	for (i = 0; i < gKeyButtonCount; i++) {
		KEY_BUTTON* btn = &gKeyButtons[i];
		if ((INT32)X >= btn->X && (INT32)X < btn->X + btn->Width &&
			(INT32)Y >= btn->Y && (INT32)Y < btn->Y + btn->Height) {
			return btn;
		}
	}
	return NULL;
}

STATIC
TOOLBAR_BUTTON*
TouchKbdHitTestToolbar(
	IN UINTN X,
	IN UINTN Y
	)
{
	// Only 1 button in toolbar now (Show/Hide)
	TOOLBAR_BUTTON* btn = &gToolbarButtons[0];
	if ((INT32)X >= btn->X && (INT32)X < btn->X + btn->Width &&
		(INT32)Y >= btn->Y && (INT32)Y < btn->Y + btn->Height) {
		return btn;
	}
	return NULL;
}

STATIC
TOOLBAR_BUTTON*
TouchKbdHitTestLayoutBar(
	IN UINTN X,
	IN UINTN Y
	)
{
	UINTN i;
	for (i = 0; i < 2; i++) {
		TOOLBAR_BUTTON* btn = &gLayoutBarButtons[i];
		if ((INT32)X >= btn->X && (INT32)X < btn->X + btn->Width &&
			(INT32)Y >= btn->Y && (INT32)Y < btn->Y + btn->Height) {
			return btn;
		}
	}
	return NULL;
}

STATIC
VOID
TouchKbdRebuildLayout(VOID)
{
	TOUCH_KEY** layout = TouchKbdGetLayout();
	UINTN newCount = TouchKbdCountKeys(layout);

	// Reallocate if needed
	if (newCount != gKeyButtonCount) {
		if (gKeyButtons != NULL) {
			MEM_FREE(gKeyButtons);
		}
		gKeyButtonCount = newCount;
		gKeyButtons = MEM_ALLOC(sizeof(KEY_BUTTON) * gKeyButtonCount);
	}

	TouchKbdCalculateLayout();
}

//////////////////////////////////////////////////////////////////////////
// Main entry point - Extended version with callbacks
//////////////////////////////////////////////////////////////////////////

VOID
AskTouchPwdEx(
	IN  CONST char* msg,
	OUT UINT32*  pwdLen,
	OUT VOID*    pwd,
	OUT INT32*   retCode,
	IN  UINTN    pwdMax,
	IN  UINT8    show,
	IN  BOOLEAN  wide,
	IN  INT32 (*KeyFilter)(IN EFI_INPUT_KEY key, IN VOID *Param),
	IN  VOID (*GetStatus)(IN CHAR16* statusStr, IN UINTN statusStrLen, IN VOID *Param),
	IN  VOID *Param
	)
{
	EFI_STATUS    res;
	EFI_INPUT_KEY key;
	EFI_EVENT     UpdateEvent;
	EFI_EVENT     BeepOffEvent;
	EFI_EVENT     InputEvents[3];
	UINTN         EventIndex = 0;
	UINTN         eventsCount = 2;
	EFI_ABSOLUTE_POINTER_STATE aps = {0};
	UINTN         curX = 0, curY = 0;
	BOOLEAN       wasTouchActive = FALSE;       // Track previous touch state
	BOOLEAN       keyProcessedThisTouch = FALSE; // Did we process a key during this touch?
	KEY_BUTTON*   highlightedKey = NULL;        // Currently highlighted key (for visual only)
	TOOLBAR_BUTTON* highlightedToolbar = NULL;  // Currently highlighted toolbar button
	TOOLBAR_BUTTON* highlightedLayoutBar = NULL; // Currently highlighted layout bar button
	BOOLEAN       beepOn = FALSE;
	UINTN         pwdIdx = 0;    // Current password length
	UINTN         pwdPos = 0;    // Current cursor position
	UINTN         lineMax;
	UINT8         visible = show;
	CHAR16        statusStr[STATUS_BUFFER_SIZE + 1];

	if (wide)
		lineMax = pwdMax / 2;
	else
		lineMax = pwdMax;

	// Ensure we have space for at least one character + null terminator
	if (lineMax < 2)
		lineMax = 2;

	// Initialize current layout from global setting
	gCurrentLayout = gKeyboardLayout;

	// Check if touch is available
	if (gTouchPointer == NULL) {
		ERR_PRINT(L"Touch input not available\n");
		*retCode = AskPwdRetCancel;
		return;
	}

	// Handle timeout
	if (gPasswordTimeout) {
		InputEvents[0] = gST->ConIn->WaitForKey;
		eventsCount = 2;
		if (gTouchPointer != NULL) {
			eventsCount = 3;
			InputEvents[2] = gTouchPointer->WaitForInput;
		}
		gBS->CreateEvent(EVT_TIMER, 0, (EFI_EVENT_NOTIFY)NULL, NULL, &InputEvents[1]);
		gBS->SetTimer(InputEvents[1], TimerPeriodic, 10000000 * gPasswordTimeout);
		gBS->WaitForEvent(eventsCount, InputEvents, &EventIndex);
		gPasswordTimeout = 0;
		gBS->CloseEvent(InputEvents[1]);
		if (EventIndex == 1) {
			*retCode = AskPwdRetTimeout;
			return;
		}
	}

	InitConsoleControl();
	if (gBeepEnabled) {
		InitSpeaker();
	}

	// Initialize drawing contexts
	TouchKbdCreateDrawContexts();

	// Get screen size and create screen buffer
	if (gTouchKbdScreen != NULL) MEM_FREE(gTouchKbdScreen);
	ScreenSaveBlt(&gTouchKbdScreen);
	gTouchKbdWidth = gTouchKbdScreen->Width;
	gTouchKbdHeight = gTouchKbdScreen->Height;

	// Count keys and allocate button array
	TOUCH_KEY** layout = TouchKbdGetLayout();
	gKeyButtonCount = TouchKbdCountKeys(layout);
	gKeyButtons = MEM_ALLOC(sizeof(KEY_BUTTON) * gKeyButtonCount);
	if (gKeyButtons == NULL) {
		MEM_FREE(gTouchKbdScreen);
		gTouchKbdScreen = NULL;
		ERR_PRINT(L"Memory allocation failed\n");
		*retCode = AskPwdRetCancel;
		return;
	}

	// Calculate layout and draw
	TouchKbdCalculateLayout();

	// Clear screen
	BltFill(gTouchKbdScreen, gColorBlack, 0, 0, (INT32)gTouchKbdWidth, (INT32)gTouchKbdHeight);

	// Get initial status and draw
	GetStatus(statusStr, STATUS_BUFFER_SIZE, Param);
	TouchKbdDrawStatusLine(statusStr);
	TouchKbdDrawAllKeys();
	TouchKbdDrawLayoutBar();
	TouchKbdDrawPasswordZone(pwd, 0, 0, lineMax, visible, wide);

	ScreenUpdateDirty(gTouchKbdScreen);

	// Initialize password
	pwdIdx = 0;
	pwdPos = 0;
	if (*pwdLen > 0) {
		pwdIdx = *pwdLen;
		if (wide)
			pwdIdx /= 2;
		pwdPos = pwdIdx;
	} else {
		SET_VAR_CHAR(pwd, wide, 0, '\0');
	}

	// Setup events
	InputEvents[0] = gST->ConIn->WaitForKey;
	gBS->CreateEvent(EVT_TIMER, 0, (EFI_EVENT_NOTIFY)NULL, NULL, &InputEvents[1]);
	gBS->CreateEvent(EVT_TIMER, 0, (EFI_EVENT_NOTIFY)NULL, NULL, &BeepOffEvent);
	gBS->CreateEvent(EVT_TIMER, 0, (EFI_EVENT_NOTIFY)NULL, NULL, &UpdateEvent);
	gBS->SetTimer(UpdateEvent, TimerRelative, 500000);  // 20 times per second
	gBS->SetTimer(BeepOffEvent, TimerRelative, gBeepDurationDefault * 10);
	gBS->SetTimer(InputEvents[1], TimerRelative, 5000000);

	if (gTouchPointer != NULL) {
		eventsCount = 3;
		InputEvents[2] = gTouchPointer->WaitForInput;
		// Clear pending touch events
		while (gBS->CheckEvent(InputEvents[2]) == EFI_SUCCESS) {
			gTouchPointer->GetState(gTouchPointer, &aps);
		}
	}

	// Clear pending keyboard events
	while (gBS->CheckEvent(InputEvents[0]) == EFI_SUCCESS) {
		gST->ConIn->ReadKeyStroke(gST->ConIn, &key);
	}

	// Main input loop
	do {
		ZeroMem(&key, sizeof(key));
		res = gBS->WaitForEvent(eventsCount, InputEvents, &EventIndex);

		// Handle keyboard input (for physical keyboard fallback)
		if (EventIndex == 0) {
			res = gST->ConIn->ReadKeyStroke(gST->ConIn, &key);
			if (EFI_ERROR(res)) continue;

			FlushInputDelay(100000);

			if (key.ScanCode == SCAN_ESC) {
				*retCode = AskPwdRetCancel;
				break;
			}

			// Pass key to KeyFilter callback
			*retCode = KeyFilter(key, Param);

			if (*retCode == AskPwdRetShow) {
				visible = visible ? 0 : 1;
				TouchKbdDrawPasswordZone(pwd, pwdIdx, pwdPos, lineMax, visible, wide);
				ScreenUpdateDirty(gTouchKbdScreen);
				continue;
			}

			if (*retCode == AskPwdRetCancel) {
				// Redraw status (callback may have changed state)
				GetStatus(statusStr, STATUS_BUFFER_SIZE, Param);
				TouchKbdDrawStatusLine(statusStr);
				ScreenUpdateDirty(gTouchKbdScreen);
				continue;
			}

			if (*retCode != AskPwdRetNone) {
				goto exit_loop;
			}

			if (key.ScanCode == SCAN_LEFT) {
				if (pwdPos > 0) {
					pwdPos--;
					TouchKbdDrawPasswordZone(pwd, pwdIdx, pwdPos, lineMax, visible, wide);
				}
			}

			if (key.ScanCode == SCAN_RIGHT) {
				if (pwdPos < pwdIdx) {
					pwdPos++;
					TouchKbdDrawPasswordZone(pwd, pwdIdx, pwdPos, lineMax, visible, wide);
				}
			}

			if (key.ScanCode == SCAN_UP || key.ScanCode == SCAN_DOWN) {
				// Pass up/down arrows to KeyFilter
				*retCode = KeyFilter(key, Param);

				if (*retCode == AskPwdRetShow) {
					visible = visible ? 0 : 1;
					TouchKbdDrawPasswordZone(pwd, pwdIdx, pwdPos, lineMax, visible, wide);
					ScreenUpdateDirty(gTouchKbdScreen);
				} else if (*retCode == AskPwdRetCancel) {
					GetStatus(statusStr, STATUS_BUFFER_SIZE, Param);
					TouchKbdDrawStatusLine(statusStr);
					ScreenUpdateDirty(gTouchKbdScreen);
				} else if (*retCode != AskPwdRetNone) {
					goto exit_loop;
				}
			}

			if (key.ScanCode == SCAN_DELETE) {
				if (pwdPos < pwdIdx) {
					// Delete char at cursor
					UINTN i;
					for (i = pwdPos; i < pwdIdx - 1; i++) {
						SET_VAR_CHAR(pwd, wide, i, GET_VAR_CHAR(pwd, wide, i + 1));
					}
					pwdIdx--;
					SET_VAR_CHAR(pwd, wide, pwdIdx, '\0');
					TouchKbdDrawPasswordZone(pwd, pwdIdx, pwdPos, lineMax, visible, wide);
				}
			}

			if (key.ScanCode == SCAN_INSERT) {
				// Insert space at cursor
				if (pwdIdx < lineMax - 1) {
					UINTN i;
					for (i = pwdIdx; i > pwdPos; i--) {
						SET_VAR_CHAR(pwd, wide, i, GET_VAR_CHAR(pwd, wide, i - 1));
					}
					SET_VAR_CHAR(pwd, wide, pwdPos, ' ');
					pwdIdx++;
					SET_VAR_CHAR(pwd, wide, pwdIdx, '\0');
					TouchKbdDrawPasswordZone(pwd, pwdIdx, pwdPos, lineMax, visible, wide);
				}
			}

			if (key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
				*retCode = AskPwdRetLogin;
				break;
			}

			if (key.UnicodeChar == CHAR_BACKSPACE && pwdPos > 0) {
				// Delete char before cursor
				UINTN i;
				pwdPos--;
				for (i = pwdPos; i < pwdIdx - 1; i++) {
					SET_VAR_CHAR(pwd, wide, i, GET_VAR_CHAR(pwd, wide, i + 1));
				}
				pwdIdx--;
				SET_VAR_CHAR(pwd, wide, pwdIdx, '\0');
				TouchKbdDrawPasswordZone(pwd, pwdIdx, pwdPos, lineMax, visible, wide);
			}

			if (key.UnicodeChar >= 32 && key.UnicodeChar < 127) {
				if (pwdPos < pwdIdx) {
					// Replace mode: overwrite char at cursor
					SET_VAR_CHAR(pwd, wide, pwdPos, (CHAR8)key.UnicodeChar);
					pwdPos++;
				} else if (pwdIdx < lineMax - 1) {
					// Append mode: add at end
					SET_VAR_CHAR(pwd, wide, pwdIdx++, (CHAR8)key.UnicodeChar);
					SET_VAR_CHAR(pwd, wide, pwdIdx, '\0');
					pwdPos = pwdIdx;
				}
				TouchKbdDrawPasswordZone(pwd, pwdIdx, pwdPos, lineMax, visible, wide);
				if (gBeepControlEnabled && gBeepEnabled) {
					SpeakerBeep((UINT16)gBeepToneDefault, gBeepNumberDefault, 0, 0);
					gBS->SetTimer(BeepOffEvent, TimerRelative, gBeepDurationDefault * 10);
					beepOn = TRUE;
				}
			}
		}

		// Stop beep if needed
		if (gBeepControlEnabled && gBeepEnabled && beepOn) {
			if (gBS->CheckEvent(BeepOffEvent) == EFI_SUCCESS) {
				beepOn = FALSE;
				SpeakerBeep((UINT16)gBeepToneDefault, 0, 0, 0);
			}
		}

		// Handle touch input - get current state
		BOOLEAN gotTouchState = FALSE;
		if (EventIndex == 2) {
			res = gTouchPointer->GetState(gTouchPointer, &aps);
			if (!EFI_ERROR(res)) {
				gotTouchState = TRUE;
				curX = (UINTN)(aps.CurrentX * gTouchKbdWidth /
					(gTouchPointer->Mode->AbsoluteMaxX - gTouchPointer->Mode->AbsoluteMinX));
				curY = (UINTN)(aps.CurrentY * gTouchKbdHeight /
					(gTouchPointer->Mode->AbsoluteMaxY - gTouchPointer->Mode->AbsoluteMinY));
			}
		}
		// Also poll touch state on timer events to catch missed releases
		// Poll if: touch was active OR any element is highlighted
		else if (EventIndex == 1 && (wasTouchActive || highlightedKey != NULL || highlightedToolbar != NULL || highlightedLayoutBar != NULL)) {
			res = gTouchPointer->GetState(gTouchPointer, &aps);
			if (!EFI_ERROR(res)) {
				gotTouchState = TRUE;
				curX = (UINTN)(aps.CurrentX * gTouchKbdWidth /
					(gTouchPointer->Mode->AbsoluteMaxX - gTouchPointer->Mode->AbsoluteMinX));
				curY = (UINTN)(aps.CurrentY * gTouchKbdHeight /
					(gTouchPointer->Mode->AbsoluteMaxY - gTouchPointer->Mode->AbsoluteMinY));
			} else if (highlightedKey != NULL || highlightedToolbar != NULL || highlightedLayoutBar != NULL) {
				// GetState failed but we have highlighted elements - force clear them
				// This handles cases where touch was released but GetState doesn't report it
				if (highlightedKey != NULL) {
					TouchKbdDrawKey(highlightedKey, FALSE);
					highlightedKey = NULL;
				}
				if (highlightedToolbar != NULL) {
					TouchKbdDrawToolbarButton(highlightedToolbar, FALSE);
					highlightedToolbar = NULL;
				}
				if (highlightedLayoutBar != NULL) {
					TouchKbdDrawToolbarButton(highlightedLayoutBar, FALSE);
					highlightedLayoutBar = NULL;
				}
				wasTouchActive = FALSE;
				keyProcessedThisTouch = FALSE;
				ScreenUpdateDirty(gTouchKbdScreen);  // Immediate update
			}
		}

		// Process touch state only if we got valid data
		if (gotTouchState) {
			BOOLEAN isTouchActive = (aps.ActiveButtons != 0);
			KEY_BUTTON* hitButton = TouchKbdHitTestKey(curX, curY);
			TOOLBAR_BUTTON* hitToolbar = TouchKbdHitTestToolbar(curX, curY);
			TOOLBAR_BUTTON* hitLayoutBar = TouchKbdHitTestLayoutBar(curX, curY);

			// Touch just released (was active, now inactive)
			if (wasTouchActive && !isTouchActive) {
				if (highlightedKey != NULL) {
					TouchKbdDrawKey(highlightedKey, FALSE);
					highlightedKey = NULL;
				}
				if (highlightedToolbar != NULL) {
					TouchKbdDrawToolbarButton(highlightedToolbar, FALSE);
					highlightedToolbar = NULL;
				}
				if (highlightedLayoutBar != NULL) {
					TouchKbdDrawToolbarButton(highlightedLayoutBar, FALSE);
					highlightedLayoutBar = NULL;
				}
				keyProcessedThisTouch = FALSE;  // Reset for next touch
				ScreenUpdateDirty(gTouchKbdScreen);  // Immediate update to clear highlights
			}
			// Touch active and haven't processed yet this touch
			else if (isTouchActive && !keyProcessedThisTouch) {
				// Clear any old highlights first
				if (highlightedKey != NULL) {
					TouchKbdDrawKey(highlightedKey, FALSE);
					highlightedKey = NULL;
				}
				if (highlightedToolbar != NULL) {
					TouchKbdDrawToolbarButton(highlightedToolbar, FALSE);
					highlightedToolbar = NULL;
				}
				if (highlightedLayoutBar != NULL) {
					TouchKbdDrawToolbarButton(highlightedLayoutBar, FALSE);
					highlightedLayoutBar = NULL;
				}

				// Toolbar button (Show/Hide only)
				if (hitToolbar != NULL) {
					TouchKbdDrawToolbarButton(hitToolbar, TRUE);
					highlightedToolbar = hitToolbar;
					keyProcessedThisTouch = TRUE;

					// TOOLBAR_BTN_SHOW is the only toolbar button now
					visible = visible ? 0 : 1;
					TouchKbdDrawPasswordZone(pwd, pwdIdx, pwdPos, lineMax, visible, wide);
				}
				// Layout bar button (<< or >>)
				else if (hitLayoutBar != NULL) {
					TouchKbdDrawToolbarButton(hitLayoutBar, TRUE);
					highlightedLayoutBar = hitLayoutBar;
					keyProcessedThisTouch = TRUE;

					if (hitLayoutBar->Type == LAYOUTBAR_BTN_PREV) {
						gCurrentLayout = (gCurrentLayout + LAYOUT_COUNT - 1) % LAYOUT_COUNT;
					} else {  // LAYOUTBAR_BTN_NEXT
						gCurrentLayout = (gCurrentLayout + 1) % LAYOUT_COUNT;
					}
					TouchKbdRebuildLayout();
					BltFill(gTouchKbdScreen, gColorBlack, 0, 0, (INT32)gTouchKbdWidth, (INT32)gTouchKbdHeight);
					GetStatus(statusStr, STATUS_BUFFER_SIZE, Param);
					TouchKbdDrawStatusLine(statusStr);
					TouchKbdDrawAllKeys();
					TouchKbdDrawLayoutBar();
					TouchKbdDrawPasswordZone(pwd, pwdIdx, pwdPos, lineMax, visible, wide);
					highlightedLayoutBar = NULL;
				}
				// Key button
				else if (hitButton != NULL) {
					TouchKbdDrawKey(hitButton, TRUE);
					highlightedKey = hitButton;
					keyProcessedThisTouch = TRUE;

					TOUCH_KEY* pressedKey = hitButton->Key;

					switch (pressedKey->Type) {
					case KEY_TYPE_CHAR:
					case KEY_TYPE_SPACE:
					case KEY_TYPE_TAB:
					{
						// Get the character based on current modifier state
						CHAR8 ch = 0;
						if (pressedKey->Type == KEY_TYPE_CHAR) {
							if (gAltGrActive && pressedKey->AltGr != 0) {
								ch = pressedKey->AltGr;
							} else if (gShiftActive != gCapsLockActive) {
								ch = pressedKey->Shifted;
							} else {
								ch = pressedKey->Normal;
							}
						} else {
							// Space or Tab
							ch = pressedKey->Normal;
						}

						// Add the character if valid
						if (ch != 0 && pwdIdx < lineMax - 1) {
							if (pwdPos < pwdIdx) {
								// Replace mode - cursor in middle of password
								SET_VAR_CHAR(pwd, wide, pwdPos, ch);
								pwdPos++;
							} else {
								// Append mode - cursor at end
								SET_VAR_CHAR(pwd, wide, pwdIdx, ch);
								pwdIdx++;
								SET_VAR_CHAR(pwd, wide, pwdIdx, '\0');
								pwdPos = pwdIdx;
							}
							TouchKbdDrawPasswordZone(pwd, pwdIdx, pwdPos, lineMax,
								visible, wide);
							if (gBeepControlEnabled && gBeepEnabled) {
								SpeakerBeep((UINT16)gBeepToneDefault, gBeepNumberDefault, 0, 0);
								gBS->SetTimer(BeepOffEvent, TimerRelative, gBeepDurationDefault * 10);
								beepOn = TRUE;
							}
						}
					}
					if (gShiftActive && !gCapsLockActive) {
						gShiftActive = FALSE;
						TouchKbdDrawAllKeys();
						TouchKbdDrawKey(hitButton, TRUE);
					}
					if (gAltGrActive) {
						gAltGrActive = FALSE;
						TouchKbdDrawAllKeys();
						TouchKbdDrawKey(hitButton, TRUE);
					}
					break;

					case KEY_TYPE_SHIFT:
					gShiftActive = !gShiftActive;
					TouchKbdDrawAllKeys();
					TouchKbdDrawKey(hitButton, TRUE);
					break;

					case KEY_TYPE_CAPS:
					gCapsLockActive = !gCapsLockActive;
					TouchKbdDrawAllKeys();
					TouchKbdDrawKey(hitButton, TRUE);
					break;

					case KEY_TYPE_ALTGR:
					gAltGrActive = !gAltGrActive;
					TouchKbdDrawAllKeys();
					TouchKbdDrawKey(hitButton, TRUE);
					break;

					case KEY_TYPE_BACKSPACE:
					if (pwdPos > 0) {
						UINTN i;
						pwdPos--;
						for (i = pwdPos; i < pwdIdx - 1; i++) {
							SET_VAR_CHAR(pwd, wide, i, GET_VAR_CHAR(pwd, wide, i + 1));
						}
						pwdIdx--;
						SET_VAR_CHAR(pwd, wide, pwdIdx, '\0');
						TouchKbdDrawPasswordZone(pwd, pwdIdx, pwdPos, lineMax,
							visible, wide);
					}
					break;

					case KEY_TYPE_DELETE:
					if (pwdPos < pwdIdx) {
						UINTN i;
						for (i = pwdPos; i < pwdIdx - 1; i++) {
							SET_VAR_CHAR(pwd, wide, i, GET_VAR_CHAR(pwd, wide, i + 1));
						}
						pwdIdx--;
						SET_VAR_CHAR(pwd, wide, pwdIdx, '\0');
						TouchKbdDrawPasswordZone(pwd, pwdIdx, pwdPos, lineMax,
							visible, wide);
					}
					break;

					case KEY_TYPE_INSERT:
					if (pwdIdx < lineMax - 1) {
						UINTN i;
						for (i = pwdIdx; i > pwdPos; i--) {
							SET_VAR_CHAR(pwd, wide, i, GET_VAR_CHAR(pwd, wide, i - 1));
						}
						SET_VAR_CHAR(pwd, wide, pwdPos, ' ');
						pwdIdx++;
						SET_VAR_CHAR(pwd, wide, pwdIdx, '\0');
						TouchKbdDrawPasswordZone(pwd, pwdIdx, pwdPos, lineMax,
							visible, wide);
					}
					break;

					case KEY_TYPE_ARROW_L:
					if (pwdPos > 0) {
						pwdPos--;
						TouchKbdDrawPasswordZone(pwd, pwdIdx, pwdPos, lineMax,
							visible, wide);
					}
					break;

					case KEY_TYPE_ARROW_R:
					if (pwdPos < pwdIdx) {
						pwdPos++;
						TouchKbdDrawPasswordZone(pwd, pwdIdx, pwdPos, lineMax,
							visible, wide);
					}
					break;

					case KEY_TYPE_ARROW_U:
					case KEY_TYPE_ARROW_D:
					{
						// Pass up/down arrows to KeyFilter
						EFI_INPUT_KEY arrowKey;
						ZeroMem(&arrowKey, sizeof(arrowKey));
						arrowKey.ScanCode = pressedKey->ScanCode;
						arrowKey.UnicodeChar = 0;

						*retCode = KeyFilter(arrowKey, Param);

						if (*retCode == AskPwdRetShow) {
							visible = visible ? 0 : 1;
							TouchKbdDrawPasswordZone(pwd, pwdIdx, pwdPos, lineMax, visible, wide);
						} else if (*retCode == AskPwdRetCancel) {
							// Redraw status (callback may have changed state)
							GetStatus(statusStr, STATUS_BUFFER_SIZE, Param);
							TouchKbdDrawStatusLine(statusStr);
						} else if (*retCode != AskPwdRetNone) {
							goto exit_loop;
						}
					}
					break;

					case KEY_TYPE_ENTER:
					*retCode = AskPwdRetLogin;
					goto exit_loop;

					case KEY_TYPE_ESC:
					*retCode = AskPwdRetCancel;
					goto exit_loop;

					case KEY_TYPE_FN:
					{
						// Build EFI_INPUT_KEY for the function key and pass to KeyFilter
						EFI_INPUT_KEY fnKey;
						ZeroMem(&fnKey, sizeof(fnKey));
						fnKey.ScanCode = pressedKey->ScanCode;
						fnKey.UnicodeChar = 0;

						*retCode = KeyFilter(fnKey, Param);

						if (*retCode == AskPwdRetShow) {
							visible = visible ? 0 : 1;
							TouchKbdDrawPasswordZone(pwd, pwdIdx, pwdPos, lineMax, visible, wide);
						} else if (*retCode == AskPwdRetCancel) {
							// Redraw status (callback may have changed state)
							GetStatus(statusStr, STATUS_BUFFER_SIZE, Param);
							TouchKbdDrawStatusLine(statusStr);
						} else if (*retCode != AskPwdRetNone) {
							goto exit_loop;
						}
					}
					break;

					default:
						break;
					}
				}
			}
		}

		// ALWAYS update touch state tracking (must be outside the if/else blocks)
		if (gotTouchState) {
			wasTouchActive = (aps.ActiveButtons != 0);
		}

		// Update screen periodically
		if (gBS->CheckEvent(UpdateEvent) == EFI_SUCCESS) {
			ScreenUpdateDirty(gTouchKbdScreen);
			gBS->SetTimer(UpdateEvent, TimerRelative, 500000);
		}

	} while (TRUE);

exit_loop:
	// Set output length
	*pwdLen = (UINT32)pwdIdx;
	if (wide) *pwdLen *= 2;

	// Cleanup
	MEM_BURN(&key, sizeof(key));
	gBS->CloseEvent(InputEvents[1]);
	gBS->CloseEvent(UpdateEvent);
	gBS->CloseEvent(BeepOffEvent);

	// Clear screen
	ScreenFillRect(&gColorBlack, 0, 0, gTouchKbdWidth, gTouchKbdHeight);
	gBS->Stall(500000);

	// Free resources
	if (gKeyButtons != NULL) {
		MEM_FREE(gKeyButtons);
		gKeyButtons = NULL;
	}
	if (gTouchKbdScreen != NULL) {
		MEM_FREE(gTouchKbdScreen);
		gTouchKbdScreen = NULL;
	}

	// Reset modifier states for next use
	gShiftActive = FALSE;
	gCapsLockActive = FALSE;
	gAltGrActive = FALSE;
}
