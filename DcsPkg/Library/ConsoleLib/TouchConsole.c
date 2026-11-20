/** @file
Touch console implementation - full touch keyboard UI for all console operations

This file provides a complete touch-based console interface where the on-screen
keyboard is always visible and all input (GetKey, ReadLine, AskYesNo, AskPassword)
goes through the touch keyboard interface.

The screen is divided into:
- Status/text area (top) - for console output
- Password/input zone (middle) - for text input display
- Touch keyboard (bottom) - for input

Copyright (c) 2026. DiskCryptor, David Xanatos

This program and the accompanying materials are licensed and made available
under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>

#include <Library/CommonLib.h>
#include <Library/GraphLib.h>
#include <Library/ConsoleLib.h>

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
// Layout names (for keyboard layout switching)
//////////////////////////////////////////////////////////////////////////
static CHAR8* gLayoutNames[] = {
    "QWERTY",   // KB_MAP_QWERTY = 0
    "QWERTZ",   // KB_MAP_QWERTZ = 1
    "AZERTY"    // KB_MAP_AZERTY = 2
};
#define LAYOUT_COUNT 3

//////////////////////////////////////////////////////////////////////////
// Constants
//////////////////////////////////////////////////////////////////////////
#define TOUCH_TEXT_SCALE    96   // Scale for text rendering
#define TOUCH_CHAR_WIDTH    9    // Approximate char width at scale 96
#define TOUCH_CHAR_HEIGHT   15   // Approximate char height at scale 96
#define TOUCH_LINE_SPACING  2    // Extra pixels between lines

// Text attributes (matching %N, %E, %O, %H, %V color codes)
#define ATTR_NORMAL         0   // %N - light gray
#define ATTR_ERROR          1   // %E - yellow
#define ATTR_WARNING        2   // %O - orange
#define ATTR_HIGHLIGHT      3   // %H - bright white
#define ATTR_VALUE          4   // %V - green

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
// Private Data Structure - Extended for full touch console
//////////////////////////////////////////////////////////////////////////

typedef struct _TOUCH_CONSOLE_DATA {
    // Screen buffer
    BLT_HEADER      *Screen;

    // Screen dimensions
    UINTN           ScreenWidth;
    UINTN           ScreenHeight;

    // Text console buffer for status area
    CHAR16          *TextBuffer;
    UINT8           *AttrBuffer;
    UINTN           TextBufferSize;     // chars allocated in TextBuffer/AttrBuffer
    INT32           TextCols;
    INT32           TextRows;
    INT32           CursorCol;
    INT32           CursorRow;

    // Console area
    INT32           ConsoleLeft;
    INT32           ConsoleTop;
    INT32           ConsoleRight;
    INT32           ConsoleBottom;

    // Keyboard layout
    KEY_BUTTON      *KeyButtons;
    UINTN           KeyButtonCount;
    INT32           KeyWidth;
    INT32           KeyHeight;
    INT32           KeySpacing;
    INT32           KeyboardTop;
    INT32           KeyboardBottom;

    // Current keyboard layout
    INT32           CurrentLayout;

    // Modifier states
    BOOLEAN         ShiftActive;
    BOOLEAN         CapsLockActive;
    BOOLEAN         AltGrActive;

    // Drawing contexts
    DRAW_CONTEXT    CtxKeyNormal;
    DRAW_CONTEXT    CtxKeyPressed;
    DRAW_CONTEXT    CtxKeyModifier;
    DRAW_CONTEXT    CtxKeyText;
    DRAW_CONTEXT    CtxTextNormal;
    DRAW_CONTEXT    CtxTextError;
    DRAW_CONTEXT    CtxTextWarning;
    DRAW_CONTEXT    CtxTextHighlight;
    DRAW_CONTEXT    CtxTextValue;

    // State
    BOOLEAN         Initialized;
    BOOLEAN         KeyboardVisible;

} TOUCH_CONSOLE_DATA;

// Static console data
static TOUCH_CONSOLE_DATA gTouchData;

//////////////////////////////////////////////////////////////////////////
// Forward Declarations
//////////////////////////////////////////////////////////////////////////

STATIC TOUCH_KEY** TouchGetLayout(VOID);
STATIC UINTN TouchCountKeys(IN TOUCH_KEY** Layout);
STATIC VOID TouchCalculateLayout(VOID);
STATIC VOID TouchCreateDrawContexts(VOID);
STATIC VOID TouchDrawKey(IN KEY_BUTTON* Button, IN BOOLEAN Pressed);
STATIC VOID TouchDrawAllKeys(VOID);
STATIC VOID TouchRebuildLayout(VOID);
STATIC KEY_BUTTON* TouchHitTestKey(IN UINTN X, IN UINTN Y);
STATIC VOID TouchConsoleRefresh(VOID);
STATIC VOID TouchConsoleScroll(VOID);
STATIC VOID TouchConsolePutChar(IN CHAR16 Ch, IN UINT8 Attr);
STATIC VOID TouchConsolePrintInternal(IN CONST CHAR16 *Text, IN UINT8 Attr);
STATIC EFI_INPUT_KEY TouchWaitForKey(VOID);
STATIC BOOLEAN TouchEnsureInitialized(VOID);

//////////////////////////////////////////////////////////////////////////
// Keyboard Layout Translation for Physical Keyboard
//////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////
// Helper Functions
//////////////////////////////////////////////////////////////////////////

STATIC
TOUCH_KEY**
TouchGetLayout(VOID)
{
    // the layout configured now (it can change in the F6 menu)
    switch (gKeyboardLayout) {
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
UINTN
TouchCountKeys(
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
TouchCreateDrawContexts(VOID)
{
    // Normal key
    gTouchData.CtxKeyNormal.Color = gColorGray;
    gTouchData.CtxKeyNormal.DashLine = 0xFFFFFFFF;
    gTouchData.CtxKeyNormal.Op = DrawOpSet;
    gTouchData.CtxKeyNormal.Brush = gBrush3;

    // Pressed key
    gTouchData.CtxKeyPressed.Color = gColorGreen;
    gTouchData.CtxKeyPressed.DashLine = 0xFFFFFFFF;
    gTouchData.CtxKeyPressed.Op = DrawOpSet;
    gTouchData.CtxKeyPressed.Brush = gBrush3;

    // Modifier key (active)
    gTouchData.CtxKeyModifier.Color = gColorBlue;
    gTouchData.CtxKeyModifier.DashLine = 0xFFFFFFFF;
    gTouchData.CtxKeyModifier.Op = DrawOpSet;
    gTouchData.CtxKeyModifier.Brush = gBrush3;

    // Key text
    gTouchData.CtxKeyText.Color = gColorWhite;
    gTouchData.CtxKeyText.DashLine = 0xFFFFFFFF;
    gTouchData.CtxKeyText.Op = DrawOpSet;
    gTouchData.CtxKeyText.Brush = NULL;

    // Normal text (white)
    gTouchData.CtxTextNormal.Color = gColorWhite;
    gTouchData.CtxTextNormal.DashLine = 0xFFFFFFFF;
    gTouchData.CtxTextNormal.Op = DrawOpSet;
    gTouchData.CtxTextNormal.Brush = NULL;

    // Error text (red)
    // Error text (yellow)
    gTouchData.CtxTextError.Color.Blue = 0;
    gTouchData.CtxTextError.Color.Green = 255;
    gTouchData.CtxTextError.Color.Red = 255;
    gTouchData.CtxTextError.Color.Reserved = 0;
    gTouchData.CtxTextError.DashLine = 0xFFFFFFFF;
    gTouchData.CtxTextError.Op = DrawOpSet;
    gTouchData.CtxTextError.Brush = NULL;

    // Warning text (orange)
    gTouchData.CtxTextWarning.Color.Blue = 0;
    gTouchData.CtxTextWarning.Color.Green = 165;
    gTouchData.CtxTextWarning.Color.Red = 255;
    gTouchData.CtxTextWarning.Color.Reserved = 0;
    gTouchData.CtxTextWarning.DashLine = 0xFFFFFFFF;
    gTouchData.CtxTextWarning.Op = DrawOpSet;
    gTouchData.CtxTextWarning.Brush = NULL;

    // Highlight text (bright white)
    gTouchData.CtxTextHighlight.Color.Blue = 255;
    gTouchData.CtxTextHighlight.Color.Green = 255;
    gTouchData.CtxTextHighlight.Color.Red = 255;
    gTouchData.CtxTextHighlight.Color.Reserved = 0;
    gTouchData.CtxTextHighlight.DashLine = 0xFFFFFFFF;
    gTouchData.CtxTextHighlight.Op = DrawOpSet;
    gTouchData.CtxTextHighlight.Brush = NULL;

    // Value text (green)
    gTouchData.CtxTextValue.Color.Blue = 0;
    gTouchData.CtxTextValue.Color.Green = 255;
    gTouchData.CtxTextValue.Color.Red = 0;
    gTouchData.CtxTextValue.Color.Reserved = 0;
    gTouchData.CtxTextValue.DashLine = 0xFFFFFFFF;
    gTouchData.CtxTextValue.Op = DrawOpSet;
    gTouchData.CtxTextValue.Brush = NULL;
}

STATIC
VOID
TouchDrawKey(
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
        ctx = &gTouchData.CtxKeyPressed;
    } else if (Button->Key->Type == KEY_TYPE_SHIFT && gTouchData.ShiftActive) {
        ctx = &gTouchData.CtxKeyModifier;
    } else if (Button->Key->Type == KEY_TYPE_CAPS && gTouchData.CapsLockActive) {
        ctx = &gTouchData.CtxKeyModifier;
    } else if (Button->Key->Type == KEY_TYPE_ALTGR && gTouchData.AltGrActive) {
        ctx = &gTouchData.CtxKeyModifier;
    } else {
        ctx = &gTouchData.CtxKeyNormal;
    }

    // Draw key background
    BltFill(gTouchData.Screen, gColorBlack,
        Button->X, Button->Y,
        Button->X + Button->Width, Button->Y + Button->Height);

    // Draw key border
    BltBox(gTouchData.Screen, ctx,
        Button->X + 2, Button->Y + 2,
        Button->X + Button->Width - 2, Button->Y + Button->Height - 2);

    // Determine what character to display
    if (Button->Key->Type == KEY_TYPE_CHAR) {
        if (gTouchData.AltGrActive && Button->Key->AltGr != 0) {
            ch = Button->Key->AltGr;
        } else if (gTouchData.ShiftActive != gTouchData.CapsLockActive) {
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
    BltText(gTouchData.Screen, &gTouchData.CtxKeyText, textX, textY, 128, displayLabel, FALSE);

    Button->Pressed = Pressed;
}

STATIC
VOID
TouchDrawAllKeys(VOID)
{
    UINTN i;
    for (i = 0; i < gTouchData.KeyButtonCount; i++) {
        TouchDrawKey(&gTouchData.KeyButtons[i], FALSE);
    }
}

STATIC
VOID
TouchCalculateLayout(VOID)
{
    TOUCH_KEY** layout = TouchGetLayout();
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
    gTouchData.KeySpacing = 4;

    // Calculate available space for keyboard
    INT32 topMargin = 10;
    INT32 bottomMargin = 10;  // Small margin from screen bottom (layout bar removed)
    INT32 availableWidth = (INT32)gTouchData.ScreenWidth - 40;
    INT32 availableHeight = (INT32)gTouchData.ScreenHeight - topMargin - bottomMargin;

    // Calculate key size
    gTouchData.KeyWidth = (availableWidth - (maxRowWidth + 1) * gTouchData.KeySpacing) / maxRowWidth;
    gTouchData.KeyHeight = (availableHeight - ((INT32)numRows + 1) * gTouchData.KeySpacing) / (INT32)numRows;

    // Limit key height
    if (gTouchData.KeyHeight > gTouchData.KeyWidth) {
        gTouchData.KeyHeight = gTouchData.KeyWidth;
    }

    // Reduce key height by 20% to give more space to console area
    gTouchData.KeyHeight = (gTouchData.KeyHeight * 80) / 100;

    // Calculate keyboard dimensions
    INT32 keyboardHeight = (INT32)numRows * (gTouchData.KeyHeight + gTouchData.KeySpacing);

    // Position keyboard at bottom of screen
    INT32 keyboardAreaTop = (INT32)gTouchData.ScreenHeight - keyboardHeight - bottomMargin;
    gTouchData.KeyboardTop = keyboardAreaTop;
    gTouchData.KeyboardBottom = gTouchData.KeyboardTop + keyboardHeight;

    // Console area fills from top to just above keyboard
    INT32 consoleGap = 10;
    gTouchData.ConsoleLeft = 20;
    gTouchData.ConsoleTop = 5;
    gTouchData.ConsoleRight = (INT32)gTouchData.ScreenWidth - 20;
    gTouchData.ConsoleBottom = gTouchData.KeyboardTop - consoleGap;

    // Calculate text console dimensions
    INT32 consoleWidth = gTouchData.ConsoleRight - gTouchData.ConsoleLeft;
    INT32 consoleHeight = gTouchData.ConsoleBottom - gTouchData.ConsoleTop;
    gTouchData.TextCols = consoleWidth / TOUCH_CHAR_WIDTH;
    gTouchData.TextRows = consoleHeight / (TOUCH_CHAR_HEIGHT + TOUCH_LINE_SPACING);

    // Limit console dimensions (25 rows = standard terminal, allow up to 40 for larger screens)
    if (gTouchData.TextCols > 120) gTouchData.TextCols = 120;
    if (gTouchData.TextRows > 40) gTouchData.TextRows = 40;
    if (gTouchData.TextCols < 20) gTouchData.TextCols = 20;
    if (gTouchData.TextRows < 5) gTouchData.TextRows = 5;

    // Create button layout
    y = gTouchData.KeyboardTop;
    for (row = 0; layout[row] != NULL; row++) {
        // Calculate row width to center it
        totalUnits = 0;
        for (col = 0; layout[row][col].Label[0] != 0; col++) {
            totalUnits += layout[row][col].Width;
        }

        INT32 rowWidth = totalUnits * (gTouchData.KeyWidth + gTouchData.KeySpacing) - gTouchData.KeySpacing;
        x = ((INT32)gTouchData.ScreenWidth - rowWidth) / 2;

        for (col = 0; layout[row][col].Label[0] != 0; col++) {
            TOUCH_KEY* key = &layout[row][col];
            KEY_BUTTON* button = &gTouchData.KeyButtons[buttonIdx++];

            button->Key = key;
            button->X = x;
            button->Y = y;
            button->Width = key->Width * (gTouchData.KeyWidth + gTouchData.KeySpacing) - gTouchData.KeySpacing;
            button->Height = gTouchData.KeyHeight;
            button->Pressed = FALSE;

            x += button->Width + gTouchData.KeySpacing;
        }
        y += gTouchData.KeyHeight + gTouchData.KeySpacing;
    }
}

STATIC
VOID
TouchRebuildLayout(VOID)
{
    TOUCH_KEY** layout = TouchGetLayout();
    UINTN newCount = TouchCountKeys(layout);

    // Reallocate if needed
    if (newCount != gTouchData.KeyButtonCount) {
        if (gTouchData.KeyButtons != NULL) {
            MEM_FREE(gTouchData.KeyButtons);
        }
        gTouchData.KeyButtonCount = newCount;
        gTouchData.KeyButtons = MEM_ALLOC(sizeof(KEY_BUTTON) * gTouchData.KeyButtonCount);
    }

    TouchCalculateLayout();
}

STATIC
KEY_BUTTON*
TouchHitTestKey(
    IN UINTN X,
    IN UINTN Y
    )
{
    UINTN i;
    for (i = 0; i < gTouchData.KeyButtonCount; i++) {
        KEY_BUTTON* btn = &gTouchData.KeyButtons[i];
        if ((INT32)X >= btn->X && (INT32)X < btn->X + btn->Width &&
            (INT32)Y >= btn->Y && (INT32)Y < btn->Y + btn->Height) {
            return btn;
        }
    }
    return NULL;
}

//////////////////////////////////////////////////////////////////////////
// Console Text Rendering
//////////////////////////////////////////////////////////////////////////

STATIC
VOID
TouchConsoleRenderLine(
    IN INT32 Row
    )
{
    if (Row < 0 || Row >= gTouchData.TextRows) {
        return;
    }

    // Calculate pixel coordinates
    INT32 pixelY = gTouchData.ConsoleTop + (Row * (TOUCH_CHAR_HEIGHT + TOUCH_LINE_SPACING));
    INT32 pixelX = gTouchData.ConsoleLeft;

    // Clear line area
    BltFill(gTouchData.Screen, gColorBlack,
            gTouchData.ConsoleLeft, pixelY,
            gTouchData.ConsoleRight, pixelY + TOUCH_CHAR_HEIGHT + TOUCH_LINE_SPACING);

    // Get line data
    INT32 lineOffset = Row * gTouchData.TextCols;
    CHAR16 *lineText = &gTouchData.TextBuffer[lineOffset];
    UINT8 *lineAttr = &gTouchData.AttrBuffer[lineOffset];

    // Render text in segments by attribute
    INT32 segStart = 0;
    UINT8 currentAttr = lineAttr[0];
    CHAR16 charBuf[128];

    for (INT32 col = 0; col <= gTouchData.TextCols; col++) {
        UINT8 attr = (col < gTouchData.TextCols) ? lineAttr[col] : 0xFF;

        if (attr != currentAttr || col == gTouchData.TextCols) {
            // Render segment
            INT32 segLen = col - segStart;
            if (segLen > 0 && segLen < 128) {
                CopyMem(charBuf, &lineText[segStart], segLen * sizeof(CHAR16));
                charBuf[segLen] = 0;

                PDRAW_CONTEXT ctx;
                switch (currentAttr) {
                    case ATTR_ERROR:
                        ctx = &gTouchData.CtxTextError;
                        break;
                    case ATTR_WARNING:
                        ctx = &gTouchData.CtxTextWarning;
                        break;
                    case ATTR_HIGHLIGHT:
                        ctx = &gTouchData.CtxTextHighlight;
                        break;
                    case ATTR_VALUE:
                        ctx = &gTouchData.CtxTextValue;
                        break;
                    default:
                        ctx = &gTouchData.CtxTextNormal;
                        break;
                }

                BltTextMono(gTouchData.Screen, ctx,
                        pixelX + (segStart * TOUCH_CHAR_WIDTH),
                        pixelY,
                        TOUCH_TEXT_SCALE, charBuf, TRUE);
            }
            segStart = col;
            currentAttr = attr;
        }
    }
}

STATIC
VOID
TouchConsoleRefresh(VOID)
{
    if (!gTouchData.Initialized || gTouchData.Screen == NULL) {
        return;
    }

    // Clear console area
    BltFill(gTouchData.Screen, gColorBlack,
            gTouchData.ConsoleLeft, gTouchData.ConsoleTop,
            gTouchData.ConsoleRight, gTouchData.ConsoleBottom);

    // Render all lines
    for (INT32 row = 0; row < gTouchData.TextRows; row++) {
        TouchConsoleRenderLine(row);
    }
}

STATIC
VOID
TouchConsoleScroll(VOID)
{
    // Move all lines up by one
    UINTN lineSize = (UINTN)gTouchData.TextCols * sizeof(CHAR16);
    UINTN attrLineSize = (UINTN)gTouchData.TextCols;

    for (INT32 row = 0; row < gTouchData.TextRows - 1; row++) {
        CopyMem(&gTouchData.TextBuffer[row * gTouchData.TextCols],
                &gTouchData.TextBuffer[(row + 1) * gTouchData.TextCols],
                lineSize);
        CopyMem(&gTouchData.AttrBuffer[row * gTouchData.TextCols],
                &gTouchData.AttrBuffer[(row + 1) * gTouchData.TextCols],
                attrLineSize);
    }

    // Clear last line
    INT32 lastRow = gTouchData.TextRows - 1;
    for (INT32 col = 0; col < gTouchData.TextCols; col++) {
        gTouchData.TextBuffer[lastRow * gTouchData.TextCols + col] = L' ';
        gTouchData.AttrBuffer[lastRow * gTouchData.TextCols + col] = ATTR_NORMAL;
    }

    gTouchData.CursorRow = gTouchData.TextRows - 1;
}

STATIC
VOID
TouchConsolePutChar(
    IN CHAR16 Ch,
    IN UINT8 Attr
    )
{
    if (!gTouchData.Initialized) {
        return;
    }

    if (Ch == L'\n') {
        gTouchData.CursorCol = 0;
        gTouchData.CursorRow++;
        if (gTouchData.CursorRow >= gTouchData.TextRows) {
            TouchConsoleScroll();
        }
        return;
    }

    if (Ch == L'\r') {
        gTouchData.CursorCol = 0;
        return;
    }

    if (Ch == L'\b') {
        // Wrap back to the previous row so erase sequences clear wrapped text
        if (gTouchData.CursorCol <= 0 && gTouchData.CursorRow > 0) {
            gTouchData.CursorRow--;
            gTouchData.CursorCol = gTouchData.TextCols;
        }
        if (gTouchData.CursorCol > 0) {
            gTouchData.CursorCol--;
            INT32 idx = gTouchData.CursorRow * gTouchData.TextCols + gTouchData.CursorCol;
            gTouchData.TextBuffer[idx] = L' ';
            gTouchData.AttrBuffer[idx] = ATTR_NORMAL;
        }
        return;
    }

    // Store character
    if (gTouchData.CursorRow >= 0 && gTouchData.CursorRow < gTouchData.TextRows &&
        gTouchData.CursorCol >= 0 && gTouchData.CursorCol < gTouchData.TextCols) {
        INT32 idx = gTouchData.CursorRow * gTouchData.TextCols + gTouchData.CursorCol;
        gTouchData.TextBuffer[idx] = Ch;
        gTouchData.AttrBuffer[idx] = Attr;
    }

    // Advance cursor
    gTouchData.CursorCol++;
    if (gTouchData.CursorCol >= gTouchData.TextCols) {
        gTouchData.CursorCol = 0;
        gTouchData.CursorRow++;
        if (gTouchData.CursorRow >= gTouchData.TextRows) {
            TouchConsoleScroll();
        }
    }
}

STATIC
VOID
TouchConsolePrintInternal(
    IN CONST CHAR16 *Text,
    IN UINT8 Attr
    )
{
    if (Text == NULL) {
        return;
    }

    // Ensure graphics are initialized
    if (!TouchEnsureInitialized()) {
        return;
    }

    while (*Text) {
        TouchConsolePutChar(*Text, Attr);
        Text++;
    }

    TouchConsoleRefresh();
    if (gTouchData.Screen != NULL) {
        ScreenUpdateDirty(gTouchData.Screen);
    }
}

STATIC
VOID
TouchDrawFullScreen(VOID)
{
    if (gTouchData.Screen == NULL) {
        return;
    }

    // Clear entire screen
    BltFill(gTouchData.Screen, gColorBlack, 0, 0, (INT32)gTouchData.ScreenWidth, (INT32)gTouchData.ScreenHeight);

    // Draw console text
    TouchConsoleRefresh();

    // Draw keyboard
    TouchDrawAllKeys();
}

//////////////////////////////////////////////////////////////////////////
// Key Input Handler
//////////////////////////////////////////////////////////////////////////

/**
  Map an absolute pointer state to screen coordinates.
  Returns FALSE if the device reports an empty coordinate range.
**/
STATIC
BOOLEAN
TouchGetScreenPos(
    IN EFI_ABSOLUTE_POINTER_STATE *Aps,
    OUT UINTN *X,
    OUT UINTN *Y
    )
{
    EFI_ABSOLUTE_POINTER_MODE *mode = gTouchPointer->Mode;
    UINT64 cx, cy;

    if (mode == NULL ||
        mode->AbsoluteMaxX <= mode->AbsoluteMinX ||
        mode->AbsoluteMaxY <= mode->AbsoluteMinY) {
        return FALSE;
    }

    cx = MIN(MAX(Aps->CurrentX, mode->AbsoluteMinX), mode->AbsoluteMaxX);
    cy = MIN(MAX(Aps->CurrentY, mode->AbsoluteMinY), mode->AbsoluteMaxY);
    *X = (UINTN)((cx - mode->AbsoluteMinX) * gTouchData.ScreenWidth /
        (mode->AbsoluteMaxX - mode->AbsoluteMinX));
    *Y = (UINTN)((cy - mode->AbsoluteMinY) * gTouchData.ScreenHeight /
        (mode->AbsoluteMaxY - mode->AbsoluteMinY));
    return TRUE;
}

/**
  Wait for a key press from either physical keyboard or touch keyboard.
  Handles touch keyboard highlighting and returns the resulting key.
**/
STATIC
EFI_INPUT_KEY
TouchWaitForKey(VOID)
{
    EFI_STATUS res;
    EFI_INPUT_KEY key;
    EFI_EVENT InputEvents[3];
    UINTN eventsCount = 2;
    UINTN EventIndex;
    EFI_ABSOLUTE_POINTER_STATE aps = {0};
    UINTN curX = 0, curY = 0;
    BOOLEAN wasTouchActive = FALSE;
    BOOLEAN keyProcessedThisTouch = FALSE;
    KEY_BUTTON* highlightedKey = NULL;
    EFI_INPUT_KEY resultKey;
    BOOLEAN gotKey = FALSE;

    ZeroMem(&resultKey, sizeof(resultKey));

    // Ensure screen is allocated and drawn
    if (gTouchData.Screen == NULL) {
        ScreenSaveBlt(&gTouchData.Screen);
        if (gTouchData.Screen != NULL) {
            gTouchData.ScreenWidth = gTouchData.Screen->Width;
            gTouchData.ScreenHeight = gTouchData.Screen->Height;
            TouchRebuildLayout();
            TouchDrawFullScreen();
        }
    }

    // Refresh console and update screen
    TouchConsoleRefresh();
    ScreenUpdateDirty(gTouchData.Screen);

    // Setup events
    InputEvents[0] = gST->ConIn->WaitForKey;
    gBS->CreateEvent(EVT_TIMER, 0, (EFI_EVENT_NOTIFY)NULL, NULL, &InputEvents[1]);
    gBS->SetTimer(InputEvents[1], TimerRelative, 500000);  // 50ms timer

    if (gTouchPointer != NULL) {
        eventsCount = 3;
        InputEvents[2] = gTouchPointer->WaitForInput;
        // Clear pending touch events (touch state is position-based, old positions are stale)
        while (gBS->CheckEvent(InputEvents[2]) == EFI_SUCCESS) {
            gTouchPointer->GetState(gTouchPointer, &aps);
        }
    }

    // Check for already-pending keyboard input first (don't discard buffered keystrokes)
    // through the shared mapper (layout, AltGr, Caps Lock, dead keys)
    res = KbReadKey(&key);
    if (!EFI_ERROR(res)) {
        gBS->CloseEvent(InputEvents[1]);
        return key;
    }

    // Main input loop
    while (!gotKey) {
        ZeroMem(&key, sizeof(key));
        res = gBS->WaitForEvent(eventsCount, InputEvents, &EventIndex);

        // Handle physical keyboard input
        if (EventIndex == 0) {
            res = KbReadKey(&key);   // mapped as on the text console
            if (!EFI_ERROR(res)) {
                resultKey = key;
                gotKey = TRUE;
                break;
            }
        }

        // Handle touch input
        BOOLEAN gotTouchState = FALSE;
        if (EventIndex == 2 && gTouchPointer != NULL) {
            KbResetState();   // a physical dead key does not carry over to touch input
            res = gTouchPointer->GetState(gTouchPointer, &aps);
            if (!EFI_ERROR(res)) {
                gotTouchState = TouchGetScreenPos(&aps, &curX, &curY);
            }
        }
        // Poll touch on timer if we have highlighted elements
        else if (EventIndex == 1 && gTouchPointer != NULL &&
                 (wasTouchActive || highlightedKey != NULL)) {
            res = gTouchPointer->GetState(gTouchPointer, &aps);
            if (!EFI_ERROR(res)) {
                gotTouchState = TouchGetScreenPos(&aps, &curX, &curY);
            } else if (highlightedKey != NULL) {
                // Clear highlight on failed GetState
                TouchDrawKey(highlightedKey, FALSE);
                highlightedKey = NULL;
                wasTouchActive = FALSE;
                keyProcessedThisTouch = FALSE;
                ScreenUpdateDirty(gTouchData.Screen);
            }
        }

        // Process touch state
        if (gotTouchState) {
            BOOLEAN isTouchActive = (aps.ActiveButtons != 0);
            KEY_BUTTON* hitButton = TouchHitTestKey(curX, curY);

            // Touch released
            if (wasTouchActive && !isTouchActive) {
                if (highlightedKey != NULL) {
                    TouchDrawKey(highlightedKey, FALSE);
                    highlightedKey = NULL;
                }
                keyProcessedThisTouch = FALSE;
                ScreenUpdateDirty(gTouchData.Screen);
            }
            // Touch active and not yet processed
            else if (isTouchActive && !keyProcessedThisTouch) {
                // Clear old highlight
                if (highlightedKey != NULL) {
                    TouchDrawKey(highlightedKey, FALSE);
                    highlightedKey = NULL;
                }

                // Key button hit
                if (hitButton != NULL) {
                    TouchDrawKey(hitButton, TRUE);
                    highlightedKey = hitButton;
                    keyProcessedThisTouch = TRUE;

                    TOUCH_KEY* pressedKey = hitButton->Key;

                    switch (pressedKey->Type) {
                    case KEY_TYPE_CHAR:
                    case KEY_TYPE_SPACE:
                    case KEY_TYPE_TAB:
                    {
                        CHAR8 ch = 0;
                        if (pressedKey->Type == KEY_TYPE_CHAR) {
                            if (gTouchData.AltGrActive && pressedKey->AltGr != 0) {
                                ch = pressedKey->AltGr;
                            } else if (gTouchData.ShiftActive != gTouchData.CapsLockActive) {
                                ch = pressedKey->Shifted;
                            } else {
                                ch = pressedKey->Normal;
                            }
                        } else {
                            ch = pressedKey->Normal;
                        }
                        if (ch != 0) {
                            resultKey.ScanCode = 0;
                            resultKey.UnicodeChar = (CHAR16)ch;
                            gotKey = TRUE;
                        }
                        // Reset shift after character (unless caps lock)
                        if (gTouchData.ShiftActive && !gTouchData.CapsLockActive) {
                            gTouchData.ShiftActive = FALSE;
                            TouchDrawAllKeys();
                            if (highlightedKey) TouchDrawKey(highlightedKey, TRUE);
                        }
                        if (gTouchData.AltGrActive) {
                            gTouchData.AltGrActive = FALSE;
                            TouchDrawAllKeys();
                            if (highlightedKey) TouchDrawKey(highlightedKey, TRUE);
                        }
                    }
                    break;

                    case KEY_TYPE_SHIFT:
                        gTouchData.ShiftActive = !gTouchData.ShiftActive;
                        TouchDrawAllKeys();
                        TouchDrawKey(hitButton, TRUE);
                        break;

                    case KEY_TYPE_CAPS:
                        gTouchData.CapsLockActive = !gTouchData.CapsLockActive;
                        TouchDrawAllKeys();
                        TouchDrawKey(hitButton, TRUE);
                        break;

                    case KEY_TYPE_ALTGR:
                        gTouchData.AltGrActive = !gTouchData.AltGrActive;
                        TouchDrawAllKeys();
                        TouchDrawKey(hitButton, TRUE);
                        break;

                    case KEY_TYPE_BACKSPACE:
                        resultKey.ScanCode = 0;
                        resultKey.UnicodeChar = CHAR_BACKSPACE;
                        gotKey = TRUE;
                        break;

                    case KEY_TYPE_ENTER:
                        resultKey.ScanCode = 0;
                        resultKey.UnicodeChar = CHAR_CARRIAGE_RETURN;
                        gotKey = TRUE;
                        break;

                    case KEY_TYPE_ESC:
                        resultKey.ScanCode = SCAN_ESC;
                        resultKey.UnicodeChar = 0;
                        gotKey = TRUE;
                        break;

                    case KEY_TYPE_DELETE:
                        resultKey.ScanCode = SCAN_DELETE;
                        resultKey.UnicodeChar = 0;
                        gotKey = TRUE;
                        break;

                    case KEY_TYPE_INSERT:
                        resultKey.ScanCode = SCAN_INSERT;
                        resultKey.UnicodeChar = 0;
                        gotKey = TRUE;
                        break;

                    case KEY_TYPE_ARROW_L:
                        resultKey.ScanCode = SCAN_LEFT;
                        resultKey.UnicodeChar = 0;
                        gotKey = TRUE;
                        break;

                    case KEY_TYPE_ARROW_R:
                        resultKey.ScanCode = SCAN_RIGHT;
                        resultKey.UnicodeChar = 0;
                        gotKey = TRUE;
                        break;

                    case KEY_TYPE_ARROW_U:
                        resultKey.ScanCode = SCAN_UP;
                        resultKey.UnicodeChar = 0;
                        gotKey = TRUE;
                        break;

                    case KEY_TYPE_ARROW_D:
                        resultKey.ScanCode = SCAN_DOWN;
                        resultKey.UnicodeChar = 0;
                        gotKey = TRUE;
                        break;

                    case KEY_TYPE_FN:
                        resultKey.ScanCode = pressedKey->ScanCode;
                        resultKey.UnicodeChar = 0;
                        gotKey = TRUE;
                        break;

                    default:
                        break;
                    }
                }

                ScreenUpdateDirty(gTouchData.Screen);
            }

            wasTouchActive = (aps.ActiveButtons != 0);
        }

        // Reset timer
        if (EventIndex == 1) {
            gBS->SetTimer(InputEvents[1], TimerRelative, 500000);
        }
    }

    // Clear any remaining highlight before returning (with brief delay for visual feedback)
    if (highlightedKey != NULL) {
        gBS->Stall(100000);  // 100ms delay for visual feedback
        TouchDrawKey(highlightedKey, FALSE);
        ScreenUpdateDirty(gTouchData.Screen);
    }

    // Cleanup
    gBS->CloseEvent(InputEvents[1]);

    return resultKey;
}

//////////////////////////////////////////////////////////////////////////
// Public Interface - Initialization
//////////////////////////////////////////////////////////////////////////

/**
  Minimal initialization - just sets up state, no graphics.
  Graphics are initialized lazily when first needed.
**/
EFI_STATUS
TouchConsoleInitialize(VOID)
{
    // Just zero out the structure - actual initialization is lazy
    ZeroMem(&gTouchData, sizeof(gTouchData));

    // Initialize from global keyboard layout setting
    gTouchData.CurrentLayout = gKeyboardLayout;

    // Mark as not yet initialized - will be done on first use
    gTouchData.Initialized = FALSE;

    return EFI_SUCCESS;
}

/**
  Perform actual graphics initialization when first needed.
  Called by functions that need the touch UI to be visible.
**/
STATIC
BOOLEAN
TouchEnsureInitialized(VOID)
{
    UINTN bufferSize;

    if (gTouchData.Initialized) {
        return TRUE;
    }

    // Switch console to graphics mode - crucial for graphics to be visible
    InitConsoleControl();

    // Initialize drawing contexts
    TouchCreateDrawContexts();

    // Get screen and allocate
    if (gTouchData.Screen == NULL) {
        ScreenSaveBlt(&gTouchData.Screen);
    }
    if (gTouchData.Screen == NULL) {
        return FALSE;
    }

    gTouchData.ScreenWidth = gTouchData.Screen->Width;
    gTouchData.ScreenHeight = gTouchData.Screen->Height;

    // Count keys and allocate button array
    if (gTouchData.KeyButtons == NULL) {
        TOUCH_KEY** layout = TouchGetLayout();
        gTouchData.KeyButtonCount = TouchCountKeys(layout);
        gTouchData.KeyButtons = MEM_ALLOC(sizeof(KEY_BUTTON) * gTouchData.KeyButtonCount);
        if (gTouchData.KeyButtons == NULL) {
            return FALSE;
        }
    }

    // Calculate layout
    TouchCalculateLayout();

    // Allocate text buffers
    bufferSize = (UINTN)(gTouchData.TextCols * gTouchData.TextRows);
    if (bufferSize > 0 && (gTouchData.TextBuffer == NULL || gTouchData.AttrBuffer == NULL)) {
        MEM_FREE(gTouchData.TextBuffer);
        MEM_FREE(gTouchData.AttrBuffer);
        gTouchData.TextBuffer = MEM_ALLOC(bufferSize * sizeof(CHAR16));
        gTouchData.AttrBuffer = MEM_ALLOC(bufferSize);
        gTouchData.TextBufferSize = bufferSize;

        if (gTouchData.TextBuffer == NULL || gTouchData.AttrBuffer == NULL) {
            MEM_FREE(gTouchData.TextBuffer);
            MEM_FREE(gTouchData.AttrBuffer);
            gTouchData.TextBuffer = NULL;
            gTouchData.AttrBuffer = NULL;
            gTouchData.TextBufferSize = 0;
            return FALSE;
        }

        // Initialize text buffers
        for (UINTN i = 0; i < bufferSize; i++) {
            gTouchData.TextBuffer[i] = L' ';
            gTouchData.AttrBuffer[i] = ATTR_NORMAL;
        }
    }

    gTouchData.CursorCol = 0;
    gTouchData.CursorRow = 0;
    gTouchData.ShiftActive = FALSE;
    gTouchData.CapsLockActive = FALSE;
    gTouchData.AltGrActive = FALSE;
    gTouchData.KeyboardVisible = TRUE;
    gTouchData.Initialized = TRUE;

    // Draw initial screen - use ScreenDrawBlt for full screen update
    TouchDrawFullScreen();
    ScreenDrawBlt(gTouchData.Screen, 0, 0);

    return TRUE;
}

VOID
TouchConsoleShutdown(VOID)
{
    // Text and pixel buffers may hold echoed password characters
    if (gTouchData.TextBuffer != NULL) {
        MEM_BURN(gTouchData.TextBuffer, gTouchData.TextBufferSize * sizeof(CHAR16));
        MEM_FREE(gTouchData.TextBuffer);
        gTouchData.TextBuffer = NULL;
    }
    if (gTouchData.AttrBuffer != NULL) {
        MEM_BURN(gTouchData.AttrBuffer, gTouchData.TextBufferSize);
        MEM_FREE(gTouchData.AttrBuffer);
        gTouchData.AttrBuffer = NULL;
    }
    gTouchData.TextBufferSize = 0;
    if (gTouchData.KeyButtons != NULL) {
        MEM_FREE(gTouchData.KeyButtons);
        gTouchData.KeyButtons = NULL;
    }
    if (gTouchData.Screen != NULL) {
        // Clear screen before freeing
        ScreenFillRect(&gColorBlack, 0, 0, gTouchData.ScreenWidth, gTouchData.ScreenHeight);
        MEM_BURN(gTouchData.Screen->Pixels,
            (UINTN)gTouchData.Screen->Width * gTouchData.Screen->Height * sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL));
        MEM_FREE(gTouchData.Screen);
        gTouchData.Screen = NULL;
    }

    gTouchData.Initialized = FALSE;
    gTouchData.ShiftActive = FALSE;
    gTouchData.CapsLockActive = FALSE;
    gTouchData.AltGrActive = FALSE;
}

VOID*
TouchConsoleGetPrivateData(VOID)
{
    return &gTouchData;
}

//////////////////////////////////////////////////////////////////////////
// Public Interface - Output Functions
//////////////////////////////////////////////////////////////////////////

// Colour codes of the format become marker + letter; formatted twice with two markers,
// only where the results differ is a colour code (as EfiAttrPrint.c, ATTR_MARK_1)
#define COLOR_MARKER_1 ((CHAR16)0xF8F0)
#define COLOR_MARKER_2 ((CHAR16)0xF8F1)

/**
  Copy Input to Output (OutputSize bytes), replacing each colour code "%X" by Marker followed by X.
  "%%" and any other "%." pair are copied whole (left to UnicodeVSPrint); a pair is never split; a
  lone '%' at the end is dropped.
**/
STATIC
VOID
EscapeColorCodes(
    IN CONST CHAR16 *Input,
    OUT CHAR16 *Output,
    IN UINTN OutputSize,
    IN CHAR16 Marker
    )
{
    UINTN outIdx = 0;
    UINTN maxIdx = OutputSize / sizeof(CHAR16) - 1;

    while (*Input) {
        if (*Input == L'%' && *(Input + 1)) {
            CHAR16 code = *(Input + 1);
            if (outIdx + 2 > maxIdx) break;
            if (code == L'N' || code == L'E' || code == L'H' || code == L'V' || code == L'O' || code == L'B') {
                Output[outIdx++] = Marker;
            } else {
                Output[outIdx++] = L'%';
            }
            Output[outIdx++] = code;
            Input += 2;
            continue;
        }
        if (outIdx + 1 > maxIdx || *Input == L'%') break;
        Output[outIdx++] = *Input++;
    }
    Output[outIdx] = 0;
}

/**
  Print Text (formatted with COLOR_MARKER_1) applying the colour codes: the positions where Other
  (the same text formatted with COLOR_MARKER_2) differs.
  N (normal), E (error), H (highlight), V (value), O (orange/warning)
**/
STATIC
VOID
TouchConsolePrintWithColors(
    IN CONST CHAR16 *Text,
    IN CONST CHAR16 *Other
    )
{
    UINT8 currentAttr = ATTR_NORMAL;
    CONST CHAR16 *p = Text;
    CONST CHAR16 *q = Other;
    CHAR16 segment[256];
    UINTN segIdx = 0;

    if (Text == NULL || Other == NULL) return;

    while (*p) {
        // A colour code from the format: the two formattings differ here
        if (*p != *q && *(p + 1)) {
            CHAR16 code = *(p + 1);
            UINT8 newAttr = currentAttr;
            BOOLEAN isColorCode = TRUE;

            switch (code) {
                case L'N': newAttr = ATTR_NORMAL; break;
                case L'E': newAttr = ATTR_ERROR; break;
                case L'H': newAttr = ATTR_HIGHLIGHT; break;
                case L'V': newAttr = ATTR_VALUE; break;
                case L'O': newAttr = ATTR_WARNING; break;
                default: isColorCode = FALSE; break;
            }

            // Flush current segment
            if (segIdx > 0) {
                segment[segIdx] = 0;
                TouchConsolePrintInternal(segment, currentAttr);
                segIdx = 0;
            }
            if (isColorCode) {
                currentAttr = newAttr;
            }
            p += 2;  // Skip marker + X
            q += 2;
            continue;
        }
        if (*p != *q) {
            break;   // a marker cut off at the end of the buffer
        }

        // Regular character
        if (segIdx < 255) {
            segment[segIdx++] = *p;
        }
        p++;
        q++;

        // Flush if segment is full
        if (segIdx >= 255) {
            segment[segIdx] = 0;
            TouchConsolePrintInternal(segment, currentAttr);
            segIdx = 0;
        }
    }

    // Flush remaining
    if (segIdx > 0) {
        segment[segIdx] = 0;
        TouchConsolePrintInternal(segment, currentAttr);
    }
    MEM_BURN(segment, sizeof(segment));
}

VOID
TouchConsolePrint(
    IN CONST CHAR16 *Format,
    ...
    )
{
    VA_LIST Args;
    VA_LIST Args2;
    CHAR16 EscapedFormat[1024];
    CHAR16 EscapedFormat2[1024];
    CHAR16 Buffer[1024];
    CHAR16 Buffer2[1024];

    // Format twice with different markers for the colour codes
    EscapeColorCodes(Format, EscapedFormat, sizeof(EscapedFormat), COLOR_MARKER_1);
    EscapeColorCodes(Format, EscapedFormat2, sizeof(EscapedFormat2), COLOR_MARKER_2);

    VA_START(Args, Format);
    VA_COPY(Args2, Args);
    UnicodeVSPrint(Buffer, sizeof(Buffer), EscapedFormat, Args);
    UnicodeVSPrint(Buffer2, sizeof(Buffer2), EscapedFormat2, Args2);
    VA_END(Args2);
    VA_END(Args);

    TouchConsolePrintWithColors(Buffer, Buffer2);
    MEM_BURN(Buffer, sizeof(Buffer));
    MEM_BURN(Buffer2, sizeof(Buffer2));
}

VOID
TouchConsolePrintError(
    IN CONST CHAR16 *Format,
    ...
    )
{
    VA_LIST Args;
    CHAR16 Buffer[1024];

    VA_START(Args, Format);
    UnicodeVSPrint(Buffer, sizeof(Buffer), Format, Args);
    VA_END(Args);

    TouchConsolePrintInternal(Buffer, ATTR_ERROR);
}

VOID
TouchConsolePrintWarning(
    IN CONST CHAR16 *Format,
    ...
    )
{
    VA_LIST Args;
    CHAR16 Buffer[1024];

    VA_START(Args, Format);
    UnicodeVSPrint(Buffer, sizeof(Buffer), Format, Args);
    VA_END(Args);

    TouchConsolePrintInternal(Buffer, ATTR_WARNING);
}

VOID
TouchConsolePrintAt(
    IN INT32 Col,
    IN INT32 Row,
    IN CONST CHAR16 *Format,
    ...
    )
{
    VA_LIST Args;
    VA_LIST Args2;
    CHAR16 EscapedFormat[1024];
    CHAR16 EscapedFormat2[1024];
    CHAR16 Buffer[1024];
    CHAR16 Buffer2[1024];

    if (Col >= 0) gTouchData.CursorCol = Col;
    if (Row >= 0) gTouchData.CursorRow = Row;

    // Format twice with different markers for the colour codes
    EscapeColorCodes(Format, EscapedFormat, sizeof(EscapedFormat), COLOR_MARKER_1);
    EscapeColorCodes(Format, EscapedFormat2, sizeof(EscapedFormat2), COLOR_MARKER_2);

    VA_START(Args, Format);
    VA_COPY(Args2, Args);
    UnicodeVSPrint(Buffer, sizeof(Buffer), EscapedFormat, Args);
    UnicodeVSPrint(Buffer2, sizeof(Buffer2), EscapedFormat2, Args2);
    VA_END(Args2);
    VA_END(Args);

    TouchConsolePrintWithColors(Buffer, Buffer2);
    MEM_BURN(Buffer, sizeof(Buffer));
    MEM_BURN(Buffer2, sizeof(Buffer2));
}

VOID
TouchConsoleClear(VOID)
{
    if (!gTouchData.Initialized) {
        return;
    }

    UINTN bufferSize = (UINTN)(gTouchData.TextCols * gTouchData.TextRows);
    for (UINTN i = 0; i < bufferSize; i++) {
        gTouchData.TextBuffer[i] = L' ';
        gTouchData.AttrBuffer[i] = ATTR_NORMAL;
    }

    gTouchData.CursorCol = 0;
    gTouchData.CursorRow = 0;

    TouchDrawFullScreen();
    if (gTouchData.Screen != NULL) {
        ScreenUpdateDirty(gTouchData.Screen);
    }
}

VOID
TouchConsoleSetCursor(
    IN INT32 Col,
    IN INT32 Row
    )
{
    if (Col >= 0 && Col < gTouchData.TextCols) {
        gTouchData.CursorCol = Col;
    }
    if (Row >= 0 && Row < gTouchData.TextRows) {
        gTouchData.CursorRow = Row;
    }
}

VOID
TouchConsoleEnableCursor(
    IN BOOLEAN Enable
    )
{
    // Touch console doesn't have a blinking cursor
}

VOID
TouchConsoleGetCursor(
    OUT INT32 *Col,
    OUT INT32 *Row
    )
{
    if (Col != NULL) *Col = gTouchData.CursorCol;
    if (Row != NULL) *Row = gTouchData.CursorRow;
}

VOID
TouchConsoleGetSize(
    OUT INT32 *Cols,
    OUT INT32 *Rows
    )
{
    if (Cols != NULL) *Cols = gTouchData.TextCols;
    if (Rows != NULL) *Rows = gTouchData.TextRows;
}

//////////////////////////////////////////////////////////////////////////
// Public Interface - Input Functions
//////////////////////////////////////////////////////////////////////////

EFI_INPUT_KEY
TouchConsoleGetKey(VOID)
{
    // Ensure graphics are initialized
    TouchEnsureInitialized();
    return TouchWaitForKey();
}

EFI_INPUT_KEY
TouchConsoleKeyWait(
    IN CHAR16 *Prompt,
    IN UINTN MilliDelay,
    IN UINT16 DefaultScanCode,
    IN UINT16 DefaultChar
    )
{
    // Print prompt if provided
    if (Prompt != NULL) {
        TouchConsolePrintInternal(Prompt, ATTR_NORMAL);
    }

    // For now, just wait for key (timeout not implemented with touch)
    // TODO: Implement proper timeout with countdown display
    EFI_INPUT_KEY key = TouchWaitForKey();

    // If ESC or timeout would occur, return default
    if (key.ScanCode == SCAN_ESC && DefaultScanCode != 0) {
        key.ScanCode = DefaultScanCode;
        key.UnicodeChar = DefaultChar;
    }

    return key;
}

VOID
TouchConsoleFlushInput(
    IN UINTN DelayUs
    )
{
    EFI_INPUT_KEY key;
    EFI_ABSOLUTE_POINTER_STATE aps;

    KbResetState();   // also a key held after a dead key
    if (DelayUs > 0) {
        gBS->Stall(DelayUs);
    }

    // Flush keyboard
    while (gBS->CheckEvent(gST->ConIn->WaitForKey) == EFI_SUCCESS) {
        gST->ConIn->ReadKeyStroke(gST->ConIn, &key);
    }

    // Flush touch
    if (gTouchPointer != NULL) {
        while (gBS->CheckEvent(gTouchPointer->WaitForInput) == EFI_SUCCESS) {
            gTouchPointer->GetState(gTouchPointer, &aps);
        }
    }
}

BOOLEAN
TouchConsoleReadLine(
    OUT UINTN *Length,
    OUT CHAR16 *Line,
    OUT CHAR8 *AsciiLine,
    IN UINTN MaxLen,
    IN UINT8 ShowChars
    )
{
    UINTN count = 0;
    EFI_INPUT_KEY key;
    BOOLEAN visible = (ShowChars != 0);

    if (Line == NULL || MaxLen < 2) {
        if (Length) *Length = 0;
        return FALSE;
    }

    Line[0] = 0;
    if (AsciiLine) AsciiLine[0] = 0;

    while (TRUE) {
        key = TouchWaitForKey();

        // ESC - cancel
        if (key.ScanCode == SCAN_ESC) {
            TouchConsolePrintInternal(L"\r\n", ATTR_NORMAL);
            if (Length) *Length = 0;
            Line[0] = 0;
            if (AsciiLine) AsciiLine[0] = 0;
            return FALSE;
        }

        // Enter - done
        if (key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
            TouchConsolePrintInternal(L"\r\n", ATTR_NORMAL);
            Line[count] = 0;
            if (AsciiLine) {
                for (UINTN i = 0; i <= count; i++) {
                    AsciiLine[i] = (CHAR8)(Line[i] & 0x7F);
                }
            }
            if (Length) *Length = count;
            return TRUE;
        }

        // Backspace
        if (key.UnicodeChar == CHAR_BACKSPACE) {
            if (count > 0) {
                count--;
                Line[count] = 0;
                if (visible) {
                    TouchConsolePrintInternal(L"\b \b", ATTR_NORMAL);
                }
            }
            continue;
        }

        // Printable character
        if (key.UnicodeChar >= 32 && key.UnicodeChar < 127 && count < MaxLen - 1) {
            Line[count] = key.UnicodeChar;
            count++;
            Line[count] = 0;
            if (visible) {
                CHAR16 str[2] = { key.UnicodeChar, 0 };
                TouchConsolePrintInternal(str, ATTR_NORMAL);
            } else {
                TouchConsolePrintInternal(L"*", ATTR_NORMAL);
            }
        }
    }
}

UINT8
TouchConsoleAskYesNo(
    IN CHAR8 *Prompt,
    IN UINT8 Visible
    )
{
    EFI_INPUT_KEY key;

    // Print prompt
    if (Prompt != NULL) {
        CHAR16 widePrompt[256];
        UINTN i;
        for (i = 0; i < 255 && Prompt[i]; i++) {
            widePrompt[i] = (CHAR16)Prompt[i];
        }
        widePrompt[i] = 0;
        TouchConsolePrintInternal(widePrompt, ATTR_NORMAL);
    }

    TouchConsolePrintInternal(L" (y/n): ", ATTR_NORMAL);

    while (TRUE) {
        key = TouchWaitForKey();

        if (key.UnicodeChar == 'y' || key.UnicodeChar == 'Y') {
            TouchConsolePrintInternal(L"y\r\n", ATTR_NORMAL);
            return 1;
        }
        if (key.UnicodeChar == 'n' || key.UnicodeChar == 'N' ||
            key.ScanCode == SCAN_ESC) {
            TouchConsolePrintInternal(L"n\r\n", ATTR_NORMAL);
            return 0;
        }
    }
}

