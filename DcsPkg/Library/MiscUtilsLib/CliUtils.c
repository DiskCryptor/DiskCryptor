/** @file
  CliUtils - Console/CLI utility functions for DiskCryptor UEFI

  SPDX-License-Identifier: MIT

  Copyright (c) 2024-2026 DiskCryptor contributors

**/

#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseMemoryLib.h>

#include "MiscUtilsLib.h"

//////////////////////////////////////////////////////////////////////////
// Console Input
//////////////////////////////////////////////////////////////////////////

/* UefiGetKey */
EFI_INPUT_KEY
EFIAPI
UefiGetKey (
    VOID
    )
{
    EFI_INPUT_KEY  Key;
    UINTN          EventIndex;

    ZeroMem(&Key, sizeof(Key));

    gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &EventIndex);
    gST->ConIn->ReadKeyStroke(gST->ConIn, &Key);

    return Key;
}

/* UefiFlushInputDelay */
VOID
EFIAPI
UefiFlushInputDelay (
    IN UINTN  Delay
    )
{
    EFI_INPUT_KEY  Key;
    EFI_EVENT      InputEvents[2];
    UINTN          EventIndex = 0;

    InputEvents[0] = gST->ConIn->WaitForKey;
    gBS->CreateEvent(EVT_TIMER, 0, (EFI_EVENT_NOTIFY)NULL, NULL, &InputEvents[1]);
    gBS->SetTimer(InputEvents[1], TimerPeriodic, Delay);

    while (EventIndex == 0) {
        gBS->WaitForEvent(2, InputEvents, &EventIndex);
        if (EventIndex == 0) {
            gST->ConIn->ReadKeyStroke(gST->ConIn, &Key);
        }
    }

    gBS->CloseEvent(InputEvents[1]);
}

/* UefiFlushInput */
VOID
EFIAPI
UefiFlushInput (
    VOID
    )
{
    UefiFlushInputDelay(1000000);
}

/* UefiKeyWait */
EFI_INPUT_KEY
EFIAPI
UefiKeyWait (
    IN CHAR16  *Prompt,
    IN UINTN   Seconds,
    IN UINT16  DefaultScan,
    IN UINT16  DefaultChar
    )
{
    EFI_INPUT_KEY  Key;
    EFI_EVENT      InputEvents[2];
    UINTN          EventIndex;

    UefiFlushInput();

    Key.ScanCode = DefaultScan;
    Key.UnicodeChar = DefaultChar;

    InputEvents[0] = gST->ConIn->WaitForKey;

    gBS->CreateEvent(EVT_TIMER, 0, (EFI_EVENT_NOTIFY)NULL, NULL, &InputEvents[1]);
    gBS->SetTimer(InputEvents[1], TimerPeriodic, 10000000);

    while (Seconds > 0) {
        Print(Prompt, Seconds);

        gBS->WaitForEvent(2, InputEvents, &EventIndex);

        if (EventIndex == 0) {
            if (!EFI_ERROR(gST->ConIn->ReadKeyStroke(gST->ConIn, &Key))) {
                break;
            }
            continue;
        } else {
            Seconds--;
        }
    }

    Print(Prompt, Seconds);

    gBS->CloseEvent(InputEvents[1]);
    return Key;
}

//////////////////////////////////////////////////////////////////////////
// Console Output
//////////////////////////////////////////////////////////////////////////

/* UefiPrintBytes */
VOID
EFIAPI
UefiPrintBytes (
    IN UINT8  *Data,
    IN UINTN  Size
    )
{
    UINTN  Index;

    if (Data == NULL || Size == 0) {
        return;
    }

    for (Index = 0; Index < Size; Index++) {
        Print(L"%02x", Data[Index]);
    }
}
