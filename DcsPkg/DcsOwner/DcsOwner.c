/** @file
DCS Owner - protected Secure Boot / PK virtualization driver

Config lives in runtime-inaccessible EFI variables; the OS can only propose
changes through RT mirrors, which are committed at boot after a physical-presence
confirmation. The committed presets are measured into PCR 7, then a runtime
GetVariable hook reports the overridden values to the OS.

Variable overrides are table-driven (gVarMap[]). Each entry maps:
  Name   - the real UEFI variable intercepted at runtime
  NameRT - the RT mirror the OS writes to propose changes
  NameBS - the BS-only private store holding the committed value

The MySecureBoot variable is handled separately because it controls multiple
outputs (SecureBoot + SetupMode) rather than being a simple 1:1 blob proxy.

Copyright (c) 2026. DiskCryptor, David Xanatos

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include "DcsOwner.h"
#include "TpmKill.h"

#include <Library/CommonLib.h>
#include <Library/UefiRuntimeLib.h>
#include <DcsConfig.h>
#include <Guid/EventGroup.h>
#include <Guid/GlobalVariable.h>
#include <Guid/ImageAuthentication.h>
#include <Guid/MemoryAttributesTable.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/DevicePath.h>
#include <IndustryStandard/PeImage.h>
#include "DcsMatExec.h"
#include <Protocol/DcsOwnerProto.h>
#include <Library/BaseCryptLib.h>
#include <Protocol/Tcg2Protocol.h>
#include <Protocol/TcgService.h>
#include <IndustryStandard/UefiTcgPlatform.h>
#ifdef DCSOWNER_PCR_INDEX
#include <IndustryStandard/Tpm12.h>
#endif
#include "../Library/MiscUtilsLib/MiscUtilsLib.h"

//////////////////////////////////////////////////////////////////////////
// Variable override table
//////////////////////////////////////////////////////////////////////////

DCSOWNER_VAR_MAP gVarMap[] = {
    // Secure Boot
    {
        EFI_PLATFORM_KEY_NAME,
        L"OwnerPK_RT",
        L"OwnerPK_BS",
        &gEfiGlobalVariableGuid,
        EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
            EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
        DescribeCertFingerprint
    },
    {
        EFI_KEY_EXCHANGE_KEY_NAME,
        L"OwnerKEK_RT",
        L"OwnerKEK_BS",
        &gEfiGlobalVariableGuid,
        EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
            EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
        DescribeCertFingerprint
    },
    {
        EFI_IMAGE_SECURITY_DATABASE,
        L"OwnerDB_RT",
        L"OwnerDB_BS",
        &gEfiImageSecurityDatabaseGuid,
        EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
            EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
        DescribeCertFingerprint
    },
    {
        EFI_IMAGE_SECURITY_DATABASE1,
        L"OwnerDBX_RT",
        L"OwnerDBX_BS",
        &gEfiImageSecurityDatabaseGuid,
        EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
            EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
        DescribeCertFingerprint
    },
    // TpmKill
    /*{
        DCSOWNER_VAR_TPMKILL,
        L"DcsTpmKill_RT",
        L"DcsTpmKill",
        &gEfiDcsOwnerGuid,
        EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
            EFI_VARIABLE_RUNTIME_ACCESS,
        NULL
	},*/
    // Major Privacy
    {
        L"UserPubKey",
        L"UserPubKey_RT",
        L"UserPubKey_BS",
        &gEfiDcsOwnerGuid,
        EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
            EFI_VARIABLE_RUNTIME_ACCESS,
        NULL
	},
    {
        L"SuspendIsolator",
        L"SuspendIsolator_RT",
        L"SuspendIsolator_BS",
        &gEfiDcsOwnerGuid,
        EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
            EFI_VARIABLE_RUNTIME_ACCESS,
        NULL
    },
};

#define VAR_MAP_COUNT  (sizeof(gVarMap) / sizeof(gVarMap[0]))
CONST UINTN gVarMapCount = VAR_MAP_COUNT;

//////////////////////////////////////////////////////////////////////////
// Runtime override state (must survive ExitBootServices)
//////////////////////////////////////////////////////////////////////////

typedef struct _DCSOWNER_VAR_STATE {
    VOID    *Data;
    UINTN   Size;
    BOOLEAN Synthetic;   // TRUE if real variable doesn't exist on firmware
} DCSOWNER_VAR_STATE;

STATIC EFI_GET_VARIABLE           gOrgGetVariable = NULL;
STATIC EFI_SET_VARIABLE           gOrgSetVariable = NULL;
STATIC EFI_GET_NEXT_VARIABLE_NAME gOrgGetNextVariableName = NULL;
STATIC EFI_EVENT                  mVirtualAddrChangeEvent;
STATIC EFI_EVENT                  mExitBsEvent = NULL;
STATIC UINT32                     mOrigRtCrc   = 0;
STATIC BOOLEAN                    mUnhooked    = FALSE;

STATIC BOOLEAN  mActive         = FALSE;
STATIC BOOLEAN  mHooksInstalled = FALSE;
STATIC BOOLEAN  mEnumHooked     = FALSE;
STATIC BOOLEAN  mVirtualized    = FALSE;
STATIC BOOLEAN  mSbOverride     = FALSE;
STATIC UINT8    mSbValue        = 0;
STATIC UINT8    mEffSb          = 0;
STATIC BOOLEAN  mBootMenuLocked = FALSE;
STATIC BOOLEAN  mInstallForLock = FALSE;   // set when BootMenuLock needs the hooks the no-op gate skipped
BOOLEAN         gDcsVerboseDebug = FALSE;
BOOLEAN         gUseConfigFile   = FALSE;   // set in DcsOwnerMain: DcsProp file present?

STATIC DCSOWNER_VAR_STATE mVarState[sizeof(gVarMap) / sizeof(gVarMap[0])];

STATIC VOID    DcsOwnerInstallHooks (IN UINT8 EffSb);   // called lazily from BootMenuLock

// ---------------------------------------------------------------------------
// No-op gate: when there is nothing to enforce (no variable override active and
// boot-menu lock not configured), DcsOwner installs no hooks and leaves the
// firmware's gRT / MAT / gBS tables completely untouched.
//
// TESTING TOGGLE: set to 0 to disable the gate and force the old behavior
// (always install the hooks + MAT machinery, even with nothing to enforce).
// ---------------------------------------------------------------------------
#define DCSOWNER_NOOP_GATE  1

//////////////////////////////////////////////////////////////////////////
// Small variable helpers (all under gEfiDcsOwnerGuid)
//////////////////////////////////////////////////////////////////////////

UINT8
CfgGetU8 (
    IN  CHAR16    *Name,
    OUT BOOLEAN   *Present
    )
{
    EFI_STATUS  Status;
    VOID        *Val = NULL;
    UINTN       Size = 0;
    UINT32      Attr = 0;
    UINT8       Result = 0;

    if (Present) *Present = FALSE;
    Status = EfiGetVar(Name, &gEfiDcsOwnerGuid, &Val, &Size, &Attr);
    if (!EFI_ERROR(Status) && Val != NULL) {
        if (Size >= 1) {
            Result = ((UINT8 *)Val)[0];
        }
        if (Present) *Present = TRUE;
        MEM_FREE(Val);
    }
    return Result;
}

VOID *
CfgGetBytes (
    IN  CHAR16    *Name,
    OUT UINTN     *Size
    )
{
    EFI_STATUS  Status;
    VOID        *Val = NULL;
    UINTN       Sz = 0;
    UINT32      Attr = 0;

    *Size = 0;
    Status = EfiGetVar(Name, &gEfiDcsOwnerGuid, &Val, &Sz, &Attr);
    if (!EFI_ERROR(Status) && Val != NULL && Sz > 0) {
        *Size = Sz;
        return Val;
    }
    if (Val != NULL) {
        MEM_FREE(Val);
    }
    return NULL;
}

VOID
CfgSetU8 (
    IN CHAR16    *Name,
    IN UINT8     Value,
    IN UINT32    Attr
    )
{
    if (Value == 0) {
        EfiSetVar(Name, &gEfiDcsOwnerGuid, NULL, 0, Attr);
    } else {
        EfiSetVar(Name, &gEfiDcsOwnerGuid, &Value, sizeof(Value), Attr);
    }
}

VOID
CfgSetBytes(
    IN CHAR16* Name,
    IN VOID* Data,
    IN UINTN     Size,
    IN UINT32    Attr
)
{
    if (Size <= 8 && CompareMem(Data, "\0\0\0\0\0\0\0\0", Size) == 0) {
        Data = NULL;
    }

    if (Data != NULL && Size > 0) {
        EfiSetVar(Name, &gEfiDcsOwnerGuid, Data, Size, Attr);
    } else {
        EfiSetVar(Name, &gEfiDcsOwnerGuid, NULL, 0, Attr);
    }
}

//////////////////////////////////////////////////////////////////////////
// Setting sources (EFI variable vs DcsProp file)
//////////////////////////////////////////////////////////////////////////

BOOLEAN
DcsOwnerGetVerboseDebug (
    VOID
    )
{
    if (gUseConfigFile)
        return (BOOLEAN)(ConfigReadInt(DCSOWNER_CFG_DEBUG, 0) != 0);
    return (BOOLEAN)(CfgGetU8(DCSOWNER_VAR_DEBUG, NULL) != 0);
}

UINT8
DcsOwnerGetTpmKillMode (
    VOID
    )
{
    if (gUseConfigFile)
        return (UINT8)ConfigReadInt(DCSOWNER_CFG_TPMKILL, 0);
    return CfgGetU8(DCSOWNER_VAR_TPMKILL, NULL);
}

BOOLEAN
BytesEqual (
    IN VOID   *A,
    IN UINTN  ASize,
    IN VOID   *B,
    IN UINTN  BSize
    )
{
    if (ASize != BSize) {
        return FALSE;
    }
    if (ASize == 0) {
        return TRUE;
    }
    return (CompareMem(A, B, ASize) == 0);
}

//////////////////////////////////////////////////////////////////////////
// PCR 7 measurement
//////////////////////////////////////////////////////////////////////////

#ifdef DCSOWNER_PCR_INDEX

STATIC CONST CHAR8 mPcrTag[] = "DcsOwner";

STATIC
EFI_STATUS
DcsOwnerMeasurePcr (
    IN UINT32  PcrIndex,
    IN VOID    *Data,
    IN UINTN   Size
    )
{
    EFI_STATUS          Status;
    EFI_TCG2_PROTOCOL   *Tcg2 = NULL;
    EFI_TCG_PROTOCOL    *Tcg  = NULL;
    UINTN               TagLen = sizeof(mPcrTag) - 1;

    Status = gBS->LocateProtocol(&gEfiTcg2ProtocolGuid, NULL, (VOID **)&Tcg2);
    if (!EFI_ERROR(Status) && Tcg2 != NULL) {
        EFI_TCG2_EVENT  *Event;
        UINTN           EventSize = OFFSET_OF(EFI_TCG2_EVENT, Event) + TagLen;

        Event = AllocateZeroPool(EventSize);
        if (Event == NULL) {
            return EFI_OUT_OF_RESOURCES;
        }
        Event->Size                 = (UINT32)EventSize;
        Event->Header.HeaderSize    = sizeof(EFI_TCG2_EVENT_HEADER);
        Event->Header.HeaderVersion = EFI_TCG2_EVENT_HEADER_VERSION;
        Event->Header.PCRIndex      = PcrIndex;
        Event->Header.EventType     = EV_EFI_VARIABLE_DRIVER_CONFIG;
        CopyMem(Event->Event, mPcrTag, TagLen);

        Status = Tcg2->HashLogExtendEvent(
                          Tcg2, 0,
                          (EFI_PHYSICAL_ADDRESS)(UINTN)Data, (UINT64)Size,
                          Event);
        FreePool(Event);
        return Status;
    }

    Status = gBS->LocateProtocol(&gEfiTcgProtocolGuid, NULL, (VOID **)&Tcg);
    if (!EFI_ERROR(Status) && Tcg != NULL) {
        TCG_PCR_EVENT         *Event;
        UINTN                 EventSize = OFFSET_OF(TCG_PCR_EVENT, Event) + TagLen;
        UINT32                EventNumber = 0;
        EFI_PHYSICAL_ADDRESS  LastEntry = 0;

        Event = AllocateZeroPool(EventSize);
        if (Event == NULL) {
            return EFI_OUT_OF_RESOURCES;
        }
        Event->PCRIndex  = PcrIndex;
        Event->EventType = EV_EFI_VARIABLE_DRIVER_CONFIG;
        Event->EventSize = (UINT32)TagLen;
        CopyMem(Event->Event, mPcrTag, TagLen);

        Status = Tcg->HashLogExtendEvent(
                          Tcg,
                          (EFI_PHYSICAL_ADDRESS)(UINTN)Data, (UINT64)Size,
                          TPM_ALG_SHA,
                          Event, &EventNumber, &LastEntry);
        FreePool(Event);
        return Status;
    }

    return EFI_UNSUPPORTED;
}

#endif

//////////////////////////////////////////////////////////////////////////
// Hooked GetVariable (runtime)
//////////////////////////////////////////////////////////////////////////

STATIC
EFI_STATUS
EFIAPI
DcsOwnerGetVariable (
    IN     CHAR16    *VariableName,
    IN     EFI_GUID  *VendorGuid,
    OUT    UINT32    *Attributes OPTIONAL,
    IN OUT UINTN     *DataSize,
    OUT    VOID      *Data OPTIONAL
    )
{
    UINTN   i = VAR_MAP_COUNT;
    VOID    *Src   = NULL;
    UINTN   SrcLen = 0;
    UINT32  SrcAttr = 0;
    UINT8   ByteVal = 0;

    if (!mActive || VariableName == NULL || VendorGuid == NULL || DataSize == NULL) {
        return gOrgGetVariable(VariableName, VendorGuid, Attributes, DataSize, Data);
    }

    // Special: SecureBoot and SetupMode (driven by MySecureBoot)
    if (mSbOverride && CompareGuid(VendorGuid, &gEfiGlobalVariableGuid)) {
        if (StrCmp(VariableName, EFI_SECURE_BOOT_MODE_NAME) == 0) {
            ByteVal = mSbValue;
            Src = &ByteVal; SrcLen = 1;
            SrcAttr = EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;
        } else if (StrCmp(VariableName, EFI_SETUP_MODE_NAME) == 0) {
            ByteVal = 0;
            Src = &ByteVal; SrcLen = 1;
            SrcAttr = EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;
        }
    }

    // Table-driven variable overrides
    if (Src == NULL) {
        for (i = 0; i < VAR_MAP_COUNT; i++) {
            if (mVarState[i].Data != NULL &&
                CompareGuid(VendorGuid, gVarMap[i].Guid) &&
                StrCmp(VariableName, gVarMap[i].Name) == 0) {
                Src = mVarState[i].Data;
                SrcLen = mVarState[i].Size;
                SrcAttr = gVarMap[i].Attr;
                break;
            }
        }
    }

    if (Src != NULL) {
        if (i < VAR_MAP_COUNT && mVarState[i].Synthetic) {
            SrcAttr |= DCSOWNER_ATTR_VIRTUAL;
        }
        if (*DataSize < SrcLen) {
            *DataSize = SrcLen;
            if (Attributes != NULL) {
                *Attributes = SrcAttr;
            }
            return EFI_BUFFER_TOO_SMALL;
        }
        if (Data != NULL) {
            CopyMem(Data, Src, SrcLen);
        }
        *DataSize = SrcLen;
        if (Attributes != NULL) {
            *Attributes = SrcAttr;
        }
        return EFI_SUCCESS;
    }

    return gOrgGetVariable(VariableName, VendorGuid, Attributes, DataSize, Data);
}

//////////////////////////////////////////////////////////////////////////
// Hooked SetVariable (runtime) - blocks writes to overridden variables
//////////////////////////////////////////////////////////////////////////

STATIC
EFI_STATUS
EFIAPI
DcsOwnerSetVariable (
    IN CHAR16    *VariableName,
    IN EFI_GUID  *VendorGuid,
    IN UINT32    Attributes,
    IN UINTN     DataSize,
    IN VOID      *Data
    )
{
    UINTN i;

    if (VariableName == NULL || VendorGuid == NULL) {
        return gOrgSetVariable(VariableName, VendorGuid, Attributes, DataSize, Data);
    }

    // Allow DcsBoot to unlock by deleting BootDC5B
    if (mBootMenuLocked &&
        StrStr(VariableName, L"BootDC5B") == VariableName && DataSize == 0) {
        mBootMenuLocked = FALSE;
    }

    // Boot menu lock: block all Boot* variable writes
    if (mBootMenuLocked) {
        if (StrStr(VariableName, L"Boot") == VariableName) {
            return EFI_SUCCESS;
        }
    }

    if (!mActive) {
        return gOrgSetVariable(VariableName, VendorGuid, Attributes, DataSize, Data);
    }

    // Block writes to overridden variables
    if (CompareGuid(VendorGuid, &gEfiGlobalVariableGuid)) {
        if (mSbOverride) {
            if (StrCmp(VariableName, EFI_SECURE_BOOT_MODE_NAME) == 0 ||
                StrCmp(VariableName, EFI_SETUP_MODE_NAME) == 0) {
                return EFI_WRITE_PROTECTED;
            }
        }
    }

    for (i = 0; i < VAR_MAP_COUNT; i++) {
        if (mVarState[i].Data != NULL &&
            CompareGuid(VendorGuid, gVarMap[i].Guid) &&
            StrCmp(VariableName, gVarMap[i].Name) == 0) {
            return EFI_WRITE_PROTECTED;
        }
    }

    return gOrgSetVariable(VariableName, VendorGuid, Attributes, DataSize, Data);
}

//////////////////////////////////////////////////////////////////////////
// Hooked GetNextVariableName (runtime) - injects synthetic entries
//////////////////////////////////////////////////////////////////////////

STATIC
EFI_STATUS
EFIAPI
DcsOwnerGetNextVariableName (
    IN OUT UINTN     *VariableNameSize,
    IN OUT CHAR16    *VariableName,
    IN OUT EFI_GUID  *VendorGuid
    )
{
    EFI_STATUS  Status;
    UINTN       i;
    UINTN       RequiredSize;
    BOOLEAN     CurrentIsSynthetic;
    UINTN       CurrentIndex;

    if (!mActive || !mEnumHooked ||
        VariableNameSize == NULL || VariableName == NULL || VendorGuid == NULL) {
        return gOrgGetNextVariableName(VariableNameSize, VariableName, VendorGuid);
    }

    // Determine if the current variable is one of our synthetic entries
    CurrentIsSynthetic = FALSE;
    CurrentIndex = VAR_MAP_COUNT;
    if (VariableName[0] != L'\0') {
        for (i = 0; i < VAR_MAP_COUNT; i++) {
            if (mVarState[i].Synthetic && mVarState[i].Data != NULL &&
                CompareGuid(VendorGuid, gVarMap[i].Guid) &&
                StrCmp(VariableName, gVarMap[i].Name) == 0) {
                CurrentIsSynthetic = TRUE;
                CurrentIndex = i;
                break;
            }
        }
    }

    if (!CurrentIsSynthetic) {
        // Try firmware enumeration first
        Status = gOrgGetNextVariableName(VariableNameSize, VariableName, VendorGuid);
        if (!EFI_ERROR(Status)) {
            return Status;
        }

        // Firmware exhausted — append synthetic entries starting from first
        if (Status == EFI_NOT_FOUND) {
            for (i = 0; i < VAR_MAP_COUNT; i++) {
                if (mVarState[i].Synthetic && mVarState[i].Data != NULL) {
                    RequiredSize = (StrLen(gVarMap[i].Name) + 1) * sizeof(CHAR16);
                    if (*VariableNameSize < RequiredSize) {
                        *VariableNameSize = RequiredSize;
                        return EFI_BUFFER_TOO_SMALL;
                    }
                    StrCpyS(VariableName, *VariableNameSize / sizeof(CHAR16), gVarMap[i].Name);
                    CopyMem(VendorGuid, gVarMap[i].Guid, sizeof(EFI_GUID));
                    return EFI_SUCCESS;
                }
            }
            return EFI_NOT_FOUND;
        }
        return Status;
    }

    // Current is synthetic — find the next synthetic entry after CurrentIndex
    for (i = CurrentIndex + 1; i < VAR_MAP_COUNT; i++) {
        if (mVarState[i].Synthetic && mVarState[i].Data != NULL) {
            RequiredSize = (StrLen(gVarMap[i].Name) + 1) * sizeof(CHAR16);
            if (*VariableNameSize < RequiredSize) {
                *VariableNameSize = RequiredSize;
                return EFI_BUFFER_TOO_SMALL;
            }
            StrCpyS(VariableName, *VariableNameSize / sizeof(CHAR16), gVarMap[i].Name);
            CopyMem(VendorGuid, gVarMap[i].Guid, sizeof(EFI_GUID));
            return EFI_SUCCESS;
        }
    }

    return EFI_NOT_FOUND;
}

//////////////////////////////////////////////////////////////////////////
// Virtual address change fixup
//////////////////////////////////////////////////////////////////////////

/**
  ExitBootServices safety net.

  Our runtime hook only survives the handoff if the OS maps our image's code
  executable, which it decides from the Memory Attributes Table. We patch that
  table when we hook, but some firmware republishes it afterwards - during the
  later LoadImage calls for the OS loader - and rebuilds it from image records
  that still mark our code no-execute, silently undoing our flip before the OS
  reads it. We cannot win that race, but we can read the live table one last
  time here, at the final moment boot services are alive, and if our code page
  is no longer executable we restore the firmware's own GetVariable/SetVariable
  pointers. The OS then calls into firmware memory it still maps executable and
  there is no fault; the override is simply lost on that machine.

  No boot services or console output here - this runs inside ExitBootServices.
  Restoring the exact pointers makes gRT byte-for-byte what it was before we
  hooked, so its original CRC is valid again and we just put it back.
**/
STATIC
VOID
EFIAPI
DcsOwnerExitBootServices (
    IN EFI_EVENT  Event,
    IN VOID       *Context
    )
{
    BOOLEAN  mp;

    // Boot services are ending; stop the module re-asserting the MAT flip.
    MatExecDisarm();

    if (!mHooksInstalled || mUnhooked) {
        return;
    }

    if (MatExecAddrExecutable((EFI_PHYSICAL_ADDRESS)(UINTN)DcsOwnerGetVariable, &mp, TRUE)) {
        if (gDcsVerboseDebug) {
            OUT_PRINT(L"DcsOwner: ExitBootServices - MAT flip held, keeping the hook\n");
            gBS->Stall(3 * 1000 * 1000);   // 3s so the line is readable before Windows takes the screen
        }
        return;                     // our flip held; keep the hook
    }

    // The flip was lost - the OS would map our hook no-execute. Restore the
    // firmware's own service pointers so it calls into executable memory.
    gST->RuntimeServices->GetVariable = gOrgGetVariable;
    gST->RuntimeServices->SetVariable = gOrgSetVariable;
    if (mEnumHooked) {
        gST->RuntimeServices->GetNextVariableName = gOrgGetNextVariableName;
    }
    gST->RuntimeServices->Hdr.CRC32 = mOrigRtCrc;

    mUnhooked = TRUE;
    mActive   = FALSE;

    if (gDcsVerboseDebug) {
        OUT_PRINT(L"DcsOwner: ExitBootServices - firmware reverted our MAT flip, unhooked to boot safely (override OFF)\n");
        gBS->Stall(5 * 1000 * 1000);       // 5s so you can read it before the handoff
    }
}

STATIC
VOID
EFIAPI
DcsOwnerVirtualNotify (
    IN EFI_EVENT  Event,
    IN VOID       *Context
    )
{
    UINTN i;

    // If ExitBootServices already restored the firmware's pointers, gRT is no
    // longer ours to convert - the firmware will fix its own entries.
    if (mUnhooked) {
        return;
    }

    /*
     * SetVirtualAddressMap() is a one-shot, but the event group can be
     * signalled from more than one path on some firmware. Converting a
     * pointer twice turns it into garbage, so the fixup has to be idempotent.
     */
    if (mVirtualized) {
        return;
    }
    mVirtualized = TRUE;

    EfiConvertPointer(0x0, (VOID **)&gOrgGetVariable);
    EfiConvertPointer(0x0, (VOID **)&gOrgSetVariable);
    if (gOrgGetNextVariableName != NULL) {
        EfiConvertPointer(0x0, (VOID **)&gOrgGetNextVariableName);
    }

    for (i = 0; i < VAR_MAP_COUNT; i++) {
        if (mVarState[i].Data != NULL) {
            EfiConvertPointer(0x0, (VOID **)&mVarState[i].Data);
        }
    }
}

//////////////////////////////////////////////////////////////////////////
// Protocol implementation
//////////////////////////////////////////////////////////////////////////

STATIC
EFI_STATUS
EFIAPI
DcsOwnerProtoGetVariable (
    IN     EFI_DCSOWNER_PROTOCOL  *This,
    IN     CONST CHAR16           *Name,
    IN OUT UINTN                  *DataSize,
    OUT    VOID                   *Data OPTIONAL,
    OUT    UINT32                 *Attributes OPTIONAL
    )
{
    UINTN  i;
    VOID   *Src;
    UINTN  SrcLen;
    UINT32 SrcAttr;

    if (Name == NULL || DataSize == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    // MySecureBoot special case
    if (StrCmp(Name, DCSOWNER_VAR_SB) == 0) {
        BOOLEAN Present;
        UINT8 Val = CfgGetU8(DCSOWNER_VAR_SB, &Present);
        if (!Present) {
            return EFI_NOT_FOUND;
        }
        if (*DataSize < 1) {
            *DataSize = 1;
            return EFI_BUFFER_TOO_SMALL;
        }
        if (Data != NULL) {
            ((UINT8 *)Data)[0] = Val;
        }
        *DataSize = 1;
        if (Attributes != NULL) {
            *Attributes = DCSOWNER_ATTR_PRIVATE;
        }
        return EFI_SUCCESS;
    }

    // Table-driven entries: return committed data
    for (i = 0; i < VAR_MAP_COUNT; i++) {
        if (StrCmp(Name, gVarMap[i].Name) == 0) {
            VOID  *FreeBuf = NULL;
            Src = NULL; SrcLen = 0;

            if (mHooksInstalled) {
                // After TakeOwnership: use loaded runtime state
                Src = mVarState[i].Data;
                SrcLen = mVarState[i].Size;
            } else {
                // Before TakeOwnership: read directly from BS store
                FreeBuf = CfgGetBytes((CHAR16 *)gVarMap[i].NameBS, &SrcLen);
                Src = FreeBuf;
            }
            SrcAttr = gVarMap[i].Attr;

            if (Src == NULL || SrcLen == 0) {
                if (FreeBuf != NULL) MEM_FREE(FreeBuf);
                *DataSize = 0;
                if (Attributes != NULL) {
                    *Attributes = SrcAttr;
                }
                return EFI_NOT_FOUND;
            }
            if (*DataSize < SrcLen) {
                *DataSize = SrcLen;
                if (FreeBuf != NULL) MEM_FREE(FreeBuf);
                return EFI_BUFFER_TOO_SMALL;
            }
            if (Data != NULL) {
                CopyMem(Data, Src, SrcLen);
            }
            *DataSize = SrcLen;
            if (Attributes != NULL) {
                *Attributes = SrcAttr;
            }
            if (FreeBuf != NULL) MEM_FREE(FreeBuf);
            return EFI_SUCCESS;
        }
    }

    return EFI_NOT_FOUND;
}

STATIC
EFI_STATUS
EFIAPI
DcsOwnerProtoSetVariable (
    IN  EFI_DCSOWNER_PROTOCOL  *This,
    IN  CONST CHAR16           *Name,
    IN  UINTN                  DataSize,
    IN  VOID                   *Data OPTIONAL
    )
{
    UINTN i;
    UINT8 Val;

    if (Name == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    // MySecureBoot special case
    if (StrCmp(Name, DCSOWNER_VAR_SB) == 0) {
        Val = (DataSize > 0 && Data != NULL) ? ((UINT8 *)Data)[0] : 0;
        CfgSetU8(DCSOWNER_VAR_SB, Val, DCSOWNER_ATTR_PRIVATE);
        CfgSetU8(DCSOWNER_VAR_SB_RT, Val, DCSOWNER_ATTR_MIRROR);
        mSbOverride = DCSOWNER_SB_ACTIVE(Val);
        mSbValue    = (UINT8)DCSOWNER_SB_VALUE(Val);
        return EFI_SUCCESS;
    }

    // Table-driven entries
    for (i = 0; i < VAR_MAP_COUNT; i++) {
        if (StrCmp(Name, gVarMap[i].Name) == 0) {
            // Persist to both private and mirror
            CfgSetBytes((CHAR16 *)gVarMap[i].NameBS, Data, DataSize, DCSOWNER_ATTR_PRIVATE);
            CfgSetBytes((CHAR16 *)gVarMap[i].NameRT, Data, DataSize, DCSOWNER_ATTR_MIRROR);

            // Update in-memory runtime state
            if (mVarState[i].Data != NULL) {
                FreePool(mVarState[i].Data);
                mVarState[i].Data = NULL;
                mVarState[i].Size = 0;
            }
            if (DataSize > 0 && Data != NULL) {
                mVarState[i].Data = AllocateRuntimePool(DataSize);
                if (mVarState[i].Data != NULL) {
                    CopyMem(mVarState[i].Data, Data, DataSize);
                    mVarState[i].Size = DataSize;
                } else {
                    return EFI_OUT_OF_RESOURCES;
                }
            }
            return EFI_SUCCESS;
        }
    }

    return EFI_NOT_FOUND;
}

//////////////////////////////////////////////////////////////////////////
// Boot menu lock / boot order management
//////////////////////////////////////////////////////////////////////////

STATIC CHAR16 *sDcsBootEfi     = L"EFI\\" DCS_DIRECTORY L"\\DcsBoot.efi";
STATIC CHAR16 *sDcsBootEfiDesc = _T(DCS_CAPTION) L"(DCS) loader";

STATIC
EFI_STATUS
UpdateBootOrder (
    VOID
    )
{
    EFI_STATUS  Status;
    UINTN       Len;
    UINT32      Attr;
    CHAR16      *Tmp = NULL;

    Status = EfiGetVar(L"BootDC5B", &gEfiGlobalVariableGuid, &Tmp, &Len, &Attr);
    if (EFI_ERROR(Status)) {
        InitFS();
        BootMenuItemCreate(L"BootDC5B", sDcsBootEfiDesc, gFileRootHandle, sDcsBootEfi, TRUE);
        Status = BootOrderInsert(L"BootOrder", 0, 0x0DC5B);
    } else {
        UINTN BoIndex = 1;
        if (EFI_ERROR(BootOrderPresent(L"BootOrder", 0x0DC5B, &BoIndex)) || BoIndex != 0) {
            Status = BootOrderInsert(L"BootOrder", 0, 0x0DC5B);
        }
    }
    MEM_FREE(Tmp);
    return Status;
}

STATIC
EFI_STATUS
EFIAPI
DcsOwnerProtoBootMenuLock (
    IN  EFI_DCSOWNER_PROTOCOL  *This,
    IN  UINT32                 LockFlags
    )
{
    if ((LockFlags & DCSOWNER_UPDATE_BOOTORDER) != 0) {
        UpdateBootOrder();
    }
    if ((LockFlags & DCSOWNER_SET_BOOTNEXT) != 0) {
        UINT16 DcsBootNum = 0x0DC5B;
        EfiSetVar(L"BootNext", &gEfiGlobalVariableGuid,
                  &DcsBootNum, sizeof(DcsBootNum),
                  EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_RUNTIME_ACCESS |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS);
    }
    if ((LockFlags & DCSOWNER_LOCK_BOOT_VARS) != 0) {
        // The lock is enforced by the runtime SetVariable hook. If the no-op gate
        // skipped installation (no variable override), install now - it needs the
        // same MAT machinery to stay executable at runtime.
        if (!mHooksInstalled) {
            mInstallForLock = TRUE;
            DcsOwnerInstallHooks(mEffSb);
        }
        mBootMenuLocked = TRUE;
    }
    return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
DcsOwnerProtoTakeOwnership (
    IN  EFI_DCSOWNER_PROTOCOL  *This
    );

EFI_STATUS
EFIAPI
DcsOwnerShowConfigMenu (
    IN  EFI_DCSOWNER_PROTOCOL  *This
    );

STATIC
EFI_STATUS
EFIAPI
DcsOwnerShowBootPrompt (
    IN  EFI_DCSOWNER_PROTOCOL  *This
)
{
    EFI_INPUT_KEY key;

    UINTN  KeySize;
    VOID   *KeyData = CfgGetBytes(L"UserPubKey_BS", &KeySize);
    if (KeyData != NULL) {

        //gST->ConOut->ClearScreen(gST->ConOut);

        OUT_PRINT(L"\n");
        OUT_PRINT(L"                 ###############################\n");
        OUT_PRINT(L"                 ##                           ##\n");
        OUT_PRINT(L"                 ##         .-------.         ##\n");
        OUT_PRINT(L"                 ##        (  .---.  )        ##\n");
        OUT_PRINT(L"                 ##        (  |   |  )        ##\n");
        OUT_PRINT(L"                 ##         \\ '---' /         ##\n");
        OUT_PRINT(L"                 ##          \\_###_/          ##\n");
        OUT_PRINT(L"                 ##            ###            ##\n");
        OUT_PRINT(L"                  ##           ###           ##\n");
        OUT_PRINT(L"                   ##          ###          ##\n");
        OUT_PRINT(L"                    ###         #         ###\n");
        OUT_PRINT(L"                      ###               ###\n");
        OUT_PRINT(L"                        #####       #####\n");
        OUT_PRINT(L"                            #########\n");
        OUT_PRINT(L"\n");
        OUT_PRINT(L"                   M A J O R   P R I V A C Y\n");
        OUT_PRINT(L"\n");
        // 18

        UINT8  Hash[32] = {0};
        Sha256HashAll(KeyData, KeySize, Hash);
        OUT_PRINT(L"          User Key: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X...\n",
                Hash[0], Hash[1], Hash[2], Hash[3], Hash[4],
                Hash[5], Hash[6], Hash[7], Hash[8], Hash[9]);
        
        OUT_PRINT(L"\n");

        MEM_FREE(KeyData);
    } 

    UINT8 Val = CfgGetU8(L"SuspendIsolator_BS", NULL);
    if (Val != 0) {
        gBS->SetWatchdogTimer(0, 0, 0, NULL); // disable 5-min UEFI watchdog so password prompt can wait indefinitely
        OUT_PRINT(L"          WARNING: Kernel Isolator enforcement is suspended\n");
        OUT_PRINT(L"                   press Enter to continue boot\n");
        OUT_PRINT(L"                   press F12 to open config menu\n");
        do key = GetKey(); while (key.UnicodeChar != CHAR_CARRIAGE_RETURN && key.ScanCode != SCAN_F12);
        if (key.ScanCode == SCAN_F12) {
            This->ShowConfigMenu(This);
        }
    }
    
    key = KeyWait(L"Boot in %2d sec\r", 3, 0, 0);
    if ((key.UnicodeChar != CHAR_CARRIAGE_RETURN) && (key.ScanCode != 0 || key.UnicodeChar != 0)) {
        do {
            OUT_PRINT(L"[Enter] resume Boot  [F12] open Config\n");
            key = GetKey();
            if (key.ScanCode == SCAN_F12) {
                This->ShowConfigMenu(This);
            }
        } while (key.UnicodeChar != CHAR_CARRIAGE_RETURN);
    }

    return EFI_SUCCESS;
}

EFI_GUID gEfiDcsOwnerProtocolGuid = EFI_DCSOWNER_PROTOCOL_GUID;
STATIC EFI_DCSOWNER_PROTOCOL gDcsOwnerProtocol = {
    DcsOwnerProtoGetVariable,
    DcsOwnerProtoSetVariable,
    DcsOwnerProtoTakeOwnership,
    DcsOwnerProtoBootMenuLock,
    DcsOwnerShowConfigMenu,
    DcsOwnerShowBootPrompt,
};


//////////////////////////////////////////////////////////////////////////
// Install the runtime hooks
//////////////////////////////////////////////////////////////////////////

STATIC
VOID
DcsOwnerInstallHooks (
    IN UINT8   EffSb
    )
{
    EFI_STATUS  Status;
    BOOLEAN     HaveVarOverride = FALSE;
    BOOLEAN     HaveSynthetic = FALSE;
    BOOLEAN     MatPresent = FALSE;
    UINTN       i;
    UINTN       TempSize;

    mSbOverride = DCSOWNER_SB_ACTIVE(EffSb);
    mSbValue    = (UINT8)DCSOWNER_SB_VALUE(EffSb);

    if (mSbOverride) {
        HaveVarOverride = TRUE;
    }

    // Probe each overridden variable to see if it exists on firmware
    for (i = 0; i < VAR_MAP_COUNT; i++) {
        if (mVarState[i].Data != NULL) {
            HaveVarOverride = TRUE;

            TempSize = 0;
            Status = gST->RuntimeServices->GetVariable(
                         (CHAR16 *)gVarMap[i].Name, gVarMap[i].Guid,
                         NULL, &TempSize, NULL);
            if (Status == EFI_NOT_FOUND) {
                mVarState[i].Synthetic = TRUE;
                HaveSynthetic = TRUE;
            }
        }
    }

#if DCSOWNER_NOOP_GATE
    // Nothing to override -> do not touch any firmware table. Boot-menu lock also
    // needs the hooks, but it is requested later via BootMenuLock(); that path
    // sets mInstallForLock and calls us again, so we install lazily only if it is
    // actually used. Result: a machine with no override and no lock stays a true
    // no-op. (Set DCSOWNER_NOOP_GATE to 0 above to disable this gate for testing.)
    if (!HaveVarOverride && !mInstallForLock) {
        if (gDcsVerboseDebug) {
            OUT_PRINT(L"DcsOwner: nothing to enforce, leaving firmware services untouched\n");
        }
        return;
    }
#endif

    /*
     * A hook only survives the OS handoff if the DXE core loaded us as a
     * runtime image and the fixup event is registered, so both are settled
     * before gRT is touched. Failing closed here costs the override; failing
     * open costs the machine, because the first runtime GetVariable() the OS
     * makes would jump into memory that is no longer ours and there is no
     * way to recover from that once we are past ExitBootServices.
     */
    if (!MatExecImageIsRuntime()) {
        ERR_PRINT(L"DcsOwner: not loaded as a runtime image, variable hooks disabled\n");
        return;
    }

    if (!MatExecAddrExecutable((EFI_PHYSICAL_ADDRESS)(UINTN)DcsOwnerGetVariable, &MatPresent, FALSE)) {
        // The MAT would map our hook no-execute. Flip our code section RO in the
        // table (and arm the LoadImage re-assert); only continue if that took.
        if (!MatExecMakeExecutable((EFI_PHYSICAL_ADDRESS)(UINTN)DcsOwnerGetVariable)) {
            ERR_PRINT(L"DcsOwner: %a, could not make the hook executable via the memory attributes table, variable hooks disabled\n",
                      MatPresent ? "loaded after EndOfDxe with no MAT record"
                                 : "hook page marked no-execute");
            return;
        }
        if (gDcsVerboseDebug) {
            OUT_PRINT(L"DcsOwner: hook code added to the memory attributes table\n");
        }
    }

    Status = gBS->CreateEventEx(
                    EVT_NOTIFY_SIGNAL, TPL_NOTIFY,
                    DcsOwnerVirtualNotify, NULL,
                    &gEfiEventVirtualAddressChangeGuid,
                    &mVirtualAddrChangeEvent);
    if (EFI_ERROR(Status)) {
        ERR_PRINT(L"DcsOwner: virtual address change registration failed: %r, variable hooks disabled\n", Status);
        return;
    }


    // Remember the runtime table CRC before we disturb it, so ExitBootServices
    // can put the table back exactly if it has to un-hook.
    mOrigRtCrc = gST->RuntimeServices->Hdr.CRC32;

    // Always hook Get/SetVariable (SetVariable needed for boot menu lock,
    // GetVariable needed for overrides — both are cheap no-ops when inactive)
    gOrgGetVariable = gST->RuntimeServices->GetVariable;
    gOrgSetVariable = gST->RuntimeServices->SetVariable;
    gST->RuntimeServices->GetVariable = DcsOwnerGetVariable;
    gST->RuntimeServices->SetVariable = DcsOwnerSetVariable;

    if (HaveVarOverride) {
        mActive = TRUE;
    }

    // Only hook enumeration when at least one override has no real variable
    if (HaveSynthetic) {
        gOrgGetNextVariableName = gST->RuntimeServices->GetNextVariableName;
        gST->RuntimeServices->GetNextVariableName = DcsOwnerGetNextVariableName;
        mEnumHooked = TRUE;
    }

    MatExecRecomputeTableCrc(&gST->RuntimeServices->Hdr);

    // Last-moment safety net against firmware that republishes the MAT.
    Status = gBS->CreateEvent(EVT_SIGNAL_EXIT_BOOT_SERVICES, TPL_CALLBACK,
                              DcsOwnerExitBootServices, NULL, &mExitBsEvent);
    if (EFI_ERROR(Status) && gDcsVerboseDebug) {
        OUT_PRINT(L"DcsOwner: ExitBootServices registration failed: %r\n", Status);
    }

    if (HaveVarOverride && gDcsVerboseDebug) {
        OUT_PRINT(L"DcsOwner: override active (SecureBoot=%a",
                  mSbOverride ? (mSbValue ? "ON" : "OFF") : "passthrough");
        for (i = 0; i < VAR_MAP_COUNT; i++) {
            if (mVarState[i].Data != NULL) {
                OUT_PRINT(L", %s=%d%a", gVarMap[i].Name, (int)mVarState[i].Size,
                          mVarState[i].Synthetic ? " [new]" : "");
            }
        }
        OUT_PRINT(L")\n");
    }

    mHooksInstalled = TRUE;
}

STATIC
VOID
DcsOwnerLoadState (
    VOID
    )
{
    UINT8    SbVal;
    UINTN   i;

    // Read current committed MySecureBoot
    SbVal = CfgGetU8(DCSOWNER_VAR_SB, NULL);
    mEffSb = SbVal;

    // Free any prior runtime state
    for (i = 0; i < VAR_MAP_COUNT; i++) {
        if (mVarState[i].Data != NULL) {
            FreePool(mVarState[i].Data);
            mVarState[i].Data = NULL;
            mVarState[i].Size = 0;
        }
        mVarState[i].Synthetic = FALSE;
    }

    // Load committed (BS private) values into runtime state
    for (i = 0; i < VAR_MAP_COUNT; i++) {
        UINTN Size;
        VOID  *Data = CfgGetBytes((CHAR16 *)gVarMap[i].NameBS, &Size);
        if (Data != NULL) {
            if (Size > 0) {
                mVarState[i].Data = AllocateRuntimePool(Size);
                if (mVarState[i].Data != NULL) {
                    CopyMem(mVarState[i].Data, Data, Size);
                    mVarState[i].Size = Size;
                }
            }
            MEM_FREE(Data);
        }
    }
}

STATIC
EFI_STATUS
EFIAPI
DcsOwnerProtoTakeOwnership (
    IN  EFI_DCSOWNER_PROTOCOL  *This
    )
{
    if (mHooksInstalled) {
        return EFI_ALREADY_STARTED;
    }

    gDcsVerboseDebug = DcsOwnerGetVerboseDebug();

    // Load the latest committed state right before activation
    DcsOwnerLoadState();

    DcsOwnerInstallHooks(mEffSb);

    // Disable TPM before handing off to Windows
    UINT8   tpmMode = DcsOwnerGetTpmKillMode();
    if (tpmMode != TPM_KILL_MODE_DISABLED) {
        TPM_KILL_CONTEXT tpmCtx = { tpmMode };
        EFI_STATUS       tpmRes = TpmKillExecute(&tpmCtx);
        if (EFI_ERROR(tpmRes)) {
            ERR_PRINT(L"DcsOwner: TpmKill failed: %r\n", tpmRes);
        } else if (gDcsVerboseDebug) {
            OUT_PRINT(L"DcsOwner: TpmKill success: Shutdown=%d Protocol=%d Acpi=%d Vars=%d\n",
                tpmCtx.Tpm2Shutdown, tpmCtx.ProtocolKilled, tpmCtx.AcpiPatched, tpmCtx.VariablesDeleted);
        }
    }

    return EFI_SUCCESS;
}


//////////////////////////////////////////////////////////////////////////
// Driver unload
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
EFIAPI
DcsOwnerUnload (
    IN EFI_HANDLE  ImageHandle
    )
{
    UINTN i;

    // Restore hooked runtime services
    if (gOrgGetVariable != NULL) {
        gST->RuntimeServices->GetVariable = gOrgGetVariable;
    }
    if (gOrgSetVariable != NULL) {
        gST->RuntimeServices->SetVariable = gOrgSetVariable;
    }
    if (gOrgGetNextVariableName != NULL) {
        gST->RuntimeServices->GetNextVariableName = gOrgGetNextVariableName;
    }

    // The table entries changed again, so bring the header CRC back in step.
    MatExecRecomputeTableCrc(&gST->RuntimeServices->Hdr);

    // Drop the virtual address fixup. Its notify function lives in this
    // image, so leaving it registered across an unload hands the firmware a
    // pointer into freed memory to call at SetVirtualAddressMap() time.
    if (mVirtualAddrChangeEvent != NULL) {
        gBS->CloseEvent(mVirtualAddrChangeEvent);
        mVirtualAddrChangeEvent = NULL;
    }
    if (mExitBsEvent != NULL) {
        gBS->CloseEvent(mExitBsEvent);
        mExitBsEvent = NULL;
    }
    MatExecDisarm();
    MatExecFreeTable();

    // Uninstall protocol
    gBS->UninstallMultipleProtocolInterfaces(
        ImageHandle,
        &gEfiDcsOwnerProtocolGuid, &gDcsOwnerProtocol,
        NULL);

    // Free runtime state
    for (i = 0; i < VAR_MAP_COUNT; i++) {
        if (mVarState[i].Data != NULL) {
            FreePool(mVarState[i].Data);
            mVarState[i].Data = NULL;
            mVarState[i].Size = 0;
        }
    }

    mActive = FALSE;
    mHooksInstalled = FALSE;
    mEnumHooked = FALSE;
    mVirtualized = FALSE;
    mBootMenuLocked = FALSE;

    return EFI_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
// Driver entry
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
EFIAPI
DcsOwnerMain (
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE  *SystemTable
    )
{
    EFI_STATUS res;
    EFI_DCSOWNER_PROTOCOL *Existing = NULL;
    BOOLEAN  PrivSbPresent, RtSbPresent;
    UINT8    PrivSb, RtSb;
    BOOLEAN  AnyPending;
    UINTN    i;

    // Guard against double execution
    if (!EFI_ERROR(gBS->LocateProtocol(&gEfiDcsOwnerProtocolGuid, NULL, (VOID **)&Existing))) {
        ERR_PRINT(L"DcsOwner: already loaded, skipping\n");
        return EFI_ALREADY_STARTED;
    }

#ifdef DEBUG_BUILD
    OUT_PRINT(L"DcsOwner - DEBUG Build %a %a\n", __DATE__, __TIME__);
#endif

    InitBio();
    res = InitFS();	// Initialize FileSystem
    if (EFI_ERROR(res)) {
        res = InitPxe2(); // check and Initialize PXE boot
    }
    // Decide the config source once: use the DcsProp file if it loads, else EFI variables.
    gUseConfigFile = InitConfig(CONFIG_FILE_PATH);

    gDcsVerboseDebug = DcsOwnerGetVerboseDebug();

    ZeroMem(mVarState, sizeof(mVarState));

    //
    // 1. Read MySecureBoot config (special variable).
    //
    PrivSb = CfgGetU8(DCSOWNER_VAR_SB, &PrivSbPresent);
    RtSb   = CfgGetU8(DCSOWNER_VAR_SB_RT, &RtSbPresent);

    //
    // 2. Check for pending changes across all mapped variables.
    //
    AnyPending = (RtSbPresent && RtSb != PrivSb);
    for (i = 0; i < VAR_MAP_COUNT; i++) {
        VOID  *PrivData, *RtData;
        UINTN PrivSize, RtSize;

        PrivData = CfgGetBytes((CHAR16 *)gVarMap[i].NameBS, &PrivSize);
        RtData   = CfgGetBytes((CHAR16 *)gVarMap[i].NameRT, &RtSize);

        if (!BytesEqual(RtData, RtSize, PrivData, PrivSize)) {
            AnyPending = TRUE;
        }

        if (PrivData != NULL) MEM_FREE(PrivData);
        if (RtData != NULL)   MEM_FREE(RtData);
    }

    //
    // 3. If changes are pending, ask for confirmation and commit or revert.
    //    Only the stores are updated here — actual value loading happens in TakeOwnership.
    //
    if (AnyPending) {
        BOOLEAN    SbAccepted = FALSE;
        BOOLEAN    *VarAccepted = AllocateZeroPool(VAR_MAP_COUNT * sizeof(BOOLEAN));
        EFI_STATUS ConfirmResult;

        ConfirmResult = DcsOwnerConfirmChanges(
            RtSbPresent && RtSb != PrivSb,
            PrivSb, RtSb,
            &SbAccepted, VarAccepted);

        if (ConfirmResult == EFI_SUCCESS) {
            // Enter: apply accepted, revert rejected
            if (SbAccepted) {
                CfgSetU8(DCSOWNER_VAR_SB, RtSb, DCSOWNER_ATTR_PRIVATE);
            } else {
                CfgSetU8(DCSOWNER_VAR_SB_RT, PrivSb, DCSOWNER_ATTR_MIRROR);
            }

            for (i = 0; i < VAR_MAP_COUNT; i++) {
                if (VarAccepted[i]) {
                    UINTN RtSize;
                    VOID  *RtData = CfgGetBytes((CHAR16 *)gVarMap[i].NameRT, &RtSize);
                    CfgSetBytes((CHAR16 *)gVarMap[i].NameBS, RtData, RtSize, DCSOWNER_ATTR_PRIVATE);
                    if (RtData != NULL) MEM_FREE(RtData);
                } else {
                    UINTN PrivSize;
                    VOID  *PrivData = CfgGetBytes((CHAR16 *)gVarMap[i].NameBS, &PrivSize);
                    CfgSetBytes((CHAR16 *)gVarMap[i].NameRT, PrivData, PrivSize, DCSOWNER_ATTR_MIRROR);
                    if (PrivData != NULL) MEM_FREE(PrivData);
                }
            }
        }
        // EFI_ABORTED (Esc): no action — pending changes stay for next boot

        if (VarAccepted != NULL) FreePool(VarAccepted);
    } else {
        // No pending changes — ensure RT mirror exists so OS tool can read current state
        if (!RtSbPresent) {
            CfgSetU8(DCSOWNER_VAR_SB_RT, PrivSb, DCSOWNER_ATTR_MIRROR);
        }
        for (i = 0; i < VAR_MAP_COUNT; i++) {
            UINTN PrivSize, RtSize;
            VOID  *PrivData = CfgGetBytes((CHAR16 *)gVarMap[i].NameBS, &PrivSize);
            VOID  *RtData   = CfgGetBytes((CHAR16 *)gVarMap[i].NameRT, &RtSize);
            if (RtData == NULL && PrivData != NULL) {
                CfgSetBytes((CHAR16 *)gVarMap[i].NameRT, PrivData, PrivSize, DCSOWNER_ATTR_MIRROR);
            }
            if (PrivData != NULL) MEM_FREE(PrivData);
            if (RtData != NULL)   MEM_FREE(RtData);
        }
    }

#ifdef DCSOWNER_PCR_INDEX
    //
    // 4. Measure committed presets into PCR 7 (one extend per variable).
    //    Done at load so volume mounting between load and activation sees correct PCR state.
    //
    UINT8 EffSb = CfgGetU8(DCSOWNER_VAR_SB, NULL);
    DcsOwnerMeasurePcr(DCSOWNER_PCR_INDEX, &EffSb, sizeof(EffSb));

    for (i = 0; i < VAR_MAP_COUNT; i++) {
        UINTN Size;
        VOID  *Data = CfgGetBytes((CHAR16 *)gVarMap[i].NameBS, &Size);
        if (Data != NULL) {
            if (Size > 0) {
                DcsOwnerMeasurePcr(DCSOWNER_PCR_INDEX, Data, Size);
            }
            MEM_FREE(Data);
        }
    }
#endif

    //
    // 5. Install protocol interface so other DCS drivers can read/write by name.
    //    Hooks are NOT active yet — caller must invoke TakeOwnership() when ready.
    //    TakeOwnership will load the latest committed values and activate hooks.
    //
    EFI_STATUS ProtoStatus;
    ProtoStatus = gBS->InstallMultipleProtocolInterfaces(
                            &ImageHandle,
                            &gEfiDcsOwnerProtocolGuid, &gDcsOwnerProtocol,
                            NULL);
    if (EFI_ERROR(ProtoStatus)) {
        ERR_PRINT(L"DcsOwner: protocol install failed: %r\n", ProtoStatus);
    }

    return EFI_SUCCESS;
}
