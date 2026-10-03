/** @file
MAT execution helper - see DcsMatExec.h for the rationale.

Copyright (c) 2026. DiskCryptor, David Xanatos
Licensed under the GNU Lesser General Public License, version 3.0 (LGPL-3.0).
**/

#include "DcsMatExec.h"

#include <Library/CommonLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Guid/MemoryAttributesTable.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/DevicePath.h>
#include <IndustryStandard/PeImage.h>

// Shared verbose flag, defined in DcsOwner.c.
extern BOOLEAN gDcsVerboseDebug;

//////////////////////////////////////////////////////////////////////////
// Module state
//////////////////////////////////////////////////////////////////////////

STATIC EFI_MEMORY_ATTRIBUTES_TABLE  *mOurMat      = NULL;   // the table copy we installed
STATIC EFI_PHYSICAL_ADDRESS         mGuardAddr    = 0;      // representative code address to re-check
STATIC EFI_IMAGE_LOAD               gOrgLoadImage = NULL;   // original gBS->LoadImage
STATIC UINT32                       mOrigBsCrc    = 0;      // gBS CRC before we hooked LoadImage
STATIC BOOLEAN                      mLoadImageHooked = FALSE;

STATIC BOOLEAN MatExecFlipCore (VOID);   // defined below; used by the LoadImage hook

//////////////////////////////////////////////////////////////////////////
// Table helpers
//////////////////////////////////////////////////////////////////////////

VOID
MatExecRecomputeTableCrc (
  IN OUT EFI_TABLE_HEADER  *Hdr
  )
{
    UINT32  Crc = 0;

    if (Hdr == NULL) {
        return;
    }
    Hdr->CRC32 = 0;
    if (!EFI_ERROR(gBS->CalculateCrc32(Hdr, Hdr->HeaderSize, &Crc))) {
        Hdr->CRC32 = Crc;
    }
}

BOOLEAN
MatExecImageIsRuntime (
  VOID
  )
{
    EFI_LOADED_IMAGE_PROTOCOL  *Image = NULL;

    if (EFI_ERROR(gBS->HandleProtocol(gImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **)&Image)) ||
        Image == NULL) {
        return FALSE;
    }

    return (BOOLEAN)(Image->ImageCodeType == EfiRuntimeServicesCode &&
                     Image->ImageDataType == EfiRuntimeServicesData);
}

/**
  Locate the firmware's EFI Memory Attributes Table, or NULL if none.
**/
STATIC
EFI_MEMORY_ATTRIBUTES_TABLE *
MatExecFind (
  VOID
  )
{
    UINTN  Index;

    for (Index = 0; Index < gST->NumberOfTableEntries; Index++) {
        if (CompareGuid(&gST->ConfigurationTable[Index].VendorGuid, &gEfiMemoryAttributesTableGuid)) {
            return (EFI_MEMORY_ATTRIBUTES_TABLE *)gST->ConfigurationTable[Index].VendorTable;
        }
    }
    return NULL;
}

BOOLEAN
MatExecAddrExecutable (
  IN  EFI_PHYSICAL_ADDRESS  Addr,
  OUT BOOLEAN               *MatPresent,
  IN  BOOLEAN               Quiet
  )
{
    EFI_MEMORY_ATTRIBUTES_TABLE  *Mat  = MatExecFind();
    EFI_MEMORY_DESCRIPTOR        *Desc;
    UINTN                        Index;

    *MatPresent = FALSE;

    if (Mat == NULL || Mat->NumberOfEntries == 0 ||
        Mat->DescriptorSize < sizeof(EFI_MEMORY_DESCRIPTOR)) {
        // Nothing finer than the memory map, so runtime code stays executable.
        return TRUE;
    }

    *MatPresent = TRUE;
    Desc = (EFI_MEMORY_DESCRIPTOR *)(Mat + 1);

    for (Index = 0; Index < Mat->NumberOfEntries; Index++) {
        if (Addr >= Desc->PhysicalStart &&
            Addr <  Desc->PhysicalStart + LShiftU64(Desc->NumberOfPages, EFI_PAGE_SHIFT)) {
            if (gDcsVerboseDebug && !Quiet) {
                OUT_PRINT(L"DcsMatExec: code page described, attributes 0x%lx\n", Desc->Attribute);
            }
            return (BOOLEAN)((Desc->Attribute & EFI_MEMORY_XP) == 0);
        }
        Desc = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Desc + Mat->DescriptorSize);
    }

    return FALSE;
}

//////////////////////////////////////////////////////////////////////////
// MAT rebuild (split-and-flip)
//////////////////////////////////////////////////////////////////////////

STATIC
BOOLEAN
MatExecAppend (
  IN  UINT8                 *Base,
  IN  UINTN                 Stride,
  IN  OUT UINTN             *Count,
  IN  UINTN                 Cap,
  IN  UINT32                Type,
  IN  EFI_PHYSICAL_ADDRESS  Start,
  IN  UINT64                Pages,
  IN  UINT64                Attribute
  )
{
    EFI_MEMORY_DESCRIPTOR *d;

    if (Pages == 0) {
        return TRUE;             // empty slice - nothing to emit
    }
    if (*Count >= Cap) {
        return FALSE;            // ran out of room - caller fails closed
    }
    d = (EFI_MEMORY_DESCRIPTOR *)(Base + (*Count) * Stride);
    ZeroMem(d, Stride);
    d->Type          = Type;
    d->PhysicalStart = Start;
    d->NumberOfPages = Pages;
    d->Attribute     = Attribute;
    (*Count)++;
    return TRUE;
}

/**
  Split every existing MAT descriptor around this image's executable pages,
  flipping those pages to RO (executable) while preserving everything else, then
  install the rebuilt table. Uncovered code pages are appended as RO runtime
  code. See DcsMatExec.h for why full behavior is safe/necessary.

  @retval TRUE   Installed and mGuardAddr is now executable.
  @retval FALSE  Nothing usable was installed.
**/
STATIC
BOOLEAN
MatExecFlipCore (
  VOID
  )
{
    EFI_MEMORY_ATTRIBUTES_TABLE  *Old = MatExecFind();
    EFI_MEMORY_ATTRIBUTES_TABLE  *New;
    EFI_LOADED_IMAGE_PROTOCOL    *Image = NULL;
    EFI_IMAGE_DOS_HEADER         *Dos;
    EFI_IMAGE_NT_HEADERS64       *Nt;
    EFI_IMAGE_SECTION_HEADER     *Sec;
    EFI_PHYSICAL_ADDRESS         ImgBase, ImgStart, ImgEnd, Page;
    EFI_STATUS                   Status;
    UINT8                        *OldD, *NewD;
    UINT8                        Tmp[128];
    UINTN                        Stride, Cap, Count = 0;
    UINTN                        i, s, oi;
    UINT16                       NumSec;
    UINT32                       CodeType;
    UINT64                       CodePages = 0;
    BOOLEAN                      MatPresent;

    // Executable page ranges of this image (physical), sorted and merged.
    struct { EFI_PHYSICAL_ADDRESS Start; EFI_PHYSICAL_ADDRESS End; } Code[32];
    UINTN                        CodeCount = 0;

    if (Old == NULL) {
        if (gDcsVerboseDebug) OUT_PRINT(L"DcsMatExec: MAT gone before rebuild\n");
        return FALSE;
    }
    if (gDcsVerboseDebug) {
        OUT_PRINT(L"DcsMatExec: MAT ver=%d entries=%d descsz=%d\n",
                  Old->Version, Old->NumberOfEntries, Old->DescriptorSize);
    }
    if (Old->NumberOfEntries == 0 ||
        Old->DescriptorSize < sizeof(EFI_MEMORY_DESCRIPTOR) ||
        Old->DescriptorSize > sizeof(Tmp) ||
        (Old->Version != 1 && Old->Version != EFI_MEMORY_ATTRIBUTES_TABLE_VERSION)) {
        if (gDcsVerboseDebug) OUT_PRINT(L"DcsMatExec: MAT shape unusable\n");
        return FALSE;
    }
    Stride = Old->DescriptorSize;
    OldD   = (UINT8 *)(Old + 1);

    if (EFI_ERROR(gBS->HandleProtocol(gImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **)&Image)) ||
        Image == NULL || Image->ImageBase == NULL) {
        if (gDcsVerboseDebug) OUT_PRINT(L"DcsMatExec: no loaded image info\n");
        return FALSE;
    }
    ImgBase  = (EFI_PHYSICAL_ADDRESS)(UINTN)Image->ImageBase;
    CodeType = (UINT32)Image->ImageCodeType;

    // Parse our own PE headers to find the executable section(s).
    Dos = (EFI_IMAGE_DOS_HEADER *)(UINTN)ImgBase;
    if (Dos->e_magic == EFI_IMAGE_DOS_SIGNATURE) {
        Nt = (EFI_IMAGE_NT_HEADERS64 *)(UINTN)(ImgBase + Dos->e_lfanew);
    } else {
        Nt = (EFI_IMAGE_NT_HEADERS64 *)(UINTN)ImgBase;
    }
    if (Nt->Signature != EFI_IMAGE_NT_SIGNATURE) {
        if (gDcsVerboseDebug) OUT_PRINT(L"DcsMatExec: PE signature not found at image base\n");
        return FALSE;
    }

    NumSec   = Nt->FileHeader.NumberOfSections;
    Sec      = (EFI_IMAGE_SECTION_HEADER *)((UINT8 *)&Nt->OptionalHeader +
                                            Nt->FileHeader.SizeOfOptionalHeader);
    ImgStart = ImgBase & ~(EFI_PHYSICAL_ADDRESS)EFI_PAGE_MASK;
    ImgEnd   = (ImgBase + Nt->OptionalHeader.SizeOfImage +
                EFI_PAGE_MASK) & ~(EFI_PHYSICAL_ADDRESS)EFI_PAGE_MASK;
    if (gDcsVerboseDebug) {
        OUT_PRINT(L"DcsMatExec: image %lx..%lx (%d sections)\n", ImgStart, ImgEnd, NumSec);
    }

    // Collect executable section page ranges.
    for (s = 0; s < NumSec; s++) {
        EFI_PHYSICAL_ADDRESS cs, ce;

        if ((Sec[s].Characteristics & EFI_IMAGE_SCN_MEM_EXECUTE) == 0) {
            continue;
        }
        cs = (ImgBase + Sec[s].VirtualAddress) & ~(EFI_PHYSICAL_ADDRESS)EFI_PAGE_MASK;
        ce = (ImgBase + Sec[s].VirtualAddress + Sec[s].Misc.VirtualSize +
              EFI_PAGE_MASK) & ~(EFI_PHYSICAL_ADDRESS)EFI_PAGE_MASK;
        if (ce <= cs) {
            continue;
        }
        if (CodeCount >= ARRAY_SIZE(Code)) {
            if (gDcsVerboseDebug) OUT_PRINT(L"DcsMatExec: too many code sections\n");
            return FALSE;
        }
        Code[CodeCount].Start = cs;
        Code[CodeCount].End   = ce;
        CodeCount++;
    }
    if (CodeCount == 0) {
        if (gDcsVerboseDebug) OUT_PRINT(L"DcsMatExec: no executable section\n");
        return FALSE;
    }

    // Sort code ranges by Start, then merge touching/overlapping ones.
    for (i = 1; i < CodeCount; i++) {
        EFI_PHYSICAL_ADDRESS a = Code[i].Start, b = Code[i].End;
        s = i;
        while (s > 0 && Code[s - 1].Start > a) {
            Code[s] = Code[s - 1];
            s--;
        }
        Code[s].Start = a;
        Code[s].End   = b;
    }
    {
        UINTN m = 0;
        for (i = 0; i < CodeCount; i++) {
            if (m > 0 && Code[i].Start <= Code[m - 1].End) {
                if (Code[i].End > Code[m - 1].End) {
                    Code[m - 1].End = Code[i].End;
                }
            } else {
                Code[m++] = Code[i];
            }
        }
        CodeCount = m;
    }
    for (i = 0; i < CodeCount; i++) {
        CodePages += (Code[i].End - Code[i].Start) >> EFI_PAGE_SHIFT;
    }
    if (CodePages == 0 || CodePages > 4096) {
        if (gDcsVerboseDebug) OUT_PRINT(L"DcsMatExec: code page count out of range (%ld)\n", CodePages);
        return FALSE;
    }

    // Rebuild the table: each existing descriptor is split around our code
    // ranges, and the pieces that fall on our code pages have XP cleared / RO
    // set so the OS maps them executable. Everything else is preserved with its
    // original type and attributes. Code pages that no descriptor covered are
    // appended fresh as read-only runtime code.
    Cap = (UINTN)Old->NumberOfEntries * 2 + (UINTN)CodePages + 64;
    New = AllocatePool(sizeof(EFI_MEMORY_ATTRIBUTES_TABLE) + Cap * Stride);
    if (New == NULL) {
        if (gDcsVerboseDebug) OUT_PRINT(L"DcsMatExec: MAT alloc failed\n");
        return FALSE;
    }
    New->Version        = Old->Version;
    New->DescriptorSize = Old->DescriptorSize;
    New->Flags          = Old->Flags;
    NewD                = (UINT8 *)(New + 1);

    // Split-and-flip every existing descriptor.
    for (oi = 0; oi < Old->NumberOfEntries; oi++) {
        EFI_MEMORY_DESCRIPTOR *od = (EFI_MEMORY_DESCRIPTOR *)(OldD + oi * Stride);
        EFI_PHYSICAL_ADDRESS  os = od->PhysicalStart;
        EFI_PHYSICAL_ADDRESS  oe = os + LShiftU64(od->NumberOfPages, EFI_PAGE_SHIFT);
        EFI_PHYSICAL_ADDRESS  cur = os;
        UINT64                attrO = od->Attribute;
        UINT64                attrX = (attrO & ~(UINT64)EFI_MEMORY_XP) | EFI_MEMORY_RO;
        UINT32                typeO = od->Type;
        BOOLEAN               ok = TRUE;

        for (i = 0; i < CodeCount && ok; i++) {
            EFI_PHYSICAL_ADDRESS is = (Code[i].Start > os) ? Code[i].Start : os;
            EFI_PHYSICAL_ADDRESS ie = (Code[i].End   < oe) ? Code[i].End   : oe;

            if (is >= ie) {
                continue;                    // this code range misses this descriptor
            }
            if (cur < is) {
                ok &= MatExecAppend(NewD, Stride, &Count, Cap, typeO, cur, (is - cur) >> EFI_PAGE_SHIFT, attrO);
            }
            ok &= MatExecAppend(NewD, Stride, &Count, Cap, typeO, is, (ie - is) >> EFI_PAGE_SHIFT, attrX);
            cur = ie;
        }
        if (ok && cur < oe) {
            ok &= MatExecAppend(NewD, Stride, &Count, Cap, typeO, cur, (oe - cur) >> EFI_PAGE_SHIFT, attrO);
        }
        if (!ok) {
            if (gDcsVerboseDebug) OUT_PRINT(L"DcsMatExec: MAT capacity exceeded splitting\n");
            FreePool(New);
            return FALSE;
        }
    }

    // Cover any code page no existing descriptor described, so nothing our code
    // touches is left non-executable.
    for (i = 0; i < CodeCount; i++) {
        EFI_PHYSICAL_ADDRESS runStart = 0;
        UINT64               runPages = 0;

        for (Page = Code[i].Start; Page < Code[i].End; Page += EFI_PAGE_SIZE) {
            BOOLEAN covered = FALSE;

            for (oi = 0; oi < Old->NumberOfEntries; oi++) {
                EFI_MEMORY_DESCRIPTOR *od = (EFI_MEMORY_DESCRIPTOR *)(OldD + oi * Stride);
                EFI_PHYSICAL_ADDRESS  os = od->PhysicalStart;
                EFI_PHYSICAL_ADDRESS  oe = os + LShiftU64(od->NumberOfPages, EFI_PAGE_SHIFT);
                if (Page >= os && Page < oe) {
                    covered = TRUE;
                    break;
                }
            }

            if (!covered) {
                if (runPages == 0) {
                    runStart = Page;
                }
                runPages++;
            } else if (runPages != 0) {
                if (!MatExecAppend(NewD, Stride, &Count, Cap, CodeType, runStart, runPages,
                                   EFI_MEMORY_RUNTIME | EFI_MEMORY_RO)) {
                    FreePool(New); return FALSE;
                }
                runPages = 0;
            }
        }
        if (runPages != 0 &&
            !MatExecAppend(NewD, Stride, &Count, Cap, CodeType, runStart, runPages,
                           EFI_MEMORY_RUNTIME | EFI_MEMORY_RO)) {
            FreePool(New); return FALSE;
        }
    }

    New->NumberOfEntries = (UINT32)Count;

    // Sort by PhysicalStart; EDK2 emits the MAT sorted and the OS may assume it.
    for (i = 1; i < Count; i++) {
        EFI_MEMORY_DESCRIPTOR *cur = (EFI_MEMORY_DESCRIPTOR *)(NewD + i * Stride);
        EFI_PHYSICAL_ADDRESS   key = cur->PhysicalStart;
        UINTN                  j = i;

        CopyMem(Tmp, (UINT8 *)cur, Stride);
        while (j > 0) {
            EFI_MEMORY_DESCRIPTOR *prev = (EFI_MEMORY_DESCRIPTOR *)(NewD + (j - 1) * Stride);
            if (prev->PhysicalStart <= key) {
                break;
            }
            CopyMem(NewD + j * Stride, (UINT8 *)prev, Stride);
            j--;
        }
        CopyMem(NewD + j * Stride, Tmp, Stride);
    }

    if (gDcsVerboseDebug) {
        OUT_PRINT(L"DcsMatExec: MAT rebuilt %d -> %d entries, %ld code pages flipped RO\n",
                  Old->NumberOfEntries, New->NumberOfEntries, CodePages);
    }

    Status = gBS->InstallConfigurationTable(&gEfiMemoryAttributesTableGuid, New);
    if (EFI_ERROR(Status)) {
        if (gDcsVerboseDebug) OUT_PRINT(L"DcsMatExec: InstallConfigurationTable %r\n", Status);
        FreePool(New);
        return FALSE;
    }

    // New is the live table now. Release the copy WE installed last time (never
    // the firmware's original), so repeated re-asserts do not leak a table.
    if (mOurMat != NULL) {
        FreePool(mOurMat);
    }
    mOurMat = New;

    if (!MatExecAddrExecutable(mGuardAddr, &MatPresent, FALSE)) {
        if (gDcsVerboseDebug) OUT_PRINT(L"DcsMatExec: code still not executable after MAT rebuild\n");
        return FALSE;
    }
    return TRUE;
}

//////////////////////////////////////////////////////////////////////////
// LoadImage re-assert
//////////////////////////////////////////////////////////////////////////

STATIC
EFI_STATUS
EFIAPI
MatExecLoadImage (
  IN  BOOLEAN                   BootPolicy,
  IN  EFI_HANDLE                ParentImageHandle,
  IN  EFI_DEVICE_PATH_PROTOCOL  *DevicePath,
  IN  VOID                      *SourceBuffer OPTIONAL,
  IN  UINTN                     SourceSize,
  OUT EFI_HANDLE                *ImageHandle
  )
{
    EFI_STATUS  Status;
    BOOLEAN     mp;

    Status = gOrgLoadImage(BootPolicy, ParentImageHandle, DevicePath,
                           SourceBuffer, SourceSize, ImageHandle);

    // Loading an image can make the firmware republish the MAT from its own
    // records, dropping our flip. Re-assert it so the copy winload finally
    // reads still marks our code executable.
    if (mLoadImageHooked && !MatExecAddrExecutable(mGuardAddr, &mp, FALSE)) {
        if (gDcsVerboseDebug) {
            OUT_PRINT(L"DcsMatExec: MAT flip was dropped, re-asserting after LoadImage\n");
        }
        MatExecFlipCore();   // best effort; caller's ExitBootServices net covers any remaining miss
    }

    return Status;
}

//////////////////////////////////////////////////////////////////////////
// Public entry points
//////////////////////////////////////////////////////////////////////////

BOOLEAN
MatExecMakeExecutable (
  IN EFI_PHYSICAL_ADDRESS  GuardAddr
  )
{
    mGuardAddr = GuardAddr;

    if (!MatExecFlipCore()) {
        return FALSE;
    }

    // Arm the LoadImage re-assert (idempotent).
    if (!mLoadImageHooked) {
        mOrigBsCrc      = gBS->Hdr.CRC32;
        gOrgLoadImage   = gBS->LoadImage;
        gBS->LoadImage  = MatExecLoadImage;
        MatExecRecomputeTableCrc(&gBS->Hdr);
        mLoadImageHooked = TRUE;
        if (gDcsVerboseDebug) {
            OUT_PRINT(L"DcsMatExec: LoadImage hooked to re-assert MAT flip\n");
        }
    }
    return TRUE;
}

VOID
MatExecDisarm (
  VOID
  )
{
    if (mLoadImageHooked) {
        gBS->LoadImage = gOrgLoadImage;
        gBS->Hdr.CRC32 = mOrigBsCrc;
        mLoadImageHooked = FALSE;
    }
}

VOID
MatExecFreeTable (
  VOID
  )
{
    if (mOurMat != NULL) {
        FreePool(mOurMat);
        mOurMat = NULL;
    }
}
