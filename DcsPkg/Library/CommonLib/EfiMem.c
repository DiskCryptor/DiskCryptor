/** @file
EFI memory helpers routines/wrappers

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 
Copyright (c) 2026. DiskCryptor, David Xanatos

This program and the accompanying materials are licensed and made available
under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Uefi.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseMemoryLib.h>

#include "Library/CommonLib.h"


//////////////////////////////////////////////////////////////////////////
// Memory procedures wrappers
//////////////////////////////////////////////////////////////////////////

VOID*
MemAlloc(
   IN UINTN size
   ) {
   return AllocateZeroPool(size);
}

VOID*
MemRealloc(
	IN UINTN  OldSize,
	IN UINTN  NewSize,
	IN VOID   *OldBuffer  OPTIONAL
	) {
	return ReallocatePool(OldSize, NewSize, OldBuffer);
}

VOID
MemFree(
   IN VOID* ptr
   ) {
	if(ptr != NULL) FreePool(ptr);
}

//////////////////////////////////////////////////////////////////////////
// Memory mapped IO
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
PrepareMemory(
   IN UINTN    address,
   IN UINTN    len,
   OUT VOID**  mem)
{
   EFI_STATUS              status;
   EFI_PHYSICAL_ADDRESS    ptr;
   VOID*                   buf;
   UINTN                   pages;
   pages = ((len & ~0x0FFF) + 0x1000) >> 12;
   ptr = address & ~0x0FFF;
//	OUT_PRINT(L"mem try %0x, %0x\n", pages, (UINTN)ptr);
   status = gBS->AllocatePages(AllocateAddress, EfiMemoryMappedIO, pages, &ptr);
   if (EFI_ERROR(status)) {
      return status;
   }
   buf = (void*)(UINTN)ptr;
   SetMem(buf, pages << 12, 0);
   *mem = buf;
   return status;
}

EFI_STATUS
PrepareMemoryAny(
   IN UINTN    len,
   OUT VOID**  mem,
   OUT UINTN*  allocatedAddress)
{
   EFI_STATUS              status;
   EFI_PHYSICAL_ADDRESS    ptr;
   VOID*                   buf;
   UINTN                   pages;

   EFI_MEMORY_DESCRIPTOR*  memMap = NULL;
   EFI_MEMORY_DESCRIPTOR*  desc;
   UINTN                   memMapSize = 0;
   UINTN                   mapKey;
   UINTN                   descSize = 0;
   UINT32                  descVer;
   UINTN                   i;
   EFI_PHYSICAL_ADDRESS    best = 0;
   BOOLEAN                 found = FALSE;

   // Stay above the first MB on platforms that have low RAM; harmless on
   // platforms whose RAM starts far higher (regStart dominates).
   CONST EFI_PHYSICAL_ADDRESS floor    = 0x00100000ULL;   // 1 MB
   // Ignore transient slivers so we anchor to a real RAM bank whose base is
   // firmware-fixed and identical every boot.
   CONST UINT64               minPages = 16;              // 64 KB

   pages = ((len & ~0x0FFF) + 0x1000) >> 12;

   //
   // Deterministically pick a FIXED physical address by scanning the UEFI
   // memory map and choosing the LOWEST conventional region that fits, then
   // allocating at that region's base.
   //
   // Determinism is the property hibernation depends on: DCS runs on every
   // boot before the OS loader with the same allocation order, so the lowest
   // suitable region base resolves to the SAME address on the boot that
   // hibernates and the boot that resumes. The address then matches the one
   // recorded in the hibernation memory map and winresume accepts it.
   //
   // We deliberately do NOT cap the address at 4 GB: the ARM devices that
   // needed this path have no RAM below 4 GB. Handoff mode >= 2 carries the
   // address as bd_base64 (u64), so a high address is fine.
   //
   // Allocating at the region BASE (not a mid-region page) is intentional:
   // EDK2 serves other page/pool allocations top-down, so the bottom of a low
   // bank is least likely to be perturbed by unrelated allocations that differ
   // slightly between the hibernate and resume boots.
   //
   // AllocateAnyPages must NOT be used here: the firmware may place the block
   // at a different address across boots, desynchronizing the hibernation
   // memory map and triggering BL_LOG_ERROR_RES_INVALID_HBBOOT_MEM_MAP.
   //
   status = gBS->GetMemoryMap(&memMapSize, NULL, &mapKey, &descSize, &descVer);
   if (status != EFI_BUFFER_TOO_SMALL) {
      return EFI_ERROR(status) ? status : EFI_DEVICE_ERROR;
   }
   memMapSize += 4 * descSize;   // headroom: sizing the map may grow it
   memMap = AllocatePool(memMapSize);
   if (memMap == NULL) {
      return EFI_OUT_OF_RESOURCES;
   }
   status = gBS->GetMemoryMap(&memMapSize, memMap, &mapKey, &descSize, &descVer);
   if (EFI_ERROR(status)) {
      FreePool(memMap);
      return status;
   }

   for (i = 0; i < memMapSize / descSize; i++) {
      EFI_PHYSICAL_ADDRESS regStart, regEnd, cand;
      desc = (EFI_MEMORY_DESCRIPTOR*)((UINT8*)memMap + i * descSize);
      if (desc->Type != EfiConventionalMemory) continue;
      if (desc->NumberOfPages < minPages)       continue;   // skip slivers

      regStart = desc->PhysicalStart;
      regEnd   = desc->PhysicalStart + LShiftU64(desc->NumberOfPages, 12);

      cand = (regStart < floor) ? floor : regStart;
      cand = (cand + 0xFFF) & ~0xFFFULL;                     // page align up

      if (cand + LShiftU64(pages, 12) > regEnd) continue;    // doesn't fit

      if (!found || cand < best) {
         best  = cand;
         found = TRUE;
      }
   }
   FreePool(memMap);

   if (found) {
      ptr = best;
      status = gBS->AllocatePages(AllocateAddress, EfiMemoryMappedIO, pages, &ptr);
   }
   if (!found || EFI_ERROR(status)) {
      // Last resort so non-hibernation boots still work if the scan found
      // nothing or lost the race for the slot. NOT hibernation-safe.
      status = gBS->AllocatePages(AllocateAnyPages, EfiMemoryMappedIO, pages, &ptr);
      if (EFI_ERROR(status)) {
         return status;
      }
   }

   buf = (void*)(UINTN)ptr;
   SetMem(buf, pages << 12, 0);
   *mem = buf;
   if (allocatedAddress != NULL) {
      *allocatedAddress = (UINTN)ptr;
   }
   return status;
}

//////////////////////////////////////////////////////////////////////////
// Memory misc
//////////////////////////////////////////////////////////////////////////

EFI_STATUS MemoryHasPattern (
	CONST VOID* buffer,
	UINTN bufferLen,
	CONST VOID* pattern,
	UINTN patternLen)
{
	EFI_STATUS status = EFI_NOT_FOUND;
	if (patternLen <= bufferLen)
	{
		UINTN i;
		CONST UINT8* memPtr = (CONST UINT8*) buffer;
		for (i = 0; i <= (bufferLen - patternLen); ++i)
		{
			if (CompareMem (&memPtr[i], pattern, patternLen) == 0)
			{
				status = EFI_SUCCESS;
				break;
			}
		}
	}

	return status;
}
