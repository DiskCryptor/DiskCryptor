/** @file
GPT low level actions

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/BaseMemoryLib.h>
#include <Uefi/UefiGpt.h>
#include <Guid/Gpt.h>

#include <Library/CommonLib.h>

/**
Checks the CRC32 value in the table header.

@param  MaxSize   Max Size limit
@param  Size      The size of the table
@param  Hdr       Table to check

@return TRUE    CRC Valid
@return FALSE   CRC Invalid

**/
BOOLEAN
GptHeaderCheckCrcAltSize(
	IN UINTN                 MaxSize,
	IN UINTN                 Size,
	IN OUT EFI_TABLE_HEADER  *Hdr
	)
{
	UINT32      Crc;
	UINT32      OrgCrc;
	EFI_STATUS  Status;

	Crc = 0;

	if (Size == 0) {
		//
		// If header size is 0 CRC will pass so return FALSE here
		//
		return FALSE;
	}

	if ((MaxSize != 0) && (Size > MaxSize)) {
		return FALSE;
	}
	//
	// clear old crc from header
	//
	OrgCrc = Hdr->CRC32;
	Hdr->CRC32 = 0;

	Status = gBS->CalculateCrc32((UINT8 *)Hdr, Size, &Crc);
	Hdr->CRC32 = OrgCrc;
	if (EFI_ERROR(Status)) {
		return FALSE;
	}
	// set results
	return (BOOLEAN)(OrgCrc == Crc);
}

/**
Checks the CRC32 value in the table header.

@param  MaxSize   Max Size limit
@param  Hdr       Table to check

@return TRUE      CRC Valid
@return FALSE     CRC Invalid

**/
BOOLEAN
GptHeaderCheckCrc(
	IN UINTN                 MaxSize,
	IN OUT EFI_TABLE_HEADER  *Hdr
	)
{
	return GptHeaderCheckCrcAltSize(MaxSize, Hdr->HeaderSize, Hdr);
}

EFI_STATUS
GptCheckEntryArray(
	IN  EFI_PARTITION_TABLE_HEADER  *PartHeader,
	IN  EFI_PARTITION_ENTRY         *Entrys
	)
{
	EFI_STATUS  Status;
	UINT32      Crc;
	UINTN       Size;

	Size = (UINTN)PartHeader->NumberOfPartitionEntries * (UINTN)PartHeader->SizeOfPartitionEntry;
	Status = gBS->CalculateCrc32(Entrys, Size, &Crc);
	if (EFI_ERROR(Status)) {
		return EFI_CRC_ERROR;
	}
	Status = (PartHeader->PartitionEntryArrayCRC32 == Crc) ? EFI_SUCCESS : EFI_CRC_ERROR;
	return Status;
}

EFI_STATUS
GptUpdateCRC(
	IN  EFI_PARTITION_TABLE_HEADER  *PartHeader,
	IN  EFI_PARTITION_ENTRY         *Entrys
	)
{
	EFI_STATUS  Status;
	UINT32      Crc;
	UINTN       Size;

	Size = (UINTN)PartHeader->NumberOfPartitionEntries * (UINTN)PartHeader->SizeOfPartitionEntry;
	Status = gBS->CalculateCrc32(Entrys, Size, &Crc);
	if (EFI_ERROR(Status)) {
		return Status;
	}
	PartHeader->PartitionEntryArrayCRC32 = Crc;
	PartHeader->Header.CRC32 = 0;

	Status = gBS->CalculateCrc32((UINT8 *)PartHeader, PartHeader->Header.HeaderSize, &Crc);
	if (EFI_ERROR(Status)) {
		return Status;
	}
	PartHeader->Header.CRC32 = Crc;
	return Status;
}

/**
Read GPT
Check if the CRC field in the Partition table header is valid
for Partition entry array.

@param[in]  BlockIo     Disk Io Protocol.
@param[in]  PartHeader  Partition table header structure

@retval EFI_SUCCESS     the CRC is valid
**/
EFI_STATUS
GptReadEntryArray(
	IN  EFI_BLOCK_IO_PROTOCOL*      BlockIo,
	IN  EFI_PARTITION_TABLE_HEADER  *PartHeader,
	OUT EFI_PARTITION_ENTRY         **Entrys
	)
{
	EFI_STATUS  Status;
	UINT8       *Ptr;
	UINTN       Size;

	// Reject on-disk counts whose size would wrap; GptCheckEntryArray uses the same size.
	if (PartHeader->SizeOfPartitionEntry == 0 ||
		PartHeader->NumberOfPartitionEntries > MAX_UINT32 / PartHeader->SizeOfPartitionEntry) {
		return EFI_CRC_ERROR;
	}
	Size = (UINTN)PartHeader->NumberOfPartitionEntries * (UINTN)PartHeader->SizeOfPartitionEntry;

	//
	// Read the EFI Partition Entries
	//
	Ptr = MEM_ALLOC(Size);
	if (Ptr == NULL) {
		return EFI_BUFFER_TOO_SMALL;
	}

	Status = BlockIo->ReadBlocks(
		BlockIo,
		BlockIo->Media->MediaId,
		PartHeader->PartitionEntryLBA,
		Size,
		Ptr
		);
	if (EFI_ERROR(Status)) {
		MEM_FREE(Ptr);
		return Status;
	}

	*Entrys = (EFI_PARTITION_ENTRY*)Ptr;
	return GptCheckEntryArray(PartHeader, *Entrys);
}

EFI_STATUS
GptReadHeader(
	IN  EFI_BLOCK_IO_PROTOCOL*      BlockIo,
	IN  EFI_LBA                     HeaderLba,
	OUT EFI_PARTITION_TABLE_HEADER  **PartHeader
	)
{
	EFI_STATUS                  res = EFI_SUCCESS;
	UINT32                      BlockSize;
	EFI_PARTITION_TABLE_HEADER  *PartHdr;
	UINT32                      MediaId;

	BlockSize = BlockIo->Media->BlockSize;
	MediaId = BlockIo->Media->MediaId;
	PartHdr = MEM_ALLOC(BlockSize);

	res = BlockIo->ReadBlocks(BlockIo, MediaId, HeaderLba, BlockSize, PartHdr);
	if (EFI_ERROR(res)) {
		MEM_FREE(PartHdr);
		return res;
	}

	// Check header
	if ((PartHdr->Header.Signature != EFI_PTAB_HEADER_ID) ||
		!GptHeaderCheckCrc(BlockSize, &PartHdr->Header) ||
		PartHdr->MyLBA != HeaderLba ||
		(PartHdr->SizeOfPartitionEntry < sizeof(EFI_PARTITION_ENTRY))
		) {
		MEM_FREE(PartHdr);
		return EFI_CRC_ERROR;
	}
	*PartHeader = PartHdr;
	return EFI_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
// General EFI tables
//////////////////////////////////////////////////////////////////////////

BOOLEAN
TablesVerify(
	IN UINTN maxSize,
	IN VOID* tables)
{
	EFI_TABLE_HEADER *mhdr = (EFI_TABLE_HEADER *)tables;
	if (tables != NULL &&
		mhdr->Signature == EFITABLE_HEADER_SIGN &&
		GptHeaderCheckCrc(maxSize, mhdr)) {
		UINT8* raw = (UINT8*)tables;
		UINTN  rawSize = mhdr->HeaderSize;
		UINTN tpos = sizeof(EFI_TABLE_HEADER);
		while (tpos < rawSize) {
			EFI_TABLE_HEADER *hdr = (EFI_TABLE_HEADER *)(raw + tpos);
			if (!GptHeaderCheckCrc(rawSize - tpos, hdr)) {
				return FALSE;	// wrong crc
			}
			tpos += hdr->HeaderSize;
		}
		return TRUE;
	}
	return FALSE;
}

BOOLEAN
TablesGetData(
	IN  VOID*   tables,
	IN  UINT64  sign,
	OUT VOID**  data,
	OUT UINTN*  size)
{
	EFI_TABLE_HEADER *mhdr = (EFI_TABLE_HEADER *)tables;
	if (tables != NULL &&
		mhdr->Signature == EFITABLE_HEADER_SIGN &&
		GptHeaderCheckCrc(0, mhdr)) {
		UINT8* raw = (UINT8*)tables;
		UINTN  rawSize = mhdr->HeaderSize;
		UINTN tpos = sizeof(EFI_TABLE_HEADER);
		while (tpos < rawSize) {
			EFI_TABLE_HEADER *hdr = (EFI_TABLE_HEADER *)(raw + tpos);
			if (GptHeaderCheckCrc(rawSize - tpos, hdr)) {
				if (hdr->Signature == sign) {
					*data = raw + tpos + sizeof(EFI_TABLE_HEADER);
					*size = hdr->HeaderSize - sizeof(EFI_TABLE_HEADER);
					return TRUE;
				}
				tpos += hdr->HeaderSize;
			}
			else {
				return FALSE;
			}
		}
	}
	return FALSE;
}

BOOLEAN
TablesDelete(
	IN  VOID*   tables,
	IN  UINT64  sign
	)
{
	EFI_TABLE_HEADER *mhdr = (EFI_TABLE_HEADER *)tables;
	EFI_TABLE_HEADER *thdr = NULL;
	UINT8* raw = (UINT8*)tables;
	UINTN  rawSize = mhdr->HeaderSize;
	UINTN  tpos = sizeof(EFI_TABLE_HEADER);
	if (tables != NULL &&
		mhdr->Signature == EFITABLE_HEADER_SIGN &&
		GptHeaderCheckCrc(0, mhdr)) {
		while (tpos < rawSize) {
			EFI_TABLE_HEADER *hdr = (EFI_TABLE_HEADER *)(raw + tpos);
			if (GptHeaderCheckCrc(rawSize - tpos, hdr)) {
				if (hdr->Signature == sign) {
					thdr = hdr;
					break;
				}
				tpos += hdr->HeaderSize;
			}	else {
				return FALSE;
			}
		}
		if (thdr != NULL) {
			UINT32 Crc;
			UINTN pos;
			mhdr->HeaderSize -= thdr->HeaderSize;
			pos = tpos + thdr->HeaderSize;
			while (pos < rawSize) {
				raw[tpos] = raw[pos];
				++tpos;
				++pos;
			}
			mhdr->CRC32 = 0;
			if (EFI_ERROR(gBS->CalculateCrc32((UINT8 *)raw, mhdr->HeaderSize, &Crc))) {
				return FALSE;
			}
			mhdr->CRC32 = Crc;
			return TRUE;
		}
	}
	return FALSE;
}

BOOLEAN
TablesAppend(
	IN OUT VOID**  tables,
	IN     UINT64  sign,
	IN     VOID*   data,
	IN     UINTN   size)
{
	EFI_TABLE_HEADER *mhdr = NULL;
	EFI_TABLE_HEADER *thdr = NULL;
	UINTN  rawSize = 0;
	UINT8* raw = (UINT8*)tables;
	if (tables != NULL &&
		(mhdr = (EFI_TABLE_HEADER *)*tables) != NULL &&
		mhdr->Signature == EFITABLE_HEADER_SIGN &&
		GptHeaderCheckCrc(0, mhdr)) {
		UINT32 Crc;
		rawSize = mhdr->HeaderSize;
		raw = MEM_REALLOC(rawSize, rawSize + sizeof(EFI_TABLE_HEADER) + size, mhdr);
		if (raw == NULL) {
			return FALSE;
		}
		mhdr = (EFI_TABLE_HEADER *)raw;
		thdr = (EFI_TABLE_HEADER *)(raw + rawSize);
		thdr->HeaderSize = (UINT32)(sizeof(EFI_TABLE_HEADER) + size);
		thdr->Signature = sign;
		CopyMem(((UINT8 *)thdr) + sizeof(EFI_TABLE_HEADER), data, size);

		thdr->CRC32 = 0;
		if (EFI_ERROR(gBS->CalculateCrc32((UINT8 *)thdr, thdr->HeaderSize, &Crc))) {
			return FALSE;
		}
		thdr->CRC32 = Crc;

		mhdr->HeaderSize += (UINT32)(size + sizeof(EFI_TABLE_HEADER));
		mhdr->CRC32 = 0;
		if (EFI_ERROR(gBS->CalculateCrc32((UINT8 *)raw, mhdr->HeaderSize, &Crc))) {
			return FALSE;
		}
		mhdr->CRC32 = Crc;
		*tables = raw;
		return TRUE;
	}
	return FALSE;
}
