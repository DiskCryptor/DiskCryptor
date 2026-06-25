/** @file
Interface for DCS

Copyright (c) 2019-2026. DiskCryptor, David Xanatos

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#include <Uefi.h>
#include "DcsDiskCryptor.h"
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/DevicePathLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>
#include <Guid/Gpt.h>
#include <Guid/FileSystemInfo.h>

#include <Library/CommonLib.h>
#include <Library/BaseLib.h>
#include <Library/GraphLib.h>
#include <Library/DcsCfgLib.h>
#include <Library/DcsIntLib.h>
#include <DcsConfig.h>

#include "../DcsTpm/DcsTpmProto.h"
#include "../MiscUtilsLib/MiscUtilsLib.h"
#include "../MiscUtilsLib/Verify.h"

#include "include/dc_header.h"
#include "include/dc_keyfiles.h"
#include "include/dc_io.h"
#include "DcsConfigMenu.h"

io_db iodb; // IO/Key Storage

dc_pass gDCryptPassword; // entered password
UINT8 gDCryptTpmSecret[DC_KF_HASH_SIZE];
BOOLEAN gDCryptTpmSecretValid = FALSE;
UINT32 gDCryptFlags = 0;
dc_pass gDCryptPassCache[DC_PASS_CACHE_SIZE];
UINT32 gDCryptPassCount = 0;

int gDCryptPwdCode = AskPwdRetLogin; // entry code
int gDCryptAuthRetry = 100;
UINT8 gDCryptFailOnTimeout = 0;
int gDCryptHwCrypto = 1;
UINT8 gDCryptBootMode = 0;
CHAR8* gDCryptBootPartition = NULL;
unsigned long gDCryptBootDiskID = 0;
UINT8 gBlockUnencryptedVolumes = 0; // When TRUE, block access to unencrypted partitions

UINT8 gDCryptHandoffMode = 0; // 0 = default, 1 = basic, 2 = full, 3 = keys only
bd_data* bootDataBlock = NULL; // data to be passed to the windows driver

UINT32 gDCryptTpmVersion = 0;
UINT8 gDCryptTpmAskOwnerPw = 0;     // 0=try without owner pw first, 1=always ask



int gDCryptTouchInput = 0;

UINT8 gDCryptAutoLogin = 0;
UINT8 gDCryptAutoLoginDelay = 3;

CHAR16* gDCryptAutoPassword = L"\0";
int gDCryptHeaderKdf = 0;

// KeyFile configuration
int gDCryptKfMixer = KEYFILE_MIX_HASHED;
UINT8 gDCryptUseKeyFile = DCryptNo;
CHAR16*	gDCryptKeyFilePath = L"\0";
CHAR8* gPlatformKeyFile = NULL;
UINTN gPlatformKeyFileSize = 0;

// Hardware Key Support
UINT8 gDCryptUseHardwareKey = DCryptNone;
int gDCryptTpmMode = DCryptTpmAuto;
int gDCryptTpmPcrMask = DCS_TPM_DEFAULT_PCR_MASK;
int gDCryptTpmStorage = DCryptTpmDefault;
BOOLEAN gDCryptTpmPinUsed = FALSE;  // Set when PIN was entered (skip countdown)



//////////////////////////////////////////////////////////////////////////
// Bootloader version and signature
//////////////////////////////////////////////////////////////////////////

typedef struct _ldr_version {
	unsigned long sign1;         // signature to search for bootloader in memory
	unsigned long sign2;         // signature to search for bootloader in memory
	unsigned long ldr_ver;       // bootloader version
} ldr_version;

ldr_version ver = {
	LDR_CFG_SIGN1, LDR_CFG_SIGN2,
	DCS_VERSION
};


// Read CPU timestamp/counter (architecture-specific)
static UINT64 ReadTimestamp(VOID) {
#if defined(MDE_CPU_AARCH64)
	// Read ARM64 virtual counter (CNTVCT_EL0)
	// Encoding: ((op0&1)<<14)|(op1<<11)|(CRn<<7)|(CRm<<3)|op2 = 0x5F02
	return _ReadStatusReg(0x5F02);
#else
	return AsmReadTsc();
#endif
}

// Cached ticks per millisecond (calibrated once)
static UINT64 gTicksPerMs = 0;

// Calibrate timer frequency using gBS->Stall (call once at startup)
static VOID CalibrateTimer(VOID) {
	if (gTicksPerMs != 0) return; // already calibrated
	UINT64 Start = ReadTimestamp();
	gBS->Stall(10000); // 10ms stall
	UINT64 End = ReadTimestamp();
	UINT64 Elapsed = (End >= Start) ? (End - Start) : (Start - End);
	gTicksPerMs = Elapsed / 10; // ticks per ms
	if (gTicksPerMs == 0) gTicksPerMs = 1; // prevent div by zero
}

// Helper to calculate elapsed milliseconds from timer ticks
static UINT64 GetElapsedMs(UINT64 StartTick, UINT64 EndTick) {
	if (gTicksPerMs == 0) CalibrateTimer();
	UINT64 ElapsedTicks = (EndTick >= StartTick) ? (EndTick - StartTick) : (StartTick - EndTick);
	return ElapsedTicks / gTicksPerMs;
}

VOID CleanSensitiveDataDC(BOOLEAN panic)
{
	MEM_BURN(&iodb, sizeof(iodb));

	MEM_BURN(&gDCryptPassword, sizeof(gDCryptPassword));

	MEM_BURN(gDCryptPassCache, sizeof(gDCryptPassCache));

	MEM_BURN(gDCryptTpmSecret, sizeof(gDCryptTpmSecret));

	if (panic && bootDataBlock != NULL) {
		MEM_BURN(bootDataBlock, sizeof(*bootDataBlock));
	}
}

//////////////////////////////////////////////////////////////////////////
// DCrypt Boot params memory
//////////////////////////////////////////////////////////////////////////

EFI_STATUS PrepLegacyBootDataBlock()
{
	EFI_STATUS ret = EFI_SUCCESS;
	UINTN addr;
	UINTN len = sizeof(bd_data);

	// Note: the legacy memory range is compatible with an unmodified dcrypt.sys but on some UEFI's it's not free :/

	if (bootDataBlock != NULL) return ret;

	// select memory in range 500-640k
	for (addr = 500*1024; addr < 640*1024; addr += PAGE_SIZE) {
		ret = PrepareMemory(addr, len, &bootDataBlock);
		if (!EFI_ERROR(ret)) {
			break;
		}
	}

	if (EFI_ERROR(ret)) {
		return ret;
	}

	// set memory region to be zeroed by the driver
	bootDataBlock->bd_size = (u32)len;
	bootDataBlock->bd_base = (u32)addr;

	return ret;
}

EFI_STATUS PrepareBootDataBlock(BOOLEAN full)
{
	EFI_STATUS ret = EFI_SUCCESS;
	UINTN addr;
	UINTN len = sizeof(bd_data);
	if (full) {
		len += DC_PASS_CACHE_SIZE * sizeof(dc_pass);
		len += MOUNT_MAX * sizeof(header_key);
	}

	// Note: using the new ranges requires an updated dcrypt.sys

	if (bootDataBlock != NULL) return ret;

	if (gDCryptHandoffMode >= 2)
		ret = PrepareMemoryAny(len, &bootDataBlock, &addr);
	else
	{
		// x86/x64: select memory in range 1-16M in steps of 1M
		for (addr = 0x00100000; addr <= 0x01000000; addr += (256 * PAGE_SIZE)) {
			ret = PrepareMemory(addr, len, &bootDataBlock);
			if (!EFI_ERROR(ret)) {
				break;
			}
		}
	}

	if (EFI_ERROR(ret)) {
		return ret;
	}

	if (gConfigDebug) {
		OUT_PRINT(L"DEBUG: bdb address 0x%p, size %d\n", addr, len);
	}
	
	// set memory region to be zeroed by the driver
	bootDataBlock->bd_size = (u32)len;
	if (gDCryptHandoffMode >= 2)
		bootDataBlock->bd_base64 = (u64)addr;
	else
		bootDataBlock->bd_base = (u32)addr;

	if (full) {
		gDCryptFlags |= BDB_BF_BOOT_KEYS;
	}

	return EFI_SUCCESS;
}

EFI_STATUS SetBootDataBlock()
{
	EFI_STATUS ret = EFI_SUCCESS;
	int i;

	if (bootDataBlock == NULL)
		return EFI_UNSUPPORTED;

	// setup boot data block signature
	bootDataBlock->sign1 = BDB_SIGN1;
	bootDataBlock->sign2 = BDB_SIGN2;
	bootDataBlock->sign3 = BDB_SIGN3;
	bootDataBlock->zero = 0;

	// memory region gets already set by PrepareBootDataBlock

	if (gDCryptHandoffMode >= 2)
	{
		UINTN addr = (UINTN)bootDataBlock->bd_base64;
		ret = EfiSetVar(L"DcsBootDataAddr", NULL, &addr, sizeof(addr), EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS);
		if (EFI_ERROR(ret)) {
			return ret;
		}
	}

	// set password
	if (gDCryptHandoffMode != 3) {
		bootDataBlock->password_size = gDCryptPassword.size; // in bytes
		CopyMem(bootDataBlock->password_data, gDCryptPassword.pass, bootDataBlock->password_size);
		bootDataBlock->password_kdf = gDCryptPassword.kdf;
		bootDataBlock->password_slot = gDCryptPassword.slot;
	}

	// set the disk keys if possible
	if (gDCryptFlags & BDB_BF_BOOT_KEYS) {
		
		long offset = sizeof(bd_data);

		if (gDCryptPassCount && gDCryptHandoffMode != 3) {
			gDCryptFlags |= BDB_BF_PASS_CACHE;

			bootDataBlock->pass_offset = offset;
			//bootDataBlock->pass_offset = bootDataBlock->key_offset + (bootDataBlock->key_size * bootDataBlock->key_count);
			bootDataBlock->pass_size = sizeof(dc_pass);
			bootDataBlock->pass_count = gDCryptPassCount;

			dc_pass* passes = (dc_pass*)(((char*)bootDataBlock) + bootDataBlock->pass_offset);

			for (i = 0; i < (int)gDCryptPassCount; i++) {
				passes[i] = gDCryptPassCache[i];
			}

			offset = bootDataBlock->pass_offset + (bootDataBlock->pass_size * bootDataBlock->pass_count);
		}

		bootDataBlock->key_offset = offset;
		bootDataBlock->key_size = sizeof(header_key);
		bootDataBlock->key_count = iodb.n_mount;

		header_key* keys = (header_key*)(((char*)bootDataBlock) + bootDataBlock->key_offset);

		for (i = 0; i < iodb.n_mount; i++) {
			keys[i].alg = iodb.p_mount[i].h_alg;
			keys[i].kdf = iodb.p_mount[i].h_kdf;
			memcpy(keys[i].guid, iodb.p_mount[i].disk_guid, sizeof(keys[i].guid));
			memcpy(keys[i].key, iodb.p_mount[i].h_key, PKCS_DERIVE_MAX);
		}
	}

	// pass block unencrypted volumes flag to the driver
	if (gBlockUnencryptedVolumes) {
		gDCryptFlags |= BDB_BF_NO_UNENCRYPTED;
	}

	// set additional data
	bootDataBlock->flags = gDCryptFlags;

	return ret;
}

//////////////////////////////////////////////////////////////////////////
// Read/Write - Partition-level I/O
//////////////////////////////////////////////////////////////////////////

// Raw partition I/O using partition-relative sector addresses
// Called from dc_crypt_io/dc_mount_io with partition-relative LBA
int dc_direct_io(mount_inf *mount, void *buff, u16 sectors, u64 start, int read)
{
	EFI_STATUS           Status;
	DCSINT_BLOCK_IO      *DcsIntBlockIo = NULL;
	EFI_BLOCK_IO_PROTOCOL *BlockIo;

	if (mount == NULL || mount->BlockIo == NULL) {
		ERR_PRINT(L"\nhdd_io: mount or BlockIo is NULL\n");
		return 0;
	}

	BlockIo = (EFI_BLOCK_IO_PROTOCOL*)mount->BlockIo;
	DcsIntBlockIo = GetBlockIoByProtocol(BlockIo);

	if (DcsIntBlockIo != NULL) {
		// Hook is installed - use LowRead/LowWrite to access underlying partition BlockIo
		// start is partition-relative (0 = partition start)
		if (read)
			Status = DcsIntBlockIo->LowRead(BlockIo, BlockIo->Media->MediaId, start, sectors * mount->bps, buff);
		else
			Status = DcsIntBlockIo->LowWrite(BlockIo, BlockIo->Media->MediaId, start, sectors * mount->bps, buff);
	}
	else {
		// Hook not yet installed - use BlockIo directly (only for reads during setup)
		if (read)
			Status = BlockIo->ReadBlocks(BlockIo, BlockIo->Media->MediaId, start, sectors * mount->bps, buff);
		else
			Status = EFI_DEVICE_ERROR; // Don't allow writes before hook is installed
	}

	return EFI_ERROR(Status) ? 0 : 1;
}

// Volume-level write hook - handles encrypted partition writes or blocks unencrypted
EFI_STATUS
DCVolumeIO_Write(
	IN EFI_BLOCK_IO_PROTOCOL *This,
	IN UINT32                MediaId,
	IN EFI_LBA               Lba,
	IN UINTN                 BufferSize,
	IN VOID                  *Buffer
	)
{
	EFI_STATUS           Status = EFI_SUCCESS;
	DCSINT_BLOCK_IO      *DcsIntBlockIo = NULL;
	mount_inf            *mount = NULL;
	VOID                 *writeBuff;

	DcsIntBlockIo = GetBlockIoByProtocol(This);
	if (DcsIntBlockIo == NULL)
		return EFI_NOT_FOUND;

	mount = (mount_inf*)DcsIntBlockIo->FilterParams;
	if (mount == NULL)
		return EFI_DEVICE_ERROR; // Blocked partition

	// use a copy of the buffer to not change the input buffer
	writeBuff = MEM_ALLOC(BufferSize);
	if (writeBuff == NULL)
		return EFI_BAD_BUFFER_SIZE;
	CopyMem(writeBuff, Buffer, BufferSize);

	// Lba is partition-relative, pass directly to dc_mount_io
	if (!dc_mount_io(mount, writeBuff, (u16)(BufferSize / mount->bps), Lba, 0))
		Status = EFI_DEVICE_ERROR;

	MEM_FREE(writeBuff);

	return Status;
}

// Volume-level read hook - handles encrypted partition reads or blocks unencrypted
EFI_STATUS
DCVolumeIO_Read(
	IN EFI_BLOCK_IO_PROTOCOL *This,
	IN UINT32                MediaId,
	IN EFI_LBA               Lba,
	IN UINTN                 BufferSize,
	OUT VOID                 *Buffer
	)
{
	EFI_STATUS           Status = EFI_SUCCESS;
	DCSINT_BLOCK_IO      *DcsIntBlockIo = NULL;
	mount_inf            *mount = NULL;

	DcsIntBlockIo = GetBlockIoByProtocol(This);
	if (DcsIntBlockIo == NULL)
		return EFI_NOT_FOUND;

	mount = (mount_inf*)DcsIntBlockIo->FilterParams;
	if (mount == NULL)
		return EFI_DEVICE_ERROR; // Blocked partition

	// Lba is partition-relative, pass directly to dc_mount_io
	if (!dc_mount_io(mount, Buffer, (u16)(BufferSize / mount->bps), Lba, 1))
		Status = EFI_DEVICE_ERROR;

	return Status;
}

// Check if a partition handle is the boot ESP (the ESP from which DCS was started)
// Returns TRUE if this is the boot ESP, FALSE otherwise
static BOOLEAN
IsBootEsp(
	IN EFI_HANDLE PartitionHandle
	)
{
	EFI_DEVICE_PATH *PartPath;
	EFI_DEVICE_PATH *BootPath;
	UINTN PartPathSize;
	UINTN BootPathSize;

	if (IsPxeBoot()) {
		// If booted from PXE, there is no boot ESP to exempt
		return FALSE;
	}

	if (gFileRootHandle == NULL || PartitionHandle == NULL) {
		return FALSE;
	}

	// Direct handle comparison is the simplest check
	if (PartitionHandle == gFileRootHandle) {
		return TRUE;
	}

	// Also compare device paths in case handles differ
	PartPath = DevicePathFromHandle(PartitionHandle);
	BootPath = DevicePathFromHandle(gFileRootHandle);

	if (PartPath == NULL || BootPath == NULL) {
		return FALSE;
	}

	PartPathSize = GetDevicePathSize(PartPath);
	BootPathSize = GetDevicePathSize(BootPath);

	if (PartPathSize != BootPathSize) {
		return FALSE;
	}

	return (CompareMem(PartPath, BootPath, PartPathSize) == 0);
}

// Find mount_inf for a partition (identified by device path), returns NULL if not mounted
static mount_inf*
GetPartitionMount(
	IN EFI_DEVICE_PATH *PartPath
	)
{
	UINTN pathSize;

	if (PartPath == NULL)
		return NULL;

	pathSize = GetDevicePathSize(PartPath);

	for (int i = 0; i < iodb.n_mount; i++) {
		EFI_DEVICE_PATH *mountPath = (EFI_DEVICE_PATH*)iodb.p_mount[i].efi_path;
		if (mountPath != NULL &&
			GetDevicePathSize(mountPath) == pathSize &&
			CompareMem(PartPath, mountPath, pathSize) == 0) {
			return &iodb.p_mount[i];
		}
	}
	return NULL;
}

// Helper: Get disk number (1-based index among non-partition handles)
static int
GetDiskNumber(EFI_HANDLE diskHandle)
{
	int diskNum = 0;
	for (UINTN j = 0; j < gBIOCount; j++) {
		if (!EfiIsPartition(gBIOHandles[j])) {
			diskNum++;
			if (gBIOHandles[j] == diskHandle) {
				return diskNum;
			}
		}
	}
	return 0; // not found
}


//////////////////////////////////////////////////////////////////////////
// Mounting
//////////////////////////////////////////////////////////////////////////

// Check if raw partition data contains a known filesystem boot sector.
// Encrypted partitions look like random data and won't match any of these.
// Multiple fields are validated to minimize false positives.
// If SerialNumber is not NULL, writes the formatted volume serial number.
static const UINT16*
GetFilesystemInfo(
	UINT8 *Data,
	UINT16 *SerialNumber  // Optional: buffer for formatted serial (min 18 chars for "XXXXXXXX-XXXXXXXX\0")
)
{
	UINT32 serial32;
	UINT64 serial64;

	// Initialize output if provided
	if (SerialNumber != NULL)
		SerialNumber[0] = L'\0';

	// ReFS: Signature at offset 3, serial at offset 0x38 (no 0x55AA requirement)
	if (CompareMem(Data + 3, "ReFS", 4) == 0) {
		if (SerialNumber != NULL) {
			serial64 = *(UINT64*)(Data + 0x38);
			UnicodeSPrint(SerialNumber, 18 * sizeof(UINT16), L"%08X-%08X",
				(UINT32)(serial64 >> 32), (UINT32)(serial64 & 0xFFFFFFFF));
		}
		return L"ReFS";
	}

	// All FAT/NTFS/exFAT boot sectors have the 0x55AA signature at offset 510
	if (Data[510] != 0x55 || Data[511] != 0xAA)
		return NULL;

	// NTFS: OEM ID at offset 3, serial at offset 72 (8 bytes)
	if (CompareMem(Data + 3, "NTFS    ", 8) == 0) {
		if (SerialNumber != NULL) {
			serial64 = *(UINT64*)(Data + 72);
			UnicodeSPrint(SerialNumber, 18 * sizeof(UINT16), L"%08X-%08X",
				(UINT32)(serial64 >> 32), (UINT32)(serial64 & 0xFFFFFFFF));
		}
		return L"NTFS";
	}

	// exFAT: OEM ID at offset 3, serial at offset 100 (4 bytes)
	if (CompareMem(Data + 3, "EXFAT   ", 8) == 0) {
		if (SerialNumber != NULL) {
			serial32 = *(UINT32*)(Data + 100);
			UnicodeSPrint(SerialNumber, 10 * sizeof(UINT16), L"%04X-%04X",
				(serial32 >> 16) & 0xFFFF, serial32 & 0xFFFF);
		}
		return L"exFAT";
	}

	// FAT32: FS type string at offset 82, serial at offset 67 (4 bytes)
	if (CompareMem(Data + 82, "FAT32   ", 8) == 0) {
		if (SerialNumber != NULL) {
			serial32 = *(UINT32*)(Data + 67);
			UnicodeSPrint(SerialNumber, 10 * sizeof(UINT16), L"%04X-%04X",
				(serial32 >> 16) & 0xFFFF, serial32 & 0xFFFF);
		}
		return L"FAT32";
	}

	// FAT16: FS type string at offset 54, serial at offset 39 (4 bytes)
	if (CompareMem(Data + 54, "FAT16   ", 8) == 0) {
		if (SerialNumber != NULL) {
			serial32 = *(UINT32*)(Data + 39);
			UnicodeSPrint(SerialNumber, 10 * sizeof(UINT16), L"%04X-%04X",
				(serial32 >> 16) & 0xFFFF, serial32 & 0xFFFF);
		}
		return L"FAT16";
	}

	// FAT12: FS type string at offset 54, serial at offset 39 (4 bytes)
	if (CompareMem(Data + 54, "FAT12   ", 8) == 0) {
		if (SerialNumber != NULL) {
			serial32 = *(UINT32*)(Data + 39);
			UnicodeSPrint(SerialNumber, 10 * sizeof(UINT16), L"%04X-%04X",
				(serial32 >> 16) & 0xFFFF, serial32 & 0xFFFF);
		}
		return L"FAT12";
	}

	return NULL;
}

// Check if a partition's GPT type is one we should try to decrypt.
// Reads GPT from the disk, finds the partition by start LBA, checks the type.
// Returns TRUE for System (ESP), Basic Data, and Recovery partitions.
// Returns TRUE if GPT cannot be read (MBR disk) to avoid skipping anything.
static BOOLEAN
IsTargetPartitionType(
	EFI_BLOCK_IO_PROTOCOL *DiskBio,
	EFI_LBA               PartStart
)
{
	EFI_PARTITION_TABLE_HEADER *gptHdr = NULL;
	EFI_PARTITION_ENTRY        *gptEntry = NULL;
	BOOLEAN result = TRUE; // default: allow
	UINT32 gi;

	if (DiskBio == NULL)
		return TRUE;

	if (EFI_ERROR(GptReadHeader(DiskBio, 1, &gptHdr)) || gptHdr == NULL)
		return TRUE; // not a GPT disk

	if (EFI_ERROR(GptReadEntryArray(DiskBio, gptHdr, &gptEntry)) || gptEntry == NULL) {
		MEM_FREE(gptHdr);
		return TRUE;
	}

	for (gi = 0; gi < gptHdr->NumberOfPartitionEntries; gi++) {
		if (gptEntry[gi].StartingLBA == PartStart) {
			EFI_GUID *type = &gptEntry[gi].PartitionTypeGUID;
			if (!CompareGuid(type, &gEfiPartTypeSystemPartGuid) &&
				!CompareGuid(type, &gEfiPartTypeBasicDataPartGuid) &&
				!CompareGuid(type, &gEfiPartTypeMsRecoveryPartGuid)) {
				result = FALSE;
			}
			break;
		}
	}

	MEM_FREE(gptEntry);
	MEM_FREE(gptHdr);
	return result;
}

VOID
DcTryDecrypt(int* vol_found, int* hdr_found)
{
	EFI_STATUS       ret = EFI_SUCCESS;
	UINTN            i;
	HARDDRIVE_DEVICE_PATH part;
	EFI_HANDLE       disk;
	int              diskNum;
	EFI_BLOCK_IO_PROTOCOL *partBlockIo;
	EFI_BLOCK_IO_PROTOCOL *diskBlockIo;
	EFI_DEVICE_PATH* partPath;
	dc_header*       header = NULL;
	int	             header_size = 0;
	int	             hdr_len;
	int				 hdr_alg;
	u8               hdr_key[PKCS_DERIVE_MAX];
	int				 hdr_kdf;
	int				 key_slot;
	mount_inf*       mount;
	const UINT16*    fsType;
	UINT16           fsSerial[18];

	// check all partitions if the password works for one
	for (i = 0; i < gBIOCount; ++i) {

		ret = EfiGetPartDetails(gBIOHandles[i], &part, &disk);
		if (EFI_ERROR(ret)) continue; // means it's not a partition same as EfiIsPartition() == FALSE

		// Get disk number for debug output
		diskNum = GetDiskNumber(disk);

		// Get partition's BlockIo and device path
		partBlockIo = EfiGetBlockIO(gBIOHandles[i]);
		partPath = DevicePathFromHandle(gBIOHandles[i]);
		diskBlockIo = EfiGetBlockIO(disk);

		if (partBlockIo == NULL || partPath == NULL) {
			continue;
		}

		// Skip already mounted partitions
		if (GetPartitionMount(partPath) != NULL) {
			if (gConfigDebug) {
				OUT_PRINT(L"Skipping volume %d:%d (already mounted)\n", diskNum, part.PartitionNumber);
			}
			continue;
		}

		if (partBlockIo->Media->BlockSize > MAX_SECTOR_SIZE) {
			ERR_PRINT(L"Partition has unsupported block size %d\n", partBlockIo->Media->BlockSize);
			continue;
		}

		// Skip partitions whose GPT type is not a decryption target
		// (only System, Basic Data, and Recovery are tried by default).
		// MBR partitions or partitions not found in GPT are always allowed.
		if (diskBlockIo != NULL && !IsTargetPartitionType(diskBlockIo, part.PartitionStart)) {
			if (gConfigDebug) {
				OUT_PRINT(L"Skipping volume %d:%d (non-target partition type)\n", diskNum, part.PartitionNumber);
			}
			continue;
		}

		// Determine header size to read based on the password (key slot)
		hdr_len = ROUND_TO_FULL_SECTORS(dc_get_min_header_len(&gDCryptPassword), partBlockIo->Media->BlockSize);
		if (hdr_len > header_size) {
			if (header) {
				MEM_BURN(header, header_size);
				MEM_FREE(header);
				header_size = 0;
			}
			header = (dc_header*)MEM_ALLOC(hdr_len);
			if (header == NULL) {
				ERR_PRINT(L"Not enough memory to allocate header buffer\n");
				continue;
			}
			header_size = hdr_len;
		}

		// Read header from partition start (LBA 0 of partition)
		ret = partBlockIo->ReadBlocks(partBlockIo, partBlockIo->Media->MediaId, 0, hdr_len, header);
		if (EFI_ERROR(ret)) {
			ERR_PRINT(L"Can't read partition, status %r\n", ret);
			continue;
		}

		// Skip partitions with recognized filesystem signatures (FAT12/16/32, NTFS, exFAT, ReFS).
		// These are not encrypted and attempting decryption on them wastes time.
		if (GetFilesystemInfo((UINT8*)header, NULL)) {
			if (gConfigDebug) {
				OUT_PRINT(L"Skipping volume %d:%d (known filesystem)\n", diskNum, part.PartitionNumber);
			}
			continue;
		}

		if (gConfigDebug) {
			OUT_PRINT(L"Mounting volume %d:%d ... ", diskNum, part.PartitionNumber);
		}

		UINT64 StartTick = ReadTimestamp();
		int decrypt_result = dc_decrypt_header(header, hdr_len, &gDCryptPassword, &hdr_alg, hdr_key, &hdr_kdf, &key_slot);
		UINT64 EndTick = ReadTimestamp();
		UINT64 ElapsedMs = GetElapsedMs(StartTick, EndTick);

		if (decrypt_result == 0)
		{
			if (gConfigDebug) {
				ERR_PRINT(L"Fail (%llu ms)\n", ElapsedMs);
			}

			continue;
		}
		(*vol_found)++;

		if ((iodb.n_mount >= MOUNT_MAX) ||
			(iodb.n_key >= MOUNT_MAX - ((header->flags & VF_REENCRYPT) ? 1 : 0)))
		{
			ERR_PRINT(L"Not enough memory to mount all partitions\n");
			continue;
		}
		mount = &iodb.p_mount[iodb.n_mount];

		// Store partition device path and BlockIo for hook registration
		// The hook modifies the BlockIo function pointers in place, so we can store it now
		mount->efi_path = partPath;
		mount->BlockIo  = partBlockIo;
		mount->size     = part.PartitionSize;
		mount->bps      = partBlockIo->Media->BlockSize;

		mount->version  = header->version;
		mount->features = header->feature_flags;
		mount->flags    = header->flags;
		mount->tmp_size = header->tmp_size / mount->bps;

		if (header->version >= DC_HDR_VERSION_2) {
			mount->head_len = ROUND_TO_FULL_SECTORS(header->head_len, mount->bps) / mount->bps;
			if (header->flags & VF_STORAGE_FILE) {
				mount->use_size = mount->size;
				mount->stor_off = header->stor_off / mount->bps;
			} else {
				mount->use_size = mount->size - (header->stor_len / mount->bps);
				mount->stor_off = mount->use_size;
			}
			mount->stor_len = header->stor_len / mount->bps;
		} else {
			mount->head_len = ROUND_TO_FULL_SECTORS(DC_AREA_SIZE, mount->bps) / mount->bps;
			if (header->flags & VF_STORAGE_FILE) {
				mount->use_size = mount->size;
				mount->stor_off = header->stor_off / mount->bps;
			} else {
				mount->use_size = mount->size - mount->head_len;
				mount->stor_off = mount->use_size;
			}
			mount->stor_len = mount->head_len;
		}

		mount->disk_id  = header->disk_id;

		memcpy(mount->disk_guid, header->salt, 16); // the first 128 bits of the header salt are used as a disk GUID
		mount->h_alg = hdr_alg;
		mount->h_kdf = hdr_kdf;
		memcpy(mount->h_key, hdr_key, PKCS_DERIVE_MAX);
		mount->d_key      = &iodb.p_key[iodb.n_key++];
		xts_set_key(header->key_1, header->alg_1, mount->d_key);
		if (header->flags & VF_REENCRYPT) {
			mount->o_key  = &iodb.p_key[iodb.n_key++];
			xts_set_key(header->key_2, header->alg_2, mount->o_key);
		}

		iodb.n_mount++;

		if (gConfigDebug) {
			OUT_PRINT(L"%VSuccess%N (%llu ms) [%s%s%d/%d, %uKB%s%s]",
				ElapsedMs,
				mount->version >= DC_HDR_VERSION_2 ? L"v2" : L"v1",
				(mount->features & FF_KEY_SLOTS) ? L"+" : L"-",
				hdr_kdf,
				key_slot,
				(mount->head_len * mount->bps) / 1024,
				(mount->flags & VF_BACKUP_HEADER) ? L"x2" : L"",
				(mount->flags & VF_STORAGE_FILE) ? L"" : L"@");
			// Read and decrypt first sector to detect filesystem type
			if (dc_mount_io(mount, header, 1, 0, 1) && (fsType = GetFilesystemInfo((UINT8*)header, fsSerial))) {
				OUT_PRINT(L" (FS: %s)\n", fsType);
			} else {
				ERR_PRINT(L" (FS: unknown)\n");
			}
		}
	}

	if (/*!*vol_found &&*/ hdr_found && !IsPxeBoot())
	{
		//OUT_PRINT(L"enum my root\n");

		EFI_FILE* root;
		ret = FileOpenRoot(gFileRootHandle, &root);
		if (EFI_ERROR(ret)) { ERR_PRINT(L"FileOpenRoot %r\n", ret); }
		else
		{
			EFI_FILE* dir;
			ret = root->Open(root, &dir, L"EFI\\" DCS_DIRECTORY, EFI_FILE_READ_ONLY, 0);
			if (EFI_ERROR(ret)) { ERR_PRINT(L"root->Open %r\n", ret); }
			else
			{
				EFI_FILE_INFO* DirInfo;
				UINTN          BufferSize;
				UINTN          DirBufferSize;

				DirBufferSize = sizeof(EFI_FILE_INFO) + 1024;
				DirInfo = MEM_ALLOC(DirBufferSize);

				for (; !EFI_ERROR(ret);) {
					BufferSize = DirBufferSize;
					ret = dir->Read(dir, &BufferSize, DirInfo);

					if (EFI_ERROR(ret) || (BufferSize == 0))
						break; // done

					if ((DirInfo->Attribute & EFI_FILE_DIRECTORY) != 0)
						continue; // skip directories

					if (StrnCmp(DirInfo->FileName, L"TestHeader_", 11) != 0)
						continue; // not what we were looking for

					EFI_FILE* file;
					ret = dir->Open(dir, &file, DirInfo->FileName, EFI_FILE_MODE_READ, 0);
					if (EFI_ERROR(ret)) { ERR_PRINT(L"dir->Open %r\n", ret); }
					else
					{
						OUT_PRINT(L"Trying to decrypt test header for: %s ... ", &DirInfo->FileName[11]);

						UINTN fileSize = DC_AREA_SIZE;
						ret = file->Read(file, &fileSize, header);
						if (EFI_ERROR(ret)) { ERR_PRINT(L"file->read %r\n", ret); }
						else
						{
							if (fileSize < DC_AREA_SIZE) {
								ERR_PRINT(L"is to small %d\n", &DirInfo->FileName[11], fileSize);
							}
							else {
								UINT64 HdrStartTick = ReadTimestamp();
								int hdr_decrypt_result = dc_decrypt_header(header, (int)fileSize, &gDCryptPassword, NULL, NULL, NULL, NULL);
								UINT64 HdrEndTick = ReadTimestamp();
								UINT64 HdrElapsedMs = GetElapsedMs(HdrStartTick, HdrEndTick);

								if (hdr_decrypt_result == 0) {
									ERR_PRINT(L"Fail (%llu ms)\n", HdrElapsedMs);
								}
								else {
									(*hdr_found)++;
									OUT_PRINT(L"%VSuccess%N (%llu ms)\n", HdrElapsedMs);
								}
							}
						}
						file->Close(file);
					}
				}

				MEM_FREE(DirInfo);

				dir->Close(dir);
			}
			root->Close(root);
		}
	}

	// clear data
	if (header) {
		MEM_BURN(header, header_size);
		MEM_FREE(header);
		MEM_BURN(hdr_key, sizeof(hdr_key));
	}
}

EFI_STATUS
MountDisks(
	IN EFI_HANDLE ImageHandle,
	IN EFI_SYSTEM_TABLE *SystemTable)
{
	EFI_STATUS ret = EFI_SUCCESS;
	UINTN i;
	UINTN mountedCount = 0;
	UINTN blockedCount = 0;

	// If no volumes were decrypted and we're not blocking unencrypted volumes, nothing to do
	if (iodb.n_mount == 0 && !gBlockUnencryptedVolumes) {
		return ret;
	}

	// Single pass over all partitions - install appropriate hooks
	for (i = 0; i < gBIOCount; ++i) {
		EFI_DEVICE_PATH *partPath;
		mount_inf *mount;
		HARDDRIVE_DEVICE_PATH partInfo;
		EFI_HANDLE disk;
		int diskNum = 0;

		// Only process partitions, not whole disks
		if (!EfiIsPartition(gBIOHandles[i])) {
			continue;
		}

		partPath = DevicePathFromHandle(gBIOHandles[i]);
		if (partPath == NULL) {
			continue;
		}

		// Get partition info for debug output
		if (gConfigDebug) {
			if (!EFI_ERROR(EfiGetPartDetails(gBIOHandles[i], &partInfo, &disk))) {
				diskNum = GetDiskNumber(disk);
			}
		}

		// Check if this partition was decrypted
		mount = GetPartitionMount(partPath);
		if (mount != NULL) {
			// Decrypted partition - install crypto hook
			if (gConfigDebug) {
				OUT_PRINT(L"Hooking volume %d:%d (decrypted)\n", diskNum, partInfo.PartitionNumber);
			}
			ret = AddCryptoMount(partPath, DCVolumeIO_Read, DCVolumeIO_Write, mount);
			if (EFI_ERROR(ret)) {
				ERR_PRINT(L"Failed to hook volume %d:%d: %r\n", diskNum, partInfo.PartitionNumber, ret);
			} else {
				mountedCount++;
			}
		}
		else if (gBlockUnencryptedVolumes) {
			// Unencrypted partition - block it (except boot ESP)
			if (IsBootEsp(gBIOHandles[i])) {
				if (gConfigDebug) {
					OUT_PRINT(L"Skipping boot ESP (volume %d:%d)\n", diskNum, partInfo.PartitionNumber);
				}
				continue;
			}

			if (gConfigDebug) {
				OUT_PRINT(L"Blocking volume %d:%d\n", diskNum, partInfo.PartitionNumber);
			}
			ret = AddCryptoMount(partPath, DCVolumeIO_Read, DCVolumeIO_Write, NULL);
			if (EFI_ERROR(ret)) {
				ERR_PRINT(L"Failed to block volume %d:%d: %r\n", diskNum, partInfo.PartitionNumber, ret);
			} else {
				blockedCount++;
			}
		}
	}

	if (gConfigDebug) {
		if (mountedCount > 0) {
			OUT_PRINT(L"Hooked %d decrypted volume(s)\n", mountedCount);
		}
		if (blockedCount > 0) {
			OUT_PRINT(L"Blocked %d unencrypted volume(s)\n", blockedCount);
		}
	}

	return ret;
}

// Name of the dedicated DCS boot partition
#define DCS_BOOT_PARTITION_NAME  L"DCS Boot Partition"

// Check if a GPT partition name matches "DCS Boot"
static BOOLEAN
IsDcsBootPartition(
	IN EFI_PARTITION_ENTRY *Entry
	)
{
	if (Entry == NULL) return FALSE;
	return (StrnCmp(Entry->PartitionName, DCS_BOOT_PARTITION_NAME, sizeof(Entry->PartitionName) / sizeof(CHAR16)) == 0);
}

// Check if a GPT partition entry is an ESP (EFI System Partition)
static BOOLEAN
IsEspPartitionEntry(
	IN EFI_PARTITION_ENTRY *Entry
)
{
	if (Entry == NULL) return FALSE;
	return CompareGuid(&Entry->PartitionTypeGUID, &gEfiPartTypeSystemPartGuid);
}

// Find ESP on the boot disk (LDR_BT_MBR_BOOT mode)
// If booted from shared Windows ESP -> return that ESP's GUID
// If booted from dedicated "DCS Boot" partition -> find Windows ESP on same disk
static EFI_STATUS
FindBootEspOnBootDisk(
	OUT EFI_GUID *EspGuid
	)
{
	EFI_STATUS res;
	EFI_HANDLE diskHandle;
	HARDDRIVE_DEVICE_PATH partInfo;
	EFI_BLOCK_IO_PROTOCOL *bio;
	EFI_PARTITION_TABLE_HEADER *gptHdr = NULL;
	EFI_PARTITION_ENTRY *gptEntry = NULL;
	EFI_PARTITION_ENTRY *bootEspEntry = NULL;
	EFI_GUID bootEspGuid;

	if (EspGuid == NULL) return EFI_INVALID_PARAMETER;

	if (gFileRootHandle == NULL) {
		return EFI_NOT_FOUND;
	}

	// Get the boot ESP's GUID and disk handle
	res = EfiGetPartGUID(gFileRootHandle, &bootEspGuid);
	if (EFI_ERROR(res)) {
		if (gConfigDebug) {
			ERR_PRINT(L"Cannot get boot ESP GUID: %r\n", res);
		}
		return res;
	}

	res = EfiGetPartDetails(gFileRootHandle, &partInfo, &diskHandle);
	if (EFI_ERROR(res)) {
		if (gConfigDebug) {
			ERR_PRINT(L"Cannot get boot disk: %r\n", res);
		}
		return res;
	}

	// Read GPT to check if boot ESP is named "DCS Boot"
	bio = EfiGetBlockIO(diskHandle);
	if (bio == NULL) {
		return EFI_NOT_FOUND;
	}

	res = GptReadHeader(bio, 1, &gptHdr);
	if (EFI_ERROR(res)) return res;

	res = GptReadEntryArray(bio, gptHdr, &gptEntry);
	if (EFI_ERROR(res)) {
		MEM_FREE(gptHdr);
		return res;
	}

	// Find the boot ESP entry in GPT
	for (UINT32 i = 0; i < gptHdr->NumberOfPartitionEntries; i++) {
		if (CompareGuid(&gptEntry[i].UniquePartitionGUID, &bootEspGuid)) {
			bootEspEntry = &gptEntry[i];
			break;
		}
	}

	if (bootEspEntry != NULL && IsDcsBootPartition(bootEspEntry)) {
		// Variant b: DCS booted from dedicated "DCS Boot" partition
		// Find the Windows ESP (non-DCS ESP) on the same disk
		res = EFI_NOT_FOUND;
		for (UINT32 i = 0; i < gptHdr->NumberOfPartitionEntries; i++) {
			if (IsEspPartitionEntry(&gptEntry[i]) && !IsDcsBootPartition(&gptEntry[i])) {
				CopyGuid(EspGuid, &gptEntry[i].UniquePartitionGUID);
				res = EFI_SUCCESS;
				break;
			}
		}
	} else {
		// Variant a: DCS booted from the shared Windows ESP
		CopyGuid(EspGuid, &bootEspGuid);
		res = EFI_SUCCESS;
	}

	MEM_FREE(gptEntry);
	MEM_FREE(gptHdr);
	return res;
}

// Find ESP on the first disk with a non-DCS ESP (LDR_BT_MBR_FIRST mode)
static EFI_STATUS
FindBootEspOnFirstDisk(
	OUT EFI_GUID *EspGuid
	)
{
	EFI_STATUS res = EFI_NOT_FOUND;
	EFI_BLOCK_IO_PROTOCOL *bio;
	EFI_PARTITION_TABLE_HEADER *gptHdr = NULL;
	EFI_PARTITION_ENTRY *gptEntry = NULL;

	if (EspGuid == NULL) return EFI_INVALID_PARAMETER;

	for (UINTN i = 0; i < gBIOCount; i++) {
		if (EfiIsPartition(gBIOHandles[i])) continue;

		bio = EfiGetBlockIO(gBIOHandles[i]);
		if (bio == NULL) continue;

		res = GptReadHeader(bio, 1, &gptHdr);
		if (EFI_ERROR(res)) continue;

		res = GptReadEntryArray(bio, gptHdr, &gptEntry);
		if (EFI_ERROR(res)) {
			MEM_FREE(gptHdr);
			continue;
		}

		res = EFI_NOT_FOUND;
		for (UINT32 j = 0; j < gptHdr->NumberOfPartitionEntries; j++) {
			if (IsEspPartitionEntry(&gptEntry[j]) && !IsDcsBootPartition(&gptEntry[j])) {
				CopyGuid(EspGuid, &gptEntry[j].UniquePartitionGUID);
				res = EFI_SUCCESS;
				break;
			}
		}

		MEM_FREE(gptEntry);
		MEM_FREE(gptHdr);
		
		if (!EFI_ERROR(res)) break;
	}
	return res;
}

// Find ESP on disk containing an encrypted partition
// Used for LDR_BT_AP_PASSWORD and LDR_BT_DISK_ID modes
// If diskId is non-zero, only search for partitions with that disk_id
// Variant a: encrypted ESP -> return its GUID
// Variant b: unencrypted ESP + encrypted data -> return the ESP's GUID
static EFI_STATUS
FindBootEspForPasswordMode(
	IN UINT32 diskId,
	OUT EFI_GUID *EspGuid
)
{
	EFI_STATUS res;
	EFI_BLOCK_IO_PROTOCOL *bio;
	EFI_PARTITION_TABLE_HEADER *gptHdr = NULL;
	EFI_PARTITION_ENTRY *gptEntry = NULL;
	BOOLEAN hasDecryptedPartition;
	BOOLEAN hasMatchingDiskId;
	EFI_GUID candidateEspGuid;
	BOOLEAN hasCandidate;

	if (EspGuid == NULL) return EFI_INVALID_PARAMETER;

	// Check each disk for encrypted partitions
	for (UINTN i = 0; i < gBIOCount; i++) {
		if (EfiIsPartition(gBIOHandles[i])) continue;

		bio = EfiGetBlockIO(gBIOHandles[i]);
		if (bio == NULL) continue;

		res = GptReadHeader(bio, 1, &gptHdr);
		if (EFI_ERROR(res)) continue;

		res = GptReadEntryArray(bio, gptHdr, &gptEntry);
		if (EFI_ERROR(res)) {
			MEM_FREE(gptHdr);
			continue;
		}

		hasDecryptedPartition = FALSE;
		hasMatchingDiskId = FALSE;
		hasCandidate = FALSE;
		ZeroMem(&candidateEspGuid, sizeof(EFI_GUID));

		// First pass: look for ESP partitions and check encryption status
		for (UINT32 j = 0; j < gptHdr->NumberOfPartitionEntries; j++) {
			EFI_PARTITION_ENTRY *entry = &gptEntry[j];
			EFI_HANDLE partHandle;
			mount_inf *mount;

			// Skip unused entries
			if (CompareGuid(&entry->PartitionTypeGUID, &gEfiPartTypeUnusedGuid)) continue;

			// Find partition handle by GUID
			if (EFI_ERROR(EfiFindPartByGUID(&entry->UniquePartitionGUID, &partHandle))) continue;

			EFI_DEVICE_PATH *partPath = DevicePathFromHandle(partHandle);
			mount = GetPartitionMount(partPath);

			// If filtering by disk_id, check if this partition matches
			if (diskId != 0 && mount != NULL && mount->disk_id == diskId) {
				hasMatchingDiskId = TRUE;
			}

			if (IsEspPartitionEntry(entry)) {
				// Variant a: encrypted ESP - return immediately if disk_id matches or not filtering
				if (mount != NULL) {
					if (diskId == 0 || mount->disk_id == diskId) {
						CopyGuid(EspGuid, &entry->UniquePartitionGUID);
						MEM_FREE(gptEntry);
						MEM_FREE(gptHdr);
						return EFI_SUCCESS;
					}
				}
				// Remember this ESP as candidate for variant b
				if (!IsDcsBootPartition(entry)) {
					hasCandidate = TRUE;
					CopyGuid(&candidateEspGuid, &entry->UniquePartitionGUID);
				}
			} else if (mount != NULL) {
				hasDecryptedPartition = TRUE;
			}
		}

		MEM_FREE(gptEntry);
		MEM_FREE(gptHdr);

		// Variant b: unencrypted ESP + encrypted data partition on same disk
		// If filtering by disk_id, only return if the disk has a matching partition
		if (hasDecryptedPartition && hasCandidate) {
			if (diskId == 0 || hasMatchingDiskId) {
				CopyGuid(EspGuid, &candidateEspGuid);
				return EFI_SUCCESS;
			}
		}
	}

	return EFI_NOT_FOUND;
}

EFI_STATUS
SelectBootPartition()
{
	EFI_STATUS ret;
	EFI_GUID guid;

	// Check if specific partition is configured (explicit config overrides boot mode)
	if (gDCryptBootPartition != NULL && gDCryptBootPartition[0] != '\0') {
		DcsAsciiStrToGuid(&guid, gDCryptBootPartition);
		EFI_HANDLE h;
		ret = EfiFindPartByGUID(&guid, &h);
		if (!EFI_ERROR(ret)) {
			if (gConfigDebug) {
				OUT_PRINT(L"Boot partition (configured): %g\n", &guid);
			}
			EfiSetVar(L"DcsExecPartGuid", NULL, &guid, sizeof(EFI_GUID), EFI_VARIABLE_BOOTSERVICE_ACCESS);
			return EFI_SUCCESS;
		}
	}

	switch (gDCryptBootMode) {
	case LDR_BT_MBR_BOOT:	ret = FindBootEspOnBootDisk(&guid); break;
	case LDR_BT_MBR_FIRST:	ret = FindBootEspOnFirstDisk(&guid); break;
	case LDR_BT_AP_PASSWORD:ret = FindBootEspForPasswordMode(0, &guid); break;
	case LDR_BT_DISK_ID:	ret = FindBootEspForPasswordMode(gDCryptBootDiskID, &guid); break;
	default:
		ERR_PRINT(L"Unsupported boot mode: %d\n", gDCryptBootMode);
		ret = EFI_UNSUPPORTED;
		break;
	}

	if (EFI_ERROR(ret)) {
		ERR_PRINT(L"Failed to select boot partition: %r\n", ret);
		return ret;
	}

	if (gConfigDebug) {
		OUT_PRINT(L"Selected boot partition: %g\n", &guid);
	}

	EfiSetVar(L"DcsExecPartGuid", NULL, &guid, sizeof(EFI_GUID), EFI_VARIABLE_BOOTSERVICE_ACCESS);
	return EFI_SUCCESS;
}


//////////////////////////////////////////////////////////////////////////
// DiskCryptor Entry Point
//////////////////////////////////////////////////////////////////////////
EFI_STATUS
DcsDiskCryptor(
	IN EFI_HANDLE ImageHandle,
	IN EFI_SYSTEM_TABLE *SystemTable)
{
	EFI_STATUS ret = EFI_SUCCESS;
	int vol_found = 0;
	int hdr_found = 0;

	if (gConfigDebug) {
		OUT_PRINT(L"DiskCryptor UEFI bootloader version: %d.%02d\n", ver.ldr_ver / 100, ver.ldr_ver % 100);
	}

	// Load Certificate from Loader or directly from disk
	if (DcsLdrGetCertState(&gVerifyCertInfo.State) == EFI_NOT_READY) {
		VerifyInit();
	}

	// setup clear data inplementation callabck
	SetCleanSensitiveDataFunc(CleanSensitiveDataDC);

	// Load auth parameters
	DCAuthLoadConfig();

	if (!EFI_ERROR(InitDcsTpm()) && gDcsTpm != NULL) {

		DCS_TPM_INFO tpmInfo;
		if (!EFI_ERROR(gDcsTpm->GetInfo(gDcsTpm, &tpmInfo))) {
			gDCryptTpmVersion = tpmInfo.TpmVersion;
			if (gDCryptTpmVersion < 0x200) {
				gDCryptTpmAskOwnerPw = 1;  // TPM 1.2 always needs owner password
			}
		}

		// Measure config to TPM PCR 8 (DcsProp protection)
		// This ensures that if the config file is tampered with, PCR 8 changes
		// and the sealed password cannot be retrieved
		gDcsTpm->UpdatePcr8(gDcsTpm, gConfigBufferSize, gConfigBuffer);
	}

	// init structs
	zeroauto(&iodb, sizeof(iodb));

	// init crypto
	gDCryptHwCrypto = xts_init(gDCryptHwCrypto);
	if (gConfigDebug && gDCryptHwCrypto != 0) {
		ERR_PRINT(L"Using Hardware Crypt, Type %d\n", gDCryptHwCrypto);
	}

	// Verify block I/O handles are available (initialized by InitBio)
	if (gBIOCount == 0) {
		ERR_PRINT(L"No block I/O devices found\n");
		return EFI_NOT_FOUND;
	}

	if (gConfigDebug) {
		UINTN diskCount = 0, partCount = 0;
		for (UINTN i = 0; i < gBIOCount; i++) {
			if (EfiIsPartition(gBIOHandles[i]))
				partCount++;
			else
				diskCount++;
		}
		OUT_PRINT(L"DEBUG: found %d disks and %d partitions\n", diskCount, partCount);
	}

	// prepare memory for boot data
	ret = PrepareBootDataBlock(TRUE);
	if (EFI_ERROR(ret)) {
		ret = PrepareBootDataBlock(FALSE);
	}
	if (EFI_ERROR(ret)) {
		ERR_PRINT(L"Failed to allocate required memory range for boot params: %r\n", ret);
		return ret;
	}

	// prompt for password and try decrypt partitions
	ret = DcMain(&vol_found, &hdr_found);
	// Reset Console buffer
	gST->ConIn->Reset(gST->ConIn, FALSE);

	// Lock TPM to prevent OS from reading the secret
	if (gDcsTpm && gDCryptTpmVersion > 0) {
		EFI_STATUS ret2;
		UINT32  lock = 1;
		ret2 = gDcsTpm->UpdatePcr8(gDcsTpm, sizeof(lock), &lock);
		if (EFI_ERROR(ret2)) {
			ERR_PRINT(L"Warning: Could not lock TPM, error: %r\n", ret2);
		}
	}

	if (EFI_ERROR(ret)) {
		return ret; // returning error will trigger clearence of sensitive data
	}

	if (hdr_found > 0)
		gDCryptFlags |= BDB_BF_HDR_FOUND;

	// set boot data values
	ret = SetBootDataBlock();
	if (EFI_ERROR(ret)) {
		ERR_PRINT(L"Cannot set boot params for driver: %r\n", ret);
		return ret;
	}

	// after setting up the BDB we dont need the passwords anymore
	MEM_BURN(&gDCryptPassword, sizeof(gDCryptPassword));
	MEM_BURN(gDCryptPassCache, sizeof(gDCryptPassCache));

	if (gConfigDebug) {
		OUT_PRINT(L"Volumes Mounted: %d, Headers Approved: %d\n", vol_found, hdr_found);
	}

	if (vol_found == 0 && hdr_found > 0)
		return EFI_SUCCESS;

	// Install hooks
	ret = MountDisks(ImageHandle, SystemTable);
	if (EFI_ERROR(ret)) {
		ERR_PRINT(L"MountDisks %r\n", ret);
		return ret;
	}

	if (gDCryptBootMode == 6) { // boot menu
		return EFI_DCS_INPUT_REQUIRED; 
	}

	// Select boot partition
	ret = SelectBootPartition();
	if (EFI_ERROR(ret)) {
		ERR_PRINT(L"SelectBootPartition failed %r\n", ret);
		return ret;
	}

	return EFI_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
// USB Key File Support
//////////////////////////////////////////////////////////////////////////

#define USB_KEYFILE_NAME L"\\KeyFile.bin"
#define USB_KEYFILE_MAX_ENTRIES 16

// Structure to hold USB key file information for picker
typedef struct {
	EFI_HANDLE  Handle;           // File system handle
	CHAR16      VolumeLabel[64];  // USB volume label for display
} USB_KEYFILE_ENTRY;

// Get volume label from a file system handle
STATIC EFI_STATUS
GetVolumeLabel(
	IN  EFI_HANDLE Handle,
	OUT CHAR16     *Label,
	IN  UINTN      LabelSize
)
{
	EFI_STATUS ret;
	EFI_FILE *root = NULL;
	UINT8 buffer[sizeof(EFI_FILE_SYSTEM_INFO) + 256];
	UINTN bufSize = sizeof(buffer);
	EFI_FILE_SYSTEM_INFO *fsInfo = (EFI_FILE_SYSTEM_INFO *)buffer;

	if (Label == NULL || LabelSize < 2) {
		return EFI_INVALID_PARAMETER;
	}

	ret = FileOpenRoot(Handle, &root);
	if (EFI_ERROR(ret) || root == NULL) {
		StrCpyS(Label, LabelSize / sizeof(CHAR16), L"USB Drive");
		return EFI_SUCCESS;
	}

	ret = root->GetInfo(root, &gEfiFileSystemInfoGuid, &bufSize, fsInfo);
	FileClose(root);

	if (EFI_ERROR(ret) || fsInfo->VolumeLabel[0] == L'\0') {
		StrCpyS(Label, LabelSize / sizeof(CHAR16), L"USB Drive");
	} else {
		StrCpyS(Label, LabelSize / sizeof(CHAR16), fsInfo->VolumeLabel);
	}

	return EFI_SUCCESS;
}

// Find all USB drives containing KeyFile.bin at root
STATIC EFI_STATUS
FindUsbKeyFiles(
	OUT USB_KEYFILE_ENTRY **Entries,
	OUT UINTN             *Count
)
{
	EFI_STATUS ret;
	UINTN i, count = 0;
	USB_KEYFILE_ENTRY *list;
	EFI_BLOCK_IO_PROTOCOL *bio;
	EFI_FILE *root = NULL;
	EFI_FILE *keyFile = NULL;
	EFI_HANDLE *fsHandles = NULL;
	UINTN fsCount = 0;

	if (Entries == NULL || Count == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	*Entries = NULL;
	*Count = 0;

	// Re-enumerate file system handles to detect USB drives plugged in after boot
	ret = EfiGetHandles(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, 0, &fsHandles, &fsCount);
	if (EFI_ERROR(ret) || fsCount == 0) {
		return EFI_NOT_FOUND;
	}

	// Allocate temporary list
	list = MEM_ALLOC(USB_KEYFILE_MAX_ENTRIES * sizeof(USB_KEYFILE_ENTRY));
	if (list == NULL) {
		MEM_FREE(fsHandles);
		return EFI_OUT_OF_RESOURCES;
	}

	// Iterate over all file system handles
	for (i = 0; i < fsCount && count < USB_KEYFILE_MAX_ENTRIES; i++) {
		// Get block I/O to check if removable media
		bio = EfiGetBlockIO(fsHandles[i]);
		if (bio == NULL) continue;
		if (!bio->Media->RemovableMedia) continue;

		// Try to open root
		if (EFI_ERROR(FileOpenRoot(fsHandles[i], &root)) || root == NULL) continue;

		// Try to open KeyFile.bin
		if (!EFI_ERROR(root->Open(root, &keyFile, USB_KEYFILE_NAME, EFI_FILE_MODE_READ, 0))) {
			// Found a key file - add to list
			list[count].Handle = fsHandles[i];
			GetVolumeLabel(fsHandles[i], list[count].VolumeLabel, sizeof(list[count].VolumeLabel));
			count++;
			FileClose(keyFile);
		}
		FileClose(root);
	}

	MEM_FREE(fsHandles);

	if (count == 0) {
		MEM_FREE(list);
		return EFI_NOT_FOUND;
	}

	*Entries = list;
	*Count = count;
	return EFI_SUCCESS;
}

// Display picker dialog for multiple USB key files
STATIC EFI_STATUS
SelectUsbKeyFile(
	IN  USB_KEYFILE_ENTRY *Entries,
	IN  UINTN             Count,
	OUT UINTN             *SelectedIndex
)
{
	EFI_INPUT_KEY key;
	INTN selected = 0;
	UINTN i;

	if (Entries == NULL || Count == 0 || SelectedIndex == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	for (;;) {
		// Clear screen and draw header
		gST->ConOut->ClearScreen(gST->ConOut);
		OUT_PRINT(L"=== Select USB Key File ===\n\n");
		OUT_PRINT(L"Multiple USB drives with KeyFile.bin found.\n");
		OUT_PRINT(L"Please select which one to use:\n\n");

		// Draw entries
		for (i = 0; i < Count; i++) {
			if ((INTN)i == selected) {
				OUT_PRINT(L"%H> %s%N\n", Entries[i].VolumeLabel);
			} else {
				OUT_PRINT(L"  %s\n", Entries[i].VolumeLabel);
			}
		}

		// Draw navigation hints
		OUT_PRINT(L"\n[Up/Down] Navigate  [Enter] Select  [Esc] Cancel\n");

		// Get input
		key = GetKey();
		FlushInputDelay(50000);

		if (key.ScanCode == SCAN_ESC) {
			return EFI_ABORTED;
		}

		if (key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
			*SelectedIndex = (UINTN)selected;
			return EFI_SUCCESS;
		}

		if (key.ScanCode == SCAN_UP) {
			if (selected > 0) {
				selected--;
			}
		}

		if (key.ScanCode == SCAN_DOWN) {
			if ((UINTN)selected < Count - 1) {
				selected++;
			}
		}
	}
}

// Load key file from USB drive(s), showing picker if multiple found
STATIC EFI_STATUS
LoadUsbKeyFile(
	OUT UINT8  **FileData,
	OUT UINTN  *FileSize
)
{
	EFI_STATUS ret;
	USB_KEYFILE_ENTRY *entries = NULL;
	UINTN count = 0;
	UINTN selectedIndex = 0;
	EFI_FILE *root = NULL;

	if (FileData == NULL || FileSize == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	*FileData = NULL;
	*FileSize = 0;

	// Find all USB drives with KeyFile.bin
	ret = FindUsbKeyFiles(&entries, &count);
	if (EFI_ERROR(ret)) {
		ERR_PRINT(L"No USB drive with KeyFile.bin found\n");
		return ret;
	}

	// If multiple found, show picker
	if (count > 1) {
		ret = SelectUsbKeyFile(entries, count, &selectedIndex);
		if (EFI_ERROR(ret)) {
			MEM_FREE(entries);
			return ret;
		}
		// Clear screen after picker
		gST->ConOut->ClearScreen(gST->ConOut);
	}

	// Open root of selected drive
	ret = FileOpenRoot(entries[selectedIndex].Handle, &root);
	if (EFI_ERROR(ret)) {
		ERR_PRINT(L"Failed to open USB drive: %r\n", ret);
		MEM_FREE(entries);
		return ret;
	}

	// Load the key file
	ret = FileLoad(root, USB_KEYFILE_NAME, (VOID **)FileData, FileSize);
	FileClose(root);

	if (EFI_ERROR(ret)) {
		ERR_PRINT(L"Failed to load KeyFile.bin from USB: %r\n", ret);
	} else if (gConfigDebug) {
		OUT_PRINT(L"DEBUG: Loaded KeyFile.bin from USB: %s, size: %d\n",
			entries[selectedIndex].VolumeLabel, *FileSize);
	}

	MEM_FREE(entries);
	return ret;
}

// Load key file using file picker - allows browsing USB drives and selecting any file
STATIC EFI_STATUS
LoadFilePickerKeyFile(
	OUT UINT8  **FileData,
	OUT UINTN  *FileSize
)
{
	EFI_STATUS ret;
	EFI_HANDLE *fsHandles = NULL;
	UINTN fsCount = 0;
	FILE_PICKER_VOLUME *usbVolumes = NULL;
	UINTN usbCount = 0;
	UINTN i;
	EFI_BLOCK_IO_PROTOCOL *bio;
	FILE_PICKER_CONFIG config;
	EFI_HANDLE selectedHandle = NULL;
	CHAR16 *selectedPath = NULL;
	EFI_FILE *root = NULL;

	if (FileData == NULL || FileSize == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	*FileData = NULL;
	*FileSize = 0;

	// Re-enumerate file system handles to detect USB drives plugged in after boot
	ret = EfiGetHandles(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, 0, &fsHandles, &fsCount);
	if (EFI_ERROR(ret) || fsCount == 0) {
		ERR_PRINT(L"No file systems found\n");
		return EFI_NOT_FOUND;
	}

	// Allocate array for USB volumes (worst case: all are USB)
	usbVolumes = MEM_ALLOC(fsCount * sizeof(FILE_PICKER_VOLUME));
	if (usbVolumes == NULL) {
		MEM_FREE(fsHandles);
		return EFI_OUT_OF_RESOURCES;
	}

	// Find all USB (removable) drives and get their volume labels
	for (i = 0; i < fsCount; i++) {
		// Get block I/O to check if removable media
		bio = EfiGetBlockIO(fsHandles[i]);
		if (bio == NULL) continue;
		if (!bio->Media->RemovableMedia) continue;

		// Add to USB volume list
		usbVolumes[usbCount].Handle = fsHandles[i];

		// Allocate and get volume label
		usbVolumes[usbCount].DisplayName = MEM_ALLOC(128 * sizeof(CHAR16));
		if (usbVolumes[usbCount].DisplayName != NULL) {
			GetVolumeLabel(fsHandles[i], usbVolumes[usbCount].DisplayName, 128 * sizeof(CHAR16));
		}
		usbCount++;
	}

	MEM_FREE(fsHandles);

	if (usbCount == 0) {
		MEM_FREE(usbVolumes);
		ERR_PRINT(L"No USB drives found\n");
		return EFI_NOT_FOUND;
	}

	// Configure file picker for USB drives with any file type
	FilePickerInitConfig(&config);
	config.Volumes = usbVolumes;
	config.VolumeCount = usbCount;
	config.Extensions = NULL;  // Show all files
	config.Title = L"Select Key File";

	// Show file picker
	ret = FilePickerShow(&config, &selectedHandle, &selectedPath);

	// Free volume labels
	for (i = 0; i < usbCount; i++) {
		if (usbVolumes[i].DisplayName != NULL) {
			MEM_FREE(usbVolumes[i].DisplayName);
		}
	}
	MEM_FREE(usbVolumes);

	if (EFI_ERROR(ret)) {
		if (ret == EFI_DCS_USER_CANCELED) {
			gST->ConOut->ClearScreen(gST->ConOut);
		}
		return ret;
	}

	// Clear screen after picker
	gST->ConOut->ClearScreen(gST->ConOut);

	// Load the selected file
	ret = FileOpenRoot(selectedHandle, &root);
	if (EFI_ERROR(ret)) {
		ERR_PRINT(L"Failed to open USB drive: %r\n", ret);
		MEM_FREE(selectedPath);
		return ret;
	}

	ret = FileLoad(root, selectedPath, (VOID **)FileData, FileSize);
	FileClose(root);

	if (EFI_ERROR(ret)) {
		ERR_PRINT(L"Failed to load key file: %r\n", ret);
	} else if (gConfigDebug) {
		OUT_PRINT(L"DEBUG: Loaded key file: %s, size: %d\n", selectedPath, *FileSize);
	}

	MEM_FREE(selectedPath);
	return ret;
}

//////////////////////////////////////////////////////////////////////////
// UI section
//////////////////////////////////////////////////////////////////////////

char* gDCryptPasswordMsg = NULL;
char* gDCryptStartMsg = NULL;
char* gDCryptSuccessMsg = NULL;
char* gDCryptErrorMsg = NULL;

VOID DCAuthLoadConfig()
{
	// Main:
		// Keyboard Layout
			// QWERTY	0
			// QWERTZ	1
			// AZERTY	2
	gKeyboardLayout = ConfigReadInt("KeyboardLayout", 0);

	gDCryptHeaderKdf = ConfigReadInt("HeaderKDF", KDF_DEFAULT);

	// Booting Method
		// Boot disk    								// LDR_BT_MBR_BOOT     1 // default
		// First disk    								// LDR_BT_MBR_FIRST    2
		// First partition with appropriate password	// LDR_BT_AP_PASSWORD  4
		// Specified partition							// LDR_BT_DISK_ID      5
		// Active partition 							// LDR_BT_ACTIVE       3 // not supported in EFI mode
	gDCryptBootMode = (UINT8)ConfigReadInt("BootMode", 1);
	if (gDCryptBootMode == LDR_BT_ACTIVE || (gDCryptBootMode == LDR_BT_MBR_BOOT && (gExternMode || IsPxeBoot()))) {
		gDCryptBootMode = LDR_BT_AP_PASSWORD;
	}
	gDCryptBootDiskID = (unsigned int)ConfigReadInt64("BootDiskID", 0);
	gDCryptBootPartition = ConfigReadString("BootPartition", "", NULL, 36 + 1);	// new
	gBlockUnencryptedVolumes = (UINT8)ConfigReadInt("BlockUnencryptedVolumes", 0);

	gDCryptHandoffMode = (UINT8)ConfigReadInt("HandoffMode", 0);
#ifdef _M_ARM64 // ARM64 requires at least mode 2 for proper handoff to OS loader, otherwise it may cause boot failures on some devices (e.g. Surface Pro X)
	if (gDCryptHandoffMode < 2) {
#else
	if (gDCryptHandoffMode == 0) {
#endif
		gDCryptHandoffMode = 2;
	}

// Authentication:
	gDCryptAutoLogin = (UINT8)ConfigReadInt("AutoLogin", 0); // set 1 and keep AutoPassword empty for key file only
	gDCryptAutoLoginDelay = (UINT8)ConfigReadInt("AutoLoginDelay", 3);
	gDCryptAutoPassword = ConfigReadStringW("AutoPassword", L"", NULL, MAX_PASSWORD + 1);
	gDCryptUseKeyFile = (UINT8)ConfigReadInt("UseKeyFile", DCryptNo);
	gDCryptKeyFilePath = ConfigReadStringW("KeyFilePath", L"", NULL, MAX_MSG);
	gDCryptKfMixer = ConfigReadInt("KeyfileMixer", KEYFILE_MIX_HASHED);

	// Hardware Key Support
	gDCryptUseHardwareKey = (UINT8)ConfigReadInt("UseHardwareKey", DCryptTPM);
	gDCryptTpmAskOwnerPw = (UINT8)ConfigReadInt("TpmAskOwnerPw", 0);
	gDCryptTpmMode = ConfigReadInt("TpmMode", DCryptTpmAuto);
	gDCryptTpmPcrMask = ConfigReadInt("TpmPcrMask", DCS_TPM_DEFAULT_PCR_MASK);
	gDCryptTpmStorage = ConfigReadInt("TpmStorage", DCryptTpmDefault);

	// Picture Password - new
	gDCryptTouchInput = ConfigReadInt("TouchInput", 0);
	//gPasswordPictureFileName = ConfigReadStringW("PasswordPicture", L"\\EFI\\" DCS_DIRECTORY L"\\login.bmp", NULL, MAX_MSG); // h1630 v1090
	//gPasswordPictureChars = ConfigReadString("PictureChars", gPasswordPictureCharsDefault, NULL, MAX_MSG);
	//gPasswordPictureCharsLen = AsciiStrnLenS(gPasswordPictureChars, MAX_MSG);
	gPasswordVisible = (UINT8)ConfigReadInt("AuthorizeVisible", 0);   // show chars
	//gPasswordHideLetters = ConfigReadInt("PasswordHideLetters", 0);   // always show letters in touch points
	//gPasswordShowMark = ConfigReadInt("AuthorizeMarkTouch", 0);       // show touch points

	// Password Prompt Message
	gDCryptPasswordMsg = ConfigReadString("PasswordMsg", "Enter password:", NULL, MAX_MSG);

	// Display Entered Password * or hide completely
	gPasswordProgress = (UINT8)ConfigReadInt("AuthorizeProgress", 1); // print "*"

	// Authentication TimeOut
	gPasswordTimeout = (UINT8)ConfigReadInt("PasswordTimeout", 180);   // If no password for <seconds> => <ESC>
	// cancel timeout when any key pressed [ ] - DCS always behaves this way

	// Trying password message - new
	gDCryptStartMsg = MEM_ALLOC(MAX_MSG); 
	ConfigReadString("AuthStartMsg", "Authorizing... ", gDCryptStartMsg, MAX_MSG);

	// Success message - new
	gDCryptSuccessMsg = MEM_ALLOC(MAX_MSG); 
	ConfigReadString("AuthSuccessMsg", "Password correct", gDCryptSuccessMsg, MAX_MSG);

// Invalid Password:
	// use incorrect action if no password entered [ ]
	gDCryptFailOnTimeout = (UINT8)ConfigReadInt("FailOnTimeout", 0);

	// Invalid Password message
	gDCryptErrorMsg = MEM_ALLOC(MAX_MSG); 
	ConfigReadString("AuthFailedMsg", "Password incorrect", gDCryptErrorMsg, MAX_MSG);

	// Invalid Password action			ConfigReadString("ActionFailed", ...
		// Halt system					"halt"      EFI_DCS_HALT_REQUESTED
		// Reboot system				"reboot"    EFI_DCS_REBOOT_REQUESTED
		// Boot from active partition	"cancel"	EFI_DCS_USER_CANCELED
		// Exit to BIOS
		// Retry authentication			"exit"  &&  gDCryptAuthRetry > 0; else gDCryptAuthRetry == 0;
		// Load Boot Disk MBR			"cancel"	EFI_DCS_USER_CANCELED
		//								"shutdown"  EFI_DCS_SHUTDOWN_REQUESTED

	// Authentication Tries - new
	gDCryptAuthRetry = ConfigReadInt("AuthorizeRetry", 0);

// Other

	gDCryptHwCrypto = ConfigReadInt("UseHardwareCrypto", 1);
}

EFI_STATUS
DCFinalizePassword(dc_pass* pass, CHAR16* password, UINT32 password_size, int key_file, int hw_key, UINT8* aux_data, UINT32 aux_size)
{
	EFI_STATUS ret = EFI_SUCCESS;
	UINT8 *keyfile_data = NULL;
	UINTN  keyfile_size = 0;

	if (gConfigDebug) {
		OUT_PRINT(L"DEBUG: Finallizing password, size: %d, key file: %d, hw key: %d\n", password_size, key_file, hw_key);
	}

	if (password_size > MAX_PASSWORD * sizeof(CHAR16)) {
		return EFI_INVALID_PARAMETER;
	}

	if (hw_key == DCryptTPM && !gDCryptTpmSecretValid) {
		ERR_PRINT(L"TPM secret is not valid\n");
		return EFI_ACCESS_DENIED;
	}

	if (key_file == DCryptEmbedded) {
		if(!gDCryptKeyFilePath || !*gDCryptKeyFilePath) {
			ERR_PRINT(L"Embedded key file path is not configured\n");
			ret = EFI_NOT_FOUND;
		}
		else if (IsPxeBoot()) {
			ret = PxeDownloadFile(gDCryptKeyFilePath, &keyfile_data, &keyfile_size);
		} else {
			ret = FileLoad(NULL, gDCryptKeyFilePath, &keyfile_data, &keyfile_size);
		}
	}
	else if (key_file == DCryptPlatform) {
		if (gPlatformKeyFileSize == 0) {
			ERR_PRINT(L"Platform key file is not available\n");
			ret = EFI_NOT_FOUND;
		}
		else {
			keyfile_data = (UINT8*)gPlatformKeyFile;
			keyfile_size = gPlatformKeyFileSize;
		}
	}
	else if (key_file == DCryptUsbDrive) {
		ret = LoadUsbKeyFile(&keyfile_data, &keyfile_size);
	}
	else if (key_file == DCryptFilePicker) {
		ret = LoadFilePickerKeyFile(&keyfile_data, &keyfile_size);
	}

	if (EFI_ERROR(ret)) {
		ERR_PRINT(L"Failed to load key file: %r\n", ret);
		return ret;
	}

	memset(pass->pass, 0, sizeof(pass->pass));
	pass->size = (int)password_size;
	memcpy(pass->pass, password, password_size);

	int file_count = 0;
	if (hw_key == DCryptTPM) file_count++;
	else if (keyfile_data != NULL) file_count++;
	if (aux_data && aux_size > 0) file_count++;
	if (file_count == 0) {
		return EFI_SUCCESS;
	}

	// simple legacy mixing
	if (gDCryptKfMixer == KEYFILE_MIX_LEGACY)
	{
		// HW Key
		if (hw_key == DCryptTPM) {
			ret = DCApplyKeyData(pass, gDCryptTpmSecret, sizeof(gDCryptTpmSecret));
		}
		if (EFI_ERROR(ret)) goto finish;

		// Key Files
		if (keyfile_data != NULL) {
			ret = DCApplyKeyData(pass, keyfile_data, keyfile_size);
		}
		if (EFI_ERROR(ret)) goto finish;

		// Aux Key File Data
		if (aux_data && aux_size > 0) {
			ret = DCApplyKeyData(pass, aux_data, aux_size);
		}
		if (EFI_ERROR(ret)) goto finish;
	}
	else // new mixing method
	{
		// handle raw keyfile case (single keyfile with size == 64 bytes, treated as pre-hashed keyset)
		if (file_count == 1)
		{
			if (hw_key == DCryptTPM) {
				ret = dc_kf_mixer_combine(pass, gDCryptTpmSecret);
				goto finish;
			}
			else if (keyfile_size == DC_KF_HASH_SIZE) {
				ret = dc_kf_mixer_combine(pass, keyfile_data);
				goto finish;
			}
			else if (aux_data && aux_size == DC_KF_HASH_SIZE) {
				ret = dc_kf_mixer_combine(pass, aux_data);
				goto finish;
			}
		}

		// fill canonical mixing

		dc_kf_mixer mixer;

		ret = dc_kf_mixer_init(&mixer);

		if (hw_key == DCryptTPM && !EFI_ERROR(ret)) {
			ret = dc_kf_mixer_add_data(&mixer, gDCryptTpmSecret, sizeof(gDCryptTpmSecret));
		}

		if (keyfile_data != NULL && !EFI_ERROR(ret)) {
			ret = dc_kf_mixer_add_data(&mixer, keyfile_data, keyfile_size);
		}

		if (aux_data && aux_size > 0 && !EFI_ERROR(ret)) {
			ret = dc_kf_mixer_add_data(&mixer, aux_data, aux_size);
		}

		if (!EFI_ERROR(ret)) ret = dc_kf_mixer_finish(&mixer, pass);
		else dc_kf_mixer_free(&mixer);

		//ERR_PRINT(L"Result: \n");
		//DumpHex(pass->pass, pass->size);
	}

finish:
	if (keyfile_data && keyfile_data != (UINT8*)gPlatformKeyFile) {
		MEM_BURN(keyfile_data, keyfile_size);
		MEM_FREE(keyfile_data);
	}
	return ret;
}

/*VOID DumpBlob(UINT8* sectorData, UINTN sectorSize)
{
	for (UINTN idx = 0; idx < sectorSize; idx++)
	{
		UINT8 c = sectorData[idx];
		if (c > 0x1f && c < 0x7f)
			OUT_PRINT(L"%c", c);
		else
			OUT_PRINT(L"_");
	}
	OUT_PRINT(L"\n");
}*/

/**
Ask user a yes/no question and wait for valid input.

@param[in] Prompt       The prompt to display (should include [y/N] or [Y/n] hint)
@param[in] DefaultYes   If TRUE, Enter defaults to Yes; if FALSE, Enter defaults to No

@return TRUE if user answered Yes, FALSE if No or cancelled (ESC)
**/
BOOLEAN AskYesNo(CHAR16 *Prompt, BOOLEAN DefaultYes) {
  EFI_INPUT_KEY key;

  OUT_PRINT(L"%s", Prompt);

  for (;;) {
    key = GetKey();

    // Yes
    if (key.UnicodeChar == L'y' || key.UnicodeChar == L'Y') {
      OUT_PRINT(L"y\n");
      return TRUE;
    }

    // No
    if (key.UnicodeChar == L'n' || key.UnicodeChar == L'N') {
      OUT_PRINT(L"n\n");
      return FALSE;
    }

    // Enter - use default
    if (key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
      OUT_PRINT(L"%c\n", DefaultYes ? L'y' : L'n');
      return DefaultYes;
    }

    // ESC - cancel (same as No)
    if (key.ScanCode == SCAN_ESC) {
      OUT_PRINT(L"\n");
      return FALSE;
    }

    // Invalid key - ignore and wait for valid input
  }
}

// Convert a string to a tag value
// Accepts either:
//   - 1-4 character ASCII string (big-endian format)
//   - Hex notation: 0xNNNNNNNN (up to 8 hex digits)
// Returns 0 if invalid
//static UINT32
//DcStringToTag(CHAR16 *str, UINTN len)
//{
//	UINT32 tag = 0;
//	UINTN i;
//
//	if (str == NULL || len == 0) {
//		return 0;
//	}
//
//	// Check for hex notation (0x or 0X prefix)
//	if (len >= 3 && str[0] == L'0' && (str[1] == L'x' || str[1] == L'X')) {
//		// Parse as hex - skip "0x" prefix
//		if (len > 10) {  // "0x" + max 8 hex digits
//			return 0;
//		}
//		for (i = 2; i < len; i++) {
//			CHAR16 c = str[i];
//			UINT8 nibble;
//			if (c >= L'0' && c <= L'9') {
//				nibble = (UINT8)(c - L'0');
//			} else if (c >= L'a' && c <= L'f') {
//				nibble = (UINT8)(c - L'a' + 10);
//			} else if (c >= L'A' && c <= L'F') {
//				nibble = (UINT8)(c - L'A' + 10);
//			} else {
//				return 0;  // Invalid hex character
//			}
//			tag = (tag << 4) | nibble;
//		}
//		return tag;
//	}
//
//	// Parse as ASCII (1-4 printable characters)
//	if (len > 4) {
//		return 0;
//	}
//
//	for (i = 0; i < len; i++) {
//		CHAR16 c = str[i];
//		// Only allow printable ASCII (0x20-0x7E)
//		if (c < 0x20 || c > 0x7E) {
//			return 0;
//		}
//		tag = (tag << 8) | (UINT8)c;
//	}
//
//	// Left-align if less than 4 characters (pad with spaces on the right conceptually,
//	// but actually shift to MSB position)
//	while (i < 4) {
//		tag = tag << 8;
//		i++;
//	}
//
//	return tag;
//}

// Format a tag value to a display string
// If all 4 bytes are printable ASCII, outputs as ASCII (up to 4 chars)
// Otherwise outputs as hex "0xNNNNNNNN" (requires out_size >= 11)
//static VOID
//DcTagToString(UINT32 tag, CHAR16 *out, UINTN out_size)
//{
//	UINT8 bytes[4];
//	UINTN i;
//	BOOLEAN allPrintable;
//
//	if (out == NULL || out_size < 5) {
//		return;
//	}
//
//	bytes[0] = (UINT8)((tag >> 24) & 0xFF);
//	bytes[1] = (UINT8)((tag >> 16) & 0xFF);
//	bytes[2] = (UINT8)((tag >> 8) & 0xFF);
//	bytes[3] = (UINT8)(tag & 0xFF);
//
//	// Check if all non-zero bytes are printable ASCII
//	allPrintable = TRUE;
//	for (i = 0; i < 4; i++) {
//		if (bytes[i] != 0 && (bytes[i] < 0x20 || bytes[i] > 0x7E)) {
//			allPrintable = FALSE;
//			break;
//		}
//	}
//
//	if (allPrintable) {
//		// Output as ASCII string (skip trailing zeros)
//		UINTN j = 0;
//		for (i = 0; i < 4 && j < out_size - 1; i++) {
//			if (bytes[i] >= 0x20 && bytes[i] <= 0x7E) {
//				out[j++] = (CHAR16)bytes[i];
//			}
//		}
//		out[j] = L'\0';
//	} else {
//		// Output as hex notation
//		if (out_size >= 11) {
//			UnicodeSPrint(out, out_size * sizeof(CHAR16), L"0x%08x", tag);
//		} else {
//			out[0] = L'\0';
//		}
//	}
//}

// Ask user for a cache tag. Returns tag value, or 0 if cancelled/invalid.
//static UINT32
//DcAskCacheTag(UINT32 DefaultTag)
//{
//	CHAR16 tagBuf[11];
//	CHAR16 defaultTag[11];
//	UINTN tagLen;
//	UINT32 tag = 'PWD1';
//	*(char*)&tag += (char)gDCryptPassCount;
//
//	DcTagToString(DefaultTag ? DefaultTag : tag, defaultTag, sizeof(defaultTag)/sizeof(CHAR16));
//
//	OUT_PRINT(L"Enter cache tag (1-4 chars or 0xHHHHHHHH) [%s]: ", defaultTag);
//
//	// Simple inline input for tag
//	tagLen = 0;
//	ZeroMem(tagBuf, sizeof(tagBuf));
//
//	if(!GetLine(&tagLen, tagBuf, NULL, 11, TRUE))
//		return 0; // cancelled
//
//	// If empty, use default
//	if (tagLen == 0) {
//		return DefaultTag ? DefaultTag : tag;
//	}
//
//	// Convert to tag value
//	tag = DcStringToTag(tagBuf, tagLen);
//	if (tag == 0) {
//		ERR_PRINT(L"Invalid tag. Use 1-4 ASCII chars or hex (0x...).\n");
//		return 0;
//	}
//
//	return tag;
//}

static BOOLEAN
DcAskLabel(char* outTag) // max 20 0 padded
{
	CHAR16 tagBuf[SLOT_LABEL_LEN + 1];
	CHAR16 defaultTag[SLOT_LABEL_LEN + 1];
	UnicodeSPrint(defaultTag, sizeof(defaultTag) / sizeof(CHAR16), L"Password %d", gDCryptPassCount + 1); // default label
	UINTN len = 0;

	ZeroMem(outTag, SLOT_LABEL_LEN);

	OUT_PRINT(L"Enter cache label [%s]: ", defaultTag);

	if(!GetLine(&len, tagBuf, NULL, sizeof(tagBuf) / sizeof(CHAR16), TRUE))
		return 0; // cancelled

	// If empty, use default
	if (len == 0) {
		CopyMem(tagBuf, defaultTag, sizeof(tagBuf));
	}

	for(len = 0; len < 20 && tagBuf[len] != L'\0'; len++) {
		outTag[len] = (char)tagBuf[len];
	}
	return 1;
}

INT32
HandleFuncKeys(
	IN EFI_INPUT_KEY key,
	IN VOID *Param
)
{
	PDCRYPT_PW_PROMPT pParams = (PDCRYPT_PW_PROMPT)Param;

	if (key.ScanCode == SCAN_F1 && pParams->Type == DCryptPwPromptPassword) {
		return AskPwdRetHelp;
	}

	if (key.ScanCode == SCAN_F2 && pParams->Type == DCryptPwPromptPassword) {
		//return AskPwdRetChange;
	}

	if (key.ScanCode == SCAN_F3 && pParams->Type == DCryptPwPromptPassword) {
		return AskPwdForcePass;
	}

	if (key.ScanCode == SCAN_F4 && pParams->Type == DCryptPwPromptPassword) {
		return AskPwdCachePass;
	}

	if (key.ScanCode == SCAN_F5) {
		return AskPwdRetShow;
	}

	if (key.ScanCode == SCAN_F6 && pParams->Type == DCryptPwPromptPassword) {
		return AskPwdRetSetParams;
	}

	if (key.ScanCode == SCAN_F7) {
		pParams->KeyFile = ++pParams->KeyFile % DCryptKeyFileMax;
		if (pParams->KeyFile == DCryptEmbedded && (!gDCryptKeyFilePath || !*gDCryptKeyFilePath)) {
			pParams->KeyFile++; // skip embedded if no path configured
		}
		return AskPwdRetStatus;
	}

	if (key.ScanCode == SCAN_F8 && pParams->Type == DCryptPwPromptPassword) { 
		pParams->HwKey = ++pParams->HwKey % DCryptHwKeyMax;
		return AskPwdRetStatus;
	}

	if (key.ScanCode == SCAN_F9) {
		// unused <---
	}

	if (key.ScanCode == SCAN_F10 && pParams->Type == DCryptPwPromptPassword) {
		return AskPwdRetSave;
	}

	if (key.ScanCode == SCAN_F11) {
		// unused <---
	}

	if (key.ScanCode == SCAN_F12) {
		// unused <---
	}

	if (key.UnicodeChar == CHAR_TAB) {
		// unused <---
	}

	return AskPwdRetNone;
}

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

// Display strings for KeyFile options (indexed by DCryptKeyFile enum)
STATIC CONST CHAR16* const gKeyFileNames[] = {
	L"No",                      // DCryptNo = 0
	L"%EEmbedded%N",            // DCryptEmbedded
	L"%EFrom USB%N",            // DCryptUsbDrive
	L"%EFile Picker%N",         // DCryptFilePicker
	L"%EPlatform%N",            // DCryptPlatform
};

// Display strings for HwKey options (indexed by DCryptHwKey enum)
STATIC CONST CHAR16* const gHwKeyNames[] = {
	L"None",                    // DCryptNone = 0
	L"%ETPM%N",                 // DCryptTPM
};

VOID
FormatStatus(
	IN CHAR16* statusStr,
	IN UINTN statusStrLen,
	IN VOID *Param
)
{
	PDCRYPT_PW_PROMPT pParams = (PDCRYPT_PW_PROMPT)Param;

	CHAR16* statusEnd = statusStr + statusStrLen; // statusStr must be 1 char longer than statusStrLen to allow null-termination

	if (pParams->Type == DCryptPwPromptPassword && statusEnd > statusStr) {
		statusStr += UnicodeSPrint(statusStr, (statusEnd - statusStr) * 2, L"[F1] Help  [F6] Options ");
	}

	if (statusEnd > statusStr) {
		CONST CHAR16* keyFileName = (pParams->KeyFile >= 0 && pParams->KeyFile < ARRAY_SIZE(gKeyFileNames)) ? gKeyFileNames[pParams->KeyFile] : L"Unknown";
		statusStr += UnicodeSPrint(statusStr, (statusEnd - statusStr) * 2, L"[F7] Keyfile: %s ", keyFileName);
	}

	if (pParams->Type == DCryptPwPromptPassword && statusEnd > statusStr) {
		CONST CHAR16* hwKeyName = (pParams->HwKey >= 0 && pParams->HwKey < ARRAY_SIZE(gHwKeyNames)) ? gHwKeyNames[pParams->HwKey] : L"Unknown";
		statusStr += UnicodeSPrint(statusStr, (statusEnd - statusStr) * 2, L"[F8] Hardware key: %s ", hwKeyName);
	}

	while(statusEnd > statusStr)
		*statusStr++ = L' ';
	*statusStr = L'\0';
}

EFI_STATUS
DcMain(int* vol_found, int* hdr_found)
{
	EFI_STATUS     ret = EFI_SUCCESS;
	CHAR16         password[MAX_PASSWORD]; // password in UTF16-LE encoding
	UINT32         password_size = 0;
	int		       retry = gDCryptAuthRetry;
	EFI_INPUT_KEY  key;
	DCRYPT_PW_PROMPT Params = { DCryptPwPromptPassword, gDCryptUseKeyFile };
	UINT8          sbState = 0;
	DcsLdrGetMokSBState(&sbState);

	PlatformGetID(NULL, &gPlatformKeyFile, &gPlatformKeyFileSize);
	//OUT_PRINT(L"Platform ID: %a\n", gPlatformKeyFile);

	gDCryptPwdCode = AskPwdRetCancel;
	gDCryptTpmPinUsed = FALSE;

	// TPM Auto-load: try to load password from TPM before showing prompt
	if (gDCryptUseHardwareKey == DCryptTPM) 
	{
		ret = DcTpmLoad(password, &password_size);

		if (gDCryptTpmSecretValid)
			Params.HwKey = DCryptTPM;

		if (ret == EFI_DCS_INPUT_REQUIRED) {
			// password required in addition to TPM secret
		}
		else if (!EFI_ERROR(ret)) {

			if (!gDCryptTpmPinUsed && !gBlockUnencryptedVolumes && !sbState) {
				OUT_PRINT(L"\n%OWARNING:%N %HSecure Boot is disabled%N without it unattended TPM unlock is unsafe.\n");
				OUT_PRINT(L"Please considder using a TPM PIN or enabling Secure Boot for better security.\n\n");
				gDCryptAutoLoginDelay = 15;
			}

			gDCryptPwdCode = AskPwdRetLogin;
		}
	}

	if (gDCryptTpmSecretValid && !gVerifyCertInfo.s.active) {
		OUT_PRINT(L"\n");
		OUT_PRINT(L"  %O+======================================================================+%N\n");
		OUT_PRINT(L"  %O|%N                                                                      %O|%N\n");
		OUT_PRINT(L"  %O|%N   %ESUPPORT CERTIFICATE REQUIRED%N                                       %O|%N\n");
		OUT_PRINT(L"  %O|%N                                                                      %O|%N\n");
		OUT_PRINT(L"  %O|%N   DiskCryptor Pro TPM Module requires a valid Support Certificate.   %O|%N\n");
		OUT_PRINT(L"  %O|%N                                                                      %O|%N\n");
		OUT_PRINT(L"  %O|%N   Please visit the web shop at %Hdiskcryptor.org%N to obtain one.        %O|%N\n");
		OUT_PRINT(L"  %O|%N                                                                      %O|%N\n");
		OUT_PRINT(L"  %O+======================================================================+%N\n");
		OUT_PRINT(L"\n");
		if (!gDcsLdr) {
			key = KeyWait(L"  Please wait %2d seconds...\r", 60, 0, 0);
			if (key.ScanCode != 0 || key.UnicodeChar != 0) {
				OUT_PRINT(L"  Cancelled.                    \n");
				gDCryptTpmSecretValid = FALSE;
				ret = EFI_ABORTED;
			}
		}
		OUT_PRINT(L"\n");
	}
	
	// Auto-login: if enabled and not already loaded from TPM, use configured password (and key file if configured)
	if (gDCryptAutoLogin && gDCryptPwdCode != AskPwdRetLogin) 
	{
		if (gDCryptAutoPassword && *gDCryptAutoPassword && !EFI_ERROR(StrCpyS(password, MAX_PASSWORD, gDCryptAutoPassword))) {
			password_size = (int)StrLen(gDCryptAutoPassword) * 2;
		}

		gDCryptPassword.kdf = gDCryptHeaderKdf;
		gDCryptPassword.slot = -KEY_SLOT_COUNT;

		gDCryptPwdCode = AskPwdRetLogin;
		ret = EFI_SUCCESS;
	}

	if (gDCryptPwdCode == AskPwdRetLogin)
	{
		// Only show countdown for truly unattended mode (no PIN, no password interaction)
		if (!gDCryptTpmPinUsed) {
			key = KeyWait(L"Auto mount in %2d\r", gDCryptAutoLoginDelay ? gDCryptAutoLoginDelay : 1, 0, 0);
			if ((key.UnicodeChar != CHAR_CARRIAGE_RETURN) && (key.ScanCode != 0 || key.UnicodeChar != 0)) {
				OUT_PRINT(L"Cancelled.               \n");
				ret = EFI_ABORTED;
			}
		}

		if (!EFI_ERROR(ret)) {
			if (gConfigDebug) {
				CONST CHAR16* keyFileName = (Params.KeyFile >= 0 && Params.KeyFile < ARRAY_SIZE(gKeyFileNames)) ? gKeyFileNames[Params.KeyFile] : L"Unknown";
				CONST CHAR16* hwKeyName = (Params.HwKey >= 0 && Params.HwKey < ARRAY_SIZE(gHwKeyNames)) ? gHwKeyNames[Params.HwKey] : L"Unknown";
				OUT_PRINT(L"Auto Mount:%s KeyFile: %s; HW-Key: %s\n", password_size> 0 ? L" Preset Password;" : L"", keyFileName, hwKeyName);
			}

			ret = DCFinalizePassword(&gDCryptPassword, password, password_size, Params.KeyFile, Params.HwKey, NULL, 0);
			if (EFI_ERROR(ret)) {
				ERR_PRINT(L"Failed to finalize password, error: %r\n", ret);
			}
		}

		Params.HwKey = DCryptNone;
		MEM_BURN(gDCryptTpmSecret, sizeof(gDCryptTpmSecret));
		gDCryptTpmSecretValid = FALSE;

		if (!EFI_ERROR(ret)) 
		{
			if (!gConfigDebug) {
				OUT_PRINT(L"Mounting volumes...");
			}
			DcTryDecrypt(vol_found, NULL);

			if (*vol_found > 0) {
				if (!gConfigDebug) {
					OUT_PRINT(L"%VSuccess!%N\n");
				}
				ret = EFI_SUCCESS;
				goto finish;
			}
			if (!gConfigDebug) {
				ERR_PRINT(L"Failed!\n");
			}
		}
	}

	// zero memory
	MEM_BURN(password, sizeof(password));
	password_size = 0;
	MEM_BURN(&gDCryptPassword, sizeof(gDCryptPassword));

	do {
		// password prompt
		if (gDCryptTouchInput == 1 && gGraphOut != NULL && ((gTouchPointer != NULL) || (gTouchSimulate != 0))) {
			//AskPictPwdInt(AskPwdLogin, MAX_PASSWORD, gDCryptPassword.pass, &gDCryptPassword.size, &gDCryptPwdCode, TRUE);
			//AskTouchPwdInt(AskPwdLogin, MAX_PASSWORD, password, &password_size, &gDCryptPwdCode, TRUE);
			AskTouchPwdEx(gDCryptPasswordMsg, &password_size, password, &gDCryptPwdCode, MAX_PASSWORD, gPasswordVisible, TRUE, HandleFuncKeys, FormatStatus, &Params);
		} else {
			//AskConsolePwdInt(gDCryptPasswordMsg, &password_size, password, &gDCryptPwdCode, MAX_PASSWORD, gPasswordVisible, TRUE);
			AskConsolePwdEx(gDCryptPasswordMsg, &password_size, password, &gDCryptPwdCode, MAX_PASSWORD, gPasswordVisible, TRUE, HandleFuncKeys, FormatStatus, &Params);
		}

		//if (gDCryptPwdCode == AskPwdRetChange) {
		//	gDcsTpm->MenuShow(gDcsTpm);  
		//	continue;
		//}

		if (gDCryptPwdCode == AskPwdRetSetParams) {
			DcsConfigMenuShow(); 
			continue;
		}

		if (gDCryptPwdCode == AskPwdRetHelp) {
			DcsShowHelp(); 
			continue;
		}
		
		if (gDCryptPwdCode == AskPwdRetCancel) {
			ret = EFI_DCS_USER_CANCELED;
			goto finish;
		}

		if (gDCryptPwdCode == AskPwdRetTimeout) {
			if (gDCryptFailOnTimeout) {
				break;
			}
			ret = EFI_DCS_USER_TIMEOUT;
			goto finish;
		}

		if (gDCryptPwdCode == AskPwdRetSave) {
			// Show TPM secret management menu
			DcTpmMenu();
			if (gDCryptTpmSecretValid) {
				Params.HwKey = DCryptTPM;
			}
			continue;
		}

		ret = DCFinalizePassword(&gDCryptPassword, password, password_size, Params.KeyFile, Params.HwKey, NULL, 0);
		if (ret == EFI_DCS_USER_CANCELED) {
			continue;
		} else if (EFI_ERROR(ret)){
			ERR_PRINT(L"Failed finalize Password: %r\n", ret);
			continue;
		}
		gDCryptPassword.kdf = gDCryptHeaderKdf;
		gDCryptPassword.slot = -KEY_SLOT_COUNT;

		if (gDCryptPwdCode == AskPwdCachePass) {
			if (gDCryptPassCount >= DC_PASS_CACHE_SIZE) {
				ERR_PRINT(L"Password cache is full. Cannot cache more passwords.\n");
			}
			else if (gDCryptHandoffMode != 3) {
				if (DcAskLabel(gDCryptPassword.label)) {
					gDCryptPassCache[gDCryptPassCount++] = gDCryptPassword;
					OUT_PRINT(L"Password Cached\n");
				}
			}
			ZeroMem(gDCryptPassword.label, sizeof(gDCryptPassword.label));
			password_size = 0;

			// try to mount volumes with this password
			OUT_PRINT(L"%a\n", gDCryptStartMsg);
			int mount_before = iodb.n_mount;
			DcTryDecrypt(vol_found, hdr_found);
			if (iodb.n_mount > mount_before) {
				OUT_PRINT(L"%a\n", gDCryptSuccessMsg);
			}
			continue;
		}

		OUT_PRINT(L"%a\n", gDCryptStartMsg);

		DcTryDecrypt(vol_found, hdr_found);

		if (*vol_found > 0 || *hdr_found > 0) {
			OUT_PRINT(L"%a\n", gDCryptSuccessMsg);
			ret = EFI_SUCCESS;
			goto finish;
		}
		else {
			ERR_PRINT(L"%a\n", gDCryptErrorMsg);
			// clear previous failed authentication information
			//MEM_BURN(&gDCryptPassword, sizeof(gDCryptPassword)); // leave it for next try, maybe user just made a typo and wants to try again without re-entering the password

			if (gDCryptPwdCode == AskPwdForcePass) {
				ret = EFI_SUCCESS;
				goto finish;
			}
		}

	} while (!retry || --retry > 0); // retry == 0 means infinite retries

	ret = RETURN_ABORTED;

finish:
	MEM_BURN(password, sizeof(password));
	MEM_BURN(gDCryptTpmSecret, sizeof(gDCryptTpmSecret));
	return ret;
}