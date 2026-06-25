/** @file
EFI common library (helpers)

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 
Copyright (c) 2019-2026. DiskCryptor, David Xanatos

This program and the accompanying materials are licensed and made available
under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#ifndef __COMMONLIB_H__
#define __COMMONLIB_H__

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Protocol/BlockIo.h>
#include <Protocol/DcsBmlProto.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/UsbIo.h>
#include <Protocol/AbsolutePointer.h>
#include <Guid/FileInfo.h>
#include <Uefi/UefiGpt.h>

//////////////////////////////////////////////////////////////////////////
// Custom error codes
//////////////////////////////////////////////////////////////////////////

#define EFI_DCS_SHUTDOWN_REQUESTED	ENCODE_ERROR(0x0DC5001)
#define EFI_DCS_REBOOT_REQUESTED    ENCODE_ERROR(0x0DC5002)
#define EFI_DCS_HALT_REQUESTED	    ENCODE_ERROR(0x0DC5003)
#define EFI_DCS_USER_CANCELED       ENCODE_ERROR(0x0DC5004)
#define EFI_DCS_POSTEXEC_REQUESTED  ENCODE_WARNING(0x0DC5005)
#define EFI_DCS_USER_TIMEOUT        ENCODE_ERROR(0x0DC5006)
#define EFI_DCS_DATA_NOT_FOUND      ENCODE_ERROR(0x0DC5007)
#define EFI_DCS_INPUT_REQUIRED      ENCODE_WARNING(0x0DC5008)

//////////////////////////////////////////////////////////////////////////
// Check error 
//////////////////////////////////////////////////////////////////////////
extern UINTN gCELine;
#define CE(ex) gCELine = __LINE__; if(EFI_ERROR(res = ex)) goto err

#ifndef CSTATIC_ASSERT
#define CSTATIC_ASSERT(b, name) typedef int StaticAssertFailed##name[b ? 1 : -1];
#endif

//////////////////////////////////////////////////////////////////////////
// defines
//////////////////////////////////////////////////////////////////////////
#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))
#define FIELD_OFFSET(t, f) ((UINTN)(&((t*)0)->f))

//////////////////////////////////////////////////////////////////////////
// Memory procedures wrappers
//////////////////////////////////////////////////////////////////////////

#define MEM_ALLOC MemAlloc
#define MEM_FREE MemFree
#define MEM_REALLOC MemRealloc
#define MEM_BURN(ptr,count) do { volatile char *burnPtr = (volatile char *)(ptr); UINTN burnCount = (UINTN) count; while (burnCount--) *burnPtr++ = 0; } while (0)

VOID*
MemAlloc(
   IN UINTN size
   );

VOID
MemFree(
   IN VOID* ptr
   );

VOID*
MemRealloc(
	IN UINTN  OldSize,
	IN UINTN  NewSize,
	IN VOID   *OldBuffer  OPTIONAL
	);

EFI_STATUS
PrepareMemory(
   IN UINTN    address,
   IN UINTN    len,
   OUT VOID**  mem
   );

EFI_STATUS
PrepareMemoryAny(
   IN UINTN    len,
   OUT VOID**  mem,
   OUT UINTN*  allocatedAddress
   );

EFI_STATUS
MemoryHasPattern (
	CONST VOID* buffer,
	UINTN bufferLen,
	CONST VOID* pattern,
	UINTN patternLen);

//////////////////////////////////////////////////////////////////////////
// handles
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
EfiGetHandles(
   IN  EFI_LOCATE_SEARCH_TYPE   SearchType,
   IN  EFI_GUID                 *Protocol, OPTIONAL
   IN  VOID                     *SearchKey, OPTIONAL
   OUT EFI_HANDLE               **Buffer,
   OUT UINTN                    *Count
   );

EFI_STATUS
EfiGetStartDevice(
   OUT EFI_HANDLE* handle
   );
//////////////////////////////////////////////////////////////////////////
// Print handle info
//////////////////////////////////////////////////////////////////////////

VOID 
EfiPrintDevicePath(
   IN EFI_HANDLE handle
   );

VOID 
EfiPrintPath(
   IN EFI_DEVICE_PATH *DevicePath
   );

VOID
EfiPrintProtocols(
   IN EFI_HANDLE handle
   );

//////////////////////////////////////////////////////////////////////////
// Block I/O
//////////////////////////////////////////////////////////////////////////

EFI_BLOCK_IO_PROTOCOL*
EfiGetBlockIO(
   IN EFI_HANDLE handle
   );

extern EFI_HANDLE* gBIOHandles;
extern UINTN       gBIOCount;

EFI_STATUS
InitBio();

BOOLEAN
EfiIsPartition(
	IN    EFI_HANDLE              h
	);

EFI_STATUS
EfiGetPartDetails(
	IN    EFI_HANDLE              h,
	OUT   HARDDRIVE_DEVICE_PATH*  dpVolme,
	OUT   EFI_HANDLE*             hDisk
	);

EFI_STATUS
EfiGetPartGUID(
	IN    EFI_HANDLE              h,
	OUT   EFI_GUID*               guid
	);

EFI_STATUS
EfiFindPartByGUID(
	IN   EFI_GUID*               guid,
	OUT  EFI_HANDLE*             h
	);

//////////////////////////////////////////////////////////////////////////
// GPT
//////////////////////////////////////////////////////////////////////////

BOOLEAN
GptHeaderCheckCrc(
	IN UINTN                 MaxSize,
	IN OUT EFI_TABLE_HEADER  *Hdr
	);

EFI_STATUS
GptCheckEntryArray(
	IN  EFI_PARTITION_TABLE_HEADER  *PartHeader,
	IN  EFI_PARTITION_ENTRY         *Entrys
	);

EFI_STATUS
GptUpdateCRC(
	IN  EFI_PARTITION_TABLE_HEADER  *PartHeader,
	IN  EFI_PARTITION_ENTRY         *Entrys
	);

EFI_STATUS
GptReadEntryArray(
	IN  EFI_BLOCK_IO_PROTOCOL*      BlockIo,
	IN  EFI_PARTITION_TABLE_HEADER  *PartHeader,
	OUT EFI_PARTITION_ENTRY         **Entrys
	);

EFI_STATUS
GptReadHeader(
	IN  EFI_BLOCK_IO_PROTOCOL*      BlockIo,
	IN  EFI_LBA                     HeaderLba,
	OUT EFI_PARTITION_TABLE_HEADER  **PartHeader
	);

//////////////////////////////////////////////////////////////////////////
// General EFI tables
//////////////////////////////////////////////////////////////////////////
#define EFITABLE_HEADER_SIGN SIGNATURE_64('E','F','I','T','A','B','L','E')

BOOLEAN
TablesVerify(
	IN UINTN maxSize,
	IN VOID* tables);

BOOLEAN
TablesGetData(
	IN  VOID*   tables,
	IN  UINT64  sign,
	OUT VOID**  data,
	OUT UINTN*  size);

BOOLEAN
TablesDelete(
	IN  VOID*   tables,
	IN  UINT64  sign
	);

BOOLEAN
TablesAppend(
	IN OUT VOID**  tables,
	IN     UINT64  sign,
	IN     VOID*   data,
	IN     UINTN   size);

//////////////////////////////////////////////////////////////////////////
// Bluetooth
//////////////////////////////////////////////////////////////////////////
extern EFI_HANDLE* gBluetoothIoHandles;
extern UINTN       gBluetoothIoCount;

extern EFI_HANDLE* gBluetoothHcHandles;
extern UINTN       gBluetoothHcCount;

extern EFI_HANDLE* gBluetoothConfigHandles;
extern UINTN       gBluetoothConfigCount;

EFI_STATUS
InitBluetooth();

//////////////////////////////////////////////////////////////////////////
// TCG
//////////////////////////////////////////////////////////////////////////
extern EFI_HANDLE* gTcgHandles;
extern UINTN       gTcgCount;

extern EFI_HANDLE* gTcg2Handles;
extern UINTN       gTcg2Count;

EFI_STATUS
InitTcg();

//////////////////////////////////////////////////////////////////////////
// USB
//////////////////////////////////////////////////////////////////////////
extern EFI_HANDLE* gUSBHandles;
extern UINTN       gUSBCount;

EFI_STATUS
InitUsb();

EFI_STATUS
UsbGetIO(
	IN    EFI_HANDLE					Handle,
	OUT   EFI_USB_IO_PROTOCOL**	UsbIo
	);

EFI_STATUS
UsbGetIOwithDescriptor(
	IN    EFI_HANDLE					Handle,
	OUT   EFI_USB_IO_PROTOCOL**	UsbIo,
	OUT   EFI_USB_DEVICE_DESCRIPTOR* UsbDescriptor
	);

EFI_STATUS
UsbGetId(
	IN    EFI_HANDLE		Handle,
	OUT   CHAR8**			id
	);

#define PC_to_RDR_XfrBlock_Message 0x6F

#pragma pack(1)
typedef struct _CCID_HEADER_OUT {
	UINT8    bMessageType;     // Type of the message
	UINT32   dwLength;         // Length of data
	UINT8    bSlot;            // 
	UINT8    bSeq;             // 
	UINT8    bReserved;        // 
	UINT16   wLevelParameter;  // 0000h Short APDU level 
} CCID_HEADER_OUT;

typedef struct _CCID_HEADER_IN {
	UINT8    bMessageType;     // Type of the message
	UINT32   dwLength;         // Length of data
	UINT8    bSlot;            // 
	UINT8    bSeq;             // 
	UINT8    bStatus;          // 
	UINT8    bError;           // 
	UINT8    bChainParameter;
} CCID_HEADER_IN;
#pragma pack()

EFI_STATUS
UsbScTransmit(
	IN    EFI_USB_IO_PROTOCOL    *UsbIO,
	IN    UINT8*                 cmd,
	IN    UINTN                  cmdLen,
	OUT   UINT8*                 resp,
	OUT   UINTN*                 respLen,
	OUT   UINT16*                statusSc
	);

//////////////////////////////////////////////////////////////////////////
// Touch
//////////////////////////////////////////////////////////////////////////

extern EFI_HANDLE* gTouchHandles;
extern UINTN       gTouchCount;
extern int         gTouchSimulate;
extern EFI_ABSOLUTE_POINTER_PROTOCOL*	gTouchPointer;
extern UINT32      gTouchSimulateStep;

EFI_STATUS
InitTouch();

EFI_STATUS
TouchGetIO(
	IN    EFI_HANDLE								Handle,
	OUT   EFI_ABSOLUTE_POINTER_PROTOCOL**	io
	);


//////////////////////////////////////////////////////////////////////////
// Console I/O
//////////////////////////////////////////////////////////////////////////

#define OUT_PRINT(format, ...) AttrPrintEx(-1,-1, format, ##__VA_ARGS__)
#define ERR_PRINT(format, ...) AttrPrintEx(-1,-1, L"%E" format L"%N" , ##__VA_ARGS__)
#define RED_PRINT(format, ...) AttrPrintEx(-1,-1, L"%O" format L"%N" , ##__VA_ARGS__)

VOID
PrintBytes(
	IN UINT8* Data,
	IN UINTN Size);

VOID
DumpHex(
	IN VOID*  Data,
	IN INTN   Size);

EFI_STATUS
ConsoleGetOutput(
	IN EFI_HANDLE handle,
	OUT   EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL**	io
	);

VOID 
FlushInput();

VOID
FlushInputDelay(
	IN UINTN delay
	);

EFI_INPUT_KEY
KeyWait(
   CHAR16* Prompt,
   UINTN mDelay,
   UINT16 scanCode,
   UINT16 unicodeChar);

EFI_INPUT_KEY
GetKey(void);

VOID
ConsoleShowTip(
	IN CHAR16* tip,
	IN UINTN   delay);

BOOLEAN
GetLine(
   UINTN    *length,
   CHAR16   *line,
   CHAR8    *asciiLine,
   UINTN    line_max,
   UINT8    show);

int
AskAsciiString(
   CHAR8* prompt,
   CHAR8* str,
   UINTN max_len,
   UINT8 visible,
	CHAR8* defStr);

int
AskInt(
   CHAR8* prompt,
   UINT8 visible);


UINT8
AskConfirm(
   CHAR8* prompt,
   UINT8 visible);

UINT64
AskUINT64(
	IN char* prompt,
	IN UINT64 def);

UINT64
AskHexUINT64(
	IN char* prompt,
	IN UINT64 def);

UINTN
AskUINTN(
	IN char* prompt,
	IN UINTN def);

BOOLEAN
AsciiHexToDigit(
	OUT UINT8  *b, 
	IN  CHAR8  *str
	);

BOOLEAN
AsciiHexToByte(
	OUT UINT8  *b,
	IN  CHAR8  *str
	);

BOOLEAN
DcsAsciiStrToGuid(
	OUT EFI_GUID  *guid, 
	IN  CHAR8     *str
	);

BOOLEAN
AsciiHexToBytes(
	OUT UINT8  *b,
	IN  UINTN  *bytesLen,
	IN  CHAR8  *str
	);

BOOLEAN
DcsStrHexToBytes(
	OUT UINT8  *b,
	IN  UINTN  *bytesLen,
	IN  CHAR16  *str
	);

//////////////////////////////////////////////////////////////////////////
// Keyboard Mapper
//////////////////////////////////////////////////////////////////////////

#define KB_MAP_QWERTY  0
#define KB_MAP_QWERTZ  1
#define KB_MAP_AZERTY  2

extern int gKeyboardLayout;

EFI_INPUT_KEY 
MapKeyboardKey(
	EFI_INPUT_KEY key
	);

//////////////////////////////////////////////////////////////////////////
// Menu
//////////////////////////////////////////////////////////////////////////
typedef EFI_STATUS(*MENU_ACTION)(IN VOID *ctx);

typedef struct _MENU_ITEM MENU_ITEM;
typedef struct _MENU_ITEM {
	CHAR16         Text[128];
	CHAR16         Select;
	MENU_ACTION    Action;
	VOID*          Context;
	MENU_ITEM      *Next;
} MENU_ITEM, *PMENU_ITEM;

PMENU_ITEM
DcsMenuAppend(
	IN PMENU_ITEM  menu,
	IN CHAR16     *text,
	IN CHAR16     select,
	IN MENU_ACTION action,
	IN VOID*       actionContext
	);

VOID
DcsMenuPrint(
	IN  PMENU_ITEM head
	);

//////////////////////////////////////////////////////////////////////////
// Attribute print
//////////////////////////////////////////////////////////////////////////

extern BOOLEAN	gShellReady;

VOID
SetShellAPI(
	IN VOID* shellProtocol,
	IN VOID* shellParametersProtocol
	);

/**
Print at a specific location on the screen.

This function will move the cursor to a given screen location and print the specified string.

If -1 is specified for either the Row or Col the current screen location for BOTH
will be used.

If either Row or Col is out of range for the current console, then ASSERT.
If Format is NULL, then ASSERT.

In addition to the standard %-based flags as supported by UefiLib Print() this supports
the following additional flags:
%N       -   Set output attribute to normal
%H       -   Set output attribute to highlight
%E       -   Set output attribute to error
%B       -   Set output attribute to blue color
%V       -   Set output attribute to green color

Note: The background color is controlled by the shell command cls.

@param[in] Col        the column to print at
@param[in] Row        the row to print at
@param[in] Format     the format string
@param[in] ...        The variable argument list.

@return EFI_SUCCESS           The printing was successful.
@return EFI_DEVICE_ERROR      The console device reported an error.
**/
EFI_STATUS
EFIAPI
AttrPrintEx(
	IN INT32                Col OPTIONAL,
	IN INT32                Row OPTIONAL,
	IN CONST CHAR16         *Format,
	...
	);

//////////////////////////////////////////////////////////////////////////
// Console control
//////////////////////////////////////////////////////////////////////////

extern EFI_HANDLE* gConsoleControlHandles;
extern UINTN       gConsoleControlCount;

EFI_STATUS
InitConsoleControl();

//////////////////////////////////////////////////////////////////////////
// Beep
//////////////////////////////////////////////////////////////////////////
extern EFI_HANDLE*                gSpeakerHandles;
extern UINTN                      gSpeakerCount;
extern EFI_GUID                   gSpeakerGuid;

extern int gBeepEnabled;
extern BOOLEAN	gBeepControlEnabled;
extern int gBeepDevice;
extern int gBeepNumberDefault;
extern int gBeepDurationDefault;
extern int gBeepIntervalDefault;
extern int gBeepToneDefault;


EFI_STATUS
InitSpeaker();

EFI_STATUS
SpeakerBeep(
	IN UINT16  Tone,
	IN UINTN   NumberOfBeeps,
	IN UINTN   Duration,
	IN UINTN   Interval
	);

EFI_STATUS
SpeakerSelect(
	IN UINTN index
	);

//////////////////////////////////////////////////////////////////////////
// BML
//////////////////////////////////////////////////////////////////////////
extern EFI_HANDLE*                gBmlHandles;
extern UINTN                      gBmlCount;
extern EFI_DCSBML_PROTOCOL*	      gBml;
extern EFI_GUID                   gBmlGuid;

EFI_STATUS
InitBml();

EFI_STATUS
BmlLock(
    IN UINT32 lock
    );


//////////////////////////////////////////////////////////////////////////
// Efi variables
//////////////////////////////////////////////////////////////////////////

#define DCS_BOOT_STR L"DcsBoot"

extern EFI_GUID gEfiDcsVariableGuid;

EFI_STATUS
EfiGetVar(
   IN  CONST CHAR16*    varName,
   IN  EFI_GUID*        varGuid,
   OUT VOID**           varValue,
   OUT UINTN*           varSize,
   OUT UINT32*          varAttr
   );

EFI_STATUS
EfiSetVar(
   IN  CONST CHAR16*    varName,
   IN  EFI_GUID*        varGuid,
   IN  VOID*            varValue,
   IN  UINTN            varSize,
   IN  UINT32           varAttr
   );

EFI_STATUS
BootOrderInsert(
	IN CHAR16 *OrderVarName,
	IN UINTN index,
	UINT16   value);

EFI_STATUS
BootOrderRemove(
	IN CHAR16 *OrderVarName,
	UINT16   value
	);

EFI_STATUS
BootOrderPresent(
    IN CHAR16 *OrderVarName,
    UINT16   value,
    UINTN     *index);

EFI_STATUS
BootMenuItemCreate(
	IN CHAR16     *VarName,
	IN CHAR16     *Desc,
	IN EFI_HANDLE volumeHandle,
	IN CHAR16     *Path,
	IN BOOLEAN    Reduced
	);

EFI_STATUS
BootMenuItemRemove(
	IN CHAR16     *VarName
	);



//////////////////////////////////////////////////////////////////////////
// File
//////////////////////////////////////////////////////////////////////////


extern EFI_FILE*      gFileRoot;
extern EFI_HANDLE     gFileRootHandle;

extern EFI_HANDLE* gFSHandles;
extern UINTN       gFSCount;

EFI_STATUS
InitFS();

EFI_STATUS
DirectoryCreate(
   IN    EFI_FILE*   root,
   IN    CHAR16*     name
   );
   
EFI_STATUS
DirectoryExists(
   IN    EFI_FILE*   root,
   IN    CHAR16*     name
   );

EFI_STATUS
FileOpenRoot(
   IN    EFI_HANDLE rootHandle,
   OUT   EFI_FILE** rootFile);

EFI_STATUS
FileOpen(
   IN    EFI_FILE*   root,
   IN    CHAR16*     name,
   OUT   EFI_FILE**  file,
   IN    UINT64      mode,
   IN    UINT64      attributes
   );

EFI_STATUS
FileClose(
   IN EFI_FILE* f);

EFI_STATUS
FileDelete(
   IN    EFI_FILE*   root,
   IN    CHAR16*     name
   );

EFI_STATUS
FileRead(
   IN       EFI_FILE*   f,
   OUT      VOID*       data,
   IN OUT   UINTN*      bytes,
   IN OUT   UINT64*     position);

EFI_STATUS
FileWrite(
   IN       EFI_FILE*   f,
   IN       VOID*       data,
   IN OUT   UINTN       bytes,
   IN OUT   UINT64*     position);

UINTN
FileAsciiPrint(
	IN EFI_FILE            *f,
	IN CONST CHAR8         *format,
	...
	);

EFI_STATUS
FileGetInfo(
   IN    EFI_FILE*         f,
   OUT   EFI_FILE_INFO**   info,
   OUT   UINTN*            size
   );

EFI_STATUS
FileGetSize(
   IN    EFI_FILE*   f,
   OUT   UINTN*     size
   );

EFI_STATUS
FileLoad(
   IN    EFI_FILE*   root,
   IN    CHAR16*     name,
   OUT   VOID**      data,
   OUT   UINTN*      size
   );

EFI_STATUS
FileSave(
   IN    EFI_FILE*   root,
   IN    CHAR16*     name,
   IN    VOID*       data,
   IN    UINTN      size
   );

EFI_STATUS
FileExist(
	IN    EFI_FILE*   root,
	IN    CHAR16*     name
	);

EFI_STATUS
FileRename(
	IN    EFI_FILE*   root,
	IN    CHAR16*     src,
	IN    CHAR16*     dst
	);

EFI_STATUS
FileCopy(
	IN    EFI_FILE*   srcroot,
	IN    CHAR16*     src,
	IN    EFI_FILE*   dstroot,
	IN    CHAR16*     dst,
	IN    UINTN       bufSz
	);

//////////////////////////////////////////////////////////////////////////
// File Picker
//////////////////////////////////////////////////////////////////////////

/**
 * Volume specification for custom volume lists
 */
typedef struct {
    EFI_HANDLE  Handle;       // Volume handle (must have SimpleFileSystem)
    CHAR16      *DisplayName; // Custom display name (NULL = auto-generate)
} FILE_PICKER_VOLUME;

/**
 * File picker configuration
 */
typedef struct {
    FILE_PICKER_VOLUME  *Volumes;      // Array of volumes (NULL = auto-discover from gFSHandles)
    UINTN               VolumeCount;   // Number of volumes (0 if auto-discover)
    CONST CHAR16        **Extensions;  // NULL-terminated array of extensions (e.g., {L".efi", NULL})
                                       // NULL = show all files
    CHAR16              *Title;        // Custom title (NULL = default)
} FILE_PICKER_CONFIG;

/**
 * Initialize file picker configuration with defaults
 */
VOID
FilePickerInitConfig(
    OUT FILE_PICKER_CONFIG  *Config
);

/**
 * Display file picker UI with full configuration
 *
 * @param[in]  Config          Configuration for the picker (NULL = use defaults)
 * @param[out] SelectedHandle  Receives the handle of the volume containing the selected file
 * @param[out] SelectedPath    Receives the allocated path string (caller must MEM_FREE)
 *
 * @retval EFI_SUCCESS              File was selected successfully
 * @retval EFI_DCS_USER_CANCELED    User pressed ESC to cancel
 * @retval EFI_NOT_FOUND            No accessible volumes found
 * @retval EFI_OUT_OF_RESOURCES     Memory allocation failed
 * @retval EFI_INVALID_PARAMETER    Output pointers are NULL
 */
EFI_STATUS
EFIAPI
FilePickerShow(
    IN  CONST FILE_PICKER_CONFIG  *Config   OPTIONAL,
    OUT EFI_HANDLE                *SelectedHandle,
    OUT CHAR16                    **SelectedPath
);

/**
 * Simplified file picker for common use cases
 *
 * @param[in]  Extensions       NULL-terminated array of extensions (e.g., {L".efi", NULL})
 *                              Pass NULL to show all files
 * @param[in]  Title            Title string for the picker UI (NULL for default)
 * @param[out] SelectedHandle   Receives the volume handle
 * @param[out] SelectedPath     Receives the allocated path (caller must MEM_FREE)
 */
EFI_STATUS
EFIAPI
FilePickerSelectFile(
    IN  CONST CHAR16  **Extensions    OPTIONAL,
    IN  CONST CHAR16  *Title          OPTIONAL,
    OUT EFI_HANDLE    *SelectedHandle,
    OUT CHAR16        **SelectedPath
);

//////////////////////////////////////////////////////////////////////////
// Exec
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
EfiExec(
   IN    EFI_HANDLE  deviceHandle,
   IN    CHAR16*     path
   );

EFI_STATUS
ConnectAllEfi(
   VOID
   );

VOID
EfiCpuHalt();


#endif
