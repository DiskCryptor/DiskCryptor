/** @file
Password library

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI 
Copyright (c) 2019-2026. DiskCryptor, David Xanatos

This program and the accompanying materials are licensed and made available 
under the terms and conditions of the GNU Lesser General Public License, version 3.0 (LGPL-3.0).

The full text of the license may be found at
https://opensource.org/licenses/LGPL-3.0
**/

#ifndef __PASSWORDLIB_H__
#define __PASSWORDLIB_H__

#include <Uefi.h>
#include <Protocol/GraphicsOutput.h>

#define SET_VAR_CHAR(asciiLine, wide, pos, value) \
	if (wide) ((CHAR16*)asciiLine)[pos] = (CHAR16)(value); \
	else ((CHAR8*)asciiLine)[pos] = (CHAR8)(value);

#define GET_VAR_CHAR(asciiLine, wide, pos) \
	(wide ? ((CHAR16*)asciiLine)[pos] : ((CHAR8*)asciiLine)[pos])

extern CHAR16*	gPasswordPictureFileName;

extern CHAR8*	gPasswordPictureChars;
extern CHAR8*	gPasswordPictureCharsDefault;
extern UINTN	gPasswordPictureCharsLen;
extern UINT8	gPasswordVisible;
extern UINT8	gPasswordProgress;
extern int		gPasswordTimeout;

extern int		gPasswordHideLetters;
extern int		gPasswordShowMark;
extern VOID*	gPictPwdBmp;
extern UINTN	gPictPwdBmpSize;

extern int		gPlatformLocked;
extern int		gTPMLocked;
extern int		gTPMLockedInfoDelay;
extern int		gSCLocked;

enum AskPwdType {
	AskPwdLogin = 1,
	AskPwdNew,
	AskPwdConfirm
};

enum AskPwdRetCode {
	AskPwdRetStatus = -2,  // Update status line
	AskPwdRetNone   = -1,  // No action, continue
	AskPwdRetCancel = 0,
	AskPwdRetLogin  = 1,
	AskPwdRetChange = 2,
	AskPwdForcePass = 3,
	AskPwdRetTimeout= 4,
	AskPwdRetShow   = 5,
	AskPwdRetCodeMax
};

VOID
AskPictPwdInt(
	IN  UINTN	pwdType,
	IN  UINTN	pwdMax,
	OUT VOID*	pwd,
	OUT UINT32*	pwdLen,
	OUT INT32*	retCode,
	IN  BOOLEAN wide
	);

VOID
AskConsolePwdInt(
	IN  CONST char* msg,
	OUT UINT32   *length,
	OUT VOID     *asciiLine,
	OUT INT32    *retCode,
	IN  UINTN    length_max,
	IN  UINT8    show,
	IN  BOOLEAN  wide
	);

VOID
AskConsolePwdEx(
  IN  CONST char* msg,
  OUT UINT32   *length,
  OUT VOID     *asciiLine,
  OUT INT32    *retCode,
  IN  UINTN    length_max,
  IN  UINT8    show,
  IN  BOOLEAN  wide,
  IN  INT32 (*FuncHandler)(IN EFI_INPUT_KEY key, IN VOID *Param),
  IN  VOID (*GetStatus)(IN CHAR16* statusStr, IN UINTN statusStrLen, IN VOID *Param),
  IN  VOID *Param
  );

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
	);

extern EFI_GUID*                     gSmbSystemUUID;        // Universal unique ID 
extern CHAR8*                        gSmbSystemSerial;      // System serial
extern CHAR8*                        gSmbSystemSKU;         // SKU number
extern CHAR8*                        gSmbSystemManufacture;     // computer manufacturer
extern CHAR8*                        gSmbSystemModel;           // computer model
extern CHAR8*                        gSmbSystemVersion;         // computer version

extern CHAR8*                        gSmbBaseBoardSerial;       // Base board serial
extern UINT64*                       gSmbProcessorID;           // Processor ID

extern CHAR8*                        gSmbBiosVendor;           // BIOS vendor
extern CHAR8*                        gSmbBiosVersion;          // BIOS version
extern CHAR8*                        gSmbBiosDate;             // BIOS date

EFI_STATUS
SMBIOSGetSerials();

EFI_STATUS
PlatformGetID(
	IN  EFI_HANDLE  handle,
	OUT CHAR8       **id,
	OUT UINTN       *idLen
	);

EFI_STATUS
PlatformGetIDCRC(
	IN  EFI_HANDLE  handle,
	OUT UINT32      *crc32
	);

extern UINTN        gBioIndexAuth;
extern BOOLEAN gBioIndexAuthOnRemovable;

typedef struct _DCS_AUTH_DATA_MARK {
	UINT32     HeaderCrc;
	UINT32     PlatformCrc;
	UINT32     AuthDataSize;
	UINT32     Reserved;
} DCS_AUTH_DATA_MARK;


EFI_STATUS
PlatformGetAuthData(
	OUT UINT8      **data,
	OUT UINTN      *len,
	OUT EFI_HANDLE *secRegionHandle
	);

//////////////////////////////////////////////////////////////////////////
// Certificates
//////////////////////////////////////////////////////////////////////////
extern CHAR8* gDCS_platform_crt_der;

#endif
