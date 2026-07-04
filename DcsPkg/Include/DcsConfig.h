/** @file
DCS configuration

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI
Copyright (c) 2019-2026. DiskCryptor, David Xanatos

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the Apache License, Version 2.0.

The full text of the license may be found at
https://opensource.org/licenses/Apache-2.0
**/

#ifndef __DCSCONFIG_H__
#define __DCSCONFIG_H__

#include <Uefi.h>

#define _T2(x) L##x
#define _T(x) _T2(x)

//////////////////////////////////////////////////////////////////////////
// Build Config
//////////////////////////////////////////////////////////////////////////

#define DCS_DIRECTORY L"DCS"

#define DCS_CAPTION "Disk Cryptor" //Disk Cryptography Services
#define DCS_VERSION 238 // 2.38

#define NO_BML

#define OPT_EXTERN_KEY L"-extern"

//////////////////////////////////////////////////////////////////////////
// Dynamic Config
//////////////////////////////////////////////////////////////////////////
#define CONFIG_FILE_PATH L"\\EFI\\" DCS_DIRECTORY L"\\DcsProp"

extern CHAR16  *gConfigFileName;
extern char    *gConfigBuffer;
extern UINTN    gConfigBufferSize;
extern char    *gConfigBufferUpdated;
extern UINTN    gConfigBufferUpdatedSize;
extern BOOLEAN  gConfigDebug;
extern BOOLEAN  gExternMode;

BOOLEAN InitConfig(CHAR16* configFileName);
BOOLEAN ConfigRead(char *configKey, char *configValue, int maxValueSize);
int ConfigReadInt(char *configKey, int defaultValue);
__int64 ConfigReadInt64(char *configKey, __int64 defaultValue);
char *ConfigReadString(char *configKey, char *defaultValue, char *str, int maxLen);
CHAR16 *ConfigReadStringW(char *configKey, CHAR16 *defaultValue, CHAR16 *str, int maxLen);

//////////////////////////////////////////////////////////////////////////
// Config String Builder for XML generation
//////////////////////////////////////////////////////////////////////////

typedef struct _CFG_STRING {
	CHAR8   *Str;
	UINTN    Len;
	UINTN    Size;
} CFG_STRING;

EFI_STATUS CfgStrInit(CFG_STRING *S, UINTN InitialSize);
VOID CfgStrFree(CFG_STRING *S);
EFI_STATUS CfgStrAppend(CFG_STRING *S, CONST CHAR8 *Str);

//////////////////////////////////////////////////////////////////////////
// Config XML Writing Functions
//////////////////////////////////////////////////////////////////////////

EFI_STATUS CfgWriteHeader(CFG_STRING *S);
EFI_STATUS CfgWriteFooter(CFG_STRING *S);
VOID CfgMarkUpdated(CHAR8 *ConfigContent, CONST CHAR8 *ConfigKey);
EFI_STATUS CfgWriteString(CFG_STRING *S, CHAR8 *ConfigContent, CONST CHAR8 *ConfigKey, CONST CHAR8 *ConfigValue);
EFI_STATUS CfgWriteInteger(CFG_STRING *S, CHAR8 *ConfigContent, CONST CHAR8 *ConfigKey, INT32 ConfigValue);
EFI_STATUS CfgWriteInteger64(CFG_STRING *S, CHAR8 *ConfigContent, CONST CHAR8 *ConfigKey, INT64 ConfigValue);
EFI_STATUS CfgWriteStringW(CFG_STRING *S, CHAR8 *ConfigContent, CONST CHAR8 *ConfigKey, CONST CHAR16 *ConfigValue);
EFI_STATUS ConfigSave(CFG_STRING *NewConfig); 

BOOLEAN InitParams();

VOID SetCleanSensitiveDataFunc(void(*cleanSensitiveData)(BOOLEAN));
VOID CleanSensitiveData(BOOLEAN panic);

#endif
