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
#define DCS_VERSION 250 // 2.50

#define OPT_EXTERN_KEY L"-extern"

//////////////////////////////////////////////////////////////////////////
// Inter-module communication (DcsBoot <-> DcsInt)
//////////////////////////////////////////////////////////////////////////

//
// Configuration passed from DcsBoot to DcsInt via LoadOptions,
// and updated by DcsInt before returning to DcsBoot.
//
// DcsInt accepts a boot config only with this magic, this version and exactly this
// size - DcsBoot and DcsInt must come from the same build. Bump the version on any layout change.
#define DCS_BOOT_CONFIG_MAGIC    SIGNATURE_32('D', 'C', 'S', 'B')
#define DCS_BOOT_CONFIG_VERSION  2

typedef struct _DCS_BOOT_CONFIG {
    UINT32      Size;               // sizeof(DCS_BOOT_CONFIG) (first, where older builds read it)
    UINT32      Magic;              // DCS_BOOT_CONFIG_MAGIC
    UINT32      Version;            // DCS_BOOT_CONFIG_VERSION

    // Recovery mode (set by DcsInt to indicate recovery boot)
    BOOLEAN     ExternMode;

    // Set by DcsInt on a successful unlock: the user entered the password or a TPM /
    // recovery PIN - only then may DcsBoot open the recovery or boot menu. FALSE by default.
    BOOLEAN     UnlockInteractive;

    // Config file content (passed from DcsBoot, avoids double-read). The file is always
    // CONFIG_FILE_PATH; its name is not passed.
    CHAR8       *ConfigBuffer;      // Config file content
    UINTN       ConfigBufferSize;   // Size of config buffer

    // Exec parameters (replaces DcsExecPartGuid/DcsExecCmd variables)
    EFI_GUID    ExecPartGuid;       // Partition GUID to boot from
    CHAR16      ExecCmd[512];       // Boot command/path
} DCS_BOOT_CONFIG;

// Builds before the magic/version check accept any block of at least their own size,
// 1080 bytes on X64/AARCH64 - this layout (the flags packed after Version) stays smaller, so such
// a DcsInt refuses it and loads the config itself instead of misreading it. Keep it that way.
#if defined(MDE_CPU_X64) || defined(MDE_CPU_AARCH64)
STATIC_ASSERT(sizeof(DCS_BOOT_CONFIG) < 1080, "DCS_BOOT_CONFIG must stay smaller than the pre-#155 layout");
#endif

//
// Global pointer to boot config (set in DcsInt from LoadOptions)
//
extern DCS_BOOT_CONFIG *gDcsBootConfig;

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
BOOLEAN InitConfigFromBootConfig(IN DCS_BOOT_CONFIG *BootConfig);
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
EFI_STATUS CfgCopyUnmarked(CFG_STRING *S, CHAR8 *ConfigContent);
EFI_STATUS CfgLoadCurrent(CHAR8 **Content);
EFI_STATUS CfgReloadCurrent(VOID);

// VerboseDebug when the key is absent - one default for every module
#ifdef DEBUG_BUILD
#define DCS_VERBOSE_DEBUG_DEFAULT  1
#else
#define DCS_VERBOSE_DEBUG_DEFAULT  0
#endif
EFI_STATUS ConfigSave(CFG_STRING *NewConfig); 

BOOLEAN InitParams();

VOID SetCleanSensitiveDataFunc(void(*cleanSensitiveData)(BOOLEAN));
VOID CleanSensitiveData(BOOLEAN panic);

#endif
