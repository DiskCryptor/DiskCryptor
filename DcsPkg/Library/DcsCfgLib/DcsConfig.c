/** @file
Interface for DCS

Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
Copyright (c) 2016. VeraCrypt, Mounir IDRASSI
Copyright (c) 2019-2026. DiskCryptor, David Xanatos

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the Apache License, Version 2.0.

The full text of the license may be found at
https://opensource.org/licenses/Apache-2.0
**/

#include <Uefi.h>
#include <DcsConfig.h>

#include <Library/CommonLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>
#include "../Library/MiscUtilsLib/MiscUtilsLib.h"
#include "common/Xml.h"


//////////////////////////////////////////////////////////////////////////
// Config
//////////////////////////////////////////////////////////////////////////
CHAR16* gConfigFileName = NULL;

char *gConfigBuffer = NULL;
UINTN gConfigBufferSize = 0;
char *gConfigBufferUpdated = NULL;
UINTN gConfigBufferUpdatedSize = 0;

BOOLEAN gConfigDebug = FALSE;
BOOLEAN  gExternMode = FALSE;

//
// Boot config passed from DcsBoot via LoadOptions
//
DCS_BOOT_CONFIG *gDcsBootConfig = NULL;

BOOLEAN
InitConfig(CHAR16* configFileName)
{
	EFI_STATUS res;

	gConfigFileName = configFileName;

	if (gConfigBuffer) return TRUE;
	if (gConfigFileName == NULL) return FALSE;

	if (IsPxeBoot()) {
		res = PxeDownloadFile(gConfigFileName, &gConfigBuffer, &gConfigBufferSize);
	} else {
		res = FileLoad(NULL, gConfigFileName, &gConfigBuffer, &gConfigBufferSize);
	}
	if (EFI_ERROR(res)) {
		ERR_PRINT(L"Failed to load config file %r\n", res);
		return FALSE;
	}

#ifdef DEBUG_BUILD
	gConfigDebug = TRUE;
#else
	gConfigDebug = ConfigReadInt("VerboseDebug", 0) ? TRUE : FALSE;
#endif

	return TRUE;
}

/**
  Initialize config from DCS_BOOT_CONFIG passed via LoadOptions.

  @param[in] BootConfig  Pointer to boot config from caller.

  @retval TRUE   Config initialized successfully.
  @retval FALSE  Invalid or missing config.
**/
BOOLEAN
InitConfigFromBootConfig(
	IN DCS_BOOT_CONFIG *BootConfig
	)
{
	// only a boot config of this build (the caller checked the block's size)
	if (BootConfig == NULL || BootConfig->Magic != DCS_BOOT_CONFIG_MAGIC ||
		BootConfig->Version != DCS_BOOT_CONFIG_VERSION || BootConfig->Size != sizeof(DCS_BOOT_CONFIG)) {
		return FALSE;
	}

	// Store pointer to boot config for later updates
	gDcsBootConfig = BootConfig;

	// Use config buffer from caller (avoids re-reading file); the file is always CONFIG_FILE_PATH
	gConfigFileName = CONFIG_FILE_PATH;
	gConfigBuffer = BootConfig->ConfigBuffer;
	gConfigBufferSize = BootConfig->ConfigBufferSize;

	gExternMode = BootConfig->ExternMode;

	gConfigDebug = ConfigReadInt("VerboseDebug", DCS_VERBOSE_DEBUG_DEFAULT) ? TRUE : FALSE;

	return TRUE;
}

BOOLEAN
ConfigRead(char *configKey, char *configValue, int maxValueSize)
{
	char *xml;

	if (gConfigFileName == NULL) {
		ERR_PRINT(L"Config was not initialized!\n"); 
		//if (FileLoad(NULL, L"\\EFI\\VeraCrypt\\DcsProp", &gConfigBuffer, &gConfigBufferSize) != EFI_SUCCESS) {
		return FALSE;
		//}
	}

	xml = gConfigBufferUpdated != NULL? gConfigBufferUpdated : gConfigBuffer;
	if (xml != NULL)
	{
		xml = XmlFindElementByAttributeValue(xml, "config", "key", configKey);
		if (xml != NULL)
		{
			XmlGetNodeText(xml, configValue, maxValueSize);
			return TRUE;
		}
	}

	return FALSE;
}

int ConfigReadInt(char *configKey, int defaultValue)
{
	char s[32];
	if (ConfigRead(configKey, s, sizeof(s))) {
		if (*s == '-') {
			return (-1) * (int)AsciiStrDecimalToUintn(&s[1]);
		}
		return (int)AsciiStrDecimalToUintn(s);
	}
	else
		return defaultValue;
}

__int64 ConfigReadInt64(char *configKey, __int64 defaultValue)
{
	char s[32];
	if (ConfigRead(configKey, s, sizeof(s))) {
		if (*s == '-') {
			return -(__int64)AsciiStrDecimalToUint64(&s[1]); // __allmul is not available
		}
		return (__int64)AsciiStrDecimalToUint64(s);
	}
	else
		return defaultValue;
}

char *ConfigReadString(char *configKey, char *defaultValue, char *str, int maxLen)
{
	if (str == NULL) {
		str = MEM_ALLOC(maxLen);
	}

	if (!ConfigRead(configKey, str, maxLen)) {
		AsciiStrCpyS(str, maxLen, defaultValue);
	}
	return str;
}

CHAR16 *ConfigReadStringW(char *configKey, CHAR16 *defaultValue, CHAR16 *str, int maxLen)
{
	char* strTemp = NULL;

	if (str == NULL) {
		str = MEM_ALLOC(maxLen * sizeof(CHAR16));
	}

	strTemp = MEM_ALLOC(maxLen);
	if (!ConfigRead(configKey, strTemp, maxLen)) {
		StrCpyS(str, maxLen, defaultValue);
	}
	else {
		AsciiStrToUnicodeStrS(strTemp, str, maxLen);
	}
	MEM_FREE(strTemp);

	return str;
}

BOOLEAN 
InitParams()
{
	EFI_STATUS res;
	CHAR16*    cmd = NULL;
	UINTN      cmdSize;
	UINT32     cmdAttr;

	res = EfiGetVar(L"DcsExecMode", NULL, &cmd, &cmdSize, &cmdAttr);
	if (!EFI_ERROR(res)) {
		EfiSetVar(L"DcsExecMode", NULL, NULL, 0, cmdAttr); // clear variable
		// Only DcsRe's volatile BS-only variable counts; the OS can create NV/RT ones
		if (cmd != NULL && cmdAttr == EFI_VARIABLE_BOOTSERVICE_ACCESS &&
			cmdSize >= sizeof(CHAR16) && (cmdSize % sizeof(CHAR16)) == 0 &&
			cmd[cmdSize / sizeof(CHAR16) - 1] == 0 &&
			StrStr(cmd, OPT_EXTERN_KEY) != NULL) {
			gExternMode = TRUE;
		}
	}
	MEM_FREE(cmd);

	return TRUE;
}


void(*gCleanSensitiveData)(BOOLEAN) = NULL;

VOID SetCleanSensitiveDataFunc(void(*cleanSensitiveData)(BOOLEAN))
{
	gCleanSensitiveData = cleanSensitiveData;
}

VOID CleanSensitiveData(BOOLEAN panic)
{
	if (!gCleanSensitiveData) {
		// we can't print from here as in some cases (VirtualNotifyEvent) this will crash the system!!!
		//ERR_PRINT(L"Can't Clean Sensitive Data from RAM!!!");
		return;
	}
	gCleanSensitiveData(panic);
}

//////////////////////////////////////////////////////////////////////////
// Config String Builder for XML generation
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
CfgStrInit(
	CFG_STRING *S,
	UINTN       InitialSize
)
{
	S->Size = InitialSize;
	S->Len = 0;
	S->Str = MEM_ALLOC(S->Size);
	if (S->Str == NULL)
		return EFI_OUT_OF_RESOURCES;
	S->Str[0] = '\0';
	return EFI_SUCCESS;
}

VOID
CfgStrFree(
	CFG_STRING *S
)
{
	if (S->Str != NULL) {
		MEM_FREE(S->Str);
		S->Str = NULL;
	}
	S->Len = 0;
	S->Size = 0;
}

// Append len bytes of Str (need not be NUL-terminated)
STATIC
EFI_STATUS
CfgStrAppendN(
	CFG_STRING  *S,
	CONST CHAR8 *Str,
	UINTN        len
)
{
	if (S->Len + len + 1 > S->Size) {
		UINTN newSize = S->Size * 2;
		CHAR8 *newStr;
		if (S->Len + len + 1 > newSize)
			newSize = S->Len + len + 1;
		newStr = MEM_ALLOC(newSize);
		if (newStr == NULL)
			return EFI_OUT_OF_RESOURCES;
		CopyMem(newStr, S->Str, S->Len + 1);
		MEM_FREE(S->Str);
		S->Str = newStr;
		S->Size = newSize;
	}

	CopyMem(S->Str + S->Len, Str, len);
	S->Len += len;
	S->Str[S->Len] = '\0';
	return EFI_SUCCESS;
}

EFI_STATUS
CfgStrAppend(
	CFG_STRING  *S,
	CONST CHAR8 *Str
)
{
	return CfgStrAppendN(S, Str, AsciiStrLen(Str));
}

// Element text with &, < and > encoded, as XmlGetNodeText decodes it
STATIC
EFI_STATUS
CfgStrAppendQuoted(
	CFG_STRING  *S,
	CONST CHAR8 *Str
)
{
	EFI_STATUS   Status;
	CONST CHAR8 *Run = Str;
	CONST CHAR8 *Ent;

	for (; *Str != '\0'; Str++) {
		Ent = (*Str == '&') ? "&amp;" : (*Str == '<') ? "&lt;" : (*Str == '>') ? "&gt;" : NULL;
		if (Ent == NULL) continue;
		Status = CfgStrAppendN(S, Run, (UINTN)(Str - Run));
		if (EFI_ERROR(Status)) return Status;
		Status = CfgStrAppend(S, Ent);
		if (EFI_ERROR(Status)) return Status;
		Run = Str + 1;
	}
	return CfgStrAppendN(S, Run, (UINTN)(Str - Run));
}

//////////////////////////////////////////////////////////////////////////
// Config XML Writing Functions
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
CfgWriteHeader(
	CFG_STRING *S
)
{
	return CfgStrAppend(S, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<DiskCrypto>\n\t<configuration>");
}

EFI_STATUS
CfgWriteFooter(
	CFG_STRING *S
)
{
	return CfgStrAppend(S, "\n\t</configuration>\n</DiskCrypto>\n");
}

// Mark a config value as updated in the original content (so it won't be copied again)
VOID
CfgMarkUpdated(
	CHAR8       *ConfigContent,
	CONST CHAR8 *ConfigKey
)
{
	if (ConfigContent != NULL) {
		CHAR8 *c = XmlFindElementByAttributeValue(ConfigContent, "config", "key", ConfigKey);
		if (c != NULL)
			c[1] = '!';  // Mark as updated by changing <config to <!onfig
	}
}

EFI_STATUS
CfgWriteString(
	CFG_STRING  *S,
	CHAR8       *ConfigContent,
	CONST CHAR8 *ConfigKey,
	CONST CHAR8 *ConfigValue
)
{
	EFI_STATUS Status;

	CfgMarkUpdated(ConfigContent, ConfigKey);

	Status = CfgStrAppend(S, "\n\t\t<config key=\"");
	if (EFI_ERROR(Status)) return Status;

	Status = CfgStrAppend(S, ConfigKey);
	if (EFI_ERROR(Status)) return Status;

	Status = CfgStrAppend(S, "\">");
	if (EFI_ERROR(Status)) return Status;

	Status = CfgStrAppendQuoted(S, ConfigValue);   // encoded, read back as written
	if (EFI_ERROR(Status)) return Status;

	Status = CfgStrAppend(S, "</config>");
	return Status;
}

/**
  The config file as it is now, so a save builds on what another module saved in this boot.

  @param[out] Content  NUL-terminated buffer (MEM_FREE); NULL if there was no config at boot and none now.
  @retval other        A config existed at boot but cannot be read now - the save must not go ahead.
**/
EFI_STATUS
CfgLoadCurrent(
	OUT CHAR8  **Content
)
{
	EFI_STATUS  res = EFI_NOT_FOUND;
	VOID       *Buf = NULL;
	UINTN       Size = 0;

	*Content = NULL;
	if (gConfigFileName != NULL) {
		if (IsPxeBoot()) {
			res = PxeDownloadFile(gConfigFileName, &Buf, &Size);
		} else {
			res = FileLoad(NULL, gConfigFileName, &Buf, &Size);
		}
	}
	if (!EFI_ERROR(res) && Buf != NULL) {
		*Content = MEM_ALLOC(Size + 1);
		if (*Content != NULL) {
			CopyMem(*Content, Buf, Size);
			(*Content)[Size] = '\0';
		}
	}
	if (Buf != NULL) {
		MEM_FREE(Buf);
	}
	if (*Content != NULL) {
		return EFI_SUCCESS;
	}
	if (gConfigBufferUpdated == NULL && gConfigBuffer == NULL) {
		return EFI_SUCCESS;   // no config at boot, none readable now
	}
	return EFI_NOT_READY;
}

/**
  Make the config as it is now this module's copy (as ConfigSave does), so a menu
  shows what another module saved in this boot.
**/
EFI_STATUS
CfgReloadCurrent(
	VOID
)
{
	CHAR8      *Content = NULL;
	EFI_STATUS  Status = CfgLoadCurrent(&Content);

	if (EFI_ERROR(Status) || Content == NULL) {
		return EFI_ERROR(Status) ? Status : EFI_NOT_FOUND;   // the module keeps its copy
	}
	if (gConfigBufferUpdated != NULL) {
		MEM_FREE(gConfigBufferUpdated);
	}
	gConfigBufferUpdated = Content;
	gConfigBufferUpdatedSize = AsciiStrLen(Content);
	return EFI_SUCCESS;
}

/**
  Copy every <config> element of ConfigContent that CfgWrite* did not replace (those
  are marked "<!onfig") byte for byte - nothing decoded and re-encoded, nothing too long to
  drop. A malformed element (no end) fails the save instead of writing a damaged file.
**/
EFI_STATUS
CfgCopyUnmarked(
	CFG_STRING  *S,
	CHAR8       *ConfigContent
)
{
	EFI_STATUS  Status;
	CHAR8      *Xml;
	CHAR8      *Gt;
	CHAR8      *End;

	if (ConfigContent == NULL) return EFI_SUCCESS;

	Xml = ConfigContent;
	while ((Xml = XmlFindElement(Xml, "config")) != NULL) {
		Gt = AsciiStrStr(Xml, ">");
		if (Gt == NULL) return EFI_COMPROMISED_DATA;
		if (Gt[-1] == '/') {
			End = Gt + 1;                                  // <config key="..."/>
		} else {
			End = AsciiStrStr(Gt, "</config>");
			if (End == NULL) return EFI_COMPROMISED_DATA;
			End += sizeof("</config>") - 1;
		}

		Status = CfgStrAppend(S, "\n\t\t");
		if (EFI_ERROR(Status)) return Status;
		Status = CfgStrAppendN(S, Xml, (UINTN)(End - Xml));
		if (EFI_ERROR(Status)) return Status;

		Xml = End;
	}
	return EFI_SUCCESS;
}

EFI_STATUS
CfgWriteInteger(
	CFG_STRING  *S,
	CHAR8       *ConfigContent,
	CONST CHAR8 *ConfigKey,
	INT32        ConfigValue
)
{
	CHAR8 ValBuf[32];

	if (ConfigValue < 0) {
		ValBuf[0] = '-';
		AsciiValueToStringS(ValBuf + 1, sizeof(ValBuf) - 1, 0, -ConfigValue, 0);
	} else {
		AsciiValueToStringS(ValBuf, sizeof(ValBuf), 0, ConfigValue, 0);
	}

	return CfgWriteString(S, ConfigContent, ConfigKey, ValBuf);
}

EFI_STATUS
CfgWriteInteger64(
	CFG_STRING  *S,
	CHAR8       *ConfigContent,
	CONST CHAR8 *ConfigKey,
	INT64        ConfigValue
)
{
	CHAR8 ValBuf[32];

	if (ConfigValue < 0) {
		ValBuf[0] = '-';
		AsciiValueToStringS(ValBuf + 1, sizeof(ValBuf) - 1, 0, (UINT64)(-ConfigValue), 0);
	} else {
		AsciiValueToStringS(ValBuf, sizeof(ValBuf), 0, (UINT64)ConfigValue, 0);
	}

	return CfgWriteString(S, ConfigContent, ConfigKey, ValBuf);
}

EFI_STATUS
CfgWriteStringW(
	CFG_STRING   *S,
	CHAR8        *ConfigContent,
	CONST CHAR8  *ConfigKey,
	CONST CHAR16 *ConfigValue
)
{
	EFI_STATUS  Status;
	UINTN       Len;
	CHAR8      *AsciiValue;

	if (ConfigValue == NULL) {
		return CfgWriteString(S, ConfigContent, ConfigKey, "");
	}

	Len = StrLen(ConfigValue);
	AsciiValue = MEM_ALLOC(Len + 1);
	if (AsciiValue == NULL) {
		return EFI_OUT_OF_RESOURCES;
	}

	UnicodeStrToAsciiStrS(ConfigValue, AsciiValue, Len + 1);
	Status = CfgWriteString(S, ConfigContent, ConfigKey, AsciiValue);
	MEM_FREE(AsciiValue);

	return Status;
}

//////////////////////////////////////////////////////////////////////////
// Config Save Function
//////////////////////////////////////////////////////////////////////////

EFI_STATUS
ConfigSave(
	CFG_STRING *NewConfig
)
{
	EFI_STATUS Status;
	EFI_FILE  *Root = NULL;

	// Check if config was initialized
	if (gConfigFileName == NULL) {
		ERR_PRINT(L"Config not initialized, cannot save.\n");
		return EFI_NOT_READY;
	}

	// Save to config file (PXE or local file system)
	if (IsPxeBoot()) {
		Status = PxeUploadFile(gConfigFileName, NewConfig->Str, NewConfig->Len);
		if (EFI_ERROR(Status)) {
			ERR_PRINT(L"Failed to upload config via PXE: %r\n", Status);
			return Status;
		}
	} else {
		// Open root file system
		Status = FileOpenRoot(gFileRootHandle, &Root);
		if (EFI_ERROR(Status)) {
			ERR_PRINT(L"Failed to open root: %r\n", Status);
			return Status;
		}

		// Save to config file
		Status = FileSave(Root, gConfigFileName, NewConfig->Str, NewConfig->Len);
		FileClose(Root);
		if (EFI_ERROR(Status)) {
			ERR_PRINT(L"Failed to save config: %r\n", Status);
			return Status;
		}
	}

	// Update the in-memory config buffer so subsequent reads see the new values
	if (gConfigBufferUpdated != NULL) {
		MEM_FREE(gConfigBufferUpdated);
	}
	gConfigBufferUpdated = MEM_ALLOC(NewConfig->Len + 1);
	if (gConfigBufferUpdated != NULL) {
		CopyMem(gConfigBufferUpdated, NewConfig->Str, NewConfig->Len + 1);
		gConfigBufferUpdatedSize = NewConfig->Len;
	}

	return EFI_SUCCESS;
}
