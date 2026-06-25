#ifndef _DCSDISKCRYPTOR_H_
#define _DCSDISKCRYPTOR_H_

#include <Uefi.h>
#include <Library/PasswordLib.h>
#include "include/defines.h"
#include "include/volume_header.h"
#include "include/bootloader.h"
#include "include/dc_keyfiles.h"

#define DC_APP_NAME "DiskCryptor"

#define MAX_MSG 256

extern char*   gDCryptPasswordMsg;
extern int     gDCryptAuthRetry;

extern char*   gDCryptStartMsg;
extern char*   gDCryptSuccessMsg;
extern char*   gDCryptErrorMsg;

extern dc_pass gDCryptPassword; // entered password
extern int     gDCryptHeaderKdf;
extern int	   gDCryptKfMixer;

extern UINT8   gDCryptTpmSecret[DC_KF_HASH_SIZE];
extern BOOLEAN gDCryptTpmSecretValid;

extern UINT32  gDCryptTpmVersion;
extern UINT8   gDCryptTpmAskOwnerPw;

extern int     gDCryptTpmMode;
extern int     gDCryptTpmPcrMask;
extern int     gDCryptTpmStorage;
extern BOOLEAN gDCryptTpmPinUsed;
extern BOOLEAN gConfigDebug;

extern int     gKeyboardLayout;
extern int     gDCryptHwCrypto;
extern UINT8   gDCryptBootMode;
extern UINT8   gBlockUnencryptedVolumes;
extern UINT8   gDCryptHandoffMode;

enum AskPwdRetCodeEx {
	AskPwdCachePass = AskPwdRetCodeMax,
	AskPwdRetSetParams,
	AskPwdRetHelp,
	AskPwdRetSave,
};

enum DCryptKeyFile {
	DCryptNo = 0,
	DCryptEmbedded  = 1,
	DCryptUsbDrive  = 2,
	DCryptFilePicker= 3,
	DCryptPlatform  = 4,
	DCryptKeyFileMax
};

enum DCryptHwKey {
	DCryptNone = 0,
	DCryptTPM = 1,
	//DCryptUsbKey = 2, // todo: fido 2 or something like that
	DCryptHwKeyMax
};

enum DCryptTpmMode {
	DCryptTpmAuto = 0,      // Unattended unlock (PCR only)
	DCryptTpmPass = 1,      // Mix password with TPM secret after unseal
	DCryptTpmPin = 2,       // TPM-validated PIN required to unseal
	DCryptTpmPinPass = 3,   // Both: PIN to unseal, then mix with password
};

enum DCryptTpmStorage {
	DCryptTpmDefault = 0,
	DCryptTpmFile = 1,
	DCryptTpmNV = 2,
};

enum CryptPwPromptType {
	DCryptPwPromptNone = 0,
	DCryptPwPromptPassword,
	DCryptPwPromptTpmSecret,
	DCryptPwPromptBackup,
};

typedef struct _DCRYPT_PW_PROMPT
{
	int Type;
	int KeyFile;
	int HwKey;

} DCRYPT_PW_PROMPT, *PDCRYPT_PW_PROMPT;

EFI_STATUS
DcTpmLoad(CHAR16 *password, UINT32 *password_size);

EFI_STATUS
DcTpmMenu();

EFI_STATUS
DcTpmAskPcrMask(
	OUT UINT32  *PcrMask,
	IN  UINT32  DefaultMask
);

VOID
DCAuthLoadConfig();

BOOLEAN
AskYesNo(CHAR16 *Prompt, BOOLEAN DefaultYes);

EFI_STATUS DCFinalizePassword(dc_pass* pass, CHAR16* password, UINT32 password_size, int key_file, int hw_key, UINT8* data, UINT32 data_size);

INT32 HandleFuncKeys(EFI_INPUT_KEY key, VOID *Param);
VOID FormatStatus(CHAR16* statusStr, UINTN statusStrLen, VOID *Param);

EFI_STATUS
DcMain(
	IN OUT int* vol_found, 
	IN OUT int* hdr_found
	);



//////////////////////////////////////////////////////////////////////////
// DCS TPM
//////////////////////////////////////////////////////////////////////////

extern struct _EFI_DCS_TPM_PROTOCOL* gDcsTpm;

EFI_STATUS
InitDcsTpm();

#endif // _DCSDISKCRYPTOR_H_
