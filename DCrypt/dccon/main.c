/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2019-2026
	* DavidXanatos <info@diskcryptor.org>
	* Copyright (c) 2008-2010 
	* ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
    *

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 3 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include "defines.h"
#include "main.h"
#include "version.h"
#include "boot_menu.h"
#include "misc.h"
#include "mbrinst.h"
#include "efiinst.h"
#include "gpt_sup.h"
#include "drv_ioctl.h"
#include "drvinst.h"
#include "rand.h"
#include "keyfiles.h"
#include "cd_enc.h"
#include "bootloader.h"
#include "console.h"
#include "w10.h"
#include "benchmark.h"
#include "shadow.h"
#include "dc_header.h"
#include "cert_utils.h"
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

typedef struct _bench_item {
	wchar_t *alg;
	double   speed;

} bench_item;

/* Global abort flag for cancelling KDF operations */
static volatile LONG g_abort_operation = 0;

static BOOL WINAPI console_ctrl_handler(DWORD ctrl_type)
{
	switch (ctrl_type) {
		case CTRL_C_EVENT:
		case CTRL_BREAK_EVENT:
			wprintf(L"\nCancelling operation...\n");
			InterlockedExchange(&g_abort_operation, 1);
			return TRUE;
		case CTRL_CLOSE_EVENT:
		case CTRL_LOGOFF_EVENT:
		case CTRL_SHUTDOWN_EVENT:
			InterlockedExchange(&g_abort_operation, 1);
			return FALSE;
	}
	return FALSE;
}

       vol_inf   volumes[MAX_VOLUMES];
       u32       vol_cnt;
extern int       g_argc;
extern wchar_t **g_argv;
static int       rng_inited;
static wchar_t   boot_dev[MAX_PATH];

static void print_usage(int subject)
{
	wprintf(
		L"DiskCryptor (c) <info@diskcryptor.org>\n"
		L"\n"
		L"Usage: dccon ...\n"
		L"________________________________________________________________________________\n"
		L"\n");
	if (subject & 0x01) wprintf(
		L" -enum                           Enum all volume devices in system\n"
		L" -info [dev]                     Display information about device\n"
		L" -version                        Display DiskCryptor version\n"
		L" -benchmark [-um]                Encryption benchmark (-um for user-mode)\n"
		L" -benchmark_kdf [-um]            KDF benchmark (-um for user-mode)\n"
		L" -config                         Change program configuration\n"
		L" -keygen [file]                  Make 64 bytes random keyfile\n"
		L" -bsod                           Erase all keys in memory and generate BSOD\n"
		L"________________________________________________________________________________\n"
		L"\n"
		L" -addpass [param]                Add password to password cache\n"
		L"    -p  [password]               Get password from command line\n"
		L"    -kf [keyfiles path]          Use keyfiles\n"
		L" -clean                          Wipe cached passwords in memory\n"
		L"________________________________________________________________________________\n"
		L"\n"
		L" -mount [dev] [param]            Mount encrypted device, or unlock a locked one\n"
		L"    -mp [mount point]            Add volume mount point\n"
		L"    -p  [password]               Get password from command line\n"
		L"    -kdf [key derivation]        KDF type: 0 - PBKDF2, 1-10 - Argon2id\n"
		L"    -kf [keyfiles path]          Use keyfiles\n"
		L"    -ro						   Mount volume read-only\n"
		L"    -no_hiber 				   Lock on hibernation (erase keys, unlock on resume)\n"
		L"    -ignore_crc                  Header damaged (checksum error) and not repairable from\n"
		L"                                 the backup header: mount it as it is, read-only, to\n"
		L"                                 copy the data (no header write, no transcryption)\n"
		L" -mountall [param]               Mount all encrypted devices\n"
		L"    -p  [password]               Get password from command line\n"
		L"    -kdf [key derivation]        KDF type: 0 - PBKDF2, 1-10 - Argon2id\n"
		L"    -kf [keyfiles path]          Use keyfiles\n"
		L" -unmount [dev] [param]          Unmount encrypted device\n"
		L"    -f                           Force unmount and close all opened files\n"
		L"    -dp                          Delete volume mount point\n"
		L" -unmountall                     Force unmount all devices\n"
		L"________________________________________________________________________________\n"
		L"\n"
		L" -encrypt [dev] [param]          Encrypt volume device\n"
		L"    -p  [password]               Get password from command line\n"
		L"    -kdf [key derivation]        KDF type: 0 - PBKDF2, 1-10 - Argon2id\n"
		L"    -kf [keyfiles path]          Use keyfiles\n"
		L"             ======  Cipher settings:   ======\n"
		L"    -a                           AES cipher\n"
		L"    -t                           Twofish cipher\n"
		L"    -s                           Serpent cipher\n"
		L"    -at                          AES-Twofish ciphers chain\n"
		L"    -ts                          Twofish-Serpent ciphers chain\n"
		L"    -sa                          Serpent-AES ciphers chain\n"
		L"    -ats                         AES-Twofish-Serpent ciphers chain\n"
		L"             ======  Original data wipe settings:  ======\n"
		L"    -dod_e                       US DoD 5220.22-M (8-306./E)          (3 passes)\n"
		L"    -dod                         US DoD 5220.22-M (8-306./E, C and E) (7 passes)\n"
		L"    -g                           Gutmann mode                         (35 passes)\n"
		L"    -skip                        Skip unused sectors (experimental)\n"
		L"    -delshadows                  Skipping unused sectors (-skip, or resuming such an operation):\n"
		L"                                 delete the volume's shadow copies without asking\n"
		L"    -keepshadows                 ... keep them without asking (they may become corrupt);\n"
		L"                                 without either option dccon asks on the console\n"
		L"             ======  Power-loss protection:  ======\n"
		L"    -safefast                    Journal checksums (default): fast; a sector torn by a\n"
		L"                                 power loss is detected, not repaired (reads as zeros)\n"
		L"    -safe                        Journal a copy of every block, slower; repairs it\n"
		L"    -nosafe                      No power-loss protection\n"
		L"                                 (v2 headers only, not for -format / -enciso)\n"
		L" -encrypt2                       Start prepared system volume encryption\n"
		L" -decrypt [dev] [param]          Decrypt volume device\n"
		L"    -p  [password]               Get password from command line\n"
		L"    -kdf [key derivation]        KDF type: 0 - PBKDF2, 1-10 - Argon2id\n"
		L"    -kf [keyfiles path]          Use keyfiles\n"
		L"    -safefast / -safe / -nosafe  Power-loss protection: checksums (default) / copies / off\n"
		L" -reencrypt [dev] [param]        Re-encrypt device with new parameters,\n"
		L"                                 parameters are equal to -encrypt\n"
		L" -format [dev] [param]           Format volume device with encryption,\n"
		L"                                 parameters are equal to -encrypt\n"
		L"    -q                           Quick format\n"
		L"    -fat                         Format to FAT file system\n"
		L"    -fat32                       Format to FAT32 file system\n"
		L"    -exfat                       Format to exFAT file system\n"
		L"    -ntfs                        Format to NTFS file system\n"
		L"    -raw                         File system does not needed\n"
		L" -enciso [src] [dst] [param]     Encrypt .iso image,\n"
		L"                                 parameters are equal to -encrypt\n"
		L"    -src                         Source file\n"
		L"    -dst                         Destination file\n"
		L"________________________________________________________________________________\n"
		L"\n"
		L" -chpass [dev] [param]           Change volume password\n"
		L"    -op  [password]              Get old password from command line\n"
		L"    -okdf [key derivation]       Old KDF type: 0 - PBKDF2, 1-10 - Argon2id\n"
		L"    -np  [password]              Get new password from command line\n"
		L"    -nkdf [key derivation]       New KDF type: 0 - PBKDF2, 1-10 - Argon2id\n"
		L"    -okf [keyfiles path]         Old keyfiles\n"
		L"    -nkf [keyfiles path]         New keyfiles\n"
		L" -backup [dev] [file] [param]    Backup volume header to file\n"
		L"    -p  [password]               Get password from command line\n"
		L"    -kdf [key derivation]        KDF type: 0 - PBKDF2, 1-10 - Argon2id\n"
		L"    -kf [keyfiles path]          Use keyfiles\n"
		L" -restore [dev] [file] [param]   Restore volume header from file\n"
		L"    -p  [password]               Get password from command line\n"
		L"    -kdf [key derivation]        KDF type: 0 - PBKDF2, 1-10 - Argon2id\n"
		L"    -kf [keyfiles path]          Use keyfiles\n"
		L"________________________________________________________________________________\n"
		L"\n");
	if (subject == 0x01) wprintf(
		L"Bootloader and UEFI/SecureBoot management:\n"
		L" -boot [action]                  Bootloader installation and configuration\n"
		L" -efi [action]                   UEFI variables and Secure Boot management\n"
		L" -mok [action]                   Shim MOK management (enroll, list, delete)\n"
		L"\n"
		L"Support certificate management:\n"
		L" -support [action]               Support certificate management\n"
		L"    -get_key [serial]            Download certificate using serial key\n"
		L"                                 (format: DC20X-XXXXX-XXXXX-XXXXX-XXXXX)\n"
		L"    -apply_cert                  Apply certificate.dat to registry\n"
		L"    -show                        Show current certificate\n"
		L"    -hwid                        Display hardware UUID\n"
		L"\n"
		L"________________________________________________________________________________\n"
		L"\n");
	if (subject & 0x02) wprintf(
		L" -boot [action]\n"
		L"    -mode                        Show boot mode (MBR/EFI [SecureBoot])\n"
		L"    -enum                        Enumerate all HDDs\n"
		L"    -config  [hdd/file]          Change bootloader configuration\n"
		L"  MBR (or legacy CSM) boot:\n"
		L"    -setmbr  [hdd] [opt]         Setup bootloader to HDD master boot record\n"
		L"    -updmbr  [hdd]               Update bootloader on HDD master boot record\n"
		L"    -delmbr  [hdd]               Delete bootloader from HDD master boot record\n"
		L"    -setpar  [root par] [opt]    Setup bootloader to bootable partition\n"
		L"    -makeiso [file] [opt]        Make bootloader image (.iso)\n"
		L"    -makepxe [file] [opt]        Make bootloader image for PXE network booting\n"
		L"    -small                       Use small bootloader, only with AES\n"
		L"  EFI boot:\n"
		L"    -setefi  [hdd] [opt]         Setup DCS bootloader to HDD EFI partition\n"
		L"		-shim                      Force adding shim loader for secure boot\n"
		L"		-noshim                    Don't add shim loader for secure boot, even when needed\n"
		L"		-bme                       Add boot menu entry\n"
		L"		-nobme                     Don't add boot menu entry\n"
		L"		-esp                       Create dedicated DCS ESP partition (allows encrypting Windows ESP)\n"
		L"		-noesp                     Use Windows ESP (default, cannot encrypt it)\n"
		L"    -updefi  [hdd]               Update DCS bootloader on HDD EFI partition\n"
		L"    -delefi  [hdd] [opt]         Delete DCS bootloader from HDD EFI partition\n"
		L"		-esp                       Also delete DCS ESP partition\n"
		L"    -getinfo [hdd]               Print collected PlatformInfo file to console\n"
		L"    -setshim [hdd] [opt]         Install Secure Boot shim on HDD EFI partition\n"
		L"		-bme                       Create boot menu entry pointing to shim\n"
		L"		-nobme                     Remove boot menu entry if pointing to shim\n"
		L"    -delshim [hdd] [opt]         Remove Secure Boot shim from HDD EFI partition\n"
		L"		-bme                       Create boot menu entry pointing to DcsBoot.efi\n"
		L"		-nobme                     Remove boot menu entry if pointing to shim\n"
		L"    -addbme  [hdd]               Add DCS entry to EFI boot menu\n"
		L"    -rembme                      Remove DCS entry from EFI boot menu\n"
		L"    -replacems [hdd]             Replace Windows Boot Manager with DCS loader\n"
		L"    -restorems [hdd]             Restore Windows Boot Manager file (bootmgfw.efi)\n"
		L"    -removems                    Remove Windows Boot Manager EFI boot entry\n"
		L"    -mountesp [letter]           Mount dedicated DCS ESP to drive letter\n"
		L"                                    to dismount use mountvol.exe [letter] /D\n"
		//L"    -umountesp [letter]          Unmount dedicated DCS ESP from drive letter\n"
		L"    -makerec [root par] [opt]    Setup EFI recovery DCS to bootable partition\n"
		L"    -mkefiiso [file] [opt]       Make EFI bootloader image (.iso)\n"
		L"    -mkefipxe [dir] [opt]        Make EFI bootloader image for PXE network booting\n"
		L"________________________________________________________________________________\n"
		L"\n");
	if (subject & 0x04) wprintf(
		L" -efi [action]\n"
		L"  EFI variables:\n"
		L"    -list                        List all EFI variables (name and GUID)\n"
		L"    -get [name] [opt]            Get EFI variable value\n"
		L"       -guid [guid]              Variable GUID (default: global EFI GUID)\n"
		L"       -file [path]              Save to file\n"
		L"       -dmp_hex                  Hex dump to screen\n"
		L"    -set [name] [opt]            Set EFI variable value\n"
		L"       -guid [guid]              Variable GUID (default: global EFI GUID)\n"
		L"       -file [path]              Load value from file\n"
		L"       -data [string]            Set value from command line\n"
		L"    -del [name] [opt]            Delete EFI variable\n"
		L"       -guid [guid]              Variable GUID (default: global EFI GUID)\n"
		L"  Secure Boot signature database tools:\n"
		L"    -sb_info                     Show SecureBoot status and whether DCS EFI loader is properly signed\n"
		L"    -dump -file [path]           List certificates (CN) and hashes from signature DB\n"
		L"    -extract [opt]               Extract signatures from EFI signature database\n"
		L"       -file [path]              Input file (e.g., exported db, dbx, KEK)\n"
		L"       -dir [path]               Output directory for extracted files\n"
		L"    -pack [opt]                  Pack signatures into EFI signature database\n"
		L"       -dir [path]               Input directory with signature files\n"
		L"       -file [path]              Output file\n"
		L"    -sb_set [opt]                Set authenticated Secure Boot variable (signed)\n"
		L"       -name [var]               Variable name (PK, KEK, db, dbx, dbt, dbr)\n"
		L"       -guid [guid]              Variable GUID (auto-selected if not specified)\n"
		L"       -file [path]              Content file (signature database)\n"
		L"       -cert [path]              PFX certificate for signing (KEK or PK)\n"
		L"       -pass [password]          PFX password (will prompt if not provided)\n"
		L"       -append                   Append to existing variable instead of replace\n"
		L"  Secure Boot overrides (DcsOwner EFI module):\n"
		L"    -sb_override <none|off|on>   Overwrite SecureBoot status reported to windows\n"
		L"    -sb_set_pk [path]            Overwrite PK with own Platform Key\n"
		L"    -sb_clear_pk                 Clear own Platform Key\n"
		L"________________________________________________________________________________\n"
		L"\n");
	if (subject & 0x08) wprintf(
		L" -mok [action]\n"
		L"  MOK certificate management:\n"
		L"    -list                        List enrolled MOK certificates (MokListRT)\n"
		L"       -new                      List pending enrollment requests (MokNew)\n"
		L"       -del                      List pending deletion requests (MokDel)\n"
		L"       -x                        Use blacklist (MokListXRT/MokXNew/MokXDel)\n"
		L"       -pk                       List Platform Key\n"
		L"       -kek                      List Key Exchange Keys\n"
		L"       -db                       List signature database\n"
		L"       -dbx                      List signature blacklist\n"
		L"       -all                      List all UEFI databases\n"
		L"    -import <file...> [-x]       Import DER certificate(s) into MOK\n"
		L"    -delete <file...> [-x]       Request deletion of certificate(s)\n"
		L"    -import-hash <hash> [-x]     Import hash into MOK\n"
		L"    -delete-hash <hash> [-x]     Request hash deletion from MOK\n"
		L"    -export -dir <path> [-x]     Export enrolled certs to DER files\n"
		L"    -revoke-import               Revoke pending enrollment request\n"
		L"    -revoke-delete               Revoke pending deletion request\n"
		L"    -reset [-x]                  Clear entire MOK list\n"
		L"    -test <file>                 Test if certificate is enrolled\n"
		L"  Password & authentication:\n"
		L"    -password                    Set MOK password\n"
		L"    -clear-password              Clear MOK password\n"
		L"    -generate-hash [-p pass]     Generate password hash\n"
		L"  Secure Boot state:\n"
		L"    -sb-state                    Show SecureBoot and shim validation state\n"
		L"    -enable-validation           Enable shim signature validation\n"
		L"    -disable-validation          Disable shim signature validation\n"
		L"    -use-db                      Enable use of db for validation\n"
		L"    -ignore-db                   Disable use of db for validation\n"
		//L"  SBAT policy:\n"
		//L"    -sbat                        List SBAT revocation entries\n"
		//L"    -sbat-policy <val>           Set SBAT policy (latest|automatic|previous|delete)\n"
		L"  Verbosity & timeout:\n"
		L"    -timeout <val>               Set MOK prompt timeout (-1 to 32767)\n"
		L"    -verbose <true|false>        Set shim verbose output\n"
		L"    -fb-verbose <true|false>     Set fallback verbose output\n"
		L"    -fb-noreboot <true|false>    Set fallback no-reboot flag\n"
		);
}

static void print_error(int resl)
{
	if (resl == ST_OK) {
		wprintf(L"Success\n");
		return;
	}

	wchar_t* status_str = dc_get_status_str(resl);
	if(status_str != NULL)
		wprintf(L"Error: %s\n", status_str);
	else
		wprintf(L"Undefined Error: %d\n", resl);
}

static void make_dev_status(vol_inf *inf, wchar_t *status)
{
	wcscpy(status, L"unmounted");

	if (DC_IS_LOCKED(inf->status.flags)) {
		/* keys erased at hibernation, I/O fails until unlocked (-mount) or unmounted */
		wcscpy(status, L"locked");
	} else if (inf->status.flags & F_ENABLED) {
		wcscpy(status, L"mounted");
	}

	if (inf->status.flags & F_UNSUPRT) {
		wcscpy(status, L"unsupported");
	}

	if (wcscmp(inf->device, boot_dev) == 0) {
		wcscat(status, L", boot");
	}

	if (inf->status.flags & F_SYSTEM) {
		wcscat(status, L", system");
	}
}

/*
   a locked volume (keys erased at hibernation, F_LOCKED) can only be unlocked (-mount)
   or unmounted (-unmount [-f]), the driver rejects every other operation
*/
static int is_locked_msg(vol_inf *inf, wchar_t *dev)
{
	if (DC_IS_LOCKED(inf->status.flags) == 0) {
		return 0;
	}
	wprintf(
		L"This device is locked, its keys were erased at hibernation.\n"
		L"Unlock it with \"dccon -mount %s\" or unmount it with \"dccon -unmount %s [-f]\"\n", dev, dev);
	return 1;
}

/* an ST_CANCEL step without a visible reason is retried for this many seconds */
#define CANCEL_RETRY_SECS 5

typedef struct _lock_wait {
	int notified; /* the "locked" message was printed */
	int relocked; /* the volume was locked - a skip-unused session lost its bitmap */
	int retries;  /* seconds of ST_CANCEL retries without a visible reason */
} lock_wait;

/*
   transcryption steps return ST_CANCEL while the volume is locked, while a lock or unmount is
   in progress and right after an unlock / resume (F_ENABLED | F_PREVENT_ENC): keep waiting. An
   ST_CANCEL without a visible reason (e.g. F_PREVENT_ENC cleared before the status query) is
   retried for CANCEL_RETRY_SECS seconds.
   Returns 1 to retry the step (after a 1 s wait), 0 to report the error.
*/
static int wait_if_locked(vol_inf *inf, lock_wait *lw)
{
	dc_status status;
	int       have_status = (dc_get_device_status(inf->device, &status) == ST_OK);

	if ( have_status && DC_IS_LOCKED(status.flags) )
	{
		if (lw->notified == 0) {
			wprintf(
				L"\nThe volume is locked (keys erased at hibernation), waiting for an unlock (dccon -mount)\n"
				L"Press ESC to stop waiting\n");
			lw->notified = 1;
		}
		lw->relocked = 1;
		lw->retries = 0;
		Sleep(1000);
		return 1;
	}
	if ( have_status && ((status.flags & (F_ENABLED | F_PREVENT_ENC)) == (F_ENABLED | F_PREVENT_ENC)) )
	{
		/* lock / unmount in progress or just unlocked: transient */
		lw->retries = 0;
		Sleep(1000);
		return 1;
	}
	if (lw->retries < CANCEL_RETRY_SECS) {
		lw->retries++;
		Sleep(1000);
		return 1;
	}
	return 0;
}

static void lock_wait_reset(lock_wait *lw)
{
	lw->notified = 0;
	lw->retries  = 0;
}

static void print_devices()
{
	wchar_t  stat[MAX_PATH];
	wchar_t  size[MAX_PATH];
	wchar_t *mnt;
	u32      i;

	wprintf(
		L"------------------------------------------------------------------\n"
		L"volume |     mount point      |   size  |       status\n"
		L"-------+----------------------+---------+-------------------------\n");

	for (i = 0; i < vol_cnt; i++)
	{
		dc_format_byte_size(
			size, countof(size), volumes[i].status.dsk_size);

		make_dev_status(&volumes[i], stat);

		if (volumes[i].status.mnt_point[0] != L'\\') {
			mnt = volumes[i].status.mnt_point;
		} else mnt = L"";
		
		wprintf(L"pt%d    | %-20s | %-7s | %-23s\n", i, mnt, size, stat);
	}
}

static void enum_devices()
{
	vol_inf info;
	
	if (dc_first_volume(&info) == ST_OK)
	{
		do
		{
			volumes[vol_cnt++] = info;
		} while (dc_next_volume(&info) == ST_OK);
	}
}

static vol_inf *find_device(wchar_t *name)
{
	wchar_t w_name[MAX_PATH];
	u32     i;

	if (name == NULL) 
	{
		for (i = 0; i < vol_cnt; i++) {
			if (volumes[i].status.flags & F_SYSTEM) return &volumes[i];
		}
		return NULL;
	}
	wcscpy(w_name, name); _wcslwr(w_name);

	if ( (w_name[0] == L'p') && (w_name[1] == L't') && (isdigit(name[2]) != 0) ) {
		if ( (i = _wtoi(name+2)) < vol_cnt ) return &volumes[i];
	} else 
	{
		if (w_name[1] == L':') {
			w_name[2] = 0;
		}
		for (i = 0; i < vol_cnt; i++) {
			if (_wcsicmp(w_name, volumes[i].status.mnt_point) == 0) return &volumes[i];
		}
	}
	return NULL;
}

static 
void dc_getpass_loop(dc_pass *pass)
{
	wchar_t ch;
	u32     pos;

	for (pos = 0;;)
	{
		ch = _getch();

		if (ch == '\r') {
			break;
		}

		/* reseed RNG */
		if (rng_inited != 0) {
			rnd_reseed_now();
		}

		if (ch == 8)
		{
			if (pos > 0) {
				_putch(8); pos--;
			}
			_putch(' '); _putch(8);
			continue;
		}

		if ( (ch == 0) || (ch == 0xE0) ) {
			_getch();
		}

		if ( (ch < ' ') || (ch > '~') || (pos == MAX_PASSWORD) ) {
			continue;
		}

		pass->pass[pos++] = ch; _putch('*');
	}

	_putch('\n');

	pass->size = pos * 2;
}

static
int dc_get_password(int confirm, dc_pass *pass)
{
	dc_pass *cfm_p;
	int      succs;

	cfm_p = NULL; succs = 0;
	do
	{
		dc_getpass_loop(pass);

		if (confirm != 0) 
		{
			if ( (cfm_p = secure_alloc(sizeof(dc_pass))) == NULL ) {
				break;
			}
			wprintf(L"Confirm password: ");
			dc_getpass_loop(cfm_p);

			if (IS_EQUAL_PASS(pass, cfm_p) == 0)
			{
				wprintf(L"The password was not correctly confirmed.\n");
				break;
			}
		}
		succs = 1;
	} while (0);

	if (cfm_p != NULL) {
		secure_free(cfm_p);
	}

	return succs;
}

/* steps that returned ST_RW_ERR passed a block with bad sectors */
static void print_bad_blocks(int bad_blocks)
{
	if (bad_blocks != 0) {
		wprintf(
			L"Warning: %d block(s) contained sectors that could not be read or written (bad sectors).\n"
			L"The contents of these sectors are lost: unreadable sectors now read as zeros.\n"
			L"Check the disk for errors and restore the affected files from a backup.\n", bad_blocks);
	}
}

static int check_shadows(vol_inf *inf, int wp_mode);

/* after an unlock, before the first step: a lock freed the allocation bitmap of a
   skip-unused session, the step would load it again. 1: go on, 0: stop (session paused) */
static int unlock_check_shadows(vol_inf *inf, lock_wait *lw, dc_status *status)
{
	if (lw->relocked == 0 || DC_IS_LOCKED(status->flags)) return 1;
	lw->relocked = 0;
	if (check_shadows(inf, status->crypt.wp_mode) == ST_OK) return 1;
	dc_sync_enc_state(inf->device);
	return 0;
}

static int dc_encrypt_loop(vol_inf *inf, int wp_mode)
{
	dc_status status;
	int       i = 0;
	wchar_t  *wp_str;
	char      ch;
	int       resl;
	int       ret = ST_OK;
	int       bad_blocks = 0;
	lock_wait lw = { 0, 0 };

bgn_loop:;
	cls_console();

	switch (wp_mode)
	{
		case WP_NONE: wp_str = L"None"; break;
		case WP_DOD_E: wp_str = L"US DoD 5220.22-M (8-306. / E) (3 passes)"; break;
		case WP_DOD: wp_str = L"US DoD 5220.22-M (8-306. / E, C and E) (7 passes)"; break;
		case WP_GUTMANN: wp_str = L"Gutmann (35 passes)"; break;
		case WP_SKIP_UNUSED: wp_str = L"Skip unused sectors"; break;
		default: wp_str = L"None"; break;
	}

	wprintf(
		L"Encrypting progress...\n"
		L"Old data wipe mode: %s\n\n"
		L"Press ESC to cancel encrypting or press \"W\" to change wipe mode\n", wp_str);

	do
	{
		if (_kbhit() != 0)
		{
			if ( (ch = _getch()) == 0x1B )
			{
				wprintf(L"\nEncryption cancelled\n");
				dc_sync_enc_state(inf->device);
				break;
			}

			if (tolower(ch) == 'w')
			{
				wprintf(L"\n"
					L"1 - None (fastest)\n"
					L"2 - US DoD 5220.22-M (8-306. / E) (3 passes)\n"
					L"3 - US DoD 5220.22-M (8-306. / E, C and E) (7 passes)\n"
					L"4 - Gutmann (35 passes)\n");

				switch (getchr('1', '4'))
				{
					case '1': wp_mode = WP_NONE; break;
					case '2': wp_mode = WP_DOD_E; break;
					case '3': wp_mode = WP_DOD; break;
					case '4': wp_mode = WP_GUTMANN; break;
				}

				goto bgn_loop;
			}
		}

		if (i-- == 0) {
			dc_sync_enc_state(inf->device); i = DC_SYNC_EVERY_STEPS - 1;
		}

		dc_get_device_status(
			inf->device, &status);

		wprintf(
			L"\r%-.3f %%", 
			(double)(status.tmp_size) / (double)(status.dsk_size) * 100);

		if (unlock_check_shadows(inf, &lw, &status) == 0) break;

		resl = dc_enc_step(inf->device, wp_mode);

		if (resl == ST_RW_ERR) bad_blocks++;

		if (resl == ST_FINISHED) {
			wprintf(L"\nEncryption finished\n"); break;
		}

		if (resl == ST_CANCEL) {
			if (wait_if_locked(inf, &lw) != 0) continue;
		} else {
			lock_wait_reset(&lw);
		}

		if ( (resl != ST_OK) && (resl != ST_RW_ERR) ) {
			/* e.g. the step stays refused (device still locked / busy): fail the command */
			wprintf(L"\nEncryption error %d\n", resl);
			/* save the progress the driver holds (as the GUI does on an error) */
			dc_sync_enc_state(inf->device);
			ret = resl; break;
		}
	} while (1);

	print_bad_blocks(bad_blocks);
	return ret;
}

static int dc_format_loop(vol_inf *inf, int wp_mode)
{
	dc_status status;
	wchar_t  *wp_str;
	char      ch;
	int       resl;

bgn_loop:;
	cls_console();

	switch (wp_mode)
	{
		case WP_NONE: wp_str = L"None"; break;
		case WP_DOD_E: wp_str = L"US DoD 5220.22-M (8-306. / E) (3 passes)"; break;
		case WP_DOD: wp_str = L"US DoD 5220.22-M (8-306. / E, C and E) (7 passes)"; break;
		case WP_GUTMANN: wp_str = L"Gutmann (35 passes)"; break;
		case WP_SKIP_UNUSED: wp_str = L"Skip unused sectors"; break;
		default: wp_str = L"None"; break;
	}

	wprintf(
		L"Formatting progress...\n"
		L"Old data wipe mode: %s\n\n"
		L"Press ESC to cancel encrypting or press \"W\" to change wipe mode\n", wp_str);

	do
	{
		if (_kbhit() != 0)
		{
			if ( (ch = _getch()) == 0x1B )
			{
				wprintf(L"\nFormatting cancelled\n");
				resl = ST_OK; break;
			}

			if (tolower(ch) == 'w')
			{
				wprintf(L"\n"
					L"1 - None (fastest)\n"
					L"2 - US DoD 5220.22-M (8-306. / E) (3 passes)\n"
					L"3 - US DoD 5220.22-M (8-306. / E, C and E) (7 passes)\n"
					L"4 - Gutmann (35 passes)\n");

				switch (getchr('1', '4'))
				{
					case '1': wp_mode = WP_NONE; break;
					case '2': wp_mode = WP_DOD_E; break;
					case '3': wp_mode = WP_DOD; break;
					case '4': wp_mode = WP_GUTMANN; break;
				}

				goto bgn_loop;
			}
		}

		dc_get_device_status(inf->device, &status);

		wprintf(
			L"\r%-.3f %%", 
			(double)(status.tmp_size) / (double)(status.dsk_size) * 100);

		resl = dc_format_step(inf->device, wp_mode);

		if (resl == ST_FINISHED) {
			_putch('\n'); break;
		}

		if ( (resl != ST_OK) && (resl != ST_RW_ERR) ) {
			wprintf(L"\nFormatting error %d\n", resl);
			break;
		}
	} while (1);

	if (resl != ST_FINISHED) {
		dc_done_format(inf->device);
	}

	return ST_OK;
}

static int dc_decrypt_loop(vol_inf *inf)
{
	dc_status status;
	int       i = 0;
	int       resl;
	int       ret = ST_OK;
	int       bad_blocks = 0;
	lock_wait lw = { 0, 0 };

	cls_console();

	wprintf(
		L"Decrypting progress...\n"
		L"Press ESC to cancel decrypting\n");

	do
	{
		if ( (_kbhit() != 0) && (_getch() == 0x1B) ) {
			wprintf(L"\nDecryption cancelled\n");
			dc_sync_enc_state(inf->device); break;
		}

		if (i-- == 0) {
			dc_sync_enc_state(inf->device); i = DC_SYNC_EVERY_STEPS - 1;					
		}

		dc_get_device_status(inf->device, &status);

		wprintf(
			L"\r%-.3f %%", 
			100 - ((double)(status.tmp_size) / (double)(status.dsk_size) * 100));

		if (unlock_check_shadows(inf, &lw, &status) == 0) break;

		resl = dc_dec_step(inf->device);

		if (resl == ST_RW_ERR) bad_blocks++;

		if (resl == ST_FINISHED) {
			wprintf(L"\nDecryption finished\n"); break;
		}

		if (resl == ST_CANCEL) {
			if (wait_if_locked(inf, &lw) != 0) continue;
		} else {
			lock_wait_reset(&lw);
		}

		if ( (resl != ST_OK) && (resl != ST_RW_ERR) ) {
			/* e.g. the step stays refused (device still locked / busy): fail the command */
			wprintf(L"\nDecryption error %d\n", resl);
			/* save the progress the driver holds (as the GUI does on an error) */
			dc_sync_enc_state(inf->device);
			ret = resl; break;
		}
	} while (1);

	print_bad_blocks(bad_blocks);
	return ret;
}

static BOOL dc_cd_callback(ULONGLONG isosize, ULONGLONG encsize, PVOID param)
{
	if ( (_kbhit() != 0) && (_getch() == 0x1B) ) {
		wprintf(L"\nEncryption cancelled\n");
		return FALSE;
	}

	wprintf(
		L"\r%-.3f %%", 
		(double)(encsize) / (double)(isosize) * 100);

	return TRUE;
}

int dc_set_boot_interactive(int d_num, int small_boot)
{
	ldr_config conf;
	int        resl;

	if ( (resl = dc_set_mbr(d_num, 0, small_boot)) == ST_NF_SPACE )
	{
		wprintf(
			L"Not enough space after partitions to install bootloader.\n"
			L"Install bootloader to first HDD track (incompatible with third-party bootmanagers, like GRUB) Y/N?\n");

		if (tolower(_getch()) == 'y') 
		{
			if ( ((resl = dc_set_mbr(d_num, 1, small_boot)) == ST_OK) && 
				 (dc_get_mbr_config(d_num, NULL, &conf) == ST_OK) )
			{
				conf.boot_type = LDR_BT_ACTIVE;
						
				if ( (resl = dc_set_mbr_config(d_num, NULL, &conf)) != ST_OK ) {
					dc_unset_mbr(d_num);
				}
			}
		} 
	}

	return resl;
}

int dc_set_efi_boot_interactive(int d_num, int add_bme, int shim, int esp, int esp_size_mb)
{
	int        resl;
	int        replace_ms = 0;
	int		   sb_no_pass;
	int        esp_part = -1;
	wchar_t    esp_path[MAX_PATH];

	sb_no_pass = (dc_efi_is_secureboot() && !dc_efi_dcs_is_signed());
	if (shim == -1) shim = sb_no_pass;

	/* Ask about dedicated DCS ESP partition */
	if (esp == -1) {
		wprintf(L"Do you want to create a dedicated DCS ESP partition? (allows encrypting Windows ESP) Y/N?\n");
		esp = (tolower(_getch()) == 'y');
	}

	if (esp == 1) {
		/* Use dedicated DCS ESP partition */
		wprintf(L"Setting up dedicated DCS ESP partition...\n");

		resl = dc_get_or_create_dcs_esp(&d_num, esp_path, &esp_part, esp_size_mb);
		if (resl != ST_OK) {
			wprintf(L"Failed to create DCS ESP partition\n");
			return resl;
		}

		wprintf(L"Using DCS ESP partition %d\n", esp_part);

		/* For dedicated ESP, no need to ask about replacing MS bootloader */
		if (add_bme == -1) {
			wprintf(L"Do you want to add a DCS loader boot menu entry (recommended). Y/N?\n");
			add_bme = (tolower(_getch()) == 'y');
		}

		wprintf(L"Installing EFI Disk Cryptography Services (DCS) bootloader...\n");

		resl = dc_set_efi_boot(d_num, esp_part, 0, shim);

		if (resl == ST_OK && add_bme == 1) {
			resl = dc_efi_set_bme(L"DiskCrypto (DCS) loader", d_num);
		}
	} else {
		/* Standard installation to Windows ESP */
		if (add_bme == -1) {
			wprintf(L"Do you want to add a DCS loader boot menu entry (recommended). Y/N?\n");
			add_bme = (tolower(_getch()) == 'y');
		}

		if (add_bme == 1 && dc_efi_is_msft_on_disk(d_num))
		{
			wprintf(L"Note: Some EFI implementations are not adhering to the standard and always start the windows bootloader.\n");

			if (sb_no_pass) {
				wprintf(L"Secure Boot is enabled, hence the workaround for this issue cannot be applied.\n");
			}
			else
			{
				wprintf(L"Do you want to replace the windows bootloader file (BOOTMGFW.EFI) with a redirection to the DCS loader as a workaround? Y/N?\n");
				replace_ms = (tolower(_getch()) == 'y');
			}
		}

		wprintf(L"Installing EFI Disk Cryptography Services (DCS) bootloader...\n");

		resl = dc_set_efi_boot(d_num, -1, replace_ms, shim);

		if (resl == ST_OK && add_bme == 1) {
			resl = dc_efi_set_bme(L"DiskCrypto (DCS) loader", d_num);
		}
	}

	if (shim) {
		wprintf(L"\nFor compatibility with secure boot the shim loader was installed.\n"
			L"Upon reboot you will be encounter an 'Verification failed: (0x1A) Security Violation' error message, "
			L"to resolve this, you will need to start the 'MOK Manager' and enroll a certificate located at \\EFI\\Boot\\CustomSigner.der\n"
			L"After one more reboot the DCS loader should boot and show you a password prompt.\n"
			L"You can run 'dccon -mok -guide' to view a verbose how to.\n");
	}

	return resl;
}

static 
dc_pass* dc_load_pass_and_keyfiles(
		   wchar_t *p_param, wchar_t *kdf_param, wchar_t *kf_param, wchar_t *gp_msg, int confirm
		   )
{
	dc_pass *pass;
	int      clean = 0;
	wchar_t *cmde;
	size_t   plen;
	int      resl;

	if ( (pass = secure_alloc(sizeof(dc_pass))) == NULL ) {
		clean_cmd_line();
		return NULL;
	}
	pass->kdf = 0;

	if (p_param == NULL)  p_param = L"-p";
	if (kdf_param == NULL)  kdf_param = L"-kdf";
	if (kf_param == NULL) kf_param = L"-kf";
	if (gp_msg == NULL)   gp_msg = L"Enter password: ";
	
	if (cmde = get_param(p_param))
	{
		plen       = wcslen(cmde) * sizeof(wchar_t);
		pass->size = d32(min(plen, MAX_PASSWORD * sizeof(wchar_t)));
		mincpy(&pass->pass, cmde, pass->size);
		memset(cmde, 0, plen); clean = 1;
	} else 
	{
		wprintf(gp_msg);
		
		if (dc_get_password(confirm, pass) == 0) {
			secure_free(pass); clean_cmd_line();
			return NULL;
		}
	}

	if (cmde = get_param(kdf_param))
	{
		pass->kdf = _wtoi(cmde);
		if( (pass->kdf < 0) || (pass->kdf > 10) ) {
			wprintf(L"Argon2id cost must be between 1 and 10\n");
			secure_free(pass); pass = NULL;
			clean = 1;
		}
	}

	if (cmde = get_param(kf_param)) 
	{
		if ( (resl = dc_add_keyfiles(pass, cmde)) != ST_OK) 
		{
			printf("Keyfiles not loaded, error %d\n", resl);
			secure_free(pass); pass = NULL;
		}
		burn(cmde, wcslen(cmde) * sizeof(wchar_t)); 
		clean = 1;
	}

	if (clean != 0) {
		clean_cmd_line();
	}

	if (pass->size == 0) {
		secure_free(pass); pass = NULL;
	}

	return pass;
}

static void get_crypt_info(crypt_info *crypt)
{
	wchar_t *head_len;
	wchar_t *slot_count;

	memset(crypt, 0, sizeof(crypt_info));

	/* get cipher */
	if (is_param(L"-a") != 0) {
		crypt->cipher_id = CF_AES;
	} else if (is_param(L"-t") != 0) {
		crypt->cipher_id = CF_TWOFISH;
	} else if (is_param(L"-s") != 0) {
		crypt->cipher_id = CF_SERPENT;
	} else if (is_param(L"-at") != 0) {
		crypt->cipher_id = CF_AES_TWOFISH;
	} else if (is_param(L"-ts") != 0) {
		crypt->cipher_id = CF_TWOFISH_SERPENT;
	} else if (is_param(L"-sa") != 0) {
		crypt->cipher_id = CF_SERPENT_AES;
	} else if (is_param(L"-ats") != 0) {
		crypt->cipher_id = CF_AES_TWOFISH_SERPENT;
	}

	/* get wipe mode */
	if (is_param(L"-dod_e") != 0) {
		crypt->wp_mode = WP_DOD_E;
	} else if (is_param(L"-dod") != 0) {
		crypt->wp_mode = WP_DOD;
	} else if (is_param(L"-g") != 0) {
		crypt->wp_mode = WP_GUTMANN;
	} else if (is_param(L"-skip") != 0) {
		crypt->wp_mode = WP_SKIP_UNUSED;
	}

	/* get key slots count */
	if (slot_count = get_param(L"-slots")) {
		crypt->slot_count = (u8)_wtoi(slot_count);
	}

	/* get header length */
	if (head_len = get_param(L"-len")) {
		crypt->head_len = _wtoi(head_len);
	}
	
	if (crypt->head_len || crypt->slot_count)
	{
		crypt->version = DC_HDR_VERSION_2;
		if (crypt->head_len == 0 && crypt->slot_count > 0) {
			crypt->head_len = DC_BASE_SIZE + crypt->slot_count * (PKCS_DERIVE_MAX + sizeof(dc_slot_info));
			if(crypt->head_len < DC_AREA_SIZE)
				crypt->head_len = DC_AREA_SIZE;
			else { // round crypt->head_len up to a power of 2: 2048, 4096, 8192, ...
				unsigned long index;
				if(_BitScanReverse(&index, crypt->head_len - 1))
					crypt->head_len = 1ul << (index + 1);
			}
		}
	}

	/* get header version */
	if (crypt->version != 0)
		return;
	if (is_param(L"-v2")) {
		crypt->version = DC_HDR_VERSION_2;
	} else if (is_param(L"-v1")) {
		crypt->version = DC_HDR_VERSION;
	}
}

/* power-loss protection (journaled transcryption, v2 headers), as the GUI: checksums by
 * default (-safefast), -safe journals a copy of every block, -nosafe turns it off; only a new
 * session takes it (a resumed one keeps the mode it was started with) */
static void get_safe_flag(crypt_info *crypt)
{
	if (is_param(L"-nosafe") != 0) {
		return;
	}
	crypt->flags |= (is_param(L"-safe") != 0 && is_param(L"-safefast") == 0) ? EF_SAFE_TRANSCRYPT : EF_SAFE_TRANSCRYPT_FAST;
}

/* before a skip-unused start or resume: existing shadow copies would become corrupt (see dcapi
 * shadow.h). -delshadows deletes them without asking, -keepshadows goes on with them, else the
 * console asks. A failed deletion is reported and the operation goes on.
 * ST_OK: go on, ST_CANCEL: stop. */
static int check_shadows(vol_inf *inf, int wp_mode)
{
	int count = 0, left = -1, resl;

	if (wp_mode != WP_SKIP_UNUSED) return ST_OK;

	if ( (resl = dc_count_shadows(inf->w32_device, &count)) == ST_OK ) {
		if (count == 0) return ST_OK;
		wprintf(L"\nVolume %s has %d shadow copies (System Restore points, Previous Versions or backup snapshots).\n",
			inf->status.mnt_point, count);
	} else {
		wprintf(L"\nThe shadow copies of volume %s could not be checked (error %d).\n", inf->status.mnt_point, resl);
	}
	wprintf(
		L"\"Skip unused sectors\" does not process sectors that are unused now, but older shadow copies\n"
		L"may still keep data in them. Those shadow copies would become corrupt.\n");

	if (is_param(L"-keepshadows") != 0) {
		wprintf(L"Shadow copies kept (-keepshadows): they may become unusable.\n");
		return ST_OK;
	}
	if (is_param(L"-delshadows") == 0)
	{
		wprintf(
			L"\n"
			L"1 - Delete all shadow copies of this volume (recommended)\n"
			L"2 - Keep them (they may become unusable)\n"
			L"3 - Cancel\n");
		switch (getchr('1', '3'))
		{
			case '2': wprintf(L"Shadow copies kept.\n"); return ST_OK;
			case '3': wprintf(L"Cancelled. A started operation stays paused, run the same command to resume it.\n"); return ST_CANCEL;
		}
	}
	wprintf(L"Deleting the shadow copies...\n");
	if ( (resl = dc_delete_shadows(inf->w32_device, &left, NULL)) == ST_OK ) {
		wprintf(L"Shadow copies deleted.\n");
	} else if (left > 0) {
		wprintf(L"%d shadow copies could not be deleted; the operation continues, they may become unusable.\n", left);
	} else {
		wprintf(L"The shadow copies could not be deleted (error %d); the operation continues, they may become unusable.\n", resl);
	}
	return ST_OK;
}

static int dc_bench_cmp(const bench_item *arg1, const bench_item *arg2)
{
	if (arg1->speed > arg2->speed) {
		return -1;
	} else {
		return (arg1->speed < arg2->speed);
	}
}

int wmain(int argc, wchar_t *argv[])
{
	vol_inf *inf;
	int      resl;
	int      vers;
	int      d_inited;

	for (; argc > 1; argc--) 
	{
		if (wcscmp(argv[argc - 1], L"-dbg_wait") == 0)
		{
			while (! IsDebuggerPresent())
				Sleep(500);
			__debugbreak();
		}
		else
			break;
	}

	g_argc = argc; g_argv = argv;
	do
	{
#ifdef _M_IX86 
		if (is_wow64() != 0) {
			wprintf(L"Please use x64 version of DiskCryptor\n");
			resl = ST_ERROR; break;
		}
#endif
		if (is_admin() != ST_OK) {
			wprintf(L"Administrator privileges required\n");
			resl = ST_NO_ADMIN; break;
		}

		/* Register Ctrl+C handler for cancelling operations */
		SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

		if (argc < 2) {
			print_usage(0x01);
			resl = ST_OK; break;
		}

		d_inited = 0;

		dc_efi_init();

		if ( dc_is_driver_works() && (dc_open_device() == ST_OK) )
		{
			if ((vers = dc_get_version()) == DC_DRIVER_VER) {
				/* get information of all volumes in system */
				enum_devices(); d_inited = 1;
			}
		}

		if ( (argc >= 2) && (wcscmp(argv[1], L"-version") == 0) ) 
		{
			wprintf(L"DiskCryptor %S console\n", DC_PRODUCT_VER);
			resl = ST_OK; break;
		}

		if (dc_is_old_runned() != 0)
		{
			wprintf(L"DiskCryptor 0.1-0.4 installed, please completely "
				L"uninstall it before use this version\n");
			resl = ST_OK; break;
		}

		if ( (argc >= 2) && (wcscmp(argv[1], L"-help") == 0) ) 
		{
			print_usage(0xFF);
			resl = ST_OK; break;
		}

		if ( (argc >= 2) && (wcscmp(argv[1], L"-boot") == 0) ) 
		{
			if (argc > 2)
				resl = boot_menu(argc, argv);
			else
			{
				print_usage(0x02);
				resl = ST_OK;
			}
			break;
		}	

		if ( (argc >= 2) && (wcscmp(argv[1], L"-efi") == 0) ) 
		{
			if (argc > 2)
				resl = efi_menu(argc, argv);
			else
			{
				print_usage(0x04);
				resl = ST_OK;
			}
			break;
		}	

		if ( (argc >= 2) && (wcscmp(argv[1], L"-mok") == 0) ) 
		{
			if (argc > 2)
				resl = mok_menu(argc, argv);
			else
			{
				print_usage(0x08);
				resl = ST_OK;
			}
			break;
		}

		if ( (argc >= 3) && (wcscmp(argv[1], L"-offline_install") == 0) ) {
			resl = install_dc_offline(argv[2]); 
			if (resl == ST_OK) 
				wprintf(L"DiskCryptor driver installed successfully\n");
			else
				wprintf(L"Error installing DiskCryptor driver\n");
			break;
		}

		if ( (argc >= 3) && (wcscmp(argv[1], L"-offline_remove") == 0) ) {
			resl = remove_dc_offline(argv[2]); 
			if (resl == ST_OK) 
				wprintf(L"DiskCryptor driver removed successfully\n");
			else
				wprintf(L"Error removing DiskCryptor driver\n");
			break;
		}

		if (dc_is_driver_works() == FALSE) 
		{
			wprintf(
				L"DiskCryptor is not installed,\n"
				L"please install DiskCryptor and reboot you system\n");
			resl = ST_OK; break;
		}

#ifndef _DEBUG
		if (d_inited == 0)
		{
			if (vers > DC_DRIVER_VER) 
			{
				wprintf(
					L"DiskCryptor driver ver %d detected\n"
					L"Please use last program version\n", vers);
				resl = ST_OK; break;
			}

			if (vers < DC_DRIVER_VER)
			{
				wprintf(
					L"Old DiskCryptor driver detected\n"
					L"please update DiskCryptor and reboot you system\n");
				resl = ST_OK; break;
			}

			resl = ST_ERROR; break;
		}
#endif

		/* initialize user mode RNG part */
		if ( (resl = rnd_init()) != ST_OK ) {
			break;
		}
		rng_inited = 1;

		/* get boot device */
		if (dc_get_boot_device(boot_dev) != ST_OK) {
			boot_dev[0] = 0;
		}

		if ( (argc == 2) && (wcscmp(argv[1], L"-enum") == 0) ) {
			print_devices();
			resl = ST_OK; break;
		}

		if ( (argc == 3) && (wcscmp(argv[1], L"-info") == 0) ) 
		{
			wchar_t stat[MAX_PATH];
			wchar_t size[MAX_PATH];

			if ( (inf = find_device(argv[2])) == NULL ) {
				resl = ST_NF_DEVICE; break;
			}

			dc_format_byte_size(
				size, countof(size), inf->status.dsk_size);

			make_dev_status(inf, stat);

			wprintf(
				L"Device:            %s\n"
				L"SymLink:           %s\n"
				L"Mount point:       %s\n"
				L"Capacity:          %s\n"
				L"Status:            %s\n",
				inf->device, inf->w32_device, inf->status.mnt_point,
				size, stat);

			if (DC_IS_LOCKED(inf->status.flags))
			{
				wprintf(
					L"                   keys erased at hibernation, I/O fails until the device is\n"
					L"                   unlocked (-mount) or unmounted (-unmount [-f])\n");
			}

			if (inf->status.flags & F_ENABLED)
			{
				double portion;

				if (DC_IS_LOCKED(inf->status.flags))
				{
					/* the lock tore down the transcryption session, F_SYNC is not reported */
					portion = -1;
				} else if (inf->status.flags & F_SYNC)
				{
					portion = (double)(inf->status.tmp_size) / 
						(double)(inf->status.dsk_size) * 100;
				} else {
					portion = 100;
				}

				wprintf(
					L"Cipher:            %s (XTS Mode)\n"
					//L"Encryption mode:   XTS\n"
					L"Header KDF:        %s\n"
					L"Header Format:     %s\n",
					dc_get_cipher_name(inf->status.crypt.cipher_id),
					inf->status.crypt.head_kdf > 0 ? L"Argon2id v1.3" : L"Pkcs5.2 SHA-512",
					inf->status.crypt.version == DC_HDR_VERSION_2 ? L"2" : L"1");

				if (portion < 0) {
					wprintf(L"Encrypted portion: n/a (locked)\n");
				} else {
					wprintf(L"Encrypted portion: %-.3f%%\n", portion);
				}
			}

			resl = ST_OK; break;
		}

		if ( (argc >= 3) && (wcscmp(argv[1], L"-mount") == 0) ) 
		{
			wchar_t  vol_n[MAX_PATH];
			wchar_t  mnt_p[MAX_PATH];
			dc_pass *pass;
			wchar_t *mp_c;
			wchar_t *slot;
			size_t   s;
			int 	flags = 0;

			if ( (inf = find_device(argv[2])) == NULL ) {
				resl = ST_NF_DEVICE; break;
			}

			if (DC_IS_LOCKED(inf->status.flags))
			{
				/*
				   unlock in place: the driver keeps the original mount flags (only
				   MF_USE_BACKUP applies) and also tries the cached passwords / boot keys
				*/
				if ( (get_param(L"-mp") != NULL) || (is_param(L"-ro") != 0) || (is_param(L"-no_hiber") != 0) ) {
					wprintf(L"Unlocking a locked device, its mount options are kept (-mp, -ro, -no_hiber ignored)\n");
				}

				if ( (pass = dc_load_pass_and_keyfiles(NULL, NULL, NULL, NULL, 0)) == NULL ) {
					resl = ST_OK; break;
				}
				if ( (slot = get_param(L"-slot")) != NULL ) {
					pass->slot = _wtoi(slot);
				}

				/* a volume mounted from its backup header is unlocked from it by default
				   (the driver ORs it in as well) */
				if ( (is_param(L"-use_backup") != 0) || (inf->status.mnt_flags & MF_USE_BACKUP) ) {
					flags |= MF_USE_BACKUP;
				}

				InterlockedExchange(&g_abort_operation, 0);
				resl = dc_mount_volume(inf->device, pass, flags, &g_abort_operation);
				if (resl == ST_DEVICE_BUSY) {
					/* locked again (or another volume) while the header was probed: once more */
					resl = dc_mount_volume(inf->device, pass, flags, &g_abort_operation);
				}

				secure_free(pass);

				switch (resl)
				{
					case ST_OK:
						wprintf(L"device %s unlocked\n", argv[2]);
					break;
					case ST_CANCEL:
						if (g_abort_operation == 0) {
							/* refused by the driver, not aborted by the user */
							wprintf(L"The device cannot be unlocked while the system is entering hibernation, try again after the resume\n");
						}
					break;
					case ST_ALR_MOUNT:
						wprintf(L"This device is already mounted and not locked\n");
						resl = ST_OK;
					break;
					case ST_MEDIA_CHANGED:
						wprintf(
							L"The volume header does not match the locked volume, the device stays locked.\n"
							L"Unmount it instead (dccon -unmount %s [-f])\n", argv[2]);
					break;
					case ST_ERROR:
						wprintf(
							L"The device cannot be unlocked in its current state (e.g. its decryption has just finished).\n"
							L"Unmount it instead (dccon -unmount %s [-f])\n", argv[2]);
					break;
				}
				break;
			}

			if (inf->status.flags & F_ENABLED) {
				wprintf(L"This device is already mounted\n");
				resl = ST_OK; break;
			}

			if (inf->status.flags & (F_UNSUPRT | F_DISABLE | F_FORMATTING)) {
				wprintf(L"Invalid device state\n");
				resl = ST_OK; break;
			}

			pass = dc_load_pass_and_keyfiles(NULL, NULL, NULL, NULL, 0);
			mp_c = get_param(L"-mp");

			if (pass == NULL) {
				resl = ST_OK; break;
			}
			if (slot = get_param(L"-slot")) {
				pass->slot = _wtoi(slot);
			}

			if ( (mp_c != NULL) && (inf->status.mnt_point[0] == L'\\') ) {
				flags |= MF_DELMP;
			}

			if (is_param(L"-ro") != 0) {
				flags |= MF_READ_ONLY;
			}

			if (is_param(L"-no_hiber") != 0) {
				flags |= MF_NO_HIBER;
			}

			if (is_param(L"-use_backup") != 0) {
				flags |= MF_USE_BACKUP;
			}

			/* the driver repairs a torn header itself (backup header, tmp_size); only a header it
			   cannot repair is taken as it is - read-only, nothing is written to the volume */
			if (is_param(L"-ignore_crc") != 0) {
				flags |= MF_IGNORE_CRC;
			}

			InterlockedExchange(&g_abort_operation, 0);
			resl = dc_mount_volume(inf->device, pass, flags, &g_abort_operation);

			if ( (resl == ST_OK) && (mp_c != NULL) )
			{
				if (inf->status.mnt_point[0] != L'\\') {
					wprintf(L"device %s already have mount point\n", argv[2]);
				} else if (wcsncmp(inf->w32_device, L"\\\\?\\Volume{", 11) != 0) {
					/* listed by its device name (the Windows 7 EFI system partition): no volume GUID name */
					wprintf(L"device %s has no volume name, a mount point cannot be set\n", argv[2]);
				} else
				{
					_snwprintf(
						vol_n, countof(vol_n), L"%s\\", inf->w32_device);

					wcsncpy(mnt_p, mp_c, countof(mnt_p));
					if ( (s = wcslen(mnt_p)) && (mnt_p[s-1] != L'\\') ) {
						mnt_p[s] = L'\\'; mnt_p[s+1] = 0;
					}

					if (SetVolumeMountPoint(mnt_p, vol_n) == 0) {
						wprintf(L"Error when adding mount point\n");
					}
				}
			}

			if (resl == ST_OK) {
				dc_status st;

				wprintf(L"device %s mounted\n", argv[2]);
				if ( dc_get_device_status(inf->device, &st) == ST_OK && (st.mnt_flags & MF_IGNORE_CRC) ) {
					wprintf(
						L"The volume header is damaged and was taken as it is: the volume is mounted read-only,\n"
						L"nothing is written to it and a transcryption cannot continue. Copy the data off.\n");
					if (st.flags & F_SYNC) {
						wprintf(L"The volume is partly encrypted: data near the encryption boundary may read wrong.\n");
					}
				}
			} else if (resl == ST_HDR_DAMAGED) {
				wprintf(
					L"The password is right but the volume header is damaged (checksum error) and could not be\n"
					L"repaired. Restore an exported header, or try the backup header (-use_backup; after a\n"
					L"password change with the previous password), or mount it read-only with\n"
					L"  dccon -mount %s -ignore_crc\n"
					L"to copy the data.\n", argv[2]);
			}

			secure_free(pass);
			break;
		}

		if ( (argc >= 2) && (wcscmp(argv[1], L"-mountall") == 0) ) 
		{
			dc_pass *pass;
			int      n_mount;

			pass = dc_load_pass_and_keyfiles(NULL, NULL, NULL, NULL, 0);
			InterlockedExchange(&g_abort_operation, 0);
			resl = dc_mount_all(pass, &n_mount, 0, &g_abort_operation);

			if (resl == ST_OK) {
				/* locked devices unlocked with this password are counted as well */
				wprintf(L"%d devices mounted or unlocked\n", n_mount);
			}

			if (pass != NULL) {
				secure_free(pass);
			}
			break;
		}

		if ( (argc >= 3) && (wcscmp(argv[1], L"-unmount") == 0) )
		{
			int flags = 0;

			if ( (inf = find_device(argv[2])) == NULL ) {
				resl = ST_NF_DEVICE; break;
			}

			if (is_param(L"-f") != 0) {
				flags |= MF_FORCE;
			}

			if (is_param(L"-dp") != 0) {
				flags |= MF_DELMP;
			}

			if ( !(inf->status.flags & F_ENABLED) ) {
				wprintf(L"This device is not mounted\n");
				resl = ST_OK; break;
			}

			resl = dc_unmount_volume(inf->device, flags);

			if ( (resl == ST_LOCK_ERR) && DC_IS_LOCKED(inf->status.flags) )
			{
				/* the FS cannot flush its cache, every write to a locked volume fails */
				wprintf(
					L"The file system of this locked volume cannot be flushed.\n"
					L"Would you like to force an unmount on this volume? Data not yet written is lost. (Y/N)\n");

				if (tolower(_getch()) == 'y') {
					resl = dc_unmount_volume(inf->device, flags | MF_FORCE);
				}
			} else
			if (resl == ST_LOCK_ERR)
			{
				wprintf(
					L"This volume contains opened files.\n"
					L"Would you like to force an unmount on this volume? (Y/N)\n");

				if (tolower(_getch()) == 'y') {
					resl = dc_unmount_volume(inf->device, flags | MF_FORCE);
				}
			}

			if (resl == ST_OK) {
				wprintf(L"device %s unmounted\n", argv[2]);
			}
			break;
		}

		if ( (argc >= 2) && (wcscmp(argv[1], L"-unmountall") == 0) ) 
		{
			resl = dc_unmount_all();

			if (resl == ST_OK) {
				wprintf(L"all devices unmounted\n");
			}
			break;
		}

		if ( (argc >= 2) && (wcscmp(argv[1], L"-clean") == 0) ) 
		{
			resl = dc_device_control(DC_CTL_CLEAR_PASS, NULL, 0, NULL, 0) == NO_ERROR ? ST_OK : ST_ERROR;

			if (resl == ST_OK) {
				wprintf(L"passwords has been erased in memory\n");
			}
			break;
		}

		if ( (argc >= 2) && (wcscmp(argv[1], L"-addpass") == 0) )
		{
			dc_pass *pass;

			pass = dc_load_pass_and_keyfiles(NULL, NULL, NULL, NULL, 0);

			if (pass == NULL) {
				resl = ST_OK; break;
			}

			InterlockedExchange(&g_abort_operation, 0);
			resl = dc_add_password(pass, &g_abort_operation);

			secure_free(pass);
		}

		if ( (argc >= 3) && (wcscmp(argv[1], L"-encrypt") == 0) )
		{
			dc_pass   *pass;			
			crypt_info crypt;
			int        is_efi;
			DC_FLAGS   dc_flags;
			int        flags = 0;

			if (dc_device_control(DC_CTL_GET_FLAGS, NULL, 0, &dc_flags, sizeof(dc_flags)) != NO_ERROR) {
				resl = ST_ERROR; break;
			}

			if ( (inf = find_device(argv[2])) == NULL ) {
				resl = ST_NF_DEVICE; break;
			}

			if (is_locked_msg(inf, argv[2]) != 0) {
				resl = ST_DEVICE_BUSY; break;
			}

			is_efi = dc_efi_check();

			/* set default params */
			crypt.cipher_id = CF_AES;
			crypt.wp_mode   = WP_NONE;

			get_crypt_info(&crypt);
			get_safe_flag(&crypt);

			if (is_param(L"-backup_header")) {
				flags |= VF_BACKUP_HEADER;
			}

			if (is_param(L"-try_schrink")) {
				crypt.flags |= (EF_USE_SLACK | EF_TRY_SHRINK);
			}
			else if (is_param(L"-use_slack")) {
				crypt.flags |= EF_USE_SLACK;
			}

			if (inf->status.flags & F_SYNC) 
			{
				if (crypt.wp_mode == WP_NONE) {
					crypt.wp_mode = inf->status.crypt.wp_mode;
				}
				/* the session keeps its own mode */
				if (check_shadows(inf, inf->status.crypt.wp_mode) != ST_OK) { resl = ST_OK; break; }
				resl = dc_encrypt_loop(inf, crypt.wp_mode);
				break;
			}

			if (inf->status.flags & F_ENABLED) {
				wprintf(L"This device is already encrypted\n");
				resl = ST_OK; break;
			}

			if (inf->status.flags & (F_UNSUPRT | F_DISABLE)) {
				wprintf(L"Invalid device state\n");
				resl = ST_OK; break;
			}

			if ( (inf->status.flags & F_SYSTEM) || (wcscmp(inf->device, boot_dev) == 0) )
			{
				ldr_config conf;
				int        dsk_1, dsk_2;

				if ( (crypt.cipher_id != CF_AES) )
				{
					if (!is_efi && (dc_flags.load_flags & DST_SMALL_MEM) )
					{
						wprintf(
							L"Your BIOS does not provide enough base memory, "
							L"you can only use AES to encrypt the boot partition.");
						resl = ST_OK; break;
					}
				}				
				if (is_efi) {
					dsk_1 = dsk_2 = dc_efi_get_os_disk();
				} else if (dc_get_boot_disk(&dsk_1, &dsk_2) != ST_OK) {
					dsk_1 = dsk_2 = -1;
				}
				if (dsk_1 == -1)
				{
					wprintf(
						L"This partition is needed for system booting, bootable HDD not found\n"
						L"You must be use external bootloader\n"
						L"Continue operation (Y/N)?\n\n"
						);

					if (tolower(_getch()) != 'y') {
						resl = ST_OK; break;
					}
				} else if ((is_efi ? dc_get_efi_config(dsk_1, NULL, &conf) : dc_get_mbr_config(dsk_1, NULL, &conf)) != ST_OK)
				{
					wprintf(
						L"This partition is needed for system booting\n"
						L"You must install bootloader to HDD, or use external bootloader\n\n"
						L"1 - Install to HDD\n"
						L"2 - I already have external bootloader\n"
						);

					if (getchr('1', '2') == '1') 
					{
						if (is_efi) {
							if ((resl = dc_set_efi_boot_interactive(-1, -1, -1, -1, 0)) != ST_OK) {
								break;
							}
						}
						else {
							if ((resl = dc_set_boot_interactive(-1, -1)) != ST_OK) {
								break;
							}
						}
					}
				}				
			}

			pass = dc_load_pass_and_keyfiles(NULL, NULL, NULL, NULL, 1);

			if (pass == NULL) {
				resl = ST_OK; break;
			}

			if (is_efi && (inf->status.flags & F_SYSTEM) && !(dc_flags.load_flags & DST_BOOTLOADER))
			{
				resl = dc_prep_encrypt(inf->device, pass, &crypt, flags);

				secure_free(pass);

				if (resl == ST_OK) {
					wprintf(
						L"\n"
						L"The bootloader has been configured, after the reboot it should show you a password prompt.\n"
						L"You can abort by pressing escape instead of entering a password.\n"
						L"\n"
						L"Run \"dccon.exe -encrypt2\" after the reboot to start pending volume encryption.\n"
						);
				}
			}
			else
			{
				InterlockedExchange(&g_abort_operation, 0);
				resl = dc_start_encrypt(inf->device, pass, &crypt, flags, &g_abort_operation);

				secure_free(pass);

				/* cancelled = the session stays paused at its start */
				if (resl == ST_OK && check_shadows(inf, crypt.wp_mode) == ST_OK) {
					resl = dc_encrypt_loop(inf, crypt.wp_mode);
				}
			}

			break;
		}

		if ((argc >= 2) && (wcscmp(argv[1], L"-encrypt2") == 0))
		{
			DC_FLAGS flags;
			if (dc_device_control(DC_CTL_GET_FLAGS, NULL, 0, &flags, sizeof(flags)) == NO_ERROR) {
				if ((flags.boot_flags & BDB_BF_HDR_FOUND) == 0) {
					resl = ST_BL_NOT_PASSED; break;
				}
			}

			resl = ST_NF_FILE;

			vol_inf  info;
			if (dc_first_volume(&info) == ST_OK)
			{
				do
				{
					if ( !(info.status.flags & F_ENABLED) )
					{
						if (dc_has_pending_header(info.device)) {
							resl = ST_OK;
							break;
						}
					}
				} while (dc_next_volume(&info) == ST_OK);
			}

			if (resl != ST_OK) {
				break;
			}

			wprintf(
				L"\n"
				L"Starting pending encryption operation for: %s\n", 
				info.device
			);

			wchar_t path[MAX_PATH];
			resl = dc_get_pending_header_nt(info.device, path);
			if (resl == ST_OK) {
				resl = dc_start_encrypt2(info.device, path);
			}
			
			/* cancelled = the session stays paused at its start (resumed with -encrypt); an
			   unknown status asks */
			if (resl == ST_OK) {
				int wp = dc_get_device_status(info.device, &info.status) == ST_OK ? info.status.crypt.wp_mode : WP_SKIP_UNUSED;
				if (check_shadows(&info, wp) == ST_OK) {
					resl = dc_encrypt_loop(&info, info.status.crypt.wp_mode);
				}
			}

			break;
		}

		if ( (argc >= 3) && (wcscmp(argv[1], L"-decrypt") == 0) ) 
		{
			dc_pass *pass;	
			crypt_info crypt;
			DC_FLAGS flags;

			crypt.cipher_id = CF_AES;
			crypt.wp_mode   = WP_NONE;

			get_crypt_info(&crypt);
			get_safe_flag(&crypt);

			if ( (inf = find_device(argv[2])) == NULL ) {
				resl = ST_NF_DEVICE; break;
			}

			if (is_locked_msg(inf, argv[2]) != 0) {
				resl = ST_DEVICE_BUSY; break;
			}

			if (inf->status.flags & F_SYNC) {
				if (check_shadows(inf, inf->status.crypt.wp_mode) != ST_OK) { resl = ST_OK; break; }
				resl = dc_decrypt_loop(inf);
				break;
			}

			if ( !(inf->status.flags & F_ENABLED) ) {
				wprintf(L"This device is not mounted\n");
				resl = ST_OK; break;
			}

			if (inf->status.flags & F_FORMATTING) {
				wprintf(L"Invalid device state\n");
				resl = ST_OK; break;
			}
			if ( (inf->status.flags & F_SYSTEM) && 
				 (dc_device_control(DC_CTL_GET_FLAGS, NULL, 0, &flags, sizeof(flags)) == NO_ERROR) && (flags.conf_flags & CONF_BLOCK_UNENC_HDDS) )
			{
				wprintf(L"This device cannot be decrypted because "
					    L"'Deny access to unencrypted HDDs' option is enabled.\n");
				resl = ST_OK; break;
			}
			pass = dc_load_pass_and_keyfiles(NULL, NULL, NULL, NULL, 0);

			if (pass == NULL) {
				resl = ST_OK; break;
			}

			InterlockedExchange(&g_abort_operation, 0);
			resl = dc_start_decrypt(inf->device, pass, &crypt, &g_abort_operation);

			secure_free(pass);

			if (resl == ST_OK && check_shadows(inf, crypt.wp_mode) == ST_OK) {
				resl = dc_decrypt_loop(inf);
			}
			break;
		}

		if ( (argc >= 3) && (wcscmp(argv[1], L"-reencrypt") == 0) ) 
		{
			crypt_info crypt;
			dc_pass   *pass;

			if ( (inf = find_device(argv[2])) == NULL ) {
				resl = ST_NF_DEVICE; break;
			}

			if (is_locked_msg(inf, argv[2]) != 0) {
				resl = ST_DEVICE_BUSY; break;
			}

			crypt = inf->status.crypt;
			get_crypt_info(&crypt);
			get_safe_flag(&crypt);

			if ( !(inf->status.flags & F_ENABLED) ) {
				wprintf(L"This device is not mounted\n");
				resl = ST_OK; break;
			}

			if (inf->status.flags & F_FORMATTING) {
				wprintf(L"Invalid device state\n");
				resl = ST_OK; break;
			}

			if (inf->status.flags & F_SYNC)
			{
				if (inf->status.flags & F_REENCRYPT)
				{
					if (check_shadows(inf, inf->status.crypt.wp_mode) != ST_OK) { resl = ST_OK; break; }
					resl = dc_encrypt_loop(inf, crypt.wp_mode);
					break;
				} else 
				{
					wprintf(L"This device is not complete encrypted\n");
					resl = ST_OK; break;
				}
			}

			pass = dc_load_pass_and_keyfiles(NULL, NULL, NULL, NULL, 0);

			if (pass == NULL) {
				resl = ST_OK; break;
			}

			InterlockedExchange(&g_abort_operation, 0);
			resl = dc_start_re_encrypt(inf->device, pass, &crypt, &g_abort_operation);

			secure_free(pass);

			if (resl == ST_OK && check_shadows(inf, crypt.wp_mode) == ST_OK) {
				resl = dc_encrypt_loop(inf, crypt.wp_mode);
			}
			break;
		}

		if ( (argc >= 3) && (wcscmp(argv[1], L"-chpass") == 0) ) 
		{
			//crypt_info crypt;
			dc_pass   *old_p, *new_p;
			int flags = 0; // todo
			
			if ( (inf = find_device(argv[2])) == NULL ) {
				resl = ST_NF_DEVICE; break;
			}

			if (is_locked_msg(inf, argv[2]) != 0) {
				resl = ST_DEVICE_BUSY; break;
			}

			if ( !(inf->status.flags & F_ENABLED) ) {
				wprintf(L"This device is not mounted\n");
				resl = ST_OK; break;
			}

			if (inf->status.flags & F_SYNC) {
				wprintf(L"This device is not complete encrypted\n");
				resl = ST_OK; break;
			}

			if (inf->status.flags & F_FORMATTING) {
				wprintf(L"Invalid device state\n");
				resl = ST_OK; break;
			}

			//crypt = inf->status.crypt;
			//
			//get_crypt_info(&crypt);

			old_p = NULL; new_p = NULL;
			do
			{
				old_p = dc_load_pass_and_keyfiles(
					L"-op", L"-oc", L"-okf", L"Enter old password: ", 0);

				if (old_p == NULL) {
					resl = ST_OK; break;
				}

				new_p = dc_load_pass_and_keyfiles(
					L"-np", L"-nc", L"-nkf", L"Enter new password: ", 1);

				if (new_p == NULL) {
					resl = ST_OK; break;
				}

				InterlockedExchange(&g_abort_operation, 0);
				resl = dc_change_password(inf->device, old_p, new_p, flags, &g_abort_operation);

				if (resl == ST_OK) {
					wprintf(L"The password successfully changed\n");
				}
			} while (0);

			if (old_p != NULL) {
				secure_free(old_p);
			}

			if (new_p != NULL) {
				secure_free(new_p);
			}
			break;
		}

		if ( (argc >= 3) && (wcscmp(argv[1], L"-format") == 0) ) 
		{
			crypt_info crypt;
			dc_pass   *pass;
			wchar_t   *fs;
			int        flags = 0;

			if ( (inf = find_device(argv[2])) == NULL ) {
				resl = ST_NF_DEVICE; break;
			}

			if (is_locked_msg(inf, argv[2]) != 0) {
				resl = ST_DEVICE_BUSY; break;
			}

			crypt = inf->status.crypt;
			get_crypt_info(&crypt);

			if (is_param(L"-backup_header")) {
				flags |= VF_BACKUP_HEADER;
			}

			if (inf->status.flags & F_FORMATTING) {				
				resl = ST_OK;
			} else 
			{
				if (inf->status.flags & F_ENABLED) {
					wprintf(L"This device is mounted, please unmount it\n");
					resl = ST_OK; break;
				}

				pass = dc_load_pass_and_keyfiles(NULL, NULL, NULL, NULL, 1);

				if (pass == NULL) {
					resl = ST_OK; break;
				}

				InterlockedExchange(&g_abort_operation, 0);
				resl = dc_start_format(inf->device, pass, &crypt, flags, &g_abort_operation);

				secure_free(pass);
			}

			if (resl == ST_OK) 
			{
				if (is_param(L"-q") != 0) {
					resl = dc_done_format(inf->device);
				} else {
					resl = dc_format_loop(inf, crypt.wp_mode);
				}

				if (is_param(L"-ntfs") != 0) {
					fs = L"NTFS";
				} else if (is_param(L"-fat") != 0) {
					fs = L"FAT";
				} else if (is_param(L"-fat32") != 0) {
					fs = L"FAT32";
				} else if (is_param(L"-exfat") != 0) {
					fs = L"exFAT";
				} else fs = NULL;

				if (resl == ST_OK) 
				{
					wprintf(L"Creating file system...\n");

					if (fs != NULL) {
						resl = dc_format_fs(inf->w32_device, fs);
					}

					if (resl == ST_OK) {
						wprintf(L"Formatting successfully completed.\n");
					}
				}
			}
			break;
		}

		if ( (argc >= 2) && (wcscmp(argv[1], L"-benchmark") == 0) )
		{
			dc_bench_info info;
			bench_item    bench[CF_CIPHERS_NUM];
			int           i;
			int           use_um = is_param(L"-um");

			if (use_um) {
				wprintf(L"Running user-mode benchmark...\n\n");
			}

			for (i = 0; i < CF_CIPHERS_NUM; i++) {
				int bench_result;
				if (use_um)
					bench_result = dc_benchmark_um(i, &info);
				else
					bench_result = dc_benchmark(i, &info);
				if (bench_result != ST_OK) break;
				bench[i].alg   = dc_get_cipher_name(i);
				bench[i].speed = (double)info.datalen / ( (double)info.enctime / (double)info.cpufreq) / 1024 / 1024;
			}
			qsort(&bench, CF_CIPHERS_NUM, sizeof(bench[0]), dc_bench_cmp);

			wprintf(
				L"---------------------+--------------\n"
				L"        cipher       |     speed\n"
				L"---------------------+--------------\n");

			for (i = 0; i < CF_CIPHERS_NUM; i++) {
				wprintf(L" %-19s | %-.2f mb/s\n", bench[i].alg, bench[i].speed);
			}
			resl = ST_OK; break;
		}

		if ( (argc >= 2) && (wcscmp(argv[1], L"-benchmark_kdf") == 0) )
		{
			dc_kdf_bench_info info;
			int               i;
			int               use_um = is_param(L"-um");
			int               bench_result;

			if (use_um) {
				wprintf(L"Running user-mode KDF benchmark...\n\n");
			}

			wprintf(
				L"------------------------------------------+-----------\n"
				L"                   KDF                    |    Time\n"
				L"------------------------------------------+-----------\n");

			/* Benchmark KDFs from kdf_bench_costs array */
			for (i = 0; i <= 10; i++)
			{
				wchar_t s_name[64];

				if (use_um)
					bench_result = dc_benchmark_kdf_um(i, &info);
				else
					bench_result = dc_benchmark_kdf(i, &info);

				if (i == 0) {
					wcscpy(s_name, L"PBKDF2-SHA512 [i=1000]");
				} else {
					_snwprintf(s_name, countof(s_name), L"Argon2id [%dMiB, t=%d, p=%d]",
						info.memory_mib, info.time_cost, info.parallelism);
				}

				if (bench_result != ST_OK) {
					wprintf(L" %-40s | error\n", s_name);
					continue;
				}

				if (info.elapsed_us == 0) {
					wprintf(L" %-40s | OUT OF MEM\n", s_name);
				} else {
					wprintf(L" %-40s | %8.2f ms\n", s_name, (double)info.elapsed_us / 1000.0);
				}
			}
			resl = ST_OK; break;
		}

		if ( (argc >= 4) && (wcscmp(argv[1], L"-backup") == 0) ) 
		{
			dc_pass *pass;
			int      bytes = DC_AREA_MAX_SIZE;
			u8      *backup = malloc(bytes);
			int      flags = 0; // todo

			if ( (inf = find_device(argv[2])) == NULL ) {
				resl = ST_NF_DEVICE; break;
			}

			if (is_locked_msg(inf, argv[2]) != 0) {
				resl = ST_DEVICE_BUSY; break;
			}

			if (inf->status.flags & F_SYNC) {
				wprintf(L"This device is not complete encrypted\n");
				resl = ST_OK; break;
			}

			pass = dc_load_pass_and_keyfiles(NULL, NULL, NULL, NULL, 0);

			if (pass == NULL) {
				resl = ST_OK; break;
			}

			InterlockedExchange(&g_abort_operation, 0);
			resl = dc_backup_header(inf->device, pass, backup, &bytes, flags, &g_abort_operation);

			secure_free(pass);

			if (resl == ST_OK) {
				resl = save_file(argv[3], backup, bytes);
			}

			secure_free(backup);

			if (resl == ST_OK) {
				wprintf(L"Volume header backup successfully saved.\n");
			}			
		}

		if ( (argc >= 4) && (wcscmp(argv[1], L"-restore") == 0) ) 
		{
			dc_pass *pass;
			u8      *backup;
			u32      bytes;
			int      flags = 0; // todo

			if ( (inf = find_device(argv[2])) == NULL ) {
				resl = ST_NF_DEVICE; break;
			}

			if (inf->status.flags & F_ENABLED) {
				wprintf(L"Please unmount device first\n");
				resl = ST_OK; break;
			}

			do
			{
				if ( (resl = load_file(argv[3], &backup, &bytes)) != ST_OK ) {
					backup = NULL; break;
				}

				if (bytes != DC_AREA_SIZE) {
					resl = ST_NOT_BACKUP; break;
				}

				pass = dc_load_pass_and_keyfiles(NULL, NULL, NULL, NULL, 0);

				if (pass == NULL) {
					resl = ST_OK; break;
				}

				InterlockedExchange(&g_abort_operation, 0);
				resl = dc_restore_header(inf->device, pass, backup, bytes, flags, &g_abort_operation);

				secure_free(pass);
			} while (0);

			/* prevent leaks */
			if (backup != NULL) {
				burn(backup, DC_AREA_SIZE);
				free(backup);
			}

			if (resl == ST_OK) {
				wprintf(L"Volume header successfully restored.\n");
			}
		}

		if ( (argc >= 2) && (wcscmp(argv[1], L"-config") == 0) )
		{
			dc_conf_data dc_conf;

			if ( (resl = dc_load_config(&dc_conf) == NO_ERROR ? ST_OK : ST_ERROR) != ST_OK ) {
				break;
			}

			do
			{
				vol_inf *inf = find_device(NULL);
				int      onoff;
				char     ch;

				cls_console();

				wprintf(
					L"0 - On/Off passwords caching (%s)\n"
					L"1 - On/Off hiding $dcsys$ files (%s)\n"
					L"2 - On/Off hardware cryptography support (%s)\n"
					L"3 - On/Off automounting at boot time (%s)\n"
					L"4 - On/Off IO chunking for SSD disks [deprecated] (%s)\n"
					L"5 - On/Off disable TRIM on encrypted SSD disks (%s)\n"
					L"--------------------------------------------------\n"
					L"6 - On/Off Deny access to unencrypted removable devices (%s)\n"
					L"7 - On/Off Deny access to unencrypted HDDs (%s)\n"
					L"8 - On/Off Deny access to unencrypted CD-ROM (%s)\n"
					L"--------------------------------------------------\n"
					L"9 - On/Off Protect unmounted volumes from formatting (%s)\n"
					L"h - On/Off Allow hibernation by locking encrypted volumes, system not encrypted (%s)\n"
					L"--------------------------------------------------\n"
					L"x - Save changes and exit\n\n",
					on_off(dc_conf.conf_flags & CONF_CACHE_PASSWORD),
					on_off(dc_conf.conf_flags & CONF_HIDE_DCSYS),
					(dc_conf.load_flags & DST_HW_CRYPTO) ?
					    on_off(dc_conf.conf_flags & CONF_HW_CRYPTO) : L"not available",
					on_off(dc_conf.conf_flags & CONF_AUTOMOUNT_BOOT),
					on_off(dc_conf.conf_flags & CONF_ENABLE_SSD_OPT),
					on_off(dc_conf.conf_flags & CONF_DISABLE_TRIM),
					on_off(dc_conf.conf_flags & CONF_BLOCK_UNENC_REMOVABLE),
					(inf != NULL && IS_BLOCK_UNENC_HDDS_DISABLED(inf->status.flags) == 0) ?
					    on_off(dc_conf.conf_flags & CONF_BLOCK_UNENC_HDDS) : L"non permitted",
					on_off(dc_conf.conf_flags & CONF_BLOCK_UNENC_CDROM),
					on_off(dc_conf.conf_flags & CONF_PROTECT_RAW_VOLUMES),
					on_off(dc_conf.conf_flags & CONF_HIBER_LOCK)
					);

				do {
					ch = _getch();
					ch = tolower(ch);
				} while (!((ch >= '0' && ch <= '9') || ch == 'h' || ch == 'x'));

				if (ch == 'x') {
					break;
				}

				if ( ((ch == '2') && (dc_conf.load_flags & DST_HW_CRYPTO) == 0) ||
					 ((ch == '7') && (inf == NULL || IS_BLOCK_UNENC_HDDS_DISABLED(inf->status.flags))) )
				{
					continue;
				}

				wprintf(L"0 - OFF\n1 - ON\n"); onoff = (getchr('0', '1') == '1');

				switch (ch) {
					case '0': set_flag(dc_conf.conf_flags, CONF_CACHE_PASSWORD, onoff); break;
					case '1': set_flag(dc_conf.conf_flags, CONF_HIDE_DCSYS, onoff); break;
					case '2': set_flag(dc_conf.conf_flags, CONF_HW_CRYPTO, onoff); break;
					case '3': set_flag(dc_conf.conf_flags, CONF_AUTOMOUNT_BOOT, onoff); break;
					case '4': set_flag(dc_conf.conf_flags, CONF_ENABLE_SSD_OPT, onoff); break;
					case '5': set_flag(dc_conf.conf_flags, CONF_DISABLE_TRIM, onoff); break;
					/**/
					case '6': set_flag(dc_conf.conf_flags, CONF_BLOCK_UNENC_REMOVABLE, onoff); break;
					case '7': set_flag(dc_conf.conf_flags, CONF_BLOCK_UNENC_HDDS, onoff); break;
					case '8': set_flag(dc_conf.conf_flags, CONF_BLOCK_UNENC_CDROM, onoff); break;
					/**/
					case '9': set_flag(dc_conf.conf_flags, CONF_PROTECT_RAW_VOLUMES, onoff); break;
					case 'h':
						set_flag(dc_conf.conf_flags, CONF_HIBER_LOCK, onoff);
						if (onoff) {
							wprintf(
								L"Note: at hibernation the encrypted volumes are locked - their keys are erased, after\n"
								L"the resume each must be unlocked with its password. NOT protected: file contents and\n"
								L"file system data of these volumes held in memory go to the unencrypted hibernation\n"
								L"file. Fast Startup and hybrid sleep lock the volumes too.\n\n");
						}
						break;
				}
			} while (1);

			if ( (resl = dc_save_config(&dc_conf) == NO_ERROR ? ST_OK : ST_ERROR) == ST_OK ) {
				wprintf(L"Configuration successfully saved\n");
			}
		}

		if ( (argc >= 3) && (wcscmp(argv[1], L"-keygen") == 0) )
		{
			u8 kf[64];

			resl = dc_device_control(DC_CTL_GET_RAND, NULL, 0, kf, sizeof(kf)) == NO_ERROR ? ST_OK : ST_ERROR;

			if ( resl != ST_OK ) {
				break;
			}
			resl = save_file(argv[2], kf, sizeof(kf));
			/* prevent leaks */
			burn(kf, sizeof(kf));
		}

		if ( (argc >= 2) && (wcscmp(argv[1], L"-bsod") == 0) )
		{
			dc_get_bsod(); resl = ST_OK;
			break;
		}

		if ( (argc >= 2) && (wcscmp(argv[1], L"-support") == 0) )
		{
			if (is_param(L"-hwid"))
			{
				WCHAR uuid[40] = {0};
				if (dc_get_system_uuid(uuid, countof(uuid))) {
					wprintf(L"Hardware ID: %s\n", uuid);
					resl = ST_OK;
				} else {
					wprintf(L"Failed to retrieve hardware ID\n");
					resl = ST_ERROR;
				}
			}
			else if (is_param(L"-get_key"))
			{
				wchar_t* serial = get_param(L"-get_key");
				/* Serial key format: DC20_-XXXXX-XXXXX-XXXXX-XXXXX (29 chars) */
				if (!serial || wcslen(serial) < 29) {
					wprintf(L"Error: Valid serial key required (format: DC20_-XXXXX-XXXXX-XXXXX-XXXXX)\n");
					resl = ST_INVALID_PARAM; break;
				}

				wprintf(L"Downloading certificate...\n");

				PSTR cert = NULL;
				ULONG cert_len = 0;
				resl = dc_download_certificate(serial, &cert, &cert_len);

				if (resl == ST_OK && cert) {
					/* Save to certificate.dat in install directory */
					WCHAR path[MAX_PATH];
					GetModuleFileName(NULL, path, MAX_PATH);
					PathRemoveFileSpec(path);
					wcscat(path, L"\\certificate.dat");

					resl = save_file(path, cert, cert_len);
					free(cert);

					if (resl == ST_OK) {
						wprintf(L"Certificate saved to: %s\n", path);
					}
				}
			}
			else if (is_param(L"-apply_cert"))
			{
				WCHAR path[MAX_PATH];
				GetModuleFileName(NULL, path, MAX_PATH);
				PathRemoveFileSpec(path);
				wcscat(path, L"\\certificate.dat");

				char* cert = NULL;
				int cert_len = 0;

				resl = load_file(path, (void**)&cert, &cert_len);
				if (resl == ST_OK && cert) {
					/* Convert to wide string */
					int wlen = MultiByteToWideChar(CP_UTF8, 0, cert, cert_len, NULL, 0);
					WCHAR* wcert = malloc((wlen + 1) * sizeof(WCHAR));
					if (wcert) {
						MultiByteToWideChar(CP_UTF8, 0, cert, cert_len, wcert, wlen);
						wcert[wlen] = 0;

						resl = dc_save_certificate(wcert);

						free(wcert);
					} else {
						resl = ST_NOMEM;
					}
					free(cert);

					if (resl == ST_OK) {
						DC_FLAGS2 flags2;
						wprintf(L"Certificate applied to registry\n");
						/* dc_save_certificate had the driver check the new certificate:
						 * read the result */
						if (dc_device_control(DC_CTL_GET_FLAGS, NULL, 0, &flags2, sizeof(flags2)) == NO_ERROR) {
							wprintf(L"Certificate %s by the driver\n", (flags2.load_flags & DST_PRO_ENABLED) ? L"accepted" : L"NOT accepted");
						}
					}
				}
			}
			else if (is_param(L"-show"))
			{
				WCHAR cert[4096] = {0};
				resl = dc_load_certificate(cert, countof(cert));
				if (resl == ST_OK) {
					wprintf(L"%s\n", cert);
				}
			}
			else
			{
				wprintf(L"Unknown -support action. Use -help for usage.\n");
				resl = ST_INVALID_PARAM;
			}
			break;
		}

		if ( (argc >= 4) && (wcscmp(argv[1], L"-enciso") == 0) ) 
		{
			dc_pass   *pass;			
			crypt_info crypt;
			
			/* get encryption params */
			crypt.cipher_id = CF_AES;
			get_crypt_info(&crypt);

			pass = dc_load_pass_and_keyfiles(NULL, NULL, NULL, NULL, 1);

			if (pass == NULL) {
				resl = ST_OK; break;
			}

			resl = (dc_encrypt_iso_image(argv[2], argv[3], pass, crypt.cipher_id, dc_cd_callback, NULL) == NO_ERROR) ? ST_OK : ST_ERROR;

			_putch('\n');

			secure_free(pass);

			if (resl == ST_OK) {
				wprintf(L"ISO image successfully encrypted.\n");
			}
			if (resl == ST_CANCEL) { resl = ST_OK; }
		}
	} while (0);

	if (resl != ST_OK) {
		//wprintf(L"Error: %d\n", resl); // wprintf(L"Error: 0x%08x\n", resl);
		print_error(resl);
	}

	return resl;
}
