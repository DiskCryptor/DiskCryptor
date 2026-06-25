/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2020-2026
	* DavidXanatos <info@diskcryptor.org>
	* Copyright (c) 2008
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
#include "drv_ioctl.h"
#include "bootloader.h"
#include "misc.h"
#include "mbrinst.h"
#include "efiinst.h"
#include "gpt_sup.h"
#include "disk_name.h"
#include "console.h"

static int onoff_req()
{
	wprintf(L"0 - OFF\n1 - ON\n");

	return getchr('0', '1') == '1';
}

static void menu_0_1(ldr_config *conf)
{
	wchar_t  auth[MAX_PATH];
	wchar_t *dp_type;
	char     ch;
			
	do
	{
		cls_console();

		if (conf->options & LDR_OP_EPS_TMO) 
		{
			_snwprintf(
				auth, countof(auth), L"%d seconds", conf->timeout);
		} else {
			wcscpy(auth, L"disabled");
		}

		if (conf->logon_type & LDR_LT_DSP_PASS) {
			dp_type = L"display \"*\"";
		} else {
			dp_type = L"disabled";
		}

		wprintf(
			L"1 - On/Off \"enter password\" message (%s)\n"
			L"2 - Change display password type (%s)\n"
			L"3 - Change password prompt text (%S)\n"
			L"4 - Enable embedded keyfile (%s)\n"
			L"5 - Change authentication timeout (%s)\n"
			L"6 - Cancel timeout if any key pressed (%s)\n"
			L"7 - Return to main menu\n\n",
			on_off(conf->logon_type & LDR_LT_MESSAGE),
			dp_type,
			conf->eps_msg,
			conf->logon_type & LDR_LT_EMBED_KEY ? L"enabled":L"disabled",
			auth,
			on_off(conf->options & LDR_OP_TMO_STOP));

		if ( (ch = getchr('1', '7')) == '7' ) {
			break;
		}

		if (ch == '1') {
			set_flag(conf->logon_type, LDR_LT_MESSAGE, onoff_req());
		}

		if (ch == '2')
		{
			wprintf(
				L"1 - disabled\n"
				L"2 - display \"*\"\n");

			if (getchr('1', '2') == '2') {
				conf->logon_type |= LDR_LT_DSP_PASS;
			} else {
				conf->logon_type &= ~LDR_LT_DSP_PASS;
			}
		}

		if (ch == '3') 
		{
			wprintf(L"Enter new prompt text: ");

			memset(conf->eps_msg, 0, sizeof(conf->eps_msg));
			fgets(conf->eps_msg, _countof(conf->eps_msg), stdin);
			conf->eps_msg[strlen(conf->eps_msg) - 1] = 0;
		}

		if (ch == '4')
		{
			wchar_t path[MAX_PATH];
			u8     *keyfile;
			u32     keysize;

			wprintf(L"Please enter path to keyfile: ");

			memset(&conf->emb_key, 0, sizeof(conf->emb_key));
			conf->logon_type &= ~LDR_LT_EMBED_KEY;
			conf->logon_type |= LDR_LT_GET_PASS;
			
			fgetws(path, _countof(path), stdin);
			path[wcslen(path) - 1] = 0;
			
			if (path[0] != 0)
			{
				if (load_file(path, &keyfile, &keysize) != ST_OK) {
					wprintf(L"keyfile not loaded\n");
					Sleep(1000);
				} else
				{
					if (keysize != 64) {
						wprintf(L"Embedded keyfile must be 64byte size\n");						
						Sleep(1000);
					} else 
					{
						wprintf(
							L"1 - Use embedded keyfile and password\n"
							L"2 - Use only embedded keyfile\n");

						if (getchr('1', '2') == '2') {							
							conf->logon_type &= ~LDR_LT_GET_PASS;
						}

						memcpy(&conf->emb_key, keyfile, sizeof(conf->emb_key));
						conf->logon_type |= LDR_LT_EMBED_KEY;
					}
					burn(keyfile, keysize);
					my_free(keyfile);
				}
			}
		}

		if (ch == '5')
		{				
			wprintf(L"Enter new timeout in seconds or 0 to disable: ");

			if (wscanf(L"%d", &conf->timeout) == 0) {
				conf->timeout = 0;
			}

			set_flag(conf->options, LDR_OP_EPS_TMO, (conf->timeout != 0));
		}

		if (ch == '6') {
			set_flag(conf->options, LDR_OP_TMO_STOP, onoff_req());
		}
	} while (1);
}

static void menu_0_2(ldr_config *conf)
{
	wchar_t *action;
	char     inv_msg[MAX_PATH];
	int      msgf, i, j;
	char     ch;	

	do
	{
		cls_console();

		action = L"halt system";

		if (conf->error_type & LDR_ET_REBOOT) {
			action = L"reboot system";
		}

		if (conf->error_type & LDR_ET_BOOT_ACTIVE) {
			action = L"boot from active partition";
		}

		if (conf->error_type & LDR_ET_EXIT_TO_BIOS) {
			action = L"exit to BIOS";
		}

		if (conf->error_type & LDR_ET_RETRY) {
			action = L"retry authentication";
		}

		if (conf->error_type & LDR_ET_MBR_BOOT) {
			action = L"load boot disk";
		}

		for (i = 0, j = 0; i < sizeof(conf->err_msg); i++) {
			if (conf->err_msg[i] != '\n') {
				inv_msg[j++] = conf->err_msg[i];
			}
		}

		inv_msg[j] = 0;

		wprintf(
			L"1 - On/Off invalid password message (%s)\n"
			L"2 - Invalid password action (%s)\n"
			L"3 - Invalid password message (%S)\n"
			L"4 - Return to main menu\n\n",
			on_off(conf->error_type & LDR_ET_MESSAGE),
			action, inv_msg);

		if ( (ch = getchr('1', '4')) == '4' ) {
			break;
		}

		if (ch == '1') {
			set_flag(conf->error_type, LDR_ET_MESSAGE, onoff_req());
		}

		if (ch == '2')
		{
			wprintf(
				L"1 - halt system\n"
				L"2 - reboot system\n"
				L"3 - boot from active partition\n"
				L"4 - load boot disk\n"
				L"5 - exit to BIOS\n"
				L"6 - retry authentication\n");

			msgf = (conf->error_type & LDR_ET_MESSAGE);

			switch (getchr('1', '6'))
			{
				case '1': conf->error_type = 0; break;
				case '2': conf->error_type = LDR_ET_REBOOT; break;
				case '3': conf->error_type = LDR_ET_BOOT_ACTIVE; break;
				case '4': conf->error_type = LDR_ET_MBR_BOOT; break;
				case '5': conf->error_type = LDR_ET_EXIT_TO_BIOS; break;
				case '6': conf->error_type = LDR_ET_RETRY; break;
			}

			conf->error_type |= msgf;
		}

		if (ch == '3') 
		{
			wprintf(L"Enter new message text: ");

			memset(conf->err_msg, 0, sizeof(conf->err_msg));
			fgets(conf->err_msg, _countof(conf->err_msg), stdin);
		}
	} while (1);
}

static u32 disk_id_select()
{
	vol_inf *vol;
	u32      i, idn = 0;
	u32      ids[MAX_VOLUMES];
	wchar_t  s_size[MAX_PATH];
	u32      id = 0;

	for (i = 0; i < vol_cnt; i++)
	{
		vol = &volumes[i];

		if ( (vol->status.flags & F_ENABLED) && (vol->status.disk_id != 0) ) 
		{
			dc_format_byte_size(
				s_size, countof(s_size), vol->status.dsk_size
				);

			if (idn == 0) {
				wprintf(L"\nSelect partition:\n");
			}

			ids[idn++] = vol->status.disk_id;

			wprintf(
				L"%d - pt%d (%s) (%s)\n", 
				idn, i, vol->status.mnt_point, s_size);		
		}
	}

	if (idn == 0) {
		wprintf(L"Mounted partitions with valid disk_id not found\n");
		_getch();
	} else {
		id = ids[getchr('1', '1'+(u8)idn-1) - '1'];
	}

	return id;
}

static void menu_0_3(ldr_config *conf)
{
	wchar_t *methd = NULL;
	wchar_t  part[MAX_PATH];
	wchar_t  s_size[MAX_PATH];
	u32      i, found, id;
	char     ch;
	vol_inf *vol;	

	do
	{
		cls_console();

		switch (conf->boot_type)
		{
			case LDR_BT_MBR_BOOT: methd = L"load boot disk"; break;
			case LDR_BT_MBR_FIRST: methd = L"load first disk"; break;
			case LDR_BT_ACTIVE: methd = L"load OS from active partition"; break;
			case LDR_BT_AP_PASSWORD: methd = L"boot from first partition with appropriate password"; break;
			case LDR_BT_DISK_ID:
				{
					/* find partition by disk_id */
					found = 0;
					for (i = 0; i < vol_cnt; i++)
					{
						vol = &volumes[i];

						if ( (vol->status.flags & F_ENABLED) && (vol->status.disk_id == conf->disk_id) ) 
						{
							dc_format_byte_size(
								s_size, countof(s_size), vol->status.dsk_size);

							_snwprintf(
								part, countof(part), L"boot from pt%d (%s) (%s)", 
								i, vol->status.mnt_point, s_size);
							found = 1;
						}
					}

					if (found == 0) 
					{
						_snwprintf(
							part, countof(part), L"boot from unknown partition, id %0.8x", conf->disk_id);
					}
					methd = part;
				}
			break;
		}

		if (conf->options & LDR_OP_EXTERNAL)
		{
			wprintf(
				L"Current booting method: %s\n\n"
				L"1 - Set \"load first disk\"\n"
				L"2 - Set \"boot from first partition with appropriate password\"\n"
				L"3 - Set \"boot from specified partition\"\n"
				L"4 - Return to main menu\n\n",
				methd);
		} else 
		{
			wprintf(
				L"Current booting method: %s\n\n"
				L"1 - Set \"load boot disk\"\n"
				L"2 - Set \"load first disk\"\n"
				L"3 - Set \"load OS from active partition\"\n"
				L"4 - Set \"boot from first partition with appropriate password\"\n"
				L"5 - Set \"boot from specified partition\"\n"
				L"6 - Return to main menu\n\n",
				methd);
		}

		if (conf->options & LDR_OP_EXTERNAL)
		{
			if ( (ch = getchr('1', '4')) == '4' ) {
				break;
			}

			switch (ch)
			{
				case '1': conf->boot_type = LDR_BT_MBR_FIRST; break;
				case '2': conf->boot_type = LDR_BT_AP_PASSWORD; break;
				case '3': 
					{
						if ( (id = disk_id_select()) != 0 ) {
							conf->disk_id   = id;
							conf->boot_type = LDR_BT_DISK_ID;
						}
					}
				break;
			}
		} else 
		{
			if ( (ch = getchr('1', '6')) == '6' ) {
				break;
			}

			switch (ch)
			{
				case '1': conf->boot_type = LDR_BT_MBR_BOOT; break;
				case '2': conf->boot_type = LDR_BT_MBR_FIRST; break;
				case '3': conf->boot_type = LDR_BT_ACTIVE; break;
				case '4': conf->boot_type = LDR_BT_AP_PASSWORD; break;
				case '5':
					{
						if ( (id = disk_id_select()) != 0 ) {
							conf->disk_id   = id;
							conf->boot_type = LDR_BT_DISK_ID;
						}
					}
				break;
			}
		}
	} while (1);
}

static void menu_0_4(ldr_config *conf)
{
	wchar_t *layout = NULL;
	char     ch; 

	do
	{
		cls_console();

		switch (conf->kbd_layout)
		{
			case LDR_KB_QWERTY: layout = L"QWERTY"; break;
			case LDR_KB_QWERTZ: layout = L"QWERTZ"; break;
			case LDR_KB_AZERTY: layout = L"AZERTY"; break;
		}

		wprintf(
			L"Current keyboard layout: %s\n\n"
			L"1 - Set layout to \"QWERTY\"\n"
			L"2 - Set layout to \"QWERTZ\"\n"
			L"3 - Set layout to \"AZERTY\"\n"
			L"4 - Return to main menu\n\n",
			layout);

		if ( (ch = getchr('1', '4')) == '4' ) {
			break;
		}

		switch (ch)
		{
			case '1': conf->kbd_layout = LDR_KB_QWERTY; break;
			case '2': conf->kbd_layout = LDR_KB_QWERTZ; break;
			case '3': conf->kbd_layout = LDR_KB_AZERTY; break;			
		}
	} while (1);
}

void boot_conf_menu(ldr_config *conf, wchar_t *msg)
{
	char ch;

	do
	{
		cls_console();

		if (msg != NULL) {
			wprintf(L"%s\n\n", msg);
		}

		wprintf(
			L"1 - Change logon options\n"
			L"2 - Change incorrect password action\n"
			L"3 - Use incorrect password action if no password entered (%s)\n"
			L"4 - Use hardware cryptography when possible (%s)\n"
			L"5 - Set booting method\n"
			L"6 - Set bootauth keyboard layout\n"
			L"7 - Save changes and exit\n\n",
			on_off(conf->options & LDR_OP_NOPASS_ERROR),
			on_off(conf->options & LDR_OP_HW_CRYPTO)
			);

		if ( (ch = getchr('1', '7')) == '7' ) {
			break;
		}

		switch (ch)
		{
			case '1': menu_0_1(conf); break;
			case '2': menu_0_2(conf); break;
			case '3': {
				set_flag(conf->options, LDR_OP_NOPASS_ERROR, onoff_req());
			}
			break;
			case '4': {
				set_flag(conf->options, LDR_OP_HW_CRYPTO, onoff_req());
			}
			break;
			case '5': menu_0_3(conf); break;
			case '6': menu_0_4(conf); break;
		}
	} while (1);
}

static int dsk_num(wchar_t *str, int *num) 
{
	//if ( ((str[0] == L'h') || (str[0] == L's')) && (str[1] == L'd') && (isdigit(str[2]) != 0) ) { // hd* hdd, sd* ssd
	if ( (str[0] == L'h') && (str[1] == L'd') && (isdigit(str[2]) != 0) ) {
		num[0] = _wtoi(str+2);
		return 1;
	} else {
		return 0;
	}
}

static int dc_is_disk_ssd(int dsk_num)
{
	wchar_t disk[MAX_PATH];
	_snwprintf(disk, countof(disk), L"\\\\.\\PhysicalDrive%d", dsk_num);
	return dc_is_device_ssd(disk);
}

int boot_menu(int argc, wchar_t *argv[])
{
	ldr_config conf;
	int        resl = ST_INVALID_PARAM;
	int        is_small = 0;
	int        is_shim = -1;
	int        is_bme = -1;
	int        is_esp = -1;

	if (is_param(L"-small")) is_small = 1;

	if (is_param(L"-shim")) is_shim = 1;
	else if (is_param(L"-noshim")) is_shim = 0;

	if (is_param(L"-bme")) is_bme = 1;
	else if (is_param(L"-nobme")) is_bme = 0;

	if (is_param(L"-esp")) is_esp = 1;
	else if (is_param(L"-noesp")) is_esp = 0;

	do
	{
		if ((argc == 3) && (wcscmp(argv[2], L"-mode") == 0))
		{
			int			is_efi = dc_efi_check();
			int			sb_enabled = is_efi ? dc_efi_is_secureboot() : 0;
			int			has_dcs_esp = is_efi ? (dc_find_dcs_esp(-1) > 0) : 0;
			const wchar_t *mode_str = is_efi ? (has_dcs_esp ? L"ESP" : L"EFI") : L"MBR";

			wprintf(L"Boot mode: %s%s\n", mode_str, sb_enabled ? L" (SecureBoot)" : L"");

			resl = ST_OK; break;
		}
		
		if ( (argc == 3) && (wcscmp(argv[2], L"-enum") == 0) )
		{
			wchar_t  s_size[MAX_PATH];
			wchar_t  h_name[MAX_PATH];
			wchar_t  str[16];
			u64      size;
			int      i, bd_1, bd_2;
			int      is_gpt;
			int      mbr_ldr, efi_ldr, has_bme, replaced_ms, has_shim;

			wprintf(
				L"-------------------------------------------------------------------\n"
				L"HDD  |           name            |  size   | bootable | bootloader \n" 
				L"-----+---------------------------+---------+----------+------------\n");

			if (dc_efi_check()) {
				bd_1 = bd_2 = dc_efi_get_os_disk();
			} else if (dc_get_boot_disk(&bd_1, &bd_2) != ST_OK) {
				bd_1 = bd_2 = -1;
			}

			for (i = 0; i < 100; i++)
			{
				if (size = dc_dsk_get_size(i, 0)) 
				{
					dc_format_byte_size(s_size, countof(s_size), size);

					if (dc_get_hw_name(i, 0, h_name, countof(h_name)) != ST_OK) {
						h_name[0] = 0;
					}

					is_gpt = (dc_is_gpt_disk(i) == 1);
					//mbr_ldr = (dc_get_mbr_config(i, NULL, &conf) == ST_OK);
					mbr_ldr = (dc_has_dc_mbr(i) == ST_OK);
					efi_ldr = (dc_get_efi_config(i, NULL, &conf) == ST_OK);

					if (mbr_ldr && efi_ldr) {
						wcscpy(str, L"MBR, EFI");
					} else if (mbr_ldr) {
						wcscpy(str, L"MBR");
					} else if (efi_ldr) {
						wcscpy(str, L"EFI");
					} else {
						wcscpy(str, L"none");
					}

					if (efi_ldr) {
						has_bme = dc_efi_is_bme_set(i);
						has_shim = dc_efi_is_shim_set(i);
						replaced_ms = dc_efi_is_msft_boot_replaced(i, -1);
						if (has_bme)
							wcscat(str, L"<");
						else
							wcscat(str, L" ");
						if (has_shim)
							wcscat(str, L"~");
						if (replaced_ms)
							wcscat(str, L"+");
					}

					wprintf(
						L"hd%d%s | %-25s | %-8s| %-3s, %-3s | %s\n",
						i, dc_is_disk_ssd(i) ? L"*" : L" ", h_name, s_size, is_gpt ? L"GPT" : L"MBR", (i == bd_1) || (i == bd_2) ? L"yes" : L"no", str
					);
				} 
			}

			//wprintf(
			//	L"-------------------------------------------------------------------\n"
			//	L"* - SSD detected\n"
			//	L"< - EFI Boot Menu Entry present\n"
			//	L"+ - Windows bootloader replaced to load DCS loader\n"
			//	L"~ - Secure Boot Shim installed\n"
			//);

			resl = ST_OK; break;
		}

		if ( (argc >= 4) && (wcscmp(argv[2], L"-setmbr") == 0) )
		{
			int d_num;
			
			if (dsk_num(argv[3], &d_num) == 0) {
				resl = ST_OK; break;
			}			

			if ( (resl = dc_set_boot_interactive(d_num, is_small)) == ST_OK) {
				wprintf(L"Bootloader successfully installed to %s\n", argv[3]);
			}
			break; 
		}

		if ( (argc == 4) && (wcscmp(argv[2], L"-delmbr") == 0) )
		{
			int d_num;
			
			if (dsk_num(argv[3], &d_num) == 0) {
				resl = ST_OK; break;
			}

			if ( (resl = dc_unset_mbr(d_num)) == ST_OK ) {
				wprintf(L"Bootloader successfully removed from %s\n", argv[3]);
			}
			break;
		}

		if ( (argc == 4) && (wcscmp(argv[2], L"-updmbr") == 0) )
		{
			int d_num;
			
			if (dsk_num(argv[3], &d_num) == 0) {
				resl = ST_OK; break;
			}

			if ( (resl = dc_update_boot(d_num)) == ST_OK ) {
				wprintf(L"Bootloader on %s successfully updated\n", argv[3]);
			}
			break;
		}	

		if ( (argc >= 4) && (wcscmp(argv[2], L"-setpar") == 0) )
		{
			if ( (resl = dc_set_boot(argv[3], 0, is_small)) == ST_FORMAT_NEEDED )
			{
				wprintf(
				   L"Removable media not correctly formatted\n"
				   L"Format media? (Y/N)\n"
				   );

				if (tolower(_getch()) == 'y') {
					resl = dc_set_boot(argv[3], 1, is_small);
				} else {
					resl = ST_OK; break;
				}
			}

			if (resl != ST_OK) {
				break;
			}

			if ( (resl = dc_mbr_config_by_partition(argv[3], 0, &conf)) != ST_OK ) {
				break;
			}

			conf.options  |= LDR_OP_EXTERNAL;
			conf.boot_type = LDR_BT_AP_PASSWORD;

			boot_conf_menu(
				&conf, L"Please set bootloader options:");

			if ( (resl = dc_mbr_config_by_partition(argv[3], 1, &conf)) == ST_OK ) {
				wprintf(L"Bootloader successfully installed\n");
			}
			break;
		}

		if ( (argc >= 4) && (wcscmp(argv[2], L"-makeiso") == 0) )
		{
			if ( (resl = dc_make_iso(argv[3], is_small)) != ST_OK ) {
				break;
			}

			if ( (resl = dc_get_mbr_config(0, argv[3], &conf)) != ST_OK ) {
				break;
			}

			conf.options  |= LDR_OP_EXTERNAL;
			conf.boot_type = LDR_BT_MBR_FIRST;

			boot_conf_menu(
				&conf, L"Please set bootloader options:");

			if ( (resl = dc_set_mbr_config(0, argv[3], &conf)) == ST_OK ) {
				wprintf(L"Bootloader .iso image successfully created: %s\n", argv[3]);
			}
			break;
		}

		if ( (argc >= 4) && (wcscmp(argv[2], L"-makepxe") == 0) )
		{
			if ( (resl = dc_make_pxe(argv[3], is_small)) != ST_OK ) {
				break;
			}

			if ( (resl = dc_get_mbr_config(0, argv[3], &conf)) != ST_OK ) {
				break;
			}

			conf.options  |= LDR_OP_EXTERNAL;
			conf.boot_type = LDR_BT_MBR_FIRST;

			boot_conf_menu(
				&conf, L"Please set bootloader options:");

			if ( (resl = dc_set_mbr_config(0, argv[3], &conf)) == ST_OK ) {
				wprintf(L"Bootloader PXE image successfully created: %s\n", argv[3]);
			}
			break;
		}

		if ( (argc >= 4) && (wcscmp(argv[2], L"-mkefiiso") == 0) )
		{
			if ( (resl = dc_make_efi_iso(argv[3], is_shim)) != ST_OK ) {
				break;
			}

			dc_efi_config_init(&conf);
			conf.options  |= LDR_OP_EXTERNAL;
			conf.boot_type = LDR_BT_MBR_FIRST;

			boot_conf_menu(
				&conf, L"Please set EFI bootloader options:");

			if ( (resl = dc_set_efi_config(0, argv[3], &conf)) == ST_OK ) {
				wprintf(L"EFI Bootloader ISO image successfully created: %s\n", argv[3]);
			}
			break;
		}

		if ( (argc >= 4) && (wcscmp(argv[2], L"-mkefipxe") == 0) )
		{
			if ( (resl = dc_make_efi_pxe(argv[3], is_shim)) != ST_OK ) {
				break;
			}

			dc_efi_config_init(&conf);
			conf.options  |= LDR_OP_EXTERNAL;
			conf.boot_type = LDR_BT_MBR_FIRST;

			boot_conf_menu(
				&conf, L"Please set EFI bootloader options:");

			if ( (resl = dc_set_efi_config(0, argv[3], &conf)) == ST_OK ) {
				wprintf(L"EFI Bootloader PXE image successfully created: %s\n", argv[3]);
			}
			break;
		}

		if ( (argc == 4) && (wcscmp(argv[2], L"-config") == 0) )
		{
			int      d_num;
			wchar_t *file;
			int      ispar;
			int      isefi;
			
			if ( ((argv[3][1] == L':')  && (argv[3][2] == 0)) ||
				 ((argv[3][0] == L'\\') && (argv[3][5] == L':')) )
			{
				ispar = 1;
			} 
			else 
			{
				if (dsk_num(argv[3], &d_num) == 0) {
					file = argv[3]; d_num = 0;
				} else {
					file = NULL;
				}

				ispar = 0;
			}

			if (!file){
				if (ispar != 0) { isefi = dc_is_dcs_on_partition(argv[3]);
				} else { isefi = dc_is_dcs_on_disk(d_num); }
			}

			if (isefi) { // EFI
				if (ispar != 0) { resl = dc_efi_config_by_partition(argv[3], 0, &conf); }
				else { resl = dc_get_efi_config(d_num, NULL, &conf); }
			} else { // MBR
				if (ispar != 0) { resl = dc_mbr_config_by_partition(argv[3], 0, &conf); }
				else { resl = dc_get_mbr_config(d_num, file, &conf); }
			}

			if (resl != ST_OK) {
				break;
			}

			boot_conf_menu(
				&conf, L"Please change bootloader options:");

			if (isefi) { // EFI
				if (ispar != 0) { resl = dc_efi_config_by_partition(argv[3], 1, &conf); }
				else { resl = dc_set_efi_config(d_num, NULL, &conf); }
			} else { // MBR
				if (ispar != 0) { resl = dc_mbr_config_by_partition(argv[3], 1, &conf); }
				else { resl = dc_set_mbr_config(d_num, file, &conf); }
			}

			if (resl == ST_OK) {
				wprintf(L"Bootloader configuration successfully changed\n");
			}
			break;
		}

		// EFI
		if ((argc >= 4) && (wcscmp(argv[2], L"-setefi") == 0))
		{
			int d_num;

			if (dsk_num(argv[3], &d_num) == 0) {
				resl = ST_OK; break;
			}

			if ((resl = dc_set_efi_boot_interactive(d_num, is_bme, is_shim, is_esp)) == ST_OK) {
				wprintf(L"EFI bootloader successfully installed to %s\n", argv[3]);
			}
			break;
		}

		if ((argc >= 4) && (wcscmp(argv[2], L"-updefi") == 0))
		{
			int d_num;

			if (dsk_num(argv[3], &d_num) == 0) {
				resl = ST_OK; break;
			}

			if ( (resl = dc_update_efi_boot(d_num, -1)) == ST_OK ) {
				wprintf(L"EFI bootloader on %s successfully updated\n", argv[3]);
			}
			break;
		}

		if ((argc >= 3) && (wcscmp(argv[2], L"-delefi") == 0))
		{
			int d_num = -1;

			/* Try to find disk number in argv[3] or argv[4] */
			if (argc >= 4 && dsk_num(argv[3], &d_num) != 0) {
				/* Found disk in argv[3] */
			} else if (argc >= 5 && dsk_num(argv[4], &d_num) != 0) {
				/* Found disk in argv[4] */
			}

			/* If -esp specified, delete the DCS ESP partition */
			if (is_esp == 1) {
				/* Use OS disk if no disk specified */
				if (d_num == -1) {
					d_num = dc_efi_get_os_disk();
					wprintf(L"Using OS disk: %d\n", d_num);
				}

				if (d_num < 0) {
					wprintf(L"Error: Could not determine disk number\n");
					resl = ST_NF_DEVICE;
					break;
				}

				/* Find DCS ESP partition by label/name and delete it */
				wprintf(L"Searching for DCS ESP partition on disk %d...\n", d_num);
				int dcs_esp = dc_find_dcs_esp(d_num);
				if (dcs_esp > 0) {
					wprintf(L"Found DCS ESP partition: %d\n", dcs_esp);
					wprintf(L"Deleting partition...\n");
					resl = dc_gpt_delete_partition(d_num, dcs_esp);
					if (resl == ST_OK) {
						wprintf(L"DCS ESP partition %d successfully deleted\n", dcs_esp);
					} else {
						wprintf(L"Error: Could not delete DCS ESP partition %d, error %d\n", dcs_esp, resl);
					}
				} else {
					wprintf(L"No DCS ESP partition found (looked for GPT name 'DCS Boot' or label 'DCS_BOOT')\n");
					resl = ST_NF_DEVICE;
				}
			} else {
				/* Normal -delefi without -esp */
				if (d_num == -1) {
					wprintf(L"Error: Disk number required (e.g., hd0)\n");
					resl = ST_NF_DEVICE;
					break;
				}
				if ((resl = dc_unset_efi_boot(d_num, -1)) == ST_OK) {
					wprintf(L"EFI bootloader successfully removed\n");
				}
			}
			break;
		}

		if ((argc == 4) && (wcscmp(argv[2], L"-getinfo") == 0))
		{
			int d_num;
			char* infoContent = NULL;
			DWORD size = 0;
			
			if (dsk_num(argv[3], &d_num) == 0) {
				resl = ST_OK; break;
			}

			resl = dc_get_platform_info(d_num, &infoContent, &size);
			if (resl == ST_OK) {
				for (DWORD i = 0; i < size; i++) {
					if (infoContent[i] == '\r') continue;
					putchar(infoContent[i]);
				}

				free(infoContent);
			}
			break;
		}

		if ((argc >= 3) && (wcscmp(argv[2], L"-addbme") == 0))
		{
			int d_num;

			if (dsk_num(argv[3], &d_num) == 0) {
				resl = ST_OK; break;
			}

			if ((resl = dc_efi_set_bme(L"DiskCrypto (DCS) loader", d_num)) == ST_OK) {
				wprintf(L"DCS boot menu entry successfully added for %s\n", argv[3]);
			}
			break;
		}

		if ((argc >= 3) && (wcscmp(argv[2], L"-rembme") == 0))
		{
			if ((resl = dc_efi_del_bme()) == ST_OK) {
				wprintf(L"DCS boot menu entry successfully removed\n");
			}
			break;
		}

		if ((argc >= 3) && (wcscmp(argv[2], L"-replacems") == 0))
		{
			int d_num;

			if (dsk_num(argv[3], &d_num) == 0) {
				resl = ST_OK; break;
			}

			if ((resl = dc_efi_replace_msft_boot(d_num, -1)) == ST_OK) {
				wprintf(L"DCS bootloader successfully replaced Microsoft Boot Manager file (bootmgfw.efi) on %s\n", argv[3]);
			}
			break;
		}

		if ((argc >= 3) && (wcscmp(argv[2], L"-restorems") == 0))
		{
			int d_num;

			if (dsk_num(argv[3], &d_num) == 0) {
				resl = ST_OK; break;
			}

			if ((resl = dc_efi_restore_msft_boot(d_num, -1)) == ST_OK) {
				wprintf(L"Microsoft Boot Manager file (bootmgfw.efi) successfully restored on %s\n", argv[3]);
			}
			break;
		}

		if ((argc >= 3) && (wcscmp(argv[2], L"-removems") == 0))
		{
			if ((resl = dc_efi_del_msft_bme()) == ST_OK) {
				wprintf(L"Windows Boot Manager EFI boot entry successfully removed\n");
			} else {
				wprintf(L"Windows Boot Manager EFI boot entry not found\n");
			}
			break;
		}

		if ((argc >= 4) && (wcscmp(argv[2], L"-makerec") == 0))
		{
			if ( (resl = dc_make_efi_rec(argv[3], 0, is_shim)) == ST_FORMAT_NEEDED )
			{
				wprintf(
				   L"Removable media not correctly formatted\n"
				   L"Format media? (Y/N)\n"
				   );

				if (tolower(_getch()) == 'y') {
					resl = dc_make_efi_rec(argv[3], 1, is_shim);
				} else {
					resl = ST_OK; break;
				}
			}

			if (resl != ST_OK) {
				break;
			}

			if ( (resl = dc_efi_config_by_partition(argv[3], 0, &conf)) != ST_OK ) {
				break;
			}

			conf.options  |= LDR_OP_EXTERNAL;
			conf.boot_type = LDR_BT_AP_PASSWORD;

			boot_conf_menu(
				&conf, L"Please set EFI bootloader options:");

			if ( (resl = dc_efi_config_by_partition(argv[3], 1, &conf)) == ST_OK ) {
				wprintf(L"EFI recovery bootloader successfully installed\n");
			}
			break;
		}

		if ((argc >= 4) && (wcscmp(argv[2], L"-mountesp") == 0))
		{
			wchar_t letter = argv[3][0];
			wchar_t device_path[MAX_PATH];
			wchar_t disk_path[MAX_PATH];
			wchar_t dos_name[4];
			int dcs_esp_part;
			int os_disk;
			int is_dedicated = 0;
			HANDLE hdisk;
			DWORD bytes;
			u8 buff[sizeof(DRIVE_LAYOUT_INFORMATION_EX) + sizeof(PARTITION_INFORMATION_EX) * 127];
			PDRIVE_LAYOUT_INFORMATION_EX dli = pv(buff);

			/* Validate drive letter */
			if (!iswalpha(letter)) {
				wprintf(L"Error: Invalid drive letter '%s'\n", argv[3]);
				resl = ST_ERROR; break;
			}
			letter = towupper(letter);

			/* Check if drive letter is already in use */
			DWORD drives = GetLogicalDrives();
			if (drives & (1 << (letter - L'A'))) {
				wprintf(L"Error: Drive letter %c: is already in use\n", letter);
				resl = ST_ERROR; break;
			}

			/* Get OS disk */
			os_disk = dc_efi_get_os_disk();
			if (os_disk < 0) {
				wprintf(L"Error: Could not determine boot disk\n");
				resl = ST_NF_DEVICE; break;
			}

			/* Find DCS ESP partition */
			dcs_esp_part = dc_find_dcs_esp(os_disk);
			if (dcs_esp_part <= 0) {
				wprintf(L"Error: No dedicated DCS ESP partition found\n");
				wprintf(L"       (looked for GPT name 'DCS Boot' or label 'DCS_BOOT')\n");
				resl = ST_NF_DEVICE; break;
			}

			/* Check if partition has GPT name "DCS Boot" - confirms it's a dedicated ESP */
			_snwprintf(disk_path, MAX_PATH, L"\\\\.\\PhysicalDrive%d", os_disk);
			hdisk = CreateFile(disk_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
			if (hdisk != INVALID_HANDLE_VALUE) {
				if (DeviceIoControl(hdisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, NULL, 0, dli, sizeof(buff), &bytes, NULL)) {
					for (DWORD i = 0; i < dli->PartitionCount; i++) {
						if (dli->PartitionEntry[i].PartitionNumber == dcs_esp_part) {
							if (dli->PartitionStyle == PARTITION_STYLE_GPT &&
								_wcsicmp(dli->PartitionEntry[i].Gpt.Name, DCS_BOOT_PARTITION_NAME) == 0) {
								is_dedicated = 1;
							}
							break;
						}
					}
				}
				CloseHandle(hdisk);
			}

			if (!is_dedicated) {
				wprintf(L"Error: DCS is installed to the Windows EFI partition, not a dedicated DCS ESP\n");
				wprintf(L"       This command only works with a dedicated DCS ESP partition\n");
				wprintf(L"       (partition must have GPT name 'DCS Boot')\n");
				resl = ST_ERROR; break;
			}

			/* Build device path and mount */
			swprintf_s(device_path, MAX_PATH, L"\\Device\\Harddisk%d\\Partition%d", os_disk, dcs_esp_part);
			swprintf_s(dos_name, 4, L"%c:", letter);

			if (!DefineDosDevice(DDD_RAW_TARGET_PATH, dos_name, device_path)) {
				wprintf(L"Error: Failed to mount partition (error %d)\n", GetLastError());
				resl = ST_ERROR; break;
			}

			wprintf(L"DCS ESP partition %d mounted to %c:\\\n", dcs_esp_part, letter);
			resl = ST_OK;
			break;
		}

		//if ((argc >= 4) && (wcscmp(argv[2], L"-umountesp") == 0))
		//{
		//	wchar_t letter = argv[3][0];
		//	wchar_t device_path[MAX_PATH];
		//	wchar_t dos_name[4];
		//	int dcs_esp_part;
		//	int os_disk;

		//	/* Validate drive letter */
		//	if (!iswalpha(letter)) {
		//		wprintf(L"Error: Invalid drive letter '%s'\n", argv[3]);
		//		resl = ST_ERROR; break;
		//	}
		//	letter = towupper(letter);

		//	/* Get OS disk and DCS ESP for device path */
		//	os_disk = dc_efi_get_os_disk();
		//	if (os_disk < 0) {
		//		wprintf(L"Error: Could not determine boot disk\n");
		//		resl = ST_NF_DEVICE; break;
		//	}

		//	dcs_esp_part = dc_find_dcs_esp(os_disk);
		//	if (dcs_esp_part <= 0) {
		//		wprintf(L"Error: No dedicated DCS ESP partition found\n");
		//		resl = ST_NF_DEVICE; break;
		//	}

		//	swprintf_s(device_path, MAX_PATH, L"\\Device\\Harddisk%d\\Partition%d", os_disk, dcs_esp_part);
		//	swprintf_s(dos_name, 4, L"%c:", letter);

		//	if (!DefineDosDevice(DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE,
		//		dos_name, device_path)) {
		//		wprintf(L"Error: Failed to unmount partition (error %d)\n", GetLastError());
		//		resl = ST_ERROR; break;
		//	}

		//	wprintf(L"DCS ESP partition unmounted from %c:\\\n", letter);
		//	resl = ST_OK;
		//	break;
		//}

	} while (0);

	return resl;
}
