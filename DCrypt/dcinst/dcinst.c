/*  *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2020-2026
	* DavidXanatos <info@diskcryptor.org>
	* Copyright (c) 2009-2013
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
#include <tchar.h>
#include "drv_ioctl.h"
#include "drvinst.h"
#include "mbrinst.h"
#include "efiinst.h"
#include "w10.h"

/*
    -setup  - install or update driver (update bootloader when needed)
	-unins  - uninstall driver
	-unldr  - uninstall bootloader
	-isenc  - check for boot device encryption
	-isboot - check for bootloader on boot device
*/

int APIENTRY _tWinMain(HINSTANCE hInstance,
                       HINSTANCE hPrevInstance,
                       LPTSTR    lpCmdLine,
                       int       nCmdShow)
{
	DWORD status = ERROR_INVALID_FUNCTION;
	int is_efi_boot;

	//int argc = 0;
	//wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	//if (!argv) {
	//	return -1;
	//}

	dc_efi_init();
	is_efi_boot = dc_efi_check();

	if (dc_is_old_runned() != 0) return ERROR_REVISION_MISMATCH;
	dc_open_device();

	if (_tcsicmp(lpCmdLine, _T("-setup")) == 0)
	{
		if (dc_is_driver_installed() != FALSE)
		{
			if (is_efi_boot) {
				status = dc_update_efi_boot(-1, -1);
			}
			else {
				status = dc_update_boot(-1);
			}

			if ( status != ST_OK && status != ST_BLDR_NOTINST )
			{
				return 100000 + status;
			}
			status = dc_update_driver();
		} else {
			status = dc_install_driver();
		}
	}

	if (_tcsicmp(lpCmdLine, _T("-unins")) == 0)
	{
		if (dc_is_driver_installed() == FALSE)
		{
			return ERROR_PRODUCT_UNINSTALLED;
		}
		status = dc_remove_driver();

		if (is_w10_reflect_supported())
		{
			remove_w10_reflect_driver();
		}
	}

	if (_tcsicmp(lpCmdLine, _T("-unldr")) == 0)
	{
		if (is_efi_boot) {
			status = dc_unset_efi_boot(-1, -1);
		}
		else {
			status = dc_unset_mbr(-1);
		}

		if ( status != ST_OK )
		{
			return 100000 + status; 
		}
	}

	if (_tcsicmp(lpCmdLine, _T("-isboot")) == 0)
	{
		ldr_config conf;
		
		if (is_efi_boot) {
			status = dc_get_efi_config(-1, NULL, &conf);
		}
		else {
			status = dc_get_mbr_config(-1, NULL, &conf);
		}

		if ( status != ST_OK )
		{
			return 100000 + status; 
		}
	}		

	if (_tcsicmp(lpCmdLine, _T("-isenc")) == 0)
	{
		int is_enc = dc_is_boot_encrypted();

		status = is_enc != 0 ? ST_ENCRYPTED : NO_ERROR;
	}

	if (_tcsicmp(lpCmdLine, _T("-reflect")) == 0)
	{
		if (!is_w10_reflect_supported())
		{
			return ST_ERROR;
		}
		
		status = ST_OK;

		update_w10_reflect_driver();

		dc_update_efi_boot(-1, -1); // Note: this will fail and do nothing if the bootloader is not installed on the default EFI partition
	}

	//LocalFree(argv);

	return status;
}