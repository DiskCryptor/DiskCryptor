/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2026
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
#include "cd_enc.h"
#include "dc_header.h"
#ifdef _M_ARM64
#include "xts_small.h"
#include "sha512_pkcs5_2_small.h"
#else
#include "xts_fast.h"
#include "sha512_pkcs5_2.h"
#endif
#include "..\crc32.h"
#include "drvinst.h"
#include "misc.h"

#define CD_BUFSZ (1024 * 1024)

DWORD dc_encrypt_iso_image(PCWSTR src_path, PCWSTR dst_path, dc_pass* password, int cipher, DC_CD_CALLBACK callback, PVOID param)
{
	HANDLE        h_src = INVALID_HANDLE_VALUE;
	HANDLE        h_dst = INVALID_HANDLE_VALUE;
	LARGE_INTEGER isosize, encsize;
	xts_key*      header_key = NULL;
	xts_key*      volume_key = NULL;
	dc_header*    header = NULL;
	PUCHAR        buffer = NULL;
	UCHAR         salt[HEADER_SALT_SIZE], *dk = NULL;
	DWORD         status, bytes, blocklen, writelen;
	
	dc_init_crypto();

	// open source file and get file size
	if ( (h_src = CreateFile(src_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, 0)) == INVALID_HANDLE_VALUE ||
		 (GetFileSizeEx(h_src, &isosize) == FALSE) )
	{
		status = GetLastError();
		goto cleanup;
	}

	// create destination file
	if ( (h_dst = CreateFile(dst_path, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, 0)) == INVALID_HANDLE_VALUE )
	{
		status = GetLastError();
		goto cleanup;
	}
	
	// allocate required memory
	if ( (header_key = (xts_key*)secure_alloc(sizeof(xts_key))) == NULL ||
		 (volume_key = (xts_key*)secure_alloc(sizeof(xts_key))) == NULL ||
		 (dk = (PUCHAR)secure_alloc(DISKKEY_SIZE)) == NULL ||
		 (header = (dc_header*)secure_alloc(sizeof(dc_header))) == NULL ||
		 (buffer = (PUCHAR)VirtualAlloc(NULL, CD_BUFSZ, MEM_COMMIT+MEM_RESERVE, PAGE_READWRITE)) == NULL )
	{
		status = ERROR_NOT_ENOUGH_MEMORY;
		goto cleanup;
	}

	// create the volume header
	memset(header, 0, sizeof(dc_header));
	
	if ( (status = dc_device_control(DC_CTL_GET_RAND, NULL, 0, salt, HEADER_SALT_SIZE)) != NO_ERROR ) goto cleanup;
	if ( (status = dc_device_control(DC_CTL_GET_RAND, NULL, 0, &header->disk_id, sizeof(header->disk_id))) != NO_ERROR ) goto cleanup;
	if ( (status = dc_device_control(DC_CTL_GET_RAND, NULL, 0, header->key_1, sizeof(header->key_1))) != NO_ERROR ) goto cleanup;

	header->sign     = DC_VOLUME_SIGN;
	header->version  = DC_HDR_VERSION;
	header->flags    = VF_NO_REDIR;
	header->alg_1    = cipher;
	header->data_off = sizeof(dc_header);
	header->hdr_crc  = calculate_header_crc_um(header);

	// derive the header key
	sha512_pkcs5_2(1000, password->pass, password->size, salt, HEADER_SALT_SIZE, dk, PKCS_DERIVE_MAX);

	// initialize encryption keys
	if (!xts_set_key(header->key_1, cipher, volume_key)) { status = ST_INVALID_PARAM; goto cleanup; }
	if (!xts_set_key(dk, cipher, header_key)) { status = ST_INVALID_PARAM; goto cleanup; }

	// encrypt the volume header
	xts_encrypt((const unsigned char*)header, (unsigned char*)header, sizeof(dc_header), 0, header_key);

	// save salt
	memcpy(header->salt, salt, HEADER_SALT_SIZE);

	// write volume header to output file
	if (WriteFile(h_dst, header, sizeof(dc_header), &bytes, NULL) == 0)
	{
		status = GetLastError();
		goto cleanup;
	}

	// encryption loop
	for (encsize.QuadPart = 0; encsize.QuadPart < isosize.QuadPart; )
	{
		blocklen = (DWORD)(min(isosize.QuadPart - encsize.QuadPart, CD_BUFSZ));
		writelen = _align(blocklen, CD_SECTOR_SIZE);

		if (ReadFile(h_src, buffer, blocklen, &bytes, NULL) == FALSE || bytes < blocklen)
		{
			status = GetLastError();
			goto cleanup;
		}
		xts_encrypt(buffer, buffer, writelen, encsize.QuadPart, volume_key);

		if (WriteFile(h_dst, buffer, writelen, &bytes, NULL) == FALSE || bytes < writelen)
		{
			status = GetLastError();
			goto cleanup;
		}

		if (callback(isosize.QuadPart, (encsize.QuadPart += writelen), param) == FALSE)
		{
			status = ERROR_OPERATION_ABORTED;
			goto cleanup;
		}
	}
	status = NO_ERROR;

cleanup:
	if (buffer != NULL) VirtualFree(buffer, 0, MEM_RELEASE);
	if (header != NULL) secure_free(header);
	if (dk != NULL) secure_free(dk);
	if (volume_key != NULL) secure_free(volume_key);
	if (header_key != NULL) secure_free(header_key);
	if (h_src != INVALID_HANDLE_VALUE) CloseHandle(h_src);

	if (h_dst != INVALID_HANDLE_VALUE) {
		CloseHandle(h_dst);
		if (status != NO_ERROR) DeleteFile(dst_path);
	}
	return status;
}

 