/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2010-2013
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

#include <ntifs.h>
#include <ntdddisk.h>
#include <ntstrsafe.h>
#include "defines.h"
#include "debug.h"
#include "devhook.h"
#include "ssd_trim.h"
#include "misc.h"
#include "device_io.h"

// function types declaration
KSTART_ROUTINE dc_trim_thread;

#define MAX_TRIM_FILES 128
#define TRIM_MIN_LEN   4096

static BOOLEAN dc_is_trim_supported(dev_hook *hook)
{
	STORAGE_PROPERTY_QUERY pquery = { StorageDeviceTrimProperty,  PropertyStandardQuery, };
	DEVICE_TRIM_DESCRIPTOR trimds  = { 0 };
	NTSTATUS               status;
	
	if ( !NT_SUCCESS(status = io_device_control(hook->orig_dev,
		                                        IOCTL_STORAGE_QUERY_PROPERTY,
												&pquery, sizeof(pquery), &trimds, sizeof(trimds))) )
	{
		DbgMsg("IOCTL_STORAGE_QUERY_PROPERTY fails, dev=%ws, status=%08x\n", hook->dev_name, status);
		return FALSE;
	}
	if (trimds.Version < sizeof(DEVICE_TRIM_DESCRIPTOR) || trimds.Size < sizeof(DEVICE_TRIM_DESCRIPTOR)) {
		DbgMsg("Invalid DEVICE_TRIM_DESCRIPTOR returned, dev=%ws\n", hook->dev_name);
		return FALSE;
	}
	DbgMsg("device %ws TrimEnabled = %d\n", hook->dev_name, trimds.TrimEnabled);
	return trimds.TrimEnabled;
}

/*
 * The trim files cover nearly all free clusters with ValidDataLength set and no zeroing,
 * so their contents are the old free-cluster data (the plaintext of deleted files, as seen
 * through the hook). They get a protected DACL granting SYSTEM and Administrators only (a
 * file orphaned by a crash stays admin-only) and FILE_DELETE_ON_CLOSE (the file goes away
 * even when the disposition call fails). FAT/exFAT ignore the descriptor (no ACLs there).
 */
typedef struct _trim_sd {
	SECURITY_DESCRIPTOR sd;
	ULONG               acl_buf[32];   /* ULONG aligned ACL storage, 128 bytes */
} trim_sd;

static BOOLEAN dc_build_trim_sd(trim_sd *tsd)
{
	PACL  acl = (PACL)tsd->acl_buf;
	PSID  sys_sid = SeExports->SeLocalSystemSid;
	PSID  adm_sid = SeExports->SeAliasAdminsSid;
	ULONG acl_len;

	acl_len = (ULONG)(sizeof(ACL) +
		(sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG) + RtlLengthSid(sys_sid)) +
		(sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG) + RtlLengthSid(adm_sid)));
	acl_len = (acl_len + 3) & ~3UL;	/* ULONG aligned */

	if (acl_len > sizeof(tsd->acl_buf)) return FALSE;

	if ( !NT_SUCCESS(RtlCreateAcl(acl, acl_len, ACL_REVISION)) ||
		 !NT_SUCCESS(RtlAddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS, sys_sid)) ||
		 !NT_SUCCESS(RtlAddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS, adm_sid)) ||
		 !NT_SUCCESS(RtlCreateSecurityDescriptor(&tsd->sd, SECURITY_DESCRIPTOR_REVISION)) ||
		 !NT_SUCCESS(RtlSetDaclSecurityDescriptor(&tsd->sd, TRUE, acl, FALSE)) )
	{
		return FALSE;
	}
	/* do not merge the inheritable ACEs of the root directory */
	tsd->sd.Control |= SE_DACL_PROTECTED;
	return TRUE;
}

static HANDLE dc_create_trim_file(dev_hook *hook, ULONGLONG length, PSECURITY_DESCRIPTOR sd)
{
	FILE_VALID_DATA_LENGTH_INFORMATION vdli;
	FILE_END_OF_FILE_INFORMATION       eofi;
	OBJECT_ATTRIBUTES                  obj_a;
	UNICODE_STRING                     u_name;	
	IO_STATUS_BLOCK                    iosb;
	wchar_t                            buff[MAX_PATH];
	HANDLE                             h_file;
	NTSTATUS                           status;

	if ( !NT_SUCCESS(status = RtlStringCchPrintfW(buff, MAX_PATH, L"%s\\$DC_TRIM_%x$", hook->dev_name, __rdtsc())) ) return NULL;
	RtlInitUnicodeString(&u_name, buff);
	/* explicit admin-only descriptor (no root ACL inheritance) */
	InitializeObjectAttributes(&obj_a, &u_name, OBJ_KERNEL_HANDLE, NULL, sd);

	/* DELETE is required by FILE_DELETE_ON_CLOSE; hidden/system keeps the file out
	 * of normal listings while it exists */
	if ( !NT_SUCCESS(status = ZwCreateFile(&h_file, GENERIC_WRITE | DELETE, &obj_a, &iosb, NULL,
		                                   FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, 0, FILE_CREATE,
		                                   FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE, NULL, 0)) )
	{
		DbgMsg("Cannot create trim file, status=%08x, path=%ws\n", status, buff);
		return NULL;
	}
	vdli.ValidDataLength.QuadPart = length;
	eofi.EndOfFile.QuadPart = length;

	if ( !NT_SUCCESS(status = ZwSetInformationFile(h_file, &iosb, &eofi, sizeof(eofi), FileEndOfFileInformation)) ||
		 !NT_SUCCESS(status = ZwSetInformationFile(h_file, &iosb, &vdli, sizeof(vdli), FileValidDataLengthInformation)) )
	{
		DbgMsg("Cannot allocate space for trim, status=%08x, path=%ws\n", status, buff);
	}
	return h_file;
}

static void dc_do_trim(dev_hook *hook)
{
	FILE_FS_SIZE_INFORMATION     sinf;
	FILE_DISPOSITION_INFORMATION dinf = { TRUE };
	HANDLE                       h_files[MAX_TRIM_FILES];
	int                          n_files = 0, i;
	HANDLE                       h_file;
	IO_STATUS_BLOCK              iosb;	
	NTSTATUS                     status;
	ULONGLONG                    length;
	trim_sd                      tsd;

	/* fail closed - no trim files with an inherited ACL */
	if (dc_build_trim_sd(&tsd) == FALSE) {
		DbgMsg("Cannot build trim file security descriptor, dev=%ws\n", hook->dev_name);
		return;
	}

	// create first trim file
	if ( (h_file = dc_create_trim_file(hook, TRIM_MIN_LEN, &tsd.sd)) == NULL ) {
		return;
	} else {
		h_files[n_files++] = h_file;
	}
	for (i = 0; i < MAX_TRIM_FILES - 1; i++)
	{
		/* the last file created (h_file is NULL after a failed create) */
		status = ZwQueryVolumeInformationFile(h_files[n_files - 1], &iosb, &sinf, sizeof(sinf), FileFsSizeInformation);

		if ( (NT_SUCCESS(status) == FALSE) || (sinf.AvailableAllocationUnits.QuadPart == 0) ) {
			break;
		} else {
			length = max(sinf.AvailableAllocationUnits.QuadPart / 2, 1) * d64(sinf.BytesPerSector * sinf.SectorsPerAllocationUnit);
		}
		if (h_file = dc_create_trim_file(hook, length, &tsd.sd)) {
			h_files[n_files++] = h_file;
		}
	}
	// delete trim files (FILE_DELETE_ON_CLOSE deletes them on close as well)
	for (i = 0; i < n_files; i++) {
		status = ZwSetInformationFile(h_files[i], &iosb, &dinf, sizeof(dinf), FileDispositionInformation);
		if (NT_SUCCESS(status) == FALSE) {
			DbgMsg("Cannot set trim file disposition, status=%08x, dev=%ws\n", status, hook->dev_name);
		}
		ZwClose(h_files[i]);
	}
}

static void dc_trim_thread(dev_hook *hook)
{
	if (dc_is_trim_supported(hook) != FALSE) {
		dc_do_trim(hook);
	}
	dc_deref_hook(hook);
	PsTerminateSystemThread(STATUS_SUCCESS);
}

void dc_trim_free_space(dev_hook *hook)
{
	dc_reference_hook(hook);

	if (start_system_thread(dc_trim_thread, hook, NULL) != ST_OK) {
		dc_deref_hook(hook);
	}
}