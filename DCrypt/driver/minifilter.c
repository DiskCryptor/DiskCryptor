/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2026
    * DavidXanatos <info@diskcryptor.org>
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
#include <fltKernel.h>
#include <ntstrsafe.h>
#include "minifilter.h"
#include "devhook.h"
#include "misc_volume.h"
#include "misc_mem.h"
#include "device_io.h" /* io_check_media */
#include "disk_info.h" /* dc_query_dev_length */
#include "misc.h"      /* dc_delay */
#include "debug.h"

/*
 * The file IDs of the storage files are cached, tagged with dev_hook->stor_gen, which
 * storage.c (the only code that creates, renames or deletes them) increments after every
 * change; a cache whose generation differs is re-queried. The generation is read BEFORE
 * the query, so a change racing the query leaves an outdated tag. Only "found" and "does
 * not exist" results are cached. The root directory ID is cached once per instance.
 */
typedef struct _mf_context {
	dev_hook*  dev_hook;

	KSPIN_LOCK id_lock;     /* protects the fields below */
	LONG       id_gen;      /* dev_hook->stor_gen the storage IDs were queried under */
	BOOLEAN    id_valid;
	BOOLEAN    sys_found;   /* $dcsys$ exists, sys_id valid */
	BOOLEAN    bak_found;   /* $dcbak$ exists, bak_id valid */
	BOOLEAN    log_found;   /* $dclog$ exists, log_id valid */
	BOOLEAN    root_valid;  /* root_id valid */
	LONGLONG   sys_id;
	LONGLONG   bak_id;
	LONGLONG   log_id;
	LONGLONG   root_id;

} mf_context;

typedef struct _mf_stor_ids {
	BOOLEAN  sys_found;
	BOOLEAN  bak_found;
	BOOLEAN  log_found;
	LONGLONG sys_id;
	LONGLONG bak_id;
	LONGLONG log_id;
} mf_stor_ids;

/* the storage files ($dcsys$ / $dcbak$ / $dclog$) are protected as one set while either flag is set */
#define MF_PROTECT_FLAGS (F_PROTECT_DCSYS | F_PROTECT_DCLOG)

/* ShrinkPrepare / ShrinkCommit completion context (pre-op -> post-op), NonPagedPool */
typedef struct _mf_shrink_prep {
	dev_hook* hook;     /* referenced by the instance context while the op is in flight */
	LONGLONG  sectors;  /* Prepare: requested partition size (before the storage adjustment);
	                       Commit: the prepared target, taken under busy_lock in the pre-op */
	BOOLEAN   commit;   /* a ShrinkCommit - the pre-op holds hook->busy_lock */
} mf_shrink_prep;

static NTSTATUS FLTAPI mf_instance_setup_callback(IN PCFLT_RELATED_OBJECTS    FltObjects,
	                                              IN FLT_INSTANCE_SETUP_FLAGS Flags,
										          IN DEVICE_TYPE              VolumeDeviceType,
										          IN FLT_FILESYSTEM_TYPE      VolumeFilesystemType)
{
	wchar_t        buff[128];
	UNICODE_STRING name = { 0, sizeof(buff) - sizeof(wchar_t), buff };
	dev_hook*      hook = NULL;
	mf_context*    mf_ctx = NULL;
	NTSTATUS       status = STATUS_FLT_DO_NOT_ATTACH;

	// attach only to disk file systems
	if (VolumeDeviceType != FILE_DEVICE_DISK_FILE_SYSTEM) goto cleanup;
	
	// get volume device name and find corresponding hook device
	if ( !NT_SUCCESS(FltGetVolumeName(FltObjects->Volume, &name, NULL)) ) goto cleanup;
	name.Buffer[name.Length / sizeof(wchar_t)] = 0;
	if ( (hook = dc_find_hook(name.Buffer)) == NULL ) goto cleanup;

	// allocate and set new filter instance context
	if ( !NT_SUCCESS(FltAllocateContext(FltObjects->Filter,
		                                FLT_INSTANCE_CONTEXT, sizeof(mf_context), NonPagedPool, (PVOID*)&mf_ctx)) ) goto cleanup;

	/* FltAllocateContext does not zero the context: id_valid / root_valid must start FALSE */
	RtlZeroMemory(mf_ctx, sizeof(mf_context));
	KeInitializeSpinLock(&mf_ctx->id_lock);
	mf_ctx->dev_hook = hook;

	if ( !NT_SUCCESS(FltSetInstanceContext(FltObjects->Instance, FLT_SET_CONTEXT_KEEP_IF_EXISTS, mf_ctx, NULL)) ) goto cleanup;
	status = STATUS_SUCCESS;

cleanup:
	if (mf_ctx != NULL) FltReleaseContext(mf_ctx);
	if (status != STATUS_SUCCESS && hook != NULL) dc_deref_hook(hook);
	return status;
}

static void FLTAPI mf_teardown_complete_callback(IN PCFLT_RELATED_OBJECTS       FltObjects,
	                                             IN FLT_INSTANCE_TEARDOWN_FLAGS Reason)
{
	mf_context* mf_ctx;

	if (NT_SUCCESS(FltDeleteInstanceContext(FltObjects->Instance, (PVOID*)&mf_ctx)) && mf_ctx != NULL)
	{
		/*
		 * The context is always released; only dc_deref_hook is guarded. The references
		 * taken in mf_instance_setup_callback keep hook_dev and pdo_dev allocated, so the
		 * check should never fail; if it does, some other reference is unbalanced and
		 * dereferencing the hook would make it worse.
		 */
		if (mf_ctx->dev_hook != NULL &&
			MmIsAddressValid(mf_ctx->dev_hook) &&
			MmIsAddressValid(mf_ctx->dev_hook->pdo_dev))
		{
			dc_deref_hook(mf_ctx->dev_hook);
		}
		FltReleaseContext(mf_ctx);
	}
}

/*
 * FileInternalInformation of an open file object (on FAT/exFAT derived from the dirent
 * position: it changes with a rename and can be reused). Needs no handle access rights.
 * PASSIVE_LEVEL.
 */
static NTSTATUS mf_query_fo_id(PFLT_INSTANCE instance, PFILE_OBJECT file, LONGLONG* id)
{
	FILE_INTERNAL_INFORMATION info;
	NTSTATUS                  status;

	status = FltQueryInformationFile(instance, file, &info, sizeof(info), FileInternalInformation, NULL);
	*id = NT_SUCCESS(status) ? info.IndexNumber.QuadPart : 0;
	return status;
}

/*
 * Open "<volume>\<rel_name>" below this instance for FILE_READ_ATTRIBUTES (enough
 * for FileInternalInformation), sharing everything (anyone may hold $dcsys$ open
 * for write). rel_name L"" opens the root directory.
 */
static NTSTATUS mf_open_volume_path(PCFLT_RELATED_OBJECTS objects, dev_hook* hook, const wchar_t* rel_name,
	                                ULONG options, HANDLE* h_file)
{
	wchar_t           buff[128];
	OBJECT_ATTRIBUTES obj_a;
	UNICODE_STRING    name;
	IO_STATUS_BLOCK   iosb;
	NTSTATUS          status;

	*h_file = NULL;
	status  = RtlStringCchPrintfW(buff, (sizeof(buff) / sizeof(buff[0])), L"%s\\%s", hook->dev_name, rel_name);
	if ( !NT_SUCCESS(status) ) return status;

	RtlInitUnicodeString(&name, buff);
	InitializeObjectAttributes(&obj_a, &name, OBJ_KERNEL_HANDLE, NULL, NULL);

	status = FltCreateFile(objects->Filter, objects->Instance, h_file, FILE_READ_ATTRIBUTES | SYNCHRONIZE,
		                   &obj_a, &iosb, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
		                   FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT | options, NULL, 0, 0);
	if ( !NT_SUCCESS(status) ) *h_file = NULL;
	return status;
}

/* FileInternalInformation of an open (kernel) handle */
static NTSTATUS mf_query_handle_id(PCFLT_RELATED_OBJECTS objects, HANDLE h_file, LONGLONG* id)
{
	PFILE_OBJECT p_file;
	NTSTATUS     status;

	*id    = 0;
	status = ObReferenceObjectByHandle(h_file, 0, *IoFileObjectType, KernelMode, (PVOID*)&p_file, NULL);
	if ( !NT_SUCCESS(status) ) return status;

	status = mf_query_fo_id(objects->Instance, p_file, id);
	ObDereferenceObject(p_file);
	return status;
}

static NTSTATUS mf_query_path_id(PCFLT_RELATED_OBJECTS objects, dev_hook* hook, const wchar_t* rel_name,
	                             ULONG options, LONGLONG* id)
{
	HANDLE   h_file;
	NTSTATUS status;

	*id    = 0;
	status = mf_open_volume_path(objects, hook, rel_name, options, &h_file);
	if ( !NT_SUCCESS(status) ) return status;

	status = mf_query_handle_id(objects, h_file, id);
	FltClose(h_file);
	return status;
}

/* results that describe the current state of the storage file and may be cached */
static BOOLEAN mf_id_status_cacheable(NTSTATUS status)
{
	return NT_SUCCESS(status) || status == STATUS_OBJECT_NAME_NOT_FOUND ||
		   status == STATUS_OBJECT_PATH_NOT_FOUND || status == STATUS_FILE_IS_A_DIRECTORY;
}

/*
 * Current IDs of the storage files, from the generation-tagged cache (see mf_context)
 * or, if that is outdated, queried by name. PASSIVE_LEVEL.
 */
static void mf_get_storage_ids(mf_context* mf_ctx, PCFLT_RELATED_OBJECTS objects, mf_stor_ids* ids)
{
	KIRQL    irql;
	LONG     gen;
	NTSTATUS s_sys, s_bak, s_log;

	/* read the generation before the query (see mf_context) */
	gen = InterlockedCompareExchange(&mf_ctx->dev_hook->stor_gen, 0, 0);

	KeAcquireSpinLock(&mf_ctx->id_lock, &irql);
	if (mf_ctx->id_valid && mf_ctx->id_gen == gen)
	{
		ids->sys_found = mf_ctx->sys_found;
		ids->bak_found = mf_ctx->bak_found;
		ids->log_found = mf_ctx->log_found;
		ids->sys_id    = mf_ctx->sys_id;
		ids->bak_id    = mf_ctx->bak_id;
		ids->log_id    = mf_ctx->log_id;
		KeReleaseSpinLock(&mf_ctx->id_lock, irql);
		return;
	}
	KeReleaseSpinLock(&mf_ctx->id_lock, irql);

	s_sys = mf_query_path_id(objects, mf_ctx->dev_hook, L"$dcsys$", FILE_NON_DIRECTORY_FILE, &ids->sys_id);
	s_bak = mf_query_path_id(objects, mf_ctx->dev_hook, L"$dcbak$", FILE_NON_DIRECTORY_FILE, &ids->bak_id);
	s_log = mf_query_path_id(objects, mf_ctx->dev_hook, L"$dclog$", FILE_NON_DIRECTORY_FILE, &ids->log_id);
	ids->sys_found = NT_SUCCESS(s_sys) != FALSE;
	ids->bak_found = NT_SUCCESS(s_bak) != FALSE;
	ids->log_found = NT_SUCCESS(s_log) != FALSE;

	if (mf_id_status_cacheable(s_sys) && mf_id_status_cacheable(s_bak) && mf_id_status_cacheable(s_log))
	{
		KeAcquireSpinLock(&mf_ctx->id_lock, &irql);
		mf_ctx->sys_found = ids->sys_found;
		mf_ctx->bak_found = ids->bak_found;
		mf_ctx->log_found = ids->log_found;
		mf_ctx->sys_id    = ids->sys_id;
		mf_ctx->bak_id    = ids->bak_id;
		mf_ctx->log_id    = ids->log_id;
		mf_ctx->id_gen    = gen;
		mf_ctx->id_valid  = TRUE;
		KeReleaseSpinLock(&mf_ctx->id_lock, irql);
	}
}

static BOOLEAN mf_is_storage_id(const mf_stor_ids* ids, LONGLONG id)
{
	return (ids->sys_found && id == ids->sys_id) || (ids->bak_found && id == ids->bak_id) ||
	       (ids->log_found && id == ids->log_id);
}

/* ID of the volume root directory (cached for the instance lifetime). PASSIVE_LEVEL. */
static BOOLEAN mf_get_root_id(mf_context* mf_ctx, PCFLT_RELATED_OBJECTS objects, LONGLONG* id)
{
	KIRQL    irql;
	LONGLONG root_id;
	BOOLEAN  valid;

	KeAcquireSpinLock(&mf_ctx->id_lock, &irql);
	valid = mf_ctx->root_valid;
	*id   = mf_ctx->root_id;
	KeReleaseSpinLock(&mf_ctx->id_lock, irql);
	if (valid) return TRUE;

	/* not hard-coded (NTFS root FRN 5): FAT/exFAT derive the ID differently */
	if ( !NT_SUCCESS(mf_query_path_id(objects, mf_ctx->dev_hook, L"", FILE_DIRECTORY_FILE, &root_id)) ) return FALSE;

	KeAcquireSpinLock(&mf_ctx->id_lock, &irql);
	mf_ctx->root_id    = root_id;
	mf_ctx->root_valid = TRUE;
	KeReleaseSpinLock(&mf_ctx->id_lock, irql);
	*id = root_id;
	return TRUE;
}

/* "$dcsys$" / "$dclog$" or "<name>:<stream>" (length in bytes); used by the directory hiding */
static BOOLEAN is_dcsys_name(const wchar_t* buff, ULONG length)
{
	return length >= 14 && (length == 14 || (length >= 16 && buff[7] == L':')) &&
	       (_wcsnicmp(buff, L"$dcsys$", 7) == 0 || _wcsnicmp(buff, L"$dclog$", 7) == 0);
}

/*
 * $dcbak$ can hold the live storage (during and after a failed relocation by
 * dc_apply_layout), so it is protected exactly like $dcsys$. Compares like the file
 * systems do: RtlUpcaseUnicodeChar (_wcsnicmp folds only ASCII), trailing dots / spaces
 * ignored (FAT / exFAT strip them; fail closed for NTFS). upper7 is the 7-character name
 * in upper case.
 */
static BOOLEAN mf_storage_name_is(const wchar_t* buff, ULONG n, const wchar_t* upper7)
{
	ULONG i;

	if (n < 7) return FALSE;
	for (i = 0; i < 7; i++) {
		if (RtlUpcaseUnicodeChar(buff[i]) != upper7[i]) return FALSE;
	}
	for (i = 7; i < n; i++) {
		if (buff[i] == L':') return TRUE;               /* a stream of the file */
		if (buff[i] != L'.' && buff[i] != L' ') return FALSE;
	}
	return TRUE;
}

static BOOLEAN is_storage_name(const wchar_t* buff, ULONG length)
{
	ULONG n = length / sizeof(wchar_t);

	return mf_storage_name_is(buff, n, L"$DCSYS$") || mf_storage_name_is(buff, n, L"$DCBAK$") ||
	       mf_storage_name_is(buff, n, L"$DCLOG$");
}

/* last path component of a name (length in bytes), trailing backslashes ignored */
static void mf_last_component(const wchar_t* buff, ULONG length, const wchar_t** comp, ULONG* comp_len)
{
	ULONG n = length / sizeof(wchar_t), i;

	while (n > 0 && buff[n - 1] == L'\\') n--;
	i = n;
	while (i > 0 && buff[i - 1] != L'\\') i--;

	*comp     = buff + i;
	*comp_len = (n - i) * sizeof(wchar_t);
}

/*
* Access mask for operations that must be denied on $dcsys$:
* - Content access (read/write/execute)
* - Modification (write attributes, delete, change permissions)
*
* MAXIMUM_ALLOWED reaches the file system unmapped and grants every right the DACL
* allows. The GENERIC_* bits are normally mapped before the create reaches us; they
* are listed for safety only.
*/
#define DCSYS_DENIED_ACCESS ( \
      FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_EXECUTE | \
      FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | \
      DELETE | WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY | \
      MAXIMUM_ALLOWED | GENERIC_ALL | GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE )

/*
 * TRUE if this create must not be allowed on $dcsys$: denied access rights, or a
 * disposition / FILE_DELETE_ON_CLOSE that destroys the file contents (the file system
 * checks those rights against the DACL, not against DesiredAccess).
 */
static BOOLEAN mf_dcsys_create_denied(PFLT_CALLBACK_DATA Data)
{
	PIO_SECURITY_CONTEXT s_ctx       = Data->Iopb->Parameters.Create.SecurityContext;
	ULONG                options     = Data->Iopb->Parameters.Create.Options;
	ULONG                disposition = (options >> 24) & 0xFF;
	ACCESS_MASK          access      = s_ctx->DesiredAccess;

	/*
	 * with FILE_OPEN_FOR_BACKUP_INTENT the rights SeBackup / SeRestore grant are moved
	 * into PreviouslyGrantedAccess, only the remainder stays in DesiredAccess
	 */
	if (s_ctx->AccessState != NULL) {
		access |= s_ctx->AccessState->PreviouslyGrantedAccess | s_ctx->AccessState->OriginalDesiredAccess;
	}
	if (access & DCSYS_DENIED_ACCESS) return TRUE;
	/*
	 * every disposition but FILE_OPEN: FILE_CREATE / FILE_OPEN_IF of a missing storage
	 * file would pre-create it and make dc_create_dcsys (FILE_CREATE) fail
	 */
	if (disposition != FILE_OPEN) return TRUE;
	if (options & FILE_DELETE_ON_CLOSE) return TRUE;
	return FALSE;
}

/* the create changes the file in a way FltCancelFileOpen in post-create cannot undo */
static BOOLEAN mf_create_destructive(PFLT_CALLBACK_DATA Data)
{
	ULONG options     = Data->Iopb->Parameters.Create.Options;
	ULONG disposition = (options >> 24) & 0xFF;

	return disposition == FILE_SUPERSEDE || disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF ||
		   (options & FILE_DELETE_ON_CLOSE) != 0;
}

/*
 * A destructive open-by-ID must be decided before it reaches the file system. The ID
 * in the name is not compared directly (a 16-byte ID is an object ID on NTFS, a
 * FILE_ID_128 on ReFS): it is opened below this instance and the internal ID of the
 * file it resolves to is compared. Fail-closed if the file cannot be resolved.
 */
static BOOLEAN mf_is_storage_by_id_create(mf_context* mf_ctx, PCFLT_RELATED_OBJECTS objects, const wchar_t* p_buff, USHORT length)
{
	LARGE_INTEGER     id_buff[2];
	UNICODE_STRING    name;
	OBJECT_ATTRIBUTES obj_a;
	IO_STATUS_BLOCK   iosb;
	HANDLE            h_root = NULL, h_file = NULL;
	LONGLONG          id;
	mf_stor_ids       ids;
	BOOLEAN           result = TRUE;

	mf_get_storage_ids(mf_ctx, objects, &ids);
	if (!ids.sys_found && !ids.bak_found && !ids.log_found) return FALSE; /* nothing to protect right now */

	if (p_buff == NULL) return TRUE;
	/* "\<id>" form: strip the backslash (a relative open by ID must not have one) */
	if ((length == sizeof(wchar_t) + sizeof(LARGE_INTEGER) || length == sizeof(wchar_t) + 2 * sizeof(LARGE_INTEGER)) && p_buff[0] == L'\\') {
		p_buff++, length -= sizeof(wchar_t);
	}
	if (length != sizeof(LARGE_INTEGER) && length != 2 * sizeof(LARGE_INTEGER)) return TRUE;

	/* copy out: after a stripped backslash the ID is not 8-byte aligned */
	RtlCopyMemory(id_buff, p_buff, length);
	name.Buffer        = (PWCH)id_buff;
	name.Length        = length;
	name.MaximumLength = length;

	if ( !NT_SUCCESS(mf_open_volume_path(objects, mf_ctx->dev_hook, L"", FILE_DIRECTORY_FILE, &h_root)) ) goto cleanup;

	InitializeObjectAttributes(&obj_a, &name, OBJ_KERNEL_HANDLE, h_root, NULL);
	if ( !NT_SUCCESS(FltCreateFile(objects->Filter, objects->Instance, &h_file, FILE_READ_ATTRIBUTES | SYNCHRONIZE,
		                           &obj_a, &iosb, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
		                           FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_BY_FILE_ID | FILE_OPEN_REPARSE_POINT, NULL, 0, 0)) )
	{
		h_file = NULL;
		goto cleanup;
	}
	if ( !NT_SUCCESS(mf_query_handle_id(objects, h_file, &id)) ) goto cleanup;

	result = mf_is_storage_id(&ids, id);

cleanup:
	if (h_file != NULL) FltClose(h_file);
	if (h_root != NULL) FltClose(h_root);
	return result;
}

/*
 * Pre-create. Hot path for ordinary opens: instance context, flag tests and, for
 * absolute names, a string compare. Only creates that would be denied on the
 * storage files need any check at all, and the driver's own worker thread is
 * always allowed.
 *
 * Relative opens (RelatedFileObject / RootDirectory):
 * - empty name or ":<stream>" reopens the related file itself, so a FILE_READ_ATTRIBUTES
 *   handle of $dcsys$ could be upgraded: the related file's ID is compared with the
 *   storage file IDs;
 * - a storage name is the storage file only relative to the volume root directory: the
 *   related file's ID is compared with the root's (fail-closed if unknown).
 *
 * Open-by-ID with denied rights is decided in post-create (mf_post_create); only
 * destructive dispositions are decided here.
 */
static FLT_PREOP_CALLBACK_STATUS FLTAPI mf_irp_mj_create(IN OUT PFLT_CALLBACK_DATA    Data,
	                                                     IN     PCFLT_RELATED_OBJECTS FltObjects,
												         OUT    PVOID*                CompletionContext)
{
	mf_context*               mf_ctx;
	PFILE_OBJECT              f_obj = FltObjects->FileObject;
	PFILE_OBJECT              related;
	wchar_t*                  p_buff;
	USHORT                    length;
	LONGLONG                  id, root_id;
	mf_stor_ids               ids;
	BOOLEAN                   denied = FALSE;
	FLT_PREOP_CALLBACK_STATUS ret = FLT_PREOP_SUCCESS_NO_CALLBACK;

	*CompletionContext = NULL;

	if ( f_obj == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL ) { /* create is always PASSIVE */
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	if ( !NT_SUCCESS(FltGetInstanceContext(FltObjects->Instance, (PVOID*)&mf_ctx)) || mf_ctx == NULL )
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (mf_ctx->dev_hook && (mf_ctx->dev_hook->flags & MF_PROTECT_FLAGS) &&
		mf_ctx->dev_hook->wrk_thread_id != PsGetCurrentThreadId() &&
		mf_dcsys_create_denied(Data))
	{
		p_buff  = f_obj->FileName.Buffer;
		length  = (p_buff != NULL) ? f_obj->FileName.Length : 0;
		related = f_obj->RelatedFileObject;

		if (Data->Iopb->Parameters.Create.Options & FILE_OPEN_BY_FILE_ID)
		{
			if (mf_create_destructive(Data)) {
				denied = mf_is_storage_by_id_create(mf_ctx, FltObjects, p_buff, length);
			} else {
				ret = FLT_PREOP_SUCCESS_WITH_CALLBACK; /* mf_post_create */
			}
		}
		else if (related != NULL && (length == 0 || p_buff[0] == L':'))
		{
			/* reopen of the related file (or of a stream of it) */
			if (NT_SUCCESS(mf_query_fo_id(FltObjects->Instance, related, &id))) {
				mf_get_storage_ids(mf_ctx, FltObjects, &ids);
				denied = mf_is_storage_id(&ids, id);
			}
		}
		else
		{
			while (length >= sizeof(wchar_t) && p_buff[0] == L'\\') p_buff++, length -= sizeof(wchar_t);
			while (length >= sizeof(wchar_t) && p_buff[length / sizeof(wchar_t) - 1] == L'\\') length -= sizeof(wchar_t);

			if (is_storage_name(p_buff, length))
			{
				/* an absolute name is relative to the volume root; a relative one only
				   names the storage file if the related directory is the root */
				denied = related == NULL ||
					     !mf_get_root_id(mf_ctx, FltObjects, &root_id) ||
					     !NT_SUCCESS(mf_query_fo_id(FltObjects->Instance, related, &id)) ||
					     id == root_id;
			}
		}

		if (denied) {
			DbgMsg("Denied access to storage file, desired access: 0x%x, options: 0x%x, thread ID: 0x%p, worker thread ID: 0x%p\n",
				Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess, Data->Iopb->Parameters.Create.Options,
				PsGetCurrentThreadId(), mf_ctx->dev_hook->wrk_thread_id);
			/* only read-only attribute access (FILE_READ_ATTRIBUTES, SYNCHRONIZE, READ_CONTROL) gets through */
			Data->IoStatus.Status      = STATUS_ACCESS_DENIED;
			Data->IoStatus.Information = 0;
		}
	}
	FltReleaseContext(mf_ctx);
	return denied ? FLT_PREOP_COMPLETE : ret;
}

/*
 * Post-create of an open-by-ID with rights that are denied on the storage files
 * (non-destructive dispositions only, see mf_irp_mj_create): the internal ID of the file
 * actually opened is compared, which covers every ID form. Nothing has touched the file
 * yet and the caller has no handle, so cancelling the open is safe. Create post-ops run
 * at PASSIVE_LEVEL (needed here); checked defensively.
 */
static FLT_POSTOP_CALLBACK_STATUS FLTAPI mf_post_create(IN OUT PFLT_CALLBACK_DATA       Data,
	                                                    IN     PCFLT_RELATED_OBJECTS    FltObjects,
	                                                    IN     PVOID                    CompletionContext,
	                                                    IN     FLT_POST_OPERATION_FLAGS Flags)
{
	mf_context* mf_ctx;
	LONGLONG    id;
	mf_stor_ids ids;

	if ( (Flags & FLTFL_POST_OPERATION_DRAINING) || KeGetCurrentIrql() != PASSIVE_LEVEL ) {
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	if ( !NT_SUCCESS(Data->IoStatus.Status) || Data->IoStatus.Status == STATUS_REPARSE || FltObjects->FileObject == NULL ) {
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	if ( !NT_SUCCESS(FltGetInstanceContext(FltObjects->Instance, (PVOID*)&mf_ctx)) || mf_ctx == NULL ) {
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (mf_ctx->dev_hook && NT_SUCCESS(mf_query_fo_id(FltObjects->Instance, FltObjects->FileObject, &id)))
	{
		mf_get_storage_ids(mf_ctx, FltObjects, &ids);

		if (mf_is_storage_id(&ids, id))
		{
			DbgMsg("Denied open-by-ID of storage file, desired access: 0x%x, options: 0x%x, thread ID: 0x%p\n",
				Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess, Data->Iopb->Parameters.Create.Options,
				PsGetCurrentThreadId());
			FltCancelFileOpen(FltObjects->Instance, FltObjects->FileObject);
			Data->IoStatus.Status      = STATUS_ACCESS_DENIED;
			Data->IoStatus.Information = 0;
		}
	}
	FltReleaseContext(mf_ctx);
	return FLT_POSTOP_FINISHED_PROCESSING;
}

/*
 * The create filter leaves only read-attribute handles to the storage files, which stops
 * rename, delete, truncate and attribute changes. Set-information paths not covered by
 * handle rights are filtered here:
 * - a hard link FROM a storage file (needs no handle access; the new name could be opened
 *   with full access); a rename from a storage file is denied too (defense in depth);
 * - a rename or hard link ONTO a storage name in the root with replace-if-exists: it
 *   deletes the storage file (rights checked against the DACL, not via a create we see).
 * The destination is decided by the opened target directory (ParentOfTarget), which
 * follows reparse points, not by the name string. All requestor modes are checked; only
 * the worker thread (storage.c's renames) is exempt.
 */
static BOOLEAN mf_is_link_or_rename_class(FILE_INFORMATION_CLASS i_class, BOOLEAN* is_link)
{
	switch (i_class)
	{
		case FileLinkInformation:
		case FileLinkInformationBypassAccessCheck:
		case FileLinkInformationEx:
		case FileLinkInformationExBypassAccessCheck:
			*is_link = TRUE;
			return TRUE;
		case FileRenameInformation:
		case FileRenameInformationBypassAccessCheck:
		case FileRenameInformationEx:
		case FileRenameInformationExBypassAccessCheck:
			*is_link = FALSE;
			return TRUE;
	}
	return FALSE;
}

/* *name_match: the last name component of the rename / link buffer is a storage name;
 * FALSE if the buffer is malformed */
static BOOLEAN mf_rename_buffer_name(PFLT_CALLBACK_DATA Data, BOOLEAN* name_match)
{
	/* FILE_LINK_INFORMATION has the same layout as FILE_RENAME_INFORMATION (also the Ex forms) */
	PFILE_RENAME_INFORMATION ren_info = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
	ULONG                    length   = Data->Iopb->Parameters.SetFileInformation.Length;
	const wchar_t*           comp;
	ULONG                    comp_len;

	if (ren_info == NULL || length < (ULONG)FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) ||
		ren_info->FileNameLength > length - (ULONG)FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName))
	{
		return FALSE;
	}

	mf_last_component(ren_info->FileName, ren_info->FileNameLength, &comp, &comp_len);
	*name_match = is_storage_name(comp, comp_len);
	return TRUE;
}

/*
 * TRUE if a rename / link would create or replace a storage name in the volume root.
 * - ParentOfTarget != NULL: the target directory was opened (reparse points followed);
 *   it is the root if its internal ID equals the root's. The final component is taken
 *   from the rename buffer and from the target file object (holds the reparsed final
 *   component); either matching counts. Fail-closed if the IDs cannot be compared.
 * - ParentOfTarget == NULL (rename / link in the source's own directory): the matching
 *   name is denied in any directory; the source's parent cannot be determined reliably.
 */
static BOOLEAN mf_is_storage_destination(mf_context* mf_ctx, PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects)
{
	PFILE_OBJECT             target   = Data->Iopb->Parameters.SetFileInformation.ParentOfTarget;
	const wchar_t*           comp;
	ULONG                    comp_len;
	LONGLONG                 id, root_id;
	BOOLEAN                  name_match;

	if ( !mf_rename_buffer_name(Data, &name_match) ) return FALSE;

	if (target == NULL) return name_match;

	if (!name_match && target->FileName.Buffer != NULL && target->FileName.Length != 0)
	{
		mf_last_component(target->FileName.Buffer, target->FileName.Length, &comp, &comp_len);
		name_match = is_storage_name(comp, comp_len);
	}
	if (!name_match) return FALSE;

	if ( !mf_get_root_id(mf_ctx, FltObjects, &root_id) ||
		 !NT_SUCCESS(mf_query_fo_id(FltObjects->Instance, target, &id)) )
	{
		return TRUE;
	}
	return id == root_id;
}

static FLT_PREOP_CALLBACK_STATUS FLTAPI mf_set_information(IN OUT PFLT_CALLBACK_DATA    Data,
	                                                       IN     PCFLT_RELATED_OBJECTS FltObjects,
												           OUT    PVOID*                CompletionContext)
{
	mf_context*               mf_ctx;
	LONGLONG                  id;
	mf_stor_ids               ids;
	BOOLEAN                   is_link = FALSE;
	BOOLEAN                   denied = FALSE;

	if ( !mf_is_link_or_rename_class(Data->Iopb->Parameters.SetFileInformation.FileInformationClass, &is_link) ) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	if (KeGetCurrentIrql() > APC_LEVEL || FltObjects->FileObject == NULL) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	if ( !NT_SUCCESS(FltGetInstanceContext(FltObjects->Instance, (PVOID*)&mf_ctx)) || mf_ctx == NULL ) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	/* at APC_LEVEL the ID queries are not done: deny a storage name as the target in
	   any directory (fail closed) */
	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		BOOLEAN name_match;

		if (mf_ctx->dev_hook && (mf_ctx->dev_hook->flags & MF_PROTECT_FLAGS) &&
			mf_ctx->dev_hook->wrk_thread_id != PsGetCurrentThreadId() &&
			mf_rename_buffer_name(Data, &name_match))
		{
			denied = name_match;
		}
		if (denied) {
			Data->IoStatus.Status      = STATUS_ACCESS_DENIED;
			Data->IoStatus.Information = 0;
		}
		FltReleaseContext(mf_ctx);
		return denied ? FLT_PREOP_COMPLETE : FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (mf_ctx->dev_hook && (mf_ctx->dev_hook->flags & MF_PROTECT_FLAGS) &&
		mf_ctx->dev_hook->wrk_thread_id != PsGetCurrentThreadId())
	{
		/* hard link or rename whose source is a storage file */
		if (NT_SUCCESS(mf_query_fo_id(FltObjects->Instance, FltObjects->FileObject, &id)))
		{
			mf_get_storage_ids(mf_ctx, FltObjects, &ids);
			denied = mf_is_storage_id(&ids, id);
		}

		/* rename or hard link onto a storage name in the root, any requestor mode */
		if (!denied && mf_is_storage_destination(mf_ctx, Data, FltObjects))
		{
			denied = TRUE;
		}

		if (denied) {
			DbgMsg("Denied %s involving storage file, class: %d, thread ID: 0x%p\n", is_link ? "link" : "rename",
				(int)Data->Iopb->Parameters.SetFileInformation.FileInformationClass, PsGetCurrentThreadId());
			Data->IoStatus.Status      = STATUS_ACCESS_DENIED;
			Data->IoStatus.Information = 0;
		}
	}
	FltReleaseContext(mf_ctx);
	return denied ? FLT_PREOP_COMPLETE : FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS FLTAPI mf_directory_control(IN OUT PFLT_CALLBACK_DATA    Data,
	                                                         IN     PCFLT_RELATED_OBJECTS FltObjects,
												             OUT    PVOID*                CompletionContext)
{
	mf_context* mf_ctx;
	BOOLEAN     postop_needed = FALSE;

	if ( (dc_conf_flags & CONF_HIDE_DCSYS) == 0 || Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY )
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	if (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass != FileBothDirectoryInformation &&
		Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass != FileDirectoryInformation &&
		Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass != FileFullDirectoryInformation &&
		Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass != FileIdBothDirectoryInformation &&
		Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass != FileIdFullDirectoryInformation &&
		Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass != FileNamesInformation)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	__try {
		if (FltObjects->FileObject->FileName.Length != sizeof(wchar_t)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
		if (FltObjects->FileObject->FileName.Buffer == NULL || FltObjects->FileObject->FileName.Buffer[0] != L'\\') return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	
	if ( NT_SUCCESS(FltGetInstanceContext(FltObjects->Instance, (PVOID*)&mf_ctx)) && mf_ctx != NULL )
	{
		postop_needed = mf_ctx->dev_hook && (mf_ctx->dev_hook->flags & MF_PROTECT_FLAGS) != 0;
		FltReleaseContext(mf_ctx);
	}
	return postop_needed ? FLT_PREOP_SYNCHRONIZE : FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static BOOLEAN is_dcsys_info_entry(FILE_INFORMATION_CLASS entry_class, PVOID entry)
{
	switch (entry_class) 
	{
		case FileBothDirectoryInformation:
			return is_dcsys_name(((PFILE_BOTH_DIR_INFORMATION)entry)->FileName, ((PFILE_BOTH_DIR_INFORMATION)entry)->FileNameLength);
		case FileDirectoryInformation:
			return is_dcsys_name(((PFILE_DIRECTORY_INFORMATION)entry)->FileName, ((PFILE_DIRECTORY_INFORMATION)entry)->FileNameLength);
		case FileFullDirectoryInformation:
			return is_dcsys_name(((PFILE_FULL_DIR_INFORMATION)entry)->FileName, ((PFILE_FULL_DIR_INFORMATION)entry)->FileNameLength);
		case FileIdBothDirectoryInformation:
			return is_dcsys_name(((PFILE_ID_BOTH_DIR_INFORMATION)entry)->FileName, ((PFILE_ID_BOTH_DIR_INFORMATION)entry)->FileNameLength);
		case FileIdFullDirectoryInformation:
			return is_dcsys_name(((PFILE_ID_FULL_DIR_INFORMATION)entry)->FileName, ((PFILE_ID_FULL_DIR_INFORMATION)entry)->FileNameLength);
		case FileNamesInformation:
			return is_dcsys_name(((PFILE_NAMES_INFORMATION)entry)->FileName, ((PFILE_NAMES_INFORMATION)entry)->FileNameLength);
	}
	return FALSE;
}

/*
 * The query returned only the hidden $dcsys$ entry: the file system cursor is already
 * past it, so the query is reissued for the next entry (STATUS_NO_MORE_FILES invented
 * here could end the enumeration early). SL_RESTART_SCAN must be cleared, or the reissue
 * would return $dcsys$ again. The pre-op returned FLT_PREOP_SYNCHRONIZE, as
 * FltReissueSynchronousIo requires.
 */
#ifndef SL_NO_CURSOR_UPDATE
#define SL_NO_CURSOR_UPDATE 0x10
#endif
static void mf_reissue_past_dcsys(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects)
{
	/* a reissue without cursor update or from a given index would return $dcsys$ again,
	   unfiltered (it bypasses this instance); FltReissueSynchronousIo also requires
	   PASSIVE_LEVEL. In those cases end the query (STATUS_NO_MORE_FILES). */
	if ( (Data->Iopb->OperationFlags & (SL_NO_CURSOR_UPDATE | SL_INDEX_SPECIFIED)) ||
		 KeGetCurrentIrql() != PASSIVE_LEVEL )
	{
		Data->IoStatus.Status      = STATUS_NO_MORE_FILES;
		Data->IoStatus.Information = 0;
		return;
	}
	if (Data->Iopb->OperationFlags & SL_RESTART_SCAN) {
		Data->Iopb->OperationFlags = (UCHAR)(Data->Iopb->OperationFlags & ~SL_RESTART_SCAN);
		FltSetCallbackDataDirty(Data);
	}
	FltReissueSynchronousIo(FltObjects->Instance, Data);
}

static FLT_POSTOP_CALLBACK_STATUS FLTAPI mf_post_directory_control(IN OUT PFLT_CALLBACK_DATA       Data,
	                                                               IN     PCFLT_RELATED_OBJECTS    FltObjects,
																   IN     PVOID                    CompletionContext,
																   IN     FLT_POST_OPERATION_FLAGS Flags)
{
	FILE_INFORMATION_CLASS     i_class = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass;
	PFILE_BOTH_DIR_INFORMATION cur_dir = (PFILE_BOTH_DIR_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
	PFILE_BOTH_DIR_INFORMATION lst_dir = (PFILE_BOTH_DIR_INFORMATION)NULL;
	ULONG                      length  = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.Length;

	/* while draining the buffer holds no result and nothing may be reissued */
	if ( (Flags & FLTFL_POST_OPERATION_DRAINING) || NT_SUCCESS(Data->IoStatus.Status) == FALSE )
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	__try
	{
		if (Data->Iopb->OperationFlags & SL_RETURN_SINGLE_ENTRY)
		{
			if (is_dcsys_info_entry(i_class, cur_dir))
			{
				/* also with SL_RESTART_SCAN */
				mf_reissue_past_dcsys(Data, FltObjects);
			}
		} else
		{
			for (;;)
			{
				if (is_dcsys_info_entry(i_class, cur_dir))
				{
					if (cur_dir->NextEntryOffset != 0)
					{
						if (cur_dir->NextEntryOffset <= length) {
							memmove(cur_dir, addof(cur_dir, cur_dir->NextEntryOffset), length - cur_dir->NextEntryOffset);
						}
					} else
					{
						if (lst_dir == NULL) {
							/* the only entry in the buffer - not necessarily the
							   last of the directory (the next one may not have fit) */
							mf_reissue_past_dcsys(Data, FltObjects);
						} else {
							lst_dir->NextEntryOffset = 0;
						}
					}
					break;
				}
				if ( (cur_dir->NextEntryOffset == 0) || (cur_dir->NextEntryOffset > length) ) {
					break;
				} else {
					lst_dir = cur_dir; length -= cur_dir->NextEntryOffset; 
					cur_dir = (PFILE_BOTH_DIR_INFORMATION)((char*)cur_dir + cur_dir->NextEntryOffset);
				}
			}
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
	}
	return FLT_POSTOP_FINISHED_PROCESSING;
}

/*
 * TRUE if an FSCTL_MOVE_FILE would move the clusters of a storage file (the defrag API
 * needs only a read-attributes handle). The header and the redirect keep the physical
 * stor_off, so after a move the file system would reuse the old clusters - without the
 * driver, writes there overwrite the only copy of the volume's first sectors. Denying
 * the move makes defrag skip the file and a shrink stop at it. The handle in the input
 * buffer belongs to the requestor. Fail closed if the file's ID cannot be read.
 * PASSIVE_LEVEL (checked by the caller).
 */
static BOOLEAN mf_is_storage_move(mf_context* mf_ctx, PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects)
{
	PVOID        p_buff = Data->Iopb->Parameters.FileSystemControl.Buffered.SystemBuffer;
	ULONG        length = Data->Iopb->Parameters.FileSystemControl.Buffered.InputBufferLength;
	HANDLE       h_file;
	PFILE_OBJECT f_obj  = NULL;
	PFLT_VOLUME  volume = NULL;
	mf_stor_ids  ids;
	LONGLONG     id;
	BOOLEAN      moved  = FALSE;

	if (p_buff == NULL) return FALSE; /* the file system rejects it */

#if defined(_WIN64)
	if (FltIs32bitProcess(Data)) {
		if (length < sizeof(MOVE_FILE_DATA32)) return FALSE;
		h_file = (HANDLE)(ULONG_PTR)((PMOVE_FILE_DATA32)p_buff)->FileHandle;
	} else
#endif
	{
		if (length < sizeof(MOVE_FILE_DATA)) return FALSE;
		h_file = ((PMOVE_FILE_DATA)p_buff)->FileHandle;
	}

	if ( !NT_SUCCESS(ObReferenceObjectByHandle(h_file, 0, *IoFileObjectType, Data->RequestorMode, (PVOID*)&f_obj, NULL)) ) {
		return FALSE; /* invalid handle: the file system fails the request */
	}

	/* a file of another volume is not ours to judge (and is rejected by the file system) */
	if ( NT_SUCCESS(FltGetVolumeFromFileObject(FltObjects->Filter, f_obj, &volume)) && volume == FltObjects->Volume )
	{
		mf_get_storage_ids(mf_ctx, FltObjects, &ids);

		if (ids.sys_found || ids.bak_found || ids.log_found) {
			if ( !NT_SUCCESS(mf_query_fo_id(FltObjects->Instance, f_obj, &id)) ) {
				moved = TRUE; /* fail closed */
			} else {
				moved = mf_is_storage_id(&ids, id);
			}
		}
	}
	if (volume != NULL) FltObjectDereference(volume);
	ObDereferenceObject(f_obj);
	return moved;
}

static FLT_PREOP_CALLBACK_STATUS FLTAPI mf_filesystem_control(IN OUT PFLT_CALLBACK_DATA    Data,
	                                                          IN     PCFLT_RELATED_OBJECTS FltObjects,
												              OUT    PVOID*                CompletionContext)
{
	mf_context*                mf_ctx;
	PSHRINK_VOLUME_INFORMATION shrink_info;
	PVOID                      p_buff = Data->Iopb->Parameters.FileSystemControl.Buffered.SystemBuffer;
	ULONG                      length = Data->Iopb->Parameters.FileSystemControl.Buffered.InputBufferLength;
	ULONG                      c_code = Data->Iopb->Parameters.FileSystemControl.Buffered.FsControlCode;
	FLT_PREOP_CALLBACK_STATUS  ret = FLT_PREOP_SUCCESS_NO_CALLBACK;

	/* the post-op tells ShrinkPrepare from ShrinkCommit by the context */
	*CompletionContext = NULL;

	if (Data->Iopb->MinorFunction != IRP_MN_USER_FS_REQUEST) return FLT_PREOP_SUCCESS_NO_CALLBACK;

	/* the storage files must not be moved by defrag / shrink */
	if (c_code == FSCTL_MOVE_FILE)
	{
		BOOLEAN denied = FALSE;

		if (KeGetCurrentIrql() != PASSIVE_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;
		if ( !NT_SUCCESS(FltGetInstanceContext(FltObjects->Instance, (PVOID*)&mf_ctx)) || mf_ctx == NULL ) {
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
		if (mf_ctx->dev_hook && (mf_ctx->dev_hook->flags & MF_PROTECT_FLAGS) &&
			mf_ctx->dev_hook->wrk_thread_id != PsGetCurrentThreadId() &&
			mf_is_storage_move(mf_ctx, Data, FltObjects))
		{
			DbgMsg("Denied FSCTL_MOVE_FILE of the storage file, thread ID: 0x%p\n", PsGetCurrentThreadId());
			Data->IoStatus.Status      = STATUS_ACCESS_DENIED;
			Data->IoStatus.Information = 0;
			denied = TRUE;
		}
		FltReleaseContext(mf_ctx);
		return denied ? FLT_PREOP_COMPLETE : FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (c_code != FSCTL_EXTEND_VOLUME && c_code != FSCTL_SHRINK_VOLUME) return FLT_PREOP_SUCCESS_NO_CALLBACK;

	if ( !NT_SUCCESS(FltGetInstanceContext(FltObjects->Instance, (PVOID*)&mf_ctx)) || mf_ctx == NULL )
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	/* File system extend of a mounted encrypted volume (not by the worker thread, which holds
	 * busy_lock and sizes it itself; not after a finished decryption, F_PLAIN_IO).
	 * 1. The storage provider may extend while dc_update_volume still relocates the layout and
	 *    has not published the new use_size, or before IOCTL_VOLUME_UPDATE_PROPERTIES arrived.
	 *    Wait until no update runs (busy_lock) and the lower length is no longer larger than
	 *    dsk_size. An extend that cannot get busy_lock within 30 s, or whose grow is not taken
	 *    over in 10 s, is refused (STATUS_DEVICE_BUSY): a layout operation may be writing the
	 *    partition end.
	 * 2. The file system may never reach past use_size, the I/O bound: clamp the new sector
	 *    count to use_size / bps (this also keeps the storage in the slack out).
	 * Plain waits only: no hook state is changed, no remove-lock reference is taken. */
	if (c_code == FSCTL_EXTEND_VOLUME && mf_ctx->dev_hook != NULL) {
		dev_hook *hk = mf_ctx->dev_hook;

		DbgMsg("mf_filesystem_control: FSCTL_EXTEND_VOLUME to %I64d sectors, flags 0x%X, dsk_size %I64u, use_size %I64u\n",
			(length >= sizeof(LONGLONG) && p_buff != NULL) ? ((PLARGE_INTEGER)p_buff)->QuadPart : -1ll,
			hk->flags, hk->dsk_size, hk->use_size);
		if ((hk->flags & F_ENABLED) && !(hk->flags & F_PLAIN_IO) && hk->wrk_thread_id != PsGetCurrentThreadId())
		{
			NTSTATUS refuse = STATUS_SUCCESS;

			if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
				LARGE_INTEGER wait_to;
				ULONGLONG     len;
				int           i, pending;

				wait_to.QuadPart = -30ll * 10000000ll; /* 30 s */
				for (i = 0; ; i++)
				{
					if (KeWaitForSingleObject(&hk->busy_lock, Executive, KernelMode, FALSE, &wait_to) != STATUS_SUCCESS) {
						DbgMsg("mf_filesystem_control: FSCTL_EXTEND_VOLUME refused, busy_lock not free after 30 s\n");
						refuse = STATUS_DEVICE_BUSY;
						break;
					}
					/* under busy_lock: no update is half done. Only a mounted, started volume is
					 * queried; otherwise leave the loop, the re-check before the clamp handles it */
					pending = (hk->flags & F_ENABLED) && !(hk->flags & F_PLAIN_IO) && hk->pnp_state == Started &&
						NT_SUCCESS(dc_query_dev_length(hk, &len, NULL)) && len > hk->dsk_size;
					KeReleaseMutex(&hk->busy_lock, FALSE);
					if (!pending) break;
					if (i >= 100) {
						DbgMsg("mf_filesystem_control: FSCTL_EXTEND_VOLUME refused, partition grow (%I64u > %I64u) not taken over in 10 s\n",
							len, hk->dsk_size);
						refuse = STATUS_DEVICE_BUSY;
						break;
					}
					dc_delay(100);
				}
			}
			if (refuse != STATUS_SUCCESS) {
				Data->IoStatus.Status      = refuse;
				Data->IoStatus.Information = 0;
				FltReleaseContext(mf_ctx);
				return FLT_PREOP_COMPLETE;
			}
			/* re-checked after the wait (unmounted / decrypted meanwhile: nothing to clamp) */
			if ((hk->flags & F_ENABLED) && !(hk->flags & F_PLAIN_IO) && length >= sizeof(LONGLONG) && p_buff != NULL)
			{
				LONGLONG cap = (LONGLONG)(hk->use_size / max(hk->bps, SECTOR_SIZE));
				if (((PLARGE_INTEGER)p_buff)->QuadPart > cap) {
					DbgMsg("mf_filesystem_control: FSCTL_EXTEND_VOLUME clamped from %I64d to %I64d sectors (use_size %I64u)\n",
						((PLARGE_INTEGER)p_buff)->QuadPart, cap, hk->use_size);
					((PLARGE_INTEGER)p_buff)->QuadPart = cap;
				}
			}
		}
	}

	if (mf_ctx->dev_hook && (mf_ctx->dev_hook->flags & F_ENABLED) && mf_ctx->dev_hook->wrk_thread_id != PsGetCurrentThreadId()
		&& (IS_STORAGE_ON_END(mf_ctx->dev_hook->flags) != 0 || (mf_ctx->dev_hook->flags & F_HEAD_BACKUP) != 0))
	{
		if (c_code == FSCTL_SHRINK_VOLUME && length >= sizeof(SHRINK_VOLUME_INFORMATION))
		{
			shrink_info = (PSHRINK_VOLUME_INFORMATION)p_buff;

			if (shrink_info->ShrinkRequestType == ShrinkPrepare)
			{
				/*
				 * The requested size is stored as pending by the post-op only if the Prepare
				 * succeeded. Without the context the shrink is refused: passing it on would
				 * leave the storage behind on the Commit.
				 */
				mf_shrink_prep* prep;
				dev_hook*       sh = mf_ctx->dev_hook;

				/* $dcsys$ storage file + backup header: the backup header goes to the end of the
				 * new partition, which must lie behind the (unmovable) file. The size cannot be
				 * raised here: refuse a shrink that leaves less than that area behind the file. */
				if ( (sh->flags & F_PROTECT_DCSYS) && (sh->flags & F_HEAD_BACKUP) && !IS_STORAGE_ON_END(sh->flags) )
				{
					u64 new_bytes = (shrink_info->NewNumberOfSectors > 0) ?
						(u64)shrink_info->NewNumberOfSectors * max(sh->bps, SECTOR_SIZE) : 0;

					if (dc_dcsys_end_overlap(sh, new_bytes)) {
						DbgMsg("mf_filesystem_control: ShrinkPrepare refused, new size %I64u leaves no room for the backup header after $dcsys$ [%I64u, +%u)\n",
							new_bytes, sh->stor_off, sh->stor_len);
						FltReleaseContext(mf_ctx);
						Data->IoStatus.Status      = STATUS_INVALID_PARAMETER;
						Data->IoStatus.Information = 0;
						return FLT_PREOP_COMPLETE;
					}
				}

				prep = (mf_shrink_prep*)mm_pool_alloc(sizeof(mf_shrink_prep));

				if (prep == NULL) {
					FltReleaseContext(mf_ctx);
					Data->IoStatus.Status      = STATUS_INSUFFICIENT_RESOURCES;
					Data->IoStatus.Information = 0;
					return FLT_PREOP_COMPLETE;
				}
				/* ShrinkPrepare: partition size for the post operation after commit */
				prep->hook    = mf_ctx->dev_hook;
				prep->sectors = shrink_info->NewNumberOfSectors;
				prep->commit  = FALSE;
				/* Adjust sector count to account for storage area at partition end */
				if (IS_STORAGE_ON_END(mf_ctx->dev_hook->flags)) {
					shrink_info->NewNumberOfSectors -= (mf_ctx->dev_hook->stor_len / max(mf_ctx->dev_hook->bps, SECTOR_SIZE));
					if (shrink_info->NewNumberOfSectors < 0) shrink_info->NewNumberOfSectors = 0;
				}
				DbgMsg("mf_filesystem_control: ShrinkPrepare, requested=%I64d, fsctl=%I64u\n",
					prep->sectors, shrink_info->NewNumberOfSectors);
				*CompletionContext = prep;
				ret = FLT_PREOP_SUCCESS_WITH_CALLBACK;
			}
			else if (shrink_info->ShrinkRequestType == ShrinkCommit)
			{
				/*
				 * The post-op relocates the storage / backup header / end sectors while the
				 * partition still has its old size; once it is cut the old place lies past the
				 * end and cannot be read any more (storage on end: RAW after the next mount), so
				 * the relocation must not time out after the commit. busy_lock is taken HERE,
				 * before the file system sees the commit (bounded wait, 30 s), and held into the
				 * post-op (FLT_PREOP_SYNCHRONIZE: same thread), where dc_update_volume re-acquires
				 * it recursively and the post-op releases it. Not obtained, or a state in which
				 * dc_update_volume would not relocate: the commit is refused before anything
				 * moved. A finished decryption (F_PLAIN_IO) has nothing to relocate and is passed.
				 * Deadlocks: taken before the file system holds anything for this request (an
				 * unmount holding busy_lock while it locks the volume makes the wait time out);
				 * order busy_lock -> step slot as in dc_update_volume.
				 * A removable medium must be verified as the mounted one, which is only possible
				 * at PASSIVE_LEVEL; otherwise the commit is refused.
				 */
				dev_hook*       sh = mf_ctx->dev_hook;
				mf_shrink_prep* cm;
				LARGE_INTEGER   wait_to;
				NTSTATUS        refuse = STATUS_SUCCESS;

				wait_to.QuadPart = -30ll * 10000000ll; /* 30 s */

				if ( (cm = (mf_shrink_prep*)mm_pool_alloc(sizeof(mf_shrink_prep))) == NULL ) {
					refuse = STATUS_INSUFFICIENT_RESOURCES;
				} else if (KeWaitForSingleObject(&sh->busy_lock, Executive, KernelMode, FALSE, &wait_to) != STATUS_SUCCESS) {
					DbgMsg("mf_filesystem_control: ShrinkCommit refused, busy_lock not free after 30 s\n");
					refuse = STATUS_DEVICE_BUSY;
				} else {
					if ( (sh->flags & F_ENABLED) && !(sh->flags & F_PLAIN_IO) &&
						 ( (sh->mnt_flags & MF_IGNORE_CRC) || (sh->flags & (F_DISABLE | F_HIBER_ERASE)) ||
						   sh->pnp_state != Started || sh->pending_shrink_sectors <= 0 ) )
					{
						DbgMsg("mf_filesystem_control: ShrinkCommit refused, the layout would not be relocated (flags 0x%X, mnt_flags 0x%X, pending %I64d)\n",
							sh->flags, sh->mnt_flags, sh->pending_shrink_sectors);
						refuse = STATUS_INVALID_DEVICE_STATE;
					}
					else if ( (sh->flags & F_REMOVABLE) &&
						 (KeGetCurrentIrql() != PASSIVE_LEVEL || io_check_media(sh) != ST_OK) )
					{
						DbgMsg("mf_filesystem_control: ShrinkCommit refused, mounted medium not verified\n");
						refuse = STATUS_MEDIA_CHANGED;
					}
					if (refuse != STATUS_SUCCESS) KeReleaseMutex(&sh->busy_lock, FALSE);
				}
				if (refuse != STATUS_SUCCESS) {
					if (cm != NULL) mm_pool_free(cm);
					FltReleaseContext(mf_ctx);
					Data->IoStatus.Status      = refuse;
					Data->IoStatus.Information = 0;
					return FLT_PREOP_COMPLETE;
				}
				/* the target checked above: a ShrinkAbort / Prepare of a second caller (no
				 * busy_lock) may change pending_shrink_sectors before the post-op */
				cm->hook    = sh;
				cm->sectors = sh->pending_shrink_sectors;
				cm->commit  = TRUE;
				DbgMsg("mf_filesystem_control: ShrinkCommit, busy_lock held, requesting post-op callback\n");
				*CompletionContext = cm;
				/* synchronized: the post-op runs dc_update_volume, which needs PASSIVE_LEVEL
				   and the owner thread of busy_lock */
				ret = FLT_PREOP_SYNCHRONIZE;
			}
			else if (shrink_info->ShrinkRequestType == ShrinkAbort)
			{
				/* ShrinkAbort: clear pending state */
				mf_ctx->dev_hook->pending_shrink_sectors = -1;
				DbgMsg("mf_filesystem_control: ShrinkAbort, cleared pending shrink\n");
			}
		}
		/* FSCTL_EXTEND_VOLUME: waited for and clamped to use_size above */
	}
	FltReleaseContext(mf_ctx);
	return ret;
}

static FLT_POSTOP_CALLBACK_STATUS FLTAPI mf_post_filesystem_control(IN OUT PFLT_CALLBACK_DATA       Data,
	                                                                IN     PCFLT_RELATED_OBJECTS    FltObjects,
																    IN     PVOID                    CompletionContext,
																    IN     FLT_POST_OPERATION_FLAGS Flags)
{
	mf_shrink_prep* prep = (mf_shrink_prep*)CompletionContext;
	dev_hook*       hk;
	LONGLONG        pending_sectors;
	ULONGLONG       new_size;
	NTSTATUS        status;

	UNREFERENCED_PARAMETER(FltObjects);

	if (prep == NULL) return FLT_POSTOP_FINISHED_PROCESSING;

	/*
	 * ShrinkPrepare (may run at DISPATCH_LEVEL: only stores the value). The target becomes
	 * pending only once the file system accepted it; a failed Prepare leaves the earlier
	 * one. While draining the outcome is unknown, so nothing stays pending (a Commit is
	 * then refused).
	 */
	if (!prep->commit)
	{
		if (Flags & FLTFL_POST_OPERATION_DRAINING) {
			prep->hook->pending_shrink_sectors = -1;
		} else if (NT_SUCCESS(Data->IoStatus.Status)) {
			prep->hook->pending_shrink_sectors = prep->sectors;
			DbgMsg("mf_post_filesystem_control: ShrinkPrepare accepted, pending=%I64d\n", prep->sectors);
		} else {
			DbgMsg("mf_post_filesystem_control: ShrinkPrepare failed with status 0x%X, pending unchanged\n", Data->IoStatus.Status);
		}
		mm_pool_free(prep);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	/*
	 * ShrinkCommit (FLT_PREOP_SYNCHRONIZE: the thread of the pre-op, IRQL <= APC_LEVEL).
	 * The pre-op holds hk->busy_lock; every path below releases it. The hook cannot go
	 * away meanwhile: the removal takes busy_lock before the hook is freed.
	 * While draining IoStatus is not the commit's result: nothing is relocated, the
	 * IOCTL_VOLUME_UPDATE_PROPERTIES path re-syncs the size (not for a storage-on-end
	 * shrink: the old storage lies past the new end).
	 */
	hk = prep->hook;

	if (Flags & FLTFL_POST_OPERATION_DRAINING) {
		DbgMsg("mf_post_filesystem_control: draining, ShrinkCommit not processed\n");
	}
	else if (!NT_SUCCESS(Data->IoStatus.Status)) {
		/* only successful shrink operations; the prepared target stays for a retried commit */
		DbgMsg("mf_post_filesystem_control: shrink failed with status 0x%X, skipping\n", Data->IoStatus.Status);
	}
	else
	{
		/* the target of ShrinkPrepare as the pre-op saw it under busy_lock; the
		 * committed shrink consumes the pending one */
		pending_sectors = prep->sectors;
		hk->pending_shrink_sectors = -1; /* Clear pending state */

		/* > 0: new_len == 0 selects dc_update_volume's IOCTL path, which counts its
		 * busy_lock wait as a remove-lock holder; this post-op holds no reference */
		if (pending_sectors > 0)
		{
			/* pending_shrink_sectors already contains full partition size from ShrinkPrepare */
			new_size = pending_sectors * hk->bps;
			DbgMsg("mf_post_filesystem_control: ShrinkCommit post-op, new_size=%I64u\n", new_size);

			/* busy_lock is held - its bounded wait cannot time out here */
			status = dc_update_volume(hk, new_size);
			if (!NT_SUCCESS(status)) {
				DbgMsg("mf_post_filesystem_control: dc_update_volume failed with status 0x%X\n", status);
				/* Don't fail the FSCTL - filesystem already shrunk, storage relocation will be retried via IOCTL path
				 * (except a storage-on-end shrink: the old storage lies past the new end) */
			}
		}
		else
		{
			DbgMsg("mf_post_filesystem_control: no pending shrink target, skipping\n");
		}
	}

	KeReleaseMutex(&hk->busy_lock, FALSE);
	mm_pool_free(prep);
	return FLT_POSTOP_FINISHED_PROCESSING;
}


static const FLT_OPERATION_REGISTRATION mf_op_callbacks[] = {
	{ IRP_MJ_CREATE,              0, mf_irp_mj_create,      mf_post_create }, /* post only for open-by-ID */
	{ IRP_MJ_SET_INFORMATION,     0, mf_set_information,    NULL }, /* rename / link protection */
	{ IRP_MJ_DIRECTORY_CONTROL,   0, mf_directory_control,  mf_post_directory_control },
	{ IRP_MJ_FILE_SYSTEM_CONTROL, 0, mf_filesystem_control, mf_post_filesystem_control },
    { IRP_MJ_OPERATION_END }
};

static const FLT_CONTEXT_REGISTRATION mf_contexts[] = {
	{ FLT_INSTANCE_CONTEXT, 0, NULL, sizeof(mf_context), '4_cd', NULL, NULL, NULL },
	{ FLT_CONTEXT_END }
};

static const FLT_REGISTRATION mf_registration = {
    sizeof(FLT_REGISTRATION),                       //  Size
    FLT_REGISTRATION_VERSION_0200,                  //  Version
    FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP, //  Flags
    mf_contexts,                                    //  Context
    mf_op_callbacks,                                //  Operation callbacks
    NULL,                                           //  MiniFilterUnload
    mf_instance_setup_callback,                     //  InstanceSetup
    NULL,                                           //  InstanceQueryTeardown
    NULL,                                           //  InstanceTeardownStart
    mf_teardown_complete_callback,                  //  InstanceTeardownComplete
    NULL,                                           //  GenerateFileName
    NULL,                                           //  GenerateDestinationFileName
    NULL                                            //  NormalizeNameComponent
};

void mf_init(PDRIVER_OBJECT drv_obj)
{
	PFLT_FILTER mf_filter;

	if (NT_SUCCESS(FltRegisterFilter(drv_obj, &mf_registration, &mf_filter)) == FALSE) {
		return;
	}
	if (NT_SUCCESS(FltStartFiltering(mf_filter)) == FALSE) {
		FltUnregisterFilter(mf_filter);
	}
}