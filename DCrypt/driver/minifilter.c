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
#include "debug.h"

typedef struct _mf_context {
	dev_hook* dev_hook;
	LONGLONG  dcsys_id;

} mf_context;

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

	mf_ctx->dev_hook = hook;
	mf_ctx->dcsys_id = 0;

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
		// Workaround for strange crashes when disconnecting USB devices
		if ( !MmIsAddressValid(mf_ctx) ||
			 !MmIsAddressValid(mf_ctx->dev_hook) ||
			 !MmIsAddressValid(mf_ctx->dev_hook->pdo_dev) )
		{
			return;
		}

		if (mf_ctx->dev_hook != NULL) dc_deref_hook(mf_ctx->dev_hook);
		FltReleaseContext(mf_ctx);
	}
}

static LONGLONG mf_query_dcsys_id(dev_hook* hook, PCFLT_RELATED_OBJECTS objects)
{
	wchar_t                   buff[128];
	FILE_INTERNAL_INFORMATION info = { 0 };
	OBJECT_ATTRIBUTES         obj_a;
	UNICODE_STRING            name;
	IO_STATUS_BLOCK           iosb;
	HANDLE                    h_file = NULL;
	PFILE_OBJECT              p_file = NULL;

	if ( !NT_SUCCESS(RtlStringCchPrintfW(buff, (sizeof(buff) / sizeof(buff[0])), L"%s\\$dcsys$", hook->dev_name)) )
	{
		goto cleanup;
	}

	RtlInitUnicodeString(&name, buff);
	InitializeObjectAttributes(&obj_a, &name, OBJ_KERNEL_HANDLE, NULL, NULL);

	if ( !NT_SUCCESS(FltCreateFile(objects->Filter,
		                           objects->Instance, &h_file, GENERIC_READ, 
								   &obj_a, &iosb, NULL, 0, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, 0)) )
	{
		h_file = NULL;
		goto cleanup;
	}

	if ( !NT_SUCCESS(ObReferenceObjectByHandle(h_file, 0, NULL, KernelMode, (PVOID*)&p_file, NULL)) )
	{
		p_file = NULL;
		goto cleanup;
	}

	if ( !NT_SUCCESS(FltQueryInformationFile(objects->Instance, p_file, &info, sizeof(info), FileInternalInformation, NULL)) )
	{
		info.IndexNumber.QuadPart = 0;
	}

cleanup:
	if (p_file != NULL) ObDereferenceObject(p_file);
	if (h_file != NULL) FltClose(h_file);
	return info.IndexNumber.QuadPart;
}

static BOOLEAN is_dcsys_name(const wchar_t* buff, ULONG length)
{
	return length >= 14 && (length == 14 || buff[7] == L':') && _wcsnicmp(buff, L"$dcsys$", 7) == 0;
}

/*
* Access mask for operations that must be denied on $dcsys$:
* - Content access (read/write/execute)
* - Modification (write attributes, delete, change permissions)
*/
#define DCSYS_DENIED_ACCESS ( \
      FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_EXECUTE | \
      FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | \
      DELETE | WRITE_DAC | WRITE_OWNER )

static FLT_PREOP_CALLBACK_STATUS FLTAPI mf_irp_mj_create(IN OUT PFLT_CALLBACK_DATA    Data,
	                                                     IN     PCFLT_RELATED_OBJECTS FltObjects,
												         OUT    PVOID*                CompletionContext)
{
	mf_context* mf_ctx;
	wchar_t*    p_buff = FltObjects->FileObject->FileName.Buffer;
	USHORT      length = FltObjects->FileObject->FileName.Length;
	BOOLEAN     denied = FALSE;
	BOOLEAN     is_dcsys = FALSE;

	if ( !NT_SUCCESS(FltGetInstanceContext(FltObjects->Instance, (PVOID*)&mf_ctx)) || mf_ctx == NULL )
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (mf_ctx->dev_hook && (mf_ctx->dev_hook->flags & F_PROTECT_DCSYS))
	{
		if (Data->Iopb->Parameters.Create.Options & FILE_OPEN_BY_FILE_ID)
		{
			if (mf_ctx->dcsys_id == 0 && KeGetCurrentIrql() == PASSIVE_LEVEL)
			{
				mf_ctx->dcsys_id = mf_query_dcsys_id(mf_ctx->dev_hook, FltObjects);
			}
			is_dcsys = (mf_ctx->dcsys_id != 0) &&
				     (length == sizeof(LARGE_INTEGER) && ((PLARGE_INTEGER)p_buff)->QuadPart == mf_ctx->dcsys_id);
		} else {
			while (length >= sizeof(wchar_t) && p_buff[0] == L'\\') p_buff++, length -= sizeof(wchar_t);
			is_dcsys = is_dcsys_name(p_buff, length);
		}

		if (is_dcsys) {
			DbgMsg("Access to $dcsys$ file, desired access: 0x%x, thread ID: 0x%p, worker thread ID: 0x%p\n",
				Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess, PsGetCurrentThreadId(), mf_ctx->dev_hook->wrk_thread_id);
			if (mf_ctx->dev_hook->wrk_thread_id != PsGetCurrentThreadId())
			{
				/* Allow read-only attribute access (FILE_READ_ATTRIBUTES, SYNCHRONIZE, READ_CONTROL) */
				denied = (Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & DCSYS_DENIED_ACCESS) != 0;
			}
		}

		if (denied) {
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
		postop_needed = mf_ctx->dev_hook && (mf_ctx->dev_hook->flags & F_PROTECT_DCSYS) != 0;
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

static FLT_POSTOP_CALLBACK_STATUS FLTAPI mf_post_directory_control(IN OUT PFLT_CALLBACK_DATA       Data,
	                                                               IN     PCFLT_RELATED_OBJECTS    FltObjects,
																   IN     PVOID                    CompletionContext,
																   IN     FLT_POST_OPERATION_FLAGS Flags)
{
	FILE_INFORMATION_CLASS     i_class = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass;
	PFILE_BOTH_DIR_INFORMATION cur_dir = (PFILE_BOTH_DIR_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
	PFILE_BOTH_DIR_INFORMATION lst_dir = (PFILE_BOTH_DIR_INFORMATION)NULL;
	ULONG                      length  = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.Length;

	if (NT_SUCCESS(Data->IoStatus.Status) == FALSE)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	__try
	{
		if (Data->Iopb->OperationFlags & SL_RETURN_SINGLE_ENTRY)
		{
			if (is_dcsys_info_entry(i_class, cur_dir))
			{
				if (Data->Iopb->OperationFlags & SL_RESTART_SCAN) {
					Data->IoStatus.Status      = STATUS_NO_MORE_FILES;
					Data->IoStatus.Information = 0;
				} else {
					FltReissueSynchronousIo(FltObjects->Instance, Data);
				}
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
							Data->IoStatus.Status      = STATUS_NO_MORE_FILES;
							Data->IoStatus.Information = 0;
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

	if (Data->Iopb->MinorFunction != IRP_MN_USER_FS_REQUEST) return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (c_code != FSCTL_EXTEND_VOLUME && c_code != FSCTL_SHRINK_VOLUME) return FLT_PREOP_SUCCESS_NO_CALLBACK;

	if ( !NT_SUCCESS(FltGetInstanceContext(FltObjects->Instance, (PVOID*)&mf_ctx)) || mf_ctx == NULL )
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (mf_ctx->dev_hook && (mf_ctx->dev_hook->flags & F_ENABLED) && mf_ctx->dev_hook->wrk_thread_id != PsGetCurrentThreadId()
		&& (IS_STORAGE_ON_END(mf_ctx->dev_hook->flags) != 0 || (mf_ctx->dev_hook->flags & F_HEAD_BACKUP) != 0))
	{
		if (c_code == FSCTL_SHRINK_VOLUME && length >= sizeof(SHRINK_VOLUME_INFORMATION))
		{
			shrink_info = (PSHRINK_VOLUME_INFORMATION)p_buff;

			if (shrink_info->ShrinkRequestType == ShrinkPrepare)
			{
				/* ShrinkPrepare: store partition size for post operation after commit */
				mf_ctx->dev_hook->pending_shrink_sectors = shrink_info->NewNumberOfSectors;
				/* Adjust sector count to account for storage area at partition end */
				if (IS_STORAGE_ON_END(mf_ctx->dev_hook->flags)) { 
					shrink_info->NewNumberOfSectors -= (mf_ctx->dev_hook->stor_len / max(mf_ctx->dev_hook->bps, SECTOR_SIZE));
					if (shrink_info->NewNumberOfSectors < 0) shrink_info->NewNumberOfSectors = 0;
				}
				DbgMsg("mf_filesystem_control: ShrinkPrepare, pending=%I64d, fsctl=%I64u\n",
					mf_ctx->dev_hook->pending_shrink_sectors, shrink_info->NewNumberOfSectors);
			}
			else if (shrink_info->ShrinkRequestType == ShrinkCommit)
			{
				/* ShrinkCommit: request post-op callback to relocate storage/header */
				DbgMsg("mf_filesystem_control: ShrinkCommit, requesting post-op callback\n");
				ret = FLT_PREOP_SUCCESS_WITH_CALLBACK;
			}
			else if (shrink_info->ShrinkRequestType == ShrinkAbort)
			{
				/* ShrinkAbort: clear pending state */
				mf_ctx->dev_hook->pending_shrink_sectors = -1;
				DbgMsg("mf_filesystem_control: ShrinkAbort, cleared pending shrink\n");
			}
		}
		else if (c_code == FSCTL_EXTEND_VOLUME && length >= sizeof(u64))
		{
			/* Adjust sector count to account for storage area at partition end */
			if (IS_STORAGE_ON_END(mf_ctx->dev_hook->flags)) {
				((PLARGE_INTEGER)p_buff)->QuadPart -= (mf_ctx->dev_hook->stor_len / max(mf_ctx->dev_hook->bps, SECTOR_SIZE));
				if (((PLARGE_INTEGER)p_buff)->QuadPart < 0) ((PLARGE_INTEGER)p_buff)->QuadPart = 0;
			}
			DbgMsg("mf_filesystem_control: expand pre-op, IOCTL path will handle storage relocation\n");
		}
	}
	FltReleaseContext(mf_ctx);
	return ret;
}

static FLT_POSTOP_CALLBACK_STATUS FLTAPI mf_post_filesystem_control(IN OUT PFLT_CALLBACK_DATA       Data,
	                                                                IN     PCFLT_RELATED_OBJECTS    FltObjects,
																    IN     PVOID                    CompletionContext,
																    IN     FLT_POST_OPERATION_FLAGS Flags)
{
	mf_context* mf_ctx;
	LONGLONG    pending_sectors;
	ULONGLONG   new_size;
	NTSTATUS    status;

	/* Only process successful shrink operations */
	if (!NT_SUCCESS(Data->IoStatus.Status)) {
		DbgMsg("mf_post_filesystem_control: shrink failed with status 0x%X, skipping\n", Data->IoStatus.Status);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if ( !NT_SUCCESS(FltGetInstanceContext(FltObjects->Instance, (PVOID*)&mf_ctx)) || mf_ctx == NULL )
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (mf_ctx->dev_hook)
	{
		/* Get stored shrink target from ShrinkPrepare and calculate new partition size */
		pending_sectors = mf_ctx->dev_hook->pending_shrink_sectors;
		mf_ctx->dev_hook->pending_shrink_sectors = -1; /* Clear pending state */

		if (pending_sectors >= 0)
		{
			/* pending_shrink_sectors already contains full partition size from ShrinkPrepare */
			new_size = pending_sectors * mf_ctx->dev_hook->bps;
			DbgMsg("mf_post_filesystem_control: ShrinkCommit post-op, new_size=%I64u\n", new_size);

			status = dc_update_volume(mf_ctx->dev_hook, new_size);
			if (!NT_SUCCESS(status)) {
				DbgMsg("mf_post_filesystem_control: dc_update_volume failed with status 0x%X\n", status);
				/* Don't fail the FSCTL - filesystem already shrunk, storage relocation will be retried via IOCTL path */
			}
		}
		else
		{
			DbgMsg("mf_post_filesystem_control: no pending shrink target, skipping\n");
		}
	}

	FltReleaseContext(mf_ctx);
	return FLT_POSTOP_FINISHED_PROCESSING;
}


static const FLT_OPERATION_REGISTRATION mf_op_callbacks[] = {
	{ IRP_MJ_CREATE,              0, mf_irp_mj_create,      NULL },
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