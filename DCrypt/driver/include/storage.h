#ifndef _STORAGE_H_
#define _STORAGE_H_

int  dc_create_storage(dev_hook *hook, u64 *storage, u32 *stor_len, u32 margin);
void dc_delete_storage(dev_hook *hook);
int  dc_get_storage_size(dev_hook *hook, u32 *stor_len);
int  dc_get_volume_slack(dev_hook *hook, u64 *slack_size);
int  dc_try_shrink_fs(dev_hook *hook, u64 shrink_bytes);
int  dc_try_expand_fs(dev_hook *hook, u64 expand_bytes);
int  dc_rename_storage(dev_hook *hook, wchar_t *old_name, wchar_t *new_name);
void dc_delete_storage_by_name(dev_hook *hook, wchar_t *name);

NTSTATUS dc_delete_file(HANDLE h_file);

#endif