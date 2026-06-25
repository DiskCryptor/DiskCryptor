#ifndef _MOUNT_
#define _MOUNT_

#include "devhook.h"
#include "enc_dec.h"

int dc_add_password(dc_pass *pass);
void dc_cache_password(dc_pass *pass);
int dc_lookup_password(const char* label, dc_pass *pass);
int dc_enum_pass_cache(dc_pass_info *items, int max_count, int *total_count);
void dc_clean_pass_cache();
void dc_clean_keys();

void dc_set_boot_keys(struct _header_key* keys, int count);
void dc_clean_boot_keys();

int dc_mount_device(wchar_t *dev_name, dc_pass *password, u32 mnt_flags, ULONG *interrupt_cmd);
int dc_process_unmount(dev_hook *hook, int opt);

void dc_unmount_async(dev_hook *hook);

int dc_unmount_device(wchar_t *dev_name, int force);

int dc_mount_all(dc_pass *password, u32 flags, ULONG *interrupt_cmd);
int dc_num_mount();

NTSTATUS dc_probe_mount(dev_hook *hook, PIRP irp);

void dc_init_mount();

int dc_get_pending_encrypt(wchar_t *dev_name, wchar_t* path);

#define MAX_MNT_PROBES 32

#endif