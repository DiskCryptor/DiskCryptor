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

void dc_clear_secrets(BOOLEAN force_cache);

int dc_mount_device(wchar_t *dev_name, dc_pass *password, u32 mnt_flags, ULONG *interrupt_cmd);

/* lock on hibernate: lock at S4 (busy_lock held; save_failed: the state save right
 * before failed), auto-unlock on resume (no lock held; retry: back off on I/O errors) */
int dc_lock_volume(dev_hook *hook, int save_failed);
int dc_unlock_locked_volumes(int retry);
int dc_num_locked();
/* S4 transition in progress (first S4 SET_POWER .. S0 SET_POWER): no mount / unlock */
void dc_set_s4_transition(BOOLEAN active);
/* test under the volume's busy_lock (the S4 path flushes it after setting the flag) */
BOOLEAN dc_s4_transition_active();
int dc_process_unmount(dev_hook *hook, int opt);

/* wait for busy_lock while holding a remove-lock reference. The waiter is counted in
 * hook->rl_waiters while blocked, and the unmount drain (which holds busy_lock) does not wait
 * for counted references. A counted waiter touches no key or session state until it has
 * busy_lock, i.e. after the unmount has finished; it then re-validates the volume state. */
void     dc_wait_busy_lock_rl(dev_hook *hook);
NTSTATUS dc_wait_busy_lock_rl_timeout(dev_hook *hook, PLARGE_INTEGER timeout);
/* drain test: remove-lock references beyond base are all counted busy_lock waiters */
BOOLEAN  dc_rl_drained(dev_hook *hook, LONG base);

/* internal mount flag: the mount probe (mount_item_proc) holds an IRP and its remove-lock
 * reference while it mounts, so its busy_lock waits are counted. Never accepted from user mode
 * (masked out of DC_CTL_MOUNT / DC_CTL_MOUNT_ALL) and never stored in hook->mnt_flags. */
#define MF_PROBE_RL 0x40000000

/* how a mount obtained its header (dc_header_recover) */
#define DC_HDR_INTACT   0 /* the primary (or, MF_USE_BACKUP, the backup) header was valid */
#define DC_HDR_BACKUP   1 /* the primary was damaged, the backup header is used */
#define DC_HDR_REPAIRED 2 /* the primary was damaged, its tmp_size was restored */
#define DC_HDR_FORCED   3 /* the primary was damaged and taken as it is (MF_IGNORE_CRC) */

void dc_unmount_async(dev_hook *hook);

int dc_unmount_device(wchar_t *dev_name, int force);

int dc_mount_all(dc_pass *password, u32 flags, ULONG *interrupt_cmd);
int dc_num_mount();

NTSTATUS dc_probe_mount(dev_hook *hook, PIRP irp);

void dc_init_mount();

int dc_get_pending_encrypt(wchar_t *dev_name, wchar_t* path);

#define MAX_MNT_PROBES 32

#endif