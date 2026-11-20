#ifndef _DISK_INFO_H_
#define _DISK_INFO_H_

NTSTATUS dc_fill_device_info(dev_hook *hook);
BOOLEAN  dc_mbr_boot_volume(dev_hook *hook); /* DC_MBR_LEGACY_GUARD, see driver.h; PASSIVE_LEVEL */
NTSTATUS dc_query_dev_length(dev_hook *hook, ULONGLONG *length, ULONG *bps); /* no hook writes */
void     dc_media_baseline(dev_hook *hook); /* after dc_fill_device_info, busy_lock held, before F_ENABLED */

#endif