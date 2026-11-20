#ifndef _MISC_IRP_
#define _MISC_IRP_

NTSTATUS dc_complete_irp(PIRP irp, NTSTATUS status, ULONG_PTR bytes);

NTSTATUS dc_forward_irp(dev_hook *hook, PIRP irp);
NTSTATUS dc_forward_irp_sync(dev_hook *hook, PIRP irp);
NTSTATUS dc_release_irp(dev_hook *hook, PIRP irp, NTSTATUS status);

NTSTATUS dc_create_close_irp(PDEVICE_OBJECT dev_obj, PIRP irp);

NTSTATUS dc_power_irp(dev_hook *hook, PIRP irp);
void     dc_init_power_irp();

#endif