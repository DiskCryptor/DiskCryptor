#ifndef _READWRITE_
#define _READWRITE_

NTSTATUS io_read_write_irp(dev_hook *hook, PIRP irp);

#ifdef DC_CONCURRENT_TRANSCRYPT
/* Extended version with transcrypt boundary and key snapshots.
 * trans_io: TRUE if this I/O is during transcryption (needs pending count tracking)
 * trans_boundary: snapshotted tmp_size value at I/O start time
 * snapshot_dsk_key: snapshotted dsk_key to prevent race during key changes
 * snapshot_tmp_key: snapshotted tmp_key to prevent race during key swap
 * untracked: the request is counted in hook->trans.untracked_io until it completes;
 *            FALSE for tracked requests */
NTSTATUS io_encrypted_irp_io(dev_hook *hook, PIRP irp, BOOLEAN is_sync, BOOLEAN trans_io, ULONGLONG trans_boundary, xts_key *snapshot_dsk_key, xts_key *snapshot_tmp_key, BOOLEAN untracked);

/* forward a read/write IRP of a volume that is not mounted (the mount probe's request): counted
 * as untracked until it completes, or dispatched normally if the volume was enabled meanwhile */
NTSTATUS io_forward_plain_irp(dev_hook *hook, PIRP irp);

/* the same for a data-changing IOCTL of a volume that is not mounted (dc_io_control_irp) */
NTSTATUS io_forward_plain_ioctl(dev_hook *hook, PIRP irp);
#else
NTSTATUS io_encrypted_irp_io(dev_hook *hook, PIRP irp, BOOLEAN is_sync);
#define io_forward_plain_irp(_hook_, _irp_) dc_forward_irp(_hook_, _irp_)
#define io_forward_plain_ioctl(_hook_, _irp_) dc_forward_irp(_hook_, _irp_)
#endif

void io_init();
void io_free();

#endif
