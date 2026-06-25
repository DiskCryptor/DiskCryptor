#ifndef _READWRITE_
#define _READWRITE_

NTSTATUS io_read_write_irp(dev_hook *hook, PIRP irp);

#ifdef DC_CONCURRENT_TRANSCRYPT
/* Extended version with transcrypt boundary and key snapshots.
 * trans_io: TRUE if this I/O is during transcryption (needs pending count tracking)
 * trans_boundary: snapshotted tmp_size value at I/O start time
 * snapshot_dsk_key: snapshotted dsk_key to prevent race during key changes
 * snapshot_tmp_key: snapshotted tmp_key to prevent race during key swap */
NTSTATUS io_encrypted_irp_io(dev_hook *hook, PIRP irp, BOOLEAN is_sync, BOOLEAN trans_io, ULONGLONG trans_boundary, xts_key *snapshot_dsk_key, xts_key *snapshot_tmp_key);
#else
NTSTATUS io_encrypted_irp_io(dev_hook *hook, PIRP irp, BOOLEAN is_sync);
#endif

void io_init();
void io_free();

#endif
