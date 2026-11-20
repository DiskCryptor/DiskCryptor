#ifndef _DC_IO_H_
#define _DC_IO_H_

typedef struct _mount_inf {
	void      *efi_path; // EFI_DEVICE_PATH* - partition device path for hook registration
	void      *BlockIo;  // EFI_BLOCK_IO_PROTOCOL* - partition BlockIo (set after hook installed)
	s32        h_alg;
	s32        h_kdf;
	u8         h_key[PKCS_DERIVE_MAX];
	xts_key   *d_key;
	xts_key   *o_key;
	u64        size;	// in sectors (partition size)
	u32        bps;		// bytes per sector
	u16		   version;
	u32        features;
	u32        flags;
	u64        tmp_size; // in sectors
	u64        stor_off; // in sectors
	u32        stor_len; // in sectors
	u32        head_len; // in sectors
	u64        use_size; // in sectors
	u32        disk_id;
	u8         disk_guid[16];

	// the block a power loss interrupted in a protected transcryption session (dc_journal_recover):
	// read from pend_img (the block as the driver will complete it), never written. pend_img NULL:
	// the block could not be rebuilt, I/O to it fails.
	u64        pend_off; // in sectors
	u64        pend_len; // in sectors, 0: no pending block
	u8        *pend_img; // pend_len * bps bytes

} mount_inf;

#define MOUNT_MAX 32
#define KEY_MAX   32

#pragma warning(push)
#pragma warning(disable: 4324) // structure was padded due to alignment specifier
typedef struct _io_db {
	mount_inf p_mount[MOUNT_MAX];
	u8        n_mount;
	xts_key   p_key[KEY_MAX];
	u8        n_key;
} io_db;
#pragma warning(pop)

extern io_db iodb;

// Direct I/O - uses partition-relative sector addresses
// mount: mounted partition info (must have BlockIo set after hook installed)
// start: sector offset relative to partition start (not disk start)
int dc_direct_io(mount_inf *mount, void *buff, u16 sectors, u64 start, int read);

// Volume-level I/O handler for encrypted partitions (entry point for partition hooks)
// mount: mounted partition info
// start: sector offset relative to partition start
int dc_mount_io(mount_inf *mount, void *buff, u16 sectors, u64 start, int read);

// The boundary of a power-loss protected transcryption session from its journal
// (dc_safe_efi.c). Called with the mount entry filled from header (tmp_size from the header,
// keys set). Read-only: nothing is written, the driver completes the session at its mount.
#define DCS_JR_NONE        0  // not a protected session: the header's boundary
#define DCS_JR_EXACT       1  // journal empty: the header's boundary is exact
#define DCS_JR_RECOVERED   2  // tmp_size taken from the newest committed record
#define DCS_JR_PENDING     3  // as RECOVERED, plus a pending block rebuilt in pend_img (*lost: torn units, zeros)
#define DCS_JR_QUARANTINE  4  // as RECOVERED, but the pending block could not be rebuilt: I/O to it fails
#define DCS_JR_NO_JOURNAL  5  // unusable or unreadable journal, or no memory: the header's boundary (as before the journal)
#define DCS_JR_CONFLICT   -1  // the journal contradicts the header: do not mount (the driver refuses it too)
// from_bak: header is the backup header (dc_header_recover_efi returned DCS_HR_BACKUP)
int dc_journal_recover(mount_inf *mount, dc_header *header, int from_bak, u32 *lost);

// A damaged primary header (dc_decrypt_header_ex: signature right, CRC wrong), repaired
// in memory as the driver does (dc_safe_efi.c). block_io: the partition's EFI_BLOCK_IO_PROTOCOL.
#define DCS_HR_DAMAGED   0  // not repairable: do not mount (the password was right - not a password error)
#define DCS_HR_REPAIRED  1  // the torn save's tmp_size restored in header
#define DCS_HR_BACKUP    2  // header holds the backup header's fields (the primary's salt kept)
int dc_header_recover_efi(void *block_io, u64 part_sectors, u32 bps, dc_header *header, int hdr_size, dc_pass *password);

#endif