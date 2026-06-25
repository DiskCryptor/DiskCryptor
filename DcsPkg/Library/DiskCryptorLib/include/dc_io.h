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

#endif