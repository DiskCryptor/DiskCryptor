#ifndef _VOLUME_HEADER_H_
#define _VOLUME_HEADER_H_

#define DC_VOLUME_SIGN    0x50524344        // volume header signature, text value 'DCRP'

#define HEADER_SALT_SIZE  64                // salt size in header = 512 bits
#define MAX_KEY_SIZE      (32*3)            // maximum actual key size for cascade cipher = 768 bits
#define PKCS_DERIVE_MAX   (MAX_KEY_SIZE*2)  // maximum key size into which password is expanded = 192 bytes
#define DISKKEY_SIZE	  256               // number of key bytes stored in header (taken with reserve)

#define SECTOR_SIZE       512
#define MAX_SECTOR_SIZE   4096
#define CD_SECTOR_SIZE    2048

#define MIN_PASSWORD      1	                // Minimum password length
#define MAX_PASSWORD      128               // Maximum password length

#define KEY_SLOT_COUNT    4                 // default number of key slots in v2 header
#define KEY_SLOT_MAX      100               // a reasonable maximum number of key slots, hard limit is 255
#define ALL_KEY_SLOTS     (-KEY_SLOT_MAX)

#define SLOT_LABEL_LEN    20

//                        1                 // 0.5 - 0.9 header version
#define DC_HDR_VERSION    2					// 1.0 - 1.4.1 header version
#define DC_HDR_VERSION_2  3					// 2.0 + header version

#define FF_KEY_SLOTS      0x01              // header supports key slots V1
#define FF_SAFE_TRANSCRYPT 0x02             // power-loss protected (journaled) transcryption session, log at log_offset (valid with VF_TMP_MODE)
#define FF_SAFE_FAST      0x04              // with FF_SAFE_TRANSCRYPT: the journal records a checksum per 512-byte unit of each block (LR_SUM), not its post-image

#define VF_NONE           0x00
#define VF_TMP_MODE       0x01              // temporary encryption mode
#define VF_REENCRYPT      0x02              // volume re-encryption in progress
#define VF_STORAGE_FILE   0x04              // redirected area are placed in file
#define VF_NO_REDIR       0x08              // redirection area is not present - iso/file container
#define VF_EXTENDED       0x10              // this volume placed on extended partition (used only by MBR bootloader)
#define VF_BACKUP_HEADER  0x20              // backup header at partition end
#define VF_NO_HIBER       0x40				// this volume must be unmounted before hibernation

#pragma pack (push, 1)

typedef struct _dc_pass {
	int            size;                    // password length in bytes without terminating null
	wchar_t        pass[MAX_PASSWORD];      // password in UTF16-LE encoding
	int            kdf;                     // password cost factor, 0 for legacy PBKDF2
	int            slot;					// s = 0 header key; s > 0 - keyslot index (1-based); s < 0 try all slots and hreader up to abs(n)
	unsigned long  flags;
	char           label[SLOT_LABEL_LEN];
	char           reserved[92];

} dc_pass; //384

#define PF_NONE           0x00
#define PF_KEYFILE_MIXED  0x01

static_assert(sizeof(wchar_t)* MAX_PASSWORD >= DISKKEY_SIZE, "Password field in dc_pass to short");

typedef struct _dc_header {
	unsigned char  salt[HEADER_SALT_SIZE];   // salt	64 byte - 512 bits
	unsigned long  sign;                    // signature 'DCRP'
	unsigned long  hdr_crc;                 // crc32 of decrypted volume header
	unsigned short version;                 // volume format version
	unsigned long  flags;                   // volume flags
	unsigned long  disk_id;                 // unique volume identifier
	int            alg_1;                   // crypt algo 1
	unsigned char  key_1[DISKKEY_SIZE];     // crypt key 1
	int            alg_2;                   // crypt algo 2
	unsigned char  key_2[DISKKEY_SIZE];     // crypt key 2
	// 602

	union {
		unsigned __int64 stor_off;          // redirection area offset
		unsigned __int64 data_off;          // volume data offset, if redirection area is not used
	};
	union {
		unsigned char deprecated[8];        // use_size in 0.5 - 0.9
		struct {							// 2.0 +
			unsigned long stor_len;         // redirection area size in bytes
			unsigned long head_len;         // header size in bytes
		};
	};
	unsigned __int64 tmp_size;              // temporary part size - encryption/decryption position offset
	unsigned char  tmp_wp_mode;             // data wipe mode
	// 627

	// v2
	char           footer_cnt;				// footer length in blocks of 16 bytes, reserved for future use, 0 default = 1k header base
											// > 0 reduce base size, < 0 increase base size up to 1k - (-128 * 16) = 3k
											// footer is excluded form v2 crc calculation, footer may be plaintext
	unsigned long  feature_flags;			// feature flags bitmask (FF_*) for features in v2 and header
	unsigned short ext_hdr_off;             // extended header offset in bytes from the header start, 0 if not used

	// feature_flags & FF_KEY_SLOTS
	unsigned char  head_kdf;                // Header Key Derivation Function, 0 for legacy PBKDF2, 1-10 for Argon2id
	// key slots
	         //    key_slot_off     == DC_BASE_SIZE
	unsigned short slot_area_len;           // keyslot area size (must be multiple of xts block size)
	unsigned char  key_slot_count;			// number of key slots available
             //    key_slot_size    == slot_area_len / key_slot_count
	// embedded slot info
	         //    slot_info_off    == key_slot_off + slot_area_len
	unsigned short slot_info_size;			// single keyslot descriptor size
	         //    slot_info_len    == key_slot_count * slot_info_size	
	// 640

	// feature_flags & FF_SAFE_TRANSCRYPT, valid while VF_TMP_MODE
	unsigned __int64 log_offset;            // byte offset of the $dclog$ journal from the partition start, 0 = none
	// 648

	unsigned char  reserved[376];           // reserved, zeros for future use
	// 1024

	unsigned char  space[1024];             // reserved for key slots
	// 2048

} dc_header;

//const dc_header_test = FIELD_OFFSET(dc_header, ext_hdr_off);

#define IS_INVALID_SECTOR_SIZE(_s) ( (_s) % SECTOR_SIZE )

#define ROUND_TO_FULL_SECTORS(len, bps) ( ( ((len) + (bps) - 1) / (bps) ) * (bps) )

#define DC_BASE_SIZE         (1024)
#define DC_AREA_SIZE         (2 * 1024)
#define DC_HEAD_SPACE        (DC_AREA_SIZE - DC_BASE_SIZE)
#define DC_CRC_AREA_SIZE_1   ((DC_AREA_SIZE - HEADER_SALT_SIZE) - 8)
#define DC_CRC_AREA_SIZE_2   ((DC_BASE_SIZE - HEADER_SALT_SIZE) - 8)
#define DC_AREA_MAX_SIZE     (32 * 1024 * 1024) // hard limit is 4GB
#define DC_AREA_MAX_SIZE_UI  (4 * 1024 * 1024)



// Keyslot types and layout in the reserved space of the header

#define DC_SLOT_TYPE_0  0					// 0 - XOR Wrap

#define SF_ACTIVE         0x01              // active
#define SF_DISABLED       0x02              // disabled
#define SF_CORRUPT        0x04              // corrupt
//#define SF_TPM_SLOT       0x10              // dedicated to TPM
//#define SF_RECOVERY_SLOR  0x20              //

typedef struct _dc_slot_info {
	unsigned long  crc;                     // crc32 of slot ciphertext + descriptor
	unsigned long  flags;                   // slot flags (ACTIVE, etc.)
	unsigned short type;                    // slot type
	char           slot_name[SLOT_LABEL_LEN]; // slot name in UTF-8 encoding, zero padded, not required NUL terminated
	union {
		unsigned char data[2]; // or 34     // format specific data
		struct {
			unsigned char slot_kdf;			// Slot Key Derivation Function, 0 for legacy PBKDF2, 1-10 for Argon2id
		} data_0;
	};
} dc_slot_info;

//const dc_slot_infor_test = sizeof(dc_slot_info);

static_assert(sizeof(dc_slot_info) == 32, "Invalid dc_slot_info size");



// Extended header format and layout in the reserved space of the header

#define MIN_EXT_HDR_SIZE  10 // minimum extended header size to fit crc, size and version fields

#define DC_EXT_VERSION    0                 // extended header version

typedef struct _dc_ext_header {
	unsigned long  crc;                     // crc32 of extended header data (for consistency check only)
	unsigned long  size;                    // size of extended header data in bytes
	unsigned short version;                 // extended header version
	unsigned char  data[0];				    // variant
} dc_ext_header;

//const dc_ext_header_test = sizeof(dc_ext_header);

//static_assert(sizeof(dc_ext_header) == 64, "Invalid dc_ext_header size");


/*
 * Journal of a power-loss protected transcryption session ($dclog$, a contiguous file in
 * the volume, written raw at dc_header.log_offset). Layout (sec = max(bps, 4096)):
 *   [log header: DC_LOG_HEAD_SIZE][commit A][record A][data: block_max][record B][commit B]
 * A record holds the post-image of the block it describes (the block exactly as it is written
 * in place); the commit says the in-place write is durable. Records alternate between pair A
 * (seq odd) and pair B (seq even); a record is only written after the previous one is committed,
 * so one data area is enough.
 */
#define DC_LOG_HEAD_SIZE  4096
#define DC_LOG_VERSION    1

#define DC_LOG_HEAD_MAGIC "DCLOGHD"         // 8 bytes with the terminating zero
#define DC_LOG_REC_MAGIC  "DCLOG1\0"
#define DC_LOG_COM_MAGIC  "DCCOMIT"

#define LR_STEP           1                 // a transcribed block, data area holds its post-image
#define LR_SKIP           2                 // unallocated blocks / the log itself passed without a write (committed with the record)
#define LR_SUM            3                 // a transcribed block (FF_SAFE_FAST): data area holds a 64-bit checksum of each 512-byte unit of its post-image

#define LR_ENC            1                 // encryption: the boundary moves up (offs + size)
#define LR_DEC            2                 // decryption: the boundary moves down (offs)
#define LR_REENC          3                 // re-encryption: up, like LR_ENC

typedef struct _dc_log_head {
	unsigned char    magic[8];              // DC_LOG_HEAD_MAGIC
	unsigned long    version;               // DC_LOG_VERSION
	unsigned long    sec;                   // record / commit sector size
	unsigned __int64 log_id;                // random per session; every record and commit carries it
	unsigned long    disk_id;               // == dc_header.disk_id
	unsigned long    log_len;               // bytes of $dclog$ used: DC_LOG_HEAD_SIZE + 4 * sec + block_max
	unsigned long    block_max;             // size of the data area
	unsigned long    crc;                   // crc32 of this structure with crc = 0
} dc_log_head;

typedef struct _dc_log_rec {
	unsigned char    magic[8];              // DC_LOG_REC_MAGIC
	unsigned __int64 log_id;
	unsigned __int64 seq;                   // 1, 2, ... within the session; pair A for odd, B for even
	unsigned long    type;                  // LR_STEP, LR_SKIP, LR_SUM
	unsigned long    dir;                   // LR_ENC, LR_DEC, LR_REENC
	unsigned __int64 offs;                  // block start, partition offset (as tmp_size)
	unsigned long    size;                  // block / run length, a multiple of the sector size
	unsigned long    data_crc;              // crc32 of the data area used: the post-image (LR_STEP), the checksum table padded to sec (LR_SUM)
	unsigned __int64 tmp_before;            // boundary before this record
	// tmp_size of the last primary / backup DC header write that succeeded (ok) and that was
	// attempted (try; a failed write may still have reached the disk). The recovery accepts a
	// record only when the header it mounts from carries one of the two values of its kind.
	unsigned __int64 hdr_ok, hdr_try;
	unsigned __int64 bak_ok, bak_try;
	unsigned long    rec_crc;               // crc32 of this structure with rec_crc = 0
} dc_log_rec;

typedef struct _dc_log_commit {
	unsigned char    magic[8];              // DC_LOG_COM_MAGIC
	unsigned __int64 log_id;
	unsigned __int64 seq;                   // == the record's
	unsigned long    crc;                   // crc32 of this structure with crc = 0
} dc_log_commit;

#pragma pack (pop)

/* Header V1
*
* 0-626:	 header data		
* 627-2047:  zeros
*
*/


/* Header V2
*
* 0-626:	 header data		
* 640-1023:  optional footer
* 1024-1919: key slots and slot info (up to 4 slots with 32 byte descriptor each)
* 1920-2047: space for extended header
*/

// The default header layout with 4 key slots must fit into DC_AREA_SIZE (2 KiB).

static_assert(sizeof(dc_header) == DC_AREA_SIZE, "Invalid dc_header size");
static_assert(FIELD_OFFSET(dc_header, space) == DC_BASE_SIZE, "Invalid dc_header base layout");
static_assert(FIELD_OFFSET(dc_header, log_offset) == 640, "Invalid dc_header log_offset position");
static_assert(sizeof(dc_log_head) <= DC_LOG_HEAD_SIZE && sizeof(dc_log_rec) <= 512 && sizeof(dc_log_commit) <= 512, "Invalid journal structure size");

// The default header layout with 4 key slots and extended header must fit into DC_AREA_SIZE (2 KiB).
// This maintains compatibility with existing v1 headers and avoids the need for redirection area expansion.
static_assert(DC_BASE_SIZE + KEY_SLOT_COUNT * (PKCS_DERIVE_MAX + sizeof(dc_slot_info)) <= DC_AREA_SIZE, "Invalid default header layout");


#define KDF_SHA512_PKCS5_2	0

#define KDF_ARGON_MIN		1
#define KDF_ARGON_DEFAULT	5
#define KDF_ARGON_MAX		10

#define KDF_NONE	-1
#define KDF_DEFAULT -2
#define KDF_ALL		-3


#endif