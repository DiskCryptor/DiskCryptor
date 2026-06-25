#ifndef _BOOTLOADER_H_
#define _BOOTLOADER_H_

#define LDR_LT_GET_PASS  1               // entering password needed
#define LDR_LT_EMBED_KEY 2               // use embedded key
#define LDR_LT_MESSAGE   4               // display enter password message
#define LDR_LT_DSP_PASS  8               // display '*'
#define LDR_LT_USE_OSK   16              // use on screen keyboard
//#define LDR_LT_		 32
//#define LDR_LT_		 64
//#define LDR_LT_		 128

#define LDR_ET_MESSAGE      1            // display error message
#define LDR_ET_REBOOT       2            // reboot after 1 second
#define LDR_ET_BOOT_ACTIVE  4            // boot from active partition
#define LDR_ET_EXIT_TO_BIOS 8            // exit to bios
#define LDR_ET_RETRY        16           // retry authentication again
#define LDR_ET_MBR_BOOT     32           // load boot disk MBR
//#define LDR_ET_		    64
//#define LDR_ET_		    128

#define LDR_BT_MBR_BOOT    1             // load boot disk MBR
#define LDR_BT_MBR_FIRST   2             // load first disk MBR
#define LDR_BT_ACTIVE      3             // boot from active partition on boot disk
#define LDR_BT_AP_PASSWORD 4             // boot from first partition with appropriate password
#define LDR_BT_DISK_ID     5             // find partition by disk_id
//#define LDR_BT_MAX       255

#define LDR_KB_QWERTY 0                  // QWERTY keyboard layout
#define LDR_KB_QWERTZ 1                  // QWERTZ keyboard layout
#define LDR_KB_AZERTY 2			         // AZERTY keyboard layout
//#define LDR_KB_MAX  255

#define LDR_OP_EXTERNAL     0x0001       // this option indicate external bootloader usage
#define LDR_OP_EPS_TMO      0x0002       // set time limit for password entering
#define LDR_OP_TMO_STOP     0x0004       // cancel timeout if any key pressed
#define LDR_OP_NOPASS_ERROR 0x0008       // use incorrect password action if no password entered
#define LDR_OP_HW_CRYPTO    0x0010       // use hardware cryptography when possible
#define LDR_OP_SMALL_BOOT   0x0020       // this is a small (aes only) bootloader
#define LDR_OP_DEBUG        0x0040       // enable debug output
#define LDR_OP_AUTH_MSG     0x0080       // show authorizing message
#define LDR_OP_OK_MSG       0x0100       // show password correct message
//#define LDR_OP_           0x0200
//#define LDR_OP_           0x0400
//#define LDR_OP_           0x0800
//#define LDR_OP_           0x1000
//#define LDR_OP_           0x2000
//#define LDR_OP_           0x4000
//#define LDR_OP_           0x8000

#define LDR_CFG_SIGN1 0x1434A669
#define LDR_CFG_SIGN2 0x7269DA46


#define BDB_SIGN1 0x01F53F55
#define BDB_SIGN2 0x9E4361E4
#define BDB_SIGN3 0x55454649

#define BDB_BF_HDR_FOUND		0x01
#define BDB_BF_BOOT_KEYS		0x02
#define BDB_BF_PASS_CACHE 		0x04
#define BDB_BF_NO_UNENCRYPTED	0x08

#define DC_PASS_CACHE_SIZE  8

#pragma pack (push, 1)
#pragma warning(disable:4201)

typedef struct _bd_data {	
	unsigned long  sign1;
	unsigned long  sign2;
	unsigned long  bd_base;	              // boot data block base
	unsigned long  bd_size;               // boot data block size (including stack)
	int     password_size;                // password length in bytes without terminating null
	wchar_t password_data[MAX_PASSWORD];  // password in UTF16-LE encoding

	struct {
		unsigned long  sign3;			  // old int15 handler
		unsigned long  zero;			  // old int13 handler

		// uefi data
		unsigned long flags;

		unsigned __int64 bd_base64;

		int password_kdf;				  // key derivation function for password
		int password_slot;				  // key slot to be used
		int password_flags;               // password flags (e.g., key file usage, etc.)
		char password_reserved[112];

		unsigned long  key_offset; 		  // offset of header keys array from the start of this structure
		unsigned long  key_size;	      // size of single header key entry in bytes
		unsigned long  key_count;	      // number of header keys included in the array

		unsigned long  pass_offset;
		unsigned long  pass_size;
		unsigned long  pass_count;

		//u8              unused[1216];
	};

} bd_data;

typedef struct _header_key {
	unsigned char  guid[16];			  // disk guid
	int			   alg;                   // cipher id
	unsigned char  key[DISKKEY_SIZE];     // RAW key data
	int			   kdf;                   // kdf

	unsigned char  reserved[232];
} header_key; // 512

#pragma warning(default:4201)
#pragma pack (pop)

#endif
