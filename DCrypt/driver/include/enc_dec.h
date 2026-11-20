#ifndef _ENC_DEC_
#define _ENC_DEC_

/* block size of an encryption with wipe passes: each pass rewrites the locked block (Gutmann: 35
   times), so a short block keeps the I/O waiting for it short. Also the session's wipe buffer size. */
#define DC_WIPE_BLOCK      (1280 * 1024)

#define SYNC_STEP_UPDATE   0
#define SYNC_STEP_FINISH   1
#define SYNC_STEP_INIT     2

/* Encryption start/stop functions - used by both paths */
int  dc_encrypt_start(wchar_t *dev_name, dc_pass *password, crypt_info *crypt, u32 flags, BOOLEAN confirmed, ULONG *interrupt_cmd);
int  dc_decrypt_start(wchar_t *dev_name, dc_pass *password, crypt_info *crypt, ULONG *interrupt_cmd);
int  dc_reencrypt_start(wchar_t *dev_name, dc_pass *password, crypt_info *crypt, ULONG *interrupt_cmd);
int  dc_update_layout(wchar_t *dev_name, dc_pass *password, crypt_info *crypt, u32 flags, ULONG *interrupt_cmd);
void dc_sync_all_encs();

#ifdef DC_CONCURRENT_TRANSCRYPT
/* Concurrent transcryption functions */
int  dc_transcrypt_init(dev_hook *hook, u32 type);
int  dc_encrypt_step(wchar_t *dev_name);
int  dc_decrypt_step(wchar_t *dev_name);
int  dc_sync_step(wchar_t *dev_name);
int  dc_save_enc_state(dev_hook *hook, u32 step); /* ST_OK or the header write error */
void dc_wait_for_transcrypt(dev_hook *hook);
/* hold the step slot (busy_lock held, PASSIVE_LEVEL): no step runs until released */
void dc_acquire_step_slot(dev_hook *hook);
void dc_release_step_slot(dev_hook *hook);
void dc_transcrypt_cleanup(dev_hook *hook);
/* undo a session whose initial header is not on disk, when it ends (unmount / lock) */
int  dc_init_pending_undo(dev_hook *hook);
/* FF_SAFE_FAST: complete the pending block of the journal recovery (step slot held) */
int  dc_safe_resolve_pending(dev_hook *hook);
#else
/* Sync thread functions */
int  dc_enable_sync_mode(dev_hook *hook, int type);
int  dc_send_sync_packet(wchar_t *dev_name, u32 type, void *param);

typedef struct _sync_packet {
	LIST_ENTRY entry_list;
	u32        type;
	PIRP       irp;
	void      *param;
	KEVENT     sync_event;
	int        status;

} sync_packet;

#define S_OP_ENC_BLOCK  0 // encrypt the next few hundred sectors
#define S_OP_DEC_BLOCK  1 // decrypt the next few hundred sectors
#define S_OP_SYNC       2 // update and save header to disk
#define S_OP_FINALIZE   3
#endif /* !DC_CONCURRENT_TRANSCRYPT */

/* Init type constants - used by both paths */
#define S_INIT_NONE       0
#define S_INIT_ENC        1
#define S_INIT_DEC        2
#define S_CONTINUE_ENC    3
#define S_INIT_RE_ENC     4
#define S_CONTINUE_RE_ENC 5
#define S_UPDATE_LAYOUT   6


#endif