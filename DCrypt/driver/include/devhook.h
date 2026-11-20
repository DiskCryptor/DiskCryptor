#ifndef _DEVHOOK_
#define _DEVHOOK_

#include "defines.h"
#include "xts_fast.h"
#include "driver.h"
#include "data_wipe.h"
#include "alloc_bitmap.h"
#include "dc_dev.h"

#ifdef DC_CONCURRENT_TRANSCRYPT
/*
 * Concurrent transcryption state structure.
 * Used to track the currently active transcryption block so that
 * concurrent I/O can detect overlap and wait if necessary.
 *
 * Synchronization protocol:
 * 1. I/O acquires range_lock, checks active block, increments pending_io_count,
 *    snapshots hook->tmp_size, releases range_lock, proceeds with I/O
 * 2. When I/O completes, decrements pending_io_count, signals io_done_event if zero
 * 3. Transcryption waits for pending_io_count == 0 before starting a new block,
 *    so no I/O uses a stale tmp_size
 */
typedef struct _transcrypt_state {
    KSPIN_LOCK       range_lock;       // Protects active range and pending count
    KEVENT           block_complete;   // Signaled when block finishes (or idle)
    KEVENT           io_done_event;    // Signaled when pending_io_count reaches 0
    KEVENT           idle_event;       // Signaled when transcryption is not in progress
    volatile LONG64  active_start;     // -1 when idle, otherwise start of active block
    volatile LONG64  active_end;       // End of active block
    volatile LONG    pending_io_count; // Count of I/Os using current tmp_size snapshot
    volatile LONG    in_progress;      // Non-zero when transcryption step is active
    volatile LONG    slot_waiters;     // dc_acquire_step_slot callers waiting; steps yield to them
    /* bad-sector handling of dc_transcrypt_step. Used only by the holder of the step
     * slot (in_progress), reset by dc_transcrypt_init. */
    u64              rd_retry_offs;    // block whose read failed in the previous step(s)
    u32              rd_retry_cnt;     // failed reads of that block so far (0 = none)
    /* data requests admitted WITHOUT F_SYNC that have not completed yet (raw or encrypted
     * read/write, data-changing IOCTLs of a plain volume). Counted before the flags are read,
     * uncounted on completion (or at once on seeing F_SYNC). A transcryption start publishes
     * F_SYNC and waits for 0 (dc_drain_untracked_io), so no request dispatched before F_SYNC is
     * in flight when the first range is locked. Never reset: in-flight requests still decrement. */
    volatile LONG    untracked_io;
    /* unused (a block's bad-sector map is kept behind tmp_buff, DC_STEP_BAD_MAP in enc_dec.c);
     * reserved so that dev_hook keeps its layout - untracked_io above took its first word */
    u32              bad_map_unused[(1280 * 1024) / 512 / 32 - 1];
    /* S_INIT_ENC wiped the originals and both its initial header save and the copy-back
     * failed: the session runs in redirect mode without a header on disk. Every save writes
     * the full header (SYNC_STEP_INIT) until one succeeds; encryption steps are refused until
     * then. Reset by dc_transcrypt_init. */
    volatile LONG    init_hdr_pending;
    /* the session was installed from the BACKUP header (MF_USE_BACKUP mount / unlock): the
     * next save writes the full primary header (HF_DEFAULT) once - a base-only write would put
     * the backup's salt over the primary's key slots, which are bound to its own salt.
     * Set by mount after dc_transcrypt_init, which resets it. */
    volatile LONG    full_hdr_once;
    /* the backup header could not be decrypted when the session was installed (boot keys /
     * automount match by salt, or a backup under another password): bak_salt / bak_key are the
     * primary's. The next save writes the backup as a full copy of the primary - a
     * dc_update_backup would re-seal its base under the primary salt over its own key slots,
     * whose passwords then no longer work. Set by dc_install_session after dc_transcrypt_init. */
    volatile LONG    bak_clone_once;
} transcrypt_state;

/* untracked_io was carved out of bad_map_unused - the layout must not change */
C_ASSERT(sizeof(((transcrypt_state*)0)->untracked_io) +
	sizeof(((transcrypt_state*)0)->bad_map_unused) == ((1280 * 1024) / 512 / 32) * sizeof(u32));
C_ASSERT(FIELD_OFFSET(transcrypt_state, untracked_io) ==
	FIELD_OFFSET(transcrypt_state, rd_retry_cnt) + sizeof(((transcrypt_state*)0)->rd_retry_cnt));
C_ASSERT(FIELD_OFFSET(transcrypt_state, bad_map_unused) + sizeof(((transcrypt_state*)0)->bad_map_unused) ==
	FIELD_OFFSET(transcrypt_state, init_hdr_pending));
#endif /* DC_CONCURRENT_TRANSCRYPT */

typedef enum _dc_pnp_state {

    NotStarted = 0,         // Not started yet
    Started,                // Device has received the START_DEVICE IRP
    Stopped,                // Device has received the STOP_DEVICE IRP
	SurpriseRemove,         // Device has received the SURPRISE_REMOVAL IRP
    Deleted                 // Device has received the REMOVE_DEVICE IRP

} dc_pnp_state;


typedef align16 struct _dev_hook
{
	u32            ext_type;		// device extention type
	PDEVICE_OBJECT orig_dev;
	PDEVICE_OBJECT hook_dev;
	PDEVICE_OBJECT pdo_dev;
	LIST_ENTRY     hooks_list;
	IO_REMOVE_LOCK remove_lock;

	wchar_t        dev_name[MAX_DEVICE + 1];

	xts_key       *dsk_key;			// volume encryption key

	u32            flags;			// device flags
	u32            mnt_flags;		// mount flags
	u32            disk_id;			// unique volume id

	HANDLE         wrk_thread_id;	// worker thread id
	/* storage file generation, incremented after every create / rename / delete of
	 * $dcsys$ / $dcbak$; the minifilter then re-queries its cached storage file IDs
	 * (mf_get_storage_ids) */
	volatile LONG  stor_gen;

	KEVENT         paging_count_event;
	LONG           paging_count;
	
	ULONG          chg_count;		// media changes counter
	ULONG          mnt_chg_count;	// media change count of the mounted medium (removable)
	/* identity of the mounted removable medium (device_io.c io_same_medium), under id_lock */
	KSPIN_LOCK     id_lock;
	u8             mnt_id[64];		// salt of the DC header the volume was mounted from / DC last wrote
	u64            mnt_id_off;		// disk offset of that header (0, or the backup header)
	LONG           mnt_id_valid;	// mnt_id holds a DC header salt
	u32            id_crc0[2];		// crc32 of sector 0 as a DC write left it: [0] last write, [1] a failed one since
	LONG           id_crc0_ok[2];
	u32            id_crcoff[2];	// the same for the sector at mnt_id_off (mnt_id_off != 0)
	LONG           id_crcoff_ok[2];
	u32            chg_mount;		// mount changes counter
	
	volatile long     io_depth;		// depth of the I/O queue
	volatile LONG     rl_waiters;	// remove-lock holders blocked on busy_lock (dc_wait_busy_lock_rl)
	volatile LONG     rl_timeouts;	// counted waiters that left by timeout (dc_rl_drained)
	volatile LONGLONG expect_off;	// expected next I/O offset

	u32            max_chunk;
	int            mnt_probed;
	int            mnt_probe_cnt;

	crypt_info     crypt;
	wipe_ctx       wp_ctx;

	u8            *tmp_buff;
	xts_key       *tmp_key;

	xts_key       *hdr_key;
	dc_header     *tmp_header;
	xts_key       *bak_key;
	u8            *bak_salt;

	u64            dsk_size;		// full device size
	u64            use_size;		// user available part size
	u32            bps;				// bytes per sector

	ULONGLONG      tmp_size; 
	
	ULONGLONG      stor_off;		// redirection area offset (0 if redirection is not used), contains partition begin sectors
	ULONG          stor_len;		// redirection area size
	ULONG          head_len;		// DC header length (offset to data)
	ULONGLONG      tail_off;		// redirection area 2 offset (tail_off = stor_off + stor_len - tail_len), contains partition end sectors if backup header is used
	ULONG          tail_len;		// DC backup header length (may transiently differ from head_len)

	LONGLONG       pending_shrink_sectors; // pending shrink target from ShrinkPrepare (volatile, -1 = none)

	KMUTEX         busy_lock;

#ifdef DC_CONCURRENT_TRANSCRYPT
	transcrypt_state trans;			// concurrent transcryption state
#else
	u32            sync_init_type;
	int            sync_init_status;// sync mode init status

	LIST_ENTRY     sync_req_queue;
	LIST_ENTRY     sync_irp_queue;
	KSPIN_LOCK     sync_req_lock;
	KEVENT         sync_req_event;
	KEVENT         sync_enter_event;
#endif

	dc_alloc_bitmap *alloc_bitmap;	// allocation bitmap for skip unused sectors

	/* lock on hibernate, see dc_lock_volume / dc_mount_device; busy_lock */
	u32            lock_flags;		// F_SYNC | F_REENCRYPT of the session torn down by the lock, DC_LOCK_SAVE_FAILED
	u8             lock_kcv[32];	// key check value of dsk_key (zero sector encrypted at offset 0)
	volatile LONG  lock_failed;		// S4 lock attempt failed, keys still live (read by the dump policy)
	u32            lock_seq;		// incremented by every lock: an unlock that probed the header without busy_lock re-checks it

	dc_pnp_state   pnp_state;
	dc_pnp_state   pnp_prev_state;

} dev_hook;

dev_hook *dc_find_hook(wchar_t *dev_name);

void dc_insert_hook(dev_hook *hook);
void dc_remove_hook(dev_hook *hook);

void dc_reference_hook(dev_hook *hook);
void dc_deref_hook(dev_hook *hook);

dev_hook *dc_first_hook();
dev_hook *dc_next_hook(dev_hook *hook);

#define dc_set_pnp_state(_hook_, _state_) \
	(_hook_)->pnp_prev_state = (_hook_)->pnp_state; \
	(_hook_)->pnp_state = (_state_);

#define dc_restore_pnp_state(_hook_) \
	(_hook_)->pnp_state = (_hook_)->pnp_prev_state;

/*
 * Atomic updates of hook->flags.
 * A transcryption step runs without busy_lock and changes flags (F_PLAIN_IO,
 * F_HEAD_BACKUP) while unmount, power and IOCTL paths change other bits of the
 * same word. A plain read-modify-write on either side can silently undo the
 * other's change, so every runtime writer that can overlap a step uses these.
 */
#define dc_hook_set_flags(_hook_, _f_) \
	InterlockedOr((LONG volatile*)&(_hook_)->flags, (LONG)(_f_))

#define dc_hook_clear_flags(_hook_, _f_) \
	InterlockedAnd((LONG volatile*)&(_hook_)->flags, ~(LONG)(_f_))

/*
 * The "unmount / erase keys on hibernation" option (F_NO_HIBER) cannot work on the volume
 * that boots the system or receives the hibernation image or crash dump: the image is
 * written onto that very volume, so erasing its keys first writes it unencrypted (plaintext
 * RAM inside the encrypted volume, failed resume) or, with other mounts present, bugchecks.
 */
#define DC_NO_HIBER_FORBIDDEN(_hook_) \
	( ((_hook_)->flags & (F_SYSTEM | F_HIBERNATE | F_CRASHDUMP)) || \
	  ((_hook_)->pdo_dev != NULL && ((_hook_)->pdo_dev->Flags & DO_SYSTEM_BOOT_PARTITION)) )

/*
 * A session whose initial header is not on disk yet (init_hdr_pending) is never locked -
 * the unlock needs that header. Part of both lock predicates so the dump policy counts such
 * a volume as live ahead of time too. A plain LONG read: safe at HIGH_LEVEL.
 */
#ifdef DC_CONCURRENT_TRANSCRYPT
#define DC_INIT_HDR_PENDING(_hook_) ((_hook_)->trans.init_hdr_pending != 0)
#else
#define DC_INIT_HDR_PENDING(_hook_) 0
#endif

/* What dc_lock_volume refuses besides the tests in the predicates below: a volume being
 * formatted. Both predicates exclude it, so the policy never expects a lock that then fails.
 * Flags only - the ahead-of-time evaluation runs without busy_lock, where dsk_key may be freed
 * by a concurrent unmount; a missing data key is refused by dc_lock_volume, fail closed. */
#define DC_LOCK_POSSIBLE(_hook_) \
	( !((_hook_)->flags & F_FORMATTING) )

/*
 * The ONE predicate for "this volume's keys are erased at S4" - used both by the S4
 * erase (misc_irp.c) and by the hibernation dump policy (dump_helpers.c), so the two
 * never disagree (a lingering F_NO_HIBER on a forbidden volume stays counted).
 * Only reads flags and the nonpaged PDO flags: safe at HIGH_LEVEL (dump time).
 * Never a volume with a paging file - it is not locked (paging reads after the resume
 * would fail -> KERNEL_DATA_INPAGE_ERROR), so it stays counted by the policy.
 */
#define DC_WILL_HIBER_ERASE(_hook_) \
	( ((_hook_)->flags & (F_ENABLED | F_NO_HIBER)) == (F_ENABLED | F_NO_HIBER) && !DC_NO_HIBER_FORBIDDEN(_hook_) && \
	  (_hook_)->paging_count == 0 && !DC_INIT_HDR_PENDING(_hook_) && DC_LOCK_POSSIBLE(_hook_) )

/*
 * Lock on hibernate: the volume is locked - keys erased, FS still mounted,
 * every read/write fails with STATUS_FVE_LOCKED_VOLUME until dc_mount_device unlocks it
 * in place or dc_process_unmount dismounts it. F_HIBER_ERASE (= F_LOCKED) is set together
 * with F_DISABLE and only on F_ENABLED volumes; unmount clears it (F_CLEAR_ON_UNMOUNT).
 */
#define DC_HOOK_LOCKED(_hook_) DC_IS_LOCKED((_hook_)->flags)

/* the status a locked volume fails read/write IRPs with (ntstatus.h, older WDKs lack it) */
#ifndef STATUS_FVE_LOCKED_VOLUME
#define STATUS_FVE_LOCKED_VOLUME ((NTSTATUS)0xC0210000L)
#endif

/*
 * A volume that may be locked at S4 without the no-hibernation option, because the
 * hibernation image could not be protected (a critical action sends no QUERY_POWER, or the
 * power manager ignored the veto). Never the image / dump / boot volume (its keys encrypt the
 * image), never a volume with a paging file (paging I/O must not fail before the resume
 * unlock - the dump policy keeps counting it and refuses the image).
 */
#define DC_HIBER_LOCKABLE(_hook_) \
	( ((_hook_)->flags & (F_ENABLED | F_HIBER_ERASE)) == F_ENABLED && !DC_NO_HIBER_FORBIDDEN(_hook_) && \
	  (_hook_)->paging_count == 0 && !DC_INIT_HDR_PENDING(_hook_) && DC_LOCK_POSSIBLE(_hook_) )

/*
 * lock_flags bit - the transcryption state save right before the lock failed, so
 * the on-disk header may carry an older boundary than the in-memory tmp_size. Not an F_* bit
 * that lock_flags takes from hook->flags (F_SYNC | F_REENCRYPT).
 */
#define DC_LOCK_SAVE_FAILED 0x80000000

void dc_init_devhook();



#endif