#ifndef _DEVHOOK_
#define _DEVHOOK_

#include "defines.h"
#ifdef _M_ARM64
#include "xts_small.h"
#else
#include "xts_fast.h"
#endif
#include "driver.h"
#include "data_wipe.h"
#include "alloc_bitmap.h"

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
 * 3. Transcryption waits for pending_io_count == 0 before starting a new block
 * 4. This ensures no I/O is using a stale tmp_size while transcryption processes
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
} transcrypt_state;
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

	KEVENT         paging_count_event;
	LONG           paging_count;
	
	ULONG          chg_count;		// media changes counter
	u32            chg_mount;		// mount changes counter
	
	volatile long     io_depth;		// depth of the I/O queue
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

void dc_init_devhook();



#endif