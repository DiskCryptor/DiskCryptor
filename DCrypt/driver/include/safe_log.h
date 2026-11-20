#ifndef _SAFE_LOG_H_
#define _SAFE_LOG_H_

/*
 * Power-loss protected (journaled) transcryption. See safe_log.c.
 *
 * One dc_slog per session that runs in safe mode, kept in a side table (not in dev_hook).
 * Lifetime: created at the session start (dc_slog_create) or by the recovery at mount
 * (dc_slog_mount), freed by dc_sync_cleanup. All fields except the quarantine range are used
 * by the step slot holder only (a step, or a state save with the slot held / steps stopped).
 * quar, q_start, q_end are written under hook->trans.range_lock and read under it by the
 * I/O path (dc_slog_quar_range).
 */
typedef struct _dc_slog {
	LIST_ENTRY entry;
	dev_hook  *hook;

	u64        log_off;     /* partition offset of $dclog$ */
	u32        log_len;     /* DC_LOG_HEAD_SIZE + 4 * sec + block_max */
	u32        sec;         /* record / commit sector size */
	u32        block_max;   /* data area size */
	u64        log_id;
	u64        seq;         /* seq of the last record written (0: none in this session) */
	int        dirty;       /* the record sectors may hold records (cleared by dc_slog_empty) */
	int        need_hdr;    /* no record until a save wrote every header (set by the mount) */
	int        dead;        /* read-only mount with an unreadable journal - no step, no save */
	int        fast;        /* FF_SAFE_FAST: blocks are journaled as LR_SUM (checksums), else LR_STEP (post-images) */
	int        lost_rep;    /* FF_SAFE_FAST: a block completed at the mount had torn units (zeros) - the next step reports it */

	/* tmp_size the last primary / backup header write attempted (try) and that succeeded (ok).
	 * Records carry all four; the recovery accepts a record when the header it mounted from
	 * matches one of the pair of that header (a failed write may have reached the disk). */
	u64        hdr_ok, hdr_try;
	u64        bak_ok, bak_try;

	/* pending block or run, never read and transformed again while pending:
	 *  SL_PEND_WRITTEN - its record (LR_STEP / LR_SUM) is durable, the in-place write / commit is
	 *                    not: completed from the post-image in the log (LR_STEP), or unit by unit
	 *                    from the block on the disk and the checksums (LR_SUM, dc_safe_resolve);
	 *  SL_PEND_UNKNOWN - its record write failed (it may still be on the disk), nothing was
	 *                    written in place: released after the record sector is invalidated. */
	int        pend;
	u32        pend_type;   /* LR_STEP, LR_SKIP, LR_SUM */
	u64        pend_seq;
	u64        pend_offs;
	u32        pend_size;
	u32        pend_dir;
	u32        pend_crc;    /* the record's data_crc */

	/* quarantine: a pending block that could not be completed; I/O to the disk range
	 * [q_start, q_end) fails until it is (range_lock) */
	int        quar;
	u64        q_start, q_end;

	u8        *sbuf;        /* one sector (sec bytes) for the record / commit I/O */
} dc_slog;

#define SL_PEND_WRITTEN 1
#define SL_PEND_UNKNOWN 2

/* FF_SAFE_FAST: one 64-bit checksum per SL_SUM_UNIT bytes of a block; the table of a full block */
#define SL_SUM_UNIT       512
#define DC_SLOG_SUM_BYTES ((ENC_BLOCK_SIZE / SL_SUM_UNIT) * 8)

extern volatile LONG dc_slog_quar_cnt; /* number of quarantined blocks, all volumes */

void     dc_slog_init();
dc_slog *dc_slog_get(dev_hook *hook);
void     dc_slog_free(dev_hook *hook);

/* session start: create $dclog$, write its log header and empty record pairs (flushed). fast:
   FF_SAFE_FAST - the data area holds a checksum table (DC_SLOG_SUM_BYTES), not a block */
int      dc_slog_create(dev_hook *hook, u64 hdr_tmp, u64 *log_off, int fast);
/* a failed start: free the state and delete the file (FS context, the volume mounted or not) */
void     dc_slog_discard(dev_hook *hook);

u32      dc_slog_dir(BOOLEAN is_decrypt, BOOLEAN is_reencrypt);
u64      dc_slog_rec_end(u32 dir, u64 offs, u32 size);

/* write a record (LR_STEP: with the post-image in the data area; LR_SUM: with the
 * checksum table, dc_slog_data_len bytes, zero-padded; LR_SKIP: committed in the same write)
 * and flush. On success s->seq is the record's seq. */
int      dc_slog_write_record(dev_hook *hook, dc_slog *s, u32 type, u32 dir, u64 offs, u32 size,
                              const void *data, u64 tmp_before);
/* the commit of record seq, flushed */
int      dc_slog_commit(dev_hook *hook, dc_slog *s, u64 seq);
/* zero the record sector record seq is written to (a failed record write), flushed */
int      dc_slog_invalidate(dev_hook *hook, dc_slog *s, u64 seq);
/* the post-image of the pending block from the data area, checked against its crc */
int      dc_slog_read_post_image(dev_hook *hook, dc_slog *s, void *buff);
/* FF_SAFE_FAST: bytes of the data area a record of this type and block size uses */
u32      dc_slog_data_len(dc_slog *s, u32 type, u32 size);
/* FF_SAFE_FAST: the checksum of one SL_SUM_UNIT unit, of each unit of a block */
u64      dc_slog_sum64(const u8 *unit);
void     dc_slog_sums(const u8 *buff, u32 size, u64 *table);
/* FF_SAFE_FAST: the checksum table of the pending block (DC_SLOG_SUM_BYTES buffer), crc checked */
int      dc_slog_read_sums(dev_hook *hook, dc_slog *s, u64 *table);
/* a flush whose failure counts (a device without a cache that does not implement it: ST_OK) */
int      dc_slog_flush(dev_hook *hook);
/* a pending block in place from its post-image, bad sectors passed on a working device, flushed */
int      dc_slog_write_in_place(dev_hook *hook, void *buff, u32 size, u64 offs);
/* invalidate both records (flushed) */
int      dc_slog_empty(dev_hook *hook, dc_slog *s);
/* zero the whole journal (flushed); buff: a zero-filled scratch buffer of buff_len bytes */
int      dc_slog_zero_all(dev_hook *hook, dc_slog *s, u8 *buff, u32 buff_len);

/* quarantine range of this volume (caller holds hook->trans.range_lock) */
BOOLEAN  dc_slog_quar_range(dev_hook *hook, u64 *q_start, u64 *q_end);

/*
 * Recovery at mount / unlock (before the session is installed): hcopy is the header the volume
 * is mounted from (from_bak: the backup header); other_tmp / other_ok: the tmp_size of the other
 * header, when it was read. *tmp_size in: the boundary the session would use, out: the
 * recovered one. Creates the session's dc_slog. ST_OK also when the header has no usable
 * journal (the session then continues without protection, FF_SAFE_TRANSCRYPT cleared in
 * hcopy). ST_LOG_CONFLICT: the journal contradicts the header, the mount is refused.
 * *recovered: a record was applied (the caller saves the header right after the mount).
 */
int      dc_slog_mount(dev_hook *hook, dc_header *hcopy, BOOLEAN from_bak, u64 other_tmp, BOOLEAN other_ok,
                       u64 *tmp_size, int *recovered);

/* boundary values the journal of hcopy's session holds - tmp_size candidates for a torn header */
int      dc_slog_tmp_hints(dev_hook *hook, dc_header *hcopy, u64 *out, int max);

#endif
