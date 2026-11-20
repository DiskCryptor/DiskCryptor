/*
    * DCrypt volume_lib - reading the power-loss journal ($dclog$)
    * Copyright (c) 2026 David Xanatos <info@diskcryptor.org>
    *
    * SPDX-License-Identifier: MIT
*/
#ifndef _JOURNAL_H_
#define _JOURNAL_H_

#include "defines.h"
#include "volume_header.h"
#include "dc_dev.h"
#include "dc_status.h"

/*
 * The read-only half of a power-loss protected transcryption session's journal: validating
 * the log header, reading both record / commit pairs, picking the record that decides the
 * boundary, and the boundary hints for a torn header. Raw reads and CRC32, no crypto, no
 * writes, no state kept between calls.
 *
 * Shared by the driver (driver/safe_log.c), which adds the writing side, and the boot loader
 * (DCS), which needs the recovered boundary to read the boot volume before the driver runs.
 * Layout and record format: volume_header.h.
 */

/* the largest data area a journal may declare: one transcryption block (the driver's
   ENC_BLOCK_SIZE, asserted there) */
#define DC_LOG_BLOCK_LIMIT (8 * 1024 * 1024)
/* FF_SAFE_FAST: one 64-bit checksum per DC_LOG_SUM_UNIT bytes; the table of a full block */
#define DC_LOG_SUM_UNIT    512
#define DC_LOG_SUM_BYTES   ((DC_LOG_BLOCK_LIMIT / DC_LOG_SUM_UNIT) * 8)
/* scratch buffer the calls below take: the log header, or one record / commit sector (a
   journal sector is at most this large) */
#define DC_LOG_SCRATCH     (DC_LOG_HEAD_SIZE * 2)

/* journal layout from its offset, see volume_header.h */
#define DC_LOG_COM_A(_j)   ((_j)->log_off + DC_LOG_HEAD_SIZE)
#define DC_LOG_REC_A(_j)   (DC_LOG_COM_A(_j) + (_j)->sec)
#define DC_LOG_DATA(_j)    (DC_LOG_REC_A(_j) + (_j)->sec)
#define DC_LOG_REC_B(_j)   (DC_LOG_DATA(_j) + (_j)->block_max)
#define DC_LOG_COM_B(_j)   (DC_LOG_REC_B(_j) + (_j)->sec)

typedef struct _dc_journal {
	/* dc_journal_open: the validated log header */
	u64        log_off;      /* partition offset of $dclog$ */
	u32        log_len;      /* DC_LOG_HEAD_SIZE + 4 * sec + block_max */
	u32        sec;          /* record / commit sector size */
	u32        block_max;    /* data area size */
	u64        log_id;
	int        fast;         /* the data area is a checksum table (FF_SAFE_FAST journal) */

	/* dc_journal_scan: [0] pair A (odd seq), [1] pair B (even seq) */
	dc_log_rec rec[2];
	int        basic[2];     /* magic, log_id, crc, seq != 0 and the pair's seq parity */
	int        valid[2];     /* basic, sane bounds, bound to the header mounted from */
	int        committed[2]; /* LR_SKIP, or a commit of the same seq */
	u64        max_seq;      /* highest seq of a basic record or commit */
	int        any_basic;    /* a basic record or commit exists: the record sectors are dirty */

	/* dc_journal_pick */
	int        newest;       /* index of the record that decides, -1: none (the header is exact) */
	int        pending;      /* it is LR_STEP / LR_SUM and not committed; its data area, checked
	                            against data_crc, is in the caller's data buffer */
	u64        boundary;     /* its end in its direction (dc_log_rec_end). For a pending record
	                            this is the boundary AFTER the block is completed: until then
	                            [offs, offs + size) is mixed old / new content. A read-only
	                            reader must read the block from the post-image (LR_STEP), resolve
	                            it unit by unit with the checksums (LR_SUM) or refuse it - never
	                            route it by this boundary alone */
} dc_journal;

/*
 * Units: every offset and length here is in BYTES from the partition start, as on disk,
 * including dc_dev.head_len (the header area, head_len rounded up to bps) and j->boundary
 * (always bps aligned for a valid record). A caller that keeps its layout in sectors converts.
 */

/* record arithmetic, shared with the writing side */
u64 dc_log_rec_end(u32 dir, u64 offs, u32 size);           /* LR_DEC: offs, else offs + size */
u32 dc_log_data_len(u32 sec, u32 type, u32 size);          /* data area bytes a record uses */
u32 dc_log_head_crc(dc_log_head *h);
u32 dc_log_rec_crc(dc_log_rec *r);
u32 dc_log_com_crc(dc_log_commit *c);
/* FF_SAFE_FAST: the checksum of one DC_LOG_SUM_UNIT unit (XXH64, seed 0) */
u64 dc_log_sum64(const u8 *unit);
/* the data area size of a checksum journal of sector size sec */
#define DC_LOG_FAST_BLOCK(_sec) ((DC_LOG_SUM_BYTES + (_sec) - 1) / (_sec) * (_sec))

/*
 * Read and validate the log header at hcopy->log_offset. min_off: the lowest offset the
 * journal may start at (the header area length; 0: not checked). scratch: DC_LOG_SCRATCH
 * bytes. The caller decides whether hcopy is a protected session (FF_SAFE_TRANSCRYPT etc.).
 * ST_OK: j's log header fields are set. ST_INV_VOLUME: no usable journal. Else a read error.
 */
int dc_journal_open(dc_dev *dev, dc_rw_fn rw, const dc_header *hcopy, u64 min_off, u8 *scratch, dc_journal *j);

/*
 * After dc_journal_open: read both commit / record pairs and classify them. from_bak: hcopy
 * is the backup header (the records bind to bak_ok / bak_try, else hdr_ok / hdr_try).
 * dev->head_len is the header area length in bytes (records never touch it, nor the backup
 * header area with VF_BACKUP_HEADER). ST_LOG_CONFLICT: the journal kind does not match the
 * header's FF_SAFE_FAST, or a record bound to this header is of the other kind. Else ST_OK
 * or a read error.
 */
int dc_journal_scan(dc_dev *dev, dc_rw_fn rw, const dc_header *hcopy, int from_bak, u8 *scratch, dc_journal *j);

/*
 * After dc_journal_scan: the newest valid record decides. A pending LR_STEP / LR_SUM needs its
 * data area intact (data_crc); a torn one never was durable, so the record is dropped and the
 * previous one decides. data: j->block_max bytes, or NULL - then ST_SMALL_BUFF is returned,
 * j unchanged, when the data area has to be read. ST_LOG_CONFLICT: the newest record and its
 * predecessor do not chain. Else ST_OK (j->newest, j->pending, j->boundary set) or a read error.
 */
int dc_journal_pick(dc_dev *dev, dc_rw_fn rw, dc_journal *j, u8 *data);

/*
 * The boundary values the journal of hcopy's session holds (start and end of both records and
 * the header values they carry): candidates for the tmp_size of a torn primary header. Only
 * hints; dc_header_repair_tmp tests each against the CRC. Returns the number stored in out
 * (at most max).
 */
int dc_journal_tmp_hints(dc_dev *dev, dc_rw_fn rw, const dc_header *hcopy, u64 *out, int max);

#endif
