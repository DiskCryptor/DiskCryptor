/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2019-2026
	* DavidXanatos <info@diskcryptor.org>
    *

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 3 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
 * Power-loss protected (journaled) transcryption - the $dclog$ journal.
 *
 * Before a block is written in place, its post-image (the block exactly as it is written)
 * goes to the journal with a record, and is flushed; after the in-place write (flushed) a
 * commit follows (flushed), and only then does the boundary move and the block unlock. So the
 * in-memory boundary that routes user I/O never runs ahead of what the journal describes
 * durably, and a block that may be half written is never read and transformed again: it is
 * completed from its post-image (idempotent - no user write can have reached it).
 *
 * Header binding: every record carries the tmp_size the last primary / backup header write
 * attempted and the one that succeeded; the recovery accepts only records that match the
 * header it mounts from (otherwise the header's boundary is exact: a save writes it exactly).
 *
 * The state lives in a side table, so dev_hook keeps its layout.
 */

#include <ntifs.h>
#include "defines.h"
#include "devhook.h"
#include "misc.h"
#include "debug.h"
#include "misc_mem.h"
#include "device_io.h"
#include "storage.h"
#include "prng.h"
#include "crc32.h"
#include "header_io.h"
#include "journal.h"
#include "safe_log.h"

volatile LONG     dc_slog_quar_cnt = 0;
static LIST_ENTRY dc_slog_list;
static KSPIN_LOCK dc_slog_lock;

/* journal layout, see volume_header.h - volume_lib's (journal.h), so the recovery there reads
 * where this writes (dc_slog has the same log_off / sec / block_max fields) */
#define SL_COM_A(_s)  DC_LOG_COM_A(_s)
#define SL_REC_A(_s)  DC_LOG_REC_A(_s)
#define SL_DATA(_s)   DC_LOG_DATA(_s)
#define SL_REC_B(_s)  DC_LOG_REC_B(_s)
#define SL_COM_B(_s)  DC_LOG_COM_B(_s)
#define SL_REC(_s, _seq) (((_seq) & 1) ? SL_REC_A(_s) : SL_REC_B(_s))
#define SL_COM(_s, _seq) (((_seq) & 1) ? SL_COM_A(_s) : SL_COM_B(_s))

#define SL_BLOCK_LIMIT DC_LOG_BLOCK_LIMIT /* largest data area a journal may declare (journal.h) */
#define SL_BLOCK_SMALL (1280 * 1024)     /* data area of the fallback of dc_slog_create */
#if ENC_BLOCK_SIZE > SL_BLOCK_LIMIT
#error ENC_BLOCK_SIZE exceeds the journal data area limit
#endif
#if SL_BLOCK_LIMIT > ENC_BLOCK_SIZE
#error a post-image of SL_BLOCK_LIMIT would not fit tmp_buff (ENC_BLOCK_SIZE)
#endif
#if SL_SUM_UNIT != DC_LOG_SUM_UNIT || DC_SLOG_SUM_BYTES != DC_LOG_SUM_BYTES
#error the checksum journal layout differs from volume_lib's (journal.h)
#endif

void dc_slog_init()
{
	InitializeListHead(&dc_slog_list);
	KeInitializeSpinLock(&dc_slog_lock);
}

static dc_slog *dc_slog_find_locked(dev_hook *hook)
{
	PLIST_ENTRY e;

	for (e = dc_slog_list.Flink; e != &dc_slog_list; e = e->Flink) {
		dc_slog *s = CONTAINING_RECORD(e, dc_slog, entry);
		if (s->hook == hook) return s;
	}
	return NULL;
}

dc_slog *dc_slog_get(dev_hook *hook)
{
	dc_slog *s;
	KIRQL    irql;

	KeAcquireSpinLock(&dc_slog_lock, &irql);
	s = dc_slog_find_locked(hook);
	KeReleaseSpinLock(&dc_slog_lock, irql);
	return s;
}

static void dc_slog_insert(dc_slog *s)
{
	KIRQL irql;

	KeAcquireSpinLock(&dc_slog_lock, &irql);
	InsertTailList(&dc_slog_list, &s->entry);
	KeReleaseSpinLock(&dc_slog_lock, irql);
}

static void dc_slog_release(dc_slog *s)
{
	if (s->sbuf != NULL) mm_pool_free(s->sbuf);
	mm_pool_free(s);
}

/* the state only - the file stays (a later mount recovers from it). The I/O path reads the
 * quarantine under dc_slog_lock (dc_slog_quar_range), so unlinking under it is enough. */
void dc_slog_free(dev_hook *hook)
{
	dc_slog *s;
	KIRQL    irql;

	KeAcquireSpinLock(&dc_slog_lock, &irql);
	if ( (s = dc_slog_find_locked(hook)) != NULL ) {
		RemoveEntryList(&s->entry);
		if (s->quar) {
			s->quar = 0;
			InterlockedDecrement(&dc_slog_quar_cnt);
		}
	}
	KeReleaseSpinLock(&dc_slog_lock, irql);

	if (s != NULL) {
		DbgMsg("dc_slog_free: dev=%ws\n", hook->dev_name);
		dc_slog_release(s);
	}
}

BOOLEAN dc_slog_quar_range(dev_hook *hook, u64 *q_start, u64 *q_end)
{
	dc_slog *s;
	BOOLEAN  quar = FALSE;
	KIRQL    irql;

	KeAcquireSpinLock(&dc_slog_lock, &irql);
	if ( (s = dc_slog_find_locked(hook)) != NULL && s->quar ) {
		*q_start = s->q_start;
		*q_end   = s->q_end;
		quar     = TRUE;
	}
	KeReleaseSpinLock(&dc_slog_lock, irql);
	return quar;
}

/* the journal order rests on the flushes - a failed one is a failed write. A device
 * without a write cache may not implement the flush at all: that is not a failure. */
int dc_slog_flush(dev_hook *hook)
{
	NTSTATUS status = io_device_request(hook->orig_dev, IRP_MJ_FLUSH_BUFFERS, NULL, 0, 0);

	if (NT_SUCCESS(status) || status == STATUS_INVALID_DEVICE_REQUEST || status == STATUS_NOT_SUPPORTED ||
		status == STATUS_NOT_IMPLEMENTED) {
		return ST_OK;
	}
	DbgMsg("dc_slog_flush: flush failed, status %08x, dev=%ws\n", status, hook->dev_name);
	return ST_IO_ERROR;
}

static int sl_flush(dev_hook *hook)
{
	return dc_slog_flush(hook);
}

/*
 * Write a pending block in place again from its post-image (step retries, recovery), flushed.
 * On a working device a piece that keeps failing is a bad sector and is passed, as the normal
 * step passes it, rather than keeping the block pending forever.
 */
int dc_slog_write_in_place(dev_hook *hook, void *buff, u32 size, u64 offs)
{
	int resl = io_hook_rw(hook, buff, size, offs, 0);

	if (resl == ST_RW_ERR && hook->pnp_state == Started) {
		resl = io_hook_rw_skip_bads(hook, buff, size, offs, 0);
		if (resl == ST_RW_ERR) {
			u32 len   = max(hook->bps, SECTOR_SIZE);
			u8 *probe = (u8*)mm_pool_alloc(len);

			/* bad sectors only on a device that still works (the disk start reads) */
			if (probe != NULL && hook->pnp_state == Started && io_hook_rw(hook, probe, len, 0, 1) == ST_OK) {
				DbgMsg("dc_slog_write_in_place: block at %I64x written with bad sectors, dev=%ws\n", offs, hook->dev_name);
				resl = ST_OK;
			}
			if (probe != NULL) mm_pool_free(probe);
		}
	}
	if (resl == ST_OK) {
		resl = sl_flush(hook);
	}
	return resl;
}

/*
 * FF_SAFE_FAST. A record holds a 64-bit checksum (XXH64, seed 0) of each 512-byte unit of the
 * block as it is written in place, not the block. After a power loss the recovery tells each
 * unit apart: the checksum matches (written), it matches after the unit is transformed again
 * (still the old content) or neither (torn: zeroed in the new state, like an unreadable sector).
 * A false match is a 2^-64 event. A wipe pass destroys the old content, so a wiping session
 * uses the full journal.
 */
/* the checksum is volume_lib's (journal.c dc_log_sum64), so the boot loader that checks a
 * pending block at boot computes exactly what the step wrote */
u64 dc_slog_sum64(const u8 *unit)
{
	return dc_log_sum64(unit);
}

void dc_slog_sums(const u8 *buff, u32 size, u64 *table)
{
	u32 i;

	for (i = 0; i < size / SL_SUM_UNIT; i++) {
		table[i] = dc_slog_sum64(buff + (size_t)i * SL_SUM_UNIT);
	}
}

u32 dc_slog_data_len(dc_slog *s, u32 type, u32 size)
{
	return dc_log_data_len(s->sec, type, size);
}

u32 dc_slog_dir(BOOLEAN is_decrypt, BOOLEAN is_reencrypt)
{
	return is_decrypt ? LR_DEC : (is_reencrypt ? LR_REENC : LR_ENC);
}

u64 dc_slog_rec_end(u32 dir, u64 offs, u32 size)
{
	return dc_log_rec_end(dir, offs, size);
}

/* the record / commit / log header CRCs are volume_lib's (journal.c), so the recovery there
 * checks exactly what is written here */
#define sl_rec_crc  dc_log_rec_crc
#define sl_com_crc  dc_log_com_crc
#define sl_head_crc dc_log_head_crc

/* the commit sector of record seq in s->sbuf */
static void sl_build_commit(dc_slog *s, u64 seq)
{
	dc_log_commit *c = (dc_log_commit*)s->sbuf;

	memset(s->sbuf, 0, s->sec);
	memcpy(c->magic, DC_LOG_COM_MAGIC, sizeof(c->magic));
	c->log_id = s->log_id;
	c->seq    = seq;
	c->crc    = sl_com_crc(c);
}

int dc_slog_create(dev_hook *hook, u64 hdr_tmp, u64 *log_off, int fast)
{
	dc_slog     *s;
	dc_log_head *h;
	u32          sec, len, flen;
	u64          off = 0;
	int          resl;

	if (hook->bps == 0 || hook->bps > MAX_SECTOR_SIZE) {
		return ST_INV_SECT;
	}
	sec = max(hook->bps, 4096);
	/* fast: the data area holds the checksum table of a full block (a multiple of sec) */
	len = DC_LOG_HEAD_SIZE + 4 * sec + (fast ? (DC_SLOG_SUM_BYTES + sec - 1) / sec * sec : ENC_BLOCK_SIZE);

	dc_slog_free(hook); /* nothing may be left from an earlier session */

	if ( (s = (dc_slog*)mm_pool_alloc(sizeof(dc_slog))) == NULL ) {
		return ST_NOMEM;
	}
	memset(s, 0, sizeof(dc_slog));
	if ( (s->sbuf = (u8*)mm_pool_alloc(max(sec, DC_LOG_HEAD_SIZE))) == NULL ) {
		mm_pool_free(s);
		return ST_NOMEM;
	}
	s->hook      = hook;
	s->sec       = sec;
	s->block_max = len - DC_LOG_HEAD_SIZE - 4 * sec;
	s->log_len   = len;
	s->fast      = fast;
	s->hdr_ok    = s->hdr_try = hdr_tmp;
	s->bak_ok    = s->bak_try = hdr_tmp;
	cp_rand_bytes((u8*)&s->log_id, sizeof(s->log_id));
	if (s->log_id == 0) s->log_id = 1;

	/* a contiguous $dclog$ outside the header areas (a leftover one is deleted first). A
	 * full / fragmented volume may have no contiguous room for the 8 MiB data area: then the
	 * small one (the steps follow block_max) */
	flen = len;
	if ( (resl = dc_create_log_file(hook, &off, &flen, hook->head_len, fast ? 0 : 8)) != ST_OK && fast ) {
		DbgMsg("dc_slog_create: $dclog$ not created (%d), dev=%ws\n", resl, hook->dev_name);
		dc_slog_release(s);
		return ST_LOG_CREATE;
	}
	if (resl != ST_OK) {
		DbgMsg("dc_slog_create: $dclog$ of %u bytes not created (%d), trying %u, dev=%ws\n",
			len, resl, DC_LOG_HEAD_SIZE + 4 * sec + SL_BLOCK_SMALL, hook->dev_name);
		s->block_max = SL_BLOCK_SMALL;
		s->log_len   = len = DC_LOG_HEAD_SIZE + 4 * sec + SL_BLOCK_SMALL;
		flen = len;
		if ( (resl = dc_create_log_file(hook, &off, &flen, hook->head_len, 0)) != ST_OK ) {
			DbgMsg("dc_slog_create: $dclog$ not created (%d), dev=%ws\n", resl, hook->dev_name);
			dc_slog_release(s);
			return ST_LOG_CREATE;
		}
	}
	s->log_off = off;

	do
	{
		resl = ST_LOG_CREATE;
		if ( (off % hook->bps) != 0 || flen < len || off < hook->head_len || off + len > hook->dsk_size ) {
			DbgMsg("dc_slog_create: $dclog$ unusable at %I64x, length %u\n", off, flen);
			break;
		}

		/* the log header, then both record / commit pairs zeroed, flushed - before the DC
		 * header carries FF_SAFE_TRANSCRYPT and log_offset */
		memset(s->sbuf, 0, DC_LOG_HEAD_SIZE);
		h = (dc_log_head*)s->sbuf;
		memcpy(h->magic, DC_LOG_HEAD_MAGIC, sizeof(h->magic));
		h->version   = DC_LOG_VERSION;
		h->sec       = sec;
		h->log_id    = s->log_id;
		h->disk_id   = hook->disk_id;
		h->log_len   = len;
		h->block_max = s->block_max;
		h->crc       = sl_head_crc(h);
		if ( (resl = io_hook_rw(hook, s->sbuf, DC_LOG_HEAD_SIZE, off, 0)) != ST_OK ) break;

		memset(s->sbuf, 0, sec);
		if ( (resl = io_hook_rw(hook, s->sbuf, sec, SL_COM_A(s), 0)) != ST_OK ) break;
		if ( (resl = io_hook_rw(hook, s->sbuf, sec, SL_REC_A(s), 0)) != ST_OK ) break;
		if ( (resl = io_hook_rw(hook, s->sbuf, sec, SL_REC_B(s), 0)) != ST_OK ) break;
		if ( (resl = io_hook_rw(hook, s->sbuf, sec, SL_COM_B(s), 0)) != ST_OK ) break;
		resl = sl_flush(hook);
	} while (0);

	if (resl != ST_OK) {
		DbgMsg("dc_slog_create: journal init failed (%d), dev=%ws\n", resl, hook->dev_name);
		dc_slog_release(s);
		dc_delete_log_file(hook);
		return (resl == ST_MEDIA_CHANGED || resl == ST_NO_MEDIA) ? resl : ST_LOG_CREATE;
	}

	dc_slog_insert(s);
	dc_hook_set_flags(hook, F_PROTECT_DCLOG);
	*log_off = off;

	DbgMsg("dc_slog_create: $dclog$ at %I64x, %u bytes, sec %u, dev=%ws\n", off, len, sec, hook->dev_name);
	return ST_OK;
}

void dc_slog_discard(dev_hook *hook)
{
	dc_slog *s = dc_slog_get(hook);

	/* a header that may still point here (a failed start write that reached the disk)
	 * must not find a valid journal in clusters the file system reuses after the delete */
	if (s != NULL && !s->dead && s->log_off >= hook->head_len) {
		memset(s->sbuf, 0, DC_LOG_HEAD_SIZE);
		if (io_hook_rw(hook, s->sbuf, DC_LOG_HEAD_SIZE, s->log_off, 0) != ST_OK || sl_flush(hook) != ST_OK) {
			DbgMsg("dc_slog_discard: journal header not invalidated, dev=%ws\n", hook->dev_name);
		}
	}
	dc_slog_free(hook);
	dc_hook_clear_flags(hook, F_PROTECT_DCLOG);
	dc_delete_log_file(hook);
}

int dc_slog_write_record(dev_hook *hook, dc_slog *s, u32 type, u32 dir, u64 offs, u32 size,
	                     const void *data, u64 tmp_before)
{
	dc_log_rec *r;
	u64         seq = s->seq + 1;
	u32         dlen = dc_slog_data_len(s, type, size);
	int         resl;

	/* the record type of the session (fast: LR_SUM), and the data area holds what it carries */
	if ( (type == LR_STEP && s->fast) || (type == LR_SUM && !s->fast) ||
		 (dlen != 0 && (data == NULL || dlen > s->block_max || size > ENC_BLOCK_SIZE)) ) {
		return ST_INVALID_PARAM;
	}
	/* a failed write may have left a record on the disk: the record sectors are dirty now */
	s->dirty = 1;

	/* LR_STEP / LR_SUM: the post-image / checksum table first, then its record; one flush makes
	 * both durable. A torn data area makes the record invalid (data_crc) - safe, nothing is
	 * written in place before this flush returned. */
	if (dlen != 0) {
		if ( (resl = io_hook_rw(hook, (void*)data, dlen, SL_DATA(s), 0)) != ST_OK ) return resl;
	}

	memset(s->sbuf, 0, s->sec);
	r = (dc_log_rec*)s->sbuf;
	memcpy(r->magic, DC_LOG_REC_MAGIC, sizeof(r->magic));
	r->log_id     = s->log_id;
	r->seq        = seq;
	r->type       = type;
	r->dir        = dir;
	r->offs       = offs;
	r->size       = size;
	r->data_crc   = (dlen != 0) ? crc32((const unsigned char*)data, dlen) : 0;
	r->tmp_before = tmp_before;
	r->hdr_ok     = s->hdr_ok;
	r->hdr_try    = s->hdr_try;
	r->bak_ok     = s->bak_ok;
	r->bak_try    = s->bak_try;
	r->rec_crc    = sl_rec_crc(r);

	/* LR_SKIP: nothing is written in place, so the durable record is its own commit (the
	 * recovery takes a valid LR_SKIP as committed) */
	if ( (resl = io_hook_rw(hook, s->sbuf, s->sec, SL_REC(s, seq), 0)) != ST_OK ) return resl;
	if ( (resl = sl_flush(hook)) != ST_OK ) return resl;

	s->seq = seq;
	return ST_OK;
}

int dc_slog_commit(dev_hook *hook, dc_slog *s, u64 seq)
{
	int resl;

	sl_build_commit(s, seq);
	if ( (resl = io_hook_rw(hook, s->sbuf, s->sec, SL_COM(s, seq), 0)) == ST_OK ) {
		resl = sl_flush(hook);
	}
	return resl;
}

int dc_slog_invalidate(dev_hook *hook, dc_slog *s, u64 seq)
{
	int resl;

	memset(s->sbuf, 0, s->sec);
	if ( (resl = io_hook_rw(hook, s->sbuf, s->sec, SL_REC(s, seq), 0)) == ST_OK ) {
		resl = sl_flush(hook);
	}
	return resl;
}

int dc_slog_read_post_image(dev_hook *hook, dc_slog *s, void *buff)
{
	int resl;

	if (s->pend_size == 0 || s->pend_size > s->block_max || s->pend_size > ENC_BLOCK_SIZE) {
		return ST_INVALID_PARAM;
	}
	if ( (resl = io_hook_rw(hook, buff, s->pend_size, SL_DATA(s), 1)) != ST_OK ) {
		return resl;
	}
	if (crc32((const unsigned char*)buff, s->pend_size) != s->pend_crc) {
		DbgMsg("dc_slog_read_post_image: data area does not match the record (seq %I64u), dev=%ws\n", s->pend_seq, hook->dev_name);
		return ST_LOG_CONFLICT;
	}
	return ST_OK;
}

int dc_slog_read_sums(dev_hook *hook, dc_slog *s, u64 *table)
{
	u32 dlen = dc_slog_data_len(s, LR_SUM, s->pend_size);
	int resl;

	if (s->pend_type != LR_SUM || s->pend_size == 0 || s->pend_size > ENC_BLOCK_SIZE ||
		dlen > s->block_max || dlen > DC_SLOG_SUM_BYTES) {
		return ST_INVALID_PARAM;
	}
	if ( (resl = io_hook_rw(hook, table, dlen, SL_DATA(s), 1)) != ST_OK ) {
		return resl;
	}
	if (crc32((const unsigned char*)table, dlen) != s->pend_crc) {
		DbgMsg("dc_slog_read_sums: data area does not match the record (seq %I64u), dev=%ws\n", s->pend_seq, hook->dev_name);
		return ST_LOG_CONFLICT;
	}
	return ST_OK;
}

int dc_slog_empty(dev_hook *hook, dc_slog *s)
{
	int resl;

	if (s->dirty == 0) {
		return ST_OK;
	}
	/* the commits too: seq restarts after a remount of an empty journal, and an old commit
	 * must never confirm a new record of the same seq */
	memset(s->sbuf, 0, s->sec);
	if ( (resl = io_hook_rw(hook, s->sbuf, s->sec, SL_REC_A(s), 0)) == ST_OK &&
		 (resl = io_hook_rw(hook, s->sbuf, s->sec, SL_REC_B(s), 0)) == ST_OK &&
		 (resl = io_hook_rw(hook, s->sbuf, s->sec, SL_COM_A(s), 0)) == ST_OK &&
		 (resl = io_hook_rw(hook, s->sbuf, s->sec, SL_COM_B(s), 0)) == ST_OK &&
		 (resl = sl_flush(hook)) == ST_OK )
	{
		s->dirty = 0;
	}
	if (resl != ST_OK) {
		DbgMsg("dc_slog_empty: failed (%d), dev=%ws\n", resl, hook->dev_name);
	}
	return resl;
}

int dc_slog_zero_all(dev_hook *hook, dc_slog *s, u8 *buff, u32 buff_len)
{
	u32 done, chunk;
	int resl = ST_OK;

	buff_len -= buff_len % s->sec;
	if (buff_len == 0) {
		return ST_INVALID_PARAM;
	}
	for (done = 0; done < s->log_len; done += chunk) {
		chunk = min(s->log_len - done, buff_len);
		if ( (resl = io_hook_rw(hook, buff, chunk, s->log_off + done, 0)) != ST_OK ) break;
	}
	if (resl == ST_OK) resl = sl_flush(hook);
	if (resl == ST_OK) {
		s->dirty = 0;
	}
	return resl;
}

/*
 * Recovery (mount / unlock)
 *
 * Reading the journal - the log header, both record / commit pairs, which record decides and
 * the hints for a torn header - is volume_lib's (journal.c), shared with the boot loader so
 * both read a journal the same way. What follows is the driver's side: completing a pending
 * block, the quarantine and the session state.
 */

/*
 * The boundary values the journal of hcopy's session holds (start and end of both records and
 * the header values they carry): tmp_size candidates for a primary header torn by a power loss.
 * Only hints, dc_header_repair_tmp tests each against the header's CRC. Reads only, keeps no
 * state. Returns the number of values stored in out (at most max).
 */
int dc_slog_tmp_hints(dev_hook *hook, dc_header *hcopy, u64 *out, int max)
{
	dc_dev dev;

	dc_dev_of(hook, &dev);
	return dc_journal_tmp_hints(&dev, dc_hook_rw, hcopy, out, max);
}

int dc_slog_mount(dev_hook *hook, dc_header *hcopy, BOOLEAN from_bak, u64 other_tmp, BOOLEAN other_ok,
	              u64 *tmp_size, int *recovered)
{
	dc_slog     *s = NULL;
	dc_journal  *j = NULL;
	u8          *data = NULL;
	u64          hdr = hcopy->tmp_size, boundary;
	int          n, resl = ST_OK;
	BOOLEAN      read_only = (hook->mnt_flags & MF_READ_ONLY) != 0;
	dc_dev       dev;

	*recovered = 0;
	dc_slog_free(hook);

	if ( !(hcopy->flags & VF_TMP_MODE) || hcopy->version < DC_HDR_VERSION_2 ||
		 !(hcopy->feature_flags & FF_SAFE_TRANSCRYPT) )
	{
		return ST_OK;
	}
	dc_dev_of(hook, &dev);

	do
	{
		if ( (s = (dc_slog*)mm_pool_alloc(sizeof(dc_slog))) == NULL ||
			 (memset(s, 0, sizeof(dc_slog)), (s->sbuf = (u8*)mm_pool_alloc(DC_LOG_SCRATCH)) == NULL) ||
			 (j = (dc_journal*)mm_pool_alloc(sizeof(dc_journal))) == NULL )
		{
			resl = ST_NOMEM; break;
		}
		memset(j, 0, sizeof(dc_journal));
		s->hook = hook;

		/* the log header (ST_INV_VOLUME: no usable journal, see below) */
		if ( (resl = dc_journal_open(&dev, dc_hook_rw, hcopy, hook->head_len, s->sbuf, j)) != ST_OK ) {
			DbgMsg("dc_slog_mount: no journal (%d), dev=%ws\n", resl, hook->dev_name);
			break;
		}
		s->log_off   = j->log_off;
		s->log_len   = j->log_len;
		s->sec       = j->sec;
		s->block_max = j->block_max;
		s->log_id    = j->log_id;
		s->fast      = j->fast;

		/* both records and commits; ST_LOG_CONFLICT: the journal kind or a bound record's kind
		 * contradicts the header */
		if ( (resl = dc_journal_scan(&dev, dc_hook_rw, hcopy, from_bak, s->sbuf, j)) != ST_OK ) {
			DbgMsg("dc_slog_mount: records not usable (%d)\n", resl);
			break;
		}

		/* the newest valid record decides; the data area is read only for a pending one, so
		 * the buffer is allocated only then */
		while ( (resl = dc_journal_pick(&dev, dc_hook_rw, j, data)) == ST_SMALL_BUFF && data == NULL ) {
			if ( (data = (u8*)mm_pool_alloc(s->block_max)) == NULL ) {
				resl = ST_NOMEM; break;
			}
		}
		if (resl != ST_OK) break;
		n = j->newest;

		s->seq   = j->max_seq;
		s->dirty = j->any_basic;
		if (from_bak) {
			s->bak_ok = s->bak_try = hdr;
			s->hdr_ok = s->hdr_try = other_ok ? other_tmp : 0;
		} else {
			s->hdr_ok = s->hdr_try = hdr;
			s->bak_ok = s->bak_try = other_ok ? other_tmp : 0;
		}
		/* no new record before a save wrote every header and emptied the journal: the value of
		 * a header this mount did not read is unknown (records would carry a wrong one), and a
		 * record ignored here (torn data area) must not be overwritten by a record not bound to
		 * a header the next mount finds. The save follows the install. */
		s->need_hdr = from_bak || (!other_ok && (hcopy->flags & VF_BACKUP_HEADER)) || j->any_basic;

		if (n < 0) {
			/* no record after the header state on disk: the header's boundary is exact */
			DbgMsg("dc_slog_mount: journal empty, boundary %I64x, dev=%ws\n", *tmp_size, hook->dev_name);
			resl = ST_OK; break;
		}

		boundary = j->boundary;

		if (j->rec[n].type == LR_SUM && !j->committed[n])
		{
			/* FF_SAFE_FAST: completing the block needs the data keys - right after the session
			 * install (dc_safe_resolve_pending), or by the first step. Until then the boundary
			 * stays before it and I/O to it fails (quarantine; no tracked I/O runs yet). */
			DbgMsg("dc_slog_mount: pending block %I64x+%u (checksums), completed after the install\n", j->rec[n].offs, j->rec[n].size);
			s->pend      = SL_PEND_WRITTEN;
			s->pend_type = LR_SUM;
			s->pend_seq  = j->rec[n].seq;
			s->pend_offs = j->rec[n].offs;
			s->pend_size = j->rec[n].size;
			s->pend_dir  = j->rec[n].dir;
			s->pend_crc  = j->rec[n].data_crc;
			s->q_start   = j->rec[n].offs;
			s->q_end     = j->rec[n].offs + j->rec[n].size;
			s->quar      = 1;
			InterlockedIncrement(&dc_slog_quar_cnt);
			boundary     = j->rec[n].tmp_before;
		}
		else if (j->rec[n].type == LR_STEP && !j->committed[n])
		{
			/* complete the block from its post-image (data holds it, crc checked) */
			int wr = ST_ERROR;

			if (!read_only) {
				if ( (wr = dc_slog_write_in_place(hook, data, j->rec[n].size, j->rec[n].offs)) == ST_OK ) {
					wr = dc_slog_commit(hook, s, j->rec[n].seq);
				}
			}
			if (wr != ST_OK) {
				/* quarantine: the boundary stays before the block, I/O to it fails
				 * until a later step / mount completes it. No tracked I/O runs yet (F_SYNC is
				 * published by the session install after this). */
				DbgMsg("dc_slog_mount: pending block %I64x+%u not completed (%s %d), quarantined\n",
					j->rec[n].offs, j->rec[n].size, read_only ? "read-only" : "write", wr);
				s->pend      = SL_PEND_WRITTEN;
				s->pend_type = LR_STEP;
				s->pend_seq  = j->rec[n].seq;
				s->pend_offs = j->rec[n].offs;
				s->pend_size = j->rec[n].size;
				s->pend_dir  = j->rec[n].dir;
				s->pend_crc  = j->rec[n].data_crc;
				s->q_start   = j->rec[n].offs;
				s->q_end     = j->rec[n].offs + j->rec[n].size;
				s->quar      = 1;
				InterlockedIncrement(&dc_slog_quar_cnt);
				boundary     = j->rec[n].tmp_before;
			} else {
				DbgMsg("dc_slog_mount: pending block %I64x+%u completed from the journal\n", j->rec[n].offs, j->rec[n].size);
			}
		}
		DbgMsg("dc_slog_mount: record %I64u (type %u, dir %u), boundary %I64x -> %I64x, dev=%ws\n",
			j->rec[n].seq, j->rec[n].type, j->rec[n].dir, *tmp_size, boundary, hook->dev_name);
		*tmp_size  = boundary;
		*recovered = 1;
		resl = ST_OK;
	} while (0);

	if (data != NULL) {
		mm_pool_free(data);
	}
	if (j != NULL) {
		mm_pool_free(j);
	}

	if (resl == ST_INV_VOLUME) {
		/* no usable journal: the header's boundary decides; the session continues
		 * without protection - the next save writes the header without the journal */
		DbgMsg("dc_slog_mount: no usable journal, session continues unprotected, dev=%ws\n", hook->dev_name);
		hcopy->feature_flags &= ~(FF_SAFE_TRANSCRYPT | FF_SAFE_FAST);
		hcopy->log_offset     = 0;
		hcopy->hdr_crc        = calculate_header_crc(hcopy);
		if (s != NULL) dc_slog_release(s);
		return ST_OK;
	}
	/* an unreadable journal must not make the data unreachable - a read-only mount
	 * goes on with the header's boundary (at worst the last unsaved blocks read wrong) as a dead
	 * session: no step, no header save (dc_save_enc_state refuses), FF_SAFE_TRANSCRYPT kept, so a
	 * later read-write mount still recovers from the journal */
	if (resl != ST_OK && s != NULL && s->quar == 0 && read_only && (resl == ST_RW_ERR || resl == ST_IO_ERROR)) {
		DbgMsg("dc_slog_mount: journal unreadable (%d), read-only mount, session stopped, dev=%ws\n", resl, hook->dev_name);
		s->dead = 1;
		resl    = ST_OK;
	}
	if (resl != ST_OK) {
		if (s != NULL) {
			if (s->quar) InterlockedDecrement(&dc_slog_quar_cnt);
			dc_slog_release(s);
		}
		return resl;
	}

	dc_slog_insert(s);
	dc_hook_set_flags(hook, F_PROTECT_DCLOG);
	return ST_OK;
}
