/*
    * DCrypt volume_lib - reading the power-loss journal ($dclog$)
    * Copyright (c) 2026 David Xanatos <info@diskcryptor.org>
    *
    * SPDX-License-Identifier: MIT
    *
    * Shared so the driver and the boot loader read a journal the same way. See journal.h.
*/
#include "defines.h"
#include "dc_internal.h"
#include "journal.h"
#include "crc32.h"

/* CRT-free: the firmware build has no memcmp */
static int jl_magic_eq(const unsigned char *m, const char *magic)
{
	int i;
	for (i = 0; i < 8; i++) {
		if (m[i] != (unsigned char)magic[i]) return 0;
	}
	return 1;
}

/*
 * FF_SAFE_FAST. A record holds a 64-bit checksum of each 512-byte unit of the block as it is
 * written in place. The checksum is XXH64 (seed 0) of the 512 bytes: fast, and a stale or torn
 * unit that happens to match is a 2^-64 event.
 */
#define JL_P1 0x9E3779B185EBCA87ULL
#define JL_P2 0xC2B2AE3D27D4EB4FULL
#define JL_P3 0x165667B19E3779F9ULL
#define JL_P4 0x85EBCA77C2B2AE63ULL

static __inline u64 jl_rotl(u64 x, int r)    { return (x << r) | (x >> (64 - r)); }
static __inline u64 jl_round(u64 acc, u64 v) { acc += v * JL_P2; acc = jl_rotl(acc, 31); return acc * JL_P1; }
static __inline u64 jl_merge(u64 acc, u64 v) { acc ^= jl_round(0, v); return acc * JL_P1 + JL_P4; }

u64 dc_log_sum64(const u8 *unit)
{
	const u64 *p = (const u64*)unit;
	u64        v1 = JL_P1 + JL_P2, v2 = JL_P2, v3 = 0, v4 = 0 - JL_P1, h;
	int        i;

	for (i = 0; i < DC_LOG_SUM_UNIT / 8; i += 4) {
		v1 = jl_round(v1, p[i]);
		v2 = jl_round(v2, p[i + 1]);
		v3 = jl_round(v3, p[i + 2]);
		v4 = jl_round(v4, p[i + 3]);
	}
	h = jl_rotl(v1, 1) + jl_rotl(v2, 7) + jl_rotl(v3, 12) + jl_rotl(v4, 18);
	h = jl_merge(h, v1);
	h = jl_merge(h, v2);
	h = jl_merge(h, v3);
	h = jl_merge(h, v4);
	h += DC_LOG_SUM_UNIT;
	h ^= h >> 33; h *= JL_P2;
	h ^= h >> 29; h *= JL_P3;
	h ^= h >> 32;
	return h;
}

u64 dc_log_rec_end(u32 dir, u64 offs, u32 size)
{
	return (dir == LR_DEC) ? offs : offs + size;
}

u32 dc_log_data_len(u32 sec, u32 type, u32 size)
{
	if (type == LR_STEP) return size;
	if (type == LR_SUM) {
		u32 n = (size / DC_LOG_SUM_UNIT) * 8;
		return (n + sec - 1) / sec * sec;
	}
	return 0;
}

u32 dc_log_rec_crc(dc_log_rec *r)
{
	u32 saved = r->rec_crc, crc;

	r->rec_crc = 0;
	crc = crc32((const unsigned char*)r, sizeof(dc_log_rec));
	r->rec_crc = saved;
	return crc;
}

u32 dc_log_com_crc(dc_log_commit *c)
{
	u32 saved = c->crc, crc;

	c->crc = 0;
	crc = crc32((const unsigned char*)c, sizeof(dc_log_commit));
	c->crc = saved;
	return crc;
}

u32 dc_log_head_crc(dc_log_head *h)
{
	u32 saved = h->crc, crc;

	h->crc = 0;
	crc = crc32((const unsigned char*)h, sizeof(dc_log_head));
	h->crc = saved;
	return crc;
}

int dc_journal_open(dc_dev *dev, dc_rw_fn rw, const dc_header *hcopy, u64 min_off, u8 *scratch, dc_journal *j)
{
	dc_log_head *h;
	u64          lo = hcopy->log_offset;
	u32          sec;
	int          resl;

	if (dev->bps == 0 || dev->bps > MAX_SECTOR_SIZE || lo == 0 || (lo % dev->bps) != 0 ||
		lo < min_off || lo >= dev->dsk_size)
	{
		DbgMsg("dc_journal_open: log_offset %I64x unusable\n", lo);
		return ST_INV_VOLUME;
	}
	if ( (resl = rw(dev->ctx, scratch, DC_LOG_HEAD_SIZE, lo, 1)) != ST_OK ) {
		DbgMsg("dc_journal_open: log header read failed (%d)\n", resl);
		return resl;
	}
	h   = (dc_log_head*)scratch;
	sec = h->sec;
	if ( !jl_magic_eq(h->magic, DC_LOG_HEAD_MAGIC) || h->version != DC_LOG_VERSION ||
		 h->crc != dc_log_head_crc(h) || h->disk_id != hcopy->disk_id ||
		 sec < dev->bps || (sec % dev->bps) != 0 || sec > DC_LOG_SCRATCH ||
		 h->block_max == 0 || h->block_max > DC_LOG_BLOCK_LIMIT || (h->block_max % sec) != 0 ||
		 h->log_len != DC_LOG_HEAD_SIZE + 4 * sec + h->block_max ||
		 lo + h->log_len > dev->dsk_size )
	{
		DbgMsg("dc_journal_open: log header invalid\n");
		return ST_INV_VOLUME;
	}
	j->log_off   = lo;
	j->log_len   = h->log_len;
	j->sec       = sec;
	j->block_max = h->block_max;
	j->log_id    = h->log_id;
	/* the data area size says which kind of journal it is (a checksum journal's holds the
	 * table of a full block, a full journal's at least 1.25 MiB) */
	j->fast      = (h->block_max == DC_LOG_FAST_BLOCK(sec));
	return ST_OK;
}

static BOOLEAN jl_rec_bounds_ok(dc_dev *dev, dc_journal *j, const dc_header *hcopy, dc_log_rec *r)
{
	u64 end_max = dev->dsk_size;

	if (hcopy->flags & VF_BACKUP_HEADER) {
		end_max -= dev->head_len; /* never the backup header area */
	}
	/* the record types of the session: fast LR_SUM, else LR_STEP; LR_SKIP in both */
	if (r->type != LR_SKIP && r->type != (u32)(j->fast ? LR_SUM : LR_STEP)) return FALSE;
	if (r->dir != LR_ENC && r->dir != LR_DEC && r->dir != LR_REENC) return FALSE;
	if ((r->dir == LR_REENC) != ((hcopy->flags & VF_REENCRYPT) != 0)) return FALSE;
	if (r->size == 0 || (r->size % dev->bps) != 0 || (r->offs % dev->bps) != 0) return FALSE;
	if (r->type == LR_STEP && r->size > j->block_max) return FALSE;
	if (r->type == LR_SUM && (r->size > DC_LOG_BLOCK_LIMIT || (r->size % DC_LOG_SUM_UNIT) != 0 ||
		dc_log_data_len(j->sec, LR_SUM, r->size) > j->block_max)) return FALSE;
	if (r->offs < dev->head_len || r->offs > end_max || r->size > end_max - r->offs) return FALSE;
	/* the record is adjacent to the boundary it started from */
	if (r->dir == LR_DEC) {
		if (r->offs + r->size != r->tmp_before) return FALSE;
	} else {
		if (r->offs != r->tmp_before) return FALSE;
	}
	return TRUE;
}

int dc_journal_scan(dc_dev *dev, dc_rw_fn rw, const dc_header *hcopy, int from_bak, u8 *scratch, dc_journal *j)
{
	u64 hdr = hcopy->tmp_size;
	int i, resl;

	/* a header that disagrees with the journal's kind (a lost or added FF_SAFE_FAST)
	 * would make the recovery ignore the pending block: refused */
	if (j->fast != ((hcopy->feature_flags & FF_SAFE_FAST) != 0)) {
		DbgMsg("dc_journal_scan: journal kind (%s) does not match the header\n", j->fast ? "checksums" : "copies");
		return ST_LOG_CONFLICT;
	}
	for (i = 0; i < 2; i++) {
		j->basic[i] = j->valid[i] = j->committed[i] = 0;
		memset(&j->rec[i], 0, sizeof(dc_log_rec));
	}
	j->max_seq   = 0;
	j->any_basic = 0;
	j->newest    = -1;
	j->pending   = 0;
	j->boundary  = 0;

	for (i = 0; i < 2; i++)
	{
		dc_log_rec    *r = &j->rec[i];
		dc_log_commit *m;
		u64            seq_par = (i == 0) ? 1 : 0;
		BOOLEAN        com_basic, bound;
		u64            com_seq;

		/* the commit first: its seq counts for the next seq too (never reused) */
		if ( (resl = rw(dev->ctx, scratch, j->sec, (i == 0) ? DC_LOG_COM_A(j) : DC_LOG_COM_B(j), 1)) != ST_OK ) return resl;
		m = (dc_log_commit*)scratch;
		com_basic = jl_magic_eq(m->magic, DC_LOG_COM_MAGIC) && m->log_id == j->log_id && m->crc == dc_log_com_crc(m);
		com_seq   = m->seq;
		if (com_basic) {
			j->any_basic = 1;
			if (com_seq > j->max_seq) j->max_seq = com_seq;
		}

		if ( (resl = rw(dev->ctx, scratch, j->sec, (i == 0) ? DC_LOG_REC_A(j) : DC_LOG_REC_B(j), 1)) != ST_OK ) return resl;
		memcpy(r, scratch, sizeof(dc_log_rec));
		j->basic[i] = jl_magic_eq(r->magic, DC_LOG_REC_MAGIC) && r->log_id == j->log_id &&
		              r->rec_crc == dc_log_rec_crc(r) && r->seq != 0 && (r->seq & 1) == seq_par;
		if (!j->basic[i]) continue;

		j->any_basic = 1;
		if (r->seq > j->max_seq) j->max_seq = r->seq;

		bound = from_bak ? (r->bak_ok == hdr || r->bak_try == hdr) : (r->hdr_ok == hdr || r->hdr_try == hdr);

		/* a record of this session of the other kind is a contradiction, not noise */
		if (bound && r->type != LR_SKIP && r->type != (u32)(j->fast ? LR_SUM : LR_STEP)) {
			DbgMsg("dc_journal_scan: record %I64u of type %u in a %s journal\n", r->seq, r->type, j->fast ? "checksum" : "copy");
			return ST_LOG_CONFLICT;
		}
		j->valid[i]     = jl_rec_bounds_ok(dev, j, hcopy, r) && bound;
		j->committed[i] = (r->type == LR_SKIP) || (com_basic && com_seq == r->seq);
	}
	return ST_OK;
}

int dc_journal_pick(dc_dev *dev, dc_rw_fn rw, dc_journal *j, u8 *data)
{
	int i, n = -1, o, resl;

	/* the newest valid record decides; a pending LR_STEP / LR_SUM needs its data area intact
	 * (a torn data area: the record never was durable, the previous one decides) */
	for (;;)
	{
		int best = -1;

		for (i = 0; i < 2; i++) {
			if (j->valid[i] && (best < 0 || j->rec[i].seq > j->rec[best].seq)) best = i;
		}
		if (best < 0) break;

		if ( (j->rec[best].type == LR_STEP || j->rec[best].type == LR_SUM) && !j->committed[best] ) {
			u32 dlen = dc_log_data_len(j->sec, j->rec[best].type, j->rec[best].size);

			if (data == NULL) {
				return ST_SMALL_BUFF; /* nothing changed yet: the caller allocates and calls again */
			}
			if ( (resl = rw(dev->ctx, data, dlen, DC_LOG_DATA(j), 1)) != ST_OK ) return resl;
			if (crc32(data, dlen) != j->rec[best].data_crc) {
				DbgMsg("dc_journal_pick: pending record %I64u has a torn data area, ignored\n", j->rec[best].seq);
				j->valid[best] = 0;
				continue;
			}
		}
		n = best;
		break;
	}

	j->newest   = n;
	j->pending  = 0;
	j->boundary = 0;
	if (n < 0) {
		return ST_OK; /* no record after the header state on disk: the header's boundary is exact */
	}

	/* chain: a valid previous record (seq - 1) ends where the newest starts. A missing or
	 * invalid predecessor proves nothing (overwritten, torn, invalidated); the header binding
	 * already shows the record is newer than the header state on disk. */
	o = 1 - n;
	if (j->valid[o] && j->rec[o].seq + 1 == j->rec[n].seq) {
		if (dc_log_rec_end(j->rec[o].dir, j->rec[o].offs, j->rec[o].size) != j->rec[n].tmp_before) {
			DbgMsg("dc_journal_pick: records %I64u and %I64u do not chain\n", j->rec[o].seq, j->rec[n].seq);
			return ST_LOG_CONFLICT;
		}
	}
	j->pending  = (j->rec[n].type == LR_STEP || j->rec[n].type == LR_SUM) && !j->committed[n];
	j->boundary = dc_log_rec_end(j->rec[n].dir, j->rec[n].offs, j->rec[n].size);
	return ST_OK;
}

int dc_journal_tmp_hints(dc_dev *dev, dc_rw_fn rw, const dc_header *hcopy, u64 *out, int max)
{
	dc_journal j;
	u8        *buf;
	u64        rec_off[2];
	int        i, n = 0;

	if (hcopy->version < DC_HDR_VERSION_2 || !(hcopy->feature_flags & FF_SAFE_TRANSCRYPT) || max <= 0) {
		return 0;
	}
	if ( (buf = (u8*)dc_alloc(DC_LOG_SCRATCH)) == NULL ) {
		return 0;
	}
	/* the checks of the mount, except the header area (a torn header is not checked yet) */
	if (dc_journal_open(dev, rw, hcopy, 0, buf, &j) == ST_OK)
	{
		rec_off[0] = DC_LOG_REC_A(&j);
		rec_off[1] = DC_LOG_REC_B(&j);

		for (i = 0; i < 2; i++)
		{
			dc_log_rec *r;
			u64         v[6];
			int         k;

			if (rw(dev->ctx, buf, j.sec, rec_off[i], 1) != ST_OK) continue;
			r = (dc_log_rec*)buf;
			if ( !jl_magic_eq(r->magic, DC_LOG_REC_MAGIC) || r->log_id != j.log_id ||
				 r->rec_crc != dc_log_rec_crc(r) || r->seq == 0 )
			{
				continue;
			}
			v[0] = r->tmp_before;
			v[1] = dc_log_rec_end(r->dir, r->offs, r->size);
			v[2] = r->hdr_ok;  v[3] = r->hdr_try;
			v[4] = r->bak_ok;  v[5] = r->bak_try;
			for (k = 0; k < 6 && n < max; k++) out[n++] = v[k];
		}
	}
	dc_free(buf);
	return n;
}
