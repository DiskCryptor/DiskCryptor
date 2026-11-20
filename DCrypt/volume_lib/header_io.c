/*
    * DCrypt volume_lib - reading and writing a header on a device
    * Copyright (c) 2026 David Xanatos <info@diskcryptor.org>
    *
    * SPDX-License-Identifier: MIT
    *
    * See PROVENANCE.md: this file began as an extraction from DiskCryptor's
    * driver, and everything that still carried ntldr's expression was rewritten
    * before the licence changed.
*/
#include "defines.h"
#include "dc_internal.h"
#include "header_io.h"
#include "crypto_head.h"
#include "crc32.h"

int io_read_header_full(dc_dev *dev, dc_rw_fn rw, u64 pos, dc_header **header, xts_key *hdr_key, int hdr_len)
{
	int      buff_len = ROUND_TO_FULL_SECTORS(max(hdr_len, PAGE_SIZE), dev->bps);
	u8      *buff = NULL;
	u8      *buff2 = NULL;
	int      resl = ST_OK;

	/* v2 headers handling */
	if ((*header)->version < DC_HDR_VERSION_2) {
		return ST_OK; /* nothing to do for v1 headers */
	}

	/* bound head_len before it sizes buffers and reads: >= 0x80000000 would turn negative in
	   the (int) compares below and the key slot copy would overrun the buffers. Same rule as
	   the mount (dc_check_header_geometry). */
	if ((*header)->head_len < DC_AREA_SIZE || (*header)->head_len > DC_AREA_MAX_SIZE ||
		IS_INVALID_SECTOR_SIZE((*header)->head_len)) {
		return ST_INV_VOLUME;
	}

	do
	{
		/* allocate raw buffer and read raw header data from disk */
		if ( (buff = dc_alloc(buff_len)) == NULL ) { resl = ST_NOMEM; break; }
		if ( (resl = rw(dev->ctx, buff, hdr_len, pos, 1)) != ST_OK ) break;

		/* if header length is greater than read length, reallocate header buffer and read the rest of header */
		if (hdr_len < (int)(*header)->head_len)
		{
			/* reallocate raw buffer */
			buff2 = buff;
			buff_len = ROUND_TO_FULL_SECTORS(max((int)(*header)->head_len, PAGE_SIZE), dev->bps);
			if ( (buff = dc_alloc(buff_len)) == NULL ) { resl = ST_NOMEM; break; }
			memcpy(buff, buff2, hdr_len);

			/* reallocate (partially) decrypted header */
			memcpy(buff2, *header, hdr_len);
			dc_free(*header);
			buff_len = ROUND_TO_FULL_SECTORS(((dc_header*)buff2)->head_len, dev->bps);
			if ((*header = dc_alloc(buff_len)) == NULL) { resl = ST_NOMEM; break; }
			memcpy(*header, buff2, hdr_len);

			dc_free(buff2);
			buff2 = NULL;

			/* read the rest of header */
			if ( (resl = rw(dev->ctx, buff + hdr_len, (int)(*header)->head_len - hdr_len, pos + hdr_len, 1)) != ST_OK ) break;

			hdr_len = (int)(*header)->head_len;
		}

		/*
		 * Decrypt the rest; cp_decrypt_header only covered DC_AREA_SIZE.
		 *
		 * The source is buff + DC_AREA_SIZE, not buff. buff holds the raw
		 * header from offset 0, so the tail's ciphertext starts DC_AREA_SIZE
		 * into it - which is also the XTS offset it was encrypted at, hence the
		 * same constant appearing three times on this line.
		 *
		 * Reading from buff instead decrypted the base's ciphertext a second
		 * time under the tail's tweak and wrote the result over the tail, so
		 * every header longer than DC_AREA_SIZE came back with rubbish past the
		 * base. It went unnoticed because nothing that decides whether a volume
		 * mounts lives out there: the base carries the keys, and the key slots
		 * are copied across raw just below.
		 */
		if (hdr_len > DC_AREA_SIZE) {
			xts_decrypt(buff + DC_AREA_SIZE, ((u8*)*header) + DC_AREA_SIZE,
			            hdr_len - DC_AREA_SIZE, DC_AREA_SIZE, hdr_key);
		}

		/* load keyslots */
		if ((*header)->feature_flags & FF_KEY_SLOTS) {
			cp_copy_keylots(*header, buff, (u8*)*header);
		}
	} while (0);

	if (resl != ST_OK) {
		dc_free(*header); *header = NULL;
	}
	if (buff != NULL) dc_free(buff);
	if (buff2 != NULL) dc_free(buff2);
	return resl;
}

int io_read_header(dc_dev *dev, dc_rw_fn rw, u64 pos, dc_header **header, xts_key **out_key, dc_pass *password, int* out_kdf, ULONG *interrupt_cmd)
{
	xts_key *hdr_key = NULL;
	int      resl;

	/*
	 * How much to read before anything is known about the volume.
	 *
	 * Two lower bounds apply and the larger wins: the device's own idea of its
	 * header length, and whatever the password needs - a slot unlock has to
	 * reach the slot holding its key, which sits past the base. Rounded up to
	 * whole sectors, the unit both the device and XTS work in.
	 *
	 * This only opens the base. head_len lives inside the header, so it is not
	 * knowable until the base is decrypted; io_read_header_full comes back for
	 * the rest once it is.
	 */
	int hdr_len = ROUND_TO_FULL_SECTORS(
	                  max((int)dev->head_len, cp_get_min_header_len(password)),
	                  dev->bps);

	if ((*header = dc_alloc(hdr_len)) == NULL) {
		return ST_NOMEM;
	}

	resl = rw(dev->ctx, *header, hdr_len, pos, 1);

	if (resl == ST_OK && (hdr_key = dc_alloc(sizeof(xts_key))) == NULL) {
		resl = ST_NOMEM;
	}

	if (resl == ST_OK) {
		/* one call covers the whole search: every KDF the password admits,
		   every slot it names, every cipher */
		if (cp_decrypt_header(hdr_key, *header, hdr_len, password,
		                      out_kdf, NULL, NULL, interrupt_cmd) == 0) {
			resl = ST_PASS_ERR;
		}
	}

	if (resl == ST_OK) {
		resl = io_read_header_full(dev, rw, pos, header, hdr_key, hdr_len);
	}

	if (resl != ST_OK) {
		dc_free(*header);
		*header = NULL;
		dc_free(hdr_key);
		return resl;
	}

	/* the key belongs to the caller now, if it asked for one */
	if (out_key != NULL) {
		*out_key = hdr_key;
	} else {
		dc_free(hdr_key);
	}
	return ST_OK;
}

/*
 * Length of the v2 CRC range (it starts at &header->version), or 0 if footer_cnt
 * puts it outside the dc_header. footer_cnt is signed and not yet authenticated:
 * the range must be non-empty and end within sizeof(dc_header), the smallest
 * buffer a header is ever held in.
 */
static int header_crc_len_v2(const dc_header *header)
{
	int start = (int)((const u8*)&header->version - (const u8*)header);
	int len   = DC_CRC_AREA_SIZE_2 - (int)(signed char)header->footer_cnt * 16;

	if (len <= 0 || len > (int)sizeof(dc_header) - start) {
		return 0;
	}
	return len;
}

unsigned long calculate_header_crc(dc_header* header)
{
	if (header->version >= DC_HDR_VERSION_2) {
		// version 2 and later have the CRC calculated only over the header base
		int len = header_crc_len_v2(header);

		/* invalid footer_cnt: read nothing; is_volume_header_correct rejects such a header */
		if (len == 0) {
			return 0;
		}
		return crc32((const unsigned char*)&header->version, (unsigned long)len);
	}
	return crc32((const unsigned char*)&header->version, DC_CRC_AREA_SIZE_1);
}

/*
 * Three things have to hold before a decrypted buffer may be treated as a
 * header, and they are checked cheapest-first.
 *
 * The salt is tested before the signature rather than after. A sector that was
 * never written, or was wiped, is all zeroes - and zero is a value the salt may
 * never take, because it is what derives the key that decrypted everything
 * else. Catching that first means a blank sector is rejected for the reason it
 * is actually wrong, instead of getting as far as a CRC over zeroes.
 */
BOOLEAN is_volume_header_correct(dc_header *header)
{
	u32 i, salt_bits;

	if (header == NULL) {
		return FALSE;
	}

	for (i = 0, salt_bits = 0; i < HEADER_SALT_SIZE; i++) {
		salt_bits |= header->salt[i];
	}
	if (salt_bits == 0) {
		return FALSE;
	}

	if (header->sign != DC_VOLUME_SIGN) {
		return FALSE;
	}

	/* a footer_cnt that puts the CRC range outside the header is never valid */
	if (header->version >= DC_HDR_VERSION_2 && header_crc_len_v2(header) == 0) {
		return FALSE;
	}

	return (header->hdr_crc == calculate_header_crc(header)) ? TRUE : FALSE;
}

/*
 * The signature decrypted (so the key is right) but the header does not validate. The
 * expected cause is a header rewrite torn by a power loss on 512-byte media: a periodic
 * transcryption save changes hdr_crc (sector 0) and tmp_size (sector 1), and only one of the
 * two sectors reached the disk.
 */
BOOLEAN is_volume_header_damaged(dc_header *header)
{
	u32 i, salt_bits;

	if (header == NULL) {
		return FALSE;
	}
	for (i = 0, salt_bits = 0; i < HEADER_SALT_SIZE; i++) {
		salt_bits |= header->salt[i];
	}
	if (salt_bits == 0 || header->sign != DC_VOLUME_SIGN) {
		return FALSE;
	}
	return is_volume_header_correct(header) ? FALSE : TRUE;
}

/*
 * Repair a torn transcryption header: find the tmp_size among the n candidates in cand that
 * makes it validate. Exactly one distinct candidate may match: it is stored and 1 returned.
 * None, or two different ones (a CRC32 collision: the boundary would be a guess), leave the
 * header unchanged and return 0. Only for a damaged header in transcryption mode.
 */
int dc_header_repair_tmp(dc_header *header, const u64 *cand, int n)
{
	u64 orig, found = 0;
	int i, hits = 0;

	if (cand == NULL || n <= 0 || is_volume_header_damaged(header) == FALSE || !(header->flags & VF_TMP_MODE)) {
		return 0;
	}
	orig = header->tmp_size;

	for (i = 0; i < n && hits < 2; i++)
	{
		if (cand[i] == orig || (hits == 1 && cand[i] == found)) {
			continue;
		}
		header->tmp_size = cand[i];
		if (is_volume_header_correct(header) != FALSE) {
			if (hits++ == 0) found = cand[i];
		}
	}
	header->tmp_size = (hits == 1) ? found : orig;
	return (hits == 1) ? 1 : 0;
}

/*
 * The backup header of a damaged primary. head_len lies in sector 1, which a session's saves
 * leave alone, so it says where the backup is even when sector 0 is the torn one.
 */
u32 dc_header_backup_len(const dc_header *h, u64 dsk_size, u32 bps)
{
	u32 blen;

	if ( h->version < DC_HDR_VERSION_2 || !(h->flags & VF_BACKUP_HEADER) || bps == 0 ||
		 h->head_len < DC_AREA_SIZE || h->head_len > DC_AREA_MAX_SIZE || IS_INVALID_SECTOR_SIZE(h->head_len) )
	{
		return 0;
	}
	blen = ROUND_TO_FULL_SECTORS(h->head_len, bps);
	return ((u64)blen * 2 <= dsk_size) ? blen : 0;
}

/*
 * hb is a backup of this session state: the same transcryption flags, cipher and key as
 * sector 0 of the primary. A backup from before or after the session would mount a partly
 * transcrypted volume wrongly.
 */
BOOLEAN dc_header_same_state(const dc_header *h, const dc_header *hb)
{
	u32 i;

	if ( hb->disk_id != h->disk_id || hb->alg_1 != h->alg_1 ||
		 (hb->flags & (VF_TMP_MODE | VF_REENCRYPT)) != (h->flags & (VF_TMP_MODE | VF_REENCRYPT)) )
	{
		return FALSE;
	}
	for (i = 0; i < sizeof(h->key_1); i++) {
		if (hb->key_1[i] != h->key_1[i]) return FALSE;
	}
	return TRUE;
}

/*
 * Recover a damaged primary h (signature right, CRC not; see is_volume_header_damaged). The
 * rules (why: see the driver's dc_header_recover in mount.c):
 *  1. a transcryption header: the tmp_size the checksum in sector 0 was made for, among the
 *     stored value plus / minus whole steps, the data end variants, the session start and the
 *     journal's values (exactly one may match). backup == repaired means sector 0 is the older
 *     save, so the stored value is taken (if it is one a save writes), with the checksum made
 *     for it; otherwise the repaired value is kept.
 *  2. no tmp_size fits: the backup header of this state.
 * The header is changed in memory only.
 */
int dc_header_recover_tmp(dc_header *h, const dc_header *hb, u64 dsk_size, u32 bps, const u64 *hints, int n_hints, u64 *cand)
{
	static const u32 steps[2] = { DC_REPAIR_STEP_BLOCK, DC_REPAIR_STEP_WIPE };
	u64 ends[DC_REPAIR_ENDS];
	int n_ends = 0, e;
	u64 hl;
	int fixed = 0;
	u64 stored = h->tmp_size;

	/* the session start and the data end variants (a save after the last, partial block), with and
	 * without the end storage and the backup header area. A session boundary lies in
	 * [hl, dsk_size]; a value below hl (a FINISH save: 0) is never one. */
	hl = (h->version >= DC_HDR_VERSION_2) ? (u64)h->head_len : DC_AREA_SIZE;
	hl = ROUND_TO_FULL_SECTORS(hl, (u64)max(bps, SECTOR_SIZE));
	ends[n_ends++] = dsk_size;
	if (h->version >= DC_HDR_VERSION_2) {
		u64 sl = h->stor_len;

		if (hl < dsk_size)      ends[n_ends++] = dsk_size - hl;
		if (sl < dsk_size)      ends[n_ends++] = dsk_size - sl;
		if (sl + hl < dsk_size) ends[n_ends++] = dsk_size - sl - hl;
	}
	ends[n_ends++] = hl;

	/* 1. the tmp_size of a torn transcryption save */
	if (h->flags & VF_TMP_MODE)
	{
		u64 t = stored;
		int n = 0, k, s;

		if (cand != NULL)
		{
			for (k = 1; k <= DC_REPAIR_STEPS; k++) {
				for (s = 0; s < 2; s++) {
					u64 d = (u64)k * steps[s];

					if (d <= dsk_size && t <= dsk_size - d) cand[n++] = t + d;
					if (t >= d) cand[n++] = t - d;
				}
			}
			for (e = 0; e < n_ends; e++) cand[n++] = ends[e];
			for (k = 0; k < n_hints && k < DC_REPAIR_HINTS; k++) cand[n++] = hints[k];
			fixed = dc_header_repair_tmp(h, cand, n);
		}
		if (fixed) {
			DbgMsg("dc_header_recover_tmp: tmp_size %I64x -> %I64x restored (%d candidates)\n", t, h->tmp_size, n);
			if (hb != NULL && hb->tmp_size == h->tmp_size) {
				/* sector 0 is the older save (the backup's), so the stored value is the newer one - if
				 * a periodic save could have written it: in [hl, dsk_size] and whole steps from the
				 * repaired value, or a data end. Never a FINISH save's tmp_size 0: a boundary below the
				 * data start would transcrypt the header area. Otherwise keep the repaired value. */
				u64     d     = (stored > h->tmp_size) ? stored - h->tmp_size : h->tmp_size - stored;
				BOOLEAN model = (d % DC_REPAIR_STEP_BLOCK) == 0 || (d % DC_REPAIR_STEP_WIPE) == 0;

				for (e = 0; e < n_ends && !model; e++) model = (stored == ends[e]);
				if (stored >= hl && stored <= dsk_size && model) {
					h->tmp_size = stored;
					h->hdr_crc  = calculate_header_crc(h);
					DbgMsg("dc_header_recover_tmp: the backup holds the repaired value - the newer save is the stored %I64x\n", stored);
				} else {
					DbgMsg("dc_header_recover_tmp: the stored %I64x is no session boundary, the repaired value is kept\n", stored);
				}
			}
			if (is_volume_header_correct(h) == FALSE || h->tmp_size < hl || h->tmp_size > dsk_size) {
				/* the checksum was just made for it; a boundary outside the data is no repair */
				return DC_REPAIR_BAD;
			}
			return DC_REPAIR_TMP;
		}
	}

	/* 2. the backup header of this state */
	return (hb != NULL) ? DC_REPAIR_BACKUP : DC_REPAIR_NONE;
}

/*
 * The geometry a decrypted header describes must fit the device before a mount derives its
 * layout from it: the layout code (the driver's dc_header_layout, the boot loader's mount
 * setup) uses unsigned arithmetic that wraps on a bad header. Shared by the driver
 * (dc_check_geometry) and DCS, so both accept the same headers. dsk_size: device (partition)
 * size in bytes; bps: its sector size. Returns ST_OK or ST_INV_VOLUME.
 *
 * Checks only invariants every producer keeps and any layout needs:
 *  - v2: DC_AREA_SIZE <= head_len <= DC_AREA_MAX_SIZE, a multiple of SECTOR_SIZE; v1 uses
 *    DC_AREA_SIZE (head_len/stor_len 0).
 *  - v2: stor_len >= head_len * (VF_BACKUP_HEADER ? 2 : 1), head_len rounded to bps.
 *  - the head area lies inside the device; slack / no-redirect storage leaves use_size > 0;
 *    slack storage does not reach into the head area; a $dcsys$ file lies inside the device.
 * Deliberately NOT checked:
 *  - slack storage stor_off against dsk_size - stor_len: a live resize (dc_update_volume)
 *    can leave a stale stor_off, a valid on-disk state. Logged only.
 *  - tmp_size against the data end: a live shrink during a session can leave it above the
 *    new end; the driver's step and readers clamp it.
 *
 * Two states are repaired in hcopy instead of refused: a v1 header with VF_BACKUP_HEADER, and
 * a storage file that overlaps the backup header area. Both are mounted without the backup
 * layout: VF_BACKUP_HEADER is cleared and hdr_crc recomputed; a later header write stores the
 * corrected flags.
 */
int dc_check_header_geometry(dc_header *hcopy, u64 dsk_size, u32 bps)
{
	u64 head_len;
	u64 stor_len;

	if (hcopy == NULL || bps == 0 || dsk_size == 0) {
		return ST_INV_VOLUME; /* no device info (dsk_size reset by a media change) */
	}
	if (hcopy->version >= DC_HDR_VERSION_2) {
		if (hcopy->head_len < DC_AREA_SIZE || hcopy->head_len > DC_AREA_MAX_SIZE || IS_INVALID_SECTOR_SIZE(hcopy->head_len)) {
			DbgMsg("mount: invalid head_len %u\n", hcopy->head_len);
			return ST_INV_VOLUME;
		}
		head_len = ROUND_TO_FULL_SECTORS((u64)hcopy->head_len, (u64)bps);
		stor_len = hcopy->stor_len;

		if (stor_len < head_len * ((hcopy->flags & VF_BACKUP_HEADER) ? 2 : 1)) {
			DbgMsg("mount: storage %I64u too small for head_len %I64u (backup %d)\n",
				stor_len, head_len, (hcopy->flags & VF_BACKUP_HEADER) != 0);
			return ST_INV_VOLUME;
		}
	} else {
		/* v1 has no room for a backup header (its storage holds only the head copy). Mount it
		 * without the backup layout: the last head_len bytes then read the old backup header
		 * as data (normally unused space). */
		if (hcopy->flags & VF_BACKUP_HEADER) {
			DbgMsg("mount: v1 header with a backup header, ignoring the backup header\n");
			hcopy->flags &= ~VF_BACKUP_HEADER;
			hcopy->hdr_crc = calculate_header_crc(hcopy);
		}
		head_len = ROUND_TO_FULL_SECTORS((u64)DC_AREA_SIZE, (u64)bps);
		stor_len = head_len; /* as dc_header_layout */
	}

	/* a partial transcryption's boundary is sector aligned (head_len + n steps). Not bounded by
	 * the device size: a live shrink during a session can leave it above the new end. */
	if ( (hcopy->flags & VF_TMP_MODE) && (hcopy->tmp_size % bps) != 0 ) {
		DbgMsg("mount: tmp_size %I64u not sector aligned\n", hcopy->tmp_size);
		return ST_INV_VOLUME;
	}

	if (head_len >= dsk_size) {
		DbgMsg("mount: head_len %I64u does not fit device size %I64u\n", head_len, dsk_size);
		return ST_INV_VOLUME;
	}
	/* every producer writes 512-byte multiples; a misaligned storage misaligns every
	 * redirected request. Not bps: a volume moved to a 4Kn disk keeps its 512-aligned values. */
	if ( (stor_len % SECTOR_SIZE) != 0 ||
		 ((hcopy->flags & VF_STORAGE_FILE) && (hcopy->stor_off % SECTOR_SIZE) != 0) ) /* slack: stor_off is not used */
	{
		DbgMsg("mount: storage [%I64u, +%I64u) not sector aligned\n", hcopy->stor_off, stor_len);
		return ST_INV_VOLUME;
	}
	if (hcopy->flags & VF_STORAGE_FILE) {
		if (hcopy->stor_off > dsk_size || stor_len > dsk_size - hcopy->stor_off) {
			DbgMsg("mount: storage file [%I64u, +%I64u) outside device size %I64u\n",
				hcopy->stor_off, stor_len, dsk_size);
			return ST_INV_VOLUME;
		}
		/* $dcsys$ overlapping the head area would make the head redirect map into the
		 * storage it reads from. No producer creates that. */
		if (hcopy->stor_off < head_len) {
			DbgMsg("mount: storage file [%I64u, +%I64u) overlaps the head area (head_len %I64u)\n",
				hcopy->stor_off, stor_len, head_len);
			return ST_INV_VOLUME;
		}
		/* The same with the backup header area at the partition end: the tail redirect would
		 * map the end of the file into the file itself. dc_update_volume leaves this when the
		 * partition is cut into the file without a session. Mount it without the backup
		 * layout, like the v1 case above. */
		if ((hcopy->flags & VF_BACKUP_HEADER) && hcopy->stor_off + stor_len > dsk_size - head_len) {
			DbgMsg("mount: storage file [%I64u, +%I64u) overlaps the backup header area (head_len %I64u), ignoring the backup header (run chkdsk: the last sectors may read stale data)\n",
				hcopy->stor_off, stor_len, head_len);
			hcopy->flags &= ~VF_BACKUP_HEADER;
			hcopy->hdr_crc = calculate_header_crc(hcopy);
		}
	} else {
		if (stor_len >= dsk_size) {
			DbgMsg("mount: storage %I64u does not fit device size %I64u\n", stor_len, dsk_size);
			return ST_INV_VOLUME;
		}
		if ((hcopy->flags & VF_NO_REDIR) == 0) {
			/* slack storage sits at the device end, [dsk_size - stor_len, dsk_size); reaching
			 * below head_len it would hold the redirect target of the head area itself. */
			if (stor_len > dsk_size - head_len) {
				DbgMsg("mount: storage %I64u overlaps the head area (head_len %I64u, device size %I64u)\n",
					stor_len, head_len, dsk_size);
				return ST_INV_VOLUME;
			}
			if (hcopy->stor_off != 0 && hcopy->stor_off != dsk_size - stor_len) {
				/* see above: not rejected; the storage is taken at the device end as always */
				DbgMsg("mount: header stor_off %I64u differs from the device end storage %I64u (resized?)\n",
					hcopy->stor_off, dsk_size - stor_len);
			}
		}
	}
	return ST_OK;
}

int io_write_header(dc_dev *dev, dc_rw_fn rw, u64 pos, dc_header *header, xts_key *hdr_key, dc_pass *password, u32 flags, ULONG *interrupt_cmd)
{
	u8         salt[HEADER_SALT_SIZE];
	int        hdr_len = ROUND_TO_FULL_SECTORS(DC_AREA_SIZE, dev->bps);
	int        mem_len = DC_AREA_SIZE;
	dc_header *hcopy = NULL;
	xts_key   *h_key = hdr_key;
	u64        offset = 0;
	u32        length = hdr_len;
	int        resl;

	if (hdr_key != NULL && hdr_key->encrypt == NULL) return ST_ERROR;
	if (password != NULL && password->size == 0) return ST_ERROR;

	if (header->version >= DC_HDR_VERSION_2)
	{
		hdr_len = ROUND_TO_FULL_SECTORS(header->head_len, dev->bps);
		mem_len = header->head_len;

		/* when updating header calculate minumum required write length and offset and check header correctness */
		if ((flags & HF_UPDATE_ALL) != 0 && (flags & HF_UPDATE_ALL) != HF_UPDATE_ALL)
		{
			if (hdr_key == NULL) {
				DbgMsg("partial header update atempt without header key\n");
				return ST_ERROR;
			}

			length = DC_BASE_SIZE;
			if (header->feature_flags & FF_KEY_SLOTS) {
				length += header->slot_area_len + (header->key_slot_count * header->slot_info_size);
			}

			if (flags & HF_UPDATE_EXT) {
				if (header->ext_hdr_off == 0) {
					DbgMsg("extended header update atempt but ext_hdr_off is zero\n");
					flags &= ~HF_UPDATE_EXT;
				}
				else if ((u32)header->ext_hdr_off + MIN_EXT_HDR_SIZE >= header->head_len || header->ext_hdr_off < length) {
					DbgMsg("invalid extended header offset\n");
					return ST_INV_VOLUME;
				}
			}

			if (flags & HF_UPDATE_SLOTS) {
				if (!(header->feature_flags & FF_KEY_SLOTS)) {
					DbgMsg("slots area update atempt but slot not enabled\n");
					flags &= ~HF_UPDATE_SLOTS;
				}
				else if (header->head_len <= length) {
					DbgMsg("invalid keyslot area length\n");
					return ST_INV_VOLUME;
				}
			}

			if (flags & HF_UPDATE_BASE)
				offset = 0;
			else if (flags & HF_UPDATE_SLOTS)
				offset = DC_BASE_SIZE;
			else if (flags & HF_UPDATE_EXT)
				offset = header->ext_hdr_off;
			else
				return ST_OK; // nothing to do
			offset = (offset / (u64)dev->bps) * (u64)dev->bps; // align to sector, round down

			if (flags & HF_UPDATE_EXT)
				length = header->head_len;
			else if (flags & HF_UPDATE_SLOTS)
				length = DC_BASE_SIZE + header->slot_area_len + (header->key_slot_count * header->slot_info_size);
			else if (flags & HF_UPDATE_BASE)
				length = DC_BASE_SIZE;
			length = (u32)ROUND_TO_FULL_SECTORS((length - offset), dev->bps); // align to sector, round up

			if (offset + length > header->head_len) {
				DbgMsg("invalid header, update range %I64u, %d is invalid\n", offset, length);
				return ST_INV_VOLUME;
			}
		}
		else // full header write
		{
			length = hdr_len;
		}

		if ((flags & HF_CLEAR_SLOTS) && (header->feature_flags & FF_KEY_SLOTS)) {
			/* clear key slots and info - use random data for slots area, and zero info area */
			dc_rand(((u8*)header) + DC_BASE_SIZE, header->slot_area_len);
			memset(((u8*)header) + DC_BASE_SIZE + header->slot_area_len, 0, (header->key_slot_count * header->slot_info_size));
		}
	}

	//DbgMsg("io_write_header: offset %I64u, length %u, flags 0x%X\n", offset, length, flags);

	/*
	 * XTS works a sector at a time and counts the length down by one sector per
	 * turn, so a length that is not a whole number of them wraps and runs past
	 * the buffer. Refuse instead: a header that long cannot have come from this
	 * function, and writing one half-sealed would leave key material in the
	 * clear on disk - much worse than not writing it at all.
	 */
	if ((mem_len % XTS_SECTOR_SIZE) != 0) {
		DbgMsg("header length %d is not a whole number of sectors\n", mem_len);
		return ST_INV_DATA_SIZE;
	}

	/*
	 * The sealing itself. Everything above decided what to write and how much;
	 * from here it is: take a copy, check it, get a key, encrypt, put back the
	 * parts that must not be encrypted, write.
	 *
	 * PAGE_SIZE is a floor on the allocation, not on the header: a partial
	 * update writes from an offset, and the gap-filling below can reach past
	 * mem_len.
	 */
	hcopy = dc_alloc(max(hdr_len, PAGE_SIZE));
	if (hcopy == NULL) {
		resl = ST_NOMEM;
		goto done;
	}
	memcpy(hcopy, header, mem_len);

	if (is_volume_header_correct(hcopy) == FALSE) {
		resl = ST_INV_VOLUME;
		goto done;
	}

	if (h_key != NULL) {
		/*
		 * Re-sealing under a key the caller already has. The salt that derived
		 * it has to stay exactly as it is, so keep a copy to put back after the
		 * encryption runs over it.
		 */
		memcpy(salt, header->salt, HEADER_SALT_SIZE);
	} else {
		/*
		 * Sealing under a password instead, which means a fresh salt and a key
		 * derived from it.
		 *
		 * The header goes into the entropy pool first. At boot the pool has
		 * had little chance to collect anything, and the header - full of
		 * ciphertext and a previous salt - is the best material to hand.
		 */
		if ((h_key = dc_alloc(sizeof(xts_key))) == NULL) {
			resl = ST_NOMEM;
			goto done;
		}

		dc_rand_seed(header, DC_AREA_SIZE);
		dc_rand(salt, HEADER_SALT_SIZE);
		memcpy(hcopy->salt, salt, HEADER_SALT_SIZE);

		if (!cp_set_header_key(h_key, salt, header->alg_1, password, interrupt_cmd)) {
			resl = ST_INVALID_PARAM;
			goto done;
		}
	}

	xts_encrypt(pv(hcopy), pv(hcopy), mem_len, 0, h_key);

	/*
	 * Two things must not stay encrypted, for the same underlying reason - they
	 * are what a reader needs before it holds any key at all.
	 *
	 * The salt derives the header key, so it goes back in the clear. The key
	 * slots are each wrapped under their own slot key rather than the header
	 * key, so they are copied across verbatim - but only when the write will
	 * actually cover them, and not when the caller asked for them to be wiped.
	 */
	memcpy(hcopy->salt, salt, HEADER_SALT_SIZE);

	if (header->version >= DC_HDR_VERSION_2 && !(flags & HF_CLEAR_SLOTS) &&
	    (header->feature_flags & FF_KEY_SLOTS) &&
	    offset + length > DC_BASE_SIZE &&
	    offset < DC_BASE_SIZE + header->slot_area_len)
	{
		cp_copy_keylots(header, (u8*)header, (u8*)hcopy);
	}

	/*
	 * A sector-aligned write can reach past the header proper. Whatever it
	 * covers beyond that is random rather than zeroes, so the end of the header
	 * is not visible to someone looking at the disk.
	 */
	if ((offset + length) > mem_len) {
		dc_rand(((u8*)hcopy) + mem_len, (int)(offset + length) - mem_len);
	}

	resl = rw(dev->ctx, ((u8*)hcopy) + offset, length, offset + pos, 0);

done:
	burn(salt, sizeof(salt));
	if (h_key != NULL && h_key != hdr_key) dc_free(h_key);
	dc_free(hcopy);
	return resl;
}

int get_ext_header(dc_header *header, dc_ext_header **out_ext_hdr)
{
	dc_ext_header* ext_hdr;

	*out_ext_hdr = NULL;

	if (header->version < DC_HDR_VERSION_2) 
		return ST_INCOMPATIBLE;

	if (header->ext_hdr_off == 0) 
		return ST_INCOMPATIBLE;

	if (header->ext_hdr_off < DC_BASE_SIZE + ((header->feature_flags & FF_KEY_SLOTS) ? (header->slot_area_len + (header->key_slot_count * header->slot_info_size)) : 0)) {
		DbgMsg("invalid extended header offset, overlaps with key slots area\n");
		return ST_INV_VOLUME;
	}

	if ((u32)header->ext_hdr_off + MIN_EXT_HDR_SIZE > header->head_len) {
		DbgMsg("invalid extended header offset %d\n", header->ext_hdr_off);
		return ST_INV_VOLUME;
	}
	
	ext_hdr = (dc_ext_header*)(((u8*)header) + header->ext_hdr_off);
	if (header->ext_hdr_off + ext_hdr->size > header->head_len || ext_hdr->size < MIN_EXT_HDR_SIZE) {
		DbgMsg("invalid extended header size %d\n", ext_hdr->size);
		return ST_INV_VOLUME;
	}

	if (ext_hdr->crc != crc32((const unsigned char*)&ext_hdr->size, ext_hdr->size - 4)) {
		DbgMsg("invalid extended header CRC\n");
		return ST_INV_VOLUME;
	}

	*out_ext_hdr = ext_hdr;
	return ST_OK;
}
