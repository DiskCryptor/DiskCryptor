/*
 * The boot loader's side of a power-loss protected transcryption session.
 *
 * After a power loss the header's tmp_size can lag the real boundary and the block being
 * transcribed may be half written; the driver recovers both from its journal ($dclog$) at its
 * mount. The boot loader reads the system volume before that, so it recovers the same boundary
 * with the same journal reader (volume_lib journal.c) and serves a pending block the way the
 * driver will complete it:
 *  - a copy journal (LR_STEP): the block's post-image from the journal;
 *  - a checksum journal (LR_SUM, FF_SAFE_FAST): each 512-byte unit as on the disk if its
 *    checksum matches, transformed if it matches after the step's transform, else zeros
 *    (as dc_safe_complete_sums).
 * Read-only: the driver's recovery finds the journal as the power loss left it.
 */
#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>

#include "include/defines.h"
#include "include/volume_header.h"
#include "include/bootloader.h"
#include "include/dc_header.h"
#include "include/dc_io.h"
#include "volume_lib/journal.h"
#include "volume_lib/header_io.h"

/* journal reads in pieces dc_direct_io takes (a u16 sector count); 1 MiB at any sector size */
#define JR_CHUNK (1024 * 1024)

/* dc_rw_fn over the partition, raw (the journal and the block are read as the disk holds them) */
static int jr_rw(void *ctx, void *buff, u32 length, u64 offset, int is_read)
{
	mount_inf *mount = (mount_inf*)ctx;
	u8        *p     = (u8*)buff;

	if (is_read == 0 || mount->bps == 0 || (offset % mount->bps) != 0 || (length % mount->bps) != 0) {
		return ST_RW_ERR; /* read-only, whole sectors */
	}
	while (length != 0) {
		u32 chunk = (length < JR_CHUNK) ? length : JR_CHUNK;

		if (dc_direct_io(mount, p, (u16)(chunk / mount->bps), offset / mount->bps, 1) == 0) {
			return ST_IO_ERROR;
		}
		p += chunk; offset += chunk; length -= chunk;
	}
	return ST_OK;
}

static void jr_free(u8 *p, u32 len)
{
	if (p != NULL) {
		burn(p, len); /* a decryption's new state is plaintext */
		FreePool(p);
	}
}

/*
 * The pending LR_SUM block of record r, as the driver's dc_safe_complete_sums will write it in
 * place: read from the disk into img, each unit kept, transformed or zeroed. table: the record's
 * checksums (checked against data_crc by dc_journal_pick). Returns the number of torn units.
 */
static u32 jr_resolve_sums(mount_inf *mount, dc_log_rec *r, const u64 *table, u8 *img)
{
	u32 n = r->size / DC_LOG_SUM_UNIT, i, lost = 0;
	u8  unit[DC_LOG_SUM_UNIT];

	for (i = 0; i < n; i++)
	{
		u8 *u  = img + (UINTN)i * DC_LOG_SUM_UNIT;
		u64 uo = r->offs + (u64)i * DC_LOG_SUM_UNIT; /* XTS offset: the partition offset (no VF_NO_REDIR here) */

		if (dc_log_sum64(u) == table[i]) continue; /* written */

		/* not written yet: the old content, transformed as the step did */
		memcpy(unit, u, DC_LOG_SUM_UNIT);
		if (r->dir == LR_REENC) {
			xts_decrypt(unit, unit, DC_LOG_SUM_UNIT, uo, mount->o_key);
			xts_encrypt(unit, unit, DC_LOG_SUM_UNIT, uo, mount->d_key);
		} else if (r->dir == LR_ENC) {
			xts_encrypt(unit, unit, DC_LOG_SUM_UNIT, uo, mount->d_key);
		} else {
			xts_decrypt(unit, unit, DC_LOG_SUM_UNIT, uo, mount->d_key);
		}
		if (dc_log_sum64(unit) == table[i]) {
			memcpy(u, unit, DC_LOG_SUM_UNIT);
			continue;
		}
		/* torn by the power loss: zeros in the new state */
		memset(u, 0, DC_LOG_SUM_UNIT);
		if (r->dir != LR_DEC) {
			xts_encrypt(u, u, DC_LOG_SUM_UNIT, uo, mount->d_key);
		}
		lost++;
	}
	burn(unit, sizeof(unit));
	return lost;
}

int dc_journal_recover(mount_inf *mount, dc_header *header, int from_bak, u32 *lost)
{
	u8         *scratch;
	dc_journal  j;
	dc_dev      dev;
	dc_log_rec *r;
	u8         *data = NULL, *img;
	u32         data_len = 0;
	int         resl;

	*lost = 0;
	mount->pend_off = 0;
	mount->pend_len = 0;
	mount->pend_img = NULL;

	if ( !(header->flags & VF_TMP_MODE) || header->version < DC_HDR_VERSION_2 ||
		 !(header->feature_flags & FF_SAFE_TRANSCRYPT) || mount->bps == 0 )
	{
		return DCS_JR_NONE;
	}

	/* the device in bytes, as the driver's dc_dev_of: the header area is head_len rounded to bps */
	ZeroMem(&dev, sizeof(dev));
	dev.ctx      = mount;
	dev.bps      = mount->bps;
	dev.dsk_size = mount->size * mount->bps;
	dev.head_len = mount->head_len * mount->bps;

	/* pool memory, as every other buffer the loader reads into (BlockIo alignment) */
	if ( (scratch = (u8*)AllocatePool(DC_LOG_SCRATCH)) == NULL ) {
		return DCS_JR_NO_JOURNAL;
	}
	/* the driver's dc_slog_mount: records bound to hdr_ok / hdr_try, or to bak_ok / bak_try when
	 * mounted from the backup header. A journal that cannot be opened (ST_INV_VOLUME): the driver
	 * goes on unprotected; a read error: its read-only mount uses the header's boundary */
	resl = dc_journal_open(&dev, jr_rw, header, dev.head_len, scratch, &j);
	if (resl == ST_OK) {
		resl = dc_journal_scan(&dev, jr_rw, header, from_bak, scratch, &j);
	}
	FreePool(scratch);
	if (resl != ST_OK) {
		return (resl == ST_LOG_CONFLICT) ? DCS_JR_CONFLICT : DCS_JR_NO_JOURNAL;
	}
	while ( (resl = dc_journal_pick(&dev, jr_rw, &j, data)) == ST_SMALL_BUFF && data == NULL ) {
		data_len = j.block_max;
		if ( (data = (u8*)AllocatePool(data_len)) == NULL ) {
			resl = ST_NOMEM;
			break;
		}
	}
	if (resl != ST_OK) {
		jr_free(data, data_len);
		return (resl == ST_LOG_CONFLICT) ? DCS_JR_CONFLICT : DCS_JR_NO_JOURNAL;
	}
	if (j.newest < 0) {
		jr_free(data, data_len);
		return DCS_JR_EXACT;
	}

	/* a valid record is bps aligned (offs and size), so is its end */
	mount->tmp_size = j.boundary / mount->bps;
	if (!j.pending) {
		jr_free(data, data_len);
		return DCS_JR_RECOVERED;
	}

	r = &j.rec[j.newest];
	mount->pend_off = r->offs / mount->bps;
	mount->pend_len = r->size / mount->bps;

	if (r->type == LR_STEP) {
		/* the post-image, data_crc checked: the block exactly as the driver writes it in place */
		mount->pend_img = data;
		return DCS_JR_PENDING;
	}

	/* LR_SUM: data holds the checksum table; the block is rebuilt from the disk with the keys */
	if ( (img = (u8*)AllocatePool(r->size)) == NULL ) {
		jr_free(data, data_len);
		return DCS_JR_QUARANTINE;
	}
	if (jr_rw(mount, img, r->size, r->offs, 1) != ST_OK) {
		/* the driver at its mount leaves such a block pending too (no salvage at the mount) */
		jr_free(img, r->size);
		jr_free(data, data_len);
		return DCS_JR_QUARANTINE;
	}
	*lost = jr_resolve_sums(mount, r, (const u64*)data, img);
	jr_free(data, data_len);
	mount->pend_img = img;
	return DCS_JR_PENDING;
}

/*
 * A primary header whose signature decrypts but whose CRC does not match (a header save torn
 * by a power loss), repaired in memory as the driver's dc_header_recover does (header_io.c
 * dc_header_recover_tmp): the tmp_size of the torn save, or the backup header of this state.
 * Nothing is written; the driver repairs the header on the disk at its mount.
 *
 * password: the one the driver will have at boot, or NULL when it gets none (HandoffMode 3,
 * keys only): the driver then cannot open the backup header, so neither does this - both
 * sides must decide alike.
 * header: the damaged primary, hdr_size bytes (at least a dc_header). On DCS_HR_BACKUP its
 * fields are replaced by the backup's, except the salt: its first 16 bytes are the disk GUID
 * the header key handover to the driver names.
 */
int dc_header_recover_efi(void *block_io, u64 part_sectors, u32 bps, dc_header *header, int hdr_size, dc_pass *password)
{
	mount_inf  dev_m;    /* what jr_rw / dc_direct_io use: BlockIo, bps, size */
	dc_dev     dev;
	dc_header *hb = NULL;
	u64        hints[DC_REPAIR_HINTS];
	u64       *cand = NULL;
	u64        dsk = part_sectors * bps;
	u32        blen = 0;
	int        n_hints = 0, r, res;
	u8         dk[PKCS_DERIVE_MAX];

	if (header == NULL || hdr_size < (int)sizeof(dc_header) || bps == 0 || part_sectors == 0) {
		return DCS_HR_DAMAGED;
	}
	ZeroMem(&dev_m, sizeof(dev_m));
	dev_m.BlockIo = block_io;
	dev_m.bps     = bps;
	dev_m.size    = part_sectors;
	ZeroMem(&dev, sizeof(dev));
	dev.ctx      = &dev_m;
	dev.bps      = bps;
	dev.dsk_size = dsk;

	/* the backup header (head_len lies in sector 1, unchanged by a session's saves). It has its
	 * own salt, so the password goes through the key derivation again */
	if ( password != NULL &&
		 (blen = dc_header_backup_len(header, dsk, bps)) != 0 &&
		 (hb = (dc_header*)AllocatePool(blen)) != NULL )
	{
		if ( jr_rw(&dev_m, hb, blen, dsk - blen, 1) != ST_OK ||
			 dc_decrypt_header(hb, (int)blen, password, NULL, dk, NULL, NULL) == 0 ||
			 !dc_header_same_state(header, hb) )
		{
			burn(hb, blen);
			FreePool(hb);
			hb = NULL;
		}
	}

	/* the journal's values are candidates too */
	if ( (header->flags & VF_TMP_MODE) &&
		 (cand = (u64*)AllocatePool(sizeof(u64) * DC_REPAIR_CAND)) != NULL )
	{
		n_hints = dc_journal_tmp_hints(&dev, jr_rw, header, hints, DC_REPAIR_HINTS);
	}
	r = dc_header_recover_tmp(header, hb, dsk, bps, hints, n_hints, cand);
	if (cand != NULL) FreePool(cand);

	if (r == DC_REPAIR_TMP) {
		res = DCS_HR_REPAIRED;
	} else if (r == DC_REPAIR_BACKUP) {
		u8 salt[HEADER_SALT_SIZE];

		memcpy(salt, header->salt, sizeof(salt));
		memcpy(header, hb, sizeof(dc_header));
		memcpy(header->salt, salt, sizeof(salt));
		burn(salt, sizeof(salt));
		res = DCS_HR_BACKUP;
	} else {
		res = DCS_HR_DAMAGED; /* DC_REPAIR_NONE / DC_REPAIR_BAD */
	}
	if (hb != NULL) {
		burn(hb, blen);
		FreePool(hb);
	}
	burn(dk, sizeof(dk));
	return res;
}
