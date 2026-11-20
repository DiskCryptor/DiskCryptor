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
#ifndef _HEADER_IO_H_
#define _HEADER_IO_H_

#include "defines.h"
#include "volume_header.h"
#include "xts_fast.h"
#include "dc_dev.h"
/* HF_* - the flags argument below */
#include "dc_status.h"

int io_read_header_full(dc_dev *dev, dc_rw_fn rw, u64 pos, dc_header **header, xts_key *hdr_key, int hdr_len);
int io_read_header(dc_dev *dev, dc_rw_fn rw, u64 pos, dc_header **header, xts_key **out_key, dc_pass *password, int* out_kdf, ULONG *interrupt_cmd);
int io_write_header(dc_dev *dev, dc_rw_fn rw, u64 pos, dc_header *header, xts_key *hdr_key, dc_pass *password, u32 flags, ULONG *interrupt_cmd);

unsigned long calculate_header_crc(dc_header* header);

BOOLEAN is_volume_header_correct(dc_header *header);
/* signature right, CRC (or footer) wrong - see header_io.c */
BOOLEAN is_volume_header_damaged(dc_header *header);
int dc_header_repair_tmp(dc_header *header, const u64 *cand, int n);

/*
 * The decisions of a torn header's recovery, shared by the driver (mount.c dc_header_recover)
 * and the boot loader (DCS). The caller does the I/O: it decrypts the backup header
 * (dc_header_backup_len says where and whether), keeps it only when dc_header_same_state, gets
 * the journal's hints (journal.h dc_journal_tmp_hints) and calls dc_header_recover_tmp.
 */
#define DC_REPAIR_STEP_BLOCK (8 * 1024 * 1024) /* a transcryption step (the driver's ENC_BLOCK_SIZE, asserted there) */
#define DC_REPAIR_STEP_WIPE  (1280 * 1024)     /* a wiping session's step (DC_WIPE_BLOCK, asserted there) */
#define DC_REPAIR_STEPS      64                /* per direction and step size: 512 MiB of 8 MiB steps */
#define DC_REPAIR_HINTS      12                /* dc_journal_tmp_hints: 6 per record */
#define DC_REPAIR_ENDS       5                 /* the data end variants and the session start */
#define DC_REPAIR_CAND       (4 * DC_REPAIR_STEPS + DC_REPAIR_ENDS + DC_REPAIR_HINTS) /* the candidate buffer, u64s */

#define DC_REPAIR_NONE    0   /* nothing fits and no backup: damaged (or taken as it is, on request) */
#define DC_REPAIR_BACKUP  1   /* use the backup header */
#define DC_REPAIR_TMP     2   /* tmp_size restored in place, the header validates */
#define DC_REPAIR_BAD    -1   /* a tmp_size fitted but gives no usable header: damaged */

/* length of the backup header at dsk_size - len, or 0 when h has none (or it would not fit) */
u32 dc_header_backup_len(const dc_header *h, u64 dsk_size, u32 bps);
/* hb is a backup of h's session state: the fields a session's saves leave alone agree */
BOOLEAN dc_header_same_state(const dc_header *h, const dc_header *hb);
/* hb: the same-state backup or NULL; hints: n_hints journal values; cand: DC_REPAIR_CAND u64s
   of scratch, or NULL (no tmp_size repair). Returns DC_REPAIR_* */
int dc_header_recover_tmp(dc_header *h, const dc_header *hb, u64 dsk_size, u32 bps, const u64 *hints, int n_hints, u64 *cand);
/* the geometry of a decrypted header fits a device of dsk_size bytes with bps-byte sectors:
   ST_OK or ST_INV_VOLUME; may clear VF_BACKUP_HEADER - see header_io.c */
int dc_check_header_geometry(dc_header *hcopy, u64 dsk_size, u32 bps);


int get_ext_header(dc_header *header, dc_ext_header **out_ext_hdr);

#endif