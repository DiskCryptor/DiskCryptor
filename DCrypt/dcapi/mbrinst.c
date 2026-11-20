/*
    *
    * DiskCryptor - open source partition encryption tool
	* Copyright (c) 2007-2008 
	* ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
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

#include <windows.h>
#include <stdio.h>
#include "dcconst.h"
#include "volume_header.h"
#include "bootloader.h"
#include "mbrinst.h"
#include "dcres.h"
#include "misc.h"
#include "ntdll.h"
#include "iso_fs.h"
#include "drv_ioctl.h"

#define OLD_SIGN      0x20B60251
#define NEW_SIGN      0x10EB9090
#define DC_ISO_SIZE   1835008
#define BOOT_MAX_SIZE (2048 * 1024)
#define K64_SIZE      (64 * 1024)

u64 dc_dsk_get_size(int dsk_num, int precision) 
{
	dc_disk_p       *dp = NULL;
	u64              mid, size  = 0;
	u64              high, low;
	u64              bps, pos;
	u32              bytes;
	DISK_GEOMETRY_EX dgx;
	u8               buff[SECTOR_SIZE];

	do
	{
		if ( (dp = dc_disk_open(dsk_num, 0)) == NULL ) {
			break;
		}
		
		if (DeviceIoControl(
			 dp->hdisk, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, 
			 NULL, 0, &dgx, sizeof(dgx), &bytes, NULL)) 
		{
			size = dgx.DiskSize.QuadPart; break;
		}

		bps  = d64(dp->bps);
		high = ( (d64(dp->spc) * bps) + dp->size) / bps;
		low  = dp->size / bps;	
		size = dp->size;

		/* binary search disk space in hidden cylinder */
		if (precision != 0) 
		{
			do
			{
				mid = (high + low) / 2;
				pos = mid * bps;

				if (dc_disk_read(dp, buff, sizeof(buff), pos) == ST_OK) {
					low = mid+1; 
				} else {
					high = mid-1;
				}

				if (high <= low) {
					size = low * bps; break;
				}
			} while (1);
		}
	} while (0);

	if (dp != NULL) {
		dc_disk_close(dp);
	}

	return size;
}

static
mbr_config *dc_find_conf(char *data, u32 size)
{
	mbr_config *cnf;
	mbr_config *conf = NULL;

	for (; size > sizeof(mbr_config); size--, data++)
	{
		cnf = pv(data);

		if ( (cnf->sign1 == LDR_CFG_SIGN1) && (cnf->sign2 == LDR_CFG_SIGN2) ) {
			conf = cnf;	break;
		}
	}

	return conf;
}

int dc_make_iso(wchar_t *file, int small_boot)
{
	u8   *isobuf = NULL;
	int   bootsz, ldrsz;
	void *boot, *loader;	
	int   resl;

	do
	{
		struct iso_primary_descriptor *pd, *bd, *td;
		struct iso_path_table         *pt;
		struct iso_directory_record   *dr;
		struct iso_validation_entry   *ve;
		struct iso_initial_entry      *ie;
		
		if ( (isobuf = calloc(1, DC_ISO_SIZE)) == NULL ) {
			resl = ST_NOMEM; break;
		}
		if ( (boot = dc_extract_rsrc(&bootsz, IDR_MBR)) == NULL ) {
			resl = ST_ERROR; break;
		}
		if (small_boot != 0) {
			loader = dc_extract_rsrc(&ldrsz, IDR_DCLDR_SMALL);
		} else {
			loader = dc_extract_rsrc(&ldrsz, IDR_DCLDR);
		}
		if (loader == NULL) {
			resl = ST_ERROR; break;
		}
		/*
		  for more information please read 
		    http://users.pandora.be/it3.consultants.bvba/handouts/ISO9960.html
			http://www.phoenix.com/NR/rdonlyres/98D3219C-9CC9-4DF5-B496-A286D893E36A/0/specscdrom.pdf
		*/
		pd = addof(isobuf, 0x8000);
		bd = addof(isobuf, 0x8800);
		td = addof(isobuf, 0x9000);
		pt = addof(isobuf, 0xA000);
		dr = addof(isobuf, 0xC000);
		ve = addof(isobuf, 0xC800);
		ie = addof(isobuf, 0xC820);
		/* primary volume descriptor */
		pd->type[0] = ISO_VD_PRIMARY;
		mincpy(pd->id, ISO_STANDARD_ID, sizeof(ISO_STANDARD_ID));
		pd->version[0] = 1;
		mincpy(pd->volume_id, "DiskCryptor boot disk           ", 32);
		p32(pd->volume_space_size)[0] = DC_ISO_SIZE / ISOFS_BLOCK_SIZE;
		p32(pd->volume_space_size)[1] = BE32(DC_ISO_SIZE / ISOFS_BLOCK_SIZE);
		p32(pd->volume_set_size)[0] = 0x01000001;
		p32(pd->volume_sequence_number)[0] = 0x01000001;
		p32(pd->logical_block_size)[0] = 0x00080800;
		pd->path_table_size[0] = 0x0A;
		pd->path_table_size[7] = 0x0A;
		pd->type_l_path_table[0] = 0x14;
		pd->root_directory_record[0] = 0x22;
		pd->root_directory_record[2] = 0x18;
		/* boot record volume descriptor */
		bd->type[0] = ISO_VD_BOOT;
		mincpy(bd->id, ISO_STANDARD_ID, sizeof(ISO_STANDARD_ID));
		bd->version[0] = 1;
		mincpy(bd->system_id, "EL TORITO SPECIFICATION", 23);
		bd->volume_id[31] = 0x19;
		/* volume descriptor set terminator */
		td->type[0] = ISO_VD_END;
		mincpy(td->id, ISO_STANDARD_ID, sizeof(ISO_STANDARD_ID));
		td->version[0] = 1;
		/* iso path table */
		pt->name_len[0] = 1;
		pt->extent[0] = 0x18;
		pt->parent[0] = 1;
		/* root directory record */
		dr[0].length[0] = sizeof(struct iso_directory_record);
		dr[0].ext_attr_length[0] = 0x18;
		dr[0].extent[6] = 0x18;
		dr[0].size[0] = 0x08;
		dr[0].size[5] = 0x08;
		dr[0].date[6] = 0x02;
		dr[0].interleave[0] = 0x01;
		p32(dr[0].volume_sequence_number + 2)[0] = 0x00000101;
		dr[1].length[0] = sizeof(struct iso_directory_record);
		dr[1].ext_attr_length[0] = 0x18;
		dr[1].extent[6] = 0x18;
		dr[1].size[0] = 0x08;
		dr[1].size[5] = 0x08;
		dr[1].date[6] = 0x02;
		dr[1].interleave[0] = 0x01;
		p32(dr[1].volume_sequence_number + 2)[0] = 0x00010101;
		/* validation entry */
		ve->header_id[0] = 1;
		ve->checksum[0] = 0xAA;
		ve->checksum[1] = 0x55;
		ve->key_byte1[0] = 0x55;
		ve->key_byte2[0] = 0xAA;
		/* initial/default entry */
		ie->boot_indicator[0] = 0x88;
		ie->media_type[0] = 0x02; /* 1.44m diskette emulation */
		ie->sector_count[0] = 1;
		ie->load_rba[0] = 26; /* sector number */
		/* copy boot sector */
		memcpy(isobuf + 0xD000, boot, SECTOR_SIZE);
		/* copy bootloader */
		memcpy(isobuf + 0xD200, loader, ldrsz);

		/* write image to file */
		resl = save_file(file, isobuf, DC_ISO_SIZE);
	} while (0);

	if (isobuf != NULL) {
		free(isobuf);
	}

	return resl;
}

int dc_make_pxe(wchar_t *file, int small_boot)
{
	u8   *isobuf = NULL;
	int   ldrsz, resl;
	void *loader;
	
	do
	{
		if (small_boot != 0) {
			loader = dc_extract_rsrc(&ldrsz, IDR_DCLDR_SMALL);
		} else {
			loader = dc_extract_rsrc(&ldrsz, IDR_DCLDR);
		}
		if (loader == NULL) {
			resl = ST_ERROR; break;
		}
		/* write image to file */
		resl = save_file(file, loader, ldrsz);
	} while (0);

	if (isobuf != NULL) {
		free(isobuf);
	}
	return resl;
}


int dc_get_boot_disk(int *dsk_1, int *dsk_2)
{
	drive_inf info;
	int       resl;

	resl = dc_get_drive_info(
		L"\\\\.\\GLOBALROOT\\ArcName\\multi(0)disk(0)rdisk(0)partition(1)", &info);

	if ( (resl != ST_OK) || (info.dsk_num > 2) ) {
		resl = ST_NF_BOOT_DEV;
	} else 
	{
		if (info.dsk_num > 1) {
			*dsk_1 = info.disks[0].number;
			*dsk_2 = info.disks[1].number;
		} else {
			*dsk_1 = info.disks[0].number;
			*dsk_2 = info.disks[0].number;
		}
	}
	return resl;
}

static int dc_format_media_and_set_boot(
			 HANDLE h_device, wchar_t *root, int dsk_num, DISK_GEOMETRY *dg, int small_boot
			 )
{
	u8                        buff[sizeof(DRIVE_LAYOUT_INFORMATION) + 
		                           sizeof(PARTITION_INFORMATION) * 3];
	PDRIVE_LAYOUT_INFORMATION dli = pv(buff);
	u64                       d_size;
	u32                       bytes;
	int                       resl, succs;
	int                       locked;
	u8                       *mbr_sec;
	
	locked = 0; mbr_sec = NULL;
	do
	{
		d_size = d64(dg->Cylinders.QuadPart) * d64(dg->SectorsPerTrack) * 
			     d64(dg->TracksPerCylinder)  * d64(dg->BytesPerSector);

		if (d_size < K64_SIZE) {
			resl = ST_NF_SPACE; break;
		}

		succs = DeviceIoControl(
			h_device, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &bytes, NULL);

		if (succs == 0) {
			resl = ST_LOCK_ERR; break;
		} else {
			locked = 1;
		}

		DeviceIoControl(
			h_device, IOCTL_DISK_DELETE_DRIVE_LAYOUT, NULL, 0, NULL, 0, &bytes, NULL);

		if ( (mbr_sec = malloc(dg->BytesPerSector)) == NULL ) {
			resl = ST_NOMEM; break;
		}
		memset(mbr_sec, 0, dg->BytesPerSector);
		memset(buff, 0, sizeof(buff));

		WriteFile(h_device, mbr_sec, dg->BytesPerSector, &bytes, NULL);
		
		dli->PartitionCount = 4;
		dli->Signature      = 0;
		dli->PartitionEntry[0].StartingOffset.QuadPart  = K64_SIZE;
		dli->PartitionEntry[0].PartitionLength.QuadPart = d_size - K64_SIZE;
		dli->PartitionEntry[0].HiddenSectors            = 0;
		dli->PartitionEntry[0].PartitionNumber          = 0;
		dli->PartitionEntry[0].PartitionType            = PARTITION_FAT32;
		dli->PartitionEntry[0].BootIndicator            = TRUE;
		dli->PartitionEntry[0].RecognizedPartition      = TRUE;
		dli->PartitionEntry[0].RewritePartition         = TRUE;

		succs = DeviceIoControl(
			h_device, IOCTL_DISK_SET_DRIVE_LAYOUT, dli, sizeof(buff), NULL, 0, &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		DeviceIoControl(
			h_device, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &bytes, NULL);

		succs = DeviceIoControl(
			h_device, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &bytes, NULL);

		if (succs != 0) { locked = 0; }

		CloseHandle(h_device); h_device = NULL;

		if ( (resl = dc_format_fs(root, L"FAT32")) != ST_OK ) {
			break;
		}		
		resl = dc_set_mbr(dsk_num, 1, small_boot);
	} while(0);

	if ( (locked != 0) && (h_device != NULL) ) {
		DeviceIoControl(h_device, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &bytes, NULL);
	}
	if (h_device != NULL) {
		CloseHandle(h_device);
	}
	if (mbr_sec != NULL) {
		free(mbr_sec);
	}
	return resl;
}

static int dc_is_mbr_present(int dsk_num)
{
	dc_disk_p *dp;
	dc_mbr     mbr;
	int        resl;

	do
	{
		if ( (dp = dc_disk_open(dsk_num, 0)) == NULL ) {
			resl = ST_ERROR; break;
		}

		if ( (resl = dc_disk_read(dp, &mbr, sizeof(mbr), 0)) != ST_OK ) {
			break;
		}

		if ( (mbr.magic != 0xAA55) || (dc_fs_type(pv(&mbr)) != FS_UNK) ) {
			resl = ST_MBR_ERR; break;
		} else {
			resl = ST_OK;
		}
	} while (0);

	if (dp != NULL) {
		dc_disk_close(dp);
	}

	return resl;
}

/* a GPT protective (or hybrid) MBR: an entry of type 0xEE */
static int dc_mbr_has_gpt_entry(const dc_mbr *mbr)
{
	int i;

	for (i = 0; i < 4; i++) {
		if (mbr->pt[i].os == 0xEE) return 1;
	}
	return 0;
}

/* 1 if the MBR of the disk could be read and is a GPT protective MBR */
static int dc_disk_is_gpt_mbr(int dsk_num)
{
	dc_mbr     mbr;
	dc_disk_p *dp;
	int        is_gpt = 0;

	if ( (dp = dc_disk_open(dsk_num, 0)) == NULL ) return 0;

	if ( (IS_INVALID_SECTOR_SIZE(dp->bps) == 0) && (dc_disk_read(dp, &mbr, sizeof(mbr), 0) == ST_OK) &&
		 (mbr.magic == 0xAA55) && dc_mbr_has_gpt_entry(&mbr) ) {
		is_gpt = 1;
	}
	dc_disk_close(dp);
	return is_gpt;
}

int dc_set_boot(wchar_t *root, int format, int small_boot)
{
	wchar_t               disk[MAX_PATH];
	HANDLE                hdisk   = NULL;
	int                   resl, succs;
	u32                   bytes;	
	DISK_GEOMETRY         dg;
	STORAGE_DEVICE_NUMBER d_num;
	
	if (root[0] != L'\\') 
	{
		_snwprintf(
			disk, countof(disk), L"\\\\.\\%c:", root[0]);
	} else {
		wcsncpy(disk, root, countof(disk));
	}

	do
	{
		/* open partition */
		hdisk = CreateFile(
			disk, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		if (hdisk == INVALID_HANDLE_VALUE) {			
			resl = ST_ACCESS_DENIED; hdisk = NULL; break;
		}

		succs = DeviceIoControl(
			hdisk, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &dg, sizeof(dg), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		if (dg.MediaType != RemovableMedia) {
			resl = ST_INV_MEDIA_TYPE; break;
		}

		if (IS_INVALID_SECTOR_SIZE(dg.BytesPerSector) != 0) {
			resl = ST_INV_SECT; break;
		}

		succs = DeviceIoControl(
			hdisk, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &d_num, sizeof(d_num), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		if (format == 0) 
		{
			if (dc_is_mbr_present(d_num.DeviceNumber) != ST_OK) {
				resl = ST_FORMAT_NEEDED; break;
			}
			/* a GPT medium needs the MBR layout of a format (dc_set_mbr refuses GPT disks) */
			if (dc_disk_is_gpt_mbr(d_num.DeviceNumber) != 0) {
				resl = ST_FORMAT_NEEDED; break;
			}

			if ( (resl = dc_set_mbr(d_num.DeviceNumber, 1, small_boot)) == ST_NF_SPACE )
			{
				if ( (resl = dc_set_mbr(d_num.DeviceNumber, 0, small_boot)) == ST_NF_SPACE ) {
					resl = ST_FORMAT_NEEDED;
				}
			}
		} else
		{
			resl  = dc_format_media_and_set_boot(hdisk, disk, d_num.DeviceNumber, &dg, small_boot);
			hdisk = NULL;
		}	
	} while (0);

	if (hdisk != NULL) {
		CloseHandle(hdisk);
	}
	return resl;
}

/* allow_gpt: dc_update_boot only - rewrites an installed loader (possibly on a hybrid MBR),
   where refusing after dc_unset_mbr would leave the disk without a loader */
static int dc_set_mbr_i(int dsk_num, int begin, int small_boot, int allow_gpt)
{
	dc_mbr      mbr;
	dc_mbr      old_mbr;
	u64         dsk_sze;
	u64         max_end;
	u64         min_str;
	u64         ldr_off;
	mbr_config *conf;
	pt_ent     *pt;
	void       *data, *n_data;
	int         size, i;
	int         resl, n_size;
	dc_disk_p  *dp;

	dp = NULL; n_data = NULL;
	do
	{
		if ( (dp = dc_disk_open(dsk_num, 0)) == NULL ) {
			resl = ST_ERROR; break;
		}

		if (IS_INVALID_SECTOR_SIZE(dp->bps) != 0) {
			resl = ST_INV_SECT; break;
		}

		if (data = dc_extract_rsrc(&size, IDR_MBR)) {
			memcpy(&mbr, data, sizeof(mbr));
		} else {
			resl = ST_ERROR; break;
		}

		if (small_boot != 0) {
			data = dc_extract_rsrc(&size, IDR_DCLDR_SMALL);
		} else {
			data = dc_extract_rsrc(&size, IDR_DCLDR);
		}
		if (data == NULL) {
			resl = ST_ERROR; break;
		}

		/* align dcldr size to sector size */
		n_size = _align(size, SECTOR_SIZE);
		n_data = malloc(n_size);

		if (n_data == NULL) {
			resl = ST_NOMEM; break;
		}

		memset(n_data, 0, n_size);
		memcpy(n_data, data, size);

		if ( (conf = dc_find_conf(n_data, n_size)) == NULL ) {
			resl = ST_ERROR; break;
		}

		/* get disk size */
		if ( (dsk_sze = dc_dsk_get_size(dsk_num, 1)) == 0 ) {			
			resl = ST_IO_ERROR; break;
		}

		/* read disk MBR */
		if ( (resl = dc_disk_read(dp, &old_mbr, sizeof(old_mbr), 0)) != ST_OK ) {
			break;
		}

		if ( (old_mbr.magic != 0xAA55) || (dc_fs_type(pv(&old_mbr)) != FS_UNK) ) {
			resl = ST_MBR_ERR; break;
		}

		if ( (old_mbr.sign == NEW_SIGN) || (old_mbr.sign == OLD_SIGN) ) {
			resl = ST_BLDR_INSTALLED; break;
		}

		/* never a new install on a GPT disk: on a disk over 2 TiB (entry capped at 0xFFFFFFFF
		   sectors) or with a hybrid MBR the space check below can pass, and the loader would
		   overwrite the backup GPT and the end of the last partition */
		if ( (allow_gpt == 0) && dc_mbr_has_gpt_entry(&old_mbr) ) {
			resl = ST_MBR_ERR; break;
		}

		/* finds free space before and after partitions */
		min_str = 64; max_end = 0;
		for (i = 0, max_end = 0; i < 4; i++) 
		{
			if ( (pt = &old_mbr.pt[i])->prt_size == 0 ) {
				continue;
			}

			min_str = min(min_str, pt->start_sect);
			max_end = max(max_end, pt->start_sect + pt->prt_size);
		}
		max_end *= d64(dp->bps); min_str *= d64(dp->bps);

		if (begin != 0) 
		{
			if (min_str < n_size + SECTOR_SIZE) {
				resl = ST_NF_SPACE; break;
			}
			ldr_off = SECTOR_SIZE;		
		} else 
		{
			ldr_off = dsk_sze - n_size - (8 * SECTOR_SIZE); /* reserve last 8 sectors for LDM data */

			if (max_end > ldr_off) {
				resl = ST_NF_SPACE; break;
			}
		}
		/* set OP_SMALL_BOOT if needed */
		if (small_boot != 0) {
			conf->options |= LDR_OP_SMALL_BOOT;
		}
		/* save old MBR */
		memcpy(conf->save_mbr, &old_mbr, sizeof(old_mbr));

		/* prepare new MBR */
		memcpy(mbr.data, old_mbr.data, sizeof(mbr.data));

		mbr.set.sector = ldr_off / SECTOR_SIZE;
		mbr.set.numb   = n_size / SECTOR_SIZE;

		/* write bootloader data */
		if ( (resl = dc_disk_write(dp, n_data, n_size, ldr_off)) != ST_OK ) {
			break;
		}		
		if ( (resl = dc_disk_write(dp, &mbr, sizeof(mbr), 0)) != ST_OK ) {
			break;
		}
	} while (0);

	if (dp != NULL) {
		dc_disk_close(dp);
	}
	if (n_data != NULL) {
		free(n_data);
	}	
	return resl;
}

static int dc_set_mbr_ex(int dsk_num, int begin, int small_boot, int allow_gpt)
{
	DC_FLAGS flags;
	int      dsk_1, dsk_2;
	int      resl;

	if (small_boot == -1)
	{
		if (dc_device_control(DC_CTL_GET_FLAGS, NULL, 0, &flags, sizeof(flags)) == NO_ERROR) {
			small_boot = (flags.load_flags & DST_SMALL_MEM) != 0;
		} else {
			small_boot = 0;
		}
	}
	/* if dsk_num == -1 then find boot disk */
	if (dsk_num == -1) 
	{
		resl = dc_get_boot_disk(&dsk_1, &dsk_2);

		/* a mirror: refuse before writing either disk, not after the first one is written */
		if ( (resl == ST_OK) && (allow_gpt == 0) && (dc_disk_is_gpt_mbr(dsk_1) || dc_disk_is_gpt_mbr(dsk_2)) ) {
			resl = ST_MBR_ERR;
		}
		if (resl == ST_OK)
		{
			resl = dc_set_mbr_i(dsk_1, begin, small_boot, allow_gpt);

			if ( (resl == ST_OK) && (dsk_1 != dsk_2) ) {
				resl = dc_set_mbr_i(dsk_2, begin, small_boot, allow_gpt);
			}
		}
	} else {
		resl = dc_set_mbr_i(dsk_num, begin, small_boot, allow_gpt);
	}
	return resl;
}

int dc_set_mbr(int dsk_num, int begin, int small_boot)
{
	return dc_set_mbr_ex(dsk_num, begin, small_boot, 0);
}

int dc_has_dc_mbr(int dsk_num)
{
	dc_mbr      mbr;
	int         resl;
	dc_disk_p  *dp;

	dp = NULL;
	do
	{
		if ((dp = dc_disk_open(dsk_num, 0)) == NULL) {
			resl = ST_ERROR; break;
		}

		if (IS_INVALID_SECTOR_SIZE(dp->bps) != 0) {
			resl = ST_INV_SECT; break;
		}

		/* read disk MBR */
		if ((resl = dc_disk_read(dp, &mbr, sizeof(mbr), 0)) != ST_OK) {
			break;
		}

		if ((mbr.magic != 0xAA55) || (dc_fs_type(pv(&mbr)) != FS_UNK)) {
			resl = ST_MBR_ERR; break;
		}

		if ((mbr.sign != NEW_SIGN) && (mbr.sign != OLD_SIGN)) {
			resl = ST_NF_FILE; break;
		}

		resl = ST_OK;
	} while (0);

	return resl;
}

static
int get_ldr_body_ptr(dc_disk_p *dp, dc_mbr *mbr, u64 *start, int *size)
{
	int resl;

	do
	{
		if ( (resl = dc_disk_read(dp, mbr, sizeof(dc_mbr), 0)) != ST_OK ) {
			break;
		}

		if (mbr->magic != 0xAA55) {
			resl = ST_MBR_ERR; break;
		}

		if ( (mbr->sign != NEW_SIGN) && (mbr->sign != OLD_SIGN) ) {
			resl = ST_BLDR_NOTINST; break;
		}

		*start = mbr->set.sector * SECTOR_SIZE;
		*size  = mbr->set.numb   * SECTOR_SIZE;
	} while (0);

	return resl;
}

int dc_get_mbr_config(
	  int dsk_num, wchar_t *file, ldr_config *conf
	  )
{
	mbr_config *cnf;
	HANDLE      hfile;
	void       *data;
	int         size, resl;
	dc_mbr      mbr;		
	u64         offs;
	u32         bytes;
	int         dsk_2;
	dc_disk_p  *dp;

	hfile = NULL; dp = NULL; data = NULL;
	do
	{
		/* if dsk_num == -1 then find boot disk */
		if (dsk_num == -1) 
		{
			if ( (resl = dc_get_boot_disk(&dsk_num, &dsk_2)) != ST_OK ) {
				break;
			}
		}

		if (file != NULL) 
		{
			/* open file */
			hfile = CreateFile(
				file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

			if (hfile == INVALID_HANDLE_VALUE) {
				resl  = ST_NF_FILE;
				hfile = NULL; break;
			}

			/* get size of file */
			size = GetFileSize(hfile, NULL);

			if ( (size == 0) || (size > BOOT_MAX_SIZE) ) {
				resl = ST_INV_BLDR_SIZE; break;
			}
		} else 
		{
			if ( (dp = dc_disk_open(dsk_num, 0)) == NULL ) {
				resl = ST_ACCESS_DENIED; break;
			}
			/* get bootloader body offset */
			if ( (resl = get_ldr_body_ptr(dp, &mbr, &offs, &size)) != ST_OK ) {
				break;
			}
		}

		/* load bootloader body */
		if ( (data = malloc(size)) == NULL ) {
			resl = ST_NOMEM; break;
		}
		
		if (file != NULL) 
		{
			/* read bootloader body from file */
			if (ReadFile(hfile, data, size, &bytes, NULL) == FALSE) {
				resl = ST_IO_ERROR; break;
			}
		} else 
		{
			/* read bootloader body from disk */
			if ( (resl = dc_disk_read(dp, data, size, offs)) != ST_OK ) {				
				break;
			}
		}

		/* find bootloader config */
		if ( (cnf = dc_find_conf(data, size)) == NULL ) {
			resl = ST_BLDR_NO_CONF; break;
		}

		memset(conf, 0, sizeof(ldr_config));
		if (cnf->ldr_ver <= DC_BOOT_OLD)
			memcpy(conf, cnf, sizeof(mbr_config));
		else
			memcpy(conf, cnf, sizeof(ldr_config));
		resl = ST_OK;
	} while (0);

	if (data != NULL)  { free(data); }
	if (hfile != NULL) { CloseHandle(hfile); }
	if (dp != NULL)    { dc_disk_close(dp); }

	return resl;
}

static
int dc_set_mbr_config_i(
	  int dsk_num, wchar_t *file, ldr_config *conf
	  )
{
	u8          old_mbr[512];
	u32			version;
	HANDLE      hfile;
	int         size, resl;
	mbr_config *cnf;
	dc_mbr      mbr;
	void       *data;	
	u64         offs;
	u32         bytes;
	dc_disk_p  *dp;
	
	dp = NULL; hfile = NULL; data = NULL;
	do
	{
		if (file != NULL) 
		{
			/* open file */
			hfile = CreateFile(
				file, GENERIC_READ | GENERIC_WRITE, 
				FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

			if (hfile == INVALID_HANDLE_VALUE) {
				resl  = ST_NF_FILE;
				hfile = NULL; break;
			}

			/* get size of file */
			size = GetFileSize(hfile, NULL);

			if ( (size == 0) || (size > BOOT_MAX_SIZE) ) {
				resl = ST_INV_BLDR_SIZE; break;
			}
		} else 
		{
			if ( (dp = dc_disk_open(dsk_num, 0)) == NULL ) {
				resl = ST_ACCESS_DENIED; break;
			}
			/* get bootloader body offset */
			if ( (resl = get_ldr_body_ptr(dp, &mbr, &offs, &size)) != ST_OK ) {
				break;
			}
		}

		/* load bootloader body */
		if ( (data = malloc(size)) == NULL ) {
			resl = ST_NOMEM; break;
		}

		if (file != NULL) 
		{
			/* read bootloader body from file */
			if (ReadFile(hfile, data, size, &bytes, NULL) == FALSE) {
				resl = ST_IO_ERROR; break;
			}
		} else 
		{
			/* read bootloader body from disk */
			if ( (resl = dc_disk_read(dp, data, size, offs)) != ST_OK ) {
				break;
			}
		}

		/* find bootloader config */
		if ( (cnf = dc_find_conf(data, size)) == NULL ) {
			resl = ST_BLDR_NO_CONF; break;
		}

		/* save current version */
		version = cnf->ldr_ver;
		/* save old mbr */
		memcpy(old_mbr, cnf->save_mbr, sizeof(old_mbr));
		/* copy new values to config */
		if (version <= DC_BOOT_OLD)
			memcpy(cnf, conf, sizeof(mbr_config));
		else
			memcpy(cnf, conf, sizeof(ldr_config));
		/* restore current version */
		cnf->ldr_ver = version;
		/* restore old mbr */
		memcpy(cnf->save_mbr, old_mbr, sizeof(old_mbr));
		/* set unchangeable fields to default */
		cnf->sign1 = LDR_CFG_SIGN1; cnf->sign2 = LDR_CFG_SIGN2;
		
		if (file != NULL) 
		{
			/* save bootloader body to file */
			SetFilePointer(hfile, 0, NULL, FILE_BEGIN);
			SetEndOfFile(hfile);

			if (WriteFile(hfile, data, size, &bytes, NULL) == FALSE) {
				resl = ST_IO_ERROR; break;
			}
		} else 
		{
			/* save bootloader body to disk */
			if ( (resl = dc_disk_write(dp, data, size, offs)) != ST_OK ) {
				break;
			}
		}
		resl = ST_OK;
	} while (0);

	if (data != NULL)  { free(data); }
	if (hfile != NULL) { CloseHandle(hfile); }
	if (dp != NULL)    { dc_disk_close(dp); }

	return resl;
}

int dc_set_mbr_config(
	  int dsk_num, wchar_t *file, ldr_config *conf
	  )
{
	int dsk_1, dsk_2;
	int resl;

	/* if dsk_num == -1 then find boot disk */
	if (dsk_num == -1) 
	{
		resl = dc_get_boot_disk(&dsk_1, &dsk_2);

		if (resl == ST_OK)
		{
			resl = dc_set_mbr_config_i(dsk_1, file, conf);

			if ( (resl == ST_OK) && (dsk_1 != dsk_2) ) {
				resl = dc_set_mbr_config_i(dsk_2, file, conf);
			}
		}
	} else {
		resl = dc_set_mbr_config_i(dsk_num, file, conf);
	}

	return resl;
}

int dc_mbr_config_by_partition(
      wchar_t *root, int set_conf, ldr_config *conf
	  )
{
	HANDLE        hdisk;
	wchar_t       name[MAX_PATH];
	DISK_GEOMETRY dg;
	drive_inf     info;
	int           resl, succs;
	u32           bytes;
	
	if (root[0] != L'\\')
	{
		_snwprintf(
			name, countof(name), L"\\\\.\\%c:", root[0]);
	} else {
		wcsncpy(name, root, countof(name));
	}

	info.dsk_num = 0;
	do
	{
		/* open partition */
		hdisk = CreateFile(
			name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		if (hdisk == INVALID_HANDLE_VALUE) {			
			resl  = ST_ACCESS_DENIED;
			hdisk = NULL; break;
		}

		succs = DeviceIoControl(
			hdisk, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &dg, sizeof(dg), &bytes, NULL);

		if (succs == 0) {
			resl = ST_ERROR; break;
		}

		if ( (dg.MediaType == FixedMedia) || (dg.MediaType == RemovableMedia) )
		{
			if ( (resl = dc_get_drive_info(name, &info)) != ST_OK ) {
				break;
			}
		} else  {
			resl = ST_INV_MEDIA_TYPE; break;		
		}

		if (set_conf != 0) {
			resl = dc_set_mbr_config(info.disks[0].number, NULL, conf);
		} else {
			resl = dc_get_mbr_config(info.disks[0].number, NULL, conf);
		}
	} while (0);

	if (hdisk != NULL) {
		CloseHandle(hdisk);
	}

	return resl;
}


static int dc_unset_mbr_i(int dsk_num)
{
	dc_mbr      mbr;
	dc_mbr      old_mbr;
	int         size, resl;
	mbr_config *cnf;
	void       *data;
	u64         offs;
	dc_disk_p  *dp;
	int         backsz;
	void       *back;

	data = NULL; dp = NULL;
	do
	{
		if ( (dp = dc_disk_open(dsk_num, 0)) == NULL ) {
			resl = ST_ACCESS_DENIED; break;
		}
		/* get bootloader body offset */
		if ( (resl = get_ldr_body_ptr(dp, &mbr, &offs, &size)) != ST_OK ) {			
			break;
		}
		/* uninstall new bootloader */
		if ( (data = malloc(size)) == NULL ) {
			resl = ST_NOMEM; break;
		}
		/* read bootloader body */
		if ( (resl = dc_disk_read(dp, data, size, offs)) != ST_OK ) {				
			break;
		}
		if ( (cnf = dc_find_conf(data, size)) != NULL ) {
			/* copy saved old MBR */
			memcpy(&old_mbr, cnf->save_mbr, sizeof(old_mbr));
		}
		else if ((back = dc_extract_rsrc(&backsz, IDR_BACK)) != NULL) {
			/* copy standard backup MBR */
			memcpy(&old_mbr, back, sizeof(old_mbr));
		}
		else {
			resl = ST_BLDR_NO_CONF; break;
		}

		/* copy new partition table to old MBR */
		memcpy(old_mbr.data, mbr.data, sizeof(mbr.data));

		/* zero bootloader sectors */
		memset(&mbr, 0, sizeof(mbr));
			
		for (; size; size -= SECTOR_SIZE, offs += SECTOR_SIZE) {
			dc_disk_write(dp, &mbr, sizeof(mbr), offs);
		}
		/* write new MBR */
		resl = dc_disk_write(dp, &old_mbr, sizeof(old_mbr), 0);
	} while (0);

	if (data != NULL) { free(data); }
	if (dp != NULL)   { dc_disk_close(dp); }

	return resl;

}

int dc_unset_mbr(int dsk_num)
{
	int dsk_1, dsk_2;
	int resl;

	/* if dsk_num == -1 then find boot disk */
	if (dsk_num == -1) 
	{
		resl = dc_get_boot_disk(&dsk_1, &dsk_2);

		if (resl == ST_OK)
		{
			resl = dc_unset_mbr_i(dsk_1);

			if ( (resl == ST_OK) && (dsk_1 != dsk_2) ) {
				resl = dc_unset_mbr_i(dsk_2);
			}
		}
	} else {
		resl = dc_unset_mbr_i(dsk_num);
	}

	return resl;
}

int dc_update_boot(int dsk_num)
{
	ldr_config conf;
	int        resl;

	do
	{
		if ( (resl = dc_get_mbr_config(dsk_num, NULL, &conf)) != ST_OK ) {
			break;
		}

		if ( (resl = dc_unset_mbr(dsk_num)) != ST_OK ) {
			break;
		}

		/* allow_gpt: a loader is installed (dc_get_mbr_config above), only rewritten here */
		if ( (resl = dc_set_mbr_ex(dsk_num, 0, conf.options & LDR_OP_SMALL_BOOT, 1)) != ST_OK )
		{
			if ( (resl = dc_set_mbr_ex(dsk_num, 1, conf.options & LDR_OP_SMALL_BOOT, 1)) != ST_OK ) {
				break;
			}
		}
		resl = dc_set_mbr_config(dsk_num, NULL, &conf);
	} while (0);

	return resl;
}



int dc_get_drive_info(wchar_t *w32_name, drive_inf *info)
{
	PARTITION_INFORMATION_EX ptix;
	PARTITION_INFORMATION    pti;
	STORAGE_DEVICE_NUMBER    dnum;
	u8                       buff[4096];
	PVOLUME_DISK_EXTENTS     ext = pv(buff);
	u32                      bytes, i;	
	int                      resl;
	int                      succs;
	HANDLE                   hdisk;

	memset(info, 0, sizeof(drive_inf));
	
	do
	{
		hdisk = CreateFile(
			w32_name, SYNCHRONIZE | GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 
			NULL, OPEN_EXISTING, 0, NULL);

		if (hdisk == INVALID_HANDLE_VALUE) {
			resl = ST_ERROR; break;
		}

		succs = DeviceIoControl(
			hdisk, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, &ptix, sizeof(ptix), &bytes, NULL);

		if (succs != 0) 
		{
			/*	if (ptix.PartitionStyle = PARTITION_STYLE_GPT) {
				info->use_gpt = 1;
			 */
			info->dsk_num  = ptix.PartitionNumber;
			info->par_size = ptix.PartitionLength.QuadPart;				
		} else 
		{
			succs = DeviceIoControl(hdisk, IOCTL_DISK_GET_PARTITION_INFO, NULL, 0, &pti, sizeof(pti), &bytes, NULL);

			if (succs != 0) {
				info->dsk_num  = pti.PartitionNumber;
				info->par_size = pti.PartitionLength.QuadPart;				
			} else {
				info->dsk_num = 0;
				succs = DeviceIoControl(hdisk, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &info->par_size, sizeof(info->par_size), &bytes, NULL);
				if ( succs == 0 ) return ST_ERROR;
			}			
		}

		succs = DeviceIoControl(hdisk, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &dnum, sizeof(dnum), &bytes, NULL);

		if (succs != 0) {
			info->dsk_num         = 1;
			info->dsk_type        = DSK_BASIC;
			info->par_numb        = dnum.PartitionNumber;
			info->disks[0].number = dnum.DeviceNumber;
			info->disks[0].size   = dc_dsk_get_size(dnum.DeviceNumber, 0);
		} else 
		{
			succs = DeviceIoControl(hdisk, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0, ext, sizeof(buff), &bytes, NULL);
				
			if (succs != 0) 
			{
				for (i = 0; i < ext->NumberOfDiskExtents; i++) {
					info->disks[i].number    = ext->Extents[i].DiskNumber;
					info->disks[i].prt_start = ext->Extents[i].StartingOffset.QuadPart;
					info->disks[i].prt_size  = ext->Extents[i].ExtentLength.QuadPart;
					info->disks[i].size      = dc_dsk_get_size(info->disks[i].number, 0);
				}

				if ( (info->dsk_num = ext->NumberOfDiskExtents) == 1 ) {
					info->dsk_type = DSK_DYN_SIMPLE;
				} else {					
					info->dsk_type = DSK_DYN_SPANNED;
				}
			} else {
				resl = ST_IO_ERROR; break;
			}
		}
		resl = ST_OK;
	} while (0);

	if (hdisk != INVALID_HANDLE_VALUE) {
		CloseHandle(hdisk);
	}

	return resl;
}

