#ifndef _HEADER_IO_H_
#define _HEADER_IO_H_

#include "devhook.h"

int io_read_header_full(dev_hook *hook, u64 pos, dc_header **header, xts_key *hdr_key, int hdr_len);
int io_read_header(dev_hook *hook, u64 pos, dc_header **header, xts_key **out_key, dc_pass *password, int* out_kdf, ULONG *interrupt_cmd);
int io_write_header(dev_hook *hook, u64 pos, dc_header *header, xts_key *hdr_key, dc_pass *password, u32 flags, ULONG *interrupt_cmd);

unsigned long calculate_header_crc(dc_header* header);

BOOLEAN is_volume_header_correct(dc_header *header);

int init_header_v2(dc_header *header, crypt_info *crypt, dc_pass *password);

int get_ext_header(dc_header *header, dc_ext_header **out_ext_hdr);

#endif