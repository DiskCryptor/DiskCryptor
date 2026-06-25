#ifndef _MISC_
#define _MISC_

#include "dcapi.h"

/* exported functions */
int dc_api enable_privilege(wchar_t *name);
int dc_api is_admin();
int dc_api is_wow64();
int dc_api is_win_vista();

PVOID dc_api secure_alloc(ULONG length);
void  dc_api secure_free(PVOID ptr);

void dc_api dc_format_byte_size(
	   wchar_t *wc_buf, int wc_size, u64 num_bytes
	   );

wchar_t dc_api *dc_get_cipher_name(int cipher_id);
wchar_t dc_api *dc_get_mode_name(int mode_id);
wchar_t dc_api *dc_get_prf_name(int prf_id);
wchar_t dc_api *dc_get_status_str(int resl);

int dc_api dc_format_fs(wchar_t *root, wchar_t *fs);
int dc_api save_file(wchar_t *name, void *data, int size);
int dc_api load_file(wchar_t *name, void **data, int *size);
void dc_api my_free(PVOID ptr);

int dc_api is_all_zeros(const char* bytes, size_t size);
int dc_api calc_crc32(const char* bytes, size_t size);

/* private functions for internal use */

int dc_fs_type(u8 *buff);

typedef struct _dc_disk_p {
	HANDLE     hdisk;
	MEDIA_TYPE media;
	u32        bps;   /* bytes per sector */
	u32        spc;   /* sectors per cylinder */
	u64        size;  /* disk size */

} dc_disk_p;

dc_disk_p  dc_api *dc_disk_open(int dsk_num, int is_cd);
void       dc_api  dc_disk_close(dc_disk_p *dp);
int        dc_api  dc_disk_read(dc_disk_p *dp, void *buff, int size, u64 offset);
int        dc_api  dc_disk_write(dc_disk_p *dp, void *buff, int size, u64 offset);

#define FS_UNK   0
#define FS_FAT12 1
#define FS_FAT16 2
#define FS_FAT32 3
#define FS_NTFS  4
#define FS_EXFAT 5

int dc_api dc_buffer_contains_pattern(const byte *buffer, size_t bufferSize, const byte *pattern, size_t patternSize);
int dc_api dc_buffer_contains_string(const byte *buffer, size_t bufferSize, const char *str);
int dc_api dc_buffer_contains_wide_string(const byte *buffer, size_t bufferSize, const wchar_t *str);

#endif