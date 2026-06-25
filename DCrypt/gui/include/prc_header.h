#ifndef _PRC_HEADER_H_
#define _PRC_HEADER_H_

#include "main.h"

/* Entry points for header configuration dialog */
int _dlg_header_config_volume(HWND hwnd, _dnode *node);
int _dlg_header_config_file(HWND hwnd, wchar_t *file_path);

void _format_hdr_size(u32 size, wchar_t *buf, int buf_len, BOOLEAN no_hint);

#endif /* _PRC_HEADER_H_ */
