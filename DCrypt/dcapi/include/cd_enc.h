#ifndef _CD_ENC_H_
#define _CD_ENC_H_

//#ifdef _M_ARM64
//#include "xts_small.h"
//#else
#include "xts_fast.h"
//#endif
#include "volume_header.h"
#include "dcapi.h"

typedef BOOL (DC_CD_CALLBACK)(ULONGLONG isosize, ULONGLONG encsize, PVOID param);

DWORD dc_api dc_encrypt_iso_image(PCWSTR src_path, PCWSTR dst_path, dc_pass* password, int cipher, DC_CD_CALLBACK callback, PVOID param);

#endif