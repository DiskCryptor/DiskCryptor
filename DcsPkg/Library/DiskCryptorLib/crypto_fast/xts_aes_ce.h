/*
    *
    * DiskCryptor - open source partition encryption tool
    * ARM64 AES Crypto Extensions support
    * Copyright (c) 2026
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
#ifndef _XTS_AES_CE_H_
#define _XTS_AES_CE_H_

#ifdef _M_ARM64

#include "xts_fast.h"

int  _stdcall xts_aes_ce_available(void);
void _stdcall xts_aes_ce_encrypt(const unsigned char *in, unsigned char *out, size_t len, unsigned __int64 offset, xts_key *key);
void _stdcall xts_aes_ce_decrypt(const unsigned char *in, unsigned char *out, size_t len, unsigned __int64 offset, xts_key *key);

void _stdcall aes256_arm64_encrypt(const unsigned char *in, unsigned char *out, aes256_key *key);
void _stdcall aes256_arm64_decrypt(const unsigned char *in, unsigned char *out, aes256_key *key);

#endif /* _M_ARM64 */

#endif /* _XTS_AES_CE_H_ */
