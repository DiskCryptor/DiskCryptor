/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2026
    * DavidXanatos <info@diskcryptor.org>
	* Copyright (c) 2007-2010
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
#include <math.h>

#include "main.h"
#include "pass.h"

#include "prc_keyfiles.h"
#include "keyfiles.h"

#include "dc_header.h"

static void _check_password(dc_pass *pass, _pass_inf *inf)
{
	wchar_t c;
	int     flags = 0;
	int     chars = 0;
	int     i, len;

	len = pass->size / sizeof(wchar_t);

	for ( i = 0; i < len; i++ )
	{
		c = pass->pass[i];
		do
		{
			if ( (c >= L'a') && (c <= L'z') ) {
				flags |= P_AZ_L; break;
			}
			if ( (c >= L'A') && (c <= L'Z') ) {
				flags |= P_AZ_H; break;
			}
			if ( (c >= L'0') && (c <= L'9') ) {
				flags |= P_09; break;
			}
			if (c == L' ') {
				flags |= P_SPACE; break;
			}
			if ( ((c >= L'!') && (c <= L'/')) ||
				 ((c >= L':') && (c <= L'@')) ||
				 ((c >= L'[') && (c <= L'`')) ||
				 ((c >= L'{') && (c <= L'~')) ||
				 ((c >= L'\x00A1') && (c <= L'\x00BF')) ||
				 (c == L'\x20AC') || (c == L'\x00A3') || (c == L'\x00A5') ||
				 (c == L'\x00A7') || (c == L'\x00B6') || (c == L'\x00D7') )
			{
				flags |= P_SPCH; break;
			} else {
				flags |= P_NCHAR;
			}
		} while (0);
	}

	if (flags & P_09) {
		chars += '9' - '0' + 1;
	}
	if (flags & P_AZ_L) {
		chars += 'z' - 'a' + 1;
	}
	if (flags & P_AZ_H) {
		chars += 'Z' - 'A' + 1;
	}
	if (flags & P_SPACE) {
		chars++;
	}
	if (flags & P_SPCH) {
		chars += ('/' - '!') + ('@' - ':') + ('`' - '[') + ('~' - '{') + (0xBF - 0xA1) + 6;
	}
	if (flags & P_NCHAR) {
		chars += 64;
	}
	inf->flags   = flags;
	inf->entropy = chars ? len * log(chars) / log(2) : 0;
	inf->length  = len;
}


//////////////////////////////////////////////////////////////////////////////////////
// Password entropy increase estimation from PBKDF2 to Argon2id,
// accounting for GPU parallelism collapse
//
// PBKDF2-HMAC-SHA512(1000) baseline on the attacker GPU (H/s).
#define PBKDF2_SHA512_1000_HPS     2267000.0
//
// Assume 24 GiB VRAM class for RTX 4090 (MiB).
#define GPU_VRAM_MIB              24576.0
// Calibration datapoint from hashcat v7.0.0 release notes:
// Argon2id RFC9106 settings m=65536 KiB (64 MiB), t=3, p=1 -> 1703 H/s
// https://github.com/hashcat/hashcat/blob/master/docs/releases_notes_v7.0.0.md#22-argon2
#define A2_REF_HPS                1703.0
#define A2_REF_M_MIB              64.0
#define A2_REF_T                  3.0
//
// Returns "effective additional entropy" in bits:
// H_eff = H_pw + log2(PBKDF2_rate / Argon2_rate)
// Argon2_rate is modeled to include VRAM parallelism:
// R_a2 ~ K * VRAM / (t * m^2)
// with K calibrated from the real RTX 4090 datapoint above.
//
double dc_effective_entropy_pbkdf2_to_argon2id(u32 m_kib, u32 t_cost)
{
	if (m_kib == 0 || t_cost == 0)
		return 0;

	// Calibrate K so the model matches the known datapoint exactly.
	const double K = (A2_REF_HPS * A2_REF_T * (A2_REF_M_MIB * A2_REF_M_MIB)) / GPU_VRAM_MIB;

	// Argon2id guesses/s with VRAM limits showing up (1 / (t*m^2)).
	const double m = (double)m_kib/1024.0;
	const double t = (double)t_cost;
	double Argon2_rate = (K * GPU_VRAM_MIB) / (t * m * m);
	if (!(Argon2_rate > 0.0)) return 0.0;

	double added_bits = log(PBKDF2_SHA512_1000_HPS / Argon2_rate) / log(2.0); // log2(PBKDF2_rate / Argon2_rate)
	if (added_bits < 0.0)  return 0.0;

	return added_bits;
}


void _draw_pass_rating(
		HWND     hwnd,
		dc_pass *pass,
		int      kb_layout,
		int      header_kdf,
		int     *entropy
	)
{
	int k = 0;
	int idx = -1;

	_pass_inf inf;
	_check_password(pass, &inf);

	if (header_kdf > 0 && inf.entropy > 0)
	{
		u32 memory_cost, time_cost, parallelism;
		argon2_mk_params_um(header_kdf, &memory_cost, &time_cost, &parallelism);

		inf.entropy += dc_effective_entropy_pbkdf2_to_argon2id(memory_cost, time_cost);
	}

	while ( pass_gr_ctls[k].id != -1 )
	{
		pass_gr_ctls[k].hwnd = GetDlgItem( hwnd, pass_gr_ctls[k].id );
		pass_gr_ctls[k].color = _cl(COLOR_BTNFACE, 70);

		// pass_pe_ctls has fewer entries than pass_gr_ctls, check terminator
		if ( pass_pe_ctls[k].id != -1 )
		{
			pass_pe_ctls[k].hwnd = GetDlgItem( hwnd, pass_pe_ctls[k].id );
			pass_pe_ctls[k].color = _cl(COLOR_BTNFACE, 70);
		}

		k++;
	}

	if ( inf.flags & P_AZ_L  ) pass_gr_ctls[0].color = CL_BLUE;
	if ( inf.flags & P_AZ_H  ) pass_gr_ctls[1].color = CL_BLUE;
	if ( inf.flags & P_09    ) pass_gr_ctls[2].color = CL_BLUE;
	if ( inf.flags & P_SPACE ) pass_gr_ctls[3].color = CL_BLUE;
	if ( inf.flags & P_SPCH  ) pass_gr_ctls[4].color = CL_BLUE;
	if ( inf.flags & P_NCHAR ) pass_gr_ctls[5].color = CL_BLUE;

	if ( kb_layout != -1 )
	{
		pass_gr_ctls[5].color = GetSysColor(COLOR_GRAYTEXT);
		if ( kb_layout != LDR_KB_QWERTY )
		{
			pass_gr_ctls[4].color = pass_gr_ctls[5].color;
		}
	}
	*entropy = (int)inf.entropy;

	if ( inf.entropy > 192 ) idx = 4;
	if ( inf.entropy < 193 ) idx = 3;
	if ( inf.entropy < 129 ) idx = 2;
	if ( inf.entropy < 81  ) idx = 1;
	if ( inf.entropy < 65  ) idx = 0;

	// Only highlight a strength indicator if there's actually a password
	// idx remains -1 when entropy is 0 (no password)
	if ( inf.entropy && idx >= 0 && idx < 5 )
	{
		pass_pe_ctls[idx].color = CL_BLUE;
	}

	k = 0;
	while ( pass_gr_ctls[k].id != -1 )
	{
		if ( pass_gr_ctls[k].hwnd )
		{
			InvalidateRect(pass_gr_ctls[k].hwnd, NULL, TRUE);
		}
		// pass_pe_ctls has fewer entries, check terminator before accessing
		if ( pass_pe_ctls[k].id != -1 && pass_pe_ctls[k].hwnd )
		{
			InvalidateRect(pass_pe_ctls[k].hwnd, NULL, TRUE);
		}
		k++;
	}
}

int __mix_keyfiles_pass(dc_pass *pass, keyfiles_state *kf_state)
{
	int rlt = ST_OK;
	_list_key_files *key_file;

	if ( kf_state == NULL )
		return ST_OK;

	if (_keyfiles_count(kf_state) > 0) {
		pass->flags |= PF_KEYFILE_MIXED;
	}

	if (kf_state->mix_mode == KEYFILE_MIX_LEGACY)
	{
		for (key_file = _first_keyfile(kf_state); key_file != NULL && rlt == ST_OK; key_file = _next_keyfile(key_file, kf_state))
		{
			if ( key_file->is_virtual && key_file->virtual_data != NULL ) {
				rlt = dc_add_virtual_keyfile( pass, key_file->virtual_data, key_file->virtual_size );
			}
			else {
				rlt = dc_add_keyfiles( pass, key_file->path );
			}
		}
	}
	else
	{
		BOOLEAN kf_is_raw = FALSE;

		// handle raw keyfile case (single keyfile with size == 64 bytes, treated as pre-hashed keyset)
		if (_keyfiles_count(kf_state) == 1)
		{
			_list_key_files *first = _first_keyfile(kf_state);
			if ( !first->is_virtual )
			{
				HANDLE h_file = CreateFile(first->path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
				if (h_file != INVALID_HANDLE_VALUE)
				{
					if (GetFileSize(h_file, NULL) == 64) // == SHA512_DIGEST_SIZE
					{
						byte keyfile[64];

						kf_is_raw = TRUE;

						if (!ReadFile(h_file, keyfile, sizeof(keyfile), NULL, NULL)) {
							rlt = ST_ERROR;
						} else {
							dc_kf_mixer_combine(pass, keyfile);
						}
					}
					CloseHandle(h_file);
				}
			}
			else if (first->is_virtual && first->virtual_data != NULL && first->virtual_size == 64) // == SHA512_DIGEST_SIZE
			{
				kf_is_raw = TRUE;
				dc_kf_mixer_combine(pass, first->virtual_data);
			}
		}

		if (!kf_is_raw)
		{
			dc_kf_mixer mixer;
			rlt = dc_kf_mixer_init(&mixer);
			if (rlt == ST_OK)
			{
				for (key_file = _first_keyfile(kf_state); key_file != NULL && rlt == ST_OK; key_file = _next_keyfile(key_file, kf_state))
				{
					if (key_file->is_virtual && key_file->virtual_data != NULL) {
						rlt = dc_kf_mixer_add_data(&mixer, key_file->virtual_data, key_file->virtual_size);
					}
					else {
						rlt = dc_kf_mixer_add_file(&mixer, key_file->path);
					}
				}

				if (rlt == ST_OK) {
					rlt = dc_kf_mixer_finish(&mixer, pass);
				}
				else {
					dc_kf_mixer_free(&mixer);
				}
			}
		}
	}

	return rlt;
}

dc_pass *__get_pass_keyfiles(
		HWND h_pass,
		BOOL use_keyfiles,
		keyfiles_state *kf_state
	)
{
	dc_pass *pass;
	wchar_t *s_pass;
	size_t   plen;
	int      rlt;

	if ( (pass = secure_alloc(sizeof(dc_pass))) == NULL )
	{
		return NULL;
	}
	if ( (s_pass = secure_alloc((MAX_PASSWORD + 1) * sizeof(wchar_t))) == NULL)
	{
		secure_free(pass);
		return NULL;
	}
	GetWindowText( h_pass, s_pass, MAX_PASSWORD + 1 );
	if ( wcslen(s_pass) > 0 )
	{
		plen       = wcslen(s_pass) * sizeof(wchar_t);
		pass->size = d32( min( plen, MAX_PASSWORD * sizeof(wchar_t) ) );

		mincpy( &pass->pass, s_pass, pass->size );
	}
	burn( s_pass, (MAX_PASSWORD + 1) * sizeof(wchar_t) );
	secure_free( s_pass );

	if ( use_keyfiles && kf_state != NULL )
	{
		rlt = __mix_keyfiles_pass(pass, kf_state);

		if (rlt != ST_OK) {
			__error_s(GetParent(h_pass), L"Keyfiles not loaded", rlt);

			secure_free(pass);
			pass = NULL;
		}
	}

	return pass;
}


void _wipe_pass_control(
		HWND hwnd,
		int  edit_pass
	)
{
	wchar_t wipe[MAX_PASSWORD + 1];
	wipe[MAX_PASSWORD] = 0;

	memset( wipe, '#', MAX_PASSWORD * sizeof(wchar_t) );
	SetWindowText( GetDlgItem(hwnd, edit_pass), wipe );
}


BOOL _input_verify(
		dc_pass *pass,
		dc_pass *verify,
		keyfiles_state *kf_state,
		int      kb_layout,
		int     *msg_idx
	)
{
	BOOL correct = FALSE;

	_pass_inf info;
	_check_password( pass, &info );

	*msg_idx = ST_PASS_CORRECT;
	if ( info.length )
	{
		if ( (kb_layout == LDR_KB_QWERTY && info.flags & P_NCHAR) ||
			 ((kb_layout == LDR_KB_QWERTZ || kb_layout == LDR_KB_AZERTY) &&
			 (info.flags & P_NCHAR || info.flags & P_SPCH)))
		{

			*msg_idx = ST_PASS_SPRS_SYMBOLS;
		} else {
			correct = TRUE;
		}
	} else {
		*msg_idx = ST_PASS_EMPTY;
	}

	if ( correct && verify != NULL )
	{
		if ( !IS_EQUAL_PASS(pass, verify) )
		{
			*msg_idx = ST_PASS_NOT_CONFIRMED;
		}
		if ( verify->size == 0 )
		{
			*msg_idx = ST_PASS_EMPTY_CONFIRM;
		}
	}
	else
	{
		if ( kf_state != NULL )
		{
			if ( _keyfiles_count(kf_state) == 0 )
			{
				*msg_idx = ST_PASS_EMPTY_KEYLIST;
			}
		}
	}
	return (
		(  info.length && !verify ) ||
		(  info.length &&  verify && IS_EQUAL_PASS(pass, verify) ) ||
		( !info.length && kf_state != NULL && _keyfiles_count(kf_state) )
	);

}
