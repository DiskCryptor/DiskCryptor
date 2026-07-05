/*
    *
    * DiskCryptor - open source partition encryption tool
    * ARM64 NEON Serpent implementation
    * Copyright (c) 2026
    *
    * Based on SSE2 implementation by ntldr
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

#ifdef _M_ARM64

#include <arm_neon.h>
#include "serpent.h"
#include "xts_fast.h"
#include "xts_serpent_neon.h"

/* NEON is always available on ARM64 */
int _stdcall xts_serpent_neon_available(void)
{
    return 1;
}

/* Transpose 4x4 matrix of 32-bit values stored in 4 128-bit vectors */
#define transpose(_B0, _B1, _B2, _B3) {                      \
    uint32x4x2_t _t01 = vtrnq_u32(_B0, _B1);                 \
    uint32x4x2_t _t23 = vtrnq_u32(_B2, _B3);                 \
    uint64x2_t _u0 = vreinterpretq_u64_u32(_t01.val[0]);     \
    uint64x2_t _u1 = vreinterpretq_u64_u32(_t01.val[1]);     \
    uint64x2_t _u2 = vreinterpretq_u64_u32(_t23.val[0]);     \
    uint64x2_t _u3 = vreinterpretq_u64_u32(_t23.val[1]);     \
    _B0 = vreinterpretq_u32_u64(vcombine_u64(vget_low_u64(_u0), vget_low_u64(_u2)));   \
    _B1 = vreinterpretq_u32_u64(vcombine_u64(vget_low_u64(_u1), vget_low_u64(_u3)));   \
    _B2 = vreinterpretq_u32_u64(vcombine_u64(vget_high_u64(_u0), vget_high_u64(_u2))); \
    _B3 = vreinterpretq_u32_u64(vcombine_u64(vget_high_u64(_u1), vget_high_u64(_u3))); \
}

/* Key XOR for forward rounds */
#define KXf(_B0, _B1, _B2, _B3, _ctx, round)             \
    _B0 = veorq_u32(_B0, vdupq_n_u32((_ctx)->expkey[4*round  ])); \
    _B1 = veorq_u32(_B1, vdupq_n_u32((_ctx)->expkey[4*round+1])); \
    _B2 = veorq_u32(_B2, vdupq_n_u32((_ctx)->expkey[4*round+2])); \
    _B3 = veorq_u32(_B3, vdupq_n_u32((_ctx)->expkey[4*round+3]));

/* NOT operation */
#define NOT_NEON(_X) ( vmvnq_u32(_X) )

/* Rotate left */
#define ROL_NEON(_X, _rot) ( \
    vorrq_u32(vshlq_n_u32(_X, _rot), vshrq_n_u32(_X, 32-_rot)) )

/* Rotate right */
#define ROR_NEON(_X, _rot) ( ROL_NEON(_X, (32-_rot)) )

/* Linear transformation (forward) */
#define LTf(_B0, _B1, _B2, _B3)                     \
    _B0 = ROL_NEON(_B0, 13);                        \
    _B2 = ROL_NEON(_B2, 3);                         \
    _B1 = veorq_u32(_B1, _B0);                      \
    _B1 = veorq_u32(_B1, _B2);                      \
    _B3 = veorq_u32(_B3, _B2);                      \
    _B3 = veorq_u32(_B3, vshlq_n_u32(_B0, 3));      \
    _B1 = ROL_NEON(_B1, 1);                         \
    _B3 = ROL_NEON(_B3, 7);                         \
    _B0 = veorq_u32(_B0, _B1);                      \
    _B0 = veorq_u32(_B0, _B3);                      \
    _B2 = veorq_u32(_B2, _B3);                      \
    _B2 = veorq_u32(_B2, vshlq_n_u32(_B1, 7));      \
    _B0 = ROL_NEON(_B0, 5);                         \
    _B2 = ROL_NEON(_B2, 22);

/* Inverse linear transformation */
#define ITf(_B0, _B1, _B2, _B3)                     \
    _B2 = ROR_NEON(_B2, 22);                        \
    _B0 = ROR_NEON(_B0, 5);                         \
    _B2 = veorq_u32(_B2, _B3);                      \
    _B2 = veorq_u32(_B2, vshlq_n_u32(_B1, 7));      \
    _B0 = veorq_u32(_B0, _B1);                      \
    _B0 = veorq_u32(_B0, _B3);                      \
    _B3 = ROR_NEON(_B3, 7);                         \
    _B1 = ROR_NEON(_B1, 1);                         \
    _B3 = veorq_u32(_B3, _B2);                      \
    _B3 = veorq_u32(_B3, vshlq_n_u32(_B0, 3));      \
    _B1 = veorq_u32(_B1, _B0);                      \
    _B1 = veorq_u32(_B1, _B2);                      \
    _B2 = ROR_NEON(_B2, 3);                         \
    _B0 = ROR_NEON(_B0, 13);

/* S-boxes for encryption */
#define sE1(_B0, _B1, _B2, _B3) {        \
    uint32x4_t _tt = _B1;                \
    _B3 = veorq_u32(_B3, _B0);           \
    _B1 = vandq_u32(_B1, _B3);           \
    _tt = veorq_u32(_tt, _B2);           \
    _B1 = veorq_u32(_B1, _B0);           \
    _B0 = vorrq_u32(_B0, _B3);           \
    _B0 = veorq_u32(_B0, _tt);           \
    _tt = veorq_u32(_tt, _B3);           \
    _B3 = veorq_u32(_B3, _B2);           \
    _B2 = vorrq_u32(_B2, _B1);           \
    _B2 = veorq_u32(_B2, _tt);           \
    _tt = NOT_NEON(_tt);                 \
    _tt = vorrq_u32(_tt, _B1);           \
    _B1 = veorq_u32(_B1, _B3);           \
    _B1 = veorq_u32(_B1, _tt);           \
    _B3 = vorrq_u32(_B3, _B0);           \
    _B1 = veorq_u32(_B1, _B3);           \
    _tt = veorq_u32(_tt, _B3);           \
    _B3 = _B0;                           \
    _B0 = _B1;                           \
    _B1 = _tt;                           \
}

#define sE2(_B0, _B1, _B2, _B3) {        \
    uint32x4_t _tt;                      \
    _B0 = NOT_NEON(_B0);                 \
    _B2 = NOT_NEON(_B2);                 \
    _tt = _B0;                           \
    _B0 = vandq_u32(_B0, _B1);           \
    _B2 = veorq_u32(_B2, _B0);           \
    _B0 = vorrq_u32(_B0, _B3);           \
    _B3 = veorq_u32(_B3, _B2);           \
    _B1 = veorq_u32(_B1, _B0);           \
    _B0 = veorq_u32(_B0, _tt);           \
    _tt = vorrq_u32(_tt, _B1);           \
    _B1 = veorq_u32(_B1, _B3);           \
    _B2 = vorrq_u32(_B2, _B0);           \
    _B2 = vandq_u32(_B2, _tt);           \
    _B0 = veorq_u32(_B0, _B1);           \
    _B1 = vandq_u32(_B1, _B2);           \
    _B1 = veorq_u32(_B1, _B0);           \
    _B0 = vandq_u32(_B0, _B2);           \
    _tt = veorq_u32(_tt, _B0);           \
    _B0 = _B2;                           \
    _B2 = _B3;                           \
    _B3 = _B1;                           \
    _B1 = _tt;                           \
}

#define sE3(_B0, _B1, _B2, _B3) {        \
    uint32x4_t _tt = _B0;                \
    _B0 = vandq_u32(_B0, _B2);           \
    _B0 = veorq_u32(_B0, _B3);           \
    _B2 = veorq_u32(_B2, _B1);           \
    _B2 = veorq_u32(_B2, _B0);           \
    _B3 = vorrq_u32(_B3, _tt);           \
    _B3 = veorq_u32(_B3, _B1);           \
    _tt = veorq_u32(_tt, _B2);           \
    _B1 = _B3;                           \
    _B3 = vorrq_u32(_B3, _tt);           \
    _B3 = veorq_u32(_B3, _B0);           \
    _B0 = vandq_u32(_B0, _B1);           \
    _tt = veorq_u32(_tt, _B0);           \
    _B1 = veorq_u32(_B1, _B3);           \
    _B1 = veorq_u32(_B1, _tt);           \
    _B0 = _B2;                           \
    _B2 = _B1;                           \
    _B1 = _B3;                           \
    _B3 = NOT_NEON(_tt);                 \
}

#define sE4(_B0, _B1, _B2, _B3) {        \
    uint32x4_t _tt = _B0;                \
    _B0 = vorrq_u32(_B0, _B3);           \
    _B3 = veorq_u32(_B3, _B1);           \
    _B1 = vandq_u32(_B1, _tt);           \
    _tt = veorq_u32(_tt, _B2);           \
    _B2 = veorq_u32(_B2, _B3);           \
    _B3 = vandq_u32(_B3, _B0);           \
    _tt = vorrq_u32(_tt, _B1);           \
    _B3 = veorq_u32(_B3, _tt);           \
    _B0 = veorq_u32(_B0, _B1);           \
    _tt = vandq_u32(_tt, _B0);           \
    _B1 = veorq_u32(_B1, _B3);           \
    _tt = veorq_u32(_tt, _B2);           \
    _B1 = vorrq_u32(_B1, _B0);           \
    _B1 = veorq_u32(_B1, _B2);           \
    _B0 = veorq_u32(_B0, _B3);           \
    _B2 = _B1;                           \
    _B1 = vorrq_u32(_B1, _B3);           \
    _B0 = veorq_u32(_B0, _B1);           \
    _B1 = _B2;                           \
    _B2 = _B3;                           \
    _B3 = _tt;                           \
}

#define sE5(_B0, _B1, _B2, _B3) {        \
    uint32x4_t _tt;                      \
    _B1 = veorq_u32(_B1, _B3);           \
    _B3 = NOT_NEON(_B3);                 \
    _B2 = veorq_u32(_B2, _B3);           \
    _B3 = veorq_u32(_B3, _B0);           \
    _tt = _B1;                           \
    _B1 = vandq_u32(_B1, _B3);           \
    _B1 = veorq_u32(_B1, _B2);           \
    _tt = veorq_u32(_tt, _B3);           \
    _B0 = veorq_u32(_B0, _tt);           \
    _B2 = vandq_u32(_B2, _tt);           \
    _B2 = veorq_u32(_B2, _B0);           \
    _B0 = vandq_u32(_B0, _B1);           \
    _B3 = veorq_u32(_B3, _B0);           \
    _tt = vorrq_u32(_tt, _B1);           \
    _tt = veorq_u32(_tt, _B0);           \
    _B0 = vorrq_u32(_B0, _B3);           \
    _B0 = veorq_u32(_B0, _B2);           \
    _B2 = vandq_u32(_B2, _B3);           \
    _B0 = NOT_NEON(_B0);                 \
    _tt = veorq_u32(_tt, _B2);           \
    _B2 = _B0;                           \
    _B0 = _B1;                           \
    _B1 = _tt;                           \
}

#define sE6(_B0, _B1, _B2, _B3) {        \
    uint32x4_t _tt;                      \
    _B0 = veorq_u32(_B0, _B1);           \
    _B1 = veorq_u32(_B1, _B3);           \
    _B3 = NOT_NEON(_B3);                 \
    _tt = _B1;                           \
    _B1 = vandq_u32(_B1, _B0);           \
    _B2 = veorq_u32(_B2, _B3);           \
    _B1 = veorq_u32(_B1, _B2);           \
    _B2 = vorrq_u32(_B2, _tt);           \
    _tt = veorq_u32(_tt, _B3);           \
    _B3 = vandq_u32(_B3, _B1);           \
    _B3 = veorq_u32(_B3, _B0);           \
    _tt = veorq_u32(_tt, _B1);           \
    _tt = veorq_u32(_tt, _B2);           \
    _B2 = veorq_u32(_B2, _B0);           \
    _B0 = vandq_u32(_B0, _B3);           \
    _B2 = NOT_NEON(_B2);                 \
    _B0 = veorq_u32(_B0, _tt);           \
    _tt = vorrq_u32(_tt, _B3);           \
    _tt = veorq_u32(_tt, _B2);           \
    _B2 = _B0;                           \
    _B0 = _B1;                           \
    _B1 = _B3;                           \
    _B3 = _tt;                           \
}

#define sE7(_B0, _B1, _B2, _B3) {        \
    uint32x4_t _tt;                      \
    _B2 = NOT_NEON(_B2);                 \
    _tt = _B3;                           \
    _B3 = vandq_u32(_B3, _B0);           \
    _B0 = veorq_u32(_B0, _tt);           \
    _B3 = veorq_u32(_B3, _B2);           \
    _B2 = vorrq_u32(_B2, _tt);           \
    _B1 = veorq_u32(_B1, _B3);           \
    _B2 = veorq_u32(_B2, _B0);           \
    _B0 = vorrq_u32(_B0, _B1);           \
    _B2 = veorq_u32(_B2, _B1);           \
    _tt = veorq_u32(_tt, _B0);           \
    _B0 = vorrq_u32(_B0, _B3);           \
    _B0 = veorq_u32(_B0, _B2);           \
    _tt = veorq_u32(_tt, _B3);           \
    _tt = veorq_u32(_tt, _B0);           \
    _B3 = NOT_NEON(_B3);                 \
    _B2 = vandq_u32(_B2, _tt);           \
    _B3 = veorq_u32(_B3, _B2);           \
    _B2 = _tt;                           \
}

#define sE8(_B0, _B1, _B2, _B3) {        \
    uint32x4_t _tt = _B1;                \
    _B1 = vorrq_u32(_B1, _B2);           \
    _B1 = veorq_u32(_B1, _B3);           \
    _tt = veorq_u32(_tt, _B2);           \
    _B2 = veorq_u32(_B2, _B1);           \
    _B3 = vorrq_u32(_B3, _tt);           \
    _B3 = vandq_u32(_B3, _B0);           \
    _tt = veorq_u32(_tt, _B2);           \
    _B3 = veorq_u32(_B3, _B1);           \
    _B1 = vorrq_u32(_B1, _tt);           \
    _B1 = veorq_u32(_B1, _B0);           \
    _B0 = vorrq_u32(_B0, _tt);           \
    _B0 = veorq_u32(_B0, _B2);           \
    _B1 = veorq_u32(_B1, _tt);           \
    _B2 = veorq_u32(_B2, _B1);           \
    _B1 = vandq_u32(_B1, _B0);           \
    _B1 = veorq_u32(_B1, _tt);           \
    _B2 = NOT_NEON(_B2);                 \
    _B2 = vorrq_u32(_B2, _B0);           \
    _tt = veorq_u32(_tt, _B2);           \
    _B2 = _B1;                           \
    _B1 = _B3;                           \
    _B3 = _B0;                           \
    _B0 = _tt;                           \
}

/* S-boxes for decryption */
#define sD1(_B0, _B1, _B2, _B3) {        \
    uint32x4_t _tt = _B1;                \
    _B2 = NOT_NEON(_B2);                 \
    _B1 = vorrq_u32(_B1, _B0);           \
    _tt = NOT_NEON(_tt);                 \
    _B1 = veorq_u32(_B1, _B2);           \
    _B2 = vorrq_u32(_B2, _tt);           \
    _B1 = veorq_u32(_B1, _B3);           \
    _B0 = veorq_u32(_B0, _tt);           \
    _B2 = veorq_u32(_B2, _B0);           \
    _B0 = vandq_u32(_B0, _B3);           \
    _tt = veorq_u32(_tt, _B0);           \
    _B0 = vorrq_u32(_B0, _B1);           \
    _B0 = veorq_u32(_B0, _B2);           \
    _B3 = veorq_u32(_B3, _tt);           \
    _B2 = veorq_u32(_B2, _B1);           \
    _B3 = veorq_u32(_B3, _B0);           \
    _B3 = veorq_u32(_B3, _B1);           \
    _B2 = vandq_u32(_B2, _B3);           \
    _tt = veorq_u32(_tt, _B2);           \
    _B2 = _B1;                           \
    _B1 = _tt;                           \
}

#define sD2(_B0, _B1, _B2, _B3) {        \
    uint32x4_t _tt = _B1;                \
    _B1 = veorq_u32(_B1, _B3);           \
    _B3 = vandq_u32(_B3, _B1);           \
    _tt = veorq_u32(_tt, _B2);           \
    _B3 = veorq_u32(_B3, _B0);           \
    _B0 = vorrq_u32(_B0, _B1);           \
    _B2 = veorq_u32(_B2, _B3);           \
    _B0 = veorq_u32(_B0, _tt);           \
    _B0 = vorrq_u32(_B0, _B2);           \
    _B1 = veorq_u32(_B1, _B3);           \
    _B0 = veorq_u32(_B0, _B1);           \
    _B1 = vorrq_u32(_B1, _B3);           \
    _B1 = veorq_u32(_B1, _B0);           \
    _tt = NOT_NEON(_tt);                 \
    _tt = veorq_u32(_tt, _B1);           \
    _B1 = vorrq_u32(_B1, _B0);           \
    _B1 = veorq_u32(_B1, _B0);           \
    _B1 = vorrq_u32(_B1, _tt);           \
    _B3 = veorq_u32(_B3, _B1);           \
    _B1 = _B0;                           \
    _B0 = _tt;                           \
    _tt = _B2;                           \
    _B2 = _B3;                           \
    _B3 = _tt;                           \
}

#define sD3(_B0, _B1, _B2, _B3) {        \
    uint32x4_t _tt;                      \
    _B2 = veorq_u32(_B2, _B3);           \
    _B3 = veorq_u32(_B3, _B0);           \
    _tt = _B3;                           \
    _B3 = vandq_u32(_B3, _B2);           \
    _B3 = veorq_u32(_B3, _B1);           \
    _B1 = vorrq_u32(_B1, _B2);           \
    _B1 = veorq_u32(_B1, _tt);           \
    _tt = vandq_u32(_tt, _B3);           \
    _B2 = veorq_u32(_B2, _B3);           \
    _tt = vandq_u32(_tt, _B0);           \
    _tt = veorq_u32(_tt, _B2);           \
    _B2 = vandq_u32(_B2, _B1);           \
    _B2 = vorrq_u32(_B2, _B0);           \
    _B3 = NOT_NEON(_B3);                 \
    _B2 = veorq_u32(_B2, _B3);           \
    _B0 = veorq_u32(_B0, _B3);           \
    _B0 = vandq_u32(_B0, _B1);           \
    _B3 = veorq_u32(_B3, _tt);           \
    _B3 = veorq_u32(_B3, _B0);           \
    _B0 = _B1;                           \
    _B1 = _tt;                           \
}

#define sD4(_B0, _B1, _B2, _B3) {        \
    uint32x4_t _tt = _B2;                \
    _B2 = veorq_u32(_B2, _B1);           \
    _B0 = veorq_u32(_B0, _B2);           \
    _tt = vandq_u32(_tt, _B2);           \
    _tt = veorq_u32(_tt, _B0);           \
    _B0 = vandq_u32(_B0, _B1);           \
    _B1 = veorq_u32(_B1, _B3);           \
    _B3 = vorrq_u32(_B3, _tt);           \
    _B2 = veorq_u32(_B2, _B3);           \
    _B0 = veorq_u32(_B0, _B3);           \
    _B1 = veorq_u32(_B1, _tt);           \
    _B3 = vandq_u32(_B3, _B2);           \
    _B3 = veorq_u32(_B3, _B1);           \
    _B1 = veorq_u32(_B1, _B0);           \
    _B1 = vorrq_u32(_B1, _B2);           \
    _B0 = veorq_u32(_B0, _B3);           \
    _B1 = veorq_u32(_B1, _tt);           \
    _B0 = veorq_u32(_B0, _B1);           \
    _tt = _B0;                           \
    _B0 = _B2;                           \
    _B2 = _B3;                           \
    _B3 = _tt;                           \
}

#define sD5(_B0, _B1, _B2, _B3) {        \
    uint32x4_t _tt = _B2;                \
    _B2 = vandq_u32(_B2, _B3);           \
    _B2 = veorq_u32(_B2, _B1);           \
    _B1 = vorrq_u32(_B1, _B3);           \
    _B1 = vandq_u32(_B1, _B0);           \
    _tt = veorq_u32(_tt, _B2);           \
    _tt = veorq_u32(_tt, _B1);           \
    _B1 = vandq_u32(_B1, _B2);           \
    _B0 = NOT_NEON(_B0);                 \
    _B3 = veorq_u32(_B3, _tt);           \
    _B1 = veorq_u32(_B1, _B3);           \
    _B3 = vandq_u32(_B3, _B0);           \
    _B3 = veorq_u32(_B3, _B2);           \
    _B0 = veorq_u32(_B0, _B1);           \
    _B2 = vandq_u32(_B2, _B0);           \
    _B3 = veorq_u32(_B3, _B0);           \
    _B2 = veorq_u32(_B2, _tt);           \
    _B2 = vorrq_u32(_B2, _B3);           \
    _B3 = veorq_u32(_B3, _B0);           \
    _B2 = veorq_u32(_B2, _B1);           \
    _B1 = _B3;                           \
    _B3 = _tt;                           \
}

#define sD6(_B0, _B1, _B2, _B3) {        \
    uint32x4_t _tt = _B3;                \
    _B1 = NOT_NEON(_B1);                 \
    _B2 = veorq_u32(_B2, _B1);           \
    _B3 = vorrq_u32(_B3, _B0);           \
    _B3 = veorq_u32(_B3, _B2);           \
    _B2 = vorrq_u32(_B2, _B1);           \
    _B2 = vandq_u32(_B2, _B0);           \
    _tt = veorq_u32(_tt, _B3);           \
    _B2 = veorq_u32(_B2, _tt);           \
    _tt = vorrq_u32(_tt, _B0);           \
    _tt = veorq_u32(_tt, _B1);           \
    _B1 = vandq_u32(_B1, _B2);           \
    _B1 = veorq_u32(_B1, _B3);           \
    _tt = veorq_u32(_tt, _B2);           \
    _B3 = vandq_u32(_B3, _tt);           \
    _tt = veorq_u32(_tt, _B1);           \
    _B3 = veorq_u32(_B3, _tt);           \
    _tt = NOT_NEON(_tt);                 \
    _B3 = veorq_u32(_B3, _B0);           \
    _B0 = _B1;                           \
    _B1 = _tt;                           \
    _tt = _B3;                           \
    _B3 = _B2;                           \
    _B2 = _tt;                           \
}

#define sD7(_B0, _B1, _B2, _B3) {        \
    uint32x4_t _tt = _B2;                \
    _B0 = veorq_u32(_B0, _B2);           \
    _B2 = vandq_u32(_B2, _B0);           \
    _tt = veorq_u32(_tt, _B3);           \
    _B2 = NOT_NEON(_B2);                 \
    _B3 = veorq_u32(_B3, _B1);           \
    _B2 = veorq_u32(_B2, _B3);           \
    _tt = vorrq_u32(_tt, _B0);           \
    _B0 = veorq_u32(_B0, _B2);           \
    _B3 = veorq_u32(_B3, _tt);           \
    _tt = veorq_u32(_tt, _B1);           \
    _B1 = vandq_u32(_B1, _B3);           \
    _B1 = veorq_u32(_B1, _B0);           \
    _B0 = veorq_u32(_B0, _B3);           \
    _B0 = vorrq_u32(_B0, _B2);           \
    _B3 = veorq_u32(_B3, _B1);           \
    _tt = veorq_u32(_tt, _B0);           \
    _B0 = _B1;                           \
    _B1 = _B2;                           \
    _B2 = _tt;                           \
}

#define sD8(_B0, _B1, _B2, _B3) {        \
    uint32x4_t _tt = _B2;                \
    _B2 = veorq_u32(_B2, _B0);           \
    _B0 = vandq_u32(_B0, _B3);           \
    _tt = vorrq_u32(_tt, _B3);           \
    _B2 = NOT_NEON(_B2);                 \
    _B3 = veorq_u32(_B3, _B1);           \
    _B1 = vorrq_u32(_B1, _B0);           \
    _B0 = veorq_u32(_B0, _B2);           \
    _B2 = vandq_u32(_B2, _tt);           \
    _B3 = vandq_u32(_B3, _tt);           \
    _B1 = veorq_u32(_B1, _B2);           \
    _B2 = veorq_u32(_B2, _B0);           \
    _B0 = vorrq_u32(_B0, _B2);           \
    _tt = veorq_u32(_tt, _B1);           \
    _B0 = veorq_u32(_B0, _B3);           \
    _B3 = veorq_u32(_B3, _tt);           \
    _tt = vorrq_u32(_tt, _B0);           \
    _B3 = veorq_u32(_B3, _B2);           \
    _tt = veorq_u32(_tt, _B2);           \
    _B2 = _B1;                           \
    _B1 = _B0;                           \
    _B0 = _B3;                           \
    _B3 = _tt;                           \
}

/* Full Serpent encrypt (4 blocks in parallel) */
#define serpent256_neon_encrypt(_B0, _B1, _B2, _B3, _ctx)                       \
    transpose(_B0,_B1,_B2,_B3);                                                 \
    KXf(_B0,_B1,_B2,_B3,_ctx, 0); sE1(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);   \
    KXf(_B0,_B1,_B2,_B3,_ctx, 1); sE2(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);   \
    KXf(_B0,_B1,_B2,_B3,_ctx, 2); sE3(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);   \
    KXf(_B0,_B1,_B2,_B3,_ctx, 3); sE4(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);   \
    KXf(_B0,_B1,_B2,_B3,_ctx, 4); sE5(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);   \
    KXf(_B0,_B1,_B2,_B3,_ctx, 5); sE6(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);   \
    KXf(_B0,_B1,_B2,_B3,_ctx, 6); sE7(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);   \
    KXf(_B0,_B1,_B2,_B3,_ctx, 7); sE8(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);   \
    KXf(_B0,_B1,_B2,_B3,_ctx, 8); sE1(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);   \
    KXf(_B0,_B1,_B2,_B3,_ctx, 9); sE2(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);   \
    KXf(_B0,_B1,_B2,_B3,_ctx, 10); sE3(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);  \
    KXf(_B0,_B1,_B2,_B3,_ctx, 11); sE4(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);  \
    KXf(_B0,_B1,_B2,_B3,_ctx, 12); sE5(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);  \
    KXf(_B0,_B1,_B2,_B3,_ctx, 13); sE6(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);  \
    KXf(_B0,_B1,_B2,_B3,_ctx, 14); sE7(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);  \
    KXf(_B0,_B1,_B2,_B3,_ctx, 15); sE8(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);  \
    KXf(_B0,_B1,_B2,_B3,_ctx, 16); sE1(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);  \
    KXf(_B0,_B1,_B2,_B3,_ctx, 17); sE2(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);  \
    KXf(_B0,_B1,_B2,_B3,_ctx, 18); sE3(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);  \
    KXf(_B0,_B1,_B2,_B3,_ctx, 19); sE4(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);  \
    KXf(_B0,_B1,_B2,_B3,_ctx, 20); sE5(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);  \
    KXf(_B0,_B1,_B2,_B3,_ctx, 21); sE6(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);  \
    KXf(_B0,_B1,_B2,_B3,_ctx, 22); sE7(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);  \
    KXf(_B0,_B1,_B2,_B3,_ctx, 23); sE8(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);  \
    KXf(_B0,_B1,_B2,_B3,_ctx, 24); sE1(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);  \
    KXf(_B0,_B1,_B2,_B3,_ctx, 25); sE2(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);  \
    KXf(_B0,_B1,_B2,_B3,_ctx, 26); sE3(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);  \
    KXf(_B0,_B1,_B2,_B3,_ctx, 27); sE4(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);  \
    KXf(_B0,_B1,_B2,_B3,_ctx, 28); sE5(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);  \
    KXf(_B0,_B1,_B2,_B3,_ctx, 29); sE6(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);  \
    KXf(_B0,_B1,_B2,_B3,_ctx, 30); sE7(_B0,_B1,_B2,_B3); LTf(_B0,_B1,_B2,_B3);  \
    KXf(_B0,_B1,_B2,_B3,_ctx, 31); sE8(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 32); \
    transpose(_B0,_B1,_B2,_B3);

/* Full Serpent decrypt (4 blocks in parallel) */
#define serpent256_neon_decrypt(_B0, _B1, _B2, _B3, _ctx)                       \
    transpose(_B0,_B1,_B2,_B3);                                                 \
    KXf(_B0,_B1,_B2,_B3,_ctx, 32); sD8(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 31); \
    ITf(_B0,_B1,_B2,_B3); sD7(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 30);  \
    ITf(_B0,_B1,_B2,_B3); sD6(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 29);  \
    ITf(_B0,_B1,_B2,_B3); sD5(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 28);  \
    ITf(_B0,_B1,_B2,_B3); sD4(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 27);  \
    ITf(_B0,_B1,_B2,_B3); sD3(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 26);  \
    ITf(_B0,_B1,_B2,_B3); sD2(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 25);  \
    ITf(_B0,_B1,_B2,_B3); sD1(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 24);  \
    ITf(_B0,_B1,_B2,_B3); sD8(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 23);  \
    ITf(_B0,_B1,_B2,_B3); sD7(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 22);  \
    ITf(_B0,_B1,_B2,_B3); sD6(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 21);  \
    ITf(_B0,_B1,_B2,_B3); sD5(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 20);  \
    ITf(_B0,_B1,_B2,_B3); sD4(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 19);  \
    ITf(_B0,_B1,_B2,_B3); sD3(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 18);  \
    ITf(_B0,_B1,_B2,_B3); sD2(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 17);  \
    ITf(_B0,_B1,_B2,_B3); sD1(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 16);  \
    ITf(_B0,_B1,_B2,_B3); sD8(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 15);  \
    ITf(_B0,_B1,_B2,_B3); sD7(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 14);  \
    ITf(_B0,_B1,_B2,_B3); sD6(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 13);  \
    ITf(_B0,_B1,_B2,_B3); sD5(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 12);  \
    ITf(_B0,_B1,_B2,_B3); sD4(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 11);  \
    ITf(_B0,_B1,_B2,_B3); sD3(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 10);  \
    ITf(_B0,_B1,_B2,_B3); sD2(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 9);   \
    ITf(_B0,_B1,_B2,_B3); sD1(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 8);   \
    ITf(_B0,_B1,_B2,_B3); sD8(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 7);   \
    ITf(_B0,_B1,_B2,_B3); sD7(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 6);   \
    ITf(_B0,_B1,_B2,_B3); sD6(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 5);   \
    ITf(_B0,_B1,_B2,_B3); sD5(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 4);   \
    ITf(_B0,_B1,_B2,_B3); sD4(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 3);   \
    ITf(_B0,_B1,_B2,_B3); sD3(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 2);   \
    ITf(_B0,_B1,_B2,_B3); sD2(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 1);   \
    ITf(_B0,_B1,_B2,_B3); sD1(_B0,_B1,_B2,_B3); KXf(_B0,_B1,_B2,_B3,_ctx, 0);   \
    transpose(_B0,_B1,_B2,_B3);

/* Polynomial for GF(2^128): x^128 + x^7 + x^2 + x + 1 = 0x87 in little-endian */
static const unsigned char serpent_xts_poly[16] = { 0x87, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

/* GF(2^128) multiply by x for XTS tweak - same as AES version */
static __forceinline uint8x16_t neon_next_tweak(uint8x16_t tweak)
{
    uint8x16_t poly_vec = vld1q_u8(serpent_xts_poly);
    int8x16_t  signed_tweak;
    uint8x16_t carry;
    unsigned char carry_bit;
    uint64x2_t tweak64;
    uint64x2_t shifted;
    uint64x2_t carry_between;
    unsigned __int64 carry_low;
    uint8x16_t result;

    signed_tweak = vreinterpretq_s8_u8(tweak);
    carry = vreinterpretq_u8_s8(vshrq_n_s8(signed_tweak, 7));
    carry_bit = vgetq_lane_u8(carry, 15);

    tweak64 = vreinterpretq_u64_u8(tweak);
    shifted = vshlq_n_u64(tweak64, 1);
    carry_between = vshrq_n_u64(tweak64, 63);
    carry_low = vgetq_lane_u64(carry_between, 0);
    shifted = vsetq_lane_u64(vgetq_lane_u64(shifted, 1) | carry_low, shifted, 1);

    result = vreinterpretq_u8_u64(shifted);
    if (carry_bit & 1) {
        result = veorq_u8(result, poly_vec);
    }

    return result;
}

/* XTS-Serpent encrypt using NEON */
void _stdcall xts_serpent_neon_encrypt(const unsigned char *in, unsigned char *out, size_t len, unsigned __int64 offset, xts_key *key)
{
    uint8x16_t t0_8, t1_8, t2_8, t3_8;
    uint32x4_t t0, t1, t2, t3;
    uint32x4_t b0, b1, b2, b3;
    uint8x16_t idx;
    unsigned __int64 sector_num;
    uint64x2_t idx64;
    int i;

    sector_num = offset / XTS_SECTOR_SIZE;

    do {
        sector_num++;

        /* Prepare index block */
        idx64 = vdupq_n_u64(0);
        idx64 = vsetq_lane_u64(sector_num, idx64, 0);
        idx = vreinterpretq_u8_u64(idx64);

        /* Derive first tweak value */
        serpent256_encrypt((const unsigned char *)&idx, (unsigned char *)&t0_8, &key->tweak_k.serpent);

        for (i = 0; i < XTS_BLOCKS_IN_SECTOR / 4; i++) {
            /* Derive t1-t3 */
            t1_8 = neon_next_tweak(t0_8);
            t2_8 = neon_next_tweak(t1_8);
            t3_8 = neon_next_tweak(t2_8);

            /* Convert to 32-bit vectors for Serpent */
            t0 = vreinterpretq_u32_u8(t0_8);
            t1 = vreinterpretq_u32_u8(t1_8);
            t2 = vreinterpretq_u32_u8(t2_8);
            t3 = vreinterpretq_u32_u8(t3_8);

            /* Load and pre-tweak 4 blocks */
            b0 = veorq_u32(vld1q_u32((const unsigned int *)(in + 0)),  t0);
            b1 = veorq_u32(vld1q_u32((const unsigned int *)(in + 16)), t1);
            b2 = veorq_u32(vld1q_u32((const unsigned int *)(in + 32)), t2);
            b3 = veorq_u32(vld1q_u32((const unsigned int *)(in + 48)), t3);

            /* Encrypt 4 blocks in parallel */
            serpent256_neon_encrypt(b0, b1, b2, b3, &key->crypt_k.serpent);

            /* Post-tweak and store */
            vst1q_u32((unsigned int *)(out + 0),  veorq_u32(b0, t0));
            vst1q_u32((unsigned int *)(out + 16), veorq_u32(b1, t1));
            vst1q_u32((unsigned int *)(out + 32), veorq_u32(b2, t2));
            vst1q_u32((unsigned int *)(out + 48), veorq_u32(b3, t3));

            /* Derive next t0 */
            t0_8 = neon_next_tweak(t3_8);

            in += XTS_BLOCK_SIZE * 4;
            out += XTS_BLOCK_SIZE * 4;
        }
    } while (len -= XTS_SECTOR_SIZE);
}

/* XTS-Serpent decrypt using NEON */
void _stdcall xts_serpent_neon_decrypt(const unsigned char *in, unsigned char *out, size_t len, unsigned __int64 offset, xts_key *key)
{
    uint8x16_t t0_8, t1_8, t2_8, t3_8;
    uint32x4_t t0, t1, t2, t3;
    uint32x4_t b0, b1, b2, b3;
    uint8x16_t idx;
    unsigned __int64 sector_num;
    uint64x2_t idx64;
    int i;

    sector_num = offset / XTS_SECTOR_SIZE;

    do {
        sector_num++;

        /* Prepare index block */
        idx64 = vdupq_n_u64(0);
        idx64 = vsetq_lane_u64(sector_num, idx64, 0);
        idx = vreinterpretq_u8_u64(idx64);

        /* Derive first tweak value */
        serpent256_encrypt((const unsigned char *)&idx, (unsigned char *)&t0_8, &key->tweak_k.serpent);

        for (i = 0; i < XTS_BLOCKS_IN_SECTOR / 4; i++) {
            /* Derive t1-t3 */
            t1_8 = neon_next_tweak(t0_8);
            t2_8 = neon_next_tweak(t1_8);
            t3_8 = neon_next_tweak(t2_8);

            /* Convert to 32-bit vectors for Serpent */
            t0 = vreinterpretq_u32_u8(t0_8);
            t1 = vreinterpretq_u32_u8(t1_8);
            t2 = vreinterpretq_u32_u8(t2_8);
            t3 = vreinterpretq_u32_u8(t3_8);

            /* Load and pre-tweak 4 blocks */
            b0 = veorq_u32(vld1q_u32((const unsigned int *)(in + 0)),  t0);
            b1 = veorq_u32(vld1q_u32((const unsigned int *)(in + 16)), t1);
            b2 = veorq_u32(vld1q_u32((const unsigned int *)(in + 32)), t2);
            b3 = veorq_u32(vld1q_u32((const unsigned int *)(in + 48)), t3);

            /* Decrypt 4 blocks in parallel */
            serpent256_neon_decrypt(b0, b1, b2, b3, &key->crypt_k.serpent);

            /* Post-tweak and store */
            vst1q_u32((unsigned int *)(out + 0),  veorq_u32(b0, t0));
            vst1q_u32((unsigned int *)(out + 16), veorq_u32(b1, t1));
            vst1q_u32((unsigned int *)(out + 32), veorq_u32(b2, t2));
            vst1q_u32((unsigned int *)(out + 48), veorq_u32(b3, t3));

            /* Derive next t0 */
            t0_8 = neon_next_tweak(t3_8);

            in += XTS_BLOCK_SIZE * 4;
            out += XTS_BLOCK_SIZE * 4;
        }
    } while (len -= XTS_SECTOR_SIZE);
}

#endif /* _M_ARM64 */
