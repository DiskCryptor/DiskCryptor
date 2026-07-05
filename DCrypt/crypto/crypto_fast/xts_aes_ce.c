/*
    *
    * DiskCryptor - open source partition encryption tool
    * ARM64 AES with Crypto Extensions (CE) implementation
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

#ifdef _M_ARM64

#include <arm_neon.h>
#if !defined(_KERNEL_MODE) && !defined(_UEFI)
#include <Windows.h>
#endif
#include "aes_key.h"
#include "xts_fast.h"
#include "xts_aes_ce.h"

/* Check for ARM64 Crypto Extensions support */
int _stdcall xts_aes_ce_available(void)
{
#if defined(_KERNEL_MODE) || defined(_UEFI)
    /* ARM64 Crypto Extensions are mandatory on Windows/UEFI ARM64 */
    return 1;
#else
    return IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE);
#endif
}

/* Single block AES-256 encrypt using ARM64 CE
 * ARM64 AESE does: AddRoundKey, SubBytes, ShiftRows (in that order)
 * So we need: 13x (AESE+AESMC) + 1x AESE + final XOR
 */
void _stdcall aes256_arm64_encrypt(const unsigned char *in, unsigned char *out, aes256_key *key)
{
    uint8x16_t block = vld1q_u8(in);

    /* Rounds 0-12: AESE (AddRoundKey + SubBytes + ShiftRows) + AESMC (MixColumns) */
    block = vaeseq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->enc_key[0])));
    block = vaesmcq_u8(block);
    block = vaeseq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->enc_key[4])));
    block = vaesmcq_u8(block);
    block = vaeseq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->enc_key[8])));
    block = vaesmcq_u8(block);
    block = vaeseq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->enc_key[12])));
    block = vaesmcq_u8(block);
    block = vaeseq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->enc_key[16])));
    block = vaesmcq_u8(block);
    block = vaeseq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->enc_key[20])));
    block = vaesmcq_u8(block);
    block = vaeseq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->enc_key[24])));
    block = vaesmcq_u8(block);
    block = vaeseq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->enc_key[28])));
    block = vaesmcq_u8(block);
    block = vaeseq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->enc_key[32])));
    block = vaesmcq_u8(block);
    block = vaeseq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->enc_key[36])));
    block = vaesmcq_u8(block);
    block = vaeseq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->enc_key[40])));
    block = vaesmcq_u8(block);
    block = vaeseq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->enc_key[44])));
    block = vaesmcq_u8(block);
    block = vaeseq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->enc_key[48])));
    block = vaesmcq_u8(block);

    /* Round 13: AESE only (no MixColumns for final round) */
    block = vaeseq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->enc_key[52])));

    /* Final AddRoundKey */
    block = veorq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->enc_key[56])));

    vst1q_u8(out, block);
}

/* Single block AES-256 decrypt using ARM64 CE
 * ARM64 AESD does: AddRoundKey, InvSubBytes, InvShiftRows (in that order)
 * So we need: 13x (AESD+AESIMC) + 1x AESD + final XOR
 */
void _stdcall aes256_arm64_decrypt(const unsigned char *in, unsigned char *out, aes256_key *key)
{
    uint8x16_t block = vld1q_u8(in);

    /* Rounds 0-12: AESD (AddRoundKey + InvSubBytes + InvShiftRows) + AESIMC (InvMixColumns) */
    block = vaesdq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->dec_key[0])));
    block = vaesimcq_u8(block);
    block = vaesdq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->dec_key[4])));
    block = vaesimcq_u8(block);
    block = vaesdq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->dec_key[8])));
    block = vaesimcq_u8(block);
    block = vaesdq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->dec_key[12])));
    block = vaesimcq_u8(block);
    block = vaesdq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->dec_key[16])));
    block = vaesimcq_u8(block);
    block = vaesdq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->dec_key[20])));
    block = vaesimcq_u8(block);
    block = vaesdq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->dec_key[24])));
    block = vaesimcq_u8(block);
    block = vaesdq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->dec_key[28])));
    block = vaesimcq_u8(block);
    block = vaesdq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->dec_key[32])));
    block = vaesimcq_u8(block);
    block = vaesdq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->dec_key[36])));
    block = vaesimcq_u8(block);
    block = vaesdq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->dec_key[40])));
    block = vaesimcq_u8(block);
    block = vaesdq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->dec_key[44])));
    block = vaesimcq_u8(block);
    block = vaesdq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->dec_key[48])));
    block = vaesimcq_u8(block);

    /* Round 13: AESD only (no InvMixColumns for final round) */
    block = vaesdq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->dec_key[52])));

    /* Final AddRoundKey */
    block = veorq_u8(block, vreinterpretq_u8_u32(vld1q_u32(&key->dec_key[56])));

    vst1q_u8(out, block);
}

/* Polynomial for GF(2^128): x^128 + x^7 + x^2 + x + 1 = 0x87 in little-endian */
static const unsigned char xts_poly[16] = { 0x87, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

/* GF(2^128) multiply by x for XTS tweak */
static __forceinline uint8x16_t neon_next_tweak(uint8x16_t tweak)
{
    uint8x16_t poly_vec = vld1q_u8(xts_poly);
    int8x16_t  signed_tweak;
    uint8x16_t carry;
    unsigned char carry_bit;
    uint64x2_t tweak64;
    uint64x2_t shifted;
    uint64x2_t carry_between;
    unsigned __int64 carry_low;
    uint8x16_t result;

    /* Get the high bit of the last byte (bit 127) */
    signed_tweak = vreinterpretq_s8_u8(tweak);
    carry = vreinterpretq_u8_s8(vshrq_n_s8(signed_tweak, 7));

    /* Extract carry from bit 127 */
    carry_bit = vgetq_lane_u8(carry, 15);

    /* Shift left by 1 using 64-bit operations */
    tweak64 = vreinterpretq_u64_u8(tweak);
    shifted = vshlq_n_u64(tweak64, 1);

    /* Handle carry between the two 64-bit halves */
    carry_between = vshrq_n_u64(tweak64, 63);
    carry_low = vgetq_lane_u64(carry_between, 0);
    shifted = vsetq_lane_u64(vgetq_lane_u64(shifted, 1) | carry_low, shifted, 1);

    /* XOR with polynomial if carry_bit was set */
    result = vreinterpretq_u8_u64(shifted);
    if (carry_bit & 1) {
        result = veorq_u8(result, poly_vec);
    }

    return result;
}

/* XTS-AES-256 encrypt using ARM64 CE - processes 4 blocks at a time */
void _stdcall xts_aes_ce_encrypt(const unsigned char *in, unsigned char *out, size_t len, unsigned __int64 offset, xts_key *key)
{
    uint8x16_t t0, t1, t2, t3;
    uint8x16_t b0, b1, b2, b3;
    uint8x16_t idx;
    unsigned __int64 sector_num;
    uint64x2_t idx64;
    int i;

    sector_num = offset / XTS_SECTOR_SIZE;

    do {
        /* Update tweak unit index */
        sector_num++;

        /* Prepare index block */
        idx64 = vdupq_n_u64(0);
        idx64 = vsetq_lane_u64(sector_num, idx64, 0);
        idx = vreinterpretq_u8_u64(idx64);

        /* Derive first tweak value by encrypting sector number */
        aes256_arm64_encrypt((const unsigned char *)&idx, (unsigned char *)&t0, &key->tweak_k.aes);

        for (i = 0; i < XTS_BLOCKS_IN_SECTOR / 4; i++) {
            /* Derive t1-t3 */
            t1 = neon_next_tweak(t0);
            t2 = neon_next_tweak(t1);
            t3 = neon_next_tweak(t2);

            /* Load and pre-tweak 4 blocks */
            b0 = veorq_u8(vld1q_u8(in + 0),  t0);
            b1 = veorq_u8(vld1q_u8(in + 16), t1);
            b2 = veorq_u8(vld1q_u8(in + 32), t2);
            b3 = veorq_u8(vld1q_u8(in + 48), t3);

            /* Encrypt 4 blocks - inline AES rounds for better performance */
            {
                uint8x16_t rk;

                #define AES_ENC_ROUND(rk_idx) \
                    rk = vreinterpretq_u8_u32(vld1q_u32(&key->crypt_k.aes.enc_key[rk_idx])); \
                    b0 = vaeseq_u8(b0, rk); b0 = vaesmcq_u8(b0); \
                    b1 = vaeseq_u8(b1, rk); b1 = vaesmcq_u8(b1); \
                    b2 = vaeseq_u8(b2, rk); b2 = vaesmcq_u8(b2); \
                    b3 = vaeseq_u8(b3, rk); b3 = vaesmcq_u8(b3);

                /* Rounds 0-12: AESE + AESMC */
                AES_ENC_ROUND(0);
                AES_ENC_ROUND(4);
                AES_ENC_ROUND(8);
                AES_ENC_ROUND(12);
                AES_ENC_ROUND(16);
                AES_ENC_ROUND(20);
                AES_ENC_ROUND(24);
                AES_ENC_ROUND(28);
                AES_ENC_ROUND(32);
                AES_ENC_ROUND(36);
                AES_ENC_ROUND(40);
                AES_ENC_ROUND(44);
                AES_ENC_ROUND(48);

                /* Round 13: AESE only (no MixColumns) */
                rk = vreinterpretq_u8_u32(vld1q_u32(&key->crypt_k.aes.enc_key[52]));
                b0 = vaeseq_u8(b0, rk);
                b1 = vaeseq_u8(b1, rk);
                b2 = vaeseq_u8(b2, rk);
                b3 = vaeseq_u8(b3, rk);

                /* Final AddRoundKey */
                rk = vreinterpretq_u8_u32(vld1q_u32(&key->crypt_k.aes.enc_key[56]));
                b0 = veorq_u8(b0, rk);
                b1 = veorq_u8(b1, rk);
                b2 = veorq_u8(b2, rk);
                b3 = veorq_u8(b3, rk);

                #undef AES_ENC_ROUND
            }

            /* Post-tweak and store */
            vst1q_u8(out + 0,  veorq_u8(b0, t0));
            vst1q_u8(out + 16, veorq_u8(b1, t1));
            vst1q_u8(out + 32, veorq_u8(b2, t2));
            vst1q_u8(out + 48, veorq_u8(b3, t3));

            /* Derive next t0 */
            t0 = neon_next_tweak(t3);

            /* Update pointers */
            in += XTS_BLOCK_SIZE * 4;
            out += XTS_BLOCK_SIZE * 4;
        }
    } while (len -= XTS_SECTOR_SIZE);
}

/* XTS-AES-256 decrypt using ARM64 CE - processes 4 blocks at a time */
void _stdcall xts_aes_ce_decrypt(const unsigned char *in, unsigned char *out, size_t len, unsigned __int64 offset, xts_key *key)
{
    uint8x16_t t0, t1, t2, t3;
    uint8x16_t b0, b1, b2, b3;
    uint8x16_t idx;
    unsigned __int64 sector_num;
    uint64x2_t idx64;
    int i;

    sector_num = offset / XTS_SECTOR_SIZE;

    do {
        /* Update tweak unit index */
        sector_num++;

        /* Prepare index block */
        idx64 = vdupq_n_u64(0);
        idx64 = vsetq_lane_u64(sector_num, idx64, 0);
        idx = vreinterpretq_u8_u64(idx64);

        /* Derive first tweak value by encrypting sector number */
        aes256_arm64_encrypt((const unsigned char *)&idx, (unsigned char *)&t0, &key->tweak_k.aes);

        for (i = 0; i < XTS_BLOCKS_IN_SECTOR / 4; i++) {
            /* Derive t1-t3 */
            t1 = neon_next_tweak(t0);
            t2 = neon_next_tweak(t1);
            t3 = neon_next_tweak(t2);

            /* Load and pre-tweak 4 blocks */
            b0 = veorq_u8(vld1q_u8(in + 0),  t0);
            b1 = veorq_u8(vld1q_u8(in + 16), t1);
            b2 = veorq_u8(vld1q_u8(in + 32), t2);
            b3 = veorq_u8(vld1q_u8(in + 48), t3);

            /* Decrypt 4 blocks - inline AES rounds for better performance */
            {
                uint8x16_t rk;

                #define AES_DEC_ROUND(rk_idx) \
                    rk = vreinterpretq_u8_u32(vld1q_u32(&key->crypt_k.aes.dec_key[rk_idx])); \
                    b0 = vaesdq_u8(b0, rk); b0 = vaesimcq_u8(b0); \
                    b1 = vaesdq_u8(b1, rk); b1 = vaesimcq_u8(b1); \
                    b2 = vaesdq_u8(b2, rk); b2 = vaesimcq_u8(b2); \
                    b3 = vaesdq_u8(b3, rk); b3 = vaesimcq_u8(b3);

                /* Rounds 0-12: AESD + AESIMC */
                AES_DEC_ROUND(0);
                AES_DEC_ROUND(4);
                AES_DEC_ROUND(8);
                AES_DEC_ROUND(12);
                AES_DEC_ROUND(16);
                AES_DEC_ROUND(20);
                AES_DEC_ROUND(24);
                AES_DEC_ROUND(28);
                AES_DEC_ROUND(32);
                AES_DEC_ROUND(36);
                AES_DEC_ROUND(40);
                AES_DEC_ROUND(44);
                AES_DEC_ROUND(48);

                /* Round 13: AESD only (no InvMixColumns) */
                rk = vreinterpretq_u8_u32(vld1q_u32(&key->crypt_k.aes.dec_key[52]));
                b0 = vaesdq_u8(b0, rk);
                b1 = vaesdq_u8(b1, rk);
                b2 = vaesdq_u8(b2, rk);
                b3 = vaesdq_u8(b3, rk);

                /* Final AddRoundKey */
                rk = vreinterpretq_u8_u32(vld1q_u32(&key->crypt_k.aes.dec_key[56]));
                b0 = veorq_u8(b0, rk);
                b1 = veorq_u8(b1, rk);
                b2 = veorq_u8(b2, rk);
                b3 = veorq_u8(b3, rk);

                #undef AES_DEC_ROUND
            }

            /* Post-tweak and store */
            vst1q_u8(out + 0,  veorq_u8(b0, t0));
            vst1q_u8(out + 16, veorq_u8(b1, t1));
            vst1q_u8(out + 32, veorq_u8(b2, t2));
            vst1q_u8(out + 48, veorq_u8(b3, t3));

            /* Derive next t0 */
            t0 = neon_next_tweak(t3);

            /* Update pointers */
            in += XTS_BLOCK_SIZE * 4;
            out += XTS_BLOCK_SIZE * 4;
        }
    } while (len -= XTS_SECTOR_SIZE);
}

#endif /* _M_ARM64 */
