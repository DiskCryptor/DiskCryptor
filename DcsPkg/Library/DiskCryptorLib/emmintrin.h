#ifndef _EMMINTRIN_UEFI_H
#define _EMMINTRIN_UEFI_H

#ifndef CRYPTOPP_ALIGN_DATA
	#if defined(_MSC_VER)
		#define CRYPTOPP_ALIGN_DATA(x) __declspec(align(x))
	#elif defined(__GNUC__)
		#define CRYPTOPP_ALIGN_DATA(x) __attribute__((aligned(x)))
	#else
		#define CRYPTOPP_ALIGN_DATA(x)
	#endif
#endif

#ifndef CRYPTOPP_SECTION_ALIGN16
	#if defined(__GNUC__) && !defined(__APPLE__)
		// the alignment attribute doesn't seem to work without this section attribute when -fdata-sections is turned on
		#define CRYPTOPP_SECTION_ALIGN16 __attribute__((section ("CryptoPP_Align16")))
	#else
		#define CRYPTOPP_SECTION_ALIGN16
	#endif
#endif


typedef union __declspec(intrin_type) CRYPTOPP_ALIGN_DATA(8) __m64
{
    unsigned __int64    m64_u64;
    float               m64_f32[2];
    __int8              m64_i8[8];
    __int16             m64_i16[4];
    __int32             m64_i32[2];
    __int64             m64_i64;
    unsigned __int8     m64_u8[8];
    unsigned __int16    m64_u16[4];
    unsigned __int32    m64_u32[2];
} __m64;

typedef union __declspec(intrin_type) CRYPTOPP_ALIGN_DATA(16) __m128 {
     float               m128_f32[4];
     unsigned __int64    m128_u64[2];
     __int8              m128_i8[16];
     __int16             m128_i16[8];
     __int32             m128_i32[4];
     __int64             m128_i64[2];
     unsigned __int8     m128_u8[16];
     unsigned __int16    m128_u16[8];
     unsigned __int32    m128_u32[4];
 } __m128;

typedef union __declspec(intrin_type) CRYPTOPP_ALIGN_DATA(16) __m128i {
    __int8              m128i_i8[16];
    __int16             m128i_i16[8];
    __int32             m128i_i32[4];
    __int64             m128i_i64[2];
    unsigned __int8     m128i_u8[16];
    unsigned __int16    m128i_u16[8];
    unsigned __int32    m128i_u32[4];
    unsigned __int64    m128i_u64[2];
} __m128i;

typedef struct __declspec(intrin_type) CRYPTOPP_ALIGN_DATA(16) __m128d {
    double              m128d_f64[2];
} __m128d;

#define _MM_SHUFFLE2(x,y) (((x)<<1) | (y))
#define _MM_SHUFFLE(fp3,fp2,fp1,fp0) (((fp3) << 6) | ((fp2) << 4) | \
                                     ((fp1) << 2) | ((fp0)))

/*
 * SSE/SSE2 Intrinsic declarations for MSVC
 * These are compiler intrinsics - MSVC recognizes them by name and generates
 * inline SSE instructions. No 'extern' keyword - that would make them external linkage.
 */

void  __cdecl _m_empty(void);
__m64 __cdecl _m_pxor(__m64 _MM1, __m64 _MM2);

#define _mm_xor_si64      _m_pxor
#define _mm_empty         _m_empty

/* SSE2 Integer intrinsics */
int __cdecl _mm_extract_epi16(__m128i _A, int _Imm);
__m128i __cdecl _mm_load_si128(__m128i const*_P);
__m128i __cdecl _mm_loadu_si128(__m128i const*_P);
void __cdecl _mm_store_si128(__m128i *_P, __m128i _B);
void __cdecl _mm_storeu_si128(__m128i *_P, __m128i _B);

__m128i __cdecl _mm_xor_si128(__m128i _A, __m128i _B);
__m128i __cdecl _mm_or_si128(__m128i _A, __m128i _B);
__m128i __cdecl _mm_and_si128(__m128i _A, __m128i _B);
__m128i __cdecl _mm_andnot_si128(__m128i _A, __m128i _B);

__m128i __cdecl _mm_add_epi32(__m128i _A, __m128i _B);
__m128i __cdecl _mm_add_epi64(__m128i _A, __m128i _B);
__m128i __cdecl _mm_sub_epi32(__m128i _A, __m128i _B);
__m128i __cdecl _mm_mul_epu32(__m128i _A, __m128i _B);

__m128i __cdecl _mm_slli_si128(__m128i _A, int _Imm);
__m128i __cdecl _mm_slli_epi16(__m128i _A, int _Count);
__m128i __cdecl _mm_slli_epi32(__m128i _A, int _Count);
__m128i __cdecl _mm_slli_epi64(__m128i _A, int _Count);
__m128i __cdecl _mm_sll_epi16(__m128i _A, __m128i _Count);
__m128i __cdecl _mm_sll_epi32(__m128i _A, __m128i _Count);
__m128i __cdecl _mm_sll_epi64(__m128i _A, __m128i _Count);

__m128i __cdecl _mm_srli_si128(__m128i _A, int _Imm);
__m128i __cdecl _mm_srli_epi16(__m128i _A, int _Count);
__m128i __cdecl _mm_srli_epi32(__m128i _A, int _Count);
__m128i __cdecl _mm_srli_epi64(__m128i _A, int _Count);
__m128i __cdecl _mm_srl_epi16(__m128i _A, __m128i _Count);
__m128i __cdecl _mm_srl_epi32(__m128i _A, __m128i _Count);
__m128i __cdecl _mm_srl_epi64(__m128i _A, __m128i _Count);

__m128i __cdecl _mm_srai_epi16(__m128i _A, int _Count);
__m128i __cdecl _mm_srai_epi32(__m128i _A, int _Count);
__m128i __cdecl _mm_sra_epi16(__m128i _A, __m128i _Count);
__m128i __cdecl _mm_sra_epi32(__m128i _A, __m128i _Count);

__m128i __cdecl _mm_shuffle_epi32(__m128i _A, int _Imm);
__m128i __cdecl _mm_shufflehi_epi16(__m128i _A, int _Imm);
__m128i __cdecl _mm_shufflelo_epi16(__m128i _A, int _Imm);

__m128i __cdecl _mm_unpacklo_epi32(__m128i _A, __m128i _B);
__m128i __cdecl _mm_unpackhi_epi32(__m128i _A, __m128i _B);
__m128i __cdecl _mm_unpacklo_epi64(__m128i _A, __m128i _B);
__m128i __cdecl _mm_unpackhi_epi64(__m128i _A, __m128i _B);

__m128i __cdecl _mm_cvtsi64_si128(__int64);
__m128i __cdecl _mm_set_epi64(__m64 _Q1, __m64 _Q0);
__m128i __cdecl _mm_set_epi32(int _I3, int _I2, int _I1, int _I0);
__m128i __cdecl _mm_setr_epi32(int _I0, int _I1, int _I2, int _I3);
__m128i __cdecl _mm_set1_epi32(int _I);

/* AES-NI intrinsic */
__m128i __cdecl _mm_aesenc_si128(__m128i /* v */, __m128i /* rkey */);

#endif /* _EMMINTRIN_UEFI_H */