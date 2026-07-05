#ifndef _INTRIN_H_
#define _INTRIN_H_

#include <Uefi.h> 
#include <Library/BaseLib.h> 
#include <Library/BaseMemoryLib.h>

#ifndef memcpy
#define memcpy(dest,source,count)         CopyMem(dest,source,(UINTN)(count))
#endif
#ifndef memset
#define memset(dest,ch,count)             SetMem(dest,(UINTN)(count),(UINT8)(ch))
#endif
#define memchr(buf,ch,count)              ScanMem8(buf,(UINTN)(count),(UINT8)ch)
#define memcmp(buf1,buf2,count)           (int)(CompareMem(buf1,buf2,(UINTN)(count)))


// config
#ifdef __GNUC__
	#define VC_INLINE	static inline __attribute__((always_inline))
#elif defined (_MSC_VER)
	#define VC_INLINE	__forceinline
#else
	#define VC_INLINE	static inline
#endif

//defs
#ifdef  __cplusplus
extern "C" {
#endif
extern unsigned __int64 __cdecl _rotl64(unsigned __int64,int);
extern unsigned __int64 __cdecl _rotr64(unsigned __int64,int);
extern unsigned int __cdecl _rotl(unsigned int,int);
extern unsigned int __cdecl _rotr(unsigned int,int);
extern unsigned char _rotr8(unsigned char value, unsigned char shift);
extern unsigned short _rotr16(unsigned short value, unsigned char shift);
extern unsigned char _rotl8(unsigned char value, unsigned char shift);
extern unsigned short _rotl16(unsigned short value, unsigned char shift);
#ifdef  __cplusplus
}
#endif

#ifdef TC_NO_COMPILER_INT64
typedef unsigned __int32	TC_LARGEST_COMPILER_UINT;
#else
typedef unsigned __int64	TC_LARGEST_COMPILER_UINT;
typedef __int64 int64;
typedef unsigned __int64 uint64;
#define LL(x) x##ui64
#endif

// misc
#if defined(_MSC_VER) && !defined(_UEFI)
	#if _MSC_VER >= 1400
		#if !defined(TC_WINDOWS_DRIVER) && !defined(_UEFI)
			// VC2005 workaround: disable declarations that conflict with winnt.h
			#define _interlockedbittestandset CRYPTOPP_DISABLED_INTRINSIC_1
			#define _interlockedbittestandreset CRYPTOPP_DISABLED_INTRINSIC_2
			#define _interlockedbittestandset64 CRYPTOPP_DISABLED_INTRINSIC_3
			#define _interlockedbittestandreset64 CRYPTOPP_DISABLED_INTRINSIC_4
			#include <intrin.h>
			#undef _interlockedbittestandset
			#undef _interlockedbittestandreset
			#undef _interlockedbittestandset64
			#undef _interlockedbittestandreset64
		#endif
		#define CRYPTOPP_FAST_ROTATE(x) 1
	#elif !defined(_UEFI) &&  _MSC_VER >= 1300
		#define CRYPTOPP_FAST_ROTATE(x) ((x) == 32 | (x) == 64)
	#else
		#define CRYPTOPP_FAST_ROTATE(x) ((x) == 32)
	#endif
#elif (defined(__MWERKS__) && TARGET_CPU_PPC) || \
	(defined(__GNUC__) && (defined(_ARCH_PWR2) || defined(_ARCH_PWR) || defined(_ARCH_PPC) || defined(_ARCH_PPC64) || defined(_ARCH_COM)))
	#define CRYPTOPP_FAST_ROTATE(x) ((x) == 32)
#elif defined(__GNUC__) && (CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X86)	// depend on GCC's peephole optimization to generate rotate instructions
	#define CRYPTOPP_FAST_ROTATE(x) 1
#else
	#define CRYPTOPP_FAST_ROTATE(x) 0
#endif

#if defined( _MSC_VER ) && ( _MSC_VER > 800 ) && !defined(_UEFI)
#pragma intrinsic(memcpy,memset)
#endif

#if _MSC_VER >= 1300 && !defined(__INTEL_COMPILER)
// Intel C++ Compiler 10.0 calls a function instead of using the rotate instruction when using these instructions
#pragma intrinsic(_rotr,_rotl,_rotr64,_rotl64)

#define rotr32(x,n)	_rotr(x, n)
#define rotl32(x,n)	_rotl(x, n)
#define rotr64(x,n)	_rotr64(x, n)
#define rotl64(x,n)	_rotl64(x, n)

#else

#define rotr32(x,n)	(((x) >> n) | ((x) << (32 - n)))
#define rotl32(x,n)	(((x) << n) | ((x) >> (32 - n)))
#define rotr64(x,n)	(((x) >> n) | ((x) << (64 - n)))
#define rotl64(x,n)	(((x) << n) | ((x) >> (64 - n)))

#endif

#if _MSC_VER >= 1400 && !defined(__INTEL_COMPILER)
// Intel C++ Compiler 10.0 calls a function instead of using the rotate instruction when using these instructions
#pragma intrinsic(_rotr8,_rotl8,_rotr16,_rotl16)

#define rotr8(x,n)	_rotr8(x, n)
#define rotl8(x,n)	_rotl8(x, n)
#define rotr16(x,n)	_rotr16(x, n)
#define rotl16(x,n)	_rotl16(x, n)

#else

#define rotr8(x,n)	(((x) >> n) | ((x) << (8 - n)))
#define rotl8(x,n)	(((x) << n) | ((x) >> (8 - n)))
#define rotr16(x,n)	(((x) >> n) | ((x) << (16 - n)))
#define rotl16(x,n)	(((x) << n) | ((x) >> (16 - n)))

#endif

#if defined(__GNUC__) && defined(__linux__)
#define CRYPTOPP_BYTESWAP_AVAILABLE
#include <byteswap.h>
#elif defined(_MSC_VER) && _MSC_VER >= 1300 && !defined(_UEFI)
#pragma intrinsic(_byteswap_ulong,_byteswap_uint64)
#define CRYPTOPP_BYTESWAP_AVAILABLE
#define bswap_32(x)	_byteswap_ulong(x)
#define bswap_64(x)	_byteswap_uint64(x)
#elif defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define CRYPTOPP_BYTESWAP_AVAILABLE
#define bswap_16 OSSwapInt16
#define bswap_32 OSSwapInt32
#define bswap_64 OSSwapInt64
#else
#if CRYPTOPP_FAST_ROTATE(32)
#define bswap_32(x)	(rotr32((x), 8U) & 0xff00ff00) | (rotl32((x), 8U) & 0x00ff00ff)
#else
#define CRYPTOPP_BYTESWAP_AVAILABLE
#define bswap_32(x)	(rotl32((((x) & 0xFF00FF00) >> 8) | (((x) & 0x00FF00FF) << 8), 16U))
#define bswap_64(x)	rotl64(((((((x & LL(0xFF00FF00FF00FF00)) >> 8) | ((x & LL(0x00FF00FF00FF00FF)) << 8)) & LL(0xFFFF0000FFFF0000)) >> 16) | (((((x & LL(0xFF00FF00FF00FF00)) >> 8) | ((x & LL(0x00FF00FF00FF00FF)) << 8)) & LL(0x0000FFFF0000FFFF)) << 16)), 32U)
#endif
#ifndef TC_NO_COMPILER_INT64
#define bswap_64(x)	rotl64(((((((x & LL(0xFF00FF00FF00FF00)) >> 8) | ((x & LL(0x00FF00FF00FF00FF)) << 8)) & LL(0xFFFF0000FFFF0000)) >> 16) | (((((x & LL(0xFF00FF00FF00FF00)) >> 8) | ((x & LL(0x00FF00FF00FF00FF)) << 8)) & LL(0x0000FFFF0000FFFF)) << 16)), 32U)
#endif
#endif

VC_INLINE unsigned int ByteReverseWord32 (unsigned int value)
{
#if defined(__GNUC__) && defined(CRYPTOPP_X86_ASM_AVAILABLE)
	__asm__ ("bswap %0" : "=r" (value) : "0" (value));
	return value;
#elif defined(CRYPTOPP_BYTESWAP_AVAILABLE)
	return bswap_32(value);
#elif defined(__MWERKS__) && TARGET_CPU_PPC
	return (uint32)__lwbrx(&value,0);
#elif _MSC_VER >= 1400 || (_MSC_VER >= 1300 && !defined(_DLL))
	return _byteswap_ulong(value);
#elif CRYPTOPP_FAST_ROTATE(32)
	// 5 instructions with rotate instruction, 9 without
	return (rotr32(value, 8U) & 0xff00ff00) | (rotl32(value, 8U) & 0x00ff00ff);
#else
	// 6 instructions with rotate instruction, 8 without
	value = ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8);
	return rotl32(value, 16U);
#endif
}

#ifndef TC_NO_COMPILER_INT64

VC_INLINE unsigned __int64 ByteReverseWord64(unsigned __int64 value)
{
#if defined(__GNUC__) && defined(CRYPTOPP_X86_ASM_AVAILABLE) && defined(__x86_64__)
	__asm__ ("bswap %0" : "=r" (value) : "0" (value));
	return value;
#elif defined(CRYPTOPP_BYTESWAP_AVAILABLE)
	return bswap_64(value);
#elif defined(_MSC_VER) && _MSC_VER >= 1300
	return _byteswap_uint64(value);
#else
	value = ((value & LL(0xFF00FF00FF00FF00)) >> 8) | ((value & LL(0x00FF00FF00FF00FF)) << 8);
	value = ((value & LL(0xFFFF0000FFFF0000)) >> 16) | ((value & LL(0x0000FFFF0000FFFF)) << 16);
	return rotl64(value, 32U);
#endif
}

VC_INLINE void CorrectEndianess(unsigned __int64 *out, const unsigned __int64 *in, UINTN byteCount)

{
	UINTN i, count = byteCount/sizeof(unsigned __int64);
	for (i=0; i<count; i++)
		out[i] = ByteReverseWord64(in[i]);
}

#endif

#define _byteswap_ulong(x)		bswap_32(x)
#define _byteswap_uint64(x)		bswap_64(x)

/* __stosd is x86-specific, provide portable replacement */
#ifndef __stosd
#define __stosd(dst, val, count) do { \
    unsigned long *_p = (unsigned long*)(dst); \
    UINTN _n = (count); \
    while (_n--) *_p++ = (val); \
} while(0)
#endif

#endif // _INTRIN_H_
