/*
 * Copyright (c) 2026 Vector 35 Inc
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef BN_PSEUDOC_HELPERS_H
#define BN_PSEUDOC_HELPERS_H

/* Standalone scalar helpers for Binary Ninja Pseudo C. No Binary Ninja library
 * is required. See README.md for the supported subset and compilation examples.
 * C requires GCC/Clang extensions; C++ uses C++11 templates and memcpy.
 */
/* Some C++ standard libraries undefine min/max, while others cannot be included
 * with those macros active. Preserve caller definitions across the includes.
 */
#ifdef min
#pragma push_macro("min")
#undef min
#define BN_PSEUDOC_RESTORE_MIN
#endif
#ifdef max
#pragma push_macro("max")
#undef max
#define BN_PSEUDOC_RESTORE_MAX
#endif

#include <limits.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if CHAR_BIT != 8
#error "Pseudo C helpers require eight-bit bytes"
#endif

#ifdef __cplusplus
#include <type_traits>
#if __cplusplus < 201103L && (!defined(_MSVC_LANG) || _MSVC_LANG < 201103L)
#error "Pseudo C helpers require C++11 or later"
#endif
#else
#include <stdbool.h>
#if !defined(__GNUC__) && !defined(__clang__)
#error "Pseudo C helpers require GCC/Clang C11 extensions, or C++11 mode"
#endif
#endif

#ifdef BN_PSEUDOC_RESTORE_MIN
#pragma pop_macro("min")
#undef BN_PSEUDOC_RESTORE_MIN
#endif
#ifdef BN_PSEUDOC_RESTORE_MAX
#pragma pop_macro("max")
#undef BN_PSEUDOC_RESTORE_MAX
#endif

#if defined(__SIZEOF_INT128__) && __SIZEOF_INT128__ == 16
#define BN_PSEUDOC_HAS_INT128 1
__extension__ typedef unsigned __int128 bn_pseudoc_uint128;
#ifndef BN_PSEUDOC_NO_EXTENDED_TYPES
__extension__ typedef __int128 int128_t;
typedef bn_pseudoc_uint128 uint128_t;
#endif
#else
#define BN_PSEUDOC_HAS_INT128 0
#endif

#if defined(__FLT16_MANT_DIG__) && __FLT16_MANT_DIG__ == 11 && __FLT16_MAX_EXP__ == 16
#define BN_PSEUDOC_HAS_FLOAT16 1
#ifndef BN_PSEUDOC_NO_EXTENDED_TYPES
typedef _Float16 float16;
typedef _Float16 float16_t;
#endif
#else
#define BN_PSEUDOC_HAS_FLOAT16 0
#endif

/* Annotation only. Do not erase custom calling conventions: the header cannot
 * reconstruct their ABI. An existing user definition takes precedence.
 */
#ifndef __pure
#define __pure
#endif
#ifndef __noreturn
#define __noreturn
#endif

#ifdef __cplusplus
namespace bn_pseudoc_detail
{

template <class To, class From>
inline typename std::remove_cv<To>::type bit_cast(From value)
{
	typename std::remove_cv<To>::type result;
	static_assert(sizeof(result) == sizeof(value), "BIT_CAST size mismatch");
	static_assert(std::is_trivially_copyable<To>::value && std::is_trivially_copyable<From>::value,
		"BIT_CAST requires trivially copyable types");
	memcpy(&result, &value, sizeof(result));
	return result;
}

template <class To, size_t Offset, class From>
inline typename std::remove_cv<To>::type read_part(From value)
{
	typename std::remove_cv<To>::type result;
	static_assert(Offset <= sizeof(value) && sizeof(result) <= sizeof(value) - Offset,
		"READ_PART outside source");
	static_assert(std::is_trivially_copyable<To>::value && std::is_trivially_copyable<From>::value,
		"READ_PART requires trivially copyable types");
	memcpy(&result, reinterpret_cast<const unsigned char*>(&value) + Offset, sizeof(result));
	return result;
}

template <class Part, size_t Offset, class To, class From>
inline void write_part(To& destination, From value)
{
	static_assert(sizeof(Part) == sizeof(value), "WRITE_PART size mismatch");
	static_assert(Offset <= sizeof(destination) && sizeof(Part) <= sizeof(destination) - Offset,
		"WRITE_PART outside destination");
	static_assert(!std::is_const<To>::value && !std::is_volatile<To>::value,
		"WRITE_PART requires a non-const, non-volatile destination");
	static_assert(std::is_trivially_copyable<To>::value && std::is_trivially_copyable<From>::value,
		"WRITE_PART requires trivially copyable types");
	memcpy(reinterpret_cast<unsigned char*>(&destination) + Offset, &value, sizeof(value));
}

} // namespace bn_pseudoc_detail

#ifndef BIT_CAST
#define BIT_CAST(type, value) (::bn_pseudoc_detail::bit_cast<type>((value)))
#endif
#ifndef READ_PART
#define READ_PART(type, value, offset) (::bn_pseudoc_detail::read_part<type, (offset)>((value)))
#endif
#ifndef WRITE_PART
/* Sequence destination evaluation before value evaluation, as in the C helper. */
#define WRITE_PART(type, destination, offset, value) ([&]() { \
	auto* _bn_part_destination = &(destination); \
	auto _bn_part_value = (value); \
	::bn_pseudoc_detail::write_part<type, (offset)>(*_bn_part_destination, _bn_part_value); \
}())
#endif

#else /* GCC/Clang C */

#ifndef BIT_CAST
/* The comma expression strips top-level qualifiers without integer promotion.
 * typeof is unevaluated: a bit copy must not need a floating conversion merely
 * to initialize its destination (notably _Float16 under Clang-CL).
 */
#define BIT_CAST(type, value) __extension__ ({ \
	__auto_type _bn_bit_cast_source = (value); \
	__typeof__((void)0, (type){0}) _bn_bit_cast_result; \
	_Static_assert(sizeof(_bn_bit_cast_result) == sizeof(_bn_bit_cast_source), "BIT_CAST size mismatch"); \
	memcpy(&_bn_bit_cast_result, &_bn_bit_cast_source, sizeof(_bn_bit_cast_result)); \
	_bn_bit_cast_result; \
})
#endif
#ifndef READ_PART
#define READ_PART(type, value, offset) __extension__ ({ \
	__auto_type _bn_part_source = (value); \
	__typeof__((void)0, (type){0}) _bn_part_result; \
	_Static_assert((size_t)(offset) <= sizeof(_bn_part_source) \
		&& sizeof(_bn_part_result) <= sizeof(_bn_part_source) - (size_t)(offset), "READ_PART outside source"); \
	memcpy(&_bn_part_result, (const unsigned char*)&_bn_part_source + (offset), sizeof(_bn_part_result)); \
	_bn_part_result; \
})
#endif
#ifndef WRITE_PART
#define WRITE_PART(type, destination, offset, value) __extension__ ({ \
	__auto_type _bn_part_destination = &(destination); \
	__auto_type _bn_part_value = (value); \
	_Static_assert(sizeof(type) == sizeof(_bn_part_value), "WRITE_PART size mismatch"); \
	_Static_assert((size_t)(offset) <= sizeof(*_bn_part_destination) \
		&& sizeof(type) <= sizeof(*_bn_part_destination) - (size_t)(offset), "WRITE_PART outside destination"); \
	_Static_assert(!__builtin_types_compatible_p(__typeof__(_bn_part_destination), \
		const __typeof__(*_bn_part_destination)*), "WRITE_PART destination is const"); \
	_Static_assert(!__builtin_types_compatible_p(__typeof__(_bn_part_destination), \
		volatile __typeof__(*_bn_part_destination)*), "WRITE_PART destination is volatile"); \
	(void)memcpy((unsigned char*)_bn_part_destination + (offset), &_bn_part_value, sizeof(type)); \
})
#endif

#endif /* __cplusplus */

/* Counts are reduced modulo the value width, or width+1 for a carry rotation.
 * The carry input is one bit; RLC/RRC return the value, not the updated carry.
 * Special cases avoid shifts by the full width, including for 128-bit values.
 */
#define BN_PSEUDOC_ROTATIONS(suffix, type, bits) \
static inline type ROL##suffix(type value, uint64_t count) \
{ \
	unsigned n = (unsigned)(count % (bits)); \
	return n ? (type)((value << n) | (value >> ((bits) - n))) : value; \
} \
static inline type ROR##suffix(type value, uint64_t count) \
{ \
	unsigned n = (unsigned)(count % (bits)); \
	return n ? (type)((value >> n) | (value << ((bits) - n))) : value; \
} \
static inline type RLC##suffix(type value, uint64_t count, bool carry) \
{ \
	unsigned n = (unsigned)(count % ((bits) + 1)); \
	if (!n) return value; \
	if (n == (bits)) return (type)((value >> 1) | ((type)carry << ((bits) - 1))); \
	return (type)((value << n) | ((type)carry << (n - 1)) \
		| (n > 1 ? value >> ((bits) + 1 - n) : 0)); \
} \
static inline type RRC##suffix(type value, uint64_t count, bool carry) \
{ \
	unsigned n = (unsigned)(count % ((bits) + 1)); \
	if (!n) return value; \
	if (n == (bits)) return (type)((value << 1) | (type)carry); \
	return (type)((value >> n) | ((type)carry << ((bits) - n)) \
		| (n > 1 ? value << ((bits) + 1 - n) : 0)); \
} \
static inline bool TEST_BIT##suffix(type value, uint64_t index) \
{ \
	return index < (bits) && ((value >> index) & 1) != 0; \
}

BN_PSEUDOC_ROTATIONS(B, uint8_t, 8)
BN_PSEUDOC_ROTATIONS(W, uint16_t, 16)
BN_PSEUDOC_ROTATIONS(D, uint32_t, 32)
BN_PSEUDOC_ROTATIONS(Q, uint64_t, 64)
#if BN_PSEUDOC_HAS_INT128
BN_PSEUDOC_ROTATIONS(O, bn_pseudoc_uint128, 128)
#endif
#undef BN_PSEUDOC_ROTATIONS

#define LOWB(value) ((uint8_t)(value))
#define LOWW(value) ((uint16_t)(value))
#define LOWD(value) ((uint32_t)(value))
#define LOWQ(value) ((uint64_t)(value))
static inline uint8_t HIGHB(uint16_t value) { return (uint8_t)(value >> 8); }
static inline uint16_t HIGHW(uint32_t value) { return (uint16_t)(value >> 16); }
static inline uint32_t HIGHD(uint64_t value) { return (uint32_t)(value >> 32); }
#if BN_PSEUDOC_HAS_INT128
#define LOWO(value) ((bn_pseudoc_uint128)(value))
static inline uint64_t HIGHQ(bn_pseudoc_uint128 value) { return (uint64_t)(value >> 64); }
#endif

#define BN_PSEUDOC_COMBINE(bits, narrow, wide) \
static inline wide bn_pseudoc_combine##bits(narrow high, narrow low) \
{ return ((wide)high << (bits)) | (wide)low; }
BN_PSEUDOC_COMBINE(8, uint8_t, uint16_t)
BN_PSEUDOC_COMBINE(16, uint16_t, uint32_t)
BN_PSEUDOC_COMBINE(32, uint32_t, uint64_t)
#if BN_PSEUDOC_HAS_INT128
BN_PSEUDOC_COMBINE(64, uint64_t, bn_pseudoc_uint128)
#endif
#undef BN_PSEUDOC_COMBINE

/* Portable implementations avoid compiler-specific bit-reversal intrinsics.
 * CLS counts leading bits equal to the sign bit, excluding the sign bit itself.
 */
#define BN_PSEUDOC_BIT_FUNCTIONS(bits, type) \
static inline type bn_pseudoc_rbit##bits(type value) \
{ \
	type result = 0; \
	for (unsigned i = 0; i < (bits); ++i) { result = (type)((result << 1) | (value & 1)); value >>= 1; } \
	return result; \
} \
static inline unsigned bn_pseudoc_cls##bits(type value) \
{ \
	unsigned count = 0; \
	const unsigned sign = (unsigned)(value >> ((bits) - 1)); \
	for (unsigned i = (bits) - 1; i && (unsigned)((value >> (i - 1)) & 1) == sign; --i) ++count; \
	return count; \
}
BN_PSEUDOC_BIT_FUNCTIONS(8, uint8_t)
BN_PSEUDOC_BIT_FUNCTIONS(16, uint16_t)
BN_PSEUDOC_BIT_FUNCTIONS(32, uint32_t)
BN_PSEUDOC_BIT_FUNCTIONS(64, uint64_t)
#if BN_PSEUDOC_HAS_INT128
BN_PSEUDOC_BIT_FUNCTIONS(128, bn_pseudoc_uint128)
#endif
#undef BN_PSEUDOC_BIT_FUNCTIONS

#ifdef __cplusplus
namespace bn_pseudoc_detail
{

template <size_t Bytes> struct integer_width;
#define BN_PSEUDOC_CPP_INTEGER(bytes, bits, unsigned_type) \
template <> struct integer_width<bytes> { \
	typedef unsigned_type type; \
	static type rbit(type value) { return bn_pseudoc_rbit##bits(value); } \
	static unsigned cls(type value) { return bn_pseudoc_cls##bits(value); } \
};
BN_PSEUDOC_CPP_INTEGER(1, 8, uint8_t)
BN_PSEUDOC_CPP_INTEGER(2, 16, uint16_t)
BN_PSEUDOC_CPP_INTEGER(4, 32, uint32_t)
BN_PSEUDOC_CPP_INTEGER(8, 64, uint64_t)
#if BN_PSEUDOC_HAS_INT128
BN_PSEUDOC_CPP_INTEGER(16, 128, bn_pseudoc_uint128)
#endif
#undef BN_PSEUDOC_CPP_INTEGER

template <class T> struct is_integer
	: std::integral_constant<bool, std::is_integral<T>::value || std::is_enum<T>::value> {};
#if BN_PSEUDOC_HAS_INT128
template <> struct is_integer<bn_pseudoc_uint128> : std::true_type {};
template <> struct is_integer<__int128> : std::true_type {};
#endif

template <size_t Bytes> struct double_width;
template <> struct double_width<1> { typedef uint16_t type; };
template <> struct double_width<2> { typedef uint32_t type; };
template <> struct double_width<4> { typedef uint64_t type; };
#if BN_PSEUDOC_HAS_INT128
template <> struct double_width<8> { typedef bn_pseudoc_uint128 type; };
#endif
template <class High, class Low>
inline typename double_width<sizeof(Low)>::type combine(High high, Low low)
{
	static_assert(sizeof(High) == sizeof(Low), "COMBINE requires equally sized halves");
	static_assert(is_integer<High>::value && is_integer<Low>::value, "COMBINE requires integers");
	typedef typename double_width<sizeof(Low)>::type Result;
	typedef typename integer_width<sizeof(Low)>::type Half;
	return (Result(Half(high)) << (8 * sizeof(Low))) | Result(Half(low));
}

template <class T> inline typename integer_width<sizeof(T)>::type rbit(T value)
{
	static_assert(is_integer<T>::value, "__rbit requires an integer");
	typedef integer_width<sizeof(T)> Width;
	return Width::rbit(typename Width::type(value));
}
template <class T> inline unsigned cls(T value)
{
	static_assert(is_integer<T>::value, "__cls requires an integer");
	typedef integer_width<sizeof(T)> Width;
	return Width::cls(typename Width::type(value));
}

} // namespace bn_pseudoc_detail

#ifndef COMBINE
#define COMBINE(high, low) (::bn_pseudoc_detail::combine((high), (low)))
#endif
#ifndef BN_PSEUDOC_NO_BIT_INTRINSICS
#ifndef __rbit
#define __rbit(value) (::bn_pseudoc_detail::rbit((value)))
#endif
#ifndef __cls
#define __cls(value) (::bn_pseudoc_detail::cls((value)))
#endif
#endif

/* Functions, not macros, keep C++ standard headers usable after this header. */
#ifndef BN_PSEUDOC_NO_MINMAX
#ifndef min
template <class A, class B> inline typename std::common_type<A, B>::type min(A a, B b) { return a < b ? a : b; }
#endif
#ifndef max
template <class A, class B> inline typename std::common_type<A, B>::type max(A a, B b) { return a > b ? a : b; }
#endif
#endif

#else /* GCC/Clang C */

#if BN_PSEUDOC_HAS_INT128
#define BN_PSEUDOC_COMBINE64 , char (*)[8]: bn_pseudoc_combine64
#define BN_PSEUDOC_BITS128(prefix) , char (*)[16]: prefix##128
#else
#define BN_PSEUDOC_COMBINE64
#define BN_PSEUDOC_BITS128(prefix)
#endif
#ifndef COMBINE
#define COMBINE(high, low) __extension__ ({ \
	_Static_assert(sizeof(high) == sizeof(low), "COMBINE requires equally sized halves"); \
	(void)sizeof((high) | 0); (void)sizeof((low) | 0); \
	_Generic((char (*)[sizeof(low)])0, char (*)[1]: bn_pseudoc_combine8, \
		char (*)[2]: bn_pseudoc_combine16, char (*)[4]: bn_pseudoc_combine32 \
		BN_PSEUDOC_COMBINE64)((high), (low)); \
})
#endif

/* Dispatch by width, not typedef identity: long and long long may both be 64 bits.
 * The unevaluated bitwise expression rejects non-integer operands.
 */
#define BN_PSEUDOC_BIT_DISPATCH(value, prefix) _Generic( \
	((void)sizeof((value) | 0), (char (*)[sizeof(value)])0), \
	char (*)[1]: prefix##8, char (*)[2]: prefix##16, char (*)[4]: prefix##32, char (*)[8]: prefix##64 \
	BN_PSEUDOC_BITS128(prefix))
#ifndef BN_PSEUDOC_NO_BIT_INTRINSICS
#ifndef __rbit
#define __rbit(value) BN_PSEUDOC_BIT_DISPATCH((value), bn_pseudoc_rbit)((value))
#endif
#ifndef __cls
#define __cls(value) BN_PSEUDOC_BIT_DISPATCH((value), bn_pseudoc_cls)((value))
#endif
#endif

#ifndef BN_PSEUDOC_NO_MINMAX
#ifndef min
#define min(a, b) __extension__ ({ __auto_type _bn_min_a = (a); __auto_type _bn_min_b = (b); \
	_bn_min_a < _bn_min_b ? _bn_min_a : _bn_min_b; })
#endif
#ifndef max
#define max(a, b) __extension__ ({ __auto_type _bn_max_a = (a); __auto_type _bn_max_b = (b); \
	_bn_max_a > _bn_max_b ? _bn_max_a : _bn_max_b; })
#endif
#endif

#endif /* __cplusplus */

/* Compatibility with older Pseudo C exports. Current output uses math.h names. */
#ifndef FCMP_UO
#define FCMP_UO(a, b) isunordered((a), (b))
#endif
#ifndef FCMP_O
#define FCMP_O(a, b) (!isunordered((a), (b)))
#endif

#endif /* BN_PSEUDOC_HELPERS_H */
