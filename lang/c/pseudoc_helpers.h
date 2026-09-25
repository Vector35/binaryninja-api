#ifndef BN_PSEUDOC_HELPERS_H
#define BN_PSEUDOC_HELPERS_H

#include <string.h>

// Representation transfers emitted by Pseudo C. This helper uses GCC/Clang C
// extensions to evaluate the source once and avoid aliasing or union punning.
#ifndef BIT_CAST
#define BIT_CAST(type, value) __extension__ ({ \
	__auto_type _bn_bit_cast_source = (value); \
	__auto_type _bn_bit_cast_result = (type){0}; \
	_Static_assert(sizeof(_bn_bit_cast_result) == sizeof(_bn_bit_cast_source), "BIT_CAST size mismatch"); \
	memcpy(&_bn_bit_cast_result, &_bn_bit_cast_source, sizeof(_bn_bit_cast_result)); \
	_bn_bit_cast_result; \
})
#endif

#endif
