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

#ifndef READ_PART
#define READ_PART(type, value, offset) __extension__ ({ \
	__auto_type _bn_part_source = (value); \
	type _bn_part_result; \
	_Static_assert((offset) <= sizeof(_bn_part_source) \
		&& sizeof(_bn_part_result) <= sizeof(_bn_part_source) - (offset), "READ_PART outside source"); \
	memcpy(&_bn_part_result, (const unsigned char*)&_bn_part_source + (offset), sizeof(_bn_part_result)); \
	_bn_part_result; \
})
#endif

#ifndef WRITE_PART
#define WRITE_PART(type, destination, offset, value) __extension__ ({ \
	__auto_type _bn_part_destination = &(destination); \
	__auto_type _bn_part_value = (value); \
	_Static_assert(sizeof(type) == sizeof(_bn_part_value), "WRITE_PART size mismatch"); \
	_Static_assert((offset) <= sizeof(*_bn_part_destination) \
		&& sizeof(type) <= sizeof(*_bn_part_destination) - (offset), "WRITE_PART outside destination"); \
	(void)memcpy((unsigned char*)_bn_part_destination + (offset), &_bn_part_value, sizeof(type)); \
})
#endif

#endif
