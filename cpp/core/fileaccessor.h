#pragma once

#ifdef __cplusplus
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#else
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#endif

extern "C" {
	struct BNFileAccessor
	{
		void* context;
		uint64_t (*getLength)(void* ctxt);
		size_t (*read)(void* ctxt, void* dest, uint64_t offset, size_t len);
		size_t (*write)(void* ctxt, uint64_t offset, const void* src, size_t len);
	};
}