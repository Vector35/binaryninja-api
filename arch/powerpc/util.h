#ifdef __clang__
#define FALL_THROUGH
#elif defined(__GNUC__) && __GNUC__ >= 7
#define FALL_THROUGH __attribute__((fallthrough));
#else
#define FALL_THROUGH
#endif

#define ADDRMASK(addressSize, target) \
	if (addressSize == 4) \
	{ \
		target &= 0xffffffff; \
	}

#define EXTOPT(rawInsn, addressSize, extend, TYPE) \
	{ \
		int L_tmp = ((rawInsn >> 10) & 1); \
		if ((L_tmp == 1) && (addressSize == 8)) \
		{ \
			extend = OTI_ ## TYPE ## EXT64_IMMS; \
		} \
		else \
		{ \
			extend = OTI_ ## TYPE ## EXT32_IMMS; \
		} \
	}

#define EXTOPTZ(data, addressSize, extend) EXTOPT(data, addressSize, extend, Z)
#define EXTOPTS(data, addressSize, extend) EXTOPT(data, addressSize, extend, S)

#define ADDRNEG1(addressSize) (addressSize == 4) ? ((uint32_t)-1) : ((uint64_t)-1)

inline uint32_t bswap32(uint32_t x)
{
	return ((x&0xFF)<<24) |
		((x&0xFF00)<<8) |
		((x&0xFF0000)>>8) |
		((x&0xFF000000)>>24);
}

uint64_t sign_extend(size_t addressSize_local, uint64_t target, int signBit);
