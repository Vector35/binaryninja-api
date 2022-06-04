#pragma once
#include "binaryninja_defs.h"

extern "C" {
	struct BNBinaryReader;
	struct BNBinaryView;
	// Stream reader object
	BINARYNINJACOREAPI BNBinaryReader* BNCreateBinaryReader(BNBinaryView* view);
	BINARYNINJACOREAPI void BNFreeBinaryReader(BNBinaryReader* stream);
	BINARYNINJACOREAPI BNEndianness BNGetBinaryReaderEndianness(BNBinaryReader* stream);
	BINARYNINJACOREAPI void BNSetBinaryReaderEndianness(BNBinaryReader* stream, BNEndianness endian);

	BINARYNINJACOREAPI bool BNReadData(BNBinaryReader* stream, void* dest, size_t len);
	BINARYNINJACOREAPI bool BNRead8(BNBinaryReader* stream, uint8_t* result);
	BINARYNINJACOREAPI bool BNRead16(BNBinaryReader* stream, uint16_t* result);
	BINARYNINJACOREAPI bool BNRead32(BNBinaryReader* stream, uint32_t* result);
	BINARYNINJACOREAPI bool BNRead64(BNBinaryReader* stream, uint64_t* result);
	BINARYNINJACOREAPI bool BNReadLE16(BNBinaryReader* stream, uint16_t* result);
	BINARYNINJACOREAPI bool BNReadLE32(BNBinaryReader* stream, uint32_t* result);
	BINARYNINJACOREAPI bool BNReadLE64(BNBinaryReader* stream, uint64_t* result);
	BINARYNINJACOREAPI bool BNReadBE16(BNBinaryReader* stream, uint16_t* result);
	BINARYNINJACOREAPI bool BNReadBE32(BNBinaryReader* stream, uint32_t* result);
	BINARYNINJACOREAPI bool BNReadBE64(BNBinaryReader* stream, uint64_t* result);

	BINARYNINJACOREAPI uint64_t BNGetReaderPosition(BNBinaryReader* stream);
	BINARYNINJACOREAPI void BNSeekBinaryReader(BNBinaryReader* stream, uint64_t offset);
	BINARYNINJACOREAPI void BNSeekBinaryReaderRelative(BNBinaryReader* stream, int64_t offset);
	BINARYNINJACOREAPI bool BNIsEndOfFile(BNBinaryReader* stream);
}