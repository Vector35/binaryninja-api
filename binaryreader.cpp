#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


BinaryReader::BinaryReader(BinaryView* data, BNEndianness endian): m_view(data)
{
	m_stream = BNCreateBinaryReader(data->GetObject());
	BNSetBinaryReaderEndianness(m_stream, endian);
}


BinaryReader::~BinaryReader()
{
	BNFreeBinaryReader(m_stream);
}


BNEndianness BinaryReader::GetEndianness() const
{
	return BNGetBinaryReaderEndianness(m_stream);
}


void BinaryReader::SetEndianness(BNEndianness endian)
{
	BNSetBinaryReaderEndianness(m_stream, endian);
}


void BinaryReader::Read(void* dest, size_t len)
{
	if (!BNReadData(m_stream, dest, len))
		throw ReadException();
}


DataBuffer BinaryReader::Read(size_t len)
{
	DataBuffer result(len);
	Read(result.GetData(), len);
	return result;
}


string BinaryReader::ReadString(size_t len)
{
	DataBuffer result = Read(len);
	return string((const char*)result.GetData(), len);
}


uint8_t BinaryReader::Read8()
{
	uint8_t result;
	if (!BNRead8(m_stream, &result))
		throw ReadException();
	return result;
}


uint16_t BinaryReader::Read16()
{
	uint16_t result;
	if (!BNRead16(m_stream, &result))
		throw ReadException();
	return result;
}


uint32_t BinaryReader::Read32()
{
	uint32_t result;
	if (!BNRead32(m_stream, &result))
		throw ReadException();
	return result;
}


uint64_t BinaryReader::Read64()
{
	uint64_t result;
	if (!BNRead64(m_stream, &result))
		throw ReadException();
	return result;
}


uint16_t BinaryReader::ReadLE16()
{
	uint16_t result;
	if (!BNReadLE16(m_stream, &result))
		throw ReadException();
	return result;
}


uint32_t BinaryReader::ReadLE32()
{
	uint32_t result;
	if (!BNReadLE32(m_stream, &result))
		throw ReadException();
	return result;
}


uint64_t BinaryReader::ReadLE64()
{
	uint64_t result;
	if (!BNReadLE64(m_stream, &result))
		throw ReadException();
	return result;
}


uint16_t BinaryReader::ReadBE16()
{
	uint16_t result;
	if (!BNReadBE16(m_stream, &result))
		throw ReadException();
	return result;
}


uint32_t BinaryReader::ReadBE32()
{
	uint32_t result;
	if (!BNReadBE32(m_stream, &result))
		throw ReadException();
	return result;
}


uint64_t BinaryReader::ReadBE64()
{
	uint64_t result;
	if (!BNReadBE64(m_stream, &result))
		throw ReadException();
	return result;
}


bool BinaryReader::TryRead(void* dest, size_t len)
{
	return BNReadData(m_stream, dest, len);
}


bool BinaryReader::TryRead(DataBuffer& dest, size_t len)
{
	dest.SetSize(len);
	return TryRead(dest.GetData(), len);
}


bool BinaryReader::TryReadString(string& dest, size_t len)
{
	DataBuffer result(len);
	if (!TryRead(result.GetData(), len))
		return false;
	dest = string((const char*)result.GetData(), len);
	return true;
}


bool BinaryReader::TryRead8(uint8_t& result)
{
	return BNRead8(m_stream, &result);
}


bool BinaryReader::TryRead16(uint16_t& result)
{
	return BNRead16(m_stream, &result);
}


bool BinaryReader::TryRead32(uint32_t& result)
{
	return BNRead32(m_stream, &result);
}


bool BinaryReader::TryRead64(uint64_t& result)
{
	return BNRead64(m_stream, &result);
}


bool BinaryReader::TryReadLE16(uint16_t& result)
{
	return BNReadLE16(m_stream, &result);
}


bool BinaryReader::TryReadLE32(uint32_t& result)
{
	return BNReadLE32(m_stream, &result);
}


bool BinaryReader::TryReadLE64(uint64_t& result)
{
	return BNReadLE64(m_stream, &result);
}


bool BinaryReader::TryReadBE16(uint16_t& result)
{
	return BNReadBE16(m_stream, &result);
}


bool BinaryReader::TryReadBE32(uint32_t& result)
{
	return BNReadBE32(m_stream, &result);
}


bool BinaryReader::TryReadBE64(uint64_t& result)
{
	return BNReadBE64(m_stream, &result);
}


uint64_t BinaryReader::GetOffset() const
{
	return BNGetReaderPosition(m_stream);
}


void BinaryReader::Seek(uint64_t offset)
{
	BNSeekBinaryReader(m_stream, offset);
}


void BinaryReader::SeekRelative(int64_t offset)
{
	BNSeekBinaryReaderRelative(m_stream, offset);
}


bool BinaryReader::IsEndOfFile() const
{
	return BNIsEndOfFile(m_stream);
}
