// Copyright (c) 2015-2022 Vector 35 Inc
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#include "binaryreader.h"
#include "binaryreader.hpp"
#include "getobject.hpp"
#include "databuffer.hpp"

using namespace BinaryNinja;
using namespace std;


BinaryReader::BinaryReader(BinaryView* data, BNEndianness endian) : m_view(data)
{
	m_stream = BNCreateBinaryReader(GetView(data));
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


template <typename T>
T BinaryReader::Read()
{
	T value;
	Read((char*)&value, sizeof(T));
	return value;
}

template <typename T>
vector<T> BinaryReader::ReadVector(size_t count)
{
	T* buff = new T[count];
	Read((char*)buff, count * sizeof(T));
	std::vector<T> out(buff, buff + count);
	return out;
}


string BinaryReader::ReadCString(size_t maxSize)
{
	string result;
	try
	{
		for (size_t i = 0; i < maxSize; i++)
		{
			char cur = Read8();
			if (cur == 0)
				break;
			result.push_back(cur);
		}
	}
	catch (ReadException&)
	{
		;
	}
	return result;
}
