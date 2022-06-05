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

#include "binaryninja_defs.h"
#include "binarywriter.hpp"
#include "getobject.hpp"
#include "databuffer.hpp"

using namespace BinaryNinja;
using namespace std;


BinaryWriter::BinaryWriter(BinaryView* data, BNEndianness endian) : m_view(data)
{
	m_stream = BNCreateBinaryWriter(GetView(data));
	BNSetBinaryWriterEndianness(m_stream, endian);
}


BinaryWriter::~BinaryWriter()
{
	BNFreeBinaryWriter(m_stream);
}


BNEndianness BinaryWriter::GetEndianness() const
{
	return BNGetBinaryWriterEndianness(m_stream);
}


void BinaryWriter::SetEndianness(BNEndianness endian)
{
	BNSetBinaryWriterEndianness(m_stream, endian);
}


void BinaryWriter::Write(const void* src, size_t len)
{
	if (!BNWriteData(m_stream, src, len))
		throw WriteException();
}


void BinaryWriter::Write(const DataBuffer& buf)
{
	Write(buf.GetData(), buf.GetLength());
}


void BinaryWriter::Write(const string& str)
{
	Write(str.c_str(), str.size());
}


void BinaryWriter::Write8(uint8_t val)
{
	if (!BNWrite8(m_stream, val))
		throw WriteException();
}


void BinaryWriter::Write16(uint16_t val)
{
	if (!BNWrite16(m_stream, val))
		throw WriteException();
}


void BinaryWriter::Write32(uint32_t val)
{
	if (!BNWrite32(m_stream, val))
		throw WriteException();
}


void BinaryWriter::Write64(uint64_t val)
{
	if (!BNWrite64(m_stream, val))
		throw WriteException();
}


void BinaryWriter::WriteLE16(uint16_t val)
{
	if (!BNWriteLE16(m_stream, val))
		throw WriteException();
}


void BinaryWriter::WriteLE32(uint32_t val)
{
	if (!BNWriteLE32(m_stream, val))
		throw WriteException();
}


void BinaryWriter::WriteLE64(uint64_t val)
{
	if (!BNWriteLE64(m_stream, val))
		throw WriteException();
}


void BinaryWriter::WriteBE16(uint16_t val)
{
	if (!BNWriteBE16(m_stream, val))
		throw WriteException();
}


void BinaryWriter::WriteBE32(uint32_t val)
{
	if (!BNWriteBE32(m_stream, val))
		throw WriteException();
}


void BinaryWriter::WriteBE64(uint64_t val)
{
	if (!BNWriteBE64(m_stream, val))
		throw WriteException();
}


bool BinaryWriter::TryWrite(const void* src, size_t len)
{
	return BNWriteData(m_stream, src, len);
}


bool BinaryWriter::TryWrite(const DataBuffer& buf)
{
	return TryWrite(buf.GetData(), buf.GetLength());
}


bool BinaryWriter::TryWrite(const string& str)
{
	return TryWrite(str.c_str(), str.size());
}


bool BinaryWriter::TryWrite8(uint8_t val)
{
	return BNWrite8(m_stream, val);
}


bool BinaryWriter::TryWrite16(uint16_t val)
{
	return BNWrite16(m_stream, val);
}


bool BinaryWriter::TryWrite32(uint32_t val)
{
	return BNWrite32(m_stream, val);
}


bool BinaryWriter::TryWrite64(uint64_t val)
{
	return BNWrite64(m_stream, val);
}


bool BinaryWriter::TryWriteLE16(uint16_t val)
{
	return BNWriteLE16(m_stream, val);
}


bool BinaryWriter::TryWriteLE32(uint32_t val)
{
	return BNWriteLE32(m_stream, val);
}


bool BinaryWriter::TryWriteLE64(uint64_t val)
{
	return BNWriteLE64(m_stream, val);
}


bool BinaryWriter::TryWriteBE16(uint16_t val)
{
	return BNWriteBE16(m_stream, val);
}


bool BinaryWriter::TryWriteBE32(uint32_t val)
{
	return BNWriteBE32(m_stream, val);
}


bool BinaryWriter::TryWriteBE64(uint64_t val)
{
	return BNWriteBE64(m_stream, val);
}


uint64_t BinaryWriter::GetOffset() const
{
	return BNGetWriterPosition(m_stream);
}


void BinaryWriter::Seek(uint64_t offset)
{
	BNSeekBinaryWriter(m_stream, offset);
}


void BinaryWriter::SeekRelative(int64_t offset)
{
	BNSeekBinaryWriterRelative(m_stream, offset);
}
