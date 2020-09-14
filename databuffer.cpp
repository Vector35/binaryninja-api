// Copyright (c) 2015-2021 Vector 35 Inc
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

#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


DataBuffer::DataBuffer()
{
	m_buffer = BNCreateDataBuffer(nullptr, 0);
}


DataBuffer::DataBuffer(size_t len)
{
	m_buffer = BNCreateDataBuffer(nullptr, len);
}


DataBuffer::DataBuffer(const void* data, size_t len)
{
	m_buffer = BNCreateDataBuffer(data, len);
}


DataBuffer::DataBuffer(const DataBuffer& buf)
{
	m_buffer = BNDuplicateDataBuffer(buf.m_buffer);
}

DataBuffer::DataBuffer(DataBuffer&& buf)
{
	m_buffer = buf.m_buffer;
	buf.m_buffer = BNCreateDataBuffer(nullptr, 0);
}

DataBuffer::DataBuffer(BNDataBuffer* buf)
{
	m_buffer = buf;
}


DataBuffer::~DataBuffer()
{
	BNFreeDataBuffer(m_buffer);
}


DataBuffer& DataBuffer::operator=(const DataBuffer& buf)
{
	if (this != &buf)
	{
		BNFreeDataBuffer(m_buffer);
		m_buffer = BNDuplicateDataBuffer(buf.m_buffer);
	}

	return *this;
}

DataBuffer& DataBuffer::operator=(DataBuffer&& buf)
{
	if (this != &buf)
	{
		BNClearDataBuffer(m_buffer);
		BNDataBuffer* temp = m_buffer;
		m_buffer = buf.m_buffer;
		buf.m_buffer = temp;
	}

	return *this;
}

bool DataBuffer::operator==(const DataBuffer& other) const
{
	uint8_t* data = (uint8_t*)GetData();
	uint8_t* otherData = (uint8_t*)other.GetData();
	if (GetLength() != other.GetLength())
		return false;
	if (data == otherData)
		return true;

	for (size_t i = 0; i < GetLength(); i++)
	{
		if (data[i] != otherData[i])
			return false;
	}
	return true;
}

bool DataBuffer::operator!=(const DataBuffer& other) const
{
	return !(*this == other);
}

void* DataBuffer::GetData()
{
	return BNGetDataBufferContents(m_buffer);
}


const void* DataBuffer::GetData() const
{
	return BNGetDataBufferContents(m_buffer);
}


void* DataBuffer::GetDataAt(size_t offset)
{
	return BNGetDataBufferContentsAt(m_buffer, offset);
}


const void* DataBuffer::GetDataAt(size_t offset) const
{
	return BNGetDataBufferContentsAt(m_buffer, offset);
}


size_t DataBuffer::GetLength() const
{
	return BNGetDataBufferLength(m_buffer);
}


void DataBuffer::SetSize(size_t len)
{
	BNSetDataBufferLength(m_buffer, len);
}


void DataBuffer::Clear()
{
	BNClearDataBuffer(m_buffer);
}


void DataBuffer::Append(const void* data, size_t len)
{
	BNAppendDataBufferContents(m_buffer, data, len);
}


void DataBuffer::Append(const DataBuffer& buf)
{
	BNAppendDataBuffer(m_buffer, buf.m_buffer);
}


void DataBuffer::AppendByte(uint8_t val)
{
	Append(&val, 1);
}


DataBuffer DataBuffer::GetSlice(size_t start, size_t len)
{
	BNDataBuffer* result = BNGetDataBufferSlice(m_buffer, start, len);
	return DataBuffer(result);
}


uint8_t& DataBuffer::operator[](size_t offset)
{
	return ((uint8_t*)GetData())[offset];
}


const uint8_t& DataBuffer::operator[](size_t offset) const
{
	return ((const uint8_t*)GetData())[offset];
}


string DataBuffer::ToEscapedString() const
{
	char* str = BNDataBufferToEscapedString(m_buffer);
	string result = str;
	BNFreeString(str);
	return result;
}


DataBuffer DataBuffer::FromEscapedString(const string& src)
{
	return DataBuffer(BNDecodeEscapedString(src.c_str()));
}


string DataBuffer::ToBase64() const
{
	char* str = BNDataBufferToBase64(m_buffer);
	string result = str;
	BNFreeString(str);
	return result;
}


DataBuffer DataBuffer::FromBase64(const string& src)
{
	return DataBuffer(BNDecodeBase64(src.c_str()));
}


bool DataBuffer::ZlibCompress(DataBuffer& output) const
{
	BNDataBuffer* result = BNZlibCompress(output.m_buffer);
	if (!result)
		return false;
	output = DataBuffer(result);
	return true;
}


bool DataBuffer::ZlibDecompress(DataBuffer& output) const
{
	BNDataBuffer* result = BNZlibDecompress(output.m_buffer);
	if (!result)
		return false;
	output = DataBuffer(result);
	return true;
}


string BinaryNinja::EscapeString(const string& s)
{
	DataBuffer buffer(s.c_str(), s.size());
	return buffer.ToEscapedString();
}


string BinaryNinja::UnescapeString(const string& s)
{
	DataBuffer buffer = DataBuffer::FromEscapedString(s);
	return string((const char*)buffer.GetData(), buffer.GetLength());
}
