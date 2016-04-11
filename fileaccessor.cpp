// Copyright (c) 2015-2016 Vector 35 LLC
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


uint64_t FileAccessor::GetLengthCallback(void* ctxt)
{
	FileAccessor* file = (FileAccessor*)ctxt;
	return file->GetLength();
}


size_t FileAccessor::ReadCallback(void* ctxt, void* dest, uint64_t offset, size_t len)
{
	FileAccessor* file = (FileAccessor*)ctxt;
	return file->Read(dest, offset, len);
}


size_t FileAccessor::WriteCallback(void* ctxt, uint64_t offset, const void* src, size_t len)
{
	FileAccessor* file = (FileAccessor*)ctxt;
	return file->Write(offset, src, len);
}


FileAccessor::FileAccessor()
{
	m_callbacks.context = this;
	m_callbacks.getLength = GetLengthCallback;
	m_callbacks.read = ReadCallback;
	m_callbacks.write = WriteCallback;
}


FileAccessor::FileAccessor(BNFileAccessor* accessor): m_callbacks(*accessor)
{
}


CoreFileAccessor::CoreFileAccessor(BNFileAccessor* accessor): FileAccessor(accessor)
{
}


uint64_t CoreFileAccessor::GetLength() const
{
	return m_callbacks.getLength(m_callbacks.context);
}


size_t CoreFileAccessor::Read(void* dest, uint64_t offset, size_t len)
{
	return m_callbacks.read(m_callbacks.context, dest, offset, len);
}


size_t CoreFileAccessor::Write(uint64_t offset, const void* src, size_t len)
{
	return m_callbacks.write(m_callbacks.context, offset, src, len);
}

