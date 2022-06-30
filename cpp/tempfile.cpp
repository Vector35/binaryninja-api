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

#include "binaryninja/tempfile.hpp"
#include "binaryninja/databuffer.hpp"

using namespace BinaryNinja;
using namespace std;


TemporaryFile::TemporaryFile()
{
	m_object = BNCreateTemporaryFile();
}


TemporaryFile::TemporaryFile(const DataBuffer& contents)
{
	m_object = BNCreateTemporaryFileWithContents(contents.GetBufferObject());
}


TemporaryFile::TemporaryFile(const string& contents)
{
	DataBuffer buf(contents.c_str(), contents.size());
	m_object = BNCreateTemporaryFileWithContents(buf.GetBufferObject());
}


TemporaryFile::TemporaryFile(BNTemporaryFile* file)
{
	m_object = file;
}


string TemporaryFile::GetPath() const
{
	if (!m_object)
		return string();

	char* str = BNGetTemporaryFilePath(m_object);
	string result = str;
	BNFreeString(str);
	return result;
}


DataBuffer TemporaryFile::GetContents()
{
	if (!m_object)
		return DataBuffer();
	return DataBuffer(BNGetTemporaryFileContents(m_object));
}
