#include "binaryninjaapi.h"

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
